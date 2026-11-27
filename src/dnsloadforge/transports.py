"""How queries reach the target: UDP, TCP, DNS over TLS and DNS over HTTPS.

UDP is what an office mostly sends, and it stays the engine's own path.  The
others are here because a filter has to be judged on every road a client takes to
it: TCP (RFC 7766) for large answers, DNS over TLS (RFC 7858) for Android's
Private DNS and the encrypted DNS in Windows 11, and DNS over HTTPS (RFC 8484) for
browsers.  A filter that blocks a name over UDP and resolves it over DoH has a
hole a browser walks straight through.

Two halves:

* :func:`exchange` and :func:`probe` send one query and wait, with plain sockets.
  The preflight check and the deployment checks use them.
* :class:`StreamChannel` (TCP, DoT) and :class:`HttpChannel` (DoH) carry a run's
  traffic.  Each stands where the engine's UDP socket stands -- the same
  ``pending`` table, the same ``transport.sendto`` -- over a pool of connections.

Connections are opened before the first query, so a handshake is never counted as
latency.  TCP and DoT pipeline queries on every connection and match answers by
ID: servers answer in whatever order they finish (Quad9, Google and Cloudflare all
answered a pipelined batch out of order when this was checked on 2026-11-26).
DoH sends one request at a time on each keep-alive connection, because HTTP/1.1
answers strictly in order and one slow lookup would hold up every answer behind
it; the pool starts with room for a page load's whole burst.  When every
connection is busy the query is dropped and counted, like any sender-side limit,
and the pool grows.  A query left waiting when a server closes its connection is
sent again once on another, as a resolver library would.

HTTP/2, which some DoH services insist on (Quad9 answers HTTP/1.1 with 505), is not
in the standard library, so it is not spoken here; DoT reaches those services.
"""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import socket
import ssl
import struct
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import __version__
from .packets import DNSError, decode_message, encode_query
from .spec import DEFAULT_PORTS, TRANSPORT_LABELS, TRANSPORTS, endpoint_label

__all__ = [
    "Endpoint",
    "HttpChannel",
    "HttpResponse",
    "HttpResponseParser",
    "QueryIds",
    "StreamChannel",
    "TransportError",
    "describe_error",
    "exchange",
    "http_problem",
    "is_loopback",
    "make_channel",
    "parse_doh_url",
    "pool_size",
    "probe",
]

#: Room enough that it never limits: a UDP socket or a pipelined stream.
UNLIMITED = 1 << 30

#: Connections per sending thread for TCP and DoT, which pipeline.
DEFAULT_STREAM_CONNECTIONS = 4
#: A DoH pool starts sized for the rate and grows to this when it runs short.
MAX_HTTP_CONNECTIONS = 256

_MAX_HEAD = 16 * 1024
#: Larger than any DNS message; an error page can be long, an answer cannot.
_MAX_BODY = 1 << 20

#: What OpenSSL says when a chain ends at a root that is not in the trust store.
_ROOT_MISSING = (
    "unable to get local issuer certificate",
    "self-signed certificate in certificate chain",
    "self signed certificate in certificate chain",
)


class TransportError(OSError):
    """A query could not be carried; the message says why in plain words.
    ``retry`` is False when trying again cannot help: a certificate problem, an
    HTTP error."""

    def __init__(self, message: str, *, retry: bool = True) -> None:
        super().__init__(message)
        self.retry = retry


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_doh_url(url: str) -> tuple[str, str, int, str]:
    """``https://dns.google/dns-query`` as ``("https", "dns.google", 443,
    "/dns-query")``.  The RFC 8484 template suffix ``{?dns}`` is accepted and
    dropped: the query goes in a POST body."""
    text = re.sub(r"\{\?dns\}$", "", url.strip())
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise ValueError(f"{url!r} is not a DNS-over-HTTPS URL (https://host/path)")
    if not parts.hostname:
        raise ValueError(f"{url!r} has no host")
    if parts.query or parts.fragment:
        raise ValueError(f"{url!r}: leave the query string out; the tool sends the query itself")
    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError:
        raise ValueError(f"{url!r} has an invalid port") from None
    return scheme, parts.hostname, port, parts.path or "/dns-query"


@dataclass(frozen=True)
class Endpoint:
    """Where a DNS service listens and how to talk to it."""

    server: str
    port: int = 53
    transport: str = "udp"
    #: The name the certificate is checked against, sent as SNI and as the DoH
    #: ``Host``.  Empty means ``server``.
    tls_name: str = ""
    path: str = "/dns-query"
    verify: bool = True
    ca_file: str = ""

    def __post_init__(self) -> None:
        if self.transport not in TRANSPORTS:
            raise ValueError(f"unknown transport {self.transport!r}; choose from {', '.join(TRANSPORTS)}")

    @classmethod
    def from_config(cls, config) -> "Endpoint":
        """The endpoint a :class:`~dnsloadforge.spec.RunConfig` is aimed at."""
        return cls(
            server=config.server,
            port=config.port,
            transport=config.transport,
            tls_name=config.tls_name,
            path=config.doh_path,
            verify=config.tls_verify,
            ca_file=config.ca_file,
        )

    @property
    def host_name(self) -> str:
        return self.tls_name or self.server

    @property
    def encrypted(self) -> bool:
        return self.transport in ("tls", "https")

    @property
    def label(self) -> str:
        return endpoint_label(self.transport, self.server, self.port, self.tls_name, self.path)

    def ssl_context(self) -> ssl.SSLContext | None:
        """TLS 1.2 or later (RFC 8310), the system's roots or ``ca_file``, and
        HTTP/1.1 offered by ALPN for DoH.  ``None`` for the plain transports."""
        if not self.encrypted:
            return None
        try:
            context = ssl.create_default_context(cafile=self.ca_file or None)
        except (OSError, ssl.SSLError) as exc:
            raise TransportError(f"cannot read the CA file {self.ca_file}: {exc}", retry=False) from exc
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if not self.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if self.transport == "https":
            context.set_alpn_protocols(["http/1.1"])
        return context


def describe_error(endpoint: Endpoint, exc: BaseException | None) -> str:
    """A failure to reach ``endpoint``, in words an operator can act on."""
    if exc is None:
        return f"no connection to {endpoint.label} could be opened"
    if isinstance(exc, TransportError):
        return str(exc)
    where = f"{endpoint.server}:{endpoint.port}"
    name = endpoint.host_name
    if isinstance(exc, ssl.SSLCertVerificationError):
        message = (exc.verify_message or str(exc)).strip()
        if any(text in message for text in _ROOT_MISSING) and not endpoint.ca_file:
            hint = ""
            if sys.platform == "win32":
                hint = (
                    " Windows downloads root certificates the first time something needs one, and Python only "
                    f"sees those already downloaded: open https://{name}/ once in a browser, then try again."
                )
            return (
                f"the certificate of {name} does not lead to a root this machine trusts ({message}).{hint} "
                "For an appliance with its own CA, pass --ca-file; --insecure skips the check."
            )
        if "self-signed certificate" in message or "self signed certificate" in message:
            return f"{name} presented a self-signed certificate: pass it with --ca-file, or --insecure to skip the check"
        if "mismatch" in message:
            return f"the certificate is not issued for {name} ({message}); give the name it carries with --tls-name"
        if "expired" in message:
            return f"the certificate of {name} has expired"
        return f"the certificate of {name} failed verification: {message}"
    if isinstance(exc, ssl.SSLError):
        reason = getattr(exc, "reason", None) or str(exc)
        return (
            f"the TLS handshake with {where} failed ({reason}): is port {endpoint.port} really "
            f"{TRANSPORT_LABELS.get(endpoint.transport, endpoint.transport)}?"
        )
    if isinstance(exc, (TimeoutError, socket.timeout, asyncio.TimeoutError)):
        return f"{where} did not answer in time (a firewall may be dropping port {endpoint.port})"
    if isinstance(exc, ConnectionRefusedError):
        return f"nothing is listening on {where}"
    if isinstance(exc, ConnectionResetError):
        return f"{where} reset the connection"
    if isinstance(exc, socket.gaierror):
        return f"cannot resolve {endpoint.server}"
    if isinstance(exc, OSError):
        return f"{where}: {exc.strerror or exc}"
    return f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# HTTP/1.1, just enough of it for DoH
# ---------------------------------------------------------------------------


def http_request_head(endpoint: Endpoint) -> bytes:
    """A DoH POST up to its length, which is the only part that changes."""
    host = endpoint.host_name
    shown = f"[{host}]" if ":" in host else host
    if endpoint.port != DEFAULT_PORTS[endpoint.transport]:
        shown += f":{endpoint.port}"
    return (
        f"POST {endpoint.path} HTTP/1.1\r\n"
        f"Host: {shown}\r\n"
        f"User-Agent: DNS-Load-Forge/{__version__}\r\n"
        "Accept: application/dns-message\r\n"
        "Content-Type: application/dns-message\r\n"
        "Content-Length: "
    ).encode("ascii")


def http_request(head: bytes, query: bytes) -> bytes:
    return head + str(len(query)).encode("ascii") + b"\r\n\r\n" + query


@dataclass
class HttpResponse:
    status: int
    reason: str
    #: Header names in lower case; repeated headers joined with ", ".
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def keep_alive(self) -> bool:
        return "close" not in self.headers.get("connection", "").lower()


def http_problem(response: HttpResponse) -> str:
    """Why an HTTP response is not a DNS answer, or "" when it is one."""
    if response.status == 200:
        kind = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if kind != "application/dns-message":
            return f"the server answered with {kind or 'no content type'}, not a DNS message: check the URL"
        if len(response.body) < 12:
            return "the server answered with an empty DNS message"
        return ""
    if response.status == 505:
        return (
            "HTTP 505: the server only speaks HTTP/2, and this tool speaks HTTP/1.1 "
            "(test the service over DNS over TLS if it offers it)"
        )
    if response.status == 404:
        return "HTTP 404: there is no DoH endpoint at this path; check the URL"
    if response.status in (400, 415):
        return f"HTTP {response.status}: the server rejected the query; check the URL path"
    if response.status in (301, 302, 303, 307, 308):
        location = response.headers.get("location", "")
        return f"HTTP {response.status}: the server redirects to {location or 'another URL'}; use that URL"
    if response.status == 429:
        return "HTTP 429: the server is rate-limiting this client"
    return f"HTTP {response.status} {response.reason}".strip()


class HttpResponseParser:
    """HTTP/1.1 responses read from a byte stream as it arrives: bodies by
    Content-Length or chunked, several responses in one read, one response split
    across any number of reads."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._head: tuple[int, str, dict[str, str]] | None = None
        self._mode = ""
        self._length = 0
        self._chunk: int | None = None
        self._body = bytearray()

    def feed(self, data: bytes) -> list[HttpResponse]:
        self._buffer += data
        responses: list[HttpResponse] = []
        while True:
            response = self._step()
            if response is None:
                return responses
            responses.append(response)

    def eof(self) -> HttpResponse | None:
        """The connection closed: a body that runs to the close is complete now."""
        if self._head is not None and self._mode == "close":
            self._body += self._buffer
            self._buffer.clear()
            return self._done()
        return None

    def _step(self) -> HttpResponse | None:
        buffer = self._buffer
        while self._head is None:
            end = buffer.find(b"\r\n\r\n")
            if end < 0:
                if len(buffer) > _MAX_HEAD:
                    raise TransportError("the server sent an oversized HTTP header", retry=False)
                return None
            lines = bytes(buffer[:end]).decode("latin-1").split("\r\n")
            del buffer[: end + 4]
            version, _, rest = lines[0].partition(" ")
            code, _, reason = rest.partition(" ")
            if not version.startswith("HTTP/1.") or not code.isdigit():
                raise TransportError(f"the server did not answer in HTTP/1.1 ({lines[0][:60]!r})", retry=False)
            status = int(code)
            if 100 <= status < 200:
                continue  # informational: the real response follows
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, sep, value = line.partition(":")
                if sep:
                    key = name.strip().lower()
                    headers[key] = f"{headers[key]}, {value.strip()}" if key in headers else value.strip()
            self._head = (status, reason.strip(), headers)
            self._body = bytearray()
            self._chunk = None
            if "chunked" in headers.get("transfer-encoding", "").lower():
                self._mode = "chunked"
            elif "content-length" in headers:
                try:
                    self._length = int(headers["content-length"])
                except ValueError:
                    raise TransportError("the server sent a malformed Content-Length", retry=False) from None
                if not 0 <= self._length <= _MAX_BODY:
                    raise TransportError("the server sent an oversized answer", retry=False)
                self._mode = "length"
            elif status in (204, 304):
                self._mode = "empty"
            else:
                self._mode = "close"
        if self._mode == "empty":
            return self._done()
        if self._mode == "length":
            if len(buffer) < self._length:
                return None
            self._body = bytearray(buffer[: self._length])
            del buffer[: self._length]
            return self._done()
        if self._mode == "chunked":
            return self._chunked()
        if len(buffer) > _MAX_BODY:
            raise TransportError("the server sent an oversized answer", retry=False)
        return None  # the body runs to the end of the connection: see eof()

    def _chunked(self) -> HttpResponse | None:
        buffer = self._buffer
        while True:
            if self._chunk is None:
                end = buffer.find(b"\r\n")
                if end < 0:
                    return None
                size_text = bytes(buffer[:end]).split(b";", 1)[0].strip()
                del buffer[: end + 2]
                try:
                    size = int(size_text, 16)
                except ValueError:
                    raise TransportError("the server sent a malformed chunked body", retry=False) from None
                self._chunk = size if size else -1
            if self._chunk == -1:
                # Trailers, if any, then the blank line that ends the body.
                end = buffer.find(b"\r\n")
                if end < 0:
                    return None
                line = bytes(buffer[:end])
                del buffer[: end + 2]
                if not line:
                    return self._done()
                continue
            if len(buffer) < self._chunk + 2:
                return None
            self._body += buffer[: self._chunk]
            del buffer[: self._chunk + 2]
            self._chunk = None
            if len(self._body) > _MAX_BODY:
                raise TransportError("the server sent an oversized answer", retry=False)

    def _done(self) -> HttpResponse:
        assert self._head is not None
        status, reason, headers = self._head
        self._head = None
        body = bytes(self._body)
        self._body = bytearray()
        return HttpResponse(status, reason, headers, body)


# ---------------------------------------------------------------------------
# one query at a time: preflight probes and the deployment checks
# ---------------------------------------------------------------------------


def _connect(endpoint: Endpoint, timeout: float) -> socket.socket:
    sock = socket.create_connection((endpoint.server, endpoint.port), timeout=timeout)
    try:
        context = endpoint.ssl_context()
        if context is None:
            return sock
        return context.wrap_socket(sock, server_hostname=endpoint.host_name)
    except BaseException:
        sock.close()
        raise


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise TransportError("the server closed the connection before answering")
        data += chunk
    return bytes(data)


def _exchange_udp(endpoint: Endpoint, query: bytes, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in endpoint.server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((endpoint.server, endpoint.port))
        sock.send(query)
        deadline = time.monotonic() + timeout
        while True:
            data = sock.recv(65535)
            if data[:2] == query[:2]:
                return data
            if time.monotonic() > deadline:
                raise TimeoutError


def _exchange_http(sock: socket.socket, endpoint: Endpoint, query: bytes) -> bytes:
    sock.sendall(http_request(http_request_head(endpoint), query))
    parser = HttpResponseParser()
    while True:
        chunk = sock.recv(65535)
        if chunk:
            responses = parser.feed(chunk)
        else:
            last = parser.eof()
            if last is None:
                raise TransportError("the server closed the connection before answering")
            responses = [last]
        if responses:
            response = responses[0]
            problem = http_problem(response)
            if problem:
                raise TransportError(problem, retry=response.status >= 500 and response.status != 505)
            return response.body


def exchange(endpoint: Endpoint, query: bytes, timeout: float = 2.0) -> bytes:
    """Send one query and return the answer's bytes, or raise
    :class:`TransportError` saying why there is none.  Over UDP an answer with
    another ID is skipped, as a resolver library would; each of the others opens
    a connection for this one query."""
    try:
        if endpoint.transport == "udp":
            return _exchange_udp(endpoint, query, timeout)
        with _connect(endpoint, timeout) as sock:
            if endpoint.transport in ("tcp", "tls"):
                sock.sendall(struct.pack("!H", len(query)) + query)
                (length,) = struct.unpack("!H", _recv_exact(sock, 2))
                return _recv_exact(sock, length)
            return _exchange_http(sock, endpoint, query)
    except TransportError:
        raise
    except OSError as exc:
        raise TransportError(describe_error(endpoint, exc), retry=not isinstance(exc, ssl.SSLError)) from exc


def probe(endpoint: Endpoint, *, timeout: float = 1.5, attempts: int = 2) -> tuple[bool, str]:
    """Ask ``endpoint`` for example.com: ``(True, "")`` when a DNS answer came
    back, else ``(False, why)``.  A UDP send succeeds whether or not anything is
    listening, so asking a question is the only honest readiness test."""
    reason = ""
    for _ in range(max(1, attempts)):
        query, _qid = encode_query("example.com", "A")
        try:
            decode_message(exchange(endpoint, query, timeout))
            return True, ""
        except TransportError as exc:
            reason = str(exc)
            if not exc.retry:
                break
        except DNSError as exc:
            return False, f"the answer was not a DNS message ({exc})"
    return False, reason


# ---------------------------------------------------------------------------
# a run's traffic: connection pools in the place of the engine's UDP socket
# ---------------------------------------------------------------------------


class QueryIds:
    """Transaction IDs for one path to the target.  They only need to be unique
    among the queries outstanding on that path, which is what ``pending`` holds."""

    pending: dict
    next_qid: int

    def alloc_qid(self) -> int:
        for _ in range(0xFFFF):
            qid = self.next_qid
            self.next_qid = 1 if qid >= 0xFFFF else qid + 1
            if qid not in self.pending:
                return qid
        raise RuntimeError("transaction ID space exhausted: too many queries in flight on one path to the target")

    def room(self) -> int:
        """How many more queries this path can take right now."""
        return UNLIMITED

    def saturated(self, count: int) -> None:
        """``count`` queries were dropped because :meth:`room` ran out."""


def pool_size(config, channels: int = 1, shard_count: int = 1, burst: int = 24) -> tuple[int, int]:
    """``(size, grow_to)`` for each of a shard's channels.

    ``config.connections`` fixes the pool.  Otherwise TCP and DoT, which pipeline,
    use a few connections.  DoH carries one request per connection at a time, and
    a page load fires up to ``burst`` lookups at once (the engine's MAX_BURST), so
    its pool starts with room for a whole burst, or a fifth of a second of queries
    when that is more, and grows when it runs short.  A pool of four dropped a
    third of a 20-qps run against real DoH services, all of it in bursts.
    """
    channels = max(1, channels)
    if config.connections > 0:
        size = max(1, config.connections // channels)
        return size, size
    if config.transport in ("tcp", "tls"):
        size = max(1, DEFAULT_STREAM_CONNECTIONS // channels)
        return size, size
    rate = config.target_qps / max(1, shard_count)
    size = max(1, min(64, max(burst, math.ceil(rate * 0.2))) // channels)
    return size, max(size, MAX_HTTP_CONNECTIONS // channels)


class _Channel(QueryIds):
    """A pool of connections to one endpoint, from one source address."""

    #: How often the pool is looked after: reconnects, connections that went quiet.
    TICK_S = 0.25

    def __init__(
        self,
        engine,
        endpoint: Endpoint,
        index: int,
        source_ip: str = "",
        *,
        size: int = 1,
        grow_to: int = 0,
        timeout: float = 2.0,
    ) -> None:
        self.engine = engine
        self.endpoint = endpoint
        self.index = index
        self.source_ip = source_ip
        self.pending: dict = {}
        self.next_qid = 1
        self.size = max(1, size)
        self.grow_to = max(self.size, grow_to)
        self.timeout = timeout
        #: The engine sends with ``protocol.transport.sendto``; the pool is its own
        #: transport, and ``transport.close()`` closes the pool.
        self.transport: _Channel | None = self
        self.connections: list = []
        self.last_error = ""
        #: Queries already re-sent once after a connection closed under them.
        self._retried: set[int] = set()
        self._connecting = 0
        self._closing = False
        self._failures = 0
        self._retry_at = 0.0
        self._tasks: set[asyncio.Task] = set()
        self._context = endpoint.ssl_context()
        self._connect_timeout = max(2.0, min(10.0, timeout * 2.5))

    # -- opening ----------------------------------------------------------

    def _new_connection(self) -> asyncio.Protocol:
        raise NotImplementedError

    async def open(self) -> None:
        """Open the pool before the first query.  Raises :class:`TransportError`,
        with the reason, when not one connection can be made."""
        results = await asyncio.gather(*(self._open_one() for _ in range(self.size)), return_exceptions=True)
        if not self.connections:
            error = next((r for r in results if isinstance(r, BaseException)), None)
            raise TransportError(describe_error(self.endpoint, error), retry=False)
        self._spawn(self._maintain())

    async def _open_one(self) -> None:
        loop = asyncio.get_running_loop()
        tls = self._context is not None
        self._connecting += 1
        try:
            await asyncio.wait_for(
                loop.create_connection(
                    self._new_connection,
                    self.endpoint.server,
                    self.endpoint.port,
                    ssl=self._context,
                    server_hostname=self.endpoint.host_name if tls else None,
                    ssl_handshake_timeout=self._connect_timeout if tls else None,
                    local_addr=(self.source_ip, 0) if self.source_ip else None,
                ),
                timeout=self._connect_timeout + 1.0,
            )
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            self._failures += 1
            self._retry_at = time.monotonic() + min(2.0, 0.1 * 2 ** min(self._failures, 5))
            self.last_error = describe_error(self.endpoint, exc)
            self.engine.stats.on_connection(failed=1, error=self.last_error)
            raise
        finally:
            self._connecting -= 1
        self._failures = 0

    async def _reopen(self) -> None:
        if self._closing or len(self.connections) + self._connecting >= self.size:
            return
        try:
            await self._open_one()
        except asyncio.CancelledError:
            raise
        except BaseException:  # noqa: BLE001 - counted in _open_one; the maintainer tries again
            pass

    def _spawn(self, coro) -> None:
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _maintain(self) -> None:
        while not self._closing:
            await asyncio.sleep(self.TICK_S)
            now = time.monotonic()
            self._retried.intersection_update(self.pending)
            self._tend(now)
            missing = self.size - len(self.connections) - self._connecting
            if missing > 0 and now >= self._retry_at:
                for _ in range(min(missing, 4)):
                    self._spawn(self._reopen())

    # -- connection events ------------------------------------------------

    def _opened(self, connection) -> None:
        self.connections.append(connection)
        self.engine.stats.on_connection(opened=1)
        if self._closing:
            connection.transport.abort()

    def _lost(self, connection, exc: BaseException | None) -> None:
        """A connection closed.

        Servers close connections as a matter of course -- an idle timeout, a
        recycle after so many queries, ``Connection: close`` -- and a resolver
        library re-sends what was waiting on one, so each unanswered query is sent
        again once, on another connection, and its latency keeps counting from the
        first send.  Only a query that cannot be re-sent fails, and only a close
        that cost queries, or came with an error, counts as a lost connection.
        When the run is ending, whatever is left is the engine's to time out.
        """
        if connection in self.connections:
            self.connections.remove(connection)
        stranded = self._stranded(connection)
        if self._closing:
            self.engine.stats.on_connection(closed=1)
            return
        failed: list[int] = []
        resent = 0
        for qid, packet in stranded:
            if qid not in self.pending:
                continue  # already timed out
            if qid in self._retried or not self._resend(packet):
                failed.append(qid)
            else:
                self._retried.add(qid)
                resent += 1
        if exc is None and not connection.problem and not failed:
            self.engine.stats.on_connection(closed=1, retried=resent)
            # Replace it now rather than at the next tick, so the pool does not run short.
            self._spawn(self._reopen())
        else:
            reason = connection.problem or (
                "the server closed a connection with queries unanswered" if exc is None else describe_error(self.endpoint, exc)
            )
            self.last_error = reason
            self.engine.stats.on_connection(closed=1, lost=1, retried=resent, error=reason)
        if failed:
            self.engine._fail_queries(self, failed)

    def _resend(self, packet: bytes) -> bool:
        try:
            self.sendto(packet)
        except TransportError:
            return False
        return True

    def sendto(self, packet: bytes) -> None:
        raise NotImplementedError

    def _stranded(self, connection) -> list[tuple[int, bytes]]:
        """The queries waiting on ``connection`` (ID and packet), forgotten here."""
        raise NotImplementedError

    def _tend(self, now: float) -> None:
        """Periodic upkeep, between reconnects."""

    def _down_reason(self) -> str:
        if self.connections:
            return "every connection to the server is busy"
        detail = f": {self.last_error}" if self.last_error else ""
        return f"no open connection to {self.endpoint.label}{detail}"

    # -- closing ----------------------------------------------------------

    def close(self) -> None:
        """Close every connection.  Called when the run ends."""
        if self._closing:
            return
        self._closing = True
        for task in list(self._tasks):
            task.cancel()
        for connection in list(self.connections):
            if connection.transport is not None:
                connection.transport.close()

    async def wait_closed(self, timeout: float = 1.0) -> None:
        """Give the closes a moment to finish politely, then cut what is left."""
        deadline = time.monotonic() + timeout
        while self.connections and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        for connection in list(self.connections):
            if connection.transport is not None:
                connection.transport.abort()
        await asyncio.sleep(0)


class _StreamConnection(asyncio.Protocol):
    """One TCP or TLS connection carrying length-prefixed DNS messages."""

    def __init__(self, channel: "StreamChannel") -> None:
        self.channel = channel
        self.transport: asyncio.Transport | None = None
        self.buffer = bytearray()
        #: Queries sent on this connection and not yet answered (or timed out).
        self.inflight = 0
        #: When this connection last made progress while queries were waiting.
        self.waiting_since = 0.0
        self.paused = False
        self.problem = ""

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport
        self.channel._opened(self)

    def data_received(self, data: bytes) -> None:
        buffer = self.buffer
        buffer += data
        while len(buffer) >= 2:
            length = (buffer[0] << 8) | buffer[1]
            if len(buffer) < 2 + length:
                break
            message = bytes(buffer[2 : 2 + length])
            del buffer[: 2 + length]
            self.channel._message(self, message)

    def eof_received(self) -> bool:
        return False  # close our side as well

    def pause_writing(self) -> None:
        self.paused = True

    def resume_writing(self) -> None:
        self.paused = False

    def connection_lost(self, exc: Exception | None) -> None:
        self.transport = None
        self.channel._lost(self, exc)


class StreamChannel(_Channel):
    """TCP or DNS over TLS: queries pipelined on every connection and answers
    matched by ID, since a server answers in whatever order it finishes."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        #: Each unanswered query's connection, and its packet in case it must be re-sent.
        self._where: dict[int, tuple[_StreamConnection, bytes]] = {}
        self._turn = 0

    def _new_connection(self) -> asyncio.Protocol:
        return _StreamConnection(self)

    def room(self) -> int:
        # With nothing open, sending fails -- and says why -- rather than dropping.
        if not self.connections or any(not c.paused for c in self.connections):
            return UNLIMITED
        return 0

    def saturated(self, count: int) -> None:
        self.engine.stats.on_connection(busy_drops=count)

    def sendto(self, packet: bytes) -> None:
        # A transport is "closing" from the moment a send fails until its
        # connection_lost arrives; writing to it then only makes asyncio complain.
        live = [c for c in self.connections if c.transport is not None and not c.transport.is_closing() and not c.paused]
        if not live:
            raise TransportError(self._down_reason())
        self._turn = (self._turn + 1) % len(live)
        connection = live[self._turn]
        qid = (packet[0] << 8) | packet[1]
        previous = self._where.get(qid)
        if previous is not None:  # an ID reused after its query timed out
            previous[0].inflight = max(0, previous[0].inflight - 1)
        self._where[qid] = (connection, packet)
        if connection.inflight == 0:
            connection.waiting_since = time.monotonic()
        connection.inflight += 1
        connection.transport.write(struct.pack("!H", len(packet)) + packet)

    def _message(self, connection: _StreamConnection, message: bytes) -> None:
        if len(message) >= 2:
            qid = (message[0] << 8) | message[1]
            entry = self._where.get(qid)
            if entry is not None and entry[0] is connection:
                del self._where[qid]
                connection.inflight = max(0, connection.inflight - 1)
        connection.waiting_since = time.monotonic()
        self.engine._handle_response(self, message)

    def _stranded(self, connection) -> list[tuple[int, bytes]]:
        stranded = [(qid, packet) for qid, (owner, packet) in self._where.items() if owner is connection]
        for qid, _packet in stranded:
            del self._where[qid]
        return stranded

    def _tend(self, now: float) -> None:
        # Forget the queries the engine has already timed out.
        for qid in [qid for qid in self._where if qid not in self.pending]:
            owner, _packet = self._where.pop(qid)
            owner.inflight = max(0, owner.inflight - 1)
        # A connection that stopped answering keeps swallowing its share of the
        # traffic; replace it, and say so.
        limit = max(2.0 * self.timeout, 2.0)
        for connection in list(self.connections):
            if connection.inflight and now - connection.waiting_since > limit and connection.transport is not None:
                connection.problem = f"a connection gave no answers for {limit:g}s and was replaced"
                connection.transport.abort()


class _HttpConnection(asyncio.Protocol):
    """One HTTP/1.1 connection with at most one DoH request on it."""

    def __init__(self, channel: "HttpChannel") -> None:
        self.channel = channel
        self.transport: asyncio.Transport | None = None
        self.parser = HttpResponseParser()
        #: The ID of the query awaiting its response, if any, and its packet.
        self.qid: int | None = None
        self.packet = b""
        self.sent_at = 0.0
        self.problem = ""

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport
        self.channel._opened(self)

    def data_received(self, data: bytes) -> None:
        try:
            responses = self.parser.feed(data)
        except TransportError as exc:
            self.problem = str(exc)
            if self.transport is not None:
                self.transport.abort()
            return
        for response in responses:
            self.channel._response(self, response)

    def eof_received(self) -> bool:
        try:
            response = self.parser.eof()
        except TransportError as exc:
            self.problem, response = str(exc), None
        if response is not None:
            self.channel._response(self, response)
        return False

    def connection_lost(self, exc: Exception | None) -> None:
        self.transport = None
        self.channel._lost(self, exc)


class HttpChannel(_Channel):
    """DNS over HTTPS (RFC 8484): POSTs over HTTP/1.1 keep-alive connections, one
    request at a time on each."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._idle: deque[_HttpConnection] = deque()
        self._head = http_request_head(self.endpoint)

    def _new_connection(self) -> asyncio.Protocol:
        return _HttpConnection(self)

    def _opened(self, connection) -> None:
        super()._opened(connection)
        if not self._closing:
            self._idle.append(connection)

    def room(self) -> int:
        if not self.connections:
            return UNLIMITED  # sending fails, and says why
        return len(self._idle)

    def saturated(self, count: int) -> None:
        self.engine.stats.on_connection(busy_drops=count)
        if self.size < self.grow_to:
            self.size += 1
            if self._connecting < 4:
                self._spawn(self._reopen())

    def sendto(self, packet: bytes) -> None:
        connection = None
        while self._idle:
            candidate = self._idle.popleft()
            if candidate.transport is not None and not candidate.transport.is_closing() and candidate.qid is None:
                connection = candidate
                break
        if connection is None:
            raise TransportError(self._down_reason())
        connection.qid = (packet[0] << 8) | packet[1]
        connection.packet = packet
        connection.sent_at = time.monotonic()
        connection.transport.write(http_request(self._head, packet))

    def _response(self, connection: _HttpConnection, response: HttpResponse) -> None:
        qid, connection.qid = connection.qid, None
        if not response.keep_alive:
            # Retired by the server; the close is ours, and the pool replaces it.
            if connection.transport is not None:
                connection.transport.close()
        elif connection.transport is not None and not self._closing:
            self._idle.append(connection)
        if qid is None:
            return  # nothing was asked on this connection (an error page before a close)
        problem = http_problem(response)
        if problem:
            self.last_error = problem
            self.engine.stats.on_connection(error=problem)
            self.engine._fail_queries(self, [qid])
            return
        # HTTP/1.1 answers in order, so this is the answer to ``qid`` whatever ID
        # the server wrote in it (RFC 8484 lets a client send ID 0; some echo it).
        body = bytearray(response.body)
        body[0], body[1] = qid >> 8, qid & 0xFF
        self.engine._handle_response(self, bytes(body))

    def _stranded(self, connection) -> list[tuple[int, bytes]]:
        try:
            self._idle.remove(connection)
        except ValueError:
            pass
        qid, connection.qid = connection.qid, None
        return [(qid, connection.packet)] if qid is not None else []

    def _tend(self, now: float) -> None:
        limit = max(2.0 * self.timeout, 2.0)
        for connection in list(self.connections):
            if connection.qid is not None and now - connection.sent_at > limit and connection.transport is not None:
                connection.problem = f"a request went unanswered for {limit:g}s; its connection was replaced"
                connection.transport.abort()


def make_channel(
    engine, config, index: int, source_ip: str = "", *, channels: int = 1, shard_count: int = 1, burst: int = 24
) -> _Channel:
    """The connection pool that carries ``config``'s traffic from ``source_ip``."""
    endpoint = Endpoint.from_config(config)
    size, grow_to = pool_size(config, channels, shard_count, burst)
    kind = HttpChannel if config.transport in ("https", "http") else StreamChannel
    return kind(engine, endpoint, index, source_ip, size=size, grow_to=grow_to, timeout=config.timeout_s)
