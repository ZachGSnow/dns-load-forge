"""Deployment checks: is the filter where it should be, and can it be gone around?

The load test answers "does it block the right names, at volume".  These checks
answer the questions that come before it, each with a handful of single queries:

* **Resolver** -- which resolver answers, and through which upstream it reaches
  the internet (NSID, the whoami services, the AS that owns the egress address).
* **This network** -- is DNS intercepted on the path, and can a client go around
  the filter with a public resolver, plain or encrypted?
* **Encrypted DNS** -- does the filter switch off the escape hatches it can: the
  Firefox canary, iCloud Private Relay, the DDR designation (RFC 9462)?
* **Security** -- DNSSEC validation, DNS rebinding protection.
* **Content controls** -- SafeSearch and YouTube Restricted Mode enforcement.
* **Policy** -- the vendors' own test domains, and whether a name blocked for A is
  also blocked for AAAA, HTTPS, TXT and MX.

Every result carries its evidence -- the queries and what came back -- so a report
can show its working.  A full run sends a few dozen packets.  The expected answers
were checked against live resolvers on 2026-11-26; vendors change them, which is why
the evidence is always shown.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from . import packets as pk

__all__ = [
    "CHECKS",
    "CheckContext",
    "CheckResult",
    "Exchange",
    "STATUSES",
    "ask",
    "block_reason",
    "run_checks",
    "summarise",
    "tcp_reachable",
]

#: Worst first: the order results are summarised in.
STATUSES: tuple[str, ...] = ("fail", "warn", "error", "pass", "info", "skip")

#: Answers that mean "blocked" whoever the target is: null routes and the public
#: filters' documented block pages.  Umbrella's test names resolve to 146.112.59.12
#: on an unfiltered resolver, inside the same network as its block pages, so only
#: the exact block-page addresses count, never the whole range.
KNOWN_BLOCK_ADDRESSES: frozenset[str] = frozenset(
    {
        "0.0.0.0",
        "::",
        "127.0.0.1",
        "::1",
        # Cisco Umbrella / OpenDNS block pages.
        *(f"146.112.61.{n}" for n in (104, 105, 106, 107, 108, 110)),
        *(f"::ffff:146.112.61.{n}" for n in (104, 105, 106, 107, 108, 110)),
        # Cloudflare Gateway block page.
        "162.159.36.12",
        "162.159.46.12",
        # DNSFilter block pages.
        *(f"45.54.28.{n}" for n in range(9, 19)),
        # AdGuard Family block page.
        "94.140.14.35",
    }
)


@dataclass
class Exchange:
    """One query and what came back, kept as evidence."""

    server: str
    port: int
    qname: str
    qtype: str
    qclass: str = "IN"
    rcode: str = ""
    addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    txt: list[list[str]] = field(default_factory=list)
    svcb: list[dict] = field(default_factory=list)
    other: int = 0
    ede: list[tuple[int, str]] = field(default_factory=list)
    nsid: str = ""
    ad: bool = False
    latency_ms: float = 0.0
    error: str = ""

    @property
    def answered(self) -> bool:
        return not self.error

    @property
    def policy_ede(self) -> int | None:
        return next((code for code, _ in self.ede if code in pk.EDE_POLICY_CODES), None)

    @property
    def has_data(self) -> bool:
        return bool(self.addresses or self.cnames or self.txt or self.svcb or self.other)

    def answer_text(self) -> str:
        """The answer, short enough for a table cell."""
        if self.error:
            return self.error
        parts = list(self.addresses[:4])
        parts += [f"CNAME {name}" for name in self.cnames[:1]]
        parts += [" ".join(record) for record in self.txt[:2]]
        parts += [f"{s['priority']} {s['target']}" for s in self.svcb[:2]]
        if self.other and not parts:
            parts.append(f"{self.other} record(s)")
        return ", ".join(parts) or "(no records)"

    def as_dict(self) -> dict:
        return {
            "server": f"{self.server}:{self.port}" if self.port != 53 else self.server,
            "qname": self.qname,
            "qtype": self.qtype if self.qclass == "IN" else f"{self.qclass} {self.qtype}",
            "rcode": self.rcode or "-",
            "answer": self.answer_text(),
            "ede": ", ".join(pk.ede_label(code) + (f" ({text})" if text else "") for code, text in self.ede),
            "nsid": self.nsid,
            "ad": self.ad,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
        }


def _exchange(server: str, port: int, qname: str, qtype: str, qclass: int, msg: pk.DNSMessage, latency_ms: float) -> Exchange:
    cname_type = 5
    svcb_types = (64, 65)
    addresses = msg.answer_ips + msg.hint_ips
    return Exchange(
        server=server,
        port=port,
        qname=qname,
        qtype=qtype,
        qclass="CH" if qclass == pk.QCLASS_CH else "IN",
        rcode=msg.rcode_name,
        addresses=addresses,
        cnames=[a.ip for a in msg.answers if a.rtype == cname_type and a.ip],
        txt=msg.txt_records,
        svcb=[
            {"priority": a.svc_priority, "target": a.svc_target, "alpn": list(a.svc_alpn), "port": a.svc_port}
            for a in msg.answers
            if a.rtype in svcb_types
        ],
        other=sum(1 for a in msg.answers if a.rtype not in (1, 28, cname_type, 16, *svcb_types)),
        ede=list(msg.ede),
        nsid=msg.nsid_text,
        ad=msg.authenticated,
        latency_ms=latency_ms,
    )


def _ask_tcp(server: str, port: int, query: bytes, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.sendall(struct.pack("!H", len(query)) + query)
        header = b""
        while len(header) < 2:
            chunk = sock.recv(2 - len(header))
            if not chunk:
                raise OSError("connection closed")
            header += chunk
        (length,) = struct.unpack("!H", header)
        body = b""
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                raise OSError("connection closed")
            body += chunk
        return body


def ask(
    server: str,
    port: int,
    qname: str,
    qtype: str = "A",
    *,
    qclass: int = pk.QCLASS_IN,
    timeout: float = 2.0,
    nsid: bool = False,
    dnssec_ok: bool = False,
) -> Exchange:
    """One query over UDP, retried over TCP when the answer comes back truncated."""
    options = [(pk.EDNS_NSID, b"")] if nsid else []
    query, qid = pk.encode_query(qname, qtype, qclass=qclass, dnssec_ok=dnssec_ok, options=options)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    started = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((server, port))
            sock.send(query)
            deadline = time.monotonic() + timeout
            while True:
                message = pk.decode_message(sock.recv(65535))
                if message.qid == qid:
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError
        if message.truncated:
            message = pk.decode_message(_ask_tcp(server, port, query, timeout))
    except (TimeoutError, socket.timeout):
        return Exchange(server, port, qname, qtype, "CH" if qclass == pk.QCLASS_CH else "IN", error="no answer")
    except ConnectionRefusedError:
        return Exchange(server, port, qname, qtype, error="refused the connection")
    except OSError as exc:
        return Exchange(server, port, qname, qtype, error=f"unreachable ({exc.strerror or exc})")
    except pk.DNSError as exc:
        return Exchange(server, port, qname, qtype, error=f"malformed answer ({exc})")
    return _exchange(server, port, qname, qtype, qclass, message, (time.perf_counter() - started) * 1000.0)


def tcp_reachable(host: str, port: int, timeout: float = 1.5) -> tuple[bool, str]:
    """Can a TCP connection be opened?  Nothing is sent: this is all a DNS-over-HTTPS
    or DNS-over-TLS client needs to start going around the filter."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "connected"
    except (TimeoutError, socket.timeout):
        return False, "timed out"
    except OSError as exc:
        return False, exc.strerror or str(exc)


def block_reason(exchange: Exchange, sinkholes: Iterable[str] = ()) -> str:
    """How an answer says "blocked", or "" when it resolved (or did not answer)."""
    if exchange.error:
        return ""
    code = exchange.policy_ede
    if code is not None:
        return f"EDE {pk.ede_label(code)}"
    if exchange.rcode in ("NXDOMAIN", "REFUSED", "SERVFAIL"):
        return exchange.rcode
    known = KNOWN_BLOCK_ADDRESSES | set(sinkholes)
    if exchange.addresses and all(ip in known for ip in exchange.addresses):
        return f"block page {exchange.addresses[0]}"
    if not exchange.addresses and not exchange.cnames:
        return "no records"
    return ""


@dataclass
class CheckResult:
    id: str
    group: str
    title: str
    status: str
    summary: str
    detail: str = ""
    evidence: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "group": self.group,
            "title": self.title,
            "status": self.status,
            "summary": self.summary,
            "detail": self.detail,
            "evidence": self.evidence,
        }


Asker = Callable[..., Exchange]
Connector = Callable[[str, int, float], "tuple[bool, str]"]


@dataclass
class CheckContext:
    """The target under test and how to reach it, plus what the checks share."""

    server: str
    port: int = 53
    target_name: str = ""
    kind: str = "appliance"
    blocks: tuple[str, ...] = ()
    sinkholes: tuple[str, ...] = ()
    #: Block-listed names from the catalogue, for the cross-type check.
    samples: tuple[str, ...] = ()
    #: Run the checks about the network this machine sits on (interception,
    #: bypass).  They send a few packets to public resolvers.
    network: bool = True
    timeout: float = 2.0
    ask: Asker = ask
    connect: Connector = tcp_reachable
    #: Names the vendor check found blocked on A, for the cross-type check.
    blocked_names: list[str] = field(default_factory=list)

    def query(self, qname: str, qtype: str = "A", **kwargs) -> Exchange:
        return self.ask(self.server, self.port, qname, qtype, timeout=self.timeout, **kwargs)

    def query_many(self, items: Sequence[tuple[str, str]], **kwargs) -> list[Exchange]:
        with ThreadPoolExecutor(max_workers=8) as pool:
            return list(pool.map(lambda item: self.query(item[0], item[1], **kwargs), items))


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


def _txt_value(exchange: Exchange, key: str) -> str:
    for record in exchange.txt:
        if len(record) >= 2 and record[0].lower() == key:
            return record[1]
        if record and record[0].lower().startswith(key + " "):
            return record[0][len(key) + 1 :]
    return ""


def _asn_name(ctx: CheckContext, address: str) -> str:
    """The AS that owns an address, from Team Cymru's DNS interface."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ""
    if ip.is_private or ip.is_loopback:
        return "a private address"
    if ip.version == 4:
        name = ".".join(reversed(address.split("."))) + ".origin.asn.cymru.com"
    else:
        name = ".".join(reversed(ip.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
    origin = ctx.query(name, "TXT")
    text = "".join(origin.txt[0]) if origin.txt else ""
    asn = text.split("|")[0].strip().split(" ")[0] if text else ""
    if not asn.isdigit():
        return ""
    owner = ctx.query(f"AS{asn}.asn.cymru.com", "TXT")
    owner_text = "".join(owner.txt[0]) if owner.txt else ""
    label = owner_text.split("|")[-1].strip() if owner_text.count("|") >= 4 else ""
    return f"AS{asn} {label}".strip()


def check_identity(ctx: CheckContext) -> CheckResult:
    probe, akamai, google = ctx.query_many(
        [("example.com", "A"), ("whoami.ds.akahelp.net", "TXT"), ("o-o.myaddr.l.google.com", "TXT")], nsid=True
    )
    chaos = [ctx.query(name, "TXT", qclass=pk.QCLASS_CH) for name in ("id.server", "hostname.bind", "version.bind")]
    evidence = [e.as_dict() for e in (probe, akamai, google, *chaos)]
    if not any(e.answered for e in (probe, akamai, google)):
        return CheckResult(
            "identity", "Resolver", "Who answers", "error",
            f"{ctx.server}:{ctx.port} answered none of the identity queries.",
            "Check the address and port, and that this machine is allowed to query it.",
            evidence,
        )
    egress = _txt_value(akamai, "ns") or (google.txt[0][0] if google.txt and google.txt[0] else "")
    subnet = _txt_value(akamai, "ecs") or next(
        (" ".join(r[1:]) for r in google.txt if r and r[0].startswith("edns0-client-subnet")), ""
    )
    owner = _asn_name(ctx, egress) if egress else ""
    names = [e.nsid for e in (probe, akamai, google) if e.nsid] + [
        " ".join(e.txt[0]) for e in chaos if e.txt and e.txt[0]
    ]
    parts = []
    if names:
        parts.append(f"answers as {', '.join(dict.fromkeys(names))}")
    if egress:
        parts.append(f"reaches the internet from {egress}" + (f" ({owner})" if owner else ""))
    parts.append(f"passes your client subnet ({subnet}) upstream" if subnet else "passes no client subnet upstream")
    version = next((" ".join(e.txt[0]) for e in chaos if e.qname == "version.bind" and e.txt and e.txt[0]), "")
    if version:
        parts.append(f"reports its version as {version!r}")
    return CheckResult(
        "identity", "Resolver", "Who answers", "info",
        parts[0][0].upper() + "; ".join(parts)[1:] + ".",
        "Confirms which resolver handles the queries and which upstream it uses. A forwarded client subnet tells "
        "authoritative servers where your users are; a reported version tells attackers what to try.",
        evidence,
    )


# ---------------------------------------------------------------------------
# This network
# ---------------------------------------------------------------------------

#: Public resolvers, the query that makes each one name itself, and how to
#: recognise its answer.
_PUBLIC = (
    ("Google", "8.8.8.8", "example.com", "A", pk.QCLASS_IN, lambda e: e.nsid.startswith("gpdns-")),
    ("Cloudflare", "1.1.1.1", "whoami.cloudflare", "TXT", pk.QCLASS_CH, lambda e: bool(e.txt)),
    ("Quad9", "9.9.9.9", "id.server", "TXT", pk.QCLASS_CH, lambda e: bool(re.match(r"^res\d+\.", " ".join(e.txt[0]) if e.txt else ""))),
)


def check_interception(ctx: CheckContext) -> CheckResult:
    # 192.0.2.1 is TEST-NET-1 (RFC 5737): no DNS server lives there, so any answer
    # came from something on the path that grabs port 53.
    probe = ctx.ask("192.0.2.1", 53, "example.com", "A", timeout=1.5)
    if probe.answered:
        return CheckResult(
            "interception", "This network", "DNS interception", "fail",
            "Something on this network answered a query sent to 192.0.2.1, an address no DNS server uses: "
            "DNS here is intercepted.",
            "A transparent proxy or firewall rewrites DNS on this path, so what clients reach may not be the "
            "target under test. Find the device doing it before trusting any result.",
            [probe.as_dict()],
        )
    return CheckResult(
        "interception", "This network", "DNS interception", "pass",
        "Not intercepted: a query to 192.0.2.1 (an address no DNS server uses) went unanswered.",
        "", [probe.as_dict()],
    )


def check_plain_bypass(ctx: CheckContext) -> CheckResult:
    with ThreadPoolExecutor(max_workers=3) as pool:
        probes = list(
            pool.map(
                lambda item: ctx.ask(item[1], 53, item[2], item[3], qclass=item[4], timeout=1.5, nsid=True), _PUBLIC
            )
        )
    direct, redirected = [], []
    for (name, *_rest, is_them), probe in zip(_PUBLIC, probes):
        if probe.answered and is_them(probe):
            direct.append(name)
        elif probe.answered:
            redirected.append(name)
    evidence = [p.as_dict() for p in probes]
    if direct:
        return CheckResult(
            "plain-bypass", "This network", "Plain DNS bypass", "warn",
            f"{', '.join(direct)} answered directly on port 53: a client can skip the filter by changing its DNS server.",
            "Block outbound port 53 except to the filter, or redirect it there, so the filter cannot be bypassed.",
            evidence,
        )
    if redirected:
        return CheckResult(
            "plain-bypass", "This network", "Plain DNS bypass", "pass",
            f"Queries to {', '.join(redirected)} were answered by something else: port 53 is redirected.",
            "", evidence,
        )
    return CheckResult(
        "plain-bypass", "This network", "Plain DNS bypass", "pass",
        "Public resolvers did not answer on port 53: outbound DNS is blocked.", "", evidence,
    )


def check_encrypted_bypass(ctx: CheckContext) -> CheckResult:
    endpoints = [(host, port) for port in (443, 853) for host in ("1.1.1.1", "8.8.8.8", "9.9.9.9")]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda hp: ctx.connect(hp[0], hp[1], 1.5), endpoints))
    evidence = [
        {"server": f"{host}:{port}", "qname": "DoH" if port == 443 else "DoT", "qtype": "TCP", "rcode": "-",
         "answer": detail, "ede": "", "nsid": "", "ad": False, "latency_ms": 0.0, "error": "" if ok else detail}
        for (host, port), (ok, detail) in zip(endpoints, results)
    ]
    open_ = [f"{host}:{port}" for (host, port), (ok, _) in zip(endpoints, results) if ok]
    if open_:
        return CheckResult(
            "encrypted-bypass", "This network", "Encrypted DNS bypass", "warn",
            f"DNS over HTTPS or TLS to public resolvers is reachable ({', '.join(open_)}): browsers and apps can "
            "resolve around the filter.",
            "Block the well-known DoH/DoT endpoints at the firewall, or use a filter that also controls the browser. "
            "The canary checks below show what the filter itself does to discourage it.",
            evidence,
        )
    return CheckResult(
        "encrypted-bypass", "This network", "Encrypted DNS bypass", "pass",
        "Public DoH (443) and DoT (853) endpoints were not reachable.", "", evidence,
    )


# ---------------------------------------------------------------------------
# Encrypted DNS signals
# ---------------------------------------------------------------------------


def _negative(exchange: Exchange) -> bool:
    return exchange.answered and (exchange.rcode != "NOERROR" or not exchange.addresses)


def check_firefox_canary(ctx: CheckContext) -> CheckResult:
    probe = ctx.query("use-application-dns.net", "A")
    if not probe.answered:
        return CheckResult("firefox-canary", "Encrypted DNS", "Firefox canary", "error", "No answer.", "", [probe.as_dict()])
    if _negative(probe):
        return CheckResult(
            "firefox-canary", "Encrypted DNS", "Firefox canary", "pass",
            "use-application-dns.net does not resolve: Firefox will not turn on DNS over HTTPS by itself.",
            "", [probe.as_dict()],
        )
    return CheckResult(
        "firefox-canary", "Encrypted DNS", "Firefox canary", "warn",
        "use-application-dns.net resolves: Firefox may turn on DNS over HTTPS and bypass this filter.",
        "Answer NXDOMAIN for use-application-dns.net (most filters have a setting for it).", [probe.as_dict()],
    )


def check_private_relay(ctx: CheckContext) -> CheckResult:
    probes = ctx.query_many([("mask.icloud.com", "A"), ("mask-h2.icloud.com", "A")])
    evidence = [p.as_dict() for p in probes]
    if not all(p.answered for p in probes):
        return CheckResult("private-relay", "Encrypted DNS", "iCloud Private Relay", "error", "No answer.", "", evidence)
    off = [p.qname for p in probes if _negative(p) or block_reason(p, ctx.sinkholes)]
    if len(off) == len(probes):
        return CheckResult(
            "private-relay", "Encrypted DNS", "iCloud Private Relay", "pass",
            "mask.icloud.com and mask-h2.icloud.com are both blocked: Apple devices turn Private Relay off here.",
            "", evidence,
        )
    status = "warn"
    if off:
        summary = f"Only {off[0]} is blocked: Private Relay can still start through the other name."
    else:
        summary = "Both Private Relay names resolve: Safari on Apple devices can send its DNS around the filter."
    return CheckResult(
        "private-relay", "Encrypted DNS", "iCloud Private Relay", status, summary,
        "Answer NXDOMAIN (or no records) for both mask.icloud.com and mask-h2.icloud.com; Apple documents "
        "that a fast negative answer, not a timeout, is what turns Private Relay off.",
        evidence,
    )


def check_ddr(ctx: CheckContext) -> CheckResult:
    probe = ctx.query("_dns.resolver.arpa", "SVCB")
    if not probe.answered:
        return CheckResult("ddr", "Encrypted DNS", "Designated resolvers (DDR)", "error", "No answer.", "", [probe.as_dict()])
    if not probe.svcb:
        return CheckResult(
            "ddr", "Encrypted DNS", "Designated resolvers (DDR)", "info",
            "Designates no encrypted resolver: Windows 11 and Apple devices stay on plain DNS to it.",
            "", [probe.as_dict()],
        )
    names = []
    for record in probe.svcb:
        protocol = "DoT" if "dot" in record["alpn"] else ("DoQ" if "doq" in record["alpn"] else "DoH")
        names.append(f"{record['target']} ({protocol}{':' + str(record['port']) if record['port'] else ''})")
    return CheckResult(
        "ddr", "Encrypted DNS", "Designated resolvers (DDR)", "info",
        f"Designates {', '.join(dict.fromkeys(names))}: devices that support DDR upgrade to encrypted DNS with it.",
        "Check that the designated names belong to the filter: a forwarder that passes on an upstream's "
        "designation sends clients straight to that upstream, around the filter (RFC 9462).",
        [probe.as_dict()],
    )


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


def check_dnssec(ctx: CheckContext) -> CheckResult:
    broken, signed = ctx.query_many([("dnssec-failed.org", "A"), ("isc.org", "A")], dnssec_ok=True)
    evidence = [broken.as_dict(), signed.as_dict()]
    if not broken.answered:
        return CheckResult("dnssec", "Security", "DNSSEC validation", "error", "No answer.", "", evidence)
    if broken.rcode == "SERVFAIL" or (not broken.addresses and broken.rcode != "NOERROR"):
        detail = "A signed name was marked authenticated (AD)." if signed.ad else ""
        return CheckResult(
            "dnssec", "Security", "DNSSEC validation", "pass",
            "Validates DNSSEC: a deliberately broken zone (dnssec-failed.org) fails instead of resolving.",
            detail, evidence,
        )
    return CheckResult(
        "dnssec", "Security", "DNSSEC validation", "warn",
        "Does not validate DNSSEC: dnssec-failed.org, whose signatures are deliberately broken, resolved.",
        "Without validation a forged answer is accepted. Turn on validation in the filter or its upstream.",
        evidence,
    )


def _private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def check_rebinding(ctx: CheckContext) -> CheckResult:
    probes = ctx.query_many([("10.0.0.1.nip.io", "A"), ("192-168-1-1.sslip.io", "A"), ("localtest.me", "A")])
    evidence = [p.as_dict() for p in probes]
    leaking = [p.qname for p in probes if any(_private(ip) for ip in p.addresses)]
    if not any(p.answered for p in probes):
        return CheckResult("rebinding", "Security", "DNS rebinding protection", "error", "No answer.", "", evidence)
    if leaking:
        return CheckResult(
            "rebinding", "Security", "DNS rebinding protection", "info",
            f"Public names answer with private addresses ({', '.join(leaking)}): no DNS rebinding protection.",
            "Rebinding protection stops a web page from reaching devices on your LAN by name. Turning it on can "
            "break split-horizon DNS, so treat this as a decision, not a defect.",
            evidence,
        )
    return CheckResult(
        "rebinding", "Security", "DNS rebinding protection", "pass",
        "Public names that point at private addresses were stopped.", "", evidence,
    )


# ---------------------------------------------------------------------------
# Content controls
# ---------------------------------------------------------------------------

_SAFESEARCH = (
    ("Google", "www.google.com", ("forcesafesearch.google.com",)),
    ("YouTube", "www.youtube.com", ("restrict.youtube.com", "restrictmoderate.youtube.com")),
    ("Bing", "www.bing.com", ("strict.bing.com",)),
    ("DuckDuckGo", "duckduckgo.com", ("safe.duckduckgo.com",)),
)


def check_safesearch(ctx: CheckContext) -> CheckResult:
    names = [(name, "A") for _, user, targets in _SAFESEARCH for name in (user, *targets)]
    answers = dict(zip([n for n, _ in names], ctx.query_many(names)))
    enforced, not_enforced = [], []
    for engine, user, targets in _SAFESEARCH:
        seen = set(answers[user].addresses)
        allowed = set().union(*(answers[t].addresses for t in targets))
        via_cname = any(t in answers[user].cnames for t in targets)
        (enforced if (seen and seen <= allowed) or via_cname else not_enforced).append(engine)
    evidence = [answers[n].as_dict() for n, _ in names]
    family = "block_adult" in ctx.blocks
    status = "warn" if family and not_enforced else "info"
    if not enforced:
        summary = "No SafeSearch enforcement: search engines resolve to their normal addresses."
    elif not not_enforced:
        summary = "Enforced for Google, YouTube, Bing and DuckDuckGo."
    else:
        summary = f"Enforced for {', '.join(enforced)}; not for {', '.join(not_enforced)}."
    return CheckResult(
        "safesearch", "Content controls", "SafeSearch enforcement", status, summary,
        "A filter enforces SafeSearch by answering the search engine's name with its restricted address. "
        + ("This target is expected to block adult content, so a gap here is worth closing." if family else ""),
        evidence,
    )


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

#: The vendors' own test names, each blocked by that vendor's filters by design.
#: Checked live on 2026-11-26.  On an unfiltered resolver Umbrella's names resolve
#: to 146.112.59.12, Cloudflare's to its edge and Palo Alto's to a CNAME to
#: google.com, so a block here means that vendor's policy is applied.
VENDOR_TEST_NAMES: tuple[tuple[str, str, str], ...] = (
    ("Cisco Umbrella", "internetbadguys.com", "phishing"),
    ("Cisco Umbrella", "examplemalwaredomain.com", "malware"),
    ("Cisco Umbrella", "examplebotnetdomain.com", "botnet"),
    ("Cisco Umbrella", "exampleadultsite.com", "adult"),
    ("Cloudflare", "malware.testcategory.com", "malware"),
    ("Cloudflare", "phishing.testcategory.com", "phishing"),
    ("Cloudflare", "nudity.testcategory.com", "adult"),
    ("Quad9", "isitblocked.org", "malware"),
    ("Palo Alto Networks", "test-malware.testpanw.com", "malware"),
    ("Palo Alto Networks", "test-c2.testpanw.com", "command and control"),
)


def check_vendor_tests(ctx: CheckContext) -> CheckResult:
    probes = ctx.query_many([(name, "A") for _, name, _ in VENDOR_TEST_NAMES])
    rows, blocked_by = [], {}
    for (vendor, name, kind), probe in zip(VENDOR_TEST_NAMES, probes):
        reason = block_reason(probe, ctx.sinkholes)
        row = probe.as_dict()
        row["vendor"] = vendor
        row["kind"] = kind
        row["blocked"] = reason
        rows.append(row)
        if reason:
            blocked_by.setdefault(vendor, []).append(kind)
            ctx.blocked_names.append(name)
    if not any(p.answered for p in probes):
        return CheckResult("vendor-tests", "Policy", "Vendor test domains", "error", "No answer.", "", rows)
    total = sum(len(v) for v in blocked_by.values())
    if not total:
        summary = "None of the vendors' test names is blocked."
    else:
        summary = f"Blocked {total} of {len(VENDOR_TEST_NAMES)}: " + "; ".join(
            f"{vendor} ({', '.join(kinds)})" for vendor, kinds in blocked_by.items()
        ) + "."
    return CheckResult(
        "vendor-tests", "Policy", "Vendor test domains", "info", summary,
        "Each vendor publishes names its own filter always blocks, so they show whose policy is live. "
        "A filter is not expected to block another vendor's test names.",
        rows,
    )


def check_cross_type(ctx: CheckContext) -> CheckResult:
    candidates = list(dict.fromkeys([*ctx.blocked_names, *ctx.samples]))[:8]
    probes = ctx.query_many([(name, "A") for name in candidates]) if candidates else []
    names = [p.qname for p in probes if block_reason(p, ctx.sinkholes)][:4]
    if not names:
        return CheckResult(
            "cross-type", "Policy", "Blocked for every query type", "skip",
            "No name was blocked on A to test with.", "", [p.as_dict() for p in probes],
        )
    probes = ctx.query_many([(name, qtype) for name in names for qtype in ("AAAA", "HTTPS", "TXT", "MX")])
    evidence = [p.as_dict() for p in probes]
    known = KNOWN_BLOCK_ADDRESSES | set(ctx.sinkholes)
    address_leaks = sorted(
        {f"{p.qname} {p.qtype}" for p in probes
         if p.qtype in ("AAAA", "HTTPS") and not p.policy_ede and any(ip not in known for ip in p.addresses)}
    )
    data_leaks = sorted(
        {f"{p.qname} {p.qtype}" for p in probes
         if p.qtype in ("TXT", "MX") and not p.policy_ede and p.rcode == "NOERROR" and p.has_data}
    )
    if address_leaks:
        return CheckResult(
            "cross-type", "Policy", "Blocked for every query type", "fail",
            f"Blocked for A but answered with real addresses for {', '.join(address_leaks)}.",
            "A browser connects to AAAA and HTTPS-record addresses without asking for A, so these names are not "
            "really blocked.",
            evidence,
        )
    if data_leaks:
        return CheckResult(
            "cross-type", "Policy", "Blocked for every query type", "warn",
            f"Blocked for A but TXT or MX data came back for {', '.join(data_leaks)}.",
            "Answering other record types for a blocked name keeps it usable as a data channel, which is how "
            "malware tunnels out through DNS.",
            evidence,
        )
    return CheckResult(
        "cross-type", "Policy", "Blocked for every query type", "pass",
        f"{len(names)} name(s) blocked for A were also blocked for AAAA, HTTPS, TXT and MX.", "", evidence,
    )


#: In run order.  The vendor check feeds the cross-type check, so it runs first.
CHECKS: tuple[tuple[str, Callable[[CheckContext], CheckResult], bool], ...] = (
    ("identity", check_identity, False),
    ("interception", check_interception, True),
    ("plain-bypass", check_plain_bypass, True),
    ("encrypted-bypass", check_encrypted_bypass, True),
    ("firefox-canary", check_firefox_canary, False),
    ("private-relay", check_private_relay, False),
    ("ddr", check_ddr, False),
    ("dnssec", check_dnssec, False),
    ("rebinding", check_rebinding, False),
    ("safesearch", check_safesearch, False),
    ("vendor-tests", check_vendor_tests, False),
    ("cross-type", check_cross_type, False),
)


def run_checks(ctx: CheckContext, only: Iterable[str] | None = None, progress: Callable[[str], None] | None = None) -> list[CheckResult]:
    """Run every check (or ``only`` those ids), in order.  A check that raises is
    reported as an error rather than ending the run."""
    wanted = set(only) if only else None
    results: list[CheckResult] = []
    for check_id, fn, needs_network in CHECKS:
        if wanted is not None and check_id not in wanted:
            continue
        if needs_network and not ctx.network:
            continue
        if progress is not None:
            progress(check_id)
        try:
            results.append(fn(ctx))
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the rest
            results.append(CheckResult(check_id, "Errors", check_id, "error", f"{type(exc).__name__}: {exc}"))
    return results


def summarise(results: Sequence[CheckResult]) -> dict:
    counts = {status: 0 for status in STATUSES}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    worst = next((status for status in STATUSES if counts.get(status)), "skip")
    return {"counts": counts, "worst": worst, "total": len(results)}
