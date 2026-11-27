"""TCP, DNS over TLS and DNS over HTTPS.

The HTTP parser is tested at every split point, because a TCP read can end
anywhere.  The connection pools are tested end to end against the mock (TCP and
plain-HTTP DoH on loopback) and against small servers that misbehave on purpose:
one that hangs up in the middle of a pipeline, one that retires every connection
after one answer.  TLS itself needs a certificate the standard library cannot make,
so it was verified live against Quad9, Google, Cloudflare and OpenDNS on
2026-11-26; the TLS-specific code is the error wording, which is tested here.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import pathlib
import socket
import ssl
import struct
import sys
import threading
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge import cli  # noqa: E402
from dnsloadforge import packets as pk  # noqa: E402
from dnsloadforge.checks import context_for_target, run_checks  # noqa: E402
from dnsloadforge.engine import DnsLoadEngine  # noqa: E402
from dnsloadforge.mockappliance import MockAppliance  # noqa: E402
from dnsloadforge.spec import RunConfig, endpoint_label  # noqa: E402
from dnsloadforge.stats import StatsAggregator  # noqa: E402
from dnsloadforge.targets import Target, find_target, load_targets  # noqa: E402
from dnsloadforge.transports import (  # noqa: E402
    Endpoint,
    HttpResponse,
    HttpResponseParser,
    TransportError,
    describe_error,
    exchange,
    http_problem,
    parse_doh_url,
    pool_size,
    probe,
)

from test_engine import block_heavy, synthetic_catalogue  # noqa: E402


def parse(argv: list[str]) -> argparse.Namespace:
    return cli.build_parser().parse_args(argv)


def dns_answer(query: bytes) -> bytes:
    return pk.encode_response(pk.decode_message(query), rcode=0)


ONE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 12\r\n\r\n"
    + b"\x12\x34" + b"\x81\x80" + b"\x00" * 8
)
CHUNKED = (
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/dns-message\r\n\r\n"
    b"5;ext=1\r\nhello\r\n7\r\n, world\r\n0\r\nX-Trailer: yes\r\n\r\n"
)


class TestHttpResponseParser(unittest.TestCase):
    def test_a_response_with_a_length(self) -> None:
        [response] = HttpResponseParser().feed(ONE)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers["content-type"], "application/dns-message")
        self.assertEqual(len(response.body), 12)
        self.assertTrue(response.keep_alive)

    def test_every_split_point_gives_the_same_response(self) -> None:
        """A TCP read can end anywhere, including inside the header terminator."""
        for stream in (ONE, CHUNKED):
            for cut in range(1, len(stream)):
                with self.subTest(cut=cut):
                    parser = HttpResponseParser()
                    first = parser.feed(stream[:cut])
                    rest = parser.feed(stream[cut:])
                    responses = first + rest
                    self.assertEqual(len(responses), 1)
                    self.assertEqual(responses[0].body, HttpResponseParser().feed(stream)[0].body)

    def test_one_byte_at_a_time(self) -> None:
        parser = HttpResponseParser()
        responses = []
        for byte in ONE + CHUNKED:
            responses += parser.feed(bytes([byte]))
        self.assertEqual([len(r.body) for r in responses], [12, 12])

    def test_several_responses_in_one_read(self) -> None:
        responses = HttpResponseParser().feed(ONE + CHUNKED + ONE)
        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[1].body, b"hello, world")

    def test_informational_responses_are_skipped(self) -> None:
        [response] = HttpResponseParser().feed(b"HTTP/1.1 100 Continue\r\n\r\n" + ONE)
        self.assertEqual(response.status, 200)

    def test_a_body_that_runs_to_the_close(self) -> None:
        parser = HttpResponseParser()
        self.assertEqual(parser.feed(b"HTTP/1.1 503 Busy\r\nConnection: close\r\n\r\nback later"), [])
        response = parser.eof()
        self.assertEqual((response.status, response.body), (503, b"back later"))
        self.assertFalse(response.keep_alive)

    def test_not_http_is_an_error(self) -> None:
        with self.assertRaises(TransportError):
            HttpResponseParser().feed(b"\x00\x1c\x12\x34 this is DNS over TCP, not HTTP\r\n\r\n")


class TestHttpProblems(unittest.TestCase):
    def response(self, status: int, kind: str = "application/dns-message", body: bytes = b"\x00" * 12) -> HttpResponse:
        return HttpResponse(status, "", {"content-type": kind}, body)

    def test_a_dns_answer_is_no_problem(self) -> None:
        self.assertEqual(http_problem(self.response(200)), "")

    def test_each_failure_says_what_to_do(self) -> None:
        self.assertIn("HTTP/2", http_problem(self.response(505)))
        self.assertIn("check the URL", http_problem(self.response(404)))
        self.assertIn("not a DNS message", http_problem(self.response(200, "text/html")))
        self.assertIn("empty", http_problem(self.response(200, body=b"")))
        self.assertIn("rate-limiting", http_problem(self.response(429)))


class TestUrlsAndLabels(unittest.TestCase):
    def test_doh_urls(self) -> None:
        self.assertEqual(parse_doh_url("https://dns.google/dns-query"), ("https", "dns.google", 443, "/dns-query"))
        # The RFC 8484 template form, as services publish it.
        self.assertEqual(
            parse_doh_url("https://doh.example:8443/q{?dns}"), ("https", "doh.example", 8443, "/q")
        )
        self.assertEqual(parse_doh_url("http://127.0.0.1:8053"), ("http", "127.0.0.1", 8053, "/dns-query"))
        for bad in ("ftp://dns.google/", "https:///dns-query", "https://dns.google/dns-query?dns=AAAB"):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                parse_doh_url(bad)

    def test_labels(self) -> None:
        self.assertEqual(endpoint_label("udp", "10.0.0.5", 53), "10.0.0.5:53")
        self.assertEqual(endpoint_label("tcp", "10.0.0.5", 53), "tcp://10.0.0.5:53")
        self.assertEqual(endpoint_label("tls", "9.9.9.9", 853, "dns.quad9.net"), "tls://dns.quad9.net:853 (9.9.9.9)")
        self.assertEqual(
            endpoint_label("https", "dns.google", 443, "dns.google"), "https://dns.google/dns-query"
        )
        self.assertEqual(endpoint_label("http", "127.0.0.1", 8053), "http://127.0.0.1:8053/dns-query")
        self.assertEqual(RunConfig(server="10.0.0.5").target, "10.0.0.5:53")


class TestErrorWording(unittest.TestCase):
    endpoint = Endpoint("9.9.9.9", 853, "tls", "dns.quad9.net")

    def cert_error(self, message: str) -> ssl.SSLCertVerificationError:
        error = ssl.SSLCertVerificationError(1, message)
        error.verify_message = message
        return error

    def test_a_missing_root_points_at_the_fixes(self) -> None:
        text = describe_error(self.endpoint, self.cert_error("unable to get local issuer certificate"))
        self.assertIn("--ca-file", text)
        self.assertIn("--insecure", text)
        if sys.platform == "win32":
            self.assertIn("in a browser", text)

    def test_a_name_mismatch_points_at_tls_name(self) -> None:
        text = describe_error(self.endpoint, self.cert_error("Hostname mismatch, certificate is not valid for 'x'."))
        self.assertIn("--tls-name", text)

    def test_plain_network_failures(self) -> None:
        self.assertIn("nothing is listening", describe_error(self.endpoint, ConnectionRefusedError()))
        self.assertIn("did not answer in time", describe_error(self.endpoint, TimeoutError()))

    def test_certificate_settings(self) -> None:
        self.assertEqual(self.endpoint.ssl_context().minimum_version, ssl.TLSVersion.TLSv1_2)
        unchecked = Endpoint("10.0.0.5", 853, "tls", verify=False).ssl_context()
        self.assertEqual(unchecked.verify_mode, ssl.CERT_NONE)
        self.assertIsNone(Endpoint("10.0.0.5", 53, "tcp").ssl_context())
        with self.assertRaises(TransportError):
            Endpoint("10.0.0.5", 853, "tls", ca_file="does-not-exist.pem").ssl_context()


class TestPoolSizes(unittest.TestCase):
    def test_sizes(self) -> None:
        self.assertEqual(pool_size(RunConfig(transport="tls")), (4, 4))
        self.assertEqual(pool_size(RunConfig(transport="tls", connections=10)), (10, 10))
        # DoH starts with room for a whole page-load burst, and may grow.
        size, grow_to = pool_size(RunConfig(transport="https", target_qps=5))
        self.assertEqual(size, 24)
        self.assertGreater(grow_to, size)
        self.assertEqual(pool_size(RunConfig(transport="https", target_qps=1000))[0], 64)
        # Split between the source addresses of a pool-mode run.
        self.assertEqual(pool_size(RunConfig(transport="https", target_qps=5), channels=4)[0], 6)


class MockCase(unittest.TestCase):
    def setUp(self) -> None:
        self.catalogue = synthetic_catalogue()
        self.mock = MockAppliance(
            scenario="good", blocklist=self.catalogue.blocked_domains(), latency_ms=0.0, jitter_ms=0.0, port=0, doh_port=0
        )
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def endpoint(self, transport: str, **extra) -> Endpoint:
        port = self.mock.doh_port if transport == "http" else self.mock.port
        return Endpoint(self.mock.host, port, transport, **extra)

    def run_engine(self, transport: str, *, appliance: MockAppliance | None = None, port: int | None = None, **overrides):
        appliance = appliance or self.mock
        if port is None:
            port = appliance.doh_port if transport == "http" else appliance.port
        params = dict(
            server=appliance.host,
            port=port,
            transport=transport,
            personas=200,
            target_qps=300.0,
            duration_s=1.5,
            timeout_s=0.5,
            seed=5,
        )
        params.update(overrides)
        stats = StatsAggregator()
        engine = DnsLoadEngine(RunConfig(**params), self.catalogue, stats=stats, model=block_heavy(self.catalogue))
        return asyncio.run(engine.run()), stats.snapshot()


class TestMockTransports(MockCase):
    def test_the_mock_answers_tcp_on_its_udp_port(self) -> None:
        self.assertEqual(self.mock.tcp_port, self.mock.port)
        for transport in ("udp", "tcp", "http"):
            with self.subTest(transport=transport):
                self.assertEqual(probe(self.endpoint(transport)), (True, ""))

    def test_doh_post_and_get_both_answer(self) -> None:
        import base64
        import http.client

        query, qid = pk.encode_query("example.org", "A")
        self.assertEqual(pk.decode_message(exchange(self.endpoint("http"), query)).qid, qid)
        connection = http.client.HTTPConnection(self.mock.host, self.mock.doh_port, timeout=2)
        encoded = base64.urlsafe_b64encode(query).rstrip(b"=").decode()
        connection.request("GET", f"/dns-query?dns={encoded}", headers={"Accept": "application/dns-message"})
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(pk.decode_message(response.read()).qid, qid)
        connection.close()

    def test_a_wrong_path_is_explained(self) -> None:
        ok, why = probe(self.endpoint("http", path="/wrong"))
        self.assertFalse(ok)
        self.assertIn("HTTP 404", why)

    def test_a_closed_port_is_explained(self) -> None:
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))  # bound, never listening: connections are refused
        self.addCleanup(holder.close)
        ok, why = probe(Endpoint("127.0.0.1", holder.getsockname()[1], "tcp"), timeout=3, attempts=1)
        self.assertFalse(ok)
        self.assertIn("127.0.0.1", why)


class TestEngineOverStreams(MockCase):
    def test_every_transport_reaches_the_same_verdict(self) -> None:
        for transport in ("udp", "tcp", "http"):
            with self.subTest(transport=transport):
                result, snapshot = self.run_engine(transport)
                self.assertGreater(result.sent, 200)
                self.assertEqual(result.timeouts + result.errors, 0)
                self.assertEqual(snapshot["verdict"]["status"], "filtering")
                self.assertEqual(snapshot["outcomes"]["false_negative"], 0)
                self.assertEqual(snapshot["outcomes"]["false_positive"], 0)
                if transport == "udp":
                    self.assertNotIn("connections", snapshot)
                else:
                    connections = snapshot["connections"]
                    self.assertGreaterEqual(connections["opened"], 1)
                    self.assertEqual(connections["lost"], 0)
                    self.assertEqual(connections["open"], 0, "every connection is closed at the end")

    def test_a_doh_server_that_turns_queries_away_scores_errors_not_timeouts(self) -> None:
        lossy = MockAppliance(scenario="lossy", drop_rate=0.3, latency_ms=0.0, jitter_ms=0.0, port=0, doh_port=0)
        lossy.start()
        self.addCleanup(lossy.stop)
        result, snapshot = self.run_engine("http", appliance=lossy)
        self.assertGreater(result.errors, 0)
        self.assertEqual(result.timeouts, 0)
        self.assertIn("503", snapshot["connections"]["last_error"])

    def test_a_full_doh_pool_drops_queries_on_the_senders_side(self) -> None:
        slow = MockAppliance(scenario="good", latency_ms=40.0, jitter_ms=0.0, port=0, doh_port=0)
        slow.start()
        self.addCleanup(slow.stop)
        result, snapshot = self.run_engine("http", appliance=slow, connections=1, target_qps=200.0)
        self.assertGreater(result.dropped, 0)
        self.assertGreater(snapshot["connections"]["busy_drops"], 0)
        self.assertEqual(result.errors, 0, "a busy pool is the sender's limit, not the server's failure")
        self.assertEqual(snapshot["connections"]["opened"], 1, "a fixed pool does not grow")


class HangUpServer:
    """Answers DNS over TCP, but hangs up after ``per_connection`` answers with
    the rest of the pipeline unanswered."""

    def __init__(self, per_connection: int = 5) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.per_connection = per_connection
        self.stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn: socket.socket) -> None:
        conn.settimeout(1.0)
        buffer, answered = b"", 0
        with conn:
            while answered < self.per_connection and not self.stop.is_set():
                try:
                    data = conn.recv(65535)
                except OSError:
                    return
                if not data:
                    return
                buffer += data
                while len(buffer) >= 2 and answered < self.per_connection:
                    (length,) = struct.unpack("!H", buffer[:2])
                    if len(buffer) < 2 + length:
                        break
                    reply = dns_answer(buffer[2 : 2 + length])
                    buffer = buffer[2 + length :]
                    conn.sendall(struct.pack("!H", len(reply)) + reply)
                    answered += 1

    def close(self) -> None:
        self.stop.set()
        self.sock.close()


class RetireEveryTime(BaseHTTPRequestHandler):
    """A DoH server that answers, then closes, every connection."""

    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        reply = dns_answer(self.rfile.read(int(self.headers["Content-Length"])))
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(reply)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(reply)
        self.close_connection = True

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        pass


class TestConnectionsThatEnd(MockCase):
    def test_queries_a_server_hangs_up_on_are_sent_again_and_the_connection_replaced(self) -> None:
        server = HangUpServer(per_connection=5)
        self.addCleanup(server.close)
        result, snapshot = self.run_engine("tcp", port=server.port, server="127.0.0.1", target_qps=200.0)
        connections = snapshot["connections"]
        self.assertGreater(connections["retried"], 0, "the stranded queries were sent again")
        self.assertGreater(connections["opened"], 4, "closed connections are replaced")
        self.assertGreater(result.received, 20)
        # A query stranded twice fails at once; none is left to time out.
        self.assertEqual(result.timeouts, 0)
        self.assertGreaterEqual(result.received + result.timeouts + result.errors, result.sent)

    def test_a_politely_retired_doh_connection_is_not_a_failure(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), RetireEveryTime)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        result, snapshot = self.run_engine(
            "http", port=server.server_address[1], server="127.0.0.1", target_qps=20.0, duration_s=1.5
        )
        connections = snapshot["connections"]
        self.assertGreater(result.received, 5)
        self.assertEqual(result.errors, 0)
        self.assertEqual(connections["lost"], 0)
        self.assertGreater(connections["closed"], 5)


class TestChecksOverDoh(MockCase):
    def test_the_targets_own_queries_go_over_its_transport(self) -> None:
        target = Target(name="mock doh", server=self.mock.host, port=self.mock.doh_port, transport="http")
        ctx = context_for_target(target, network=False, samples=[])
        [result] = run_checks(ctx, only=["firefox-canary"])
        self.assertEqual(result.status, "warn")  # the mock resolves the canary
        self.assertTrue(result.evidence[0]["server"].startswith(f"http://127.0.0.1:{self.mock.doh_port}/"))


class TestTargetsAndCommandLine(unittest.TestCase):
    def test_a_doh_url_makes_an_https_target(self) -> None:
        _, [target] = cli.resolve_targets(parse(["run", "--doh-url", "https://dns.google/dns-query"]))
        self.assertEqual((target.transport, target.server, target.port), ("https", "dns.google", 443))
        self.assertEqual(target.kind, "public", "the public-resolver guard knows the name")
        _, [pinned] = cli.resolve_targets(
            parse(["run", "--doh-url", "https://dns.google/dns-query", "--server", "8.8.8.8"])
        )
        self.assertEqual((pinned.server, pinned.tls_name), ("8.8.8.8", "dns.google"))

    def test_a_transport_sets_the_usual_port(self) -> None:
        config = cli.build_config(parse(["run", "--server", "10.0.0.5", "--transport", "tls", "--insecure"]))
        self.assertEqual((config.transport, config.port, config.tls_verify), ("tls", 853, False))
        self.assertEqual(config.target, "tls://10.0.0.5:853")

    def test_conflicting_flags_are_refused(self) -> None:
        for argv in (
            ["run", "--target", "quad9", "--transport", "tls"],
            ["run", "--doh-url", "https://dns.google/dns-query", "--transport", "tls"],
        ):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                cli.resolve_targets(parse(argv))

    def test_a_public_doh_url_is_guarded_at_load_rate(self) -> None:
        args = parse(["run", "--doh-url", "https://dns.google/dns-query", "--qps", "5000"])
        with unittest.mock.patch.object(cli, "probe_target", return_value=(True, "")):
            problems = cli.preflight(cli.build_config(args), synthetic_catalogue(), args)
        self.assertTrue(any("public resolver" in p for p in problems), problems)

    def test_targets_file_entries(self) -> None:
        target = Target.from_dict({"name": "lab", "url": "https://doh.lab.example/dns-query", "server": "10.0.0.5"})
        self.assertEqual((target.transport, target.server, target.tls_name), ("https", "10.0.0.5", "doh.lab.example"))
        self.assertEqual(target.as_dict()["endpoint"], "https://doh.lab.example/dns-query (10.0.0.5)")
        self.assertEqual(Target.from_dict({"name": "dot", "server": "10.0.0.5", "transport": "tls"}).port, 853)
        for bad in (
            {"name": "x", "server": "10.0.0.5", "transport": "http"},  # plain HTTP only on loopback
            {"name": "x", "server": "10.0.0.5", "transport": "quic"},
            {"name": "x", "server": "10.0.0.5", "transport": "tls", "tls_name": "not a name"},
            {"name": "x", "server": "10.0.0.5", "transport": "https", "doh_path": "dns-query"},
        ):
            with self.subTest(entry=bad), self.assertRaises(ValueError):
                Target.from_dict(bad)

    def test_a_short_name_means_the_plain_service(self) -> None:
        targets = load_targets(None)
        self.assertEqual(find_target("familyshield", targets).transport, "udp")
        self.assertEqual(find_target("quad9 dot", targets).name, "Quad9 over DoT")
        self.assertEqual(find_target("cloudflare family doh", targets).name, "Cloudflare Family over DoH")
        with self.assertRaises(ValueError):
            find_target("cloudflare", targets)

    def test_the_mock_rehearses_doh_over_plain_http(self) -> None:
        args = parse(["run", "--mock", "--transport", "https", "--no-dashboard"])
        catalogue = synthetic_catalogue()
        config = cli.build_config(args)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            mock = cli._setup_mock(args, catalogue, config)
        self.addCleanup(mock.stop)
        self.assertEqual((config.transport, config.port), ("http", mock.doh_port))
        self.assertTrue(config.target_name.endswith("over DoH"))
        self.assertIn("no certificate", buffer.getvalue())
        names = [t.name for t in cli._with_mock_target([], cli._adhoc_from_args(args), mock, config, args)]
        self.assertEqual(len(names), 3, names)


if __name__ == "__main__":
    unittest.main()
