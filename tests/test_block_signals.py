"""How a filter signals a block, and the leak a block on A/AAAA alone leaves open.

Two gaps this closes, both stated in the README as known limitations before:

* **HTTPS/SVCB leaks.**  A filter that blocks a name's A and AAAA lookups but answers
  its HTTPS record with real ``ipv4hint``/``ipv6hint`` addresses has not blocked
  anything: a browser connects to the hints without asking for an address.
* **Unknown block pages.**  Only a block-page address the tool had been told about
  counted as a block.  Filters now say so themselves with an Extended DNS Error
  (RFC 8914) -- observed live: Cloudflare 1.1.1.2 sends 16, Quad9 and AdGuard 17,
  DNS4EU 15 -- so a block is recognised whatever address comes back.
"""

from __future__ import annotations

import asyncio
import pathlib
import socket
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge import packets as pk  # noqa: E402
from dnsloadforge.engine import DnsLoadEngine, block_signal, classify  # noqa: E402
from dnsloadforge.mockappliance import MockAppliance  # noqa: E402
from dnsloadforge.spec import Category, Outcome  # noqa: E402
from dnsloadforge.stats import StatsAggregator  # noqa: E402

from test_engine import EndToEndCase, block_heavy, config_for  # noqa: E402

SINK = frozenset({"0.0.0.0", "::"})


class TestWireFormat(unittest.TestCase):
    def response(self, **kwargs) -> pk.DNSMessage:
        query, _ = pk.encode_query("name.example.com", kwargs.pop("qtype", "A"))
        return pk.decode_message(pk.encode_response(query, edns_udp_size=1232, **kwargs))

    def test_extended_dns_errors_are_read(self) -> None:
        message = self.response(edns_options=[pk.ede_option(17, "malware"), pk.ede_option(3)])
        self.assertEqual(message.ede, [(17, "malware"), (3, "")])
        self.assertEqual(message.policy_ede, 17)
        self.assertEqual(pk.ede_label(17), "17 Filtered")

    def test_a_non_policy_error_is_not_a_block(self) -> None:
        """6 is DNSSEC Bogus: a failure, not a policy decision."""
        self.assertIsNone(self.response(rcode=2, edns_options=[pk.ede_option(6)]).policy_ede)

    def test_every_policy_code_counts(self) -> None:
        for code in (4, 15, 16, 17, 18):
            with self.subTest(code=code):
                self.assertEqual(self.response(edns_options=[pk.ede_option(code)]).policy_ede, code)

    def test_nsid_is_read_and_requested(self) -> None:
        message = self.response(edns_options=[(pk.EDNS_NSID, b"res715.ord")])
        self.assertEqual(message.nsid_text, "res715.ord")
        self.assertEqual(self.response(edns_options=[(pk.EDNS_NSID, b"\x01\xff")]).nsid_text, "01ff")
        query, _ = pk.encode_query("name.example.com", "A", options=[(pk.EDNS_NSID, b"")])
        self.assertIn(pk.EDNS_NSID, pk.decode_message(query).edns_options)

    def test_https_hints_are_addresses(self) -> None:
        rdata = pk.svcb_rdata(1, ".", alpn=("h2",), ipv4hint=["192.0.2.7", "192.0.2.8"], ipv6hint=["2001:db8::1"])
        message = self.response(qtype="HTTPS", answers=[pk.RR("name.example.com", "HTTPS", 60, rdata)])
        self.assertEqual(message.hint_ips, ["192.0.2.7", "192.0.2.8", "2001:db8::1"])
        self.assertEqual(message.answer_ips, [], "hints are not A/AAAA records")
        self.assertEqual(message.answers[0].svc_priority, 1)

    def test_alias_mode_has_a_target_and_no_hints(self) -> None:
        rdata = pk.svcb_rdata(0, "cdn.example.net")
        message = self.response(qtype="HTTPS", answers=[pk.RR("name.example.com", "HTTPS", 60, rdata)])
        self.assertEqual(message.answers[0].svc_target, "cdn.example.net")
        self.assertEqual(message.hint_ips, [])

    def test_damaged_options_and_parameters_do_not_lose_the_rcode(self) -> None:
        rdata = pk.svcb_rdata(1, ".", ipv4hint=["192.0.2.7"])[:-2]  # truncated hint
        message = self.response(qtype="HTTPS", answers=[pk.RR("name.example.com", "HTTPS", 60, rdata)])
        self.assertEqual(message.rcode_name, "NOERROR")
        self.assertEqual(message.hint_ips, [])
        packet = pk.encode_response(
            pk.encode_query("name.example.com", "A")[0], rcode=3, edns_udp_size=1232,
            edns_options=[pk.ede_option(15, "x")],
        )
        self.assertEqual(pk.decode_message(packet[:-1]).rcode_name, "NXDOMAIN")


class TestRealResponses(unittest.TestCase):
    """Raw answers captured from public resolvers (tests/fixtures/real_responses.json),
    so the decoder is pinned against what real servers send -- compressed names, EDE
    and NSID options, HTTPS hints -- not only against this module's own encoder."""

    def setUp(self) -> None:
        import json

        path = pathlib.Path(__file__).resolve().parent / "fixtures" / "real_responses.json"
        self.responses = {r["label"]: r for r in json.loads(path.read_text(encoding="utf-8"))["responses"]}

    def test_each_capture_decodes_as_recorded(self) -> None:
        for label, record in self.responses.items():
            with self.subTest(capture=label):
                message = pk.decode_message(bytes.fromhex(record["hex"]))
                self.assertEqual(message.rcode_name, record["rcode"])
                self.assertEqual(message.answer_ips, record["answer_ips"])
                self.assertEqual(message.hint_ips, record["hint_ips"])
                self.assertEqual([code for code, _ in message.ede], record["ede"])
                self.assertEqual(bool(message.nsid), record["has_nsid"])

    def test_the_captures_score_as_their_filters_meant(self) -> None:
        cloudflare = pk.decode_message(bytes.fromhex(self.responses["cloudflare-security-block"]["hex"]))
        quad9 = pk.decode_message(bytes.fromhex(self.responses["quad9-block"]["hex"]))
        https = pk.decode_message(bytes.fromhex(self.responses["https-hints"]["hex"]))
        for message in (cloudflare, quad9):
            outcome, _ = classify(
                Category.BLOCK_MALWARE.value, message.rcode_name, message.answer_ips, frozenset(), policy_ede=message.policy_ede
            )
            self.assertEqual(outcome, Outcome.BLOCKED.value, "the filter's own EDE marks the block, no sinkhole list needed")
        outcome, _ = classify(Category.BLOCK_ADS.value, https.rcode_name, https.answer_ips + https.hint_ips, SINK)
        self.assertEqual(outcome, Outcome.FALSE_NEGATIVE.value, "an unfiltered HTTPS answer carries usable addresses")


class TestScoring(unittest.TestCase):
    def test_a_policy_error_on_an_allow_listed_name_is_a_false_positive(self) -> None:
        """Even when the address looks real: it is a block page nobody listed."""
        outcome, _ = classify(Category.ENTERPRISE.value, "NOERROR", ["198.51.100.9"], SINK, policy_ede=15)
        self.assertEqual(outcome, Outcome.FALSE_POSITIVE.value)

    def test_a_policy_error_on_a_block_listed_name_is_a_block_not_a_leak(self) -> None:
        outcome, _ = classify(Category.BLOCK_MALWARE.value, "NOERROR", ["198.51.100.9"], SINK, policy_ede=17)
        self.assertEqual(outcome, Outcome.BLOCKED.value)

    def test_real_https_hints_for_a_block_listed_name_are_a_leak(self) -> None:
        outcome, _ = classify(Category.BLOCK_ADS.value, "NOERROR", ["192.0.2.7"], SINK)
        self.assertEqual(outcome, Outcome.FALSE_NEGATIVE.value)

    def test_sinkhole_hints_and_hintless_records_are_blocks(self) -> None:
        self.assertEqual(classify(Category.BLOCK_ADS.value, "NOERROR", ["0.0.0.0"], SINK)[0], Outcome.BLOCKED.value)
        self.assertEqual(classify(Category.BLOCK_ADS.value, "NOERROR", [], SINK)[0], Outcome.BLOCKED.value)

    def test_the_reverse_name_exception_still_comes_first(self) -> None:
        outcome, _ = classify(
            Category.ALLOW_POPULAR.value, "NXDOMAIN", [], SINK, qname="7.2.0.192.in-addr.arpa", policy_ede=15
        )
        self.assertEqual(outcome, Outcome.NXDOMAIN.value)

    def test_block_signals_name_the_mechanism(self) -> None:
        self.assertEqual(block_signal("NXDOMAIN", [], SINK), "nxdomain")
        self.assertEqual(block_signal("REFUSED", [], SINK), "refused")
        self.assertEqual(block_signal("NOERROR", ["0.0.0.0"], SINK), "sinkhole")
        self.assertEqual(block_signal("NOERROR", [], SINK), "nodata")
        self.assertEqual(block_signal("NOERROR", ["198.51.100.9"], SINK), "address")
        self.assertEqual(block_signal("SERVFAIL", [], SINK), "servfail")


class TestAgainstTheMock(EndToEndCase):
    def run_mock(self, **mock_options):
        config_overrides = mock_options.pop("config", {})
        appliance = MockAppliance(blocklist=self.blocked, latency_ms=0.05, jitter_ms=0.0, port=0, **mock_options)
        appliance.start()
        try:
            stats = StatsAggregator()
            engine = DnsLoadEngine(
                config_for(appliance, **config_overrides), self.catalogue, stats=stats, model=block_heavy(self.catalogue)
            )
            result = asyncio.run(engine.run())
        finally:
            appliance.stop()
        return result, stats.snapshot()

    def test_a_filter_that_leaks_https_is_caught(self) -> None:
        """Measured against the mock's https-leak scenario: A and AAAA are blocked,
        HTTPS answers carry real hints, and the verdict must say it leaks."""
        result, snapshot = self.run_mock(scenario="https-leak")
        self.assertGreater(snapshot["outcomes"]["false_negative"], 0)
        self.assertTrue(snapshot["false_negatives"])
        self.assertEqual({row["qtype"] for row in snapshot["false_negatives"]}, {"HTTPS"})
        self.assertEqual(result.verdict["status"], "degraded")
        self.assertIn("Leaking", result.verdict["note"])

    def test_an_honest_filter_still_scores_clean(self) -> None:
        """The same traffic against an honest filter: HTTPS answers for allowed names
        carry hints too, and none of it may become a finding."""
        result, snapshot = self.run_mock(scenario="good")
        self.assertEqual(snapshot["outcomes"]["false_negative"], 0)
        self.assertEqual(snapshot["outcomes"]["false_positive"], 0)
        self.assertEqual(result.verdict["status"], "filtering")

    def test_block_signals_and_extended_errors_are_reported(self) -> None:
        _result, snapshot = self.run_mock(scenario="good", block_mode="sinkhole", block_ede=17)
        signals = snapshot["block_signals"]
        self.assertGreater(signals.get("sinkhole", 0), 0)
        self.assertGreater(signals.get("nodata", 0), 0, "sinkholing cannot put 0.0.0.0 in an MX answer")
        self.assertEqual([row["code"] for row in snapshot["ede"]], [17])
        self.assertEqual(snapshot["ede"][0]["name"], "Filtered")

    def test_an_unlisted_block_page_is_recognised_by_its_extended_error(self) -> None:
        """A block page at an address no target preset lists: before, every one of
        these was a leak; with the filter's own EDE it is a block."""
        _result, snapshot = self.run_mock(scenario="good", block_mode="sinkhole", sinkhole_ip="198.51.100.9", block_ede=15)
        self.assertEqual(snapshot["outcomes"]["false_negative"], 0)
        self.assertGreater(snapshot["block_signals"].get("address", 0), 0)

    def test_nsid_names_the_answering_instance_when_asked(self) -> None:
        _result, snapshot = self.run_mock(scenario="good", config={"nsid": True})
        self.assertEqual([row["id"] for row in snapshot["nsid"]], ["mock-1"])
        _result, quiet = self.run_mock(scenario="good")
        self.assertEqual(quiet["nsid"], [], "no NSID unless asked for")


class TestMockReplies(unittest.TestCase):
    def ask(self, appliance: MockAppliance, qname: str, qtype: str, **query_options) -> pk.DNSMessage:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            query, _ = pk.encode_query(qname, qtype, **query_options)
            sock.sendto(query, (appliance.host, appliance.port))
            return pk.decode_message(sock.recvfrom(4096)[0])
        finally:
            sock.close()

    def test_blocked_answers_carry_the_configured_error_and_allowed_ones_none(self) -> None:
        with MockAppliance(scenario="good", blocklist={"bad.example.com"}, latency_ms=0.0, jitter_ms=0.0, port=0) as app:
            blocked = self.ask(app, "bad.example.com", "A")
            allowed = self.ask(app, "fine.example.com", "A")
        self.assertEqual(blocked.rcode_name, "NXDOMAIN")
        self.assertEqual(blocked.policy_ede, 15)
        self.assertEqual(allowed.ede, [])

    def test_the_error_can_be_switched_off(self) -> None:
        with MockAppliance(scenario="good", blocklist={"bad.example.com"}, block_ede=0, latency_ms=0.0, jitter_ms=0.0, port=0) as app:
            self.assertEqual(self.ask(app, "bad.example.com", "A").ede, [])


if __name__ == "__main__":
    unittest.main()
