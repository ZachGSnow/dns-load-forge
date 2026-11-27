"""Deployment checks.

Each check is driven by a fake resolver, so every pass/warn/fail path is exercised
without the network; the expected answers in the fakes are the ones observed live
on 2026-11-26 (OpenDNS FamilyShield, Cloudflare 1.1.1.3, Quad9).  One end-to-end
test runs the whole battery through the dashboard API against the mock appliance.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge import checks as ck  # noqa: E402
from dnsloadforge import cli  # noqa: E402
from dnsloadforge.checks import CheckContext, Exchange  # noqa: E402
from dnsloadforge.mockappliance import MockAppliance  # noqa: E402
from dnsloadforge.server import serve  # noqa: E402
from dnsloadforge.spec import RunConfig  # noqa: E402

from test_targets import synthetic_catalogue  # noqa: E402

TARGET = "10.0.0.53"


class FakeResolver:
    """Answers (server, qname, qtype) from a table; anything else goes unanswered."""

    def __init__(self, table: dict) -> None:
        self.table = table
        self.asked: list[tuple[str, str, str]] = []

    def __call__(self, server, port, qname, qtype="A", **_kwargs) -> Exchange:
        self.asked.append((server, qname, qtype))
        spec = self.table.get((server, qname, qtype), self.table.get((None, qname, qtype)))
        if spec is None:
            return Exchange(server, port, qname, qtype, error="no answer")
        return Exchange(server, port, qname, qtype, **spec)


def context(table: dict, **overrides) -> CheckContext:
    params = dict(server=TARGET, ask=FakeResolver(table), connect=lambda host, port, timeout: (False, "timed out"))
    params.update(overrides)
    return CheckContext(**params)


def ok(*addresses: str, **extra) -> dict:
    return {"rcode": "NOERROR", "addresses": list(addresses), **extra}


NX = {"rcode": "NXDOMAIN"}
NODATA = {"rcode": "NOERROR"}


class TestHelpers(unittest.TestCase):
    def test_block_reasons(self) -> None:
        self.assertEqual(ck.block_reason(Exchange("s", 53, "n", "A", **NX)), "NXDOMAIN")
        self.assertEqual(ck.block_reason(Exchange("s", 53, "n", "A", **ok("0.0.0.0"))), "block page 0.0.0.0")
        self.assertEqual(ck.block_reason(Exchange("s", 53, "n", "A", **ok("146.112.61.108"))), "block page 146.112.61.108")
        self.assertEqual(ck.block_reason(Exchange("s", 53, "n", "A", **ok("198.51.100.4", ede=[(17, "")]))), "EDE 17 Filtered")
        self.assertEqual(ck.block_reason(Exchange("s", 53, "n", "A", **NODATA)), "no records")
        self.assertEqual(ck.block_reason(Exchange("s", 53, "n", "A", **ok("198.51.100.4"))), "")
        self.assertEqual(ck.block_reason(Exchange("s", 53, "n", "A", error="no answer")), "")

    def test_umbrellas_unfiltered_answer_is_not_mistaken_for_its_block_page(self) -> None:
        """On an unfiltered resolver Umbrella's test names resolve to 146.112.59.12,
        inside the same network as the block pages: only the exact pages count."""
        self.assertEqual(ck.block_reason(Exchange("s", 53, "n", "A", **ok("146.112.59.12"))), "")

    def test_an_ipv4_mapped_block_page_is_the_block_page(self) -> None:
        self.assertEqual(ck.normal_address("::ffff:9270:3d6a"), "146.112.61.106")
        self.assertEqual(ck.block_reason(Exchange("s", 53, "n", "AAAA", **ok("::ffff:9270:3d6a"))), "block page 146.112.61.106")


class TestNetworkChecks(unittest.TestCase):
    def test_interception(self) -> None:
        self.assertEqual(ck.check_interception(context({})).status, "pass")
        caught = ck.check_interception(context({("192.0.2.1", "example.com", "A"): ok("198.51.100.1")}))
        self.assertEqual(caught.status, "fail")
        self.assertIn("intercepted", caught.summary)

    def test_plain_bypass(self) -> None:
        self.assertEqual(ck.check_plain_bypass(context({})).status, "pass")
        direct = context({("8.8.8.8", "example.com", "A"): ok("198.51.100.1", nsid="gpdns-ord")})
        result = ck.check_plain_bypass(direct)
        self.assertEqual(result.status, "warn")
        self.assertIn("Google", result.summary)
        redirected = ck.check_plain_bypass(context({("8.8.8.8", "example.com", "A"): ok("198.51.100.1", nsid="filter-a")}))
        self.assertEqual(redirected.status, "pass")
        self.assertIn("redirected", redirected.summary)

    def test_encrypted_bypass(self) -> None:
        self.assertEqual(ck.check_encrypted_bypass(context({})).status, "pass")
        open_doh = context({}, connect=lambda host, port, timeout: (host == "1.1.1.1" and port == 443, "x"))
        result = ck.check_encrypted_bypass(open_doh)
        self.assertEqual(result.status, "warn")
        self.assertIn("1.1.1.1:443", result.summary)


class TestCanaries(unittest.TestCase):
    def test_firefox_canary(self) -> None:
        self.assertEqual(ck.check_firefox_canary(context({(None, "use-application-dns.net", "A"): NX})).status, "pass")
        self.assertEqual(ck.check_firefox_canary(context({(None, "use-application-dns.net", "A"): NODATA})).status, "pass")
        self.assertEqual(
            ck.check_firefox_canary(context({(None, "use-application-dns.net", "A"): ok("35.190.14.201")})).status, "warn"
        )

    def test_private_relay_including_familyshields_half_block(self) -> None:
        both = context({(None, "mask.icloud.com", "A"): NX, (None, "mask-h2.icloud.com", "A"): NX})
        self.assertEqual(ck.check_private_relay(both).status, "pass")
        half = context({(None, "mask.icloud.com", "A"): ok("17.248.168.210"), (None, "mask-h2.icloud.com", "A"): ok("146.112.61.106")})
        result = ck.check_private_relay(half)
        self.assertEqual(result.status, "warn")
        self.assertIn("Only mask-h2.icloud.com", result.summary)

    def test_ddr_names_the_designated_endpoints(self) -> None:
        svcb = [{"priority": 1, "target": "family.cloudflare-dns.com", "alpn": ["h2", "h3"], "port": 443},
                {"priority": 2, "target": "family.cloudflare-dns.com", "alpn": ["dot"], "port": 853}]
        result = ck.check_ddr(context({(None, "_dns.resolver.arpa", "SVCB"): {"rcode": "NOERROR", "svcb": svcb}}))
        self.assertEqual(result.status, "info")
        self.assertIn("family.cloudflare-dns.com (DoH:443)", result.summary)
        self.assertIn("DoT:853", result.summary)
        self.assertIn("no encrypted resolver", ck.check_ddr(context({(None, "_dns.resolver.arpa", "SVCB"): NODATA})).summary)


class TestSecurityAndContent(unittest.TestCase):
    def test_dnssec(self) -> None:
        validating = context({(None, "dnssec-failed.org", "A"): {"rcode": "SERVFAIL"}, (None, "isc.org", "A"): ok("151.101.3.42", ad=True)})
        self.assertEqual(ck.check_dnssec(validating).status, "pass")
        blind = context({(None, "dnssec-failed.org", "A"): ok("96.99.227.255")})
        self.assertEqual(ck.check_dnssec(blind).status, "warn")

    def test_rebinding(self) -> None:
        open_ = context({(None, "10.0.0.1.nip.io", "A"): ok("10.0.0.1"), (None, "localtest.me", "A"): ok("127.0.0.1")})
        self.assertEqual(ck.check_rebinding(open_).status, "info")
        stripped = context({(None, "10.0.0.1.nip.io", "A"): NODATA, (None, "localtest.me", "A"): NX})
        self.assertEqual(ck.check_rebinding(stripped).status, "pass")

    def test_safesearch_like_cloudflare_family(self) -> None:
        """Observed live: 1.1.1.3 enforces Google, Bing and DuckDuckGo but not YouTube."""
        table = {
            (None, "www.google.com", "A"): ok("216.239.38.120"),
            (None, "forcesafesearch.google.com", "A"): ok("216.239.38.120"),
            (None, "www.youtube.com", "A"): ok("142.250.190.14"),
            (None, "restrict.youtube.com", "A"): ok("216.239.38.120"),
            (None, "restrictmoderate.youtube.com", "A"): ok("216.239.38.119"),
            (None, "www.bing.com", "A"): ok("150.171.28.16", cnames=["strict.bing.com"]),
            (None, "strict.bing.com", "A"): ok("150.171.28.16"),
            (None, "duckduckgo.com", "A"): ok("40.89.244.237"),
            (None, "safe.duckduckgo.com", "A"): ok("40.89.244.237"),
        }
        result = ck.check_safesearch(context(table, blocks=("block_adult",)))
        self.assertEqual(result.status, "warn")
        self.assertEqual(result.summary, "Enforced for Google, Bing, DuckDuckGo; not for YouTube.")
        self.assertEqual(ck.check_safesearch(context(table)).status, "info", "not a family filter: informational")


class TestPolicy(unittest.TestCase):
    def test_vendor_names_and_cross_type_consistency(self) -> None:
        table = {
            (None, "internetbadguys.com", "A"): ok("146.112.61.108"),
            (None, "exampleadultsite.com", "A"): ok("146.112.61.106"),
            (None, "examplemalwaredomain.com", "A"): ok("146.112.59.12"),
            (None, "malware.testcategory.com", "A"): ok("0.0.0.0", ede=[(16, "")]),
            (None, "internetbadguys.com", "AAAA"): ok("::ffff:9270:3d6c"),
            (None, "internetbadguys.com", "HTTPS"): NODATA,
            (None, "internetbadguys.com", "TXT"): NODATA,
            (None, "internetbadguys.com", "MX"): NODATA,
            (None, "exampleadultsite.com", "AAAA"): ok("::ffff:9270:3d6a"),
            (None, "exampleadultsite.com", "TXT"): {"rcode": "NOERROR", "txt": [["v=spf1 -all"]]},
            (None, "malware.testcategory.com", "AAAA"): ok("::", ede=[(16, "")]),
        }
        ctx = context(table)
        vendors = ck.check_vendor_tests(ctx)
        self.assertEqual(vendors.status, "info")
        self.assertIn("Blocked 3 of", vendors.summary)
        self.assertIn("Cloudflare (malware)", vendors.summary)
        cross = ck.check_cross_type(ctx)
        self.assertEqual(cross.status, "pass", "a content name's TXT record is not a tunnel worth flagging")

    def test_an_https_leak_on_a_blocked_name_fails(self) -> None:
        table = {
            (None, "isitblocked.org", "A"): NX,
            (None, "isitblocked.org", "HTTPS"): ok("192.0.2.7"),
        }
        ctx = context(table)
        ck.check_vendor_tests(ctx)
        result = ck.check_cross_type(ctx)
        self.assertEqual(result.status, "fail")
        self.assertIn("isitblocked.org HTTPS", result.summary)

    def test_txt_data_for_a_blocked_malware_name_is_a_warning(self) -> None:
        table = {
            (None, "isitblocked.org", "A"): NX,
            (None, "isitblocked.org", "TXT"): {"rcode": "NOERROR", "txt": [["exfil"]]},
        }
        ctx = context(table)
        ck.check_vendor_tests(ctx)
        self.assertEqual(ck.check_cross_type(ctx).status, "warn")

    def test_nothing_blocked_skips_the_cross_type_check(self) -> None:
        self.assertEqual(ck.check_cross_type(context({})).status, "skip")


class TestIdentity(unittest.TestCase):
    def test_identity_reads_nsid_egress_subnet_and_version(self) -> None:
        table = {
            (None, "example.com", "A"): ok("198.51.100.1", nsid="res715.ord"),
            (None, "whoami.ds.akahelp.net", "TXT"): {"rcode": "NOERROR", "txt": [["ns", "192.0.2.53"], ["ecs", "203.0.113.0/24/24"]]},
            (None, "version.bind", "TXT"): {"rcode": "NOERROR", "txt": [["Q9-P-2026080500"]]},
        }
        result = ck.check_identity(context(table))
        self.assertEqual(result.status, "info")
        self.assertIn("res715.ord", result.summary)
        self.assertIn("192.0.2.53", result.summary)
        self.assertIn("203.0.113.0/24", result.summary)
        self.assertNotIn("/24/24", result.summary)
        self.assertIn("Q9-P-2026080500", result.summary)

    def test_a_silent_target_is_an_error_not_a_pass(self) -> None:
        self.assertEqual(ck.check_identity(context({})).status, "error")


class TestRunner(unittest.TestCase):
    def test_network_checks_can_be_left_out_and_a_crash_is_contained(self) -> None:
        ctx = context({}, network=False)
        ids = [r.id for r in ck.run_checks(ctx)]
        self.assertNotIn("interception", ids)
        self.assertIn("dnssec", ids)

        def broken(_ctx):
            raise RuntimeError("boom")

        original = ck.CHECKS
        try:
            ck.CHECKS = (("broken", broken, False),)
            result = ck.run_checks(ctx)[0]
        finally:
            ck.CHECKS = original
        self.assertEqual(result.status, "error")
        self.assertIn("boom", result.summary)

    def test_summary_names_the_worst_status(self) -> None:
        results = [ck.CheckResult("a", "g", "t", "pass", ""), ck.CheckResult("b", "g", "t", "warn", "")]
        summary = ck.summarise(results)
        self.assertEqual(summary["worst"], "warn")
        self.assertEqual(summary["counts"]["pass"], 1)


class TestAgainstTheMock(unittest.TestCase):
    """The whole battery through the dashboard API, against the mock appliance with
    Umbrella's test names on its block list.  No public resolver is contacted."""

    def test_the_dashboard_runs_the_checks_and_refuses_overlap(self) -> None:
        mock = MockAppliance(
            scenario="good", blocklist={"internetbadguys.com", "isitblocked.org"}, latency_ms=0.0, jitter_ms=0.0, port=0
        ).start()
        self.addCleanup(mock.stop)
        http, controller = serve(
            RunConfig(server=mock.host, port=mock.port), synthetic_catalogue(), port=0, autostart=False,
            log=lambda message: None,
        )
        self.addCleanup(http.server_close)
        self.addCleanup(http.shutdown)

        started = controller.start_checks({"network": False})
        self.assertTrue(started["ok"], started)
        self.assertFalse(controller.start_checks({"network": False})["ok"], "a second run must be refused")
        self.assertFalse(controller.start({})["ok"], "a load run must wait for the checks")
        deadline = time.time() + 60
        while controller.checks_payload()["state"] == "running" and time.time() < deadline:
            time.sleep(0.1)
        payload = controller.checks_payload()
        self.assertEqual(payload["state"], "done")
        by_id = {r["id"]: r for r in payload["results"]}
        self.assertNotIn("interception", by_id)
        self.assertIn("mock-1", by_id["identity"]["summary"])
        self.assertIn("Blocked 2 of", by_id["vendor-tests"]["summary"])
        self.assertEqual(by_id["cross-type"]["status"], "pass")
        self.assertTrue(by_id["vendor-tests"]["evidence"])

    def test_the_command_prints_json(self) -> None:
        mock = MockAppliance(scenario="good", latency_ms=0.0, jitter_ms=0.0, port=0).start()
        self.addCleanup(mock.stop)
        buffer = io.StringIO()
        args = cli.build_parser().parse_args(
            ["checks", "--server", mock.host, "--port", str(mock.port), "--no-network", "--only", "dnssec", "--json"]
        )
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(cli.cmd_checks(args), 0)
        report = json.loads(buffer.getvalue())
        self.assertEqual([c["id"] for c in report["checks"]], ["dnssec"])
        # The mock does not validate DNSSEC: the deliberately broken zone resolves.
        self.assertEqual(report["checks"][0]["status"], "warn")


if __name__ == "__main__":
    unittest.main()
