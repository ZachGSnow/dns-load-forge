"""Named targets, per-target scoring, comparison runs, dashboard request screening
and domain-source management.

The scoring tests exist because of a measured defect: against OpenDNS the tool
reported a block as a false negative (OpenDNS answers a blocked name with an address
on its block page, not NXDOMAIN) and reported ordinary NXDOMAINs for reverse-DNS and
``corp.local`` names as false positives.  Both made a healthy public filter read as
broken.
"""

from __future__ import annotations

import http.client
import json
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge import cli, domainlist, server as server_module  # noqa: E402
from dnsloadforge.compare import format_comparison, summarise_run  # noqa: E402
from dnsloadforge.domainlist import DomainCatalogue, DomainPool  # noqa: E402
from dnsloadforge.engine import classify  # noqa: E402
from dnsloadforge.mockappliance import MockAppliance  # noqa: E402
from dnsloadforge.server import RunController, serve  # noqa: E402
from dnsloadforge.spec import Category, Outcome, RunConfig, SinkholeSet  # noqa: E402
from dnsloadforge.stats import StatsAggregator  # noqa: E402
from dnsloadforge.targets import (  # noqa: E402
    BUILTIN_TARGETS,
    Target,
    adhoc_target,
    find_target,
    load_targets,
    public_target_problem,
)


def synthetic_catalogue(per_category: int = 40) -> DomainCatalogue:
    pools = {category.value: DomainPool(category.value) for category in Category}
    for category in Category:
        domains = [f"{index:03d}.{category.value.replace('_', '-')}.example.com" for index in range(per_category)]
        pools[category.value] = DomainPool(category.value, domains=domains, weights=[1.0] * len(domains))
    return DomainCatalogue(pools=pools, fetched_at=0.0, offline=True)


# ---------------------------------------------------------------------------
# target model
# ---------------------------------------------------------------------------


class TestTargetValidation(unittest.TestCase):
    def test_a_minimal_target_is_valid_and_defaults_to_an_appliance(self) -> None:
        target = Target(name="Lab filter", server="10.0.0.10")
        self.assertEqual(target.port, 53)
        self.assertEqual(target.kind, "appliance")
        self.assertFalse(target.is_public)

    def test_rejects_bad_input_with_a_clear_message(self) -> None:
        bad = [
            dict(name="", server="10.0.0.1"),
            dict(name="x", server=""),
            dict(name="x", server="not an address!"),
            dict(name="x", server="10.0.0.1", port=0),
            dict(name="x", server="10.0.0.1", port=70000),
            dict(name="x", server="10.0.0.1", kind="cloud"),
            dict(name="x", server="10.0.0.1", blocks=["block_ads", "block_nothing"]),
            dict(name="x", server="10.0.0.1", sinkhole_ips=["nope"]),
            dict(name="x", server="10.0.0.1", sinkhole_cidrs=["10.0.0.0/99"]),
        ]
        for fields in bad:
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    Target(**fields)

    def test_from_dict_rejects_non_objects_and_bad_block_lists(self) -> None:
        with self.assertRaises(ValueError):
            Target.from_dict("not an object")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            Target.from_dict({"name": "x", "server": "10.0.0.1", "blocks": "block_ads"})


class TestTargetScoring(unittest.TestCase):
    def test_all_block_categories_is_the_default(self) -> None:
        self.assertEqual(Target(name="x", server="10.0.0.1").expectations(), {})

    def test_categories_a_target_does_not_block_become_unjudged(self) -> None:
        target = Target(name="x", server="10.0.0.1", blocks=["block_adult", "block_malware"])
        self.assertEqual(
            target.expectations(),
            {"block_ads": "unknown", "block_phishing": "unknown"},
        )

    def test_a_baseline_target_expects_nothing_to_be_blocked(self) -> None:
        target = Target(name="x", server="10.0.0.1", blocks=[])
        self.assertEqual(set(target.expectations().values()), {"unknown"})
        self.assertEqual(len(target.expectations()), 4)

    def test_apply_aims_and_scores_a_copy_without_touching_the_original(self) -> None:
        base = RunConfig(server="1.2.3.4", target_qps=250.0, seed=9)
        target = Target(
            name="Cloud", server="9.9.9.9", port=5353, kind="public",
            blocks=["block_malware"], sinkhole_ips=["10.9.9.9"], sinkhole_cidrs=["146.112.61.0/24"],
        )
        run = target.apply(base)
        self.assertEqual((run.server, run.port, run.target_name), ("9.9.9.9", 5353, "Cloud"))
        self.assertEqual(run.target_qps, 250.0)
        self.assertEqual(run.seed, 9)
        self.assertTrue(run.ignore_internal)
        self.assertEqual(run.expect_for("block_ads"), "unknown")
        self.assertEqual(run.expect_for("block_malware"), "block")
        self.assertIn("10.9.9.9", run.sinkhole_ips)
        self.assertEqual(run.sinkhole_cidrs, ("146.112.61.0/24",))
        self.assertEqual(base.server, "1.2.3.4")
        self.assertFalse(base.ignore_internal)


class TestBuiltinPresets(unittest.TestCase):
    def test_every_preset_is_valid_and_uniquely_named(self) -> None:
        names = [t.name.lower() for t in BUILTIN_TARGETS]
        self.assertEqual(len(names), len(set(names)))
        for target in BUILTIN_TARGETS:
            target.validate()
            self.assertTrue(target.builtin)

    def test_opendns_is_recognised_by_its_block_page_network(self) -> None:
        opendns = find_target("OpenDNS FamilyShield", list(BUILTIN_TARGETS))
        self.assertIn("146.112.61.0/24", opendns.sinkhole_cidrs)
        self.assertNotIn("block_ads", opendns.blocks or [])


class TestTargetLoading(unittest.TestCase):
    def write(self, text: str) -> str:
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        handle.write(text)
        handle.close()
        self.addCleanup(pathlib.Path(handle.name).unlink, missing_ok=True)
        return handle.name

    def test_file_targets_join_the_presets_and_can_replace_one(self) -> None:
        path = self.write(json.dumps({"targets": [
            {"name": "Office filter", "server": "10.1.1.5"},
            {"name": "quad9", "server": "9.9.9.10", "kind": "public", "blocks": ["block_malware"]},
        ]}))
        targets = load_targets(path)
        by_name = {t.name.lower(): t for t in targets}
        self.assertEqual(by_name["office filter"].server, "10.1.1.5")
        self.assertEqual(by_name["quad9"].server, "9.9.9.10", "a file entry replaces the preset of that name")
        self.assertIn("opendns familyshield", by_name)

    def test_a_missing_explicit_file_is_an_error_not_a_silent_fallback(self) -> None:
        with self.assertRaises(ValueError):
            load_targets("definitely-not-here.json")

    def test_malformed_files_are_reported(self) -> None:
        for text in ("{not json", json.dumps({"targets": "nope"}), json.dumps([{"name": "x"}])):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    load_targets(self.write(text))

    def test_lookup_is_case_insensitive_and_accepts_an_unambiguous_fragment(self) -> None:
        targets = list(BUILTIN_TARGETS)
        self.assertEqual(find_target("cloudflare security", targets).server, "1.1.1.2")
        self.assertEqual(find_target("familyshield", targets).server, "208.67.222.123")
        with self.assertRaises(ValueError):
            find_target("cloudflare", targets)  # two matches
        with self.assertRaises(ValueError):
            find_target("nothing like it", targets)


class TestPublicTargetGuard(unittest.TestCase):
    def test_a_public_target_is_refused_above_the_limit_unless_overridden(self) -> None:
        cloud = Target(name="Cloud", server="1.1.1.2", kind="public")
        self.assertTrue(public_target_problem(cloud, 500.0, allow=False))
        self.assertEqual(public_target_problem(cloud, 500.0, allow=True), "")
        self.assertEqual(public_target_problem(cloud, 100.0, allow=False), "")

    def test_an_appliance_is_never_refused(self) -> None:
        self.assertEqual(public_target_problem(Target(name="x", server="10.0.0.1"), 50_000.0, allow=False), "")


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


class TestSinkholeSet(unittest.TestCase):
    def test_matches_exact_addresses_and_networks(self) -> None:
        sinks = SinkholeSet(["0.0.0.0"], ["146.112.61.0/24"])
        self.assertIn("0.0.0.0", sinks)
        self.assertIn("146.112.61.106", sinks)
        self.assertNotIn("146.112.62.1", sinks)
        self.assertNotIn("8.8.8.8", sinks)

    def test_garbage_and_family_mismatches_do_not_match_or_raise(self) -> None:
        sinks = SinkholeSet([], ["146.112.61.0/24", "2001:db8::/32"])
        self.assertNotIn("not-an-ip", sinks)
        self.assertNotIn("", sinks)
        self.assertNotIn("2001:4860::1", sinks)
        self.assertIn("2001:db8::1", sinks)


class TestScoringRules(unittest.TestCase):
    SINK = SinkholeSet(["0.0.0.0"], ["146.112.61.0/24"])

    def test_an_opendns_block_page_answer_is_a_block_not_a_leak(self) -> None:
        outcome, _ = classify(Category.BLOCK_MALWARE.value, "NOERROR", ["146.112.61.106"], self.SINK)
        self.assertEqual(outcome, Outcome.BLOCKED.value)

    def test_without_the_network_the_same_answer_is_still_a_leak(self) -> None:
        outcome, _ = classify(Category.BLOCK_MALWARE.value, "NOERROR", ["146.112.61.106"], SinkholeSet(["0.0.0.0"]))
        self.assertEqual(outcome, Outcome.FALSE_NEGATIVE.value)

    def test_a_block_page_answer_for_an_allowed_name_is_a_false_positive(self) -> None:
        outcome, _ = classify(Category.ALLOW_POPULAR.value, "NOERROR", ["146.112.61.104"], self.SINK)
        self.assertEqual(outcome, Outcome.FALSE_POSITIVE.value)

    def test_nxdomain_for_a_reverse_lookup_is_never_a_finding(self) -> None:
        for ignore_internal in (False, True):
            with self.subTest(ignore_internal=ignore_internal):
                outcome, _ = classify(
                    Category.ALLOW_POPULAR.value, "NXDOMAIN", [], self.SINK,
                    qname="125.217.23.in-addr.arpa", ignore_internal=ignore_internal,
                )
                self.assertEqual(outcome, Outcome.NXDOMAIN.value)

    def test_internal_names_are_only_excused_when_the_target_is_public(self) -> None:
        name = "_kerberos._tcp.corp.local"
        appliance, _ = classify(Category.ENTERPRISE.value, "NXDOMAIN", [], self.SINK, qname=name)
        public, _ = classify(Category.ENTERPRISE.value, "NXDOMAIN", [], self.SINK, qname=name, ignore_internal=True)
        self.assertEqual(appliance, Outcome.FALSE_POSITIVE.value, "an appliance in front of AD must resolve it")
        self.assertEqual(public, Outcome.NXDOMAIN.value)

    def test_ordinary_names_are_still_false_positives_on_a_public_target(self) -> None:
        outcome, _ = classify(
            Category.ENTERPRISE.value, "NXDOMAIN", [], self.SINK,
            qname="login.microsoftonline.com", ignore_internal=True,
        )
        self.assertEqual(outcome, Outcome.FALSE_POSITIVE.value)

    def test_refused_for_an_internal_name_is_still_reported(self) -> None:
        outcome, _ = classify(
            Category.ENTERPRISE.value, "REFUSED", [], self.SINK, qname="dc01.corp.local", ignore_internal=True
        )
        self.assertEqual(outcome, Outcome.FALSE_POSITIVE.value)

    def test_a_category_expected_to_be_unjudged_never_yields_a_leak(self) -> None:
        outcome, _ = classify(Category.BLOCK_ADS.value, "NOERROR", ["5.6.7.8"], self.SINK, "unknown")
        self.assertEqual(outcome, Outcome.ALLOWED.value)


class TestVerdictFollowsTheTarget(unittest.TestCase):
    def feed(self, stats: StatsAggregator, category: str, outcome: str, count: int, rcode: str = "NOERROR") -> None:
        for index in range(count):
            stats.on_send(1)
            stats.on_result(
                qname=f"d{index}.example.com", client_ip="10.0.0.1", category=category, qtype="A",
                rcode=rcode, outcome=outcome, latency_ms=5.0,
            )

    def test_an_unfiltered_baseline_is_not_called_filtering(self) -> None:
        stats = StatsAggregator()
        stats.set_expectations(Target(name="x", server="8.8.8.8", blocks=[]).expectations())
        self.feed(stats, Category.ALLOW_POPULAR.value, Outcome.ALLOWED.value, 300)
        self.assertEqual(stats.snapshot()["verdict"]["status"], "baseline")

    def test_leaks_in_categories_the_target_does_not_block_do_not_trigger_passthrough(self) -> None:
        stats = StatsAggregator()
        stats.set_expectations(Target(name="x", server="1.1.1.2", blocks=["block_malware"]).expectations())
        self.feed(stats, Category.ALLOW_POPULAR.value, Outcome.ALLOWED.value, 300)
        self.feed(stats, Category.BLOCK_MALWARE.value, Outcome.BLOCKED.value, 300, rcode="NXDOMAIN")
        # 400 ad lookups resolved: a family-safe resolver is not meant to block ads.
        self.feed(stats, Category.BLOCK_ADS.value, Outcome.ALLOWED.value, 400)
        snapshot = stats.snapshot()
        self.assertEqual(snapshot["verdict"]["status"], "filtering")
        ads = next(row for row in snapshot["by_category"] if row["category"] == "block_ads")
        self.assertEqual(ads["expect"], "unknown")

    def test_the_default_expectations_still_flag_passthrough(self) -> None:
        stats = StatsAggregator()
        self.feed(stats, Category.BLOCK_ADS.value, Outcome.FALSE_NEGATIVE.value, 400)
        self.assertEqual(stats.snapshot()["verdict"]["status"], "passthrough")


# ---------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------


class TestComparisonRun(unittest.TestCase):
    """Two real mock appliances, one honest and one not enforcing, compared through
    the controller exactly as the dashboard does it."""

    def setUp(self) -> None:
        self.catalogue = synthetic_catalogue()
        blocked = self.catalogue.blocked_domains()
        self.good = MockAppliance(scenario="good", blocklist=blocked, latency_ms=0.05, jitter_ms=0.0, port=0, quiet=True)
        self.lax = MockAppliance(scenario="passthrough", blocklist=blocked, latency_ms=0.05, jitter_ms=0.0, port=0, quiet=True)
        for appliance in (self.good, self.lax):
            appliance.start()
            self.addCleanup(appliance.stop)
        self.targets = [
            Target(name="Honest filter", server=self.good.host, port=self.good.port),
            Target(name="Lax filter", server=self.lax.host, port=self.lax.port),
        ]
        base = RunConfig(personas=200, target_qps=800.0, duration_s=2.0, timeout_s=0.4, seed=5)
        self.controller = RunController(
            self.targets[0].apply(base), self.catalogue, targets=self.targets, log=lambda message: None
        )

    def test_the_same_traffic_is_sent_to_each_target_and_the_difference_is_visible(self) -> None:
        with mock.patch.object(server_module, "COMPARE_COOLDOWN_S", 0.1):
            result = self.controller.start({"targets": ["Honest filter", "Lax filter"]})
            self.assertTrue(result["ok"], result)
            self.assertTrue(self.controller.wait(timeout=60))

        history = self.controller.history_payload()["runs"]
        self.assertEqual([run["target"] for run in history], ["Honest filter", "Lax filter"])
        honest, lax = history
        self.assertGreater(honest["blocked"], 20, "the honest filter should have blocked bad names")
        self.assertEqual(honest["block_rate"], 1.0)
        # A filter that is not enforcing still scores a little: an empty answer to a
        # non-address lookup (HTTPS, TXT) is counted as a block by design.
        self.assertLess(lax["block_rate"], 0.25)
        self.assertGreater(honest["block_rate"] - lax["block_rate"], 0.6)
        self.assertGreater(lax["leaked"], 20)
        self.assertEqual(honest["verdict"], "filtering")
        # A short run may not send the 200 block-listed queries the passthrough verdict
        # needs; what matters is that the lax filter is never called healthy.
        self.assertIn(lax["verdict"], ("passthrough", "degraded"))
        self.assertEqual(honest["seed"], lax["seed"])
        self.assertAlmostEqual(honest["sent"] / lax["sent"], 1.0, delta=0.15)

        table = format_comparison(history)
        self.assertIn("Honest filter", table)
        self.assertIn(lax["verdict"].upper(), table)

    def test_progress_is_reported_while_a_comparison_runs(self) -> None:
        with mock.patch.object(server_module, "COMPARE_COOLDOWN_S", 0.1):
            self.controller.start({"targets": ["Honest filter", "Lax filter"]})
            run = self.controller.snapshot()["run"]
            self.assertEqual((run["plan_index"], run["plan_total"]), (1, 2))
            self.assertEqual(run["target_name"], "Honest filter")
            self.assertTrue(self.controller.wait(timeout=60))

    def test_stopping_cancels_the_rest_of_the_comparison(self) -> None:
        with mock.patch.object(server_module, "COMPARE_COOLDOWN_S", 0.1):
            self.controller.config.duration_s = 30.0
            self.controller.start({"targets": ["Honest filter", "Lax filter"]})
            time.sleep(1.0)
            self.controller.stop()
            self.assertTrue(self.controller.wait(timeout=30))
        self.assertLessEqual(len(self.controller.history_payload()["runs"]), 1)

    def test_a_comparison_needs_a_finite_duration_and_known_targets(self) -> None:
        self.controller.config.duration_s = 0.0
        refused = self.controller.start({"targets": ["Honest filter", "Lax filter"]})
        self.assertFalse(refused["ok"])
        self.assertIn("duration", refused["message"])
        self.controller.config.duration_s = 2.0
        unknown = self.controller.start({"targets": ["Honest filter", "No such target"]})
        self.assertFalse(unknown["ok"])
        self.assertEqual(self.controller.state, "idle")

    def test_run_settings_from_the_browser_must_be_sane(self) -> None:
        for bad in (float("nan"), float("inf"), -5.0, 0.0, 1e12):
            with self.subTest(target_qps=bad):
                refused = self.controller.start({"target_qps": bad})
                self.assertFalse(refused["ok"])
                self.assertEqual(self.controller.state, "idle")
        self.assertEqual(self.controller.config.target_qps, 800.0, "a refused request must not change the config")

    def test_a_refused_request_leaves_every_setting_untouched(self) -> None:
        """One valid value beside an unknown target must not change the rate."""
        before = (self.controller.config.target_qps, self.controller.config.duration_s)
        refused = self.controller.start({"target_qps": 123.0, "duration_s": 7.0, "targets": ["No such target"]})
        self.assertFalse(refused["ok"])
        self.assertEqual((self.controller.config.target_qps, self.controller.config.duration_s), before)

    def test_a_zero_duration_means_until_stopped_and_is_accepted(self) -> None:
        self.controller.config.duration_s = 5.0
        self.controller._apply_overrides({"duration_s": 0})
        self.assertEqual(self.controller.config.duration_s, 0.0)

    def test_a_public_target_is_refused_above_the_limit_in_the_dashboard_path_too(self) -> None:
        self.controller.targets.append(Target(name="Cloud", server="1.1.1.2", kind="public"))
        refused = self.controller.start({"target": "Cloud"})
        self.assertFalse(refused["ok"])
        self.assertIn("public resolver", refused["message"])
        self.assertEqual(self.controller.state, "idle")

    def test_summaries_reduce_a_snapshot_to_comparable_numbers(self) -> None:
        stats = StatsAggregator()
        config = RunConfig(server="10.0.0.1", target_name="T", seed=3)
        for index in range(250):
            stats.on_send(1)
            stats.on_result(
                qname=f"d{index}.example.com", client_ip="c", category="block_ads", qtype="A",
                rcode="NXDOMAIN" if index % 5 else "NOERROR",
                outcome="blocked" if index % 5 else "false_negative", latency_ms=4.0,
            )
        summary = summarise_run(stats.snapshot(), config, index=1)
        self.assertEqual(summary["target"], "T")
        self.assertEqual(summary["blocked"], 200)
        self.assertEqual(summary["leaked"], 50)
        self.assertAlmostEqual(summary["block_rate"], 0.8)
        self.assertIsNone(summary["false_block_rate"], "no allowed traffic was sent, so there is no rate")


# ---------------------------------------------------------------------------
# dashboard request screening
# ---------------------------------------------------------------------------


class TestDashboardScreening(unittest.TestCase):
    """The dashboard can start load tests, so a web page open in another tab must not
    be able to drive it, either directly (cross-site) or via DNS rebinding."""

    def setUp(self) -> None:
        self.http, self.controller = serve(
            RunConfig(server="127.0.0.1", port=9), synthetic_catalogue(), port=0, autostart=False,
            log=lambda message: None,
        )
        # Cleanups run last-in first: stop serving before closing the socket.
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        self.port = self.http.server_address[1]

    def request(self, method: str, path: str, body: dict | None = None, headers: dict | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            payload = json.dumps(body) if body is not None else None
            merged = {"Content-Type": "application/json"} if payload is not None else {}
            merged.update(headers or {})
            connection.request(method, path, body=payload, headers=merged)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def same_origin(self) -> dict:
        return {"Origin": f"http://127.0.0.1:{self.port}"}

    def test_a_normal_same_origin_request_is_served(self) -> None:
        status, body = self.request("POST", "/api/control", {"action": "stop"}, self.same_origin())
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"], "nothing is running, so stop is a harmless no-op")

    def test_requests_without_an_origin_header_work_for_scripts_and_curl(self) -> None:
        status, _ = self.request("POST", "/api/control", {"action": "stop"})
        self.assertEqual(status, 200)

    def test_a_cross_origin_post_is_refused(self) -> None:
        status, _ = self.request("POST", "/api/control", {"action": "start"}, {"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(self.controller.state, "idle")

    def test_a_cross_site_fetch_is_refused_by_its_fetch_metadata(self) -> None:
        status, _ = self.request("POST", "/api/control", {"action": "start"}, {"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)

    def test_a_form_post_is_refused_because_it_is_not_json(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request("POST", "/api/control", body='{"action":"start"}', headers={"Content-Type": "text/plain"})
            self.assertEqual(connection.getresponse().status, 415)
        finally:
            connection.close()
        self.assertEqual(self.controller.state, "idle")

    def test_a_rebound_host_name_is_refused_for_reads_and_writes(self) -> None:
        for method, body in (("GET", None), ("POST", {"action": "stop"})):
            with self.subTest(method=method):
                status, _ = self.request(method, "/api/stats", body, {"Host": "evil.example"})
                self.assertEqual(status, 421)

    def test_localhost_by_name_is_accepted(self) -> None:
        status, _ = self.request("GET", "/api/health", headers={"Host": f"localhost:{self.port}"})
        self.assertEqual(status, 200)

    def test_new_read_endpoints_answer(self) -> None:
        for path in ("/api/targets", "/api/history", "/api/sources", "/api/history/export.json"):
            with self.subTest(path=path):
                status, body = self.request("GET", path)
                self.assertEqual(status, 200)
                json.loads(body)

    def test_list_management_is_refused_politely_when_unavailable(self) -> None:
        status, body = self.request("POST", "/api/sources/refresh", {}, self.same_origin())
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["ok"])

    def test_bad_source_requests_get_a_400(self) -> None:
        status, _ = self.request("POST", "/api/sources/enabled", {"slug": 5, "enabled": "yes"}, self.same_origin())
        self.assertEqual(status, 400)
        status, _ = self.request("POST", "/api/sources/refresh", {"slugs": "all"}, self.same_origin())
        self.assertEqual(status, 400)


class TestRemoteDashboardGuard(unittest.TestCase):
    def test_binding_beyond_loopback_needs_an_explicit_flag(self) -> None:
        args = cli.build_parser().parse_args(["run", "--listen-host", "0.0.0.0"])
        with self.assertRaises(ValueError):
            cli.check_dashboard_bind(args)
        allowed = cli.build_parser().parse_args(["run", "--listen-host", "0.0.0.0", "--allow-remote-dashboard"])
        cli.check_dashboard_bind(allowed)
        cli.check_dashboard_bind(cli.build_parser().parse_args(["run"]))


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------


def parse(argv: list[str]):
    return cli.build_parser().parse_args(argv)


class TestCommandLineTargets(unittest.TestCase):
    def test_a_bare_server_is_an_ad_hoc_appliance_target(self) -> None:
        available, chosen = cli.resolve_targets(parse(["run", "--server", "10.0.0.10"]))
        self.assertEqual(chosen[0].server, "10.0.0.10")
        self.assertEqual(chosen[0].kind, "appliance")
        self.assertEqual(available[0].name, chosen[0].name, "the picker lists the target actually in use")

    def test_a_well_known_public_resolver_is_scored_as_public(self) -> None:
        _, chosen = cli.resolve_targets(parse(["run", "--server", "8.8.8.8"]))
        self.assertEqual(chosen[0].kind, "public")
        _, forced = cli.resolve_targets(parse(["run", "--server", "10.0.0.10", "--target-kind", "public"]))
        self.assertEqual(forced[0].kind, "public")

    def test_repeating_target_selects_several_in_order(self) -> None:
        _, chosen = cli.resolve_targets(parse(["run", "--target", "quad9", "--target", "familyshield"]))
        self.assertEqual([t.server for t in chosen], ["9.9.9.9", "208.67.222.123"])

    def test_server_and_target_together_are_ambiguous(self) -> None:
        with self.assertRaises(ValueError):
            cli.resolve_targets(parse(["run", "--server", "10.0.0.1", "--target", "quad9"]))

    def test_build_config_carries_the_targets_scoring_rules(self) -> None:
        _, chosen = cli.resolve_targets(parse(["run", "--target", "familyshield"]))
        config = cli.build_config(parse(["run", "--target", "familyshield"]), chosen[0])
        self.assertEqual(config.server, "208.67.222.123")
        self.assertTrue(config.ignore_internal)
        self.assertEqual(config.expect_for("block_ads"), "unknown")
        self.assertIn("146.112.61.0/24", config.sinkhole_cidrs)

    def test_preflight_checks_every_target_in_a_comparison(self) -> None:
        args = parse(["run", "--target", "cloudflare security", "--target", "quad9", "--qps", "5000", "--mock"])
        # --mock suppresses the guard (the traffic never leaves the machine), so
        # compare against the same arguments without it.
        args.mock = False
        _, chosen = cli.resolve_targets(args)
        config = cli.build_config(args, chosen[0])
        with mock.patch.object(cli, "probe_reachable", return_value=True):
            problems = cli.preflight(config, synthetic_catalogue(), args, chosen)
        self.assertGreaterEqual(sum("public resolver" in p for p in problems), 1)

    def test_version_is_answered_by_the_top_level_parser_not_sent_to_run(self) -> None:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), self.assertRaises(SystemExit) as raised:
            cli.main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("DNS Load Forge", buffer.getvalue())

    def test_the_targets_command_lists_presets(self) -> None:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = cli.main(["targets"])
        self.assertEqual(code, 0)
        self.assertIn("OpenDNS FamilyShield", buffer.getvalue())
        self.assertIn("(none - baseline)", buffer.getvalue())

    def test_the_targets_command_has_machine_readable_output(self) -> None:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            cli.main(["targets", "--json"])
        data = json.loads(buffer.getvalue())
        self.assertTrue(any(item["name"] == "Quad9" for item in data))


# ---------------------------------------------------------------------------
# domain sources
# ---------------------------------------------------------------------------

SOURCE = {
    "slug": "test-ads", "category": "block_ads", "url": "http://lists.invalid/ads.txt",
    "format": "plain", "tier": "primary", "ranked": False, "description": "test list",
}


class SourceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = self.tmp.name
        patcher = mock.patch.object(domainlist, "load_sources", lambda *a, **k: [dict(SOURCE)])
        patcher.start()
        self.addCleanup(patcher.stop)


class TestSourceRefresh(SourceCase):
    def test_a_successful_fetch_is_reported_as_updated_and_cached(self) -> None:
        with mock.patch.object(domainlist, "fetch_url", return_value=(200, b"ads.example.org\ntrack.example.net\n", {"etag": "v1"})):
            result = domainlist.refresh_source("test-ads", self.cache)
        self.assertEqual((result["status"], result["count"], result["error"]), ("updated", 2, ""))
        row = domainlist.source_inventory(self.cache)[0]
        self.assertTrue(row["cached"])
        self.assertEqual(row["count"], 2)
        self.assertFalse(row["stale"])

    def test_not_modified_is_reported_as_unchanged(self) -> None:
        with mock.patch.object(domainlist, "fetch_url", return_value=(200, b"ads.example.org\n", {"etag": "v1"})):
            domainlist.refresh_source("test-ads", self.cache)
        with mock.patch.object(domainlist, "fetch_url", return_value=(304, b"", {})):
            result = domainlist.refresh_source("test-ads", self.cache)
        self.assertEqual(result["status"], "unchanged")
        self.assertEqual(result["count"], 1)

    def test_a_failed_fetch_keeps_the_cached_copy_and_says_why(self) -> None:
        with mock.patch.object(domainlist, "fetch_url", return_value=(200, b"ads.example.org\n", {})):
            domainlist.refresh_source("test-ads", self.cache)
        with mock.patch.object(domainlist, "fetch_url", side_effect=OSError("network unreachable")):
            result = domainlist.refresh_source("test-ads", self.cache)
        self.assertEqual(result["status"], "failed")
        self.assertIn("network unreachable", result["error"])
        self.assertEqual(result["count"], 1, "the earlier copy is still in use")

    def test_a_failure_with_nothing_cached_is_reported_not_raised(self) -> None:
        with mock.patch.object(domainlist, "fetch_url", side_effect=OSError("down")):
            result = domainlist.refresh_source("test-ads", self.cache)
        self.assertEqual((result["status"], result["count"]), ("failed", 0))

    def test_an_empty_download_does_not_wipe_the_cache(self) -> None:
        with mock.patch.object(domainlist, "fetch_url", return_value=(200, b"ads.example.org\n", {})):
            domainlist.refresh_source("test-ads", self.cache)
        with mock.patch.object(domainlist, "fetch_url", return_value=(200, b"# nothing here\n", {})):
            result = domainlist.refresh_source("test-ads", self.cache)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["count"], 1)

    def test_unknown_sources_raise(self) -> None:
        with self.assertRaises(KeyError):
            domainlist.refresh_source("nope", self.cache)


class TestSourceToggle(SourceCase):
    def prime(self) -> None:
        with mock.patch.object(domainlist, "fetch_url", return_value=(200, b"ads.example.org\n", {})):
            domainlist.refresh_source("test-ads", self.cache)

    def test_a_disabled_source_is_left_out_of_the_catalogue_and_survives_a_restart(self) -> None:
        self.prime()
        on = domainlist.load_catalogue(self.cache, offline=True)
        self.assertIn("ads.example.org", on.domains_for("block_ads"))

        domainlist.set_source_enabled("test-ads", False, self.cache)
        self.assertEqual(domainlist.read_disabled_sources(self.cache), {"test-ads"})
        self.assertFalse(domainlist.source_inventory(self.cache)[0]["enabled"])
        off = domainlist.load_catalogue(self.cache, offline=True)
        self.assertNotIn("ads.example.org", off.domains_for("block_ads"))

        domainlist.set_source_enabled("test-ads", True, self.cache)
        again = domainlist.load_catalogue(self.cache, offline=True)
        self.assertIn("ads.example.org", again.domains_for("block_ads"))

    def test_unknown_sources_are_rejected(self) -> None:
        with self.assertRaises(KeyError):
            domainlist.set_source_enabled("nope", False, self.cache)


class TestControllerListJobs(SourceCase):
    def make(self) -> RunController:
        loads: list[int] = []

        def loader() -> DomainCatalogue:
            loads.append(1)
            return synthetic_catalogue(10)

        self.loads = loads
        return RunController(
            RunConfig(server="127.0.0.1", port=9), synthetic_catalogue(),
            catalogue_loader=loader, cache_dir=self.cache, log=lambda message: None,
        )

    def wait_for_job(self, controller: RunController, timeout: float = 20.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = controller.sources_payload()["job"]
            if job["state"] in ("done", "error"):
                return job
            time.sleep(0.05)
        self.fail("the list job did not finish")

    def test_refreshing_updates_the_cache_then_swaps_in_a_rebuilt_catalogue(self) -> None:
        controller = self.make()
        before = controller.catalogue
        with mock.patch.object(domainlist, "fetch_url", return_value=(200, b"ads.example.org\n", {})):
            started = controller.refresh_sources()
            self.assertTrue(started["ok"], started)
            job = self.wait_for_job(controller)
        self.assertEqual(job["state"], "done")
        self.assertEqual([r["status"] for r in job["results"]], ["updated"])
        self.assertEqual(len(self.loads), 1)
        self.assertIsNot(controller.catalogue, before)

    def test_a_dead_source_is_reported_in_the_job_without_failing_it(self) -> None:
        controller = self.make()
        with mock.patch.object(domainlist, "fetch_url", side_effect=OSError("down")):
            controller.refresh_sources(["test-ads"])
            job = self.wait_for_job(controller)
        self.assertEqual(job["state"], "done")
        self.assertEqual(job["results"][0]["status"], "failed")

    def test_list_changes_are_refused_while_a_run_is_in_progress(self) -> None:
        controller = self.make()
        controller._state = "running"
        refused = controller.refresh_sources()
        self.assertFalse(refused["ok"])
        self.assertIn("stop the current run", refused["message"])
        self.assertFalse(controller.set_source_enabled("test-ads", False)["ok"])

    def test_a_run_is_refused_while_lists_are_updating(self) -> None:
        controller = self.make()
        controller._job = {"kind": "refresh", "state": "running"}
        refused = controller.start({})
        self.assertFalse(refused["ok"])
        self.assertIn("lists", refused["message"])

    def test_unknown_sources_are_rejected_up_front(self) -> None:
        controller = self.make()
        self.assertFalse(controller.refresh_sources(["nope"])["ok"])
        self.assertFalse(controller.set_source_enabled("nope", False)["ok"])

    def test_a_dashboard_without_a_loader_cannot_manage_lists(self) -> None:
        controller = RunController(RunConfig(), synthetic_catalogue(), cache_dir=self.cache, log=lambda m: None)
        self.assertFalse(controller.refresh_sources()["ok"])
        self.assertFalse(controller.sources_payload()["available"])


class TestCacheLocation(unittest.TestCase):
    def test_the_environment_override_wins(self) -> None:
        with mock.patch.dict("os.environ", {"DNSLOADFORGE_CACHE": "C:/somewhere/else"}):
            self.assertEqual(domainlist.default_cache_dir(), pathlib.Path("C:/somewhere/else"))

    def test_a_checkout_keeps_its_cache_beside_the_source(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop("DNSLOADFORGE_CACHE", None)
            self.assertEqual(domainlist.default_cache_dir().name, "cache")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
