"""End-to-end engine tests against the built-in mock appliance.

This is the layer that actually proves the tool works, because it exercises the
whole requested path: a simulated office sends real UDP, a resolver answers, and
the verdict is derived from what came back.  Every scenario the operator is meant
to be able to distinguish -- an honest filter, one that blocks nothing, one that
blocks too much, one that is dropping under load -- is asserted to produce a
*different* verdict, which is the only way to know the tool's headline output is
not just a constant string.

Runs are deliberately small (a few hundred queries, a couple of seconds).  The
mock answers on loopback with sub-millisecond latency, so a short run still yields
far more than the aggregator's minimum sample.
"""

from __future__ import annotations

import pathlib
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge.domainlist import DomainCatalogue, DomainPool  # noqa: E402
from dnsloadforge.engine import DnsLoadEngine, classify, run_threaded  # noqa: E402
from dnsloadforge.mockappliance import MockAppliance  # noqa: E402
from dnsloadforge.profiles import PersonaModel, _cdf  # noqa: E402
from dnsloadforge.spec import RCODE_ERROR, RCODE_TIMEOUT, Category, Outcome, RunConfig  # noqa: E402
from dnsloadforge.stats import RecordLog, StatsAggregator  # noqa: E402

BLOCK_CATEGORIES = (
    Category.BLOCK_ADS.value,
    Category.BLOCK_MALWARE.value,
    Category.BLOCK_PHISHING.value,
    Category.BLOCK_ADULT.value,
)
ALLOW_CATEGORIES = (
    Category.ALLOW_POPULAR.value,
    Category.ALLOW_LONGTAIL.value,
    Category.ENTERPRISE.value,
)


def synthetic_catalogue() -> DomainCatalogue:
    """Small, deterministic, and self-consistent: the block domains are exactly
    the ones the mock will be told to block, so a mismatch cannot be mistaken for
    a filter behaving badly."""
    pools: dict[str, DomainPool] = {}
    for category in Category:
        pools[category.value] = DomainPool(category=category.value, source="synthetic")
    for category in BLOCK_CATEGORIES + ALLOW_CATEGORIES + (Category.BORDERLINE.value,):
        domains = [f"d{index:03d}.{category.replace('_', '-')}.example.com" for index in range(30)]
        pools[category] = DomainPool(
            category=category, domains=domains, weights=[1.0] * len(domains), source="synthetic"
        )
    # A couple of enterprise breakage names of the kind that matter most.
    pools[Category.ENTERPRISE.value] = DomainPool(
        category=Category.ENTERPRISE.value,
        domains=[
            "login.microsoftonline.com",
            "outlook.office365.com",
            "windowsupdate.com",
            "_ldap._tcp.corp.local",
        ]
        + [f"host{index:02d}.corp.local" for index in range(20)],
        weights=[1.0] * 24,
        source="synthetic",
    )
    return DomainCatalogue(pools=pools, fetched_at=1.0, offline=True)


def mix_model(catalogue: DomainCatalogue, mix: dict[str, float], personas: int = 200) -> PersonaModel:
    """A model whose every persona draws from one specified category mix.

    The shipped role mixes are *realistic* -- block-listed lookups are a few percent
    of an office's traffic, because most traffic is legitimate -- which means a
    short test run would never reach the aggregator's 200-query minimum for the
    block categories.  Overriding the mix makes the verdicts reachable in seconds
    while leaving the code under test untouched.
    """
    model = PersonaModel(
        catalogue,
        personas=personas,
        source_ips=["127.0.0.1"],
        seed=11,
        roles=["knowledge_worker"],
        nxdomain_share=0.0,
    )
    cdf = _cdf(mix)
    for persona in model.personas:
        persona.cat_cdf = cdf
        # Disable the repeat set so the sampled mix is exactly the one requested.
        persona.hot = []
        persona.hot_cdf = ()
    return model


def block_heavy(catalogue: DomainCatalogue) -> PersonaModel:
    return mix_model(
        catalogue,
        {Category.BLOCK_ADS.value: 0.45, Category.BLOCK_MALWARE.value: 0.25, Category.ALLOW_POPULAR.value: 0.30},
    )


def allow_heavy(catalogue: DomainCatalogue) -> PersonaModel:
    return mix_model(
        catalogue,
        {Category.ENTERPRISE.value: 0.55, Category.ALLOW_POPULAR.value: 0.45},
    )


def config_for(appliance: MockAppliance, **overrides) -> RunConfig:
    params = dict(
        server=appliance.host,
        port=appliance.port,
        personas=200,
        target_qps=400.0,
        duration_s=3.0,
        timeout_s=0.4,
        seed=5,
    )
    params.update(overrides)
    return RunConfig(**params)


class TestClassifyTable(unittest.TestCase):
    """The classification matrix, asserted directly.  These are the rules the whole
    verdict rests on, so they are tested without a socket in sight."""

    SINK = frozenset({"0.0.0.0", "::"})

    def cases(self):
        return [
            # (category, rcode, answers, expected outcome)
            (Category.ALLOW_POPULAR.value, "NOERROR", ["1.2.3.4"], Outcome.ALLOWED.value),
            (Category.ALLOW_POPULAR.value, "NXDOMAIN", [], Outcome.FALSE_POSITIVE.value),
            (Category.ALLOW_POPULAR.value, "REFUSED", [], Outcome.FALSE_POSITIVE.value),
            (Category.ALLOW_POPULAR.value, "SERVFAIL", [], Outcome.FALSE_POSITIVE.value),
            (Category.ALLOW_POPULAR.value, "NOERROR", ["0.0.0.0"], Outcome.FALSE_POSITIVE.value),
            (Category.ENTERPRISE.value, "REFUSED", [], Outcome.FALSE_POSITIVE.value),
            (Category.BLOCK_ADS.value, "NXDOMAIN", [], Outcome.BLOCKED.value),
            (Category.BLOCK_ADS.value, "REFUSED", [], Outcome.BLOCKED.value),
            (Category.BLOCK_ADS.value, "NOERROR", ["0.0.0.0"], Outcome.BLOCKED.value),
            (Category.BLOCK_ADS.value, "NOERROR", [], Outcome.BLOCKED.value),
            (Category.BLOCK_MALWARE.value, "NOERROR", ["5.6.7.8"], Outcome.FALSE_NEGATIVE.value),
            (Category.BLOCK_PHISHING.value, "NOERROR", ["5.6.7.8"], Outcome.FALSE_NEGATIVE.value),
            (Category.NXDOMAIN_PROBE.value, "NXDOMAIN", [], Outcome.NXDOMAIN.value),
            (Category.NXDOMAIN_PROBE.value, "NOERROR", ["1.2.3.4"], Outcome.ALLOWED.value),
            (Category.BORDERLINE.value, "NOERROR", ["1.2.3.4"], Outcome.ALLOWED.value),
            # The grey-zone category must never be scored as a filter failure.
            (Category.BORDERLINE.value, "NXDOMAIN", [], Outcome.NXDOMAIN.value),
            (Category.BORDERLINE.value, "NOERROR", ["0.0.0.0"], Outcome.BLOCKED.value),
            (Category.BORDERLINE.value, "REFUSED", [], Outcome.ERROR.value),
        ]

    def test_matrix(self) -> None:
        for category, rcode, answers, expected in self.cases():
            with self.subTest(category=category, rcode=rcode, answers=answers):
                outcome, _answer = classify(category, rcode, answers, self.SINK)
                self.assertEqual(outcome, expected)

    def test_borderline_never_yields_fp_or_fn(self) -> None:
        for rcode in ("NOERROR", "NXDOMAIN", "REFUSED", "SERVFAIL", "FORMERR"):
            for answers in ([], ["1.2.3.4"], ["0.0.0.0"]):
                outcome, _ = classify(Category.BORDERLINE.value, rcode, answers, self.SINK)
                self.assertNotIn(outcome, (Outcome.FALSE_POSITIVE.value, Outcome.FALSE_NEGATIVE.value))

    def test_nodata_is_not_treated_as_a_block(self) -> None:
        """A name that exists without an address is a normal answer, not a block."""
        self.assertEqual(
            classify(Category.ALLOW_POPULAR.value, "NOERROR", [], self.SINK)[0], Outcome.ALLOWED.value
        )

    def test_nodata_on_a_blocklist_name_counts_as_blocked(self) -> None:
        """NOERROR with no records is how a sinkholing appliance blocks a query type
        it cannot put 0.0.0.0 into.  Treating it as a leak would flood the findings
        with noise from every non-address lookup and hide the real result."""
        self.assertEqual(
            classify(Category.BLOCK_ADS.value, "NOERROR", [], self.SINK)[0], Outcome.BLOCKED.value
        )

    def test_a_named_address_is_a_leak(self) -> None:
        """The unambiguous leak: a block-listed name handed back a usable address."""
        self.assertEqual(
            classify(Category.BLOCK_MALWARE.value, "NOERROR", ["5.6.7.8"], self.SINK)[0],
            Outcome.FALSE_NEGATIVE.value,
        )

    def test_answer_representation_is_kept_for_the_report(self) -> None:
        _outcome, answer = classify(Category.BLOCK_MALWARE.value, "NOERROR", ["5.6.7.8"], self.SINK)
        self.assertEqual(answer, "5.6.7.8")


class EndToEndCase(unittest.TestCase):
    def setUp(self) -> None:
        self.catalogue = synthetic_catalogue()
        self.blocked = self.catalogue.blocked_domains()

    def run_with_model(self, appliance: MockAppliance, model: PersonaModel, **overrides):
        """Run one engine shard with an injected model."""
        import asyncio

        stats = StatsAggregator()
        config = config_for(appliance, **overrides)
        engine = DnsLoadEngine(config, self.catalogue, stats=stats, model=model)
        result = asyncio.run(engine.run())
        return result, stats


class TestMockBaseline(unittest.TestCase):
    """The mock is the tool's own known-good baseline, so it must not manufacture
    findings.  Its DGA heuristic is the risk: no label heuristic can separate a
    machine-generated name from a legitimate hashed hostname, and an early version
    flagged 1.69% of the real popular list, which the dashboard correctly reported
    as false positives against a filter that had done nothing wrong."""

    def test_hashed_cdn_hostnames_and_real_names_are_left_alone(self) -> None:
        from dnsloadforge.mockappliance import _looks_like_dga

        for real in (
            "office365.com",
            "d1afz1hb3hiij6.cloudfront.net",
            "tombak118gas.org",
            "pulseadnetwork.com",
            "windowsupdate.com",
            "login.microsoftonline.com",
            "a1b2c3d4e5f6.s3.amazonaws.com",
            "2001-ipv6.example.com",
        ):
            with self.subTest(qname=real):
                self.assertFalse(_looks_like_dga(real))

    def test_genuine_junk_is_still_caught(self) -> None:
        from dnsloadforge.mockappliance import _looks_like_dga

        for junk in ("kq3vz9xm4pl2.com", "z9x8c7v6b5n4.top", "qqqqqqqqqqqqqqqq.com"):
            with self.subTest(qname=junk):
                self.assertTrue(_looks_like_dga(junk))

    def test_reserved_tlds_are_always_nxdomain_even_with_the_heuristic_off(self) -> None:
        """Reserved names are resolver correctness, not policy, so they must not be
        behind the opt-in switch -- the engine's probes depend on them."""
        appliance = MockAppliance(scenario="good", dga_nxdomain=False, latency_ms=0.0, jitter_ms=0.0, port=0)
        appliance.start()
        try:
            import socket as _socket

            from dnsloadforge import packets as pk

            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            try:
                for qname in ("kq3vz9xm4pl2.invalid", "something.test"):
                    query, _ = pk.encode_query(qname, "A")
                    sock.sendto(query, (appliance.host, appliance.port))
                    message = pk.decode_message(sock.recvfrom(4096)[0])
                    self.assertEqual(message.rcode_name, "NXDOMAIN", qname)
                # A real name is answered normally.
                query, _ = pk.encode_query("office365.com", "A")
                sock.sendto(query, (appliance.host, appliance.port))
                self.assertEqual(pk.decode_message(sock.recvfrom(4096)[0]).rcode_name, "NOERROR")
            finally:
                sock.close()
        finally:
            appliance.stop()


class TestVerdictsAgainstMock(EndToEndCase):
    def test_honest_filter_is_reported_as_filtering(self) -> None:
        appliance = MockAppliance(scenario="good", blocklist=self.blocked, latency_ms=0.05, jitter_ms=0.0, port=0)
        appliance.start()
        try:
            result, stats = self.run_with_model(appliance, block_heavy(self.catalogue))
        finally:
            appliance.stop()

        snapshot = stats.snapshot()
        outcomes = snapshot["outcomes"]
        self.assertGreater(result.sent, 500)
        self.assertGreater(outcomes["blocked"], 200, "the filter should have blocked a lot of bad names")
        self.assertGreater(outcomes["allowed"], 50)
        self.assertEqual(outcomes["false_positive"], 0)
        self.assertEqual(outcomes["false_negative"], 0)
        self.assertEqual(result.verdict["status"], "filtering")
        # And it really did talk to the appliance.
        self.assertGreaterEqual(appliance.stats["received"], result.sent)

    def test_an_honest_filter_scores_no_findings_under_a_realistic_mix(self) -> None:
        """The most important regression test in the suite.

        Every other verdict test overrides the persona mix so the verdict is
        reachable in seconds.  This one deliberately does not: it uses the shipped
        role mixes with the repeat-set behaviour enabled, which is the path 70% of
        real queries take.  A mis-attributed category anywhere on that path makes an
        appliance that behaved perfectly look like it is blocking legitimate traffic,
        and that is a finding an operator would escalate.
        """
        appliance = MockAppliance(
            scenario="good", blocklist=self.blocked, latency_ms=0.05, jitter_ms=0.0, port=0
        )
        appliance.start()
        try:
            model = PersonaModel(
                self.catalogue, personas=400, source_ips=["127.0.0.1"], seed=17
            )
            result, stats = self.run_with_model(
                appliance, model, target_qps=500.0, duration_s=5.0
            )
        finally:
            appliance.stop()

        snapshot = stats.snapshot()
        self.assertGreater(result.sent, 1500)
        self.assertEqual(snapshot["outcomes"]["false_positive"], 0, snapshot["false_positives"][:3])
        self.assertEqual(snapshot["outcomes"]["false_negative"], 0, snapshot["false_negatives"][:3])
        self.assertEqual(snapshot["outcomes"]["timeout"], 0)
        self.assertGreater(snapshot["outcomes"]["blocked"], 0, "the filter does block some bad names")
        self.assertGreater(snapshot["outcomes"]["allowed"], 500)
        self.assertEqual(result.verdict["status"], "filtering")

    def test_passthrough_filter_is_reported_as_passthrough(self) -> None:
        """The most common real finding: deployed, but not enforcing."""
        appliance = MockAppliance(
            scenario="passthrough", blocklist=self.blocked, latency_ms=0.05, jitter_ms=0.0, port=0
        )
        appliance.start()
        try:
            result, stats = self.run_with_model(appliance, block_heavy(self.catalogue))
        finally:
            appliance.stop()
        snapshot = stats.snapshot()
        self.assertEqual(result.verdict["status"], "passthrough")
        # The point of the finding: nearly all bad traffic resolved.  A handful may
        # still show as blocked (a sinkholing resolver cannot answer every query
        # type), which is exactly why passthrough is decided on a rate.
        blocked = snapshot["outcomes"]["blocked"]
        block_sent = sum(r["sent"] for r in snapshot["by_category"] if r["expect"] == "block")
        self.assertLess(blocked / block_sent, 0.20)
        self.assertGreater(snapshot["outcomes"]["false_negative"], 200)
        self.assertIn("Not filtering", result.verdict["note"])

    def test_overblocking_is_reported_as_false_positives(self) -> None:
        """The failure that costs money: a legitimate name that will not resolve."""
        # Overblock the *whole* enterprise list, not a few names: a filter that
        # blocks one sign-in endpoint is a ticket, one that blocks all of them is
        # an outage, and that is the finding being exercised here.
        appliance = MockAppliance(
            scenario="overblocker",
            blocklist=self.blocked,
            overblock_extra=set(self.catalogue.domains_for(Category.ENTERPRISE.value)),
            latency_ms=0.05,
            jitter_ms=0.0,
            port=0,
        )
        appliance.start()
        try:
            result, stats = self.run_with_model(appliance, allow_heavy(self.catalogue))
        finally:
            appliance.stop()

        snapshot = stats.snapshot()
        self.assertEqual(result.verdict["status"], "degraded")
        self.assertIn("Blocking legitimate traffic", result.verdict["note"])
        self.assertGreater(snapshot["outcomes"]["false_positive"], 200)
        named = {row["qname"] for row in snapshot["false_positives"]}
        self.assertIn("login.microsoftonline.com", named)
        row = next(r for r in snapshot["false_positives"] if r["qname"] == "login.microsoftonline.com")
        self.assertEqual(row["category"], Category.ENTERPRISE.value)
        self.assertEqual(row["rcode"], "NXDOMAIN")
        self.assertEqual(row["count"], row["count"])  # counted, not just listed
        self.assertGreaterEqual(row["count"], 1)

    def test_refused_everything_breaks_allowlisted_traffic(self) -> None:
        appliance = MockAppliance(
            scenario="refused", blocklist=self.blocked, latency_ms=0.05, jitter_ms=0.0, port=0
        )
        appliance.start()
        try:
            result, stats = self.run_with_model(appliance, allow_heavy(self.catalogue))
        finally:
            appliance.stop()
        self.assertEqual(result.verdict["status"], "degraded")
        self.assertGreater(stats.snapshot()["outcomes"]["false_positive"], 200)
        self.assertGreater(stats.snapshot()["rcodes"]["REFUSED"], 200)

    def test_sinkhole_mode_is_classified_as_blocked(self) -> None:
        """Some appliances answer 0.0.0.0 instead of NXDOMAIN; that is still a block."""
        appliance = MockAppliance(
            scenario="good",
            blocklist=self.blocked,
            block_mode="sinkhole",
            sinkhole_ip="0.0.0.0",
            latency_ms=0.05,
            jitter_ms=0.0,
            port=0,
        )
        appliance.start()
        try:
            result, stats = self.run_with_model(appliance, block_heavy(self.catalogue))
        finally:
            appliance.stop()
        snapshot = stats.snapshot()
        self.assertGreater(snapshot["outcomes"]["blocked"], 200)
        self.assertEqual(snapshot["outcomes"]["false_positive"], 0)
        self.assertEqual(result.verdict["status"], "filtering")

    def test_dropping_under_load_is_reported_as_degraded(self) -> None:
        appliance = MockAppliance(
            scenario="lossy", blocklist=self.blocked, drop_rate=1.0, latency_ms=0.0, jitter_ms=0.0, port=0
        )
        appliance.start()
        try:
            result, stats = self.run_with_model(appliance, block_heavy(self.catalogue))
        finally:
            appliance.stop()
        self.assertEqual(result.received, 0)
        self.assertGreater(result.timeouts, 0)
        self.assertEqual(result.verdict["status"], "degraded")
        self.assertIn("answered none", result.verdict["note"])
        self.assertEqual(stats.snapshot()["rcodes"]["TIMEOUT"], result.timeouts)

    def test_servfail_storm_is_reported_as_degraded(self) -> None:
        appliance = MockAppliance(
            scenario="servfail", blocklist=self.blocked, servfail_rate=1.0, latency_ms=0.0, jitter_ms=0.0, port=0
        )
        appliance.start()
        try:
            result, stats = self.run_with_model(appliance, block_heavy(self.catalogue))
        finally:
            appliance.stop()
        # A SERVFAIL on a block-listed name counts as blocked, but an all-SERVFAIL
        # resolver still has to be reported as degraded rather than as filtering.
        self.assertEqual(result.verdict["status"], "degraded")

    def test_slow_resolver_shows_up_in_the_latency_percentiles(self) -> None:
        appliance = MockAppliance(scenario="slow", blocklist=self.blocked, latency_ms=60.0, jitter_ms=0.0, port=0)
        appliance.start()
        try:
            _result, stats = self.run_with_model(appliance, block_heavy(self.catalogue))
        finally:
            appliance.stop()
        latency = stats.snapshot()["latency_ms"]
        self.assertGreaterEqual(latency["p50"], 50.0)
        self.assertGreaterEqual(latency["p95"], latency["p50"])


class TestEngineMechanics(EndToEndCase):
    def test_pacing_hits_the_requested_rate(self) -> None:
        appliance = MockAppliance(scenario="good", blocklist=self.blocked, latency_ms=0.05, jitter_ms=0.0, port=0)
        appliance.start()
        try:
            for target in (300.0, 1000.0):
                with self.subTest(target=target):
                    result, _stats = self.run_with_model(
                        appliance, block_heavy(self.catalogue), target_qps=target, duration_s=3.0
                    )
                    self.assertLess(
                        abs(result.achieved_qps - target) / target,
                        0.25,
                        f"asked for {target} qps, achieved {result.achieved_qps:.0f}",
                    )
        finally:
            appliance.stop()

    def test_bursty_arrivals_are_not_a_flat_stream(self) -> None:
        """Compound arrivals are the point of the model, so per-second counts must
        vary rather than coming out identical."""
        appliance = MockAppliance(scenario="good", blocklist=self.blocked, latency_ms=0.05, jitter_ms=0.0, port=0)
        appliance.start()
        try:
            _result, stats = self.run_with_model(
                appliance, block_heavy(self.catalogue), target_qps=1200.0, duration_s=5.0
            )
        finally:
            appliance.stop()
        counts = [point["sent"] for point in stats.snapshot()["series"] if point["sent"]]
        self.assertGreater(len(counts), 2)
        self.assertGreater(len(set(counts)), 1, "a compound Poisson process must not produce a constant rate")

    def test_timeout_is_attributed_to_every_black_holed_query(self) -> None:
        """A socket that accepts but never answers: every query must end up as a
        timeout, not vanish."""
        blackhole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blackhole.bind(("127.0.0.1", 0))
        blackhole.settimeout(0.1)
        host, port = blackhole.getsockname()
        try:
            stats = StatsAggregator()
            import asyncio

            config = RunConfig(
                server=host, port=port, personas=50, target_qps=200.0, duration_s=1.5, timeout_s=0.3, seed=3
            )
            engine = DnsLoadEngine(config, self.catalogue, stats=stats, model=block_heavy(self.catalogue))
            result = asyncio.run(engine.run())
        finally:
            blackhole.close()

        self.assertGreater(result.sent, 100)
        self.assertEqual(result.received, 0)
        self.assertEqual(result.timeouts, result.sent)
        self.assertEqual(stats.snapshot()["totals"]["received"], 0)

    def test_in_flight_cap_reports_drops_instead_of_unbounded_queueing(self) -> None:
        blackhole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blackhole.bind(("127.0.0.1", 0))
        blackhole.settimeout(0.1)
        host, port = blackhole.getsockname()
        try:
            import asyncio

            stats = StatsAggregator()
            config = RunConfig(
                server=host,
                port=port,
                personas=200,
                target_qps=4000.0,
                duration_s=1.5,
                timeout_s=1.0,
                max_inflight=25,
                seed=3,
            )
            engine = DnsLoadEngine(config, self.catalogue, stats=stats, model=block_heavy(self.catalogue))
            result = asyncio.run(engine.run())
        finally:
            blackhole.close()

        self.assertGreater(result.dropped, 0, "an in-flight cap must produce drops on a black hole")
        # Drops stay out of the error counters -- a query never sent is not a query
        # the appliance failed, and mixing them let error_pct exceed 100%.
        self.assertEqual(stats.snapshot()["totals"]["dropped"], result.dropped)
        self.assertEqual(stats.snapshot()["outcomes"]["error"], 0)
        self.assertLessEqual(stats.snapshot()["rates"]["error_pct"], 100.0)

    def test_dry_run_generates_without_sending(self) -> None:
        appliance = MockAppliance(scenario="good", blocklist=self.blocked, latency_ms=0.05, port=0)
        appliance.start()
        try:
            import asyncio

            stats = StatsAggregator()
            config = RunConfig(
                server=appliance.host,
                port=appliance.port,
                personas=100,
                target_qps=500.0,
                duration_s=1.0,
                timeout_s=0.3,
                dry_run=True,
                seed=3,
            )
            engine = DnsLoadEngine(config, self.catalogue, stats=stats, model=block_heavy(self.catalogue))
            result = asyncio.run(engine.run())
        finally:
            appliance.stop()

        self.assertGreater(stats.snapshot()["totals"]["sent"], 0)
        self.assertEqual(stats.snapshot()["rates"]["in_flight"], 0)

    def test_record_log_captures_outcomes_for_every_query(self) -> None:
        appliance = MockAppliance(scenario="good", blocklist=self.blocked, latency_ms=0.05, jitter_ms=0.0, port=0)
        appliance.start()
        temp = tempfile.TemporaryDirectory()
        try:
            import asyncio

            path = pathlib.Path(temp.name) / "records.jsonl"
            stats = StatsAggregator()
            config = RunConfig(
                server=appliance.host,
                port=appliance.port,
                personas=100,
                target_qps=300.0,
                duration_s=2.0,
                timeout_s=0.4,
                seed=3,
            )
            with RecordLog(path) as log:
                engine = DnsLoadEngine(
                    config, self.catalogue, stats=stats, record_log=log, model=block_heavy(self.catalogue)
                )
                result = asyncio.run(engine.run())

            records = list(RecordLog(path).read_records())
        finally:
            appliance.stop()
            temp.cleanup()

        self.assertGreater(len(records), 100)
        self.assertEqual(len(records), result.received + result.timeouts + result.errors)
        outcomes = {record["outcome"] for record in records}
        self.assertIn(Outcome.BLOCKED.value, outcomes)
        self.assertTrue(all(record["category"] for record in records))
        self.assertTrue(all(record["client_ip"] == "127.0.0.1" for record in records))
        blocked = [r for r in records if r["outcome"] == Outcome.BLOCKED.value]
        self.assertTrue(all(r["rcode"] == "NXDOMAIN" for r in blocked))

    def test_sharding_splits_the_rate_rather_than_multiplying_it(self) -> None:
        appliance = MockAppliance(scenario="good", blocklist=self.blocked, latency_ms=0.05, jitter_ms=0.0, port=0)
        appliance.start()
        try:
            stats = StatsAggregator()
            config = RunConfig(
                server=appliance.host,
                port=appliance.port,
                personas=400,
                target_qps=1500.0,
                duration_s=3.0,
                timeout_s=0.4,
                seed=3,
            )
            results = run_threaded(config, self.catalogue, stats=stats, threads=2)
        finally:
            appliance.stop()

        self.assertEqual(len(results), 2)
        total = sum(r.sent for r in results)
        achieved = total / max(max(r.duration_s for r in results), 1e-9)
        # Two shards must share one office's load, not run two offices.
        self.assertLess(achieved, 1500.0 * 1.6, f"sharding multiplied the load: {achieved:.0f} qps")
        self.assertGreater(achieved, 1500.0 * 0.5, f"sharding under-delivered: {achieved:.0f} qps")

    def test_unassigned_pool_address_gives_an_actionable_error(self) -> None:
        """Pool mode's most likely failure is addresses that were never created, so
        the error has to say that instead of leaking an errno."""
        import asyncio

        config = RunConfig(
            server="127.0.0.1",
            port=5,
            mode="pool",
            source_ips=["10.255.255.250"],
            personas=10,
            target_qps=10.0,
            duration_s=0.2,
        )
        engine = DnsLoadEngine(config, self.catalogue, stats=StatsAggregator(), model=block_heavy(self.catalogue))
        with self.assertRaises(OSError) as context:
            asyncio.run(engine.run())
        self.assertIn("New-LabSourceIPs.ps1", str(context.exception))

    def test_empty_catalogue_refuses_to_invent_traffic(self) -> None:
        import asyncio

        empty = DomainCatalogue(
            pools={c.value: DomainPool(category=c.value) for c in Category}, fetched_at=0.0
        )
        # Building the model should already refuse.
        with self.assertRaises(ValueError):
            DnsLoadEngine(RunConfig(server="127.0.0.1", port=9, personas=5), empty)


if __name__ == "__main__":
    unittest.main()
