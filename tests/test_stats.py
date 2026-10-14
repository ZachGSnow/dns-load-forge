"""Aggregation and verdict tests.

Two things here matter more than coverage percentage:

* **Received must exclude timeouts.**  If a timeout were counted as received, the
  received-qps line on the dashboard would stay flat while the appliance dropped
  every packet, which is the exact failure the tool exists to expose.
* **Verdict precedence.**  "Nothing answered" must outrank "no false positives",
  and "blocks nothing at all" must read as ``passthrough`` rather than as a long
  list of leaks.  Those orderings are asserted directly.
"""

from __future__ import annotations

import json
import pathlib
import random
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge.spec import (  # noqa: E402
    LATENCY_BUCKETS_MS,
    RCODE_ERROR,
    RCODE_TIMEOUT,
    RECORD_FIELDS,
    Category,
    Outcome,
)
from dnsloadforge.stats import (  # noqa: E402
    RecordLog,
    StatsAggregator,
    percentile_from_histogram,
)


class AggregatorCase(unittest.TestCase):
    """Helpers that drive the aggregator the way the engine does."""

    def setUp(self) -> None:
        self.stats = StatsAggregator()
        self.stats.set_run(state="running", started_at=1_700_000_000.0, target_qps=100.0)
        self.now = 1_700_000_000.0

    def send(self, count: int = 1, now: float | None = None) -> None:
        self.stats.on_send(count, 40 * count, now if now is not None else self.now)

    def result(
        self,
        *,
        category: str = Category.ALLOW_POPULAR.value,
        rcode: str = "NOERROR",
        outcome: str = Outcome.ALLOWED.value,
        latency_ms: float = 5.0,
        qname: str = "example.com",
        client_ip: str = "10.0.0.1",
        now: float | None = None,
        qtype: str = "A",
        answer_ip: str = "",
    ) -> None:
        self.stats.on_result(
            qname=qname,
            client_ip=client_ip,
            category=category,
            qtype=qtype,
            rcode=rcode,
            outcome=outcome,
            latency_ms=latency_ms,
            bytes_received=60,
            answer_ip=answer_ip,
            now=now if now is not None else self.now,
        )


class TestPercentiles(unittest.TestCase):
    def test_upper_bound_of_the_bucket_is_returned(self) -> None:
        histogram = [0] * len(LATENCY_BUCKETS_MS)
        histogram[0] = 100  # everything in (0, 0.5]ms
        self.assertEqual(percentile_from_histogram(histogram, LATENCY_BUCKETS_MS, 95.0), 0.5)

    def test_empty_histogram_reports_zero(self) -> None:
        self.assertEqual(
            percentile_from_histogram([0] * len(LATENCY_BUCKETS_MS), LATENCY_BUCKETS_MS, 95.0), 0.0
        )

    def test_percentile_tracks_the_distribution(self) -> None:
        histogram = [0] * len(LATENCY_BUCKETS_MS)
        histogram[2] = 50   # 50 in (1, 2]ms
        histogram[5] = 48   # 48 in (10, 20]ms
        histogram[6] = 2    # 2 in (20, 30]ms
        self.assertEqual(percentile_from_histogram(histogram, LATENCY_BUCKETS_MS, 50.0), 2.0)
        self.assertEqual(percentile_from_histogram(histogram, LATENCY_BUCKETS_MS, 96.0), 20.0)
        self.assertEqual(percentile_from_histogram(histogram, LATENCY_BUCKETS_MS, 99.0), 30.0)

    def test_an_infinite_overflow_bucket_never_returns_infinity(self) -> None:
        """Infinity is not valid JSON, so a slow-response run must not be able to
        blank the whole dashboard payload."""
        buckets = (1.0, 5.0, float("inf"))
        histogram = [0, 0, 10]
        value = percentile_from_histogram(histogram, buckets, 95.0)
        self.assertTrue(value == value and value != float("inf"))
        self.assertEqual(value, 5.0)


class TestIngestSemantics(AggregatorCase):
    def test_received_excludes_timeouts(self) -> None:
        self.send(4)
        self.result(outcome=Outcome.ALLOWED.value, rcode="NOERROR")
        self.result(outcome=Outcome.TIMEOUT.value, rcode=RCODE_TIMEOUT, latency_ms=0.0)
        self.result(outcome=Outcome.ERROR.value, rcode=RCODE_ERROR, latency_ms=0.0)
        snapshot = self.stats.snapshot()

        self.assertEqual(snapshot["totals"]["sent"], 4)
        self.assertEqual(snapshot["totals"]["received"], 1, "a timeout is completed, not received")
        self.assertEqual(snapshot["totals"]["timeouts"], 1)
        self.assertEqual(snapshot["totals"]["errors"], 1)
        self.assertEqual(snapshot["totals"]["completed"], 3)
        self.assertEqual(snapshot["rcodes"]["TIMEOUT"], 1)
        self.assertEqual(snapshot["rcodes"]["ERROR"], 1)

    def test_in_flight_tracks_outstanding_queries(self) -> None:
        self.send(3)
        self.assertEqual(self.stats.snapshot()["rates"]["in_flight"], 3)
        self.result()
        self.assertEqual(self.stats.snapshot()["rates"]["in_flight"], 2)

    def test_error_percentage_is_a_share_of_sent(self) -> None:
        self.send(200)
        for _ in range(20):
            self.result(outcome=Outcome.TIMEOUT.value, rcode=RCODE_TIMEOUT, latency_ms=0.0)
        for _ in range(180):
            self.result()
        self.assertAlmostEqual(self.stats.snapshot()["rates"]["error_pct"], 10.0, places=1)

    def test_drops_are_not_counted_as_errors(self) -> None:
        """A dropped query was never sent, so it is not a query the appliance failed.
        Folding the two together made error_pct exceed 100% -- the first benchmark run
        reported '128.5% loss' against a healthy generator."""
        self.send(10)
        self.stats.on_drop(4)
        snapshot = self.stats.snapshot()
        self.assertEqual(snapshot["totals"]["dropped"], 4)
        self.assertEqual(snapshot["totals"]["intended"], 14)
        self.assertEqual(snapshot["totals"]["errors"], 0)
        self.assertEqual(snapshot["outcomes"]["error"], 0)
        self.assertAlmostEqual(snapshot["rates"]["dropped_pct"], 100.0 * 4 / 14, places=2)

    def test_no_rate_can_exceed_one_hundred_percent(self) -> None:
        """The hard version: a timeout lands a second after the send it belongs to, so
        a window can accumulate more errors than sends and report a loss above 100%.
        Both reported rates are divided so that cannot happen."""
        rng = random.Random(1)
        stats = StatsAggregator()
        stats.set_run(state="running", started_at=1_000.0)
        now = 1_000.0
        for _ in range(8):
            count = rng.randint(50, 300)
            for _ in range(count):
                stats.on_send(1, 40, now)
            for _ in range(count // 2):
                stats.on_result(
                    qname="a.example.com", client_ip="10.0.0.1", category=Category.ALLOW_POPULAR.value,
                    qtype="A", rcode="NOERROR", outcome=Outcome.ALLOWED.value,
                    latency_ms=3.0, bytes_received=60, now=now,
                )
            for _ in range(count - count // 2):
                stats.on_result(
                    qname="a.example.com", client_ip="10.0.0.1", category=Category.ALLOW_POPULAR.value,
                    qtype="A", rcode=RCODE_TIMEOUT, outcome=Outcome.TIMEOUT.value,
                    latency_ms=0.0, bytes_received=0, now=now + 1.0,
                )
            now += 1.0

        rates = stats.snapshot()["rates"]
        for key in ("error_pct", "window_error_pct", "dropped_pct"):
            with self.subTest(rate=key):
                self.assertGreaterEqual(rates[key], 0.0)
                self.assertLessEqual(rates[key], 100.0)

    def test_window_error_rate_reacts_before_the_run_total_does(self) -> None:
        """A run that starts failing halfway through must look bad immediately, not
        only at the end once the healthy first half has been diluted in."""
        stats = StatsAggregator()
        stats.set_run(state="running", started_at=1_000.0)
        now = 1_000.0
        for _ in range(20):
            for _ in range(100):
                stats.on_send(1, 40, now)
                stats.on_result(
                    qname="a.example.com", client_ip="10.0.0.1", category=Category.ALLOW_POPULAR.value,
                    qtype="A", rcode="NOERROR", outcome=Outcome.ALLOWED.value,
                    latency_ms=3.0, bytes_received=60, now=now,
                )
            now += 1.0
        healthy = stats.snapshot()["rates"]
        self.assertLess(healthy["window_error_pct"], 1.0)

        # Now everything starts timing out.
        for _ in range(5):
            for _ in range(100):
                stats.on_send(1, 40, now)
                stats.on_result(
                    qname="a.example.com", client_ip="10.0.0.1", category=Category.ALLOW_POPULAR.value,
                    qtype="A", rcode=RCODE_TIMEOUT, outcome=Outcome.TIMEOUT.value,
                    latency_ms=0.0, bytes_received=0, now=now,
                )
            now += 1.0
        failing = stats.snapshot()["rates"]
        # The window reflects the failure immediately...
        self.assertGreaterEqual(failing["window_error_pct"], 90.0)
        # ...while the run total is still diluted by the healthy period, which is why
        # the dashboard shows both.
        self.assertLess(failing["error_pct"], 50.0)

    def test_backpressure_is_surfaced_in_the_verdict_note(self) -> None:
        """If the generator could not offer the requested rate, every conclusion about
        the appliance is suspect, so the caveat is appended to the note rather than
        left for the operator to notice in a table."""
        stats = StatsAggregator()
        now = 1_700_000_000.0
        stats.set_run(state="running", started_at=now)
        for _ in range(300):
            stats.on_send(1, 40, now)
            stats.on_result(
                qname="a.example.com", client_ip="10.0.0.1", category=Category.BLOCK_ADS.value,
                qtype="A", rcode="NXDOMAIN", outcome=Outcome.BLOCKED.value,
                latency_ms=4.0, bytes_received=60, now=now,
            )
        for _ in range(300):
            stats.on_send(1, 40, now)
            stats.on_result(
                qname="b.example.com", client_ip="10.0.0.1", category=Category.ALLOW_POPULAR.value,
                qtype="A", rcode="NOERROR", outcome=Outcome.ALLOWED.value,
                latency_ms=4.0, bytes_received=60, now=now,
            )
        verdict = stats.snapshot()["verdict"]
        self.assertEqual(verdict["status"], "filtering")
        self.assertNotIn("Caution", verdict["note"])

        stats.on_drop(600)  # 600 of 1200 intended queries never left the sender
        verdict = stats.snapshot()["verdict"]
        self.assertIn("Caution", verdict["note"])
        self.assertIn("max-inflight", verdict["note"])

    def test_buckets_rotate_on_second_boundaries(self) -> None:
        for offset in range(3):
            self.send(1, now=self.now + offset)
            self.result(now=self.now + offset)
        series = self.stats.snapshot()["series"]
        self.assertEqual(len(series), 3)
        self.assertEqual([point["sent"] for point in series], [1, 1, 1])
        self.assertEqual([point["t"] for point in series], [1_700_000_000, 1_700_000_001, 1_700_000_002])

    def test_gaps_become_empty_buckets_so_the_time_axis_stays_honest(self) -> None:
        """A stalled send loop must appear as a zero-activity period, not as two
        adjacent seconds, which would make the chart lie about the rate."""
        self.send(1, now=self.now)
        self.result(now=self.now)
        self.send(1, now=self.now + 5)
        self.result(now=self.now + 5)
        series = self.stats.snapshot()["series"]
        self.assertEqual(len(series), 6)
        self.assertEqual([point["sent"] for point in series], [1, 0, 0, 0, 0, 1])

    def test_series_is_capped_at_the_window_length(self) -> None:
        stats = StatsAggregator(series_seconds=10)
        stats.set_run(state="running", started_at=self.now)
        for offset in range(40):
            stats.on_send(1, 40, self.now + offset)
        self.assertEqual(len(stats.snapshot()["series"]), 10)

    def test_by_category_always_reports_every_category(self) -> None:
        self.send(1)
        self.result()
        rows = self.stats.snapshot()["by_category"]
        self.assertEqual(len(rows), len(Category))
        self.assertEqual([row["category"] for row in rows], [c.value for c in Category])

    def test_pass_rate_falls_with_failures(self) -> None:
        for _ in range(10):
            self.send(1)
            self.result(category=Category.ENTERPRISE.value, outcome=Outcome.ALLOWED.value)
        for _ in range(10):
            self.send(1)
            self.result(category=Category.ENTERPRISE.value, outcome=Outcome.FALSE_POSITIVE.value, rcode="REFUSED")
        row = next(r for r in self.stats.snapshot()["by_category"] if r["category"] == Category.ENTERPRISE.value)
        self.assertEqual(row["sent"], 20)
        self.assertEqual(row["fp"], 10)
        self.assertAlmostEqual(row["pass_rate"], 0.5, places=3)

    def test_findings_are_deduplicated_and_counted(self) -> None:
        for _ in range(7):
            self.send(1)
            self.result(
                qname="login.microsoftonline.com",
                client_ip="10.0.0.9",
                category=Category.ENTERPRISE.value,
                outcome=Outcome.FALSE_POSITIVE.value,
                rcode="NXDOMAIN",
            )
        findings = self.stats.snapshot()["false_positives"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["count"], 7)
        self.assertEqual(findings[0]["qname"], "login.microsoftonline.com")
        self.assertEqual(findings[0]["rcode"], "NXDOMAIN")

    def test_top_domains_and_clients_are_ranked(self) -> None:
        for _ in range(5):
            self.send(1)
            self.result(qname="hot.example.com")
        self.send(1)
        self.result(qname="cold.example.com")
        snapshot = self.stats.snapshot()
        self.assertEqual(snapshot["top_domains"][0]["qname"], "hot.example.com")
        self.assertEqual(snapshot["top_domains"][0]["count"], 5)
        self.assertEqual(snapshot["top_clients"][0]["client_ip"], "10.0.0.1")
        self.assertEqual(snapshot["totals"]["unique_clients"], 1)
        self.assertEqual(snapshot["totals"]["unique_domains"], 2)

    def test_snapshot_is_strictly_json_serialisable(self) -> None:
        """``allow_nan=False`` is what the HTTP layer uses, so this is a real
        guarantee, not a formality."""
        self.send(1)
        self.result(latency_ms=0.1)
        self.result(outcome=Outcome.TIMEOUT.value, rcode=RCODE_TIMEOUT, latency_ms=0.0)
        payload = json.dumps(self.stats.snapshot(), allow_nan=False)
        self.assertIn('"verdict"', payload)

    def test_reset_clears_findings_so_runs_do_not_contaminate_each_other(self) -> None:
        self.send(1)
        self.result(outcome=Outcome.FALSE_POSITIVE.value, rcode="REFUSED")
        self.stats.reset()
        snapshot = self.stats.snapshot()
        self.assertEqual(snapshot["totals"]["sent"], 0)
        self.assertEqual(snapshot["false_positives"], [])


class TestVerdict(unittest.TestCase):
    def _run(self, plan: list[tuple[str, str, str]]) -> dict:
        stats = StatsAggregator()
        now = 1_700_000_000.0
        stats.set_run(state="running", started_at=now, target_qps=1000.0)
        for category, rcode, outcome in plan:
            stats.on_send(1, 40, now)
            stats.on_result(
                qname=f"{outcome}.example.com",
                client_ip="10.0.0.1",
                category=category,
                qtype="A",
                rcode=rcode,
                outcome=outcome,
                latency_ms=4.0,
                bytes_received=60,
                now=now,
            )
        return stats.snapshot()["verdict"]

    def test_idle_when_nothing_has_run(self) -> None:
        stats = StatsAggregator()
        self.assertEqual(stats.snapshot()["verdict"]["status"], "idle")

    def test_unknown_below_the_minimum_sample(self) -> None:
        plan = [(Category.BLOCK_ADS.value, "NXDOMAIN", Outcome.BLOCKED.value)] * 10
        self.assertEqual(self._run(plan)["status"], "unknown")

    def test_filtering_when_blocking_and_allowing_correctly(self) -> None:
        plan = [(Category.BLOCK_ADS.value, "NXDOMAIN", Outcome.BLOCKED.value)] * 300
        plan += [(Category.ALLOW_POPULAR.value, "NOERROR", Outcome.ALLOWED.value)] * 300
        verdict = self._run(plan)
        self.assertEqual(verdict["status"], "filtering")
        self.assertIn("Filtering correctly", verdict["note"])

    def test_passthrough_outranks_leaks(self) -> None:
        """A resolver that blocks nothing is better described as passthrough than
        as 300 separate leaks -- and the operator's next action differs."""
        plan = [(Category.BLOCK_MALWARE.value, "NOERROR", Outcome.FALSE_NEGATIVE.value)] * 300
        plan += [(Category.ALLOW_POPULAR.value, "NOERROR", Outcome.ALLOWED.value)] * 100
        verdict = self._run(plan)
        self.assertEqual(verdict["status"], "passthrough")
        self.assertIn("Not filtering", verdict["note"])

    def test_degraded_when_legitimate_traffic_is_blocked(self) -> None:
        plan = [(Category.BLOCK_ADS.value, "NXDOMAIN", Outcome.BLOCKED.value)] * 300
        plan += [(Category.ENTERPRISE.value, "REFUSED", Outcome.FALSE_POSITIVE.value)] * 50
        verdict = self._run(plan)
        self.assertEqual(verdict["status"], "degraded")
        self.assertIn("Blocking legitimate traffic", verdict["note"])

    def test_degraded_when_answering_but_failing(self) -> None:
        plan = [(Category.BLOCK_ADS.value, "NXDOMAIN", Outcome.BLOCKED.value)] * 100
        plan += [(Category.ALLOW_POPULAR.value, "NOERROR", Outcome.ALLOWED.value)] * 100
        plan += [(Category.ALLOW_POPULAR.value, RCODE_TIMEOUT, Outcome.TIMEOUT.value)] * 100
        verdict = self._run(plan)
        self.assertEqual(verdict["status"], "degraded")
        self.assertIn("failing under load", verdict["note"])

    def test_degraded_when_nothing_answers(self) -> None:
        plan = [(Category.ALLOW_POPULAR.value, RCODE_TIMEOUT, Outcome.TIMEOUT.value)] * 300
        verdict = self._run(plan)
        self.assertEqual(verdict["status"], "degraded")
        self.assertIn("answered none", verdict["note"])

    def test_degraded_when_bad_traffic_leaks(self) -> None:
        plan = [(Category.BLOCK_ADS.value, "NXDOMAIN", Outcome.BLOCKED.value)] * 250
        plan += [(Category.BLOCK_MALWARE.value, "NOERROR", Outcome.FALSE_NEGATIVE.value)] * 50
        plan += [(Category.ALLOW_POPULAR.value, "NOERROR", Outcome.ALLOWED.value)] * 100
        verdict = self._run(plan)
        self.assertEqual(verdict["status"], "degraded")
        self.assertIn("Leaking known-bad", verdict["note"])


class TestRecordLog(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_jsonl_round_trip_preserves_the_field_mapping(self) -> None:
        """The engine writes a positional tuple and the reader maps it back by
        name, so this pins the order both sides depend on."""
        values = (
            1.5, "10.0.0.1", 7, "developer", "example.com", "A",
            "allow_popular", "NOERROR", "allowed", 4.2, "93.184.216.34", 29, 45,
        )
        path = self.dir / "records.jsonl"
        with RecordLog(path) as log:
            log.write(values)

        records = list(RecordLog(path).read_records())
        self.assertEqual(len(records), 1)
        self.assertEqual(list(records[0].keys()), list(RECORD_FIELDS))
        for field, expected in zip(RECORD_FIELDS, values):
            self.assertEqual(records[0][field], expected)

    def test_reads_back_a_csv_log_with_types_restored(self) -> None:
        """A CSV log must be readable through the same interface as JSONL.  Reading
        it as JSON silently skipped every row, so the export looked empty rather
        than broken."""
        path = self.dir / "records.csv"
        rows = [
            (10.5, "10.0.0.1", 3, "developer", "a.example.com", "A",
             "allow_popular", "NOERROR", "allowed", 4.25, "93.184.216.34", 29, 45),
            (11.5, "10.0.0.2", 4, "kiosk_shared", "b.example.com", "AAAA",
             "block_ads", "NXDOMAIN", "blocked", 0.5, "", 29, 12),
        ]
        with RecordLog(path, fmt="csv") as log:
            for row in rows:
                log.write(row)

        records = list(RecordLog(path, fmt="csv").read_records())
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["qname"], "a.example.com")
        self.assertEqual(records[0]["ts"], 10.5)
        self.assertIsInstance(records[0]["ts"], float)
        self.assertEqual(records[0]["persona_id"], 3)
        self.assertIsInstance(records[0]["persona_id"], int)
        self.assertEqual(records[0]["latency_ms"], 4.25)
        self.assertEqual(records[1]["outcome"], "blocked")
        self.assertEqual(records[1]["bytes_received"], 12)

    def test_csv_has_a_header_and_escapes_quotes(self) -> None:
        path = self.dir / "records.csv"
        with RecordLog(path, fmt="csv") as log:
            log.write((1.0, "10.0.0.1", 1, "exec", 'weird,"name".example', "A",
                       "enterprise", "NXDOMAIN", "false_positive", 1.0, "", 29, 0))
        text = path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(text[0], ",".join(RECORD_FIELDS))
        self.assertIn('"weird,""name"".example"', text[1])

    def test_sampling_keeps_a_representative_fraction(self) -> None:
        path = self.dir / "sampled.jsonl"
        with RecordLog(path, sample=0.1) as log:
            for index in range(1000):
                log.write((float(index), "ip", index, "role", "a.com", "A", "c", "NOERROR", "allowed", 1.0, "", 1, 1))
        self.assertLess(log.written, 200)
        self.assertGreater(log.written, 50)

    def test_max_bytes_stops_writing_and_says_so(self) -> None:
        path = self.dir / "big.jsonl"
        log = RecordLog(path, max_bytes=200, flush_every=1).open()
        try:
            for index in range(200):
                log.write((float(index), "10.0.0.1", index, "role", "example.com", "A",
                           "allow_popular", "NOERROR", "allowed", 1.0, "", 29, 45))
        finally:
            log.close()
        self.assertTrue(log.truncated)
        self.assertIn("max_bytes", path.read_text(encoding="utf-8"))

    def test_corrupt_lines_are_skipped_not_fatal(self) -> None:
        path = self.dir / "corrupt.jsonl"
        path.write_text('{"ts": 1}\nnot json\n\n{"ts": 2}\n', encoding="utf-8")
        records = list(RecordLog(path).read_records())
        self.assertEqual([r["ts"] for r in records], [1, 2])

    def test_read_missing_file_yields_nothing(self) -> None:
        self.assertEqual(list(RecordLog(self.dir / "nope.jsonl").read_records()), [])

    def test_rejects_an_invalid_sample(self) -> None:
        with self.assertRaises(ValueError):
            RecordLog(self.dir / "x.jsonl", sample=1.5)


if __name__ == "__main__":
    unittest.main()
