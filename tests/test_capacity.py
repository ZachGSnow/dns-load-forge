"""Capacity search.

The search itself is tested against model targets -- a function from a rate to
what such a target would answer -- so every way a search can end is exercised in
milliseconds: a clear knee, a target that never breaks, one that fails at the
first rate, a generator that cannot keep up, and a stop.  Two end-to-end tests
then drive real load: the dashboard's controller against the mock's rate
limiter, and the command line's exit code.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge import capacity  # noqa: E402
from dnsloadforge import cli  # noqa: E402
from dnsloadforge.capacity import CapacityPlan, Slo, Step, judge, measure, nice_rate, search  # noqa: E402
from dnsloadforge.mockappliance import MockAppliance  # noqa: E402
from dnsloadforge.server import RunController  # noqa: E402
from dnsloadforge.spec import RunConfig  # noqa: E402
from dnsloadforge.targets import Target  # noqa: E402

from test_cli import parse, tiny_catalogue  # noqa: E402
from test_engine import synthetic_catalogue  # noqa: E402


def snapshot(
    *,
    sent: int = 6000,
    received: int | None = None,
    timeouts: int = 0,
    errors: int = 0,
    dropped: int = 0,
    servfail: int = 0,
    rate_limited: int = 0,
    p95: float = 20.0,
) -> dict:
    """What a finished step's snapshot looks like, reduced to what is judged."""
    received = sent - timeouts - errors if received is None else received
    return {
        "totals": {"sent": sent, "received": received, "timeouts": timeouts, "errors": errors, "intended": sent + dropped},
        "rates": {"dropped_pct": round(100.0 * dropped / max(sent + dropped, 1), 3)},
        "latency_ms": {"run_p50": p95 / 4, "run_p95": p95, "run_p99": p95 * 2},
        "rcodes": {"SERVFAIL": servfail},
        "ede": [{"code": 31, "name": "Rate Limited", "count": rate_limited}] if rate_limited else [],
    }


def knee_at(limit: float, *, generator_cap: float = float("inf")):
    """A target that answers in 20 ms up to ``limit`` qps and slows to 300 ms
    above it, measured by a generator that can send ``generator_cap`` qps."""

    def run_step(rate: float) -> tuple[dict, float]:
        offered = min(rate, generator_cap)
        sent = int(offered * 10)
        return snapshot(sent=sent, p95=20.0 if rate <= limit else 300.0), offered

    return run_step


FAST = CapacityPlan(start_qps=200, max_qps=20_000, growth=2, step_s=10, refine=2)


def run(plan: CapacityPlan, run_step, **kwargs):
    return search(plan, Slo(), run_step, pause=lambda _s: None, **kwargs)


class TestRatesAndPlans(unittest.TestCase):
    def test_rates_are_rounded_to_what_a_step_can_claim(self) -> None:
        self.assertEqual([nice_rate(r) for r in (1519, 2278, 675, 99.6, 3.2)], [1500, 2300, 680, 100, 3])

    def test_the_ramp(self) -> None:
        self.assertEqual(CapacityPlan(start_qps=200, max_qps=2000, growth=2).ramp(), [200, 400, 800, 1600, 2000])
        self.assertEqual(CapacityPlan(start_qps=500, max_qps=500).ramp(), [500])

    def test_plans_that_cannot_work_are_refused(self) -> None:
        for bad in (
            CapacityPlan(start_qps=0),
            CapacityPlan(start_qps=500, max_qps=100),
            CapacityPlan(growth=1.0),
            CapacityPlan(step_s=1),
            CapacityPlan(refine=9),
            CapacityPlan(start_qps=5, step_s=10),  # 50 queries a step: too few to judge
        ):
            with self.subTest(plan=bad), self.assertRaises(ValueError):
                bad.validate()
        with self.assertRaises(ValueError):
            Slo(p95_ms=0).validate()


class TestJudging(unittest.TestCase):
    def judged(self, rate: float = 1000, achieved: float = 1000, **figures) -> Step:
        return judge(measure(Step(1, "ramp", rate), snapshot(**figures), achieved), Slo())

    def test_a_healthy_step_passes(self) -> None:
        step = self.judged()
        self.assertEqual((step.status, step.reasons), ("pass", []))

    def test_each_limit_names_itself(self) -> None:
        self.assertIn("loss", self.judged(timeouts=120).reasons[0])
        self.assertIn("SERVFAIL", self.judged(servfail=120).reasons[0])
        self.assertIn("rate-limited", self.judged(rate_limited=60).reasons[0])
        self.assertIn("p95", self.judged(p95=150).reasons[0])
        self.assertEqual(len(self.judged(timeouts=120, p95=150).reasons), 2)

    def test_a_rate_this_machine_could_not_send_is_no_evidence(self) -> None:
        step = self.judged(rate=10_000, achieved=6_000)
        self.assertEqual(step.status, "generator")
        self.assertIn("--threads", step.reasons[0])

    def test_a_full_in_flight_budget_is_ours_unless_the_target_was_failing(self) -> None:
        # Healthy target, queries dropped: the budget was the limit.
        healthy = self.judged(dropped=300)
        self.assertEqual(healthy.status, "generator")
        self.assertIn("--max-inflight", healthy.reasons[0])
        # Failing target: the unanswered queries filled the budget; its failure.
        failing = self.judged(dropped=300, timeouts=900)
        self.assertEqual(failing.status, "fail")
        self.assertIn("never sent", failing.reasons[-1])

    def test_too_few_queries_are_not_judged(self) -> None:
        self.assertEqual(self.judged(sent=100).status, "small")


class TestSearch(unittest.TestCase):
    def test_ramp_then_narrow_down(self) -> None:
        result = run(FAST, knee_at(3000))
        self.assertEqual([s.target_qps for s in result.steps], [200, 400, 800, 1600, 3200, 2400, 2800])
        self.assertEqual([s.phase for s in result.steps][-2:], ["refine", "refine"])
        self.assertEqual((result.sustained_qps, result.knee_qps, result.limit), (2800, 3200, "target"))
        self.assertIn("Sustains 2,800 qps", result.summary)
        self.assertIn("p95 300 ms", result.summary)

    def test_a_target_that_never_breaks(self) -> None:
        result = run(CapacityPlan(start_qps=200, max_qps=1000, growth=2, step_s=10), knee_at(50_000))
        self.assertEqual((result.sustained_qps, result.knee_qps, result.limit), (1000, None, "max"))
        self.assertIn("Raise the highest rate", result.summary)

    def test_a_target_that_fails_from_the_start(self) -> None:
        result = run(FAST, knee_at(100))
        self.assertEqual((result.sustained_qps, result.knee_qps, result.limit), (None, 200, "start"))
        self.assertEqual(len(result.steps), 1, "nothing to narrow down between")

    def test_the_generator_limit_is_not_reported_as_the_targets(self) -> None:
        result = run(FAST, knee_at(50_000, generator_cap=1000))
        self.assertEqual(result.limit, "generator")
        self.assertEqual(result.sustained_qps, 800)
        self.assertIn("at least 800 qps", result.summary)

    def test_a_stop_ends_it_and_the_cut_step_is_not_judged(self) -> None:
        calls = {"n": 0}
        model = knee_at(50_000)

        def run_step(rate: float):
            calls["n"] += 1
            return model(rate)

        result = run(FAST, run_step, should_stop=lambda: calls["n"] >= 3)
        self.assertEqual(result.state, "stopped")
        self.assertEqual(result.steps[-1].status, "stopped")
        self.assertEqual(result.sustained_qps, 400, "the step cut short does not count")

    def test_progress_is_reported_as_it_happens(self) -> None:
        started, finished = [], []
        run(
            CapacityPlan(start_qps=200, max_qps=400, growth=2, step_s=10, refine=0),
            knee_at(50_000),
            on_start=lambda index, phase, rate: started.append((index, phase, rate)),
            on_step=lambda step: finished.append(step.index),
        )
        self.assertEqual(started, [(1, "ramp", 200), (2, "ramp", 400)])
        self.assertEqual(finished, [1, 2])


class TestControllerAgainstTheMock(unittest.TestCase):
    """The dashboard's path: real load against the mock's rate limiter, which
    answers SERVFAIL with EDE 31 above its limit."""

    def test_the_search_finds_the_rate_limit(self) -> None:
        appliance = MockAppliance(scenario="good", rate_limit_qps=600, latency_ms=0.0, jitter_ms=0.0, port=0)
        appliance.start()
        self.addCleanup(appliance.stop)
        config = RunConfig(server=appliance.host, port=appliance.port, personas=200, timeout_s=0.5, seed=3)
        target = Target(name="Rate-limited mock", server=appliance.host, port=appliance.port)
        controller = RunController(config, synthetic_catalogue(), targets=[target], log=lambda _m: None)
        with mock.patch.object(capacity, "STEP_PAUSE_S", 0.2):
            started = controller.start_capacity(
                {"target": target.name, "start_qps": 150, "max_qps": 1200, "growth": 2, "step_s": 3, "refine": 1}
            )
            self.assertTrue(started["ok"], started)
            # One search at a time, and no run while it lasts.
            self.assertFalse(controller.start_capacity({"target": target.name})["ok"])
            self.assertFalse(controller.start({})["ok"])
            deadline = time.time() + 90
            while controller.capacity_payload()["state"] == "running" and time.time() < deadline:
                time.sleep(0.2)
        payload = controller.capacity_payload()
        self.assertEqual(payload["state"], "done", payload)
        result = payload["result"]
        self.assertEqual(result["limit"], "target")
        self.assertIn(result["sustained_qps"], (300, 450))
        failed = [s for s in payload["steps"] if s["status"] == "fail"]
        self.assertTrue(any("SERVFAIL" in r or "rate-limited" in r for s in failed for r in s["reasons"]), failed)
        self.assertEqual(controller.state, "stopped")
        self.assertEqual(controller.history, [], "the steps do not fill the comparison history")
        # The report shows the search, and no step of it posing as "the run".
        page = controller.report_html()
        self.assertIn("<h2>Capacity", page)
        self.assertNotIn("<h2>The run", page)

    def test_bad_requests_and_public_targets_are_refused(self) -> None:
        public = Target(name="Shared", server="9.9.9.9", kind="public")
        controller = RunController(RunConfig(), synthetic_catalogue(), targets=[public], log=lambda _m: None)
        for payload in (
            {"target": "Shared", "max_qps": 5000},  # a public resolver, above 100 qps
            {"start_qps": "fast"},
            {"growth": 1.0},
            {"slo": {"p95_ms": -1}},
            {"step_s": float("nan")},
        ):
            with self.subTest(payload=payload):
                answer = controller.start_capacity(payload)
                self.assertFalse(answer["ok"])
                self.assertIn("bad parameter", answer["message"])


class TestCommandLine(unittest.TestCase):
    def test_capacity_against_the_mock_and_the_required_rate(self) -> None:
        args = parse(
            [
                "capacity", "--mock", "--start-qps", "150", "--max-qps", "300", "--step-seconds", "3",
                "--growth", "2", "--refine", "0", "--personas", "50", "--timeout", "0.5",
                "--json", "--require", "100000",
            ]
        )
        buffer = io.StringIO()
        with mock.patch.object(cli, "_load_lists", return_value=tiny_catalogue()), mock.patch.object(
            capacity, "STEP_PAUSE_S", 0.2
        ), contextlib.redirect_stdout(buffer):
            code = cli.cmd_capacity(args)
        report = json.loads(buffer.getvalue()[buffer.getvalue().index("{"):])
        self.assertEqual(code, 1, "the required rate was not met")
        self.assertFalse(report["requirement_met"])
        self.assertEqual([s["target_qps"] for s in report["steps"]], [150, 300])
        self.assertEqual(report["limit"], "max")

    def test_capacity_takes_no_fixed_rate(self) -> None:
        """--qps and --duration would be ignored by a search, so they are not offered."""
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parse(["capacity", "--qps", "500"])


if __name__ == "__main__":
    unittest.main()
