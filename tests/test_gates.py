"""Assertions with exit codes and JUnit, and the Prometheus metrics.

A gate that passes when it should fail is worse than none: a nightly job would
report green over a filter that broke the sign-in page.  So every way an
assertion can fail is tested -- the limit crossed, the value never measured, no
run at all -- along with the exit code and the XML a CI system reads.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import pathlib
import re
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge import cli  # noqa: E402
from dnsloadforge.gates import (  # noqa: E402
    DEFAULT_ASSERTIONS,
    evaluate,
    format_results,
    junit_xml,
    parse_assertion,
)
from dnsloadforge.metrics import CONTENT_TYPE, _label, render_metrics  # noqa: E402
from dnsloadforge.server import serve  # noqa: E402
from dnsloadforge.spec import RunConfig  # noqa: E402
from dnsloadforge.stats import StatsAggregator  # noqa: E402

from test_cli import parse, tiny_catalogue  # noqa: E402
from test_engine import synthetic_catalogue  # noqa: E402

SUMMARY = {
    "target": "Lab filter",
    "server": "10.0.0.5:53",
    "transport": "udp",
    "finished_at": 1_800_000_000.0,
    "elapsed_s": 62.4,
    "verdict": "filtering",
    "sent": 60_000,
    "block_rate": 0.982,
    "false_block_rate": 0.0,
    "leaked": 186,
    "false_positives": 0,
    "error_pct": 0.1,
    "servfail_pct": 0.0,
    "dropped_pct": 0.0,
    "timeouts": 60,
    "achieved_qps": 1002.4,
    "latency_ms": {"p50": 2.0, "p95": 9.0, "p99": 20.0},
}


class TestParsing(unittest.TestCase):
    def test_the_forms_an_operator_types(self) -> None:
        for text, metric, op, value in (
            ("p95<=50", "p95", "<=", 50.0),
            (" block_rate >= 95 ", "block_rate", ">=", 95.0),
            ("loss<1", "loss", "<", 1.0),
            ("verdict==filtering", "verdict", "==", "filtering"),
            ("false_positives==0", "false_positives", "==", 0.0),
        ):
            with self.subTest(text=text):
                parsed = parse_assertion(text)
                self.assertEqual((parsed.metric, parsed.op, parsed.value), (metric, op, value))

    def test_mistakes_are_refused_with_the_reason(self) -> None:
        for text, reason in (
            ("p96<=50", "unknown metric"),
            ("p95=>50", "is not an assertion"),
            ("p95<=fast", "compared with a number"),
            ("verdict>=filtering", "only be compared"),
            ("verdict==great", "one of"),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, reason):
                parse_assertion(text)

    def test_a_typo_fails_before_any_traffic(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            parse(["run", "--assert", "p96<=50"])
        self.assertIn("unknown metric", stderr.getvalue())


class TestEvaluation(unittest.TestCase):
    def test_pass_and_fail_with_the_figures(self) -> None:
        results = evaluate(
            [parse_assertion(text) for text in ("block_rate>=95", "p95<=5", "verdict==filtering", "achieved_qps>=1000")],
            SUMMARY,
        )
        self.assertEqual([r.passed for r in results], [True, False, True, True])
        self.assertEqual(results[0].message, "block_rate was 98.2%")
        self.assertEqual(results[1].message, "p95 was 9 ms, needs <= 5 ms")

    def test_a_value_that_was_never_measured_fails(self) -> None:
        """A baseline target blocks nothing, so it has no block rate to meet."""
        [result] = evaluate([parse_assertion("block_rate>=95")], {**SUMMARY, "block_rate": None})
        self.assertFalse(result.passed)
        self.assertIn("not measured", result.message)

    def test_the_default_is_a_working_filter_or_a_baseline(self) -> None:
        for verdict, passed in (("filtering", True), ("baseline", True), ("degraded", False), ("unknown", False)):
            with self.subTest(verdict=verdict):
                [result] = evaluate(DEFAULT_ASSERTIONS, {**SUMMARY, "verdict": verdict})
                self.assertEqual(result.passed, passed)

    def test_the_console_table(self) -> None:
        results = evaluate([parse_assertion("p95<=5")], SUMMARY) + evaluate(
            [parse_assertion("p95<=5")], {**SUMMARY, "target": "Other"}
        )
        text = format_results(results)
        self.assertIn("FAIL  [Lab filter] p95 <= 5", text)
        self.assertIn("2 of 2 failed.", text)


class TestJunit(unittest.TestCase):
    def test_a_suite_per_target_and_a_case_per_assertion(self) -> None:
        other = {**SUMMARY, "target": "A & B <test>", "verdict": "degraded"}
        assertions = [parse_assertion("verdict==filtering"), parse_assertion("p95<=50")]
        xml = junit_xml([(SUMMARY, evaluate(assertions, SUMMARY)), (other, evaluate(assertions, other))])
        root = ET.fromstring(xml)
        self.assertEqual((root.get("tests"), root.get("failures")), ("4", "1"))
        suites = root.findall("testsuite")
        self.assertEqual([s.get("name") for s in suites], ["Lab filter", "A & B <test>"])
        failing = suites[1].find("testcase/failure")
        self.assertIsNotNone(failing)
        self.assertEqual(failing.get("message"), "verdict was degraded, needs == filtering")
        self.assertEqual(suites[0].find("testcase").get("classname"), "dnsloadforge.lab_filter")
        self.assertEqual(suites[0].get("timestamp"), "2027-01-15T08:00:00")


class TestCommandLine(unittest.TestCase):
    def run_cli(self, *extra: str, json_out: bool = False) -> tuple[int, str, str]:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.junit = pathlib.Path(folder.name) / "junit.xml"
        argv = ["run", "--mock", "--no-dashboard", "--duration", "1.5", "--qps", "200", "--personas", "50",
                "--timeout", "0.5", "--no-history", "--quiet", "--junit", str(self.junit), *extra]
        if json_out:
            argv.append("--json")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "_load_lists", return_value=tiny_catalogue()), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(err):
            code = cli.cmd_run(parse(argv))
        return code, out.getvalue(), err.getvalue()

    def test_passing_assertions_exit_zero(self) -> None:
        code, out, _err = self.run_cli("--assert", "p95<=100000", "--assert", "loss<=100")
        self.assertEqual(code, 0, out)
        self.assertIn("All 2 passed.", out)
        root = ET.parse(self.junit).getroot()
        self.assertEqual((root.get("tests"), root.get("failures")), ("2", "0"))

    def test_a_failing_assertion_exits_one(self) -> None:
        code, out, _err = self.run_cli("--assert", "p50<0.0001")
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertEqual(ET.parse(self.junit).getroot().get("failures"), "1")

    def test_json_stays_json(self) -> None:
        code, out, err = self.run_cli("--assert", "p50<0.0001", json_out=True)
        self.assertEqual(code, 1)
        json.loads(out)  # the assertions went to stderr
        self.assertIn("FAIL", err)


class TestMetrics(unittest.TestCase):
    LINE = re.compile(r'^[a-z_]+(\{([a-z_]+="([^"\\]|\\.)*",?)+\})? (-?[0-9.e+-]+|NaN)$')

    def snapshot(self) -> dict:
        stats = StatsAggregator()
        stats.set_run(server="tls://dns.example:853", transport="tls", target_name='Lab "A"', mode="personas")
        stats.on_send(3, 120)
        stats.on_result(qname="example.com", client_ip="10.0.0.9", category="allow_popular", qtype="A",
                        rcode="NOERROR", outcome="allowed", latency_ms=4.0, bytes_received=60, answer_ip="192.0.2.1")
        stats.on_connection(opened=4)
        return stats.snapshot()

    def test_the_text_format(self) -> None:
        text = render_metrics(self.snapshot(), running=True)
        names = set()
        for line in text.splitlines():
            if line.startswith("# TYPE "):
                names.add(line.split()[2])
                continue
            if line.startswith("#"):
                continue
            self.assertRegex(line, self.LINE)
            self.assertIn(re.split(r"[ {]", line)[0], names, "every sample follows its TYPE line")
        self.assertIn("dnsloadforge_running 1", text)
        self.assertIn("dnsloadforge_queries_sent_total 3", text)
        self.assertIn('dnsloadforge_outcomes_total{outcome="allowed"} 1', text)
        self.assertIn("dnsloadforge_connections_open 4", text)
        self.assertIn('target="Lab \\"A\\""', text)
        # Three answers are too few to judge: the one-hot verdict says unknown.
        self.assertIn('dnsloadforge_verdict{status="unknown"} 1', text)
        self.assertIn('dnsloadforge_verdict{status="idle"} 0', text)

    def test_label_escaping(self) -> None:
        self.assertEqual(_label('a"b\\c\nd'), 'a\\"b\\\\c\\nd')

    def test_served_at_metrics(self) -> None:
        http_server, _controller = serve(
            RunConfig(server="127.0.0.1", port=9), synthetic_catalogue(), port=0, autostart=False,
            log=lambda message: None,
        )
        self.addCleanup(http_server.server_close)
        self.addCleanup(http_server.shutdown)
        connection = http.client.HTTPConnection("127.0.0.1", http_server.server_address[1], timeout=5)
        connection.request("GET", "/metrics")
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        connection.close()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), CONTENT_TYPE)
        self.assertIn("dnsloadforge_running 0", body)


class TestSummaryFields(unittest.TestCase):
    def test_servfail_and_drops_are_in_the_summary(self) -> None:
        from dnsloadforge.compare import summarise_run

        snapshot = StatsAggregator().snapshot()
        snapshot["rcodes"]["SERVFAIL"] = 5
        snapshot["totals"]["received"] = 100
        summary = summarise_run(snapshot, RunConfig())
        self.assertEqual(summary["servfail_pct"], 5.0)
        self.assertIn("dropped_pct", summary)


if __name__ == "__main__":
    unittest.main()
