"""Run history across restarts, and the printable report.

The history file is tested for what goes wrong with files: a line half-written
by a crash, growth without bound, a path that cannot be written.  The report is
tested for what it must never do -- run a script, fetch anything, carry a
character a mail client could mangle, or show a run from an earlier session --
and for what it must show.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge import cli  # noqa: E402
from dnsloadforge.engine import run_threaded  # noqa: E402
from dnsloadforge.history import HistoryStore, default_data_dir  # noqa: E402
from dnsloadforge.mockappliance import MockAppliance  # noqa: E402
from dnsloadforge.report import render_report  # noqa: E402
from dnsloadforge.server import REPORT_CSP, RunController, serve  # noqa: E402
from dnsloadforge.spec import RunConfig  # noqa: E402
from dnsloadforge.stats import StatsAggregator  # noqa: E402

from test_cli import parse, tiny_catalogue  # noqa: E402
from test_engine import synthetic_catalogue  # noqa: E402

HOSTILE = "<script>alert(1)</script>.example.com"


def summary(target: str, finished_at: float, **extra) -> dict:
    return {"target": target, "finished_at": finished_at, "verdict": "filtering", "sent": 100, **extra}


class TestHistoryStore(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = pathlib.Path(folder.name) / "sub" / "history.jsonl"

    def test_runs_survive_a_new_store(self) -> None:
        store = HistoryStore(self.path)
        self.assertEqual(store.load(), [])
        for index in range(3):
            self.assertEqual(store.append(summary(f"t{index}", index)), "")
        self.assertEqual([r["target"] for r in HistoryStore(self.path).load()], ["t0", "t1", "t2"])

    def test_a_half_written_line_is_skipped(self) -> None:
        HistoryStore(self.path).append(summary("whole", 1))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write('{"target": "cut sho')
        self.assertEqual([r["target"] for r in HistoryStore(self.path).load()], ["whole"])

    def test_it_keeps_the_last_runs_and_never_grows_without_bound(self) -> None:
        store = HistoryStore(self.path, limit=5)
        for index in range(23):
            store.append(summary(f"t{index}", index))
        self.assertEqual([r["target"] for r in store.load()], [f"t{i}" for i in range(18, 23)])
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.assertLessEqual(len(lines), 4 * 5, "the file was compacted")

    def test_clear(self) -> None:
        store = HistoryStore(self.path)
        store.append(summary("t", 1))
        self.assertEqual(store.clear(), "")
        self.assertEqual(store.load(), [])

    def test_no_path_keeps_nothing_and_a_bad_path_says_why(self) -> None:
        self.assertEqual(HistoryStore(None).append(summary("t", 1)), "")
        self.assertEqual(HistoryStore(None).load(), [])
        self.path.parent.mkdir(parents=True)
        self.path.mkdir()  # a directory where the file should be
        self.assertIn("could not save", HistoryStore(self.path).append(summary("t", 1)))

    def test_the_data_directory_can_be_moved(self) -> None:
        with mock.patch.dict(os.environ, {"DNSLOADFORGE_DATA": str(self.path.parent)}):
            self.assertEqual(default_data_dir(), self.path.parent)


def finished_run(catalogue, appliance: MockAppliance) -> tuple[dict, RunConfig]:
    config = RunConfig(
        server=appliance.host, port=appliance.port, personas=200, target_qps=300.0, duration_s=1.5,
        timeout_s=0.5, seed=5, target_name="Lab <filter>",
    )
    stats = StatsAggregator()
    stats.set_run(server=config.target, target_qps=config.target_qps, seed=config.seed, personas=config.personas)
    run_threaded(config, catalogue, stats=stats, threads=1)
    return stats.snapshot(), config


class TestReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        catalogue = synthetic_catalogue()
        with MockAppliance(
            scenario="overblocker", blocklist=catalogue.blocked_domains(),
            overblock_extra=set(catalogue.domains_for("enterprise")), latency_ms=0.0, jitter_ms=0.0, port=0,
        ) as appliance:
            cls.snapshot, cls.config = finished_run(catalogue, appliance)
        # A name off the wire is attacker-controlled; put one in the findings.
        cls.snapshot["false_positives"].insert(
            0, {"qname": HOSTILE, "category": "enterprise", "rcode": "NXDOMAIN", "count": 1, "qtype": "A", "ede": ""}
        )

    def render(self, **kwargs) -> str:
        return render_report(self.snapshot, self.config, lists={"total": 1234, "fetched_at": 1.0}, **kwargs)

    def test_it_runs_nothing_fetches_nothing_and_is_plain_ascii(self) -> None:
        page = self.render()
        self.assertNotIn("<script", page.lower())
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn(" src=", page)
        self.assertNotIn("url(", page)
        self.assertNotIn("@import", page)
        self.assertNotIn("http://", page)
        self.assertNotIn("https://", page)
        page.encode("ascii")  # raises if not
        self.assertIn("Lab &lt;filter&gt;", page)

    def test_it_shows_the_run(self) -> None:
        page = self.render()
        for heading in ("Results", "The run", "By category", "Wrongly blocked", "Leaked", "How blocks were signalled",
                        "How the run was scored"):
            with self.subTest(heading=heading):
                self.assertIn(f"<h2>{heading}", page)
        self.assertIn("Degraded", page, "an overblocking filter is not reported as filtering")
        self.assertGreater(page.count('class="mono name"'), 1, "the wrongly blocked names are listed")

    def test_the_other_parts_appear_only_when_there_is_something_to_show(self) -> None:
        page = self.render()
        for heading in ("Comparison", "Capacity", "Deployment checks"):
            self.assertNotIn(f"<h2>{heading}", page)
        page = self.render(
            history=[summary("A", 1.0, transport="udp"), summary("B <x>", 2.0, transport="https")],
            capacity={
                "target": {"name": "Lab", "endpoint": "10.0.0.5:53"},
                "slo": {"loss_pct": 1, "servfail_pct": 1, "p95_ms": 100},
                "result": {"summary": "Sustains 2,800 qps."},
                "steps": [{"index": 1, "phase": "ramp", "target_qps": 200, "received": 10, "p95_ms": 5, "status": "pass",
                           "reasons": []}],
            },
            checks={
                "target": {"name": "Lab", "endpoint": "10.0.0.5:53"},
                "finished_at": 1.0,
                "results": [{"status": "warn", "group": "Encrypted DNS", "title": "Firefox canary",
                             "summary": "use-application-dns.net resolves.", "detail": "Answer NXDOMAIN for it."}],
            },
        )
        for heading in ("Comparison", "Capacity", "Deployment checks"):
            self.assertIn(f"<h2>{heading}", page)
        self.assertIn("B &lt;x&gt;", page)
        self.assertIn("Sustains 2,800 qps.", page)
        self.assertIn("Answer NXDOMAIN for it.", page)

    def test_an_empty_session_still_renders(self) -> None:
        page = render_report(StatsAggregator().snapshot(), RunConfig())
        self.assertIn("No run", page)
        self.assertNotIn("<h2>Results", page)


class TestServerAndCommandLine(unittest.TestCase):
    def test_the_report_route_admits_no_script(self) -> None:
        http_server, _controller = serve(
            RunConfig(server="127.0.0.1", port=9), synthetic_catalogue(), port=0, autostart=False,
            log=lambda message: None,
        )
        self.addCleanup(http_server.server_close)
        self.addCleanup(http_server.shutdown)
        connection = http.client.HTTPConnection("127.0.0.1", http_server.server_address[1], timeout=5)
        connection.request("GET", "/report")
        response = connection.getresponse()
        body = response.read().decode("ascii")
        connection.close()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Security-Policy"), REPORT_CSP)
        self.assertNotIn("script-src", REPORT_CSP)
        self.assertIn("default-src 'none'", REPORT_CSP)
        self.assertTrue(response.getheader("Content-Type").startswith("text/html"))
        self.assertIn("DNS filter report", body)

    def test_history_survives_a_restart_but_stays_out_of_the_next_report(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = pathlib.Path(folder.name) / "history.jsonl"
        HistoryStore(path).append(summary("Yesterday's client", time.time() - 86_400))
        controller = RunController(RunConfig(), synthetic_catalogue(), log=lambda _m: None, history_path=path)
        self.assertEqual([r["target"] for r in controller.history_payload()["runs"]], ["Yesterday's client"])
        self.assertNotIn("Yesterday", controller.report_html(), "an earlier session's run is not in this report")
        self.assertTrue(controller.clear_history()["ok"])
        self.assertEqual(controller.history_payload()["runs"], [])
        self.assertFalse(path.exists())

    def test_run_writes_the_report_and_saves_its_history(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        report = pathlib.Path(folder.name) / "out" / "report.html"
        args = parse(
            ["run", "--mock", "--no-dashboard", "--duration", "1.5", "--qps", "200", "--personas", "50",
             "--timeout", "0.5", "--report", str(report), "--quiet"]
        )
        buffer = io.StringIO()
        with mock.patch.dict(os.environ, {"DNSLOADFORGE_DATA": folder.name}), mock.patch.object(
            cli, "_load_lists", return_value=tiny_catalogue()
        ), contextlib.redirect_stdout(buffer):
            code = cli.cmd_run(args)
        self.assertEqual(code, 0, buffer.getvalue())
        self.assertIn("DNS filter report", report.read_text(encoding="ascii"))
        saved = (pathlib.Path(folder.name) / "history.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(saved), 1)
        self.assertEqual(json.loads(saved[0])["target"], "Mock appliance (good)")

    def test_no_history_means_none_is_written(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        args = parse(["run", "--mock", "--no-dashboard", "--duration", "1", "--qps", "200", "--personas", "50",
                      "--timeout", "0.5", "--no-history", "--quiet"])
        with mock.patch.dict(os.environ, {"DNSLOADFORGE_DATA": folder.name}), mock.patch.object(
            cli, "_load_lists", return_value=tiny_catalogue()
        ), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.cmd_run(args), 0)
        self.assertFalse((pathlib.Path(folder.name) / "history.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
