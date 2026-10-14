"""CLI wiring, safety guards and argument parsing.

These exist because of two real bugs that only end-to-end use revealed, both of
which were *wiring* faults that testing the underlying functions could never
have caught:

* ``serve --mock`` accepted the flag and silently ignored it, sending a run at
  ``127.0.0.1:53`` instead of the mock.  ``--mock`` lives in the shared option
  group, so every command that offers it has to honour it.
* ``serve`` never called preflight, so the public-resolver guard could be
  bypassed by launching ``serve`` and pressing Start -- the same traffic against
  the same target, one subcommand away from the check meant to prevent it.

Both are pinned below by driving the real command functions, with the slow
domain-list load and the network probe patched out so the tests stay offline and
fast.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge import cli  # noqa: E402
from dnsloadforge.domainlist import DomainCatalogue, DomainPool  # noqa: E402
from dnsloadforge.spec import Category, RunConfig  # noqa: E402


def tiny_catalogue() -> DomainCatalogue:
    """The smallest catalogue that preflight will accept: one block-listed name,
    one allow-listed name, one enterprise name."""
    pools = {category.value: DomainPool(category.value) for category in Category}
    pools[Category.BLOCK_ADS.value] = DomainPool(
        Category.BLOCK_ADS.value, domains=["ads.example.com"], weights=[1.0]
    )
    pools[Category.ALLOW_POPULAR.value] = DomainPool(
        Category.ALLOW_POPULAR.value, domains=["good.example.com"], weights=[1.0]
    )
    pools[Category.ENTERPRISE.value] = DomainPool(
        Category.ENTERPRISE.value, domains=["login.microsoftonline.com"], weights=[1.0]
    )
    return DomainCatalogue(pools=pools, fetched_at=0.0, offline=True)


def synthetic_catalogue(per_category: int = 40) -> DomainCatalogue:
    """Enough domains in enough categories that the persona model can build without
    falling back, so a real (if tiny) run against the mock is possible offline."""
    pools = {category.value: DomainPool(category.value) for category in Category}
    for category in Category:
        domains = [f"{index:03d}.{category.value}.example.com" for index in range(per_category)]
        pools[category.value] = DomainPool(category.value, domains=domains, weights=[1.0] * len(domains))
    return DomainCatalogue(pools=pools, fetched_at=0.0, offline=True)


def empty_catalogue() -> DomainCatalogue:
    return DomainCatalogue(pools={category.value: DomainPool(category.value) for category in Category})


def parse(argv: list[str]) -> argparse.Namespace:
    return cli.build_parser().parse_args(argv)


class TestArgumentSurface(unittest.TestCase):
    def test_every_command_offering_mock_shares_the_same_group(self) -> None:
        """The bug this guards: `--mock` was present in the shared option group but
        honoured by `run` only, so an operator found out the hard way."""
        for command in ("run", "serve", "bench"):
            with self.subTest(command=command):
                args = parse([command])
                self.assertTrue(hasattr(args, "mock"))
                self.assertTrue(hasattr(args, "allow_public_target"))
                self.assertTrue(hasattr(args, "mock_scenario"))

    def test_defaults_are_the_documented_ones(self) -> None:
        args = parse(["run"])
        self.assertEqual(args.personas, 10_000)
        self.assertEqual(args.port, 53)
        self.assertEqual(args.mode, "personas")
        self.assertEqual(args.max_per_category, cli.DEFAULT_MAX_PER_CATEGORY)
        self.assertFalse(args.allow_public_target)

    def test_lists_caps_domains_by_default(self) -> None:
        self.assertEqual(parse(["lists"]).max_per_category, cli.DEFAULT_MAX_PER_CATEGORY)

    def test_duration_means_something_different_for_bench_and_is_honoured(self) -> None:
        """`bench` runs fixed rate stages, so `--duration` is per stage there.  It used
        to be accepted and ignored, which is the `serve --mock` defect again."""
        self.assertEqual(parse(["run"]).duration, 60.0)
        self.assertEqual(parse(["bench"]).duration, cli.BENCH_STAGE_SECONDS)
        self.assertEqual(parse(["bench", "--duration", "3"]).duration, 3.0)


class TestMainRouting(unittest.TestCase):
    """`main` rewrites bare invocations into the `run` verb.  It is easy to break and
    invisible until someone types `dnsloadforge --server 10.0.0.5` and gets help."""

    def _routing(self) -> tuple[int, argparse.Namespace]:
        recorded: dict[str, argparse.Namespace] = {}

        def fake_run(args: argparse.Namespace) -> int:
            recorded["args"] = args
            return 7

        with mock.patch.object(cli, "cmd_run", fake_run):
            code = cli.main(["--server", "10.0.0.5"])
        return code, recorded["args"]

    def test_bare_options_mean_run(self) -> None:
        code, args = self._routing()
        self.assertEqual(code, 7)
        self.assertEqual(args.command, "run")
        self.assertEqual(args.server, "10.0.0.5")

    def test_an_explicit_verb_is_not_rewritten(self) -> None:
        recorded: dict[str, argparse.Namespace] = {}

        def fake_serve(args: argparse.Namespace) -> int:
            recorded["args"] = args
            return 9

        with mock.patch.object(cli, "cmd_serve", fake_serve):
            code = cli.main(["serve", "--mock"])
        self.assertEqual(code, 9)
        self.assertEqual(recorded["args"].command, "serve")

    def test_an_unknown_word_still_reaches_the_run_parser_and_is_rejected(self) -> None:
        """Silently ignoring an unrecognised verb would be worse than an error."""
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["not-a-command"])


class TestSourceIpParsing(unittest.TestCase):
    def test_comma_list(self) -> None:
        self.assertEqual(cli.parse_source_ips("10.0.0.1,10.0.0.2", None), ["10.0.0.1", "10.0.0.2"])

    def test_range_is_inclusive(self) -> None:
        self.assertEqual(
            cli.parse_source_ips("10.1.0.10-10.1.0.13", None),
            ["10.1.0.10", "10.1.0.11", "10.1.0.12", "10.1.0.13"],
        )

    def test_cidr_skips_network_and_broadcast(self) -> None:
        self.assertEqual(cli.parse_source_ips("10.2.0.0/30", None), ["10.2.0.1", "10.2.0.2"])

    def test_semicolons_are_accepted(self) -> None:
        self.assertEqual(cli.parse_source_ips("10.0.0.1;10.0.0.2", None), ["10.0.0.1", "10.0.0.2"])

    def test_duplicates_are_collapsed(self) -> None:
        self.assertEqual(cli.parse_source_ips("10.0.0.1,10.0.0.1", None), ["10.0.0.1"])

    def test_file_with_comments_and_blanks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "pool.txt"
            path.write_text("# the lab pool\n10.3.0.5\n\n10.3.0.6\n", encoding="utf-8")
            self.assertEqual(cli.parse_source_ips(None, str(path)), ["10.3.0.5", "10.3.0.6"])

    def test_a_backwards_range_is_rejected_rather_than_silently_empty(self) -> None:
        with self.assertRaises(ValueError):
            cli.parse_source_ips("10.1.0.20-10.1.0.10", None)

    def test_garbage_is_rejected(self) -> None:
        for bad in ("not-an-ip", "10.0.0.999", "10.0.0.1-"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                cli.parse_source_ips(bad, None)

    def test_unreadable_file_is_an_error_not_an_empty_pool(self) -> None:
        with self.assertRaises(ValueError):
            cli.parse_source_ips(None, "/definitely/not/here.txt")

    def test_pool_mode_without_addresses_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            cli.build_config(parse(["run", "--mode", "pool"]))

    def test_supplying_addresses_implies_pool_mode(self) -> None:
        config = cli.build_config(parse(["run", "--source-ips", "10.0.0.1"]))
        self.assertEqual(config.mode, "pool")


class TestGuards(unittest.TestCase):
    """The checks that stop this tool being misused or producing a meaningless number."""

    def setUp(self) -> None:
        self.catalogue = tiny_catalogue()
        patch = mock.patch.object(cli, "probe_reachable", return_value=True)
        patch.start()
        self.addCleanup(patch.stop)

    def _preflight(self, argv: list[str], catalogue: DomainCatalogue | None = None) -> list[str]:
        args = parse(argv)
        return cli.preflight(cli.build_config(args), catalogue or self.catalogue, args)

    def test_every_well_known_public_resolver_is_refused_at_load_rate(self) -> None:
        for resolver in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"):
            with self.subTest(resolver=resolver):
                problems = self._preflight(["run", "--server", resolver, "--qps", "5000"])
                self.assertTrue(any("public resolver" in p for p in problems), problems)

    def test_a_polite_rate_at_a_public_resolver_is_allowed(self) -> None:
        """The guard is about hammering somebody, not about touching them at all."""
        self.assertEqual(self._preflight(["run", "--server", "8.8.8.8", "--qps", "50"]), [])

    def test_the_explicit_override_works(self) -> None:
        self.assertEqual(
            self._preflight(
                ["run", "--server", "8.8.8.8", "--qps", "5000", "--allow-public-target"]
            ),
            [],
        )

    def test_mock_mode_is_exempt_so_rehearsal_needs_no_appliance(self) -> None:
        self.assertEqual(self._preflight(["run", "--mock", "--server", "203.0.113.9"]), [])

    def test_an_empty_catalogue_is_refused_with_the_fix_in_the_message(self) -> None:
        problems = self._preflight(["run", "--mock"], empty_catalogue())
        self.assertTrue(any("catalogue is empty" in p for p in problems), problems)
        self.assertTrue(any("lists --refresh" in p for p in problems), problems)

    def test_unassigned_pool_addresses_are_caught_before_a_packet_is_sent(self) -> None:
        problems = self._preflight(
            ["run", "--mode", "pool", "--source-ips", "10.255.255.250"]
        )
        self.assertTrue(any("New-LabSourceIPs.ps1" in p for p in problems), problems)

    def test_zero_personas_or_zero_qps_is_refused(self) -> None:
        self.assertTrue(self._preflight(["run", "--mock", "--personas", "0"]))
        self.assertTrue(self._preflight(["run", "--mock", "--qps", "0"]))


class TestCommandWiring(unittest.TestCase):
    """Drives the real command functions with the slow list load patched out."""

    def setUp(self) -> None:
        self.catalogue = tiny_catalogue()
        lists = mock.patch.object(cli, "_load_lists", return_value=self.catalogue)
        probe = mock.patch.object(cli, "probe_reachable", return_value=True)
        for patch in (lists, probe):
            patch.start()
            self.addCleanup(patch.stop)

    def _run(self, argv: list[str]) -> tuple[int, str]:
        args = parse(argv)
        handler = {"run": cli.cmd_run, "serve": cli.cmd_serve}[args.command]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = handler(args)
        return code, buffer.getvalue()

    def test_serve_refuses_a_public_resolver_instead_of_serving_it(self) -> None:
        """Regression: `serve` skipped preflight entirely."""
        code, output = self._run(["serve", "--server", "8.8.8.8", "--qps", "5000", "--quiet"])
        self.assertEqual(code, 2)
        self.assertIn("public resolver", output)

    def test_run_refuses_a_public_resolver(self) -> None:
        code, output = self._run(["run", "--server", "8.8.8.8", "--qps", "5000", "--quiet"])
        self.assertEqual(code, 2)
        self.assertIn("public resolver", output)

    def test_setup_mock_retargets_the_run_at_the_mock(self) -> None:
        """Regression: `serve --mock` ignored the flag and sent traffic at
        ``127.0.0.1:53``.  `_setup_mock` is the shared path both commands use."""
        args = parse(["serve", "--mock", "--qps", "10"])
        config = RunConfig(server="203.0.113.9", port=53)
        appliance = cli._setup_mock(args, self.catalogue, config)
        self.assertIsNotNone(appliance)
        try:
            self.assertEqual(config.server, appliance.host)
            self.assertEqual(config.port, appliance.port)
            self.assertNotEqual(config.port, 53, "the mock must never be confused with :53")
            self.assertTrue(appliance.running)
        finally:
            appliance.stop()
        self.assertFalse(appliance.running)

    def test_headless_report_names_the_rate_you_actually_asked_for(self) -> None:
        """Regression: `_run_headless` built its own aggregator and never set the run
        metadata, so the report read the schema default and always said "target 0" --
        and `--json` handed that same wrong number to anything consuming it."""
        catalogue = synthetic_catalogue()
        args = parse(
            ["run", "--mock", "--duration", "2", "--qps", "300", "--personas", "40", "--no-dashboard", "--quiet"]
        )
        buffer = io.StringIO()
        with mock.patch.object(cli, "_load_lists", return_value=catalogue):
            with contextlib.redirect_stdout(buffer):
                code = cli.cmd_run(args)
        output = buffer.getvalue()
        self.assertEqual(code, 0, output)
        self.assertIn("target 300", output)
        self.assertNotIn("target 0)", output)

    def test_headless_json_reports_the_real_target(self) -> None:
        catalogue = synthetic_catalogue()
        args = parse(
            ["run", "--mock", "--duration", "2", "--qps", "250", "--personas", "40", "--no-dashboard", "--quiet", "--json"]
        )
        buffer = io.StringIO()
        with mock.patch.object(cli, "_load_lists", return_value=catalogue):
            with contextlib.redirect_stdout(buffer):
                cli.cmd_run(args)
        # --json promises stdout is the report and nothing else, so this parse of the
        # whole buffer is itself part of the assertion.
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["snapshot"]["run"]["target_qps"], 250.0)
        self.assertEqual(payload["snapshot"]["run"]["personas"], 40)

    def test_setup_mock_does_nothing_without_the_flag(self) -> None:
        args = parse(["run", "--server", "203.0.113.9"])
        config = RunConfig(server="203.0.113.9", port=53)
        self.assertIsNone(cli._setup_mock(args, self.catalogue, config))
        self.assertEqual(config.port, 53)


class TestHelpers(unittest.TestCase):
    def test_resolve_threads(self) -> None:
        self.assertEqual(cli.resolve_threads("1"), 1)
        self.assertEqual(cli.resolve_threads("4"), 4)
        self.assertGreaterEqual(cli.resolve_threads("auto"), 1)
        self.assertGreaterEqual(cli.resolve_threads("0"), 1, "never zero senders")

    def test_estimate_record_bytes_tracks_the_run_length(self) -> None:
        self.assertEqual(cli.estimate_record_bytes(10_000, 0), 0)
        small = cli.estimate_record_bytes(1_000, 60)
        large = cli.estimate_record_bytes(10_000, 60)
        self.assertGreater(large, small)
        # 10k qps for a minute must land in the ~100 MB region the README warns about.
        self.assertTrue(80 * 1024**2 < large < 130 * 1024**2, large)

    def test_human_bytes(self) -> None:
        self.assertEqual(cli._human_bytes(512), "512.0 B")
        self.assertEqual(cli._human_bytes(2048), "2.0 KB")
        self.assertEqual(cli._human_bytes(5 * 1024**2), "5.0 MB")

    def test_bench_honours_the_requested_stage_length(self) -> None:
        """A four-stage bench at the requested length, on a tiny catalogue, with the
        real mock appliance -- no network beyond loopback."""
        args = parse(["bench", "--duration", "1", "--personas", "50"])
        buffer = io.StringIO()
        with mock.patch.object(cli, "load_catalogue", return_value=tiny_catalogue()):
            with contextlib.redirect_stdout(buffer):
                code = cli.cmd_bench(args)
        output = buffer.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("1s per stage", output)

    def test_print_table_handles_ragged_cell_widths(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            cli._print_table(("a", "bb"), [("1", "2"), ("333", "4")])
        self.assertIn("333", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
