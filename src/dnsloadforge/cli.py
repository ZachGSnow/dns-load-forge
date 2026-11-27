"""Command line interface.

Six commands, one of which you will actually type:

    python -m dnsloadforge --server 10.0.0.10 --qps 10000

Everything else exists for the moments around that: ``lists`` to warm the domain
cache before you unplug the laptop, ``mock`` to rehearse with no appliance at all,
``bench`` to find out whether the generator or the appliance is the bottleneck,
and ``doctor`` to explain, before sending a single packet, what this machine can
and cannot credibly simulate.

The **preflight check** is the most important thing in this module.  A load
generator aimed at a filtering appliance is easy to misuse in two specific ways --
hammering somebody else's public resolver, and reporting a number the machine
could never have produced -- so both are checked up front and printed in plain
language rather than discovered afterwards.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Sequence

from . import __version__
from .compare import format_comparison, summarise_run
from .domainlist import DomainCatalogue, default_cache_dir, load_catalogue
from .engine import detect_local_ip, run_threaded
from .gates import DEFAULT_ASSERTIONS, METRICS, evaluate, format_results, junit_xml, parse_assertion
from .history import HISTORY_FILE, HistoryStore, default_data_dir
from .mockappliance import SCENARIOS, MockAppliance
from .profiles import ROLES
from .report import render_report
from .server import DEFAULT_HOST, DEFAULT_PORT, COMPARE_COOLDOWN_S, _is_loopback, serve
from .spec import CATEGORY_EXPECTED, DEFAULT_PORTS, TRANSPORT_LABELS, TRANSPORTS, Category, RunConfig
from .stats import StatsAggregator
from .targets import (
    BLOCK_CATEGORIES,
    TARGET_KINDS,
    Target,
    adhoc_target,
    find_target,
    load_targets,
    public_target_problem,
)
from .transports import Endpoint, parse_doh_url, probe

__all__ = ["main", "build_parser"]

#: Resolvers that belong to somebody else.  A load test against these is abuse of a
#: third party's infrastructure, gets the source IP null-routed, and tells you
#: nothing about your own appliance, so it takes an explicit override.
PUBLIC_RESOLVERS = frozenset(
    {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "64.6.64.6", "64.6.65.6", "77.88.8.8",
        "94.140.14.14", "94.140.15.15", "76.76.2.0", "185.228.168.9", "156.154.70.1",
        # The filtered variants of the same services.
        "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", "208.67.222.123", "208.67.220.123",
        "9.9.9.10", "9.9.9.11", "149.112.112.10", "149.112.112.11", "94.140.14.15", "94.140.15.16",
    }
)

#: The same services by the names their DoH and DoT certificates carry, so the
#: guard holds when a run is aimed at a URL rather than an address.
PUBLIC_RESOLVER_NAMES = frozenset(
    {
        "dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one",
        "security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net",
        "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com",
        "doh.familyshield.opendns.com", "dns.adguard-dns.com", "family.adguard-dns.com",
        "unfiltered.adguard-dns.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
    }
)


def is_public_resolver(server: str, tls_name: str = "") -> bool:
    """A well-known public resolver, by address or by certificate name."""
    return server in PUBLIC_RESOLVERS or server.lower() in PUBLIC_RESOLVER_NAMES or tls_name.lower() in PUBLIC_RESOLVER_NAMES

COMMANDS = ("run", "serve", "lists", "targets", "mock", "bench", "doctor", "checks", "capacity")

#: Default per-category domain cap.  The full source set is around 5 million
#: domains, which costs roughly a gigabyte of RAM and 20 seconds of startup; a
#: quarter of a million per category keeps the popular head (where the traffic is)
#: and the high-confidence block entries (which are ordered first by their own
#: feeds) while staying light.  Raise it with --max-per-category when the point of
#: the run is long-tail coverage rather than realistic volume.
DEFAULT_MAX_PER_CATEGORY = 250_000

#: How long each ``bench`` stage runs.  ``bench`` runs fixed rate stages so that two
#: machines can be compared, so its ``--duration`` means "seconds per stage" rather
#: than "seconds to run"; the default is small because running four stages at the
#: shared 60-second default would put an hour behind an innocuous command.
BENCH_STAGE_SECONDS = 5.0


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnsloadforge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Simulate an office's DNS traffic and judge a filtering appliance.\n"
            "\n"
            "Targets are whatever resolver you point it at -- the appliance under test\n"
            "in production use, or the built-in mock appliance (--mock) for rehearsal.\n"
            "All statistics are sender-side, so no capture driver or privileges are\n"
            "needed; use scripts/Get-DnsLoadForgeCapture.ps1 for independent wire-side\n"
            "verification."
        ),
        epilog=(
            "examples:\n"
            "  python -m dnsloadforge lists --refresh              fetch the domain lists\n"
            "  python -m dnsloadforge --mock                       rehearse end to end, no appliance\n"
            "  python -m dnsloadforge --server 10.0.0.10 --qps 10000 --duration 900\n"
            "  python -m dnsloadforge --server 10.0.0.10 --mode pool --source-ips 10.1.50.10-10.1.50.250\n"
            "  python -m dnsloadforge bench                        measure what this box can generate\n"
            "  python -m dnsloadforge doctor                       check readiness before you travel\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"DNS Load Forge {__version__}")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="run a simulation and serve the dashboard")
    _add_common_run_args(run)
    _add_results_args(run, report=True)
    serve_parser = sub.add_parser("serve", help="serve the dashboard and wait for Start")
    _add_common_run_args(serve_parser)
    _add_results_args(serve_parser)
    _add_common_run_args(
        sub.add_parser(
            "bench",
            help="measure generator capacity",
            description=(
                "Measure what this machine can generate.  The rate stages are fixed\n"
                "(20k and 60k qps without network, 10k and 20k against the mock) so that\n"
                "results are comparable between machines and between runs; --qps is\n"
                "therefore not used by this command.  --personas and --duration are.\n"
            ),
        ),
        duration_default=BENCH_STAGE_SECONDS,
        duration_help=f"seconds per benchmark stage (default: {BENCH_STAGE_SECONDS:g})",
    )

    lists = sub.add_parser("lists", help="show or fetch the domain list inventory")
    lists.add_argument("--refresh", action="store_true", help="refetch every source now")
    lists.add_argument("--offline", action="store_true", help="never touch the network")
    lists.add_argument(
        "--max-per-category",
        type=int,
        default=DEFAULT_MAX_PER_CATEGORY,
        help=f"cap domains kept per category (default: {DEFAULT_MAX_PER_CATEGORY:,}; 0 = no cap)",
    )
    lists.add_argument("--only", action="append", default=None, help="restrict to a category or source slug")
    lists.add_argument("--json", action="store_true", help="emit machine-readable output")
    lists.add_argument("--cache-dir", default=None)

    targets = sub.add_parser("targets", help="list the named targets (built-in presets plus targets.json)")
    targets.add_argument("--targets", default=None, help="targets file (default: ./targets.json if present)")
    targets.add_argument("--json", action="store_true", help="emit machine-readable output")

    mock = sub.add_parser("mock", help="run the built-in mock filtering appliance standalone")
    mock.add_argument("--host", default="127.0.0.1")
    mock.add_argument("--port", type=int, default=5353)
    mock.add_argument("--scenario", choices=SCENARIOS, default="good")
    mock.add_argument("--block-mode", choices=("nxdomain", "sinkhole", "refused"), default="nxdomain")
    mock.add_argument("--blocklist-file", default=None)
    mock.add_argument("--drop-rate", type=float, default=None)
    mock.add_argument("--servfail-rate", type=float, default=None)
    mock.add_argument("--latency-ms", type=float, default=None)
    mock.add_argument("--rate-limit-qps", type=float, default=None)
    mock.add_argument(
        "--block-ede",
        type=int,
        default=15,
        metavar="CODE",
        help="Extended DNS Error code attached to blocked answers (0 for none; default 15 Blocked)",
    )
    mock.add_argument(
        "--dga-nxdomain",
        action="store_true",
        help="also NXDOMAIN names that look algorithmic (rehearses an over-eager typo-squat feed)",
    )
    mock.add_argument("--quiet", action="store_true")

    doctor = sub.add_parser("doctor", help="check readiness on this machine")
    doctor.add_argument("--server", default="")
    doctor.add_argument("--port", type=int, default=None, help=_PORT_HELP)
    _add_transport_args(doctor)
    doctor.add_argument("--target", default=None, help="check a named target instead of --server")
    doctor.add_argument("--targets", default=None, help="targets file (default: ./targets.json if present)")
    doctor.add_argument("--source-ips-file", default=None)
    doctor.add_argument("--json", action="store_true")

    checks = sub.add_parser(
        "checks",
        help="check how the filter is deployed: identity, bypass, encrypted DNS, DNSSEC, SafeSearch",
        description=(
            "Deployment checks against one target: which resolver answers, whether DNS on this\n"
            "network is intercepted or can be bypassed, the encrypted-DNS canaries, DNSSEC,\n"
            "rebinding protection, SafeSearch, the vendors' test domains, and whether a blocked\n"
            "name is blocked for every query type.  A few dozen queries in all."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    checks.add_argument("--server", default=None, help="resolver or appliance to check")
    checks.add_argument("--port", type=int, default=None, help=_PORT_HELP)
    _add_transport_args(checks)
    checks.add_argument("--target", action="append", default=None, help="a named target (see `targets`)")
    checks.add_argument("--targets", default=None, help="targets file (default: ./targets.json if present)")
    checks.add_argument("--target-kind", choices=TARGET_KINDS, default=None)
    checks.add_argument(
        "--no-network",
        action="store_true",
        help="skip the checks about this machine's network (interception, bypass), which query public resolvers",
    )
    checks.add_argument("--only", action="append", default=None, help="run only this check id; repeatable")
    checks.add_argument("--timeout", type=float, default=2.0, help="seconds to wait for each answer (default: 2)")
    checks.add_argument("--cache-dir", default=None)
    checks.add_argument("--json", action="store_true", help="emit machine-readable output")

    capacity = sub.add_parser(
        "capacity",
        help="find the highest rate the target sustains within the limits you set",
        description=(
            "Raise the rate step by step, each step a run of the same office traffic, until the\n"
            "target breaks a limit (loss, SERVFAIL, rate limiting, p95 latency); then narrow it\n"
            "down between the last step that passed and the first that failed.  The answer is\n"
            "the rate this mix of names is served at, and why the next step up failed."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_common_run_args(capacity, rates=False, dashboard=False, evidence=False)
    steps = capacity.add_argument_group("search")
    steps.add_argument("--start-qps", type=float, default=200.0, help="the first rate, in queries per second (default: 200)")
    steps.add_argument("--max-qps", type=float, default=20_000.0, help="the highest rate to try (default: 20000)")
    steps.add_argument("--growth", type=float, default=1.5, help="each ramp step is this many times the last (default: 1.5)")
    steps.add_argument("--step-seconds", type=float, default=20.0, help="how long each step runs (default: 20)")
    steps.add_argument(
        "--refine",
        type=int,
        default=2,
        help="steps that bisect between the last pass and the first failure (default: 2)",
    )
    limits = capacity.add_argument_group("limits each step must meet")
    limits.add_argument("--slo-loss", type=float, default=1.0, help="most timeouts and errors, %% of queries (default: 1)")
    limits.add_argument("--slo-servfail", type=float, default=1.0, help="most SERVFAIL answers, %% of answers (default: 1)")
    limits.add_argument("--slo-p95", type=float, default=100.0, help="highest p95 latency, in ms (default: 100)")
    limits.add_argument(
        "--require",
        type=float,
        default=None,
        metavar="QPS",
        help="exit 1 unless the target sustains at least this rate, for scripts and CI",
    )

    return parser


_PORT_HELP = "port on the target (default: 53; 853 for tls, 443 for https)"


def _add_transport_args(group) -> None:
    """How queries reach a bare --server, and how its certificate is checked."""
    group.add_argument(
        "--transport",
        choices=TRANSPORTS,
        default=None,
        help="udp (default), tcp, tls (DNS over TLS) or https (DNS over HTTPS); http is DoH without TLS, "
        "for rehearsing on this machine",
    )
    group.add_argument(
        "--doh-url",
        default=None,
        metavar="URL",
        help="a DNS-over-HTTPS endpoint, such as https://dns.example/dns-query; --server can give its address",
    )
    group.add_argument(
        "--tls-name",
        default=None,
        metavar="NAME",
        help="the name on the server's certificate, when --server is an address (DoT, DoH)",
    )
    group.add_argument(
        "--ca-file",
        default=None,
        metavar="PEM",
        help="trust these CA certificates instead of the system's, for an appliance with its own CA",
    )
    group.add_argument(
        "--insecure",
        action="store_true",
        help="do not check the server's certificate: still encrypted, but not authenticated",
    )


def _add_results_args(parser: argparse.ArgumentParser, *, report: bool = False) -> None:
    """What a session keeps: the run history, and for ``run`` a report."""
    results = parser.add_argument_group("results")
    results.add_argument(
        "--no-history",
        action="store_true",
        help="do not read or save the run history that fills the comparison table across restarts",
    )
    if report:
        results.add_argument(
            "--report",
            default=None,
            metavar="PATH",
            help="when the run ends, write a self-contained HTML report of it to PATH (prints to PDF)",
        )
        results.add_argument(
            "--assert",
            dest="assertions",
            action="append",
            default=[],
            type=_assertion,
            metavar="EXPR",
            help="a limit each run must meet, such as p95<=50, block_rate>=95 or verdict==filtering; repeatable. "
            f"The run exits 1 if one fails. Metrics: {', '.join(METRICS)}",
        )
        results.add_argument(
            "--junit",
            default=None,
            metavar="PATH",
            help="write the assertions' results as JUnit XML for CI (with no --assert, the verdict is checked)",
        )


def _assertion(text: str):
    """--assert, parsed as it is read, so a typo fails before any traffic is sent."""
    try:
        return parse_assertion(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _add_common_run_args(
    parser: argparse.ArgumentParser,
    duration_default: float = 60.0,
    duration_help: str | None = None,
    *,
    rates: bool = True,
    dashboard: bool = True,
    evidence: bool = True,
) -> None:
    """The options every traffic-sending command shares.  A command that sets the
    rate itself (``capacity``) leaves ``rates`` out, and one without a dashboard
    or a record log leaves those out, rather than accepting flags it would ignore."""
    target = parser.add_argument_group("target")
    target.add_argument("--server", default=None, help="resolver or appliance to test (default: 127.0.0.1)")
    target.add_argument("--port", type=int, default=None, help=_PORT_HELP)
    _add_transport_args(target)
    target.add_argument(
        "--target",
        action="append",
        default=None,
        help="a named target (see the `targets` command); repeat it to compare several back to back",
    )
    target.add_argument("--targets", default=None, help="targets file (default: ./targets.json if present)")
    target.add_argument(
        "--target-kind",
        choices=TARGET_KINDS,
        default=None,
        help="how to score a bare --server: appliance (default) or public resolver",
    )
    target.add_argument(
        "--allow-public-target",
        action="store_true",
        help="permit high-rate load against a well-known public resolver (off by default, deliberately)",
    )

    office = parser.add_argument_group("simulated office")
    office.add_argument("--personas", type=int, default=10_000, help="number of simulated workers (default: 10000)")
    if rates:
        office.add_argument("--qps", type=float, default=5_000.0, help="target queries per second (default: 5000)")
        office.add_argument(
            "--duration",
            type=float,
            default=duration_default,
            help=duration_help or "seconds to run; 0 = until stopped (default: 60)",
        )
    office.add_argument("--timeout", type=float, default=2.0, help="per-query timeout in seconds (default: 2)")
    office.add_argument("--seed", type=int, default=1337, help="RNG seed, so two runs are comparable")
    office.add_argument("--role", action="append", default=None, help=f"limit to a role ({', '.join(sorted(ROLES))})")
    office.add_argument("--nxdomain-share", type=float, default=0.04, help="fraction of junk/DGA probes (default: 0.04)")
    office.add_argument("--hot-share", type=float, default=0.70, help="fraction of lookups served from a client's repeat set (default: 0.70)")

    identity = parser.add_argument_group("client identity")
    identity.add_argument(
        "--mode",
        choices=("personas", "pool"),
        default="personas",
        help="personas = one source IP and N logical clients (no privileges); pool = real secondary source IPs",
    )
    identity.add_argument("--source-ips", default=None, help="pool addresses, e.g. 10.1.50.10-10.1.50.250 or a comma list")
    identity.add_argument("--source-ips-file", default=None, help="file of pool addresses, one per line")

    load = parser.add_argument_group("load shaping")
    load.add_argument("--threads", default="1", help="sending threads; 'auto' = one per CPU core (default: 1)")
    load.add_argument("--max-inflight", type=int, default=20_000, help="outstanding-query budget before the generator drops")
    load.add_argument(
        "--connections",
        type=int,
        default=0,
        help="connections per thread for tcp, tls and https (default: 4 for tcp and tls; https sizes and grows "
        "its pool to the rate)",
    )
    if rates:
        load.add_argument("--qps-burst", type=float, default=1.0, help="multiplier for the synchronised burst (1.0 = off)")
        load.add_argument("--burst-period", type=float, default=60.0, help="seconds between synchronised bursts")
        load.add_argument("--burst-len", type=float, default=2.0, help="seconds each synchronised burst lasts")

    if evidence:
        proof = parser.add_argument_group("evidence")
        proof.add_argument("--record-log", nargs="?", const="auto", default=None, help="write raw per-query records to this path")
        proof.add_argument("--record-format", choices=("jsonl", "csv"), default="jsonl")
        proof.add_argument("--record-sample", type=float, default=1.0, help="keep this fraction of records (default: 1.0)")
        proof.add_argument("--no-record-log", action="store_true", help="force the record log off even if configured")
        proof.add_argument(
            "--nsid",
            action="store_true",
            help="ask the target which server instance answered each query (EDNS NSID); shown on the dashboard",
        )

    if dashboard:
        page = parser.add_argument_group("dashboard")
        page.add_argument("--listen-host", default=DEFAULT_HOST, help=f"dashboard bind address (default: {DEFAULT_HOST})")
        page.add_argument("--dashboard-port", type=int, default=DEFAULT_PORT, help=f"dashboard port (default: {DEFAULT_PORT})")
        page.add_argument("--open-dashboard", action="store_true", help="open the dashboard in a browser")
        page.add_argument("--no-dashboard", action="store_true", help="run headless and print the summary only")
        page.add_argument(
            "--allow-remote-dashboard",
            action="store_true",
            help="allow --listen-host to be a non-loopback address. The dashboard can start load tests and has no login.",
        )

    rehearsal = parser.add_argument_group("rehearsal")
    rehearsal.add_argument("--mock", action="store_true", help="start the built-in mock appliance and target it")
    rehearsal.add_argument("--mock-scenario", choices=SCENARIOS, default="good", help="mock behaviour (default: good)")
    rehearsal.add_argument(
        "--mock-overblock",
        action="store_true",
        help="with --mock, also wrongly block the enterprise list so the false-positive report has something to find",
    )

    lists = parser.add_argument_group("domain lists")
    lists.add_argument("--refresh", action="store_true", help="refetch domain lists now")
    lists.add_argument("--offline", action="store_true", help="never touch the network; use the cache only")
    lists.add_argument(
        "--max-per-category",
        type=int,
        default=DEFAULT_MAX_PER_CATEGORY,
        help=(
            f"cap domains loaded per category (default: {DEFAULT_MAX_PER_CATEGORY:,};"
            " 0 = load everything). The cap keeps the head of each ranked list, which is"
            " where realistic traffic concentrates; loading all ~5M domains costs ~1GB"
            " and 20s of startup for a long tail that barely moves the statistics."
        ),
    )
    lists.add_argument("--cache-dir", default=None)

    out = parser.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="print the summary as JSON")
    out.add_argument("--quiet", action="store_true", help="suppress the preflight banner")
    out.add_argument("--yes", action="store_true", help="skip the destructive-target confirmation")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def parse_source_ips(spec: str | None, path: str | None) -> list[str]:
    """Parse an address pool from a range, a comma list, and/or a file.

    Accepts ``10.1.50.10-10.1.50.250``, ``10.1.50.10,10.1.50.11``, or a CIDR
    block, because the file ``New-LabSourceIPs.ps1`` writes is a plain list and
    people reasonably expect to paste a range straight onto the command line.
    """
    addresses: list[str] = []

    def add(item: str) -> None:
        item = item.strip()
        if not item or item.startswith("#"):
            return
        if "-" in item and not item.startswith("-"):
            start_text, _, end_text = item.partition("-")
            try:
                start = ipaddress.IPv4Address(start_text.strip())
                end = ipaddress.IPv4Address(end_text.strip())
            except ipaddress.AddressValueError as exc:
                raise ValueError(f"cannot parse address range {item!r}: {exc}") from exc
            if int(end) < int(start):
                raise ValueError(f"address range {item!r} runs backwards")
            for value in range(int(start), int(end) + 1):
                addresses.append(str(ipaddress.IPv4Address(value)))
        elif "/" in item:
            network = ipaddress.IPv4Network(item, strict=False)
            addresses.extend(str(host) for host in network.hosts())
        else:
            try:
                addresses.append(str(ipaddress.IPv4Address(item)))
            except ipaddress.AddressValueError as exc:
                raise ValueError(f"not an IPv4 address: {item!r}") from exc

    if spec:
        for chunk in spec.replace(";", ",").split(","):
            add(chunk)
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    add(line)
        except OSError as exc:
            raise ValueError(f"cannot read source IP file {path}: {exc}") from exc

    seen: set[str] = set()
    unique = [ip for ip in addresses if not (ip in seen or seen.add(ip))]
    return unique


def _expand(values: Iterable[str] | None) -> list[str]:
    return [v.strip().lower() for v in (values or []) if v and v.strip()]


def resolve_threads(spec: str) -> int:
    if str(spec).strip().lower() == "auto":
        return max(1, min(os.cpu_count() or 1, 16))
    return max(1, int(spec))


def resolve_targets(args: argparse.Namespace) -> tuple[list[Target], list[Target]]:
    """``(available, chosen)``: every target the dashboard may offer, and the ones
    this invocation was asked to run, in order.

    A bare ``--server`` becomes an ad-hoc target.  It is scored as a public resolver
    when the address is a well-known one, so the default rulebook does not condemn
    it for failing to resolve ``corp.local``.
    """
    available = load_targets(getattr(args, "targets", None))
    names = getattr(args, "target", None) or []
    server = getattr(args, "server", None)
    if names:
        if server:
            raise ValueError("use either --server or --target, not both")
        if any(getattr(args, flag, None) for flag in ("transport", "doh_url", "tls_name")):
            raise ValueError(
                "a named target carries its own transport; give --transport, --doh-url and --tls-name with "
                "--server, or set them on the target in targets.json"
            )
        chosen = [find_target(name, available) for name in names]
        return available, chosen
    chosen = [_adhoc_from_args(args)]
    return [*chosen, *[t for t in available if t.name != chosen[0].name]], chosen


def _adhoc_from_args(args: argparse.Namespace) -> Target:
    """The target a bare --server (or --doh-url) describes."""
    server = getattr(args, "server", None) or ""
    transport = getattr(args, "transport", None) or "udp"
    tls_name = getattr(args, "tls_name", None) or ""
    port = getattr(args, "port", None)
    path = "/dns-query"
    url = getattr(args, "doh_url", None)
    if url:
        if getattr(args, "transport", None) not in (None, "https", "http"):
            raise ValueError("--doh-url is DNS over HTTPS; leave --transport out, or set it to https")
        transport, host, url_port, path = parse_doh_url(url)
        if transport == "https" and not tls_name:
            tls_name = host
        server = server or host
        port = url_port if port is None else port
    server = server or "127.0.0.1"
    kind = getattr(args, "target_kind", None) or ("public" if is_public_resolver(server, tls_name) else "appliance")
    return adhoc_target(server, port, kind, transport=transport, tls_name=tls_name, doh_path=path)


def catalogue_loader(args: argparse.Namespace):
    """A callable that rebuilds the catalogue from the cache with this run's
    settings.  The dashboard uses it after a list refresh, so the new data is shaped
    exactly as the one it replaces (same per-category cap, same filters)."""

    def load() -> DomainCatalogue:
        return load_catalogue(
            getattr(args, "cache_dir", None),
            offline=True,
            max_per_category=getattr(args, "max_per_category", None) or None,
            only=_expand(getattr(args, "only", None)) or None,
            verbose=False,
        )

    return load


def check_dashboard_bind(args: argparse.Namespace) -> None:
    host = getattr(args, "listen_host", DEFAULT_HOST)
    if not _is_loopback(host) and not getattr(args, "allow_remote_dashboard", False):
        raise ValueError(
            f"--listen-host {host} would expose the dashboard to your network. It can start load tests "
            f"and has no login. Use 127.0.0.1, or pass --allow-remote-dashboard if you really mean it."
        )


def build_config(args: argparse.Namespace, target: Target | None = None) -> RunConfig:
    if target is None:
        target = resolve_targets(args)[1][0]
    source_ips = parse_source_ips(getattr(args, "source_ips", None), getattr(args, "source_ips_file", None))
    mode = getattr(args, "mode", "personas")
    if source_ips and mode == "personas":
        mode = "pool"
    if mode == "pool" and not source_ips:
        raise ValueError("pool mode needs --source-ips or --source-ips-file")

    categories = [c.value for c in Category]
    only = _expand(getattr(args, "only", None))
    if only:
        categories = [c for c in categories if c in only] or [c.value for c in Category]

    config = RunConfig(
        server=getattr(args, "server", None) or "127.0.0.1",
        port=int(getattr(args, "port", None) or DEFAULT_PORTS["udp"]),
        mode=mode,
        personas=int(getattr(args, "personas", 10_000)),
        target_qps=float(getattr(args, "qps", 5_000.0)),
        duration_s=float(getattr(args, "duration", 60.0)),
        timeout_s=float(getattr(args, "timeout", 2.0)),
        seed=int(getattr(args, "seed", 1337)),
        source_ips=source_ips,
        threads=resolve_threads(getattr(args, "threads", "1")),
        max_inflight=int(getattr(args, "max_inflight", 20_000)),
        qps_burst=float(getattr(args, "qps_burst", 1.0)),
        qps_burst_period_s=float(getattr(args, "burst_period", 60.0)),
        qps_burst_len_s=float(getattr(args, "burst_len", 2.0)),
        categories=categories,
        export_path="",
        nsid=bool(getattr(args, "nsid", False)),
        tls_verify=not getattr(args, "insecure", False),
        ca_file=getattr(args, "ca_file", None) or "",
        connections=max(0, int(getattr(args, "connections", 0) or 0)),
    )
    return target.apply(config)


def estimate_record_bytes(qps: float, duration_s: float) -> int:
    """Rough per-record cost of the log, for the disk warning.

    Measured against real records rather than guessed: a JSONL record with a
    typical hostname and a JSON number for the timestamp lands around 180 bytes.
    """
    if duration_s <= 0:
        return 0
    return int(qps * duration_s * 180)


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[object]], indent: str = "  ") -> None:
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    line = indent + "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print(indent + "  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print(indent + "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


def _human_bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024.0:
            return f"{value:,.1f} {unit}"
        value /= 1024.0
    return f"{value:,.1f} PB"


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------


def preflight(
    config: RunConfig,
    catalogue: DomainCatalogue,
    args: argparse.Namespace,
    targets: Sequence[Target] = (),
) -> list[str]:
    """Check the things that make a run meaningless, and say so before it starts.

    Returns a list of blocking problems.  Everything here was chosen because
    getting it wrong produces a *plausible* result rather than an obvious error,
    which is the dangerous kind.
    """
    problems: list[str] = []
    warnings: list[str] = []

    if config.personas <= 0:
        problems.append("--personas must be greater than zero")
    if config.target_qps <= 0:
        problems.append("--qps must be greater than zero")
    if config.timeout_s <= 0:
        problems.append("--timeout must be greater than zero")

    mock_mode = bool(getattr(args, "mock", False))
    if is_public_resolver(config.server, config.tls_name) and not mock_mode:
        if config.target_qps > 100 and not getattr(args, "allow_public_target", False):
            problems.append(
                f"{config.target} is a public resolver, not your appliance. Driving it at "
                f"{config.target_qps:,.0f} qps is abuse of a third party's infrastructure and tells you "
                f"nothing about your own filter. Target the appliance, or pass --mock to rehearse, "
                f"or --allow-public-target if this really is your own service."
            )
        elif config.target_qps > 100:
            warnings.append(f"targeting public resolver {config.server} with an explicit override")

    # Named targets get the same protection whether or not their address is on the
    # well-known list above: a cloud filter is somebody else's service either way.
    # Every target in a comparison is checked up front, so a run does not get to its
    # third target before refusing.
    if not mock_mode:
        for target in targets:
            if target.server == config.server and is_public_resolver(target.server, target.tls_name):
                continue
            problem = public_target_problem(target, config.target_qps, getattr(args, "allow_public_target", False))
            if problem:
                problems.append(problem)

    # Reachability: a UDP send succeeds even when nothing is listening, so the only
    # way to catch a wrong address before wasting a run is an explicit probe.
    try:
        ipaddress.IPv4Address(config.server)
        family = socket.AF_INET
    except ipaddress.AddressValueError:
        try:
            resolved = socket.gethostbyname(config.server)
            warnings.append(f"{config.server} resolved to {resolved}; use the literal address if this surprises you")
            family = socket.AF_INET
        except OSError:
            problems.append(f"cannot resolve target host {config.server!r}")
            return problems

    if not problems and not mock_mode:
        reachable, why = probe_target(config)
        if not reachable:
            problems.append(
                f"nothing answered a DNS probe on {config.target}"
                + (f": {why}" if why else "")
                + ". Check that the appliance is listening, that the port is right, and that a firewall is not "
                "dropping you. Pass --mock to rehearse without an appliance."
            )

    if not problems and not mock_mode:
        for target in list(targets)[1:]:
            other = target.apply(config)
            if other.target == config.target:
                continue
            reachable, why = probe_target(other)
            if not reachable:
                problems.append(f"nothing answered a DNS probe on {other.target} ({target.name}): {why or 'no answer'}.")

    total = catalogue.total()
    if total == 0:
        problems.append(
            "the domain catalogue is empty. Run `python -m dnsloadforge lists --refresh` while online, "
            "or pass --mock which needs no lists beyond the built-in curated set."
        )
    elif not any(catalogue.has(c.value) for c in Category if CATEGORY_EXPECTED.get(c.value) != "unknown"):
        problems.append("no block- or allow-listed domains are loaded, so nothing can be judged")

    if config.mode == "pool":
        local = {addr for addr in _local_addresses()}
        missing = [ip for ip in config.source_ips if ip not in local]
        if missing:
            problems.append(
                f"{len(missing)} pool addresses are not assigned to any interface on this machine "
                f"(first: {missing[0]}). Run scripts/New-LabSourceIPs.ps1 to create them; it needs an "
                f"elevated session. Pool mode cannot bind an address the host does not own."
            )
    else:
        warnings.append(
            "persona mode: the appliance will see one source IP and "
            f"{config.personas:,} simulated clients. Per-client policy cannot be tested this way -- "
            "use --mode pool with real secondary addresses when identity matters."
        )

    return problems


def probe_target(config: RunConfig, attempts: int = 2, timeout: float = 1.5) -> tuple[bool, str]:
    """Send a real DNS query over the run's transport and wait for a real answer:
    ``(answered, why not)``.

    UDP gives no connection-refused signal on Linux and an inconsistent one on
    Windows, so the only honest readiness test is to ask a question and see
    whether an answer comes back.
    """
    return probe(Endpoint.from_config(config), timeout=timeout, attempts=attempts)


def probe_reachable(config: RunConfig, attempts: int = 2, timeout: float = 1.5) -> bool:
    return probe_target(config, attempts=attempts, timeout=timeout)[0]


def _local_addresses() -> list[str]:
    addresses = ["127.0.0.1"]
    try:
        import psutil  # type: ignore

        for name, entries in psutil.net_if_addrs().items():
            for entry in entries:
                if entry.family == socket.AF_INET:
                    addresses.append(entry.address)
        return addresses
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        addresses.extend(socket.gethostbyname_ex(hostname)[2])
    except OSError:
        pass
    return addresses


# ---------------------------------------------------------------------------
# console reporting
# ---------------------------------------------------------------------------


def print_banner(config: RunConfig, catalogue: DomainCatalogue, args: argparse.Namespace) -> None:
    print(f"DNS Load Forge {__version__}")
    print(f"  target          {config.target}  ({config.mode} mode, {config.threads} thread(s))")
    if config.transport != "udp":
        detail = ""
        if config.transport in ("tls", "https"):
            detail = ", certificate checked" if config.tls_verify else ", certificate NOT checked (--insecure)"
        pool = f"{config.connections} connection(s)" if config.connections else "a connection pool"
        print(f"  transport       {TRANSPORT_LABELS[config.transport]}{detail}; {pool} per thread")
    print(f"  simulated        {config.personas:,} workers across {len(config.source_ips) or 1} source IP(s)")
    print(f"  load            {config.target_qps:,.0f} qps for {config.duration_s:g}s"
          f" ({config.target_qps * max(config.duration_s, 0):,.0f} queries)")
    if config.qps_burst > 1.0:
        print(f"  sync burst      x{config.qps_burst:g} for {config.qps_burst_len_s:g}s every {config.qps_burst_period_s:g}s")
    print(f"  per client      {config.target_qps * 3600 / max(config.personas, 1):,.0f} queries/hour at peak")
    print(f"  timeout         {config.timeout_s:g}s, in-flight cap {config.max_inflight:,}")
    print("  domain mix:")
    rows = [
        (row["label"], row["count"], row["expect"], row["source"] or "-")
        for row in catalogue.summary()
        if row["count"]
    ]
    _print_table(("category", "domains", "expect", "source"), rows)
    print(f"  cached lists in {default_cache_dir()}")


def print_summary(summary: dict, *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(summary, indent=2, default=str))
        return
    snapshot = summary.get("snapshot", {})
    run = snapshot.get("run", {})
    totals = snapshot.get("totals", {})
    rates = snapshot.get("rates", {})
    latency = snapshot.get("latency_ms", {})

    print()
    print("=" * 78)
    print("RESULT")
    print("=" * 78)
    if summary.get("error"):
        print(f"  RUN FAILED: {summary['error']}")
        return
    verdict = summary.get("verdict", {})
    print(f"  verdict         {verdict.get('status', 'unknown').upper()}")
    print(f"  {verdict.get('note', '')}")
    print()
    print(f"  sent            {summary.get('sent', 0):,} queries in {run.get('elapsed_s', 0):,.1f}s")
    print(f"  achieved        {summary.get('achieved_qps', 0):,.0f} qps (target {run.get('target_qps', 0):,.0f})")
    print(f"  answered        {summary.get('received', 0):,}   timeouts {summary.get('timeouts', 0):,}"
          f"   errors {summary.get('errors', 0):,}   generator drops {summary.get('dropped', 0):,}")
    print(f"  bytes           sent {_human_bytes(totals.get('bytes_sent', 0))}"
          f"  received {_human_bytes(totals.get('bytes_received', 0))}")
    print(f"  clients         {totals.get('unique_clients', 0):,}   domains touched {totals.get('unique_domains', 0):,}")
    print(f"  latency         p50 {latency.get('p50', 0):.1f}ms  p95 {latency.get('p95', 0):.1f}ms"
          f"  p99 {latency.get('p99', 0):.1f}ms  max {latency.get('max', 0):.1f}ms")
    if summary.get("malformed"):
        print(f"  malformed       {summary['malformed']:,} unparseable responses")

    rcodes = snapshot.get("rcodes", {})
    nonzero = [(k, v) for k, v in rcodes.items() if v]
    if nonzero:
        print()
        print("  response codes:")
        _print_table(("rcode", "count", "share of answered"), [
            (name, f"{count:,}",
             f"{100.0 * count / max(summary.get('received', 1), 1):.1f}%")
            for name, count in sorted(nonzero, key=lambda kv: kv[1], reverse=True)
        ], indent="    ")

    print()
    print("  by category:")
    rows = []
    for row in snapshot.get("by_category", []):
        if not row.get("sent"):
            continue
        rows.append(
            (
                row["label"],
                row["expect"],
                f"{row['sent']:,}",
                f"{row['blocked']:,}",
                f"{row['allowed']:,}",
                f"{row['fp']:,}",
                f"{row['fn']:,}",
                f"{row['p95']:.0f}ms",
                f"{100.0 * row['pass_rate']:.1f}%",
            )
        )
    if rows:
        _print_table(("category", "expect", "sent", "blocked", "allowed", "FP", "FN", "p95", "pass"), rows, indent="    ")

    for key, title in (("false_positives", "FALSE POSITIVES (legitimate traffic blocked)"),
                       ("false_negatives", "FALSE NEGATIVES (known-bad traffic allowed)")):
        findings = snapshot.get(key, [])
        print()
        print(f"  {title}: {len(findings)} distinct name/client pair(s)")
        if findings:
            detail = "rcode" if key == "false_positives" else "answer"
            _print_table(
                ("domain", "category", "client", "count", detail),
                [(f["qname"], f["category"], f["client_ip"], f["count"], f.get(detail, "")) for f in findings[:10]],
                indent="    ",
            )
            if len(findings) > 10:
                print(f"    ... and {len(findings) - 10} more")

    if summary.get("record_log"):
        print()
        print(f"  raw records     {summary['record_log']}")
    print("=" * 78)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def _load_lists(args: argparse.Namespace) -> DomainCatalogue:
    return load_catalogue(
        getattr(args, "cache_dir", None),
        refresh=bool(getattr(args, "refresh", False)),
        offline=bool(getattr(args, "offline", False)),
        max_per_category=getattr(args, "max_per_category", None) or None,
        only=_expand(getattr(args, "only", None)) or None,
        verbose=not getattr(args, "quiet", False),
    )


def cmd_lists(args: argparse.Namespace) -> int:
    catalogue = _load_lists(args)
    if getattr(args, "json", False):
        print(json.dumps({"total": catalogue.total(), "categories": catalogue.summary()}, indent=2))
        return 0
    print(f"Domain list inventory (cache: {default_cache_dir()})")
    print()
    rows = [
        (row["label"], f"{row['count']:,}", row["expect"], "cache" if row["cached"] else "fetched", row["source"] or "-")
        for row in catalogue.summary()
    ]
    _print_table(("category", "domains", "expect", "state", "source"), rows)
    print()
    print(f"  total {catalogue.total():,} domains")
    print(f"  manifest {default_cache_dir() / 'manifest.json'}")
    return 0


def cmd_targets(args: argparse.Namespace) -> int:
    targets = load_targets(getattr(args, "targets", None))
    if getattr(args, "json", False):
        print(json.dumps([t.as_dict() for t in targets], indent=2))
        return 0
    rows = []
    for target in targets:
        blocks = target.blocks if target.blocks is not None else list(BLOCK_CATEGORIES)
        rows.append(
            (
                target.name,
                target.endpoint,
                TRANSPORT_LABELS[target.transport],
                target.kind,
                ", ".join(c.replace("block_", "") for c in blocks) or "(none - baseline)",
                "preset" if target.builtin else "file",
            )
        )
    print("Named targets (use with --target NAME; repeat --target to compare)")
    print()
    _print_table(("name", "endpoint", "via", "kind", "expected to block", "from"), rows)
    print()
    print("  Presets describe each service's published behaviour -- check it against current")
    print("  documentation before relying on a verdict. Add your own in targets.json.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    target: Target | None = None
    if getattr(args, "target", None):
        target = find_target(args.target, load_targets(getattr(args, "targets", None)))
        args.server = target.server
    elif args.server or getattr(args, "doh_url", None):
        target = _adhoc_from_args(args)
        args.server = target.server
    findings: list[tuple[str, str, str]] = []

    def add(check: str, status: str, detail: str) -> None:
        findings.append((check, status, detail))

    add("python", "ok" if sys.version_info >= (3, 10) else "fail", f"{sys.version.split()[0]} on {sys.platform}")
    add("admin", "info", "elevated" if _is_admin() else "not elevated (fine for persona mode; pool mode and pktmon capture need it)")

    local_ip = detect_local_ip(args.server or "8.8.8.8")
    add("source address", "ok", f"traffic would originate from {local_ip}")

    catalogue = load_catalogue(offline=True, verbose=False)
    total = catalogue.total()
    add(
        "domain lists",
        "ok" if any(catalogue.has(c.value) for c in Category if CATEGORY_EXPECTED.get(c.value) == "block") else "warn",
        f"{total:,} domains cached; {sum(1 for r in catalogue.summary() if r['count'])} categories populated",
    )
    if total <= 300:
        add(
            "domain lists",
            "warn",
            "only the built-in curated lists are present -- run `lists --refresh` while online for a realistic mix",
        )

    if args.source_ips_file:
        try:
            pool = parse_source_ips(None, args.source_ips_file)
            present = set(_local_addresses())
            missing = [ip for ip in pool if ip not in present]
            add(
                "source IP pool",
                "ok" if not missing else "fail",
                f"{len(pool)} addresses in file, {len(missing)} not assigned to this host",
            )
        except ValueError as exc:
            add("source IP pool", "fail", str(exc))

    if target is not None:
        config = target.apply(RunConfig(tls_verify=not args.insecure, ca_file=args.ca_file or ""))
        reachable, why = probe_target(config)
        add(
            "target",
            "ok" if reachable else "fail",
            f"{config.target} answered a test query"
            if reachable
            else f"{config.target} did not answer: {why or 'check address, port and firewall'}",
        )
        if is_public_resolver(target.server, target.tls_name):
            add("target", "warn", f"{target.name} is a public resolver, not an appliance under test")

    try:
        import psutil  # type: ignore

        cpu = psutil.cpu_count(logical=True) or 1
        memory = psutil.virtual_memory().total
        add("capacity", "info", f"{cpu} logical cores, {_human_bytes(memory)} RAM")
    except Exception:
        add("capacity", "info", f"{os.cpu_count() or 1} logical cores")

    if getattr(args, "json", False):
        print(json.dumps([{"check": c, "status": s, "detail": d} for c, s, d in findings], indent=2))
    else:
        print("DNS Load Forge readiness check")
        print()
        _print_table(("check", "status", "detail"), [(c, s.upper(), d) for c, s, d in findings], indent="  ")
        print()
        if any(s == "fail" for _c, s, _d in findings):
            print("  One or more checks failed; fix those before running a test.")
        else:
            print("  Ready.")

    return 1 if any(s == "fail" for _c, s, _d in findings) else 0


def _is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except Exception:
            return False


def _record_path(args: argparse.Namespace, config: RunConfig) -> str:
    if getattr(args, "no_record_log", False):
        return ""
    requested = getattr(args, "record_log", None)
    if requested is None:
        return ""
    if requested == "auto":
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return str(Path("runs") / stamp / f"run-{{run}}.records.{args.record_format}")
    return requested


def _setup_mock(args: argparse.Namespace, catalogue: DomainCatalogue, config: RunConfig) -> MockAppliance | None:
    """Start the built-in simulator and retarget the run at it, if requested.

    Shared by ``run`` and ``serve`` on purpose.  It was originally inline in
    ``run``, and ``serve`` therefore accepted ``--mock`` and silently ignored it --
    sending a run at 127.0.0.1:53 instead.  A flag that appears in the shared option
    group has to mean the same thing in every command that offers it, or an operator
    finds out the hard way.
    """
    if not getattr(args, "mock", False):
        return None
    mock = _start_mock(args, catalogue)
    # The mock answers UDP and TCP on one port and DoH over plain HTTP on another.
    # It has no certificate, so DoT is rehearsed as TCP and DoH without the TLS.
    wanted = config.transport
    variant = _MOCK_VARIANTS.get(wanted, "")
    config.server = mock.host
    config.tls_name = ""
    if wanted in ("https", "http"):
        config.transport, config.port, config.doh_path = "http", mock.doh_port or 0, "/dns-query"
    else:
        config.transport = "tcp" if wanted in ("tcp", "tls") else "udp"
        config.port = mock.port
    config.target_name = _mock_name(args) + variant
    if wanted in ("tls", "https") and not getattr(args, "json", False):
        print(f"  the mock has no certificate, so {TRANSPORT_LABELS[wanted]} is rehearsed as {TRANSPORT_LABELS[config.transport]}")
    _wait_for_mock(mock)
    return mock


#: What the mock targets are called, by the transport they rehearse.
_MOCK_VARIANTS = {"udp": "", "tcp": " over TCP", "tls": " over TCP", "https": " over DoH", "http": " over DoH"}


def _mock_name(args: argparse.Namespace) -> str:
    # Name what it will actually do: an overblocking "good" mock is not a good filter.
    behaviour = "overblocking" if getattr(args, "mock_overblock", False) else args.mock_scenario
    return f"Mock appliance ({behaviour})"


def _with_mock_target(
    available: list[Target], original: Target, mock: MockAppliance, config: RunConfig, args: argparse.Namespace
) -> list[Target]:
    """Put the mock first in the dashboard's target list, once per transport it
    answers, so UDP, TCP and DoH can be compared on it.  A bare ``--server``
    default that the mock replaced is dropped, so the picker does not offer a
    target nobody asked for; a named ``--target`` is kept."""
    base = _mock_name(args)
    mocks = [Target(name=base, server=mock.host, port=mock.port)]
    if mock.tcp_port:
        mocks.append(Target(name=f"{base} over TCP", server=mock.host, port=mock.tcp_port, transport="tcp"))
    if mock.doh_port:
        mocks.append(Target(name=f"{base} over DoH", server=mock.host, port=mock.doh_port, transport="http"))
    kept = [t for t in available if not (t is original and not t.builtin and t.name == original.name)]
    return [*mocks, *kept]


def cmd_run(args: argparse.Namespace) -> int:
    check_dashboard_bind(args)
    available, chosen = resolve_targets(args)
    config = build_config(args, chosen[0])
    catalogue = _load_lists(args)

    mock = _setup_mock(args, catalogue, config)
    if mock is not None:
        available = _with_mock_target(available, chosen[0], mock, config, args)
        chosen = chosen[:1]
    # Under --json stdout is the report and nothing else, or anything consuming it
    # (a jq pipeline, a wrapper script) chokes on the chatter that precedes it.
    if mock is not None and not getattr(args, "json", False):
        print(f"mock appliance listening on {config.target} (scenario: {args.mock_scenario})")

    if not getattr(args, "quiet", False) and not getattr(args, "json", False):
        print_banner(config, catalogue, args)

    problems = preflight(config, catalogue, args, chosen)
    if problems:
        print()
        print("Cannot start:")
        for problem in problems:
            print(f"  - {problem}")
        if mock is not None:
            mock.stop()
        return 2

    if len(chosen) > 1 and config.duration_s <= 0:
        print()
        print("Cannot start:")
        print("  - comparing targets needs a finite --duration, so each one gets the same traffic")
        return 2

    record_path = _record_path(args, config)
    if record_path and not getattr(args, "json", False):
        estimate = estimate_record_bytes(config.target_qps, config.duration_s)
        print()
        print(f"  record log      {record_path}"
              + (f" (~{_human_bytes(estimate)} estimated)" if estimate else " (until stopped)"))

    if getattr(args, "no_dashboard", False):
        return _run_headless(config, catalogue, args, record_path, mock, chosen)

    server, controller = serve(
        config,
        catalogue,
        host=args.listen_host,
        port=args.dashboard_port,
        record_log_path=record_path,
        record_format=args.record_format,
        record_sample=args.record_sample,
        autostart=True,
        log=lambda message: print(f"  [{datetime.now().strftime('%H:%M:%S')}] {message}"),
        targets=available,
        catalogue_loader=catalogue_loader(args),
        cache_dir=getattr(args, "cache_dir", None),
        allow_public_target=getattr(args, "allow_public_target", False),
        start_payload={"targets": [t.name for t in chosen]} if len(chosen) > 1 else None,
        history_path=_history_path(args),
    )
    print()
    print(f"  dashboard       {server.url}")
    if args.open_dashboard:
        try:
            webbrowser.open(server.url)
        except Exception:
            pass

    try:
        if config.duration_s > 0:
            per_run = config.duration_s + config.timeout_s + COMPARE_COOLDOWN_S + 30
            controller.wait(timeout=per_run * len(chosen))
        else:
            print("  running until stopped -- press Ctrl-C to end the run")
            while controller.running:
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n  interrupted, stopping the run...")
        controller.stop()

    summary = controller.summary()
    print_summary(summary, as_json=args.json)
    _write_report(args, controller.report_html)
    failed = _check_gates(args, controller.session_history())

    if len(controller.history) > 1 and not getattr(args, "json", False):
        print()
        print("COMPARISON (same seed and traffic for every target)")
        print(format_comparison(controller.history))

    if mock is not None:
        if not getattr(args, "json", False):
            print(f"  mock appliance counters: {mock.stats}")
        mock.stop()

    print()
    print(f"  dashboard still serving the final results at {server.url} -- press Ctrl-C to exit")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 1 if summary.get("error") or failed else 0


def _run_headless(
    config: RunConfig,
    catalogue: DomainCatalogue,
    args: argparse.Namespace,
    record_path: str,
    mock: MockAppliance | None,
    chosen: Sequence[Target] = (),
) -> int:
    from .stats import RecordLog

    if len(chosen) > 1:
        return _run_headless_compare(config, catalogue, args, chosen)

    stats = StatsAggregator()
    # Same metadata the dashboard path sets in RunController.__init__.  Without it the
    # end-of-run report read the schema defaults and printed "target 0" no matter what
    # --qps was, and --json emitted that same wrong number to whatever consumed it.
    stats.set_run(
        server=config.target,
        transport=config.transport,
        mode=config.mode,
        personas=config.personas,
        source_ips=len(config.source_ips) or 1,
        target_qps=config.target_qps,
        seed=config.seed,
    )
    record_log = RecordLog(record_path, fmt=args.record_format, sample=args.record_sample) if record_path else None
    started = time.time()
    try:
        results = run_threaded(
            config,
            catalogue,
            stats=stats,
            record_log=record_log,
            threads=config.threads,
        )
    except KeyboardInterrupt:
        print("\n  interrupted")
        return 130
    finally:
        if record_log is not None:
            record_log.close()

    snapshot = stats.snapshot()
    summary = {
        "runs": len(results),
        "sent": sum(r.sent for r in results),
        "received": sum(r.received for r in results),
        "timeouts": sum(r.timeouts for r in results),
        "errors": sum(r.errors for r in results),
        "dropped": sum(r.dropped for r in results),
        "malformed": sum(r.malformed for r in results),
        "achieved_qps": round(sum(r.achieved_qps for r in results), 1),
        "verdict": snapshot.get("verdict", {}),
        "snapshot": snapshot,
        "record_log": record_path,
        "error": "",
        "wall_seconds": round(time.time() - started, 2),
    }
    print_summary(summary, as_json=args.json)
    record = summarise_run(snapshot, config, index=1)
    record["achieved_qps"] = summary["achieved_qps"]
    _save_history(args, [record])
    _write_report(
        args,
        lambda: render_report(
            snapshot, config, history=[record], lists=_lists_info(catalogue), achieved_qps=summary["achieved_qps"]
        ),
    )
    failed = _check_gates(args, [record])
    if mock is not None:
        if not getattr(args, "json", False):
            print(f"  mock appliance counters: {mock.stats}")
        mock.stop()
    return 1 if failed else 0


def _run_headless_compare(
    config: RunConfig,
    catalogue: DomainCatalogue,
    args: argparse.Namespace,
    chosen: Sequence[Target],
) -> int:
    """Run each target in turn on the same seed and print them side by side."""
    summaries: list[dict] = []
    last: tuple[dict, RunConfig, float] | None = None
    for index, target in enumerate(chosen):
        if index:
            time.sleep(COMPARE_COOLDOWN_S)
        run_config = target.apply(config)
        stats = StatsAggregator()
        stats.set_run(
            server=run_config.target,
            transport=run_config.transport,
            target_name=run_config.target_name,
            mode=run_config.mode,
            personas=run_config.personas,
            source_ips=len(run_config.source_ips) or 1,
            target_qps=run_config.target_qps,
            seed=run_config.seed,
        )
        if not getattr(args, "json", False):
            print(f"\n  [{index + 1}/{len(chosen)}] {target.name} ({run_config.target})")
        try:
            results = run_threaded(run_config, catalogue, stats=stats, threads=run_config.threads)
        except KeyboardInterrupt:
            print("\n  interrupted")
            break
        last = (stats.snapshot(), run_config, sum(r.achieved_qps for r in results))
        summaries.append(summarise_run(last[0], run_config, index=index + 1))
        summaries[-1]["achieved_qps"] = round(last[2], 1)

    if getattr(args, "json", False):
        print(json.dumps({"runs": summaries}, indent=2, default=str))
    else:
        print()
        print("COMPARISON (same seed and traffic for every target)")
        print(format_comparison(summaries))
    _save_history(args, summaries)
    if last is not None:
        snapshot, run_config, achieved = last
        _write_report(
            args,
            lambda: render_report(
                snapshot, run_config, history=summaries, lists=_lists_info(catalogue), achieved_qps=achieved
            ),
        )
    return 1 if _check_gates(args, summaries) else 0


def _check_gates(args: argparse.Namespace, records: Sequence[dict]) -> bool:
    """Check --assert against each finished run, print the results and write
    --junit.  True when an assertion failed, or when no run finished to check."""
    assertions = list(getattr(args, "assertions", None) or [])
    junit = getattr(args, "junit", None)
    if not assertions and not junit:
        return False
    assertions = assertions or list(DEFAULT_ASSERTIONS)
    # Under --json stdout is the report and nothing else.
    out = sys.stderr if getattr(args, "json", False) else sys.stdout
    runs = [(record, evaluate(assertions, record)) for record in records]
    results = [result for _record, outcome in runs for result in outcome]
    if results:
        print(file=out)
        print(format_results(results), file=out)
    else:
        print(file=out)
        print("  No run finished, so the assertions could not be checked.", file=out)
    if junit:
        try:
            destination = Path(junit)
            if destination.parent != Path(""):
                destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(junit_xml(runs), encoding="utf-8")
        except OSError as exc:
            print(f"  could not write the JUnit results to {junit}: {exc}", file=sys.stderr)
    return not results or any(not result.passed for result in results)


def _history_path(args: argparse.Namespace) -> Path | None:
    """Where the run history is kept, or None with --no-history."""
    if getattr(args, "no_history", False):
        return None
    return default_data_dir() / HISTORY_FILE


def _save_history(args: argparse.Namespace, records: Sequence[dict]) -> None:
    path = _history_path(args)
    if path is None:
        return
    store = HistoryStore(path)
    for record in records:
        problem = store.append(record)
        if problem:
            print(f"  warning: {problem}", file=sys.stderr)
            return


def _write_report(args: argparse.Namespace, render: Callable[[], str]) -> None:
    """Write --report, if it was asked for, once the run is over."""
    path = getattr(args, "report", None)
    if not path:
        return
    try:
        destination = Path(path)
        if destination.parent != Path(""):
            destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(render(), encoding="ascii")
    except OSError as exc:
        print(f"  could not write the report to {path}: {exc}", file=sys.stderr)
        return
    if not getattr(args, "json", False):
        print(f"  report          {path}")


def _lists_info(catalogue: DomainCatalogue) -> dict:
    return {"total": catalogue.total(), "fetched_at": catalogue.fetched_at}


def _start_mock(args: argparse.Namespace, catalogue: DomainCatalogue) -> MockAppliance:
    """Point the built-in simulator at what the catalogue says should be blocked.

    The mock and the catalogue therefore agree by construction: unless
    ``--mock-overblock`` is passed, a "good" mock produces a clean verdict, which
    makes the rehearsal a real test of this tool rather than of the mock.
    """
    blocked = catalogue.blocked_domains()
    extra = set()
    if getattr(args, "mock_overblock", False):
        extra = set(catalogue.domains_for(Category.ENTERPRISE.value)) | set(catalogue.domains_for(Category.BORDERLINE.value))
    appliance = MockAppliance(
        scenario=args.mock_scenario,
        blocklist=blocked,
        overblock_extra=extra or None,
        host="127.0.0.1",
        port=0,
        quiet=True,
        doh_port=0,
    )
    appliance.start()
    return appliance


def _wait_for_mock(mock: MockAppliance, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if probe_reachable(RunConfig(server=mock.host, port=mock.port), attempts=1, timeout=0.3):
            return
        time.sleep(0.05)


def cmd_bench(args: argparse.Namespace) -> int:
    """Measure what this machine can actually generate.

    Two numbers, because they answer different questions.  The generation rate
    (no network) is the ceiling this Python process can reach; the local-mock rate
    is what survives a real send and receive path.  If the target rate is below
    both, the appliance is the bottleneck and any failure is its fault -- which is
    the whole reason to measure before blaming.
    """
    catalogue = load_catalogue(getattr(args, "cache_dir", None), offline=True, verbose=False)
    # Honoured rather than ignored: a flag in the shared option group that one command
    # silently drops is the same defect as `serve --mock` dropping `--mock`.
    seconds = max(1.0, float(getattr(args, "duration", BENCH_STAGE_SECONDS) or BENCH_STAGE_SECONDS))
    personas = int(getattr(args, "personas", 10_000))

    print(f"DNS Load Forge {__version__} -- capacity benchmark")
    print(f"  {os.cpu_count()} logical cores; testing {personas:,} personas for {seconds:g}s per stage")
    print()

    results: dict[str, dict] = {}

    for label, qps in (("generation (no network)", 20_000.0), ("generation (no network)", 60_000.0)):
        config = RunConfig(
            server="127.0.0.1",
            port=9,
            personas=personas,
            target_qps=qps,
            duration_s=seconds,
            timeout_s=1.0,
            seed=99,
            dry_run=True,
            threads=1,
        )
        stats = StatsAggregator()
        try:
            runs = run_threaded(config, catalogue, stats=stats, threads=1)
        except ValueError as exc:
            print(f"  cannot benchmark: {exc}")
            return 2
        # Queries over the sending window, from the engine's own counters: exact, where
        # the dashboard's 5-second average is a sampling of whole seconds.
        achieved = round(sum(r.achieved_qps for r in runs), 1)
        results[f"gen-{int(qps)}"] = {"target": qps, "achieved": achieved}
        print(f"  {label:28s} target {qps:>7,.0f} qps -> achieved {achieved:>9,.0f} qps"
              f"  ({100.0 * achieved / qps:.0f}% of target)")

    # Stage two sends for real, against the built-in mock.  This is a *floor*, not a
    # ceiling: the mock is a single-threaded Python responder which becomes the
    # bottleneck well before the sender does, so a falling number here says the
    # simulator could not keep up, not that the generator ran out of capacity.  The
    # drop percentage is the honest signal of who was struggling.
    #
    # --transport is honoured here too.  The mock has no certificate, so DoT is
    # measured as TCP and DoH over plain HTTP: the framing and the connection pool,
    # without the encryption.
    wanted = getattr(args, "transport", None) or "udp"
    transport = {"tls": "tcp", "https": "http"}.get(wanted, wanted)
    via = {"tcp": ", TCP", "http": ", DoH"}.get(transport, "")
    mock = MockAppliance(
        scenario="good",
        latency_ms=0.05,
        jitter_ms=0.0,
        port=0,
        quiet=True,
        doh_port=0 if transport == "http" else None,
    )
    mock.start()
    try:
        for qps in (10_000.0, 20_000.0):
            config = RunConfig(
                server=mock.host,
                port=(mock.doh_port or 0) if transport == "http" else mock.port,
                transport=transport,
                connections=max(0, int(getattr(args, "connections", 0) or 0)),
                personas=personas,
                target_qps=qps,
                duration_s=seconds,
                timeout_s=1.0,
                seed=99,
                max_inflight=60_000,
                threads=1,
            )
            stats = StatsAggregator()
            runs = run_threaded(config, catalogue, stats=stats, threads=1)
            snapshot = stats.snapshot()
            achieved = round(sum(r.achieved_qps for r in runs), 1)
            loss = snapshot["rates"]["error_pct"]
            dropped = snapshot["rates"]["dropped_pct"]
            results[f"e2e-{int(qps)}"] = {
                "target": qps, "achieved": achieved, "loss_pct": loss, "dropped_pct": dropped
            }
            note = f", {dropped:.0f}% sender drops" if dropped >= 0.5 else ""
            print(f"  {'end-to-end (local mock' + via + ')':28s} target {qps:>7,.0f} qps -> achieved {achieved:>9,.0f} qps"
                  f"  ({100.0 * achieved / qps:.0f}% of target, {loss:.1f}% loss{note})")
    finally:
        mock.stop()

    # Only the network-free stage measures the generator itself.
    generated = max(
        value["achieved"] for key, value in results.items() if key.startswith("gen-")
    )
    through_mock = [
        value["achieved"] for key, value in results.items() if key.startswith("e2e-")
    ]
    best = max(through_mock) if through_mock else 0.0
    print()
    print(f"  generator ceiling (no network): ~{generated:,.0f} qps")
    print(f"  best observed with the mock:    ~{best:,.0f} qps")
    print(f"  the 10,000-worker office target (10,000 qps) is "
          f"{'within' if generated >= 10_000 else 'BEYOND'} reach")
    print()
    print("  The end-to-end figures are limited by the mock, which is a simple Python")
    print("  responder and saturates well below the sender; its high loss figure above")
    print("  is the mock failing to answer in time, not the generator failing to send.")
    print("  The network-free figure is what this machine can generate. On a real run,")
    print("  rising loss or a rising drop percentage means the target, not the")
    print("  generator, is falling behind.")
    if getattr(args, "json", False):
        print(json.dumps(results, indent=2))
    return 0


def cmd_mock(args: argparse.Namespace) -> int:
    from .mockappliance import main as mock_main

    argv: list[str] = ["--host", args.host, "--port", str(args.port), "--scenario", args.scenario,
                       "--block-mode", args.block_mode, "--block-ede", str(args.block_ede)]
    if args.blocklist_file:
        argv += ["--blocklist-file", args.blocklist_file]
    if args.dga_nxdomain:
        argv.append("--dga-nxdomain")
    for flag, value in (
        ("--drop-rate", args.drop_rate),
        ("--servfail-rate", args.servfail_rate),
        ("--latency-ms", args.latency_ms),
        ("--rate-limit-qps", args.rate_limit_qps),
    ):
        if value is not None:
            argv += [flag, str(value)]
    if args.quiet:
        argv.append("--quiet")
    print(f"Starting mock filtering appliance: {' '.join(argv)}")
    return mock_main(argv)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    # Line-buffer stdout.  Python block-buffers when output is redirected to a file
    # or a pipe, so `python -m dnsloadforge ... > run.log` would show nothing at all
    # until the process exits -- which for a run that waits for Ctrl-C looks like a
    # hang.  A load test that gives no feedback for ten minutes is unusable.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass

    argv = list(sys.argv[1:] if argv is None else argv)

    # Bare invocation means "run": `dnsloadforge --server 10.0.0.5` should do the
    # obvious thing rather than print help and make the operator look up a verb.
    # --version belongs to the top-level parser; sending it to `run` made
    # `dnsloadforge --version` an "unrecognized argument" error.
    if argv and argv[0] == "--version":
        pass
    elif not argv or argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv = ["run", *argv]
    elif not argv:
        argv = ["run"]
    elif argv[0].startswith("-"):
        argv = ["run", *argv]

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    handler = {
        "run": cmd_run,
        "serve": cmd_serve,
        "lists": cmd_lists,
        "targets": cmd_targets,
        "mock": cmd_mock,
        "bench": cmd_bench,
        "doctor": cmd_doctor,
        "checks": cmd_checks,
        "capacity": cmd_capacity,
    }[args.command]

    try:
        return handler(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


_STATUS_MARK = {"pass": "pass", "warn": "WARN", "fail": "FAIL", "error": "ERR ", "info": "info", "skip": "skip"}


def cmd_checks(args: argparse.Namespace) -> int:
    """Deployment checks against one target, printed as a table or JSON."""
    from .checks import context_for_target, run_checks, summarise

    _available, chosen = resolve_targets(args)
    if len(chosen) > 1:
        raise ValueError("checks run against one target at a time")
    target = chosen[0]
    ctx = context_for_target(
        target,
        network=not args.no_network,
        timeout=args.timeout,
        cache_dir=args.cache_dir,
        verify=not args.insecure,
        ca_file=args.ca_file or "",
    )
    quiet = getattr(args, "json", False)
    if not quiet:
        print(f"DNS Load Forge {__version__} -- deployment checks against {target.name} ({target.endpoint})")
    results = run_checks(ctx, only=args.only)
    summary = summarise(results)
    if quiet:
        print(json.dumps({"target": target.as_dict(), "summary": summary, "checks": [r.as_dict() for r in results]}, indent=2))
        return 0
    group = ""
    for result in results:
        if result.group != group:
            group = result.group
            print()
            print(f"  {group.upper()}")
        print(f"    {_STATUS_MARK.get(result.status, result.status):4}  {result.title:30} {result.summary}")
    counts = ", ".join(f"{count} {status}" for status, count in summary["counts"].items() if count)
    print()
    print(f"  {counts}.  Run with --json for the evidence behind each result.")
    return 0


def cmd_capacity(args: argparse.Namespace) -> int:
    """Find the highest rate the target sustains, step by step, headless.

    Prints each step as it finishes and the answer at the end; ``--json`` prints
    the whole search, and ``--require`` turns it into a pass/fail exit code.
    """
    from dataclasses import asdict, replace

    from .capacity import CapacityPlan, Slo, search

    plan = CapacityPlan(
        start_qps=args.start_qps,
        max_qps=args.max_qps,
        growth=args.growth,
        step_s=args.step_seconds,
        refine=args.refine,
    )
    slo = Slo(loss_pct=args.slo_loss, servfail_pct=args.slo_servfail, p95_ms=args.slo_p95)
    plan.validate()
    slo.validate()
    _available, chosen = resolve_targets(args)
    if len(chosen) > 1:
        raise ValueError("a capacity search runs against one target at a time")
    config = build_config(args, chosen[0])
    # The guard judges the highest rate the search may reach, not the first.
    config.target_qps = plan.max_qps
    catalogue = _load_lists(args)
    mock = _setup_mock(args, catalogue, config)
    quiet = bool(getattr(args, "json", False))
    if not quiet:
        ramp = plan.ramp()
        print(f"DNS Load Forge {__version__} -- capacity search against {config.target_name or config.target}")
        print(f"  target          {config.target}")
        print(f"  steps           {len(ramp)} from {ramp[0]:,} to {ramp[-1]:,} qps (x{plan.growth:g} each, "
              f"{plan.step_s:g}s), then up to {plan.refine} to narrow it down")
        print(f"  limits          loss <= {slo.loss_pct:g}%, SERVFAIL <= {slo.servfail_pct:g}% of answers, "
              f"p95 <= {slo.p95_ms:g} ms")
        print(f"  longest         about {plan.estimate_s() / 60:.0f} min")

    problems = preflight(config, catalogue, args, chosen)
    if problems:
        print()
        print("Cannot start:")
        for problem in problems:
            print(f"  - {problem}")
        if mock is not None:
            mock.stop()
        return 2

    def run_step(rate: float) -> tuple[dict, float]:
        step = replace(config, target_qps=float(rate), duration_s=float(plan.step_s))
        stats = StatsAggregator()
        stats.set_run(
            server=step.target,
            transport=step.transport,
            target_name=step.target_name,
            mode=step.mode,
            personas=step.personas,
            source_ips=len(step.source_ips) or 1,
            target_qps=step.target_qps,
            seed=step.seed,
        )
        results = run_threaded(step, catalogue, stats=stats, threads=step.threads)
        return stats.snapshot(), sum(r.achieved_qps for r in results)

    def on_start(index: int, phase: str, rate: float) -> None:
        if not quiet:
            print(f"  step {index:>2}  {phase:6}  {rate:>9,.0f} qps", end="", flush=True)

    def on_step(step) -> None:
        if not quiet:
            detail = "; ".join(step.reasons) or f"loss {step.loss_pct:.1f}%"
            # No answer, no latency: a p95 of 0 there would read as a fast target.
            p95 = f"{step.p95_ms:>6g} ms" if step.received else "     - ms"
            print(f"  {step.status.upper():9}  p95 {p95}  {detail}")

    if not quiet:
        print()
    try:
        result = search(plan, slo, run_step, on_step=on_step, on_start=on_start)
    except KeyboardInterrupt:
        print("\n  interrupted")
        return 130
    finally:
        if mock is not None:
            mock.stop()

    met = None
    if args.require is not None:
        met = result.sustained_qps is not None and result.sustained_qps >= args.require
    if quiet:
        report = {"target": config.target_name or config.target, "endpoint": config.target}
        report.update(plan=asdict(plan), slo=asdict(slo), **result.as_dict())
        if met is not None:
            report["required_qps"] = args.require
            report["requirement_met"] = met
        print(json.dumps(report, indent=2))
    else:
        print()
        print(f"  {result.summary}")
        if met is not None:
            print(f"  required {args.require:,.0f} qps: {'met' if met else 'NOT met'}")
    return 1 if met is False else 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Serve the dashboard without starting a run, so the operator can press Start
    when the change window opens."""
    check_dashboard_bind(args)
    args.duration = float(getattr(args, "duration", 0.0)) or 0.0
    available, chosen = resolve_targets(args)
    config = build_config(args, chosen[0])
    catalogue = _load_lists(args)

    mock = _setup_mock(args, catalogue, config)
    if mock is not None:
        available = _with_mock_target(available, chosen[0], mock, config, args)
        chosen = chosen[:1]
        print(f"mock appliance listening on {config.target} (scenario: {args.mock_scenario})")

    if not getattr(args, "quiet", False):
        print_banner(config, catalogue, args)

    # Preflight runs here too.  It used to be in `run` only, which meant the
    # public-resolver guard could be bypassed simply by launching `serve` and
    # pressing Start from the dashboard -- the same traffic, the same target, one
    # subcommand away from the check that is supposed to prevent it.
    problems = preflight(config, catalogue, args, chosen)
    if problems:
        print()
        print("Cannot start:")
        for problem in problems:
            print(f"  - {problem}")
        if mock is not None:
            mock.stop()
        return 2

    server, controller = serve(
        config,
        catalogue,
        host=args.listen_host,
        port=args.dashboard_port,
        record_log_path=_record_path(args, config),
        record_format=args.record_format,
        record_sample=args.record_sample,
        autostart=False,
        log=lambda message: print(f"  [{datetime.now().strftime('%H:%M:%S')}] {message}"),
        targets=available,
        catalogue_loader=catalogue_loader(args),
        cache_dir=getattr(args, "cache_dir", None),
        allow_public_target=getattr(args, "allow_public_target", False),
        history_path=_history_path(args),
    )
    print()
    print(f"  dashboard       {server.url}  (press Start to begin)")
    if args.open_dashboard:
        try:
            webbrowser.open(server.url)
        except Exception:
            pass
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if controller.running:
            controller.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
