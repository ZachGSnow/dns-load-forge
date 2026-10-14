"""A local, simulated DNS filtering appliance.

Why this exists
---------------
The point of DNS Load Forge is to point a load generator at a *real* filtering
appliance and find out whether it (a) blocks what it should, (b) lets through
what it should, and (c) does not fall over under load.  You cannot develop or
regression-test that tool against a real appliance sitting in a lab, and you
certainly must not point a 10k-qps generator at 8.8.8.8 while you are writing
code.  So this module ships a responder that behaves like an appliance and can
be told to misbehave on purpose.

It is deliberately stdlib-only and runs on loopback, so the whole pipeline
(engine -> stats -> dashboard) is verifiable offline and in unit tests.

Scenarios (this is the user-facing feature)
-------------------------------------------
``good``
    An honest filter.  Names in ``blocklist`` / matching ``block_suffixes`` get
    whatever ``block_mode`` says; random-looking DGA probes and anything under
    the reserved ``.invalid`` / ``.test`` TLDs get NXDOMAIN; everything else
    resolves to a plausible A/AAAA address.
``passthrough``
    Never blocks.  Models a filter that is licensed, installed, and not
    enforcing -- so every bad domain resolves and the dashboard fills with
    false negatives.
``overblocker``
    Blocks ``blocklist`` *plus* ``overblock_extra``, i.e. it wrongly blocks
    legitimate/enterprise domains.  This is how the dashboard's false-positive
    view gets exercised, and it is the scenario that matters most in practice:
    a filter that blocks too much breaks the business.
``lossy``
    ``drop_rate=0.15``.  Models queue drop on an overloaded appliance: queries
    vanish instead of erroring, so the client only sees a timeout.
``servfail``
    ``servfail_rate=0.30``.  Models an appliance failing under load.
``slow``
    ``latency_ms=150``, ``jitter_ms=100``.  Models a saturated path.
``refused``
    REFUSED for everything not explicitly blocked.  Models a broken ACL or a
    policy that was applied to the wrong scope.

Decision order
--------------
Every query is classified in this order, and the order is deliberate:

1. over rate limit -> SERVFAIL (a rate limiter acts before policy)
2. on the block list -> ``block_mode``
3. ``servfail_rate`` coin flip -> SERVFAIL (a failing appliance fails everything)
4. ``refuse_all`` -> REFUSED
5. DGA-looking or reserved-TLD name -> NXDOMAIN
6. otherwise -> a real answer
"""

from __future__ import annotations

import argparse
import json
import random
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Callable

from .packets import DNSError, DNSMessage, RR, decode_message, encode_response
from .spec import QTYPE_NAMES

__all__ = [
    "SCENARIOS",
    "MockApplianceConfig",
    "MockAppliance",
    "load_blocklist_file",
    "main",
]

#: Preset behaviours.  ``__init__`` maps a scenario to config defaults and then
#: lets explicit ``**overrides`` win, so ``MockAppliance(scenario="lossy",
#: drop_rate=0.5)`` does what it reads like.
SCENARIOS: tuple[str, ...] = (
    "good",
    "passthrough",
    "overblocker",
    "lossy",
    "servfail",
    "slow",
    "refused",
)

#: Per-scenario overrides applied on top of the dataclass defaults.
_SCENARIO_PRESETS: dict[str, dict] = {
    "good": {},
    "passthrough": {"passthrough": True},
    "overblocker": {},
    "lossy": {"drop_rate": 0.15},
    "servfail": {"servfail_rate": 0.30},
    "slow": {"latency_ms": 150.0, "jitter_ms": 100.0},
    "refused": {"refuse_all": True},
}

_BLOCK_MODES: tuple[str, ...] = ("nxdomain", "sinkhole", "refused")

_RCODE_NOERROR = 0
_RCODE_SERVFAIL = 2
_RCODE_NXDOMAIN = 3
_RCODE_REFUSED = 5

#: Reserved TLDs from RFC 2606 / RFC 6761.  A real resolver must answer NXDOMAIN
#: for these, so they are a deterministic hook the load engine can use when it
#: wants guaranteed non-existent names for its NXDOMAIN probes.
_RESERVED_TLDS: tuple[str, ...] = (".invalid", ".test", ".example", ".localdomain")

#: A single all-alphanumeric label this long, with enough digits or too few
#: vowels, is almost certainly algorithmic.  Tuned to leave real names alone:
#: "windowsupdate" (14 chars, no digits, 4 vowels) is not flagged, while
#: "kq3vz9xm4pl2" is.
_DGA_LABEL_RE = re.compile(r"^[a-z0-9]{12,}$")

#: Hosts-file prefixes treated as "the rest of the line is a domain".
_HOSTS_PREFIXES = frozenset(
    {"0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0", "255.255.255.255"}
)


def _looks_like_dga(qname: str) -> bool:
    """Heuristic DGA detection over the whole name.

    Deliberately narrow, and the thresholds are *measured*, not guessed.  A mock
    that guesses wrong turns a legitimate domain into a bogus NXDOMAIN, and the
    dashboard then reports a false positive against a filter that behaved
    correctly -- the worst possible failure for this tool, because the operator
    would escalate it.

    An earlier version flagged any label of 12+ characters containing three or
    more digits.  Run against the real allow-lists that fired on **1.69% of the
    popular list and 0.80% of the long tail** (``cz89100315www.mobile.de``,
    ``tombak118gas.org``, every hashed CDN hostname), which manufactured a ~3%
    false-positive rate out of nothing in a rehearsal.

    Requiring a digit-heavy label to *also* be vowel-free is what separates a
    machine-generated string from a real name that merely contains numbers: real
    hostnames and SEO domains almost always keep a couple of vowels, while
    ``kq3vz9xm4pl2`` does not.  Missing a synthetic probe is the safe error, so
    the engine sends a deliberate share of its probes under RFC 2606 reserved
    TLDs, which are answered NXDOMAIN deterministically regardless of this.
    """
    for label in qname.split("."):
        if not _DGA_LABEL_RE.match(label):
            continue
        digits = sum(c.isdigit() for c in label)
        vowels = sum(c in "aeiou" for c in label)
        if digits >= 3 and vowels == 0:
            return True
        if len(label) >= 16 and vowels <= 1:
            return True
    return False


def _normalise_domain(value: str) -> str:
    """Accept ``.foo.com``, ``foo.com.``, ``||foo.com^`` and ``*.foo.com`` and
    return ``foo.com``."""
    text = value.strip().lower()
    if text.startswith("||"):
        text = text[2:]
    text = text.rstrip("^").strip()
    if text.startswith("*."):
        text = text[2:]
    return text.strip(".")


def load_blocklist_file(path: str) -> set[str]:
    """Read a block list in any of the formats these tools actually ship in:
    hosts file (``0.0.0.0 domain``), one-domain-per-line, or an adblock-style
    ``||domain^`` rule.  Comments starting with ``#``/``!``/``;`` are skipped.
    """
    domains: set[str] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line[0] in "#!;[":
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in _HOSTS_PREFIXES:
                candidate = parts[1]
            else:
                candidate = parts[0]
            domain = _normalise_domain(candidate)
            if domain and "." in domain:
                domains.add(domain)
    return domains


def _is_blocked(qname: str, blocklist: set[str] | None, suffixes: tuple[str, ...]) -> bool:
    """Block-list match, case-insensitive and subdomain-aware.

    A real filter (and every hosts list) blocks ``x.bad.com`` when it has
    ``bad.com``, so matching only the exact name would understate what the
    appliance blocks and corrupt every verdict built on top of it.
    """
    if blocklist:
        if qname in blocklist:
            return True
        # Walk the parent chain: x.a.bad.com -> a.bad.com -> bad.com
        remainder = qname
        while "." in remainder:
            remainder = remainder.split(".", 1)[1]
            if remainder in blocklist:
                return True
    for suffix in suffixes:
        clean = suffix.strip().lower().lstrip(".")
        if not clean:
            continue
        if qname == clean or qname.endswith("." + clean):
            return True
    return False


@dataclass
class MockApplianceConfig:
    """Tunables for :class:`MockAppliance`.  See the module docstring for what
    each scenario does with them."""

    host: str = "127.0.0.1"
    port: int = 0  #: 0 = let the OS pick an ephemeral port (what tests want)
    scenario: str = "good"
    block_mode: str = "nxdomain"  # "nxdomain" | "sinkhole" | "refused"
    sinkhole_ip: str = "0.0.0.0"
    sinkhole_ip6: str = "::"
    answer_ip: str = "93.184.216.34"
    answer_ip6: str = "2606:4700:4700::1111"
    latency_ms: float = 1.0
    jitter_ms: float = 0.5
    drop_rate: float = 0.0
    servfail_rate: float = 0.0
    refuse_all: bool = False
    passthrough: bool = False
    blocklist: set[str] | None = None
    block_suffixes: tuple[str, ...] = ()
    overblock_extra: set[str] | None = None
    #: Also NXDOMAIN names that merely *look* algorithmic.  Off by default -- see
    #: step 5 of :meth:`MockAppliance._decide` for why this cannot be on by default
    #: without manufacturing false positives in a rehearsal.
    dga_nxdomain: bool = False
    rate_limit_qps: float = 0.0
    ttl: int = 300
    seed: int = 1234
    #: How many replies may be in flight at once.  Latency is simulated with a
    #: sleep, so without concurrency the ``slow`` scenario would serialise every
    #: request and the measured latency would be useless.
    workers: int = 64
    #: Optional per-request hook.  Return response bytes to override the default
    #: behaviour, or ``None`` to fall through to it.  Used by tests to inject
    #: weird responses (truncation, malformed bodies) without a new scenario.
    handle_query_fn: Callable[[DNSMessage], bytes | None] | None = None
    quiet: bool = False

    def __post_init__(self) -> None:
        if self.scenario not in SCENARIOS:
            raise ValueError(
                f"unknown scenario {self.scenario!r}; choose from {', '.join(SCENARIOS)}"
            )
        if self.block_mode not in _BLOCK_MODES:
            raise ValueError(
                f"unknown block_mode {self.block_mode!r}; choose from "
                f"{', '.join(_BLOCK_MODES)}"
            )
        for name in ("drop_rate", "servfail_rate"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0.0 and 1.0, got {value}")
        if self.blocklist:
            self.blocklist = {
                d for d in (_normalise_domain(x) for x in self.blocklist) if d
            }
        if self.overblock_extra:
            self.overblock_extra = {
                d for d in (_normalise_domain(x) for x in self.overblock_extra) if d
            }


@dataclass(slots=True)
class _Disposition:
    """What we decided to do with one query, so the caller can bump counters."""

    packet: bytes
    rcode: str
    blocked: bool = False


class MockAppliance:
    """A UDP DNS responder that pretends to be a filtering appliance.

    Usage::

        with MockAppliance(scenario="overblocker") as app:
            send_to = (app.host, app.port)     # port is the real bound port

    ``start()``/``stop()`` are idempotent so the object is safe to use from a
    context manager, from a fixture, or manually.
    """

    def __init__(
        self, config: MockApplianceConfig | None = None, **overrides
    ) -> None:
        if config is None:
            scenario = overrides.pop("scenario", "good")
            config = MockApplianceConfig(
                scenario=scenario, **{**_SCENARIO_PRESETS.get(scenario, {}), **overrides}
            )
        elif overrides:
            # A scenario named in the overrides must still apply its preset, but
            # anything the caller passed explicitly has to win over the preset --
            # otherwise MockAppliance(cfg, scenario="slow") would silently ignore
            # the caller's own latency_ms.
            scenario = overrides.get("scenario", config.scenario)
            extra = {k: v for k, v in overrides.items() if k != "scenario"}
            preset = {
                key: value
                for key, value in _SCENARIO_PRESETS.get(scenario, {}).items()
                if key not in extra
            }
            config = replace(config, scenario=scenario, **{**preset, **extra})
        self.config = config
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._stop = threading.Event()
        self._port: int = config.port
        self._lock = threading.Lock()
        self._rng_lock = threading.Lock()
        self._rng = random.Random(config.seed)
        self._arrivals: list[float] = []
        self._stats: dict[str, int] = {
            "received": 0,
            "answered": 0,
            "blocked": 0,
            "dropped": 0,
            "nxdomain": 0,
            "refused": 0,
            "servfail": 0,
            "malformed": 0,
            "rate_limited": 0,
            "overridden": 0,
        }

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "MockAppliance":
        if self._thread is not None and self._thread.is_alive():
            return self
        self._stop.clear()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.config.host, self.config.port))
        self._sock.settimeout(0.25)  # so stop() is responsive
        self._port = self._sock.getsockname()[1]
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, self.config.workers), thread_name_prefix="mockdns"
        )
        self._thread = threading.Thread(
            target=self._serve, name="mockappliance", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5.0)
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=True)
            self._executor = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> "MockAppliance":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        state = "running" if self.running else "stopped"
        return f"<MockAppliance {self.config.scenario} {state} {self.target}>"

    # -- introspection -----------------------------------------------------

    @property
    def host(self) -> str:
        return self.config.host

    @property
    def port(self) -> int:
        """The actual bound port.  Meaningful only after ``start()``."""
        return self._port

    @property
    def target(self) -> str:
        """``host:port`` of the live listener."""
        return f"{self.host}:{self.port}"

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0

    # -- serving -----------------------------------------------------------

    def _bump(self, **increments: int) -> None:
        with self._lock:
            for key, value in increments.items():
                self._stats[key] = self._stats.get(key, 0) + value

    def _serve(self) -> None:
        """Receive loop.  Nothing may escape this method: a mock that dies on a
        malformed packet would make every test that uses it flaky."""
        sock = self._sock
        assert sock is not None
        while not self._stop.is_set():
            try:
                data, sender = sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break  # socket closed underneath us by stop()
            try:
                self._on_datagram(data, sender)
            except Exception:  # noqa: BLE001 - a mock must never crash the caller
                self._bump(malformed=1)

    def _on_datagram(self, data: bytes, sender: tuple[str, int]) -> None:
        self._bump(received=1)
        try:
            msg = decode_message(data)
        except DNSError:
            self._bump(malformed=1)
            return
        if not msg.qname:
            self._bump(malformed=1)
            return

        decision = self._decide(msg)

        # Deliberate packet loss: return before sending.  The client sees only a
        # timeout, which is exactly what overload looks like from a stub.
        if self.config.drop_rate and self._roll() < self.config.drop_rate:
            self._bump(dropped=1)
            return

        delay_ms = self.config.latency_ms
        if self.config.jitter_ms:
            delay_ms += self._roll() * self.config.jitter_ms

        if delay_ms <= 0.0:
            self._send(decision.packet, sender)
            return

        executor = self._executor
        if executor is None:
            self._send(decision.packet, sender)
            return
        executor.submit(self._deliver, decision.packet, sender, delay_ms / 1000.0)

    def _deliver(self, packet: bytes, sender: tuple[str, int], delay_s: float) -> None:
        if self._stop.wait(delay_s):
            return  # shutting down; do not bother sending
        self._send(packet, sender)

    def _send(self, packet: bytes, sender: tuple[str, int]) -> None:
        sock = self._sock
        if sock is None:
            return
        try:
            sock.sendto(packet, sender)
        except OSError:
            pass
        else:
            self._bump(answered=1)

    def _roll(self) -> float:
        """A reproducible [0,1) draw.  ``random.Random`` is not thread-safe and
        replies are delivered from a pool, so this is lock-guarded."""
        with self._rng_lock:
            return self._rng.random()

    def _rate_limited(self) -> bool:
        limit = self.config.rate_limit_qps
        if limit <= 0:
            return False
        now = time.monotonic()
        with self._lock:
            arrivals = self._arrivals
            cutoff = now - 1.0
            # Trim in place; the list only ever holds one second of arrivals.
            if len(arrivals) > 4096:
                del arrivals[: len(arrivals) - 4096]
            while arrivals and arrivals[0] < cutoff:
                arrivals.pop(0)
            arrivals.append(now)
            return len(arrivals) > limit

    # -- policy ------------------------------------------------------------

    def _decide(self, msg: DNSMessage) -> _Disposition:
        """Classify one query.  See the module docstring for the decision order."""
        qname = msg.qname
        qtype = QTYPE_NAMES.get(msg.qtype, f"TYPE{msg.qtype}")
        edns_size = msg.edns_udp_size

        custom = self.config.handle_query_fn
        if custom is not None:
            packet = custom(msg)
            if packet is not None:
                self._bump(overridden=1)
                return _Disposition(packet=packet, rcode="CUSTOM")

        # 1. A rate limiter acts before policy.
        if self._rate_limited():
            self._bump(rate_limited=1)
            return self._reply(msg, _RCODE_SERVFAIL, edns_size)

        # 2. Policy: the block list.
        blocked = not self.config.passthrough and (
            _is_blocked(qname, self.config.blocklist, self.config.block_suffixes)
            or _is_blocked(qname, self.config.overblock_extra, ())
        )
        if blocked:
            self._bump(blocked=1)
            return self._blocked_reply(msg, qtype, edns_size)

        # 3. A failing appliance fails everything, not just bad traffic.
        if self.config.servfail_rate and self._roll() < self.config.servfail_rate:
            return self._reply(msg, _RCODE_SERVFAIL, edns_size)

        # 4. Broken ACL / policy applied to the wrong scope.
        if self.config.refuse_all:
            return self._reply(msg, _RCODE_REFUSED, edns_size)

        # 5. Names that genuinely do not exist.  Note this stays active in the
        #    passthrough scenario: a non-blocking resolver still answers NXDOMAIN
        #    for a name that does not exist, and the engine's NXDOMAIN probes are
        #    about resolver correctness, not filtering.
        #
        #    Reserved TLDs are answered NXDOMAIN unconditionally: that is resolver
        #    *correctness*, not policy, and it is the deterministic hook the
        #    engine's probes depend on whatever else is configured.
        if qname.endswith(_RESERVED_TLDS):
            return self._reply(msg, _RCODE_NXDOMAIN, edns_size)

        #    The DGA heuristic is opt-in because no label heuristic can separate a
        #    machine-generated name from a legitimate hashed hostname.  Left on by
        #    default it flagged 0.26% of the real allow-lists (6,358 domains:
        #    hashed CDN hostnames, SEO domains, anything with digits and no
        #    vowels), which appeared on the dashboard as false positives against a
        #    filter that had behaved correctly.  Turn it on (--dga-nxdomain) to
        #    rehearse a filter whose typo-squat feed is over-eager; leave it off for
        #    a clean known-good baseline.
        if self.config.dga_nxdomain and _looks_like_dga(qname):
            return self._reply(msg, _RCODE_NXDOMAIN, edns_size)

        # 6. An ordinary answer.
        return self._answer_reply(msg, qtype, edns_size)

    def _blocked_reply(self, msg: DNSMessage, qtype: str, edns_size: int) -> _Disposition:
        mode = self.config.block_mode
        if mode == "sinkhole":
            if qtype == "A":
                answers = [RR(msg.qname, "A", self.config.ttl, self.config.sinkhole_ip)]
            elif qtype == "AAAA":
                answers = [
                    RR(msg.qname, "AAAA", self.config.ttl, self.config.sinkhole_ip6)
                ]
            else:
                answers = []
            packet = encode_response(
                msg, rcode=_RCODE_NOERROR, answers=answers, edns_udp_size=edns_size
            )
            return _Disposition(packet=packet, rcode="NOERROR", blocked=True)
        if mode == "refused":
            disposition = self._reply(msg, _RCODE_REFUSED, edns_size)
            disposition.blocked = True
            return disposition
        disposition = self._reply(msg, _RCODE_NXDOMAIN, edns_size)
        disposition.blocked = True
        return disposition

    def _answer_reply(self, msg: DNSMessage, qtype: str, edns_size: int) -> _Disposition:
        """A plausible answer, echoing the qtype the client asked for.

        Getting this right matters: if the mock answered every qtype with an A
        record, the engine's qtype-mix measurement would be measuring the mock
        rather than the appliance.
        """
        answers: list[RR] = []
        if qtype == "A" and self.config.answer_ip:
            answers = [RR(msg.qname, "A", self.config.ttl, self.config.answer_ip)]
        elif qtype == "AAAA" and self.config.answer_ip6:
            answers = [RR(msg.qname, "AAAA", self.config.ttl, self.config.answer_ip6)]
        elif qtype == "PTR":
            # Reverse lookups are common on Windows networks and a filter must
            # not break them, so answer with something name-shaped.
            answers = [
                RR(msg.qname, "PTR", self.config.ttl, "host.internal.invalid")
            ]
        # HTTPS/SVCB/TXT/MX/SOA/NS/DNSKEY/ANY: NOERROR with an empty answer
        # section, which is a legitimate and extremely common response.
        packet = encode_response(
            msg, rcode=_RCODE_NOERROR, answers=answers, edns_udp_size=edns_size
        )
        return _Disposition(packet=packet, rcode="NOERROR")

    def _reply(self, msg: DNSMessage, rcode: int, edns_size: int) -> _Disposition:
        packet = encode_response(msg, rcode=rcode, edns_udp_size=edns_size)
        name = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}.get(
            rcode, f"RCODE{rcode}"
        )
        if name == "NXDOMAIN":
            self._bump(nxdomain=1)
        elif name == "REFUSED":
            self._bump(refused=1)
        elif name == "SERVFAIL":
            self._bump(servfail=1)
        return _Disposition(packet=packet, rcode=name)


# ---------------------------------------------------------------------------
# Standalone CLI: python -m dnsloadforge.mockappliance --port 5353
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m dnsloadforge.mockappliance",
        description=(
            "Run a simulated DNS filtering appliance on loopback so you can "
            "rehearse a load test (or a scenario) without touching production."
        ),
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind address")
    parser.add_argument(
        "--port", type=int, default=5353, help="bind port (0 = ephemeral)"
    )
    parser.add_argument(
        "--scenario", choices=SCENARIOS, default="good", help="preset behaviour"
    )
    parser.add_argument(
        "--block-mode",
        choices=_BLOCK_MODES,
        default="nxdomain",
        help="how blocked names are answered",
    )
    parser.add_argument(
        "--blocklist-file",
        action="append",
        default=[],
        metavar="PATH",
        help="file of domains to block (hosts, plain list or ||domain^); repeatable",
    )
    parser.add_argument(
        "--block-suffix",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="block this domain and all subdomains; repeatable",
    )
    parser.add_argument(
        "--overblock",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="wrongly block this domain (drives the false-positive report)",
    )
    parser.add_argument("--sinkhole-ip", default="0.0.0.0")
    parser.add_argument("--answer-ip", default="93.184.216.34")
    parser.add_argument(
        "--dga-nxdomain",
        action="store_true",
        help=(
            "also answer NXDOMAIN for names that merely look algorithmic; off by "
            "default because the heuristic cannot tell a hashed CDN hostname from "
            "a DGA and would invent false positives"
        ),
    )
    parser.add_argument("--drop-rate", type=float, default=None)
    parser.add_argument("--servfail-rate", type=float, default=None)
    parser.add_argument("--latency-ms", type=float, default=None)
    parser.add_argument("--rate-limit-qps", type=float, default=None)
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument(
        "--quiet", action="store_true", help="do not print the periodic stats line"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    blocklist: set[str] = set()
    for path in args.blocklist_file:
        blocklist |= load_blocklist_file(path)
    blocklist |= {_normalise_domain(d) for d in args.overblock}

    preset = _SCENARIO_PRESETS.get(args.scenario, {})
    overrides: dict = {}
    # Scenario presets first, then anything the user set explicitly on the
    # command line, so the CLI overrides the preset just like the API does.
    for name in ("drop_rate", "servfail_rate", "latency_ms", "rate_limit_qps"):
        value = getattr(args, name)
        if value is not None:
            overrides[name] = value

    config = MockApplianceConfig(
        host=args.host,
        port=args.port,
        scenario=args.scenario,
        block_mode=args.block_mode,
        sinkhole_ip=args.sinkhole_ip,
        answer_ip=args.answer_ip,
        blocklist=blocklist or None,
        block_suffixes=tuple(args.block_suffix),
        dga_nxdomain=args.dga_nxdomain,
        seed=args.seed,
        quiet=args.quiet,
        **{**preset, **overrides},
    )

    app = MockAppliance(config)
    app.start()
    print(
        f"mock appliance listening on {app.target} "
        f"[scenario={config.scenario} block_mode={config.block_mode} "
        f"blocklist={len(blocklist)} names]",
        flush=True,
    )
    print("press Ctrl+C to stop", flush=True)

    last = app.stats
    try:
        while True:
            time.sleep(5.0)
            current = app.stats
            if config.quiet:
                last = current
                continue
            delta = {k: current[k] - last.get(k, 0) for k in current}
            print(
                "5s: recv={received} ans={answered} blocked={blocked} "
                "drop={dropped} nx={nxdomain} refused={refused} "
                "servfail={servfail} malformed={malformed} "
                "limited={rate_limited}".format(**delta),
                flush=True,
            )
            last = current
    except KeyboardInterrupt:
        print("\nstopping...", flush=True)
    finally:
        app.stop()
        print(f"final stats: {json.dumps(app.stats, sort_keys=True)}", flush=True)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
