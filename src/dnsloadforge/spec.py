"""Shared vocabulary and data contracts for DNS Load Forge.

This is the leaf module: it imports nothing else from the package, and every
other module agrees on the names defined here.  If you change a Category name,
an Outcome name or a field on QueryRecord you must update ``stats.py``,
``server.py`` and ``dashboard/index.html`` together -- the dashboard renders the
snapshot schema documented at the bottom of this file.

No third-party dependencies anywhere in this package by design: it must run on a
fresh Windows box with nothing but Python installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "Category",
    "Outcome",
    "CATEGORY_EXPECTED",
    "CATEGORY_LABELS",
    "EXPECT_KEYS",
    "QTYPES",
    "QTYPE_NAMES",
    "RCODES",
    "RCODE_NAMES",
    "Transport",
    "QueryRecord",
    "RunConfig",
    "LATENCY_BUCKETS_MS",
    "SINKHOLE_IPS_DEFAULT",
    "RECORD_FIELDS",
    "INTERNAL_SUFFIXES",
    "SinkholeSet",
    "is_internal_name",
    "is_reverse_name",
]


class Category(str, Enum):
    """Where a queried domain came from, which tells us what the appliance
    *should* do with it.

    The ``_POPULAR`` / ``_LONGTAIL``/ ``ENTERPRISE`` split matters: a filtering
    appliance that wrongly blocks ``allow_popular`` or ``enterprise`` traffic is
    breaking the business, while one that wrongly blocks ``allow_longtail`` is
    merely annoying.  Segmenting the report by these categories is the whole
    point of the tool.
    """

    ALLOW_POPULAR = "allow_popular"
    ALLOW_LONGTAIL = "allow_longtail"
    ENTERPRISE = "enterprise"
    BORDERLINE = "borderline"
    BLOCK_ADS = "block_ads"
    BLOCK_MALWARE = "block_malware"
    BLOCK_PHISHING = "block_phishing"
    BLOCK_ADULT = "block_adult"
    NXDOMAIN_PROBE = "nxdomain_probe"


#: Expectation keys.  Kept as short strings because they end up as JSON keys
#: consumed by the dashboard.
EXPECT_KEYS = ("allow", "block", "unknown", "nxdomain")

#: What we expect a correctly configured filter to do with each category.
#: ``unknown`` means the category is deliberately in the grey zone -- borderline
#: trackers/telemetry/CDNs -- and is reported but never counted as a failure.
CATEGORY_EXPECTED: dict[str, str] = {
    Category.ALLOW_POPULAR.value: "allow",
    Category.ALLOW_LONGTAIL.value: "allow",
    Category.ENTERPRISE.value: "allow",
    Category.BORDERLINE.value: "unknown",
    Category.BLOCK_ADS.value: "block",
    Category.BLOCK_MALWARE.value: "block",
    Category.BLOCK_PHISHING.value: "block",
    Category.BLOCK_ADULT.value: "block",
    Category.NXDOMAIN_PROBE.value: "nxdomain",
}

#: Human labels for the dashboard / console output.
CATEGORY_LABELS: dict[str, str] = {
    Category.ALLOW_POPULAR.value: "Allow - popular",
    Category.ALLOW_LONGTAIL.value: "Allow - long tail",
    Category.ENTERPRISE.value: "Allow - enterprise/breakage",
    Category.BORDERLINE.value: "Borderline - trackers/CDN",
    Category.BLOCK_ADS.value: "Block - ads",
    Category.BLOCK_MALWARE.value: "Block - malware",
    Category.BLOCK_PHISHING.value: "Block - phishing",
    Category.BLOCK_ADULT.value: "Block - adult",
    Category.NXDOMAIN_PROBE.value: "NXDOMAIN probe",
}


class Outcome(str, Enum):
    """The verdict for a single query, derived from the response (or lack of
    one) and the category's expectation.

    ``allowed`` / ``blocked``
        Matched what we expected -- the common case, good news.
    ``false_positive``
        An allow-listed category came back REFUSED / NXDOMAIN / sinkholed /
        timed out.  This is a user-visible outage and the highest-value finding
        the tool produces.
    ``false_negative``
        A block-listed category resolved to a real address, i.e. the appliance
        let known-bad traffic through.
    ``nxdomain``
        Response was NXDOMAIN for a category that expects it (DGA-style probe).
    ``timeout`` / ``error``
        No response inside the timeout window, or a malformed response.
    """

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    NXDOMAIN = "nxdomain"
    TIMEOUT = "timeout"
    ERROR = "error"


#: QTYPE name -> number, and back.  ``HTTPS``/``SVCB`` are included because
#: modern browsers send them constantly and a surprising number of appliances
#: mishandle type 65.
QTYPES: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "DNSKEY": 48,
    "SVCB": 64,
    "HTTPS": 65,
    "ANY": 255,
}
QTYPE_NAMES: dict[int, str] = {v: k for k, v in QTYPES.items()}

#: DNS RCODE number -> name.
RCODES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
    16: "BADVERS",
}
RCODE_NAMES: dict[str, int] = {v: k for k, v in RCODES.items()}

#: Sentinel rcode used for queries that never got a response.  It is not a wire
#: value; it exists so every query lands in exactly one rcode bucket.
RCODE_TIMEOUT = "TIMEOUT"
RCODE_ERROR = "ERROR"

#: The rcode buckets the dashboard always renders, in display order.
RCODE_BUCKETS: tuple[str, ...] = (
    "NOERROR",
    "NXDOMAIN",
    "REFUSED",
    "SERVFAIL",
    "FORMERR",
    "NOTIMP",
    RCODE_TIMEOUT,
    RCODE_ERROR,
)


class Transport(str, Enum):
    UDP = "udp"
    TCP = "tcp"


#: Addresses that count as "sinkholed" rather than a real answer.  0.0.0.0 and
#: :: are the classic blackhole answers that some resolvers return instead of
#: NXDOMAIN, and a lot of appliances use them for blocked names.
SINKHOLE_IPS_DEFAULT: frozenset[str] = frozenset(
    {"0.0.0.0", "::", "127.0.0.1", "::1"}
)

#: Upper bounds, in milliseconds, of the latency histogram used for percentiles.
#: Bucket ``i`` counts queries with latency in (buckets[i-1], buckets[i]].
#: Percentiles are reported as the bucket's upper bound, which is why the low
#: end is fine-grained (latency in a filtered-DNS test is almost always < 100ms)
#: and the tail is coarse.
LATENCY_BUCKETS_MS: tuple[float, ...] = (
    0.5,
    1.0,
    2.0,
    5.0,
    10.0,
    20.0,
    30.0,
    50.0,
    75.0,
    100.0,
    150.0,
    200.0,
    300.0,
    500.0,
    750.0,
    1000.0,
    2000.0,
    5000.0,
    10000.0,
)

#: Field order for ``QueryRecord``.  The engine writes tuples in this order in
#: its hot path and only materialises dataclasses when exporting, so this tuple
#: is also the CSV header.
RECORD_FIELDS: tuple[str, ...] = (
    "ts",
    "client_ip",
    "persona_id",
    "role",
    "qname",
    "qtype",
    "category",
    "rcode",
    "outcome",
    "latency_ms",
    "answer_ip",
    "bytes_sent",
    "bytes_received",
)


@dataclass(slots=True)
class QueryRecord:
    """One DNS query and its result.  This is the unit of truth: the dashboard
    aggregates these, and ``--export`` writes them out as CSV/JSONL."""

    ts: float
    client_ip: str
    persona_id: int
    role: str
    qname: str
    qtype: str
    category: str
    rcode: str
    outcome: str
    latency_ms: float
    answer_ip: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0

    def as_tuple(self) -> tuple:
        return tuple(getattr(self, f) for f in RECORD_FIELDS)

    def as_dict(self) -> dict:
        return {f: getattr(self, f) for f in RECORD_FIELDS}

    @classmethod
    def from_tuple(cls, values: tuple) -> "QueryRecord":
        return cls(*values)


@dataclass(slots=True)
class RunConfig:
    """Everything the engine needs to execute a run.  Built by ``cli.py``.

    ``mode`` is ``"personas"`` (one source IP, N logical clients) or ``"pool"``
    (real secondary source IPs -- needs elevation and a dedicated NIC).
    """

    server: str = "127.0.0.1"
    port: int = 53
    mode: str = "personas"
    personas: int = 10_000
    target_qps: float = 1000.0
    duration_s: float = 60.0
    timeout_s: float = 2.0
    seed: int = 1337
    source_ips: list[str] = field(default_factory=list)
    threads: int = 1
    max_inflight: int = 20_000
    #: Synchronised-burst injection.  ``qps_burst > 1`` multiplies the arrival rate
    #: for ``qps_burst_len_s`` seconds every ``qps_burst_period_s`` seconds, to
    #: reproduce the top-of-the-hour stampede when the whole office opens Outlook
    #: at once.  Per-second policy counters and appliance CPU fail here far more
    #: often than they fail at the average rate, which is the point of the feature.
    qps_burst: float = 1.0
    qps_burst_period_s: float = 60.0
    qps_burst_len_s: float = 2.0
    categories: list[str] = field(default_factory=list)
    sinkhole_ips: tuple[str, ...] = tuple(SINKHOLE_IPS_DEFAULT)
    repeat: float = 0.0
    export_path: str = ""
    dry_run: bool = False
    #: Name of the target profile in use, for labelling runs and comparisons.
    target_name: str = ""
    #: Per-category expectation overrides (``{"block_ads": "unknown"}``).  Empty means
    #: every category keeps its :data:`CATEGORY_EXPECTED` default.
    expectations: dict[str, str] = field(default_factory=dict)
    #: Block-page networks (``"146.112.61.0/24"``) that count as a block, in addition
    #: to the exact addresses in ``sinkhole_ips``.
    sinkhole_cidrs: tuple[str, ...] = ()
    #: When True, NXDOMAIN for internal-only names (``*.local``, ``*.corp``) is not a
    #: false positive.  Right for a public resolver, wrong for an appliance in front
    #: of Active Directory, which is why it is per target.
    ignore_internal: bool = False

    @property
    def target(self) -> str:
        return f"{self.server}:{self.port}"

    def expect_for(self, category: str) -> str:
        """What this run expects of ``category``, honouring the target's profile."""
        return self.expectations.get(category) or CATEGORY_EXPECTED.get(category, "unknown")


#: Suffixes that only resolve inside someone's own network.  A public resolver
#: correctly answers NXDOMAIN for these.
INTERNAL_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".intranet",
    ".localdomain",
    ".home.arpa",
)


def is_internal_name(qname: str) -> bool:
    name = qname.lower().rstrip(".")
    return name.endswith(INTERNAL_SUFFIXES)


def is_reverse_name(qname: str) -> bool:
    """Reverse-DNS (PTR) names.  Most addresses have no PTR record, so NXDOMAIN here
    is ordinary and says nothing about the filter."""
    name = qname.lower().rstrip(".")
    return name.endswith((".in-addr.arpa", ".ip6.arpa"))


class SinkholeSet:
    """Addresses (and networks) that mean "this name was blocked".

    Supports ``in`` so :func:`dnsloadforge.engine.classify` can treat it like the
    frozenset it replaced.  Exact addresses are checked first, because that is the
    common case and costs a hash lookup; networks are only parsed when it misses.
    """

    __slots__ = ("_ips", "_nets")

    def __init__(self, ips=(), cidrs=()) -> None:
        import ipaddress

        self._ips = frozenset(ips)
        self._nets = tuple(ipaddress.ip_network(c, strict=False) for c in cidrs)

    def __contains__(self, ip: object) -> bool:
        if ip in self._ips:
            return True
        if not self._nets or not isinstance(ip, str):
            return False
        import ipaddress

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in net for net in self._nets if net.version == address.version)


# ---------------------------------------------------------------------------
# STATS SNAPSHOT SCHEMA -- the contract between stats.py and the dashboard.
# ---------------------------------------------------------------------------
# ``StatsAggregator.snapshot()`` returns exactly this shape.  The dashboard
# (``dashboard/index.html``) consumes ``/api/stats`` and the SSE stream
# (``/api/stream``), both of which emit this object verbatim.  Every numeric
# field is a number, never a string, so the chart code can use it directly.
#
# {
#   "run": {
#     "state": "idle" | "running" | "stopped",
#     "started_at": 1750000000.0,
#     "elapsed_s": 42.0,
#     "server": "10.1.106.5:53",
#     "mode": "personas" | "pool",
#     "personas": 10000,
#     "source_ips": 1,
#     "target_qps": 10000.0,
#     "seed": 1337
#   },
#   "totals": {
#     "sent": 42, "received": 40, "timeouts": 1, "errors": 1,
#     "bytes_sent": 2000, "bytes_received": 4000,
#     "unique_clients": 998, "unique_domains": 500
#   },
#   "rates": {                       # over the last completed 1s bucket
#     "qps_sent": 100.0, "qps_recv": 99.0, "error_pct": 1.0,
#     "qps_sent_avg": 99.5, "in_flight": 3
#   },
#   "latency_ms": {                  # rolling 60s window
#     "p50": 1.0, "p95": 5.0, "p99": 20.0,
#     "min": 0.4, "max": 120.0, "avg": 3.2
#   },
#   "outcomes": {                    # keys are Outcome values, all present
#     "allowed": 30, "blocked": 8, "false_positive": 0, "false_negative": 0,
#     "nxdomain": 1, "timeout": 1, "error": 1
#   },
#   "rcodes": {                      # keys are RCODE_BUCKETS, all present
#     "NOERROR": 32, "NXDOMAIN": 1, "REFUSED": 8, "SERVFAIL": 0,
#     "FORMERR": 0, "NOTIMP": 0, "TIMEOUT": 1, "ERROR": 1
#   },
#   "series": [                      # last 300 one-second buckets, oldest first
#     {"t": 1750000000, "sent": 100, "recv": 99, "timeout": 1,
#      "fp": 0, "fn": 0, "p95": 5.0}
#   ],
#   "by_category": [                 # one row per category, always all 9
#     {"category": "block_ads", "label": "Block - ads", "expect": "block",
#      "sent": 10, "blocked": 10, "allowed": 0, "fp": 0, "fn": 0,
#      "timeout": 0, "p95": 5.0, "pass_rate": 1.0}
#   ],
#   "top_domains": [
#     {"qname": "example.com", "count": 40, "category": "allow_popular",
#      "outcome": "allowed", "p95": 5.0}
#   ],
#   "top_clients": [
#     {"client_ip": "10.1.106.7", "count": 40, "fp": 0, "fn": 0, "timeout": 0}
#   ],
#   "false_positives": [
#     {"qname": "login.microsoftonline.com", "client_ip": "10.1.106.7",
#      "category": "enterprise", "rcode": "SERVFAIL", "count": 3,
#      "last_seen": 1750000000}
#   ],
#   "false_negatives": [
#     {"qname": "ads.example-bad.com", "client_ip": "10.1.106.7",
#      "category": "block_ads", "answer": "1.2.3.4", "count": 2,
#      "last_seen": 1750000000}
#   ],
#   "verdict": {
#     "status": "idle" | "unknown" | "passthrough" | "filtering" | "degraded" | "baseline",
#     "note": "human readable one-liner"
#   }
# }
