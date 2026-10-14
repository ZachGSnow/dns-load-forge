"""The 10,000-worker office model.

This module is what makes the tool a *simulation* rather than a traffic gun.  A
uniform random pick from a domain list produces a suspiciously smooth stream:
every client looks identical, the long tail is over-represented, and DNS caching
-- the single biggest shaper of what a resolver actually sees -- does not exist
at all.

So each of the 10,000 simulated workers is a *persona* with:

* a **role** (knowledge worker, developer, call centre, kiosk, IoT, ...) that
  sets its domain-category mix, query-type mix and query intensity;
* a **hot set** of domains it keeps coming back to.  Real clients repeat a small
  handful of names (mail, Teams, the intranet, an analytics beacon) and only
  occasionally touch something new, because everything else is already in the OS
  or browser cache.  Without this, per-client policy results are meaningless --
  every client would look like every other client.

Arrivals are modelled as a **compound Poisson process**: a persona opens a "page"
at a Poisson rate and each page fires a small burst of 1-N lookups at once.  That
burstiness is the point.  A resolver that is fine at 10,000 smooth queries per
second can still fall over on a real office's traffic, because the office arrives
in clumps.

Sizing note the operator should sanity-check: at the default 10,000 qps across
10,000 clients, each client is doing ~3,600 queries/hour at peak.  A busy
knowledge worker really does hit that during a full-tilt hour, but it is the
*peak* of the day, not the average -- see ``diurnal()``.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .spec import CATEGORY_EXPECTED, Category

__all__ = [
    "Role",
    "ROLES",
    "Persona",
    "PersonaModel",
    "diurnal_factor",
    "ROLE_TOTAL_HEADCOUNT",
]

#: Categories that personas draw their normal (non-probe) traffic from.  Note the
#: deliberate omission of ``nxdomain_probe``: those queries are generated at
#: runtime by :meth:`PersonaModel.dga_name`, not sampled from a list, because no
#: domain list contains names that are supposed to not exist.
TRAFFIC_CATEGORIES: tuple[str, ...] = (
    Category.ALLOW_POPULAR.value,
    Category.ALLOW_LONGTAIL.value,
    Category.ENTERPRISE.value,
    Category.BORDERLINE.value,
    Category.BLOCK_ADS.value,
    Category.BLOCK_MALWARE.value,
    Category.BLOCK_PHISHING.value,
    Category.BLOCK_ADULT.value,
)


def _normalise(weights: dict[str, float]) -> dict[str, float]:
    """Scale weights to sum to 1.0, rejecting negative or all-zero input.

    Normalising instead of hand-writing fractions that must add up removes a
    whole class of silent bug: a mix that sums to 0.97 quietly biases 3% of all
    traffic to whichever category happens to be looked up last.
    """
    cleaned = {k: float(v) for k, v in weights.items() if v}
    for key, value in cleaned.items():
        if value < 0:
            raise ValueError(f"negative weight for {key!r}: {value}")
    total = math.fsum(cleaned.values())
    if total <= 0:
        raise ValueError(f"weights must sum to something positive: {weights!r}")
    return {k: v / total for k, v in cleaned.items()}


def _cdf(mix: dict[str, float]) -> tuple[tuple[str, float], ...]:
    """Freeze a normalised mix into a cumulative distribution for O(log n)
    sampling without rebuilding anything per query."""
    out: list[tuple[str, float]] = []
    running = 0.0
    for key, value in sorted(mix.items()):
        running += value
        out.append((key, running))
    return tuple(out)


@dataclass(frozen=True, slots=True)
class Role:
    """A kind of worker in the simulated office.

    ``headcount_weight`` is in units of people out of 10,000, so the roster reads
    like a real seat count.  ``rate_weight`` is *relative* query intensity: the
    absolute load always comes from ``--qps``, so changing the target rate never
    changes the shape of the office, only its volume.
    """

    name: str
    label: str
    headcount_weight: int
    rate_weight: float
    category_mix: dict[str, float]
    qtype_mix: dict[str, float]
    burst_mean: float
    hot_set_min: int
    hot_set_max: int
    description: str

    @property
    def cat_cdf(self) -> tuple[tuple[str, float], ...]:
        return _cdf(_normalise(self.category_mix))

    @property
    def qtype_cdf(self) -> tuple[tuple[str, float], ...]:
        return _cdf(_normalise(self.qtype_mix))


# ---------------------------------------------------------------------------
# The roster.  Headcounts sum to exactly 10,000 -- that is the "office of 10k".
# ---------------------------------------------------------------------------

ROLES: dict[str, Role] = {
    "knowledge_worker": Role(
        name="knowledge_worker",
        label="Knowledge worker",
        headcount_weight=3800,
        rate_weight=1.0,
        category_mix={
            Category.ALLOW_POPULAR.value: 55,
            Category.ALLOW_LONGTAIL.value: 22,
            Category.ENTERPRISE.value: 11,
            Category.BORDERLINE.value: 9,
            Category.BLOCK_ADS.value: 2.2,
            Category.BLOCK_MALWARE.value: 0.5,
            Category.BLOCK_PHISHING.value: 0.2,
            Category.BLOCK_ADULT.value: 0.1,
        },
        qtype_mix={"A": 74, "AAAA": 15, "HTTPS": 6, "TXT": 2, "PTR": 1.5, "SRV": 0.5, "MX": 0.5, "CNAME": 0.5, "NS": 0.2, "SVCB": 0.8},
        burst_mean=6.0,
        hot_set_min=18,
        hot_set_max=45,
        description="Mail/Teams/intranet plus a heavy SaaS long tail; the bulk of the office.",
    ),
    "developer": Role(
        name="developer",
        label="Developer / engineer",
        headcount_weight=900,
        rate_weight=1.6,
        category_mix={
            Category.ALLOW_POPULAR.value: 50,
            Category.ALLOW_LONGTAIL.value: 30,
            Category.ENTERPRISE.value: 12,
            Category.BORDERLINE.value: 6,
            Category.BLOCK_ADS.value: 1.5,
            Category.BLOCK_MALWARE.value: 0.3,
            Category.BLOCK_PHISHING.value: 0.1,
            Category.BLOCK_ADULT.value: 0.1,
        },
        qtype_mix={"A": 68, "AAAA": 14, "HTTPS": 10, "TXT": 3, "PTR": 1, "SRV": 1, "MX": 0.5, "CNAME": 1, "NS": 0.3, "SVCB": 1.2},
        burst_mean=9.0,
        hot_set_min=25,
        hot_set_max=70,
        description="Package registries, docs, CI hosts; the deepest long tail and the most new names.",
    ),
    "call_center": Role(
        name="call_center",
        label="Contact centre agent",
        headcount_weight=1200,
        rate_weight=0.8,
        category_mix={
            Category.ALLOW_POPULAR.value: 66,
            Category.ALLOW_LONGTAIL.value: 14,
            Category.ENTERPRISE.value: 15,
            Category.BORDERLINE.value: 4,
            Category.BLOCK_ADS.value: 0.8,
            Category.BLOCK_MALWARE.value: 0.1,
            Category.BLOCK_PHISHING.value: 0.1,
            Category.BLOCK_ADULT.value: 0.0,
        },
        qtype_mix={"A": 80, "AAAA": 10, "HTTPS": 4, "TXT": 2, "PTR": 2, "MX": 1, "NS": 1},
        burst_mean=4.0,
        hot_set_min=10,
        hot_set_max=25,
        description="Very repetitive: one CRM, one softphone, same names thousands of times a day.",
    ),
    "sales_marketing": Role(
        name="sales_marketing",
        label="Sales / marketing",
        headcount_weight=1100,
        rate_weight=1.2,
        category_mix={
            Category.ALLOW_POPULAR.value: 58,
            Category.ALLOW_LONGTAIL.value: 20,
            Category.ENTERPRISE.value: 8,
            Category.BORDERLINE.value: 12,
            Category.BLOCK_ADS.value: 1.5,
            Category.BLOCK_MALWARE.value: 0.3,
            Category.BLOCK_PHISHING.value: 0.1,
            Category.BLOCK_ADULT.value: 0.1,
        },
        qtype_mix={"A": 72, "AAAA": 16, "HTTPS": 7, "TXT": 2, "PTR": 1, "MX": 1, "NS": 1},
        burst_mean=7.0,
        hot_set_min=20,
        hot_set_max=55,
        description="Trackers, ad and social CDNs -- the group with the highest borderline/analytics share.",
    ),
    "guest_byod": Role(
        name="guest_byod",
        label="Guest / BYOD",
        headcount_weight=700,
        rate_weight=0.6,
        category_mix={
            Category.ALLOW_POPULAR.value: 55,
            Category.ALLOW_LONGTAIL.value: 16,
            Category.ENTERPRISE.value: 4,
            Category.BORDERLINE.value: 12,
            Category.BLOCK_ADS.value: 8,
            Category.BLOCK_MALWARE.value: 2.5,
            Category.BLOCK_PHISHING.value: 1.5,
            Category.BLOCK_ADULT.value: 1.0,
        },
        qtype_mix={"A": 72, "AAAA": 16, "HTTPS": 7, "TXT": 2, "PTR": 1, "MX": 1, "NS": 1},
        burst_mean=4.0,
        hot_set_min=8,
        hot_set_max=20,
        description="Unmanaged phones and laptops: the dirtiest mix, and where malware actually shows up.",
    ),
    "finance_hr": Role(
        name="finance_hr",
        label="Finance / HR",
        headcount_weight=700,
        rate_weight=1.1,
        category_mix={
            Category.ALLOW_POPULAR.value: 60,
            Category.ALLOW_LONGTAIL.value: 20,
            Category.ENTERPRISE.value: 12,
            Category.BORDERLINE.value: 6,
            Category.BLOCK_ADS.value: 1.5,
            Category.BLOCK_MALWARE.value: 0.3,
            Category.BLOCK_PHISHING.value: 0.1,
            Category.BLOCK_ADULT.value: 0.1,
        },
        qtype_mix={"A": 76, "AAAA": 13, "HTTPS": 5, "TXT": 2, "PTR": 1.5, "MX": 1.5, "NS": 1},
        burst_mean=5.0,
        hot_set_min=12,
        hot_set_max=30,
        description="ERP and payroll; phishing is the realistic threat, so the phishing share is legitimately reachable.",
    ),
    "kiosk_shared": Role(
        name="kiosk_shared",
        label="Kiosk / shared terminal",
        headcount_weight=500,
        rate_weight=0.5,
        category_mix={
            Category.ALLOW_POPULAR.value: 70,
            Category.ALLOW_LONGTAIL.value: 12,
            Category.ENTERPRISE.value: 8,
            Category.BORDERLINE.value: 6,
            Category.BLOCK_ADS.value: 3,
            Category.BLOCK_MALWARE.value: 0.5,
            Category.BLOCK_PHISHING.value: 0.3,
            Category.BLOCK_ADULT.value: 0.2,
        },
        qtype_mix={"A": 74, "AAAA": 15, "HTTPS": 6, "TXT": 2, "PTR": 1.5, "SRV": 0.5, "MX": 0.5, "CNAME": 0.5},
        burst_mean=3.0,
        hot_set_min=5,
        hot_set_max=14,
        description="Training rooms and reception: tiny hot set, everything repeated constantly.",
    ),
    "helpdesk_it": Role(
        name="helpdesk_it",
        label="IT / helpdesk",
        headcount_weight=400,
        rate_weight=1.4,
        category_mix={
            Category.ALLOW_POPULAR.value: 48,
            Category.ALLOW_LONGTAIL.value: 22,
            Category.ENTERPRISE.value: 18,
            Category.BORDERLINE.value: 8,
            Category.BLOCK_ADS.value: 2,
            Category.BLOCK_MALWARE.value: 1.0,
            Category.BLOCK_PHISHING.value: 0.6,
            Category.BLOCK_ADULT.value: 0.4,
        },
        qtype_mix={"A": 70, "AAAA": 14, "HTTPS": 6, "TXT": 4, "PTR": 3, "SRV": 1.5, "MX": 0.5, "CNAME": 0.5, "NS": 0.5},
        burst_mean=7.0,
        hot_set_min=30,
        hot_set_max=80,
        description="Investigates alarms, so it legitimately resolves known-bad names -- a filter must not break that.",
    ),
    "iot_device": Role(
        name="iot_device",
        label="IoT device",
        headcount_weight=350,
        rate_weight=0.15,
        category_mix={
            Category.ALLOW_POPULAR.value: 40,
            Category.ALLOW_LONGTAIL.value: 10,
            Category.ENTERPRISE.value: 45,
            Category.BORDERLINE.value: 4,
            Category.BLOCK_ADS.value: 0.5,
            Category.BLOCK_MALWARE.value: 0.3,
            Category.BLOCK_PHISHING.value: 0.1,
            Category.BLOCK_ADULT.value: 0.1,
        },
        qtype_mix={"A": 82, "AAAA": 8, "PTR": 5, "HTTPS": 3, "SRV": 2},
        burst_mean=2.0,
        hot_set_min=3,
        hot_set_max=8,
        description="Printers, cameras, door controllers: barely any traffic, but largely enterprise/NTP/PTR names.",
    ),
    "executive": Role(
        name="executive",
        label="Executive",
        headcount_weight=250,
        rate_weight=1.8,
        category_mix={
            Category.ALLOW_POPULAR.value: 62,
            Category.ALLOW_LONGTAIL.value: 18,
            Category.ENTERPRISE.value: 13,
            Category.BORDERLINE.value: 5,
            Category.BLOCK_ADS.value: 1.5,
            Category.BLOCK_MALWARE.value: 0.3,
            Category.BLOCK_PHISHING.value: 0.1,
            Category.BLOCK_ADULT.value: 0.1,
        },
        qtype_mix={"A": 72, "AAAA": 15, "HTTPS": 7, "TXT": 2, "PTR": 1.5, "MX": 1, "NS": 0.5, "CNAME": 0.5, "SVCB": 0.5},
        burst_mean=8.0,
        hot_set_min=20,
        hot_set_max=50,
        description="Mobile clients, lots of mail and conferencing; a blocked sign-in name becomes a board-level ticket.",
    ),
    "server_infra": Role(
        name="server_infra",
        label="Server / infrastructure",
        headcount_weight=100,
        rate_weight=3.0,
        category_mix={
            Category.ALLOW_POPULAR.value: 35,
            Category.ALLOW_LONGTAIL.value: 10,
            Category.ENTERPRISE.value: 50,
            Category.BORDERLINE.value: 4,
            Category.BLOCK_ADS.value: 0.5,
            Category.BLOCK_MALWARE.value: 0.3,
            Category.BLOCK_PHISHING.value: 0.1,
            Category.BLOCK_ADULT.value: 0.1,
        },
        qtype_mix={"A": 45, "AAAA": 10, "SRV": 18, "PTR": 12, "TXT": 6, "MX": 5, "NS": 3, "HTTPS": 1},
        burst_mean=1.2,
        hot_set_min=30,
        hot_set_max=80,
        description="AD, CRL/OCSP and update infrastructure. SRV/PTR-heavy and the most catastrophic to block.",
    ),
}

ROLE_TOTAL_HEADCOUNT = sum(r.headcount_weight for r in ROLES.values())


# ---------------------------------------------------------------------------
# Diurnal curve
# ---------------------------------------------------------------------------

#: Fraction of peak query rate by hour of day, indexed 0-23.  Shaped from the
#: familiar office pattern: quiet overnight, a sharp 07:00-09:00 ramp as people
#: log in, a plateau through the morning, a lunch dip, an afternoon plateau, then
#: a fall-off.  The morning ramp matters most when vetting an appliance, because
#: that is when every client re-resolves everything at once.
_DIURNAL_HOURLY: tuple[float, ...] = (
    0.04, 0.03, 0.03, 0.03, 0.04, 0.06,   # 00-05
    0.12, 0.30, 0.62, 0.90, 1.00, 0.98,   # 06-11
    0.72, 0.80, 0.95, 0.96, 0.88, 0.70,   # 12-17
    0.48, 0.30, 0.20, 0.14, 0.09, 0.06,   # 18-23
)


def diurnal_factor(hour: float) -> float:
    """Interpolate :data:`_DIURNAL_HOURLY` at a fractional hour of day.

    Returns 0.03-1.00.  Linear interpolation between hours is plenty: the curve
    exists to reproduce the *shape* of an office day over a compressed soak test,
    not to model any particular company's login pattern.
    """
    if not 0.0 <= hour < 24.0:
        hour = hour % 24.0
    low = int(hour)
    high = (low + 1) % 24
    frac = hour - low
    return _DIURNAL_HOURLY[low] * (1.0 - frac) + _DIURNAL_HOURLY[high] * frac


# ---------------------------------------------------------------------------
# Personas
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Persona:
    """One simulated worker.

    ``cat_cdf`` and ``qtype_cdf`` are precomputed cumulative distributions so a
    query hand-out costs a ``bisect`` rather than rebuilding a weighted table.
    """

    pid: int
    role: str
    source_ip: str
    rate_weight: float
    cat_cdf: tuple[tuple[str, float], ...]
    qtype_cdf: tuple[tuple[str, float], ...]
    burst_mean: float
    hot: list[str] = field(default_factory=list)
    hot_cdf: tuple[tuple[str, float], ...] = ()
    #: Category per hot domain, captured at build time.  It has to travel with the
    #: domain rather than be looked up separately: a query's category must describe
    #: *that* query's name, or the report attributes a block-listed lookup to an
    #: allow-listed category and invents a false positive against a filter that
    #: behaved perfectly.
    hot_cats: dict[str, str] = field(default_factory=dict)

    def pick_category(self, rng: random.Random) -> str:
        return _pick_cdf(self.cat_cdf, rng)

    def pick_qtype(self, rng: random.Random) -> str:
        return _pick_cdf(self.qtype_cdf, rng)


def _pick_cdf(cdf: tuple[tuple[str, float], ...], rng: random.Random) -> str:
    """Sample a frozen cumulative distribution and validate its input.

    Validated here rather than in the caller because the engine relies on
    categories and qtypes being real names -- a typo in a role table would
    otherwise surface as a mysterious empty category row on the dashboard.
    """
    value = rng.random()
    for key, threshold in cdf:
        if value <= threshold:
            return key
    return cdf[-1][0]


class PersonaModel:
    """Builds and drives the simulated office.

    The aggregate arrival process is what the engine schedules: because the
    superposition of independent Poisson processes is itself Poisson, the engine
    can draw one inter-arrival time for the whole office and then pick *which*
    persona acted in proportion to its rate.  That is mathematically identical to
    running 10,000 independent timers, at a fraction of the cost -- and it is the
    only reason 10,000 personas are practical in one Python process.
    """

    def __init__(
        self,
        catalogue,
        *,
        personas: int = 10_000,
        source_ips: Sequence[str] = (),
        seed: int = 1337,
        roles: Iterable[str] | None = None,
        nxdomain_share: float = 0.04,
        hot_share: float = 0.70,
        max_hot_pool: int = 4096,
    ) -> None:
        self.catalogue = catalogue
        self.seed = seed
        self.nxdomain_share = float(nxdomain_share)
        self.hot_share = float(hot_share)
        self.rng = random.Random(seed)

        available = list(roles) if roles else [r.name for r in ROLES.values() if self._role_has_traffic(r)]
        if not available:
            raise ValueError("no usable roles: the catalogue has no domains in any traffic category")
        for name in available:
            if name not in ROLES:
                raise ValueError(f"unknown role {name!r}; choose from {', '.join(sorted(ROLES))}")

        self.roles = available
        self.source_ips = list(source_ips) or ["127.0.0.1"]
        self.personas: list[Persona] = []
        self._cum_weights: list[float] = []
        self._total_weight = 0.0
        self._hot_counters: dict[str, int] = {}

        self._build(int(personas), available, max_hot_pool)

    # -- construction -------------------------------------------------------

    def _role_has_traffic(self, role: Role) -> bool:
        """A role is usable only if the catalogue can actually feed it.  On a
        first offline run most pools are empty, so roles whose mix is dominated
        by missing categories are dropped rather than generating placeholder
        domains that would poison the results."""
        for category, weight in role.category_mix.items():
            if weight > 0 and self.catalogue.has(category):
                return True
        return False

    def _build(self, personas: int, available: list[str], max_hot_pool: int) -> None:
        rng = self.rng
        # Distribute headcount across the usable roles, preserving their ratio.
        usable = {name: ROLES[name] for name in available}
        headcount_total = sum(r.headcount_weight for r in usable.values())

        counts: dict[str, int] = {}
        assigned = 0
        ordered = sorted(usable, key=lambda n: usable[n].headcount_weight, reverse=True)
        for index, name in enumerate(ordered):
            if index == len(ordered) - 1:
                counts[name] = personas - assigned
            else:
                share = int(round(personas * usable[name].headcount_weight / headcount_total))
                counts[name] = share
                assigned += share
            counts[name] = max(counts.get(name, 0), 0)

        # A category's pool is shared by every persona, but each persona keeps its
        # own hot set.  Sampling independent hot sets per persona is O(personas x
        # hot), which for 10,000 x 70 is fine, but drawing from a big ranked list
        # repeatedly is not -- so we draw each hot set from the category pools
        # directly and cap the per-role hot pool.
        pid = 0
        for name in ordered:
            role = usable[name]
            cat_cdf = role.cat_cdf
            qtype_cdf = role.qtype_cdf
            for _ in range(counts[name]):
                source_ip = self.source_ips[pid % len(self.source_ips)]
                persona = Persona(
                    pid=pid,
                    role=name,
                    source_ip=source_ip,
                    rate_weight=role.rate_weight,
                    cat_cdf=cat_cdf,
                    qtype_cdf=qtype_cdf,
                    burst_mean=role.burst_mean,
                )
                hot = self._build_hot_set(role, cat_cdf, max_hot_pool)
                persona.hot = [domain for domain, _category in hot]
                persona.hot_cats = dict(hot)
                persona.hot_cdf = self._hot_cdf(persona.hot)
                self.personas.append(persona)
                pid += 1

        self._recompute_weights()

    def _build_hot_set(self, role: Role, cat_cdf, cap: int) -> list[tuple[str, str]]:
        """Draw this persona's repeated domains, weighted the same way its normal
        traffic is so the hot set does not skew the category mix.

        Returns ``(domain, category)`` pairs.  The category is the pool the domain
        was drawn from, which is exactly the category the catalogue would report
        for it -- overlap resolution guarantees a domain lives in one pool only.
        """
        size = self.rng.randint(role.hot_set_min, role.hot_set_max)
        size = min(size, cap)
        drawn: list[tuple[str, str]] = []
        seen: set[str] = set()
        guard = size * 8
        while len(drawn) < size and guard > 0:
            guard -= 1
            category = _pick_cdf(cat_cdf, self.rng)
            if not self.catalogue.has(category):
                continue
            domain = self.catalogue.sample(category, self.rng)
            if domain in seen:
                continue
            seen.add(domain)
            drawn.append((domain, category))
            self._hot_counters[domain] = self._hot_counters.get(domain, 0) + 1
        return drawn

    @staticmethod
    def _hot_cdf(domains: list[str]) -> tuple[tuple[str, float], ...]:
        """Front-biased cumulative distribution over a persona's hot set.

        The first entries are the names it looks up constantly (mail, the
        intranet) and the last are occasional.  A flat distribution would make a
        client look like it had no cache at all.
        """
        if not domains:
            return ()
        weights = [1.0 / (1.0 + index * 0.35) for index in range(len(domains))]
        total = math.fsum(weights)
        out: list[tuple[str, float]] = []
        running = 0.0
        for domain, weight in zip(domains, weights):
            running += weight / total
            out.append((domain, running))
        return tuple(out)

    def _recompute_weights(self) -> None:
        cumulative: list[float] = []
        total = 0.0
        for persona in self.personas:
            total += persona.rate_weight
            cumulative.append(total)
        self._cum_weights = cumulative
        self._total_weight = total

    # -- driving the simulation --------------------------------------------

    def choose_persona(self, rng: random.Random | None = None) -> Persona:
        """Pick which persona acted, in proportion to its rate.

        Combined with a single aggregate Poisson arrival stream this reproduces
        10,000 independent Poisson processes exactly (Poisson splitting).
        """
        if not self.personas:
            raise ValueError("no personas were built")
        rng = rng or self.rng
        target = rng.random() * self._total_weight
        low, high = 0, len(self._cum_weights) - 1
        while low < high:
            mid = (low + high) // 2
            if self._cum_weights[mid] < target:
                low = mid + 1
            else:
                high = mid
        return self.personas[low]

    def next_query(self, persona: Persona, rng: random.Random | None = None) -> tuple[str, str, str]:
        """Return ``(qname, qtype, category)`` for one lookup by ``persona``.

        The 4-step behaviour below is the whole realism story: a small chance of a
        known-bad or junk name, otherwise either a name this client already knows
        (the cache/refresh majority) or something new it has never asked for.
        """
        rng = rng or self.rng

        if rng.random() < self.nxdomain_share:
            return self.dga_name(rng), "A", Category.NXDOMAIN_PROBE.value

        if persona.hot_cdf and rng.random() < self.hot_share:
            # One draw, then read the category for *that* name.  Drawing the
            # category separately would let a block-listed domain be reported
            # under an allow-listed category, which reads as the appliance
            # blocking legitimate traffic when in fact it behaved correctly.
            domain = _pick_cdf(persona.hot_cdf, rng)
            category = persona.hot_cats.get(domain) or self._category_of_domain(domain)
            return domain, persona.pick_qtype(rng), category

        category = persona.pick_category(rng)
        if not self.catalogue.has(category):
            # Fall back to any populated traffic category rather than silently
            # emitting a name we cannot classify -- an unclassifiable query would
            # show up as a phantom row in the category table.
            category = self._first_available()
        return self.catalogue.sample(category, rng), persona.pick_qtype(rng), category

    def _category_of_domain(self, domain: str) -> str:
        """Category for a name we did not capture one for, via the catalogue's
        reverse index, falling back to any populated category."""
        return self.catalogue.category_of(domain) or self._first_available()

    def _first_available(self) -> str:
        for category in TRAFFIC_CATEGORIES:
            if self.catalogue.has(category):
                return category
        raise ValueError(
            "the catalogue has no domains in any traffic category; run "
            "`python -m dnsloadforge.domainlist --refresh` while online, or pass "
            "--domain-source github-lite"
        )

    # -- DGA / NXDOMAIN probes ---------------------------------------------

    #: TLDs used for junk probes.  RFC 2606/6761 reserved names come first and are
    #: used for a deliberate share of probes: they are guaranteed to be
    #: NXDOMAIN everywhere, which gives the report a known-good baseline instead
    #: of inferring failure from whichever domains happened to be fake.
    _DGA_TLDS: tuple[str, ...] = (
        ".invalid", ".invalid", ".test", ".example",
        ".com", ".net", ".org", ".info", ".biz", ".xyz",
        ".online", ".site", ".top", ".click", ".loan",
    )

    def dga_name(self, rng: random.Random | None = None) -> str:
        """Generate a plausible algorithmic/typo-squat probe name.

        Malware and some adware generate tens of thousands of these per host per
        day, and they are the single best way to find out whether an appliance
        correctly answers NXDOMAIN at rate or collapses under it.
        """
        rng = rng or self.rng
        length = rng.randint(8, 22)
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        label = "".join(rng.choice(alphabet) for _ in range(length))
        tld = rng.choice(self._DGA_TLDS)
        return f"{label}{tld}"

    # -- reporting ----------------------------------------------------------

    def counts_by_role(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for persona in self.personas:
            out[persona.role] = out.get(persona.role, 0) + 1
        return out

    def summary(self, target_qps: float = 0.0) -> list[dict]:
        """Role breakdown, including the per-client rate in queries per hour.

        That last column is the operator's reality check: it is the number to
        quote when someone asks what 10,000 qps means for one desk.
        """
        counts = self.counts_by_role()
        total_rate = self._total_weight or 1.0
        rows: list[dict] = []
        for name in sorted(counts, key=lambda n: counts[n], reverse=True):
            role = ROLES[name]
            headcount = counts[name]
            share = headcount / len(self.personas) if self.personas else 0.0
            role_rate = role.rate_weight * headcount / total_rate
            qps = target_qps * role_rate
            qph = (qps / headcount * 3600.0) if headcount else 0.0
            rows.append(
                {
                    "role": name,
                    "label": role.label,
                    "headcount": headcount,
                    "share": share,
                    "rate_weight": role.rate_weight,
                    "qps": qps,
                    "qph_per_client": qph,
                    "hot_set_min": role.hot_set_min,
                    "hot_set_max": role.hot_set_max,
                    "burst_mean": role.burst_mean,
                    "description": role.description,
                }
            )
        return rows

    def queries_per_client_hour(self, target_qps: float) -> float:
        if not self.personas:
            return 0.0
        return target_qps * 3600.0 / len(self.personas)

    @property
    def total_weight(self) -> float:
        return self._total_weight

    @property
    def persona_count(self) -> int:
        return len(self.personas)

    def rate_of(self, persona: Persona, target_qps: float) -> float:
        """That persona's share of the office's total query rate."""
        return target_qps * persona.rate_weight / (self._total_weight or 1.0)
