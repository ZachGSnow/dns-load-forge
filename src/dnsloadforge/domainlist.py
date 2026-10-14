"""Fetch, cache and parse the domain lists the traffic mixture is drawn from.

The generator's realism comes from here.  If every one of the 10,000 simulated
workers queried the same hundred domains the tool would measure nothing useful,
so this module assembles nine *categories* of domain -- from a hand-curated
"must not break" list through popular legitimate sites to ad/malware/phishing
blocklists -- and hands the engine a weighted sampler over each one.

Design decisions worth knowing:

* **The network is never required.**  Anything fetched is cached under
  ``lists/cache/`` with a manifest, and the curated lists in ``curated.py`` ship
  in the package.  ``offline=True`` guarantees zero network calls, so the tool
  (and its test suite) runs on an air-gapped box in front of the appliance.
* **A dead source cannot fail a run.**  Every fetch is individually wrapped: a
  retired GitHub list degrades the mixture, it does not crash the test.
* **Popularity is modelled, not ignored.**  Popular domains get Zipf-like
  weights so a real office's traffic shape (a small head carrying most queries)
  is reproduced instead of a uniform sample of a million domains.
* **No third-party dependencies.**  urllib, zipfile, csv and json are enough.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import io
import json
import math
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import curated
from .spec import CATEGORY_EXPECTED, CATEGORY_LABELS, Category

__all__ = [
    "CACHE_TTL_S",
    "USER_AGENT",
    "DomainPool",
    "DomainCatalogue",
    "default_cache_dir",
    "sources_path",
    "load_sources",
    "load_catalogue",
    "fetch_all",
    "parse_payload",
    "decode_download",
    "normalise_domain",
    "is_valid_domain",
    "main",
]

#: How long a cached list is trusted before we refetch it.  A week is a
#: deliberate compromise: blocklists churn daily, but a filter validation run
#: cares more about reproducibility than about having yesterday's phishing
#: domains, and a stable domain set is what makes two runs comparable.
CACHE_TTL_S = 7 * 24 * 3600

USER_AGENT = (
    "DnsLoadForge/0.1 (+DNS filter validation; "
    "https://github.com/ZachGSnow/dns-load-forge; run by a network engineer with permission)"
)

FETCH_TIMEOUT_S = 60.0

#: Label grammar.  Underscores are allowed because SRV records
#: (``_ldap._tcp.corp.local``) are some of the most valuable test cases and some
#: blocklists use them too.  Leading/trailing hyphens are not valid in a hostname.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")

#: Domains that 100% must not silently vanish from the mixture.  Order is the
#: tie-break: the first category listed claims an overlapping domain.  Enterprise
#: outranks the blocklists on purpose -- see ``_resolve_overlaps``.
_OVERLAP_PRECEDENCE: tuple[str, ...] = (
    Category.ENTERPRISE.value,
    Category.BLOCK_MALWARE.value,
    Category.BLOCK_PHISHING.value,
    Category.BLOCK_ADULT.value,
    Category.BLOCK_ADS.value,
    Category.BORDERLINE.value,
    Category.ALLOW_POPULAR.value,
    Category.ALLOW_LONGTAIL.value,
    Category.NXDOMAIN_PROBE.value,
)

_RANK_HEADER_NAMES = frozenset(
    {"domain", "domainname", "domain_name", "domain name", "host", "hostname", "name"}
)


# ---------------------------------------------------------------------------
# logging
# ---------------------------------------------------------------------------


def _log(message: str, *, verbose: bool = True, stream=sys.stderr) -> None:
    """Progress and warnings go to stderr so stdout stays clean for ``--json``."""
    if verbose:
        print(f"[domainlist] {message}", file=stream, flush=True)


# ---------------------------------------------------------------------------
# paths and source table
# ---------------------------------------------------------------------------


def sources_path() -> Path:
    """The bundled ``sources.json`` (next to this module, so it ships with it)."""
    return Path(__file__).with_name("sources.json")


def default_cache_dir() -> Path:
    """Where fetched lists are cached.

    Resolution order: ``$DNSLOADFORGE_CACHE``; ``lists/cache`` inside a source
    checkout, so a checkout (or a USB stick) carries its cache with it; otherwise a
    per-user directory, because a pip-installed package must not write into
    ``site-packages``.
    """
    override = os.environ.get("DNSLOADFORGE_CACHE", "").strip()
    if override:
        return Path(override)
    checkout = Path(__file__).resolve().parent.parent.parent
    if (checkout / "lists").is_dir():
        return checkout / "lists" / "cache"
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "dnsloadforge" / "lists"


def _ensure_cache_dir(cache_dir: str | Path | None) -> Path:
    path = Path(cache_dir) if cache_dir is not None else default_cache_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_sources(path: str | Path | None = None, *, verbose: bool = False) -> list[dict]:
    """Read the source table.  Returns ``[]`` (with a warning) rather than
    raising if it is missing or corrupt: the catalogue still works from curated
    domains plus whatever is cached."""
    source_file = Path(path) if path is not None else sources_path()
    try:
        with source_file.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        _log(f"source table not found at {source_file}; using curated lists only", verbose=verbose)
        return []
    except (OSError, json.JSONDecodeError) as exc:
        _log(f"source table {source_file} unreadable ({exc}); using curated lists only", verbose=verbose)
        return []

    raw = data.get("sources", data if isinstance(data, list) else [])
    sources: list[dict] = []
    for entry in raw:
        if not isinstance(entry, dict) or not entry.get("url") or not entry.get("slug"):
            continue
        category = str(entry.get("category", "")).strip().lower()
        if category not in CATEGORY_EXPECTED:
            _log(f"skipping source {entry.get('slug')!r}: unknown category {category!r}", verbose=verbose)
            continue
        fmt = str(entry.get("format", "auto")).strip().lower()
        sources.append(
            {
                "slug": str(entry["slug"]),
                "category": category,
                "url": str(entry["url"]),
                "format": fmt,
                "tier": str(entry.get("tier", "primary")),
                "ranked": bool(entry.get("ranked", fmt == "rank_csv")),
                "description": str(entry.get("description", "")),
            }
        )
    return sources


# ---------------------------------------------------------------------------
# domain validation
# ---------------------------------------------------------------------------


def normalise_domain(value: str) -> str:
    """Canonical form used everywhere: lower-case, no trailing dot, no wildcard
    prefix, no path, no adblock syntax.  A domain that arrives under two
    spellings must collapse to one name, or it would be counted twice and
    attributed to whichever list happened to be parsed first.

    Strip order matters: the path, the ABP terminator (``^``) and the ABP
    modifier list (``$third-party``) all have to go *before* the ``||`` domain
    anchor, otherwise ``||a.com^$x`` keeps its leading pipes and fails
    validation.
    """
    name = value.strip().strip(",").strip().lower()
    if not name:
        return ""
    # Comment markers are handled at line level, but a stray '#' or '!' reaching
    # this far must not become a "domain": it would pass nothing else, yet an
    # early version returned it verbatim and it then flowed into the pools as a
    # one-character hostname.
    if name[0] in ("#", "!"):
        return ""
    name = name.split("/")[0]
    name = name.split("^")[0]
    name = name.split("$")[0]
    if name.startswith("||"):
        name = name[2:]
    if name.startswith("*."):
        name = name[2:]
    if name.startswith("*"):
        name = name[1:]
    name = name.lstrip(".")
    if name.endswith("."):
        name = name[:-1]
    return name.strip().strip(".")


def _is_ip_token(token: str) -> bool:
    """Used to tell hosts-format lines from plain ones, and to reject IPs that
    some lists emit by mistake (which would otherwise become the 'domain')."""
    if not token:
        return False
    if ":" in token:
        return True
    parts = token.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def is_valid_domain(name: str) -> bool:
    """Strict enough that a stray header, path or IP never enters the mixture."""
    if not name or len(name) > 253:
        return False
    if "." not in name:
        # Single-label names are not resolvable and are usually parser debris.
        return False
    if ":" in name:
        # An IPv6 address, not a name.
        return False
    if _is_ip_token(name):
        return False
    for label in name.split("."):
        if not _LABEL_RE.match(label):
            return False
    # The TLD must not be all digits ("1.2.3.4.5" arrives in some lists).
    if name.rsplit(".", 1)[-1].isdigit():
        return False
    return True


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def decode_download(data: bytes, url: str) -> str:
    """Turn a downloaded payload into text, transparently unwrapping a zip.

    Several of the best popularity lists are published only as ``.csv.zip``
    (Umbrella, Tranco), so the decision is made on the magic bytes rather than
    the file extension -- redirects often hide the extension.
    """
    if data[:4] == b"PK\x03\x04" or url.lower().split("?")[0].endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [
                m
                for m in archive.namelist()
                if not m.endswith("/") and not Path(m).name.startswith(".")
            ]
            if not members:
                raise ValueError(f"zip archive from {url} contains no files")
            # These archives sometimes ship a readme alongside the list, so rank
            # data files (.csv first) above everything else and take the best.
            def score(name: str) -> tuple[int, int]:
                lower = name.lower()
                return (int(lower.endswith((".csv", ".txt"))), int(lower.endswith(".csv")))

            members.sort(key=score, reverse=True)
            payload = archive.read(members[0])
    else:
        payload = data

    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    return payload.decode("utf-8", "replace")


def _strip_inline_comment(line: str) -> str:
    """Drop a trailing ``#`` or ``!`` comment.  Neither character can legally
    appear in a hostname, so this is always safe."""
    for marker in ("#", "!"):
        index = line.find(marker)
        if index != -1:
            line = line[:index]
    return line.strip()


def _parse_lines(text: str, *, abp: bool) -> list[str]:
    """The workhorse for hosts/plain/abp formats.  One pass, deduped, ordered.

    The hosts-vs-plain distinction is handled by looking at the first token: if
    it is an IP address the line is a hosts entry and the rest are domain names,
    otherwise the line is a single domain.  That single rule covers every list
    in ``sources.json`` without needing a per-file decision.
    """
    out: list[str] = []
    seen: set[str] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Comment / section header / URLhaus-style marker line.
        if line[0] in "#![" or line.startswith("//"):
            continue
        # Adblock cosmetic rules (``example.com##.banner``) mention a domain but
        # are not DNS entries.  Skipping them matters because the comment
        # stripper below would otherwise leave a bare domain that we would then
        # happily add to a block list.
        if "##" in line or "#@#" in line or "#?#" in line:
            continue

        line = _strip_inline_comment(line)
        if not line:
            continue

        if abp:
            if line.startswith("||"):
                line = line[2:]
            # Adblock modifiers ($third-party, $script) are not part of the name.
            line = line.split("$", 1)[0].rstrip("^").strip()
            if not line:
                continue
            candidates = [line]
        else:
            tokens = line.split()
            if not tokens:
                continue
            if _is_ip_token(tokens[0]):
                # hosts format: "0.0.0.0 a.example b.example"
                candidates = tokens[1:]
            else:
                candidates = tokens[:1]

        for candidate in candidates:
            name = normalise_domain(candidate)
            if not name or name in seen or not is_valid_domain(name):
                continue
            seen.add(name)
            out.append(name)

    return out


def _parse_rank_csv(text: str) -> list[str]:
    """Popularity lists: ``rank,domain`` (Umbrella, Tranco) and Majestic's
    multi-column CSV with a header row.

    Streamed row by row because these files are a million lines and building a
    list of parsed rows first would cost a few hundred megabytes for no reason.
    """
    out: list[str] = []
    seen: set[str] = set()
    domain_col: int | None = None
    header_checked = False

    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        first = row[0].strip()
        if first.startswith("#"):
            continue

        if not header_checked:
            header_checked = True
            lowered = [c.strip().lower() for c in row]
            if any(cell in _RANK_HEADER_NAMES for cell in lowered):
                for index, cell in enumerate(lowered):
                    if cell in _RANK_HEADER_NAMES:
                        domain_col = index
                        break
                if domain_col is None:
                    domain_col = len(row) - 1
                continue  # consume the header row
            domain_col = len(row) - 1 if len(row) > 1 else 0

        column = domain_col if domain_col is not None else max(len(row) - 1, 0)
        candidate = row[column] if column < len(row) else ""
        name = normalise_domain(candidate)
        if not name or name in seen or not is_valid_domain(name):
            continue
        seen.add(name)
        out.append(name)

    return out


def parse_payload(text: str, fmt: str = "auto") -> list[str]:
    """Parse a list payload into validated, deduplicated, order-preserving
    domains.  ``fmt`` is the ``format`` field from ``sources.json``."""
    normalised = (fmt or "auto").strip().lower()
    if normalised == "rank_csv":
        return _parse_rank_csv(text)
    if normalised in ("hosts", "hostfile", "rpz"):
        return _parse_lines(text, abp=False)
    if normalised in ("abp", "adblock"):
        return _parse_lines(text, abp=True)
    return _parse_lines(text, abp=False)


# ---------------------------------------------------------------------------
# pools and catalogue
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class DomainPool:
    """A weighted bag of domains for one category.

    Sampling is O(log n) via a lazily built cumulative-weight table rather than
    ``random.choices``, which would rebuild that table on every one of the tens
    of thousands of queries per second the engine issues.
    """

    category: str
    domains: list[str] = field(default_factory=list)
    weights: list[float] = field(default_factory=list)
    source: str = ""
    cached: bool = False
    ranked: bool = False
    dropped_overlap: int = 0
    #: Domains re-filed as ``borderline`` because a block-listed name is their
    #: parent.  Surfaced in ``summary()`` so the operator can see how much of the
    #: popularity list sits inside a blocked tree.
    subdomain_conflicts: int = 0
    _cum: list[float] | None = field(default=None, repr=False, compare=False)
    _total: float = field(default=0.0, repr=False, compare=False)

    def __len__(self) -> int:
        return len(self.domains)

    def __bool__(self) -> bool:
        return bool(self.domains)

    def _cumulative(self) -> tuple[list[float], float]:
        if self._cum is None or len(self._cum) != len(self.domains):
            cumulative: list[float] = []
            total = 0.0
            for weight in self.weights:
                total += weight if weight > 0 else 1e-12
                cumulative.append(total)
            self._cum = cumulative
            self._total = total
        return self._cum, self._total

    def sample(self, rng: random.Random) -> str:
        """Weighted random domain.  Deterministic for a seeded ``rng``, which is
        what makes two validation runs comparable."""
        if not self.domains:
            raise ValueError(
                f"domain pool {self.category!r} is empty; run with --refresh while online, "
                f"or check the source list for this category"
            )
        if len(self.domains) == 1:
            return self.domains[0]
        cumulative, total = self._cumulative()
        if total <= 0:
            return self.domains[rng.randrange(len(self.domains))]
        return self.domains[min(bisect.bisect_right(cumulative, rng.random() * total), len(self.domains) - 1)]


@dataclass
class DomainCatalogue:
    """All nine pools plus the lookups the engine and the mock appliance need."""

    pools: dict[str, DomainPool]
    fetched_at: float = 0.0
    offline: bool = False
    _index: dict[str, str] | None = field(default=None, repr=False, compare=False)

    def has(self, category: str) -> bool:
        pool = self.pools.get(category)
        return bool(pool and pool.domains)

    def pool(self, category: str) -> DomainPool:
        if category not in self.pools:
            raise KeyError(f"unknown category {category!r}")
        return self.pools[category]

    def sample(self, category: str, rng: random.Random) -> str:
        return self.pool(category).sample(rng)

    def counts(self) -> dict[str, int]:
        return {c.value: len(self.pools.get(c.value, DomainPool(c.value))) for c in Category}

    def total(self) -> int:
        return sum(self.counts().values())

    def summary(self) -> list[dict]:
        """One row per category, in ``Category`` declaration order -- the order
        the dashboard and console table want to display."""
        rows: list[dict] = []
        for category in Category:
            pool = self.pools.get(category.value, DomainPool(category.value))
            rows.append(
                {
                    "category": category.value,
                    "label": CATEGORY_LABELS[category.value],
                    "source": pool.source or "-",
                    "count": len(pool.domains),
                    "cached": pool.cached,
                    "expect": CATEGORY_EXPECTED[category.value],
                    "ranked": pool.ranked,
                    "overlap_excluded": pool.dropped_overlap,
                    "subdomain_conflicts": pool.subdomain_conflicts,
                }
            )
        return rows

    def domains_for(self, category: str) -> list[str]:
        pool = self.pools.get(category)
        return list(pool.domains) if pool else []

    def blocked_domains(self) -> set[str]:
        """Every domain we expect to be blocked.  Handed to the mock appliance so
        the built-in simulator blocks exactly what the catalogue asserts."""
        blocked: set[str] = set()
        for category in Category:
            if self.is_blocked_category(category.value):
                blocked.update(self.domains_for(category.value))
        return blocked

    def is_blocked_category(self, category: str) -> bool:
        return CATEGORY_EXPECTED.get(category) == "block"

    def _build_index(self) -> dict[str, str]:
        index: dict[str, str] = {}
        for category in _OVERLAP_PRECEDENCE:
            pool = self.pools.get(category)
            if not pool:
                continue
            for domain in pool.domains:
                index.setdefault(domain, category)
        return index

    def category_of(self, qname: str) -> str | None:
        """Reverse lookup.  Falls back to parent domains so ``blog.example.com``
        is attributed to a listed ``example.com`` -- real traffic hits deep
        hostnames far more often than apexes."""
        if not qname:
            return None
        name = normalise_domain(qname)
        if not name:
            return None
        if self._index is None:
            self._index = self._build_index()
        hit = self._index.get(name)
        if hit:
            return hit
        labels = name.split(".")
        for start in range(1, len(labels) - 1):
            hit = self._index.get(".".join(labels[start:]))
            if hit:
                return hit
        return None


@dataclass
class _Entry:
    domain: str
    rank: int
    source_order: int
    source: str


@dataclass
class _PoolBuilder:
    """Accumulates entries from several sources before they are turned into a
    single sliced, weighted ``DomainPool``."""

    category: str
    entries: list[_Entry] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)
    cached: bool = False
    any_network: bool = False

    def add(self, domain: str, *, rank: int, source_order: int, source: str) -> bool:
        if not domain or domain in self.seen:
            return False
        self.seen.add(domain)
        self.entries.append(_Entry(domain, rank, source_order, source))
        return True

    def add_source(self, slug: str, *, cached: bool) -> None:
        if slug not in self.sources:
            self.sources.append(slug)
        if cached:
            self.cached = True
        else:
            self.any_network = True

    def finalize(self, max_n: int | None) -> DomainPool:
        ranked = any(entry.rank >= 0 for entry in self.entries)

        if ranked:
            # Sorting by rank-then-source means the head of the pool contains
            # every source's #1 domain, then every source's #2, and so on, so a
            # small --max-per-category still draws from *all* the popularity
            # lists instead of only whichever was listed first.
            ordered = sorted(
                self.entries,
                key=lambda e: (e.rank if e.rank >= 0 else 1 << 30, e.source_order),
            )
        else:
            ordered = self.entries

        limit = max_n if isinstance(max_n, int) and max_n > 0 else None
        if limit is not None:
            ordered = ordered[:limit]

        domains = [entry.domain for entry in ordered]
        if ranked:
            # Zipf-like decay: the #1 site is queried far more than the #10,000th,
            # which is what makes the generated traffic look like a real office
            # (a small head carrying most of the volume) rather than a uniform
            # sample over a million domains.
            weights = [1.0 / math.sqrt(max(entry.rank, 0) + 1) for entry in ordered]
        else:
            # Blocklists carry no popularity signal, so treat them uniformly.
            weights = [1.0] * len(ordered)

        source = "+".join(self.sources) if self.sources else ""
        if len(source) > 200:
            source = f"{self.sources[0]}+{len(self.sources) - 1} more"

        return DomainPool(
            category=self.category,
            domains=domains,
            weights=weights,
            source=source,
            cached=self.cached and not self.any_network,
            ranked=ranked,
        )


def _resolve_overlaps(pools: dict[str, DomainPool]) -> None:
    """Make each domain belong to exactly one category.

    Real lists overlap heavily -- StevenBlack's unified hosts contains Microsoft
    telemetry names that are also in our curated enterprise list.  Left alone,
    the same hostname would be counted both as "must resolve" and as "must be
    blocked", and *every* appliance would score a failure either way.  The
    first category in ``_OVERLAP_PRECEDENCE`` wins, and the number of names
    pushed out is recorded so the summary can show that the overlap was real.
    """
    owner: dict[str, str] = {}
    for category in _OVERLAP_PRECEDENCE:
        pool = pools.get(category)
        if not pool:
            continue
        for domain in pool.domains:
            owner.setdefault(domain, category)

    for category, pool in pools.items():
        if not pool.domains:
            continue
        kept_domains: list[str] = []
        kept_weights: list[float] = []
        dropped = 0
        for domain, weight in zip(pool.domains, pool.weights):
            if owner.get(domain, category) == category:
                kept_domains.append(domain)
                kept_weights.append(weight)
            else:
                dropped += 1
        if dropped:
            pool.dropped_overlap = dropped
            pool.domains = kept_domains
            pool.weights = kept_weights
            pool._cum = None


#: Categories that give a domain up when its parent is block-listed.
#:
#: ``enterprise`` is deliberately absent.  For a must-resolve name, an appliance
#: blocking its whole tree is the single most valuable finding the tool can
#: produce -- "the list you are using blocks Microsoft sign-in" -- so those names
#: stay allow-listed and are reported, loudly.
_SUBDOMAIN_CONFLICT_CATEGORIES: tuple[str, ...] = (
    Category.ALLOW_POPULAR.value,
    Category.ALLOW_LONGTAIL.value,
)


def _has_blocked_ancestor(domain: str, blocked: set[str]) -> bool:
    """True when a strict ancestor of ``domain`` is block-listed.

    Filters match subdomains -- blocking ``adsrvr.org`` blocks
    ``enduser.adsrvr.org`` -- so a popularity list that ranks an endpoint inside a
    blocked tree describes a query that is *guaranteed* to be blocked.
    """
    parts = domain.split(".")
    for index in range(1, len(parts) - 1):
        if ".".join(parts[index:]) in blocked:
            return True
    return False


def _resolve_subdomain_conflicts(pools: dict[str, DomainPool]) -> None:
    """Re-file popularity-list domains that live inside a block-listed tree.

    Why this exists.  Live measurement against the real lists found 46,342 names
    (2.65% of the popular list, clustered at the head where they dominate the
    volume) that are subdomains of something block-listed -- ``enduser.adsrvr.org``
    under ``adsrvr.org``, ``gcp.gvt2.com`` under a tracker entry.  Exact-name overlap
    resolution does not catch these, because the names differ.

    Left alone, they produced a ~5% false-positive rate *on a filter that had done
    exactly what its own list said*.  That is worse than a missing feature: the
    verdict read ``degraded`` on every run, so the tool could never pass anything,
    and a real finding would have been lost in the noise.

    Dropping them would lose legitimate coverage, so they are moved to
    ``borderline`` instead -- the category that exists precisely for traffic where
    the lists disagree.  They still generate queries and still appear in the
    per-category table, but they are never scored as a failure.  The count is kept
    per pool so the conflict is visible rather than silently smoothed over.
    """
    blocked: set[str] = set()
    for category, pool in pools.items():
        if CATEGORY_EXPECTED.get(category) == "block":
            blocked.update(pool.domains)
    if not blocked:
        return

    grey = pools.setdefault(
        Category.BORDERLINE.value, DomainPool(category=Category.BORDERLINE.value)
    )

    for category in _SUBDOMAIN_CONFLICT_CATEGORIES:
        pool = pools.get(category)
        if not pool or not pool.domains:
            continue
        kept_domains: list[str] = []
        kept_weights: list[float] = []
        moved = 0
        for domain, weight in zip(pool.domains, pool.weights):
            if _has_blocked_ancestor(domain, blocked):
                moved += 1
                grey.domains.append(domain)
                # Borderline is an unweighted pool, so a Zipf weight carried over
                # from a popularity list would silently under-sample these names
                # relative to their new neighbours.  Normalise instead.
                grey.weights.append(1.0)
            else:
                kept_domains.append(domain)
                kept_weights.append(weight)
        if moved:
            pool.subdomain_conflicts = moved
            pool.domains = kept_domains
            pool.weights = kept_weights
            pool._cum = None

    if grey.domains:
        grey._cum = None


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------


def _cache_file(cache_dir: Path, slug: str) -> Path:
    safe = re.sub(r"[^a-z0-9._-]+", "-", slug.lower())
    return cache_dir / f"{safe}.txt"


def _read_manifest(cache_dir: Path) -> dict[str, dict]:
    path = cache_dir / "manifest.json"
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_manifest(cache_dir: Path, manifest: dict[str, dict]) -> None:
    path = cache_dir / "manifest.json"
    # Write-then-rename so a crash mid-write cannot leave a truncated manifest
    # that would make every cached list look unfetched.
    tmp = path.with_name(path.name + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
        tmp.replace(path)
    except OSError as exc:  # pragma: no cover - disk trouble
        _log(f"could not write manifest: {exc}")


def _read_cache_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


def _write_cache_file(path: Path, domains: list[str]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text("\n".join(domains) + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:  # pragma: no cover - disk trouble
        _log(f"could not write cache {path.name}: {exc}")


def fetch_url(
    url: str,
    *,
    etag: str = "",
    last_modified: str = "",
    timeout: float = FETCH_TIMEOUT_S,
) -> tuple[int, bytes, dict]:
    """Conditional GET.  Returns ``(status, body, headers)``; a 304 comes back
    as ``(304, b"", headers)`` rather than an exception so the caller can treat
    it as a cache hit."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    if etag:
        request.add_header("If-None-Match", etag)
    if last_modified:
        request.add_header("If-Modified-Since", last_modified)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (
                getattr(response, "status", 200),
                response.read(),
                {k.lower(): v for k, v in response.headers.items()},
            )
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, b"", {k.lower(): v for k, v in (exc.headers or {}).items()}
        raise


def _obtain(
    source: dict,
    cache_dir: Path,
    manifest: dict[str, dict],
    *,
    refresh: bool,
    offline: bool,
    verbose: bool,
    report: dict | None = None,
) -> tuple[list[str], bool, bool]:
    """Get one source's domains.

    Returns ``(domains, from_cache, manifest_changed)``.  Precedence is: fresh
    cache -> (network) -> stale cache, so an air-gapped run in front of the
    appliance always has domains, and a failed fetch never empties a category
    that previously worked.  When ``report`` is given, the reason for a failed
    fetch is stored under ``report["error"]`` so a UI can show it.
    """
    slug = source["slug"]
    url = source["url"]
    fmt = source["format"]
    cache_file = _cache_file(cache_dir, slug)
    record = manifest.get(slug, {})

    have_cache = cache_file.exists()
    age_s = time.time() - float(record.get("fetched_at", 0.0)) if record.get("fetched_at") else None
    is_fresh = have_cache and age_s is not None and age_s < CACHE_TTL_S

    if is_fresh and not refresh:
        domains = _read_cache_file(cache_file)
        if domains:
            _log(f"{slug}: {len(domains):,} domains from cache ({age_s / 3600:.1f}h old)", verbose=verbose)
            return domains, True, False

    if offline:
        if have_cache:
            domains = _read_cache_file(cache_file)
            if domains:
                _log(f"{slug}: {len(domains):,} domains from stale cache (offline)", verbose=verbose)
                return domains, True, False
        _log(f"{slug}: no cache and offline=True; category may be incomplete", verbose=verbose)
        return [], False, False

    try:
        status, body, headers = fetch_url(
            url,
            etag=str(record.get("etag", "")),
            last_modified=str(record.get("last_modified", "")),
        )
    except Exception as exc:
        if report is not None:
            report["error"] = f"{type(exc).__name__}: {exc}"
        if have_cache:
            domains = _read_cache_file(cache_file)
            if domains:
                _log(f"{slug}: fetch failed ({exc}); using cached copy", verbose=verbose)
                return domains, True, False
        _log(f"{slug}: fetch failed and no cache available ({exc})", verbose=verbose)
        return [], False, False

    if status == 304 and have_cache:
        domains = _read_cache_file(cache_file)
        _log(f"{slug}: not modified, {len(domains):,} domains from cache", verbose=verbose)
        manifest[slug] = {**record, "fetched_at": time.time(), "category": source["category"]}
        return domains, True, True

    try:
        text = decode_download(body, url)
        domains = parse_payload(text, fmt)
    except Exception as exc:
        _log(f"{slug}: could not parse payload ({exc})", verbose=verbose)
        if report is not None:
            report["error"] = f"could not parse payload: {exc}"
        domains = []

    if not domains:
        if report is not None and not report.get("error"):
            report["error"] = "the download contained no usable domains"
        if have_cache:
            fallback = _read_cache_file(cache_file)
            if fallback:
                _log(f"{slug}: parsed 0 domains; keeping cached copy", verbose=verbose)
                return fallback, True, False
        return [], False, False

    _write_cache_file(cache_file, domains)
    manifest[slug] = {
        "url": url,
        "category": source["category"],
        "format": fmt,
        "fetched_at": time.time(),
        "count": len(domains),
        "etag": headers.get("etag", ""),
        "last_modified": headers.get("last-modified", ""),
    }
    _log(f"{slug}: fetched {len(domains):,} domains", verbose=verbose)
    return domains, False, True


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------


def load_catalogue(
    cache_dir: str | Path | None = None,
    *,
    refresh: bool = False,
    offline: bool = False,
    max_per_category: int | None = None,
    only: list[str] | None = None,
    verbose: bool = False,
) -> DomainCatalogue:
    """Assemble the full domain catalogue.

    ``only`` filters which *fetched* sources are considered, matching either a
    category value (``block_ads``) or a source slug (``urlhaus``).  The curated
    enterprise and borderline lists are always included regardless of ``only``:
    they are tiny, they never touch the network, and without them an offline run
    would have nothing worth testing.
    """
    directory = _ensure_cache_dir(cache_dir)
    manifest = _read_manifest(directory)
    manifest_changed = False

    builders: dict[str, _PoolBuilder] = {c.value: _PoolBuilder(category=c.value) for c in Category}

    for category, domains in curated.CURATED_BY_CATEGORY.items():
        builder = builders[category]
        for domain in domains:
            builder.add(normalise_domain(domain), rank=-1, source_order=-1, source=curated.CURATED_SOURCE)
        builder.add_source(curated.CURATED_SOURCE, cached=True)

    only_set = {str(item).strip().lower() for item in only} if only else None
    sources = load_sources(verbose=verbose)
    disabled = read_disabled_sources(directory)

    for order, source in enumerate(sources):
        if source["slug"] in disabled:
            _log(f"{source['slug']}: disabled, skipping", verbose=verbose)
            continue
        if only_set is not None:
            if source["slug"].lower() not in only_set and source["category"].lower() not in only_set:
                continue
        domains, from_cache, changed = _obtain(
            source, directory, manifest, refresh=refresh, offline=offline, verbose=verbose
        )
        manifest_changed = manifest_changed or changed
        builder = builders[source["category"]]
        builder.add_source(source["slug"], cached=from_cache)
        if not domains:
            continue
        ranked = bool(source.get("ranked"))
        for rank, domain in enumerate(domains):
            builder.add(domain, rank=rank if ranked else -1, source_order=order, source=source["slug"])

    if manifest_changed:
        _write_manifest(directory, manifest)

    pools = {category.value: builders[category.value].finalize(max_per_category) for category in Category}
    _resolve_overlaps(pools)
    _resolve_subdomain_conflicts(pools)

    catalogue = DomainCatalogue(pools=pools, fetched_at=time.time(), offline=offline)

    total = catalogue.total()
    if verbose:
        _log(f"catalogue ready: {total:,} domains across {len(Category)} categories", verbose=verbose)
        for category in Category:
            pool = pools[category.value]
            if not pool.domains:
                _log(f"  {category.value:16s} empty (expected for nxdomain_probe, or refresh while online)")
    return catalogue


def fetch_all(
    cache_dir: str | Path | None = None,
    *,
    force: bool = False,
    verbose: bool = False,
) -> list[dict]:
    """Warm the cache for every source and return the manifest rows.

    This is the "do this once on a connected machine before you drive to the
    client site" entry point.  ``force=False`` still fetches anything missing or
    older than :data:`CACHE_TTL_S`, which is what you want on a laptop that has
    been off the network for a while; ``force=True`` refetches everything
    regardless of age.
    """
    directory = _ensure_cache_dir(cache_dir)
    load_catalogue(directory, refresh=force, offline=False, verbose=verbose)
    manifest = _read_manifest(directory)
    rows: list[dict] = []
    for source in load_sources(verbose=verbose):
        record = manifest.get(source["slug"], {})
        rows.append(
            {
                "slug": source["slug"],
                "category": source["category"],
                "tier": source["tier"],
                "count": int(record.get("count", 0)),
                "fetched_at": float(record.get("fetched_at", 0.0)),
                "cached": bool(record),
                "url": source["url"],
            }
        )
    return rows


# ---------------------------------------------------------------------------
# source management (used by the dashboard)
# ---------------------------------------------------------------------------


def _disabled_file(cache_dir: Path) -> Path:
    return cache_dir / "disabled.json"


def read_disabled_sources(cache_dir: str | Path | None = None) -> set[str]:
    """Slugs the operator has switched off.  Stored beside the cache so the choice
    travels with it and ``sources.json`` stays a read-only, shippable file."""
    directory = Path(cache_dir) if cache_dir is not None else default_cache_dir()
    try:
        data = json.loads(_disabled_file(directory).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {str(item) for item in data} if isinstance(data, list) else set()


def set_source_enabled(slug: str, enabled: bool, cache_dir: str | Path | None = None) -> None:
    """Turn a source on or off.  Raises ``KeyError`` for an unknown slug."""
    if slug not in {s["slug"] for s in load_sources()}:
        raise KeyError(slug)
    directory = _ensure_cache_dir(cache_dir)
    disabled = read_disabled_sources(directory)
    if enabled:
        disabled.discard(slug)
    else:
        disabled.add(slug)
    tmp = _disabled_file(directory).with_suffix(".tmp")
    tmp.write_text(json.dumps(sorted(disabled)), encoding="utf-8")
    tmp.replace(_disabled_file(directory))


def source_inventory(cache_dir: str | Path | None = None) -> list[dict]:
    """One row per configured source: what it is, whether it is on, and how fresh
    the cached copy is."""
    directory = _ensure_cache_dir(cache_dir)
    manifest = _read_manifest(directory)
    disabled = read_disabled_sources(directory)
    now = time.time()
    rows = []
    for source in load_sources():
        record = manifest.get(source["slug"], {})
        fetched_at = float(record.get("fetched_at", 0.0) or 0.0)
        rows.append(
            {
                "slug": source["slug"],
                "category": source["category"],
                "tier": source["tier"],
                "url": source["url"],
                "description": source["description"],
                "enabled": source["slug"] not in disabled,
                "cached": _cache_file(directory, source["slug"]).exists(),
                "count": int(record.get("count", 0) or 0),
                "fetched_at": fetched_at,
                "age_s": (now - fetched_at) if fetched_at else None,
                "stale": bool(fetched_at) and (now - fetched_at) > CACHE_TTL_S,
            }
        )
    return rows


def refresh_source(slug: str, cache_dir: str | Path | None = None) -> dict:
    """Fetch one source now, ignoring cache age.

    Returns ``{"slug", "status", "count", "error"}`` where status is ``updated``,
    ``unchanged`` (the server said not modified) or ``failed`` (the cached copy, if
    any, was kept).  Never raises for a network problem: one dead list must not stop
    the others refreshing.
    """
    sources = {s["slug"]: s for s in load_sources()}
    if slug not in sources:
        raise KeyError(slug)
    directory = _ensure_cache_dir(cache_dir)
    manifest = _read_manifest(directory)
    report: dict = {}
    domains, from_cache, changed = _obtain(
        sources[slug], directory, manifest, refresh=True, offline=False, verbose=False, report=report
    )
    if changed:
        _write_manifest(directory, manifest)
    # _obtain returns (changed, from_cache) = (True, True) only for a 304 Not Modified.
    # Comparing fetched_at before/after instead is unreliable: on Windows the clock can
    # tick every ~15 ms, so both readings may be equal.
    if changed and not from_cache:
        status = "updated"
    elif changed:
        status = "unchanged"
    else:
        status = "failed"
    return {
        "slug": slug,
        "status": status,
        "count": len(domains),
        "error": report.get("error", "") if status == "failed" else "",
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dnsloadforge.domainlist",
        description="Fetch, cache and inspect the domain lists DNS Load Forge draws traffic from.",
    )
    parser.add_argument("--cache-dir", default="", help="where lists are cached (default: DnsLoadForge/lists/cache)")
    parser.add_argument("--refresh", action="store_true", help="ignore cache age and refetch every source")
    parser.add_argument("--offline", action="store_true", help="never touch the network; use cache + curated only")
    parser.add_argument("--max-per-category", type=int, default=0, help="cap domains kept per category (0 = no cap)")
    parser.add_argument("--only", action="append", default=None, help="limit to a category or source slug (repeatable)")
    parser.add_argument("--summary", action="store_true", help="print a per-category summary table")
    parser.add_argument("--json", action="store_true", help="emit the summary as JSON on stdout")
    parser.add_argument("--quiet", action="store_true", help="suppress progress output")
    args = parser.parse_args(argv)

    cache_dir = args.cache_dir or None
    verbose = not args.quiet

    # --refresh is meaningless with --offline; make that explicit rather than
    # silently doing neither.
    if args.refresh and args.offline:
        parser.error("--refresh and --offline are mutually exclusive")

    if args.only and args.only[0].strip().lower() == "all":
        args.only = None

    catalogue = load_catalogue(
        cache_dir,
        refresh=args.refresh,
        offline=args.offline,
        max_per_category=args.max_per_category or None,
        only=args.only,
        verbose=verbose,
    )

    rows = catalogue.summary()
    if args.json:
        json.dump(
            {
                "cache_dir": str(Path(cache_dir) if cache_dir else default_cache_dir()),
                "total": catalogue.total(),
                "offline": catalogue.offline,
                "categories": rows,
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    elif args.summary:
        width = max(len(row["label"]) for row in rows)
        print(f"\nDomain catalogue  (total {catalogue.total():,} domains)")
        print("-" * 100)
        print(f"{'category':<17} {'label':<{width}}  {'domains':>10}  {'expect':<8} source")
        print("-" * 100)
        for row in rows:
            flag = "" if row["count"] else "   <- empty"
            overlap = f"  (-{row['overlap_excluded']} overlap)" if row["overlap_excluded"] else ""
            print(
                f"{row['category']:<17} {row['label']:<{width}}  {row['count']:>10,}  "
                f"{row['expect']:<8} {row['source']}{overlap}{flag}"
            )
        print("-" * 100)
    else:
        print(f"{catalogue.total():,} domains loaded (add --summary for the per-category breakdown)")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via CLI
    raise SystemExit(main())
