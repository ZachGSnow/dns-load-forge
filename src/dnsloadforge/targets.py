"""Named targets: where to send the traffic and how to judge what comes back.

A resolver is not just an address.  What counts as a failure depends on what the
resolver is *meant* to do: a family-safe public resolver is not expected to block
ads, a public resolver correctly answers NXDOMAIN for ``corp.local``, and OpenDNS
signals a block by returning an address on its block page rather than NXDOMAIN.
Scoring all of them with one rulebook produces false findings in every direction,
so each target carries its own:

``kind``
    ``appliance`` (default) -- a filter in front of your own network.  Internal
    names such as ``_ldap._tcp.corp.local`` are expected to resolve.
    ``public`` -- a shared cloud resolver.  Internal names are expected to be
    NXDOMAIN, and load above :data:`PUBLIC_QPS_LIMIT` needs an explicit override.
``blocks``
    The categories this target is expected to block.  Traffic for the other block
    categories is still sent (it is realistic) but reported, not judged.
``sinkhole_ips`` / ``sinkhole_cidrs``
    Addresses that mean "blocked" for this target, in addition to ``0.0.0.0``.

Targets live in a ``targets.json`` file; a few well-known public filters are
built in as starting points.  Built-in presets describe published behaviour and
should be checked against the service's current documentation before you rely on
a verdict.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from .spec import CATEGORY_EXPECTED, Category, RunConfig

__all__ = [
    "Target",
    "BUILTIN_TARGETS",
    "BLOCK_CATEGORIES",
    "PUBLIC_QPS_LIMIT",
    "TARGET_KINDS",
    "load_targets",
    "find_target",
    "adhoc_target",
    "public_target_problem",
]

TARGET_KINDS = ("appliance", "public")

#: Above this rate a ``public`` target needs ``--allow-public-target``.  A shared
#: cloud resolver is somebody else's infrastructure.
PUBLIC_QPS_LIMIT = 100.0

BLOCK_CATEGORIES: tuple[str, ...] = tuple(
    category for category, expect in CATEGORY_EXPECTED.items() if expect == "block"
)

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:+()/-]{0,62}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


@dataclass
class Target:
    name: str
    server: str
    port: int = 53
    kind: str = "appliance"
    #: Categories expected to be blocked.  ``None`` means all of them.
    blocks: list[str] | None = None
    sinkhole_ips: list[str] = field(default_factory=list)
    sinkhole_cidrs: list[str] = field(default_factory=list)
    notes: str = ""
    builtin: bool = False

    def __post_init__(self) -> None:
        self.validate()

    # -- validation ---------------------------------------------------------

    def validate(self) -> None:
        if not isinstance(self.name, str) or not _NAME_RE.match(self.name):
            raise ValueError(
                f"invalid target name {self.name!r}: use 1-63 letters, digits, spaces or . _ : + ( ) / -"
            )
        host = str(self.server).strip()
        if not host:
            raise ValueError(f"target {self.name!r} has no server address")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not _HOST_RE.match(host):
                raise ValueError(f"target {self.name!r}: {host!r} is not an IP address or hostname") from None
        self.server = host
        try:
            self.port = int(self.port)
        except (TypeError, ValueError):
            raise ValueError(f"target {self.name!r}: port must be a number") from None
        if not 1 <= self.port <= 65535:
            raise ValueError(f"target {self.name!r}: port {self.port} is out of range")
        if self.kind not in TARGET_KINDS:
            raise ValueError(f"target {self.name!r}: kind must be one of {', '.join(TARGET_KINDS)}")
        if self.blocks is not None:
            unknown = [c for c in self.blocks if c not in BLOCK_CATEGORIES]
            if unknown:
                raise ValueError(
                    f"target {self.name!r}: unknown block categories {unknown}; "
                    f"valid values are {', '.join(BLOCK_CATEGORIES)}"
                )
        for ip in self.sinkhole_ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f"target {self.name!r}: {ip!r} is not an IP address") from None
        for cidr in self.sinkhole_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise ValueError(f"target {self.name!r}: {cidr!r} is not a network") from None

    # -- scoring ------------------------------------------------------------

    def expectations(self) -> dict[str, str]:
        """Per-category overrides: block categories this target is not expected to
        block become ``unknown`` (reported, never judged)."""
        if self.blocks is None:
            return {}
        return {c: "unknown" for c in BLOCK_CATEGORIES if c not in self.blocks}

    @property
    def is_public(self) -> bool:
        return self.kind == "public"

    def apply(self, config: RunConfig) -> RunConfig:
        """A copy of ``config`` aimed at this target and scored by its rules."""
        return replace(
            config,
            server=self.server,
            port=self.port,
            target_name=self.name,
            expectations=self.expectations(),
            sinkhole_cidrs=tuple(self.sinkhole_cidrs),
            sinkhole_ips=tuple(dict.fromkeys([*config.sinkhole_ips, *self.sinkhole_ips])),
            ignore_internal=self.is_public,
        )

    # -- serialisation ------------------------------------------------------

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "server": self.server,
            "port": self.port,
            "kind": self.kind,
            "blocks": list(self.blocks) if self.blocks is not None else list(BLOCK_CATEGORIES),
            "sinkhole_ips": list(self.sinkhole_ips),
            "sinkhole_cidrs": list(self.sinkhole_cidrs),
            "notes": self.notes,
            "builtin": self.builtin,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Target":
        if not isinstance(data, dict):
            raise ValueError("a target must be a JSON object")
        blocks = data.get("blocks")
        if blocks is not None and not isinstance(blocks, list):
            raise ValueError(f"target {data.get('name')!r}: blocks must be a list")
        return cls(
            name=data.get("name", ""),
            server=data.get("server", ""),
            port=data.get("port", 53),
            kind=str(data.get("kind", "appliance")).lower(),
            blocks=list(blocks) if blocks is not None else None,
            sinkhole_ips=[str(x) for x in data.get("sinkhole_ips", [])],
            sinkhole_cidrs=[str(x) for x in data.get("sinkhole_cidrs", [])],
            notes=str(data.get("notes", "")),
        )


# ---------------------------------------------------------------------------
# built-in presets
# ---------------------------------------------------------------------------

#: Well-known public filtering resolvers.  They describe each service's published
#: behaviour at the time of writing; treat them as a starting point.  The OpenDNS
#: block-page network was observed in live answers (``146.112.61.x``).
BUILTIN_TARGETS: tuple[Target, ...] = (
    Target(
        name="OpenDNS FamilyShield",
        server="208.67.222.123",
        kind="public",
        blocks=["block_adult", "block_phishing", "block_malware"],
        sinkhole_cidrs=["146.112.61.0/24"],
        notes="Blocks adult content, phishing and malware by returning a block-page address. Does not block ads.",
        builtin=True,
    ),
    Target(
        name="Cloudflare Security",
        server="1.1.1.2",
        kind="public",
        blocks=["block_malware", "block_phishing"],
        notes="Cloudflare 1.1.1.2 blocks malware and phishing. Answers 0.0.0.0 for blocked names.",
        builtin=True,
    ),
    Target(
        name="Cloudflare Family",
        server="1.1.1.3",
        kind="public",
        blocks=["block_malware", "block_phishing", "block_adult"],
        notes="Cloudflare 1.1.1.3 blocks malware, phishing and adult content.",
        builtin=True,
    ),
    Target(
        name="Quad9",
        server="9.9.9.9",
        kind="public",
        blocks=["block_malware", "block_phishing"],
        notes="Quad9 blocks malicious domains with NXDOMAIN. Does not block ads or adult content.",
        builtin=True,
    ),
    Target(
        name="Google Public DNS (unfiltered baseline)",
        server="8.8.8.8",
        kind="public",
        blocks=[],
        notes="No filtering. Use as a baseline to see what an unfiltered resolver looks like.",
        builtin=True,
    ),
)


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------


def load_targets(path: str | Path | None = None) -> list[Target]:
    """Built-in presets plus any targets in ``path``.

    A target in the file replaces a preset of the same name.  A missing default
    file is not an error; a missing or malformed *explicit* file is, because
    silently ignoring ``--targets mine.json`` would aim the run somewhere else.
    """
    merged: dict[str, Target] = {t.name.lower(): t for t in BUILTIN_TARGETS}

    explicit = path is not None
    file = Path(path) if explicit else Path("targets.json")
    if file.exists():
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read targets file {file}: {exc}") from exc
        entries = data.get("targets") if isinstance(data, dict) else data
        if not isinstance(entries, list):
            raise ValueError(f"{file}: expected a list of targets or an object with a 'targets' list")
        for entry in entries:
            target = Target.from_dict(entry)
            merged[target.name.lower()] = target
    elif explicit:
        raise ValueError(f"targets file not found: {file}")

    return list(merged.values())


def find_target(name: str, targets: list[Target]) -> Target:
    """Look a target up by name, case-insensitively, with a helpful error."""
    wanted = name.strip().lower()
    for target in targets:
        if target.name.lower() == wanted:
            return target
    matches = [t for t in targets if wanted in t.name.lower()]
    if len(matches) == 1:
        return matches[0]
    known = ", ".join(t.name for t in targets)
    raise ValueError(f"unknown target {name!r}; known targets: {known}")


def adhoc_target(server: str, port: int = 53, kind: str = "appliance") -> Target:
    """A target for a bare ``--server`` address, scored with the default rulebook."""
    return Target(name=f"{server}:{port}", server=server, port=port, kind=kind)


def public_target_problem(target: Target, qps: float, allow: bool) -> str:
    """The reason a run against ``target`` should not start, or ``""``."""
    if not target.is_public or allow or qps <= PUBLIC_QPS_LIMIT:
        return ""
    return (
        f"{target.name} ({target.server}) is a public resolver, not your own appliance. Driving it at "
        f"{qps:,.0f} qps is load on a third party's shared infrastructure and tells you little about "
        f"your own filter. Lower --qps to {PUBLIC_QPS_LIMIT:g} or below, rehearse with --mock, or pass "
        f"--allow-public-target if you are authorised to test this service."
    )
