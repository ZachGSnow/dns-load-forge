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
``transport``
    ``udp`` (default), ``tcp``, ``tls`` (DNS over TLS) or ``https`` (DNS over
    HTTPS), with ``tls_name`` (the certificate's name, when ``server`` is an
    address) and ``doh_path``.  ``"url": "https://dns.example/dns-query"`` sets
    all three at once.  ``ca_file`` trusts an appliance's own CA.

Targets live in a ``targets.json`` file; a few well-known public filters are
built in as starting points, over plain DNS and encrypted.  Built-in presets
describe published behaviour and should be checked against the service's current
documentation before you rely on a verdict.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from .spec import CATEGORY_EXPECTED, DEFAULT_PORTS, TRANSPORT_LABELS, TRANSPORTS, Category, RunConfig, endpoint_label
from .transports import is_loopback, parse_doh_url

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
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")


@dataclass
class Target:
    name: str
    server: str
    #: ``None`` means the transport's usual port: 53, 853 for DoT, 443 for DoH.
    port: int | None = None
    kind: str = "appliance"
    #: Categories expected to be blocked.  ``None`` means all of them.
    blocks: list[str] | None = None
    sinkhole_ips: list[str] = field(default_factory=list)
    sinkhole_cidrs: list[str] = field(default_factory=list)
    notes: str = ""
    builtin: bool = False
    #: How the traffic travels: one of :data:`~dnsloadforge.spec.TRANSPORTS`.
    transport: str = "udp"
    #: The certificate's name for DoT and DoH when ``server`` is an address.
    tls_name: str = ""
    doh_path: str = "/dns-query"
    #: A PEM bundle of the CAs to trust for this target's certificate.
    ca_file: str = ""

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
        self.transport = str(self.transport).strip().lower()
        if self.transport not in TRANSPORTS:
            raise ValueError(f"target {self.name!r}: transport must be one of {', '.join(TRANSPORTS)}")
        try:
            self.port = DEFAULT_PORTS[self.transport] if self.port is None else int(self.port)
        except (TypeError, ValueError):
            raise ValueError(f"target {self.name!r}: port must be a number") from None
        if not 1 <= self.port <= 65535:
            raise ValueError(f"target {self.name!r}: port {self.port} is out of range")
        if self.transport == "http" and not is_loopback(host):
            raise ValueError(
                f"target {self.name!r}: DNS over plain HTTP is for rehearsing on this machine only; use https"
            )
        self.tls_name = str(self.tls_name).strip().lower()
        if self.tls_name and not _HOST_RE.match(self.tls_name):
            raise ValueError(f"target {self.name!r}: tls_name {self.tls_name!r} is not a hostname")
        if not _PATH_RE.match(self.doh_path):
            raise ValueError(f"target {self.name!r}: doh_path {self.doh_path!r} must be a path such as /dns-query")
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

    @property
    def endpoint(self) -> str:
        """Where the traffic goes, as reports show it (``tls://dns.quad9.net:853 (9.9.9.9)``)."""
        return endpoint_label(self.transport, self.server, self.port, self.tls_name, self.doh_path)

    def apply(self, config: RunConfig) -> RunConfig:
        """A copy of ``config`` aimed at this target and scored by its rules.  How
        hard to check certificates and how many connections to open stay the
        run's; a target's own CA file wins over the run's."""
        return replace(
            config,
            server=self.server,
            port=self.port,
            transport=self.transport,
            tls_name=self.tls_name,
            doh_path=self.doh_path,
            ca_file=self.ca_file or config.ca_file,
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
            "transport": self.transport,
            "transport_label": TRANSPORT_LABELS[self.transport],
            "tls_name": self.tls_name,
            "doh_path": self.doh_path,
            "ca_file": self.ca_file,
            "endpoint": self.endpoint,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Target":
        if not isinstance(data, dict):
            raise ValueError("a target must be a JSON object")
        name = data.get("name", "")
        blocks = data.get("blocks")
        if blocks is not None and not isinstance(blocks, list):
            raise ValueError(f"target {name!r}: blocks must be a list")
        transport = str(data.get("transport", "udp")).lower()
        server = data.get("server", "")
        port = data.get("port")
        tls_name = str(data.get("tls_name", ""))
        doh_path = str(data.get("doh_path", "/dns-query"))
        if data.get("url"):
            # "url" is the DoH endpoint as services publish it; "server" may still
            # name the address to connect to, so the lookup of the host is not
            # left to the filter being tested.
            try:
                transport, host, url_port, doh_path = parse_doh_url(str(data["url"]))
            except ValueError as exc:
                raise ValueError(f"target {name!r}: {exc}") from None
            server = server or host
            port = url_port if port is None else port
            if transport == "https" and not tls_name:
                tls_name = host
        return cls(
            name=name,
            server=server,
            port=port,
            kind=str(data.get("kind", "appliance")).lower(),
            blocks=list(blocks) if blocks is not None else None,
            sinkhole_ips=[str(x) for x in data.get("sinkhole_ips", [])],
            sinkhole_cidrs=[str(x) for x in data.get("sinkhole_cidrs", [])],
            notes=str(data.get("notes", "")),
            transport=transport,
            tls_name=tls_name,
            doh_path=doh_path,
            ca_file=str(data.get("ca_file", "")),
        )


# ---------------------------------------------------------------------------
# built-in presets
# ---------------------------------------------------------------------------

#: Well-known public filtering resolvers.  They describe each service's published
#: behaviour at the time of writing; treat them as a starting point.  The OpenDNS
#: block-page network was observed in live answers (``146.112.61.x``).
#:
#: The encrypted presets connect to the resolver's address and check the
#: certificate's name, so finding the server never depends on the DNS being
#: tested; each one answered over HTTP/1.1 or TLS on 2026-11-26.  Quad9's DoH needs
#: HTTP/2, which is why Quad9 is offered over DoT only.
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
        name="OpenDNS FamilyShield over DoH",
        server="208.67.222.123",
        transport="https",
        tls_name="doh.familyshield.opendns.com",
        kind="public",
        blocks=["block_adult", "block_phishing", "block_malware"],
        sinkhole_cidrs=["146.112.61.0/24"],
        notes="FamilyShield over DNS over HTTPS (doh.familyshield.opendns.com). Compare it with the plain "
        "FamilyShield target to see whether encrypted DNS is filtered the same way.",
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
        name="Cloudflare Family over DoT",
        server="1.1.1.3",
        transport="tls",
        tls_name="family.cloudflare-dns.com",
        kind="public",
        blocks=["block_malware", "block_phishing", "block_adult"],
        notes="Cloudflare 1.1.1.3 over DNS over TLS, as Android's Private DNS uses it.",
        builtin=True,
    ),
    Target(
        name="Cloudflare Family over DoH",
        server="1.1.1.3",
        transport="https",
        tls_name="family.cloudflare-dns.com",
        kind="public",
        blocks=["block_malware", "block_phishing", "block_adult"],
        notes="Cloudflare 1.1.1.3 over DNS over HTTPS, as a browser uses it "
        "(https://family.cloudflare-dns.com/dns-query).",
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
        name="Quad9 over DoT",
        server="9.9.9.9",
        transport="tls",
        tls_name="dns.quad9.net",
        kind="public",
        blocks=["block_malware", "block_phishing"],
        notes="Quad9 over DNS over TLS. Its DNS over HTTPS needs HTTP/2, which this tool does not speak.",
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
    Target(
        name="Google Public DNS over DoH (unfiltered)",
        server="8.8.8.8",
        transport="https",
        tls_name="dns.google",
        kind="public",
        blocks=[],
        notes="No filtering, over DNS over HTTPS (https://dns.google/dns-query): the latency baseline for "
        "encrypted DNS.",
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
    """Look a target up by name, case-insensitively, with a helpful error.

    A part of a name will do when it fits one target (``quad9 dot``: every word
    in the name).  When it fits a service and its encrypted variants
    (``familyshield``), it means the plain one, as it did before there were any.
    """
    wanted = name.strip().lower()
    for target in targets:
        if target.name.lower() == wanted:
            return target
    words = wanted.split()
    matches = [t for t in targets if wanted in t.name.lower()] or [
        t for t in targets if words and all(word in t.name.lower() for word in words)
    ]
    if len(matches) == 1:
        return matches[0]
    plain = [t for t in matches if t.transport == "udp"]
    if len(plain) == 1:
        return plain[0]
    if matches:
        raise ValueError(f"{name!r} fits several targets: {', '.join(t.name for t in matches)}")
    known = ", ".join(t.name for t in targets)
    raise ValueError(f"unknown target {name!r}; known targets: {known}")


_SHORT_TRANSPORT = {"tcp": "TCP", "tls": "DoT", "https": "DoH", "http": "DoH"}


def adhoc_target(
    server: str,
    port: int | None = None,
    kind: str = "appliance",
    *,
    transport: str = "udp",
    tls_name: str = "",
    doh_path: str = "/dns-query",
) -> Target:
    """A target for a bare ``--server`` address, scored with the default rulebook."""
    port = DEFAULT_PORTS.get(transport, 53) if port is None else port
    name = f"{server}:{port}"
    if transport in _SHORT_TRANSPORT:
        name = f"{tls_name or server}:{port} {_SHORT_TRANSPORT[transport]}"
    return Target(
        name=name[:63], server=server, port=port, kind=kind, transport=transport, tls_name=tls_name, doh_path=doh_path
    )


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
