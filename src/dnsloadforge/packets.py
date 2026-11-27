"""Minimal DNS wire-format encoder/decoder.

Hand-rolled on purpose.  ``dnspython`` would be a fine dependency for a normal
application, but this package has to run on a freshly imaged Windows box with
nothing installed, and we only need: build a query, and read a response's rcode,
its addresses (A, AAAA and the hints in HTTPS/SVCB records) and the EDNS options
that say how and where it was answered (Extended DNS Errors, NSID).  That is a few
hundred lines of struct packing, so we do it here and keep the tool dependency-free.

Everything in here is pure and synchronous, which is what makes it testable
against known-good byte vectors.
"""

from __future__ import annotations

import ipaddress
import random
import struct
from dataclasses import dataclass, field
from typing import Sequence

from .spec import QTYPES, QTYPE_NAMES, RCODES

__all__ = [
    "DNSError",
    "DNSAnswer",
    "DNSMessage",
    "RR",
    "EDE_NAMES",
    "EDE_POLICY_CODES",
    "EDNS_EDE",
    "EDNS_NSID",
    "ede_label",
    "ede_option",
    "encode_query",
    "encode_response",
    "decode_message",
    "normalise_qname",
    "random_query_id",
    "svcb_rdata",
]

#: 12-byte fixed header: ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
_HEADER = struct.Struct("!HHHHHH")
_HEADER_LEN = _HEADER.size

_FLAG_QR = 0x8000
_FLAG_AA = 0x0400
_FLAG_TC = 0x0200
_FLAG_RD = 0x0100
_FLAG_RA = 0x0080
_FLAG_AD = 0x0020

#: Query classes: IN for everything, CH for the server-identity names
#: (``id.server``, ``hostname.bind``) that a resolver answers about itself.
QCLASS_IN = 1
QCLASS_CH = 3

_TYPE_OPT = 41
_TYPE_A = 1
_TYPE_AAAA = 28
_TYPE_CNAME = 5
_TYPE_SVCB = 64
_TYPE_HTTPS = 65

#: EDNS option codes this tool sends or reads.
EDNS_NSID = 3  # RFC 5001: which server instance answered
EDNS_EDE = 15  # RFC 8914: Extended DNS Errors

#: SVCB/HTTPS parameter keys that carry addresses (RFC 9460).
_SVC_IPV4HINT = 4
_SVC_IPV6HINT = 6

#: Extended DNS Error codes that mean a *policy* chose this answer, rather than a
#: resolution failure: 4 Forged Answer, 15 Blocked, 16 Censored, 17 Filtered,
#: 18 Prohibited.  Filters do not agree on which one a block gets (observed live:
#: Cloudflare 1.1.1.2 sends 16, Quad9 and AdGuard 17, DNS4EU 15), so all five count.
EDE_POLICY_CODES: frozenset[int] = frozenset({4, 15, 16, 17, 18})

#: Names from the RFC 8914 registry, for reports.  Anything else shows as its number.
EDE_NAMES: dict[int, str] = {
    0: "Other",
    1: "Unsupported DNSKEY Algorithm",
    2: "Unsupported DS Digest Type",
    3: "Stale Answer",
    4: "Forged Answer",
    5: "DNSSEC Indeterminate",
    6: "DNSSEC Bogus",
    7: "Signature Expired",
    8: "Signature Not Yet Valid",
    9: "DNSKEY Missing",
    10: "RRSIGs Missing",
    11: "No Zone Key Bit Set",
    12: "NSEC Missing",
    13: "Cached Error",
    14: "Not Ready",
    15: "Blocked",
    16: "Censored",
    17: "Filtered",
    18: "Prohibited",
    19: "Stale NXDOMAIN Answer",
    20: "Not Authoritative",
    21: "Not Supported",
    22: "No Reachable Authority",
    23: "Network Error",
    24: "Invalid Data",
}


def ede_label(code: int) -> str:
    return f"{code} {EDE_NAMES.get(code, 'EDE')}"

_MAX_NAME_LEN = 255
_MAX_LABEL_LEN = 63
_MAX_POINTER_HOPS = 32


class DNSError(ValueError):
    """Raised for malformed or unencodable DNS data."""


def normalise_qname(qname: str) -> str:
    """Lower-case, strip a single trailing dot, and reject anything that cannot
    go on the wire.  DNS names are case-insensitive, and lower-casing here means
    the stats aggregator does not have to."""
    name = qname.strip()
    if name.endswith("."):
        name = name[:-1]
    name = name.lower()
    if not name:
        raise DNSError("empty qname")
    if len(name) > _MAX_NAME_LEN:
        raise DNSError(f"qname too long ({len(name)} > {_MAX_NAME_LEN}): {name!r}")
    for label in name.split("."):
        if not label:
            raise DNSError(f"empty label in qname: {qname!r}")
        if len(label) > _MAX_LABEL_LEN:
            raise DNSError(f"label too long in qname: {qname!r}")
    return name


def random_query_id(rng: random.Random | None = None) -> int:
    if rng is not None:
        return rng.randrange(1, 0x10000)
    return random.randrange(1, 0x10000)


def _encode_name(qname: str) -> bytes:
    """Encode a dotted name into length-prefixed labels plus the root label."""
    out = bytearray()
    for label in qname.split("."):
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def encode_query(
    qname: str,
    qtype: str = "A",
    qid: int | None = None,
    *,
    rd: bool = True,
    edns: bool = True,
    udp_size: int = 1232,
    dnssec_ok: bool = False,
    options: Sequence[tuple[int, bytes]] = (),
    qclass: int = QCLASS_IN,
) -> tuple[bytes, int]:
    """Build a DNS query.  Returns ``(packet, query_id)``.

    EDNS0 (an OPT record in the additional section) is on by default: every real
    stub resolver sends it, and its advertised UDP size is what stops a filtering
    appliance from truncating large answers.  Testing without it exercises a code
    path no real client uses, which is not the traffic we want to generate.  It is
    also what lets a filter answer with an Extended DNS Error.

    ``options`` are EDNS options as ``(code, data)``; ``(EDNS_NSID, b"")`` asks the
    server to say which instance answered.
    """
    try:
        qnum = QTYPES[qtype.upper()] if isinstance(qtype, str) else int(qtype)
    except KeyError:
        raise DNSError(f"unsupported qtype: {qtype!r}") from None

    name = normalise_qname(qname)
    if qid is None:
        qid = random_query_id()
    qid &= 0xFFFF

    flags = _FLAG_RD if rd else 0
    arcount = 1 if edns else 0
    packet = bytearray(_HEADER.pack(qid, flags, 1, 0, 0, arcount))
    packet += _encode_name(name)
    packet += struct.pack("!HH", qnum, qclass)  # QTYPE, QCLASS

    if edns:
        # OPT: NAME(root) TYPE(41) CLASS(udp payload size) TTL(ext-rcode/ver/flags)
        #      RDLENGTH, then the options.  The DO bit is the top bit of the TTL field.
        ttl = 0x8000 if dnssec_ok else 0
        rdata = _encode_options(options)
        packet += struct.pack("!BHHIH", 0, _TYPE_OPT, udp_size, ttl, len(rdata)) + rdata

    return bytes(packet), qid


def _encode_options(options: Sequence[tuple[int, bytes]]) -> bytes:
    return b"".join(struct.pack("!HH", code, len(data)) + bytes(data) for code, data in options)


def txt_parts(rdata: bytes) -> list[str]:
    """A TXT record's character-strings (RFC 1035 3.3.14)."""
    parts: list[str] = []
    pos = 0
    while pos < len(rdata):
        length = rdata[pos]
        parts.append(rdata[pos + 1 : pos + 1 + length].decode("utf-8", "replace"))
        pos += 1 + length
    return parts


def ede_option(code: int, text: str = "") -> tuple[int, bytes]:
    """An Extended DNS Error option, for responders (the mock) and tests."""
    return EDNS_EDE, struct.pack("!H", code) + text.encode("utf-8")


def svcb_rdata(
    priority: int,
    target: str = ".",
    *,
    alpn: Sequence[str] = (),
    ipv4hint: Sequence[str] = (),
    ipv6hint: Sequence[str] = (),
) -> bytes:
    """SVCB/HTTPS RDATA (RFC 9460), for responders and tests.  Keys are written in
    ascending order, as the RFC requires."""
    out = bytearray(struct.pack("!H", priority))
    out += b"\x00" if target in (".", "") else _encode_name(normalise_qname(target))
    params: list[tuple[int, bytes]] = []
    if alpn:
        params.append((1, b"".join(bytes([len(p)]) + p.encode("ascii") for p in alpn)))
    if ipv4hint:
        params.append((_SVC_IPV4HINT, b"".join(ipaddress.IPv4Address(ip).packed for ip in ipv4hint)))
    if ipv6hint:
        params.append((_SVC_IPV6HINT, b"".join(ipaddress.IPv6Address(ip).packed for ip in ipv6hint)))
    for key, value in params:
        out += struct.pack("!HH", key, len(value)) + value
    return bytes(out)


@dataclass(slots=True)
class DNSAnswer:
    name: str
    rtype: int
    rtype_name: str
    ttl: int
    rdata: bytes
    rclass: int = 1
    ip: str = ""
    #: SVCB/HTTPS only: priority (0 is AliasMode), target name, and the addresses
    #: carried in ipv4hint/ipv6hint.
    svc_priority: int = 0
    svc_target: str = ""
    hints: tuple[str, ...] = ()
    svc_alpn: tuple[str, ...] = ()
    svc_port: int = 0

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.name} {self.rtype_name} {self.ip or self.rdata.hex()}"


@dataclass(slots=True)
class DNSMessage:
    """A decoded DNS message.  Only the parts a traffic generator cares about
    are populated: rcode, flags, the answer section, and the OPT record if any."""

    qid: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    qname: str = ""
    qtype: int = 0
    rcode: int = 0
    answers: list[DNSAnswer] = field(default_factory=list)
    authorities: list[DNSAnswer] = field(default_factory=list)
    additional: list[DNSAnswer] = field(default_factory=list)
    truncated: bool = False
    edns_udp_size: int = 0
    raw_len: int = 0
    #: Extended DNS Errors as (info code, extra text), in the order they came.
    ede: list[tuple[int, str]] = field(default_factory=list)
    #: The server's NSID, when it sent one (RFC 5001).
    nsid: bytes = b""
    #: Every EDNS option code present, so a responder can tell that NSID was asked for.
    edns_options: list[int] = field(default_factory=list)

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode & 0x0F, f"RCODE{self.rcode}")

    @property
    def policy_ede(self) -> int | None:
        """The first Extended DNS Error that says a policy chose this answer."""
        for code, _text in self.ede:
            if code in EDE_POLICY_CODES:
                return code
        return None

    @property
    def nsid_text(self) -> str:
        """NSID as text when it is printable ASCII (it usually is), else hex."""
        if not self.nsid:
            return ""
        if all(32 <= b < 127 for b in self.nsid):
            return self.nsid.decode("ascii")
        return self.nsid.hex()

    @property
    def hint_ips(self) -> list[str]:
        """Addresses carried in SVCB/HTTPS ipv4hint and ipv6hint parameters.

        A browser can connect to these without ever asking for A or AAAA, so a filter
        that blocks the address lookups but answers HTTPS with real hints is still
        letting the connection through.
        """
        return [ip for a in self.answers if a.rtype in (_TYPE_SVCB, _TYPE_HTTPS) for ip in a.hints]

    @property
    def is_response(self) -> bool:
        return bool(self.flags & _FLAG_QR)

    @property
    def recursive_available(self) -> bool:
        return bool(self.flags & _FLAG_RA)

    @property
    def authenticated(self) -> bool:
        """The AD flag: the resolver validated the answer with DNSSEC."""
        return bool(self.flags & _FLAG_AD)

    @property
    def txt(self) -> list[str]:
        """Every TXT record in the answer section, each record's strings joined."""
        return ["".join(parts) for parts in self.txt_records]

    @property
    def txt_records(self) -> list[list[str]]:
        """Every TXT record as its separate strings: identity services answer with
        key/value pairs such as ``"ns" "192.0.2.53"``."""
        return [txt_parts(a.rdata) for a in self.answers if a.rtype == QTYPES["TXT"]]

    @property
    def answer_ips(self) -> list[str]:
        """Only real address records.  A CNAME target is a name, not an
        address, and must not be mistaken for one when we decide whether a
        domain was sinkholed."""
        return [a.ip for a in self.answers if a.rtype in (_TYPE_A, _TYPE_AAAA) and a.ip]

    @property
    def cname_targets(self) -> list[str]:
        return [a.ip for a in self.answers if a.rtype == _TYPE_CNAME and a.ip]

    @property
    def answer_names(self) -> list[str]:
        return [a.name for a in self.answers if a.rtype == _TYPE_CNAME]


@dataclass(frozen=True, slots=True)
class RR:
    """A resource record to emit.  ``value`` is interpreted per ``qtype``:
    an IPv4/IPv6 string for A/AAAA, a domain name for CNAME/NS/PTR, free text for
    TXT, and raw bytes for anything else."""

    name: str
    qtype: str
    ttl: int
    value: object


def _encode_rdata(qtype: str, value: object) -> bytes:
    upper = qtype.upper()
    # Address parsing raises ipaddress.AddressValueError, which is a ValueError but
    # not a DNSError.  Normalising it here means a responder only has to catch one
    # exception type; the mock appliance's handler thread relies on that to count a
    # bad record instead of dying.
    if upper == "A":
        try:
            return ipaddress.IPv4Address(str(value)).packed
        except ValueError as exc:
            raise DNSError(f"not an IPv4 address: {value!r}") from exc
    if upper == "AAAA":
        try:
            return ipaddress.IPv6Address(str(value)).packed
        except ValueError as exc:
            raise DNSError(f"not an IPv6 address: {value!r}") from exc
    if upper in ("CNAME", "NS", "PTR"):
        try:
            return _encode_name(normalise_qname(str(value)))
        except DNSError as exc:
            raise DNSError(f"not a valid domain for {qtype}: {value!r}") from exc
    if upper == "TXT":
        raw = str(value).encode("utf-8")
        chunks = [raw[i : i + 255] for i in range(0, max(len(raw), 1), 255)]
        return b"".join(bytes([len(c)]) + c for c in chunks)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise DNSError(f"cannot encode rdata for qtype {qtype!r} from {value!r}")


def encode_response(
    query: bytes | DNSMessage,
    *,
    rcode: int = 0,
    answers: "Sequence[RR]" = (),
    authorities: "Sequence[RR]" = (),
    additional: "Sequence[RR]" = (),
    aa: bool = True,
    ra: bool = True,
    tc: bool = False,
    rd: bool = True,
    edns_udp_size: int = 0,
    edns_options: Sequence[tuple[int, bytes]] = (),
) -> bytes:
    """Build a response to ``query``, echoing its question section.

    This exists so the mock appliance and the test suite can produce wire-format
    responses without a second DNS library.  Records are written uncompressed --
    pointless for a responder on a loopback with one answer, and it keeps the
    encoder trivially correct.
    """
    if isinstance(query, (bytes, bytearray)):
        msg = decode_message(bytes(query))
    else:
        msg = query

    flags = _FLAG_QR
    if aa:
        flags |= _FLAG_AA
    if tc:
        flags |= _FLAG_TC
    if rd:
        flags |= _FLAG_RD
    if ra:
        flags |= _FLAG_RA
    flags |= rcode & 0x000F

    arcount = len(additional) + (1 if edns_udp_size else 0)
    out = bytearray(
        _HEADER.pack(
            msg.qid,
            flags,
            1 if msg.qname else 0,
            len(answers),
            len(authorities),
            arcount,
        )
    )

    if msg.qname:
        out += _encode_name(normalise_qname(msg.qname))
        out += struct.pack("!HH", msg.qtype or 1, 1)

    for section in (answers, authorities, additional):
        for rr in section:
            rdata = _encode_rdata(rr.qtype, rr.value)
            rtype = QTYPES[rr.qtype.upper()]
            out += _encode_name(normalise_qname(rr.name))
            out += struct.pack("!HHIH", rtype, 1, rr.ttl, len(rdata))
            out += rdata

    if edns_udp_size:
        rdata = _encode_options(edns_options)
        out += struct.pack("!BHHIH", 0, _TYPE_OPT, edns_udp_size, 0, len(rdata)) + rdata

    return bytes(out)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a (possibly compressed) name.  Returns ``(name, offset_after)``.

    Compression pointers can point anywhere earlier in the message and can chain,
    so we follow them with a hop limit; a malicious or broken responder should
    give us a parse error, not an infinite loop.
    """
    labels: list[str] = []
    hops = 0
    pos = offset
    end = None
    total = 0

    while True:
        if pos >= len(data):
            raise DNSError("name runs past end of message")
        length = data[pos]
        if length == 0:
            pos += 1
            if end is None:
                end = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DNSError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if end is None:
                end = pos + 2
            hops += 1
            if hops > _MAX_POINTER_HOPS:
                raise DNSError("compression pointer loop")
            pos = pointer
            continue
        if length & 0xC0:
            raise DNSError("reserved label type")
        pos += 1
        if pos + length > len(data):
            raise DNSError("label runs past end of message")
        total += length + 1
        if total > _MAX_NAME_LEN:
            raise DNSError("name too long")
        labels.append(data[pos : pos + length].decode("ascii", "replace"))
        pos += length

    return ".".join(labels), (end if end is not None else pos)


def _parse_rr(data: bytes, offset: int) -> tuple[DNSAnswer, int]:
    name, offset = _read_name(data, offset)
    if offset + 10 > len(data):
        raise DNSError("truncated resource record header")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    if offset + rdlength > len(data):
        raise DNSError("rdata runs past end of message")
    rdata = data[offset : offset + rdlength]
    offset += rdlength

    ip = ""
    priority, target, hints, alpn, port = 0, "", (), (), 0
    if rtype == _TYPE_A and rdlength == 4:
        ip = str(ipaddress.IPv4Address(rdata))
    elif rtype == _TYPE_AAAA and rdlength == 16:
        ip = str(ipaddress.IPv6Address(rdata))
    elif rtype == _TYPE_CNAME:
        try:
            ip = _read_name(data, offset - rdlength)[0]
        except DNSError:
            ip = ""
    elif rtype in (_TYPE_SVCB, _TYPE_HTTPS):
        priority, target, hints, alpn, port = _parse_svcb(data, offset - rdlength, offset)

    rtype_name = QTYPE_NAMES.get(rtype, f"TYPE{rtype}") if rtype != _TYPE_OPT else "OPT"
    return (
        DNSAnswer(
            name=name,
            rtype=rtype,
            rtype_name=rtype_name,
            ttl=ttl,
            rdata=rdata,
            rclass=rclass,
            ip=ip,
            svc_priority=priority,
            svc_target=target,
            hints=hints,
            svc_alpn=alpn,
            svc_port=port,
        ),
        offset,
    )


def _parse_svcb(
    data: bytes, start: int, end: int
) -> tuple[int, str, tuple[str, ...], tuple[str, ...], int]:
    """SVCB/HTTPS RDATA: priority, target, the hinted addresses, ALPN ids and port.

    Damaged parameters end the walk rather than the decode: the address hints are
    what classification needs, and a response is still worth scoring without them.
    """
    if end - start < 3:
        return 0, "", (), (), 0
    priority = struct.unpack_from("!H", data, start)[0]
    try:
        target, pos = _read_name(data, start + 2)
    except DNSError:
        return priority, "", (), (), 0
    hints: list[str] = []
    alpn: list[str] = []
    port = 0
    while pos + 4 <= end:
        key, length = struct.unpack_from("!HH", data, pos)
        pos += 4
        if pos + length > end:
            break
        value = data[pos : pos + length]
        pos += length
        if key == 1:
            at = 0
            while at < length:
                size = value[at]
                alpn.append(value[at + 1 : at + 1 + size].decode("ascii", "replace"))
                at += 1 + size
        elif key == 3 and length == 2:
            port = struct.unpack("!H", value)[0]
        elif key == _SVC_IPV4HINT:
            hints += [str(ipaddress.IPv4Address(value[i : i + 4])) for i in range(0, length - length % 4, 4)]
        elif key == _SVC_IPV6HINT:
            hints += [str(ipaddress.IPv6Address(value[i : i + 16])) for i in range(0, length - length % 16, 16)]
    return priority, target or ".", tuple(hints), tuple(alpn), port


def _parse_options(rdata: bytes, msg: "DNSMessage") -> None:
    """Read the EDNS options a response carried: Extended DNS Errors and NSID."""
    pos = 0
    while pos + 4 <= len(rdata):
        code, length = struct.unpack_from("!HH", rdata, pos)
        pos += 4
        value = rdata[pos : pos + length]
        pos += length
        if len(value) < length:
            return
        msg.edns_options.append(code)
        if code == EDNS_EDE and length >= 2:
            info = struct.unpack_from("!H", value, 0)[0]
            msg.ede.append((info, value[2:].decode("utf-8", "replace")[:200]))
        elif code == EDNS_NSID:
            msg.nsid = bytes(value[:128])


def decode_message(data: bytes) -> DNSMessage:
    """Decode a DNS message.  Raises ``DNSError`` on anything malformed."""
    if len(data) < _HEADER_LEN:
        raise DNSError(f"message shorter than header ({len(data)} bytes)")

    qid, flags, qdcount, ancount, nscount, arcount = _HEADER.unpack_from(data, 0)
    msg = DNSMessage(
        qid=qid,
        flags=flags,
        qdcount=qdcount,
        ancount=ancount,
        nscount=nscount,
        arcount=arcount,
        rcode=flags & 0x000F,
        truncated=bool(flags & _FLAG_TC),
        raw_len=len(data),
    )

    offset = _HEADER_LEN
    for _ in range(qdcount):
        name, offset = _read_name(data, offset)
        if offset + 4 > len(data):
            raise DNSError("truncated question section")
        qtype, _qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        if not msg.qname:
            msg.qname = name
            msg.qtype = qtype

    try:
        for _ in range(ancount):
            rr, offset = _parse_rr(data, offset)
            msg.answers.append(rr)
        for _ in range(nscount):
            rr, offset = _parse_rr(data, offset)
            msg.authorities.append(rr)
        for _ in range(arcount):
            rr, offset = _parse_rr(data, offset)
            if rr.rtype == _TYPE_OPT:
                # An OPT RR carries the sender's UDP payload size in its CLASS
                # field, not a real class, so it must not be read as IN/CH/HS.
                msg.edns_udp_size = rr.rclass
                _parse_options(rr.rdata, msg)
            msg.additional.append(rr)
    except DNSError:
        # A response with a damaged answer section still tells us the rcode,
        # which is most of what we are measuring.  Keep what we parsed.
        pass

    return msg
