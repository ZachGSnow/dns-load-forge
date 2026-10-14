"""Minimal DNS wire-format encoder/decoder.

Hand-rolled on purpose.  ``dnspython`` would be a fine dependency for a normal
application, but this package has to run on a freshly imaged Windows box with
nothing installed, and we only need: build a query, read a response's rcode and
its A/AAAA answers.  That is ~200 lines of struct packing, so we do it here and
keep the tool dependency-free.

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
    "encode_query",
    "encode_response",
    "decode_message",
    "normalise_qname",
    "random_query_id",
]

#: 12-byte fixed header: ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
_HEADER = struct.Struct("!HHHHHH")
_HEADER_LEN = _HEADER.size

_FLAG_QR = 0x8000
_FLAG_AA = 0x0400
_FLAG_TC = 0x0200
_FLAG_RD = 0x0100
_FLAG_RA = 0x0080

_TYPE_OPT = 41
_TYPE_A = 1
_TYPE_AAAA = 28
_TYPE_CNAME = 5

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
) -> tuple[bytes, int]:
    """Build a DNS query.  Returns ``(packet, query_id)``.

    EDNS0 (an OPT record in the additional section) is on by default: every real
    stub resolver sends it, and its advertised UDP size is what stops a filtering
    appliance from truncating large answers.  Testing without it exercises a code
    path no real client uses, which is not the traffic we want to generate.
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
    packet += struct.pack("!HH", qnum, 1)  # QTYPE, QCLASS=IN

    if edns:
        # OPT: NAME(root) TYPE(41) CLASS(udp payload size) TTL(ext-rcode/ver/flags)
        #      RDLENGTH(0).  The DO bit lives in the top bit of the TTL field.
        ttl = 0x8000 if dnssec_ok else 0
        packet += struct.pack("!BHHIH", 0, _TYPE_OPT, udp_size, ttl, 0)

    return bytes(packet), qid


@dataclass(slots=True)
class DNSAnswer:
    name: str
    rtype: int
    rtype_name: str
    ttl: int
    rdata: bytes
    rclass: int = 1
    ip: str = ""

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

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode & 0x0F, f"RCODE{self.rcode}")

    @property
    def is_response(self) -> bool:
        return bool(self.flags & _FLAG_QR)

    @property
    def recursive_available(self) -> bool:
        return bool(self.flags & _FLAG_RA)

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
        out += struct.pack("!BHHIH", 0, _TYPE_OPT, edns_udp_size, 0, 0)

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
    if rtype == _TYPE_A and rdlength == 4:
        ip = str(ipaddress.IPv4Address(rdata))
    elif rtype == _TYPE_AAAA and rdlength == 16:
        ip = str(ipaddress.IPv6Address(rdata))
    elif rtype == _TYPE_CNAME:
        try:
            ip = _read_name(data, offset - rdlength)[0]
        except DNSError:
            ip = ""

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
        ),
        offset,
    )


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
            msg.additional.append(rr)
    except DNSError:
        # A response with a damaged answer section still tells us the rcode,
        # which is most of what we are measuring.  Keep what we parsed.
        pass

    return msg
