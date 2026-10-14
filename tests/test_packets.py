"""Wire-codec tests.

The important property here is **non-circular verification**.  It is easy to write
a codec test that builds a packet with ``encode_query`` and then asserts
``decode_message`` agrees, which passes even when both share the same wrong idea
about the format.  So the foundational cases below are built from raw bytes by
hand and checked in both directions, and only the convenience paths use the two
functions together.
"""

from __future__ import annotations

import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge import packets as pk  # noqa: E402


def _name_bytes(*labels: str) -> bytes:
    out = bytearray()
    for label in labels:
        out.append(len(label))
        out += label.encode("ascii")
    out.append(0)
    return bytes(out)


class TestEncodeQuery(unittest.TestCase):
    def test_known_good_byte_vector(self) -> None:
        """The canonical example: a plain A query for example.com."""
        expected = (
            b"\x12\x34"  # transaction id
            b"\x01\x00"  # flags: RD set, QR clear
            b"\x00\x01\x00\x00\x00\x00\x00\x00"  # qd=1, an=ns=ar=0
            + _name_bytes("example", "com")
            + b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
        )
        packet, qid = pk.encode_query("example.com", "A", 0x1234, edns=False)
        self.assertEqual(packet, expected)
        self.assertEqual(qid, 0x1234)
        self.assertEqual(len(packet), 29)

    def test_edns_appends_opt_record(self) -> None:
        without, _ = pk.encode_query("example.com", "A", 1, edns=False)
        with_edns, _ = pk.encode_query("example.com", "A", 1, edns=True, udp_size=1232)
        self.assertEqual(len(with_edns), len(without) + 11)  # OPT is 1+2+2+4+2 bytes
        message = pk.decode_message(with_edns)
        self.assertEqual(message.arcount, 1)
        self.assertEqual(message.edns_udp_size, 1232)

    def test_dnssec_ok_sets_the_do_bit(self) -> None:
        packet, _ = pk.encode_query("example.com", "A", 1, dnssec_ok=True)
        # The DO bit is the top bit of the OPT record's TTL field, which sits 6
        # bytes from the end of the message.
        ttl = struct.unpack_from("!I", packet, len(packet) - 6)[0]
        self.assertEqual(ttl & 0x8000, 0x8000)

    def test_case_is_normalised_to_lower(self) -> None:
        packet, _ = pk.encode_query("ExAmPlE.CoM", "A", 1, edns=False)
        self.assertIn(b"example", packet)
        self.assertNotIn(b"ExAmPlE", packet)

    def test_trailing_dot_is_accepted(self) -> None:
        with_dot, _ = pk.encode_query("example.com.", "A", 5, edns=False)
        without, _ = pk.encode_query("example.com", "A", 5, edns=False)
        self.assertEqual(with_dot, without)

    def test_qtype_names_and_numbers_agree(self) -> None:
        by_name, _ = pk.encode_query("example.com", "AAAA", 1, edns=False)
        by_number, _ = pk.encode_query("example.com", 28, 1, edns=False)
        self.assertEqual(by_name, by_number)

    def test_rejects_unknown_qtype(self) -> None:
        with self.assertRaises(pk.DNSError):
            pk.encode_query("example.com", "NOPE")

    def test_rejects_malformed_names(self) -> None:
        for bad in ("", "..", "a..b", "a" * 64 + ".com", "x" * 260):
            with self.subTest(bad=bad), self.assertRaises(pk.DNSError):
                pk.normalise_qname(bad)

    def test_random_query_id_is_in_range(self) -> None:
        for _ in range(50):
            self.assertTrue(1 <= pk.random_query_id() <= 0xFFFF)


class TestDecode(unittest.TestCase):
    def _response(self, *, rcode: int = 0, answers: bytes = b"", ancount: int = 0, flags: int = 0x8180) -> bytes:
        header = struct.pack("!HHHHHH", 0xABCD, flags | rcode, 1, ancount, 0, 0)
        question = _name_bytes("example", "com") + b"\x00\x01\x00\x01"
        return header + question + answers

    def test_decodes_a_hand_built_response_with_a_compression_pointer(self) -> None:
        """The answer's owner name is a pointer back to offset 12 -- exactly what a
        real resolver sends, and the parser must follow it rather than read it as a
        literal label."""
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
        message = pk.decode_message(self._response(answers=answer, ancount=1))

        self.assertEqual(message.qid, 0xABCD)
        self.assertEqual(message.rcode_name, "NOERROR")
        self.assertEqual(message.qname, "example.com")
        self.assertEqual(message.qtype, 1)
        self.assertTrue(message.is_response)
        self.assertTrue(message.recursive_available)
        self.assertEqual(message.answer_ips, ["93.184.216.34"])
        self.assertEqual(message.answers[0].name, "example.com")
        self.assertEqual(message.answers[0].ttl, 60)

    def test_decodes_rcodes(self) -> None:
        for rcode, name in ((3, "NXDOMAIN"), (2, "SERVFAIL"), (5, "REFUSED"), (1, "FORMERR")):
            with self.subTest(rcode=name):
                self.assertEqual(pk.decode_message(self._response(rcode=rcode)).rcode_name, name)

    def test_decodes_truncation_flag(self) -> None:
        self.assertTrue(pk.decode_message(self._response(flags=0x8380)).truncated)

    def test_decodes_aaaa(self) -> None:
        rdata = bytes.fromhex("26064700470000000000000000001111")
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 30, 16) + rdata
        message = pk.decode_message(self._response(answers=answer, ancount=1))
        self.assertEqual(message.answer_ips, ["2606:4700:4700::1111"])

    def test_cname_targets_are_not_reported_as_answer_ips(self) -> None:
        """A regression guard: treating a CNAME's target name as an address made
        every sinkhole check wrong, because a name is not an IP."""
        target = _name_bytes("cdn")
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(target)) + target
        address = _name_bytes("cdn") + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
        message = pk.decode_message(self._response(answers=cname + address, ancount=2))

        self.assertEqual(message.answer_ips, ["1.2.3.4"])
        self.assertEqual(message.cname_targets, ["cdn"])
        self.assertEqual(len(message.answers), 2)

    def test_rejects_truncated_messages(self) -> None:
        with self.assertRaises(pk.DNSError):
            pk.decode_message(b"\x00\x01")
        with self.assertRaises(pk.DNSError):
            pk.decode_message(struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\x07exam")

    def test_rejects_a_compression_pointer_loop(self) -> None:
        """A hostile or broken responder must raise, not spin forever."""
        header = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0)
        loop = header + b"\xc0\x0c"  # points at itself
        with self.assertRaises(pk.DNSError):
            pk.decode_message(loop)

    def test_rejects_reserved_label_type(self) -> None:
        header = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0)
        with self.assertRaises(pk.DNSError):
            pk.decode_message(header + b"\x40abc")

    def test_survives_a_damaged_answer_section(self) -> None:
        """The rcode is still worth having even when the answers are corrupt, so a
        bad answer section must not discard the header."""
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 99) + b"\x01"  # rdlength lies
        message = pk.decode_message(self._response(answers=answer, ancount=1))
        self.assertEqual(message.rcode_name, "NOERROR")
        self.assertEqual(message.answer_ips, [])


class TestEncodeResponse(unittest.TestCase):
    def test_round_trips_every_supported_record_type(self) -> None:
        query, _ = pk.encode_query("example.com", "A", 0x7777)
        response = pk.encode_response(
            query,
            answers=[
                pk.RR("example.com", "A", 300, "93.184.216.34"),
                pk.RR("example.com", "AAAA", 300, "2606:4700:4700::1111"),
                pk.RR("example.com", "CNAME", 60, "cdn.example.net"),
                pk.RR("example.com", "TXT", 60, "v=spf1 -all"),
            ],
            edns_udp_size=1232,
        )
        message = pk.decode_message(response)

        self.assertEqual(message.qid, 0x7777)
        self.assertEqual(message.rcode_name, "NOERROR")
        self.assertEqual(message.answer_ips, ["93.184.216.34", "2606:4700:4700::1111"])
        self.assertEqual(message.cname_targets, ["cdn.example.net"])
        self.assertEqual(message.edns_udp_size, 1232)
        self.assertEqual(len(message.answers), 4)

    def test_carries_an_error_rcode(self) -> None:
        query, _ = pk.encode_query("blocked.example", "A")
        for name, code in (("NXDOMAIN", 3), ("REFUSED", 5), ("SERVFAIL", 2)):
            with self.subTest(rcode=name):
                self.assertEqual(pk.decode_message(pk.encode_response(query, rcode=code)).rcode_name, name)

    def test_accepts_a_decoded_message_as_input(self) -> None:
        query, _ = pk.encode_query("example.com", "A", 4321)
        message = pk.decode_message(query)
        response = pk.encode_response(message, answers=[pk.RR("example.com", "A", 60, "1.1.1.1")])
        self.assertEqual(pk.decode_message(response).answer_ips, ["1.1.1.1"])

    def test_sinkhole_is_visible_in_the_answers(self) -> None:
        query, _ = pk.encode_query("blocked.example", "A")
        response = pk.encode_response(query, answers=[pk.RR("blocked.example", "A", 60, "0.0.0.0")])
        self.assertEqual(pk.decode_message(response).answer_ips, ["0.0.0.0"])

    def test_rejects_unencodable_rdata(self) -> None:
        query, _ = pk.encode_query("example.com", "A")
        with self.assertRaises(pk.DNSError):
            pk.encode_response(query, answers=[pk.RR("example.com", "A", 60, "not-an-address")])


if __name__ == "__main__":
    unittest.main()
