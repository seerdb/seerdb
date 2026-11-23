# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for the protocol-version-319 / large-SDU handshake (#155): the
# 4-byte ("large") packet framing and the extended-ACCEPT parse. The ACCEPT
# fixture is a real 23ai (23.26) accept body captured through the proxy.

import struct
import unittest

from seerdb.client.connection import _parse_accept
from seerdb.common.tns import (
    assemble_packet,
    decode_accept_body,
    decode_packet,
    encode_accept_body,
    encode_dictionary_dty,
    encode_dictionary_login,
    encode_packet,
    split_connect,
)
from seerdb.common.tns_consts import (
    CCAP_TTC4,
    TNS_CCAP_END_OF_RESPONSE,
    TNS_DATA,
    TNS_MAX_CONNECT_DATA,
    TTI_END_OF_RESPONSE,
    DictionaryType,
)


class TestLargePacketFraming(unittest.TestCase):
    def test_large_header_is_4byte_length(self):
        # A large-SDU DATA packet uses a 4-byte length at bytes 0-3, type at 4.
        (pkt, rest) = encode_packet(TNS_DATA, b'hello', 8192, True)
        self.assertIsNone(rest)
        self.assertEqual(struct.unpack('>I', pkt[:4])[0], len(pkt))
        self.assertEqual(pkt[4], TNS_DATA)
        self.assertEqual(pkt.endswith(b'hello'), True)

    def test_legacy_header_is_2byte_length(self):
        # Legacy framing keeps the 2-byte length at bytes 0-1 (default).
        (pkt, _) = encode_packet(TNS_DATA, b'hello', 8192, False)
        self.assertEqual(struct.unpack('>H', pkt[:2])[0], len(pkt))
        self.assertEqual(pkt[4], TNS_DATA)

    def test_roundtrip_large(self):
        (pkt, _) = encode_packet(TNS_DATA, b'payload-bytes', 8192, True)
        (flag, typ, body, rest) = assemble_packet(pkt, 8192, True)
        self.assertEqual(typ, TNS_DATA)
        self.assertEqual(body, b'payload-bytes')
        self.assertEqual(rest, b'')

    def test_roundtrip_legacy_unchanged(self):
        (pkt, _) = encode_packet(TNS_DATA, b'payload-bytes', 8192, False)
        (flag, typ, body, rest) = assemble_packet(pkt, 8192, False)
        self.assertEqual(typ, TNS_DATA)
        self.assertEqual(body, b'payload-bytes')

    def test_login_advertises_319(self):
        Dict = {
            'type': DictionaryType.login,
            'env': {
                'host': 'h',
                'port': 1,
                'user': 'u',
                'password': 'p',
                'sid': 'XE',
                'app_name': 'a',
            },
            'sdu': 8192,
        }
        out = encode_dictionary_login(Dict)
        self.assertEqual(struct.unpack('>H', out[:2])[0], 319)  # version
        self.assertEqual(struct.unpack('>H', out[2:4])[0], 300)  # compat floor
        self.assertEqual(struct.unpack('>H', out[18:20])[0], 74)  # connect-data offset


class TestLongConnectData(unittest.TestCase):
    # A server reads at most 230 bytes of connect data from the CONNECT; a
    # longer descriptor hung the connect on every bed until it went out in a
    # DATA packet of its own (#1768).
    def _login(self, descriptor_len):
        def body(app_name):
            return encode_dictionary_login(
                {
                    'type': DictionaryType.login,
                    'env': {
                        'host': 'h',
                        'port': 1,
                        'user': 'u',
                        'password': 'p',
                        'sid': 'XE',
                        'app_name': app_name,
                    },
                    'sdu': 8192,
                }
            )

        short = len(body('a')) - 66
        out = body('a' * (1 + descriptor_len - short))
        self.assertEqual(len(out) - 66, descriptor_len)
        return out

    def test_230_bytes_stay_in_the_connect(self):
        out = self._login(TNS_MAX_CONNECT_DATA)
        self.assertEqual(split_connect(out), (out, None))

    def test_231_bytes_follow_in_a_data_packet(self):
        out = self._login(TNS_MAX_CONNECT_DATA + 1)
        connect, descriptor = split_connect(out)
        self.assertEqual(connect, out[:66])
        self.assertEqual(descriptor, out[66:])
        self.assertTrue(descriptor.startswith(b'(DESCRIPTION='))
        # The CONNECT still states the full length and the usual offset.
        self.assertEqual(struct.unpack('>H', connect[16:18])[0], 231)
        self.assertEqual(struct.unpack('>H', connect[18:20])[0], 74)


class TestEndOfResponseCap(unittest.TestCase):
    def _dty(self, supports_eor):
        Dict = {
            'type': DictionaryType.dty,
            'field_version': 24,
            'req': 873,
            'supports_eor': supports_eor,
        }
        return encode_dictionary_dty(Dict)

    def _ttc4(self, dty):
        # The compile-caps array is a length byte + array, after the 5-byte DTY
        # header (token + charset_in(2) + charset_out(2) + flag). Index by
        # CCAP_TTC4 into the array.
        caps_len = dty[6]
        caps = dty[7 : 7 + caps_len]
        return caps[CCAP_TTC4]

    def test_eor_bit_set_when_supported(self):
        self.assertTrue(self._ttc4(self._dty(True)) & TNS_CCAP_END_OF_RESPONSE)

    def test_eor_bit_clear_otherwise(self):
        self.assertFalse(self._ttc4(self._dty(False)) & TNS_CCAP_END_OF_RESPONSE)

    def test_end_of_response_token_is_terminal(self):
        # The EOR (29) marker terminates a response decode without raising.
        (flag, acc) = decode_packet(bytes([TTI_END_OF_RESPONSE]), (None, None, []))
        self.assertEqual(flag, True)


class TestAcceptParse(unittest.TestCase):
    # Real 23ai accept body (8-byte packet header already stripped): protocol
    # version 319, large SDU 8192 at offset 24, flags2 0x1a000000 at offset 33
    # (the 0x02000000 bit = end-of-response support).
    _ACCEPT = bytes.fromhex(
        '013f00010000000001000000003dc500000000000000000000'
        '00200000002000001a000000f0ac1eea6c5151fdc20891823652b87b'
    )

    def test_version_and_sdu(self):
        accept = _parse_accept(self._ACCEPT)
        self.assertEqual(accept['version'], 319)
        self.assertEqual(accept['sdu'], 8192)

    def test_eor_bit_detected(self):
        self.assertTrue(_parse_accept(self._ACCEPT)['eor'])

    def test_pre318_no_eor(self):
        # A legacy (version < 318) accept never reports EOR, whatever its
        # flags2 holds.
        body = struct.pack('>H', 316) + self._ACCEPT[2:]
        self.assertFalse(_parse_accept(body)['eor'])

    def test_pre315_keeps_legacy_sdu(self):
        # Below the large-SDU floor the 16-bit legacy SDU is kept.
        body = bytearray(self._ACCEPT)
        struct.pack_into('>HHH', body, 0, 313, 1, 0x1000)
        self.assertEqual(_parse_accept(bytes(body))['sdu'], 0x1000)

    def test_the_codec_writes_the_captured_accept_back(self):
        # Every field of the capture, the random connection id included,
        # encodes back to the same bytes: the accept-data offset (0x3d) is
        # what the body's length makes it.
        accept = decode_accept_body(self._ACCEPT)
        self.assertEqual(accept['data_offset'], 8 + len(self._ACCEPT))
        again = encode_accept_body(
            accept['version'],
            accept['options'],
            accept['sdu'],
            accept['tdu'],
            accept['nt_chars'],
            accept['flags0'],
            accept['flags1'],
            accept['flags2'],
            self._ACCEPT[37:],
        )
        self.assertEqual(again, self._ACCEPT)

    def test_a_short_large_accept_keeps_the_legacy_fields(self):
        # A >= 315 accept that ends before its ub4 pair keeps the 16-bit one
        # and reports no end-of-response, rather than reading past its end.
        body = bytearray(self._ACCEPT[:26])
        struct.pack_into('>H', body, 4, 0x1000)
        accept = _parse_accept(bytes(body))
        self.assertEqual(accept['sdu'], 0x1000)
        self.assertFalse(accept['eor'])

    def test_an_accept_shorter_than_its_head_is_refused(self):
        from seerdb.common.exceptions import OperationalError

        with self.assertRaises(OperationalError):
            _parse_accept(self._ACCEPT[:12])


class TestShortAcceptParse(unittest.TestCase):
    # A pre-315 server (e.g. 11g) replies with a 32-byte accept that ends right
    # after the reconnect-address fields — the large-SDU (offset 24) and
    # end-of-response flags2 (offset 33) fields only exist in the longer accepts
    # newer servers send. Parsing the short form must not read past its end.
    # (#439 — the short accept go-ora's accept_packet test covers too.)

    @staticmethod
    def _short_accept_body() -> bytes:
        # The 24-byte accept body (the 8-byte TNS header handle_login strips):
        # version 314, options, SDU 8192, TDU 32767, NT chars, data len 0,
        # data offset 32; the tail is zero, exactly as the wire short form.
        packet = bytearray(32)
        struct.pack_into('>H', packet, 0, 32)  # packet length
        packet[4] = 2  # TNS_ACCEPT
        struct.pack_into('>H', packet, 8, 314)  # protocol version
        struct.pack_into('>H', packet, 10, 0x0801)  # negotiated options
        struct.pack_into('>H', packet, 12, 8192)  # session data unit
        struct.pack_into('>H', packet, 14, 32767)  # transport data unit
        struct.pack_into('>H', packet, 16, 0x7F08)  # NT characteristics
        struct.pack_into('>H', packet, 18, 0)  # accept data length
        struct.pack_into('>H', packet, 20, 32)  # accept data offset
        return bytes(packet[8:])  # body, header stripped

    def test_version_and_legacy_sdu(self):
        accept = _parse_accept(self._short_accept_body())
        self.assertEqual(accept['version'], 314)
        # 314 < 315: the large-SDU field (offset 24) is absent, so the legacy SDU
        # is kept — and no read past the 24-byte body.
        self.assertEqual(accept['sdu'], 8192)

    def test_short_accept_disables_eor(self):
        # The flags2 field (offset 33) does not exist in the short form, so EOR
        # negotiation must fall back to off rather than overrun.
        self.assertFalse(_parse_accept(self._short_accept_body())['eor'])

    def test_short_accept_does_not_advertise_ano(self):
        # handle_login reads ACFL0/ACFL1 at body offsets 14/15 for the ANO gate;
        # on the short accept those bytes are zero, so no ANO negotiation is
        # triggered and the reads stay in bounds.
        self.assertFalse(_parse_accept(self._short_accept_body())['ano'])

    def test_the_ano_flags_gate_the_negotiation(self):
        # ACFL0 bit 0 set, bit 2 clear, ACFL1 bit 3 clear: what the Mirror and
        # a real 11g send (41 41).
        body = bytearray(self._short_accept_body())
        body[14:16] = b'\x41\x41'
        self.assertTrue(_parse_accept(bytes(body))['ano'])
        body[15] = 0x49
        self.assertFalse(_parse_accept(bytes(body))['ano'])


if __name__ == '__main__':
    unittest.main()
