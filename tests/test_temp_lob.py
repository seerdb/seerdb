# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the temporary-LOB bind path (#91).

Large CLOB / BLOB values can't be bound into a PL/SQL locator parameter through
the streamed path (ORA-01460); the driver allocates a server temp LOB
(TTI_LOBOPS CREATE_TEMP), streams the value in (WRITE) and binds the locator.
These tests pin the request/response wire bytes reverse-engineered from
python-oracledb on 21c (docs/PROTOCOL.md §14) — no server needed.
"""

import struct
import unittest

import seerdb
from seerdb.client._conn_logic import _ConnectionLogic
from seerdb.client.cursor import _bind_temp_lobs
from seerdb.common.datatypes import TempLob
from seerdb.common.lob import LOB
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    decode_lobops_oer,
    encode_dictionary_lobops,
    encode_token_oac,
    encode_token_rxd,
)
from seerdb.common.tns_consts import FIELD_VERSION_12_1, TNS_LOB_OP_WRITE


class _FieldVersionIsolated(unittest.TestCase):
    """Restore the encode/decode field-version context vars after each test.

    The bind/OER fixtures here advertise a 12c+ field version; without a reset
    that mutation leaks (context vars persist across tests in one process) and
    breaks later 11g-default tests."""

    def setUp(self):
        self._enc = _ENCODE_FIELD_VERSION.set(_ENCODE_FIELD_VERSION.get())
        self._dec = _DECODE_FIELD_VERSION.set(_DECODE_FIELD_VERSION.get())
        self.addCleanup(lambda: _ENCODE_FIELD_VERSION.reset(self._enc))
        self.addCleanup(lambda: _DECODE_FIELD_VERSION.reset(self._dec))


# A real 38-byte temp-LOB locator captured from a 21c CREATE_TEMP response.
LOCATOR = bytes.fromhex(
    '0001820880010002e31e00000129000000010369000a000000010000a62b6539000000010000'
)


class CreateTempEncode(unittest.TestCase):
    def test_clob_body(self):
        Body = encode_dictionary_lobops({'seq': 3, 'create_temp': True})[3:]
        # type 0x70 (CLOB), trailing sb4 0x0369; captured verbatim.
        self.assertEqual(
            Body.hex(),
            '01012800010a0000010001020110000001010170' + '00' * 47 + '020369',
        )

    def test_blob_body(self):
        Body = encode_dictionary_lobops(
            {'seq': 3, 'create_temp': True, 'is_blob': True}
        )[3:]
        # type 0x71 (BLOB) — one byte shorter type spec than CLOB.
        self.assertEqual(
            Body.hex(), '01012800010a00000100010201100000000171' + '00' * 47 + '020369'
        )

    def test_nclob_body(self):
        Body = encode_dictionary_lobops({'seq': 3, 'create_temp': True, 'csfrm': 2})[3:]
        # An NCLOB is a CLOB (type 0x70) with form 01 02 and the NATIONAL charset
        # 2000 (AL16UTF16) in the trailing sb4; captured from python-oracledb
        # against 23ai (#1066). Sending the CLOB body made a CLOB.
        self.assertEqual(
            Body.hex(),
            '01012800010a0000010001020110000001020170' + '00' * 47 + '0207d0',
        )


class WriteEncode(unittest.TestCase):
    def _write(self, data):
        return encode_dictionary_lobops(
            {'seq': 4, 'operation': TNS_LOB_OP_WRITE, 'locator': LOCATOR, 'data': data}
        )

    def test_short_inline(self):
        # "HI" UTF-16BE -> 0x0E marker + ub1 length 4 + data, locator ub2-prefixed.
        Out = self._write('HI'.encode('utf-16-be'))
        self.assertEqual(
            Out,
            bytes.fromhex('0360040101280000000000000001400000010100000000000000000026')
            + LOCATOR
            + bytes.fromhex('0e0400480049'),
        )

    def test_chunked_large(self):
        # > 0xFC bytes -> 0x0E + 0xFE + (<sb4 chunklen><chunk>)... + 0x00.
        Data = ('Z' * 60000).encode('utf-16-be')  # 120000 bytes
        Out = self._write(Data)
        Tail = Out[Out.index(LOCATOR) + len(LOCATOR) :]
        self.assertEqual(Tail[:2].hex(), '0efe')
        i, chunks = 2, []
        while i < len(Tail):
            n = Tail[i]
            if n == 0:
                break
            ln = int.from_bytes(Tail[i + 1 : i + 1 + n], 'big')
            i += 1 + n + ln
            chunks.append(ln)
        self.assertEqual(chunks, [32767, 32767, 32767, 21699])
        self.assertEqual(sum(chunks), len(Data))


class BindEncode(_FieldVersionIsolated):
    def setUp(self):
        super().setUp()
        _ENCODE_FIELD_VERSION.set(16)  # 21c

    def test_clob_oac(self):
        Oac = encode_token_oac(TempLob(LOCATOR, False))
        # type 0x70, max-data-length 112 (the fixed LOB buffer factor, sb4
        # 01 70), LOB cont-flag 0x02000000, charset 873 (AL32UTF8), csfrm 1.
        self.assertEqual(Oac.hex(), '7001000001700004020000000000020369010000')

    def test_blob_oac(self):
        Oac = encode_token_oac(TempLob(LOCATOR, True))
        # type 0x71, max-data-length 112, cont-flag 0x02000000, charset 0, csfrm 0.
        self.assertEqual(Oac.hex(), '710100000170000402000000000000000000')

    def test_nclob_oac(self):
        Oac = encode_token_oac(TempLob(LOCATOR, False, csfrm=2))
        # The CLOB OAC with csfrm 2; the charset field stays 873, as captured
        # from python-oracledb binding a temp NCLOB on 23ai (#1066).
        self.assertEqual(Oac.hex(), '7001000001700004020000000000020369020000')

    def test_oac_size_is_fixed_not_value_derived(self):
        # The OAC announces the fixed LOB buffer size, never the value's byte
        # budget: python-oracledb sends the same for an empty and a huge LOB, and
        # a size of 0 makes the server bind NULL (#903). The marker no longer even
        # carries a size, so the CLOB / BLOB OAC is one fixed string each.
        self.assertEqual(
            encode_token_oac(TempLob(LOCATOR, False)).hex(),
            '7001000001700004020000000000020369010000',
        )
        self.assertEqual(
            encode_token_oac(TempLob(LOCATOR, True)).hex(),
            '710100000170000402000000000000000000',
        )

    def test_rxd_descriptor(self):
        # LOB-descriptor prefix 01 28 28 + ub2 locator length + locator.
        Rxd = encode_token_rxd(TempLob(LOCATOR, False))
        self.assertEqual(
            Rxd, bytes.fromhex('012828') + struct.pack('>H', len(LOCATOR)) + LOCATOR
        )


class _StubLogic(_ConnectionLogic):
    def __init__(self, field_version):
        self.field_version = field_version


class CreateLobForm(unittest.TestCase):
    # What connection.createlob(lob_type) asks the server for (#1066).
    def test_each_lob_type_maps_to_its_type_and_form(self):
        Logic = _StubLogic(FIELD_VERSION_12_1)
        self.assertEqual(Logic._createlob_form(seerdb.DB_TYPE_CLOB), (0x70, 1))
        self.assertEqual(Logic._createlob_form(seerdb.DB_TYPE_NCLOB), (0x70, 2))
        self.assertEqual(Logic._createlob_form(seerdb.DB_TYPE_BLOB), (0x71, 1))

    def test_a_non_lob_type_is_refused(self):
        for Typ in (seerdb.DB_TYPE_VARCHAR, seerdb.DB_TYPE_JSON, 'CLOB', None):
            with self.assertRaises(seerdb.ProgrammingError):
                _StubLogic(FIELD_VERSION_12_1)._createlob_form(Typ)

    def test_an_11g_server_is_refused(self):
        with self.assertRaises(seerdb.NotSupportedError):
            _StubLogic(FIELD_VERSION_12_1 - 1)._createlob_form(seerdb.DB_TYPE_CLOB)


class BindTempLobs(unittest.TestCase):
    # A createlob() LOB binds as the temp-LOB locator marker (#1066).
    def test_a_temp_lob_becomes_its_marker(self):
        Raw = struct.pack('>H', len(LOCATOR)) + LOCATOR
        Clob = LOB(0x70, Raw, temp=True, csfrm=2)
        Blob = LOB(0x71, Raw, temp=True)
        Out = _bind_temp_lobs([1, Clob, Blob, 'x'])
        self.assertEqual(Out[0], 1)
        self.assertEqual(Out[3], 'x')
        # The marker holds the BARE locator: it writes the ub2 itself.
        self.assertEqual(
            (Out[1].locator, Out[1].is_blob, Out[1].csfrm), (LOCATOR, False, 2)
        )
        self.assertEqual((Out[2].locator, Out[2].is_blob), (LOCATOR, True))

    def test_a_fetched_lob_binds_by_its_locator_on_a_thin_session(self):
        # As python-oracledb binds one: a CLOB / BLOB by the temp-LOB marker, a
        # BFILE by its own, its locator kept as fetched.
        from seerdb.common.datatypes import BfileBind

        # As a row carries an Oracle locator: its ub2 length in front.
        Raw = struct.pack('>H', len(LOCATOR)) + LOCATOR
        Out = _bind_temp_lobs([LOB(0x70, Raw), LOB(0x72, Raw)])
        self.assertIsInstance(Out[0], TempLob)
        self.assertEqual((Out[0].locator, Out[0].is_blob), (LOCATOR, False))
        self.assertIsInstance(Out[1], BfileBind)
        self.assertEqual(Out[1].locator, Raw)

    def test_a_mirror_locator_goes_whole(self):
        # A Mirror mints a column LOB's locator without the leading ub2 length
        # an Oracle locator has, so nothing is stripped from it: cut by two
        # bytes, it named no LOB the Mirror had served (#2505).
        from seerdb.common.tns import is_prefixed_locator, mint_column_lob_locator

        Minted = mint_column_lob_locator(0)
        self.assertFalse(is_prefixed_locator(Minted))
        (Out,) = _bind_temp_lobs([LOB(0x70, Minted)])
        self.assertEqual(Out.locator, Minted)

    def test_a_dialects_session_keeps_a_fetched_lob(self):
        # 8i, 9i and a pooled 11g session bind or refuse the LOB object
        # themselves: a marker their codecs do not know aborted a pooled 11g
        # server process (ORA-03137).
        class _Dialect:
            _dialect = object()

        Fetched = LOB(0x70, LOCATOR)
        self.assertIs(_bind_temp_lobs([Fetched], _Dialect())[0], Fetched)

    def test_no_binds(self):
        self.assertEqual(_bind_temp_lobs([]), [])


class OerDecode(_FieldVersionIsolated):
    # The OER call status is 1 for a standalone op but 5 right after a PL/SQL
    # call; decode_lobops_oer must find the OER in both and report success.
    def test_call_status_1(self):
        Pkt = bytes.fromhex(
            '08002600018208800100028dc300000129000000010369000a000000'
            '010000a62b6539000000010000040101028598'
            + '00' * 21
            + '0800000000000000000000'
        )
        self.assertEqual(decode_lobops_oer(Pkt, 16), (0, None))

    def test_call_status_5(self):
        Pkt = bytes.fromhex(
            '08002600018208800100028dc300000129000000020369000a000000'
            '010000a62b653900000001000004010502859b'
            + '00' * 21
            + '0b00000000000000000000'
        )
        self.assertEqual(decode_lobops_oer(Pkt, 16), (0, None))


if __name__ == '__main__':
    unittest.main()
