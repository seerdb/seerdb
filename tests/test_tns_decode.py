# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import unittest

from seerdb.common.tns import (
    assemble_packet,
    decode_packet,
    decode_token_oac,
    decode_token_oer,
    decode_token_pro,
    decode_token_rpa,
    decode_ub4,
    parse_redirect_address,
)
from seerdb.common.tns_consts import (
    TNS_ACCEPT,
    TNS_DATA,
    TNS_RESEND,
    TTI_AUTH,
    TTI_SESS,
    VERSION_11_2_0_2,
)


def _load_capture(name):
    # tests/replay.py, which CI's unittest step, importing this module as
    # tests.test_tns_decode, does not have on its path.
    import os
    import sys

    sys.path.insert(0, os.path.dirname(__file__))
    from replay import load_capture

    return load_capture(name)


class TestDecodeUb4(unittest.TestCase):
    """Variable-length integer decode, incl. multi-byte negatives (#24)."""

    def _check(self, raw, value, consumed):
        # Append a sentinel so we also assert exactly `consumed` bytes were taken.
        got, rest = decode_ub4(bytes(raw) + b'\x5a\xa5')
        self.assertEqual(got, value)
        self.assertEqual(rest, bytes(raw)[consumed:] + b'\x5a\xa5')
        self.assertEqual(len(bytes(raw) + b'\x5a\xa5') - len(rest), consumed)

    def test_zero(self):
        self._check([0], 0, 1)

    def test_positive_widths(self):
        self._check([1, 0x2A], 42, 2)
        self._check([2, 0x01, 0x00], 256, 3)
        self._check([3, 0x12, 0x34, 0x56], 0x123456, 4)
        self._check([4, 0xFF, 0xFF, 0xFF, 0xFF], 0xFFFFFFFF, 5)

    def test_negative_width_1(self):
        # The common forms: -1 and NUMBER scale -127.
        self._check([0x81, 0x01], -1, 2)
        self._check([0x81, 0x7F], -127, 2)

    def test_negative_multibyte(self):
        # The latent bug #24 fixed: negatives wider than one byte.
        self._check([0x82, 0x01, 0x00], -256, 3)
        self._check([0x83, 0x01, 0x00, 0x00], -65536, 4)
        self._check([0x84, 0xFF, 0xFF, 0xFF, 0xFF], -0xFFFFFFFF, 5)

    def test_raw_ub2_field_consumes_two_bytes(self):
        # A length byte 5..0x7f is not a real var-int — it is the raw ub2 /
        # counter field decode_token_oer reads through here. Historic lenient
        # behaviour (consume 2 bytes) must be preserved so the OER stream stays
        # aligned; the value is discarded by the caller.
        self._check([0x07, 0x00], 0, 2)
        self._check([0x0C, 0x34], -0x34, 2)


class TestParseRedirectAddress(unittest.TestCase):
    """Parse the HOST/PORT out of a TNS_REDIRECT descriptor (#23)."""

    def test_bare_address(self):
        body = b'(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.5)(PORT=1522))'
        self.assertEqual(parse_redirect_address(body), ('10.0.0.5', 1522))

    def test_full_description(self):
        body = (
            b'(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.example.com)'
            b'(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=ORCL)))'
        )
        self.assertEqual(parse_redirect_address(body), ('db.example.com', 1521))

    def test_prefers_address_host_over_cid_host(self):
        # The descriptor can also carry the original CONNECT_DATA whose CID has
        # the *client* HOST; the ADDRESS host is the reconnect target. Here the
        # CID/HOST appears first textually, so a naive first-match would be
        # wrong — the parser must scope to the ADDRESS block.
        body = (
            b'(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)'
            b'(CID=(PROGRAM=app)(HOST=client-box)(USER=scott)))'
            b'(ADDRESS=(PROTOCOL=TCP)(HOST=server-box)(PORT=1530)))'
        )
        self.assertEqual(parse_redirect_address(body), ('server-box', 1530))

    def test_case_insensitive_and_whitespace(self):
        body = b'(address=(protocol=tcp)(Host = 192.168.1.9)(Port = 1599))'
        self.assertEqual(parse_redirect_address(body), ('192.168.1.9', 1599))

    def test_unparseable_returns_none(self):
        self.assertEqual(parse_redirect_address(b'garbage'), (None, None))


class TestTnsCommandDecoders(unittest.TestCase):
    def test_tns_assemble_00(self):
        Data = bytes([0, 8, 0, 0, 11, 0, 0, 0])
        Length = 8192
        self.assertEqual(assemble_packet(Data, Length), (True, TNS_RESEND, b'', b''))

    def test_tns_assemble_01(self):
        Data = bytes(
            [
                0,
                32,
                0,
                0,
                2,
                0,
                0,
                0,
                1,
                57,
                0,
                1,
                32,
                0,
                255,
                255,
                1,
                0,
                0,
                0,
                0,
                32,
                197,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        )
        Length = 8192
        self.assertEqual(
            assemble_packet(Data, Length), (True, TNS_ACCEPT, Data[8:], b'')
        )

    def test_tns_assemble_02(self):
        Data = bytes(
            [
                0,
                238,
                0,
                0,
                6,
                0,
                0,
                0,
                0,
                0,
                1,
                6,
                0,
                120,
                56,
                54,
                95,
                54,
                52,
                47,
                76,
                105,
                110,
                117,
                120,
                32,
                50,
                46,
                52,
                46,
                120,
                120,
                0,
                105,
                3,
                1,
                10,
                0,
                102,
                3,
                64,
                3,
                1,
                64,
                3,
                102,
                3,
                1,
                102,
                3,
                72,
                3,
                1,
                72,
                3,
                102,
                3,
                1,
                102,
                3,
                82,
                3,
                1,
                82,
                3,
                102,
                3,
                1,
                102,
                3,
                97,
                3,
                1,
                97,
                3,
                102,
                3,
                1,
                102,
                3,
                31,
                3,
                8,
                31,
                3,
                102,
                3,
                1,
                0,
                100,
                0,
                0,
                0,
                96,
                1,
                36,
                15,
                5,
                11,
                12,
                3,
                12,
                12,
                5,
                4,
                5,
                13,
                6,
                9,
                7,
                8,
                5,
                5,
                5,
                5,
                5,
                15,
                5,
                5,
                5,
                5,
                5,
                10,
                5,
                5,
                5,
                5,
                5,
                4,
                5,
                6,
                7,
                8,
                8,
                35,
                71,
                35,
                71,
                8,
                17,
                35,
                8,
                17,
                65,
                176,
                71,
                0,
                131,
                3,
                105,
                7,
                208,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                39,
                6,
                1,
                1,
                1,
                15,
                1,
                1,
                6,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                127,
                255,
                3,
                10,
                3,
                3,
                1,
                0,
                127,
                1,
                127,
                255,
                1,
                6,
                1,
                1,
                63,
                1,
                3,
                6,
                0,
                1,
                3,
                2,
                7,
                2,
                1,
                0,
                1,
                24,
                0,
                3,
            ]
        )
        Length = 8192
        self.assertEqual(
            assemble_packet(Data, Length), (True, TNS_DATA, Data[10:], b'')
        )

    def test_decode_packet_sta(self):
        self.assertEqual(
            decode_packet(bytes([9, 1, 1, 1, 8]), [1, {'foo': 'bar'}]),
            (True, [1, {'foo': 'bar'}]),
        )

    def test_decode_packet_handles_a_large_row_batch(self):
        # A single fetch batch of thousands of RXD rows must decode iteratively:
        # the old per-row recursion raised RecursionError past a few hundred rows.
        from seerdb.common.tns import encode_value
        from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TTI_RXD, TTI_STA

        row_format = [{'data_type': TNS_TYPE_NUMBER, 'column_name': b'N'}]
        count = 5000  # well past the old ~450-row recursion ceiling
        body = b''.join(
            bytes([TTI_RXD]) + encode_value(i, TNS_TYPE_NUMBER) for i in range(count)
        )
        (done, acc) = decode_packet(body + bytes([TTI_STA]), (None, row_format, []))
        self.assertTrue(done)
        rows = acc[2]
        self.assertEqual(len(rows), count)
        self.assertEqual(rows[0], [0])
        self.assertEqual(rows[-1], [count - 1])

    def test_decode_select_response_21c(self):
        # Full 'SELECT 1 FROM dual' response captured from Oracle 21c (DCB +
        # RXH + RXD + RPA + OER), decoded with the 21.1 field version. Exercises
        # the 12c per-column DCB format (sb1 scale, oaccolid) and confirms the
        # row decodes to 1. With the default 11g field version this same buffer
        # would mis-parse, so it guards the version-gated decode path.
        import contextvars

        from seerdb.common.tns import decode_packet
        from seerdb.common.tns_consts import FIELD_VERSION_21_1

        Resp = bytes.fromhex(
            '101735ebcd3cc510be7fdf53b18448bb2dda787e0608123633010201015c0200'
            '00810102000000000000000001010101013100000000010707787e0608123633'
            '00021fe80102010200062201010001020000000702c10208010603284b3a0001'
            '02000000000000040101011b010102057b00000102010e0300000000000000000'
            '0000000030001010000000002057b0101010300194f52412d30313430333a206e'
            '6f206461746120666f756e640a'
        )
        # Run in a copied context so the field-version ContextVar set by
        # decode_packet does not leak into other tests (production resets it per
        # response). Mirrors how each connection decodes in its own context.
        Result = contextvars.copy_context().run(
            decode_packet, Resp, (None, None, []), FIELD_VERSION_21_1
        )
        Rows = Result[4]
        RowFormat = Result[3][1]
        self.assertEqual(Rows, [[1]])
        self.assertEqual(RowFormat[0]['data_type'], 2)  # NUMBER
        self.assertEqual(RowFormat[0]['column_name'], b'1')

    def test_decode_select_response_10g(self):
        # Full 6-column, 3-row response captured from a live Oracle 10.2.0.5
        # server (SELECT id,name,price,created,code,flag FROM t84), decoded with
        # 10g's negotiated field version 4. Guards the pre-11g DCB format (#84):
        # the per-column metadata has no `uds flags` ub4 and the describe trailer
        # has no `dcbqcky` — both 11g additions. With the 11g layout this buffer
        # mis-parses column 2 onward and desyncs the rows.
        import contextvars
        import datetime
        from decimal import Decimal

        from seerdb.common.tns import decode_packet

        Resp = bytes.fromhex(
            '101736595fbfc8d361f990557c35c1301c42787e061008050c016b01064d02000a000116000000000000000102010202494400000001800000011e0000000002036901011e01040104044e414d4500000101020008010201160000000000000001050105055052494345000001020c00000001010000000000000001070107074352454154454400000103608000000104000000000203690101040104010404434f444500000104020001000116000000000000000104010404464c414700000105010707787e061008050c0101021fe8010a010a0602010600010f0000000702c10205616c70686103c11464077878010f010101044142303102c1020702c103046265746104c2020133077879061e010101044344303201801501063f0702c1040567616d6d6102c00207787a0c19010101044546303302c10208010603028e6a0001030000000000000401010106010302057b00000103013803000120000000000000000000000900010100000000194f52412d30313430333a206e6f206461746120666f756e640a'
        )
        Result = contextvars.copy_context().run(
            decode_packet, Resp, (None, None, []), 4
        )  # field version 4 = 10g
        RowFormat = Result[3][1]
        Rows = Result[4]
        self.assertEqual([c['data_type'] for c in RowFormat], [2, 1, 2, 12, 96, 2])
        self.assertEqual(RowFormat[1]['column_name'], b'NAME')
        self.assertEqual(
            Rows,
            [
                [
                    1,
                    'alpha',
                    Decimal('19.99'),
                    datetime.datetime(2020, 1, 15),
                    'AB01',
                    1,
                ],
                [
                    2,
                    'beta',
                    Decimal('100.5'),
                    datetime.datetime(2021, 6, 30),
                    'CD02',
                    0,
                ],
                [
                    3,
                    'gamma',
                    Decimal('0.01'),
                    datetime.datetime(2022, 12, 25),
                    'EF03',
                    1,
                ],
            ],
        )

    def test_decode_rxh_bit_vector_reuse(self):
        # Scroll re-execute LAST response from a live 23ai server (#181): the
        # cursor repositions onto a row whose value equals the last row already
        # returned, so the server omits the value and flags the column "reuse
        # previous" in the row-HEADER bit vector (not a standalone BVC token).
        # decode_token_rxh must pass that bit vector to the RXD or the RXD reads
        # the next token as a value and desyncs (it used to crash on the bogus
        # TTI_ROW token 0x0a). With no in-response previous row, the reused column
        # falls back to the seeded previous-fetch row (_DECODE_PREV_ROW).
        import contextvars

        from seerdb.common.tns import decode_packet, set_decode_prev_row
        from seerdb.common.tns_consts import FIELD_VERSION_23_4

        RowFormat = [
            {
                'column_name': b'ID',
                'data_type': 2,
                'data_length': 22,
                'data_scale': -127,
                'precision': 0,
                'max_size': 0,
                'charset': 0,
                'null_ok': 1,
                'domain_schema': None,
                'domain_name': None,
                'annotations': None,
            }
        ]
        Resp = bytes.fromhex(
            '060200000132000101010000070801060000010700010a04c9710f0c0000000401'
            '01020eae010a000000010700030000000000030160d4020400000302dfa3010900'
            '002200000000000000010a0103001d'
        )

        # Seeded with the prior batch's last row [10]: the reused column resolves
        # to 10 (the LAST row), and crucially it does not raise.
        def run_seeded():
            set_decode_prev_row([10])
            try:
                return decode_packet(Resp, (None, RowFormat, []), FIELD_VERSION_23_4)
            finally:
                set_decode_prev_row(None)

        Result = contextvars.copy_context().run(run_seeded)
        self.assertEqual(Result[4], [[10]])

        # Without a seed the reused column has no source and decodes to None —
        # but it must still stay aligned (no exception / desync).
        Result2 = contextvars.copy_context().run(
            decode_packet, Resp, (None, RowFormat, []), FIELD_VERSION_23_4
        )
        self.assertEqual(Result2[4], [[None]])

    def test_decode_refcursor_out_10g(self):
        # REF CURSOR OUT bind from a callproc, captured from a live 10.2.0.5
        # server (PROC OUT SYS_REFCURSOR opening SELECT 1 a, 'x' b ...). The
        # nested-cursor describe in the IOV path shares the per-column DCB format
        # and, like the top-level describe (#84), has no dcbqcky trailer at field
        # version 4 — skipping a phantom one consumes the cursor id and desyncs.
        import contextvars

        import seerdb
        from seerdb.client.cursor import Var
        from seerdb.common.tns import decode_packet

        Resp = bytes.fromhex(
            '00000b05010100010100000010073c010301024d020000817f0102000000000000000101010101410000006080000001010000000002036901010101010101014200000101010707787e0610081b26000000000102000801060302ac6900010101020000000000040105010401010000000101002f0000000000000000000000000700010100000000'
        )
        Bind = Var(seerdb.CURSOR)
        Result = contextvars.copy_context().run(
            decode_packet, Resp[2:], (None, None, [], [Bind]), 4
        )  # fv4 = 10g
        Record = Result[4][0]['out_values'][0]
        self.assertTrue(Record['_refcursor'])
        self.assertEqual(Record['cursor_id'], 2)
        self.assertEqual([c['data_type'] for c in Record['row_format']], [2, 96])
        self.assertEqual([c['column_name'] for c in Record['row_format']], [b'A', b'B'])

    def test_decode_token_pro_11g(self):
        # Authentic 11g PRO response (same bytes as test_tns_assemble_02, minus
        # the 8-byte TNS header and 2-byte data flags). field_version 6 = 11.2.
        Body = bytes(
            [
                1,
                6,
                0,
                120,
                56,
                54,
                95,
                54,
                52,
                47,
                76,
                105,
                110,
                117,
                120,
                32,
                50,
                46,
                52,
                46,
                120,
                120,
                0,
                105,
                3,
                1,
                10,
                0,
                102,
                3,
                64,
                3,
                1,
                64,
                3,
                102,
                3,
                1,
                102,
                3,
                72,
                3,
                1,
                72,
                3,
                102,
                3,
                1,
                102,
                3,
                82,
                3,
                1,
                82,
                3,
                102,
                3,
                1,
                102,
                3,
                97,
                3,
                1,
                97,
                3,
                102,
                3,
                1,
                102,
                3,
                31,
                3,
                8,
                31,
                3,
                102,
                3,
                1,
                0,
                100,
                0,
                0,
                0,
                96,
                1,
                36,
                15,
                5,
                11,
                12,
                3,
                12,
                12,
                5,
                4,
                5,
                13,
                6,
                9,
                7,
                8,
                5,
                5,
                5,
                5,
                5,
                15,
                5,
                5,
                5,
                5,
                5,
                10,
                5,
                5,
                5,
                5,
                5,
                4,
                5,
                6,
                7,
                8,
                8,
                35,
                71,
                35,
                71,
                8,
                17,
                35,
                8,
                17,
                65,
                176,
                71,
                0,
                131,
                3,
                105,
                7,
                208,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                39,
                6,
                1,
                1,
                1,
                15,
                1,
                1,
                6,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                127,
                255,
                3,
                10,
                3,
                3,
                1,
                0,
                127,
                1,
                127,
                255,
                1,
                6,
                1,
                1,
                63,
                1,
                3,
                6,
                0,
                1,
                3,
                2,
                7,
                2,
                1,
                0,
                1,
                24,
                0,
                3,
            ]
        )
        Pro = decode_token_pro(Body)
        self.assertEqual(Pro['server_version'], 6)
        self.assertEqual(Pro['banner'], b'x86_64/Linux 2.4.xx')
        self.assertEqual(len(Pro['compile_caps']), 39)
        self.assertEqual(Pro['compile_caps'][7], 6)  # CCAP_FIELD_VERSION = 11.2
        self.assertEqual(len(Pro['runtime_caps']), 7)

    def test_decode_token_pro_21c(self):
        # Authentic 21c PRO response body (captured via tools/capture_proxy.py).
        # field_version 16 = 21.1; the server's compile array is 45 bytes.
        Body = bytes.fromhex(
            '0106007838365f36342f4c696e757820322e342e7878006903010a006603400301'
            '400366030166034803014803660301660352030152036603016603610301610366'
            '030166031f03081f0366030100640000006001240f050b0c030c0c0504050d0609'
            '070805050505050f05050505050a050505050504050607080823472347081123081'
            '141b0470083036907d0030000000000000000000000000000000000000000000000'
            '00000000000000000000000000002d060101016f0101100101010101010'
            '17fff031003030101ff01ffff010b0101ff01060ce6017f050f7f0d0300010702010'
            '00118007f'
        )
        Pro = decode_token_pro(Body)
        self.assertEqual(Pro['server_version'], 6)
        self.assertEqual(Pro['compile_caps'][7], 16)  # CCAP_FIELD_VERSION = 21.1
        self.assertEqual(len(Pro['compile_caps']), 45)

    def test_tns_decode_token_oac_00(self):
        self.assertEqual(
            decode_token_oac(bytes([2, 3, 0, 0, 1, 22, 0, 0, 0, 0, 0, 1, 0]), None),
            (2, 22, 0, 0, b''),
        )

    def test_tns_decode_token_oac_01(self):
        Data = bytes(
            [
                2,
                0,
                0,
                129,
                127,
                1,
                2,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
                3,
                1,
                3,
                3,
                79,
                78,
                69,
                0,
                0,
                0,
                0,
                12,
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
                7,
                1,
                7,
                7,
                83,
                89,
                83,
                68,
                65,
                84,
                69,
                0,
                0,
                1,
                1,
                0,
                11,
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                1,
                5,
                5,
                82,
                79,
                87,
                73,
                68,
                0,
                0,
                1,
                2,
                0,
                1,
                7,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                0,
                2,
                31,
                232,
                1,
                2,
                1,
                2,
                0,
                6,
                34,
                1,
                3,
                0,
                1,
                15,
                0,
                0,
                0,
                7,
                2,
                193,
                2,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                14,
                1,
                116,
                1,
                1,
                0,
                2,
                3,
                161,
                0,
                8,
                1,
                6,
                3,
                42,
                55,
                122,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                4,
                1,
                1,
                1,
                4,
                1,
                1,
                2,
                5,
                123,
                0,
                0,
                1,
                1,
                0,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                0,
                1,
                1,
                25,
                79,
                82,
                65,
                45,
                48,
                49,
                52,
                48,
                51,
                58,
                32,
                110,
                111,
                32,
                100,
                97,
                116,
                97,
                32,
                102,
                111,
                117,
                110,
                100,
                10,
            ]
        )
        Rest = bytes(
            [
                1,
                3,
                1,
                3,
                3,
                79,
                78,
                69,
                0,
                0,
                0,
                0,
                12,
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
                7,
                1,
                7,
                7,
                83,
                89,
                83,
                68,
                65,
                84,
                69,
                0,
                0,
                1,
                1,
                0,
                11,
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                1,
                5,
                5,
                82,
                79,
                87,
                73,
                68,
                0,
                0,
                1,
                2,
                0,
                1,
                7,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                0,
                2,
                31,
                232,
                1,
                2,
                1,
                2,
                0,
                6,
                34,
                1,
                3,
                0,
                1,
                15,
                0,
                0,
                0,
                7,
                2,
                193,
                2,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                14,
                1,
                116,
                1,
                1,
                0,
                2,
                3,
                161,
                0,
                8,
                1,
                6,
                3,
                42,
                55,
                122,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                4,
                1,
                1,
                1,
                4,
                1,
                1,
                2,
                5,
                123,
                0,
                0,
                1,
                1,
                0,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                0,
                1,
                1,
                25,
                79,
                82,
                65,
                45,
                48,
                49,
                52,
                48,
                51,
                58,
                32,
                110,
                111,
                32,
                100,
                97,
                116,
                97,
                32,
                102,
                111,
                117,
                110,
                100,
                10,
            ]
        )
        self.assertEqual(decode_token_oac(Data, None), (2, 2, -127, 0, Rest))

    def test_tns_decode_token_oac_02(self):
        Data = bytes(
            [
                12,
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
                7,
                1,
                7,
                7,
                83,
                89,
                83,
                68,
                65,
                84,
                69,
                0,
                0,
                1,
                1,
                0,
                11,
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                1,
                5,
                5,
                82,
                79,
                87,
                73,
                68,
                0,
                0,
                1,
                2,
                0,
                1,
                7,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                0,
                2,
                31,
                232,
                1,
                2,
                1,
                2,
                0,
                6,
                34,
                1,
                3,
                0,
                1,
                15,
                0,
                0,
                0,
                7,
                2,
                193,
                2,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                14,
                1,
                116,
                1,
                1,
                0,
                2,
                3,
                161,
                0,
                8,
                1,
                6,
                3,
                42,
                55,
                122,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                4,
                1,
                1,
                1,
                4,
                1,
                1,
                2,
                5,
                123,
                0,
                0,
                1,
                1,
                0,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                0,
                1,
                1,
                25,
                79,
                82,
                65,
                45,
                48,
                49,
                52,
                48,
                51,
                58,
                32,
                110,
                111,
                32,
                100,
                97,
                116,
                97,
                32,
                102,
                111,
                117,
                110,
                100,
                10,
            ]
        )
        Rest = bytes(
            [
                1,
                7,
                1,
                7,
                7,
                83,
                89,
                83,
                68,
                65,
                84,
                69,
                0,
                0,
                1,
                1,
                0,
                11,
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                1,
                5,
                5,
                82,
                79,
                87,
                73,
                68,
                0,
                0,
                1,
                2,
                0,
                1,
                7,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                0,
                2,
                31,
                232,
                1,
                2,
                1,
                2,
                0,
                6,
                34,
                1,
                3,
                0,
                1,
                15,
                0,
                0,
                0,
                7,
                2,
                193,
                2,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                14,
                1,
                116,
                1,
                1,
                0,
                2,
                3,
                161,
                0,
                8,
                1,
                6,
                3,
                42,
                55,
                122,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                4,
                1,
                1,
                1,
                4,
                1,
                1,
                2,
                5,
                123,
                0,
                0,
                1,
                1,
                0,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                0,
                1,
                1,
                25,
                79,
                82,
                65,
                45,
                48,
                49,
                52,
                48,
                51,
                58,
                32,
                110,
                111,
                32,
                100,
                97,
                116,
                97,
                32,
                102,
                111,
                117,
                110,
                100,
                10,
            ]
        )
        self.assertEqual(decode_token_oac(Data, None), (12, 1, 0, 0, Rest))

    def test_tns_decode_token_oac_03(self):
        Data = bytes(
            [
                11,
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                1,
                5,
                5,
                82,
                79,
                87,
                73,
                68,
                0,
                0,
                1,
                2,
                0,
                1,
                7,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                0,
                2,
                31,
                232,
                1,
                2,
                1,
                2,
                0,
                6,
                34,
                1,
                3,
                0,
                1,
                15,
                0,
                0,
                0,
                7,
                2,
                193,
                2,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                14,
                1,
                116,
                1,
                1,
                0,
                2,
                3,
                161,
                0,
                8,
                1,
                6,
                3,
                42,
                55,
                122,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                4,
                1,
                1,
                1,
                4,
                1,
                1,
                2,
                5,
                123,
                0,
                0,
                1,
                1,
                0,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                0,
                1,
                1,
                25,
                79,
                82,
                65,
                45,
                48,
                49,
                52,
                48,
                51,
                58,
                32,
                110,
                111,
                32,
                100,
                97,
                116,
                97,
                32,
                102,
                111,
                117,
                110,
                100,
                10,
            ]
        )
        Rest = bytes(
            [
                0,
                5,
                1,
                5,
                5,
                82,
                79,
                87,
                73,
                68,
                0,
                0,
                1,
                2,
                0,
                1,
                7,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                0,
                2,
                31,
                232,
                1,
                2,
                1,
                2,
                0,
                6,
                34,
                1,
                3,
                0,
                1,
                15,
                0,
                0,
                0,
                7,
                2,
                193,
                2,
                7,
                120,
                119,
                9,
                6,
                8,
                41,
                17,
                14,
                1,
                116,
                1,
                1,
                0,
                2,
                3,
                161,
                0,
                8,
                1,
                6,
                3,
                42,
                55,
                122,
                0,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                4,
                1,
                1,
                1,
                4,
                1,
                1,
                2,
                5,
                123,
                0,
                0,
                1,
                1,
                0,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                5,
                0,
                1,
                1,
                25,
                79,
                82,
                65,
                45,
                48,
                49,
                52,
                48,
                51,
                58,
                32,
                110,
                111,
                32,
                100,
                97,
                116,
                97,
                32,
                102,
                111,
                117,
                110,
                100,
                10,
            ]
        )
        self.assertEqual(decode_token_oac(Data, None), (11, 1, 0, 0, Rest))

    def test_tns_decode_token_oer_04(self):
        # Real OER bytes captured from Oracle XE 11g for
        # "DROP TABLE nonexistent_xyz" — ORA-00942 with the full message
        # text as the trailing length-prefixed DALC. Exercises the unified
        # OER decoder end to end: extended error number, DML rowcount = 0,
        # and the human-readable message round-tripping cleanly.
        Data = (
            bytes(
                [
                    0x04,  # TTI_OER token
                    0x01,
                    0x05,  # call_status = 5
                    0x01,
                    0x04,  # end-to-end seq# = 4
                    0x00,  # current row # / rowcount = 0
                    0x02,
                    0x03,
                    0xAE,  # ORA error code = 942
                    0x00,
                    0x00,  # array elem error x2
                    0x01,
                    0x01,  # cursor id = 1
                    0x01,
                    0x0B,  # error position = 11
                    0x0C,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # 6 ub1 fields
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # rowid (all zero)
                    0x00,  # OS error
                    0x00,
                    0x07,  # stmt #, call # (7)
                    0x00,  # padding
                    0x00,  # success_iters
                    0x00,  # oerrdd len = 0
                    0x00,
                    0x00,
                    0x00,  # 3 batch-error counts
                    0x28,  # DALC length = 40
                ]
            )
            + b'ORA-00942: table or view does not exist\n'
        )
        Cursor = None
        RowFormat = None
        Rows = []
        self.assertEqual(
            decode_token_oer(Data, (Cursor, RowFormat, Rows)),
            (
                5,  # call_status
                942,  # ORA-00942
                1,  # cursor id
                (0, None),  # rowcount, row_format
                [],  # rows
                'ORA-00942: table or view does not exist',
                None,  # lastrowid (rowid bytes all zero -> no row)
                [],  # batch errors (none)
                None,  # array-DML row counts (not requested)
                11,  # error position (parse offset) — the 0x0B field above
                0,  # warn flags: no compilation warning on this reply (#993)
            ),
        )

    def test_an_aggregate_warning_keeps_the_oer_aligned(self):
        # A GROUP BY whose aggregate skipped NULLs sets the OER `flags` field,
        # which before 12.1 is a variable-length ub2 (`01 20`) and from 12.1 a
        # single byte (`20`). Read as one byte, 11g's reply misread the rowid
        # and everything after it, and failed (#1995). Both frames are captured
        # from live servers: 11g at fv 6, 23ai at fv 24.
        from seerdb.common.tns import _DECODE_FIELD_VERSION
        from seerdb.common.types import rowid_to_string

        captured = (
            (
                6,
                '040102010f010302057b000001080116030001200000050305eeef0104000201'
                '4d010400001200010100000000194f52412d30313430333a206e6f2064617461'
                '20666f756e640a',
                (0x05EEEF, 4, 0x14D, 4),
            ),
            (
                24,
                '04010202f1b5010302057b000001050116030020000005030b31c30204000002'
                'cf2d01040000170001010000000002057b0103010300194f52412d3031343033'
                '3a206e6f206461746120666f756e640a',
                (0x0B31C3, 1024, 0xCF2D, 4),  # relative file 1024: a bigfile tablespace
            ),
        )
        for field_version, frame, rowid in captured:
            with self.subTest(field_version=field_version):
                token = _DECODE_FIELD_VERSION.set(field_version)
                try:
                    result = decode_token_oer(bytes.fromhex(frame), (None, None, []))
                finally:
                    _DECODE_FIELD_VERSION.reset(token)
                self.assertEqual(result[1], 1403)
                self.assertEqual(result[5], 'ORA-01403: no data found')
                self.assertEqual(result[6], rowid_to_string(*rowid))
                self.assertEqual(result[10], 5)  # warn flags, now read in place

    def test_tns_decode_token_oer_rowid(self):
        # Same OER frame as _04 but with a real (non-zero) rowid in the
        # rowid slot, so the decoder must render it as the trailing lastrowid.
        from seerdb.common.tns import encode_sb4
        from seerdb.common.types import rowid_to_string

        Obj, File, Block, Slot = 4, 2, 300, 7
        RowidBytes = (
            encode_sb4(Obj)
            + encode_sb4(File)
            + b'\x00'
            + encode_sb4(Block)
            + encode_sb4(Slot)
        )
        Data = (
            bytes(
                [
                    0x04,
                    0x01,
                    0x05,
                    0x01,
                    0x04,
                    0x00,
                    0x02,
                    0x03,
                    0xAE,
                    0x00,
                    0x00,
                    0x01,
                    0x01,
                    0x01,
                    0x0B,
                    0x0C,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ]
            )
            + RowidBytes
            + bytes(
                [
                    0x00,
                    0x00,
                    0x07,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x28,
                ]
            )
            + b'ORA-00942: table or view does not exist\n'
        )
        Result = decode_token_oer(Data, (None, None, []))
        self.assertEqual(Result[6], rowid_to_string(Obj, File, Block, Slot))

    def test_tns_decode_token_rpa_00(self):
        Data = bytes(
            [
                1,
                3,
                1,
                12,
                12,
                65,
                85,
                84,
                72,
                95,
                83,
                69,
                83,
                83,
                75,
                69,
                89,
                1,
                96,
                254,
                64,
                49,
                48,
                65,
                55,
                51,
                69,
                54,
                68,
                65,
                51,
                48,
                66,
                54,
                67,
                65,
                53,
                65,
                68,
                68,
                68,
                49,
                69,
                69,
                67,
                48,
                66,
                51,
                57,
                56,
                49,
                69,
                49,
                53,
                50,
                67,
                66,
                54,
                67,
                68,
                67,
                65,
                54,
                51,
                56,
                54,
                69,
                68,
                54,
                68,
                65,
                50,
                66,
                53,
                52,
                55,
                69,
                48,
                69,
                66,
                66,
                50,
                68,
                54,
                51,
                32,
                49,
                68,
                56,
                51,
                57,
                67,
                69,
                56,
                52,
                54,
                69,
                67,
                54,
                68,
                69,
                70,
                49,
                53,
                54,
                69,
                67,
                49,
                50,
                70,
                54,
                52,
                54,
                53,
                49,
                54,
                49,
                67,
                0,
                0,
                1,
                13,
                13,
                65,
                85,
                84,
                72,
                95,
                86,
                70,
                82,
                95,
                68,
                65,
                84,
                65,
                1,
                20,
                20,
                66,
                48,
                51,
                49,
                52,
                53,
                67,
                55,
                69,
                70,
                54,
                48,
                67,
                65,
                54,
                57,
                51,
                69,
                49,
                68,
                2,
                27,
                37,
                1,
                26,
                26,
                65,
                85,
                84,
                72,
                95,
                71,
                76,
                79,
                66,
                65,
                76,
                76,
                89,
                95,
                85,
                78,
                73,
                81,
                85,
                69,
                95,
                68,
                66,
                73,
                68,
                0,
                1,
                32,
                32,
                54,
                54,
                56,
                65,
                53,
                51,
                70,
                50,
                50,
                68,
                69,
                48,
                68,
                65,
                50,
                57,
                69,
                54,
                69,
                69,
                48,
                69,
                70,
                70,
                49,
                50,
                53,
                67,
                49,
                50,
                57,
                56,
                0,
                4,
                1,
                1,
                1,
                2,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                3,
                0,
                0,
            ]
        )
        SessKey = b'10A73E6DA30B6CA5ADDD1EEC0B3981E152CB6CDCA6386ED6DA2B547E0EBB2D631D839CE846EC6DEF156EC12F6465161C'
        Salt = b'B03145C7EF60CA693E1D'
        DerivedSalt = None
        # 11g challenge — no PBKDF2 count fields (both None); the AUTH_VFR_DATA
        # flag is 6949, the SHA-1 verifier type (a real-capture confirmation of
        # the #311 constant).
        self.assertEqual(
            decode_token_rpa(Data, None),
            (TTI_SESS, SessKey, Salt, DerivedSalt, None, None, 6949),
        )

    def test_tns_decode_token_rpa_01(self):
        Data = bytes(
            [
                1,
                39,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                86,
                69,
                82,
                83,
                73,
                79,
                78,
                95,
                83,
                84,
                82,
                73,
                78,
                71,
                1,
                18,
                18,
                45,
                32,
                54,
                52,
                98,
                105,
                116,
                32,
                80,
                114,
                111,
                100,
                117,
                99,
                116,
                105,
                111,
                110,
                0,
                1,
                16,
                16,
                65,
                85,
                84,
                72,
                95,
                86,
                69,
                82,
                83,
                73,
                79,
                78,
                95,
                83,
                81,
                76,
                1,
                2,
                2,
                50,
                50,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                88,
                65,
                67,
                84,
                73,
                79,
                78,
                95,
                84,
                82,
                65,
                73,
                84,
                83,
                1,
                1,
                1,
                51,
                0,
                1,
                15,
                15,
                65,
                85,
                84,
                72,
                95,
                86,
                69,
                82,
                83,
                73,
                79,
                78,
                95,
                78,
                79,
                1,
                9,
                9,
                49,
                56,
                54,
                54,
                52,
                55,
                48,
                52,
                48,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                86,
                69,
                82,
                83,
                73,
                79,
                78,
                95,
                83,
                84,
                65,
                84,
                85,
                83,
                1,
                1,
                1,
                48,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                67,
                65,
                80,
                65,
                66,
                73,
                76,
                73,
                84,
                89,
                95,
                84,
                65,
                66,
                76,
                69,
                0,
                0,
                1,
                11,
                11,
                65,
                85,
                84,
                72,
                95,
                68,
                66,
                78,
                65,
                77,
                69,
                1,
                2,
                2,
                88,
                69,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                68,
                66,
                95,
                77,
                79,
                85,
                78,
                84,
                95,
                73,
                68,
                0,
                1,
                10,
                10,
                50,
                56,
                57,
                56,
                53,
                48,
                56,
                54,
                52,
                50,
                0,
                1,
                11,
                11,
                65,
                85,
                84,
                72,
                95,
                68,
                66,
                95,
                73,
                68,
                0,
                1,
                10,
                10,
                50,
                56,
                57,
                51,
                51,
                55,
                48,
                49,
                55,
                55,
                0,
                1,
                12,
                12,
                65,
                85,
                84,
                72,
                95,
                85,
                83,
                69,
                82,
                95,
                73,
                68,
                1,
                1,
                1,
                53,
                0,
                1,
                15,
                15,
                65,
                85,
                84,
                72,
                95,
                83,
                69,
                83,
                83,
                73,
                79,
                78,
                95,
                73,
                68,
                1,
                3,
                3,
                49,
                54,
                48,
                0,
                1,
                15,
                15,
                65,
                85,
                84,
                72,
                95,
                83,
                69,
                82,
                73,
                65,
                76,
                95,
                78,
                85,
                77,
                1,
                4,
                4,
                49,
                55,
                50,
                53,
                0,
                1,
                16,
                16,
                65,
                85,
                84,
                72,
                95,
                73,
                78,
                83,
                84,
                65,
                78,
                67,
                69,
                95,
                78,
                79,
                1,
                1,
                1,
                49,
                0,
                1,
                16,
                16,
                65,
                85,
                84,
                72,
                95,
                70,
                65,
                73,
                76,
                79,
                86,
                69,
                82,
                95,
                73,
                68,
                1,
                1,
                1,
                49,
                0,
                1,
                15,
                15,
                65,
                85,
                84,
                72,
                95,
                83,
                69,
                82,
                86,
                69,
                82,
                95,
                80,
                73,
                68,
                1,
                5,
                5,
                49,
                52,
                55,
                48,
                52,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                83,
                69,
                82,
                86,
                69,
                82,
                95,
                72,
                79,
                83,
                84,
                1,
                12,
                12,
                101,
                57,
                100,
                98,
                52,
                50,
                50,
                55,
                54,
                48,
                49,
                53,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                68,
                66,
                85,
                78,
                73,
                81,
                85,
                69,
                95,
                78,
                65,
                77,
                69,
                1,
                2,
                2,
                88,
                69,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                73,
                78,
                83,
                84,
                65,
                78,
                67,
                69,
                95,
                78,
                65,
                77,
                69,
                1,
                2,
                2,
                88,
                69,
                0,
                1,
                20,
                20,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                83,
                69,
                82,
                86,
                73,
                67,
                69,
                95,
                78,
                65,
                77,
                69,
                1,
                9,
                9,
                83,
                89,
                83,
                36,
                85,
                83,
                69,
                82,
                83,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                73,
                78,
                83,
                84,
                65,
                78,
                67,
                69,
                95,
                73,
                68,
                1,
                1,
                1,
                49,
                0,
                1,
                27,
                27,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                73,
                78,
                83,
                84,
                65,
                78,
                67,
                69,
                95,
                83,
                84,
                65,
                82,
                84,
                95,
                84,
                73,
                77,
                69,
                1,
                36,
                36,
                50,
                48,
                49,
                57,
                45,
                48,
                56,
                45,
                50,
                55,
                32,
                48,
                57,
                58,
                53,
                55,
                58,
                52,
                56,
                46,
                48,
                48,
                48,
                48,
                48,
                48,
                48,
                48,
                48,
                32,
                43,
                48,
                48,
                58,
                48,
                48,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                68,
                66,
                95,
                68,
                79,
                77,
                65,
                73,
                78,
                0,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                83,
                86,
                67,
                95,
                70,
                76,
                65,
                71,
                83,
                1,
                1,
                1,
                48,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                73,
                78,
                83,
                84,
                65,
                78,
                67,
                69,
                78,
                65,
                77,
                69,
                1,
                2,
                2,
                88,
                69,
                0,
                1,
                15,
                15,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                76,
                65,
                78,
                0,
                1,
                8,
                8,
                65,
                77,
                69,
                82,
                73,
                67,
                65,
                78,
                0,
                1,
                22,
                22,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                84,
                69,
                82,
                82,
                73,
                84,
                79,
                82,
                89,
                0,
                1,
                7,
                7,
                65,
                77,
                69,
                82,
                73,
                67,
                65,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                67,
                85,
                82,
                82,
                69,
                78,
                67,
                89,
                0,
                1,
                1,
                1,
                36,
                0,
                1,
                20,
                20,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                73,
                83,
                79,
                67,
                85,
                82,
                82,
                0,
                1,
                7,
                7,
                65,
                77,
                69,
                82,
                73,
                67,
                65,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                78,
                85,
                77,
                69,
                82,
                73,
                67,
                83,
                0,
                1,
                2,
                2,
                46,
                44,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                68,
                65,
                84,
                69,
                70,
                77,
                0,
                1,
                9,
                9,
                68,
                68,
                45,
                77,
                79,
                78,
                45,
                82,
                82,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                68,
                65,
                84,
                69,
                76,
                65,
                78,
                71,
                0,
                1,
                8,
                8,
                65,
                77,
                69,
                82,
                73,
                67,
                65,
                78,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                83,
                79,
                82,
                84,
                0,
                1,
                6,
                6,
                66,
                73,
                78,
                65,
                82,
                89,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                67,
                65,
                76,
                69,
                78,
                68,
                65,
                82,
                0,
                1,
                9,
                9,
                71,
                82,
                69,
                71,
                79,
                82,
                73,
                65,
                78,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                85,
                78,
                73,
                79,
                78,
                67,
                85,
                82,
                0,
                1,
                1,
                1,
                36,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                84,
                73,
                77,
                69,
                70,
                77,
                0,
                1,
                14,
                14,
                72,
                72,
                46,
                77,
                73,
                46,
                83,
                83,
                88,
                70,
                70,
                32,
                65,
                77,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                83,
                84,
                77,
                80,
                70,
                77,
                0,
                1,
                24,
                24,
                68,
                68,
                45,
                77,
                79,
                78,
                45,
                82,
                82,
                32,
                72,
                72,
                46,
                77,
                73,
                46,
                83,
                83,
                88,
                70,
                70,
                32,
                65,
                77,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                84,
                84,
                90,
                78,
                70,
                77,
                0,
                1,
                18,
                18,
                72,
                72,
                46,
                77,
                73,
                46,
                83,
                83,
                88,
                70,
                70,
                32,
                65,
                77,
                32,
                84,
                90,
                82,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                83,
                84,
                90,
                78,
                70,
                77,
                0,
                1,
                28,
                28,
                68,
                68,
                45,
                77,
                79,
                78,
                45,
                82,
                82,
                32,
                72,
                72,
                46,
                77,
                73,
                46,
                83,
                83,
                88,
                70,
                70,
                32,
                65,
                77,
                32,
                84,
                90,
                82,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                83,
                86,
                82,
                95,
                82,
                69,
                83,
                80,
                79,
                78,
                83,
                69,
                1,
                96,
                254,
                64,
                54,
                54,
                48,
                55,
                57,
                49,
                51,
                56,
                55,
                48,
                54,
                54,
                69,
                65,
                53,
                53,
                69,
                55,
                48,
                67,
                51,
                70,
                68,
                67,
                68,
                57,
                48,
                49,
                66,
                55,
                54,
                68,
                69,
                50,
                57,
                66,
                65,
                53,
                51,
                70,
                69,
                48,
                66,
                68,
                66,
                55,
                52,
                52,
                56,
                50,
                56,
                65,
                66,
                54,
                50,
                55,
                51,
                56,
                50,
                52,
                68,
                65,
                67,
                53,
                32,
                50,
                50,
                54,
                67,
                51,
                68,
                50,
                56,
                49,
                56,
                70,
                52,
                69,
                53,
                48,
                53,
                49,
                50,
                53,
                57,
                53,
                54,
                54,
                65,
                68,
                56,
                55,
                67,
                52,
                49,
                68,
                69,
                0,
                0,
                4,
                1,
                1,
                1,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                4,
                0,
                0,
            ]
        )
        Resp = b'660791387066EA55E70C3FDCD901B76DE29BA53FE0BDB744828AB6273824DAC5226C3D2818F4E5051259566AD87C41DE'
        # Full packed AUTH_VERSION_NO (0x0b200200 = 11.2.0.2.0); the connection
        # masks the major release out of this for its protocol gate.
        Ver = VERSION_11_2_0_2
        # The SID and SERIAL#, as the numbers the captured reply carries (#1218).
        (SessId, SerialNum) = (160, 1725)
        # AUTH_SC_DBUNIQUE_NAME; an 11g reply has no AUTH_SC_REAL_DBUNIQUE_NAME (#1774).
        DbUniqueName = 'XE'
        self.assertEqual(
            decode_token_rpa(Data, None),
            (
                TTI_AUTH,
                Resp,
                Ver,
                SessId,
                SerialNum,
                DbUniqueName,
                # 11g sends its instance's name but no identifier limit (#2456).
                {'max_identifier_length': None, 'instance_name': 'XE'},
            ),
        )


from seerdb.common.tns import decode_chr, decode_kv


class TestTnsBaseDecoders(unittest.TestCase):
    def test_decode_ub4_0(self):
        self.assertEqual(decode_ub4(bytes([0])), (0, b''))

    def test_decode_ub4_1(self):
        self.assertEqual(decode_ub4(bytes([1, 171])), (0xAB, b''))

    def test_decode_ub4_2(self):
        self.assertEqual(decode_ub4(bytes([2, 171, 205])), (0xABCD, b''))

    def test_decode_ub4_3(self):
        self.assertEqual(decode_ub4(bytes([3, 171, 205, 239])), (0xABCDEF, b''))

    def test_decode_ub4_4(self):
        self.assertEqual(decode_ub4(bytes([4, 171, 205, 239, 135])), (0xABCDEF87, b''))

    def test_decode_ub4_from_stream(self):
        Data = bytes([3, 171, 205, 239, 1, 2, 3, 4, 5])
        self.assertEqual(decode_ub4(Data), (0xABCDEF, bytes([1, 2, 3, 4, 5])))

    def test_decode_chr_0(self):
        self.assertEqual(
            decode_chr(bytes([5, 104, 101, 108, 108, 111])), (b'hello', b'')
        )

    def test_decode_chr_1(self):
        Input = bytes(
            [
                254,
                64,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                7,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                0,
            ]
        )
        Output = (
            b'HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH'
        )
        self.assertEqual(decode_chr(Input), (Output, b''))

    def test_decode_chr_2(self):
        Input = bytes(
            [
                254,
                64,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                64,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                13,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                72,
                0,
            ]
        )
        Output = b'HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH'
        self.assertEqual(decode_chr(Input), (Output, b''))

    def test_decode_kv_00(self):
        Data = bytes(
            [
                1,
                12,
                12,
                65,
                85,
                84,
                72,
                95,
                77,
                65,
                67,
                72,
                73,
                78,
                69,
                1,
                11,
                11,
                69,
                120,
                97,
                109,
                112,
                108,
                101,
                72,
                111,
                115,
                116,
                0,
            ]
        )
        self.assertEqual(
            decode_kv(Data, 1, []),
            ([(b'AUTH_MACHINE', b'ExampleHost')], b''),
        )

    def test_decode_kv_01(self):
        Data = bytes(
            [
                1,
                12,
                12,
                65,
                85,
                84,
                72,
                95,
                83,
                69,
                83,
                83,
                75,
                69,
                89,
                1,
                96,
                254,
                64,
                52,
                66,
                66,
                49,
                51,
                66,
                65,
                54,
                67,
                53,
                54,
                52,
                70,
                66,
                52,
                56,
                55,
                48,
                66,
                56,
                67,
                55,
                70,
                68,
                48,
                68,
                68,
                55,
                57,
                65,
                51,
                49,
                68,
                53,
                54,
                56,
                66,
                55,
                53,
                50,
                48,
                66,
                57,
                54,
                56,
                65,
                50,
                53,
                56,
                53,
                53,
                53,
                65,
                49,
                65,
                52,
                54,
                68,
                65,
                65,
                55,
                51,
                53,
                70,
                32,
                49,
                55,
                51,
                70,
                57,
                51,
                52,
                56,
                66,
                70,
                69,
                54,
                52,
                48,
                67,
                70,
                55,
                67,
                68,
                56,
                66,
                54,
                65,
                57,
                55,
                52,
                50,
                55,
                54,
                48,
                48,
                57,
                0,
                0,
                1,
                13,
                13,
                65,
                85,
                84,
                72,
                95,
                86,
                70,
                82,
                95,
                68,
                65,
                84,
                65,
                1,
                20,
                20,
                66,
                48,
                51,
                49,
                52,
                53,
                67,
                55,
                69,
                70,
                54,
                48,
                67,
                65,
                54,
                57,
                51,
                69,
                49,
                68,
                2,
                27,
                37,
                1,
                26,
                26,
                65,
                85,
                84,
                72,
                95,
                71,
                76,
                79,
                66,
                65,
                76,
                76,
                89,
                95,
                85,
                78,
                73,
                81,
                85,
                69,
                95,
                68,
                66,
                73,
                68,
                0,
                1,
                32,
                32,
                54,
                54,
                56,
                65,
                53,
                51,
                70,
                50,
                50,
                68,
                69,
                48,
                68,
                65,
                50,
                57,
                69,
                54,
                69,
                69,
                48,
                69,
                70,
                70,
                49,
                50,
                53,
                67,
                49,
                50,
                57,
                56,
                0,
                4,
                1,
                1,
                1,
                2,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                3,
                0,
                0,
            ]
        )
        Remainder = bytes(
            [
                4,
                1,
                1,
                1,
                2,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                3,
                0,
                0,
            ]
        )
        KVs = [
            (b'AUTH_GLOBALLY_UNIQUE_DBID\x00', b'668A53F22DE0DA29E6EE0EFF125C1298'),
            (
                b'AUTH_SESSKEY',
                b'4BB13BA6C564FB4870B8C7FD0DD79A31D568B7520B968A258555A1A46DAA735F173F9348BFE640CF7CD8B6A974276009',
            ),
            (b'AUTH_VFR_DATA', b'B03145C7EF60CA693E1D'),
        ]
        self.assertEqual(decode_kv(Data, 3, []), (KVs, Remainder))

    def test_decode_kv_02(self):
        Data = bytes(
            [
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                86,
                69,
                82,
                83,
                73,
                79,
                78,
                95,
                83,
                84,
                82,
                73,
                78,
                71,
                1,
                18,
                18,
                45,
                32,
                54,
                52,
                98,
                105,
                116,
                32,
                80,
                114,
                111,
                100,
                117,
                99,
                116,
                105,
                111,
                110,
                0,
                1,
                16,
                16,
                65,
                85,
                84,
                72,
                95,
                86,
                69,
                82,
                83,
                73,
                79,
                78,
                95,
                83,
                81,
                76,
                1,
                2,
                2,
                50,
                50,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                88,
                65,
                67,
                84,
                73,
                79,
                78,
                95,
                84,
                82,
                65,
                73,
                84,
                83,
                1,
                1,
                1,
                51,
                0,
                1,
                15,
                15,
                65,
                85,
                84,
                72,
                95,
                86,
                69,
                82,
                83,
                73,
                79,
                78,
                95,
                78,
                79,
                1,
                9,
                9,
                49,
                56,
                54,
                54,
                52,
                55,
                48,
                52,
                48,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                86,
                69,
                82,
                83,
                73,
                79,
                78,
                95,
                83,
                84,
                65,
                84,
                85,
                83,
                1,
                1,
                1,
                48,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                67,
                65,
                80,
                65,
                66,
                73,
                76,
                73,
                84,
                89,
                95,
                84,
                65,
                66,
                76,
                69,
                0,
                0,
                1,
                11,
                11,
                65,
                85,
                84,
                72,
                95,
                68,
                66,
                78,
                65,
                77,
                69,
                1,
                2,
                2,
                88,
                69,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                68,
                66,
                95,
                77,
                79,
                85,
                78,
                84,
                95,
                73,
                68,
                0,
                1,
                10,
                10,
                50,
                56,
                57,
                56,
                53,
                48,
                56,
                54,
                52,
                50,
                0,
                1,
                11,
                11,
                65,
                85,
                84,
                72,
                95,
                68,
                66,
                95,
                73,
                68,
                0,
                1,
                10,
                10,
                50,
                56,
                57,
                51,
                51,
                55,
                48,
                49,
                55,
                55,
                0,
                1,
                12,
                12,
                65,
                85,
                84,
                72,
                95,
                85,
                83,
                69,
                82,
                95,
                73,
                68,
                1,
                1,
                1,
                53,
                0,
                1,
                15,
                15,
                65,
                85,
                84,
                72,
                95,
                83,
                69,
                83,
                83,
                73,
                79,
                78,
                95,
                73,
                68,
                1,
                2,
                2,
                54,
                55,
                0,
                1,
                15,
                15,
                65,
                85,
                84,
                72,
                95,
                83,
                69,
                82,
                73,
                65,
                76,
                95,
                78,
                85,
                77,
                1,
                5,
                5,
                49,
                49,
                50,
                48,
                55,
                0,
                1,
                16,
                16,
                65,
                85,
                84,
                72,
                95,
                73,
                78,
                83,
                84,
                65,
                78,
                67,
                69,
                95,
                78,
                79,
                1,
                1,
                1,
                49,
                0,
                1,
                16,
                16,
                65,
                85,
                84,
                72,
                95,
                70,
                65,
                73,
                76,
                79,
                86,
                69,
                82,
                95,
                73,
                68,
                1,
                1,
                1,
                49,
                0,
                1,
                15,
                15,
                65,
                85,
                84,
                72,
                95,
                83,
                69,
                82,
                86,
                69,
                82,
                95,
                80,
                73,
                68,
                1,
                5,
                5,
                49,
                55,
                51,
                57,
                48,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                83,
                69,
                82,
                86,
                69,
                82,
                95,
                72,
                79,
                83,
                84,
                1,
                12,
                12,
                101,
                57,
                100,
                98,
                52,
                50,
                50,
                55,
                54,
                48,
                49,
                53,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                68,
                66,
                85,
                78,
                73,
                81,
                85,
                69,
                95,
                78,
                65,
                77,
                69,
                1,
                2,
                2,
                88,
                69,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                73,
                78,
                83,
                84,
                65,
                78,
                67,
                69,
                95,
                78,
                65,
                77,
                69,
                1,
                2,
                2,
                88,
                69,
                0,
                1,
                20,
                20,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                83,
                69,
                82,
                86,
                73,
                67,
                69,
                95,
                78,
                65,
                77,
                69,
                1,
                9,
                9,
                83,
                89,
                83,
                36,
                85,
                83,
                69,
                82,
                83,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                73,
                78,
                83,
                84,
                65,
                78,
                67,
                69,
                95,
                73,
                68,
                1,
                1,
                1,
                49,
                0,
                1,
                27,
                27,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                73,
                78,
                83,
                84,
                65,
                78,
                67,
                69,
                95,
                83,
                84,
                65,
                82,
                84,
                95,
                84,
                73,
                77,
                69,
                1,
                36,
                36,
                50,
                48,
                49,
                57,
                45,
                48,
                56,
                45,
                50,
                55,
                32,
                48,
                57,
                58,
                53,
                55,
                58,
                52,
                56,
                46,
                48,
                48,
                48,
                48,
                48,
                48,
                48,
                48,
                48,
                32,
                43,
                48,
                48,
                58,
                48,
                48,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                68,
                66,
                95,
                68,
                79,
                77,
                65,
                73,
                78,
                0,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                83,
                67,
                95,
                83,
                86,
                67,
                95,
                70,
                76,
                65,
                71,
                83,
                1,
                1,
                1,
                48,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                73,
                78,
                83,
                84,
                65,
                78,
                67,
                69,
                78,
                65,
                77,
                69,
                1,
                2,
                2,
                88,
                69,
                0,
                1,
                15,
                15,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                76,
                65,
                78,
                0,
                1,
                8,
                8,
                65,
                77,
                69,
                82,
                73,
                67,
                65,
                78,
                0,
                1,
                22,
                22,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                84,
                69,
                82,
                82,
                73,
                84,
                79,
                82,
                89,
                0,
                1,
                7,
                7,
                65,
                77,
                69,
                82,
                73,
                67,
                65,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                67,
                85,
                82,
                82,
                69,
                78,
                67,
                89,
                0,
                1,
                1,
                1,
                36,
                0,
                1,
                20,
                20,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                73,
                83,
                79,
                67,
                85,
                82,
                82,
                0,
                1,
                7,
                7,
                65,
                77,
                69,
                82,
                73,
                67,
                65,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                78,
                85,
                77,
                69,
                82,
                73,
                67,
                83,
                0,
                1,
                2,
                2,
                46,
                44,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                68,
                65,
                84,
                69,
                70,
                77,
                0,
                1,
                9,
                9,
                68,
                68,
                45,
                77,
                79,
                78,
                45,
                82,
                82,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                68,
                65,
                84,
                69,
                76,
                65,
                78,
                71,
                0,
                1,
                8,
                8,
                65,
                77,
                69,
                82,
                73,
                67,
                65,
                78,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                83,
                79,
                82,
                84,
                0,
                1,
                6,
                6,
                66,
                73,
                78,
                65,
                82,
                89,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                67,
                65,
                76,
                69,
                78,
                68,
                65,
                82,
                0,
                1,
                9,
                9,
                71,
                82,
                69,
                71,
                79,
                82,
                73,
                65,
                78,
                0,
                1,
                21,
                21,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                85,
                78,
                73,
                79,
                78,
                67,
                85,
                82,
                0,
                1,
                1,
                1,
                36,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                84,
                73,
                77,
                69,
                70,
                77,
                0,
                1,
                14,
                14,
                72,
                72,
                46,
                77,
                73,
                46,
                83,
                83,
                88,
                70,
                70,
                32,
                65,
                77,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                83,
                84,
                77,
                80,
                70,
                77,
                0,
                1,
                24,
                24,
                68,
                68,
                45,
                77,
                79,
                78,
                45,
                82,
                82,
                32,
                72,
                72,
                46,
                77,
                73,
                46,
                83,
                83,
                88,
                70,
                70,
                32,
                65,
                77,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                84,
                84,
                90,
                78,
                70,
                77,
                0,
                1,
                18,
                18,
                72,
                72,
                46,
                77,
                73,
                46,
                83,
                83,
                88,
                70,
                70,
                32,
                65,
                77,
                32,
                84,
                90,
                82,
                0,
                1,
                19,
                19,
                65,
                85,
                84,
                72,
                95,
                78,
                76,
                83,
                95,
                76,
                88,
                67,
                83,
                84,
                90,
                78,
                70,
                77,
                0,
                1,
                28,
                28,
                68,
                68,
                45,
                77,
                79,
                78,
                45,
                82,
                82,
                32,
                72,
                72,
                46,
                77,
                73,
                46,
                83,
                83,
                88,
                70,
                70,
                32,
                65,
                77,
                32,
                84,
                90,
                82,
                0,
                1,
                17,
                17,
                65,
                85,
                84,
                72,
                95,
                83,
                86,
                82,
                95,
                82,
                69,
                83,
                80,
                79,
                78,
                83,
                69,
                1,
                96,
                254,
                64,
                70,
                48,
                67,
                48,
                51,
                67,
                48,
                69,
                65,
                57,
                68,
                57,
                51,
                50,
                66,
                66,
                66,
                70,
                67,
                49,
                52,
                52,
                51,
                55,
                51,
                53,
                51,
                53,
                53,
                70,
                69,
                52,
                49,
                68,
                65,
                53,
                65,
                56,
                65,
                50,
                66,
                67,
                52,
                50,
                68,
                68,
                55,
                70,
                48,
                70,
                54,
                70,
                52,
                66,
                48,
                65,
                70,
                49,
                52,
                54,
                56,
                65,
                51,
                52,
                32,
                69,
                57,
                52,
                48,
                50,
                67,
                49,
                53,
                56,
                55,
                57,
                53,
                50,
                48,
                56,
                48,
                48,
                50,
                56,
                66,
                53,
                67,
                52,
                70,
                50,
                51,
                67,
                66,
                69,
                52,
                56,
                66,
                0,
                0,
                4,
                1,
                1,
                1,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                4,
                0,
                0,
            ]
        )
        Remainder = bytes(
            [
                4,
                1,
                1,
                1,
                3,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                4,
                0,
                0,
            ]
        )
        KVs = [
            (b'AUTH_CAPABILITY_TABLE', None),
            (b'AUTH_DBNAME', b'XE'),
            (b'AUTH_DB_ID\x00', b'2893370177'),
            (b'AUTH_DB_MOUNT_ID\x00', b'2898508642'),
            (b'AUTH_FAILOVER_ID', b'1'),
            (b'AUTH_INSTANCENAME', b'XE'),
            (b'AUTH_INSTANCE_NO', b'1'),
            (b'AUTH_NLS_LXCCALENDAR\x00', b'GREGORIAN'),
            (b'AUTH_NLS_LXCCURRENCY\x00', b'$'),
            (b'AUTH_NLS_LXCDATEFM\x00', b'DD-MON-RR'),
            (b'AUTH_NLS_LXCDATELANG\x00', b'AMERICAN'),
            (b'AUTH_NLS_LXCISOCURR\x00', b'AMERICA'),
            (b'AUTH_NLS_LXCNUMERICS\x00', b'.,'),
            (b'AUTH_NLS_LXCSORT\x00', b'BINARY'),
            (b'AUTH_NLS_LXCSTMPFM\x00', b'DD-MON-RR HH.MI.SSXFF AM'),
            (b'AUTH_NLS_LXCSTZNFM\x00', b'DD-MON-RR HH.MI.SSXFF AM TZR'),
            (b'AUTH_NLS_LXCTERRITORY\x00', b'AMERICA'),
            (b'AUTH_NLS_LXCTIMEFM\x00', b'HH.MI.SSXFF AM'),
            (b'AUTH_NLS_LXCTTZNFM\x00', b'HH.MI.SSXFF AM TZR'),
            (b'AUTH_NLS_LXCUNIONCUR\x00', b'$'),
            (b'AUTH_NLS_LXLAN\x00', b'AMERICAN'),
            (b'AUTH_SC_DBUNIQUE_NAME', b'XE'),
            (b'AUTH_SC_DB_DOMAIN', None),
            (b'AUTH_SC_INSTANCE_ID', b'1'),
            (b'AUTH_SC_INSTANCE_NAME', b'XE'),
            (b'AUTH_SC_INSTANCE_START_TIME', b'2019-08-27 09:57:48.000000000 +00:00'),
            (b'AUTH_SC_SERVER_HOST', b'e9db42276015'),
            (b'AUTH_SC_SERVICE_NAME', b'SYS$USERS'),
            (b'AUTH_SC_SVC_FLAGS', b'0'),
            (b'AUTH_SERIAL_NUM', b'11207'),
            (b'AUTH_SERVER_PID', b'17390'),
            (b'AUTH_SESSION_ID', b'67'),
            (
                b'AUTH_SVR_RESPONSE',
                b'F0C03C0EA9D932BBBFC1443735355FE41DA5A8A2BC42DD7F0F6F4B0AF1468A34E9402C1587952080028B5C4F23CBE48B',
            ),
            (b'AUTH_USER_ID', b'5'),
            (b'AUTH_VERSION_NO', str(VERSION_11_2_0_2).encode()),
            (b'AUTH_VERSION_SQL', b'22'),
            (b'AUTH_VERSION_STATUS', b'0'),
            (b'AUTH_VERSION_STRING', b'- 64bit Production'),
            (b'AUTH_XACTION_TRAITS', b'3'),
        ]
        self.assertEqual(decode_kv(Data, 39, []), (KVs, Remainder))


class TestDcbColumnFv17Domain(unittest.TestCase):
    """23ai (field version 17) per-column SQL-domain metadata (#53). Fixtures
    are the real per-column DCB bytes captured from a 23ai server: a plain
    NUMBER column and a NUMBER column using a SQL domain (PYO.PYO_DOM)."""

    # NUMBER column 'A', no domain — the two trailing fields are empty (`00 00`)
    PLAIN = bytes.fromhex('0200008101160000000000000000010101010141000000000000')
    # NUMBER column 'B' using SQL domain PYO.PYO_DOM — schema/name as
    # ub4-counted DALC strings (`01 03 03 'PYO' 01 07 07 'PYO_DOM'`).
    DOMAIN = bytes.fromhex(
        '020000810116000000000000000001010101014200000002400001030350'
        '594f01070750594f5f444f4d'
    )

    def _decode_at_fv17(self, data):
        from seerdb.common.tns import _DECODE_FIELD_VERSION, _decode_dcb_column

        tok = _DECODE_FIELD_VERSION.set(17)
        try:
            return _decode_dcb_column(data)
        finally:
            _DECODE_FIELD_VERSION.reset(tok)

    def test_plain_column_has_no_domain_and_consumes_all(self):
        col, rest = self._decode_at_fv17(self.PLAIN)
        self.assertEqual(col['domain_schema'], None)
        self.assertEqual(col['domain_name'], None)
        self.assertEqual(rest, b'')  # no desync: every byte consumed

    def test_domain_column_parses_schema_name_and_consumes_all(self):
        col, rest = self._decode_at_fv17(self.DOMAIN)
        self.assertEqual(col['domain_schema'], b'PYO')
        self.assertEqual(col['domain_name'], b'PYO_DOM')
        self.assertEqual(col['data_type'], 2)  # NUMBER
        self.assertEqual(rest, b'')  # the bug was leaving bytes here


class TestDcbColumnFv24Annotations(unittest.TestCase):
    """23ai (field version 24) per-column annotation map + vector descriptor
    (#89). Fixture is the real per-column DCB bytes captured from a 23ai server
    for a NUMBER column 'A' annotated with `Mykey 'Myval'` and a name-only
    `Flag`. The annotation block (count sent twice around a pointer, each pair
    trailed by a ub4 flags) and the trailing vector descriptor must be fully
    consumed or the row stream desyncs."""

    ANNOTATED = bytes.fromhex(
        '020000810116000000000000000001010101014100000002800000000101100102'
        '160105054d594b45590105054d7976616c00010404464c4147000000000000'
    )

    def _decode_at_fv24(self, data):
        from seerdb.common.tns import _DECODE_FIELD_VERSION, _decode_dcb_column

        tok = _DECODE_FIELD_VERSION.set(24)
        try:
            return _decode_dcb_column(data)
        finally:
            _DECODE_FIELD_VERSION.reset(tok)

    def test_annotations_decode_and_consume_all(self):
        col, rest = self._decode_at_fv24(self.ANNOTATED)
        self.assertEqual(col['data_type'], 2)  # NUMBER
        self.assertEqual(col['annotations'], {b'MYKEY': b'Myval', b'FLAG': b''})
        self.assertEqual(rest, b'')  # full per-column consume, no desync


class TestDcbColumnTailBy23aiFieldVersion(unittest.TestCase):
    """The annotation map and vector descriptor each start at their own field
    version. Fixtures are 23ai's replies to `select sysdate, user from dual`
    from a client capped at 18, 20 and 24: the describe, one row and ORA-01403.
    A column carries nothing after its domain at 18, the annotation count at
    20, and the vector descriptor too at 24. Reading both from 18 failed every
    query at 18 and 19, and a two-column one at 20 to 23."""

    PREFIX = (
        '10172e9128967ec28e03607a6eb4ef1c61ff787e0b0215032101870102820c0000000101'
        '0000000000000000010701070753595344415445000000000000'
    )
    REPLIES = {
        18: (
            '01800000018000000000020369010180023ffe0104010404555345520000010100000001'
            '0707787e0b0215052200021fe80102010200062201020001640000000707787e0b021505'
            '220350594f08010604016ceac0000101000000000000040101025969010102057b000001'
            '010003000000000000000000000000070001010000000002057b0101010300194f52412d'
            '30313430333a206e6f206461746120666f756e640a1d'
        ),
        20: (
            '0001800000018000000000020369010180023ffe01040104045553455200000101000000'
            '00010707787e0b0215042f00021fe80102010200062201020001640000000707787e0b02'
            '15042f0350594f08010604016ceaa9000101000000000000040101024718010102057b00'
            '0001010003000000000000000000000000070001010000000002057b0101010300194f52'
            '412d30313430333a206e6f206461746120666f756e640a1d'
        ),
        24: (
            '0000000001800000018000000000020369010180023ffe01040104045553455200000101'
            '00000000000000010707787e0b0215043a00021fe8010201020006220102000164000000'
            '0707787e0b0215043a0350594f08010604016ceab200010100000000000004010102471c'
            '010102057b000001010003000000000000000000000000070001010000000002057b0101'
            '010300194f52412d30313430333a206e6f206461746120666f756e640a1d'
        ),
    }

    def test_each_reply_decodes_at_its_field_version(self):
        import contextvars

        from seerdb.common.tns import decode_packet

        for fv, tail in self.REPLIES.items():
            with self.subTest(field_version=fv):
                body = bytes.fromhex(self.PREFIX + tail)
                # decode_packet pins the session's field version, which must
                # not outlive the test: run it in a copy of the context.
                result = contextvars.copy_context().run(
                    decode_packet, body, (None, None, []), fv
                )
                columns = result[3][1]
                self.assertEqual(
                    [c['column_name'] for c in columns], [b'SYSDATE', b'USER']
                )
                # The row and the closing error read cleanly only when each
                # column was consumed exactly.
                self.assertEqual(result[4][0][1], 'PYO')
                self.assertEqual(result[1], 1403)


class TestFv2Describe(unittest.TestCase):
    """Oracle 9i (field version 2) describe-in-RPA decode (#97, PROTOCOL §19.1).
    Fixture is the real 0x62-describe RPA captured from a live 9.2.0.4 server for
    `select cast(1 as number(9,4)) zqnum, cast('x' as varchar2(20)) zqvc,
    cast('y' as char(6)) zqchr, sysdate zqdate, cast(2 as integer) zqint`."""

    DESCRIBE = bytes.fromhex(
        '08010502000000011600000000000001050105055a514e554d000001800000'
        '011400000000011f0101040104045a515643000060800000010600000000011f'
        '0101050105055a5143485200000c000000010100000000000001060106065a51'
        '44415445000002000000011600000000000001050105055a51494e5400000400'
        '0000000101000300000000000000000000000000000101'
    )

    # Real describe RPA for `SELECT usernameX, usernameY FROM t9d` where t9d is
    # `(usernameX VARCHAR2(8) NOT NULL, usernameY VARCHAR2(8))`. The two columns
    # have identical-length names and differ ONLY in nullability, isolating the
    # per-column null_ok byte: NOT NULL -> 00, nullable -> 01. This is the case
    # every DUAL-alias fixture above misses (a literal is always nullable, so its
    # null_ok is 0x01 and the old two-ub4 read slipped by only when it hit 0x00).
    # A NOT-NULL column previously garbled the name to b'\x08USERNAM' and desynced
    # the stream (a multi-column NOT-NULL fetch then died with ORA-03115). #97.
    DESCRIBE_NOTNULL = bytes.fromhex(
        '08010201800000010800000000011f010009010909555345524e414d455800'
        '0001800000010800000000011f010109010909555345524e414d4559000004'
        '00000000010100030000000000000000000000000000010100000000'
    )

    def test_decode_columns(self):
        from seerdb.common.tns import decode_fv2_describe

        cols = decode_fv2_describe(self.DESCRIBE)
        got = [(c['column_name'], c['data_type']) for c in cols]
        # type codes == TNS_TYPE_*: VARCHAR2 1, NUMBER 2, CHAR 96, DATE 12
        self.assertEqual(
            got,
            [
                (b'ZQNUM', 2),
                (b'ZQVC', 1),
                (b'ZQCHR', 96),
                (b'ZQDATE', 12),
                (b'ZQINT', 2),
            ],
        )
        # literals over DUAL are always nullable
        self.assertEqual([c['null_ok'] for c in cols], [1, 1, 1, 1, 1])

    def test_decode_notnull_columns(self):
        # Regression: a NOT-NULL column (null_ok byte 0x00) must not slip the
        # stream, and null_ok must be reported per column.
        from seerdb.common.tns import decode_fv2_describe

        cols = decode_fv2_describe(self.DESCRIBE_NOTNULL)
        self.assertEqual(
            [(c['column_name'], c['data_type'], c['null_ok']) for c in cols],
            [(b'USERNAMEX', 1, 0), (b'USERNAMEY', 1, 1)],
        )


class TestFv2ExecResponse(unittest.TestCase):
    """Oracle 9i (field version 2) execute+fetch row-stream decode (#97,
    PROTOCOL §19.2): RXH + per-row RXD + short OER (ORA-01403 = end-of-fetch).
    Fixtures are real responses from a live 9.2.0.4 server."""

    # SELECT 42 AS n FROM DUAL — one NUMBER column, one row (value c1 2b = 42).
    # Recaptured for #2284: the #97 fixture's status had lost its rowid and the
    # four zeros before the message, which the status schema reads.
    NUM = bytes.fromhex(
        '0602010100010a0000000702c12b0004010102057b0000010100030000000000'
        '0302e4db01010002b892010200000000010100000000194f52412d3031343033'
        '3a206e6f206461746120666f756e640a'
    )
    # SELECT id, name, created FROM t97 — NUMBER/VARCHAR2/DATE, three rows, the
    # middle row has NULL name + NULL created (null indicator 81 01).
    NULLROWS = bytes.fromhex(
        '0602010300010a0000000702c1020005616c6963650007787e06111115080007'
        '02c103000081010081010702c10400056361726f6c0007787e06111115080004'
        '010302057b00000101000300000000000302e4db01010002b892010200000000'
        '010100000000194f52412d30313430333a206e6f206461746120666f756e640a'
    )

    def test_single_number_row(self):
        from seerdb.common.tns import decode_fv2_exec_response

        cols = [{'data_type': 2}]
        rows, err = decode_fv2_exec_response(self.NUM, cols)
        self.assertEqual(err, 1403)  # end-of-fetch marker
        self.assertEqual(rows, [[42]])

    def test_nulls_do_not_desync_rows(self):
        from seerdb.common.tns import decode_fv2_exec_response

        cols = [{'data_type': 2}, {'data_type': 1}, {'data_type': 12}]
        rows, err = decode_fv2_exec_response(self.NULLROWS, cols)
        self.assertEqual(err, 1403)
        # All three rows present; the NULL row's value columns decode to None.
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0][0], 1)
        self.assertEqual(rows[0][1], 'alice')
        self.assertEqual(rows[1][0], 2)
        self.assertEqual(rows[1][1], None)
        self.assertEqual(rows[1][2], None)
        self.assertEqual(rows[2][1], 'carol')

    def test_both_row_header_forms_read(self):
        # 9.2.0.4 ends the row header with the bit vector's and the rowid's
        # lengths for seerdb (NUM, `... 01 0a 00 00 00`), and without them for
        # ojdbc14, whose capture the REF CURSOR's rows are: `... 01 0a 00` and
        # the row's 07 straight after (#2284).
        from seerdb.common.tns import decode_fv2_describe, decode_fv2_exec_response

        self.assertEqual(
            decode_fv2_exec_response(self.NUM, [{'data_type': 2}]), ([[42]], 1403)
        )
        cols = decode_fv2_describe(TestFv2RefCursor.DESCRIBE)
        (rows, _) = decode_fv2_exec_response(TestFv2RefCursor.ROWS, cols)
        self.assertEqual(rows[0], [1, 'row 1'])

    def test_a_row_header_with_a_bit_vector_is_refused(self):
        # The vector would say which columns repeat the row before and send
        # nothing (#181); 9.2.0.4 sends none, and a row read without it would
        # be misread from the first repeat on.
        from seerdb.common.exceptions import DataError
        from seerdb.common.tns import decode_fv2_exec_response

        # NUM's header with a one-byte vector: its length, the vector as a
        # value (`01 01`), and no rowid.
        header = bytes.fromhex('0602010100010a00') + bytes.fromhex('01010101') + b'\x00'
        with self.assertRaises(DataError):
            decode_fv2_exec_response(header + self.NUM[10:], [{'data_type': 2}])

    def test_an_error_the_fetch_met_keeps_its_message(self):
        # `SELECT 1/0 FROM dual`: no rows, ORA-01476 and its text. Raised from
        # the code alone, it read `ORA-01476` (#2315). The end of a fetch,
        # ORA-01403, needs no text.
        from seerdb.common.tns import decode_fv2_exec_status

        failed = bytes.fromhex(
            '04000205c4000001010108030000000000000000000000000000010100000000'
            '244f52412d30313437363a2064697669736f7220697320657175616c20746f20'
            '7a65726f0a'
        )
        cols = [{'data_type': 2}]
        self.assertEqual(
            decode_fv2_exec_status(failed, cols),
            ([], 1476, 'ORA-01476: divisor is equal to zero'),
        )
        self.assertEqual(decode_fv2_exec_status(self.NUM, cols), ([[42]], 1403, None))


class TestFv2ZeroLengthColumn(unittest.TestCase):
    """A 9i column described with a zero data length sends only the NULL
    indicator, no value (#1185). Real 9.2.0.4 replies."""

    # SELECT NULL AS a FROM dual
    ALONE = bytes.fromhex(
        '0602010100010a00000007810104010102057b000001010003000000000000'
        '0000000000000000010100000000194f52412d30313430333a206e6f206461'
        '746120666f756e640a'
    )
    # SELECT NULL AS a, 5 AS b FROM dual
    BEFORE_A_VALUE = bytes.fromhex(
        '0602010200010a00000007810102c1060004010102057b0000010100030000'
        '000000000000000000000000010100000000194f52412d30313430333a206e'
        '6f206461746120666f756e640a'
    )

    def test_it_is_null(self):
        from seerdb.common.tns import decode_fv2_exec_response

        cols = [{'data_type': 1, 'data_length': 0}]
        self.assertEqual(decode_fv2_exec_response(self.ALONE, cols), ([[None]], 1403))

    def test_it_does_not_swallow_the_next_column(self):
        from seerdb.common.tns import decode_fv2_exec_response

        cols = [
            {'data_type': 1, 'data_length': 0},
            {'data_type': 2, 'data_length': 2},
        ]
        rows = decode_fv2_exec_response(self.BEFORE_A_VALUE, cols)
        self.assertEqual(rows, ([[None, 5]], 1403))


class TestFv2LongRows(unittest.TestCase):
    """Oracle 9i LONG columns in a batch fetch (#102): the value is a chunked
    DALC (0xfe form), no trailing descriptor. Fixture is a real response for
    `SELECT id, l FROM lobtest` — LONG 'aaaa', LONG 20×'b', and a NULL LONG."""

    RESP = bytes.fromhex(
        '0602010200010a0000000702c10200fe046161616100000702c10300fe14'
        '626262626262626262626262626262626262626200000702c10400008101'
        '04010302057b00000101000300000000000000000000000000000101194f'
        '52412d30313430333a206e6f206461746120666f756e640a'
    )

    def test_long_values_and_null(self):
        from seerdb.common.tns import decode_fv2_exec_response

        cols = [{'data_type': 2}, {'data_type': 8, 'charset': 873}]
        rows, err = decode_fv2_exec_response(self.RESP, cols)
        self.assertEqual(err, 1403)
        self.assertEqual(rows, [[1, 'aaaa'], [2, 'b' * 20], [3, None]])


class TestFv2LobRead(unittest.TestCase):
    """Oracle 9i CLOB / BLOB read (#102, PROTOCOL §19.5). 9i hands a LOB cell as
    a locator in the RXD, then the client pulls the content with a two-call
    TTI_LOBOPS GETLEN + READ sequence (the modern single READ returns empty).
    All fixtures are real frames from a live 9.2.0.4 server, query
    `SELECT c, b FROM lobtest WHERE id = 1` (c = CLOB 'hello clob content',
    b = BLOB ca fe ba be 01)."""

    # Execute+fetch response: RXH, one RXD with the CLOB + BLOB locators, OER 1403.
    RXD = bytes.fromhex(
        '0602010200010a000701565600540001020c00000001000000010000000054f7'
        '00007bdd00007bdc00020002001f000000000000000000000000000000000000'
        '000709df000000000000000000000000000000000000000000007bdc0040b89a'
        '00000001565600540001010c00000001000000010000000054f800007bdf0000'
        '7bdc000300030000020200000000000000000000000000000000000709df0000'
        '00000000000000000000000000000000000000007bdc0040b89a000000040101'
        '02057b00000101000300000000000000000000000000000101194f52412d3031'
        '3430333a206e6f206461746120666f756e640a'
    )
    # GETLEN / READ requests + responses captured for the CLOB column.
    GETLEN_REQ = bytes.fromhex(
        '036000010156000000000001000101000000540001020c000000010000000100'
        '00000054f700007bdd00007bdc00020002001f00000000000000000000000000'
        '0000000000000709df000000000000000000000000000000000000000000007b'
        'dc0040b89a000000'
    )
    GETLEN_RESP = bytes.fromhex(
        '0800540001020c00000001000000010000000054f700007bdd00007bdc000200'
        '02001f000000000000000000000000000000000000000709df00000000000000'
        '0000000000000000000000000000007bdc0040b89a0000011204010100000000'
        '000000000000000000000000000000000101'
    )
    READ_REQ = bytes.fromhex(
        '03600001015600000101000001000102000000540001020c0000000100000001'
        '0000000054f700007bdd00007bdc00020002001f000000000000000000000000'
        '000000000000000709df00000000000000000000000000000000000000000000'
        '7bdc0040b89a00000112'
    )
    READ_RESP = bytes.fromhex(
        '0efe1268656c6c6f20636c6f6220636f6e74656e74000800540001020c000000'
        '01000000010000000054f700007bdd00007bdc00020002001f00000000000000'
        '0000000000000000000000000709df0000000000000000000000000000000000'
        '00000000007bdc0040b89a000001120401010000000000000000000000000000'
        '0000000000000101'
    )

    def _locators(self):
        from seerdb.common.lob import LOB
        from seerdb.common.tns import decode_fv2_exec_response

        cols = [{'data_type': 112, 'charset': 31}, {'data_type': 113}]
        rows, err = decode_fv2_exec_response(self.RXD, cols)
        self.assertEqual(err, 1403)
        self.assertEqual(len(rows), 1)
        self.assertIsInstance(rows[0][0], LOB)
        self.assertIsInstance(rows[0][1], LOB)
        return rows[0]

    def test_rxd_yields_lob_locators(self):
        clob, blob = self._locators()
        self.assertEqual(clob.data_type, 112)
        self.assertEqual(blob.data_type, 113)
        # _read_lob_column returns the 86-byte `00 54 <84-byte locator>` block.
        self.assertEqual(len(clob.raw), 86)
        self.assertEqual(clob.raw[:2].hex(), '0054')

    def test_getlen_request_matches_capture(self):
        from seerdb.common.tns import encode_o7_lob_getlen

        clob, _ = self._locators()
        self.assertEqual(encode_o7_lob_getlen(0, clob.raw), self.GETLEN_REQ)

    def test_getlen_response_amount(self):
        from seerdb.common.tns import decode_fv2_lob_getlen

        self.assertEqual(decode_fv2_lob_getlen(self.GETLEN_RESP), 18)

    def test_read_request_matches_capture(self):
        from seerdb.common.tns import encode_o7_lob_read

        clob, _ = self._locators()
        self.assertEqual(encode_o7_lob_read(0, clob.raw, 18), self.READ_REQ)

    def test_clob_content_decodes(self):
        # The READ response content chunk (0e fe 12 <18 bytes>) decodes to the
        # CLOB text under the column charset (single-byte, not UTF-16BE).
        from seerdb.common.types import decode_fv2_lob

        content = bytes.fromhex('68656c6c6f20636c6f6220636f6e74656e74')
        self.assertEqual(decode_fv2_lob(112, content, 31), 'hello clob content')

    def test_blob_content_stays_bytes(self):
        from seerdb.common.types import decode_fv2_lob

        self.assertEqual(
            decode_fv2_lob(113, bytes.fromhex('cafebabe01'), 0),
            bytes.fromhex('cafebabe01'),
        )

    def test_empty_lob(self):
        from seerdb.common.types import decode_fv2_lob

        self.assertEqual(decode_fv2_lob(112, b'', 31), '')
        self.assertEqual(decode_fv2_lob(113, b'', 0), b'')

    def test_null_lob_row_decodes_to_none(self):
        # A row with NULL CLOB + NULL BLOB. The NULL LOB uses the scalar
        # empty-value form `00 81 01` (not the locator form), and must not
        # desync the following columns. Real RXD from a live 9.2.0.4 server,
        # `SELECT id, c, b FROM lobtest WHERE id = 95` with all-NULL LOBs.
        from seerdb.common.tns import decode_fv2_exec_response

        rxd = bytes.fromhex(
            '0602010100010a000702c15f0000810100810104010102057b0000010100'
            '0300000000000000000000000000000101194f52412d30313430333a206e'
            '6f206461746120666f756e640a'
        )
        cols = [{'data_type': 2}, {'data_type': 112, 'charset': 31}, {'data_type': 113}]
        rows, err = decode_fv2_exec_response(rxd, cols)
        self.assertEqual(err, 1403)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 94)  # id (c15f = 94)
        self.assertIsNone(rows[0][1])  # NULL CLOB
        self.assertIsNone(rows[0][2])  # NULL BLOB

    def test_chunk_parser_complete_and_terminator(self):
        # decode_fv2_lob_chunks pulls the content out of a `0e fe <chunks> 00`
        # reply and reports completion at the zero-length terminator. This
        # mirrors the multi-row READ reply, which has NO trailing OER.
        from seerdb.common.tns import decode_fv2_lob_chunks

        content, done = decode_fv2_lob_chunks(self.READ_RESP)
        self.assertTrue(done)
        self.assertEqual(content, b'hello clob content')

    def test_chunk_parser_multichunk(self):
        from seerdb.common.tns import decode_fv2_lob_chunks

        # 0e fe, two 64-byte chunks + one 2-byte chunk, then 00 terminator.
        body = (
            b'\x0e\xfe'
            + b'\x40'
            + b'A' * 64
            + b'\x40'
            + b'B' * 64
            + b'\x02'
            + b'CD'
            + b'\x00'
        )
        content, done = decode_fv2_lob_chunks(body)
        self.assertTrue(done)
        self.assertEqual(content, b'A' * 64 + b'B' * 64 + b'CD')

    def test_chunk_parser_incomplete_then_complete(self):
        # A chunk split across packets: the first slice is incomplete, the full
        # buffer completes. (The reader re-parses the accumulated buffer.)
        from seerdb.common.tns import decode_fv2_lob_chunks

        part1 = b'\x0e\xfe\x40' + b'A' * 30  # 64-byte chunk, only 30 here
        content, done = decode_fv2_lob_chunks(part1)
        self.assertFalse(done)
        full = b'\x0e\xfe\x40' + b'A' * 64 + b'\x00'
        content, done = decode_fv2_lob_chunks(full)
        self.assertTrue(done)
        self.assertEqual(content, b'A' * 64)


class TestFv2OerError(unittest.TestCase):
    """fv2 OER error + message extraction (#102). Fixture is a real parse-time
    error from a live 9.2.0.4 server (SELECT from a nonexistent table)."""

    BAD_TABLE = bytes.fromhex(
        '04000203ae00000101010e000000000000000000000000000000000000'
        '0000284f52412d30303934323a207461626c65206f722076696577206'
        '46f6573206e6f742065786973740a'
    )

    def test_decodes_code_and_message(self):
        from seerdb.common.tns import decode_fv2_oer_error

        code, msg = decode_fv2_oer_error(self.BAD_TABLE)
        self.assertEqual(code, 942)
        self.assertEqual(msg, 'ORA-00942: table or view does not exist')

    # A live 9.2.0.4 server refusing a COMMIT (a deferred primary key violated,
    # #1786): the code follows the call status directly, a field earlier than in
    # the 10g+ OER, and the two-line message comes in the chunked form.
    # Recaptured for #2284: the #1786 fixture had one zero byte more before the
    # rowid than the server sends.
    REFUSED_COMMIT = bytes.fromhex(
        '04010102082b000000000000000000000302e4d901010002b96a010100000700'
        '010100000000fe404f52412d30323039313a207472616e73616374696f6e2072'
        '6f6c6c6564206261636b0a4f52412d30303030313a20756e6971756520636f6e'
        '73747261696e74201c2850594f2e43323238345f4445465f504b292076696f6c'
        '617465640a00'
    )

    def test_decodes_a_refused_commit(self):
        from seerdb.common.tns import decode_fv2_oer_error

        code, msg = decode_fv2_oer_error(self.REFUSED_COMMIT)
        self.assertEqual(code, 2091)
        assert msg is not None
        self.assertTrue(msg.startswith('ORA-02091: transaction rolled back\nORA-00001'))

    def test_non_oer_is_no_error(self):
        from seerdb.common.tns import decode_fv2_oer_error

        # An RPA (08) token is not an error.
        self.assertEqual(decode_fv2_oer_error(bytes.fromhex('08010109')), (0, None))


class TestFv2DmlResponse(unittest.TestCase):
    """Oracle 9i DML over TTI_ALL7 (#101): RPA piggyback + short OER whose first
    field is the affected-row count. Fixture is a real UPDATE response (2 rows)
    from a live 9.2.0.4 server."""

    UPDATE_2ROWS = bytes.fromhex(
        '0801020306bbe00004010200000001010107060000000000027bdb0101'
        '0002b89201050000000001'
    )

    def test_rowcount_and_success(self):
        from seerdb.common.tns import decode_fv2_dml_response

        rowcount, ora_code = decode_fv2_dml_response(self.UPDATE_2ROWS)
        self.assertEqual(rowcount, 2)
        self.assertEqual(ora_code, 0)


class TestFv2Block(unittest.TestCase):
    """Oracle 9i anonymous PL/SQL block over TTI_ALL7 (#102, PROTOCOL §19.6).
    A block uses its own ALL7 option word (`01 21` / `02 04 29`, not the DML
    `02 80 xx`), and sends bind values in a SEPARATE round-trip after a server
    prompt rather than inline. All fixtures are real frames from a live 9.2.0.4
    server: `BEGIN NULL; END;` and `BEGIN DBMS_OUTPUT.PUT_LINE(:1); END;`."""

    NOARG_REQ = bytes.fromhex(
        '0347000121010101011000000101070101020000000000424547494e204e554c'
        '4c3b20454e443b010101010000000000'
    )
    NOARG_RESP = bytes.fromhex(
        '08010203073450000401010000000101002f00000000000000000000000000000101'
    )
    INBIND_REQ = bytes.fromhex(
        '03470002042901010101240000010107010102000000010101424547494e2044'
        '424d535f4f55545055542e5055545f4c494e45283a31293b20454e443b010101'
        '01000000000001010000027fff00000000011f01'
    )
    INBIND_VAL = bytes.fromhex('070768656c6c6f3969')
    INBIND_RESP = bytes.fromhex(
        '0801020307355e000401010000000101002f00000000000000000000000000000101'
    )

    def test_noarg_request_matches_capture(self):
        from seerdb.common.tns import encode_o7_block

        self.assertEqual(encode_o7_block(0, 'BEGIN NULL; END;'), self.NOARG_REQ)

    def test_noarg_response_success(self):
        from seerdb.common.tns import decode_fv2_dml_response

        _rowcount, ora_code = decode_fv2_dml_response(self.NOARG_RESP)
        self.assertEqual(ora_code, 0)

    def test_inbind_request_option_and_no_inline_value(self):
        from seerdb.common.tns import encode_o7_block

        got = encode_o7_block(0, 'BEGIN DBMS_OUTPUT.PUT_LINE(:1); END;', ['hello9i'])
        # Block-with-binds option word, not the DML 02 80 29.
        self.assertEqual(got[3:6], bytes.fromhex('020429'))
        # The bind VALUE must NOT be appended inline (it goes in a separate RXD).
        self.assertNotIn(b'hello9i', got)
        # Byte-identical to the capture except two intentional bind-OAC
        # differences: the max_size (we declare VARCHAR 4000 = 02 0fa0; JDBC
        # declares 32767 = 02 7fff) and the charset (we declare our AL32UTF8
        # session charset 02 0369; the capture has the JDBC client's DB charset
        # 01 1f, #174).
        Normalised = got.replace(
            bytes.fromhex('020fa0'), bytes.fromhex('027fff')
        ).replace(bytes.fromhex('020369'), bytes.fromhex('011f'))
        self.assertEqual(Normalised, self.INBIND_REQ)

    def test_inbind_value_frame_matches_capture(self):
        from seerdb.common.tns import encode_tokens_rxd

        self.assertEqual(encode_tokens_rxd(['hello9i'], b''), self.INBIND_VAL)

    def test_inbind_final_response_success(self):
        from seerdb.common.tns import decode_fv2_dml_response

        _rowcount, ora_code = decode_fv2_dml_response(self.INBIND_RESP)
        self.assertEqual(ora_code, 0)


class TestFv2OutBinds(unittest.TestCase):
    """Oracle 9i PL/SQL block OUT / IN OUT binds (#102, PROTOCOL §19.7). The
    bind mode isn't in the OAC; the server returns OUT / IN OUT values as a
    TTI_RXD (one DALC value + indicator per OUT bind, position order) before the
    RPA + OER. Fixtures are real frames from a live 9.2.0.4 server."""

    # BEGIN :1 := 42; END;  with :1 a pure-OUT number — parse-exec + the reply
    # (bind prompt + return RXD '07 02 c12b 00'(=42) + RPA + OER, one packet).
    OUTNUM_REQ = bytes.fromhex(
        '03470002042901010101140000010107010102000000010101424547494e203a'
        '31203a3d2034323b20454e443b01010101000000000006010000011600000000'
        '011f01'
    )
    OUTNUM_RESP = bytes.fromhex(
        '0b05010100010100100702c12b0008010203074790000401010000000101002f'
        '00000000000000000000000000000101'
    )
    # The same block's reply as seerdb gets it, captured for #2284.
    OUTNUM_LIVE = bytes.fromhex(
        '0b050101000101000000100702c12b000801020402100f96000401010000000101'
        '002f0000000000000000000000000000010100000000'
    )
    # IN OUT string reply: return RXD '07 04 696e5f6f 00'(=in_o) + RPA + OER.
    INOUT_RESP = bytes.fromhex(
        '0704696e5f6f00080102030747e9000401010000000101002f00000000000000'
        '000000000000000101'
    )
    # Mixed (:1 IN, :2 IN OUT, :3 OUT) reply: 2 return values '4241'(BA),'42'(B).
    MIXED_RESP = bytes.fromhex(
        '070242410001420008010203074c43000401010000000101002f000000000000'
        '00000000000000000101'
    )

    def test_var_oac_number_is_varnum(self):
        from seerdb.common import datatypes as dt
        from seerdb.common.tns import _o7_bind_oac

        self.assertEqual(
            _o7_bind_oac(dt.Var(int)), bytes.fromhex('06010000011600000000011f01')
        )

    def test_var_oac_string_size_32767(self):
        from seerdb.common import datatypes as dt
        from seerdb.common.tns import _o7_bind_oac

        # VARCHAR OUT buffer is 0x7fff (matching JDBC), not the 4000 of an
        # inline str IN bind. The OAC declares AL32UTF8 (02 0369), the driver's
        # session charset, where the JDBC capture declared its DB charset (#174).
        self.assertEqual(
            _o7_bind_oac(dt.Var(str)), bytes.fromhex('01010000027fff0000000002036901')
        )

    def test_var_oac_rowid_is_the_rowid_text(self):
        import seerdb
        from seerdb.common import datatypes as dt
        from seerdb.common.tns import _encode_8i_bind_oac, _o7_bind_oac

        # A ROWID / UROWID Var declares a VARCHAR of the longest universal rowid,
        # 5267 (0x1493) characters, on 9i and 8i as on 10g+. Declared as its own
        # type, 9i answered with a garbled error and 8i dropped the session
        # (#1399). 8i writes the size little-endian.
        for typ in (seerdb.ROWID, seerdb.DB_TYPE_UROWID):
            self.assertEqual(
                _o7_bind_oac(dt.Var(typ)),
                bytes.fromhex('010100000214930000000002036901'),
            )
            self.assertEqual(
                _encode_8i_bind_oac(dt.Var(typ)),
                bytes.fromhex('010300009314000000000000000000000000000000001f0001'),
            )

    def test_oac_datetime_declares_temporal_type(self):
        # A datetime/date inline bind must declare the matching Oracle temporal
        # type (#172) — the value encoder emits 7/11/13 binary bytes, so a
        # VARCHAR OAC would make the server fail the implicit conversion
        # (ORA-01858). type byte + max-size must match the value width.
        import datetime

        from seerdb.common.tns import (
            _o7_bind_oac,
        )
        from seerdb.common.tns_consts import (
            TNS_TYPE_DATE,
            TNS_TYPE_TIMESTAMP,
            TNS_TYPE_TIMESTAMPTZ,
        )

        # OAC layout: type, 01, 00, 00, encode_sb4(max_size), ...; encode_sb4 is
        # length-prefixed (01 07) so the width value sits at offset 5.
        date_oac = _o7_bind_oac(datetime.datetime(2026, 6, 21, 1, 2, 3))
        self.assertEqual((date_oac[0], date_oac[5]), (TNS_TYPE_DATE, 7))
        ts_oac = _o7_bind_oac(datetime.datetime(2026, 6, 21, 1, 2, 3, 500000))
        self.assertEqual((ts_oac[0], ts_oac[5]), (TNS_TYPE_TIMESTAMP, 11))
        tz_oac = _o7_bind_oac(
            datetime.datetime(2026, 6, 21, tzinfo=datetime.timezone.utc)
        )
        self.assertEqual((tz_oac[0], tz_oac[5]), (TNS_TYPE_TIMESTAMPTZ, 13))
        self.assertEqual(_o7_bind_oac(datetime.date(2026, 6, 21))[0], TNS_TYPE_DATE)

    def test_oac_interval_declares_interval_type(self):
        # INTERVAL DS/YM inline binds must declare the matching interval type
        # (#173); a VARCHAR OAC over the binary value gives ORA-01867.
        import datetime

        from seerdb.common.datatypes import IntervalYM
        from seerdb.common.tns import (
            _o7_bind_oac,
        )
        from seerdb.common.tns_consts import (
            TNS_TYPE_INTERVALDS,
            TNS_TYPE_INTERVALYM,
        )

        ds = _o7_bind_oac(datetime.timedelta(days=2, seconds=5))
        self.assertEqual((ds[0], ds[5]), (TNS_TYPE_INTERVALDS, 11))
        ym = _o7_bind_oac(IntervalYM(2, 6))
        self.assertEqual((ym[0], ym[5]), (TNS_TYPE_INTERVALYM, 5))

    def test_outnum_request_matches_capture(self):
        from seerdb.common import datatypes as dt
        from seerdb.common.tns import encode_o7_block

        self.assertEqual(
            encode_o7_block(0, 'BEGIN :1 := 42; END;', [dt.Var(int)]), self.OUTNUM_REQ
        )

    def test_decode_pure_out_number(self):
        from seerdb.common.tns import decode_fv2_block_out

        out, _rc, err = decode_fv2_block_out(self.OUTNUM_RESP, 1)
        self.assertEqual(err, 0)
        self.assertEqual(out, [bytes.fromhex('c12b')])  # Oracle number 42

    def test_decode_inout(self):
        from seerdb.common.tns import decode_fv2_block_out

        out, _rc, err = decode_fv2_block_out(self.INOUT_RESP, 1)
        self.assertEqual(out, [b'in_o'])

    def test_decode_mixed_two_outs(self):
        from seerdb.common.tns import decode_fv2_block_out

        out, _rc, err = decode_fv2_block_out(self.MIXED_RESP, 2)
        self.assertEqual(out, [b'BA', b'B'])

    def test_both_io_vector_forms_read(self):
        # 9.2.0.4 ends the I/O vector with the bit vector's and rowid's lengths
        # for seerdb, `00 00 00` before the direction, and with the buffer
        # length alone for ojdbc14, `00` (#2284), as it does the row header.
        from seerdb.common.tns import decode_fv2_block_out

        for reply in (self.OUTNUM_RESP, self.OUTNUM_LIVE):
            (out, _rc, err) = decode_fv2_block_out(reply, 1)
            self.assertEqual((out, err), ([bytes.fromhex('c12b')], 0))


class TestFv2BindDirections(unittest.TestCase):
    """The 9i bind prompt names each bind's direction, and the block exchange
    follows it (#1242). Prompts captured live from 9.2.0.4."""

    # :1 := :2 * 10 with two Vars: OUT, IN.
    OUT_IN_PROMPT = bytes.fromhex('0b0501020001010000001020')
    # ... and its reply: one OUT value (70) then the RPA + OER.
    OUT_IN_VALUES = bytes.fromhex(
        '0702c147000801020401823751000401010000000101002f'
        '0000000000000000000000000000010100000000'
    )

    def test_the_directions_are_read_in_bind_order(self):
        from seerdb.common.tns import decode_fv2_bind_directions

        self.assertEqual(decode_fv2_bind_directions(self.OUT_IN_PROMPT), [0x10, 0x20])
        three = bytes.fromhex('0b050103000101000000102030')
        self.assertEqual(decode_fv2_bind_directions(three), [0x10, 0x20, 0x30])
        # A pure-OUT block's prompt runs straight into the values' RXD, in the
        # I/O vector seerdb gets, with the bit vector's and rowid's lengths
        # (#2284), or in ojdbc14's, without them.
        both_out = bytes.fromhex('0b05010200010100000010100702c1020002c103')
        self.assertEqual(decode_fv2_bind_directions(both_out), [0x10, 0x10])
        for prompt in (TestFv2OutBinds.OUTNUM_RESP, TestFv2OutBinds.OUTNUM_LIVE):
            self.assertEqual(decode_fv2_bind_directions(prompt), [0x10])
        self.assertIsNone(decode_fv2_bind_directions(self.OUT_IN_VALUES))

    def test_8i_writes_its_bind_count_in_2_byte_fields(self):
        # Captured from 8.1.7: OUT, IN, then the one OUT value's RXD.
        from seerdb.common.tns import decode_8i_block_out, decode_fv2_bind_directions

        reply = bytes.fromhex(
            '0b050200000001000000000000000000000010200702c1470000080400f3340d'
        )
        self.assertEqual(decode_fv2_bind_directions(reply, O8i=True), [0x10, 0x20])
        self.assertEqual(decode_8i_block_out(reply, 1), [bytes.fromhex('c147')])

    def test_the_count_holds_past_255_binds(self):
        # 9.2.0.4's and 8.1.7's prompts for a block of 300 binds: IN, OUT, then
        # 298 IN. Read as its low byte alone, the count was 44, which matched
        # no block, and the client guessed the directions (#2311).
        from seerdb.common.tns import decode_8i_block_out, decode_fv2_bind_directions

        want = [0x20, 0x10] + [0x20] * 298
        prompt = _load_capture('fv2_bind_prompt_300_binds_9i.hexdump')
        self.assertEqual(decode_fv2_bind_directions(prompt), want)
        reply = _load_capture('o8i_bind_prompt_300_binds.hexdump')
        self.assertEqual(decode_fv2_bind_directions(reply, O8i=True), want)
        self.assertEqual(decode_8i_block_out(reply, 1), [bytes.fromhex('c20404')])

    def test_8i_marks_an_out_bind_the_block_never_assigned(self):
        # Captured from 8.1.7, `BEGIN IF 1 = 0 THEN :1 := 1; END IF; :2 := 5;
        # END;`: two OUTs, the first never assigned, `ff` and the indicator
        # 3105 (`ff 21 0c`), as 9i marks one (#801); then 5 and the status.
        from seerdb.common.tns import (
            decode_8i_block_cursor,
            decode_8i_block_out,
            decode_fv2_bind_directions,
        )

        reply = bytes.fromhex(
            '0b0502000000010000000000000000000000101007ff210c02c1060000080400a8e91f'
            '00000000000100000000000000000000000401000000000000000000010000002f00'
            '40000000000000000000000000000000000000000000080000010000000000000000'
            '000000000000000000'
        )
        self.assertEqual(decode_fv2_bind_directions(reply, O8i=True), [0x10, 0x10])
        self.assertEqual(decode_8i_block_out(reply, 2), [None, bytes.fromhex('c106')])
        self.assertEqual(decode_8i_block_cursor(reply, 2), 1)

    def test_an_in_only_var_is_sent_as_input_and_not_read_back(self):
        # The prompt says OUT, IN: send only the IN Var's value, and read one
        # OUT value, not two. Counting both Vars as outputs read the RPA as a
        # second value and failed "malformed Oracle NUMBER".
        import seerdb
        from seerdb.client.dialect import RECV, Fv2Dialect, Send
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import encode_tokens_rxd

        out, inp = Var(seerdb.DB_TYPE_NUMBER), Var(seerdb.DB_TYPE_NUMBER)
        inp.setvalue(0, 7)
        gen = Fv2Dialect().execute_block('begin :1 := :2 * 10; end;', [out, inp])
        sent = []
        reply = None
        replies = iter([b'open', self.OUT_IN_PROMPT, self.OUT_IN_VALUES, b'close'])
        try:
            step = next(gen)
            while True:
                if isinstance(step, Send):
                    sent.append(step)
                    step = gen.send(None)
                else:
                    self.assertIs(step, RECV)
                    step = gen.send((6, next(replies)))
        except StopIteration as done:
            reply = done.value
        self.assertIn(encode_tokens_rxd([7], b''), [s.data for s in sent])
        record = reply[4][0]
        self.assertEqual(record['out_positions'], [0])
        self.assertEqual(len(record['out_values']), 1)
        # What cursor.bind_directions reports: the prompt's masks (#2264).
        self.assertEqual(record['directions'], [0x10, 0x20])


class TestFv2RefCursor(unittest.TestCase):
    """A 9i REF CURSOR OUT bind (#2246), from ojdbc14 on 9.2.0.4: `begin open
    :1 for select n, v from t2246 order by n; end;`. The block hands back the
    REF CURSOR's server cursor id (2), which is then described, fetched and
    closed by that id, as ojdbc14 does. Replies are the captured ones."""

    PROMPT = bytes.fromhex('0b0501010001010030')  # one bind, IN OUT
    OUT = bytes.fromhex(
        '0702010200080102040201bd1d000401010000000101002f'
        '00000000000000000000000000000101'
    )
    DESCRIBE = bytes.fromhex(
        '080102020000817f011600000000000001010101014e000001800000011400000000'
        '011f0101010101015600000401010000000102000300000000000000000000000000'
        '000101'
    )
    ROWS = bytes.fromhex(
        '0602010200010a000702c1020005726f772031000702c1030005726f772032000702'
        'c1040005726f772033000702c1050005726f772034000702c1060005726f77203500'
        '04010502057b00000102000300000000000000000000000000000101194f52412d30'
        '313430333a206e6f206461746120666f756e640a'
    )

    def test_the_encoders_name_the_cursor_they_act_on(self):
        from seerdb.common.tns import (
            encode_o7_close,
            encode_o7_describe,
            encode_o7_exec,
        )

        self.assertEqual(encode_o7_describe(0, 2).hex(), '036200070102000001020101')
        self.assertEqual(encode_o7_close(0, 2).hex(), '0314000102')
        self.assertEqual(
            encode_o7_exec(0, [], 2)[:19].hex(),
            '03470002805001020000000001010701010200',
        )
        # Cursor 1, what OOPEN gives, is what they always sent.
        self.assertEqual(encode_o7_describe(0), encode_o7_describe(0, 1))
        self.assertEqual(encode_o7_close(0).hex(), '0314000101')

    def test_a_ref_cursor_bind_is_a_one_byte_slot(self):
        import seerdb
        from seerdb.client.dialect import _block_input
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import _o7_bind_oac, encode_tokens_rxd

        rc = Var(seerdb.DB_TYPE_CURSOR)
        self.assertEqual(_o7_bind_oac(rc).hex(), '66010000010100000000011f01')
        self.assertEqual(encode_tokens_rxd([_block_input(rc)], b'').hex(), '070100')

    def test_the_block_reads_the_ref_cursor_by_its_id(self):
        import seerdb
        from seerdb.client.dialect import RECV, Fv2Dialect, Send
        from seerdb.common.datatypes import Var

        rc = Var(seerdb.DB_TYPE_CURSOR)
        gen = Fv2Dialect().execute_block(
            'begin open :1 for select n, v from t2246 order by n; end;', [rc]
        )
        replies = iter(
            [
                bytes.fromhex('08010109'),  # OOPEN: 1
                self.PROMPT,
                self.OUT,
                b'\x09',
                self.DESCRIBE,
                self.ROWS,
                b'\x09',
                b'\x09',
            ]
        )
        sent = []
        try:
            step = next(gen)
            while True:
                if isinstance(step, Send):
                    sent.append(step.data)
                    step = gen.send(None)
                else:
                    self.assertIs(step, RECV)
                    step = gen.send((6, next(replies)))
        except StopIteration as done:
            reply = done.value
        marker = reply[4][0]['out_values'][0]
        self.assertIsInstance(marker, dict)  # not the cursor id's raw bytes
        self.assertEqual(marker['cursor_id'], 2)
        self.assertEqual([c['column_name'] for c in marker['row_format']], [b'N', b'V'])
        self.assertEqual(
            [list(r) for r in marker['rows']],
            [[n, f'row {n}'] for n in range(1, 6)],
        )
        from seerdb.common.tns import (
            encode_o7_close,
            encode_o7_describe,
            encode_o7_free,
        )

        self.assertIn(encode_o7_describe(0, 2), sent)
        # Closed, then freed, as ojdbc14 does: only closed, it stayed open (#2288).
        self.assertEqual(sent[-2:], [encode_o7_close(0, 2), encode_o7_free(0, 2)])


class TestFv2NestedCursor(unittest.TestCase):
    """A 9i CURSOR(...) column (#2254), from ojdbc14 on 9.2.0.4: `select o.n,
    cursor(select i.v from t2254 i where i.n <= o.n order by i.n) c from t2254 o
    order by o.n`. Each row's cell is its nested cursor's id (2, 3, 4), read by
    that id before the query's own cursor closes, as ojdbc14 does. The replies
    are the captured ones, in seerdb's order: it frees a cursor with the close
    alone, where ojdbc14 follows it with `03 08`."""

    REPLIES = [
        bytes.fromhex(
            '08010204020217a9000400000000010101450300000000000000000000000000000101'
        ),
        bytes.fromhex(
            '080102020000817f011600000000000001010101014e00006600000001050000'
            '0000000001010101014300000400000000010100030000000000000000000000'
            '0000000101'
        ),
        bytes.fromhex(
            '0602010200010a000702c10200020102000702c10300020103000702c1040002'
            '01040004010302057b0000010100030000000000000000000000000000010119'
            '4f52412d30313430333a206e6f206461746120666f756e640a'
        ),
        bytes.fromhex(
            '08010101800000011400000000011f0101010101015600000401030000000102'
            '000300000000000000000000000000000101'
        ),
        bytes.fromhex(
            '0602010100010a000705726f7720310004010102057b00000102000300000000'
            '000000000000000000000101194f52412d30313430333a206e6f206461746120'
            '666f756e640a'
        ),
        bytes.fromhex('09'),
        bytes.fromhex(
            '08010101800000011400000000011f0101010101015600000401010000000103'
            '000300000000000000000000000000000101'
        ),
        bytes.fromhex(
            '0602010100010a000705726f772031000705726f7720320004010202057b0000'
            '0103000300000000000000000000000000000101194f52412d30313430333a20'
            '6e6f206461746120666f756e640a'
        ),
        bytes.fromhex('09'),
        bytes.fromhex(
            '08010101800000011400000000011f0101010101015600000401020000000104'
            '000300000000000000000000000000000101'
        ),
        bytes.fromhex(
            '0602010100010a000705726f772031000705726f772032000705726f77203300'
            '04010302057b00000104000300000000000000000000000000000101194f5241'
            '2d30313430333a206e6f206461746120666f756e640a'
        ),
        bytes.fromhex('09'),
        bytes.fromhex('09'),
    ]

    def test_each_row_carries_its_nested_cursor_read(self):
        from seerdb.client.dialect import RECV, Fv2Dialect, Send

        gen = Fv2Dialect().execute_query(
            'select o.n, cursor(select i.v from t2254 i where i.n <= o.n'
            ' order by i.n) c from t2254 o order by o.n'
        )
        replies = iter([bytes.fromhex('08010109'), *self.REPLIES])  # OOPEN: 1
        sent = []
        try:
            step = next(gen)
            while True:
                if isinstance(step, Send):
                    sent.append(step.data)
                    step = gen.send(None)
                else:
                    self.assertIs(step, RECV)
                    step = gen.send((6, next(replies)))
        except StopIteration as done:
            result = done.value
        rows = result[4]
        self.assertEqual([r[0] for r in rows], [1, 2, 3])
        nested = [r[1] for r in rows]
        self.assertTrue(all(isinstance(n, dict) for n in nested))  # not raw ids
        self.assertEqual([n['cursor_id'] for n in nested], [2, 3, 4])
        self.assertEqual(
            [[list(r) for r in n['rows']] for n in nested],
            [[['row 1']], [['row 1'], ['row 2']], [['row 1'], ['row 2'], ['row 3']]],
        )
        from seerdb.common.tns import encode_o7_close

        # The nested cursors close before the query's own.
        self.assertEqual(sent[-1], encode_o7_close(0, 1))
        self.assertEqual(sent[-2], encode_o7_close(0, 4))


class TestFv2BatchErrors(unittest.TestCase):
    # 9.2's reply to a batcherrors array DML (#2247), captured: rows 1, 2, 1,
    # 4, 5 into a primary key. Four rows applied, ORA-24381, and the 10g+ OER's
    # three arrays behind the short status: ORA-00001 at row index 2.
    REPLY = bytes.fromhex(
        '040104025f3d000001010002000000000000000000000000000000010500010102010101'
        '010201020101160138384f52412d30303030313a20756e6971756520636f6e7374726169'
        '6e74202850594f2e5359535f43303036383837292076696f6c617465640a0000214f5241'
        '2d32343338313a206572726f7228732920696e20617272617920444d4c0a'
    )

    def test_the_failed_rows_are_read_from_the_status(self):
        from seerdb.common.tns import (
            decode_fv2_batch_errors,
            decode_fv2_dml_response,
            decode_fv2_dml_rowid,
            decode_fv2_oer_error,
        )

        self.assertEqual(
            decode_fv2_batch_errors(self.REPLY),
            [
                {
                    'offset': 2,
                    'code': 1,
                    'message': 'ORA-00001: unique constraint (PYO.SYS_C006887) violated',
                }
            ],
        )
        self.assertEqual(decode_fv2_dml_response(self.REPLY), (4, 24381))
        self.assertEqual(
            decode_fv2_oer_error(self.REPLY),
            (24381, 'ORA-24381: error(s) in array DML'),
        )
        self.assertIsNone(decode_fv2_dml_rowid(self.REPLY))  # an error carries none
        # A plain DML's status has empty arrays.
        Insert = bytes.fromhex(
            '0801020402013cf700040101000000010100020000000000030278dc01010002b912'
            '00000000000101'
        )
        self.assertEqual(decode_fv2_batch_errors(Insert), [])
        self.assertIsNotNone(decode_fv2_dml_rowid(Insert))


class TestFv2ErrorOffset(unittest.TestCase):
    # 9.2's error status carries the error's offset in the statement, the ub4
    # after the cursor id (#2263). Captured: `select 1 frm dual` (ORA-00923 at
    # `dual`, 13) and `select nosuch from dual` (ORA-00904 at `nosuch`, 7).
    E923 = bytes.fromhex(
        '040002039b00000101010d000000000000000000000000000000000000000031'
        '4f52412d30303932333a2046524f4d206b6579776f7264206e6f7420666f756e'
        '642077686572652065787065637465640a'
    )
    E904 = bytes.fromhex(
        '0400020388000001010107000000000000000000000000000000000000000028'
        '4f52412d30303930343a20224e4f53554348223a20696e76616c696420696465'
        '6e7469666965720a'
    )

    def test_the_status_says_where_the_error_is(self):
        from seerdb.client.dialect import fv2_raise_for_error
        from seerdb.common.exceptions import DatabaseError
        from seerdb.common.tns import decode_fv2_error_position

        self.assertEqual(decode_fv2_error_position(self.E923), 13)
        self.assertEqual(decode_fv2_error_position(self.E904), 7)
        with self.assertRaises(DatabaseError) as ctx:
            fv2_raise_for_error(self.E904, with_offset=True)
        self.assertEqual((ctx.exception.code, ctx.exception.offset), (904, 7))
        # 8i's status does not say (#719), so the shared path leaves it 0.
        with self.assertRaises(DatabaseError) as ctx:
            fv2_raise_for_error(self.E904)
        self.assertEqual(ctx.exception.offset, 0)


class TestFv2LobOperations(unittest.TestCase):
    """A 9i LOB object's calls (#2259), from ojdbc14 on 9.2.0.4: each is the
    GET_LENGTH request's shape with its own operation, offset, flags and
    trailer. Requests and replies are the captured ones."""

    GETLEN_REQ = bytes.fromhex(
        '036000010156000000000001000101000000540001020c000000010000000100'
        '000008e10d000286f2000286f100020002001f00000000000000000000000000'
        '00000000000202f17b000000070000000071c800000000000000000000000286'
        'f10040b92a000000'
    )
    READ_REQ = bytes.fromhex(
        '03600001015600000107000001000102000000540001020c0000000100000001'
        '00000008e10d000286f2000286f100020002001f000000000000000000000000'
        '0000000000000202f17b000000070000000071c8000000000000000000000002'
        '86f10040b92a00000103'
    )
    WRITE_REQ = bytes.fromhex(
        '03600001015600000102000001000140000000540001010c0000000100000001'
        '00000008e10e000286f4000286f1000300030000000000000000000000000000'
        '0000000000000202f17b000000070000000071c8000000000000000000000002'
        '86f10040b92a000001020e020909'
    )
    TRIM_REQ = bytes.fromhex(
        '036000010156000000000001000120000000540001020c000000010000000100'
        '000008e10d000286f2000286f100020002001f00000000000000000000000000'
        '00000000000202f17b000000070000000071c800000000000000000000000286'
        'f10040b92a00000105'
    )
    CHUNK_REQ = bytes.fromhex(
        '03600001015600000000000100024000000000540001020c0000000100000001'
        '00000008f5c100028b5500028b5400020002001f000000000000000000000000'
        '0000000000000203712b000000050004000097b7000000000000000000000002'
        '8b540040b92a000000'
    )
    CHUNK_REP = bytes.fromhex(
        '0800540001020c000000010000000100000008f5c100028b5500028b54000200'
        '02001f0000000000000000000000000000000000000203712b00000005000400'
        '0097b70000000000000000000000028b540040b92a0000021fc4040101000000'
        '000000000000000003028b5401010002b92a00000000000101'
    )
    OPEN_REQ = bytes.fromhex(
        '03600001015600000000000100028000000000540001010c0000000100000001'
        '00000008f5c200028b5700028b54000300030000000000000000000000000000'
        '0000000000000203712b000000050004000097b7000000000000000000000002'
        '8b540040b92a00000102'
    )
    ISOPEN_REQ = bytes.fromhex(
        '0360000101560000000000000103011000000000540001010c00000001000000'
        '0100000008f5c200028b5700028b540003000300000000000000000000000000'
        '000000000000000203712b000000050004000097b70000000000000000000000'
        '028b540040b92a0000'
    )
    ISOPEN_REP = bytes.fromhex(
        '0800540001010c000000010000000100000008f5c200028b5700028b54000300'
        '0300000000000000000000000000000000000000000203712b00000005000400'
        '0097b70000000000000000000000028b540040b92a0000010104010100000000'
        '0000000000000003028b5401010002b92a00000000000101'
    )
    CLOSE_REQ = bytes.fromhex(
        '0360000101560000000000000003010000000000540001010c00000001000000'
        '0100000008f5c200028b5700028b540003000300000000000000000000000000'
        '000000000000000203712b000000050004000097b70000000000000000000000'
        '028b540040b92a0000'
    )

    @staticmethod
    def _locator(request: bytes) -> bytes:
        # The locator as a fetched 9i LOB holds it: a 0x00, then the ub1
        # length and the body the request carries.
        at = request.find(bytes.fromhex('540001'))
        return bytes([0]) + request[at : at + 85]

    def test_each_call_is_built_as_ojdbc14_builds_it(self):
        from seerdb.common.tns import encode_o7_lobop
        from seerdb.common.tns_consts import (
            TNS_LOB_OP_CLOSE,
            TNS_LOB_OP_GET_CHUNK_SIZE,
            TNS_LOB_OP_GET_LENGTH,
            TNS_LOB_OP_IS_OPEN,
            TNS_LOB_OP_OPEN,
            TNS_LOB_OP_READ,
            TNS_LOB_OP_TRIM,
            TNS_LOB_OP_WRITE,
        )

        for request, operation, kw in (
            (self.GETLEN_REQ, TNS_LOB_OP_GET_LENGTH, {}),
            (self.READ_REQ, TNS_LOB_OP_READ, {'Offset': 7, 'Amount': 3}),
            (
                self.WRITE_REQ,
                TNS_LOB_OP_WRITE,
                {'Offset': 2, 'Amount': 2, 'Data': b'\x09\x09'},
            ),
            (self.TRIM_REQ, TNS_LOB_OP_TRIM, {'Amount': 5}),
            (self.CHUNK_REQ, TNS_LOB_OP_GET_CHUNK_SIZE, {}),
            (self.OPEN_REQ, TNS_LOB_OP_OPEN, {'Amount': 2}),
            (self.ISOPEN_REQ, TNS_LOB_OP_IS_OPEN, {}),
            (self.CLOSE_REQ, TNS_LOB_OP_CLOSE, {}),
        ):
            built = encode_o7_lobop(request[2], self._locator(request), operation, **kw)
            self.assertEqual(built.hex(), request.hex(), hex(operation))

    def test_a_locator_past_252_bytes_goes_whole(self):
        # The locator follows the SCN length as the bytes `source_length`
        # counts, its ub2 length and body, never in chunks: a BFILE's with a
        # 240-character file name is 265 bytes, and in chunks 9.2.0.4 refused
        # the call with ORA-03120 (#2331). The short amount, FILE_OPEN's 0x0b,
        # follows it.
        from seerdb.common.tns import encode_o7_bfile_open

        locator = (263).to_bytes(2, 'big') + bytes(range(256)) + b'\x07' * 7
        request = encode_o7_bfile_open(0, locator)
        self.assertTrue(request.endswith(locator + b'\x01\x0b'), request[-8:].hex())

    def test_a_long_write_is_chunked_as_ojdbc14_chunks_it(self):
        # 3000 characters: the 0xFE marker, 252-byte chunks and a zero.
        from seerdb.common.tns import _o7_lob_value

        value = _o7_lob_value(b'w' * 3000)
        self.assertEqual(value[:2].hex(), 'fefc')
        self.assertEqual(value[-1:], b'\x00')
        self.assertEqual(len(value), 1 + 11 * 253 + 1 + 228 + 1)
        self.assertEqual(_o7_lob_value(b'\x09\x09').hex(), '020909')

    def test_close_asks_for_no_value_and_gets_none(self):
        # CLOSE's request asks no reply value, and 9.2.0.4's reply is the RPA
        # and the locator, then the status. Read as if it carried an amount,
        # the status's first bytes came back as one: 16842752 (#2284).
        # Captured from seerdb on 9.2.0.4.
        from seerdb.common.tns import decode_fv2_lob_value
        from seerdb.common.tns_consts import TNS_LOB_OP_CLOSE

        reply = bytes.fromhex(
            '0800540001020c00000001000000010000000b91eb0002f5c60002f5c500020002'
            '001f0000008fb300481760962a00000000003a0302109d5e00000009000f00009a'
            'b40080017f03be010000000002f5c50040b8d2000004010100000000000000000000'
            '000302f5c501010002b8d20000000000010100000000'
        )
        (value, body) = decode_fv2_lob_value(reply, TNS_LOB_OP_CLOSE)
        self.assertEqual((value, len(body or b'')), (0, 84))

    def test_the_reply_gives_the_value_and_the_locator_to_keep(self):
        from seerdb.common.lob import LOB
        from seerdb.common.tns import decode_fv2_lob_value
        from seerdb.common.tns_consts import (
            TNS_LOB_OP_GET_CHUNK_SIZE,
            TNS_LOB_OP_IS_OPEN,
        )

        (chunk, body) = decode_fv2_lob_value(self.CHUNK_REP, TNS_LOB_OP_GET_CHUNK_SIZE)
        self.assertEqual(chunk, 8132)
        # IS_OPEN's answer rides the null-LOB field its request set (#2284).
        self.assertEqual(
            decode_fv2_lob_value(self.ISOPEN_REP, TNS_LOB_OP_IS_OPEN)[0], 1
        )
        # Kept, the locator is the fetched form again, so the next call works:
        # prefixed twice, it answered ORA-22275.
        fetched = self._locator(self.CHUNK_REQ)
        lob = LOB(112, fetched)
        lob._refresh(body)
        self.assertEqual(lob.raw, fetched)


class TestFv2WarnFlags(unittest.TestCase):
    # 9.2's status for `create or replace procedure p2248 is begin nosuch;
    # end;`, captured (#2262): the call succeeds, and the last of the six
    # single-byte fields after the error position is 0x21 -- bit 0x20 says
    # the procedure compiled with errors.
    CREATED_WITH_ERRORS = bytes.fromhex(
        '080102040202ef40000400000000010100180000000021000000000000000000010100000000'
    )

    def test_the_status_says_the_object_compiled_with_errors(self):
        from seerdb.common.tns import decode_fv2_warn_flags
        from seerdb.common.tns_consts import TNS_OER_WARN_COMPILATION_ERROR

        flags = decode_fv2_warn_flags(self.CREATED_WITH_ERRORS)
        self.assertTrue(flags & TNS_OER_WARN_COMPILATION_ERROR)
        # A plain insert's status sets none.
        insert = bytes.fromhex(
            '0801020402013cf700040101000000010100020000000000030278dc01010002b912'
            '00000000000101'
        )
        self.assertEqual(decode_fv2_warn_flags(insert), 0)


class TestFv2CursorCache(unittest.TestCase):
    """9i's cursor cache (#2261), from ojdbc14 on 9.2.0.4 with its statement
    cache on: a cached INSERT run twice is parsed once, then re-executed by its
    cursor with the parse bit cleared (0x8028) and no SQL. `03 14` keeps the
    cursor parsed and `03 08` frees it. Replies are the captured ones."""

    # ojdbc14's second run of `insert into t2248 (n, v) values (?, ?)`.
    REEXECUTE = bytes.fromhex(
        '03470002802801010000000001010701010200000001010201010101000000000006'
        '010000011600000000011f0101010000020fa000000000011f010703c20202086361'
        '636865642031'
    )
    OOPEN_1 = bytes.fromhex('08010109')
    OOPEN_2 = bytes.fromhex('08010209')
    INSERTED = bytes.fromhex(
        '08010204020447d90004010100000001010002000000000003028b6b01010002b912'
        '0106000000000101'
    )

    def test_a_reexecute_is_the_parse_without_its_sql(self):
        from seerdb.common.tns import encode_o7_parse

        built = encode_o7_parse(
            0,
            'insert into t2248 (n, v) values (:1, :2)',
            [101, 'cached 1'],
            Cursor=1,
            Reexecute=True,
        )
        # The same up to the bind descriptors, where seerdb declares AL32UTF8
        # for a str and ojdbc14 the database charset.
        head = 3 + 3 + 2 + 1 + 1 + 11 + 3 + 9
        self.assertEqual(built[:head].hex(), self.REEXECUTE[:head].hex())
        self.assertEqual(built[3:6].hex(), '028028')

    def _drive(self, gen, replies):
        from seerdb.client.dialect import RECV, Send

        sent = []
        replies = iter(replies)
        try:
            step = next(gen)
            while True:
                if isinstance(step, Send):
                    sent.append(step.data)
                    step = gen.send(None)
                else:
                    self.assertIs(step, RECV)
                    step = gen.send((6, next(replies)))
        except StopIteration as done:
            return (sent, done.value)

    def test_a_cached_dml_is_parsed_once_then_reexecuted_by_its_cursor(self):
        from seerdb.client.dialect import Fv2Dialect
        from seerdb.common.tns import encode_o7_close, encode_o7_free

        sql = 'insert into t2248 (n, v) values (:1, :2)'
        cache: dict = {}
        dialect = Fv2Dialect()  # one per connection, as the connection keeps it
        # First run: the statement to cache is parsed into the cursor its own
        # OOPEN gave (2 here).
        (sent, result) = self._drive(
            dialect.execute_dml(sql, [100, 'cached 0'], cache=cache),
            [self.OOPEN_2, self.INSERTED, b'\x09'],
        )
        self.assertEqual(result[3][0], 1)
        self.assertEqual(list(cache.values()), [2])
        self.assertEqual(sent[1][3:9].hex(), '028029010201')  # parse into 2
        # Second run: no OOPEN, no SQL, cursor 2.
        (sent, result) = self._drive(
            dialect.execute_dml(sql, [101, 'cached 1'], cache=cache),
            [self.INSERTED, b'\x09'],
        )
        self.assertEqual(sent[0][3:8].hex(), '0280280102')
        self.assertNotIn(sql.encode(), sent[0])
        self.assertEqual(sent[1], encode_o7_close(0, 2))
        # DDL flushes the cache and frees the cursor, then runs on the shared
        # cursor, which its OOPEN opens (1).
        (sent, _) = self._drive(
            dialect.execute_dml('drop table t2248', cache=cache),
            [b'\x09', self.OOPEN_1, self.INSERTED, b'\x09'],
        )
        self.assertEqual(sent[0], encode_o7_free(0, 2))
        self.assertEqual(cache, {})

    def test_uncached_statements_share_one_cursor(self):
        # Each statement sent an OOPEN and parsed on cursor 1 whatever it gave,
        # so every OOPEN after the first left a cursor open, and a session that
        # alternated statements ran out at open_cursors (#2288). The shared
        # cursor is opened once, and is the one the OOPEN gave (5 here).
        from seerdb.client.dialect import Fv2Dialect
        from seerdb.common.tns import encode_o7_close

        dialect = Fv2Dialect()
        (sent, _) = self._drive(
            dialect.execute_dml('drop table t2248'),
            [bytes.fromhex('08010509'), self.INSERTED, b'\x09'],
        )
        self.assertEqual(sent[0][:2].hex(), '0302')  # OOPEN
        self.assertEqual(sent[1][3:8].hex(), '0280210105')  # parsed on cursor 5
        self.assertEqual(sent[2], encode_o7_close(0, 5))
        (sent, _) = self._drive(
            dialect.execute_block('begin null; end;'), [self.INSERTED, b'\x09']
        )
        self.assertNotIn(bytes.fromhex('0302'), [s[:2] for s in sent])  # no OOPEN
        self.assertEqual(sent[0][3:7].hex(), '01210105')
        self.assertEqual(sent[1], encode_o7_close(0, 5))


class TestFv2WideDescribe(unittest.TestCase):
    """A 9i describe of more than 255 columns (#2306): its column count is a
    ub4, `02 01 2c` for 300, and was read as the byte after `08 01` -- one
    column -- so the execute defined one and 9i refused it with ORA-03115.
    The reply is the one ojdbc14 received from 9.2.0.4."""

    def test_a_300_column_describe_has_300_columns(self):
        from seerdb.common.tns import decode_fv2_describe

        columns = decode_fv2_describe(
            _load_capture('fv2_describe_300_columns_9i.hexdump')
        )
        self.assertEqual(len(columns), 300)
        self.assertEqual(
            [c['column_name'] for c in columns], [f'C{i}'.encode() for i in range(300)]
        )
        self.assertEqual({c['data_type'] for c in columns}, {2})

    def test_a_long_column_name_comes_in_chunks(self):
        # An expression's column is named by its text, which 9.2.0.4 cuts to
        # 255 characters and sends in chunks of 64 bytes (#2284).
        from seerdb.common.tns import decode_fv2_describe

        (column,) = decode_fv2_describe(
            _load_capture('fv2_describe_long_name_9i.hexdump')
        )
        self.assertEqual(column['column_name'], b"'" + b'A' * 254)
        self.assertEqual((column['data_type'], column['data_length']), (96, 300))

    def test_a_status_describes_no_columns(self):
        # A describe the server refuses answers with a status, not an RPA: no
        # columns, and the execute that follows raises the error.
        from seerdb.common.tns import decode_fv2_describe

        self.assertEqual(decode_fv2_describe(bytes.fromhex('0400010000')), [])


class TestFv2DescriptionSizes(unittest.TestCase):
    """cursor.description's sizes on 9i are 10g's, as python-oracledb reports
    them (#2326). The describe has no declared size, and its buffer stood in:
    a DATE and a ROWID reported 1, a NUMBER 22, a CLOB 4000, an NCHAR(4) its
    8 bytes. Captured from seerdb's own session on 9.2.0.4."""

    def test_each_column_reports_what_10g_does(self):
        from seerdb.client.cursor import _column_description
        from seerdb.common.tns import decode_fv2_describe

        columns = decode_fv2_describe(
            _load_capture('fv2_describe_column_types_9i.hexdump')
        )
        self.assertEqual(
            {c['column_name']: _column_description(c)[2:4] for c in columns},
            {
                b'D': (23, None),
                b'N': (10, None),
                b'NC': (4, 8),
                b'RI': (None, None),
                b'CL': (None, None),
            },
        )

    def test_each_define_asks_for_the_described_buffer(self):
        # The execute defines each column with its buffer, in bytes, not the
        # declared size: an NCHAR(4) 8 bytes, a CLOB 4000. Defined with 0, a
        # CLOB answered ORA-01002 on its fetch.
        from seerdb.common import tns, wire_schema

        columns = tns.decode_fv2_describe(
            _load_capture('fv2_describe_column_types_9i.hexdump')
        )
        read = wire_schema.compile_decoder(tns._O7_OAC, tns._THIN)
        sizes = {
            c['column_name']: read(tns._o7_define_entry(c))[0]['max_length']
            for c in columns
        }
        self.assertEqual(sizes, {b'D': 7, b'N': 22, b'NC': 8, b'RI': 128, b'CL': 4000})

    def test_a_urowid_is_defined_for_its_whole_text(self):
        # A UROWID's text runs to 5267 characters; defined as VARCHAR(128) like
        # a physical ROWID's, a longer one came back cut to 128 (#2335).
        from seerdb.common import tns, wire_schema

        read = wire_schema.compile_decoder(tns._O7_OAC, tns._THIN)
        column = {'data_type': 208, 'data_length': 1, 'charset': 0, 'csfrm': 0}
        define = read(tns._o7_define_entry(column))[0]
        self.assertEqual((define['data_type'], define['max_length']), (1, 5267))


class TestFv2ObjectColumn(unittest.TestCase):
    """A 9i object column (#2258), from 9.2.0.4: `select id, o from o2248
    order by id`, `o` a `ty2248(a NUMBER, b VARCHAR2(10))`, one row holding
    `ty2248(7, 'seven')` and one NULL. Replies are the captured ones."""

    DESCRIBE = bytes.fromhex(
        '080102020000817f01160000000000000102010202494400006d0000000207d0'
        '00000110105e89723d5c4f58d5e060007f01001cd60101000001010101014f01'
        '030350594f010606545932323438040000000001010003000000000003028b73'
        '01010002b962010100000000010100000000'
    )
    ROWS = bytes.fromhex(
        '0602010200010a0000000702c10200012424002202085e89723d5c4f58d5e060'
        '007f01001cd600000000000000000000000000010001000000010c01010c8401'
        '0c02c10805736576656e000702c10300012424002202085e89723d5c4f58d5e0'
        '60007f01001cd600000000000000000000000000010001000000000101810104'
        '010202057b000001010003000000000003028b7301010002b962010100000000'
        '010100000000194f52412d30313430333a206e6f206461746120666f756e640a'
    )
    TOID = bytes.fromhex('5e89723d5c4f58d5e060007f01001cd6')

    def test_the_describe_names_the_type(self):
        from seerdb.common.tns import decode_fv2_describe

        (n, o) = decode_fv2_describe(self.DESCRIBE)
        self.assertEqual((n['column_name'], o['column_name']), (b'ID', b'O'))
        self.assertEqual(o['data_type'], 109)
        self.assertEqual(o['type_oid'], self.TOID)
        self.assertEqual((o['type_schema'], o['type_name']), ('PYO', 'TY2248'))

    def test_the_define_names_the_type_as_ojdbc14_does(self):
        from seerdb.common.tns import _o7_define_entry, decode_fv2_describe

        (_, o) = decode_fv2_describe(self.DESCRIBE)
        # ojdbc14's define for the same column, captured: the open-ended size,
        # the TOID and version 1 where a plain column has four zeros.
        self.assertEqual(
            _o7_define_entry(o).hex(),
            '6d010000047fffffff0000011010' + self.TOID.hex() + '0101011f00',
        )

    def test_the_rows_carry_an_object_and_a_null(self):
        from seerdb.common.dbobject import ObjectImage
        from seerdb.common.tns import decode_fv2_describe, decode_fv2_exec_response

        columns = decode_fv2_describe(self.DESCRIBE)
        (rows, err) = decode_fv2_exec_response(self.ROWS, columns)
        self.assertEqual(err, 1403)  # the NULL's 81 01 read whole, the end seen
        self.assertEqual([r[0] for r in rows], [1, 2])
        image = rows[0][1]
        self.assertIsInstance(image, ObjectImage)
        self.assertEqual(image.type_oid, self.TOID)  # not the 36-byte type block
        self.assertEqual(image.image.hex(), '84010c02c10805736576656e')  # 7, 'seven'
        self.assertIsNone(rows[1][1])

    def test_a_national_lob_reads_as_al16utf16(self):
        # An NCLOB attribute's LOB has no column to name its charset (#2258).
        from seerdb.common.lob import LOB
        from seerdb.common.tns_consts import AL16UTF16_CHARSET

        self.assertEqual(
            LOB(112, b'x', csfrm=2)._charset(), {'charset': AL16UTF16_CHARSET}
        )
        self.assertEqual(LOB(112, b'x', charset=31)._charset(), {'charset': 31})
        self.assertEqual(LOB(113, b'x')._charset(), {})


class TestPre10ServerVersion(unittest.TestCase):
    """The release before 10g (#2278): 9i's login returns none, so it is asked
    once after login with the version call, as ojdbc14 asks, and 8i's phase-two
    login reply carries AUTH_VERSION_NO. Bytes from ojdbc14 on 9.2.0.4 and from
    seerdb's login on 8.1.7."""

    # ojdbc14's version call and the 9.2.0.4 reply: the banner, then 0x09200400.
    CALL = bytes.fromhex('033b00010201000101')
    REPLY = bytes.fromhex(
        '0801a24f7261636c65396920456e74657270726973652045646974696f6e2052656c65'
        '61736520392e322e302e342e30202d2036346269742050726f64756374696f6e0a5769'
        '74682074686520506172746974696f6e696e672c204f4c415020616e64204f7261636c'
        '652044617461204d696e696e67206f7074696f6e730a4a5365727665722052656c6561'
        '736520392e322e302e342e30202d2050726f64756374696f6e040920040009'
    )

    def test_the_9i_version_call_is_ojdbc14s(self):
        from seerdb.common.tns import encode_o7_version

        self.assertEqual(encode_o7_version(0), self.CALL)

    def test_the_9i_reply_gives_the_release(self):
        from seerdb.client.connection import _format_version
        from seerdb.common.tns import decode_fv2_version

        self.assertEqual(decode_fv2_version(self.REPLY), 0x09200400)
        self.assertEqual(_format_version(0x09200400), '9.2.0.4.0')
        # An error in its place leaves the version unknown, not a wrong one.
        self.assertEqual(decode_fv2_version(bytes.fromhex('0400')), 0)

    def test_the_8i_login_reply_gives_the_release(self):
        from seerdb.client.connection import _format_version
        from seerdb.common.tns import decode_8i_server_version

        # The whole 8.1.7 phase-two reply, captured from seerdb's own session.
        reply = _load_capture('o8i_login_phase2_reply.hexdump')
        self.assertEqual(decode_8i_server_version(reply), 135294976)
        self.assertEqual(_format_version(135294976), '8.1.7.0.0')
        self.assertEqual(decode_8i_server_version(reply[:40]), 0)

    def test_the_8i_login_reply_reads_by_its_pairs(self):
        # Its pairs, not a search for a key's name: an AUTH_NLS_ key comes with
        # its NUL terminator counted, and an empty value as a zero length.
        from seerdb.common.tns import parse_8i_auth_value

        reply = _load_capture('o8i_login_phase2_reply.hexdump')
        self.assertEqual(parse_8i_auth_value(reply, b'AUTH_NLS_LXLAN'), b'AMERICAN')
        self.assertEqual(
            parse_8i_auth_value(reply, b'AUTH_NLS_LXCDATEFM'), b'DD-MON-RR'
        )
        self.assertEqual(parse_8i_auth_value(reply, b'AUTH_CAPABILITY_TABLE'), b'')
        self.assertIsNone(parse_8i_auth_value(reply, b'AUTH_NO_SUCH_KEY'))


class TestFv2Bfile(unittest.TestCase):
    """Oracle 9i BFILE read (#102, PROTOCOL §19.8): FILE_OPEN -> GETLEN -> READ
    -> FILE_CLOSE over TTI_LOBOPS, where FILE_OPEN returns an open-flagged
    locator the later ops use. Fixtures are real frames from a live 9.2.0.4
    server: SELECT f FROM bftest, f = BFILENAME('BFDIR','hello.bin') (20 bytes
    'BFILE-9i-content' + ca fe ba be)."""

    RXD = bytes.fromhex(
        '0602010100010a00070122220020000108080000000100000000000000054246'
        '444952000968656c6c6f2e62696e0004010102057b0000010100030000000000'
        '0000000000000000000101194f52412d30313430333a206e6f20646174612066'
        '6f756e640a'
    )
    FOPEN_REQ = bytes.fromhex(
        '0360000101220000000000010002010000000020000108080000000100000000'
        '000000054246444952000968656c6c6f2e62696e010b'
    )
    FOPEN_RESP = bytes.fromhex(
        '080020000108080000000100010000000000054246444952000968656c6c6f2e'
        '62696e010b04010100000000000000000000000000000000000000000101'
    )
    GETLEN_REQ = bytes.fromhex(
        '0360000101220000000000010001010000002000010808000000010001000000'
        '0000054246444952000968656c6c6f2e62696e00'
    )
    GETLEN_RESP = bytes.fromhex(
        '080020000108080000000100010000000000054246444952000968656c6c6f2e'
        '62696e011404010100000000000000000000000000000000000000000101'
    )
    READ_REQ = bytes.fromhex(
        '0360000101220000010100000100010200000020000108080000000100010000'
        '000000054246444952000968656c6c6f2e62696e0114'
    )
    READ_RESP = bytes.fromhex(
        '0efe144246494c452d39692d636f6e74656e74cafebabe000800200001080800'
        '00000100010000000000054246444952000968656c6c6f2e62696e0114040101'
        '00000000000000000000000000000000000000000101'
    )
    FCLOSE_REQ = bytes.fromhex(
        '0360000101220000000000000002020000000020000108080000000100010000'
        '000000054246444952000968656c6c6f2e62696e'
    )

    def _locator(self):
        from seerdb.common.tns import _read_lob_column

        i = self.RXD.index(0x07) + 1
        loc, _ = _read_lob_column(self.RXD[i:])
        return loc

    def test_rxd_yields_bfile_lob(self):
        from seerdb.common.lob import LOB
        from seerdb.common.tns import decode_fv2_exec_response

        rows, err = decode_fv2_exec_response(self.RXD, [{'data_type': 114}])
        self.assertEqual(err, 1403)
        self.assertIsInstance(rows[0][0], LOB)
        self.assertEqual(rows[0][0].data_type, 114)
        # the locator carries the directory + file name in plain ASCII
        self.assertEqual(rows[0][0].directory_name, 'BFDIR')
        self.assertEqual(rows[0][0].filename, 'hello.bin')

    def test_file_open_request_matches_capture(self):
        from seerdb.common.tns import encode_o7_bfile_open

        self.assertEqual(encode_o7_bfile_open(0, self._locator()), self.FOPEN_REQ)

    def test_opened_locator_then_getlen_read_close(self):
        from seerdb.common.tns import (
            decode_fv2_lob_getlen,
            decode_fv2_opened_locator,
            encode_o7_bfile_close,
            encode_o7_lob_getlen,
            encode_o7_lob_read,
        )

        opened = decode_fv2_opened_locator(self.FOPEN_RESP)
        self.assertEqual(encode_o7_lob_getlen(0, opened), self.GETLEN_REQ)
        self.assertEqual(decode_fv2_lob_getlen(self.GETLEN_RESP), 20)
        self.assertEqual(encode_o7_lob_read(0, opened, 20), self.READ_REQ)
        self.assertEqual(encode_o7_bfile_close(0, opened), self.FCLOSE_REQ)

    def test_read_response_content(self):
        from seerdb.common.tns import decode_fv2_lob_chunks

        content, done = decode_fv2_lob_chunks(self.READ_RESP)
        self.assertTrue(done)
        self.assertEqual(content, b'BFILE-9i-content' + bytes.fromhex('cafebabe'))


class TestNative9iOall8Select(unittest.TestCase):
    """Oracle 9i native OALL8 (0x5e) SELECT reply decode (#792): the OCI
    fixed-width DCB describe / RXH / RXD / OER stream. Fixtures are real frames
    captured from a 9.2 server answering ``select rownum from all_objects where
    rownum <= 5`` with sqlplus ``arraysize 2`` (native_9i_fetch_arraysize2.pcap):
    the execute reply (describe + row 1), then two fetch replies (rows 2-3 and
    4-5), the second ending ORA-01403."""

    EXEC = bytes.fromhex(
        '101df3e432ba608ba95d000000000000787e0a1e142306ce0500000000000016'
        '000000010000004b010200000016000000000000000000000000000000000000'
        '000000000000000000000000000000000001060600000006524f574e554d0000'
        '0000000000000700000007787e0a1e142306060102fc0100000001000000a95d'
        '00000000000000000000000000001a5c00000000000000000000000000000502'
        '0000ff7f0702c1020805002ab42b020000000001000000000000000000000000'
        '0000000401000000010100000000000000000001001300030000000000000000'
        '0000000000000000000000000000000000001d00000100000036010000000000'
        '00000000000000000080d0d40300000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000000000000000000'
    )
    FETCH1 = bytes.fromhex(
        '060002fc0100000002000000a95d0000000038bfd6030000000001001a5c0000'
        '00000000000000000000000005020000ff7f010702c103150100010702c10408'
        '0500000000000000000001000000000000000000000000000000040100000001'
        '0300000000000000000001000000030020000000000000000000000000000000'
        '0000000000000000001e00000100000036010000000000000000000000000000'
        '80d0d40300000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
    )
    FETCH2 = bytes.fromhex(
        '060102e601000000020000005c9601000000000000000000000000001f020000'
        '0000000000000000000000000000010000000702c1050702c106040100000001'
        '0500000000000000000001000000030000000000000000000000000000000000'
        '0000000000000000001f00000100000036010000000000000000000000000000'
        '80d0d40300000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
    )

    def _decode(self, data, columns, prev=None):
        from seerdb.common.tns import (
            _DECODE_FIELD_VERSION,
            FIELD_VERSION_9_2,
            decode_9i_oall8_exec_response,
        )

        token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_9_2)
        try:
            return decode_9i_oall8_exec_response(data, columns, prev)
        finally:
            _DECODE_FIELD_VERSION.reset(token)

    def test_describe_reads_the_rownum_column(self):
        from seerdb.common.tns import decode_9i_oall8_describe

        (columns, rest) = decode_9i_oall8_describe(self.EXEC)
        self.assertEqual(len(columns), 1)
        self.assertEqual(columns[0]['column_name'], 'ROWNUM')
        self.assertEqual(columns[0]['data_type'], 2)  # NUMBER
        # The trailer lands exactly on the first row header.
        self.assertEqual(rest[0], 0x06)

    def test_exec_reply_is_the_first_row_then_more(self):
        from seerdb.common.tns import (
            decode_9i_oall8_cursor_id,
            decode_9i_oall8_describe,
            decode_9i_oall8_status,
        )

        (columns, rest) = decode_9i_oall8_describe(self.EXEC)
        (rows, terminal, _) = self._decode(rest, columns)
        self.assertEqual(rows, [[1]])
        self.assertEqual(decode_9i_oall8_status(terminal)['code'], 0)
        self.assertEqual(decode_9i_oall8_cursor_id(terminal), 1)

    # A standalone end-of-fetch status (ORA-01403), from the same session.
    STATUS_1403 = bytes.fromhex(
        '040200000001000000007b050000000001000000030000000000000000000000'
        '0000000000000000000000000000001600000100000036010000000000000000'
        '00000000000080d0d40300000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000000000000194f52412d30313430333a206e6f206461746120666f756e640a'
    )

    def test_fetch_replies_carry_the_remaining_rows(self):
        from seerdb.common.tns import (
            decode_9i_oall8_describe,
            decode_9i_oall8_status,
        )

        (columns, _) = decode_9i_oall8_describe(self.EXEC)
        (rows1, term1, last) = self._decode(self.FETCH1, columns)
        self.assertEqual(rows1, [[2], [3]])
        self.assertEqual(decode_9i_oall8_status(term1)['code'], 0)
        # arraysize 2: rows 4-5 come back with "more rows" (code 0); the
        # ORA-01403 end arrives on the next (empty) fetch.
        (rows2, term2, _) = self._decode(self.FETCH2, columns, last)
        self.assertEqual(rows2, [[4], [5]])
        self.assertEqual(decode_9i_oall8_status(term2)['code'], 0)

    def test_end_of_fetch_status_is_ora_01403(self):
        from seerdb.common.tns import decode_9i_oall8_terminal_error

        (code, message) = decode_9i_oall8_terminal_error(self.STATUS_1403)
        self.assertEqual(code, 1403)
        self.assertEqual(message, 'ORA-01403: no data found')

    # Non-query replies (an RPA piggyback then the OER): the affected-row count is
    # the status's rows. Live 9.2 replies to `insert ... values (1)` (one row) and
    # `update ... set id=id+5` (two rows). The frames recorded here at first were
    # two bytes shorter where the status carries its oerrdd, a form no request
    # reproduces -- committed or not, bound or not, INSERT or UPDATE, every live
    # reply is 150 bytes with it at 134 -- so they were taken again (#798).
    DML_INSERT = bytes.fromhex(
        '080500a35d300200000000010000000100000000000000000000000402000000'
        '010100000000000000000001000c00020000000000b266030001000000d2b800'
        '000100000000000000000d000001000000360100000000000000000000000000'
        '0080d0d403000000000d00000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000d000d01000366b200010000b8d20001'
    )
    DML_UPDATE = bytes.fromhex(
        '080500a45d300200000000010000000100000000000000000000000402000000'
        '010200000000000000000001000700060000000011b266030001000000d2b800'
        '000100000000000000000f000001000000360100000000000000000000000000'
        '0080d0d403000000000d00000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000d000d01000366b200010000b8d20001'
    )

    def test_dml_reply_reports_the_affected_row_count(self):
        from seerdb.common.tns import decode_9i_oall8_dml_response

        self.assertEqual(decode_9i_oall8_dml_response(self.DML_INSERT), (1, 0, None))
        self.assertEqual(decode_9i_oall8_dml_response(self.DML_UPDATE), (2, 0, None))

    def test_dml_reply_names_the_row_it_touched(self):
        # The status carries the rowid at offset 26 (#1079); the reply's tail
        # repeats it as a physical UROWID, big-endian, which checks the read.
        from seerdb.common.tns import decode_9i_oall8_dml_rowid
        from seerdb.common.types import urowid_to_string

        for reply in (self.DML_INSERT, self.DML_UPDATE, self.DML_FIRST_PARSE):
            with self.subTest(reply=reply[:4].hex()):
                self.assertEqual(
                    decode_9i_oall8_dml_rowid(reply), urowid_to_string(reply[-13:])
                )
        # A failed statement names no row.
        self.assertIsNone(decode_9i_oall8_dml_rowid(self.STATUS_1403))

    # Statuses of native 9.2 array INSERTs (native_9i_array_dml.pcap): rows 4, 1, 5
    # where 1 is a duplicate key; then OCI_BATCH_ERRORS batches with one failed row
    # (6, 2-duplicate, 7) and with two (2-duplicate, 8, 3-duplicate).
    ARRAY_DML_FAILED = bytes.fromhex(
        '04020000000101000000010000000000010000000200000000006a4e03000100'
        '0000d2b800000300000000000000000900000300000036010000000000000000'
        '00000000000080d0d403000000000d0000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000d000d0100034e6a00010000b8d20003384f52412d3030303031'
        '3a20756e6971756520636f6e73747261696e74202850594f2e5359535f433030'
        '39343933292076696f6c617465640a'
    )
    ARRAY_DML_ONE_BATCH_ERROR = bytes.fromhex(
        '040200000000020000003d5f0000000001000000020000000000000000000000'
        '0000000000000000000000000000000b00000300000036010000000000000000'
        '00000000000080d0d403000000000000000000000000a07dd603000000000100'
        '000000000000a87dd603000000000100000000000000b87dd603000000000100'
        '00000000000001000100000038000000384f52412d30303030313a20756e6971'
        '756520636f6e73747261696e74202850594f2e5359535f433030393439332920'
        '76696f6c617465640a000000000000214f52412d32343338313a206572726f72'
        '28732920696e20617272617920444d4c0a'
    )
    ARRAY_DML_TWO_BATCH_ERRORS = bytes.fromhex(
        '040200000000010000003d5f0000000001000000020000000000000000000000'
        '0000000000000000000000000000000d00000300000036010000000000000000'
        '00000000000080d0d403000000000000000000000000a07dd603000000000200'
        '000000000000a87dd603000000000200000000000000b87dd603000000000200'
        '00000000000001000100000000000200000038000000384f52412d3030303031'
        '3a20756e6971756520636f6e73747261696e74202850594f2e5359535f433030'
        '39343933292076696f6c617465640a00000000000038000000384f52412d3030'
        '3030313a20756e6971756520636f6e73747261696e74202850594f2e5359535f'
        '43303039343933292076696f6c617465640a000000000000214f52412d323433'
        '38313a206572726f7228732920696e20617272617920444d4c0a'
    )

    def test_a_failed_array_dml_counts_the_rows_it_applied(self):
        # The row before the duplicate went in, and the status counts it -- read
        # when asked for (Applied), as a single failed statement reports none.
        from seerdb.common.tns import decode_9i_oall8_dml_response

        (rows, code, message) = decode_9i_oall8_dml_response(
            self.ARRAY_DML_FAILED, Applied=True
        )
        self.assertEqual((rows, code), (1, 1))
        self.assertTrue(message.startswith('ORA-00001'))
        self.assertEqual(decode_9i_oall8_dml_response(self.ARRAY_DML_FAILED)[0], 0)

    def test_batch_errors_list_each_failed_row(self):
        from seerdb.common.tns import (
            decode_9i_oall8_batch_errors,
            decode_9i_oall8_dml_response,
        )

        (rows, code, message) = decode_9i_oall8_dml_response(
            self.ARRAY_DML_ONE_BATCH_ERROR, Applied=True
        )
        # The summary's own message, not the first row's listed ahead of it.
        self.assertEqual((rows, code), (2, 24381))
        self.assertTrue(message.startswith('ORA-24381'))
        errors = decode_9i_oall8_batch_errors(self.ARRAY_DML_ONE_BATCH_ERROR)
        self.assertEqual([(e['offset'], e['code']) for e in errors], [(1, 1)])
        self.assertTrue(errors[0]['message'].startswith('ORA-00001'))
        errors = decode_9i_oall8_batch_errors(self.ARRAY_DML_TWO_BATCH_ERRORS)
        self.assertEqual([(e['offset'], e['code']) for e in errors], [(0, 1), (2, 1)])
        self.assertTrue(all(e['message'].startswith('ORA-00001') for e in errors))
        self.assertEqual(decode_9i_oall8_batch_errors(self.ARRAY_DML_FAILED), [])

    # A native 9.2 OCI client's LOB calls on a CLOB selected FOR UPDATE
    # (native_9i_lob_ops.pcap): the select's reply, then each call's reply.
    LOB_GETLEN_REPLY = bytes.fromhex(
        '0800540001020c00000001000000010000000dca79000352f4000352f3000100'
        '01001f00000000000049000000008fb30000005d96022e6e3500000008001800'
        '00a2d10080149c03ec02000000000352f30040b8d200000b0000000402000000'
        '010100000000000000000000000000000000000000f352030001000000d2b800'
        '000000000000000000000a000001000000360100000000000000000000000000'
        '0080d0d403000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00'
    )
    LOB_CHUNK_REPLY = bytes.fromhex(
        '0800540001020c00000001000000010000000dca79000352f4000352f3000100'
        '01001f00000000000049000000008fb30000005d96022e6e3500000008001800'
        '00a2d10080149c03ec02000000000352f30040b8d20000c41f00000402000000'
        '010100000000000000000000000000000000000000f352030001000000d2b800'
        '000000000000000000000b000001000000360100000000000000000000000000'
        '0080d0d403000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00'
    )
    LOB_OPEN_REPLY = bytes.fromhex(
        '0800540001020c00000001000000010000000dca79000352f4000352f3000100'
        '01001f00000000000049000000008fb30000005d96022e6e3500000008001800'
        '00a2d10080149c03ec02000000000352f30040b8d20000020000000402000000'
        '010100000000000000000000000000000000000000f352030001000000d2b800'
        '000000000000000000000c000001000000360100000000000000000000000000'
        '0080d0d403000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00'
    )
    LOB_ISOPEN_REPLY = bytes.fromhex(
        '0800540001020c00000001000000010000000dca79000352f4000352f3000100'
        '01001f00000000000049000000008fb30000005d96022e6e3500000008001800'
        '00a2d10080149c03ec02000000000352f30040b8d20000010402000000010100'
        '000000000000000000000000000000000000f352030001000000d2b800000000'
        '000000000000000d0000010000003601000000000000000000000000000080d0'
        'd403000000000000000000000000000000000000000000000000000000000000'
        '000000000000000000000000000000000000000000000000000000000000'
    )
    LOB_WRITE_REPLY = bytes.fromhex(
        '0800540001020c00000001000000010000000dca79000352f4000352f3000100'
        '01001f00000000000049000000008fb30000005d96022e6e3600000008001800'
        '00a2d10080149c03ec03000000000352f30040b8d20000030000000402000000'
        '010100000000000000000000000000000000000000f352030001000000d2b800'
        '000000000000000000000e000001000000360100000000000000000000000000'
        '0080d0d403000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00'
    )
    LOB_TRIM_REPLY = bytes.fromhex(
        '0800540001020c00000001000000010000000dca79000352f4000352f3000100'
        '01001f00000000000049000000008fb30000005d96022e6e3600000008001800'
        '00a2d10080149c03ec04000000000352f30040b8d20000050000000402000000'
        '010100000000000000000000000000000000000000f352030001000000d2b800'
        '0000000000000000000010000001000000360100000000000000000000000000'
        '0080d0d403000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00'
    )
    LOB_CLOSE_REPLY = bytes.fromhex(
        '0800540001020c00000001000000010000000dca79000352f4000352f3000100'
        '01001f00000000000049000000008fb30000005d96022e6e3600000008001800'
        '00a2d10080149c03ec04000000000352f30040b8d20000040200000001010000'
        '0000000000000000000000000000000000f352030001000000d2b80000000000'
        '000000000000110000010000003601000000000000000000000000000080d0d4'
        '0300000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000'
    )
    LOB_ISOPEN2_REPLY = bytes.fromhex(
        '0800540001020c00000001000000010000000dca79000352f4000352f3000100'
        '01001f00000000000049000000008fb30000005d96022e6e3600000008001800'
        '00a2d10080149c03ec04000000000352f30040b8d20000000402000000010100'
        '000000000000000000000000000000000000f352030001000000d2b800000000'
        '00000000000000120000010000003601000000000000000000000000000080d0'
        'd403000000000000000000000000000000000000000000000000000000000000'
        '000000000000000000000000000000000000000000000000000000000000'
    )
    FOR_UPDATE_REPLY = bytes.fromhex(
        '101d607e960670164c5e000000000000787e0a1f022218a31700000000000000'
        '000000020000004b0170800000a00f0000000000000000000000000000000000'
        '00000000001f0001000000000000000000010101000000014300000000000000'
        '000171000000a00f000000000000000000000000000000000000000000000000'
        '0000000000000000000001010100000001420000000000000000070000000778'
        '7e0a1f022218060002bb02000000010000005d962a0000000000000000000000'
        '00004c5e0000000080d0d403000000000d00a25e0000000001000352f3000100'
        '00b8d2000007560000005600540001020c00000001000000010000000dca7900'
        '0352f4000352f300010001001f00000000000049000000008fb30000005d9602'
        '2e6e350000000800180000a2d10080149c03ec02000000000352f30040b8d200'
        '00560000005600540001010c00000001000000010000000dca7a000352f60003'
        '52f3000200020000000000000000000000000000000000000000022e6e350000'
        '000800180000a2d10080149c03ec02000000000352f30040b8d2000008050036'
        '6e2e020000000001000000010000000000000000000000040200000001010000'
        '0000000000000001001100030000000000f352030001000000d2b80000000000'
        '000000000000090000010000003601000000000000000000000000000080d0d4'
        '0300000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000'
    )

    # A native 9.2 OCI client's OAUTH reply (native_9i_lob_ops.pcap): the RPA of
    # AUTH_ pairs that completes an OALL8 login.
    OALL8_LOGIN_REPLY = bytes.fromhex(
        '0817001300000013415554485f56455253494f4e5f535452494e471200000012'
        '2d2036346269742050726f64756374696f6e000000001000000010415554485f'
        '56455253494f4e5f53514c02000000023138000000001300000013415554485f'
        '58414354494f4e5f545241495453010000000133000000000f0000000f415554'
        '485f56455253494f4e5f4e4f0900000009313533303933313230000000001300'
        '000013415554485f56455253494f4e5f53544154555301000000013000000000'
        '1500000015415554485f4341504142494c4954595f5441424c45000000000000'
        '00000f0000000f415554485f53455353494f4e5f494402000000023130000000'
        '000f0000000f415554485f53455249414c5f4e554d0500000005323031333100'
        '0000001000000010415554485f494e5354414e43455f4e4f0100000001310000'
        '00000f0000000f415554485f4e4c535f4c584c414e000800000008414d455249'
        '43414e000000001600000016415554485f4e4c535f4c58435445525249544f52'
        '59000700000007414d4552494341000000001500000015415554485f4e4c535f'
        '4c584343555252454e435900010000000124000000001400000014415554485f'
        '4e4c535f4c584349534f43555252000700000007414d45524943410000000015'
        '00000015415554485f4e4c535f4c58434e554d45524943530002000000022e2c'
        '000000001300000013415554485f4e4c535f4c584344415445464d0009000000'
        '0944442d4d4f4e2d5252000000001500000015415554485f4e4c535f4c584344'
        '4154454c414e47000800000008414d45524943414e0000000011000000114155'
        '54485f4e4c535f4c5843534f525400060000000642494e415259000000001500'
        '000015415554485f4e4c535f4c584343414c454e444152000900000009475245'
        '474f5249414e000000001500000015415554485f4e4c535f4c5843554e494f4e'
        '43555200010000000124000000001300000013415554485f4e4c535f4c584354'
        '494d45464d000e0000000e48482e4d492e535358464620414d00000000130000'
        '0013415554485f4e4c535f4c584353544d50464d00180000001844442d4d4f4e'
        '2d52522048482e4d492e535358464620414d000000001300000013415554485f'
        '4e4c535f4c584354545a4e464d00120000001248482e4d492e53535846462041'
        '4d20545a52000000001300000013415554485f4e4c535f4c584353545a4e464d'
        '001c0000001c44442d4d4f4e2d52522048482e4d492e535358464620414d2054'
        '5a52000000000401000000010000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000300000000000036010000'
        '00000000000000000000000080d0d40300000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000000000000000000000000'
    )

    def test_the_oall8_login_reply_names_the_release(self):
        # AUTH_VERSION_NO, in the 8i reply form: 0x09200400 is 9.2.0.4. The OALL8
        # login set no release, so connection.version was None (#798).
        from seerdb.common.tns import decode_8i_server_version

        self.assertEqual(decode_8i_server_version(self.OALL8_LOGIN_REPLY), 0x09200400)

    # 9.2 statuses (live): `CREATE OR REPLACE PROCEDURE ... BEGIN NULL; END;`,
    # the same with an undefined name in its body, and the refused
    # `SELECT nosuchcol FROM dual`.
    CREATE_CLEAN = bytes.fromhex(
        '080500c1e52e0200000000010000000000000000000000000000000401000000'
        '0100000000000000000000010000001800000000000000000000000000000000'
        '0000000000000000000007000001000000360100000000000000000000000000'
        '0080d0d403000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00'
    )
    CREATE_WITH_ERRORS = bytes.fromhex(
        '080500cce52e0200000000020000000000000000000000000000000401000000'
        '0100000000000000000000020000001800000000210000000000000000000000'
        '0000000000000000000008000001000000360100000000000000000000000000'
        '0080d0d403000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00'
    )
    QUERY_ERROR_AT_7 = bytes.fromhex(
        '0401000000010000000088030000000005000700000000000000000000000000'
        '0000000000000000000000000000000b00000100000036010000000000000000'
        '00000000000080d0d40300000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '0000000000002b4f52412d30303930343a20224e4f53554348434f4c223a2069'
        '6e76616c6964206964656e7469666965720a'
    )

    def test_a_status_carries_the_warning_and_the_error_position(self):
        # Bit 0x20 of the byte at 25 says the object compiled with errors
        # (#2262); the ub2 at 18 is where in the statement an error is (#2263).
        from seerdb.common.tns import (
            decode_9i_oall8_error_position,
            decode_9i_oall8_status,
            decode_9i_oall8_warn_flags,
        )

        self.assertEqual(decode_9i_oall8_warn_flags(self.CREATE_CLEAN) & 0x20, 0)
        self.assertEqual(
            decode_9i_oall8_warn_flags(self.CREATE_WITH_ERRORS) & 0x20, 0x20
        )
        self.assertEqual(decode_9i_oall8_status(self.QUERY_ERROR_AT_7)['code'], 904)
        self.assertEqual(decode_9i_oall8_error_position(self.QUERY_ERROR_AT_7), 7)

    # `SELECT txt, id, s` over a LONG first: the rows ('hi', 5, 'zz') and (NULL, 6,
    # 'yy'), each its own fetch (a LONG fetches one row at a time), live on 9.2.
    LONG_FIRST_ROW = bytes.fromhex(
        '0601022a030000000100000000000000000000000000000000000000d4030000'
        '00000000000000000000000020020000000007fe026869000000000002c10602'
        '7a7a080500000000000000000009000000010000000000000000000000040200'
        '0000010100000000000000000009000000030000000000b857030001000000d2'
        'b800000200000000000000000d00000100000036010000000000000000000000'
        '00000080d0d40300000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000000'
    )
    LONG_FIRST_NULL_ROW = bytes.fromhex(
        '060102e10300000001000000ffbf7f0000000000000000000000000060962a00'
        '00000000000000000000000060962a0000000700ffff7d0502c1070279790805'
        '0000000000000000000900000001000000000000000000000004020000000102'
        '00000000000000000009000000030000000000b857030001000000d2b8000002'
        '00000000000000000e0000010000003601000000000000000000000000000080'
        'd0d4030000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000'
    )

    def test_a_long_cell_ends_with_an_indicator_and_a_return_code(self):
        # The value, then a ub2 indicator and a ub2 return code, as an OUT bind's
        # cell; unread, the four bytes shifted the columns after the LONG (#798).
        columns = [
            {'data_type': 8, 'data_length': 0, 'charset': 31, 'csfrm': 1},
            {'data_type': 2, 'data_length': 22, 'charset': 0, 'csfrm': 0},
            {'data_type': 1, 'data_length': 5, 'charset': 31, 'csfrm': 1},
        ]
        (rows, _, _) = self._decode(self.LONG_FIRST_ROW, columns)
        self.assertEqual(rows, [['hi', 5, 'zz']])
        (rows, _, _) = self._decode(self.LONG_FIRST_NULL_ROW, columns)
        self.assertEqual(rows, [[None, 6, 'yy']])

    def test_a_status_whose_tail_does_not_read_still_gives_its_head(self):
        # A status the full schema cannot read -- here a live one cut after its
        # head -- still gives its code and cursor from the head (_O9I_STATUS_HEAD),
        # as every status did before the schema (#798).
        from seerdb.common.tns import (
            decode_9i_oall8_cursor_id,
            decode_9i_oall8_status,
        )

        head = self.STATUS_1403[:60]
        self.assertEqual(decode_9i_oall8_status(head)['code'], 1403)
        self.assertEqual(decode_9i_oall8_cursor_id(head), 1)

    def test_the_cursor_id_is_a_ub2(self):
        # The status's cursor id is a ub2 at 16: a session's 256th statement reads
        # `00 01` (this status head, live on 9.2). Read as one byte it was 0, and
        # the fetch failed with ORA-01002 (#798).
        from seerdb.common.tns import decode_9i_oall8_cursor_id

        # The live status head above, on the rest of a live status (EXEC's).
        status = bytearray(self.EXEC[self.EXEC.rfind(b'\x04\x01\x00\x00\x00') :])
        status[:24] = bytes.fromhex('040100000001010000000000000000000001120003000000')
        self.assertEqual(decode_9i_oall8_cursor_id(bytes(status)), 256)

    # A 300-bind block's reply (an IN Var, an OUT Var, 298 IN numbers), live on
    # 9.2: the IOV is 50 + 300 bytes.
    BLOCK_300_BINDS = bytes.fromhex(
        '0b0105002c000100010000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000002010202020202020202020202020'
        '2020202020202020202020202020202020202020202020202020202020202020'
        '2020202020202020202020202020202020202020202020202020202020202020'
        '2020202020202020202020202020202020202020202020202020202020202020'
        '2020202020202020202020202020202020202020202020202020202020202020'
        '2020202020202020202020202020202020202020202020202020202020202020'
        '2020202020202020202020202020202020202020202020202020202020202020'
        '2020202020202020202020202020202020202020202020202020202020202020'
        '2020202020202020202020202020202020202020202020202020202020202020'
        '2020202020202020202020202020202020202020202020202020202020200703'
        'c2040400000000080500195a2f02000000000100000000000000000000000000'
        '000004010000000101000000000000000000010000002f000000000000000000'
        '00000000000000000000000000000000000a0000010000003601000000000000'
        '000000000000000080d0d4030000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000'
    )

    def test_a_blocks_cursor_is_read_past_its_bind_prompt(self):
        # A scan from the reply's start lands on a `04` inside the bind prompt and
        # reads 256; closing that cursor drew ORA-00600 [12209] and lost the
        # session (#798). Read past the prompt and the OUT values, it is 1.
        from seerdb.common.tns import decode_9i_oall8_block_cursor

        self.assertEqual(decode_9i_oall8_block_cursor(self.BLOCK_300_BINDS, 300, 1), 1)

    def test_a_for_update_row_header_carries_the_rowid(self):
        # The row header names a 13-byte rowid (a ub2 at 42) between it and the
        # row: SELECT ... FOR UPDATE sends the row it locks. Unskipped, the row
        # was lost and the query came back empty (#798).
        from seerdb.common.tns import decode_9i_oall8_describe

        (columns, rest) = decode_9i_oall8_describe(self.FOR_UPDATE_REPLY)
        (rows, terminal, _) = self._decode(rest, columns)
        self.assertEqual(len(rows), 1)
        self.assertEqual([len(lob.raw) for lob in rows[0]], [86, 86])
        self.assertEqual([lob.data_type for lob in rows[0]], [112, 113])

    def test_lob_call_replies_carry_their_value_and_the_locator(self):
        # Each reply is an RPA with the locator's body (no ub2 prefix, as the LOB
        # object expects; it puts the prefix back) and the call's value.
        from seerdb.common.tns import (
            decode_9i_oall8_describe,
            decode_9i_oall8_lob_value,
        )
        from seerdb.common.tns_consts import (
            TNS_LOB_OP_CLOSE,
            TNS_LOB_OP_GET_CHUNK_SIZE,
            TNS_LOB_OP_GET_LENGTH,
            TNS_LOB_OP_IS_OPEN,
            TNS_LOB_OP_OPEN,
            TNS_LOB_OP_TRIM,
            TNS_LOB_OP_WRITE,
        )

        (columns, rest) = decode_9i_oall8_describe(self.FOR_UPDATE_REPLY)
        clob = self._decode(rest, columns)[0][0][0].raw
        for reply, op, value in (
            (self.LOB_GETLEN_REPLY, TNS_LOB_OP_GET_LENGTH, 11),
            (self.LOB_CHUNK_REPLY, TNS_LOB_OP_GET_CHUNK_SIZE, 8132),
            (self.LOB_OPEN_REPLY, TNS_LOB_OP_OPEN, 2),
            (self.LOB_ISOPEN_REPLY, TNS_LOB_OP_IS_OPEN, 1),
            (self.LOB_WRITE_REPLY, TNS_LOB_OP_WRITE, 3),
            (self.LOB_TRIM_REPLY, TNS_LOB_OP_TRIM, 5),
            (self.LOB_CLOSE_REPLY, TNS_LOB_OP_CLOSE, None),
            (self.LOB_ISOPEN2_REPLY, TNS_LOB_OP_IS_OPEN, 0),
        ):
            with self.subTest(op=hex(op)):
                (got, locator) = decode_9i_oall8_lob_value(reply, op)
                self.assertEqual(got, value)
                self.assertEqual(len(locator), len(clob) - 2)
        # A write changes the locator; the reply says so.
        self.assertEqual(
            decode_9i_oall8_lob_value(self.LOB_GETLEN_REPLY, TNS_LOB_OP_GET_LENGTH)[1],
            clob[2:],
        )
        self.assertNotEqual(
            decode_9i_oall8_lob_value(self.LOB_WRITE_REPLY, TNS_LOB_OP_WRITE)[1],
            clob[2:],
        )

    # A bound statement's first-parse reply opens with a TTI_IOV (0x0b) bind
    # prompt and the session-state RPA carries a byte (0x04) that collides with the
    # OER token -- the status reader must skip past it to the real OER. Real 9.2
    # frame for the first execute of `insert ... values (:1)` (one row).
    DML_FIRST_PARSE = bytes.fromhex(
        '0b01056601000000010000000000000000008a020000000000000000ca5e0000'
        '0000000000000100000000000000000000002008050093042c02000000000200'
        '0000020000000000000000000000040500000001010000000000000000000200'
        '0c000200000000008c44030001000000d2b80000000000000000000000080000'
        '010000003601000000000000000000000000000080d0d403000000000d000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000d000d010003448c00010000'
        'b8d20000'
    )

    def test_bound_first_parse_reply_skips_the_iov_to_the_real_oer(self):
        from seerdb.common.tns import decode_9i_oall8_dml_response

        # The row count sits in the real OER, not the 0x04 inside the RPA.
        self.assertEqual(
            decode_9i_oall8_dml_response(self.DML_FIRST_PARSE), (1, 0, None)
        )

    # A PL/SQL block's OUT value: the reply is the IOV (50 + nbinds bytes), then a
    # TTI_RXD of one value-only cell per OUT bind (each a ub1 length, the value, a
    # ub4 indicator), then the status. Real 9.2 frame for `begin :1 := 42; end;`
    # with one OUT bind -- the value is NUMBER 42 (c1 2b), to decode per the Var.
    BLOCK_OUT_42 = bytes.fromhex(
        '0b01050001000000010000000000000000000000000000000000000000000000'
        '000000000000000000000000000000000000100702c12b00000000080500d508'
        '2c02000000000100000002000000000000000000000004050000000101000000'
        '000000000000010000002f000000000000000000000000000000000000000000'
        '0000000000070000010000003601000000000000000000000000000080d0d403'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000'
    )

    def test_block_out_value_is_read_per_out_bind(self):
        from seerdb.common.tns import decode_9i_oall8_block_out

        # one bind, one OUT: raw NUMBER 42 (c1 2b), rowcount/code 0.
        (out_values, _rows, code, _msg) = decode_9i_oall8_block_out(
            self.BLOCK_OUT_42, 1, 1
        )
        self.assertEqual(out_values, [bytes.fromhex('c12b')])
        self.assertEqual(code, 0)

    # `select id, b from t order by id` over a BLOB column, rows (2, NULL) and
    # (3, EMPTY_BLOB()). A LOB query's execute is describe-only; the fetch brings
    # the rows, each LOB cell a ub4 size and then (when not zero) the locator as a
    # ub1-length value -- a NULL LOB is the zero size alone. Real 9.2 frames.
    LOB_EXEC = bytes.fromhex(
        '101d5a0517cc20e7b55e000000000000787e0a1e17392dc50600000000000000'
        '000000020000004b010200008116000000000000000000000000000000000000'
        '0000000000000000000000000000000000010206000000024944000000000000'
        '00000171000000a00f0000000000000000000000000000000000000000000000'
        '0000000000000000000000010103000000014200000000000000000700000007'
        '787e0a1e17392d080500698d2c02000000000900000000000000000000000000'
        '00000401000000010000000000000000000009001200030000000000f0440300'
        '01000000d2b800000100000000000000000c0000010000003601000000000000'
        '000000000000000080d0d4030000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000'
    )
    LOB_FETCH = bytes.fromhex(
        '0601022a020000000f00000000000000000000000000000000000000d4030000'
        '0000000000000000000000002002000000000702c10300000000150200030702'
        'c104560000005600540001010c00000001000000010000000d8041000344f100'
        '0344f0000200020000000000000000000000000000000000000000022c8d6900'
        '00000000000000000000000000000000000000000344f00040b8d20001040100'
        '000001020000007b050000000009000000030020000000f044030001000000d2'
        'b800000100000000000000000d00000100000036010000000000000000000000'
        '00000080d0d40300000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000000194f52412d30313430333a206e6f206461746120666f756e640a'
    )

    def test_lob_cells_carry_a_locator_or_null(self):
        from seerdb.common.lob import LOB
        from seerdb.common.tns import decode_9i_oall8_describe, decode_9i_oall8_status

        (columns, rest) = decode_9i_oall8_describe(self.LOB_EXEC)
        self.assertEqual([c['data_type'] for c in columns], [2, 113])  # NUMBER, BLOB
        (rows, _term, _) = self._decode(rest, columns)
        self.assertEqual(rows, [])  # describe-only execute
        (rows, term, _) = self._decode(self.LOB_FETCH, columns)
        self.assertEqual([r[0] for r in rows], [2, 3])
        self.assertIsNone(rows[0][1])  # NULL BLOB: the zero size alone
        self.assertIsInstance(rows[1][1], LOB)  # EMPTY_BLOB: a real locator
        self.assertEqual(len(rows[1][1].raw), 86)
        self.assertEqual(rows[1][1].raw[:2], bytes.fromhex('0054'))
        self.assertEqual(decode_9i_oall8_status(term)['code'], 1403)

    # BFILENAME('BFDIR', 'hello.bin') on 9.2 over the OALL8 session: the fetched
    # locator, and the replies to its FILE_OPEN and GET_LENGTH (64-bit LOBOPS).
    BFILE_LOCATOR = bytes.fromhex(
        '0020000108080000000100000000000000054246444952000968656c6c6f2e62696e'
    )
    BFILE_OPEN_REPLY = bytes.fromhex(
        '080020000108080000000100010000000000054246444952000968656c6c6f2e'
        '62696e0b00000004010000000101000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000008000001000000360100'
        '0000000000000000000000000080d0d403000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000'
    )
    BFILE_GETLEN_REPLY = bytes.fromhex(
        '080020000108080000000100010000000000054246444952000968656c6c6f2e'
        '62696e1400000004010000000101000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000009000001000000360100'
        '0000000000000000000000000080d0d403000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000'
    )

    def test_bfile_open_and_length_replies(self):
        # FILE_OPEN hands back the locator with its open flag (byte 11) set, which
        # the later calls must use; GET_LENGTH's reply carries the 20-byte length
        # where 8i's does, so the 8i reader parses it (the thin one reads 0).
        from seerdb.common.tns import (
            decode_fv2_opened_locator,
            decode_o8i_bfile_getlen,
        )

        opened = decode_fv2_opened_locator(self.BFILE_OPEN_REPLY)
        self.assertEqual(len(opened), len(self.BFILE_LOCATOR))
        self.assertEqual(self.BFILE_LOCATOR[11], 0)
        self.assertEqual(opened[11], 1)
        self.assertEqual(opened[:11], self.BFILE_LOCATOR[:11])
        self.assertEqual(decode_o8i_bfile_getlen(self.BFILE_GETLEN_REPLY), 20)

    # A fetch of `SELECT id, name, score` (rows 2-5 of five; row 5 NULL in both
    # text columns) from a live 9.2 server: each row header announces a one-byte
    # column vector, 0x07 for three columns all sent -- the TTI_RXD token.
    FETCH_THREE_COLUMNS = bytes.fromhex(
        '060002e10300000064000000ffbf7f00000058bfd60300000000010060962a00'
        '000000000000000000000000200200000000070702c103046265746103c10a64'
        '150300070702c1040567616d6d6104c2020133150300070702c1050564656c74'
        '61043e644c66150300070702c1060000040100000001050000007b0500000000'
        '110000000300200000007449030001000000d2b8000004000000000000000015'
        '0000010000003601000000000000000000000000000080d0d403000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000194f52412d3031343033'
        '3a206e6f206461746120666f756e640a'
    )
    # The execute reply's row stream for `SELECT NULL AS a, 5 AS b FROM dual`.
    UNTYPED_NULL_ROW = bytes.fromhex(
        '060102b402000000010000005d962a0000000000000000000000000000000000'
        '0000000000000000000000000000000000000702c1060805002b5f2d02000000'
        '0001000000000000000000000000000000040100000001010000000000000000'
        '0001001e00030000000000000000000000000000000000000000000000000000'
        '070000010000003601000000000000000000000000000080d0d4030000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000'
    )

    def test_a_row_header_names_its_column_vector(self):
        # The vector's length is a ub2 at the header's offset 26. Guessing it
        # from the byte after the header took a 0x07 vector for a row token and
        # misread every row after it as a NUMBER.
        from decimal import Decimal

        columns = [
            {'data_type': 2, 'data_length': 22, 'charset': 0, 'csfrm': 0},
            {'data_type': 1, 'data_length': 40, 'charset': 31, 'csfrm': 1},
            {'data_type': 2, 'data_length': 22, 'charset': 0, 'csfrm': 0},
        ]
        (rows, _, _) = self._decode(self.FETCH_THREE_COLUMNS, columns)
        self.assertEqual(
            rows,
            [
                [2, 'beta', Decimal('9.99')],
                [3, 'gamma', Decimal('100.5')],
                [4, 'delta', Decimal('-1.25')],
                [5, None, None],
            ],
        )

    def test_an_untyped_null_column_sends_no_cell(self):
        # `SELECT NULL` describes with a zero data length and sends nothing for
        # the column, not even the 0xFF NULL (#682 / #1185 at OALL8).
        columns = [
            {'data_type': 1, 'data_length': 0, 'charset': 31, 'csfrm': 1},
            {'data_type': 2, 'data_length': 2, 'charset': 0, 'csfrm': 0},
        ]
        (rows, _, _) = self._decode(self.UNTYPED_NULL_ROW, columns)
        self.assertEqual(rows, [[None, 5]])

    # `SELECT rowid, k` of a one-row table: the ROWID cell is the 16-byte OCI rowid
    # structure, little-endian.
    ROWID_ROW = bytes.fromhex(
        '060102b202000000010000005d962a0000000000000000000000000000000000'
        '00000000000000000000000000000000000007106b4b030001000000d2b80000'
        '0000000002c102080500cf952d02000000000100000000000000000000000000'
        '0000040100000001010000000000000000000100150003000000000000000000'
        '0000000000000000000000000000000000070000010000003601000000000000'
        '000000000000000080d0d4030000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000'
    )
    # `SELECT u, k` over a UROWID column: a physical rowid (the execute reply),
    # then a NULL and an index-organized table's 409-byte logical rowid, chunked
    # (the fetch reply).
    UROWID_EXEC = bytes.fromhex(
        '0601022a020000000100000000000000000000000000000000000000d4030000'
        '000000000000000000000000200200000000070d000d0100034b6b00010000b8'
        'd2000002c102080500cf952d0200000000020000000000000000000000000000'
        '0004010000000101000000000000000000020011000300000000000000000000'
        '0000000000000000000000000000000009000001000000360100000000000000'
        '0000000000000080d0d403000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000'
    )
    UROWID_FETCH = bytes.fromhex(
        '0600022a020000006400000000000000000048bfd603000000000100d4030000'
        '0000000000000000000000002002000000000307000002c10315020003079901'
        'feff02040040b96a81906b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b9a6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b'
        '6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6bfe0002c104'
        '040100000001030000007b050000000002000000030020000000000000000000'
        '0000000000000000000000000000000a00000100000036010000000000000000'
        '00000000000080d0d40300000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000000000000194f52412d30313430333a206e6f206461746120666f756e640a'
    )

    def test_a_rowid_cell_reads_as_its_text(self):
        columns = [
            {'data_type': 11, 'data_length': 16, 'charset': 0, 'csfrm': 0},
            {'data_type': 2, 'data_length': 22, 'charset': 0, 'csfrm': 0},
        ]
        (rows, _, _) = self._decode(self.ROWID_ROW, columns)
        self.assertEqual(rows, [['AAA0trAABAAALjSAAA', 1]])

    def test_a_urowid_cell_is_sized_then_framed_as_a_value(self):
        # A ub2 size, then the rowid as an ordinary (possibly chunked) value; a
        # NULL is the zero size alone. Reading it as a plain value misread every
        # column after it.
        columns = [
            {'data_type': 208, 'data_length': 4000, 'charset': 0, 'csfrm': 0},
            {'data_type': 2, 'data_length': 22, 'charset': 0, 'csfrm': 0},
        ]
        (rows, _, last) = self._decode(self.UROWID_EXEC, columns)
        self.assertEqual(rows, [['AAA0trAABAAALjSAAA', 1]])
        (rows, _, _) = self._decode(self.UROWID_FETCH, columns, last)
        self.assertEqual(rows[0], [None, 2])
        self.assertEqual(rows[1][1], 3)
        self.assertEqual(len(rows[1][0]), 545)
        self.assertTrue(rows[1][0].startswith('*BABAuWqBkGtra2tra2t'))

    # PL/SQL block replies from a live 9.2 server: two OUT binds a RETURNING ...
    # INTO that matched no row never assigned; `:result := 'got ' || :given`
    # (OUT, IN); and a SELECT ... INTO matching nothing, which fails at run time.
    BLOCK_TWO_UNASSIGNED = bytes.fromhex(
        '0b01050002000000010000000000000000000000000000000000000000000000'
        '000000000000000000000000000000000000101007ff210cff210c080500929f'
        '2d02000000000700000002000000000000000000000004050000000101000000'
        '000000000000070000002f000000000000000000000000000000000000000000'
        '00000000000a0000010000003601000000000000000000000000000080d0d403'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000'
    )
    BLOCK_OUT_THEN_IN = bytes.fromhex(
        '0b01050002000000010000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000001020070b676f7420612076616c75'
        '6500000000080500929f2d02000000000a000000020000000000000000000000'
        '040500000001010000000000000000000a0000002f0000000000000000000000'
        '0000000000000000000000000000000c00000100000036010000000000000000'
        '00000000000080d0d40300000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000000000000'
    )
    BLOCK_NO_ROWS = bytes.fromhex(
        '040100000001000000007b05000000000c0000002f0000000000000000000000'
        '0000000000000000000000000000000e00000000000036010000000000000000'
        '00000000000080d0d40300000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '0000000000002e4f52412d30313430333a206e6f206461746120666f756e640a'
        '4f52412d30363531323a206174206c696e6520310a'
    )

    def test_an_unassigned_out_bind_is_a_null(self):
        # 0xFF and a ub2 return code, nothing more (#801's OALL8 form). Read as a
        # length, the first one ran into the second and the status.
        from seerdb.common.tns import decode_9i_oall8_block_out

        (values, _, code, _) = decode_9i_oall8_block_out(
            self.BLOCK_TWO_UNASSIGNED, 2, 2
        )
        self.assertEqual((values, code), ([None, None], 0))

    def test_the_bind_prompt_names_each_binds_direction(self):
        # One mask per bind after the prompt's 50-byte head: OUT, then IN. Only the
        # OUT one comes back (#1242).
        from seerdb.common.tns import (
            decode_9i_oall8_bind_directions,
            decode_9i_oall8_block_out,
        )

        self.assertEqual(
            decode_9i_oall8_bind_directions(self.BLOCK_OUT_THEN_IN, 2), [16, 32]
        )
        (values, _, code, _) = decode_9i_oall8_block_out(self.BLOCK_OUT_THEN_IN, 2, 1)
        self.assertEqual((values, code), ([b'got a value'], 0))

    def test_a_block_that_fails_answers_with_the_bare_status(self):
        # No prompt: the reply is the status, ORA-01403. Skipping a prompt's length
        # first landed past it and read the failure as success (#1039).
        from seerdb.common.tns import (
            decode_9i_oall8_bind_directions,
            decode_9i_oall8_block_out,
        )

        self.assertIsNone(decode_9i_oall8_bind_directions(self.BLOCK_NO_ROWS, 1))
        (values, _, code, message) = decode_9i_oall8_block_out(self.BLOCK_NO_ROWS, 1, 1)
        self.assertEqual((values, code), ([], 1403))
        self.assertTrue(message.startswith('ORA-01403'))

    # `BEGIN OPEN :1 FOR SELECT 1 a, 'x' b FROM dual; END;` and
    # `BEGIN :1 := RPAD('a', 300, 'b'); END;` from a live 9.2 server.
    BLOCK_REFCURSOR = bytes.fromhex(
        '0b01050001000000010000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000030072c00000000020000004b0102'
        '0000000200000000000000000000000000000000000000000000000000000000'
        '0000000000000001010300000001410000000000000000016080000001000000'
        '00000000000000000000000000000000000000001f0001000100000000000000'
        '010103000000014200000000000000000700000007787e0a1f012b0502000000'
        '00000000080500aba62d02000000000100000002000000000000000000000004'
        '050000000101000000000000000000010000002f000000000000000000000000'
        '0000000000000000000000000000070000010000003601000000000000000000'
        '000000000080d0d4030000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '0000000000'
    )
    BLOCK_LONG_OUT = bytes.fromhex(
        '0b01050001000000010000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000001007fe4061626262626262626262'
        '6262626262626262626262626262626262626262626262626262626262626262'
        '6262626262626262626262626262626262626262626240626262626262626262'
        '6262626262626262626262626262626262626262626262626262626262626262'
        '6262626262626262626262626262626262626262626262406262626262626262'
        '6262626262626262626262626262626262626262626262626262626262626262'
        '6262626262626262626262626262626262626262626262624062626262626262'
        '6262626262626262626262626262626262626262626262626262626262626262'
        '626262626262626262626262626262626262626262626262622c626262626262'
        '6262626262626262626262626262626262626262626262626262626262626262'
        '6262626262620000000000080500aba62d020000000003000000020000000000'
        '00000000000004050000000101000000000000000000030000002f0000000000'
        '0000000000000000000000000000000000000000000900000100000036010000'
        '00000000000000000000000080d0d40300000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000000000000000000000000'
    )

    def test_a_refcursor_out_bind_carries_its_describe_and_id(self):
        # The cell is a lead byte, the opened cursor's describe and its id; the
        # rows are fetched by that id. It came back as the raw cell bytes.
        from seerdb.common.tns import decode_9i_oall8_block_out

        (values, _, code, _) = decode_9i_oall8_block_out(
            self.BLOCK_REFCURSOR, 1, 1, frozenset({0})
        )
        self.assertEqual(code, 0)
        (cursor, columns) = values[0]
        self.assertGreater(cursor, 0)
        self.assertEqual([c['column_name'] for c in columns], ['A', 'B'])

    def test_a_long_out_value_is_chunked(self):
        # Past 252 bytes the value comes 0xFE-chunked; read as one length it kept
        # the 64-byte chunk lengths in the text.
        from seerdb.common.tns import decode_9i_oall8_block_out

        (values, _, code, _) = decode_9i_oall8_block_out(self.BLOCK_LONG_OUT, 1, 1)
        self.assertEqual((values, code), ([b'a' + b'b' * 299], 0))


class TestNative9iOall8Typed(unittest.TestCase):
    # Typed columns over the native 9i OALL8 path (#798), from sqlplus 9.2's
    # native_9i_objects.pcap: an object column (`SELECT id, p` of PYO_O798_PT),
    # its NULL in the next fetch, a VARRAY column and a CURSOR(...) column.
    OBJECT_EXEC = bytes.fromhex(
        '101d0dd77d57b0dcbd62000000000000787e0a1f051234963200000100000056'
        '000000020000004b010200008116000000000000000000000000000000000000'
        '0000000000000000000000000000000000010202000000024944000000000000'
        '00000079000000d0070000000000000000000010000000105f1c3237d9a9537f'
        'e060007f0100130e010000000000000000010101000000015003000000035059'
        '4f0b0000000b50594f5f4f3739385f50540700000007787e0a1f051234060102'
        '2a0200000001000000ffbf7f00000000000000000000000000ffbf7f00000000'
        '000000000000000000bb62000000000702c1022400000024002202085f1c3237'
        'd9a9537fe060007f0100130e0000000000000000000000000001000100000000'
        '0000000000000a00000001000a84010a02c102036f6e65080500e59531020000'
        '0000010000000000000000000000000000000401000000010100000000000000'
        '0000010012000300000000005b73030001000000d2b800000100000000000000'
        '002b0000010000003601000000000000000000000000000080d0d40300000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000000000000000000000000000000000000000000000000'
    )
    OBJECT_FETCH = bytes.fromhex(
        '060002000200000002000000d4030000000048bfd60300000000010016030000'
        '000000000000000000000000d40300000000030702c103240000002400220208'
        '5f1c3237d9a9537fe060007f0100130e00000000000000000000000000010001'
        '00000000000000000000000000000100040100000001020000007b0500000000'
        '010000000300200000005b73030001000000d2b8000001000000000000000033'
        '0000010000003601000000000000000000000000000080d0d403000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000194f52412d3031343033'
        '3a206e6f206461746120666f756e640a'
    )
    VARRAY_EXEC = bytes.fromhex(
        '101dda4da24b3864bc62000000000000787e0a1f0512349832000001000000ae'
        '000000020000004b010200008116000000000000000000000000000000000000'
        '0000000000000000000000000000000000010202000000024944000000000000'
        '0000007b000000d0070000000000000000000010000000105f1c3237d9ae537f'
        'e060007f0100130e010000000000000000010101000000014e03000000035059'
        '4f0d0000000d50594f5f4f3739385f4e554d530700000007787e0a1f05123406'
        '01022a0200000001000000ffbf7f00000000000000000000000000ffbf7f0000'
        '0000000000000000000000bb62000000000702c1022400000024002202085f1c'
        '3237d9ae537fe060007f0100130e000000000000000000000000000100010000'
        '0000000000000000100000000100108801100101000302c10202c10302c10408'
        '0500e59531020000000001000000000000000000000000000000040100000001'
        '01000000000000000000010012000300000000005b73030001000000d2b80000'
        '0100000000000000003700000100000036010000000000000000000000000000'
        '80d0d40300000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
    )
    CURSOR_EXEC = bytes.fromhex(
        '101d4e92f50cc8c4ba62000000000000787e0a1f051234ae3800000000000016'
        '000000010000004b016600000005000000000000000000000000000000000000'
        '0000000000000000000000000000000000010101000000014300000000000000'
        '000700000007787e0a1f0512340601021e010000000100000061962a00000000'
        '0000000000000000000000000000000000000000000000000000000000000007'
        '2c00000000010000004b01020000001600000000000000000000000000000000'
        '00000000000000000000000000000000000000010505000000054c4556454c00'
        '000000000000000700000007787e0a1f05123403000000080500e59531020000'
        '0000010000000000000000000000000000000401000000010100000000000000'
        '0000010039000300000000005b73030001000000d2b800000100000000000000'
        '004a0000010000003601000000000000000000000000000080d0d40300000000'
        '0000000000000000000000000000000000000000000000000000000000000000'
        '000000000000000000000000000000000000000000000000'
    )

    def _decode(self, data, columns, prev=None):
        from seerdb.common.tns import (
            _DECODE_FIELD_VERSION,
            FIELD_VERSION_9_2,
            decode_9i_oall8_exec_response,
        )

        token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_9_2)
        try:
            return decode_9i_oall8_exec_response(data, columns, prev)
        finally:
            _DECODE_FIELD_VERSION.reset(token)

    def test_an_object_column_describes_as_thins_adt_with_its_type(self):
        # 9.2 describes the column with its dictionary type (121) and names the
        # type with a ub4 length; the describe ends on the first row header.
        from seerdb.common.tns import TNS_TYPE_ADT, decode_9i_oall8_describe

        (columns, rest) = decode_9i_oall8_describe(self.OBJECT_EXEC)
        self.assertEqual([c['column_name'] for c in columns], ['ID', 'P'])
        self.assertEqual(columns[1]['data_type'], TNS_TYPE_ADT)
        self.assertEqual(columns[1]['type_schema'], 'PYO')
        self.assertEqual(columns[1]['type_name'], 'PYO_O798_PT')
        self.assertEqual(
            columns[1]['type_oid'], bytes.fromhex('5f1c3237d9a9537fe060007f0100130e')
        )
        self.assertEqual(rest[0], 0x06)

    def test_an_object_cell_carries_its_image(self):
        from seerdb.common.dbobject import ObjectImage
        from seerdb.common.tns import decode_9i_oall8_describe

        (columns, rest) = decode_9i_oall8_describe(self.OBJECT_EXEC)
        (rows, terminal, _) = self._decode(rest, columns)
        self.assertEqual(len(rows), 1)
        (ident, value) = rows[0]
        self.assertEqual(ident, 1)
        self.assertIsInstance(value, ObjectImage)
        self.assertEqual(value.type_name, 'PYO_O798_PT')
        # PYO_O798_PT(1, 'one'): the pickled image, NUMBER 1 and 'one'.
        self.assertEqual(value.image, bytes.fromhex('84010a02c102036f6e65'))
        self.assertEqual(terminal[0], 0x08)  # the RPA, then the status

    def test_a_null_object_has_no_image(self):
        from seerdb.common.tns import decode_9i_oall8_describe

        (columns, _) = decode_9i_oall8_describe(self.OBJECT_EXEC)
        (rows, terminal, _) = self._decode(self.OBJECT_FETCH, columns)
        self.assertEqual(rows, [[2, None]])
        self.assertEqual(terminal[0], 0x04)

    def test_a_varray_column_reads_as_an_object_image(self):
        from seerdb.common.dbobject import ObjectImage
        from seerdb.common.tns import TNS_TYPE_ADT, decode_9i_oall8_describe

        (columns, rest) = decode_9i_oall8_describe(self.VARRAY_EXEC)
        self.assertEqual(columns[1]['data_type'], TNS_TYPE_ADT)
        self.assertEqual(columns[1]['type_name'], 'PYO_O798_NUMS')
        (rows, terminal, _) = self._decode(rest, columns)
        (ident, value) = rows[0]
        self.assertEqual(ident, 1)
        self.assertIsInstance(value, ObjectImage)
        # PYO_O798_NUMS(1, 2, 3): the collection image and its three NUMBERs.
        self.assertTrue(value.image.endswith(bytes.fromhex('02c10202c10302c104')))
        self.assertEqual(terminal[0], 0x08)

    def test_a_cursor_column_comes_opened_and_described(self):
        # The cell is a REF CURSOR OUT bind's without its indicator and return
        # code: the nested cursor's id and columns, the RPA right behind.
        from seerdb.common.tns import TNS_TYPE_REFCURSOR, decode_9i_oall8_describe

        (columns, rest) = decode_9i_oall8_describe(self.CURSOR_EXEC)
        self.assertEqual(columns[0]['data_type'], TNS_TYPE_REFCURSOR)
        (rows, terminal, _) = self._decode(rest, columns)
        ((cursor, nested),) = rows[0]
        self.assertEqual(cursor, 3)
        self.assertEqual([c['column_name'] for c in nested], ['LEVEL'])
        self.assertEqual(terminal[0], 0x08)


class TestO8iBfile(unittest.TestCase):
    """Oracle 8i native BFILE read (#401, PROTOCOL §19.17): FILE_OPEN -> GETLEN
    -> READ -> FILE_CLOSE over TTI_LOBOPS in the 8i envelope (ub4-LE lengths +
    25-byte op middle, §19.15) — no DBMS_LOB helper. Fixtures are real frames
    captured from a 9.2 OCI client -> 8.1.7 reading BFILENAME('BDUMP',
    'ORCLALRT.LOG') (the alert log; first 32 bytes 'Dump file C:\\oracle\\admin
    \\ORCL\\b')."""

    # Unopened locator (from the FILE_OPEN request) and the open-flagged locator
    # the FILE_OPEN reply hands back (byte at offset 11 flips 00 -> 01).
    LOC = bytes.fromhex(
        '0023000108080000000100000000000000054244554d50000c4f52434c414c52542e4c4f47'
    )
    FOPEN_REQ = bytes.fromhex(
        '036006012500000000000000000000000000000000000100000100000000000000'
        '0023000108080000000100000000000000054244554d50000c4f52434c414c5254'
        '2e4c4f470b000000'
    )
    FOPEN_RESP = bytes.fromhex(
        '080023000108080000000100010000000000054244554d50000c4f52434c414c52'
        '542e4c4f470b000000040100000000000000000000000000030060000000000000'
        '000000000000000000000000000000060000010000000000000000000000000000'
        '000000'
    )
    GETLEN_REQ = bytes.fromhex(
        '036007012500000000000000000000000000000000000100010000000000000000'
        '0023000108080000000100010000000000054244554d50000c4f52434c414c5254'
        '2e4c4f4700000000'
    )
    GETLEN_RESP = bytes.fromhex(
        '080023000108080000000100010000000000054244554d50000c4f52434c414c52'
        '542e4c4f47e4850000040100000000000000000000000000030060000000000000'
        '000000000000000000000000000000070000010000000000000000000000000000'
        '000000'
    )
    READ_RESP = bytes.fromhex(
        '0efe2044756d702066696c6520433a5c6f7261636c655c61646d696e5c4f52434c'
        '5c6200080023000108080000000100010000000000054244554d50000c4f52434c'
        '414c52542e4c4f4720000000'
    )
    FCLOSE_REQ = bytes.fromhex(
        '036009012500000000000000000000000000000000000000000200000000000000'
        '0023000108080000000100010000000000054244554d50000c4f52434c414c5254'
        '2e4c4f47'
    )

    def test_file_open_request_matches_capture(self):
        from seerdb.common.tns import encode_o8i_bfile_open

        self.assertEqual(encode_o8i_bfile_open(6, self.LOC), self.FOPEN_REQ)

    def test_opened_locator_then_getlen_read_close(self):
        from seerdb.common.tns import (
            decode_fv2_opened_locator,
            decode_o8i_bfile_getlen,
            encode_8i_lob_read,
            encode_o8i_bfile_close,
            encode_o8i_bfile_getlen,
        )

        # FILE_OPEN reply returns the open-flagged locator (shared 9i decoder).
        opened = decode_fv2_opened_locator(self.FOPEN_RESP)
        self.assertEqual(opened[11], 1)  # open flag set (was 0 in LOC)
        self.assertEqual(self.LOC[11], 0)
        self.assertEqual(encode_o8i_bfile_getlen(7, opened), self.GETLEN_REQ)
        self.assertEqual(decode_o8i_bfile_getlen(self.GETLEN_RESP), 34276)
        # READ reuses the 8i CLOB/BLOB read encoder (encode_8i_lob_read) with the
        # opened locator; its middle is covered by the CLOB/BLOB read tests.
        self.assertEqual(encode_8i_lob_read(8, opened, 32)[:4], b'\x03\x60\x08\x01')
        self.assertEqual(encode_o8i_bfile_close(9, opened), self.FCLOSE_REQ)

    def test_read_response_content(self):
        from seerdb.common.tns import decode_fv2_lob_chunks

        content, done = decode_fv2_lob_chunks(self.READ_RESP)
        self.assertTrue(done)
        self.assertEqual(content, b'Dump file C:\\oracle\\admin\\ORCL\\b')


class TestZeroLengthColumn(unittest.TestCase):
    """A column described with a zero data length is NULL and occupies nothing.

    `SELECT NULL AS x` (and `SELECT ''`) describes exactly this way. The server
    sends no bytes for it — not even the empty DALC an ordinary NULL would
    carry — so reading one consumed the following token and desynced the rest of
    the response (#682).
    """

    def test_it_is_null_and_consumes_nothing(self):
        from seerdb.common.tns_consts import TNS_TYPE_VARCHAR, TTI_RXD, TTI_STA

        row_format = [
            {'data_type': TNS_TYPE_VARCHAR, 'column_name': b'A', 'data_length': 0}
        ]
        body = bytes([TTI_RXD]) + bytes([TTI_STA])
        (done, acc) = decode_packet(body, (None, row_format, []))
        self.assertTrue(done)
        self.assertEqual(acc[2], [[None]])

    def test_it_does_not_swallow_the_next_column(self):
        from seerdb.common.tns import encode_value
        from seerdb.common.tns_consts import (
            TNS_TYPE_NUMBER,
            TNS_TYPE_VARCHAR,
            TTI_RXD,
            TTI_STA,
        )

        row_format = [
            {'data_type': TNS_TYPE_VARCHAR, 'column_name': b'A', 'data_length': 0},
            {'data_type': TNS_TYPE_NUMBER, 'column_name': b'N', 'data_length': 22},
        ]
        body = bytes([TTI_RXD]) + encode_value(42, TNS_TYPE_NUMBER) + bytes([TTI_STA])
        (done, acc) = decode_packet(body, (None, row_format, []))
        self.assertTrue(done)
        self.assertEqual(acc[2], [[None, 42]])

    def test_a_number_is_not_mistaken_for_one(self):
        # A NUMBER is described with max_size 0 but a non-zero data length, so
        # keying the skip on max_size would drop every numeric value.
        from seerdb.common.tns import encode_value
        from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TTI_RXD, TTI_STA

        row_format = [
            {
                'data_type': TNS_TYPE_NUMBER,
                'column_name': b'N',
                'data_length': 22,
                'max_size': 0,
            }
        ]
        body = bytes([TTI_RXD]) + encode_value(7, TNS_TYPE_NUMBER) + bytes([TTI_STA])
        (done, acc) = decode_packet(body, (None, row_format, []))
        self.assertTrue(done)
        self.assertEqual(acc[2], [[7]])

    def test_a_row_format_without_the_field_still_reads_normally(self):
        # A describe always sets the field; a hand-built format may omit it, and
        # that must not be read as "zero length".
        from seerdb.common.tns import encode_value
        from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TTI_RXD, TTI_STA

        row_format = [{'data_type': TNS_TYPE_NUMBER, 'column_name': b'N'}]
        body = bytes([TTI_RXD]) + encode_value(5, TNS_TYPE_NUMBER) + bytes([TTI_STA])
        (done, acc) = decode_packet(body, (None, row_format, []))
        self.assertTrue(done)
        self.assertEqual(acc[2], [[5]])


class TestFv2UnassignedOutBind(unittest.TestCase):
    """A 9i block reply marks an OUT bind it never assigned with four fixed
    bytes (`ff 02 0c 21`) instead of the usual DALC + indicator (#801).

    This is what `DML ... RETURNING ... INTO` produces when the statement
    matched no rows -- distinct from an explicitly assigned NULL, which is an
    empty DALC plus the `81 01` indicator. Reading the marker as a DALC consumed
    the wrong number of bytes and desynced every OUT bind after it, so a wrapped
    RETURNING that matched nothing failed with a malformed-NUMBER error instead
    of reporting zero rows. Captured live from 9.2.0.4.
    """

    # UPDATE ... RETURNING id INTO :2, matching one row, wrapped with a trailing
    # `:3 := SQL%ROWCOUNT`: both OUT binds carry a value.
    ONE_ROW = bytes.fromhex(
        '0702c1070002c1020008010204014287c0000401010000000101002f'
        '000000000002937d01010002b91a0000000000010100000000'
    )
    # The same statement matching no rows: the RETURNING bind is unassigned, the
    # rowcount bind still carries Oracle NUMBER 0 (`80`).
    NO_ROW = bytes.fromhex(
        '07ff020c2101800008010204014287c2000401010000000101002f'
        '000000000002937d01010002b91a0000000000010100000000'
    )
    # A single unassigned OUT bind and nothing after it.
    ONLY_UNASSIGNED = bytes.fromhex(
        '07ff020c210801020401428828000401010000000101002f'
        '000000000002937e01010002b9220000000000010100000000'
    )

    def test_assigned_values_decode(self):
        from seerdb.common.tns import decode_fv2_block_out

        out, _rc, err = decode_fv2_block_out(self.ONE_ROW, 2)
        self.assertEqual(err, 0)
        # Oracle NUMBER 6 (the returned id) and NUMBER 1 (SQL%ROWCOUNT).
        self.assertEqual(out, [bytes.fromhex('c107'), bytes.fromhex('c102')])

    def test_unassigned_out_does_not_desync_the_next_bind(self):
        from seerdb.common.tns import decode_fv2_block_out

        out, _rc, err = decode_fv2_block_out(self.NO_ROW, 2)
        self.assertEqual(err, 0)
        # The unassigned bind reads as NULL, and -- the point of the fix -- the
        # rowcount bind after it still decodes, as Oracle NUMBER 0.
        self.assertEqual(out, [None, bytes.fromhex('80')])

    def test_single_unassigned_out(self):
        from seerdb.common.tns import decode_fv2_block_out

        out, _rc, err = decode_fv2_block_out(self.ONLY_UNASSIGNED, 1)
        self.assertEqual(err, 0)
        self.assertEqual(out, [None])


class TestFv2ChunkedErrorMessage(unittest.TestCase):
    """A 9i/8i server error longer than 64 bytes arrives as a chunked string:
    the 0xFE marker, then a length byte per 64-byte chunk, ending with a zero
    length (#810).

    Reading the length byte directly only ever found a message short enough to
    be one chunk. A longer one came back with its chunk lengths spliced in as
    characters -- 64 reads as '@', 13 as a carriage return -- truncated at the
    front, or, when no single byte happened to fit, lost entirely so the caller
    fell back to a bare "ORA-NNNNN". Captured live from 9.2.0.4.
    """

    # BEGIN nosuchthing_xyz; END; -- note the `40` chunk length sitting between
    # NOSUCHTHING_ and XYZ, and the `0d` inside "Statement", both of which used
    # to be read as text.
    CHUNKED_OER = bytes.fromhex(
        '04000219960000010101062f00000000000000000000000000000000000000'
        'fe404f52412d30363535303a206c696e6520312c20636f6c756d6e20373a0a'
        '504c532d30303230313a206964656e74696669657220274e4f535543485448'
        '494e475f4058595a27206d757374206265206465636c617265640a4f52412d'
        '30363535303a206c696e6520312c20636f6c756d6e20373a0a504c2f53514c'
        '3a2053746174650d6d656e742069676e6f7265640a00'
    )
    EXPECTED = (
        'ORA-06550: line 1, column 7:\n'
        "PLS-00201: identifier 'NOSUCHTHING_XYZ' must be declared\n"
        'ORA-06550: line 1, column 7:\n'
        'PL/SQL: Statement ignored'
    )

    def test_chunked_message_decodes_whole(self):
        from seerdb.common.tns import decode_fv2_oer_error

        (Code, Message) = decode_fv2_oer_error(self.CHUNKED_OER)
        self.assertEqual(Code, 6550)
        self.assertEqual(Message, self.EXPECTED)

    def test_chunk_lengths_do_not_leak_into_the_text(self):
        from seerdb.common.tns import decode_fv2_oer_error

        (_Code, Message) = decode_fv2_oer_error(self.CHUNKED_OER)
        # The two that used to appear, at the chunk boundaries.
        self.assertIn("'NOSUCHTHING_XYZ'", Message)
        self.assertNotIn('@', Message)
        self.assertIn('Statement ignored', Message)
        self.assertNotIn('\r', Message)
        # And the terminator is not part of the message.
        self.assertNotIn('\x00', Message)

    def test_a_short_single_chunk_message_still_decodes(self):
        from seerdb.common.tns import decode_fv2_oer_error

        # The pre-existing form: one length byte, message runs to the end.
        Text = b'ORA-00942: table or view does not exist'
        Packet = (
            bytes.fromhex('04000219960000010101062f')
            + bytes(19)
            + bytes([len(Text)])
            + Text
        )
        (_Code, Message) = decode_fv2_oer_error(Packet)
        self.assertEqual(Message, 'ORA-00942: table or view does not exist')


if __name__ == '__main__':
    unittest.main()
