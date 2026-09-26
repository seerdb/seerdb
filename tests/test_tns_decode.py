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
        self.assertEqual(
            decode_token_rpa(Data, None), (TTI_AUTH, Resp, Ver, SessId, SerialNum)
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
    NUM = bytes.fromhex(
        '0602010100010a0000000702c12b0004010102057b00000101000300000000'
        '0000000000000000000000000101194f52412d30313430333a206e6f206461'
        '746120666f756e640a'
    )
    # SELECT id, name, created FROM t97 — NUMBER/VARCHAR2/DATE, three rows, the
    # middle row has NULL name + NULL created (null indicator 81 01).
    NULLROWS = bytes.fromhex(
        '0602010300010a0000000702c1020005616c6963650007787e061111150800'
        '0702c103000081010081010702c10400056361726f6c0007787e0611111508'
        '0004010302057b000001010003000000000000000000000000000000010100'
        '0000194f52412d30313430333a206e6f206461746120666f756e640a'
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

    def test_strip_prompt_scans_to_rxd(self):
        # The direction section length varies (JDBC sent 1 byte/bind here, the
        # live server pads with a leading 00); the scan-based strip handles both.
        from seerdb.common.tns import strip_fv2_bind_prompt

        jdbc = self.OUTNUM_RESP  # 9-byte prompt
        live = (
            bytes.fromhex('0b0501010001010000')
            + bytes.fromhex('10')
            + self.OUTNUM_RESP[9:]
        )  # extra 00 padding
        self.assertEqual(strip_fv2_bind_prompt(jdbc)[0], 0x07)
        self.assertEqual(strip_fv2_bind_prompt(live)[0], 0x07)


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
        # A pure-OUT block's prompt runs straight into the values' RXD, with
        # the JDBC-style unpadded section or the live server's padded one.
        both_out = bytes.fromhex('0b05010200010100000010100702c1020002c103')
        self.assertEqual(decode_fv2_bind_directions(both_out), [0x10, 0x10])
        for prompt in (
            TestFv2OutBinds.OUTNUM_RESP,
            bytes.fromhex('0b0501010001010000')
            + bytes.fromhex('10')
            + TestFv2OutBinds.OUTNUM_RESP[9:],
        ):
            self.assertEqual(decode_fv2_bind_directions(prompt), [0x10])
        self.assertIsNone(decode_fv2_bind_directions(self.OUT_IN_VALUES))

    def test_8i_keeps_its_bind_count_at_offset_2(self):
        # Captured from 8.1.7: OUT, IN, then the one OUT value's RXD.
        from seerdb.common.tns import decode_8i_block_out, decode_fv2_bind_directions

        reply = bytes.fromhex(
            '0b050200000001000000000000000000000010200702c1470000080400f3340d'
        )
        self.assertEqual(decode_fv2_bind_directions(reply, CountAt=2), [0x10, 0x20])
        self.assertEqual(decode_8i_block_out(reply, 1), [bytes.fromhex('c147')])

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
