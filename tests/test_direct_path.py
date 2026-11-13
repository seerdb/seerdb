# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Direct path load's codec (#2462), against python-oracledb 26.1 thin's calls to
23ai, captured: a load of three rows into a table of NUMBER, VARCHAR2(20), DATE,
TIMESTAMP and RAW(10) columns (N, V, D, T, R), at field version 24."""

import datetime
import unittest
from decimal import Decimal

from seerdb.common import tns
from seerdb.common.exceptions import DataError, IntegrityError, ProgrammingError
from seerdb.common.tns_consts import (
    FIELD_VERSION_MAX,
    TNS_TYPE_CLOB,
    TNS_TYPE_RAW,
    TNS_TYPE_VARCHAR,
)

_FV = FIELD_VERSION_MAX

# The PREPARE call (seq 6) and its reply, which describes the columns and gives
# the load's cursor, 5.
_PREPARE = bytes.fromhex(
    '03800600010101010701010f0101010101010001030350594f010300010808534545525f44504c'
    '0101000101014e01040001010156010400010101440104000101015401040001010152010402'
    '019002019000000000000000000002ffff00000101'
)
_PREPARE_REPLY = bytes.fromhex(
    '080105020000810116000000000000000001000101014e00000000000000000000018000000114'
    '0000000002036901011400010001010156000000000000000000000c0000000101000000000000'
    '000001000101014400000000000000000000b4000006010b000000000000000001000101015400'
    '00000000000000000017000000010800000000000000000100010101520000000000000000000000'
    '010f020190020190030100000105010100000120011600000000000101040103027c7d00'
)
# The rows' LOAD STREAM (seq 7) and its reply.
_LOAD_STREAM = bytes.fromhex(
    '038107000105010149020190000001013c00220502c102036f6e65077878010f0b01010b787801'
    '0f0b01011dcd65000201023c001e0503c103330374776f0778790210010101077879021002030401'
    'ff3c000905ffffffffff'
)
_LOAD_STREAM_REPLY = bytes.fromhex(
    '0800040103027c7e01030000000105010402000000000000000000000000070000000000000001'
    '030102001d'
)
# The FINISH (seq 8) and its reply.
_FINISH = bytes.fromhex('038208000102010500000101')
_FINISH_REPLY = bytes.fromhex(
    '08000403010005027c7f0103000000000002000000000000000000000000080000000000000001'
    '030102001d'
)
_ROWS = [
    (
        1,
        'one',
        datetime.datetime(2020, 1, 15, 10),
        datetime.datetime(2020, 1, 15, 10, 0, 0, 500000),
        b'\x01\x02',
    ),
    (
        Decimal('2.5'),
        'two',
        datetime.datetime(2021, 2, 16),
        datetime.datetime(2021, 2, 16, 1, 2, 3),
        b'\xff',
    ),
    (None, None, None, None, None),
]


class _AtFieldVersion24(unittest.TestCase):
    # The replies decode at the captured session's field version, set for each
    # test and put back after it.
    def setUp(self):
        self._token = tns._DECODE_FIELD_VERSION.set(_FV)

    def tearDown(self):
        tns._DECODE_FIELD_VERSION.reset(self._token)

    def _columns(self) -> list:
        (Columns, _, _) = tns.decode_direct_path_prepare_reply(_PREPARE_REPLY[1:])
        return Columns


class TestDirectPathCalls(_AtFieldVersion24):
    def test_prepare_is_the_captured_call(self):
        self.assertEqual(
            tns.encode_direct_path_prepare(
                6, _FV, 'PYO', 'SEER_DPL', ['N', 'V', 'D', 'T', 'R']
            ),
            _PREPARE,
        )

    def test_prepare_reply_gives_the_columns_and_the_cursor(self):
        (Columns, Cursor, Rest) = tns.decode_direct_path_prepare_reply(
            _PREPARE_REPLY[1:]
        )
        self.assertEqual(Cursor, 5)
        self.assertEqual(
            [(C['column_name'], C['data_type']) for C in Columns],
            [(b'N', 2), (b'V', 1), (b'D', 12), (b'T', 180), (b'R', 23)],
        )
        self.assertEqual(tns.decode_error_reply(Rest), (0, None))

    def test_load_stream_is_the_captured_call(self):
        # The rows encoded against the reply's columns, packed and framed.
        (Cells, Fast) = tns.encode_direct_path_rows(_ROWS, self._columns(), None)
        (Pieces, Length) = tns.encode_direct_path_pieces(Cells, Fast)
        self.assertEqual(
            tns.encode_direct_path_load_stream(7, _FV, 5, Pieces, Length), _LOAD_STREAM
        )

    def test_finish_is_the_captured_call(self):
        self.assertEqual(
            tns.encode_direct_path_op(8, _FV, 5, tns.DIRECT_PATH_OP_FINISH), _FINISH
        )

    def test_load_stream_and_op_replies_read_as_success(self):
        for Reply in (_LOAD_STREAM_REPLY, _FINISH_REPLY):
            Rest = tns.decode_direct_path_reply(Reply[1:])
            self.assertEqual(tns.decode_error_reply(Rest), (0, None))

    def test_the_connection_reads_the_replies(self):
        from seerdb.client._conn_logic import _ConnectionLogic

        (Columns, Cursor) = _ConnectionLogic._direct_path_reply(
            _PREPARE_REPLY, Prepare=True
        )
        self.assertEqual((len(Columns), Cursor), (5, 5))
        self.assertEqual(_ConnectionLogic._direct_path_reply(_FINISH_REPLY), ([], 0))


class TestDirectPathPieces(unittest.TestCase):
    def test_a_value_past_a_piece_splits_into_the_next(self):
        # 70000 bytes: one piece full (0xfff0 bytes of data: the value's first
        # part after its fe-and-length), the rest in a second; neither is fast.
        Value = b'z' * 70000
        (Out, Length) = tns.encode_direct_path_pieces([[b'\x02', Value]], [True, False])
        self.assertEqual(Length, len(Out))
        First = 0xFFF0 - 2 - 3  # after the first value's two bytes and the fe header
        self.assertEqual(Out[0], 0x08 | 0x01)  # first of the row, split into the next
        self.assertEqual(Out[1], 2)  # two segments
        self.assertEqual(Out[2:4], b'\x01\x02')
        self.assertEqual(Out[4:7], b'\xfe' + First.to_bytes(2, 'big'))
        At = 7 + First
        Rest = 70000 - First
        self.assertEqual(Out[At], 0x02 | 0x04)  # split from the previous, last
        self.assertEqual(Out[At + 1], 1)
        self.assertEqual(Out[At + 2 : At + 5], b'\xfe' + Rest.to_bytes(2, 'big'))
        self.assertEqual(len(Out), At + 5 + Rest)

    def test_a_fast_row_carries_its_length(self):
        (Out, _) = tns.encode_direct_path_pieces([[b'ab', None]], [True, True])
        # FIRST|LAST|FAST_PIECE|FAST_ROW, the length (data + 4), two segments.
        self.assertEqual(Out, bytes([0x3C, 0x00, 0x08, 0x02, 0x02]) + b'ab\xff')


class TestDirectPathCells(unittest.TestCase):
    def _column(self, Type, **Rest) -> dict:
        return {'column_name': b'C', 'data_type': Type, 'null_ok': 1, **Rest}

    def test_null_into_not_null_is_refused(self):
        with self.assertRaises(IntegrityError):
            tns.encode_direct_path_rows(
                [(None,)], [self._column(TNS_TYPE_VARCHAR, null_ok=0)], None
            )

    def test_a_value_past_the_column_is_refused(self):
        with self.assertRaises(DataError):
            tns.encode_direct_path_rows(
                [('abc',)], [self._column(TNS_TYPE_VARCHAR, max_size=2)], None
            )

    def test_a_raw_column_takes_bytes(self):
        with self.assertRaises(DataError):
            tns.encode_direct_path_rows([('ab',)], [self._column(TNS_TYPE_RAW)], None)

    def test_a_row_of_the_wrong_width_is_refused(self):
        with self.assertRaises(ProgrammingError):
            tns.encode_direct_path_rows(
                [('a', 'b')], [self._column(TNS_TYPE_VARCHAR)], None
            )

    def test_clob_text_is_utf16_in_a_multibyte_database(self):
        # AL32UTF8 (873): the server converts nothing, so the client sends
        # UTF-16, as python-oracledb does; a single-byte database gets UTF-8.
        Column = self._column(TNS_TYPE_CLOB)
        self.assertEqual(
            tns.encode_direct_path_rows([('é',)], [Column], 873)[0], [[b'\x00\xe9']]
        )
        self.assertEqual(
            tns.encode_direct_path_rows([('é',)], [Column], 31)[0], [[b'\xc3\xa9']]
        )


class TestDirectPathBatches(unittest.TestCase):
    def test_rows_split_into_batches(self):
        from seerdb.client._conn_logic import _ConnectionLogic

        Batches = _ConnectionLogic._direct_path_batches([(1,), (2,), (3,)], 2)
        self.assertEqual(Batches, [[(1,), (2,)], [(3,)]])
        self.assertEqual(_ConnectionLogic._direct_path_batches([], 2), [])
        with self.assertRaises(ProgrammingError):
            _ConnectionLogic._direct_path_batches([(1,)], 0)

    def test_a_dataframe_gives_its_rows(self):
        try:
            import pyarrow as pa
        except ImportError:
            self.skipTest('pyarrow is not installed')
        from seerdb.client._conn_logic import _ConnectionLogic

        Table = pa.table({'K': [1, 2, 3], 'V': ['a', None, 'c']})
        self.assertEqual(
            _ConnectionLogic._direct_path_batches(Table, 2),
            [[(1, 'a'), (2, None)], [(3, 'c')]],
        )


if __name__ == '__main__':
    unittest.main()
