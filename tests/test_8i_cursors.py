# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""8i REF CURSOR OUT binds and CURSOR() columns (#2710).

The replies are sqlplus 9.2's against 8.1.7, captured on the 9i VM: an
`OPEN :c FOR` block of two columns (N, S) whose cursor is 2, and
`SELECT 10 k, CURSOR(SELECT 20 v ...) c FROM dual`, whose nested cursor is 2.
A cell is the opened cursor's describe -- a query's TTI_DCB body with its row
size before an empty preamble -- then its id, and a return code after it in a
row.
"""

import unittest

from seerdb.common.tns import (
    decode_8i_block_cursor,
    decode_8i_block_out,
    decode_8i_dcb_describe,
    decode_8i_exec_response,
)

_BLOCK_REPLY = bytes.fromhex(
    '0b0501000000010000000000000000000000300718000000000200000033020000000200'
    '00000000000000000000000000000000000000010101000000014e000000000000000060'
    '8000000100000000000000000000000000000000001f0001010101000000015300000000'
    '000000000700000007787e0b0f1634220200000000000804006a112a0000000000010000'
    '0000000000000000000401000000000000000000010000002f0040000000000000000000'
    '000000000000000000000000160000010000000000000000000000000000000000'
)
_QUERY_REPLY = bytes.fromhex(
    '10193a6adcc1fcdce1040000787e0b0f163422fc63000000000000180000000200000033'
    '02000000020000000000000000000000000000000000000000010101000000014b000000'
    '000000000066000000050000000000000000000000000000000000000000010101000000'
    '014300000000000000000700000007787e0b0f1634220602020000000100000000000000'
    '000000000702c10b00000000180000000001000000330200000002000000000000000000'
    '000000000000000000000001020200000002323000000000000000000700000007787e0b'
    '0f16342202000000000000000804006a112a000000000001000000000000000000000004'
    '0100000000000000000001003b0003004000000000000000000000000000000000000000'
    '00001a0000010000000000000000000000000000000000'
)


class TestThe8iRefCursorCell(unittest.TestCase):
    def test_a_block_s_ref_cursor_out_is_its_cursor_and_columns(self):
        ((cursor, columns),) = decode_8i_block_out(_BLOCK_REPLY, 1, frozenset({0}))
        self.assertEqual(cursor, 2)
        self.assertEqual(
            [(c['column_name'], c['data_type']) for c in columns],
            [(b'N', 2), (b'S', 96)],
        )

    def test_the_block_s_own_cursor_follows_the_cell(self):
        self.assertGreater(decode_8i_block_cursor(_BLOCK_REPLY, 1, frozenset({0})), 0)


class TestThe8iCursorColumn(unittest.TestCase):
    def test_a_row_carries_its_nested_cursor(self):
        (columns, rest) = decode_8i_dcb_describe(_QUERY_REPLY)
        self.assertEqual([c['data_type'] for c in columns], [2, 102])
        (rows, _terminal, _last) = decode_8i_exec_response(rest, columns)
        ((k, (cursor, nested)),) = rows
        self.assertEqual((int(k), cursor), (10, 2))
        self.assertEqual([c['data_type'] for c in nested], [2])


if __name__ == '__main__':
    unittest.main()
