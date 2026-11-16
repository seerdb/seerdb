# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""Object and collection columns on 8i (SeerODBC #168).

sqlplus 9.2 against 8.1.7, captured on the 9i VM, selecting
`id, p seerdb_obt8, v seerdb_obv8` -- an object `(n NUMBER, s VARCHAR2(10))`
and a `VARRAY(5) OF NUMBER` -- for `(1, seerdb_obt8(7, 'seven'),
seerdb_obv8(1, 2, 3))` and `(2, NULL, NULL)`. Each cell is 9.2's native
object cell at 8i's widths, then a row cell's indicator and return code; a
NULL keeps the framing, with no image. Read as a plain value, the first row's
object came back as its framing and the second row was lost.
"""

import unittest

from seerdb.common.dbobject import ObjectImage
from seerdb.common.tns import _o8i_object_cell

# Row 1's P and V cells, then the rest of the reply.
_ROW1 = bytes.fromhex(
    '24000000240022020807ab32e6a0b945eaa12f1801cf992df50000000000000000000000'
    '0000010001000000000000000000000c00000001000c84010c02c10805736576656e0000'
    '0000240000002400220208f78f3ec520ab416aa4b13bc463cf1c62000000000000000000'
    '0000000001000100000000000000000000100000000100108801100101000302c10202c1'
    '0302c104000000000804002af02a00000000000100000000000000000000000401000000'
    '00000000000001001500030040000000193d0300050000cb000000010000000000002500'
    '00010000000000000000000000000000000000'
)
# Row 2's.
_ROW2 = bytes.fromhex(
    '24000000240022020807ab32e6a0b945eaa12f1801cf992df50000000000000000000000'
    '000001000100000000000000000000000000000100ffff0000240000002400220208f78f'
    '3ec520ab416aa4b13bc463cf1c6200000000000000000000000000010001000000000000'
    '00000000000000000100ffff000004020000007b05000000000100000003006000000919'
    '3d0300050000cb0000000100000000000031000001000000000000000000000000000000'
    '0000194f52412d30313430333a206e6f206461746120666f756e640a'
)

_COL = {'type_oid': b'', 'type_schema': 'SYSTEM', 'type_name': 'SEERDB_OBT8'}


class O8iObjectCellTest(unittest.TestCase):
    def test_an_object_and_a_varray(self):
        (obj, rest) = _o8i_object_cell(_COL, _ROW1)
        self.assertIsInstance(obj, ObjectImage)
        self.assertEqual(obj.image, bytes.fromhex('84010c02c10805') + b'seven')
        (arr, rest) = _o8i_object_cell(_COL, rest)
        self.assertEqual(arr.image, bytes.fromhex('8801100101000302c10202c10302c104'))
        self.assertEqual(rest[:1], b'\x08')  # the status: nothing left behind

    def test_nulls_keep_the_framing(self):
        (obj, rest) = _o8i_object_cell(_COL, _ROW2)
        self.assertIsNone(obj)
        (arr, rest) = _o8i_object_cell(_COL, rest)
        self.assertIsNone(arr)
        self.assertEqual(rest[:1], b'\x04')


if __name__ == '__main__':
    unittest.main()
