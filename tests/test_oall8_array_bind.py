# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""Associative-array binds in the OALL8 form, on 8i and 9i's native one
(SeerODBC #172).

OCI 9.2 on the 9i VM binds PL/SQL index-by tables (OCIBindByPos with a maximum
array length) into `BEGIN seerdb_aa8.go(:1, :2, :3); END;` -- a TABLE OF NUMBER
IN, `[10, 20, NULL]`, a TABLE OF VARCHAR2(20) IN OUT, `['ab', NULL, 'cde']` in
six, and a NUMBER OUT -- and a pure OUT one into `fill(:1)`, against 8.1.7 and
9.2.0.4. The descriptor is a scalar's with the array bit (0x40) and the most
elements the array may hold, a ub4 behind the size: at +8 at 8i's widths, the
`max_array` OCI's own descriptor has on 9i. The value is a ub4 count of the
elements, then each as a value, a NULL one the OUT placeholder `fd 01`; a pure
OUT array is the count 0 alone. Both servers return an array as the count, then
each element as its value and indicator, and a return code behind it when the
descriptor's 0x04 flag asks for one: OCI's did for the string array, on which it
set a return-code buffer, and seerdb's 9i native descriptor does (0x45); its 8i
one (0x43) does not, and 8.1.7 then sends none.
"""

import unittest

import seerdb
from seerdb.client.cursor import _check_object_bind_support
from seerdb.client.dialect import (
    CAP_ARRAY_BIND,
    Fv2Dialect,
    Fv2Oall8Dialect,
    O8iDialect,
    _o8i_out_positions,
)
from seerdb.common.datatypes import Var
from seerdb.common.exceptions import NotSupportedError
from seerdb.common.tns import (
    _encode_8i_bind_oac,
    _encode_8i_bind_value,
    _encode_9i_bind_oac,
    _encode_9i_bind_value,
    decode_8i_block_cursor,
    decode_8i_block_out,
    decode_9i_oall8_block_out,
    o8i_block_complete,
)


def _array(typ, size, count, values):
    var = Var(typ, size, is_array=True, num_elements=count)
    var._value = list(values)
    var.has_value = bool(values)
    return var


# OCI 9.2's descriptors, from its go() and fill() calls.
_8I_NUMBERS_OAC = bytes.fromhex('02430000160000000300000000000000000000000000000000')
_8I_STRINGS_OAC = bytes.fromhex('014700001400000006000000000000000000000000001f0001')
_9I_NUMBERS_OAC = bytes.fromhex(
    '0102430000160000000300000000000000000000000000000000000000000000000000000000000000'
)
# And its values, the same to 8.1.7 and to 9.2.
_NUMBERS_VALUE = bytes.fromhex('0300000002c10b02c115fd01')
_STRINGS_VALUE = bytes.fromhex('03000000026162fd0103636465')
# 8.1.7's reply to seerdb's go(): the prompt (IN, IN OUT, OUT), the five strings
# with an indicator each, a NULL `00 ffff`, the total 130 and the status.
_8I_GO_REPLY = bytes.fromhex(
    '0b050300000001000000000000000000000020301007050000000361625a000000ffff0463'
    '64655a0000036e6577000000ffff03c2021f0000080400fa0b2c000000000001000000000000'
    '00000000000401000000000000000000010000002f0040000000000000000000000000000000'
    '0000000000000a0000010000000000000000000000000000000000'
)
_8I_FILL_REPLY = bytes.fromhex(
    '0b0501000000010000000000000000000000100702000000036f6e6500000374776f00000804'
    '00f20b2c00000000000100000000000000000000000401000000000000000000010000002f00'
    '400000000000000000000000000000000000000000000a000001000000000000000000000000'
    '0000000000'
)
# 9.2's reply to OCI's go(): each element with its return code, 1405 (`7d05`)
# for a NULL.
_9I_GO_REPLY = bytes.fromhex(
    '0b0105000300000001000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000020301007050000000361625a0000000000ffff7d05046364655a0000'
    '0000036e65770000000000ffff7d0503c2021f00000805002471a8020000000001000000000000'
    '00000000000000000004010000000101000000000000000000010000002f000000000000000000'
    '00000000000000000000000000000000000009000001000000360100000000000000000000000000'
    '0080d0d40300000000000000000000000000000000000000000000000000000000'
)
_STRINGS_OUT = {'_array': True, 'values': [b'abZ', b'', b'cdeZ', b'new', b'']}


class Oall8ArrayBindTest(unittest.TestCase):
    def setUp(self):
        self.numbers = _array(seerdb.DB_TYPE_NUMBER, None, 3, [10, 20, None])
        self.strings = _array(seerdb.DB_TYPE_VARCHAR, 20, 6, ['ab', None, 'cde'])
        self.out = _array(seerdb.DB_TYPE_VARCHAR, 20, 4, [])

    def test_8i_descriptor_is_oci_s(self):
        self.assertEqual(_encode_8i_bind_oac(self.numbers), _8I_NUMBERS_OAC)
        # OCI's string array asked for return codes (0x04); seerdb's does not.
        Oci = bytearray(_8I_STRINGS_OAC)
        Oci[1] &= ~0x04
        self.assertEqual(_encode_8i_bind_oac(self.strings), bytes(Oci))

    def test_9i_native_descriptor_is_oci_s_with_seerdb_s_flags(self):
        # seerdb's native Var flag, 0x05, under the array bit; the rest OCI's.
        Mine = _encode_9i_bind_oac(self.numbers)
        self.assertEqual(Mine[2], 0x45)
        self.assertEqual(Mine[:2] + Mine[3:], _9I_NUMBERS_OAC[:2] + _9I_NUMBERS_OAC[3:])

    def test_the_value_is_oci_s_on_both_servers(self):
        for encode in (_encode_8i_bind_value, _encode_9i_bind_value):
            self.assertEqual(encode(self.numbers), _NUMBERS_VALUE)
            self.assertEqual(encode(self.strings), _STRINGS_VALUE)
            self.assertEqual(encode(self.out), bytes(4))

    def test_8i_reads_an_array_without_return_codes(self):
        self.assertEqual(
            decode_8i_block_out(_8I_GO_REPLY, 2, Arrays=frozenset({0})),
            [_STRINGS_OUT, bytes.fromhex('c2021f')],
        )
        self.assertEqual(
            decode_8i_block_out(_8I_FILL_REPLY, 1, Arrays=frozenset({0})),
            [{'_array': True, 'values': [b'one', b'two']}],
        )
        # The status behind the values names the block's cursor, 1; read as a
        # scalar, the array ran the reader into the wrong bytes (0).
        self.assertEqual(
            decode_8i_block_cursor(_8I_GO_REPLY, 2, Arrays=frozenset({0})), 1
        )

    def test_9i_native_reads_an_array_with_return_codes(self):
        (Values, _, Code, _) = decode_9i_oall8_block_out(
            _9I_GO_REPLY, 3, 2, Arrays=frozenset({0})
        )
        self.assertEqual(Code, 0)
        self.assertEqual(Values, [_STRINGS_OUT, bytes.fromhex('c2021f')])

    def test_8i_reply_is_whole_by_the_prompt_s_out_binds(self):
        # The IN array ahead is a Var too: taken for an OUT, the array set
        # landed on the NUMBER behind it and the reply never looked whole.
        Bind = [self.numbers, self.strings, Var(seerdb.DB_TYPE_NUMBER)]
        self.assertEqual(_o8i_out_positions(_8I_GO_REPLY, Bind, [0, 1, 2]), [1, 2])
        self.assertTrue(o8i_block_complete(_8I_GO_REPLY, Arrays=frozenset({0})))
        self.assertFalse(o8i_block_complete(_8I_GO_REPLY[:40], Arrays=frozenset({0})))

    def test_8i_and_9i_native_declare_the_bind(self):
        for dialect in (O8iDialect, Fv2Oall8Dialect):
            self.assertIn(CAP_ARRAY_BIND, dialect.capabilities(object.__new__(dialect)))
        self.assertNotIn(
            CAP_ARRAY_BIND, Fv2Dialect.capabilities(object.__new__(Fv2Dialect))
        )

    def test_the_cursor_lets_them_bind_one(self):
        class Conn:
            field_version = 2
            _native11 = False

        Conn._dialect = object.__new__(O8iDialect)
        _check_object_bind_support(Conn(), [self.numbers])
        Conn._dialect = object.__new__(Fv2Dialect)
        with self.assertRaises(NotSupportedError):
            _check_object_bind_support(Conn(), [self.numbers])


if __name__ == '__main__':
    unittest.main()
