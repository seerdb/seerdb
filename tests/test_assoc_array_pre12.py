# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""An associative-array bind's descriptor before 12c (#2706).

JDBC thin 11.2 on 11g XE binds a TABLE OF NUMBER INDEX BY BINARY_INTEGER with
the ARRAY bit in the flags byte and the capacity as the max number of array
elements: `02 43 00 00 01 58 01 03 00 00 00 00 00 00`. seerdb sent the bit in
the cont flags and the capacity as max chars, which 11g answered PLS-00306.
It now sends JDBC's layout, with each element's own length (22, where JDBC
says 88: 11g takes both).
"""

import unittest

from seerdb.common.tns import _ENCODE_FIELD_VERSION, encode_token_raw
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    TNS_TYPE_NUMBER,
)


def _raw(version: int, **kw) -> bytes:
    token = _ENCODE_FIELD_VERSION.set(version)
    try:
        return encode_token_raw(TNS_TYPE_NUMBER, 22, 0, 0, 0, **kw)
    finally:
        _ENCODE_FIELD_VERSION.reset(token)


class TestTheArrayDescriptorBefore12c(unittest.TestCase):
    def test_the_bit_and_the_capacity_sit_where_jdbc_puts_them(self):
        want = bytes.fromhex('02 43 00 00 01 16 01 03 00 00 00 00 00 00')
        for version in (FIELD_VERSION_10_2, FIELD_VERSION_11_2):
            with self.subTest(version=version):
                self.assertEqual(_raw(version, Array=3), want)

    def test_a_scalar_bind_is_unchanged(self):
        self.assertEqual(
            _raw(FIELD_VERSION_11_2),
            bytes.fromhex('02 03 00 00 01 16 00 00 00 00 00 01 00'),
        )


class TestTheMirrorReadsBothLayouts(unittest.TestCase):
    # The Mirror reads an 11g array bind's capacity where the bit is in the
    # flags byte, as JDBC thin 11.2 and seerdb now write it, and still where a
    # seerdb of before #2706 put it: the bit in the cont flags, the capacity
    # trailing.
    def test_both_give_the_capacity(self):
        from seerdb.common.tns import _oac_array_capacity

        new = _raw(FIELD_VERSION_11_2, Array=3)
        old = bytes.fromhex('02 03 00 00 01 16 00 01 40 00 00 00 00 01 03')
        for oac in (new, old):
            with self.subTest(oac=oac.hex(' ')):
                self.assertEqual(_oac_array_capacity(oac, FIELD_VERSION_11_2), 3)
        scalar = _raw(FIELD_VERSION_11_2)
        self.assertEqual(_oac_array_capacity(scalar, FIELD_VERSION_11_2), 0)


if __name__ == '__main__':
    unittest.main()
