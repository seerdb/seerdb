# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""An object bind's descriptor before 12c (#2704).

11g answered the descriptor's trailing `oaccolid` with a fatal ORA-03106, and
takes it without, as JDBC thin 11.2 sends it; so does 10g. From 12.2 the
field is read, and 12.1 has none (#1144).
"""

import unittest

from seerdb.common.tns import _ENCODE_FIELD_VERSION, _object_oac
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_2,
)

_OID = bytes.fromhex('60563f0e0d62f0ffe060a8c09600122d')


def _oac(version: int) -> bytes:
    token = _ENCODE_FIELD_VERSION.set(version)
    try:
        return _object_oac(_OID, 1, 0)
    finally:
        _ENCODE_FIELD_VERSION.reset(token)


class TestTheObjectDescriptorBefore12c(unittest.TestCase):
    def test_10g_and_11g_have_no_oaccolid(self):
        # Type 109, flags 1, precision and scale 0, size 0, no array, no
        # continuation, the 16-byte OID, version 1, charset 0, form 0, and the
        # LOB prefetch length: nothing after it.
        want = (
            bytes.fromhex('6d0100000000000110 10')
            + _OID
            + bytes.fromhex('0101 00 00 00')
        )
        for version in (FIELD_VERSION_10_2, FIELD_VERSION_11_2):
            with self.subTest(version=version):
                self.assertEqual(_oac(version), want)

    def test_12_2_keeps_it(self):
        self.assertEqual(_oac(FIELD_VERSION_12_2), _oac(FIELD_VERSION_11_2) + b'\x00')


if __name__ == '__main__':
    unittest.main()
