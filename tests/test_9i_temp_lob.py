# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""Temporary LOBs on 9i's compact form (SeerODBC #169).

ojdbc14 (9.0.2) on 9.2.0.4, captured on the 9i VM: CLOB.createTemporary, a
40000-character write, then the CLOB bound into
`select 42 || ':' || dbms_lob.getlength(?) from dual` and into
`begin ? := dbms_lob.getlength(?); end;`. seerdb's requests are checked
against those bytes: the CREATE_TEMP, and the locator bind -- its OAC, type
112 at 3876 with charset 31 and form 1, and its value, a ub4 86 and the
86-byte locator in 64-byte chunks.
"""

import unittest

from seerdb.common.datatypes import TempLob
from seerdb.common.tns import (
    _ENCODE_FIELD_VERSION,
    _o7_bind_oac,
    decode_o7_create_temp,
    encode_o7_create_temp,
    encode_tokens_rxd,
)
from seerdb.common.tns_consts import FIELD_VERSION_9_2

_CREATE_TEMP = bytes.fromhex(
    '03600001015600010a010101700101010201100000005400000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000001'
    '1f010a'
)
_CREATE_TEMP_REPLY = bytes.fromhex(
    '080054000102080003000100000000000000000001001f000a0000000100000000387e9b'
    '55a5bd004100000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000011f01018160040101000000000000000000000000'
    '00000000000000000101'
)
# The SELECT's bind section: the OAC, TTI_RXD and the value.
_SQL_BIND = bytes.fromhex(
    '70010000020f2400000000011f01070156fe400054000102080003000100000000000000'
    '000001001f000a0000000100000000387e9b55a5bd004100000000000000000000000000'
    '0000000000000000000000160000000000000000000000000000000000000000000000'
)
# The block's IN values, the RXD after the server's prompt.
_BLOCK_VALUES = bytes.fromhex(
    '070156fe400054000102080003000100000000000000000001001f000a00000001000000'
    '00387e9b55a5bd0041000000000000000000000000000000000000000000000000160000'
    '000000000000000000000000000000000000000000'
)


def _locator() -> bytes:
    # The bare locator the reply carries, its ub2 length dropped.
    return decode_o7_create_temp(_CREATE_TEMP_REPLY)


class O7TempLobTest(unittest.TestCase):
    def setUp(self):
        self._token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_9_2)

    def tearDown(self):
        _ENCODE_FIELD_VERSION.reset(self._token)

    def test_create_temp_is_ojdbc14_s(self):
        self.assertEqual(encode_o7_create_temp(0, False, 1, 31), _CREATE_TEMP)

    def test_the_reply_names_the_locator(self):
        locator = _locator()
        self.assertEqual(len(locator), 84)
        self.assertEqual(locator[:4], bytes.fromhex('00010208'))

    def test_a_statement_s_lob_bind_is_ojdbc14_s(self):
        lob = TempLob(_locator(), False)
        self.assertEqual(
            _o7_bind_oac(lob, Statement=True) + encode_tokens_rxd([lob], b''),
            _SQL_BIND,
        )

    def test_a_block_s_lob_value_is_ojdbc14_s(self):
        self.assertEqual(
            encode_tokens_rxd([TempLob(_locator(), False)], b''), _BLOCK_VALUES
        )

    def test_a_national_lob_binds_in_the_national_charset(self):
        # Declared with charset 31, an NCLOB was PLS-553.
        oac = _o7_bind_oac(TempLob(_locator(), False, csfrm=2))
        self.assertEqual(oac[-4:], bytes.fromhex('0207d002'))


if __name__ == '__main__':
    unittest.main()
