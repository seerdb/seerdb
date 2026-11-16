# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""REF binds on 9i's compact form (SeerODBC #172).

ojdbc14 (9.0.2) on 9.2.0.4, captured on the 9i VM, binds the REF of a row of
an object table of `seerdb_rb9 (n NUMBER)` into an INSERT and into a block.
Its descriptor is an object's layout with the REF type: type 111 at the REF's
length, the OID of the type it refers to, version 1, charset 31 and form 0.
Its value is the REF's bytes.
"""

import unittest

from seerdb.common.dbobject import DbRef
from seerdb.common.exceptions import NotSupportedError
from seerdb.common.tns import _ENCODE_FIELD_VERSION, _o7_bind_oac, encode_token_rxd
from seerdb.common.tns_consts import FIELD_VERSION_9_2

_TOID = bytes.fromhex('6064cf4bf4bfa46ce060007f0100603a')
# ojdbc14's REF, fetched with REF(o) from the object table.
_REF = bytes.fromhex(
    '00280209'
    '6064cf4bf4c4a46ce060007f0100603a'
    '6064cf4bf4c3a46ce060007f0100603a'
    '0040ba420000'
)
# ojdbc14's descriptor and value, from the INSERT.
_OAC = bytes.fromhex('6f010000012a0000011010') + _TOID + bytes.fromhex('0101011f00')


class O7RefBindTest(unittest.TestCase):
    def setUp(self):
        self._token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_9_2)

    def tearDown(self):
        _ENCODE_FIELD_VERSION.reset(self._token)

    def test_the_descriptor_is_ojdbc14_s(self):
        ref = DbRef(_REF, 'SEERDB_RB9', 'PYO', _TOID)
        self.assertEqual(_o7_bind_oac(ref), _OAC)

    def test_the_value_is_the_ref_s_bytes(self):
        ref = DbRef(_REF, 'SEERDB_RB9', 'PYO', _TOID)
        self.assertEqual(encode_token_rxd(ref), bytes([len(_REF)]) + _REF)

    def test_a_ref_without_its_type_s_oid_is_refused(self):
        with self.assertRaises(NotSupportedError):
            _o7_bind_oac(DbRef(_REF))


if __name__ == '__main__':
    unittest.main()
