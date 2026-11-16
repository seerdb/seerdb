# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""Object binds on 9i's compact form (SeerODBC #172).

ojdbc14 (9.0.2) on 9.2.0.4, captured on the 9i VM, binds `seerdb_obt9(7,
'seven')` -- an object of `(n NUMBER, s VARCHAR2(10))` -- into an INSERT and a
block, and a NULL of it. Its descriptor is a scalar's layout with the type's
OID and version: type 109 at the image's length, the most there is for a NULL
or an OUT one, charset 31 and form 0. Its image is 10g+'s pickled one, with
the header's length in the long form. seerdb's frame around the image is its
12c one, with the type's OID in it, which 9.2 takes as ojdbc14's empty one.
"""

import unittest

from seerdb.common.datatypes import Var
from seerdb.common.dbobject import DbObjectType
from seerdb.common.tns import _ENCODE_FIELD_VERSION, _o7_bind_oac, encode_object_image
from seerdb.common.tns_consts import (
    FIELD_VERSION_9_2,
    TNS_TYPE_NUMBER,
    TNS_TYPE_VARCHAR,
)

_TOID = bytes.fromhex('605faf548c9ed8ece060007f01000be8')
_TYPE = DbObjectType(
    'PYO',
    'SEERDB_OBT9',
    _TOID,
    1,
    [
        {'name': 'N', 'data_type': TNS_TYPE_NUMBER},
        {'name': 'S', 'data_type': TNS_TYPE_VARCHAR},
    ],
)
# ojdbc14's descriptors, from the INSERT and the INSERT of NULLs.
_OAC = bytes.fromhex('6d01000001100000011010') + _TOID + bytes.fromhex('0101011f00')
_NULL_OAC = (
    bytes.fromhex('6d010000047fffffff0000011010') + _TOID + bytes.fromhex('0101011f00')
)
# ojdbc14's image of seerdb_obt9(7, 'seven').
_IMAGE = bytes.fromhex('8401fe0000001002c10805') + b'seven'


def _seven():
    obj = _TYPE.newobject()
    obj.N = 7
    obj.S = 'seven'
    return obj


class O7ObjectBindTest(unittest.TestCase):
    def setUp(self):
        self._token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_9_2)

    def tearDown(self):
        _ENCODE_FIELD_VERSION.reset(self._token)

    def test_an_object_s_descriptor_is_ojdbc14_s(self):
        self.assertEqual(_o7_bind_oac(_seven()), _OAC)

    def test_a_null_or_out_one_is_declared_at_the_most(self):
        self.assertEqual(_o7_bind_oac(Var(_TYPE)), _NULL_OAC)

    def test_the_image_is_ojdbc14_s(self):
        self.assertEqual(encode_object_image(_seven()), _IMAGE)


if __name__ == '__main__':
    unittest.main()
