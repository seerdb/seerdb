# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""REF binds in the OALL8 form, on 8i and 9i's native one (SeerODBC #172).

OCI 9.2 on the 9i VM fetches the REF of a row of an object table of
`seerdb_rb8 (n NUMBER)` and binds it (SQLT_REF) into an INSERT, against 8.1.7
and against 9.2.0.4. Its descriptor is the one an object's has with the REF
type, naming the type the REF refers to, version 1: 9i's descriptor at 8i's
widths to 8.1.7, and to 9.2 the one OCI 11.2 sends 10g and 11g. Its value is
the REF's bytes. 8.1.7 describes a REF column, its type named, and sends the
REF in its row, as OCI defines one.
"""

import unittest

from seerdb.client.dialect import CAP_REF_BIND, Fv2Oall8Dialect, O8iDialect
from seerdb.common.dbobject import DbRef
from seerdb.common.exceptions import NotSupportedError
from seerdb.common.tns import (
    _encode_8i_bind_oac,
    _encode_8i_bind_value,
    _encode_9i_bind_oac,
    _encode_9i_bind_value,
)

_TOID_8I = bytes.fromhex('275aabec75444bc4a0cfa536716244bc')
_REF_8I = bytes.fromhex(
    '00280209'
    '6a0a987391534f29a7810c0c151f957c'
    '6d1a4efea53648ffbecd4e5b10571b12'
    '014000ff0000'
)
# OCI 9.2's descriptors, verbatim from the INSERTs.
_OAC_8I = bytes.fromhex(
    '6f000000d0070000000000000000000010000000'
    '10275aabec75444bc4a0cfa536716244bc'
    '0100000000'
)
_TOID_9I = bytes.fromhex('60658a05800d44f9e060007f01007122')
_REF_9I = bytes.fromhex(
    '00280209'
    '60658a05801244f9e060007f01007122'
    '60658a05801144f9e060007f01007122'
    '0040b8da0000'
)
_OAC_9I = bytes.fromhex(
    '006f000000d00700000000000000000000100000'
    '0010'
    '60658a05800d44f9e060007f01007122'
    '010000000000000000'
)


class OAll8RefBindTest(unittest.TestCase):
    def test_8i_s_descriptor_is_oci_s(self):
        ref = DbRef(_REF_8I, 'SEERDB_RB8', 'SYSTEM', _TOID_8I)
        self.assertEqual(_encode_8i_bind_oac(ref), _OAC_8I)

    def test_9i_native_descriptor_is_oci_s(self):
        ref = DbRef(_REF_9I, 'SEERDB_RB8', 'PYO', _TOID_9I)
        self.assertEqual(_encode_9i_bind_oac(ref), _OAC_9I)

    def test_the_value_is_the_ref_s_bytes(self):
        for raw, toid, encode in (
            (_REF_8I, _TOID_8I, _encode_8i_bind_value),
            (_REF_9I, _TOID_9I, _encode_9i_bind_value),
        ):
            self.assertEqual(
                encode(DbRef(raw, 'T', 'S', toid)), bytes([len(raw)]) + raw
            )

    def test_a_ref_without_its_type_s_oid_is_refused(self):
        with self.assertRaises(NotSupportedError):
            _encode_8i_bind_oac(DbRef(_REF_8I))
        with self.assertRaises(NotSupportedError):
            _encode_9i_bind_oac(DbRef(_REF_9I))

    def test_both_dialects_declare_the_bind(self):
        for dialect in (O8iDialect, Fv2Oall8Dialect):
            self.assertIn(CAP_REF_BIND, dialect.capabilities(object.__new__(dialect)))

    def test_8i_fetches_a_ref_column(self):
        # Refused as a type with no DbType until now; BITAND's type 29 still is.
        dialect = object.__new__(O8iDialect)
        self.assertEqual(dialect._unfetchable([{'data_type': 111}]), [])
        self.assertEqual(len(dialect._unfetchable([{'data_type': 29}])), 1)


if __name__ == '__main__':
    unittest.main()
