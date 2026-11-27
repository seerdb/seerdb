# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A temporary LOB on 8i (#2803): the CREATE_TEMP OCI 9.2 sends 8.1.7 -- 9i's,
at the 8i codec's widths -- and the bind of one by its locator. Checked
against OCI 9.2 making a temporary CLOB and BLOB on 8.1.7 and inserting them,
captured with tcpdump on the 9i VM."""

import os
import sys
import unittest

from seerdb.common.datatypes import TempLob
from seerdb.common.tns import (
    _encode_8i_bind_oac,
    _encode_8i_bind_value,
    encode_o7_create_temp,
)

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402

# WE8ISO8859P1, the 8i bed's database charset, which seerdb's 8i session
# speaks. OCI 9.2 declared 1 there (US7ASCII), its own with no NLS_LANG set.
_DB_CHARSET = 31
# Where the CLOB's charset sits in the request: behind the 86-byte locator.
_CHARSET_AT = 119


class TestTheCreateTempTo817(unittest.TestCase):
    def test_a_blob_is_oci_92s(self):
        theirs = load_capture('oci92_create_temp_blob_8i.hexdump')
        ours = encode_o7_create_temp(theirs[2], True, 0, _DB_CHARSET, O8i=True)
        self.assertEqual(ours, theirs)

    def test_a_clob_is_oci_92s_in_the_database_charset(self):
        theirs = load_capture('oci92_create_temp_clob_8i.hexdump')
        self.assertEqual(theirs[_CHARSET_AT : _CHARSET_AT + 2], b'\x01\x00')
        ours = encode_o7_create_temp(theirs[2], False, 1, _DB_CHARSET, O8i=True)
        self.assertEqual(
            ours,
            theirs[:_CHARSET_AT] + b'\x1f\x00' + theirs[_CHARSET_AT + 2 :],
        )


class TestATemporaryLobBoundIn(unittest.TestCase):
    def test_the_descriptors_and_values_are_oci_92s(self):
        call = load_capture('oci92_temp_lob_bind_in_8i.hexdump')
        at = call.index(b'\x70\x00\x00\x00\x20\x00\x00\x00')
        (clob_oac, blob_oac) = (call[at : at + 25], call[at + 25 : at + 50])
        values = call[at + 50 :]
        self.assertEqual(values[:1], b'\x07')
        clob_cell = values[1 : 1 + 4 + 1 + 86]
        blob_cell = values[1 + 91 : 1 + 91 + 91]
        clob = TempLob(clob_cell[7:], False)
        blob = TempLob(blob_cell[7:], True)
        self.assertEqual(_encode_8i_bind_oac(clob), clob_oac)
        self.assertEqual(_encode_8i_bind_oac(blob), blob_oac)
        self.assertEqual(_encode_8i_bind_value(clob), clob_cell)
        self.assertEqual(_encode_8i_bind_value(blob), blob_cell)


if __name__ == '__main__':
    unittest.main()
