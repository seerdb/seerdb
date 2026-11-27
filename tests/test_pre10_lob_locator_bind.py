# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A fetched LOB and a BFILE bound IN by their locators below 10g (#2803): on
8i as OCI 9.2 binds them to 8.1.7, and on 9i's compact form as JDBC thin's
ojdbc14 binds them to 9.2.0.4, each captured. And the two checks every DML
runs over its binds -- the LONG-class one and the cursor cache's signature --
take a dialect's LOB object as it is."""

import os
import sys
import unittest

from seerdb.common import tns
from seerdb.common.lob import LOB
from seerdb.common.tns_consts import TNS_TYPE_BFILE, TNS_TYPE_BLOB, TNS_TYPE_CLOB

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402


class TestOn8i(unittest.TestCase):
    # The 8i descriptor is 25 bytes, then the RXD token (07) and the value.
    def _split(self, capture: str, head: bytes) -> tuple[bytes, bytes]:
        call = load_capture(capture)
        at = call.index(head)
        return (call[at : at + 25], call[at + 26 :])

    def test_a_fetched_clob_is_oci_92s(self):
        (oac, value) = self._split(
            'oci92_fetched_clob_bind_8i.hexdump', b'\x70\x00\x00\x00\x20'
        )
        lob = LOB(TNS_TYPE_CLOB, value[5 : 5 + value[4]], csfrm=1)
        self.assertEqual(tns._encode_8i_bind_oac(lob), oac)
        self.assertEqual(tns._encode_8i_bind_value(lob), value)

    def test_a_bfile_is_oci_92s(self):
        # Its locator at the start of a 255-byte buffer, one chunk of it.
        (oac, value) = self._split(
            'oci92_bfile_bind_8i.hexdump', b'\x72\x00\x00\x00\x20'
        )
        raw = value[6 : 6 + int.from_bytes(value[6:8], 'big') + 2]
        lob = LOB(TNS_TYPE_BFILE, raw)
        self.assertEqual(tns._encode_8i_bind_oac(lob), oac)
        self.assertEqual(tns._encode_8i_bind_value(lob), value)


class TestOn9isCompactForm(unittest.TestCase):
    # The compact descriptor is 14 bytes; the values follow as one RXD.
    def setUp(self):
        self._token = tns._ENCODE_FIELD_VERSION.set(2)

    def tearDown(self):
        tns._ENCODE_FIELD_VERSION.reset(self._token)

    def _split(self, capture: str, head: bytes) -> tuple[bytes, bytes]:
        call = load_capture(capture)
        at = call.index(head)
        return (call[at : at + 14], call[at + 14 :])

    def _bound(self, lob: LOB) -> tuple[bytes, bytes]:
        markers = tns.o7_lob_markers([lob])
        assert markers is not None
        (marker,) = markers
        return (
            tns._o7_bind_oac(marker, Statement=True),
            tns.encode_tokens_rxd([marker], b''),
        )

    def test_a_fetched_clob_is_jdbc14s(self):
        (oac, value) = self._split(
            'jdbc14_fetched_clob_bind_9i.hexdump', b'\x70\x01\x00\x00\x02\x0f\x24'
        )
        # `07 01 56 fe 40 ...`: the RXD, a ub4 86, then the locator chunked.
        (rest, raw) = (value[4:], b'')
        while rest[0]:
            raw += rest[1 : 1 + rest[0]]
            rest = rest[1 + rest[0] :]
        self.assertEqual(self._bound(LOB(TNS_TYPE_CLOB, raw, csfrm=1)), (oac, value))

    def test_a_bfile_is_jdbc14s(self):
        (oac, value) = self._split(
            'jdbc14_bfile_bind_9i.hexdump', b'\x72\x01\x00\x00\x02\x02\x12'
        )
        raw = value[4 : 4 + value[3]]
        self.assertEqual(self._bound(LOB(TNS_TYPE_BFILE, raw)), (oac, value))


class TestTheDmlChecks(unittest.TestCase):
    _LOBS = (
        LOB(TNS_TYPE_CLOB, b'\x00\x54' + bytes(84), csfrm=1),
        LOB(TNS_TYPE_BLOB, b'\x00\x54' + bytes(84)),
        LOB(TNS_TYPE_BFILE, b'\x00\x21' + bytes(33)),
    )

    def test_a_lob_object_is_not_long_class(self):
        self.assertFalse(tns.has_long_class_bind([1, *self._LOBS], [], 4000))

    def test_a_lob_object_has_a_cache_signature(self):
        self.assertTrue(tns.exec_oac_signature([1, *self._LOBS], []))


if __name__ == '__main__':
    unittest.main()
