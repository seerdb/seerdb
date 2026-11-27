# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A LOB bind on a thin session below 12.1 (#2803): the bind descriptor JDBC
thin 11.2 sends 10.2 and 11.2 for a CLOB or BLOB, IN and OUT alike -- the older
OAC layout with a buffer of 4000, no LOB cont-flag, and the session's charset
with form 1, a BLOB's too. Checked against ojdbc6 binding a temporary CLOB and
BLOB IN and a CLOB and a BLOB OUT on 10.2.0.5, captured through
tools/capture_proxy.py."""

import os
import sys
import unittest

import seerdb
from seerdb.common.datatypes import TempLob, Var
from seerdb.common.exceptions import NotSupportedError
from seerdb.common.tns import (
    _ENCODE_FIELD_VERSION,
    _ENCODE_SERVER_FIELD_VERSION,
    encode_token_oac,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
)

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402

_LOCATOR = bytes(38)


def _oacs(capture: str) -> tuple[bytes, bytes]:
    # The CLOB's and the BLOB's bind descriptors, 16 bytes each, in a row.
    call = load_capture(capture)
    at = call.index(b'\x70\x03\x00\x00\x02\x0f\xa0')
    return (call[at : at + 16], call[at + 16 : at + 32])


class _AtFieldVersion(unittest.TestCase):
    def _oac(self, token, field_version, server=None):
        enc = _ENCODE_FIELD_VERSION.set(field_version)
        srv = _ENCODE_SERVER_FIELD_VERSION.set(server)
        try:
            return encode_token_oac(token)
        finally:
            _ENCODE_SERVER_FIELD_VERSION.reset(srv)
            _ENCODE_FIELD_VERSION.reset(enc)


class TestTheLobBindBelow121(_AtFieldVersion):
    def test_an_out_bind_is_jdbc_thins(self):
        (clob, blob) = _oacs('jdbc6_lob_bind_out_10g.hexdump')
        for fv in (FIELD_VERSION_10_2, FIELD_VERSION_11_2):
            with self.subTest(fv=fv):
                self.assertEqual(self._oac(Var(seerdb.DB_TYPE_CLOB), fv), clob)
                self.assertEqual(self._oac(Var(seerdb.DB_TYPE_BLOB), fv), blob)

    def test_a_temporary_lob_bound_in_is_jdbc_thins(self):
        (clob, blob) = _oacs('jdbc6_lob_bind_in_10g.hexdump')
        for fv in (FIELD_VERSION_10_2, FIELD_VERSION_11_2):
            with self.subTest(fv=fv):
                self.assertEqual(self._oac(TempLob(_LOCATOR, False), fv), clob)
                self.assertEqual(self._oac(TempLob(_LOCATOR, True), fv), blob)

    def test_an_nclob_takes_the_national_charset(self):
        # Not captured: an NCLOB as the session's other national binds go there.
        oac = self._oac(Var(seerdb.DB_TYPE_NCLOB), FIELD_VERSION_10_2)
        self.assertEqual(oac[11:15], b'\x02\x07\xd0\x02')

    def test_a_thin_oall8_session_to_9i_has_none(self):
        # It runs at 10.2 but its server makes no temporary LOB (#2768), so a
        # LOB Var is still refused there rather than bound unbacked.
        with self.assertRaises(NotSupportedError):
            self._oac(Var(seerdb.DB_TYPE_CLOB), FIELD_VERSION_10_2, server=2)


if __name__ == '__main__':
    unittest.main()
