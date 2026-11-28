# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""9i's default form is thin OALL8 (#2768).

Measured on the 9.2.0.4 bed (2026-11-28), the integration suite passes 678
tests over thin OALL8, 660 over the compact form and 671 over the native one,
and thin OALL8 runs what the other two run but their own form's tests. So it
became the default: `thin_oall8=False` keeps the compact form, `oall8=True`
the native one. The client identifier, which thin OALL8 refused while it was
an opt-in, is set as the compact form sets it, so the default keeps it.
"""

from __future__ import annotations

import unittest

from seerdb.client.aconnection import AsyncOracleConnect
from seerdb.client.connection import OracleConnect
from seerdb.common.exceptions import NotSupportedError, ProgrammingError
from seerdb.common.tns_consts import FIELD_VERSION_10_2


class TestTheDefaultForm(unittest.TestCase):
    def test_thin_oall8_unless_asked_otherwise(self):
        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(cls()._thin_oall8)
                self.assertTrue(cls(thin_oall8=True)._thin_oall8)
                # The compact form, the default before.
                self.assertFalse(cls(thin_oall8=False)._thin_oall8)
                # The native form.
                self.assertFalse(cls(oall8=True)._thin_oall8)
                with self.assertRaises(ProgrammingError):
                    cls(oall8=True, thin_oall8=True)


def _thin92_session() -> OracleConnect:
    # A connection as a thin OALL8 session to 9.2 is once logged in: field
    # version 10.2, no dialect, the server below 10.2.
    conn = OracleConnect()
    conn.field_version = FIELD_VERSION_10_2
    conn._thin92 = True
    conn._dialect = None
    conn._server_below_10_2 = lambda: True  # type: ignore[method-assign]
    return conn


class TestTheClientIdentifier(unittest.TestCase):
    def test_set_by_ojdbc14s_call(self):
        conn = _thin92_session()
        conn.client_identifier = 'PYOCLID'
        self.assertEqual(
            conn._fv2_client_identifier_call(),
            ('begin dbms_session.set_identifier(:1); end;', ['PYOCLID']),
        )
        # Taken by the call: the thin path's piggyback, which 9.2 does not
        # read, has nothing left to send.
        self.assertEqual(conn._flush_end_to_end_bytes(), b'')
        self.assertIsNone(conn._fv2_client_identifier_call())

    def test_the_other_attributes_stay_refused(self):
        conn = _thin92_session()
        with self.assertRaises(NotSupportedError):
            conn.module = 'M'


if __name__ == '__main__':
    unittest.main()
