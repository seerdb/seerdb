# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A temporary LOB on a thin session below 12.1 (#2803): the CREATE_TEMP in
JDBC thin 11.2's form, which 10.2 and 11.2 take where they refuse
python-oracledb's 12.1 one, and its reply, which carries the charset, an SCN
slot and an amount behind the locator. Checked against JDBC thin 11.2
(ojdbc6) making a temporary CLOB and BLOB on 10.2.0.5 and 11.2.0.2, captured
through tools/capture_proxy.py."""

import os
import sys
import unittest
from types import SimpleNamespace

from seerdb.client._conn_logic import temp_lobs_available
from seerdb.common.tns import (
    decode_create_temp_reply,
    decode_lobops_oer,
    encode_dictionary_lobops,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
)

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402


def _create_temp(theirs: bytes, is_blob: bool, field_version: int) -> bytes:
    return encode_dictionary_lobops(
        {
            'seq': theirs[2],
            'field_version': field_version,
            'create_temp': True,
            'is_blob': is_blob,
        }
    )


class TestTheCreateTempBelow121(unittest.TestCase):
    def test_a_clob_and_a_blob_are_jdbc_thins(self):
        for capture, is_blob in (
            ('jdbc6_create_temp_clob_10g.hexdump', False),
            ('jdbc6_create_temp_blob_10g.hexdump', True),
        ):
            for fv in (FIELD_VERSION_10_2, FIELD_VERSION_11_2):
                with self.subTest(capture=capture, fv=fv):
                    theirs = load_capture(capture)
                    self.assertEqual(_create_temp(theirs, is_blob, fv), theirs)

    def test_12c_keeps_python_oracledbs_create_temp(self):
        # No SCN slot, no amount, a zero locator (test_temp_lob pins its bytes).
        theirs = load_capture('jdbc6_create_temp_clob_10g.hexdump')
        ours = _create_temp(theirs, False, FIELD_VERSION_12_1)
        self.assertNotIn(b'\x00\x54', ours)
        self.assertTrue(ours.endswith(bytes(38) + b'\x02\x03\x69'))


class TestTheCreateTempsReplyBelow121(unittest.TestCase):
    def test_the_locator_and_the_status_behind_its_fields(self):
        # The SCN slot is negative in both of 10.2's replies (`81 02`, `81 4d`).
        for capture in (
            'oracle10g_create_temp_clob_reply.hexdump',
            'oracle10g_create_temp_blob_reply.hexdump',
            'oracle11g_create_temp_clob_reply.hexdump',
        ):
            with self.subTest(capture=capture):
                reply = load_capture(capture)
                (locator, status) = decode_create_temp_reply(reply)
                self.assertEqual(locator, reply[3 : 3 + reply[2]])
                self.assertEqual(status[:1], b'\x04')
                self.assertEqual(
                    decode_lobops_oer(status, FIELD_VERSION_10_2), (0, None)
                )

    def test_a_failed_call_is_its_status_alone(self):
        status = b'\x04\x01\x01\x00'
        self.assertEqual(decode_create_temp_reply(status), (None, status))


def _conn(field_version, dialect=None, below_10_2=False):
    return SimpleNamespace(
        field_version=field_version,
        _dialect=dialect,
        _server_below_10_2=lambda: below_10_2,
    )


class TestWhereATemporaryLobIsMade(unittest.TestCase):
    def test_a_thin_session_to_10g_or_11g_makes_one(self):
        self.assertTrue(temp_lobs_available(_conn(FIELD_VERSION_10_2)))
        self.assertTrue(temp_lobs_available(_conn(FIELD_VERSION_11_2)))

    def test_a_thin_oall8_session_to_9i_does_not(self):
        # It runs at 10.2, but its server is 9.2 (#2768).
        self.assertFalse(
            temp_lobs_available(_conn(FIELD_VERSION_10_2, below_10_2=True))
        )

    def test_below_10_2_none_is_made(self):
        self.assertFalse(temp_lobs_available(_conn(2)))


if __name__ == '__main__':
    unittest.main()
