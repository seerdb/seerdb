# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A temporary LOB on a thin OALL8 session to 9.2 (#2803).

The CREATE_TEMP is JDBC thin 11.2's form there -- 9i's LOBOPS fields with an
SCN slot -- which 9.2 takes where it drops the connection on ojdbc14's. Only
its locator space differs: ojdbc6 offers 40 bytes, of which 9.2 fills 38
behind the length 84; seerdb offers ojdbc14's 86 and gets the locator whole.
Checked against ojdbc6 making a temporary CLOB and BLOB on 9.2.0.4, and 9.2's
replies to seerdb's, captured through tools/capture_proxy.py."""

import os
import sys
import unittest
from types import SimpleNamespace

from seerdb.client._conn_logic import temp_lobs_available
from seerdb.common.tns import (
    _DECODE_SERVER_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    _read_lob_column,
    decode_lobops_oer,
    decode_thin92_create_temp,
    encode_thin92_create_temp,
    encode_token_oac,
)
from seerdb.common.tns_consts import FIELD_VERSION_10_2

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402

# WE8ISO8859P1, the 9i bed's database charset.
_DB_CHARSET = 31
# An empty locator: OCI's length (84) and zeros, in ojdbc6's 40 bytes and in
# ojdbc14's 86.
_EMPTY_40 = b'\x00\x54' + bytes(38)
_EMPTY_86 = b'\x00\x54' + bytes(84)


def _with_86_bytes(theirs: bytes) -> bytes:
    # ojdbc6's request with its locator space ojdbc14's: the source length
    # (byte 5) 0x56, the empty locator 86 bytes.
    at = theirs.index(_EMPTY_40)
    return theirs[:5] + b'\x56' + theirs[6:at] + _EMPTY_86 + theirs[at + 40 :]


class TestTheCreateTempTo92(unittest.TestCase):
    def test_a_clob_and_a_blob_are_jdbc_thins_but_for_the_space(self):
        for capture, is_blob in (
            ('jdbc6_create_temp_clob_9i.hexdump', False),
            ('jdbc6_create_temp_blob_9i.hexdump', True),
        ):
            with self.subTest(capture=capture):
                theirs = load_capture(capture)
                ours = encode_thin92_create_temp(
                    theirs[2], is_blob, 0 if is_blob else 1, _DB_CHARSET
                )
                self.assertEqual(theirs[5], 0x28)
                self.assertEqual(ours, _with_86_bytes(theirs))

    def test_the_reply_carries_the_whole_locator(self):
        for capture in (
            'oracle9i_create_temp_clob_reply.hexdump',
            'oracle9i_create_temp_blob_reply.hexdump',
        ):
            with self.subTest(capture=capture):
                reply = load_capture(capture)
                (locator, status) = decode_thin92_create_temp(reply)
                self.assertEqual(reply[1:3], b'\x00\x54')
                self.assertEqual(locator, reply[3 : 3 + 84])
                # The status in 9.2's own form, as the session reads it: at
                # its field version (10.2), the server's (2) for the status.
                token = _DECODE_SERVER_FIELD_VERSION.set(2)
                try:
                    got = decode_lobops_oer(status, FIELD_VERSION_10_2)
                finally:
                    _DECODE_SERVER_FIELD_VERSION.reset(token)
                self.assertEqual(got, (0, None))

    def test_a_failed_call_is_its_status_alone(self):
        status = b'\x04\x01\x01\x00'
        self.assertEqual(decode_thin92_create_temp(status), (None, status))


class TestANullLobFrom92(unittest.TestCase):
    def test_an_empty_locator_is_null(self):
        # 9.2's answer to a RETURNING of a NULL CLOB on a thin OALL8 session:
        # a ub4 86, then the locator as a value, its length 84 and zeros.
        self.assertEqual(_read_lob_column(b'\x01\x56\x56' + _EMPTY_86), (None, b''))


class TestTheSessionMakesOne(unittest.TestCase):
    def test_a_thin_oall8_session_to_9i_makes_temporary_lobs(self):
        conn = SimpleNamespace(
            field_version=FIELD_VERSION_10_2,
            _dialect=None,
            _thin92=True,
            _server_below_10_2=lambda: True,
        )
        self.assertTrue(temp_lobs_available(conn))

    def test_and_binds_a_lob_var(self):
        import seerdb
        from seerdb.common.datatypes import Var

        token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_10_2)
        try:
            oac = encode_token_oac(Var(seerdb.DB_TYPE_CLOB))
        finally:
            _ENCODE_FIELD_VERSION.reset(token)
        self.assertEqual(oac[:7], b'\x70\x03\x00\x00\x02\x0f\xa0')


if __name__ == '__main__':
    unittest.main()
