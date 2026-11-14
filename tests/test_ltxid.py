# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Transaction Guard's logical transaction id (#2650, #2654), offline.

A service created with COMMIT_OUTCOME => true reports the session's logical
transaction id as an LTXID server piggyback (17 07): in the login's challenge,
and in each reply that starts or ends a transaction. The bytes are 23ai Free's,
captured 2026-11-14 through a relay with seerdb's own login and commit.
"""

import unittest

from replay import load_capture

from seerdb.client.connection import OracleConnect
from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import (
    _AC_REPLAY_CONTEXT_FROM_THIN,
    _AC_REPLAY_CONTEXT_THIN,
    _EXT_SYNC_FROM_THIN,
    _EXT_SYNC_THIN,
    _SESS_SIGNATURE_FROM_THIN,
    _SESS_SIGNATURE_THIN,
    _THIN,
    SESSION_KEYWORD_LTXID,
    _decode_server_piggyback,
    assemble_packet,
    decode_packet,
    decode_token_rpa,
    encode_ltxid_piggyback,
    find_fast_auth_rpa,
    recording_session_keywords,
)
from seerdb.common.tns_consts import (
    CONN_STATE_AUTHENTICATED,
    CONN_STATE_DISCONNECTED,
    FIELD_VERSION_MAX,
    TNS_DATA,
    TTI_SESS,
)

# The ids both replies carry: the login's, and the commit's, one commit later.
_LOGIN_LTXID = bytes.fromhex(
    '00020002f182ab1a010000000000000001000000040000009c30a3595def6b49'
    '187b1f0000000000603d239fe3ac0284e0639600a8c0c3c3'
)
_COMMIT_LTXID = bytes.fromhex(
    '00020002f182ab1a010000000100000001000000000000009c30a3595def6b49'
    '187b1f0000000000603d239fe3ac0284e0639600a8c0c3c3'
)


def _body(name: str) -> bytes:
    (_flag, packet_type, body, rest) = assemble_packet(load_capture(name), 8192, True)
    assert packet_type == TNS_DATA and rest == b'' and body is not None
    return body


class CommitReplyTest(unittest.TestCase):
    _BODY = _body('ltxid_commit_reply_23ai.hexdump')

    def test_the_reply_decodes_to_its_status(self):
        # It raised "no decoder for response token 56": the ub4 length was read
        # as the value, and the value's own length byte as the next token.
        result = decode_packet(self._BODY, (None, None, []), FIELD_VERSION_MAX)
        self.assertIs(result[0], True)  # the status: the call succeeded

    def test_the_id_is_recorded(self):
        sink: dict = {}
        with recording_session_keywords(sink):
            decode_packet(self._BODY, (None, None, []), FIELD_VERSION_MAX)
        self.assertEqual(sink[SESSION_KEYWORD_LTXID], _COMMIT_LTXID)

    def test_the_encoder_writes_the_server_s_bytes(self):
        piggyback = encode_ltxid_piggyback(_COMMIT_LTXID)
        self.assertEqual(self._BODY[: len(piggyback)], piggyback)
        self.assertEqual(piggyback[:5], bytes.fromhex('1707013838'))


class FastAuthReplyTest(unittest.TestCase):
    _BODY = _body('ltxid_fast_auth_reply_23ai.hexdump')

    def _challenge(self, sink: dict) -> tuple:
        offset = find_fast_auth_rpa(self._BODY, False)
        self.assertGreaterEqual(offset, 0)
        with recording_session_keywords(sink):
            return decode_token_rpa(self._BODY[offset + 1 :], ())

    def test_the_challenge_carries_the_id(self):
        # The replay context (17 08) comes first; the login decoder stopped at
        # anything but a SYNC, so the id never reached the connection.
        sink: dict = {}
        result = self._challenge(sink)
        self.assertEqual(result[0], TTI_SESS)
        self.assertEqual(sink[SESSION_KEYWORD_LTXID], _LOGIN_LTXID)

    def test_the_replay_context_reencodes_to_the_server_s_bytes(self):
        at = self._BODY.index(bytes.fromhex('1708'))
        (fields, rest) = _AC_REPLAY_CONTEXT_FROM_THIN(self._BODY[at:])
        self.assertEqual(rest[:2], bytes.fromhex('1707'))
        consumed = len(self._BODY) - at - len(rest)
        self.assertEqual(
            _AC_REPLAY_CONTEXT_THIN(fields), self._BODY[at : at + consumed]
        )
        self.assertEqual(_decode_server_piggyback(self._BODY[at:]), rest)


class OtherPiggybacksTest(unittest.TestCase):
    # EXT_SYNC and SESS_SIGNATURE, which python-oracledb reads and an
    # Application Continuity service may send, laid out as its reader takes
    # them. Not captured: each is checked as a round trip and as walked past.

    def _walk(self, encode, decode, fields: dict) -> None:
        data = encode(fields) + b'\x09'
        (decoded, rest) = decode(data)
        self.assertEqual(rest, b'\x09')
        self.assertEqual({k: decoded[k] for k in fields}, fields)
        self.assertEqual(_decode_server_piggyback(data), b'\x09')

    def test_ext_sync(self):
        self._walk(
            _EXT_SYNC_THIN, _EXT_SYNC_FROM_THIN, {'dty_count': 1, 'dty_length': 1}
        )

    def test_session_signature(self):
        fields = {
            'dty_count': 1,
            'dty_length': 1,
            'flags': 3,
            'client_signature': 0x1234567890ABCDEF,
            'server_signature': 7,
        }
        self._walk(_SESS_SIGNATURE_THIN, _SESS_SIGNATURE_FROM_THIN, fields)


class Ub8Test(unittest.TestCase):
    # A thin ub8 is a ub4's form with up to 8 magnitude bytes: a signature, or
    # a LOB amount past 4 GiB. Below 2**32 its bytes are the ub4's.
    def test_round_trips(self):
        for value in (0, 1, 252, 2**32 - 1, 2**32, 5 * 2**32 + 7, 2**64 - 1):
            data = _THIN.n8(value)
            self.assertEqual(_THIN.read_n8(data + b'\x09'), (value, b'\x09'))

    def test_the_wide_form(self):
        self.assertEqual(_THIN.n8(2**32), bytes.fromhex('050100000000'))
        self.assertEqual(_THIN.n8(2**32 - 1), bytes.fromhex('04ffffffff'))


def _bare() -> OracleConnect:
    conn = object.__new__(OracleConnect)
    conn._session_keywords = {}
    conn._txn_priority = None
    conn._pooled_server = False
    conn._ltxid = b''
    conn.conn_state = CONN_STATE_AUTHENTICATED
    return conn


class ConnectionLtxidTest(unittest.TestCase):
    def test_empty_until_the_server_reports_one(self):
        self.assertEqual(_bare().ltxid, b'')

    def test_the_latest_reported_id(self):
        conn = _bare()
        for ltxid in (_LOGIN_LTXID, _COMMIT_LTXID):
            conn._session_keywords[SESSION_KEYWORD_LTXID] = ltxid
            conn._absorb_session_keywords()
            self.assertEqual(conn.ltxid, ltxid)
        conn._absorb_session_keywords()  # a reply without one keeps it
        self.assertEqual(conn.ltxid, _COMMIT_LTXID)

    def test_a_closed_connection_raises(self):
        conn = _bare()
        conn.conn_state = CONN_STATE_DISCONNECTED
        with self.assertRaises(InterfaceError):
            conn.ltxid


if __name__ == '__main__':
    unittest.main()
