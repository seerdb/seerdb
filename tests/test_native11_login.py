# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The native login of a pooled 11g session (#2466), offline.

11g's DRCP serves a pooled session only to a client in the native form, as OCI
speaks it. The requests are checked against sqlplus 11.2's own, captured
logging in to 11g XE through its pool; the replies against 11g's; the AUTH
against the Mirror's half of the same login, which reads and verifies it.
"""

import asyncio
import os
import sys
import unittest
from secrets import token_bytes
from unittest import mock

from seerdb.client.aconnection import AsyncOracleConnect
from seerdb.client.connection import OracleConnect
from seerdb.common.crypto import VFR_11G_SHA1, validate
from seerdb.common.exceptions import NotSupportedError
from seerdb.common.tns import (
    decode_auth_oci,
    decode_token_rpa_oci,
    encode_auth_oci11,
    encode_dty_oci11,
    encode_osesskey_oci11,
    encode_session_release_oci,
)
from seerdb.common.tns_consts import (
    CONN_STATE_AUTHENTICATED,
    TNS_DATA,
    TNS_VERSION_11_2,
    TNS_VERSION_12_1,
    TTI_AUTH,
    TTI_SESS,
)
from seerdb.server.auth import (
    derive_conn_key,
    encode_challenge_oci,
    encode_result_oci,
    make_challenge,
    parse_auth_response_oci,
    verify_password,
)


def _capture(name):
    # tests/replay.py, which CI's unittest step, importing this module as
    # tests.test_native11_login, does not have on its path.
    sys.path.insert(0, os.path.dirname(__file__))
    from replay import load_capture

    return load_capture(name)


def _env(**extra):
    return {'user': 'pyo', 'password': 'pyo123', **extra}


def _auth_from(challenge_payload):
    # What the client makes of a challenge, as _handle_rpa does.
    (_, SessKey, Salt, DerivedSalt, Vgen, Sder, Vfr) = decode_token_rpa_oci(
        challenge_payload
    )
    return {
        'sess': bytes.fromhex(SessKey.decode()),
        'salt': bytes.fromhex(Salt.decode()),
        'derived_salt': DerivedSalt,
        'vgen_count': Vgen,
        'sder_count': Sder,
        'verifier_type': Vfr,
    }


class Native11RequestTest(unittest.TestCase):
    """The requests, byte for byte against sqlplus 11.2's."""

    def test_the_data_type_request_is_sqlplus_11_2s(self):
        self.assertEqual(encode_dty_oci11(), _capture('oci11_dty_request.hexdump'))

    def test_the_osesskey_is_sqlplus_11_2s(self):
        # Built from the captured message's own values: every length declared at
        # three bytes a character, as sqlplus 11.2 declares them.
        Captured = _capture('oci11_osesskey_request.hexdump')
        Fields = decode_auth_oci(Captured)
        Pairs = [(P['key'], P.get('value', b'')) for P in Fields['pairs']]
        self.assertEqual(
            encode_osesskey_oci11(Fields['seq'], Fields['user'], Fields['mode'], Pairs),
            Captured,
        )

    def test_the_session_release_is_sqlplus_11_2s(self):
        Captured = _capture('oci11_session_release.hexdump')
        self.assertEqual(encode_session_release_oci(Captured[2]), Captured)


class Native11ReplyTest(unittest.TestCase):
    """11g's replies, read into what the thin replies read into."""

    def test_the_challenge_is_read(self):
        Result = decode_token_rpa_oci(_capture('oci11_login_challenge.hexdump'))
        (Kind, SessKey, Salt, DerivedSalt, Vgen, Sder, Vfr) = Result
        self.assertEqual(Kind, TTI_SESS)
        self.assertEqual(len(SessKey), 96)  # a 48-byte session, in hex
        self.assertEqual(Salt, b'7E84FAFF31AD21221995')  # 11g's 10-byte salt
        self.assertEqual((DerivedSalt, Vgen, Sder), (None, None, None))
        self.assertEqual(Vfr, VFR_11G_SHA1)

    def test_the_result_is_read(self):
        Result = decode_token_rpa_oci(_capture('oci11_login_result.hexdump'))
        (Kind, Resp, Ver, SessId, Serial, Unique, Identity) = Result
        self.assertEqual(Kind, TTI_AUTH)
        self.assertEqual(len(Resp), 96)  # the 48-byte OCI proof, in hex
        self.assertEqual(Ver, 186647040)  # 11.2.0.2.0
        self.assertEqual((SessId, Serial, Unique), (67, 3775, 'XE'))
        self.assertEqual(Identity['instance_name'], 'XE')


class Native11AuthTest(unittest.TestCase):
    """The AUTH against the Mirror's half of the login: its challenge, its
    reading and check of the proof, its result."""

    def test_the_mirror_accepts_the_proof_and_the_client_its(self):
        Challenge = make_challenge(b'pyo123', salt=token_bytes(10))
        Auth = _auth_from(encode_challenge_oci(Challenge)[10:])
        (Message, ConnKey) = encode_auth_oci11(
            {'seq': 4, 'auth': Auth, 'env': _env()}, []
        )
        (User, SessKey, Proof) = parse_auth_response_oci(Message)
        self.assertEqual(User, b'pyo')
        ServerKey = derive_conn_key(Challenge, SessKey)
        self.assertEqual(ServerKey, ConnKey)
        self.assertTrue(verify_password(ServerKey, Proof, b'pyo123'))
        Result = decode_token_rpa_oci(encode_result_oci(ServerKey)[10:])
        self.assertTrue(validate(bytes.fromhex(Result[1].decode()), ConnKey))

    def test_a_wrong_password_fails_the_mirrors_check(self):
        Challenge = make_challenge(b'pyo123', salt=token_bytes(10))
        Auth = _auth_from(encode_challenge_oci(Challenge)[10:])
        (Message, _) = encode_auth_oci11(
            {'seq': 4, 'auth': Auth, 'env': _env(password='wrong')}, []
        )
        (_, SessKey, Proof) = parse_auth_response_oci(Message)
        ServerKey = derive_conn_key(Challenge, SessKey)
        self.assertFalse(verify_password(ServerKey, Proof, b'pyo123'))

    def _pairs(self, **env):
        Challenge = make_challenge(b'pyo123', salt=token_bytes(10))
        Auth = _auth_from(encode_challenge_oci(Challenge)[10:])
        (Message, _) = encode_auth_oci11(
            {'seq': 4, 'auth': Auth, 'env': _env(**env)}, []
        )
        Fields = decode_auth_oci(Message)
        return (
            Fields,
            {P['key']: (P.get('value'), P['flags']) for P in Fields['pairs']},
        )

    def test_a_pooled_session_asks_for_a_new_one(self):
        # As the converted AUTH: a pooled session's purity defaults to NEW, and a
        # connection class goes out as given.
        (Fields, Pairs) = self._pairs(server_type='pooled', cclass='SEERDB_PROBE')
        self.assertEqual(Pairs[b'AUTH_KPPL_PURITY'], (b'1', 1))
        self.assertEqual(Pairs[b'AUTH_KPPL_CONN_CLASS'], (b'SEERDB_PROBE', 0))
        self.assertEqual(Pairs[b'AUTH_SESSKEY'][1], 1)
        self.assertEqual(Fields['mode'], 0x101)

    def test_the_logon_mode_carries_the_role(self):
        (Fields, _) = self._pairs(role=2)  # SYSOPER
        self.assertEqual(Fields['mode'], 0x101 | 2 * 32)

    def test_a_proxy_login_names_the_schema_first(self):
        # As sqlplus 11.2's `pyo[seerdb_proxy_target]` login through the pool:
        # PROXY_CLIENT_NAME ahead of the proof, the user the proxy one. Without
        # it the pool logged in as the proxy user itself (#2466).
        (Fields, Pairs) = self._pairs(proxy_user='seerdb_proxy_target')
        self.assertEqual(Fields['pairs'][0]['key'], b'PROXY_CLIENT_NAME')
        self.assertEqual(Pairs[b'PROXY_CLIENT_NAME'], (b'seerdb_proxy_target', 0))
        self.assertEqual(Fields['user'], b'pyo')
        (_, Plain) = self._pairs()
        self.assertNotIn(b'PROXY_CLIENT_NAME', Plain)


class Native11ChoiceTest(unittest.TestCase):
    """When the native form is spoken, and that nothing else leaves once it is."""

    def _conn(self, cls=OracleConnect, **kw):
        return cls(
            host='h', port=1521, user='pyo', password='pyo123', service_name='XE', **kw
        )

    def test_a_pooled_login_to_11g_is_native(self):
        Conn = self._conn(server_type='pooled')
        Conn._native11_choose(TNS_VERSION_11_2)
        self.assertTrue(Conn._native11)

    def test_a_dedicated_login_to_11g_is_native_when_opted_in(self):
        # `oall8`, which asks for the native OALL8 form on 9i, asks for it on a
        # dedicated 11g session too (#2463).
        for kw in ({'oall8': True}, {'oall8': True, 'server_type': 'dedicated'}):
            with self.subTest(kw=kw):
                Conn = self._conn(**kw)
                Conn._native11_choose(TNS_VERSION_11_2)
                self.assertTrue(Conn._native11)

    def test_a_dedicated_native_session_ends_with_the_logoff(self):
        # As sqlplus 11.2 ends one (`03 09 17`, captured on 11g XE): the plain
        # logoff; the DRCP session release aborted the dedicated server's call
        # (ORA-03137 [DRCP:kpplsSessRls_1]). A pooled one keeps the release.
        from seerdb.common.tns import encode_logoff_oci, encode_session_release_oci

        self.assertEqual(encode_logoff_oci(0x17), bytes.fromhex('030917'))
        Conn = self._conn(oall8=True)
        Conn.seq = 0x17
        self.assertEqual(Conn._native11_close_call(), bytes.fromhex('030917'))
        Pooled = self._conn(server_type='pooled')
        Pooled.seq = 0x17
        self.assertEqual(
            Pooled._native11_close_call(), encode_session_release_oci(0x17)
        )

    def test_other_logins_are_not(self):
        for kw, version in (
            ({'server_type': 'pooled'}, TNS_VERSION_12_1),
            ({'server_type': 'dedicated'}, TNS_VERSION_11_2),
            ({'oall8': True}, TNS_VERSION_12_1),
            ({}, TNS_VERSION_11_2),
        ):
            with self.subTest(kw=kw, version=version):
                Conn = self._conn(**kw)
                Conn._native11_choose(version)
                self.assertFalse(Conn._native11)

    def test_a_big_endian_client_is_refused(self):
        Conn = self._conn(server_type='pooled')
        with mock.patch.object(sys, 'byteorder', 'big'):
            with self.assertRaises(NotSupportedError):
                Conn._native11_choose(TNS_VERSION_11_2)

    def _logged_in(self, cls):
        Conn = self._conn(cls, server_type='pooled')
        Conn._native11_choose(TNS_VERSION_11_2)
        Conn.conn_state = CONN_STATE_AUTHENTICATED
        return Conn

    def test_a_logged_in_session_sends_nothing_else(self):
        # Refused before a byte is written: the connection has no socket here.
        with self.assertRaises(NotSupportedError):
            self._logged_in(OracleConnect).send(TNS_DATA, b'\x03\x5e\x05')

    def test_nor_does_an_async_one(self):
        Conn = self._logged_in(AsyncOracleConnect)
        with self.assertRaises(NotSupportedError):
            asyncio.run(Conn.send(TNS_DATA, b'\x03\x5e\x05'))


if __name__ == '__main__':
    unittest.main()
