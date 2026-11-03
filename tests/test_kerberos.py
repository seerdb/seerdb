# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Kerberos login over the ANO authentication service (#2378).

The offline tests pin each round against sqlplus 23.26's, captured logging in
by Kerberos to Oracle 26ai Free (23.26) with a ticket that is not forwardable.
The live test logs in to a Kerberos-configured instance named by
``SEERDB_TEST_KERBEROS`` (``host:port/service``), with the credential cache and
configuration the environment names, and is skipped without it.
"""

from __future__ import annotations

import asyncio
import os
import types

import pytest

from seerdb.client import kerberos
from seerdb.common import ano
from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import (
    TTI_AUTH,
    TTI_FUN,
    encode_dictionary_external_auth,
)

# The server's negotiation reply selecting KERBEROS5, then sqlplus's echo of it,
# the server naming its service and host, and sqlplus's last round: no
# credentials forwarded. Each is the ANO container, from its magic on.
_SELECTED = bytes.fromhex(
    'deadbeef009f00000000000400000400030000000000040005171a300000020006001f'
    '000e0001deadbeef00030000000200040001000100070000000000040005171a300000'
    '020006faff0001000201000900004b45524245524f533500040005171a300000040004'
    '000000090004000400000002000200020000000000040005171a300000010002000003'
    '00020000000000040005171a30000001000200'
)
_ECHO = bytes.fromhex(
    'deadbeef003200000000000100000100040000000000040005171a3000000400040000'
    '000900040004000000020001000200'
)
_SERVICE_AND_HOST = bytes.fromhex(
    'deadbeef002f000000000001000001000200000000000600006f7261636c65000c0000'
    '73756c61636f2e6c6f63616c'
)
_NO_CREDENTIALS = bytes.fromhex('deadbeef001900000000000100000100010000000000000001')


def _auth_values(container: bytes) -> list:
    # The authentication service's sub-packets, versions dropped: sqlplus's
    # carry its own release, seerdb's 11.2.0.2.
    response = ano.decode_container(container)
    (service,) = [s for s in response['services'] if s['type'] == ano.SERVICE_AUTH]
    return [(t, v) for t, v in service['subpackets'] if t != ano.SP_VERSION]


class _FakeContext:
    # GSS-API's initiator, for the offline tests: its first step an AP-REQ in a
    # Kerberos GSS token, its second the AP-REP the server sent back.
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.complete = False
        self.received: list[bytes] = []

    def step(self, token: bytes | None = None) -> bytes:
        if token is None:
            return kerberos.gss_wrap(b'\x6e\x03ap-req', b'\x01\x00')
        self.received.append(token)
        self.complete = True
        return b''


def _fake_gssapi(contexts: list) -> types.SimpleNamespace:
    def context(**kwargs: object) -> _FakeContext:
        made = _FakeContext(**kwargs)
        contexts.append(made)
        return made

    return types.SimpleNamespace(
        Name=lambda name, kind: (name, kind),
        NameType=types.SimpleNamespace(hostbased_service='hostbased'),
        MechType=types.SimpleNamespace(kerberos='krb5'),
        RequirementFlag=types.SimpleNamespace(mutual_authentication='mutual'),
        SecurityContext=context,
        exceptions=types.SimpleNamespace(GSSError=RuntimeError),
    )


def test_the_auth_service_offers_kerberos5_as_sqlplus_does() -> None:
    # The method's number and name after the marker and status (#2378).
    plain = ano.auth_service()
    offered = ano.auth_service(kerberos=True)
    assert offered[:2] == plain[:2] == b'\x00\x01'  # the authentication service
    assert (plain[2:4], offered[2:4]) == (b'\x00\x03', b'\x00\x05')
    assert offered.endswith(
        ano.sp_ub1(ano.AUTH_KERBEROS5) + ano.sp_string(b'KERBEROS5')
    )


def test_the_exchange_answers_each_round_as_sqlplus_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contexts: list = []
    monkeypatch.setattr(kerberos, '_gssapi', lambda: _fake_gssapi(contexts))
    selected = ano.decode_container(_SELECTED)
    assert kerberos.kerberos_selected(selected)
    exchange = kerberos.KerberosExchange(('fe80::8758:a6b3:6996:970f', 0, 0, 0))
    # The echo of the selection's two words, then a status byte.
    assert _auth_values(exchange.first(selected)) == _auth_values(_ECHO)
    # The principal from the server's service and host; the address typed as
    # Kerberos types it; the AP-REQ out of its GSS token.
    ap_req_round = exchange.next(ano.decode_container(_SERVICE_AND_HOST))
    assert ap_req_round is not None
    assert contexts[0].kwargs['name'] == ('oracle@sulaco.local', 'hostbased')
    assert _auth_values(ap_req_round) == [
        (ano.SP_UB2, ano.KRB5_ADDRESS_INET6),
        (ano.SP_UB4, 16),
        (ano.SP_BYTES, bytes.fromhex('fe800000000000008758a6b36996970f')),
        (ano.SP_BYTES, b'\x6e\x03ap-req'),
    ]
    assert not exchange.done
    # The AP-REP goes back into GSS-API in its token; no credentials follow.
    ap_rep = ano.auth_round([ano.sp_ub1(0), ano.sp_bytes(b'\x6f\x03ap-rep')])
    last = exchange.next(ano.decode_container(ap_rep))
    assert contexts[0].received == [kerberos.gss_wrap(b'\x6f\x03ap-rep')]
    assert last is not None and exchange.done
    assert last[10:] == _NO_CREDENTIALS[10:]  # all but the container's version


def test_an_ipv4_address_is_kerberos_type_2() -> None:
    assert kerberos._address(('192.0.2.7', 1521)) == (
        ano.KRB5_ADDRESS_INET,
        bytes([192, 0, 2, 7]),
    )


def test_a_gss_token_is_unwrapped_and_wrapped() -> None:
    message = b'\x6e' + bytes(300)  # past 127 bytes: a long DER length
    token = kerberos.gss_wrap(message, b'\x01\x00')
    assert token[:2] == b'\x60\x82'
    assert kerberos.gss_unwrap(token) == message
    with pytest.raises(InterfaceError, match='Kerberos'):
        kerberos.gss_unwrap(b'\x60\x05\x06\x03abc')
    with pytest.raises(InterfaceError, match='token id'):
        kerberos.gss_unwrap(kerberos.gss_wrap(message, b'\x02\x00'))


def test_the_external_auth_message_has_no_user_and_no_proof() -> None:
    # One AUTH, mode NoNewPass and no user: the server knows the user from
    # the ticket (#2378).
    from seerdb.client.connection import OracleConnect
    from seerdb.common.tns import DictionaryType

    client = OracleConnect(
        host='localhost', port=1, service_name='X', externalauth=True
    )
    dictionary = client._make_dict(DictionaryType.description)
    message = encode_dictionary_external_auth(dictionary)
    assert message[:4] == bytes([TTI_FUN, TTI_AUTH, dictionary['seq'], 0])
    assert b'AUTH_TOKEN' not in message and b'AUTH_PASSWORD' not in message


def test_externalauth_takes_no_password() -> None:
    import seerdb

    with pytest.raises(InterfaceError, match='no password'):
        seerdb.connect(host='localhost', port=1, externalauth=True, password='x')


_TARGET = os.environ.get('SEERDB_TEST_KERBEROS')


@pytest.mark.skipif(not _TARGET, reason='SEERDB_TEST_KERBEROS names no Kerberos bed')
def test_a_kerberos_login_is_the_tickets_user() -> None:
    pytest.importorskip('gssapi')
    import seerdb

    assert _TARGET is not None
    (address, service) = _TARGET.split('/', 1)
    (host, port) = address.rsplit(':', 1)
    query = (
        "SELECT sys_context('userenv', 'authentication_method'), "
        "sys_context('userenv', 'authenticated_identity') FROM dual"
    )
    with seerdb.connect(
        host=host, port=int(port), service_name=service, externalauth=True
    ) as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        (method, identity) = cursor.fetchone()
    assert method == 'KERBEROS' and '@' in identity

    async def run() -> tuple:
        conn = await seerdb.connect_async(
            host=host, port=int(port), service_name=service, externalauth=True
        )
        try:
            cursor = conn.cursor()
            await cursor.execute(query)
            return await cursor.fetchone()
        finally:
            await conn.close()

    assert asyncio.run(run())[0] == 'KERBEROS'
