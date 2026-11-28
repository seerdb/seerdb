# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The legacy MD5 and SHA1 data-integrity checksums (#2865).

The fixtures are a real server's side of a session that negotiated AES-256 with
a legacy checksum, with the DH secret the client derived: the 26ai bed with
SHA1, and the 10g bed with MD5 (26ai refuses MD5). Each reply's MAC was built by
the server, so opening them checks the RC4-keystream MAC against Oracle's, not
against itself: in order, and across the break/reset after ORA-00942, where
both ends re-derive.
"""

from __future__ import annotations

import os

import pytest

from seerdb.common import ano
from seerdb.common.ano_mac import AnoLegacyMac, AnoMacError
from seerdb.common.ano_session import AnoChannel, make_mac

_CAPTURES = os.path.join(os.path.dirname(__file__), 'captures')
_AES256 = ano.ENCRYPTION_ALGO_IDS['AES256']
_SHA1 = ano.INTEGRITY_ALGO_IDS['SHA1']
_MD5 = ano.INTEGRITY_ALGO_IDS['MD5']
# (fixture, checksum, a value the replies carry)
_SESSIONS = [
    pytest.param(
        'oracle26ai_sha1_session.txt', _SHA1, b"'SHA1'||LEVEL", id='26ai-sha1'
    ),
    pytest.param('oracle10g_md5_session.txt', _MD5, b'md5 1', id='10g-md5'),
]


def _session(fixture: str) -> tuple[bytes, list[bytes | None]]:
    # The secret, and the replies in order with None where the reset fell.
    secret = b''
    replies: list[bytes | None] = []
    with open(os.path.join(_CAPTURES, fixture)) as f:
        for line in f:
            if line.startswith('secret '):
                secret = bytes.fromhex(line.split()[1])
            elif line.startswith('reply '):
                replies.append(bytes.fromhex(line.split()[1]))
            elif line.strip() == 'reset':
                replies.append(None)
    return secret, replies


def _open_all(fixture: str, algo_id: int, rederive: bool) -> list[bytes]:
    secret, replies = _session(fixture)
    channel = AnoChannel(_AES256, algo_id, secret, ano.DH_SERVER_IV, ClientSide=True)
    plain = []
    for reply in replies:
        if reply is None:
            if rederive:
                channel.rederive()
            continue
        plain.append(channel.unwrap(reply))
    return plain


@pytest.mark.parametrize(('fixture', 'algo_id', 'value'), _SESSIONS)
def test_a_servers_replies_open_with_their_macs_checked(
    fixture: str, algo_id: int, value: bytes
) -> None:
    joined = b''.join(_open_all(fixture, algo_id, rederive=True))
    assert value in joined
    assert b'ORA-00942' in joined
    assert b"'AFTERTHEERROR'" in joined


@pytest.mark.parametrize(('fixture', 'algo_id', 'value'), _SESSIONS)
def test_the_mac_re_derives_after_a_break_reset(
    fixture: str, algo_id: int, value: bytes
) -> None:
    # Without the re-derivation, the first reply after the reset fails its MAC.
    with pytest.raises(AnoMacError, match='integrity check failed'):
        _open_all(fixture, algo_id, rederive=False)


@pytest.mark.parametrize(('fixture', 'algo_id', 'value'), _SESSIONS)
def test_a_changed_reply_fails_its_mac(
    fixture: str, algo_id: int, value: bytes
) -> None:
    secret, replies = _session(fixture)
    first = replies[0]
    assert first is not None
    channel = AnoChannel(_AES256, algo_id, secret, ano.DH_SERVER_IV, ClientSide=True)
    forged = bytes([first[0] ^ 1]) + first[1:]
    with pytest.raises(AnoMacError):
        channel.unwrap(forged)


def test_make_mac_builds_the_legacy_mac_for_md5_and_sha1() -> None:
    secret = bytes(range(256))
    for algo_id, size in ((_MD5, 16), (_SHA1, 20)):
        mac = make_mac(algo_id, secret, ano.DH_SERVER_IV)
        assert isinstance(mac, AnoLegacyMac)
        assert len(mac.compute(b'payload')) == size


@pytest.mark.parametrize('algo_id', [_MD5, _SHA1])
def test_client_and_server_channels_interoperate(algo_id: int) -> None:
    # A server channel's packets open in a client one and back, across a
    # re-derivation on both ends.
    secret = bytes((n * 7) % 256 for n in range(256))
    client = AnoChannel(_AES256, algo_id, secret, ano.DH_SERVER_IV, ClientSide=True)
    server = AnoChannel(_AES256, algo_id, secret, ano.DH_SERVER_IV, ClientSide=False)
    for round_ in range(3):
        for n in range(4):
            payload = f'packet {round_}.{n}'.encode() * (n + 1)
            assert server.unwrap(client.wrap(payload)) == payload
            assert client.unwrap(server.wrap(payload)) == payload
        client.rederive()
        server.rederive()
