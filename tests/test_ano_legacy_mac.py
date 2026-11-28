# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The legacy MD5 and SHA1 data-integrity checksums (#2865).

The fixture is the 26ai bed's side of a session that negotiated AES-256 with
SHA1, with the DH secret the client derived. Each reply's MAC was built by the
server, so opening them checks the RC4-keystream MAC against Oracle's, not
against itself: in order, and across the break/reset after ORA-00942, where
both ends re-derive.
"""

from __future__ import annotations

import os

import pytest

from seerdb.common import ano
from seerdb.common.ano_mac import AnoLegacyMac, AnoMacError
from seerdb.common.ano_session import AnoChannel, make_mac

_FIXTURE = os.path.join(
    os.path.dirname(__file__), 'captures', 'oracle26ai_sha1_session.txt'
)
_AES256 = ano.ENCRYPTION_ALGO_IDS['AES256']
_SHA1 = ano.INTEGRITY_ALGO_IDS['SHA1']
_MD5 = ano.INTEGRITY_ALGO_IDS['MD5']


def _session() -> tuple[bytes, list[bytes | None]]:
    # The secret, and the replies in order with None where the reset fell.
    secret = b''
    replies: list[bytes | None] = []
    with open(_FIXTURE) as f:
        for line in f:
            if line.startswith('secret '):
                secret = bytes.fromhex(line.split()[1])
            elif line.startswith('reply '):
                replies.append(bytes.fromhex(line.split()[1]))
            elif line.strip() == 'reset':
                replies.append(None)
    return secret, replies


def _open_all(rederive: bool) -> list[bytes]:
    secret, replies = _session()
    channel = AnoChannel(_AES256, _SHA1, secret, ano.DH_SERVER_IV, ClientSide=True)
    plain = []
    for reply in replies:
        if reply is None:
            if rederive:
                channel.rederive()
            continue
        plain.append(channel.unwrap(reply))
    return plain


def test_26ais_sha1_replies_open_with_their_macs_checked() -> None:
    plain = _open_all(rederive=True)
    joined = b''.join(plain)
    assert b"'SHA1'||LEVEL" in joined
    assert b'ORA-00942' in joined
    assert b"'AFTERTHEERROR'" in joined


def test_the_mac_re_derives_after_a_break_reset() -> None:
    # Without the re-derivation, the first reply after the reset fails its MAC.
    with pytest.raises(AnoMacError, match='integrity check failed'):
        _open_all(rederive=False)


def test_a_changed_reply_fails_its_mac() -> None:
    secret, replies = _session()
    first = replies[0]
    assert first is not None
    channel = AnoChannel(_AES256, _SHA1, secret, ano.DH_SERVER_IV, ClientSide=True)
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
