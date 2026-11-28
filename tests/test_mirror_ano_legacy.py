# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Mirror's ANO reply to a client that offers no SHA-2 checksum (#2858).

JDBC thin 11.2 (ojdbc6) offers AES-256 for encryption but only MD5 and SHA1 for
integrity. The 26ai bed, with SHA1 briefly allowed, answered it with the
authentication status 0xFBFF and a 1024-bit Diffie-Hellman group of Oracle's own.
It sends seerdb, which offers the SHA-2 checksums, the same status and the
2048-bit RFC 3526 group 14. Both replies were captured on 2026-11-28.

The Mirror sent 0xFCFF, which ojdbc6 reads as "Authentication service received
status failure", and the 2048-bit group, on which it fails with an index error.
"""

from __future__ import annotations

import os
import socket
import threading

from seerdb.common import ano
from seerdb.common.ano_session import AnoChannel
from seerdb.common.tns_consts import TNS_DATA
from seerdb.server.framing import PacketStream
from seerdb.server.session import _negotiate_ano_server
from tests.replay import parse_hexdump

_CAPTURES = os.path.join(os.path.dirname(__file__), 'captures')


def _capture(name: str) -> bytes:
    with open(os.path.join(_CAPTURES, name)) as f:
        return parse_hexdump(f.read())


def _services(reply: bytes) -> dict[int, list]:
    return {s['type']: s['subpackets'] for s in ano.decode_ano(reply)['services']}


_JDBC6 = _capture('oracle26ai_ano_reply_jdbc6.hexdump')
_SEERDB = _capture('oracle26ai_ano_reply_seerdb.hexdump')
_JDBC6_REQUEST = _capture('jdbc6_ano_request_11g.hexdump')


def test_a_real_server_answers_auth_with_0xfbff_to_both() -> None:
    for reply in (_JDBC6, _SEERDB):
        auth = _services(reply)[ano.SERVICE_AUTH]
        assert auth[1] == (ano.SP_STATUS, 0xFBFF)
        assert ano.AUTH_STATUS_SERVER_NONE == 0xFBFF


def test_the_mirrors_groups_are_the_ones_26ai_sends() -> None:
    for reply, group, bits in (
        (_JDBC6, ano.DH_GROUP_LEGACY, 1024),
        (_SEERDB, ano.DH_GROUP_14, 2048),
    ):
        integrity = _services(reply)[ano.SERVICE_DATA_INTEGRITY]
        assert integrity[2] == (ano.SP_UB2, bits)
        assert integrity[3] == (ano.SP_UB2, bits)
        assert integrity[4][1] == group.generator
        assert integrity[5][1] == group.prime
        assert group.bits == bits


def test_the_group_follows_the_offered_checksums() -> None:
    offer = ano.offered_algorithm_ids(
        ano.decode_container(_JDBC6_REQUEST), ano.SERVICE_DATA_INTEGRITY
    )
    assert offer == [0, 1, 3]
    assert ano.dh_group_for(offer) is ano.DH_GROUP_LEGACY
    assert ano.dh_group_for([0, 1, 3, 4, 5, 6]) is ano.DH_GROUP_14
    assert ano.dh_group_for([0, 5]) is ano.DH_GROUP_14


def test_the_reply_matches_26ais_but_for_the_key_and_checksum() -> None:
    # The Mirror picks no checksum for ojdbc6, where 26ai picked SHA1; the rest
    # of the reply, but the server's public key, is 26ai's.
    for reply, group in ((_JDBC6, ano.DH_GROUP_LEGACY), (_SEERDB, ano.DH_GROUP_14)):
        real = _services(reply)
        server = ano.server_dh_keypair(Group=group)
        ours = _services(
            ano.encode_ano_response(
                17, real[ano.SERVICE_DATA_INTEGRITY][1][1], server.public_key, group
            )
        )
        for service in (
            ano.SERVICE_SUPERVISOR,
            ano.SERVICE_AUTH,
            ano.SERVICE_ENCRYPTION,
        ):
            assert ours[service] == real[service]
        mine, theirs = (
            ours[ano.SERVICE_DATA_INTEGRITY],
            real[ano.SERVICE_DATA_INTEGRITY],
        )
        assert mine[:6] + mine[7:] == theirs[:6] + theirs[7:]
        assert len(mine[6][1]) == len(theirs[6][1]) == group.bits // 8


def _read(stream: PacketStream) -> bytes:
    packet = stream.read_packet()
    assert packet is not None, 'the Mirror closed the connection'
    return packet[1]


def _negotiate(request: bytes) -> tuple[dict[int, list], bytes]:
    # Run the Mirror's half over a socket pair, answer as a client would, and
    # return the decoded reply and what the client reads under the agreed keys.
    left, right = socket.socketpair()
    failure: list[BaseException] = []

    def serve() -> None:
        try:
            stream = PacketStream(right, sdu=8192)
            _negotiate_ano_server(stream, request, 'requested')
            stream.write_packet(TNS_DATA, b'\x00\x00under the agreed keys')
        except BaseException as exc:  # reported by the caller
            failure.append(exc)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        client = PacketStream(left, sdu=8192)
        body = _read(client)
        reply = _services(body[body.index(ano.ANO_MAGIC_BYTES) :])
        integrity = reply[ano.SERVICE_DATA_INTEGRITY]
        dh = ano.compute_dh(integrity[4][1], integrity[5][1], integrity[6][1])
        client.write_packet(
            TNS_DATA, b'\x00\x00' + ano.dh_public_key_round(dh.public_key)
        )
        thread.join(10)
        assert not failure, failure
        enc_id = reply[ano.SERVICE_ENCRYPTION][1][1]
        client.activate_ano(
            AnoChannel(
                enc_id,
                integrity[1][1],
                dh.session_key,
                ano.DH_SERVER_IV,
                ClientSide=True,
            )
        )
        return reply, _read(client)
    finally:
        left.close()
        right.close()


def test_the_mirror_answers_ojdbc6s_offer_as_26ai_does() -> None:
    reply, data = _negotiate(_JDBC6_REQUEST)
    assert reply[ano.SERVICE_AUTH][1] == (ano.SP_STATUS, 0xFBFF)
    assert reply[ano.SERVICE_ENCRYPTION][1] == (ano.SP_UB1, 17)
    integrity = reply[ano.SERVICE_DATA_INTEGRITY]
    assert integrity[1] == (ano.SP_UB1, 0)
    assert integrity[4][1] == ano.DH_GROUP_LEGACY.generator
    assert integrity[5][1] == ano.DH_GROUP_LEGACY.prime
    assert data.endswith(b'under the agreed keys')


def test_a_sha2_offer_keeps_the_2048_bit_group() -> None:
    request = ano.encode_ano(
        [
            ano.supervisor_service(),
            ano.auth_service(),
            ano.encryption_service(['AES256']),
            ano.data_integrity_service(['SHA256']),
        ]
    )
    reply, data = _negotiate(request)
    integrity = reply[ano.SERVICE_DATA_INTEGRITY]
    assert integrity[1] == (ano.SP_UB1, 5)
    assert integrity[5][1] == ano.DH_GROUP_14.prime
    assert data.endswith(b'under the agreed keys')
