# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""The packet layer through common's schemas (#2773): the TNS packet header in
both layouts, a DATA packet's data flags, the response token, and the
Mirror's OCI login reply as the client reads it."""

import socket

import handshake_11g as fx
import pytest

from seerdb.common.tns import (
    _AUTH_REPLY_FROM_OCI,
    _RESPONSE_TOKEN_FROM_THIN,
    decode_data_flags,
    decode_packet_header,
    encode_data_flags,
    encode_data_packet,
    encode_packet,
    encode_response_token,
)
from seerdb.common.tns_consts import (
    TNS_ACCEPT,
    TNS_CONNECT,
    TNS_DATA,
    TNS_DATA_FLAGS_END_OF_RESPONSE,
    TNS_DATA_FLAGS_MORE,
)
from seerdb.server import auth
from seerdb.server.framing import PacketStream, ProtocolLimitError


def test_captured_headers_read_in_the_legacy_layout() -> None:
    # 11g's CONNECT and ACCEPT, as captured: the size counts the whole packet.
    for packet, packet_type in ((fx.CONNECT, TNS_CONNECT), (fx.ACCEPT, TNS_ACCEPT)):
        header = decode_packet_header(packet, False)
        assert (header['size'], header['type']) == (len(packet), packet_type)
        assert header['header_checksum'] == 0


@pytest.mark.parametrize('large', [False, True], ids=['legacy', 'large'])
def test_a_written_header_reads_back(large: bool) -> None:
    (packet, _) = encode_packet(TNS_DATA, bytes(40), 8192, large)
    header = decode_packet_header(packet, large)
    assert (header['size'], header['type']) == (len(packet), TNS_DATA)
    # The type sits at byte 4 in both layouts.
    assert packet[4] == TNS_DATA
    with pytest.raises(IndexError):
        decode_packet_header(packet[:7], large)


def test_data_flags_follow_the_header() -> None:
    for flags in (0, TNS_DATA_FLAGS_MORE, TNS_DATA_FLAGS_END_OF_RESPONSE, 0xFFFF):
        packet = encode_data_packet(b'abc', flags)
        assert packet[8:10] == encode_data_flags(flags)
        assert decode_data_flags(packet) == flags
    with pytest.raises(IndexError):
        decode_data_flags(encode_data_packet(b'', 0)[:9])


def test_the_mirror_s_response_token_is_the_one_the_client_reads() -> None:
    # Captured from 23ai: `21 01 01` leads the first call's reply of a burst.
    assert encode_response_token(1) == bytes.fromhex('210101')
    for token in (0, 1, 255, 70000):
        (values, rest) = _RESPONSE_TOKEN_FROM_THIN(
            encode_response_token(token) + b'\x1d'
        )
        assert (values['token'], rest) == (token, b'\x1d')


def test_the_mirror_refuses_a_data_packet_without_its_data_flags() -> None:
    # Nine bytes: a legacy header and one byte where two flags bytes belong.
    a, b = socket.socketpair()
    try:
        b.sendall(b'\x00\x09\x00\x00' + bytes([TNS_DATA]) + bytes(4))
        with pytest.raises(ProtocolLimitError):
            PacketStream(a).read_packet()
    finally:
        a.close()
        b.close()


def test_the_mirror_s_oci_login_reply_is_what_the_client_reads() -> None:
    pairs = [(b'AUTH_SESSKEY', b'AB' * 48, 1), (b'AUTH_VFR_DATA', b'CD' * 10, 0x4815)]
    trailer = bytes.fromhex('040102030405')
    packet = auth._oci_auth_packet(pairs, trailer)
    header = decode_packet_header(packet, False)
    assert (header['size'], header['type']) == (len(packet), TNS_DATA)
    assert decode_data_flags(packet) == 0
    (reply, rest) = _AUTH_REPLY_FROM_OCI(packet[10:])
    assert [(p['key'], p['value'], p['flags']) for p in reply['pairs']] == pairs
    assert rest == trailer
