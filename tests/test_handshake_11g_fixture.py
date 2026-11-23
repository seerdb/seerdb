# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The captured 11g handshake fixture is well-formed.

Documents (and guards) the server->client bytes the Mirror server must
reproduce, and confirms seerdb's own client parsers accept them.
"""

from __future__ import annotations

import struct

import handshake_11g as fx

from seerdb.client.connection import _parse_accept
from seerdb.common.tns_consts import TNS_ACCEPT, TNS_CONNECT, TNS_DATA


def _packet_type(packet: bytes) -> int:
    # Legacy TNS header: type is the byte at offset 4.
    return packet[4]


def test_connect_is_a_connect_packet() -> None:
    assert _packet_type(fx.CONNECT) == TNS_CONNECT
    assert len(fx.CONNECT) == 212


def test_accept_is_version_314_legacy_framing() -> None:
    assert _packet_type(fx.ACCEPT) == TNS_ACCEPT
    body = fx.ACCEPT[8:]
    version = struct.unpack('>H', body[:2])[0]
    # 11g negotiates 314: < 315 => legacy 2-byte framing, no large SDU;
    # < 318 => no extended flags2 / end-of-response.
    assert version == 314
    accept = _parse_accept(body)
    assert accept['version'] == 314
    assert accept['sdu'] == 8192
    assert accept['eor'] is False


def test_pro_and_dty_are_ttc_data_messages() -> None:
    # On 11g these are DATA-framed, not distinct TNS packet types.
    for packet in (fx.ANO_CLIENT, fx.ANO_SERVER, fx.PRO_CLIENT, fx.PRO_SERVER):
        assert _packet_type(packet) == TNS_DATA
