# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side connect handshake parsing."""

from __future__ import annotations

import struct
from dataclasses import replace

import handshake_11g as fx
import pytest

# The captured PRO/DTY replies now live as golden fixtures alongside the
# generation test (the server module builds them from named pieces).
from test_handshake_generation import (
    DTY_REPLY,
    DTY_REPLY_SQLPLUS,
    PRO_REPLY,
    PRO_REPLY_SQLPLUS,
)

from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import decode_token_pro
from seerdb.common.tns_consts import (
    CCAP_FIELD_VERSION,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_12_2,
    FIELD_VERSION_21_1,
    FIELD_VERSION_23_1,
    FIELD_VERSION_23_4,
    TNS_DATA,
    TNS_VERSION_MIN_LARGE_SDU,
    TTI_DTY,
    TTI_PRO,
)
from seerdb.server.handshake import (
    TNS_VERSION_11_2,
    TNS_VERSION_12_2,
    TNS_VERSION_21_1,
    TNS_VERSION_23_1,
    encode_accept,
    encode_dty_reply,
    encode_pro_reply,
    negotiated_tns_version,
    parse_connect,
    pro_is_sqlplus,
    server_tns_version,
)


def test_parse_real_11g_connect() -> None:
    # body = the CONNECT with its 8-byte TNS header stripped, as read_packet yields.
    req = parse_connect(fx.CONNECT[8:])
    assert req.protocol_version == 314
    assert req.lowest_version == 300
    assert req.sdu == 8192
    assert req.tdu == 65535
    assert req.global_service_options == 0x0C41
    assert req.service_name == 'XE'
    assert req.program == 'sqlplus@firefly'
    assert req.user == 'petro'
    assert req.descriptor.startswith(b'(DESCRIPTION')


def test_descriptor_offset_is_honoured_not_assumed() -> None:
    # The 11g client puts its descriptor at packet offset 58, not the v319 74 —
    # parsing must read the offset field, so the descriptor stays intact.
    req = parse_connect(fx.CONNECT[8:])
    assert req.descriptor.endswith(b'))')
    assert b'(PORT=1599)' in req.descriptor


def test_encode_accept_byte_matches_the_real_11g_accept() -> None:
    # The killer test: our ACCEPT reproduces the captured server packet exactly.
    req = parse_connect(fx.CONNECT[8:])
    assert encode_accept(req) == fx.ACCEPT


def test_accept_caps_version_for_a_newer_client() -> None:
    # A 12c+/v319 client negotiates down to the version the Mirror speaks (314),
    # just as it would against a real 11g listener.
    req = replace(parse_connect(fx.CONNECT[8:]), protocol_version=319)
    accept = encode_accept(req)
    assert struct.unpack('>H', accept[8:10])[0] == 314


def test_accept_settles_sdu_to_the_smaller_side() -> None:
    req = replace(parse_connect(fx.CONNECT[8:]), sdu=65535)
    accept = encode_accept(req, sdu=8192)
    assert struct.unpack('>H', accept[12:14])[0] == 8192  # body[4:6] = SDU


def test_pro_reply_reproduces_the_captured_packet() -> None:
    # Re-wrapping the stored payload must reproduce the real server packet —
    # proves both the payload and our DATA framing match the wire.
    assert encode_pro_reply() == PRO_REPLY


def test_dty_reply_reproduces_the_captured_packet() -> None:
    assert encode_dty_reply() == DTY_REPLY


def test_pro_reply_is_a_data_packet_leading_tti_pro() -> None:
    packet = encode_pro_reply()
    assert packet[4] == TNS_DATA
    assert packet[10] == TTI_PRO


def test_dty_reply_leads_tti_dty() -> None:
    assert encode_dty_reply()[10] == TTI_DTY


def test_pro_reply_pins_field_version_11g() -> None:
    # The conformance check: seerdb's own PRO decoder reads field version 6
    # out of the reply's capability array — so a client negotiates 11g.
    caps = decode_token_pro(encode_pro_reply()[10:])['compile_caps']
    assert caps[CCAP_FIELD_VERSION] == FIELD_VERSION_11_2


def test_pro_reply_field_version_is_negotiable() -> None:
    # The advertised field version is the one byte a client negotiates on; the
    # rest of the pinned 11.2 identity is unchanged around it.
    from seerdb.common.tns_consts import FIELD_VERSION_12_1, FIELD_VERSION_23_1

    for version in (FIELD_VERSION_12_1, FIELD_VERSION_23_1):
        reply = encode_pro_reply(field_version=version)
        caps = decode_token_pro(reply[10:])['compile_caps']
        assert caps[CCAP_FIELD_VERSION] == version
        default = encode_pro_reply()
        assert len(reply) == len(default)
        diffs = [i for i in range(len(reply)) if reply[i] != default[i]]
        assert len(diffs) == 1


# --- sqlplus 'deadbeef' PRO dialect (#265) ---


def _read_packet_body(raw: bytes) -> tuple[int, bytes]:
    # Drive raw wire bytes through the real PacketStream.read_packet, so the body
    # is exactly what the serve loop feeds pro_is_sqlplus (header + data-flags
    # stripped) — not a hand-sliced approximation.
    import socket

    from seerdb.server.framing import PacketStream

    a, b = socket.socketpair()
    try:
        a.sendall(raw)
        a.shutdown(socket.SHUT_WR)
        packet = PacketStream(b).read_packet()
        assert packet is not None
        return packet
    finally:
        a.close()
        b.close()


def test_pro_is_sqlplus_detects_the_deadbeef_dialect() -> None:
    # Run the captured sqlplus PRO through read_packet — the exact path a live
    # client exercises. read_packet strips the 8-byte header AND the 2-byte
    # data-flags, so the deadbeef magic must be at the very start of the body.
    # (Feeding a hand-sliced PRO_CLIENT[8:] hid an off-by-two here; a live
    # sqlplus 11.2 caught it — #265.)
    typ, body = _read_packet_body(fx.PRO_CLIENT)
    assert typ == TNS_DATA
    assert pro_is_sqlplus(body) is True

    # A thin (TTI_PRO) PRO through the same path is not the sqlplus dialect.
    thin_raw = struct.pack('>HHBBH', 8 + 2 + 8, 0, TNS_DATA, 0, 0)
    thin_raw += b'\x00\x00' + bytes([TTI_PRO, 6, 5, 4, 3, 2, 1, 0])
    _typ, thin_body = _read_packet_body(thin_raw)
    assert pro_is_sqlplus(thin_body) is False


def test_sqlplus_pro_reply_reproduces_the_captured_packet() -> None:
    # Re-wrapping the stored deadbeef payload reproduces the real sqlplus-dialect
    # server PRO packet (127B) exactly.
    assert encode_pro_reply(sqlplus=True) == fx.PRO_SERVER
    assert PRO_REPLY_SQLPLUS == fx.PRO_SERVER


def test_sqlplus_dty_reply_reproduces_the_captured_packet() -> None:
    assert encode_dty_reply(sqlplus=True) == fx.DTY_SERVER
    assert DTY_REPLY_SQLPLUS == fx.DTY_SERVER


def test_sqlplus_type_reply_reproduces_the_captured_packet() -> None:
    # The deadbeef dialect's third round: the built ttc=02 reply reproduces the
    # real server packet (#265).
    from test_handshake_generation import TYPE_REPLY_SQLPLUS

    from seerdb.server.handshake import encode_type_reply_sqlplus

    assert encode_type_reply_sqlplus() == TYPE_REPLY_SQLPLUS


def test_dialects_are_distinct() -> None:
    # The two dialects' replies are genuinely different shapes (238/924 vs
    # 127/238), so serving the wrong one would break the handshake.
    assert encode_pro_reply(sqlplus=True) != encode_pro_reply(sqlplus=False)
    assert encode_dty_reply(sqlplus=True) != encode_dty_reply(sqlplus=False)


def test_too_short_raises() -> None:
    with pytest.raises(InterfaceError):
        parse_connect(b'\x01\x3a\x01\x2c')


def test_bad_offset_raises() -> None:
    # A 20-byte header claiming a descriptor 9000 bytes in.
    body = bytearray(20)
    struct.pack_into('>H', body, 18, 9000)  # cdata_offset field
    with pytest.raises(InterfaceError):
        parse_connect(bytes(body))


def test_accept_at_12_2_uses_the_large_sdu_layout() -> None:
    """A >= 315 ACCEPT moves the SDU/TDU into ub4 fields and zeroes the ub2 pair.

    Modelled on a live 21c ACCEPT (version 318), the nearest capture below the
    end-of-response era: body 37 bytes, ub4 SDU at 24, ub4 TDU at 28.
    """
    req = replace(parse_connect(fx.CONNECT[8:]), protocol_version=319, sdu=8192)
    accept = encode_accept(req, sdu=8192, tns_version=TNS_VERSION_12_2)
    body = accept[8:]
    assert struct.unpack('>H', body[0:2])[0] == TNS_VERSION_12_2
    assert len(body) == 37
    # The legacy 16-bit SDU/TDU pair is zeroed; the real values live in the ub4s.
    assert struct.unpack('>HH', body[4:8]) == (0, 0)
    assert struct.unpack('>I', body[24:28])[0] == 8192
    assert struct.unpack('>I', body[28:32])[0] > 0
    # flags2 stays zero: a client only reads it at >= 318, and a 12.2 server does
    # not advertise end-of-response.
    assert struct.unpack('>I', body[33:37])[0] == 0


def test_accept_at_11_2_is_unchanged_by_the_large_sdu_path() -> None:
    # The default is still the byte-exact captured 11g ACCEPT.
    req = parse_connect(fx.CONNECT[8:])
    assert encode_accept(req, tns_version=TNS_VERSION_11_2) == fx.ACCEPT


def test_negotiated_version_takes_the_lower_of_the_two_sides() -> None:
    req = parse_connect(fx.CONNECT[8:])  # a 314 client
    # A 12.2 Mirror still speaks 314 to an 11.2 client, so that session keeps the
    # legacy framing — the version alone decides which framing both ends use.
    assert negotiated_tns_version(req, TNS_VERSION_12_2) == 314
    newer = replace(req, protocol_version=319)
    assert negotiated_tns_version(newer, TNS_VERSION_12_2) == TNS_VERSION_12_2


def test_protocol_version_follows_the_field_version() -> None:
    """The two are one decision: a 12.2 field version implies 12.2's framing.

    Advertising 12.2 capabilities and a 12.2 release while answering 314 would
    describe a server that does not exist.
    """
    assert server_tns_version(FIELD_VERSION_11_2) == TNS_VERSION_11_2
    assert server_tns_version(FIELD_VERSION_12_1) == TNS_VERSION_11_2
    assert server_tns_version(FIELD_VERSION_12_2) == TNS_VERSION_12_2
    # The same argument one tier up: a Mirror presenting 21c or 23ai must frame
    # like one, not fall back to 12.2's 316 (#823). 318 and 319 are captured off
    # the live testbeds -- a real 23ai answers 319, not 320.
    assert server_tns_version(FIELD_VERSION_21_1) == TNS_VERSION_21_1
    assert server_tns_version(FIELD_VERSION_23_1) == TNS_VERSION_23_1
    assert server_tns_version(FIELD_VERSION_23_4) == TNS_VERSION_23_1


def test_a_12_2_mirror_is_large_sdu_without_being_asked() -> None:
    # Asking for a 12.2 field version alone must produce the >= 315 ACCEPT.
    req = replace(parse_connect(fx.CONNECT[8:]), protocol_version=319)
    accept = encode_accept(req, tns_version=server_tns_version(FIELD_VERSION_12_2))
    assert struct.unpack('>H', accept[8:10])[0] >= TNS_VERSION_MIN_LARGE_SDU
    assert len(accept[8:]) == 37


def test_a_23ai_accept_matches_the_captured_shape() -> None:
    # A live 26ai ACCEPT (version 319) is 53 bytes, not the 21c 37: flags 0x003D
    # instead of 0x002D, and sixteen trailing bytes of per-connection id. A client
    # that reads by offset needs the whole shape, so pin it (#823).
    req = replace(parse_connect(fx.CONNECT[8:]), protocol_version=319)
    body = encode_accept(req, tns_version=server_tns_version(FIELD_VERSION_23_4))[8:]
    assert struct.unpack('>H', body[0:2])[0] == TNS_VERSION_23_1
    assert len(body) == 53
    assert struct.unpack('>H', body[12:14])[0] == 0x003D
    # flags2 stays clear: a real 23ai sets FAST_AUTH | HAS_END_OF_RESPONSE there,
    # and a client turns each on only when the version AND the flag agree. The
    # Mirror sends no end-of-response markers, so claiming the bit would hang it.
    assert struct.unpack('>I', body[33:37])[0] == 0
    # The trailing id is random per connection, not a constant to copy.
    other = encode_accept(req, tns_version=server_tns_version(FIELD_VERSION_23_4))[8:]
    assert body[37:] != other[37:]
    assert body[:37] == other[:37]


def test_a_21c_accept_keeps_the_37_byte_shape() -> None:
    # The tier below 23ai is unchanged by #823 -- still the captured 21c form.
    req = replace(parse_connect(fx.CONNECT[8:]), protocol_version=319)
    body = encode_accept(req, tns_version=server_tns_version(FIELD_VERSION_21_1))[8:]
    assert struct.unpack('>H', body[0:2])[0] == TNS_VERSION_21_1
    assert len(body) == 37
    assert struct.unpack('>H', body[12:14])[0] == 0x002D
