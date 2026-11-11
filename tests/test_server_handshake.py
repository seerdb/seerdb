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
    ANO_REPLY_SQLPLUS,
    DTY_REPLY,
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
    TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE,
    TNS_DATA,
    TNS_GSO_CAN_RECV_ATTENTION,
    TNS_VERSION_MIN_LARGE_SDU,
    TNS_VERSION_MIN_OOB_CHECK,
    TTI_DTY,
    TTI_PRO,
)
from seerdb.server.handshake import (
    TNS_VERSION_11_2,
    TNS_VERSION_12_1,
    TNS_VERSION_12_2,
    TNS_VERSION_21_1,
    TNS_VERSION_23_1,
    connect_data_follows,
    encode_accept,
    encode_ano_null_reply,
    encode_dty_reply,
    encode_oci_dty_reply,
    encode_pro_reply,
    negotiated_tns_version,
    opens_with_oci_ano,
    parse_connect,
    server_tns_version,
)

# A CONNECT whose descriptor does not fit in it, captured from python-oracledb
# 26.0.1 (sdu=4096, a long program path): the CONNECT states 0x010a bytes of
# connect data at offset 74 and ends there; the descriptor follows in a DATA
# packet of its own (#1769).
_SPLIT_CONNECT = bytes.fromhex(
    '004a000001000000013f012c0401100010004f9800000001010a004a00000000'
    '8484000000000000000000000000000000000000000000000000000010000000'
    '10000000000000000001'
)
_SPLIT_CONNECT_DATA = bytes.fromhex(
    '01140000060000000000284445534352495054494f4e3d285452414e53504f52'
    '545f434f4e4e4543545f54494d454f55543d3329285344553d34303936292841'
    '4444524553533d2850524f544f434f4c3d7463702928484f53543d3132372e30'
    '2e302e312928504f52543d3135363032292928434f4e4e4543545f444154413d'
    '28534552564943455f4e414d453d465245455044423129284349443d2850524f'
    '4752414d3d2f6f70742f6170706c69636174696f6e2f76656e762f62696e2f70'
    '7974686f6e332e31322928484f53543d636c69656e742e6578616d706c652928'
    '555345523d617070292928434f4e4e454354494f4e5f49443d72646745647179'
    '4d4254516e4b7830474446635846773d3d292929'
)


def test_a_connect_carrying_its_descriptor_needs_nothing_more() -> None:
    assert not connect_data_follows(fx.CONNECT[8:])


def test_a_connect_short_of_its_descriptor_waits_for_it() -> None:
    assert connect_data_follows(_SPLIT_CONNECT[8:])
    # read_packet strips the DATA packet's header and data flags (10 bytes).
    req = parse_connect(_SPLIT_CONNECT[8:] + _SPLIT_CONNECT_DATA[10:])
    assert req.service_name == 'FREEPDB1'
    assert req.program == '/opt/application/venv/bin/python3.12'
    assert req.user == 'app'
    assert req.sdu == 4096
    assert req.descriptor.endswith(b')))')


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


def _real_11g_accept_without_oob() -> bytes:
    # The captured ACCEPT with the one bit the Mirror does not echo: it cannot
    # receive an out-of-band break, so it does not offer one (#1349).
    accept = bytearray(fx.ACCEPT)
    (options,) = struct.unpack_from('>H', accept, 10)
    struct.pack_into('>H', accept, 10, options & ~TNS_GSO_CAN_RECV_ATTENTION)
    return bytes(accept)


def test_encode_accept_byte_matches_the_real_11g_accept() -> None:
    # The killer test: our ACCEPT reproduces the captured server packet exactly,
    # but for the out-of-band bit.
    req = parse_connect(fx.CONNECT[8:])
    assert encode_accept(req) == _real_11g_accept_without_oob()


def test_accept_never_offers_out_of_band_breaks() -> None:
    # The client offers them (0x0c41 has 0x0400) and a real server echoes that,
    # but the Mirror never reads urgent data: a cancel sent that way was lost and
    # the call ran to the end (#1349). The rest of the options are echoed.
    for version in (TNS_VERSION_11_2, TNS_VERSION_23_1):
        req = replace(parse_connect(fx.CONNECT[8:]), protocol_version=319)
        accept = encode_accept(req, tns_version=version)
        (options,) = struct.unpack_from('>H', accept, 10)
        assert options == 0x0C41 & ~TNS_GSO_CAN_RECV_ATTENTION


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
    # is exactly what the serve loop feeds opens_with_oci_ano (header + data-flags
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


def test_opens_with_oci_ano_detects_the_deadbeef_round() -> None:
    # Run the captured sqlplus PRO through read_packet — the exact path a live
    # client exercises. read_packet strips the 8-byte header AND the 2-byte
    # data-flags, so the deadbeef magic must be at the very start of the body.
    # (Feeding a hand-sliced ANO_CLIENT[8:] hid an off-by-two here; a live
    # sqlplus 11.2 caught it — #265.)
    typ, body = _read_packet_body(fx.ANO_CLIENT)
    assert typ == TNS_DATA
    assert opens_with_oci_ano(body) is True

    # A thin (TTI_PRO) PRO through the same path is not the sqlplus dialect.
    thin_raw = struct.pack('>HHBBH', 8 + 2 + 8, 0, TNS_DATA, 0, 0)
    thin_raw += b'\x00\x00' + bytes([TTI_PRO, 6, 5, 4, 3, 2, 1, 0])
    _typ, thin_body = _read_packet_body(thin_raw)
    assert opens_with_oci_ano(thin_body) is False


def test_sqlplus_ano_reply_reproduces_the_captured_packet() -> None:
    # Re-wrapping the stored deadbeef payload reproduces the real server's reply
    # to sqlplus's ANO round (127B) exactly.
    assert encode_ano_null_reply() == fx.ANO_SERVER
    assert ANO_REPLY_SQLPLUS == fx.ANO_SERVER


def test_sqlplus_pro_reply_reproduces_the_captured_packet() -> None:
    assert encode_pro_reply(oci=True) == fx.PRO_SERVER
    assert PRO_REPLY_SQLPLUS == fx.PRO_SERVER


def test_sqlplus_dty_reply_reproduces_the_captured_packet() -> None:
    # sqlplus's data-type round, its third: the built ttc=02 reply reproduces the
    # real server packet (#265).
    from test_handshake_generation import DTY_REPLY_SQLPLUS

    from seerdb.server.handshake import encode_oci_dty_reply

    assert encode_oci_dty_reply() == DTY_REPLY_SQLPLUS


# sqlplus's type request (the ttc=02 round) and what the server answered, from
# captures of sqlplus 10.2 and 11.2 against 11g XE (#1764). 10g answered sqlplus
# 10.2 exactly as 11g did.
_TYPE_REQUEST_SQLPLUS_10_2 = bytes.fromhex(
    '02690369030224060101010d01010401010101010101ffff0308030301003f01473f0102'
    '01010301000001050201000018800000003c3c3c80000000d007'
)
_TYPE_REQUEST_SQLPLUS_11_2 = bytes.fromhex(
    '02690369030227060101010f010106010101010101017fff030a030701017f017fff0109'
    '0101bf010506000107040702010000180003800000003c3c3c800000000000000ed007'
)


def test_the_type_reply_carries_a_tz_file_version_only_if_the_request_did() -> None:
    # sqlplus 10.2 sends no timezone-file version in its type request, and the
    # server leaves it out of the reply; the 4 bytes it does not expect drew a
    # break (#1764). sqlplus 11.2 sends one and gets one.
    from seerdb.server.handshake import (
        build_oci_dty_reply,
        client_sends_tz_file_version,
    )

    assert not client_sends_tz_file_version(_TYPE_REQUEST_SQLPLUS_10_2)
    assert client_sends_tz_file_version(_TYPE_REQUEST_SQLPLUS_11_2)
    assert build_oci_dty_reply(tz_file_version=False) == bytes.fromhex(
        '02800000003c3c3c80000000'
    )
    assert build_oci_dty_reply() == bytes.fromhex('02800000003c3c3c800000000000000e')
    # Nothing readable keeps the form every client got before.
    assert client_sends_tz_file_version(b'')
    assert client_sends_tz_file_version(b'\x02\x69')


def test_dialects_are_distinct() -> None:
    # The two dialects' replies are genuinely different shapes (238/924 vs
    # 127/238), so serving the wrong one would break the handshake.
    assert encode_ano_null_reply() != encode_pro_reply()
    assert encode_oci_dty_reply() != encode_dty_reply()


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
    # The default is still the captured 11g ACCEPT, but for the OOB bit.
    req = parse_connect(fx.CONNECT[8:])
    assert encode_accept(req, tns_version=TNS_VERSION_11_2) == (
        _real_11g_accept_without_oob()
    )


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
    # 12.1 answers 315, not 314. This line asserted 314 until #1131: the release
    # constants lived in handshake.py and the capability thresholds in
    # tns_consts.py, so 315 was present only as TNS_VERSION_MIN_LARGE_SDU and
    # `server_tns_version` could not see it as a tier -- 12.1 fell through to
    # 11.2's 314. A Mirror asked for a 12.1 identity then answered 314, and
    # python-oracledb refuses anything below 315 outright (DPY-3010), so no
    # modern thin client would connect to it.
    assert server_tns_version(FIELD_VERSION_12_1) == TNS_VERSION_12_1
    assert server_tns_version(FIELD_VERSION_12_2) == TNS_VERSION_12_2
    # The same argument one tier up: a Mirror presenting 21c or 23ai must frame
    # like one, not fall back to 12.2's 316 (#823). 318 and 319 are captured off
    # the live testbeds -- a real 23ai answers 319, not 320.
    assert server_tns_version(FIELD_VERSION_21_1) == TNS_VERSION_21_1
    assert server_tns_version(FIELD_VERSION_23_1) == TNS_VERSION_23_1
    assert server_tns_version(FIELD_VERSION_23_4) == TNS_VERSION_23_1


def test_every_field_version_tier_has_its_own_protocol_version() -> None:
    """No tier may silently fall through to a lower release's framing (#1131).

    The specific way this went wrong is worth pinning rather than just fixing:
    12.1's protocol version, 315, WAS in the codebase -- spelled
    ``TNS_VERSION_MIN_LARGE_SDU``, because 12.1 is the release that introduced
    the 4-byte packet length. Written under a capability name in one module and
    the release names in another, nothing connected the two, so the tier table
    skipped straight from 11.2 to 12.2 and a 12.1 Mirror answered 314.

    Reading the table as a whole catches that: a version that falls through
    shows up as a duplicate, and a strictly increasing table has none.
    """
    tiers = [
        (FIELD_VERSION_11_2, TNS_VERSION_11_2),
        (FIELD_VERSION_12_1, TNS_VERSION_12_1),
        (FIELD_VERSION_12_2, TNS_VERSION_12_2),
        (FIELD_VERSION_21_1, TNS_VERSION_21_1),
        (FIELD_VERSION_23_1, TNS_VERSION_23_1),
    ]
    answered = [server_tns_version(fv) for fv, _ in tiers]
    assert answered == [tns for _, tns in tiers]
    # Strictly increasing: equal neighbours would mean one release borrowing
    # another's framing, which is the fall-through this test exists to stop.
    assert all(a < b for a, b in zip(answered, answered[1:]))
    # And the aliases still say what they mean.
    assert TNS_VERSION_MIN_LARGE_SDU == TNS_VERSION_12_1
    assert TNS_VERSION_MIN_OOB_CHECK == TNS_VERSION_21_1


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
    # flags2 now advertises HAS_END_OF_RESPONSE (#1059). A client turns the
    # capability on only when the version AND the flag agree, and it is what
    # python-oracledb gates pipelining on -- without it `run_pipeline` silently
    # ran the operations one at a time. FAST_AUTH (0x10000000) stays clear;
    # that one is still unimplemented, so a real 23ai's 0x1A000000 is not
    # matched in full on purpose.
    assert struct.unpack('>I', body[33:37])[0] == TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE
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


def test_oci_dty_reply_adds_o7logon_from_12_1() -> None:
    # A modern sqlplus uses the 12c SHA-2 verifier only when the logon types
    # carry O7LOGON, as a 12c-band server's do (18c: 0x6F) (#1282). The thin
    # reply and the 11.2 OCI one keep the captured 0x0F.
    from seerdb.common.tns_consts import (
        CCAP_LOGON_O7LOGON,
        FIELD_VERSION_11_2,
        FIELD_VERSION_12_1,
        FIELD_VERSION_18_1_EXT_1,
    )
    from seerdb.server.handshake import build_caps_block_reply

    oci_121 = build_caps_block_reply(FIELD_VERSION_12_1, oci=True)
    thin_121 = build_caps_block_reply(FIELD_VERSION_12_1)
    assert len(oci_121) == len(thin_121)
    diff = {
        (thin_121[i], oci_121[i])
        for i in range(len(oci_121))
        if oci_121[i] != thin_121[i]
    }
    # Two bytes differ: the logon types, and the field version the OCI reply
    # advertises instead (see the next test).
    logon = 0x0F
    assert diff == {
        (logon, logon | CCAP_LOGON_O7LOGON),
        (FIELD_VERSION_12_1, FIELD_VERSION_18_1_EXT_1),
    }
    assert build_caps_block_reply(FIELD_VERSION_11_2, oci=True) == (
        build_caps_block_reply(FIELD_VERSION_11_2)
    )


def test_oci_dty_reply_advertises_18c_from_12_1() -> None:
    # From 12.1 sqlplus is told 18c's field version, the one 12c-band layout
    # there are captures of; below 12.1 it gets the session's own (#1282).
    from seerdb.common.tns_consts import (
        FIELD_VERSION_11_2,
        FIELD_VERSION_12_1,
        FIELD_VERSION_18_1_EXT_1,
    )
    from seerdb.server.handshake import oci_field_version

    assert oci_field_version(FIELD_VERSION_11_2) == FIELD_VERSION_11_2
    assert oci_field_version(FIELD_VERSION_12_1) == FIELD_VERSION_18_1_EXT_1


# The capability block (the DTY proper) each sqlplus sends, one round after its
# TTI_PRO: sqlplus 23.26 and sqlplus 11.2.0.2, captured against live 11g.
_SQLPLUS_23_DTY = bytes.fromhex(
    '0269036903023706010101ef0f011b010101010101017fff031003030101ff01'
    'ffff010e0101ff01060cf6097f050fff0d0b00ff030000000000070202040d02'
    '010000180087000300000000800000003c3c3c800000000000002bd007'
)
_SQLPLUS_11_DTY = bytes.fromhex(
    '02690369030227060101010f010106010101010101017fff030a030301007f01'
    '7fff010601013f010306000103020702010000180003800000003c3c3c800000'
    '000000000ed007'
)


def test_the_lob_column_form_follows_the_client() -> None:
    # sqlplus 23.26 offers CCAP_LOB_12C and reads a LOB column with the LOB's
    # length and chunk size in it; sqlplus 11.2 does not, and reads the bare
    # locator. A live 11g answers each in its own form (#1287).
    from seerdb.common.tns_consts import CCAP_LOB, CCAP_LOB_12C
    from seerdb.server.handshake import client_compile_cap, client_field_version

    assert (client_compile_cap(_SQLPLUS_23_DTY, CCAP_LOB) or 0) & CCAP_LOB_12C
    assert not (client_compile_cap(_SQLPLUS_11_DTY, CCAP_LOB) or 0) & CCAP_LOB_12C
    # The same block carries the field version each can speak.
    assert client_field_version(_SQLPLUS_23_DTY) == 27
    assert client_field_version(_SQLPLUS_11_DTY) == 6


# The head of the fast-auth bundle the seerdb client sent a live 23ai when
# capped at field version 18, which 23ai accepted: the FAST_AUTH header, the
# PRO message, six bytes whose version byte always says 19.1 EXT 1, and the DTY
# up to its capability block, which names 18. The OSESSKEY that follows is cut.
_FAST_AUTH_FV18 = bytes.fromhex(
    '220101000106050403020100736565726462207838365f36342f4c696e75780000000000'
    '000d0269036903033506000000ea180012010100000000002990030703000100cf000004'
    '010000001000000c2000b80008640005003e0300000000000003'
)


def test_a_fast_auth_client_is_served_at_the_version_its_bundle_names() -> None:
    # Every client at field version 18 or later logs in with the bundle, so the
    # DTY a server reads its version from rides inside it. Not read there, a
    # client at 18 to 23 was served at the version the Mirror presents.
    from seerdb.server.handshake import client_field_version, fast_auth_field_version

    assert client_field_version(_FAST_AUTH_FV18) is None
    assert fast_auth_field_version(_FAST_AUTH_FV18) == 18
    assert fast_auth_field_version(_FAST_AUTH_FV18[:20]) is None
    assert fast_auth_field_version(_SQLPLUS_11_DTY) is None


# A listener's refusals (#2471), captured from 10g, 11g, 18c, 21c and 23ai Free
# for an unknown SERVICE_NAME (12514) and an unknown INSTANCE_NAME (12521).
@pytest.mark.parametrize(
    ('version_no', 'vsnnum'),
    [
        (0x0A200500, 169870592),  # 10.2.0.5: its release
        (0x0B200200, 186647040),  # 11.2.0.2: its release
        (0x12400000, 301989888),  # 18.4: 18.0 alone
        (0x15300000, 352321536),  # 21.3: 21.0 alone
        (0x171A2000, 0),  # 23.26.2: none
    ],
)
@pytest.mark.parametrize('code', [12514, 12521])
def test_a_refuse_is_the_listeners(version_no: int, vsnnum: int, code: int) -> None:
    from seerdb.server.handshake import encode_refuse

    text = (
        f'(DESCRIPTION=(TMP=)(VSNNUM={vsnnum})(ERR={code})'
        f'(ERROR_STACK=(ERROR=(CODE={code})(EMFI=4))))'
    ).encode()
    packet = encode_refuse(code, version_no)
    assert packet[4] == 4  # TNS_REFUSE
    assert int.from_bytes(packet[:2], 'big') == len(packet)
    assert packet[8:] == b'\x22\x00' + len(text).to_bytes(2, 'big') + text


def test_a_connect_names_its_instance() -> None:
    # (INSTANCE_NAME=...) is read from the descriptor, as SERVICE_NAME is.
    req = parse_connect(fx.CONNECT[8:])
    assert req.instance_name is None
    descriptor = req.descriptor.replace(
        b'(SERVICE_NAME=XE)', b'(SERVICE_NAME=XE)(INSTANCE_NAME=xe1)'
    )
    assert descriptor != req.descriptor
    body = bytearray(fx.CONNECT[8:])
    start = struct.unpack('>H', body[18:20])[0] - 8
    body[start:] = descriptor
    struct.pack_into('>H', body, 16, len(descriptor))
    assert parse_connect(bytes(body)).instance_name == 'xe1'
