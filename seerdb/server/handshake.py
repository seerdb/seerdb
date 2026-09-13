# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side connect handshake: the CONNECT / ACCEPT exchange and the PRO /
DTY negotiation replies.

The CONNECT is parsed (the mirror of §2.1) and answered with an ACCEPT at the
negotiated TNS version. The PRO and DTY replies reproduce a real XE 11.2
listener's (PROTOCOL.md §4.1): rather than store the DATA packets verbatim, the
server's fixed identity is kept as named pieces — the version banner, charset,
the server capability vectors, the type-conversion table — and the ``build_*``
payload builders assemble the TTC payload that the ``encode_*_reply`` wrappers
frame into a packet. Two dialects (§4.1):

- **TTI_PRO (0x01)** — python-oracledb / seerdb. The same capability block is the
  thin PRO reply *and* the sqlplus/deadbeef DTY reply (byte-identical, so one
  builder serves both). The thin DTY reply is the type-conversion table.
- **sqlplus `deadbeef`** — the PRO reply is an ANO null-negotiation response
  (built field-by-field from the ANO codec, §4.1.1); the extra third-round type
  reply is a DTY reply carrying the DB time zone and timezone-file version (§4.2).

The identity values were captured once from a live XE 11.2 server, and
``tests/test_handshake_generation.py`` pins the builders to those captures
byte-for-byte so the Mirror stays wire-identical; the field version the
capability block advertises is the one parameter that follows the session.
"""

from __future__ import annotations

import re
import secrets
import struct
from dataclasses import dataclass

from seerdb.common import ano
from seerdb.common.exceptions import InterfaceError
from seerdb.common.tns import (
    _DB_TZ_FRAME_PAD,
    _PRO_CHARSET_ELEMENTS,
    _PRO_FDO,
    _SERVER_COMPILE_CAPS,
    _SERVER_DTY_TABLE,
    _SERVER_RUNTIME_CAPS,
    encode_packet,
)
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    CCAP_FIELD_VERSION,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_2,
    FIELD_VERSION_21_1,
    FIELD_VERSION_23_1,
    TNS_ACCEPT,
    TNS_DATA,
    TNS_VERSION_MIN_LARGE_SDU,
    TTI_DTY,
    TTI_PRO,
)
from seerdb.server.framing import DEFAULT_SDU

# The connect-data OFFSET field is measured from the start of the whole packet
# (it includes the 8-byte TNS header), while parse_connect receives the CONNECT
# body (what PacketStream.read_packet yields — header already stripped). So the
# descriptor sits at body[offset - 8].
_TNS_HEADER_LEN = 8

# Fixed-header field offsets, relative to the CONNECT body. This prefix is
# stable across protocol versions; where the descriptor lands varies (11g/v314
# puts it at packet offset 58, v319 at 74), so the offset field below — not a
# fixed position — is authoritative.
_OFF_VERSION = 0
_OFF_LOWEST = 2
_OFF_OPTIONS = 4  # global service options
_OFF_SDU = 6
_OFF_TDU = 8
_OFF_CDATA_LEN = 16
_OFF_CDATA_OFFSET = 18
_MIN_HEADER = 20  # bytes we must have to read every field above

# The TNS protocol version the Mirror answers with. 314 (0x013a) is 11.2: below
# ``TNS_VERSION_MIN_LARGE_SDU`` (315), so the session keeps the legacy 2-byte
# packet framing. A client that speaks a newer version negotiates down to
# whatever is set here, exactly as it would against a real listener of that age.
#
# The version scale, anchored on what the testbeds actually answer: 10g -> 313,
# 11g -> 314, 21c -> 318, 23ai/26ai -> 319. 12.1 and 12.2 sit in the gap, so 12.2
# is taken as 316 — inferred from those anchors rather than captured, since there
# is no 12.2 testbed here; every other number is a live capture. What is
# *behavioural* about 316 is which side of two thresholds it falls on: >= 315
# switches the post-ACCEPT DATA stream to the 4-byte packet length, and >= 318
# (``TNS_VERSION_MIN_OOB_CHECK``) adds the extended ``flags2`` word a client reads
# for end-of-response support. 316 is large-SDU but not end-of-response, which is
# what a 12.2 server is.
#
# Note 319, not 320: a real 23ai answers exactly the value a client knows as
# ``TNS_VERSION_MIN_END_OF_RESPONSE``.
TNS_VERSION_11_2 = 314
TNS_VERSION_12_2 = 316
TNS_VERSION_21_1 = 318
TNS_VERSION_23_1 = 319

_SERVER_TNS_VERSION = TNS_VERSION_11_2


def server_tns_version(field_version: int) -> int:
    """The protocol version that goes with an advertised field version.

    These two are one decision, not two. A session that advertises a 12.2 field
    version but answers 314 is not a server that exists: it claims 12.2
    capabilities and reports a 12.2 release, then frames the connection the 11.2
    way. Deriving one from the other means asking for a 12.2 Mirror gets a 12.2
    Mirror end to end.

    Tiered exactly like :func:`seerdb.server.identity.server_identity`, on the
    same thresholds, so the release a session reports and the way it frames the
    connection can never disagree — the argument above applies at every tier, not
    just the first (#823).
    """
    if field_version >= FIELD_VERSION_23_1:
        return TNS_VERSION_23_1
    if field_version >= FIELD_VERSION_21_1:
        return TNS_VERSION_21_1
    if field_version >= FIELD_VERSION_12_2:
        return TNS_VERSION_12_2
    return TNS_VERSION_11_2


# ACCEPT body fields that are server constants at 11g, read straight off the
# captured XE 11.2 ACCEPT (tests/handshake_11g.py): protocol characteristics,
# an accept-data length of 0, a flags word, and a reserved word.
_ACCEPT_PROTO_CHARS = 0x0100
_ACCEPT_DATA_LEN = 0x0000
_ACCEPT_FLAGS = 0x0020
_ACCEPT_RESERVED = 0x4141
_DEFAULT_TDU = 0xFFFF

# A >= 315 ACCEPT carries the real SDU/TDU as 32-bit fields and zeroes the 16-bit
# pair the legacy form used, so the body grows past the legacy 24 bytes. Offsets
# and length are read off a live 21c ACCEPT (version 318, body 37 bytes) — the
# nearest capture below the end-of-response era: 16-byte fixed head, 8 zero bytes,
# ub4 SDU at 24, ub4 TDU at 28, then a byte and the flags2 word at 33. A client
# only reads flags2 at >= 318, so at 316 it stays zero and no end-of-response is
# advertised. The 21c flags/reserved words differ from the 11g pair above.
_ACCEPT_LARGE_BODY_LEN = 37
_OFF_ACCEPT_SDU32 = 24
_OFF_ACCEPT_TDU32 = 28
_ACCEPT_LARGE_FLAGS = 0x002D
_ACCEPT_LARGE_RESERVED = 0x4101
_LARGE_DEFAULT_TDU = 0x2000

# A 319 (23ai) ACCEPT grows again, read off a live 26ai (body 53 bytes): the
# flags word is 0x003D rather than 21c's 0x002D, and sixteen bytes follow the
# flags2 word — a per-connection identifier, random in every capture.
#
# flags2 stays ZERO here even though a real 23ai sends 0x1A000000. Those bits
# advertise FAST_AUTH (0x10000000) and end-of-response (0x02000000), and a
# client enables each only when the version threshold *and* the flag agree, so
# leaving them clear is how a server says "I speak 319 but not those two". The
# Mirror emits no end-of-response markers, so claiming the bit would hang any
# client that believed it.
_ACCEPT_23_BODY_LEN = 53
_ACCEPT_23_FLAGS = 0x003D
_OFF_ACCEPT_CONN_ID = 37
_ACCEPT_CONN_ID_LEN = 16

# The classic sqlplus / thick-OCI PRO request leads its TTC payload with the ANO
# container magic (0xDEADBEEF) instead of TTI_PRO (0x01); the Mirror must answer
# that request in the matching `deadbeef` dialect (#265).


def pro_is_sqlplus(pro_body: bytes) -> bool:
    """Whether a PRO request is the classic sqlplus/thick `deadbeef` dialect
    (vs the oracledb/seerdb ``TTI_PRO`` dialect, which leads with the TTI_PRO
    ``0x01`` token).

    ``pro_body`` is what :meth:`PacketStream.read_packet` yields for the PRO
    ``TNS_DATA``: the TTC payload with **both** the 8-byte TNS header and the
    2-byte data-flags already stripped (``read_packet`` returns ``packet[10:]``
    for a DATA packet), so the magic sits at the very start — verified against a
    live sqlplus 11.2, which is exactly where a wrong offset misfires (#265).
    """
    return pro_body[:4] == ano.ANO_MAGIC_BYTES


_SERVICE_RE = re.compile(rb'\(SERVICE_NAME\s*=\s*([^)\s]+)', re.IGNORECASE)
_SID_RE = re.compile(rb'\(SID\s*=\s*([^)\s]+)', re.IGNORECASE)
_PROGRAM_RE = re.compile(rb'\(PROGRAM\s*=\s*([^)]*)\)', re.IGNORECASE)
_USER_RE = re.compile(rb'\(USER\s*=\s*([^)]*)\)', re.IGNORECASE)


@dataclass(frozen=True)
class ConnectRequest:
    """The negotiable parameters and identity a client asks for in CONNECT."""

    protocol_version: int
    lowest_version: int
    global_service_options: int
    sdu: int
    tdu: int
    service_name: str | None
    program: str | None
    user: str | None
    descriptor: bytes


def _u16(body: bytes, offset: int) -> int:
    return struct.unpack('>H', body[offset : offset + 2])[0]


def _match(pattern: re.Pattern[bytes], descriptor: bytes) -> str | None:
    found = pattern.search(descriptor)
    return found.group(1).decode('ascii', 'replace') if found else None


def parse_connect(body: bytes) -> ConnectRequest:
    """Parse a CONNECT packet body into a :class:`ConnectRequest`.

    ``body`` is what :meth:`PacketStream.read_packet` returns for a
    ``TNS_CONNECT`` — the packet with its 8-byte TNS header already removed.
    Raises :class:`InterfaceError` if the packet is too short or the connect
    descriptor is out of bounds.
    """
    if len(body) < _MIN_HEADER:
        raise InterfaceError(f'CONNECT too short: {len(body)} bytes')

    cdata_len = _u16(body, _OFF_CDATA_LEN)
    cdata_offset = _u16(body, _OFF_CDATA_OFFSET)
    start = cdata_offset - _TNS_HEADER_LEN
    if start < 0 or start > len(body):
        raise InterfaceError(f'CONNECT descriptor offset out of range: {cdata_offset}')
    descriptor = body[start : start + cdata_len] if cdata_len else body[start:]

    return ConnectRequest(
        protocol_version=_u16(body, _OFF_VERSION),
        lowest_version=_u16(body, _OFF_LOWEST),
        global_service_options=_u16(body, _OFF_OPTIONS),
        sdu=_u16(body, _OFF_SDU),
        tdu=_u16(body, _OFF_TDU),
        service_name=_match(_SERVICE_RE, descriptor) or _match(_SID_RE, descriptor),
        program=_match(_PROGRAM_RE, descriptor),
        user=_match(_USER_RE, descriptor),
        descriptor=descriptor,
    )


def encode_accept(
    request: ConnectRequest,
    *,
    sdu: int = DEFAULT_SDU,
    tns_version: int = _SERVER_TNS_VERSION,
) -> bytes:
    """Build the ACCEPT reply to a parsed CONNECT (the server side of §2.2).

    Negotiates the TNS version down to what the Mirror speaks, echoes the
    client's global service options, and settles the SDU/TDU to the smaller of
    each side's. Returns the full TNS_ACCEPT packet (header included), ready to
    hand to :meth:`PacketStream.write_packet`.
    """
    version = negotiated_tns_version(request, tns_version)
    negotiated_sdu = min(request.sdu, sdu)
    if version >= TNS_VERSION_MIN_LARGE_SDU:
        # The 16-bit SDU/TDU pair is zeroed and the real values move to the ub4
        # fields the client reads at offsets 24 / 28.
        is_23 = version >= TNS_VERSION_23_1
        body_len = _ACCEPT_23_BODY_LEN if is_23 else _ACCEPT_LARGE_BODY_LEN
        large_body = bytearray(body_len)
        struct.pack_into(
            '>HHHHHHHH',
            large_body,
            0,
            version,
            request.global_service_options,
            0,
            0,
            _ACCEPT_PROTO_CHARS,
            _ACCEPT_DATA_LEN,
            _ACCEPT_23_FLAGS if is_23 else _ACCEPT_LARGE_FLAGS,
            _ACCEPT_LARGE_RESERVED,
        )
        struct.pack_into('>I', large_body, _OFF_ACCEPT_SDU32, negotiated_sdu)
        struct.pack_into(
            '>I', large_body, _OFF_ACCEPT_TDU32, min(request.tdu, _LARGE_DEFAULT_TDU)
        )
        if is_23:
            # Random per connection, as it is on the real server. It identifies
            # the session in the server's own logs; nothing reads it back here.
            large_body[_OFF_ACCEPT_CONN_ID:] = secrets.token_bytes(_ACCEPT_CONN_ID_LEN)
        packet, _ = encode_packet(TNS_ACCEPT, bytes(large_body), sdu)
        return packet
    negotiated_tdu = min(request.tdu, _DEFAULT_TDU)
    body = struct.pack(
        '>HHHHHHHH',
        version,
        request.global_service_options,
        negotiated_sdu,
        negotiated_tdu,
        _ACCEPT_PROTO_CHARS,
        _ACCEPT_DATA_LEN,
        _ACCEPT_FLAGS,
        _ACCEPT_RESERVED,
    ) + bytes(8)
    packet, _ = encode_packet(TNS_ACCEPT, body, sdu)
    return packet


def negotiated_tns_version(
    request: ConnectRequest, tns_version: int = _SERVER_TNS_VERSION
) -> int:
    """The protocol version this connection settles on.

    At or above :data:`TNS_VERSION_MIN_LARGE_SDU` the post-ACCEPT ``DATA`` stream
    switches to the 4-byte packet length, so the session has to know this to
    frame the rest of the connection (the CONNECT and ACCEPT packets themselves
    stay in the legacy 16-bit form either way — §1.1).
    """
    return min(request.protocol_version, tns_version)


# A modern thin client (seerdb, go-ora, python-oracledb) runs an ANO (native
# network security) negotiation before PRO once the ACCEPT advertised ANO-capable
# — its container leads with the DEADBEEF magic and carries the 0x0B200200 ANO
# version at body offset 6. The classic sqlplus/thick-OCI client also negotiates
# ANO but stamps version 0x00000000, and its whole login is handled by the
# `deadbeef`-dialect path (#265) — so the modern version is what tells the two
# apart here. (#437)


# --- the deadbeef PRO reply: an ANO null-negotiation response (§4.1.1) ---
# sqlplus / thick OCI leads its login with an ANO negotiation whose container
# stamps version 0x00000000 (vs a thin client's 0x0B200200); the server answers
# by selecting the null algorithm for every service, so the session stays
# plaintext. This same reply doubles as the deadbeef PRO reply. The container
# version is 0, but each service still echoes the modern VERSION_11_2_0_2.
_DEADBEEF_CONTAINER_VERSION = 0x00000000  # sqlplus/OCI stamp (not VERSION_11_2_0_2)
_NULL_ALGO = 0  # null cipher / null checksum selected → plaintext

# --- the deadbeef third-round type reply: a DTY reply (§4.2) ---
# After DTY, sqlplus / thick OCI runs a third negotiation round the server answers
# with this 16-byte TTC payload (a 26-byte DATA packet). It is a data-type reply
# carrying the server's DB session time zone (UTC here) and its timezone-file
# version. Each of the h/m/s offset fields is biased by +60 (Oracle's TZ
# encoding), so a stored 60 means a zero offset.
_DTY_TZ_BIAS = 60  # Oracle biases each of hours/min/sec by +60
_DB_TZ_HMS = (0, 0, 0)  # DB session time zone = UTC (+00:00:00)
_TZFILE_VERSION = 14  # the 11.2 default timezone-file (DST rules) version


def build_caps_block_reply(field_version: int = FIELD_VERSION_11_2) -> bytes:
    """The TTI_PRO capability block as a TTC payload (no packet header): version
    banner, charset, the charset-element array, the fixed descriptor, and the
    server 11g capability vectors. Serves both the thin PRO reply and the
    sqlplus/deadbeef DTY reply (they are byte-identical).

    ``field_version`` is the field version the Mirror advertises — the byte at
    ``CCAP_FIELD_VERSION`` in the compile capabilities, which is what a thin
    client negotiates down to and gates its 12c+ / 23ai wire formats on. The
    rest of the block is the pinned 11.2 identity whatever the version."""
    compile_caps = bytearray(_SERVER_COMPILE_CAPS)
    compile_caps[CCAP_FIELD_VERSION] = field_version
    return (
        # TTI_PRO, the negotiated field version (6 = 11g), a zero, then the
        # NUL-terminated version banner.
        bytes([TTI_PRO, FIELD_VERSION_11_2, 0])
        + b'x86_64/Linux 2.4.xx'
        + b'\x00'
        + struct.pack('<H', AL32UTF8_CHARSET)  # charset id, LE
        + bytes([1])  # flags
        + struct.pack('<H', len(_PRO_CHARSET_ELEMENTS) // 5)
        + _PRO_CHARSET_ELEMENTS
        + struct.pack('>H', len(_PRO_FDO))
        + _PRO_FDO
        + bytes([len(compile_caps)])
        + bytes(compile_caps)
        + bytes([len(_SERVER_RUNTIME_CAPS)])
        + _SERVER_RUNTIME_CAPS
    )


def build_dty_type_reply() -> bytes:
    """The thin DTY reply as a TTC payload: TTI_DTY then the server's
    type-conversion table."""
    return bytes([TTI_DTY]) + _SERVER_DTY_TABLE


def build_pro_sqlplus_reply() -> bytes:
    """The sqlplus/deadbeef PRO reply payload — an ANO null-negotiation response
    (§4.1.1), built field-by-field from the ANO codec (#564).

    Four services (supervisor, auth, encryption, data-integrity); encryption and
    data-integrity both select the null algorithm, so no cipher/MAC is activated
    and the session stays plaintext. The container stamps version 0x00000000 (the
    sqlplus/OCI form); each service echoes VERSION_11_2_0_2. This is the same reply the
    thin ANO path replays as its null-negotiation response — it *is* that response.
    """
    services = [
        ano.encode_service(
            ano.SERVICE_SUPERVISOR,
            [
                ano.sp_version(),  # VERSION_11_2_0_2
                ano.sp_status(ano.SUPERVISOR_STATUS_OK),  # 31
                ano.sp_ub2_array([ano.SERVICE_SUPERVISOR, ano.SERVICE_AUTH]),  # [4,1]
            ],
        ),
        ano.encode_service(
            ano.SERVICE_AUTH,
            [ano.sp_version(), ano.sp_status(ano.AUTH_STATUS_DEADBEEF)],
        ),
        ano.encode_service(
            ano.SERVICE_ENCRYPTION,
            [ano.sp_version(), ano.sp_ub1(_NULL_ALGO)],
        ),
        ano.encode_service(
            ano.SERVICE_DATA_INTEGRITY,
            [ano.sp_version(), ano.sp_ub1(_NULL_ALGO)],
        ),
    ]
    return ano.encode_ano(services, ContainerVersion=_DEADBEEF_CONTAINER_VERSION)


def build_type_reply_sqlplus() -> bytes:
    """The deadbeef dialect's third-round type reply payload (#265, #565).

    A DTY (data-type negotiation) reply carrying the server's DB session time zone
    and its timezone-file version (§4.2): the ``TTI_DTY`` message code, an 11-byte
    time-zone block (its h/m/s offset fields at bytes 4..6, each biased by +60),
    then the timezone-file version as a big-endian ub4.
    """
    (Hours, Minutes, Seconds) = _DB_TZ_HMS
    tz_block = (
        _DB_TZ_FRAME_PAD
        + bytes([Hours + _DTY_TZ_BIAS, Minutes + _DTY_TZ_BIAS, Seconds + _DTY_TZ_BIAS])
        + _DB_TZ_FRAME_PAD
    )
    return bytes([TTI_DTY]) + tz_block + struct.pack('>I', _TZFILE_VERSION)


def is_ano_negotiation(pro_body: bytes) -> bool:
    """Whether a post-ACCEPT packet is a modern thin client's ANO negotiation
    (vs a TTI_PRO or the sqlplus/OCI ANO, both handled by other paths)."""
    return pro_body[:4] == ano.ANO_MAGIC_BYTES and pro_body[6:10] == ano.VERSION_BYTES


def encode_ano_null_reply(*, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the null-algorithm ANO negotiation reply — §ANO (#437).

    Replays the real 11g server's response to a modern client's ANO request:
    every service selects the null algorithm, so no cipher/MAC is activated and
    the session stays plaintext. (These are the same bytes the sqlplus/OCI path
    replays as its first `deadbeef` reply — it *is* the ANO response.)
    """
    packet, _ = encode_packet(TNS_DATA, build_pro_sqlplus_reply(), sdu)
    return packet


def encode_fast_auth_reply(challenge: bytes, *, field_version: int) -> bytes:
    """The bundled reply a client\'s 23ai FAST_AUTH packet expects (§20): the PRO
    reply payload, the DTY reply payload, and the OSESSKEY auth challenge, in one
    ``DATA`` body. The client scans it for the challenge RPA
    (:func:`find_fast_auth_rpa`) and finishes O5LOGON exactly as the legacy
    three-message handshake does. ``challenge`` is :func:`encode_challenge`\'s RPA
    payload; the caller frames the whole thing with ``write_packet``.
    """
    return build_caps_block_reply(field_version) + build_dty_type_reply() + challenge


def encode_pro_reply(
    *,
    sqlplus: bool = False,
    sdu: int = DEFAULT_SDU,
    field_version: int = FIELD_VERSION_11_2,
) -> bytes:
    """Build the server's PRO (protocol negotiation) reply — §4.1.

    Reproduces the real 11g server's PRO reply, whose capability array pins the
    negotiated field version to 6. ``sqlplus`` selects the classic
    ``deadbeef`` dialect (127B) over the oracledb/seerdb ``TTI_PRO`` dialect
    (238B); pass whatever :func:`pro_is_sqlplus` reported for the request.
    Returns the full TNS_DATA packet.
    """
    payload = (
        build_pro_sqlplus_reply() if sqlplus else build_caps_block_reply(field_version)
    )
    packet, _ = encode_packet(TNS_DATA, payload, sdu)
    return packet


def encode_dty_reply(
    *,
    sqlplus: bool = False,
    sdu: int = DEFAULT_SDU,
    field_version: int = FIELD_VERSION_11_2,
) -> bytes:
    """Build the server's DTY (data-type negotiation) reply — §4.2.

    Reproduces the real 11g server's DTY reply as a full TNS_DATA packet.
    ``sqlplus`` selects the ``deadbeef`` dialect (238B — the same capability
    block as the thin PRO reply) over the oracledb/seerdb dialect (924B
    type-conversion table); use the same value the PRO reply used so both halves
    of the handshake speak one dialect.
    """
    payload = (
        build_caps_block_reply(field_version) if sqlplus else build_dty_type_reply()
    )
    packet, _ = encode_packet(TNS_DATA, payload, sdu)
    return packet


def encode_type_reply_sqlplus(*, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the deadbeef dialect's third-round data-type reply — the 26-byte
    ``ttc=02`` confirmation sqlplus/thick OCI expects after PRO and DTY, before
    it sends OSESSKEY (#265). Thin clients skip this round. Full TNS_DATA packet.
    """
    packet, _ = encode_packet(TNS_DATA, build_type_reply_sqlplus(), sdu)
    return packet


def client_field_version(dty_body: bytes) -> int | None:
    """The TTC field version a client settled on, read from its DTY.

    A client picks ``min(its own, the version the server advertised in the PRO
    reply)`` and then sends its capability block in the DTY, so this byte is the
    version the session actually agreed on -- the server does not have to infer
    it. The Mirror used to discard the DTY and keep encoding at whatever it was
    configured with, which is why a client below that version failed (#816).

    Layout, mirroring ``encode_dictionary_dty``: the TTI_DTY token, the charset
    and ncharset as little-endian ub2s, an encoding flag, then the compile
    capabilities as a length byte followed by the array. The field version is
    ``CCAP_FIELD_VERSION`` within it.

    Returns ``None`` when the block cannot be read -- a truncated packet, or the
    23ai fast-auth bundle, whose DTY does not arrive on its own. Callers fall
    back to their configured version, so an unreadable block costs nothing that
    worked before.
    """
    try:
        if not dty_body or dty_body[0] != TTI_DTY:
            return None
        caps_len = dty_body[6]
        caps = dty_body[7 : 7 + caps_len]
        if len(caps) <= CCAP_FIELD_VERSION:
            return None
        version = caps[CCAP_FIELD_VERSION]
        return version or None
    except IndexError:
        return None
