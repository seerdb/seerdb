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
    _datatype_table_12c,
    encode_packet,
)
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    CCAP_FEATURE_BACKPORT2,
    CCAP_FEATURE_BACKPORT2_TXN_PRIORITY,
    CCAP_FIELD_VERSION,
    CCAP_LOGON_O7LOGON,
    CCAP_LOGON_TYPES,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_12_2,
    FIELD_VERSION_18_1_EXT_1,
    FIELD_VERSION_21_1,
    FIELD_VERSION_23_1,
    TNS_ACCEPT,
    TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE,
    TNS_DATA,
    TNS_GSO_CAN_RECV_ATTENTION,
    TNS_MSG_TYPE_FAST_AUTH,
    TNS_REFUSE,
    TNS_VERSION_11_2,
    TNS_VERSION_12_1,
    TNS_VERSION_12_2,
    TNS_VERSION_21_1,
    TNS_VERSION_23_1,
    TNS_VERSION_MIN_LARGE_SDU,
    TNS_VERSION_MIN_OOB_CHECK,
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
    if field_version >= FIELD_VERSION_12_1:
        return TNS_VERSION_12_1
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
# flags2 carries the capability bits a real 23ai sends as 0x1A000000. A client
# enables each only when the version threshold *and* the flag agree, so what is
# left clear is how a server says "I speak 319 but not that".
#
# END_OF_RESPONSE (0x02000000) is now SET at >= 318 (#1059). It used to stay
# clear, correctly: the Mirror emitted no end-of-response markers, and claiming
# the bit would have hung any client that believed it. It emits them now, and
# the cost of not claiming it was larger than it looked -- python-oracledb
# pipelines ONLY on this capability, so without it `run_pipeline` silently fell
# back to running the operations one at a time, losing the per-operation fetch
# options captured at add time.
#
# FAST_AUTH (0x10000000) stays clear; that one is still unimplemented.
_ACCEPT_23_BODY_LEN = 53
_ACCEPT_23_FLAGS = 0x003D
# The flags2 word sits between the ub4 TDU and the connection id.
_OFF_ACCEPT_FLAGS2 = 33
_OFF_ACCEPT_CONN_ID = 37
_ACCEPT_CONN_ID_LEN = 16

# The classic sqlplus / thick-OCI PRO request leads its TTC payload with the ANO
# container magic (0xDEADBEEF) instead of TTI_PRO (0x01); the Mirror must answer
# that request in the matching `deadbeef` dialect (#265).


def opens_with_oci_ano(first: bytes) -> bool:
    """Whether a client's first DATA message is sqlplus / thick OCI's ANO
    negotiation, the ``deadbeef`` container it opens with before its PRO
    request (§4.1.1). A thin client opens with the PRO request itself, led by
    the ``TTI_PRO`` ``0x01`` token.

    ``first`` is what :meth:`PacketStream.read_packet` yields for the PRO
    ``TNS_DATA``: the TTC payload with **both** the 8-byte TNS header and the
    2-byte data-flags already stripped (``read_packet`` returns ``packet[10:]``
    for a DATA packet), so the magic sits at the very start — verified against a
    live sqlplus 11.2, which is exactly where a wrong offset misfires (#265).
    """
    return first[:4] == ano.ANO_MAGIC_BYTES


_SERVICE_RE = re.compile(rb'\(SERVICE_NAME\s*=\s*([^)\s]+)', re.IGNORECASE)
_SID_RE = re.compile(rb'\(SID\s*=\s*([^)\s]+)', re.IGNORECASE)
_INSTANCE_RE = re.compile(rb'\(INSTANCE_NAME\s*=\s*([^)\s]+)', re.IGNORECASE)
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
    instance_name: str | None = None


def _u16(body: bytes, offset: int) -> int:
    return struct.unpack('>H', body[offset : offset + 2])[0]


def _match(pattern: re.Pattern[bytes], descriptor: bytes) -> str | None:
    found = pattern.search(descriptor)
    return found.group(1).decode('ascii', 'replace') if found else None


def connect_data_follows(body: bytes) -> bool:
    """Whether a CONNECT body states connect data that is not in it.

    A client sends a descriptor over 230 bytes in a ``TNS_DATA`` packet of its
    own straight after the CONNECT, which keeps the full length and offset but
    ends where the data would start (python-oracledb, seerdb #1768). The caller
    reads that packet and appends its body before :func:`parse_connect` (#1769).
    """
    if len(body) < _MIN_HEADER:
        return False
    start = _u16(body, _OFF_CDATA_OFFSET) - _TNS_HEADER_LEN
    return len(body) - start < _u16(body, _OFF_CDATA_LEN)


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
        instance_name=_match(_INSTANCE_RE, descriptor),
    )


# A listener's refusal (#2471), as 10g, 11g, 18c, 21c and 23ai Free send one
# for a service or an instance they don't serve: user reason 0x22, system
# reason 0, then the descriptor with the error twice.
_REFUSE_USER_REASON = 0x22


def encode_refuse(code: int, version_no: int) -> bytes:
    """The TNS_REFUSE a listener answers a CONNECT with, refusing it with
    ORA-``code`` (12514 for an unknown service, 12521 for an unknown instance).

    ``VSNNUM`` is the listener's release: 10g and 11g send their packed
    release, 18c and 21c the major release alone (18.0, 21.0), 23ai 0.
    ``version_no`` is the release the Mirror presents, packed as
    ``AUTH_VERSION_NO``.
    """
    major = version_no >> 24
    vsnnum = 0 if major >= 23 else major << 24 if major >= 18 else version_no
    text = (
        f'(DESCRIPTION=(TMP=)(VSNNUM={vsnnum})(ERR={code})'
        f'(ERROR_STACK=(ERROR=(CODE={code})(EMFI=4))))'
    ).encode('ascii')
    body = struct.pack('>BBH', _REFUSE_USER_REASON, 0, len(text)) + text
    packet, _ = encode_packet(TNS_REFUSE, body, DEFAULT_SDU)
    return packet


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
    # Every option the client offered is echoed but out-of-band breaks: the
    # Mirror never reads urgent data, so a client that sent its cancel that way
    # saw the call run to the end (#1349). Without it the client interrupts
    # in-band, which the session answers as a real server does (#844).
    options = request.global_service_options & ~TNS_GSO_CAN_RECV_ATTENTION
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
            options,
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
        if version >= TNS_VERSION_MIN_OOB_CHECK:
            # Only read by a client at this version and up, so setting it below
            # would be noise an older client never looks at.
            struct.pack_into(
                '>I',
                large_body,
                _OFF_ACCEPT_FLAGS2,
                TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE,
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
        options,
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


def oci_field_version(field_version: int) -> int:
    """The field version the Mirror speaks to sqlplus / thick OCI.

    A sqlplus client lays out its requests, and reads the replies, by the field
    version the handshake advertises. Below 12.1 that is the session's own. From
    12.1 it is 18c's: the only 12c-band layout there are live captures of, so
    every byte the Mirror sends there can be checked against a real server's. A
    12.1 server's own layout differs from it (sqlplus sends a 12.1 server a
    shorter statement than an 18c one), and nothing here has seen it. sqlplus
    accepts 18c's layout over a 12.1 ACCEPT (#1282).
    """
    if field_version >= FIELD_VERSION_12_1:
        return FIELD_VERSION_18_1_EXT_1
    return field_version


def build_caps_block_reply(
    field_version: int = FIELD_VERSION_11_2,
    *,
    oci: bool = False,
    txn_priority: bool = False,
) -> bytes:
    """The TTI_PRO capability block as a TTC payload (no packet header): version
    banner, charset, the charset-element array, the fixed descriptor, and the
    server 11g capability vectors. Serves both the thin PRO reply and the
    sqlplus/deadbeef DTY reply (they are byte-identical).

    ``field_version`` is the field version the Mirror advertises — the byte at
    ``CCAP_FIELD_VERSION`` in the compile capabilities, which is what a thin
    client negotiates down to and gates its 12c+ / 23ai wire formats on. The
    rest of the block is the pinned 11.2 identity whatever the version.

    ``oci`` marks the sqlplus/deadbeef DTY reply, which advertises
    :func:`oci_field_version` instead. From 12.1 it also adds the O7LOGON logon
    type a 12c-band server advertises: without it a modern sqlplus cannot use
    the 12c SHA-2 verifier the OCI challenge then offers (#1282).

    ``txn_priority`` advertises transaction priority, as 23ai does in bit 0x01 of
    ``CCAP_FEATURE_BACKPORT2`` (#1779), when the Mirror presents a 23ai field
    version to a thin client. The 11.2 vector stops short of that byte, so it
    grows to reach it; the bytes between stay zero, which a client reads as the
    features they name being absent, exactly as when the vector ended."""
    compile_caps = bytearray(_SERVER_COMPILE_CAPS)
    compile_caps[CCAP_FIELD_VERSION] = field_version
    if oci and field_version >= FIELD_VERSION_12_1:
        compile_caps[CCAP_FIELD_VERSION] = oci_field_version(field_version)
        compile_caps[CCAP_LOGON_TYPES] |= CCAP_LOGON_O7LOGON
    if txn_priority and not oci and field_version >= FIELD_VERSION_23_1:
        compile_caps += bytes(CCAP_FEATURE_BACKPORT2 + 1 - len(compile_caps))
        compile_caps[CCAP_FEATURE_BACKPORT2] |= CCAP_FEATURE_BACKPORT2_TXN_PRIORITY
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


def build_dty_type_reply(field_version: int = FIELD_VERSION_11_2) -> bytes:
    """The thin DTY reply as a TTC payload: TTI_DTY then the server's
    type-conversion table.

    The table has two encodings and the field version picks between them. Up to
    11g each entry is single bytes (``<type> <conv> <rep> 00``); from 12.1 every
    field widens to a UB2 and the table ends in a UB2 zero. A client reads the
    table by walking entries until that terminator, so handing a 12.1+ client the
    narrow table does not merely mis-describe a few types — the client reads two
    of our bytes as one field, never lands on the terminator, runs off the end
    and blocks waiting for a continuation that never comes (#824).

    seerdb's own client has always chosen on the same threshold when it *sends*
    its table (``FieldVersion >= FIELD_VERSION_12_1``); this is the server half of
    the same decision. It tolerated the narrow table only because it stops
    reading once it has what it needs.
    """
    table = (
        _datatype_table_12c()
        if field_version >= FIELD_VERSION_12_1
        else _SERVER_DTY_TABLE
    )
    return bytes([TTI_DTY]) + table


def build_ano_null_reply() -> bytes:
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


def build_oci_dty_reply(*, tz_file_version: bool = True) -> bytes:
    """The deadbeef dialect's third-round type reply payload (#265, #565).

    A DTY (data-type negotiation) reply carrying the server's DB session time zone
    and its timezone-file version (§4.2): the ``TTI_DTY`` message code, an 11-byte
    time-zone block (its h/m/s offset fields at bytes 4..6, each biased by +60),
    then the timezone-file version as a big-endian ub4.

    The ub4 goes only to a client whose own request carried one
    (:func:`client_sends_tz_file_version`): sqlplus 10.2 sends none and answers
    one with a break, and 10g and 11g both leave it out for that client (#1764).
    """
    (Hours, Minutes, Seconds) = _DB_TZ_HMS
    tz_block = (
        _DB_TZ_FRAME_PAD
        + bytes([Hours + _DTY_TZ_BIAS, Minutes + _DTY_TZ_BIAS, Seconds + _DTY_TZ_BIAS])
        + _DB_TZ_FRAME_PAD
    )
    reply = bytes([TTI_DTY]) + tz_block
    if tz_file_version:
        reply += struct.pack('>I', _TZFILE_VERSION)
    return reply


def is_ano_negotiation(pro_body: bytes) -> bool:
    """Whether a post-ACCEPT packet is a modern thin client's ANO negotiation
    (vs a TTI_PRO or the sqlplus/OCI ANO, both handled by other paths)."""
    return pro_body[:4] == ano.ANO_MAGIC_BYTES and pro_body[6:10] == ano.VERSION_BYTES


def encode_ano_null_reply(*, sdu: int = DEFAULT_SDU) -> bytes:
    """Build the null-algorithm ANO negotiation reply — §ANO (#437).

    Replays the real 11g server's response to a modern client's ANO request:
    every service selects the null algorithm, so no cipher/MAC is activated and
    the session stays plaintext. sqlplus / thick OCI opens with an ANO round too,
    and gets these same bytes as its first reply (§4.1.1).
    """
    packet, _ = encode_packet(TNS_DATA, build_ano_null_reply(), sdu)
    return packet


def encode_fast_auth_reply(
    challenge: bytes, *, field_version: int, txn_priority: bool = False
) -> bytes:
    """The bundled reply a client\'s 23ai FAST_AUTH packet expects (§20): the PRO
    reply payload, the DTY reply payload, and the OSESSKEY auth challenge, in one
    ``DATA`` body. The client scans it for the challenge RPA
    (:func:`find_fast_auth_rpa`) and finishes O5LOGON exactly as the legacy
    three-message handshake does. ``challenge`` is :func:`encode_challenge`\'s RPA
    payload; the caller frames the whole thing with ``write_packet``.
    """
    return (
        build_caps_block_reply(field_version, txn_priority=txn_priority)
        + build_dty_type_reply(field_version)
        + challenge
    )


def encode_pro_reply(
    *,
    oci: bool = False,
    sdu: int = DEFAULT_SDU,
    field_version: int = FIELD_VERSION_11_2,
    txn_priority: bool = False,
) -> bytes:
    """Build the server's PRO (protocol negotiation) reply — §4.1.

    The ``TTI_PRO`` reply both kinds of client get, 238 bytes against an 11g
    capture: its capability array pins the negotiated field version. ``oci``
    builds sqlplus / thick OCI's form of the same block. Returns the full
    TNS_DATA packet.
    """
    payload = build_caps_block_reply(field_version, txn_priority=txn_priority, oci=oci)
    packet, _ = encode_packet(TNS_DATA, payload, sdu)
    return packet


def encode_dty_reply(
    *,
    sdu: int = DEFAULT_SDU,
    field_version: int = FIELD_VERSION_11_2,
) -> bytes:
    """Build the server's DTY (data-type negotiation) reply to a thin client —
    §4.2: the type-conversion table, 924 bytes against an 11g capture. sqlplus /
    thick OCI asks without a table and gets :func:`encode_oci_dty_reply`.
    Returns the full TNS_DATA packet.
    """
    packet, _ = encode_packet(TNS_DATA, build_dty_type_reply(field_version), sdu)
    return packet


def encode_oci_dty_reply(
    *, sdu: int = DEFAULT_SDU, tz_file_version: bool = True
) -> bytes:
    """Build sqlplus / thick OCI's data-type reply (§4.2.1) — the 26-byte
    ``ttc=02`` answer to its data-type round, its third after ANO and PRO and
    before OSESSKEY (#265); 22 bytes without the timezone-file version (#1764).
    Full TNS_DATA packet.
    """
    payload = build_oci_dty_reply(tz_file_version=tz_file_version)
    packet, _ = encode_packet(TNS_DATA, payload, sdu)
    return packet


# What follows the capabilities in sqlplus's type request: the 11-byte time-zone
# block, then a ub4 timezone-file version from 11.2 on, then the national
# charset as a little-endian ub2.
_TYPE_REQUEST_TZ_BLOCK = 11
_TYPE_REQUEST_NCHARSET = 2


def client_sends_tz_file_version(type_request: bytes) -> bool:
    """Whether sqlplus's type request (the ``ttc=02`` round) carries a
    timezone-file version, which says whether the reply should (#1764).

    Behind the compile and runtime capabilities sqlplus 11.2 sends the time-zone
    block, a ub4 timezone-file version and the national charset (17 bytes);
    sqlplus 10.2 sends the block and the charset only (13). A request that cannot
    be read keeps the 11.2 form, which every client the Mirror served before
    received.
    """
    try:
        if not type_request or type_request[0] != TTI_DTY:
            return True
        at = 6
        at += 1 + type_request[at]  # compile capabilities
        at += 1 + type_request[at]  # runtime capabilities
    except IndexError:
        return True
    rest = len(type_request) - at
    return rest != _TYPE_REQUEST_TZ_BLOCK + _TYPE_REQUEST_NCHARSET


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
    version = client_compile_cap(dty_body, CCAP_FIELD_VERSION)
    return version or None


def client_compile_cap(dty_body: bytes, index: int) -> int | None:
    """One slot of the compile capabilities a client sent in its DTY, or ``None``
    when the block cannot be read (see :func:`client_field_version`)."""
    try:
        if not dty_body or dty_body[0] != TTI_DTY:
            return None
        caps_len = dty_body[6]
        caps = dty_body[7 : 7 + caps_len]
        if len(caps) <= index:
            return None
        return caps[index]
    except IndexError:
        return None


# The bytes between a fast-auth bundle's PRO message and its DTY: the charset,
# a flag and the ncharset (five), then a version byte that is always 19.1 EXT 1
# whatever the client speaks, so it says nothing about the session.
_FAST_AUTH_DTY_GAP = 6


def fast_auth_field_version(bundle: bytes) -> int | None:
    """The TTC field version a 23ai fast-auth client settled on, read from the
    DTY inside its bundle: the FAST_AUTH header, the PRO message (its version
    list and its banner, each NUL-terminated), six bytes, then the DTY, whose
    capability block names the client's real version (§20). ``None`` when the
    bundle can't be read, as for :func:`client_field_version`.

    Without it a client at field version 18 to 23 -- all of which log in this
    way -- was served at the version the Mirror presents."""
    if len(bundle) < 5 or bundle[0] != TNS_MSG_TYPE_FAST_AUTH or bundle[4] != TTI_PRO:
        return None
    versions_end = bundle.find(b'\x00', 5)
    banner_end = bundle.find(b'\x00', versions_end + 1) if versions_end >= 0 else -1
    if banner_end < 0:
        return None
    return client_field_version(bundle[banner_end + 1 + _FAST_AUTH_DTY_GAP :])
