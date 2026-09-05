# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import base64
import datetime
import platform
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from seerdb.common.ano_session import AnoChannel
    from seerdb.common.dbobject import DbObject, DbRef
from functools import reduce

from seerdb.common import oci
from seerdb.common.crypto import encrypt_password, o5logon, server_proof
from seerdb.common.datatypes import (
    JSON,
    BinaryDouble,
    BinaryFloat,
    IntervalYM,
    RefCursorBind,
    TempLob,
    Var,
)
from seerdb.common.date import date
from seerdb.common.exceptions import DataError, InterfaceError
from seerdb.common.sqltext import is_plsql, returning_bind_positions
from seerdb.common.vector import (
    VECTOR_BIND_DESCRIPTOR,
    SparseVector,
    decode_vector,
    encode_vector,
    is_vector_bind,
)


def _json_bind_text(Token: object) -> str:
    # A dict (auto-detected) or a JSON() wrapper binds into a native JSON column
    # (#50): serialise to JSON text and bind it as a string; the server casts
    # VARCHAR -> JSON. Lazy import keeps oson off the tns import chain.
    from seerdb.common.oson import json_to_text

    return json_to_text(Token.value if isinstance(Token, JSON) else Token)


# A VECTOR element format code (== the value image's element type) mapped to the
# array typecode encode_vector reads it back from: FLOAT32/FLOAT64/INT8/BINARY.
_VEC_FORMAT_TYPECODE = {2: 'f', 3: 'd', 4: 'b', 5: 'B'}


def _vector_as(value: object, vector_format: int | None) -> object:
    # Wrap a decoded dense vector as the array.array typecode for `vector_format`
    # so encode_vector reproduces that element type (a plain list would default to
    # FLOAT32, losing INT8 / BINARY typing and FLOAT64 precision). A SparseVector
    # is self-typed and an unknown format falls through to the FLOAT32 default.
    import array

    if vector_format is None or isinstance(value, SparseVector) or value is None:
        return value
    typecode = _VEC_FORMAT_TYPECODE.get(vector_format)
    if typecode is None:
        return value
    return array.array(typecode, cast('Any', value))


def _native_lob_bind_value(image: bytes) -> bytes:
    # Native inline bind value for a LOB-backed type (VECTOR #62, JSON #70): a
    # fixed descriptor, the image length (ub2), 22 zero bytes, then the image
    # framed like RAW (encode_chr).
    return (
        VECTOR_BIND_DESCRIPTOR
        + len(image).to_bytes(2, 'big')
        + b'\x00' * 22
        + encode_chr(image)
    )


def _json_oson_image(Token: object):
    # The OSON image for a dict / JSON() bind (#70), or None when the value is
    # too large/complex for the native encoder so the caller falls back to the
    # text cast (#50/#64) — which the server parses just as well.
    from seerdb.common.oson import OsonError, encode_oson

    value = Token.value if isinstance(Token, JSON) else Token
    try:
        return encode_oson(value)
    except OsonError:
        return None


import contextvars
import logging
import math
import os
import re
import socket
import struct

from seerdb.common.tns_consts import (
    AL16UTF16_CHARSET,
    AL32UTF8_CHARSET,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_SID,
    FIELD_VERSION_9_2,
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_12_2,
    FIELD_VERSION_12_2_EXT1,
    FIELD_VERSION_19_1_EXT1,
    FIELD_VERSION_20_1,
    FIELD_VERSION_21_1,
    FIELD_VERSION_23_1,
    ISO_LATIN_1_CHARSET,
    TNS_AL8I4_ARRAY_DML_ROWCOUNTS,
    TNS_AQ_ARRAY_ENQ,
    TNS_AQ_ARRAY_FLAGS_RETURN_MESSAGE_ID,
    TNS_AQ_EXT_KEYWORD_AGENT_ADDRESS,
    TNS_AQ_EXT_KEYWORD_AGENT_NAME,
    TNS_AQ_EXT_KEYWORD_AGENT_PROTOCOL,
    TNS_AQ_EXT_KEYWORD_ORIGINAL_MSGID,
    TNS_AQ_MESSAGE_ID_LENGTH,
    TNS_AQ_MESSAGE_VERSION,
    TNS_AQ_MSG_BUFFERED,
    TNS_AQ_MSG_PERSISTENT_OR_BUFFERED,
    TNS_BIND_DIR_INPUT,
    TNS_CCAP_END_OF_RESPONSE,
    TNS_DATA,
    TNS_DATA_FLAGS_MORE,
    TNS_END_TO_END_ACTION,
    TNS_END_TO_END_CLIENT_IDENTIFIER,
    TNS_END_TO_END_CLIENT_INFO,
    TNS_END_TO_END_DBOP,
    TNS_END_TO_END_MODULE,
    TNS_ESCAPE_CHAR,
    TNS_EXEC_FLAGS_NO_CANCEL_ON_EOF,
    TNS_EXEC_FLAGS_SCROLLABLE,
    TNS_EXEC_OPTION_BATCH_ERRORS,
    TNS_EXEC_OPTION_EXECUTE,
    TNS_FUNC_AQ_DEQ,
    TNS_FUNC_AQ_ENQ,
    TNS_FUNC_ARRAY_AQ,
    TNS_FUNC_END_USER_SECURITY_CTX,
    TNS_FUNC_PIPELINE_BEGIN,
    TNS_FUNC_PIPELINE_END,
    TNS_FUNC_SESSION_STATE,
    TNS_FUNC_SET_END_TO_END_ATTR,
    TNS_FUNC_TPC_TXN_CHANGE_STATE,
    TNS_FUNC_TPC_TXN_SWITCH,
    TNS_KPD_AQ_BUFMSG,
    TNS_KPD_AQ_EITHER,
    TNS_LOB_OP_FILE_CLOSE,
    TNS_LOB_OP_FILE_OPEN,
    TNS_LOB_OP_GET_LENGTH,
    TNS_LOB_OP_READ,
    TNS_LOB_OP_WRITE,
    TNS_MSG_TYPE_FAST_AUTH,
    TNS_REDIRECT,
    TNS_SECURITY_CONTEXT_ATTACH_FLAG,
    TNS_SERVER_CONVERTS_CHARS,
    TNS_SERVER_PIGGYBACK_LTXID,
    TNS_SERVER_PIGGYBACK_OS_PID_MTS,
    TNS_SERVER_PIGGYBACK_QUERY_CACHE_INVALIDATION,
    TNS_SERVER_PIGGYBACK_SESS_RET,
    TNS_SERVER_PIGGYBACK_SYNC,
    TNS_SERVER_PIGGYBACK_TRACE_EVENT,
    TNS_SESSION_STATE_EXPLICIT_BOUNDARY,
    TNS_TYPE_ADT,
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFILE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_BLOB,
    TNS_TYPE_BOOLEAN,
    TNS_TYPE_CHAR,
    TNS_TYPE_CLOB,
    TNS_TYPE_DATE,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_JSON,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_REF,
    TNS_TYPE_REFCURSOR,
    TNS_TYPE_RID,
    TNS_TYPE_ROWID,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_UROWID,
    TNS_TYPE_VARCHAR,
    TNS_TYPE_VECTOR,
    TTI_3LOGA,
    TTI_3LOGON,
    TTI_ALL7,
    TTI_ALL8,
    TTI_AUTH,
    TTI_BVC,
    TTI_DCB,
    TTI_DTY,
    TTI_END_OF_RESPONSE,
    TTI_FETCH,
    TTI_FOB,
    TTI_FUN,
    TTI_IOV,
    TTI_IRD,
    TTI_LOB,
    TTI_LOBOPS,
    TTI_LOGOFF,
    TTI_MSG_TYPE_PIGGYBACK,
    TTI_OAC,
    TTI_OCCA,
    TTI_OER,
    TTI_PFN,
    TTI_PRO,
    TTI_RPA,
    TTI_RXD,
    TTI_RXH,
    TTI_SESS,
    TTI_SPFP,
    TTI_STA,
    TTI_STOP,
    TTI_STRT,
    TTI_SVR_PIGGYBACK,
    TTI_TOKEN,
    TTI_UDS,
    TTI_WRN,
    UTF8_CHARSET,
    CharsetDict,
    DictionaryType,
)

logger = logging.getLogger(__name__)


# --- The Mirror's wire request/reply data model (parsed requests + describe
# metadata the codec passes around). Moved here so common holds the codec's
# data types alongside its encode/decode functions. ---


# AL32UTF8 (AL32UTF8_CHARSET) — what seerdb advertises and what an 11g DUAL
# column reports. _CSFRM_DB is the database charset form (not the national one).
_CSFRM_DB = 1
_CSFRM_NCHAR = 2  # national charset form (NCHAR / NVARCHAR2 -> AL16UTF16 / UTF-16BE)


@dataclass(frozen=True)
class ColumnMeta:
    """One result column's metadata for the describe (11g scalar column)."""

    name: bytes
    data_type: int
    data_length: int
    max_size: int
    charset: int = AL32UTF8_CHARSET
    csfrm: int = _CSFRM_DB
    precision: int = 0
    scale: int = 0
    null_ok: int = 1
    # Object-type identity for an ADT / REF column (#119/#494): the referenced
    # type's 16-byte OID, owner schema, and name — carried in the describe so the
    # client can label a REF (``ref.type_name``) and lay out an object.
    type_oid: bytes = b''
    type_schema: bytes = b''
    type_name: bytes = b''
    # A native VECTOR column's element format (2 FLOAT32, 3 FLOAT64, 4 INT8,
    # 5 BINARY), so the Mirror re-encodes its value image with the right element
    # type. None when unknown (a non-VECTOR column, or an upstream that does not
    # report it) — the encoder then falls back to FLOAT32 (#55).
    vector_format: int | None = None


@dataclass(frozen=True)
class ExecRequest:
    """A parsed execute: the SQL text, its options, and any bind values."""

    sql: str
    cursor: int
    bind_count: int
    fetch: int
    binds: list = field(default_factory=list)
    # One entry per array-DML (executemany) iteration; a plain execute has a
    # single row equal to ``binds`` (empty for a statement with no binds).
    bind_rows: list = field(default_factory=list)
    # Per-bind (tns_type, max_size) from the OACs, in bind order — the type +
    # return-buffer size a PL/SQL block's OUT binds need (#483).
    bind_meta: list = field(default_factory=list)
    # Per-bind (tns_type, csfrm, max_size) — the bind format the Mirror remembers
    # for a cursor so a cached re-execute (no OACs on the wire) can decode its RXD
    # values (#80/#486).
    bind_types: list = field(default_factory=list)
    autocommit: bool = False
    # Array-DML batcherrors mode (#18): apply the good rows and collect per-row
    # failures rather than aborting the whole executemany.
    batcherrors: bool = False
    # Server-side scrollable cursor (#181/#485): the SCROLLABLE exec flag on the
    # opening execute, and the fetch orientation + 1-based position a scroll
    # re-execute carries in al8i4[10]/al8i4[11]. Zero orientation means "no
    # scroll" (a plain execute).
    scrollable: bool = False
    scroll_orientation: int = 0
    scroll_position: int = 0
    # Array-DML per-iteration row counts requested (al8i4[9] & 0xC000, #18).
    arraydmlrowcounts: bool = False
    # Positions of the binds a `RETURNING ... INTO` clause fills (#689). They are
    # described like any other bind but carry no value in the row data, and the
    # reply owes one set of values per iteration.
    return_binds: frozenset = frozenset()


@dataclass(frozen=True)
class TempLobRef:
    """A bind that arrived as a temp-LOB locator, not an inline value (#412).

    A programmatic client that wrote a large LOB over ``TTI_LOBOPS`` binds the
    minted locator instead of the bytes. The session resolves ``locator`` to the
    content accumulated by the WRITE calls before handing it to the backend."""

    locator: bytes
    is_blob: bool


@dataclass(frozen=True)
class LobOpsRequest:
    """A parsed TTI_LOBOPS request: which op, and the fields it carries (#412)."""

    kind: str  # 'create_temp' | 'write' | 'read'
    is_blob: bool = False
    locator: bytes = b''
    payload: bytes = b''


@dataclass(frozen=True)
class ScalarOutBind:
    """A scalar PL/SQL OUT bind value + its declared type, for the IOV reply."""

    value: object
    tns_type: int


@dataclass(frozen=True)
class RefCursorOutBind:
    """A REF CURSOR OUT bind: the nested result's columns and the cursor id the
    Mirror parked its rows on. The client drains that id with ``TTI_FETCH``."""

    columns: list[ColumnMeta]
    cursor_id: int


@dataclass(frozen=True)
class FetchRequest:
    """A parsed ``TTI_FETCH``: which cursor, and how many rows to return."""

    cursor: int
    fetch: int


# The TTC field version negotiated for the connection whose response we are
# currently decoding. Set by `decode_packet` at the top of each response and
# read by the version-gated token decoders (e.g. the 12c+ DCB column format).
# A ContextVar (not a parameter threaded through every decoder, nor a plain
# global) so concurrent async connections / sync threads each see their own
# value. Default 6 == FIELD_VERSION_11_2 (defined later); decoders only diverge
# from the 11g layout when this is >= a 12c+ field version.
_DECODE_FIELD_VERSION = contextvars.ContextVar('decode_field_version', default=6)

# Same idea for the *encode* side: the field version of the message currently
# being built, set by encode_dictionary_exec and read by encode_token_raw to
# pick the 11g vs 12c+ bind-OAC layout. Separate from the decode var so the two
# phases never interfere. Default 6 == FIELD_VERSION_11_2.
_ENCODE_FIELD_VERSION = contextvars.ContextVar('encode_field_version', default=6)

# Set True for the duration of an execute that requested array-DML row counts
# (oracledb arraydmlrowcounts, #18). It tells decode_token_rpa_piggyback to
# expect the `ub4 count | count×ub4` row-count block the server appends to the
# RPA region ahead of the trailing OER — absent the flag the RPA is just walked
# and discarded as before. The connection sets it per execute.
_DECODE_DML_ROWCOUNTS = contextvars.ContextVar('decode_dml_rowcounts', default=False)


def set_decode_dml_rowcounts(Flag: bool) -> None:
    """Arm/disarm row-count extraction for the next response decode (#18).

    The connection calls this before reading an execute's response so
    decode_token_rpa_piggyback knows whether to expect the array-DML row-count
    block. Reset every execute so a stale flag never leaks into another call."""
    _DECODE_DML_ROWCOUNTS.set(bool(Flag))


# DML RETURNING ... INTO (#120): the sorted return-bind positions for the next
# response, so the TTI_RXD decoder reads the out-bind return data (per bind:
# ub4 num_rows + per row a value + sb4 truncation length) instead of treating
# the RXD as query rows. Reset every execute.
_DECODE_RETURN_BINDS = contextvars.ContextVar('decode_return_binds', default=())


def set_decode_return_binds(Positions) -> None:
    """Arm return-bind decoding for the next response (#120). `Positions` is the
    set/list of 0-based OUT-bind positions, or empty/None to disarm."""
    _DECODE_RETURN_BINDS.set(tuple(sorted(Positions)) if Positions else ())


# The last row of the previous fetch, seeded for a scroll re-execute (#181). When
# a scroll repositions onto a row whose column values equal the last row already
# returned, the server omits those values and flags them in the row-header bit
# vector as "reuse previous". Duplicate detection is per-response in the decoder
# (Rows starts empty each call), so the cursor seeds this with the prior batch's
# last row; decode_token_rxd falls back to it for a reused column when no
# in-response previous row exists. Empty/None disarms (the default).
_DECODE_PREV_ROW: contextvars.ContextVar[list | None] = contextvars.ContextVar(
    'decode_prev_row', default=None
)


def set_decode_prev_row(Row) -> None:
    """Seed the previous-fetch row for the next scroll re-execute decode (#181),
    or pass None to disarm."""
    _DECODE_PREV_ROW.set(list(Row) if Row else None)


def assemble_packet(
    Data: bytes, Length: int, Large: bool = False
) -> tuple[bool, int | None, bytes | None, bytes | None]:
    # Two on-wire packet-header layouts share an 8-byte size and put the type at
    # byte 4. Legacy: len(ub2) + checksum(ub2) + type + flags + hdr-cksum(ub2).
    # Large-SDU (#155, negotiated at protocol version >= 315): len(ub4) + type +
    # flags + hdr-cksum(ub2) — the 4-byte length replaces the legacy len+cksum.
    # `Zero` (the hdr-cksum at bytes 6-7) is read the same way in both.
    if Large:
        (PacketSize, Type, Flags, Zero) = struct.unpack('>IBBh', Data[:8])
    else:
        (PacketSize, _, Type, Flags, Zero) = struct.unpack('>HhBBh', Data[:8])
    if Type == TNS_DATA and Zero == 0:
        BodySize = PacketSize - 10
        Rest = Data[10:]
        if BodySize <= len(Rest):
            if (PacketSize == Length - 37) or (PacketSize == Length - 81):
                return (False, None, Rest[:BodySize], Rest[BodySize:])
            else:
                return (True, TNS_DATA, Rest[:BodySize], Rest[BodySize:])
        else:
            return (False, None, None, None)
    elif Type == TNS_REDIRECT and Zero == 0:
        # The server is handing us a new address to reconnect to (shared
        # server / RAC / some listener configs). The body is the connect
        # descriptor — ASCII, carrying an (ADDRESS=...(HOST=..)(PORT=..)).
        # Return it raw (everything after the 8-byte header); handle_login
        # parses the address out. A leading 2-byte data-length some servers
        # insert is simply skipped over by the descriptor regex.
        if PacketSize <= len(Data):
            return (True, TNS_REDIRECT, Data[8:PacketSize], Data[PacketSize:])
        return (False, None, None, None)
    elif Zero == 0:
        BodySize = PacketSize - 8
        Rest = Data[8:]
        if BodySize <= len(Rest):
            return (True, Type, Rest[:BodySize], Rest[BodySize:])
        else:
            return (False, None, None, None)
    else:
        raise Exception('Cannot decode packet', Data, Length)


_REDIRECT_HOST_RE = re.compile(rb'\(HOST\s*=\s*([^)\s]+)\s*\)', re.IGNORECASE)
_REDIRECT_PORT_RE = re.compile(rb'\(PORT\s*=\s*(\d+)\s*\)', re.IGNORECASE)


def parse_redirect_address(Body: bytes) -> tuple[str | None, int | None]:
    # Pull the (HOST=..)(PORT=..) out of a TNS_REDIRECT body's connect
    # descriptor. The descriptor carries the server ADDRESS to reconnect to,
    # and may also carry the original CONNECT_DATA (whose CID has the *client*
    # HOST) after a NUL — so scope the search to the ADDRESS block, where the
    # real target lives, and only fall back to a bare first match if there is
    # no ADDRESS keyword.
    Region = Body
    Marker = re.search(rb'\(ADDRESS\b', Body, re.IGNORECASE)
    if Marker:
        Region = Body[Marker.start() :]
    Host = _REDIRECT_HOST_RE.search(Region)
    Port = _REDIRECT_PORT_RE.search(Region)
    if Host and Port:
        return (Host.group(1).decode('ascii', 'replace'), int(Port.group(1)))
    return (None, None)


# What the decoder yields for a bare TTI_FOB response (docs/PROTOCOL.md 6.9).
# The server sends one -- a packet holding nothing but the token -- when a
# statement with a RETURNING clause fails, and then waits: the real error only
# follows once the client has echoed the token back. It is a request, not a
# result, so a caller that reads it must answer it rather than hand it on (#697).
FLUSH_OUT_BINDS = (False, 'fob')
# How many of those to answer before giving up. One is what a real server asks
# for; the cap is only so a server that never stops asking ends the call instead
# of spinning on it forever.
MAX_FLUSH_OUT_BINDS = 4


def decode_packet(Data: bytes, Acc: tuple, FieldVersion: int | None = None) -> tuple:
    # FieldVersion is passed only by the top-level caller (the connection's
    # response handler); recursive token decoders omit it and inherit the value
    # via the ContextVar set here.
    if FieldVersion is not None:
        _DECODE_FIELD_VERSION.set(FieldVersion)
    # RXD (row data) and BVC (its bit vector) are the only tokens that repeat
    # proportional to the row count. Loop over them here instead of recursing per
    # row, so a large fetch batch cannot overflow Python's recursion limit (a
    # batch of a few hundred rows used to raise RecursionError). Every other token
    # appears O(1) times per response and dispatches (and may recurse) below with
    # bounded depth.
    while True:
        Token = Data[0]
        if Token == TTI_RXD:
            (Data, Acc) = _decode_rxd_step(Data, Acc)
        elif Token == TTI_BVC:
            (Data, Acc) = _decode_bvc_step(Data, Acc)
        else:
            break
    logger.debug('Token %s', Token)
    match Token:
        case t if t == TTI_DCB:
            return decode_token_dcb(Data, Acc)
        case t if t == TTI_FOB:
            return FLUSH_OUT_BINDS
        case t if t == TTI_IOV:
            return decode_token_iov(Data, Acc)
        case t if t == TTI_IRD:
            return decode_token_implicit(Data, Acc)
        case t if t == TTI_LOB:
            return decode_token_lob(Data, Acc)
        case t if t == TTI_OAC:
            return decode_token_oac(Data, Acc)
        case t if t == TTI_OER:
            return decode_token_oer(Data, Acc)
        case t if t == TTI_RXH:
            return decode_token_rxh(Data, Acc)
        case t if t == TTI_RPA:
            # In auth flow, RPA is decoded directly via _handle_rpa (which strips
            # the token byte first). The only caller of decode_packet is the SQL
            # response handler, where RPA is a server-side session-state
            # piggyback that precedes the trailing OER — skip it and continue.
            return decode_token_rpa_piggyback(Data, Acc)
        case t if t == TTI_SVR_PIGGYBACK:
            return decode_token_server_piggyback(Data, Acc)
        case t if t == TTI_STA:  # tran
            return (True, Acc)
        case t if t == TTI_END_OF_RESPONSE:
            # End-of-response marker (#155/#132): on an EOR-negotiated 23ai
            # connection the server terminates each response with this token.
            # A single (non-pipelined) call already ends on its STATUS/OER
            # terminal, so this is normally the trailing byte in the same
            # packet; handle it explicitly so it is never an "unknown type".
            return (True, Acc)
        case t if t == TTI_TOKEN:
            # Pipeline response-correlation marker (#158): a ub8 token number
            # tagging which pipelined op this response belongs to. The pipelined
            # responses arrive in op order, so consume the token and continue
            # decoding the op's response body (which ends on its own EOR).
            (_, Rest) = decode_ub4(Data[1:])
            return decode_packet(Rest, Acc)
        case t if t == TTI_UDS:
            return decode_token_uds(Data, Acc)
        case t if t == TTI_WRN:
            return decode_token_wrn(Data, Acc)
    # No case matched — raise here rather than via `case _` so every branch is a
    # value-return, matching encode_dictionary below and keeping CodeQL's flow
    # analysis happy (the `case _` wildcard reads as an implicit fall-through).
    raise Exception("Can't decode unknown type", Token, Data, Acc)


def _decode_bvc_step(Data: bytes, Acc: tuple) -> tuple:
    # Bit vector identifying columns whose value is REPEATED from the previous
    # row (so the following RXD only carries the columns whose bits are set).
    # NumColumnsSent is variable ub2; bit vector size is derived from the
    # cursor's total column count. Stash the bytes onto Acc so the next RXD
    # can consult them. Returns the ``(Rest, NewAcc)`` continuation decode_packet
    # loops on (BVC precedes an RXD, so it is a per-row token too).
    (Cursor, RowFormat, Rows, *_) = Acc
    Rest = Data[1:]
    (_, Rest) = decode_ub4(Rest)
    NumCols = len(RowFormat) if isinstance(RowFormat, list) else 0
    VecLen = (NumCols + 7) // 8
    BitVec = bytes(Rest[:VecLen])
    Rest = Rest[VecLen:]
    return (Rest, (Cursor, RowFormat, Rows, BitVec))


def decode_token_bvc(Data: bytes, Acc: tuple) -> tuple:
    # Consume a BVC and continue decoding — the full decode a direct caller
    # expects. decode_packet itself loops over the per-row step.
    (Rest, NewAcc) = _decode_bvc_step(Data, Acc)
    return decode_packet(Rest, NewAcc)


def _skip_chunked_bytes(Data: bytes) -> bytes:
    # Mirrors oracledb's skip_bytes: 1-byte length, then either that many raw
    # bytes (length < 254), nothing (length == 255 NULL marker), or a chunked
    # sequence of ub4-prefixed segments terminated by a zero-length segment
    # (length == 254 LONG marker).
    Length = Data[0]
    if Length == 254:
        Rest = Data[1:]
        while True:
            (ChunkLen, Rest) = decode_ub4(Rest)
            if ChunkLen == 0:
                return Rest
            Rest = Rest[ChunkLen:]
    elif Length == 255:
        return Data[1:]
    else:
        return Data[1 + Length :]


def _read_chunked_bytes(Data: bytes) -> tuple[bytes, bytes]:
    # The value form _skip_chunked_bytes skips, but returning the bytes: a
    # 1-byte length then that many raw bytes (length < 254), nothing (255 NULL),
    # or a chunked ub4-prefixed sequence terminated by a zero-length chunk (254).
    Length = Data[0]
    if Length == 254:
        Rest = Data[1:]
        Out = b''
        while True:
            (ChunkLen, Rest) = decode_ub4(Rest)
            if ChunkLen == 0:
                return (Out, Rest)
            Out += bytes(Rest[:ChunkLen])
            Rest = Rest[ChunkLen:]
    elif Length == 255:
        return (b'', Data[1:])
    else:
        return (bytes(Data[1 : 1 + Length]), Data[1 + Length :])


def _skip_bytes_with_length(Data: bytes) -> bytes:
    (NumBytes, Rest) = decode_ub4(Data)
    if NumBytes > 0:
        Rest = _skip_chunked_bytes(Rest)
    return Rest


# The longest value a single length byte may announce. The three bytes above it
# are markers, not lengths: 253 (0xFD) is the TTC escape byte, 254 (0xFE) opens
# a chunked value and 255 (0xFF) is NULL. A 253-byte value sent with a plain
# length byte is therefore an escape where the server expects a length, and a
# 12c+ server rejects the whole call with ORA-03125 (#707). Same limit as
# python-oracledb's TNS_MAX_SHORT_LENGTH.
_MAX_SHORT_LENGTH = 252


def _bytes_with_length(Data: bytes) -> bytes:
    # Inverse of `_skip_chunked_bytes` (oracledb write_bytes_with_length): a
    # 1-byte length + data for short values (<= 252 bytes), or the 254 LONG
    # marker followed by ub4-prefixed chunks terminated by a zero-length chunk.
    if len(Data) <= _MAX_SHORT_LENGTH:
        return bytes([len(Data)]) + Data
    Out = bytearray([254])
    for I in range(0, len(Data), 0x40):
        Chunk = Data[I : I + 0x40]
        Out += encode_sb4(len(Chunk)) + Chunk
    Out += encode_sb4(0)
    return bytes(Out)


def _read_str_with_length(Data: bytes) -> tuple[bytes, bytes]:
    (NumBytes, Rest) = decode_ub4(Data)
    if NumBytes > 0:
        # A length-prefixed string is never chunked, so the DALC value is bytes
        # (never the list form).
        return cast('tuple[bytes, bytes]', decode_dalc(Rest))
    return (b'', Rest)


def decode_token_dcb(Data: bytes, Acc: tuple) -> tuple:
    # Describe Information block. Layout reverse-engineered against Oracle 11g
    # XE, cross-referenced with python-oracledb's _process_describe_info.
    #
    #   1B   token (TTI_DCB)
    #   ...  describe-info preamble (chunked DALC: cursor uuid + timestamp)
    #   ub4  max row size                              (skip)
    #   ub4  num_columns
    #   1B   reserved (only present when num_columns > 0)
    #   per column (see _decode_dcb_column)
    #   bytes_with_length  current date                (skip)
    #   ub4  dcbflag                                   (skip)
    #   ub4  dcbmdbz                                   (skip)
    #   ub4  dcbmnpr                                   (skip)
    #   ub4  dcbmxpr                                   (skip)
    #   bytes_with_length  dcbqcky                     (skip)
    (Cursor, _, Rows) = Acc[:3]
    Rest = Data[1:]
    Rest = _skip_chunked_bytes(Rest)
    (Columns, Rest) = _decode_describe_body(Rest)
    return decode_packet(Rest, (Cursor, Columns, Rows))


def decode_token_implicit(Data: bytes, Acc: tuple) -> tuple:
    # Implicit result sets (#121, DBMS_SQL.RETURN_RESULT). Layout (oracledb
    # base.pyx _process_implicit_result):
    #   ub4  num_results
    #   per result:  ub1 len + that many bytes (skip)
    #                describe body (column metadata, _decode_describe_body)
    #                ub2 cursor id
    # Each result is a server cursor (id + row format), fetched on demand like a
    # REF CURSOR. We surface them as a record the cursor turns into nextset()
    # result sets, then continue decoding the block's trailing RPA/OER.
    (Cursor, RowFormat, Rows, *_) = Acc
    Rest = Data[1:]
    (NumResults, Rest) = decode_ub4(Rest)
    Results = []
    for _ in range(NumResults):
        PreLen = Rest[0]
        Rest = Rest[1 + PreLen :]
        (Columns, Rest) = _decode_describe_body(Rest)
        (CursorId, Rest) = decode_ub4(Rest)  # ub2 cursor id
        Results.append({'cursor_id': CursorId, 'row_format': Columns})
    Record = {'implicit_results': Results}
    return decode_packet(Rest, (Cursor, RowFormat, Rows + [Record]))


def _decode_describe_body(Rest: bytes) -> tuple[list, bytes]:
    # The describe-info body shared by the TTI_DCB token and the implicit-result
    # describe (#121): max row size, column count, a reserved byte, the
    # per-column metadata, then the describe trailer. The token-specific
    # preamble (DCB's chunked uuid/timestamp, or the implicit-result ub1 block)
    # is consumed by the caller before this point.
    (_, Rest) = decode_ub4(Rest)  # max row size
    (NumCols, Rest) = decode_ub4(Rest)
    if NumCols > 0:
        Rest = Rest[1:]  # reserved
    Columns = []
    for _ in range(NumCols):
        (Col, Rest) = _decode_dcb_column(Rest)
        Columns.append(Col)
    Rest = _skip_bytes_with_length(Rest)  # current date
    for _ in range(4):
        (_, Rest) = decode_ub4(Rest)  # dcbflag/dcbmdbz/dcbmnpr/dcbmxpr
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_11_2:
        # dcbqcky (query-cache key) is an 11g addition (the result cache landed
        # in 11g); 10g's describe ends after the four ub4 flags, so skipping a
        # phantom bytes-with-length here would consume the first row token (#84).
        Rest = _skip_bytes_with_length(Rest)
    return (Columns, Rest)


def _decode_dcb_column(Rest: bytes) -> tuple[dict, bytes]:
    # Per-column metadata. 12c+ (field version >= 12.2) differs from 11g in two
    # ways (oracledb base.pyx _process_metadata): scale is a raw signed byte
    # (sb1), and an extra ub4 `oaccolid` follows max_size. 11g keeps an
    # sb4-style variable scale (so NUMBER's -127 default arrives as 0x81 0x7f)
    # and has no oaccolid. precision is sb1 in both.
    Is12c = _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_2
    DataType = Rest[0]
    Precision = Rest[2]  # sb1
    Rest = Rest[3:]
    if Is12c:
        DataScale = Rest[0] - 256 if Rest[0] > 127 else Rest[0]  # sb1
        Rest = Rest[1:]
    else:
        (DataScale, Rest) = decode_ub4(Rest)
    (BufferSize, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)  # max_array_elems
    (_, Rest) = decode_ub4(Rest)  # cont_flags (ub8 on 12c; small)
    (OidLen, Rest) = decode_ub4(Rest)
    TypeOid = b''
    if OidLen > 0:
        # For an object (ADT, type 109) / collection column this is the type's
        # 16-byte OID; capturing it (rather than skipping) lets the row decoder
        # tie the value back to its type for the attribute-layout lookup (#115).
        (TypeOid, Rest) = _read_chunked_bytes(Rest)
    (_, Rest) = decode_ub4(Rest)  # version
    (Charset, Rest) = decode_ub4(Rest)  # charset id
    Csfrm = Rest[0]  # charset form (1 DB / 2 national)
    Rest = Rest[1:]
    (MaxSize, Rest) = decode_ub4(Rest)
    if Is12c:
        (_, Rest) = decode_ub4(Rest)  # oaccolid (12.2+)
    NullOk = Rest[0]
    Rest = Rest[2:]  # skip nulls_allowed-byte AND v7 name length
    (ColName, Rest) = _read_str_with_length(Rest)
    (TypeSchema, Rest) = _read_str_with_length(Rest)  # owner of the type (ADT)
    (TypeName, Rest) = _read_str_with_length(Rest)  # the type's name (ADT)
    (_, Rest) = decode_ub4(Rest)  # column position
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_11_2:
        # `uds flags` is an 11g addition; a 10g (field version 4) describe ends
        # the per-column metadata at column position. Reading a phantom ub4 here
        # eats the next column's first bytes (or the DCB trailer's date length),
        # desyncing the whole row decode (#84). Verified against a live 10.2.0.5
        # server across 1/2/6-column, mixed-type and 0-row describes.
        (_, Rest) = decode_ub4(Rest)  # uds flags
    DomainSchema = DomainName = b''
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_23_1:
        # 23c (field version 17) appends the column's SQL-domain schema and
        # name, each a ub4-counted DALC string (the same codec as the column
        # name above) — empty (a single 0x00) for a column with no domain.
        # Earlier code read them as plain ub4s, which only survives the empty
        # case; a real domain (e.g. `01 03 03 'PYO' 01 07 07 'PYO_DOM'`) then
        # desynced the row (#53). Reverse-engineered by diffing a domain column
        # vs a plain one on 23ai, cross-checked against python-oracledb's
        # domain_schema/domain_name. Column annotations are carried elsewhere in
        # the describe (a plain column and an annotated one have identical
        # trailing fields here), so they neither appear nor desync here.
        (DomainSchema, Rest) = _read_str_with_length(Rest)
        (DomainName, Rest) = _read_str_with_length(Rest)
    Annotations = {}
    VecDims: int | None
    VecFormat: int | None
    VecFlags: int | None
    if _DECODE_FIELD_VERSION.get() > FIELD_VERSION_23_1:  # 23ai fv >= 18 (#89)
        # Each column carries its annotation map and the vector descriptor after
        # the domain fields (oracledb base.pyx _process_metadata). Both must be
        # consumed or the row stream desyncs; the annotations are the #89 payload.
        # The count is sent twice around a 1-byte pointer, and each key/value pair
        # is followed by a ub4 flags word, with a trailing ub4 flags after the loop.
        (NumAnno, Rest) = decode_ub4(Rest)
        if NumAnno > 0:
            Rest = Rest[1:]  # pointer
            (NumAnno, Rest) = decode_ub4(Rest)  # count, repeated
            Rest = Rest[1:]  # pointer
            for _ in range(NumAnno):
                (Key, Rest) = _read_str_with_length(Rest)
                (Val, Rest) = _read_str_with_length(Rest)
                Annotations[Key] = Val or b''
                (_, Rest) = decode_ub4(Rest)  # per-pair flags
            (_, Rest) = decode_ub4(Rest)  # trailing flags
        # Vector descriptor (23.4+): dimensions (ub4) + format + flags (ub1 each).
        # For a native VECTOR column these carry the declared dimension count and
        # element format (2 FLOAT32, 3 FLOAT64, 4 INT8, 5 BINARY; 0 = flexible),
        # with flags bit 0x01 flexible-format and 0x02 sparse — the metadata a
        # thin describe otherwise drops (a plain VECTOR column is indistinguishable
        # by data type alone). Captured for TNS_TYPE_VECTOR, discarded otherwise.
        (VecDims, Rest) = decode_ub4(Rest)
        VecFormat, VecFlags = Rest[0], Rest[1]
        Rest = Rest[2:]
    else:
        # No vector descriptor on the wire (a pre-23.4 server, or one that
        # negotiates field version <= 17): report None, not a fake 0 format.
        VecDims = VecFormat = VecFlags = None
    Col = {
        'column_name': ColName,
        'data_type': DataType,
        'data_length': BufferSize,
        'data_scale': DataScale,
        'precision': Precision,
        'max_size': MaxSize,
        'charset': Charset,
        'csfrm': Csfrm,
        'null_ok': NullOk,
        'domain_schema': DomainSchema or None,
        'domain_name': DomainName or None,
        'annotations': Annotations or None,
    }
    if DataType in (TNS_TYPE_ADT, TNS_TYPE_REF):
        # Object (ADT, #115) and REF (#119) columns carry the (referenced) type
        # identity here; keep it so the row decoder can look up the attribute
        # layout / label the REF. Names are plain ASCII identifiers.
        Col['type_oid'] = TypeOid
        Col['type_schema'] = (
            TypeSchema.decode('ascii', 'replace') or None if TypeSchema else None
        )
        Col['type_name'] = (
            TypeName.decode('ascii', 'replace') or None if TypeName else None
        )
    if DataType == TNS_TYPE_VECTOR:
        # A native VECTOR column's element format + declared dimension count, so
        # the describe carries what the value's self-describing image would (#55).
        Col['vector_format'] = VecFormat
        Col['vector_dimensions'] = VecDims
        Col['vector_flags'] = VecFlags
    return (Col, Rest)


def _str_with_length(data: bytes) -> bytes:
    # Inverse of _read_str_with_length: a ub4 char-count then a DALC. An empty
    # value is just the zero count (the reader returns b'' without a DALC).
    if not data:
        return encode_sb4(0)
    return encode_sb4(len(data)) + _bytes_with_length(data)


def _encode_signed_sb4(value: int) -> bytes:
    # The 11g describe encodes scale as a variable-length *signed* integer: a
    # negative value sets the 0x80 bit of the length byte over the magnitude
    # bytes (so NUMBER's -127 "no scale" default is 0x81 0x7f). encode_sb4 only
    # covers the non-negative case; the client's decode_ub4 reads both.
    if value >= 0:
        return encode_sb4(value)
    magnitude = (-value).to_bytes(4, 'big').lstrip(b'\x00') or b'\x00'
    return bytes([0x80 | len(magnitude)]) + magnitude


# The buffer length a real server reports for a column type that always carries
# bytes in the row (#690). A zero length is not a free "unknown": the client reads
# it as "this column sends nothing at all, its value is always NULL"
# (docs/PROTOCOL.md 6.2), so a describe claiming zero for one of these makes the
# row decoder consume the wrong bytes and desync.
#
# A backend often cannot supply one -- the PEP 249 description tuple reports no
# size for a temporal, interval or REF column -- and the Mirror fills it in here
# rather than leaving each backend to remember. Measured against live 10g, 11g,
# 21c and 23ai, which all report exactly these; the odd-looking values are what
# Oracle sends, not a guess. A character or RAW column is absent on purpose: zero
# is a truthful answer there (`SELECT NULL AS x` describes exactly that way) and
# must be left alone.
_DESCRIBE_WIRE_LENGTH = {
    TNS_TYPE_NUMBER: 22,
    TNS_TYPE_DATE: 1,
    TNS_TYPE_TIMESTAMP: 11,
    TNS_TYPE_TIMESTAMPTZ: 1,
    TNS_TYPE_TIMESTAMPLTZ: 11,
    TNS_TYPE_INTERVALYM: 1,
    TNS_TYPE_INTERVALDS: 1,
    TNS_TYPE_BFLOAT: 1,
    TNS_TYPE_BDOUBLE: 1,
    TNS_TYPE_REF: 2000,
    TNS_TYPE_CLOB: 4000,
    TNS_TYPE_BLOB: 4000,
}


def describe_wire_length(col: ColumnMeta) -> int:
    """The buffer length to describe ``col`` with.

    The backend's own figure when it has one, else the length a real server
    reports for that type. Zero survives only for a type where it is true.
    """
    if col.data_length:
        return col.data_length
    return _DESCRIBE_WIRE_LENGTH.get(col.data_type, 0)


def _encode_dcb_column(col: ColumnMeta, position: int) -> bytes:
    # Inverse of _decode_dcb_column, in the layout the negotiated field version's
    # client reads: 12.2+ carries the scale as one signed byte and appends an
    # oaccolid after max_size; 23ai (17) adds the SQL-domain schema + name (empty
    # for a plain column). Fields the client skips are written as well-formed
    # zeros; only type/precision/scale/length/charset/csfrm/max_size/null_ok/name
    # carry meaning.
    field_version = _ENCODE_FIELD_VERSION.get()
    is_12c = field_version >= FIELD_VERSION_12_2
    return (
        bytes([col.data_type, 0, col.precision & 0xFF])
        + (bytes([col.scale & 0xFF]) if is_12c else _encode_signed_sb4(col.scale))
        + encode_sb4(describe_wire_length(col))  # buffer size
        + encode_sb4(0)  # max array elements
        + encode_sb4(0)  # cont flags
        # For an ADT / REF column the referenced type's OID (else absent) (#494).
        + _str_with_length(col.type_oid)
        + encode_sb4(0)  # version
        + encode_sb4(col.charset)
        + bytes([col.csfrm])
        + encode_sb4(col.max_size)
        + (encode_sb4(0) if is_12c else b'')  # oaccolid (12.2+)
        + bytes([col.null_ok, 0])  # null_ok + (skipped) v7 name length
        + _str_with_length(col.name)
        + _str_with_length(col.type_schema)  # type schema (ADT owner)
        + _str_with_length(col.type_name)  # type name
        + encode_sb4(position)  # column position
        + encode_sb4(0)  # uds flags (11g addition)
        + (
            _str_with_length(b'') + _str_with_length(b'')  # domain schema + name
            if field_version >= FIELD_VERSION_23_1
            else b''
        )
    )


def _encode_describe_body(columns: list[ColumnMeta]) -> bytes:
    # The describe body shared by the TTI_DCB block and a REF CURSOR OUT bind's
    # inline describe (#483): max row size, column count, the per-column DCB
    # metadata, then the current-date / flag / query-cache-key trailer.
    body = encode_sb4(sum(c.max_size for c in columns))  # max row size (skipped)
    body += encode_sb4(len(columns))
    if columns:
        body += bytes([0])  # reserved
    for position, col in enumerate(columns, start=1):
        body += _encode_dcb_column(col, position)
    body += _bytes_with_length(b'')  # current date (skipped)
    body += encode_sb4(0) * 4  # dcbflag / dcbmdbz / dcbmnpr / dcbmxpr
    body += _bytes_with_length(b'')  # dcbqcky query-cache key (11g)
    return body


def encode_describe(columns: list[ColumnMeta]) -> bytes:
    """Build the describe (TTI_DCB) block for a result's columns — §19.1 (11g).

    Returns the TTC payload starting at the TTI_DCB token. The cursor-uuid
    preamble is empty (the client skips it); the row tokens are appended
    separately by the exec-response encoder.
    """
    preamble = _bytes_with_length(b'')  # cursor uuid / timestamp (skipped)
    return bytes([TTI_DCB]) + preamble + _encode_describe_body(columns)


# --- Mirror thin reply/response encoders (§6) ---


def _encode_batch_ub4_array(values: list[int]) -> bytes:
    # An array-DML batch field (#18): a ub4 count, then a DALC blob packing that
    # many ub4 values back-to-back (the inverse of _read_batch_ub4_array). Empty
    # is a bare zero count.
    if not values:
        return encode_sb4(0)
    blob = b''.join(encode_sb4(v) for v in values)
    return encode_sb4(len(values)) + _bytes_with_length(blob)


def _encode_batch_messages(messages: list[str]) -> bytes:
    # The batch-error message array (#18): a ub4 count, a 1-byte indicator, then
    # per message a ub4 length + the length-prefixed text + a 2-byte trailer.
    if not messages:
        return encode_sb4(0)
    out = bytearray(encode_sb4(len(messages)) + bytes([1]))
    for message in messages:
        text = message.encode('utf-8')
        out += encode_sb4(len(text)) + _bytes_with_length(text) + bytes([0, 0])
    return bytes(out)


def _encode_oer(
    call_status: int,
    ora_code: int,
    rowcount: int,
    message: bytes,
    cursor_id: int = 0,
    batch_errors: list[tuple[int, int, str]] | None = None,
    *,
    seq: int = 0,
    error_pos: int = 0,
    sql_type: int = 0,
    call_number: int = 0,
) -> bytes:
    # An OER return-status token (§6.5, 11g) — the terminal of every response.
    # Rowid fields are zero; call status, the ORA error number, the affected-row
    # count, the cursor id (for a mid-fetch "more rows" status), and the message
    # text carry meaning. ``batch_errors`` is (offset, code, message) per row that
    # failed in an array-DML batcherrors execute — the three arrays line up by
    # position (#18). ``seq`` / ``error_pos`` / ``sql_type`` / ``call_number`` are
    # the OER fields left zero by the ordinary error/status paths but non-zero in a
    # captured terminator (see :data:`_END_OF_FETCH`); they carry the captured
    # value there and default to zero everywhere else.
    batch_errors = batch_errors or []
    codes = [code for _offset, code, _msg in batch_errors]
    offsets = [offset for offset, _code, _msg in batch_errors]
    messages = [msg for _offset, _code, msg in batch_errors]
    return (
        bytes([TTI_OER])
        + encode_sb4(call_status)
        + encode_sb4(seq)  # end-to-end seq
        + encode_sb4(rowcount)  # current row number == DML affected rows on 11g
        + encode_sb4(ora_code)  # the ORA error number (0 on success)
        + encode_sb4(0)  # array element error 1
        + encode_sb4(0)  # array element error 2
        + encode_sb4(cursor_id)  # current cursor id
        + encode_sb4(error_pos)  # error position
        + bytes([sql_type, 0, 0, 0, 0, 0])  # sql_type, fatal, flags, opts, upi, warn
        + encode_sb4(0)  # rowid data object number
        + encode_sb4(0)  # rowid relative file number
        + bytes(1)  # rowid reserved
        + encode_sb4(0)  # rowid block number
        + encode_sb4(0)  # rowid slot number
        + encode_sb4(0)  # os error
        + bytes([0, call_number])  # statement number, call number
        + encode_sb4(0)  # padding
        + encode_sb4(1)  # successful iterations
        + _bytes_with_length(b'')  # oerrdd (logical rowid)
        + _encode_batch_ub4_array(codes)  # batch error codes
        + _encode_batch_ub4_array(offsets)  # batch error row offsets
        + _encode_batch_messages(messages)  # batch error messages
        + _oer_version_tail(ora_code, rowcount)
        + _bytes_with_length(message)  # the message DALC (read only when ora_code≠0)
    )


def _oer_version_tail(ora_code: int, rowcount: int) -> bytes:
    # The fields a 12.1+ client reads between the batch-error arrays and the
    # message (its decode_token_oer): the extended error number and the ub8
    # rowcount, then from 20.1 a SQL type and a server checksum. 11g has none.
    field_version = _ENCODE_FIELD_VERSION.get()
    if field_version < FIELD_VERSION_12_1:
        return b''
    tail = encode_sb4(ora_code) + encode_sb4(rowcount)
    if field_version >= FIELD_VERSION_20_1:
        tail += encode_sb4(0) + encode_sb4(0)  # sql type, server checksum
    return tail


def _national_wire_value(value: object, col: ColumnMeta) -> object:
    # National char data (NCHAR / NVARCHAR2, csfrm 2) travels the wire as UTF-16BE
    # in the AL16UTF16 charset — the form both the thin client's decoder and
    # sqlplus expect when the describe says csfrm 2. A str value is pre-encoded to
    # those bytes; everything else (NULL, non-national columns) passes through.
    if col.csfrm == _CSFRM_NCHAR and isinstance(value, str):
        return value.encode('utf-16-be')
    return value


def encode_rows(
    rows: list[tuple], columns: list[ColumnMeta], *, fetch: int = 15
) -> bytes:
    """Build the row-transfer tokens for a fetch — §6.2 (11g).

    One row-header (TTI_RXH) followed by one TTI_RXD per row, each carrying the
    columns' values as DALC blobs. The caller frames these after the describe
    and before the fetch terminator. ``columns`` fixes the value order.
    """
    from seerdb.common.exceptions import InterfaceError

    header = (
        bytes([TTI_RXH, 0])  # token + (skipped) flags
        + encode_sb4(1)  # num requests
        + encode_sb4(0)  # iteration number
        + encode_sb4(fetch)  # num iterations
        + encode_sb4(0)  # buffer length
        + encode_sb4(0)  # bit-vector length (no column compression)
        + _bytes_with_length(b'')  # rxhrid
    )
    # A bytearray, not a `bytes` accumulator: `bytes += ` reallocates and copies
    # the whole buffer each row (O(n^2) for a large single batch — a fetch-all, a
    # scrollable open, or a pipelined prefetch); a bytearray extends in place
    # (O(n)). The OCI row encoders already do this.
    body = bytearray()
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        body += bytes([TTI_RXD]) + b''.join(
            encode_value(_national_wire_value(v, col), col.data_type)
            for v, col in zip(row, columns)
        )
    return header + bytes(body)


def encode_error(ora_code: int, message: str, error_pos: int | None = None) -> bytes:
    """OER reporting an error: the client raises ``ORA-<code>: <message>`` and
    the connection stays usable. ``error_pos`` is the parse offset of the error
    (``None`` -> 0, no specific position)."""
    return _encode_oer(
        1, ora_code, 0, message.encode('utf-8'), error_pos=error_pos or 0
    )


def encode_status(rowcount: int = 0, cursor_id: int = 0) -> bytes:
    """OER reporting success for a non-query (DDL / DML), with the affected-row
    count. No describe, no rows — the client just sees the statement completed.
    A non-zero ``cursor_id`` lets the client's cursor cache remember the server
    handle and re-execute the same DML by id with an empty query (#80/#486)."""
    return _encode_oer(0, 0, rowcount, b'', cursor_id=cursor_id)


def encode_status_with_rowcounts(
    rowcount: int, counts: list[int], *, cursor_id: int = 0
) -> bytes:
    """The DML success status when the client requested arraydmlrowcounts (#18):
    the per-iteration affected-row counts, then the ordinary status OER. The
    counts ride in front of the OER as a minimal server-side session-state RPA
    piggyback (`TTI_RPA`, zero fields) whose body is `ub4 count | count x ub4`,
    exactly where the client's decode_token_rpa_piggyback reads them when its own
    execute armed arraydmlrowcounts. Without the request the client never looks
    for them, so this form is used only then."""
    block = encode_sb4(len(counts)) + b''.join(encode_sb4(c) for c in counts)
    piggyback = bytes([TTI_RPA]) + encode_sb4(0) + block
    return piggyback + encode_status(rowcount, cursor_id=cursor_id)


# ORA-24381: the array-DML summary code the server returns when a batcherrors
# execute collected per-row failures — non-fatal, the client reads the errors
# from getbatcherrors() rather than raising (#18).
_ARRAY_DML_ERRORS = 24381


def encode_batch_errors_status(
    rowcount: int, batch_errors: list[tuple[int, int, str]]
) -> bytes:
    """OER for an array-DML ``batcherrors`` execute that collected per-row
    failures (#18): ORA-24381 with the (offset, code, message) arrays, and the
    affected-row count of the rows that applied. The client surfaces the errors
    through ``getbatcherrors()`` instead of raising."""
    message = f'ORA-{_ARRAY_DML_ERRORS:05d}: error(s) in array DML'.encode()
    return _encode_oer(
        0, _ARRAY_DML_ERRORS, rowcount, message, batch_errors=batch_errors
    )


def encode_more_rows(cursor_id: int) -> bytes:
    """Terminate a batch that did NOT drain the cursor: ``call_status = 1``, no
    error, and the cursor id — the client reads this as "more rows on cursor N"
    and issues ``TTI_FETCH`` for the rest (§5.2). The ``1403`` end-of-fetch
    (:data:`_END_OF_FETCH`) is sent only once the cursor is drained."""
    return _encode_oer(1, 0, 0, b'', cursor_id=cursor_id)


def _terminator(cursor_id: int, more: bool) -> bytes:
    return encode_more_rows(cursor_id) if more else _end_of_fetch()


def encode_query_response(
    columns: list[ColumnMeta],
    rows: list[tuple],
    *,
    cursor_id: int = 0,
    more: bool = False,
) -> bytes:
    """Assemble a SELECT execute response: describe + rows + terminator (§6).

    ``more=True`` ends the batch with a "more rows on ``cursor_id``" status
    instead of the ``ORA-01403`` end-of-fetch, so the client fetches the rest.
    """
    return (
        encode_describe(columns)
        + encode_rows(rows, columns)
        + _terminator(cursor_id, more)
    )


def encode_fetch_response(
    columns: list[ColumnMeta],
    rows: list[tuple],
    *,
    cursor_id: int = 0,
    more: bool = False,
) -> bytes:
    """Assemble a ``TTI_FETCH`` continuation response: rows + terminator, with
    **no** describe (the column metadata was established on the execute)."""
    return encode_rows(rows, columns) + _terminator(cursor_id, more)


from seerdb.common.tns_consts import (
    TNS_BIND_DIR_OUTPUT,
    TNS_FETCH_ORIENTATION_FIRST,
    TNS_FETCH_ORIENTATION_LAST,
    TNS_LOB_OP_CLOSE,
    TNS_LOB_OP_FREE_TEMP,
    TNS_LOB_OP_GET_CHUNK_SIZE,
    TNS_LOB_OP_OPEN,
    TNS_LOB_OP_TRIM,
)

# The 11g tail between the fixed header and the SQL: a [0, 0, 1] marker and a
# 5-byte server-version slot (empty only when the client thinks it is talking to
# 10g; an 11g-pinned Mirror always gets the 5-byte form).
_MARKER_LEN = 3


_SERVER_VERSION_SLOT = 5


# The autocommit bit in the OALL8 options word: the client sets it (0x100) when
# the connection is in autocommit mode, asking the server to commit after this
# statement (set_opts encodes it as Param * 256 into the options word).
_EXEC_OPTION_COMMIT = 0x100


# The array-DML batcherrors bit (0x80000): the client sets it to ask the server
# to apply the good rows and collect per-row failures rather than aborting (#18).
_EXEC_OPTION_BATCH_ERRORS = 0x80000


# A TTI_LOBOPS READ request carries the slice sqlplus wants: a 1-based source
# offset and an amount, both counts (characters for a CLOB, bytes for a BLOB),
# at these fixed ub8-LE offsets in the OCI request. sqlplus loops over them (in
# SET LONGCHUNKSIZE-sized steps) until a read returns fewer than it asked for.
_OCI_LOBOPS_OFFSET_OFF = 91


_OCI_LOBOPS_AMOUNT_OFF = 269


_OCI_LOB_CHUNK = 0xFF  # content bytes per 11g LOB_DATA chunk (matches live 11g)


def _oci_lob_data(content: bytes) -> bytes:
    # TTI_LOB content: token + single-byte-length chunks (the 11g form). Content up
    # to one chunk is a plain <len><data>; larger content uses the 0xFE chunked
    # form, a run of <ub1 len><bytes> terminated by a zero-length chunk.
    if len(content) <= _OCI_LOB_CHUNK:
        return bytes([TTI_LOB, len(content)]) + content
    out = bytearray([TTI_LOB, 0xFE])
    for start in range(0, len(content), _OCI_LOB_CHUNK):
        chunk = content[start : start + _OCI_LOB_CHUNK]
        out += bytes([len(chunk)]) + chunk
    out += bytes([0])  # zero-length chunk terminates the run
    return bytes(out)


# --- Mirror thin request parsers + LOB / out-bind / scroll codec ---


# The LOB-descriptor prefix a temp-LOB locator bind carries (shared with the
# native VECTOR / JSON binds): 01 28 28 then a ub2 locator length + locator.
_TEMP_LOB_BIND_PREFIX = b'\x01\x28\x28'
# The fixed head of a native JSON bind value (_native_lob_bind_value): the
# 19-byte descriptor + a ub2 image length + 22 zero bytes; the OSON image
# (bytes_with_length) follows.
_JSON_BIND_HEAD_LEN = len(VECTOR_BIND_DESCRIPTOR) + 2 + 22


def _read_bind_value(
    data_type: int, csfrm: int, after: bytes, toid: bytes = b''
) -> tuple[object, bytes]:
    # One RXD bind value and the bytes past it. A CLOB / BLOB bind is a temp-LOB
    # descriptor (#412), not a plain DALC: 01 28 28 | ub2 loclen | locator, with
    # no outer length — the server reads it by type (the descriptor's leading
    # 0x01 would otherwise be mistaken for a DALC length). Everything else is the
    # ordinary DALC value decoded by its OAC type and charset form. `toid` is the
    # referenced type's OID from the OAC, used to rebuild a REF bind (#139).
    if data_type == TNS_TYPE_REF:
        # A REF bind (#139): the value is just the opaque locator (a DALC). Pair
        # it with the OID the OAC carried so the backend re-binds a DbRef with
        # the referenced type's identity (its bind OAC needs the 16-byte OID).
        from seerdb.common.dbobject import DbRef

        raw, after = decode_dalc(after)
        locator = bytes(raw) if not isinstance(raw, list) else b''
        return DbRef(locator, type_oid=toid or None), after
    if (
        data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB)
        and after[:3] == _TEMP_LOB_BIND_PREFIX
    ):
        loclen = (after[3] << 8) | after[4]
        locator = after[5 : 5 + loclen]
        # Kept as a reference; the session swaps in the bytes streamed over
        # TTI_LOBOPS WRITE (the backend never sees a locator, only the value).
        return TempLobRef(locator, data_type == TNS_TYPE_BLOB), after[5 + loclen :]
    if data_type == TNS_TYPE_JSON and after[:3] == _TEMP_LOB_BIND_PREFIX:
        # A native JSON bind (#50/#70): the client sends the value inline as its
        # OSON image, not a plain DALC — the _native_lob_bind_value framing of a
        # fixed descriptor, a ub2 image length, 22 zero bytes, then the image in
        # bytes_with_length form. Skip the fixed head, read the image, and decode
        # it back to a Python value the backend re-binds (a too-large / too-wide
        # value the client couldn't OSON-encode arrives as a VARCHAR text cast
        # instead, on the ordinary DALC path below). #70.
        from seerdb.common.oson import decode_oson

        rest = after[_JSON_BIND_HEAD_LEN:]
        image, rest = decode_dalc(rest)
        if isinstance(image, list):
            return None, rest
        # Re-wrap as a JSON marker so the backend re-binds it into a JSON column
        # rather than as its bare Python type: a bare list / scalar would
        # otherwise bind as a collection / VARCHAR (only a dict is auto-detected
        # as JSON). #50/#70.
        return JSON(decode_oson(bytes(image))), rest
    if data_type == TNS_TYPE_VECTOR and after[:3] == _TEMP_LOB_BIND_PREFIX:
        # A native VECTOR bind (#55/#62): the client sends the value inline as
        # its binary image (same _native_lob_bind_value framing as JSON). Decode
        # it to a type-preserving value (array.array by the image's own element
        # type) so the backend re-binds FLOAT64 / INT8 / BINARY faithfully rather
        # than as a default FLOAT32 list.
        rest = after[_JSON_BIND_HEAD_LEN:]
        raw_image, rest = decode_dalc(rest)
        if isinstance(raw_image, list):
            return None, rest
        image = bytes(raw_image)
        decoded = decode_vector(image)
        if isinstance(decoded, SparseVector):
            return decoded, rest
        return _vector_as(decoded, image[4] if len(image) > 4 else None), rest
    raw, after = decode_dalc(after)
    return _decode_bind_value(data_type, csfrm, raw), after


def _decode_bind_value(data_type: int, csfrm: int, raw: bytes | list) -> object:
    from seerdb.common.types import decode_value

    # A bind value from the RXD, decoded by its OAC type. An empty/NULL DALC
    # (reported as a list by decode_dalc) is None. csfrm selects the char
    # encoding: 2 (national) decodes an NCHAR / NVARCHAR value as UTF-16BE, 1
    # (ordinary) as AL32UTF8 — decode_value keys on it via _string_charset (#484).
    if isinstance(raw, list) or not raw:
        return None
    raw = bytes(raw)
    column = {
        'data_type': data_type,
        'data_length': 0,
        'precision': 0,
        'data_scale': 0,
        'charset': AL32UTF8_CHARSET,
        'csfrm': csfrm or _CSFRM_DB,
    }
    return decode_value(column, bytes(raw))


def peek_exec_cursor(payload: bytes) -> tuple[int, bool]:
    """The cursor id and whether SQL is present, read from an OALL8 header without
    a full parse (#80/#486). A cached re-execute (cursor set, no SQL) carries no
    OACs, so the session uses this to supply the remembered bind types to
    :func:`parse_exec`. Returns ``(0, True)`` for anything that isn't an OALL8."""
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_ALL8:
        return (0, True)
    rest = payload[3:]
    _options, rest = decode_ub4(rest)
    cursor, rest = decode_ub4(rest)
    query_flag = rest[0] if rest else 0
    return (cursor, bool(query_flag))


def _skip_exec_middle_12c(rest: bytes, field_version: int) -> bytes:
    # The 12.2+ OALL8 block between the fixed head and the SQL (the client's
    # encode_dictionary_exec `Middle`): the 0,0,1 marker, the registration
    # fields, the array-DML row-count block (a 1 + sb4 iteration count + 1 when
    # arraydmlrowcounts was requested, else three zeros), the SQL-signature /
    # SQL-id slot, and from 12.2_EXT1 up two chunk-id bytes.
    rest = rest[3:]  # 0, 0, 1
    rest = rest[5:]  # reg_lsb .. reg_msb
    if rest[:1] == b'\x01':
        _, rest = decode_ub4(rest[1:])  # iteration count
        rest = rest[1:]
    else:
        rest = rest[3:]
    rest = rest[5:]  # al8sqlsig / SQL id
    if field_version >= FIELD_VERSION_12_2_EXT1:
        rest = rest[2:]  # chunk ids
    return rest


def parse_exec(
    payload: bytes, bind_types: list | None = None, max_string_size: int = 4000
) -> ExecRequest:
    """Parse an OALL8 execute payload (the TTC message from ``read_packet``).

    Extracts the SQL text and any bind values (positional, decoded by their OAC
    type). Raises :class:`InterfaceError` if the message is not a TTI_ALL8
    execute.

    A cached-cursor re-execute (#80/#486) carries the bind values but **no** OAC
    descriptors — the server is expected to remember the bind format from the
    first parse. Pass the remembered ``bind_types`` (the ``(data_type, csfrm,
    max_size)`` list from that first parse, exposed as ``ExecRequest.bind_types``)
    so the RXD values decode without re-reading OACs.

    ``max_string_size`` is the widest bind the server this Mirror presents as
    takes in place (what its runtime capabilities promised the client, see
    :func:`max_string_size`); a bind declared wider is LONG-class and its value
    is read after the row's others.
    """
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_ALL8:
        raise InterfaceError('not an OALL8 execute')

    rest = payload[3:]  # skip TTI_FUN, TTI_ALL8, seq
    options, rest = decode_ub4(rest)
    autocommit = bool(options & _EXEC_OPTION_COMMIT)
    batcherrors = bool(options & _EXEC_OPTION_BATCH_ERRORS)
    cursor, rest = decode_ub4(rest)
    query_flag, rest = rest[0], rest[1:]
    query_len, rest = decode_ub4(rest)
    _all8_flag, rest = rest[0], rest[1:]
    all8_len, rest = decode_ub4(rest)
    rest = rest[2:]  # two reserved bytes
    _lmax, rest = decode_ub4(rest)
    fetch, rest = decode_ub4(rest)
    _max, rest = decode_ub4(rest)
    _bind_flag, rest = rest[0], rest[1:]
    bind_count, rest = decode_ub4(rest)
    rest = rest[5:]  # five reserved bytes
    _def_flag, rest = rest[0], rest[1:]
    _def_len, rest = decode_ub4(rest)

    field_version = _DECODE_FIELD_VERSION.get()
    if field_version >= FIELD_VERSION_12_2:
        # 12.2+ replaces the marker + server-version slot with the registration /
        # array-DML row-count / SQL-signature block, and length-prefixes the SQL.
        rest = _skip_exec_middle_12c(rest, field_version)
        if query_flag:
            raw, after = decode_dalc(rest)
            sql = bytes(raw).decode('utf-8')
        else:
            sql, after = '', rest
    else:
        rest = rest[_MARKER_LEN + _SERVER_VERSION_SLOT :]
        sql = rest[:query_len].decode('utf-8') if query_flag else ''
        after = rest[query_len:]

    # The al8i4 option array follows the SQL text; decode all `all8_len` sb4
    # elements so `after` lands on the OAC/RXD tokens and the scroll request
    # (al8i4[9] exec flags, [10] orientation, [11] position) is available. A
    # scroll re-execute carries no binds, so this must run unconditionally, not
    # only in the bind path (#181/#485).
    al8: list[int] = []
    for _ in range(all8_len):
        al8_elem, after = decode_ub4(after)
        al8.append(al8_elem)
    scrollable = len(al8) > 9 and bool(al8[9] & TNS_EXEC_FLAGS_SCROLLABLE)
    arraydmlrowcounts = len(al8) > 9 and bool(al8[9] & TNS_AL8I4_ARRAY_DML_ROWCOUNTS)
    scroll_orientation = al8[10] if len(al8) > 10 else 0
    scroll_position = al8[11] if len(al8) > 11 else 0

    binds: list = []
    bind_rows: list = []
    bind_meta: list = []
    if bind_count > 0:
        # After the al8 array (already consumed above): one OAC (type descriptor)
        # per bind column, then one RXD row of values per array-DML iteration
        # (an ordinary single execute is just one row). A cached re-execute omits
        # the OACs, so `after` already sits on the first RXD — use the remembered
        # bind types instead of decoding OACs (#80/#486).
        if bind_types is not None:
            types = list(bind_types)
        else:
            types = []
            for _ in range(bind_count):
                (
                    data_type,
                    maxlen,
                    _scale,
                    _charset,
                    csfrm,
                    toid,
                    after,
                ) = decode_oac_fields(after)
                if field_version >= FIELD_VERSION_12_2:
                    # The 12.2+ bind OAC appends an oaccolid the shared decoder
                    # stops short of (the same trailer a 12.2+ describe column
                    # carries) — consume it so the next OAC aligns.
                    _, after = decode_ub4(after)
                elif data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
                    # A thin CLOB / BLOB bind is the temp-LOB locator form (#412),
                    # whose OAC appends a trailing oaccolid field the shared
                    # decoder stops short of — swallow it so the next OAC aligns.
                    after = after[1:]
                # csfrm distinguishes an NCHAR / NVARCHAR bind (2 → UTF-16BE) from
                # an ordinary char bind (1); maxlen is the OUT return-buffer size a
                # PL/SQL OUT bind needs (#483/#484). toid is the referenced type's
                # OID for a REF / object bind (empty otherwise, #139). All ride
                # alongside the type.
                types.append((data_type, csfrm, maxlen, toid))
        # Each row is a TTI_RXD token followed by one value per bind column,
        # EXCEPT the binds a `RETURNING ... INTO` clause fills from the affected
        # rows -- the client writes no value for those, in any iteration
        # (docs/PROTOCOL.md 22 and 22.1). Reading one anyway consumed the next
        # value as this one's tail and everything after it was misread (#689).
        # The row keeps a None in each such position so it stays aligned with
        # `bind_meta`, which does describe every bind.
        return_binds = returning_bind_positions(sql, bind_count)
        # A row's LONG-class values -- binds declared wider than the server takes
        # in place -- come after all its other values (docs/PROTOCOL.md 5.4); a
        # PL/SQL block's ride in place. (A cached re-execute carries no SQL, but
        # a cached cursor is DML only, #703.)
        long_binds = frozenset(
            index
            for index, (_data_type, _csfrm, maxlen, _toid) in enumerate(types)
            if maxlen > max_string_size and not is_plsql(sql)
        )
        carried = [index for index in range(len(types)) if index not in return_binds]
        order = [index for index in carried if index not in long_binds] + [
            index for index in carried if index in long_binds
        ]
        # Loop until the rows run out (executemany sends N, a plain execute
        # sends 1).
        while after and after[0] == TTI_RXD:
            after = after[1:]
            row: list = [None] * len(types)
            for index in order:
                data_type, csfrm, _maxlen, toid = types[index]
                row[index], after = _read_bind_value(data_type, csfrm, after, toid)
            bind_rows.append(row)
        if bind_rows:
            binds = bind_rows[0]
        # Per-bind (tns_type, max_size) — what a PL/SQL block's OUT binds need to
        # be registered on the backend with a correctly-sized buffer (#483).
        bind_meta = [(data_type, maxlen) for data_type, _csfrm, maxlen, _toid in types]
        bind_type_list = list(types)
    else:
        bind_type_list = []
        return_binds = frozenset()

    return ExecRequest(
        sql=sql,
        cursor=cursor,
        bind_count=bind_count,
        fetch=fetch,
        binds=binds,
        bind_rows=bind_rows,
        bind_meta=bind_meta,
        bind_types=bind_type_list,
        autocommit=autocommit,
        batcherrors=batcherrors,
        scrollable=scrollable,
        scroll_orientation=scroll_orientation,
        scroll_position=scroll_position,
        arraydmlrowcounts=arraydmlrowcounts,
        return_binds=return_binds,
    )


def _read_chunked_sql(data: bytes, total_len: int) -> bytes:
    # `data` starts at the 0xFE chunk marker; collect <ub1 len><chunk> runs until
    # the declared total is reached or a zero-length chunk terminates it.
    out = bytearray()
    i = 1  # skip the 0xFE marker
    while len(out) < total_len and i < len(data):
        chunk_len = data[i]
        i += 1
        if chunk_len == 0:
            break
        out += data[i : i + chunk_len]
        i += chunk_len
    return bytes(out[:total_len])


def parse_lobops_read(body: bytes) -> tuple[int, int]:
    """Extract ``(source_offset, amount)`` from an OCI TTI_LOBOPS READ (#405) —
    both 1-based counts (characters for a CLOB, bytes for a BLOB). A malformed /
    short request falls back to reading the whole LOB from the start."""
    if len(body) < _OCI_LOBOPS_AMOUNT_OFF + 8:
        return 1, 2**31
    offset = int.from_bytes(
        body[_OCI_LOBOPS_OFFSET_OFF : _OCI_LOBOPS_OFFSET_OFF + 8], 'little'
    )
    amount = int.from_bytes(
        body[_OCI_LOBOPS_AMOUNT_OFF : _OCI_LOBOPS_AMOUNT_OFF + 8], 'little'
    )
    return max(offset, 1), amount


def encode_lob_read_response_thin(content: bytes) -> bytes:
    """The thin TTI_LOBOPS READ reply (#413): the whole LOB content as LOB_DATA
    then a success OER (the client reads the content, skips to the OER, and stops).
    ``content`` is UTF-16BE for a CLOB, raw for a BLOB."""
    return _lob_data_thin(content) + _encode_oer(1, 0, 0, b'')


def _lob_data_thin(content: bytes) -> bytes:
    # LOB_DATA in the negotiated version's chunk framing. A short value is one
    # length byte + data at every version. A longer one is the 0xFE-marked run of
    # chunks: 11g prefixes each chunk with a single length byte, a 12.2+ client
    # reads a variable-width big-endian length (the ub4 form) per chunk — the
    # same framing its own writer uses for a long bind — and a zero terminator.
    if _ENCODE_FIELD_VERSION.get() < FIELD_VERSION_12_2:
        return _oci_lob_data(content)
    if len(content) < 0xFE:
        return bytes([TTI_LOB, len(content)]) + content
    out = bytearray([TTI_LOB, 0xFE])
    for start in range(0, len(content), _OCI_LOB_CHUNK):
        chunk = content[start : start + _OCI_LOB_CHUNK]
        out += encode_sb4(len(chunk)) + chunk
    out += encode_sb4(0)
    return bytes(out)


def mint_temp_lob_locator(index: int, is_blob: bool) -> bytes:
    """A unique opaque locator for the ``index``-th temp LOB of a session (#412).

    The value is echoed back verbatim on WRITE and on the bind, so it only has to
    be stable and distinct per temp LOB — the Mirror keys its buffer on it."""
    return (
        _TEMP_LOB_LOCATOR_PREFIX
        + struct.pack('>I', index)
        + (b'\x01' if is_blob else b'\x00')
    )


# CREATE_TEMP sends a fixed field block (no source locator), captured from the
# thin client: it opens 01 01 28 and CLOB / BLOB differ only in the LOB type byte
# (0x70 / 0x71). That opener is unmistakable against the WRITE / READ layout,
# whose second field is a locator length (~40-86), never 0x01.
_CREATE_TEMP_PREFIX = b'\x01\x01\x28'


_TEMP_LOB_LOCATOR_PREFIX = b'\x00seerdb-mirror-temp-lob-'


def _decode_lobops_chunked(data: bytes) -> bytes:
    # The WRITE payload after the 0x0E marker: a single <ub1 len><bytes> when the
    # data is <= 0xFC bytes, else a 0xFE marker then <sb4 len><chunk> repeated
    # until a zero-length terminator (§14.2). Inverse of the client encoder.
    if not data:
        return b''
    if data[0] != 0xFE:
        return data[1 : 1 + data[0]]
    rest = data[1:]
    out = bytearray()
    while rest:
        chunk_len, rest = decode_ub4(rest)
        if chunk_len == 0:
            break
        out += rest[:chunk_len]
        rest = rest[chunk_len:]
    return bytes(out)


# The opcodes the Mirror acknowledges with a content-free RPA+OER but does not
# yet act on (#417): OPEN / CLOSE bracket a write, TRIM truncates. Recognising
# them (instead of mis-routing to the READ path) is what keeps a programmatic
# client from desyncing. FREE_TEMP is handled apart (it drops the temp buffer).
# The value-returning form of GET_CHUNK_SIZE / TRIM is a #421 follow-up.
_LOBOPS_ACK_OPS = frozenset(
    {TNS_LOB_OP_OPEN, TNS_LOB_OP_CLOSE, TNS_LOB_OP_TRIM, TNS_LOB_OP_GET_CHUNK_SIZE}
)


def _lobops_locator_after_operation(rest: bytes) -> bytes:
    # From just past the operation code, walk the shared §14.1 tail to the
    # ub2-length-prefixed locator (WRITE / FREE_TEMP / OPEN / CLOSE / TRIM /
    # GET_CHUNK_SIZE all carry it identically; only what follows differs).
    rest = rest[2:]  # scn-array pointer + length
    _src_offset, rest = decode_ub4(rest)
    _dest_offset, rest = decode_ub4(rest)
    rest = rest[1:]  # amount pointer flag
    rest = rest[6:]  # three reserved ub2 array-LOB slots
    loc_len = struct.unpack('>H', rest[:2])[0]
    return rest[2 : 2 + loc_len]


def parse_lobops_request(body: bytes) -> LobOpsRequest:
    """Classify a TTI_LOBOPS message (``body`` from ``read_packet``).

    CREATE_TEMP / WRITE drive the temp-LOB write flow (#412); FREE_TEMP releases a
    temp LOB and the OPEN / CLOSE / TRIM / GET_CHUNK_SIZE state ops are
    acknowledged (#417); anything else (a READ of an emitted column locator) is
    served by the #413 read path."""
    payload = body[3:]  # skip TTI_FUN, TTI_LOBOPS, seq
    if payload[:3] == _CREATE_TEMP_PREFIX:
        # CLOB vs BLOB is the LOB type byte (0x70 / 0x71) in the fixed block.
        return LobOpsRequest(kind='create_temp', is_blob=0x71 in payload)
    # The common request layout (§14.1); walk the fields to the operation, then to
    # the ub2-prefixed locator (and, for a WRITE, the 0x0E payload).
    rest = payload[1:]  # source_pointer_flag
    _loc_len_plus2, rest = decode_ub4(rest)
    rest = rest[1:]  # dest_pointer_flag
    _dest_length, rest = decode_ub4(rest)
    _short_src_off, rest = decode_ub4(rest)
    _short_dst_off, rest = decode_ub4(rest)
    rest = rest[3:]  # charset / short-amount / null-lob pointer flags
    operation, rest = decode_ub4(rest)
    if operation == TNS_LOB_OP_WRITE:
        rest = rest[2:]  # scn-array pointer + length
        _src_offset, rest = decode_ub4(rest)
        _dest_offset, rest = decode_ub4(rest)
        rest = rest[1:]  # amount pointer flag
        rest = rest[6:]  # three reserved ub2 array-LOB slots
        loc_len = struct.unpack('>H', rest[:2])[0]
        rest = rest[2:]
        locator = rest[:loc_len]
        rest = rest[loc_len:]
        if rest and rest[0] == 0x0E:
            rest = rest[1:]
        return LobOpsRequest(
            kind='write', locator=locator, payload=_decode_lobops_chunked(rest)
        )
    if operation == TNS_LOB_OP_FREE_TEMP:
        return LobOpsRequest(
            kind='free_temp', locator=_lobops_locator_after_operation(rest)
        )
    if operation in _LOBOPS_ACK_OPS:
        return LobOpsRequest(kind='ack', locator=_lobops_locator_after_operation(rest))
    # READ (the #413 column-LOB read) and anything else fall through to the read
    # path — unchanged, so an unrecognised op behaves as before rather than worse.
    return LobOpsRequest(kind='read')


def encode_create_temp_response(locator: bytes) -> bytes:
    """The CREATE_TEMP reply (#412): a bare TTI_RPA carrying the minted locator —
    0x08, ub2 length, then the locator bytes (what the client reads back)."""
    return bytes([TTI_RPA]) + struct.pack('>H', len(locator)) + locator


def encode_lobops_ack(locator: bytes) -> bytes:
    """A content-free TTI_LOBOPS reply: a TTI_RPA echoing the (ub2-prefixed)
    locator then a success OER. The client skips the locator via its length prefix
    and walks to the OER (``decode_lobops_oer``), so no real content is carried.
    Used for WRITE (#412) and for the FREE_TEMP / OPEN / CLOSE / TRIM /
    GET_CHUNK_SIZE state ops the Mirror acknowledges (#417)."""
    rpa = bytes([TTI_RPA]) + struct.pack('>H', len(locator)) + locator
    return rpa + _encode_oer(1, 0, 0, b'')


def _encode_refcursor_out(bind: RefCursorOutBind) -> bytes:
    # A REF CURSOR OUT value in the IOV's RXD (#483/#84), the inverse of the
    # client's _read_refcursor_out: a 1-byte length, the inline describe body
    # (the same per-column DCB metadata a describe carries), the nested cursor
    # id, and a 1-byte present indicator.
    return (
        bytes([1])  # length prefix (skipped by the client)
        + _encode_describe_body(bind.columns)
        + encode_sb4(bind.cursor_id)
        + bytes([1])  # per-value present indicator
    )


def encode_out_bind_response_thin(
    out_binds: list[ScalarOutBind | RefCursorOutBind],
) -> bytes:
    """The thin reply returning a PL/SQL block's OUT bind values (#483): a
    TTI_IOV vector + a TTI_RXD row of the values + a success OER.

    ``out_binds`` is one entry per bind, in bind order — the Mirror can't tell IN
    from OUT (the wire has no direction), so it marks them all OUT and returns
    each value; the client keeps only the positions it bound as a ``Var``
    (``_assign_out_binds``). A scalar rides as a DALC + ub4 return code; a REF
    CURSOR rides as its inline describe + cursor id. The IOV header mirrors what
    ``_read_iov`` decodes: a flag, the bind count (num_requests + num_iters*256),
    the zeroed iter / buffer / bit-vector / rowid fields, then a direction byte
    per bind."""
    count = len(out_binds)
    num_requests, num_iters = count % 256, count // 256
    iov = (
        bytes([TTI_IOV, 0])  # token + flag
        + encode_sb4(num_requests)
        + encode_sb4(num_iters)
        + encode_sb4(1)  # num iters this time
        + encode_sb4(0)  # uac buffer length
        + encode_sb4(0)  # fast-fetch bit vector length
        + encode_sb4(0)  # rowid length
        + bytes([TNS_BIND_DIR_OUTPUT]) * count  # direction per bind
    )
    rxd = bytearray([TTI_RXD])
    for bind in out_binds:
        if isinstance(bind, RefCursorOutBind):
            rxd += _encode_refcursor_out(bind)
        else:
            rxd += encode_value(bind.value, bind.tns_type) + encode_sb4(0)
    return iov + bytes(rxd) + encode_status(0)


def encode_returning_response(
    rowcount: int,
    iterations: list[list[tuple]],
    return_types: list[int],
    *,
    cursor_id: int = 0,
) -> bytes:
    """The reply to a `DML ... RETURNING col INTO :b` execute (#689).

    One `TTI_RXD` per execute iteration, then the ordinary success status. A
    plain execute is one iteration; an array execute is one per row submitted,
    and an iteration that matched nothing still sends its record, with a zero
    count, so the client's positions stay aligned with the rows it sent
    (docs/PROTOCOL.md 22 and 22.1).

    Within a record the values are grouped **by bind, not by row**: for each
    return bind in bind order, the number of rows that iteration affected, then
    that many values, each a DALC followed by an sb4 truncation length (always 0
    here -- the client discards it). ``iterations`` arrives the other way round,
    as the rows each iteration returned, so it is transposed here.
    """
    out = bytearray()
    for rows in iterations:
        out.append(TTI_RXD)
        for position, tns_type in enumerate(return_types):
            out += encode_sb4(len(rows))
            for row in rows:
                value = row[position] if position < len(row) else None
                out += encode_value(value, tns_type) + encode_sb4(0)
    return bytes(out) + encode_status(rowcount, cursor_id=cursor_id)


def scroll_start_row(orientation: int, position: int, total: int) -> int:
    """The 1-based absolute row a scroll re-execute positions on (#181/#485).

    FIRST -> row 1, LAST -> the final row. For ABSOLUTE / RELATIVE / CURRENT /
    NEXT the client resolves the request to an absolute target itself and sends
    it as ``position`` (oracledb thin's ``_post_process_scroll``), so the Mirror
    takes it verbatim. A result yields 0 (an off-the-end position) when empty.
    """
    if orientation == TNS_FETCH_ORIENTATION_FIRST:
        return 1
    if orientation == TNS_FETCH_ORIENTATION_LAST:
        return total
    return position


def _scroll_terminator(cursor_id: int, server_rowcount: int, eof: bool) -> bytes:
    # The OER that ends a scroll batch (#181/#485). It carries the cumulative
    # row number (the absolute 1-based position of the last row delivered) in the
    # rowcount field — the client reads it as ``server_rowcount`` to place its
    # buffer window — and reports ORA-01403 once the batch reaches the end so the
    # client stops pulling. The cursor id ties the opening execute's response to
    # the kept-open scrollable cursor; a re-execute carries no id (0).
    if eof:
        return _encode_oer(0, 1403, server_rowcount, b'', cursor_id=cursor_id)
    return _encode_oer(1, 0, server_rowcount, b'', cursor_id=cursor_id)


def encode_scroll_open_response(
    columns: list[ColumnMeta],
    rows: list[tuple],
    cursor_id: int,
    *,
    server_rowcount: int,
    eof: bool,
) -> bytes:
    """A scrollable open reply (#181/#485): describe + the prefetched first batch
    + a scroll terminator carrying the cursor id and cumulative row number. The
    cursor stays open (the client drives later scroll re-executes against it)."""
    return (
        encode_describe(columns)
        + encode_rows(rows, columns)
        + _scroll_terminator(cursor_id, server_rowcount, eof)
    )


def encode_scroll_response(
    columns: list[ColumnMeta],
    rows: list[tuple],
    *,
    server_rowcount: int,
    eof: bool,
) -> bytes:
    """A scroll re-execute reply (#181/#485): the repositioned batch + terminator,
    with **no** describe (the metadata was established on the open). An empty
    batch (scrolled off the end) is a bare ``ORA-01403`` terminator."""
    return encode_rows(rows, columns) + _scroll_terminator(0, server_rowcount, eof)


def parse_fetch(payload: bytes) -> FetchRequest:
    """Parse a ``TTI_FETCH`` message: ``[TTI_FUN, TTI_FETCH, seq]`` + ub4 cursor
    id + ub4 row count (the inverse of ``encode_dictionary_fetch``)."""
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_FETCH:
        raise InterfaceError('not a TTI_FETCH')
    rest = payload[3:]  # skip TTI_FUN, TTI_FETCH, seq
    cursor, rest = decode_ub4(rest)
    fetch, _rest = decode_ub4(rest)
    return FetchRequest(cursor=cursor, fetch=fetch)


# --- Mirror deadbeef/OCI: version-call, piggyback, re-exec, fetch terminator ---


# The classic sqlplus / thick-OCI (deadbeef) OALL8 marshals the same execute
# fields as the thin form above, but with the OCI conventions: an 8-byte
# 0xFE indicator (0xFFFFFFFFFFFFFFFE LE) stands in for each thin 0x01 pointer
# flag, and lengths are fixed 4-byte little-endian ub4s. For a single statement
# with no binds the header up to the SQL is a **fixed 195-byte preamble** (the
# token sequence is constant — verified across captured executes of different
# SQL lengths), so the SQL, a ub1-length-prefixed text field, sits at a fixed
# offset (#265). The preamble also carries 3x the SQL byte length as a ub4 (the
# worst-case max-byte buffer for the DB charset), which cross-checks the parse.
_OCI_ALL8_IND_OFF = 11  # the SQL pointer indicator; absent on a re-execute


def is_reexecute_oci(payload: bytes) -> bool:
    """True if an OCI OALL8 is a re-execute of an already-described cursor — it
    carries no SQL (the SQL pointer at offset 11 is absent). sqlplus issues one
    to pull a LONG / LONG RAW row after setting up its streaming define, so the
    Mirror answers it with the row it parked on the describe (#407)."""
    return (
        len(payload) > _OCI_ALL8_IND_OFF + 8
        and payload[0] == TTI_FUN
        and payload[1] == TTI_ALL8
        and payload[_OCI_ALL8_IND_OFF : _OCI_ALL8_IND_OFF + 8] != oci.OCI_INDICATOR
    )


def is_version_call_oci(payload: bytes) -> bool:
    """True if this is the sqlplus / thick-OCI post-login version request.

    The version call and the sqlplus ``PASSWORD`` changepassword both arrive as a
    TTI_80SES (``0x11 0x6b``) piggyback and share the same 15-byte prefix; they
    differ only in the wrapped TTI function (``0x3b`` version vs. ``TTI_AUTH``).
    Match the inner function too, so a piggybacked changepassword is not mistaken
    for the version request (and answered with the banner)."""
    return (
        payload[:2] == oci.OCI_VERSION_CALL
        and payload[_OCI_80SES_FIXED : _OCI_80SES_FIXED + 2] == b'\x03\x3b'
    )


def encode_version_banner_oci(banner: bytes) -> bytes:
    """Build the sqlplus / thick-OCI version reply — the server's banner (#265).

    Returns the TTC payload from the TTI_RPA token: the banner as a DALC value
    (ub2 count + single ub1 chunk, since the banner is well under 254 bytes) and
    the fixed packed-version trailer.
    """
    return (
        bytes([TTI_RPA])
        + len(banner).to_bytes(2, 'little')
        + bytes([len(banner)])
        + banner
        + b'\x00'  # DALC terminator
        + _OCI_VERSION_TRAILER
    )


# The classic sqlplus / thick-OCI OALL8 arrives wrapped in an OCCA (close-cursors)
# piggyback for every statement past the first: `0x11 0x69`, then a fixed prefix
# (seq, an 8-byte indicator, the ub4 cursor count, and one 8-byte entry per closed
# cursor), then the real TTI_FUN execute. Strip it so the execute can be parsed.
_OCI_PIGGYBACK = b'\x11\x69'


_OCI_PIGGYBACK_FIXED = 3 + 8 + 4  # 0x11 0x69 seq | indicator | ub4 count


# The version call and sqlplus PASSWORD changepassword instead arrive wrapped in
# a TTI_80SES (0x11 0x6b) piggyback: a fixed 15-byte prefix (0x11 0x6b, a seq
# byte, and a 12-byte session-switch preamble) then the real TTI_FUN call. The
# preamble length is constant across captures (only the seq/count bytes vary), so
# the inner call always starts at offset 15.
_OCI_PIGGYBACK_80SES = b'\x11\x6b'
_OCI_80SES_FIXED = 15


def strip_oci_piggyback(body: bytes) -> bytes:
    """Return the real TTI_FUN call inside an OCI piggyback, or ``body`` unchanged.

    Handles both wrappers the thick-OCI client uses: the OCCA close-cursors
    piggyback (``0x11 0x69``) around every execute past the first, and the
    TTI_80SES (``0x11 0x6b``) piggyback around the version call and the
    changepassword (:func:`is_version_call_oci` splits those two apart)."""
    if body[:2] == _OCI_PIGGYBACK:
        count = int.from_bytes(body[11:15], 'little')
        return body[_OCI_PIGGYBACK_FIXED + count * 8 :]
    if body[:2] == _OCI_PIGGYBACK_80SES:
        return body[_OCI_80SES_FIXED:]
    return body


_OCI_END_OF_FETCH_MSG = b'ORA-01403: no data found\n'


_OCI_FETCH_CONST_OFF = 73


# The OCI end-of-fetch terminator sqlplus reads after the execute's rows: an OER
# carrying ORA-01403 ("no data found"), which the client treats as "cursor
# drained" rather than an error (the thin path keeps the same thing as its
# captured _END_OF_FETCH). Reduced to structure by live bisection (#265): a
# 24-byte OER header (call status + the 1403 code) and one instance constant,
# the rest zero, then the message computed.
_OCI_FETCH_OER_LEN = 136


def encode_fetch_terminator_oci(sequence: int) -> bytes:
    """The sqlplus / thick-OCI end-of-fetch reply (ORA-01403 = cursor drained)."""
    header = _oci_fetch_oer_header(sequence)
    oer = bytearray(_OCI_FETCH_OER_LEN)
    oer[0 : len(header)] = header
    off = _OCI_FETCH_CONST_OFF
    oer[off : off + len(_OCI_FETCH_CONST)] = _OCI_FETCH_CONST
    return bytes(oer) + bytes([len(_OCI_END_OF_FETCH_MSG)]) + _OCI_END_OF_FETCH_MSG


# Packed server version returned in the auth result (AUTH_VERSION_NO), from a
# real XE 11.2 auth result: 186647040 = 11.2.0.x. On the wire all these values
# (session key, salt, proof) are uppercase-hex ASCII.
_SERVER_VERSION_NO = 186647040


def encode_rpa_kv(pairs: list[tuple[bytes, bytes]]) -> bytes:
    """A TTI_RPA payload carrying key-value pairs — the shared framing of every
    auth challenge / result RPA: the RPA token, the pair count, then each pair as
    a flag-1 key-value. Decodes back through :func:`decode_token_rpa`."""
    return (
        bytes([TTI_RPA])
        + encode_sb4(len(pairs))
        + b''.join(encode_kv(Key, Value, 1) for Key, Value in pairs)
    )


def encode_token_result(
    *, session_id: int = 0, version_no: int = _SERVER_VERSION_NO
) -> bytes:
    """The token-auth result RPA — version + session id, and no server proof
    (token auth has no ConnKey, so there is nothing for the client to validate)."""
    return encode_rpa_kv(
        [
            (b'AUTH_VERSION_NO', str(version_no).encode('ascii')),
            (b'AUTH_SESSION_ID', str(session_id).encode('ascii')),
        ]
    )


@dataclass(frozen=True)
class Challenge:
    """The per-connection O5LOGON challenge state, held until the response."""

    salt: bytes
    server_session: bytes
    key_sess: bytes
    auth_sesskey: bytes  # the AUTH_SESSKEY value put on the wire


def _hexval(raw: bytes) -> bytes:
    # The wire form for AUTH_SESSKEY / AUTH_VFR_DATA / AUTH_SVR_RESPONSE: an
    # uppercase-hex ASCII string (the client bytes.fromhex()es it back).
    return raw.hex().upper().encode('ascii')


def encode_challenge(challenge: Challenge) -> bytes:
    """The auth-challenge RPA payload — AUTH_SESSKEY + the salt (AUTH_VFR_DATA).

    Returns the TTC payload starting at the TTI_RPA token, ready for
    ``PacketStream.write_packet(TNS_DATA, …)``. Decodes back through the
    client's ``decode_token_rpa`` as a ``TTI_SESS`` challenge.
    """
    return encode_rpa_kv(
        [
            (b'AUTH_SESSKEY', _hexval(challenge.auth_sesskey)),
            (b'AUTH_VFR_DATA', _hexval(challenge.salt)),
        ]
    )


# --- Generating the sqlplus / thick-OCI (deadbeef dialect) O5LOGON packets ---
#
# The challenge and result are lists of AUTH_* key-value pairs in the OCI dialect
# (the read side is _oci_auth_value) behind the 10-byte TNS DATA header, followed
# by a fixed capability/status trailer. Everything except the crypto values and
# the salt is the Mirror's constant pinned-11g identity, captured once from a live
# XE 11.2 server. encode_kv_oci computes the framing so the packets are generated
# rather than replayed verbatim; the byte-for-byte match to the original captures
# is pinned by tests/test_oci_auth_generation.py (#265).

# The 11g SHA-1 password verifier type (crypto.VFR_11G_SHA1) is carried as
# AUTH_VFR_DATA's trailing flag.

# The Mirror's fixed 11g identity, from the live XE 11.2 capture. The
# session-identity fields (AUTH_SESSION_ID / _SERIAL_NUM / _SERVER_PID) are kept
# as captured — the client does not cryptographically check them. AUTH_SVR_RESPONSE
# is the one per-login value and is appended by encode_result_oci.


def encode_result(
    session_key: bytes,
    *,
    session_id: int = 0,
    version_no: int = _SERVER_VERSION_NO,
) -> bytes:
    """The auth-result RPA payload — the server proof, version, and session id.

    Decodes back through ``decode_token_rpa`` as a ``TTI_AUTH`` result whose
    ``AUTH_SVR_RESPONSE`` the client's ``validate()`` accepts.
    """
    return encode_rpa_kv(
        [
            (b'AUTH_SVR_RESPONSE', _hexval(server_proof(session_key))),
            (b'AUTH_VERSION_NO', str(version_no).encode('ascii')),
            (b'AUTH_SESSION_ID', str(session_id).encode('ascii')),
        ]
    )


def decode_token_iov(Data: bytes, Acc: tuple) -> tuple:
    # I/O vector for an anonymous PL/SQL block's binds (section 6.5). Layout
    # cross-referenced with python-oracledb's _process_io_vector and verified
    # against XE 11g captures.
    #
    #   1B   token (TTI_IOV)
    #   ub1  flag                                   (skip)
    #   ub2  num_requests  \  num_binds =
    #   ub4  num_iters     /    num_iters*256 + num_requests
    #   ub4  num iters this time                    (skip)
    #   ub2  uac buffer length                      (skip)
    #   ub2  fast-fetch bit vector length + bytes   (skip)
    #   ub2  rowid length + bytes                   (skip)
    #   per bind: ub1 direction (16=OUT, 32=IN, 48=IN OUT)
    #
    # When any bind is OUT / IN OUT the server then sends the returned values
    # as a TTI_RXD row: each value is a DALC blob followed by a 1-byte
    # indicator. We keep the raw value bytes here (decoding needs the bind's
    # type, which only the cursor knows) and surface them through the Rows
    # accumulator as an {'out_*': ...} record the cursor maps back onto its
    # bind variables.
    (Cursor, RowFormat, Rows) = Acc[:3]
    Binds = Acc[3] if len(Acc) > 3 else None
    (Directions, OutValues, Rest) = _read_iov(Data, Binds)
    OutPositions = [I for I, D in enumerate(Directions) if D != TNS_BIND_DIR_INPUT]
    if OutPositions:
        Rows = Rows + [
            {
                'out_positions': OutPositions,
                'out_values': OutValues,
                'directions': Directions,
            }
        ]
    return decode_packet(Rest, (Cursor, RowFormat, Rows))


def _is_refcursor_bind(Bind: object) -> bool:
    if isinstance(Bind, Var):
        return Bind.dbtype.tns_type == TNS_TYPE_REFCURSOR
    return isinstance(Bind, RefCursorBind)


def _read_iov(
    Data: bytes, Binds: list | None = None
) -> tuple[list[int], list[object], bytes]:
    # Parse a TTI_IOV body starting at the token byte. Returns the per-bind
    # direction codes, the OUT/IN-OUT values (in OUT-bind order), and the
    # unconsumed tail (the RPA / OER that follow). See decode_token_iov.
    #
    # A scalar OUT value is raw DALC bytes (the cursor decodes it by the bind's
    # type). A REF CURSOR OUT value is instead an inline describe + cursor id;
    # it is returned as a {'_refcursor': True, 'cursor_id', 'row_format'} record
    # the cursor turns into a nested Cursor. Detecting which is which needs the
    # bind list, threaded in via the decode Acc.
    Rest = Data[1:]  # consume IOV token
    Rest = Rest[1:]  # skip flag (ub1)
    (NumRequests, Rest) = decode_ub4(Rest)
    (NumIters, Rest) = decode_ub4(Rest)
    NumBinds = NumIters * 256 + NumRequests
    (_, Rest) = decode_ub4(Rest)  # num iters this time
    (_, Rest) = decode_ub4(Rest)  # uac buffer length
    (BvLen, Rest) = decode_ub4(Rest)  # fast-fetch bit vector
    if BvLen > 0:
        Rest = Rest[BvLen:]
    (RidLen, Rest) = decode_ub4(Rest)  # rowid
    if RidLen > 0:
        Rest = Rest[RidLen:]
    Directions = [Rest[I] for I in range(NumBinds)]
    Rest = Rest[NumBinds:]
    HasOut = any(D != TNS_BIND_DIR_INPUT for D in Directions)
    OutValues: list = []
    if HasOut and Rest and Rest[0] == TTI_RXD:
        Rest = Rest[1:]  # consume RXD token
        for Idx, D in enumerate(Directions):
            if D == TNS_BIND_DIR_INPUT:
                continue
            Bind = Binds[Idx] if Binds and Idx < len(Binds) else None
            if _is_refcursor_bind(Bind):
                (Value, Rest) = _read_refcursor_out(Rest)
                OutValues.append(Value)
            elif Bind is not None and getattr(Bind, 'is_array', False):
                # Associative-array OUT (#122): a ub4 element count, then each
                # element as a DALC value + indicator. Kept as a list of raw
                # element bytes; the cursor decodes them by the Var's type.
                (Count, Rest) = decode_ub4(Rest)
                Elements = []
                for _ in range(Count):
                    (Val, Rest) = decode_dalc(Rest)
                    (_, Rest) = decode_ub4(Rest)  # per-element return code
                    Elements.append(b'' if Val == [] else bytes(Val))
                OutValues.append({'_array': True, 'values': Elements})
            else:
                (Val, Rest) = decode_dalc(Rest)
                # The per-value return code is a variable-length integer, not a
                # fixed byte: a non-NULL value's code is ub4(0) = one 0x00 byte,
                # but a NULL value's is ub4(-1) = 0x81 0x01 (two bytes). Skipping
                # a fixed byte desynced the decoder on a NULL OUT bind.
                (_, Rest) = decode_ub4(Rest)
                OutValues.append(b'' if Val == [] else bytes(Val))
    return (Directions, OutValues, Rest)


def _read_refcursor_out(Rest: bytes) -> tuple[dict, bytes]:
    # A REF CURSOR OUT value: a 1-byte length, then an inline describe (max row
    # size, num columns, the same per-column metadata as a DCB), then the
    # nested cursor id (ub2) and a 1-byte indicator. Mirrors oracledb's
    # _create_cursor_from_describe; byte layout verified against XE 11g.
    Rest = Rest[1:]  # skip_ub1 (length)
    (_, Rest) = decode_ub4(Rest)  # max row size
    (NumCols, Rest) = decode_ub4(Rest)
    if NumCols > 0:
        Rest = Rest[1:]  # reserved byte
    Columns = []
    for _ in range(NumCols):
        (Col, Rest) = _decode_dcb_column(Rest)
        Columns.append(Col)
    Rest = _skip_bytes_with_length(Rest)  # current date
    for _ in range(4):  # dcbflag / mdbz / mnpr / mxpr
        (_, Rest) = decode_ub4(Rest)
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_11_2:
        # dcbqcky (query-cache key) is an 11g addition; a 10g (field version 4)
        # nested-cursor describe ends after the four ub4 flags. Skipping a
        # phantom one here consumes the cursor id and desyncs the IOV decode of
        # a REF CURSOR OUT bind (#84) — same pre-11g gap as decode_token_dcb.
        Rest = _skip_bytes_with_length(Rest)  # dcbqcky
    (CursorId, Rest) = decode_ub4(Rest)
    Rest = Rest[1:]  # per-value indicator byte
    return ({'_refcursor': True, 'cursor_id': CursorId, 'row_format': Columns}, Rest)


def decode_token_lob(Data: bytes, Acc: tuple) -> tuple:
    # Defensive no-op for a TTI_LOB token seen in the general decode path. Real
    # LOB content is read by the dedicated _read_lob_response loop (see
    # lob_read), which walks TTI_LOB / RPA / OER itself — it doesn't route
    # through here.
    logger.debug('decode_token_lob: ignored (handled in _read_lob_response)')
    return (True, Acc)


def decode_token_net(Data: bytes, Acc: tuple) -> None:
    pass


def _read_batch_ub4_array(Rest: bytes) -> tuple[list, bytes]:
    # An array-DML batch field (#18): a ub4 count, then a DALC blob packing
    # that many ub4 values back-to-back. Returns the values and the remaining
    # bytes. Used for the batch-error code and row-offset arrays.
    (Count, Rest) = decode_ub4(Rest)
    if Count <= 0:
        return ([], Rest)
    (Blob, Rest) = decode_dalc(Rest)
    Buf = bytes(Blob) if not isinstance(Blob, list) else b''
    Values = []
    for _ in range(Count):
        (Value, Buf) = decode_ub4(Buf)
        Values.append(Value)
    return (Values, Rest)


def decode_token_oer(Data: bytes, Acc: tuple) -> tuple:
    # OER ("Oracle Error" return-status TTC token; emitted at the end of every
    # server response — success or failure). Unified layout: every field is
    # always present and we walk through them sequentially rather than
    # branching on success-vs-error. The trailing length-prefixed bytes are
    # the human-readable message ("ORA-NNNNN: ...") which the server
    # populates when the error number is non-zero.
    #
    # Field order cross-referenced with python-oracledb's _process_error_info,
    # adjusted for Oracle 11g: the extended ub4 error number + ub8 rowcount
    # that 12c+ adds are not present, so the message DALC comes directly
    # after the batch-error-messages count.
    (Cursor, RowFormat, Rows) = Acc[:3]
    # Array-DML row counts threaded in by decode_token_rpa_piggyback (the RPA
    # carrying them precedes this OER); None for a normal execute (#18).
    RowCounts = Acc[4] if len(Acc) > 4 else None
    Rest = Data[1:]  # consume the OER token
    (CallStatus, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)  # end-to-end seq#
    # In 11g the "current row number" field doubles as the DML affected-row
    # count: UPDATE/DELETE/INSERT set it to the number of rows touched by
    # the call. 12c+ moved the rowcount to a separate ub8 at the end of the
    # OER, but we don't have that here.
    (RowCount, Rest) = decode_ub4(Rest)
    (ErrCode, Rest) = decode_ub4(Rest)  # ORA-NNNN error number
    (_, Rest) = decode_ub4(Rest)  # array elem error #1
    (_, Rest) = decode_ub4(Rest)  # array elem error #2
    (CursorId, Rest) = decode_ub4(Rest)  # current cursor id
    (ErrorPos, Rest) = decode_ub4(Rest)  # error position (parse offset into the SQL)
    Rest = Rest[6:]  # 6 single-byte fields:
    #   sql_type, fatal,
    #   flags, user_cursor_opts,
    #   upi_param, warn_flags
    # rowid of the (last) row the statement touched — same physical-rowid
    # layout as a ROWID column (see _read_rowid_column): data object number,
    # relative file number, an unused byte, block number, slot number.
    (RowidObj, Rest) = decode_ub4(Rest)  # data object number
    (RowidFile, Rest) = decode_ub4(Rest)  # relative file number
    Rest = Rest[1:]  # rowid reserved byte
    (RowidBlock, Rest) = decode_ub4(Rest)  # block number
    (RowidSlot, Rest) = decode_ub4(Rest)  # slot number
    (_, Rest) = decode_ub4(Rest)  # os error
    Rest = Rest[2:]  # statement #, call #
    (_, Rest) = decode_ub4(Rest)  # padding (ub2)
    (_, Rest) = decode_ub4(Rest)  # successful iterations
    #   (always 1 for a
    #   single non-array
    #   execute on 11g — the
    #   real DML rowcount is
    #   the "current row
    #   number" field above)
    Rest = _skip_bytes_with_length(Rest)  # oerrdd (logical rowid)
    # Batch error code / offset / message arrays (array-DML `batcherrors`
    # mode, #18). For plain statements all three counts are zero and the loops
    # never run. When set, the three arrays line up by position: error i hit
    # row `BatchOffsets[i]` with ORA-`BatchCodes[i]` and text `BatchMessages[i]`.
    # Batch error code / offset / message arrays (array-DML `batcherrors`
    # mode, #18). For plain statements all three counts are zero and the loops
    # never run. Layout (reverse-engineered against a 21c capture): each of the
    # code and offset arrays is `ub4 count | DALC blob`, where the blob packs
    # the count ub4 values (the DALC is the 0xFE chunked form once it grows).
    # The message array is `ub4 count | ub1 indicator | count × (ub4-prefixed
    # string + 2-byte trailer)`. Error i hit row BatchOffsets[i] with
    # ORA-BatchCodes[i] and text BatchMessages[i].
    (BatchCodes, Rest) = _read_batch_ub4_array(Rest)
    (BatchOffsets, Rest) = _read_batch_ub4_array(Rest)
    BatchMessages: list = []
    (NumBatchMessages, Rest) = decode_ub4(Rest)
    if NumBatchMessages > 0:
        Rest = Rest[1:]  # indicator byte
        for _ in range(NumBatchMessages):
            (MsgBytes, Rest) = _read_str_with_length(Rest)
            Rest = Rest[2:]  # 2-byte trailer
            BatchMessages.append(
                bytes(MsgBytes).decode('utf-8', errors='replace').rstrip()
            )
    BatchErrors = [
        {
            'offset': BatchOffsets[I] if I < len(BatchOffsets) else None,
            'code': BatchCodes[I] if I < len(BatchCodes) else None,
            'message': BatchMessages[I] if I < len(BatchMessages) else None,
        }
        for I in range(max(len(BatchOffsets), len(BatchCodes), len(BatchMessages)))
    ]
    # On 11g the trailing message DALC comes right here. 12c+ inserts the
    # extended-precision error number (ub4) and rowcount (ub8) ahead of it, and
    # 20.1+ adds a ub4 sql type + ub4 server checksum (oracledb
    # _process_error_info). Skip them so the message DALC stays aligned.
    FieldVersion = _DECODE_FIELD_VERSION.get()
    if FieldVersion >= FIELD_VERSION_12_1:
        (_, Rest) = decode_ub4(Rest)  # extended error number
        (_, Rest) = decode_ub4(Rest)  # extended rowcount (ub8)
        if FieldVersion >= FIELD_VERSION_20_1:
            (_, Rest) = decode_ub4(Rest)  # sql type
            (_, Rest) = decode_ub4(Rest)  # server checksum
    Message = None
    if ErrCode != 0 and Rest:
        try:
            (Bytes, _) = decode_dalc(Rest)
        except IndexError:
            Bytes = None
        if Bytes:
            try:
                Message = bytes(Bytes).decode('utf-8', errors='replace').rstrip()
            except (TypeError, AttributeError):
                Message = None
    # Render the touched-row rowid (block 0 is the file header — never a data
    # row — so treat it as "no rowid", e.g. SELECT / DDL).
    Rowid = None
    if RowidBlock:
        from seerdb.common.types import rowid_to_string

        Rowid = rowid_to_string(RowidObj, RowidFile, RowidBlock, RowidSlot)
    RetFormat = (RowCount, RowFormat)
    return (
        CallStatus,
        ErrCode,
        CursorId,
        RetFormat,
        Rows,
        Message,
        Rowid,
        BatchErrors,
        RowCounts,
        ErrorPos,
    )


def decode_lobops_oer(Packet: bytes, FieldVersion: int) -> tuple[int, str | None]:
    # Pull the (error code, message) out of a content-free TTI_LOBOPS response
    # (WRITE / temp ops): TTI_RPA (updated locator + amount) optionally followed
    # by a trailing charset, then TTI_OER. The RPA's locator is binary and may
    # contain a 0x04 byte, so skip past it (using its ub2 length) before
    # scanning for the OER token — otherwise the scan can false-match inside the
    # locator. The OER call status is NOT fixed (1 for a standalone op, 5 right
    # after a PL/SQL call), so match the token + a valid ub4 length only, never
    # a specific status value.
    _DECODE_FIELD_VERSION.set(FieldVersion)
    Pos = 0
    if Packet and Packet[0] == TTI_RPA and len(Packet) >= 3:
        Pos = 3 + ((Packet[1] << 8) | Packet[2])  # skip ub2-prefixed locator
    while Pos < len(Packet) - 1:
        if Packet[Pos] == TTI_OER and 1 <= Packet[Pos + 1] <= 4:
            Result = decode_token_oer(Packet[Pos:], (None, None, []))
            return (Result[1], Result[5] if len(Result) > 5 else None)
        Pos += 1
    return (0, None)


def decode_oac_fields(Data: bytes) -> tuple[int, int, int, int, int, bytes, bytes]:
    # The full OAC field set, including the charset form (csfrm) byte the common
    # 5-tuple form skips, and the referenced type's OID (an object / REF bind,
    # #116/#139). csfrm distinguishes national char data (2 → AL16UTF16 /
    # UTF-16BE) from ordinary char data (1) — the server needs it to decode an
    # NCHAR / NVARCHAR bind (#484). Returns (DataType, MaxDataLength, DataScale,
    # Charset, Csfrm, ToId, Rest).
    (DataType, Flg, Pre) = struct.unpack('>BBB', Data[:3])
    (DataScale, R0) = decode_ub4(Data[3:])
    (MaxDataLength, R1) = decode_ub4(R0)
    (Mal, R2) = decode_ub4(R1)
    (Fl2, R3) = decode_ub4(R2)
    # The type OID is written with two lengths (write_bytes_with_two_lengths): a
    # ub4 count then, only when non-empty, the length-prefixed bytes — not a
    # plain DALC. An empty OID (every scalar bind) is a single 0x00 under either
    # reading, but a real OID (object type 109 / REF type 111, #139) is 16 bytes
    # behind the ub4 count, and reading it as a bare DALC desyncs the whole OAC.
    (ToIdLen, R3a) = decode_ub4(R3)
    if ToIdLen:
        (ToIdRaw, R4) = decode_dalc(R3a)
        ToId = bytes(ToIdRaw) if not isinstance(ToIdRaw, list) else b''
    else:
        ToId, R4 = b'', R3a
    (VSN, R5) = decode_ub4(R4)
    (Charset, R6) = decode_ub4(R5)
    Csfrm = R6[0]
    (Mxlc, R7) = decode_ub4(R6[1:])
    return (DataType, MaxDataLength, DataScale, Charset, Csfrm, ToId, R7)


def decode_token_oac(Data: bytes, Acc: tuple) -> tuple[int, int, int, int, bytes]:
    (DataType, MaxDataLength, DataScale, Charset, _Csfrm, _ToId, Rest) = (
        decode_oac_fields(Data)
    )
    return (DataType, MaxDataLength, DataScale, Charset, Rest)


def decode_token_rpa(Data: bytes, Acc: tuple) -> tuple:
    (Num, Rest0) = decode_ub4(Data)
    Flags: dict = {}
    (KVs, Rest1) = decode_kv(Rest0, Num, [], Flags)
    SessKey = dict(KVs).get(b'AUTH_SESSKEY')
    Salt = dict(KVs).get(b'AUTH_VFR_DATA')
    DerivedSalt = dict(KVs).get(b'AUTH_PBKDF2_CSK_SALT')
    Resp = dict(KVs).get(b'AUTH_SVR_RESPONSE')
    Value = dict(KVs).get(b'AUTH_VERSION_NO')
    # An auth *result* carries either the server proof (O5LOGON) or — for token
    # auth (#125), which has no ConnKey and no proof — just the version + session
    # id with no session-key challenge. A *challenge* always carries AUTH_SESSKEY.
    if Resp or (SessKey is None and Value is not None):
        # Keep the full packed version number; the connection decodes the major
        # release (>> 24) for its protocol gate and the full dotted string for
        # the `version` property.
        Ver = 0 if Value is None else int(Value)
        SessId = dict(KVs).get(b'AUTH_SESSION_ID')
        return (TTI_AUTH, Resp, Ver, SessId)
    else:
        # The 256-bit scheme carries the server's PBKDF2 iteration counts; the
        # client must derive the key with these, not hardcoded defaults (#309).
        # Absent (10g/11g) → None, and the crypto falls back to the defaults.
        VgenRaw = dict(KVs).get(b'AUTH_PBKDF2_VGEN_COUNT')
        SderRaw = dict(KVs).get(b'AUTH_PBKDF2_SDER_COUNT')
        VgenCount = int(VgenRaw) if VgenRaw else None
        SderCount = int(SderRaw) if SderRaw else None
        # The AUTH_VFR_DATA flag names the verifier type (SHA-1 vs SHA-2 vs
        # legacy) — needed to pick the right key schedule on a modern server for
        # a pre-SHA-2 account (#311).
        VerifierType = Flags.get(b'AUTH_VFR_DATA')
        return (
            TTI_SESS,
            SessKey,
            Salt,
            DerivedSalt,
            VgenCount,
            SderCount,
            VerifierType,
        )


def decode_token_pro(Data: bytes) -> dict:
    """Decode a TTI_PRO (protocol negotiation) server response.

    Returns the server's TTC protocol version byte, banner, and the two
    length-prefixed capability arrays (compile-time TNS_CCAP_* and runtime
    TNS_RCAP_*). `Data` starts at the message-type byte (== TTI_PRO). The
    field version the server advertises is `compile_caps[CCAP_FIELD_VERSION]`;
    the connection negotiates the effective version as min(client, server).
    Layout mirrors python-oracledb's protocol.pyx (docs/PROTOCOL.md §4.1)."""
    Off = 1  # skip the message-type byte
    ServerVersion = Data[Off]
    Off += 2  # version byte + a trailing zero
    End = Data.index(0, Off)  # NUL-terminated banner
    Banner = Data[Off:End]
    Off = End + 1
    Off += 2  # charset_id (ub2 LE)
    Off += 1  # server flags
    NumElem = int.from_bytes(Data[Off : Off + 2], 'little')
    Off += 2 + NumElem * 5  # skip the charset-element array
    FdoLen = int.from_bytes(Data[Off : Off + 2], 'big')
    Off += 2 + FdoLen  # skip the FDO blob
    CcLen = Data[Off]
    Off += 1
    CompileCaps = Data[Off : Off + CcLen]
    Off += CcLen
    RcLen = Data[Off]
    Off += 1
    RuntimeCaps = Data[Off : Off + RcLen]
    return {
        'server_version': ServerVersion,
        'banner': Banner,
        'compile_caps': CompileCaps,
        'runtime_caps': RuntimeCaps,
    }


_KNOWN_TTI_TOKENS = frozenset(
    (
        TTI_OER,
        TTI_RXH,
        TTI_RXD,
        TTI_RPA,
        TTI_STA,
        TTI_IOV,
        TTI_UDS,
        TTI_OAC,
        TTI_LOB,
        TTI_WRN,
        TTI_DCB,
        TTI_FOB,
        TTI_BVC,
    )
)


def decode_token_server_piggyback(Data: bytes, Acc: tuple) -> tuple:
    # Server-side piggyback (#130): a session-state block the server prepends to
    # a response. DRCP-pooled sessions carry SESS_RET (the assigned session id /
    # serial + any session-state key/value pairs) and OS_PID_MTS; consume it
    # byte-for-byte (the values are not needed) and continue with the rest of the
    # response. Mirrors python-oracledb _process_server_side_piggyback. ub2/ub4
    # are the variable-length form (decode_ub4); skip_ub1 is one raw byte;
    # skip_bytes is a single-byte/0xFE-chunked value (decode_dalc).
    Rest = Data[1:]
    Opcode = Rest[0]
    Rest = Rest[1:]
    if Opcode == TNS_SERVER_PIGGYBACK_SESS_RET:
        (_, Rest) = decode_ub4(Rest)  # number of DTYs (ub2)
        Rest = Rest[1:]  # length of DTYs (ub1)
        (NumElements, Rest) = decode_ub4(Rest)  # number of pairs (ub2)
        if NumElements > 0:
            Rest = Rest[1:]  # skip_ub1
            for _ in range(NumElements):
                (KeyLen, Rest) = decode_ub4(Rest)
                if KeyLen > 0:
                    (_, Rest) = decode_dalc(Rest)
                (ValLen, Rest) = decode_ub4(Rest)
                if ValLen > 0:
                    (_, Rest) = decode_dalc(Rest)
                (_, Rest) = decode_ub4(Rest)  # pair flags (ub2)
        (_, Rest) = decode_ub4(Rest)  # session flags (ub4)
        (_, Rest) = decode_ub4(Rest)  # session id (ub4)
        (_, Rest) = decode_ub4(Rest)  # serial number (ub2)
    elif Opcode == TNS_SERVER_PIGGYBACK_OS_PID_MTS:
        (_, Rest) = decode_ub4(Rest)  # ub2
        (_, Rest) = decode_dalc(Rest)  # pid bytes
    elif Opcode == TNS_SERVER_PIGGYBACK_SYNC:
        # Sessionless transactions (#133): the server reports txn-id sync state
        # as keyword-value pairs (keyword 201 = transaction id) piggybacked on
        # the next call response while a sessionless txn is active. seerdb
        # tracks the active flag client-side, so the pairs are only consumed
        # byte-for-byte here. Each pair = ub2 text-len + dalc / ub2 binary-len +
        # dalc / ub2 keyword-num, framed like the SESS_RET pair loop.
        (_, Rest) = decode_ub4(Rest)  # number of DTYs (ub2)
        Rest = Rest[1:]  # length of DTYs (ub1)
        (NumElements, Rest) = decode_ub4(Rest)  # number of pairs (ub2)
        Rest = Rest[1:]  # length (ub1)
        for _ in range(NumElements):
            (TextLen, Rest) = decode_ub4(Rest)  # text value len (ub2)
            if TextLen > 0:
                (_, Rest) = decode_dalc(Rest)
            (BinLen, Rest) = decode_ub4(Rest)  # binary value len (ub2)
            if BinLen > 0:
                (_, Rest) = decode_dalc(Rest)
            (_, Rest) = decode_ub4(Rest)  # keyword num (ub2)
        (_, Rest) = decode_ub4(Rest)  # overall flags (ub4)
    elif Opcode == TNS_SERVER_PIGGYBACK_LTXID:
        (_, Rest) = decode_dalc(Rest)  # logical transaction id
    elif Opcode in (
        TNS_SERVER_PIGGYBACK_QUERY_CACHE_INVALIDATION,
        TNS_SERVER_PIGGYBACK_TRACE_EVENT,
    ):
        pass  # no body
    else:
        raise Exception('Unhandled server-side piggyback opcode', Opcode, Data)
    return decode_packet(Rest, Acc)


def decode_token_rpa_piggyback(Data: bytes, Acc: tuple) -> tuple:
    # Walks past a server-side session-state piggyback so the next decode_packet
    # call lands on the real status token (OER). The block layout is opaque
    # enough that empirically what works is: read Num, consume that many
    # ub4-encoded fields, skip trailing alignment zeros, then continue.
    Rest = Data[1:]
    try:
        (Num, Rest) = decode_ub4(Rest)
    except IndexError:
        return (True, Acc)
    # On fv2 (9i) Num over-counts and the params end at the real status token, so
    # stop early on a known token byte. From fv4 up Num is exact, and a scrollable
    # cursor's position parameter has a value whose length byte (0x04) collides
    # with the OER token — so there we must consume exactly Num and not break on a
    # token-valued param byte, or the OER decodes off by those bytes (#181).
    BreakOnToken = _DECODE_FIELD_VERSION.get() < FIELD_VERSION_10_2
    for _ in range(max(Num, 0)):
        if not Rest or (BreakOnToken and Rest[0] in _KNOWN_TTI_TOKENS):
            break
        try:
            (_, Rest) = decode_ub4(Rest)
        except IndexError:
            return (True, Acc)
    while Rest and Rest[0] == 0:
        Rest = Rest[1:]
    # Array-DML row counts (#18): when the execute requested arraydmlrowcounts
    # the server appends a `ub4 count | count×ub4` block here, between the RPA
    # body and the trailing OER — the per-iteration affected-row counts. Without
    # it the RPA always ends on a known TTI token (the OER), so a non-token byte
    # at this point is the row-count block. Pull it out and stash it on Acc so
    # decode_token_oer can fold it into the result; the surrounding RPA fields
    # stay opaque as before.
    if _DECODE_DML_ROWCOUNTS.get() and Rest and Rest[0] not in _KNOWN_TTI_TOKENS:
        try:
            (Count, R2) = decode_ub4(Rest)
            Counts = []
            for _ in range(Count):
                (C, R2) = decode_ub4(R2)
                Counts.append(C)
        except IndexError:
            # Speculative decode: if reading the count/values runs off the end of
            # the buffer this wasn't a row-count block after all — leave Rest/Acc
            # untouched (the `else` only commits R2 on a clean parse).
            pass
        else:
            Rest = R2
            Acc = tuple(Acc) + (Counts,)
    if Rest:
        return decode_packet(Rest, Acc)
    return (True, Acc)


def decode_token_uds(Data: bytes, Acc: tuple) -> tuple:
    # User describe information
    # Contains OAC descriptor for a single column
    (Cursor, RowFormat, Rows) = Acc[:3]
    (DataType, MaxDataLength, DataScale, Charset, Rest) = decode_token_oac(Data[1:], ())
    NullOk = Rest[0]
    (ColName, Rest) = decode_dalc(Rest[1:])
    (SchemaName, Rest) = decode_dalc(Rest)
    (TypeName, Rest) = decode_dalc(Rest)
    ColPos = Rest[0]
    Rest = Rest[1:]
    Col = {
        'column_name': ColName,
        'data_type': DataType,
        'data_length': MaxDataLength,
        'data_scale': DataScale,
        'charset': Charset,
        'null_ok': NullOk,
        'position': ColPos,
    }
    NewFormat = RowFormat + [Col] if isinstance(RowFormat, list) else [Col]
    return decode_packet(Rest, (Cursor, NewFormat, Rows))


# A native JSON column (21c+, #30) is delivered exactly like a BLOB: the RXD
# carries a LOB locator and the OSON image comes back over TTI_LOBOPS. We read
# it through the same locator path and decode the OSON in `LOB.read()`. A native
# VECTOR column (23ai+, #55) works the same way — locator + binary image.
_LOB_DATA_TYPES = frozenset(
    (TNS_TYPE_CLOB, TNS_TYPE_BLOB, TNS_TYPE_BFILE, TNS_TYPE_JSON, TNS_TYPE_VECTOR)
)
_ROWID_DATA_TYPES = frozenset((TNS_TYPE_RID,))
_UROWID_DATA_TYPES = frozenset((TNS_TYPE_UROWID,))
_LONG_DATA_TYPES = frozenset((TNS_TYPE_LONG, TNS_TYPE_LONGRAW))


def _decode_rxd_step(Data: bytes, Acc: tuple) -> tuple:
    # One row of RXD data. Returns ``(Rest, NewAcc)`` — the continuation
    # decode_packet loops on — rather than recursing, so a large fetch batch (one
    # RXD per row) cannot overflow the stack. The new row is appended to the Rows
    # list in place (not ``Rows + [Row]``), which is also O(n) over the batch
    # instead of O(n^2). :func:`decode_token_rxd` wraps this for direct callers.
    Val: Any  # reused per column, heterogeneous
    # Row data (section 6.2). Each column value is normally a DALC blob whose
    # raw bytes we hand to seerdb.common.types.decode_value, which dispatches on the
    # column's TNS data type from the describe-info block.
    #
    # LOB columns are special: instead of a single DALC they carry a small
    # length-prefixed locator block (`_read_lob_column`). The locator and
    # any inline content stay opaque for now — surfaced to the caller as an
    # seerdb.common.lob.LOB object — until the LOB-content extraction work lands.
    #
    # If a BVC token preceded this RXD, Acc carries a bit vector: a set bit
    # means "this column is in the RXD"; an unset bit means "reuse the
    # previous row's value". The bit vector applies to a single RXD and is
    # cleared from Acc on the way out.
    from seerdb.common.lob import LOB
    from seerdb.common.types import decode_value

    (Cursor, RowFormat, Rows, *Extra) = Acc
    BitVec = Extra[0] if Extra else None
    Rest = Data[1:]
    ReturnPositions = _DECODE_RETURN_BINDS.get()
    if ReturnPositions:
        # DML RETURNING ... INTO (#120): this RXD is out-bind return data, not
        # query rows. Per return bind: ub4 num_rows, then per affected row a
        # length-prefixed value + an sb4 truncation length (discarded). Keep the
        # raw value bytes; the cursor decodes them by each Var's type. Surfaced
        # as a record the cursor maps onto its return Vars (one list per bind).
        ReturnValues = []
        for _ in ReturnPositions:
            (NumRows, Rest) = decode_ub4(Rest)
            Vals = []
            for _Row in range(NumRows):
                (Val, Rest) = decode_dalc(Rest)
                (_, Rest) = decode_ub4(Rest)  # sb4 actual length (trunc)
                Vals.append(Val)
            ReturnValues.append(Vals)
        Record = {
            'return_positions': list(ReturnPositions),
            'return_values': ReturnValues,
        }
        Rows.append(Record)
        return (Rest, (Cursor, RowFormat, Rows))
    Row = []
    if RowFormat:
        # Reused (bit-unset) columns copy the previous row. Within a response
        # that's the last accumulated row; for the first row of a scroll
        # re-execute it's the prior batch's last row, seeded via _DECODE_PREV_ROW
        # (#181) since duplicate detection is otherwise per-response.
        PrevRow = Rows[-1] if Rows else _DECODE_PREV_ROW.get()
        for Idx, Col in enumerate(RowFormat):
            if BitVec is not None and not _bvc_bit_set(BitVec, Idx):
                Row.append(PrevRow[Idx] if PrevRow else None)
                continue
            DataType = Col.get('data_type')
            if DataType in _LOB_DATA_TYPES:
                (Locator, Rest) = _read_lob_column(Rest)
                Row.append(None if Locator is None else LOB(DataType, Locator))
                continue
            if DataType in _ROWID_DATA_TYPES:
                (Val, Rest) = _read_rowid_column(Rest)
                Row.append(Val)
                continue
            if DataType in _UROWID_DATA_TYPES:
                (Val, Rest) = _read_urowid_column(Rest)
                Row.append(Val)
                continue
            if DataType in _LONG_DATA_TYPES:
                (Val, Rest) = _read_long_column(Rest)
                Row.append(decode_value(Col, Val))
                continue
            if DataType == TNS_TYPE_ADT:
                (Val, Rest) = _read_object_column(Rest, Col)
                Row.append(Val)
                continue
            if Col.get('data_length', None) == 0:
                # A column the server describes with a zero data length carries
                # NO bytes in the row — not even the empty DALC that an ordinary
                # NULL would send. Its value is always NULL. `SELECT NULL AS x`
                # (and `SELECT ''`) describes exactly this way, and reading a
                # DALC for it consumed the following token instead, desyncing
                # the rest of the response: the end-of-fetch OER was eaten as a
                # column value and decoding then failed on a bogus token (#682).
                #
                # This has to sit after the branches above, not before them: a
                # LONG is described with a zero data length too, and it *does*
                # carry data. It also has to key on the data length rather than
                # the max size, because a NUMBER is described with a max size of
                # zero while carrying a value. And it tests for an explicit zero
                # rather than a falsy value, because a describe always sets the
                # field while a hand-built row format may leave it out.
                Row.append(None)
                continue
            (Val, Rest) = decode_dalc(Rest)
            Row.append(decode_value(Col, Val))
    Rows.append(Row)
    return (Rest, (Cursor, RowFormat, Rows))


def decode_token_rxd(Data: bytes, Acc: tuple) -> tuple:
    # Decode one RXD row and continue decoding the rest of the response — the full
    # decode a direct caller expects. decode_packet itself loops over the per-row
    # step instead of going through this wrapper.
    (Rest, NewAcc) = _decode_rxd_step(Data, Acc)
    return decode_packet(Rest, NewAcc)


def _read_lob_column(Rest: bytes) -> tuple[bytes | None, bytes]:
    # LOB column layout in RXD (Oracle 11g):
    #
    #   ub1 0x00              → NULL LOB; total column size = 1 byte.
    #   ub4 num_bytes         → otherwise the size of the locator block.
    #   DALC locator block    → the LOB locator + any inline content section.
    #                           This is exactly what the server expects back in
    #                           TTI_LOBOPS — verified by diffing against
    #                           sqlplus's LOBOPS request locator bytes.
    #
    # The locator block is a DALC (§12.2): a single length-prefixed chunk while
    # the block stays under 254 bytes, or the 0xFE chunked form (length-prefixed
    # sub-chunks terminated by a zero length) at 254 bytes and up. A block grows
    # past 254 bytes once the LOB's content is woven inline into the locator —
    # which happens for medium CLOBs, and for NCLOBs sooner because their inline
    # content is UTF-16BE (two bytes per character). The old code assumed a
    # 1-byte size echo followed by num_bytes raw bytes; that only matched the
    # single-chunk case, so the chunked form was mis-read and the leftover
    # content bytes were then fed to decode_packet as bogus tokens (#37).
    if not Rest:
        return (None, Rest)
    if Rest[0] == 0x00:
        return (None, Rest[1:])
    (NumBytes, Body) = decode_ub4(Rest)
    if NumBytes <= 0 or not Body:
        # Defensive: malformed or unexpected layout. Surface what we have
        # rather than overrunning the buffer.
        return (bytes(Body), b'')
    (Locator, Tail) = decode_dalc(Body)
    if isinstance(Locator, list):  # 0x00 / 0xFF DALC → empty / null
        return (None, Tail)
    return (bytes(Locator), Tail)


def _read_rowid_column(Rest: bytes) -> tuple[str | None, bytes]:
    # ROWID (TNS type 11) in RXD: a 1-byte present indicator (the size the
    # server reserved; 0 / 0xff means NULL) followed by a structured physical
    # rowid -- data object (ub4), relative file (ub2), an unused ub1, block
    # (ub4) and slot (ub2). Mirrors oracledb's read_rowid; the byte counts and
    # the base64 rendering were verified against ROWIDTOCHAR on a live XE row.
    from seerdb.common.types import rowid_to_string

    if not Rest:
        return (None, Rest)
    Indicator = Rest[0]
    Rest = Rest[1:]
    if Indicator in (0, 0xFF):
        return (None, Rest)
    (Obj, Rest) = decode_ub4(Rest)
    (File, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)  # unused ub1
    (Block, Rest) = decode_ub4(Rest)
    (Slot, Rest) = decode_ub4(Rest)
    return (rowid_to_string(Obj, File, Block, Slot), Rest)


def _read_urowid_column(Rest: bytes) -> tuple[str | None, bytes]:
    # UROWID (universal/logical rowid, TNS type 208 -- e.g. an index-organized
    # table's rowid). Same RXD framing as a LOB column: ub4 num_bytes, a 1-byte
    # length echo, then num_bytes raw rowid bytes (a leading type tag + the
    # rowid body). Rendered as the "*"-prefixed base64 form. Verified against a
    # live XE IOT row vs the SELECT ROWID text.
    from seerdb.common.types import urowid_to_string

    if not Rest:
        return (None, Rest)
    (NumBytes, Rest) = decode_ub4(Rest)
    if NumBytes <= 0:
        return (None, Rest)
    Rest = Rest[1:]  # 1-byte length echo
    Value = bytes(Rest[:NumBytes])
    Rest = Rest[NumBytes:]
    return (urowid_to_string(Value), Rest)


def _read_long_column(Rest: bytes) -> tuple[bytes | None, bytes]:
    # LONG / LONG RAW in RXD: a value followed by two trailing ub4 indicators
    # (the actual/return lengths; 0 / 0 for an ordinary value). The value is
    #   0x00            -> NULL, no body
    #   0xfe            -> chunked: repeated [ub1 len][bytes] until a 0 length
    #   else            -> ub1 length + that many bytes
    # The two ub4 reads after the value keep the stream aligned regardless of
    # NULL. Structure cross-referenced with python-oracledb's column read;
    # verified against live XE captures (NULL, single-chunk, 700-byte multi-
    # chunk, and LONG-not-last rows).
    if not Rest:
        return (None, Rest)
    Marker = Rest[0]
    if Marker == 0x00:
        Val = None
        Rest = Rest[1:]
    elif Marker == 0xFE:
        Rest = Rest[1:]
        Chunks = b''
        if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_2:
            # 12c+ prefixes each chunk with a ub4 length (zero-length terminator)
            # rather than 11g's single length byte.
            while Rest:
                (ChunkLen, Rest) = decode_ub4(Rest)
                if ChunkLen == 0:
                    break
                Chunks += bytes(Rest[:ChunkLen])
                Rest = Rest[ChunkLen:]
        else:
            while Rest:
                ChunkLen = Rest[0]
                Rest = Rest[1:]
                if ChunkLen == 0:
                    break
                Chunks += bytes(Rest[:ChunkLen])
                Rest = Rest[ChunkLen:]
        Val = Chunks
    else:
        Val = bytes(Rest[1 : 1 + Marker])
        Rest = Rest[1 + Marker :]
    (_, Rest) = decode_ub4(Rest)
    (_, Rest) = decode_ub4(Rest)
    return (Val, Rest)


def _read_object_column(Rest: bytes, Col: dict) -> tuple[object, bytes]:
    # SQL OBJECT (ADT, TNS type 109) value in RXD. The wire framing mirrors
    # python-oracledb's packet.pyx read_dbobject:
    #
    #   bytes_with_length   type OID (the type's 16-byte identity)
    #   bytes_with_length   object OID
    #   bytes_with_length   snapshot                         (skip)
    #   ub2                 version                          (skip)
    #   ub4                 image length (gate: 0 => NULL)
    #   ub2                 flags                            (skip)
    #   bytes               packed image (own length prefix)
    #
    # The image is a self-delimiting blob (its own 1-byte length, or the 0xFE
    # chunked form) -- NOT raw `num_bytes` bytes; num_bytes only gates whether
    # an image is present (read_dbobject skips read_bytes when it is 0). This
    # framing needs no attribute layout, so it keeps the row stream in sync
    # regardless of whether the type has been described yet. We hand back an
    # ObjectImage placeholder; the cursor decodes the image into a DbObject
    # once it has fetched the layout (#115). XMLType (type 109 with no object
    # type) is a separate path (#124).
    from seerdb.common.dbobject import ObjectImage

    (TypeOid, Rest) = _read_str_with_length(Rest)  # type OID
    (_, Rest) = _read_str_with_length(Rest)  # object OID
    Rest = _skip_bytes_with_length(Rest)  # snapshot
    (_, Rest) = decode_ub4(Rest)  # version (ub2)
    (NumBytes, Rest) = decode_ub4(Rest)  # image-present gate
    (_, Rest) = decode_ub4(Rest)  # flags (ub2)
    if NumBytes == 0:
        return (None, Rest)
    (Image, Rest) = _read_chunked_bytes(Rest)
    Oid = bytes(TypeOid) if not isinstance(TypeOid, list) else b''
    Placeholder = ObjectImage(
        Oid or Col.get('type_oid', b''),
        Col.get('type_schema'),
        Col.get('type_name'),
        Col.get('charset'),
        Image,
    )
    return (Placeholder, Rest)


def _bvc_bit_set(BitVec: bytes, Idx: int) -> bool:
    Byte = Idx // 8
    Bit = Idx % 8
    if Byte >= len(BitVec):
        return False
    return bool(BitVec[Byte] & (1 << Bit))


def decode_token_rxh(Data: bytes, Acc: tuple) -> tuple:
    # Row Transfer Header. Fields use Oracle's variable ub1/ub2/ub4 encoding
    # (1-byte length prefix + value bytes), not the fixed 2-byte big-endian
    # layout the older version of this decoder assumed. See python-oracledb's
    # _process_row_header.
    (Cursor, RowFormat, Rows) = Acc[:3]
    Rest = Data[2:]  # skip token + 1B flags
    (_, Rest) = decode_ub4(Rest)  # num requests
    (_, Rest) = decode_ub4(Rest)  # iteration number
    (_, Rest) = decode_ub4(Rest)  # num iters
    (_, Rest) = decode_ub4(Rest)  # buffer length
    (NumBytes, Rest) = decode_ub4(Rest)  # bit vector length
    BitVec = None
    if NumBytes > 0:
        # The row header can carry a column bit vector (oracledb's
        # _get_bit_vector): an unset bit means the column repeats the previous
        # row's value and carries no bytes in the following RXD. It must be
        # passed to the RXD decoder, not skipped — skipping it makes the RXD read
        # the next token as a column value and desync (a scroll re-execute that
        # repositions onto a row whose value equals the last one returned uses
        # this compression, e.g. LAST after fetching to EOF). #181.
        Rest = Rest[1:]  # skip repeated length
        BitVec = bytes(Rest[:NumBytes])
        Rest = Rest[NumBytes:]
    Rest = _skip_bytes_with_length(Rest)  # rxhrid
    Acc = (
        (Cursor, RowFormat, Rows)
        if BitVec is None
        else (Cursor, RowFormat, Rows, BitVec)
    )
    return decode_packet(Rest, Acc)


def decode_token_wrn(Data: bytes, Acc: tuple) -> tuple:
    # Warning message (section 3.1)
    # Skip the warning and continue processing
    logger.debug('decode_token_wrn: warning received')
    Rest = Data[1:]  # skip token byte
    (ErrNum, Rest) = decode_ub4(Rest)
    (RowCount, Rest) = decode_ub4(Rest)
    (RetCode, Rest) = decode_ub4(Rest)
    (WarnFlag, Rest) = decode_ub4(Rest)
    logger.debug(
        'decode_token_wrn: err=%s rows=%s ret=%s warn=%s',
        ErrNum,
        RowCount,
        RetCode,
        WarnFlag,
    )
    return decode_packet(Rest, Acc)


def _packet_header(Size: int, Type: int, Large: bool) -> bytes:
    # The 8-byte TNS packet header in the legacy (ub2 length + ub2 checksum) or
    # large-SDU (ub4 length, #155) layout. Type sits at byte 4 in both.
    if Large:
        return struct.pack('>IBBh', Size, Type, 0, 0)
    return struct.pack('>HhBBh', Size, 0, Type, 0, 0)


def encode_data_packet(Body: bytes, DataFlags: int, Large: bool = False) -> bytes:
    # A single TNS_DATA packet carrying explicit data flags. Request pipelining
    # (#158) sets BEGIN_PIPELINE (0x1000) on the first packet of a burst and
    # END_OF_REQUEST (0x0800) on each op packet — the ordinary encode_packet
    # path always writes 0 (or 0x0020 on an oversized fragment), so the
    # pipelined sender builds its packets here instead.
    return (
        _packet_header(len(Body) + 10, TNS_DATA, Large)
        + struct.pack('>H', DataFlags)
        + Body
    )


def encode_ano_fragment(
    Data: bytes, Sdu: int, Channel: 'AnoChannel', Large: bool = False
) -> tuple[bytes, bytes | None]:
    """Frame the next encrypted DATA fragment of ``Data`` (#437/#448).

    Peels a plaintext chunk small enough that, after ``Channel`` adds the MAC +
    cipher padding + fold flag, the framed packet still fits the SDU (``Sdu - 64``
    plaintext), wraps it, and frames it as a DATA packet — carrying
    ``TNS_DATA_FLAGS_MORE`` when more remains. Returns ``(packet, rest)`` where
    ``rest`` is ``None`` once ``Data`` is exhausted; the caller loops on ``rest``.
    Each fragment is an independent encrypt+MAC unit, decrypted per packet."""
    MaxPlain = Sdu - 64
    Rest = Data[MaxPlain:] or None
    Flag = TNS_DATA_FLAGS_MORE if Rest is not None else 0x0000
    return encode_data_packet(Channel.wrap(Data[:MaxPlain]), Flag, Large), Rest


def encode_packet(
    Type: int, Data: bytes, Length: int, Large: bool = False
) -> tuple[bytes, bytes | None]:
    if Type == TNS_DATA:
        PacketSize = len(Data) + 10
        if PacketSize > Length:
            # Oversized request: split into SDU-sized DATA packets. Each
            # fragment is an ordinary DATA packet — 8-byte header + 2-byte data
            # flags + a (SDU - 10)-byte payload chunk — and the chunks
            # concatenate back into the message on the server. Non-final
            # fragments carry data flags 0x0020 (PROTOCOL.md §1.3); the final
            # one (built by the branch below) uses 0x0000. `send()` loops until
            # the rest is empty. (The old `>HhBBhBI` + trailing `0, 32` header
            # mis-encoded that 0x20 flag as a 5-byte tail and drew ORA-12592 /
            # ORA-01013 from the server — issue #8.)
            BodySize = Length - 10
            return (
                _packet_header(BodySize + 10, Type, Large)
                + struct.pack('>h', TNS_DATA_FLAGS_MORE)
                + Data[:BodySize],
                Data[BodySize:],
            )
        # The non-final fragment branch above carries data-flags 0x0020; the
        # final/whole packet uses 0x0000. The 2-byte data flags follow the
        # 8-byte header in both framing layouts.
        return (
            _packet_header(PacketSize, Type, Large) + struct.pack('>h', 0) + Data,
            None,
        )
    else:
        PacketSize = len(Data) + 8
        return (_packet_header(PacketSize, Type, Large) + Data, None)


def encode_dictionary(Dictionary: dict) -> bytes:
    # Auth dictionaries yield two values (data, conn_key); callers use
    # encode_dictionary_auth() directly for that, so this stays single-bytes.
    match Dictionary['type']:
        case DictionaryType.chgpwd:
            return encode_dictionary_chgpwd(Dictionary)
        case DictionaryType.close:
            return encode_dictionary_close(Dictionary)
        case DictionaryType.description:
            return encode_dictionary_description(Dictionary)
        case DictionaryType.dty:
            return encode_dictionary_dty(Dictionary)
        case DictionaryType.exec:
            return encode_dictionary_exec(Dictionary)
        case DictionaryType.fetch:
            return encode_dictionary_fetch(Dictionary)
        case DictionaryType.lobops:
            return encode_dictionary_lobops(Dictionary)
        case DictionaryType.login:
            return encode_dictionary_login(Dictionary)
        case DictionaryType.pig:
            return encode_dictionary_pig(Dictionary)
        case DictionaryType.pro:
            return encode_dictionary_pro(Dictionary)
        case DictionaryType.sess:
            return encode_dictionary_sess(Dictionary)
        case DictionaryType.spfp:
            return encode_dictionary_spfp(Dictionary)
        case DictionaryType.start:
            return encode_dictionary_start(Dictionary)
        case DictionaryType.stop:
            return encode_dictionary_stop(Dictionary)
        case DictionaryType.tran:
            return encode_dictionary_tran(Dictionary)
    # No case matched (the match has no value-less path); raising here rather
    # than via `case _` keeps every branch a value-return for flow analysis.
    raise Exception('unsupported dict type', Dictionary['type'])


##
## Supplementary functions
##


def encode_dictionary_auth(Dictionary: dict) -> tuple[bytes, bytes]:
    Tseq = Dictionary['seq']
    Sess = Dictionary['auth']['sess']
    Salt = Dictionary['auth']['salt']
    DerivedSalt = Dictionary['auth']['derived_salt']
    VgenCount = Dictionary['auth'].get('vgen_count')
    SderCount = Dictionary['auth'].get('sder_count')
    VerifierType = Dictionary['auth'].get('verifier_type')
    User = Dictionary['env']['user'].encode('utf-8')
    Pass = Dictionary['env']['password'].encode('utf-8')
    Role = Dictionary['env'].get('role', 0)
    Prelim = Dictionary['env'].get('prelim', 0)

    LogonMode = encode_sb4((Role * 32) | (Prelim * 128) | 1 | 256)
    (AuthPass, AuthSess, SpeedyKey, SpeedyKeyInd, ConnKey) = o5logon(
        Sess, Salt, DerivedSalt, User, Pass, VgenCount, SderCount, VerifierType
    )

    AuthPass = encode_kv(b'AUTH_PASSWORD', AuthPass.hex().upper().encode('utf-8'))

    # AUTH_PBKDF2_SPEEDY_KEY is hex-encoded like AUTH_PASSWORD / AUTH_SESSKEY
    # (the server expects the hex string, not the raw bytes — sending raw gives
    # ORA-03146 "invalid buffer length for TTC field"). 256-bit scheme only.
    PBKDF2 = (
        encode_kv(b'AUTH_PBKDF2_SPEEDY_KEY', SpeedyKey.hex().upper().encode('utf-8'))
        if SpeedyKeyInd != 0
        else b''
    )

    AuthSess = encode_kv(b'AUTH_SESSKEY', AuthSess.hex().upper().encode('utf-8'), 1)

    # Proxy authentication (#126): a `proxy_user[schema]` connect adds one auth
    # pair naming the target schema; the proxy user authenticates normally and
    # the server switches the session into the schema's context.
    ProxyUser = Dictionary['env'].get('proxy_user')
    ProxyKv = (
        encode_kv(b'PROXY_CLIENT_NAME', ProxyUser.encode('utf-8')) if ProxyUser else b''
    )
    ProxyInd = 1 if ProxyUser else 0

    # DRCP (#130): a connection class and/or session purity. When DRCP is used
    # but no purity was given, a standalone connection defaults to NEW (matching
    # python-oracledb). cclass -> AUTH_KPPL_CONN_CLASS, purity -> AUTH_KPPL_PURITY.
    CClass = Dictionary['env'].get('cclass')
    Purity = Dictionary['env'].get('purity', 0) or 0
    if (CClass or Purity) and Purity == 0:
        Purity = 1  # PURITY_NEW
    CClassKv = (
        encode_kv(b'AUTH_KPPL_CONN_CLASS', CClass.encode('utf-8')) if CClass else b''
    )
    PurityKv = (
        encode_kv(b'AUTH_KPPL_PURITY', str(Purity).encode('utf-8'), 1)
        if Purity
        else b''
    )
    DrcpInd = (1 if CClass else 0) + (1 if Purity else 0)
    DrcpKv = CClassKv + PurityKv

    # 12c+ length-prefixes the username (write_bytes_with_length), same as the
    # OSESSKEY phase; 11g sends it raw (read via the UserLen field). Sending the
    # raw form to 21c makes it read the first username byte as a length and
    # desync — surfaces as ORA-03120 (two-task conversion: integer overflow).
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)

    # At fv >= 18 (fast-auth / 23ai, #89) phase two follows python-oracledb
    # exactly: the username is NOT re-sent (has_user = 0, user length 0 — the
    # session is already established by OSESSKEY), and the OAUTH carries the
    # session-context pairs the server now requires. The legacy fv <= 17 path
    # re-sends the username and the minimal AUTH_PASSWORD/SESSKEY/SPEEDY_KEY set;
    # using either shape against the other desyncs the server's parse, surfacing
    # as ORA-03120 (two-task conversion: integer overflow). RE'd from an
    # oracledb-thin fv24 capture (docs/PROTOCOL.md §20).
    if FieldVersion > FIELD_VERSION_23_1:
        # Header replicates python-oracledb's fv24 phase two byte-for-byte: the
        # has-user pointer byte is 0 followed by an extra 0x01, the logon mode
        # gains 0x20000, and the username is still sent length-prefixed. RE'd from
        # an oracledb-thin fv24 capture (docs/PROTOCOL.md §20).
        Header = bytes([TTI_FUN, TTI_AUTH, Tseq, 0, 1])
        Mode = encode_sb4((Role * 32) | (Prelim * 128) | 1 | 256 | 0x20000)
        UserField = bytes([len(User)]) + User
        SessionKvs = _auth_session_kvs(Dictionary)
        NumPairs = 2 + SpeedyKeyInd + 5 + ProxyInd + DrcpInd
    else:
        # 12c+ length-prefixes the username (write_bytes_with_length); 11g sends
        # it raw (read via the UserLen field). Sending the raw form to 21c makes
        # it read the first username byte as a length and desync (ORA-03120).
        Header = bytes([TTI_FUN, TTI_AUTH, Tseq, 1])
        Mode = LogonMode
        UserField = (
            bytes([len(User)]) + User if FieldVersion >= FIELD_VERSION_12_1 else User
        )
        # Sync the session time zone to the client's UTC offset, the way oracledb
        # / OCI / sqlplus do (AUTH_ALTER_SESSION). Without it the session runs at
        # the server default, so CURRENT_TIMESTAMP / LOCALTIMESTAMP /
        # SESSIONTIMEZONE and TIMESTAMP WITH LOCAL TIME ZONE reflect the server's
        # zone, not the client's — a porting surprise (#307). Gated to 12c+: that
        # is where oracledb (thin, 12.1+) operates and the phase-two AUTH accepts
        # the extra pair; 10g / 11g have a stricter parse that desyncs on it, and
        # no oracledb reference to match. The fv > 17 fast-auth path already
        # carries this via _auth_session_kvs.
        if FieldVersion >= FIELD_VERSION_12_1:
            SessionKvs = encode_kv(b'AUTH_ALTER_SESSION', _local_tz_clause(), 1)
            NumPairs = 2 + SpeedyKeyInd + 1 + ProxyInd + DrcpInd
        else:
            SessionKvs = b''
            NumPairs = 2 + SpeedyKeyInd + ProxyInd + DrcpInd

    Data = (
        Header
        + encode_sb4(len(User))
        + Mode
        + bytes([1])
        + encode_sb4(NumPairs)
        + bytes([1, 1])
        + UserField
        + AuthPass
        + PBKDF2
        + AuthSess
        + SessionKvs
        + ProxyKv
        + DrcpKv
    )

    return (Data, ConnKey)


def encode_dictionary_token_auth(Dictionary: dict) -> bytes:
    """Build the token-auth AUTH message (#125).

    Token auth replaces the O5LOGON challenge/response entirely: there is no
    OSESSKEY, no session key, and no server proof. This is a single TTI_AUTH
    (func 0x73) message with no username, logon mode ``NoNewPass`` (0x1), and the
    key/value pairs carrying the token — ``AUTH_TOKEN`` always, plus
    ``AUTH_HEADER`` + ``AUTH_SIGNATURE`` for the OCI IAM (signed) variant — after
    the standard session-context pairs. RE'd from go-ora (MIT); the wire shape
    matches the ordinary AUTH header with the user fields zeroed.
    """
    Tseq = Dictionary['seq']
    Role = Dictionary['env'].get('role', 0)
    Prelim = Dictionary['env'].get('prelim', 0)
    # NoNewPass (0x1) only — no UserAndPass (0x100), since there is no password.
    Mode = encode_sb4((Role * 32) | (Prelim * 128) | 1)

    Pairs = [encode_kv(b'AUTH_TOKEN', Dictionary['token'].encode('utf-8'))]
    Header = Dictionary.get('token_header')
    Signature = Dictionary.get('token_signature')
    if Header is not None and Signature is not None:
        Pairs.append(encode_kv(b'AUTH_HEADER', Header.encode('utf-8')))
        Pairs.append(encode_kv(b'AUTH_SIGNATURE', Signature.encode('utf-8')))
    SessionKvs = _auth_session_kvs(Dictionary)  # 5 pairs (charset..connect-string)
    NumPairs = len(Pairs) + 5

    # No user: the has-user pointer byte is 0 and the user length is 0.
    HeaderBytes = bytes([TTI_FUN, TTI_AUTH, Tseq, 0]) + encode_sb4(0)
    return (
        HeaderBytes
        + Mode
        + bytes([1])
        + encode_sb4(NumPairs)
        + bytes([1, 1])
        + b''.join(Pairs)
        + SessionKvs
    )


# seerdb's advertised client version, packed the way python-oracledb encodes
# SESSION_CLIENT_VERSION: (major << 24) | (minor << 20) | (patch << 12). Keep the
# string in sync with pyproject.toml. (4.0.1 -> 67112960 in the reference capture.)
_CLIENT_VERSION = '2.4.0'


def _packed_client_version(Version: str) -> int:
    Parts = [int(p) for p in Version.split('.')[:3]] + [0, 0, 0]
    return (Parts[0] << 24) | (Parts[1] << 20) | (Parts[2] << 12)


def _local_tz_clause() -> bytes:
    # "ALTER SESSION SET TIME_ZONE='±hh:mm'" + NUL, matching the reference client:
    # the client pins the session time zone to its own UTC offset.
    Offset = datetime.datetime.now().astimezone().utcoffset() or datetime.timedelta(0)
    Total = int(Offset.total_seconds())
    Sign = '+' if Total >= 0 else '-'
    Hh, Mm = divmod(abs(Total) // 60, 60)
    return f"ALTER SESSION SET TIME_ZONE='{Sign}{Hh:02d}:{Mm:02d}'\x00".encode('utf-8')


def _auth_session_kvs(Dictionary: dict) -> bytes:
    """The session-context key/value pairs the OAUTH phase two must carry at
    fv >= 18 (#89): client charset, driver banner, packed version, the time-zone
    ALTER SESSION, and the connect descriptor."""
    Charset = struct.pack('<H', CharsetDict.get(Dictionary['req'], AL32UTF8_CHARSET))
    return (
        encode_kv(
            b'SESSION_CLIENT_CHARSET',
            str(int.from_bytes(Charset, 'little')).encode('utf-8'),
        )
        + encode_kv(
            b'SESSION_CLIENT_DRIVER_NAME',
            f'seerdb thn : {_CLIENT_VERSION}'.encode('utf-8'),
        )
        + encode_kv(
            b'SESSION_CLIENT_VERSION',
            str(_packed_client_version(_CLIENT_VERSION)).encode('utf-8'),
        )
        + encode_kv(b'AUTH_ALTER_SESSION', _local_tz_clause(), 1)
        + encode_kv(b'AUTH_CONNECT_STRING', encode_dictionary_description(Dictionary))
    )


def encode_dictionary_chgpwd(Dictionary: dict) -> bytes:
    # Password change (#21). Sent on an already-authenticated session: a single
    # TTI_AUTH call that reuses the session key from login (no fresh
    # AUTH_SESSKEY), carrying the current and new passwords. Reverse-engineered
    # from an oracledb-thin capture against 21c. Same shape as the login OAUTH
    # (encode_dictionary_auth) but:
    #   - logon mode 0x102 = WITH_PASSWORD(0x100) | CHANGE_PASSWORD(0x02), and
    #     crucially WITHOUT the LOGON(0x01) bit the login carries;
    #   - exactly two key/value pairs: AUTH_PASSWORD (current) and
    #     AUTH_NEWPASSWORD (new), both AES-CBC-encrypted with the login ConnKey;
    #   - no AUTH_SESSKEY / AUTH_PBKDF2_SPEEDY_KEY (the session already exists).
    Tseq = Dictionary['seq']
    User = Dictionary['env']['user'].encode('utf-8')
    ConnKey = Dictionary['auth']['conn_key']
    CurPass = Dictionary['auth']['old_password'].encode('utf-8')
    NewPass = Dictionary['auth']['new_password'].encode('utf-8')

    AuthPass = encode_kv(
        b'AUTH_PASSWORD',
        encrypt_password(ConnKey, CurPass).hex().upper().encode('utf-8'),
    )
    AuthNewPass = encode_kv(
        b'AUTH_NEWPASSWORD',
        encrypt_password(ConnKey, NewPass).hex().upper().encode('utf-8'),
    )

    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    # fv >= 18 (23ai, #89) needs the same header shape as the login phase two:
    # the extra leading pointer byte and the 0x20000 logon-mode bit (else the
    # server rejects the change with ORA-03120). See encode_dictionary_auth.
    if FieldVersion > FIELD_VERSION_23_1:
        Header = bytes([TTI_FUN, TTI_AUTH, Tseq, 0, 1])
        LogonMode = encode_sb4(0x102 | 0x20000)
    else:
        Header = bytes([TTI_FUN, TTI_AUTH, Tseq, 1])
        LogonMode = encode_sb4(0x102)
    UserField = (
        bytes([len(User)]) + User if FieldVersion >= FIELD_VERSION_12_1 else User
    )

    return (
        Header
        + encode_sb4(len(User))
        + LogonMode
        + bytes([1])
        + encode_sb4(2)
        + bytes([1, 1])
        + UserField
        + AuthPass
        + AuthNewPass
    )


def _fun_header(Token: int, Seq: int, FieldVersion: int, TokenNum: int = 0) -> bytes:
    # Header for a TTI function-call message. 23ai (fv > 17, #89) appends a
    # ub8 "token number" after the sequence number (oracledb's
    # _write_function_code at fv24) — present on every function message
    # (execute, fetch, commit/rollback, LOB ops, logoff, ...). Omitting it
    # desyncs the call: the server either rejects it (ORA-03146 / ORA-03120) or
    # never replies (read timeout). For an ordinary call the token is 0
    # (encode_sb4(0) == b"\x00", the historical single zero byte); request
    # pipelining (#132) numbers each piggybacked call 1..N so the server can tag
    # each response with a matching TOKEN (33) marker.
    if FieldVersion > FIELD_VERSION_23_1:
        return bytes([TTI_FUN, Token, Seq]) + encode_sb4(TokenNum)
    return bytes([TTI_FUN, Token, Seq])


def encode_pipeline_begin(
    Seq: int, FieldVersion: int, TokenNum: int, Mode: int
) -> bytes:
    # The begin-pipeline piggyback (#132): tells the server a pipelined burst is
    # starting and which error mode applies. It rides on the first pipelined
    # message (the caller sets the BEGIN_PIPELINE data flag on that packet) and
    # shares that message's token. Mirrors oracledb
    # _write_begin_pipeline_piggyback; byte-validated against a 23ai capture.
    Out = bytes([TTI_MSG_TYPE_PIGGYBACK, TNS_FUNC_PIPELINE_BEGIN, Seq])
    if FieldVersion > FIELD_VERSION_23_1:
        Out += encode_sb4(TokenNum)
    return Out + encode_sb4(0) + bytes([0]) + bytes([Mode])


def encode_pipeline_end(Seq: int, FieldVersion: int) -> bytes:
    # The PIPELINE_END (func 200) message closing a pipelined burst (#132).
    return _fun_header(TNS_FUNC_PIPELINE_END, Seq, FieldVersion) + encode_sb4(0)


def _e2e_header(Modified: bool, Value: bytes | None) -> bytes:
    # One end-to-end attribute's header: a pointer byte (1 if the attribute is
    # being set this flush, else 0) + a ub4 length of its value (0 when unset or
    # cleared). The value bytes themselves are appended later, in field order.
    if Modified:
        return bytes([1]) + encode_sb4(len(Value) if Value else 0)
    return bytes([0]) + encode_sb4(0)


def encode_close_cursors_piggyback(Seq: int, FieldVersion: int, Cursors: list) -> bytes:
    """Build the CLOSE_CURSORS (OCCA, func 105) piggyback that frees a batch of
    server cursors (#191). Rides in front of the next call's message; the server
    closes the listed cursors before processing that call. Mirrors oracledb's
    _write_close_cursors_piggyback — note the ub8 token at fv24, which the older
    encode_dictionary_pig path omitted (it was never exercised on 12c+)."""
    Out = bytes([TTI_MSG_TYPE_PIGGYBACK, TTI_OCCA, Seq])
    if FieldVersion > FIELD_VERSION_23_1:
        Out += encode_sb4(0)  # ub8 token (0)
    Out += bytes([1]) + encode_sb4(len(Cursors))  # pointer + count
    for C in Cursors:
        Out += encode_sb4(C)
    return Out


def encode_end_to_end_piggyback(Seq: int, FieldVersion: int, Attrs: dict) -> bytes:
    """Build the SET_END_TO_END_ATTR piggyback (#183, func 135) that updates the
    session's end-to-end application-tracing attributes. `Attrs` maps each name
    (client_identifier / module / action / client_info / dbop) to either its new
    str value or None (clear); only the keys present are flushed. The piggyback
    rides in front of the next call's message. Byte layout + field order mirror
    oracledb's _write_end_to_end_piggyback (validated against a 23ai capture)."""

    def enc(Name):
        return Attrs[Name].encode('utf-8') if Attrs.get(Name) is not None else None

    Mod = {
        Name: Name in Attrs
        for Name in ('client_identifier', 'module', 'action', 'client_info', 'dbop')
    }
    Val = {Name: enc(Name) for Name in Mod}
    Flags = 0
    if Mod['action']:
        Flags |= TNS_END_TO_END_ACTION
    if Mod['client_identifier']:
        Flags |= TNS_END_TO_END_CLIENT_IDENTIFIER
    if Mod['client_info']:
        Flags |= TNS_END_TO_END_CLIENT_INFO
    if Mod['module']:
        Flags |= TNS_END_TO_END_MODULE
    if Mod['dbop']:
        Flags |= TNS_END_TO_END_DBOP

    Out = bytes([TTI_MSG_TYPE_PIGGYBACK, TNS_FUNC_SET_END_TO_END_ATTR, Seq])
    if FieldVersion > FIELD_VERSION_23_1:
        Out += encode_sb4(0)  # ub8 token (0)
    Out += bytes([0, 0]) + encode_sb4(Flags)  # cidnam, cidser pointers; flags
    Out += _e2e_header(Mod['client_identifier'], Val['client_identifier'])
    Out += _e2e_header(Mod['module'], Val['module'])
    Out += _e2e_header(Mod['action'], Val['action'])
    Out += bytes([0]) + encode_sb4(0)  # cideci (unsupported)
    Out += bytes([0]) + encode_sb4(0)  # cidcct / cidecs (unsupported)
    Out += _e2e_header(Mod['client_info'], Val['client_info'])
    Out += bytes([0]) + encode_sb4(0)  # cidkstk (unsupported)
    Out += bytes([0]) + encode_sb4(0)  # cidktgt (unsupported)
    Out += _e2e_header(Mod['dbop'], Val['dbop'])
    # values, in field order, only those set to a non-None value
    for Name in ('client_identifier', 'module', 'action', 'client_info', 'dbop'):
        if Mod[Name] and Val[Name] is not None:
            Out += _bytes_with_length(Val[Name])
    return Out


# The single keyword under which the end-user security context OSON image is
# carried in the func-205 piggyback (oracledb "ORCL_XS_AUTHZ_CONTEXT").
END_USER_SEC_CTX_KEYWORD = b'ORCL_XS_AUTHZ_CONTEXT'


def encode_end_user_sec_piggyback(
    Seq: int, FieldVersion: int, OsonBytes: bytes
) -> bytes:
    """Build the end-user security context piggyback (func 205, #460) that
    attaches an end-user identity / authorization context to the session for
    Deep Data Security. `OsonBytes` is the OSON image of the context dict (see
    ``seerdb.common.end_user_sec.create_end_user_security_context``). The
    piggyback carries a single keyword-value pair — keyword
    ``ORCL_XS_AUTHZ_CONTEXT``, value = the OSON image. It rides in front of the
    next call's message and re-rides every call while a context is set (mirrors
    oracledb's _write_end_user_sec_piggyback / _write_piggybacks). Byte layout
    reconstructed from the reference thin client (docs/PROTOCOL.md §34); the
    feature is tcps-only so it cannot be captured on a cleartext transport."""
    Out = bytes([TTI_MSG_TYPE_PIGGYBACK, TNS_FUNC_END_USER_SECURITY_CTX, Seq])
    if FieldVersion > FIELD_VERSION_23_1:
        Out += encode_sb4(0)  # ub8 token (0)
    Out += encode_sb4(TNS_SECURITY_CONTEXT_ATTACH_FLAG)  # ub4 attach flag = 1
    Out += bytes([1])  # pointer(kpdkve) non-null
    Out += encode_sb4(1)  # number of key-value pairs = 1
    # One str-keyword-value-pair (flags=0, text=NULL), each field written as
    # write_bytes_with_two_lengths (ub4 count + length-prefixed bytes).
    Out += encode_sb4(0)  # kv flags
    Out += _obj_two_lengths(END_USER_SEC_CTX_KEYWORD)  # keyword
    Out += _obj_two_lengths(b'')  # text (NULL)
    Out += _obj_two_lengths(OsonBytes)  # value = OSON image
    return Out


def encode_session_state_piggyback(Seq: int, FieldVersion: int, State: int) -> bytes:
    """Build the session-state (request boundary) piggyback (func 176, #464).
    `State` is TNS_SESSION_STATE_REQUEST_BEGIN or _REQUEST_END; the explicit
    boundary bit is OR'd in. It rides in front of the next call's message and is
    one-shot (the caller clears the desired state after emitting it). Mirrors
    oracledb's _write_session_state_piggyback; byte layout in docs/PROTOCOL.md
    §35. Gated on the negotiated request-boundaries capability."""
    Out = bytes([TTI_MSG_TYPE_PIGGYBACK, TNS_FUNC_SESSION_STATE, Seq])
    if FieldVersion > FIELD_VERSION_23_1:
        Out += encode_sb4(0)  # ub8 token (0)
    # ub8 (state | explicit-boundary); small values encode like ub4.
    Out += encode_sb4(State | TNS_SESSION_STATE_EXPLICIT_BOUNDARY)
    return Out


def encode_dictionary_close(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    return _fun_header(TTI_LOGOFF, Tseq, FieldVersion)


# Env keys safe to include in a debug log. Deliberately an allow-list, NOT a
# deny-list: the connection `password` (and the changepassword `new_password`)
# is simply never read, so no secret value can flow into the logged copy. The
# whole `auth` sub-dict is dropped wholesale — it only ever holds secrets (the
# session key, salts, and the changepassword old/new passwords, #21).
_REDACT_ENV_SAFE = (
    'host',
    'port',
    'user',
    'sid',
    'service_name',
    'conn_state',
    'timeout',
    'autocommit',
    'fetch',
    'role',
    'charset',
    'prelim',
    'app_name',
)


def _redacted(Dictionary: dict) -> dict:
    # Return a copy safe to log. Secrets live in the env dict (connection
    # password) and the auth dict (changepassword passwords + session key);
    # neither secret value is ever read here, so they cannot reach a log.
    Safe = {k: v for k, v in Dictionary.items() if k not in ('env', 'auth')}
    Env = Dictionary.get('env')
    if isinstance(Env, dict):
        Safe['env'] = {k: Env[k] for k in _REDACT_ENV_SAFE if k in Env}
    if 'auth' in Dictionary:
        Safe['auth'] = '<redacted>'
    return Safe


def _tpc_xid_bytes(Xid) -> tuple | None:
    # (format_id, gtrid, bqual, xid_bytes) for a TPC Xid, or None. The wire xid
    # is gtrid + bqual zero-padded to a fixed 128 bytes (oracledb _write_message).
    if Xid is None:
        return None
    FormatId = Xid[0]
    Gtrid = Xid[1] if isinstance(Xid[1], (bytes, bytearray)) else Xid[1].encode()
    Bqual = Xid[2] if isinstance(Xid[2], (bytes, bytearray)) else Xid[2].encode()
    XidBytes = bytes(Gtrid) + bytes(Bqual) + bytes(128 - len(Gtrid) - len(Bqual))
    return (FormatId, bytes(Gtrid), bytes(Bqual), XidBytes)


def _tpc_xid_descriptor(Parts) -> bytes:
    # The format-id / gtrid-len / bqual-len / xid-pointer block shared by both
    # TPC messages (after the operation + context-pointer block).
    if Parts is not None:
        (FormatId, Gtrid, Bqual, XidBytes) = Parts
        return (
            encode_sb4(FormatId)
            + encode_sb4(len(Gtrid))
            + encode_sb4(len(Bqual))
            + bytes([1])
            + encode_sb4(len(XidBytes))
        )
    return encode_sb4(0) + encode_sb4(0) + encode_sb4(0) + bytes([0]) + encode_sb4(0)


def encode_tpc_switch(
    Seq: int,
    FieldVersion: int,
    Operation: int,
    Xid,
    Flags: int,
    Timeout: int,
    Context: bytes | None,
    AppValue: int = 0,
    InternalName: bytes | None = None,
    ExternalName: bytes | None = None,
) -> bytes:
    # TPC start (tpc_begin) / detach (tpc_end). Mirrors oracledb
    # TransactionSwitchMessage._write_message (#131).
    Parts = _tpc_xid_bytes(Xid)
    Out = _fun_header(TNS_FUNC_TPC_TXN_SWITCH, Seq, FieldVersion)
    Out += encode_sb4(Operation)
    if Context is not None:
        Out += bytes([1]) + encode_sb4(len(Context))
    else:
        Out += bytes([0]) + encode_sb4(0)
    Out += _tpc_xid_descriptor(Parts)
    Out += encode_sb4(Flags) + encode_sb4(Timeout)
    Out += bytes([1, 1, 1])  # ptrs: app value, return context, len
    Out += (
        bytes([1]) + encode_sb4(len(InternalName))
        if InternalName
        else bytes([0]) + encode_sb4(0)
    )
    Out += (
        bytes([1]) + encode_sb4(len(ExternalName))
        if ExternalName
        else bytes([0]) + encode_sb4(0)
    )
    if Context is not None:
        Out += Context
    if Parts is not None:
        Out += Parts[3]
    Out += encode_sb4(AppValue)
    if InternalName:
        Out += InternalName
    if ExternalName:
        Out += ExternalName
    return Out


def parse_tpc_switch(body: bytes, field_version: int) -> tuple[int, int, int, bytes]:
    """Decode a client TPC switch call (TTI_FUN 103) — the inverse of
    :func:`encode_tpc_switch` for the shape a sessionless begin / resume / suspend
    sends. Returns ``(operation, flags, timeout, transaction_id)``: operation is
    START (0x01) or DETACH (0x02), flags carry NEW vs RESUME, and the id is the
    xid's gtrid (empty for a suspend, which sends no xid)."""
    rest = body[3:]  # TTI_FUN, func, seq
    if field_version > FIELD_VERSION_23_1:
        _, rest = decode_ub4(rest)  # the fv24 token number
    operation, rest = decode_ub4(rest)
    rest = rest[1:]  # context pointer flag
    _ctx_len, rest = decode_ub4(rest)
    _format_id, rest = decode_ub4(rest)
    gtrid_len, rest = decode_ub4(rest)
    _bqual_len, rest = decode_ub4(rest)
    has_xid, rest = rest[0], rest[1:]
    xidbytes_len, rest = decode_ub4(rest)
    flags, rest = decode_ub4(rest)
    timeout, rest = decode_ub4(rest)
    rest = rest[3:]  # app-value / return-context / length pointers
    rest = rest[1:]
    _iname_len, rest = decode_ub4(rest)  # internal name
    rest = rest[1:]
    _ename_len, rest = decode_ub4(rest)  # external name
    xid = rest[:xidbytes_len] if has_xid else b''
    return operation, flags, timeout, xid[:gtrid_len]


def encode_tpc_change_state(
    Seq: int,
    FieldVersion: int,
    Operation: int,
    State: int,
    Xid,
    Flags: int,
    Context: bytes | None,
) -> bytes:
    # TPC prepare / commit / rollback / forget. Mirrors oracledb
    # TransactionChangeStateMessage._write_message (#131).
    Parts = _tpc_xid_bytes(Xid)
    Out = _fun_header(TNS_FUNC_TPC_TXN_CHANGE_STATE, Seq, FieldVersion)
    Out += encode_sb4(Operation)
    if Context is not None:
        Out += bytes([1]) + encode_sb4(len(Context))
    else:
        Out += bytes([0]) + encode_sb4(0)
    Out += _tpc_xid_descriptor(Parts)
    Out += encode_sb4(0)  # timeout
    Out += encode_sb4(State)
    Out += bytes([1])  # ptr (out state)
    Out += encode_sb4(Flags)
    if Context is not None:
        Out += Context
    if Parts is not None:
        Out += Parts[3]
    return Out


def encode_dictionary_description(Dictionary: dict) -> bytes:
    logger.debug('encode_dictionary_description: %s', _redacted(Dictionary))
    Hostname = socket.gethostname().encode('utf-8')
    User = Dictionary['env']['user'].encode('utf-8')
    Host = Dictionary['env'].get('host', DEFAULT_HOST).encode('utf-8')
    Port = str(Dictionary['env'].get('port', DEFAULT_PORT)).encode('utf-8')
    SID = Dictionary['env'].get('sid', DEFAULT_SID).encode('utf-8')
    ServiceName = Dictionary['env'].get('service_name', None)
    AppName = Dictionary['env'].get('app_name', 'seerdb').encode('utf-8')
    SslOpts = Dictionary['env'].get('ssl', None)
    Sn = (
        b'SID=' + SID
        if ServiceName is None
        else b'SERVICE_NAME=' + ServiceName.encode('utf-8')
    )
    Proto = b'TCP' if SslOpts is None else b'TCPS'
    # DRCP (#130): a connection class or non-default purity requests a pooled
    # server from the connection broker via (SERVER=POOLED) in the CONNECT_DATA.
    Drcp = (
        b'(SERVER=POOLED)'
        if (Dictionary['env'].get('cclass') or Dictionary['env'].get('purity'))
        else b''
    )
    return (
        b'(DESCRIPTION=(CONNECT_DATA=('
        + Sn
        + b')'
        + Drcp
        + b'(CID=(PROGRAM='
        + AppName
        + b')(HOST='
        + Hostname
        + b')(USER='
        + User
        + b')))(ADDRESS=(PROTOCOL='
        + Proto
        + b')(HOST='
        + Host
        + b')(PORT='
        + Port
        + b')))'
    )


# ---------------------------------------------------------------------------
# TTC capability vectors (carried in the TTI_DTY / DATA_TYPES message)
# ---------------------------------------------------------------------------
# The handshake advertises two length-prefixed capability arrays: compile-time
# (TNS_CCAP_*) and runtime (TNS_RCAP_*). Each is just a byte array where a
# given index is a named feature slot. Index meanings and the field-version
# values below were reverse-engineered from python-oracledb (constants.pxi /
# data_types.pyx) and verified against live 11g and 21c captures (issue #27,
# docs/PROTOCOL.md §4.2). We model them as {index: value} so the vector reads
# as a feature list instead of an opaque blob, and so a single field-version
# knob can switch seerdb between the 11g-era and 12c+-era wire contracts.

# Compile-time capability indices (into the compile_caps array):
CCAP_SQL_VERSION = 0
CCAP_LOGON_TYPES = 4
CCAP_FEATURE_BACKPORT = 5
CCAP_FIELD_VERSION = 7  # gates the auth verifier + version-gated formats
CCAP_SERVER_DEFINE_CONV = 8
CCAP_DEQUEUE_WITH_SELECTOR = 9
CCAP_TTC1 = 15
CCAP_OCI1 = 16
CCAP_TDS_VERSION = 17
CCAP_RPC_VERSION = 18
CCAP_RPC_SIG = 19
CCAP_DBF_VERSION = 21
CCAP_LOB = 23
CCAP_TTC2 = 26
CCAP_UB2_DTY = 27  # 2-byte data-type ids (12c+)
CCAP_OCI2 = 31
CCAP_CLIENT_FN = 34
CCAP_OCI3 = 35
CCAP_TTC3 = 37
CCAP_SESS_SIGNATURE_VERSION = 39
CCAP_TTC4 = 40
CCAP_LOB2 = 42
CCAP_TTC5 = 44
CCAP_FEATURE_BACKPORT2 = 45
CCAP_VECTOR_FEATURES = 52

# Bit within compile_caps[CCAP_FEATURE_BACKPORT2] that advertises the end-user
# security context piggyback (#460). 26ai advertises caps[45] = 0x03.
CCAP_FEATURE_BACKPORT2_END_USER_SEC = 0x02

# Bit within compile_caps[CCAP_TTC4] that advertises explicit request boundaries
# (#464). Paired with the runtime RCAP_TTC_SESSION_STATE_OPS bit.
CCAP_TTC4_EXPLICIT_BOUNDARY = 0x40

# TNS_CCAP_FIELD_VERSION_* values (the byte written at CCAP_FIELD_VERSION) now
# live in seerdb.common.tns_consts and are imported at the top of this module — kept
# importable as `from seerdb.common.tns import FIELD_VERSION_*` for existing callers.
# They live in the leaf constants module so seerdb.client.cursor can import the 12.1
# threshold from a lightweight leaf without pulling in the whole encoder.

# Runtime capability indices + the flag bits we set:
RCAP_COMPAT = 0
RCAP_TTC = 6
RCAP_COMPAT_81 = 2
RCAP_TTC_ZERO_COPY = 0x01
RCAP_TTC_32K = 0x04
RCAP_TTC_SESSION_STATE_OPS = 0x10  # server accepts request-boundary markers (#464)


def max_string_size(RuntimeCaps: bytes) -> int:
    """The widest character / RAW bind the server takes in place: 32767 bytes
    when its runtime capabilities carry the 32K TTC bit (12c+), else 4000. A
    bind declared wider is a LONG-class bind, and its value travels after the
    row's other values (docs/PROTOCOL.md 5.4)."""
    if len(RuntimeCaps) > RCAP_TTC and RuntimeCaps[RCAP_TTC] & RCAP_TTC_32K:
        return 32767
    return 4000


# Per-field-version capability vectors as {index: byte}; unset indices are 0.
# 11.2 reproduces seerdb's historical 11g vector byte-for-byte (asserted by
# tests/test_tns_encode.py); 21.1 matches python-oracledb 4.0.1 against 21c.
_COMPILE_CAPS = {
    FIELD_VERSION_11_2: (
        38,
        {
            CCAP_SQL_VERSION: 6,  # TNS_CCAP_SQL_VERSION_MAX
            CCAP_LOGON_TYPES: 0x6A,  # O7LOGON | O5LOGON | O5LOGON_NP | 0x40
            CCAP_FEATURE_BACKPORT: 1,
            CCAP_FIELD_VERSION: FIELD_VERSION_11_2,
            CCAP_SERVER_DEFINE_CONV: 1,
            CCAP_DEQUEUE_WITH_SELECTOR: 1,
            CCAP_TTC1: 0x29,
            CCAP_OCI1: 0x90,
            CCAP_TDS_VERSION: 3,  # TNS_CCAP_TDS_VERSION_MAX
            CCAP_RPC_VERSION: 7,  # TNS_CCAP_RPC_VERSION_MAX
            CCAP_RPC_SIG: 3,  # TNS_CCAP_RPC_SIG_VALUE
            CCAP_DBF_VERSION: 1,  # TNS_CCAP_DBF_VERSION_MAX
            CCAP_LOB: 0x4F,
            CCAP_TTC2: 4,
            CCAP_OCI2: 12,
            CCAP_CLIENT_FN: 6,
            CCAP_TTC3: 1,
            # Slots oracledb leaves 0 but seerdb's original 11g reference client
            # set; not in oracledb's named map. Kept verbatim for byte-parity.
            1: 1,
            6: 1,
            10: 1,
            11: 1,
            12: 1,
            13: 1,
            24: 1,
            25: 0x37,
            36: 1,
        },
    ),
    FIELD_VERSION_21_1: (
        53,
        {
            CCAP_SQL_VERSION: 6,
            CCAP_LOGON_TYPES: 0xEA,  # adds O8LOGON_LONG_IDENTIFIER (0x80)
            CCAP_FEATURE_BACKPORT: 0x18,
            CCAP_FIELD_VERSION: FIELD_VERSION_21_1,
            CCAP_SERVER_DEFINE_CONV: 1,
            CCAP_DEQUEUE_WITH_SELECTOR: 1,
            CCAP_TTC1: 0x29,
            CCAP_OCI1: 0x90,
            CCAP_TDS_VERSION: 3,
            CCAP_RPC_VERSION: 7,
            CCAP_RPC_SIG: 3,
            CCAP_DBF_VERSION: 1,
            CCAP_LOB: 0xCF,  # adds LOB_12C (0x80)
            CCAP_TTC2: 4,
            CCAP_UB2_DTY: 1,
            CCAP_OCI2: 0x10,
            CCAP_CLIENT_FN: 12,  # TNS_CCAP_CLIENT_FN_MAX
            CCAP_OCI3: 0x20,  # OCI3_OCSSYNC
            CCAP_TTC3: 0xB8,
            CCAP_SESS_SIGNATURE_VERSION: 8,
            CCAP_TTC4: 0x44,
            CCAP_LOB2: 5,
            CCAP_TTC5: 0x3E,
            CCAP_FEATURE_BACKPORT2: 2,
            CCAP_VECTOR_FEATURES: 3,
        },
    ),
}
_RUNTIME_CAPS = {
    FIELD_VERSION_11_2: (
        7,
        {
            RCAP_COMPAT: RCAP_COMPAT_81,
        },
    ),
    FIELD_VERSION_21_1: (
        11,
        {
            RCAP_COMPAT: RCAP_COMPAT_81,
            RCAP_TTC: RCAP_TTC_ZERO_COPY | RCAP_TTC_32K,
        },
    ),
}


def _render_caps(spec: tuple[int, dict]) -> bytes:
    """Render a (length, {index: value}) capability spec to its byte array."""
    length, values = spec
    caps = bytearray(length)
    for index, value in values.items():
        caps[index] = value
    return bytes(caps)


def capability_arrays(field_version: int = FIELD_VERSION_11_2) -> tuple[bytes, bytes]:
    """Return (compile_caps, runtime_caps) for a target TTC field version.

    Two base vectors are modelled: the 11.2 vector for pre-12c field versions
    (byte-identical to what seerdb has always sent) and the 21.1 vector for
    12c+. The capability *contents* are stable across 12c+ releases — only the
    field-version byte differs — so for any negotiated 12c+ version we render
    the 21.1 base and patch in that version. This lets the client advertise the
    highest version and operate against any server it negotiates down to
    (12.1 / 12.2 / 18c / 19c / 21c …)."""
    if not 0 <= field_version <= 0xFF:
        raise ValueError(f'field version out of range: {field_version}')
    if field_version < FIELD_VERSION_10_2:
        # Pre-10g (9i, #90): the minimal capability vector the Oracle JDBC thin
        # driver sends — crucially LOGON_TYPES = 0 (does NOT advertise O5LOGON).
        # The 11.2 vector advertises O5LOGON (0x6a), which makes 9i attempt a
        # verifier the account lacks and reject the login (ORA-01017); with the
        # minimal caps 9i falls back to the O3LOGON path. CCAP_FIELD_VERSION
        # stays 0 (9i negotiates the field version via TTI_PRO, not the caps).
        return _O3_COMPILE_CAPS, _O3_RUNTIME_CAPS
    Base = (
        FIELD_VERSION_21_1
        if field_version >= FIELD_VERSION_12_1
        else FIELD_VERSION_11_2
    )
    Compile = bytearray(_render_caps(_COMPILE_CAPS[Base]))
    Compile[CCAP_FIELD_VERSION] = field_version
    return bytes(Compile), _render_caps(_RUNTIME_CAPS[Base])


# Oracle 9i (pre-10g) capability vectors, captured from the JDBC thin driver
# (#90). Minimal by design: compile-cap index 17 = 0x03, everything else 0
# (no O5LOGON), runtime caps = a single 0x02 byte.
_O3_COMPILE_CAPS = bytes(17) + bytes([3]) + bytes(3)
_O3_RUNTIME_CAPS = bytes([2])


# 12c+ datatype table. Where the 11g table (built inline in encode_dictionary_dty
# below) uses 1-byte-per-field entries with a short (type, 0) form for unknown
# types, the 12c+ table is a flat list of uniform 4-field entries, each field a
# UB2 (type, conv, repr, 0), terminated by a UB2 0. conv defaults to type and
# repr to 1 (universal) unless overridden in _DTY_12C_OVERRIDES (repr 10 =
# Oracle-native, e.g. NUMBER / DATE). The type list + overrides regenerate
# python-oracledb 4.0.1's DATA_TYPES table byte-for-byte (verified against a 21c
# capture); the gate is the UB2_DTY capability, i.e. field version >= 12.1.
_DTY_12C_TYPES = [
    1,
    2,
    8,
    12,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    10,
    11,
    40,
    41,
    117,
    120,
    290,
    291,
    292,
    293,
    294,
    298,
    299,
    300,
    301,
    302,
    303,
    304,
    305,
    306,
    307,
    308,
    309,
    310,
    311,
    312,
    313,
    315,
    316,
    317,
    318,
    319,
    320,
    321,
    322,
    323,
    327,
    328,
    329,
    331,
    333,
    334,
    335,
    336,
    337,
    338,
    339,
    340,
    341,
    342,
    343,
    344,
    345,
    346,
    348,
    349,
    354,
    355,
    359,
    363,
    380,
    381,
    382,
    383,
    384,
    385,
    386,
    387,
    388,
    389,
    390,
    391,
    393,
    394,
    395,
    396,
    397,
    398,
    399,
    400,
    401,
    404,
    405,
    406,
    407,
    413,
    414,
    415,
    416,
    417,
    418,
    419,
    420,
    421,
    422,
    423,
    424,
    425,
    426,
    427,
    429,
    430,
    431,
    432,
    433,
    449,
    450,
    454,
    455,
    456,
    457,
    458,
    459,
    460,
    461,
    462,
    463,
    466,
    467,
    468,
    469,
    470,
    471,
    472,
    473,
    474,
    475,
    476,
    477,
    478,
    479,
    480,
    481,
    482,
    483,
    484,
    485,
    486,
    490,
    491,
    492,
    493,
    494,
    495,
    496,
    498,
    499,
    500,
    501,
    502,
    509,
    510,
    513,
    514,
    516,
    517,
    518,
    519,
    520,
    521,
    522,
    523,
    524,
    525,
    526,
    527,
    528,
    529,
    530,
    531,
    532,
    533,
    534,
    535,
    536,
    537,
    538,
    539,
    540,
    541,
    542,
    543,
    560,
    565,
    572,
    573,
    574,
    575,
    576,
    578,
    563,
    564,
    579,
    580,
    581,
    582,
    583,
    584,
    585,
    3,
    4,
    5,
    6,
    7,
    9,
    15,
    39,
    68,
    91,
    94,
    95,
    96,
    97,
    100,
    101,
    102,
    104,
    106,
    108,
    109,
    110,
    111,
    112,
    113,
    114,
    115,
    116,
    119,
    198,
    146,
    152,
    153,
    154,
    155,
    156,
    172,
    178,
    179,
    180,
    181,
    182,
    183,
    184,
    185,
    186,
    187,
    188,
    189,
    190,
    195,
    196,
    197,
    208,
    231,
    232,
    233,
    241,
    252,
    590,
    591,
    592,
    613,
    614,
    615,
    616,
    611,
    612,
    593,
    594,
    595,
    596,
    597,
    598,
    599,
    600,
    601,
    602,
    603,
    604,
    605,
    622,
    623,
    624,
    625,
    626,
    627,
    628,
    629,
    630,
    631,
    632,
    637,
    638,
    636,
    639,
    663,
    640,
    652,
    646,
    647,
    127,
    660,
    661,
    665,
    669,
    670,
]
_DTY_12C_OVERRIDES = {
    2: (2, 10),
    12: (12, 10),
    27: (27, 10),
    3: (2, 10),
    4: (2, 10),
    5: (1, 1),
    6: (2, 10),
    7: (2, 10),
    9: (1, 1),
    15: (1, 1),
    68: (2, 10),
    91: (2, 10),
    94: (1, 1),
    95: (23, 1),
    97: (96, 1),
    104: (11, 1),
    108: (109, 1),
    110: (111, 1),
    116: (102, 1),
    152: (2, 10),
    153: (2, 10),
    154: (2, 10),
    155: (1, 1),
    156: (12, 10),
    172: (2, 10),
    184: (12, 10),
    195: (112, 1),
    196: (113, 1),
    197: (114, 1),
    232: (231, 1),
    241: (109, 1),
}


def _datatype_table_12c() -> bytes:
    """Render the 12c+ datatype table: uniform UB2 (type, conv, repr, 0)
    entries terminated by a UB2 0."""
    Out = bytearray()
    for Type in _DTY_12C_TYPES:
        Conv, Rep = _DTY_12C_OVERRIDES.get(Type, (Type, 1))
        Out += struct.pack('>HHHH', Type, Conv, Rep, 0)
    Out += struct.pack('>H', 0)
    return bytes(Out)


def encode_dty_table(entries: list) -> bytes:
    """Render an fv2 / 8i DATA_TYPES conversion-table body — the older single-byte
    form (vs the 12c UB2 quads). Each entry is ``<type> <conv> <rep> 00``, a
    type-only entry is ``<type> 00``, and a type that accepts extra conversion
    sources adds them before ``rep``: ``<type> <conv> <src>... <rep> 00``. A final
    ``00`` terminates the table. Inverse of :func:`decode_dty_table`."""
    out = bytearray()
    for entry in entries:
        if len(entry) == 1:  # type only
            out += bytes([entry[0], 0])
        elif len(entry) == 3:  # type, conv, rep
            out += bytes([entry[0], entry[1], entry[2], 0])
        else:  # type, conv, (extra conversion sources...), rep
            typ, conv, extra, rep = entry
            out += bytes([typ, conv]) + bytes(extra) + bytes([rep, 0])
    return bytes(out) + b'\x00'


def decode_dty_table(body: bytes) -> list:
    """Parse an fv2 / 8i DATA_TYPES conversion-table body into entries — the
    inverse of :func:`encode_dty_table`. Each entry is ``(type,)`` (type only),
    ``(type, conv, rep)``, or ``(type, conv, (src, ...), rep)`` when the type
    accepts extra conversion sources."""
    entries: list = []
    i = 0
    while i < len(body):
        end = body.index(0, i)
        content = body[i:end]
        if not content:
            break  # terminator
        if len(content) == 1:
            entries.append((content[0],))
        elif len(content) == 3:
            entries.append((content[0], content[1], content[2]))
        else:
            entries.append((content[0], content[1], tuple(content[2:-1]), content[-1]))
        i = end + 1
    return entries


# Oracle 8i (8.1.7) DTY (data-type negotiation), captured from a live
# 9.2-client -> 8.1.7 handshake. 8i predates ~37 later data types, so its
# identity map is shorter than the modern table (1019 B vs 1167 B), and it
# negotiates a single-byte charset (WE8ISO8859P1 = 31) — 8i has no Unicode
# charset, so the modern AL32UTF8 (873) DTY draws ORA-03120. Generated from the
# header + the conversion-entry list (below) via encode_dty_table; sent verbatim
# when the server is 8i (the negotiation does not vary with the workload).
#
# The DB session time-zone block: the same 4-byte pad at both ends with the biased
# h/m/s triplet spliced between. Oracle biases each of hours/min/sec by +60, so an
# all-zero (UTC) offset is stored as (60, 60, 60). The pad is a fixed 11.2 identity.
_DB_TZ_FRAME_PAD = bytes.fromhex('80000000')
_DB_TZ_BIAS = 60  # Oracle biases each of the h/m/s offset fields by +60

# The 42-byte 8i DTY header, built from its fields: the TTI_DTY message token, the
# charset + national charset (both ISO Latin-1 / WE8ISO8859P1 = 31, the only charset
# 8i speaks), the 26-byte fv2 capability vector (carried as the captured 8i identity),
# then the DB time-zone block set to UTC.
_DTY_8I_CAPS = bytes.fromhex(  # 26-byte 8i (fv2) capability vector, captured identity
    '02150601010105010102010101010101017f0f03060300020201'
)
_DTY_8I_HEADER = (
    bytes([TTI_DTY])
    + struct.pack('<H', ISO_LATIN_1_CHARSET)  # charset
    + struct.pack('<H', ISO_LATIN_1_CHARSET)  # national charset
    + _DTY_8I_CAPS
    + _DB_TZ_FRAME_PAD
    + bytes([_DB_TZ_BIAS, _DB_TZ_BIAS, _DB_TZ_BIAS])  # h/m/s = 0 (UTC), each +60
    + _DB_TZ_FRAME_PAD
)


_DTY_8I_ENTRIES = [
    (1, 1, 1),
    (2, 2, 10),
    (8, 8, 1),
    (12, 12, 10),
    (23, 23, 1),
    (24, 24, 1),
    (25, 25, (24, 25), 1),
    (26, 26, (25, 26), 1),
    (27, 27, (10, 27), 1),
    (28, 28, (22, 28), 1),
    (29, 29, (23, 29), 1),
    (30, 30, (23, 30), 1),
    (31, 31, (25, 31), 1),
    (32, 32, (12, 32), 1),
    (33, 33, (12, 33), 1),
    (10, 10, 1),
    (11, 11, 1),
    (34, 34, 1),
    (35, 35, (1, 35), 1),
    (36, 36, 1),
    (37, 37, 1),
    (38, 38, 1),
    (40, 40, 1),
    (41, 41, 1),
    (42, 42, 1),
    (43, 43, 1),
    (44, 44, 1),
    (45, 45, 1),
    (46, 46, 1),
    (47, 47, 1),
    (48, 48, 1),
    (49, 49, 1),
    (50, 50, 1),
    (51, 51, 1),
    (52, 52, 1),
    (53, 53, 1),
    (54, 54, 1),
    (55, 55, 1),
    (56, 56, 1),
    (57, 57, 1),
    (59, 59, 1),
    (60, 60, 1),
    (61, 61, 1),
    (62, 62, 1),
    (63, 63, 1),
    (64, 64, 1),
    (65, 65, 1),
    (66, 66, 1),
    (67, 67, 1),
    (71, 71, 1),
    (72, 72, 1),
    (73, 73, 1),
    (75, 75, 1),
    (77, 77, 1),
    (78, 78, 1),
    (79, 79, 1),
    (80, 80, 1),
    (81, 81, 1),
    (82, 82, 1),
    (83, 83, 1),
    (84, 84, 1),
    (85, 85, 1),
    (86, 86, 1),
    (87, 87, (1, 87), 1),
    (89, 89, 1),
    (90, 90, 1),
    (92, 92, 1),
    (93, 93, 1),
    (98, 98, 1),
    (99, 99, 1),
    (103, 103, 1),
    (107, 107, 1),
    (117, 117, 1),
    (120, 120, 1),
    (124, 124, (1, 66), 1),
    (125, 125, 1),
    (126, 126, 1),
    (127, 127, 1),
    (128, 128, 1),
    (129, 129, 1),
    (130, 130, 1),
    (131, 131, 1),
    (132, 132, 1),
    (133, 133, 1),
    (134, 134, 1),
    (135, 135, 1),
    (137, 137, 1),
    (138, 138, 1),
    (139, 139, 1),
    (140, 140, 1),
    (141, 141, 1),
    (142, 142, 1),
    (143, 143, 1),
    (144, 144, 1),
    (145, 145, 1),
    (148, 148, (1, 37), 1),
    (149, 149, 1),
    (150, 150, 1),
    (151, 151, 1),
    (157, 157, 1),
    (158, 158, 1),
    (159, 159, 1),
    (160, 160, 1),
    (161, 161, 1),
    (162, 162, 1),
    (163, 163, 1),
    (164, 164, 1),
    (165, 165, 1),
    (166, 166, 1),
    (167, 167, 1),
    (168, 168, 1),
    (169, 169, 1),
    (170, 170, 1),
    (171, 171, 1),
    (173, 173, 1),
    (174, 174, 1),
    (175, 175, 1),
    (176, 176, 1),
    (177, 177, 1),
    (193, 193, 1),
    (194, 194, (1, 37), 1),
    (198, 198, 1),
    (199, 199, 1),
    (200, 200, 1),
    (201, 201, 1),
    (202, 202, (1, 159), 1),
    (203, 203, (1, 160), 1),
    (204, 204, (1, 162), 1),
    (205, 205, (1, 163), 1),
    (206, 206, (1, 177), 1),
    (207, 207, (1, 34), 1),
    (210, 210, 1),
    (211, 211, (1, 171), 1),
    (212, 212, 1),
    (213, 213, 1),
    (214, 214, 1),
    (215, 215, 1),
    (216, 216, 1),
    (217, 217, 1),
    (218, 218, 1),
    (219, 219, 1),
    (220, 220, 1),
    (221, 221, 1),
    (222, 222, 1),
    (223, 223, 1),
    (224, 224, 1),
    (225, 225, 1),
    (226, 226, 1),
    (227, 227, (1, 107), 1),
    (228, 228, 1),
    (229, 229, 1),
    (230, 230, 1),
    (234, 234, 1),
    (235, 235, 1),
    (236, 236, 1),
    (237, 237, 1),
    (238, 238, 1),
    (239, 239, 1),
    (242, 242, 1),
    (244, 244, 1),
    (245, 245, 1),
    (3, 2, 10),
    (4, 2, 10),
    (5, 1, 1),
    (6, 2, 10),
    (7, 2, 10),
    (9, 1, 1),
    (13,),
    (14,),
    (15, 23, 1),
    (16,),
    (17,),
    (18,),
    (19,),
    (20,),
    (21,),
    (22,),
    (39, 120, (1, 93, 1, 38), 1),
    (58, 109, 1),
    (68, 2, 10),
    (69,),
    (70,),
    (74, 109, 1),
    (76,),
    (88,),
    (91, 2, 10),
    (94, 1, 1),
    (95, 23, 1),
    (96, 96, 1),
    (97, 96, 1),
    (100,),
    (101,),
    (102, 102, 1),
    (104,),
    (105,),
    (106, 106, 1),
    (108, 109, 1),
    (109, 109, 1),
    (110, 111, 1),
    (111, 111, 1),
    (112, 112, 1),
    (113, 113, 1),
    (114, 114, 1),
    (115, 115, 1),
    (116, 102, 1),
    (118,),
    (119,),
    (121, 109, 1),
    (122, 109, 1),
    (123, 109, 1),
    (136,),
    (146, 146, 1),
    (147, 147, 1),
    (152, 2, 10),
    (153, 2, 10),
    (154, 2, 10),
    (155, 1, 1),
    (156, 12, 10),
    (172, 2, 10),
    (178, 178, 1),
    (179, 179, 1),
    (180, 180, 1),
    (181, 181, 1),
    (182, 182, 1),
    (183, 183, 1),
    (184, 12, 10),
    (185, 178, 1),
    (186, 179, 1),
    (187, 180, 1),
    (188, 181, 1),
    (189, 182, 1),
    (190, 183, 1),
    (191,),
    (192,),
    (195, 112, 1),
    (196, 113, 1),
    (197, 114, 1),
    (208, 208, 1),
    (209,),
    (231, 231, 1),
    (232, 231, 1),
    (233,),
    (240,),
    (241, 109, 1),
    (243,),
]


_DTY_8I = _DTY_8I_HEADER + encode_dty_table(_DTY_8I_ENTRIES)


# --- Captured deadbeef / thick-OCI reply templates (opaque, staged here) ---
# These byte blobs are the sqlplus / thick-OCI (deadbeef) codec's captured 11.2
# reply templates (OER status envelopes, describe/outbind/version trailers, the
# auth challenge/result trailers). They are reproduced from live XE 11.2 captures
# and are still opaque; they are collected here alongside the 8i blobs above to be
# decoded and restructured later (PROTOCOL.md §36, §39). The Mirror's encoders in
# seerdb/server/ import them.


# The capability word trailing the packed version in the post-login version reply
# (§39). Bytes [0:5] are stable across releases; the last two are a version-era
# capability level (3 on 10.2 / 11.2, larger on 21c) — the Mirror pins the 11.2
# value. Verified live by capturing sqlplus against 10.2 / 11.2 / 21c.
_OCI_VERSION_CAPS = bytes.fromhex('09010000000300')


def _oci_version_trailer(
    major: int, minor: int, component: int, patchset: int
) -> bytes:
    """The packed-version + capability trailer sqlplus reads after the banner.
    The version is the low three bytes of Oracle's packed version word in
    little-endian order — patchset, ``(minor << 4) | component``, major — then
    the capability word. Confirmed live: 10.2.0.5 → ``05 20 0a``, 11.2.0.2 →
    ``02 20 0b``, 21.0.0.0 → ``00 00 15``."""
    packed = (major << 24) | (minor << 20) | (component << 12) | (patchset << 8)
    return packed.to_bytes(4, 'big')[:3][::-1] + _OCI_VERSION_CAPS


_OCI_VERSION_TRAILER = _oci_version_trailer(11, 2, 0, 2)  # XE 11.2.0.2.0


# A 3-byte marker in the describe-column trailer. Load-bearing by position — the
# client draws ORA-03113 if it is zeroed (§36) — but its byte values' meaning is
# unpinned: carried verbatim as capture ground truth, not decoded (§39.2).
_OCI_DCB_MARKER = bytes.fromhex('060122')


# The compact 24-byte OCI OER token — the short form of _OCI_OER_ENVELOPE (§36)
# used by the simple exec / fetch-terminator / no-row status replies. Same
# logical fields as the envelope (status success at 1, sequence ub2 at 5,
# error_code ub4 at 12, statement category at 18, V$SQL command type at 22),
# packed into 24 bytes; offsets 7 and 8 are the constant 0x01.
_OCI_OER_SHORT = bytes.fromhex('040100000000000101000000000000000000000000000000')


def _oci_oer_short(
    *, sequence: int, command_type: int, category: int, error_code: int = 0
) -> bytes:
    oer = bytearray(_OCI_OER_SHORT)
    struct.pack_into('<H', oer, 5, sequence)
    struct.pack_into('<I', oer, 12, error_code)
    # FIXME: `category` at offset 18 (2 = row/value-producing, 1 = no-row) is the
    # same murky field as the envelope's offset 18; carried from the capture.
    oer[18] = category
    oer[22] = command_type
    return bytes(oer)


def _oci_exec_oer(sequence: int) -> bytes:
    # A SELECT execute's return status, wrapped in the exec-reply's zero padding.
    # ``sequence`` is the live per-session OER end-to-end counter (§36).
    return (
        b'\x00\x00\x00'
        + _oci_oer_short(sequence=sequence, command_type=oci.OCI_CMD_SELECT, category=2)
        + b'\x00' * 6
    )


# The 136-byte OCI OER return-status token, reverse-engineered against live 11g
# (docs/PROTOCOL.md §36). All three of the Mirror's OER status trailers — the
# error OER, the LONG-row fetch status, and the LOB-row fetch status — are this
# one envelope differing only in a handful of named fields, so build them rather
# than storing three near-identical blobs. The bulk (SCN/rowid/instance region,
# the fixed 0x20f6310a marker) is the same fixed frame; the fields below vary.
# FIXME: the offset-56 ub2 (0x0136 = 310) looks like the session's negotiated
# TTC protocol version (the 0x013x family; the Mirror pins 11g at 314) but is
# emitted as the captured constant, unconfirmed. Offsets 7 and 52 (both 0x01)
# are unnamed constants carried from the capture. See §36.1.
_OCI_OER_ENVELOPE = bytes.fromhex(
    '04000000000000010000000000000000000002000000030000000000000000000000'
    '00000000000000000000000000000000000001000000360100000000000000000000'
    '0000000020f6310a0000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000000'
)


def encode_oci_oer(
    status: int,
    *,
    sequence: int,
    row_kind: int = oci.OCI_OER_ROW_KIND_NONE,
    error_pos: int = 0,
    error_code: int = 0,
    command_type: int = oci.OCI_CMD_SELECT,
) -> bytes:
    """Build a 136-byte OCI OER return-status token (§36) over
    :data:`_OCI_OER_ENVELOPE`. ``status`` is SUCCESS (0x01) or ERROR (0x05);
    ``row_kind`` marks a LOB/LONG-row status; ``error_pos`` and ``error_code``
    (ub4 LE at offset 12) carry an ORA error; ``command_type`` is the V$SQL
    command type at offset 22 (SELECT by default — the envelope's value).
    ``sequence`` is the OER's **end-to-end sequence number** (a ub2 LE at offset
    5); its echo (ub2 LE at offset 49) is ``sequence + 2`` for the row/return
    statuses. The caller appends the ``ORA-…`` message DALC for the error case.

    The field is a diagnostic/tracing counter, not a protocol-correctness field:
    both reference clients (thin and thick) read it and discard it — never
    validate, echo, or transmit it. The Mirror advances it with a real
    per-session counter (:class:`~seerdb.server.session._OciSequence`) so its
    replies look like a live server's rather than emitting the frozen value each
    status was captured with; the start/step is Mirror policy (§36.1)."""
    oer = bytearray(_OCI_OER_ENVELOPE)
    oer[1] = status
    struct.pack_into('<H', oer, 5, sequence)
    oer[8] = row_kind
    # The OCI frame's error-position field is a single byte; clamp a larger
    # parse offset rather than overflow the assignment (the caret then lands at
    # the last column it can express).
    oer[20] = min(max(error_pos, 0), 0xFF)
    oer[22] = command_type
    # FIXME: the offset-49 echo is only reliably `sequence + 2` for the row /
    # return statuses; the outbind reply carries 0 there instead, so this is not
    # a settled rule. Semantics of the field are unpinned (see §36.1).
    struct.pack_into('<H', oer, 49, sequence + 2)
    struct.pack_into('<I', oer, 12, error_code)
    return bytes(oer)


# The 35-byte `08 06` OCI exec-status frame preamble, shared by the describe /
# outbind / DDL / DML statuses. It is all zero (the Mirror has no live
# per-statement session counters) but for the header, a ub2-LE **cursor id** at
# offset 4 (the DDL / DML statuses carry a live cursor id here; the describe /
# outbind status carries none), and two small marker bytes whose values track the
# statement kind but whose exact meaning is unpinned, carried from the capture:
# offset 11 is `0x02` on a value/row-producing status (describe / outbind / DML)
# and `0` on DDL; offset 15 is `0x01` on the DML status and `0` otherwise.
_OCI_STATUS_FRAME_PREFIX_LEN = 35
_OCI_STATUS_FRAME_HEADER = bytes([0x08, 0x06])
_OCI_STATUS_FRAME_CURSOR_OFF = 4  # ub2 LE cursor id
_OCI_STATUS_FRAME_ROWS_OFF = 11  # 0x02 on a value/row-producing status
_OCI_STATUS_FRAME_DML_OFF = 15  # 0x01 on the DML status


def _oci_status_frame_prefix(
    cursor_id: int = 0, *, row_producing: bool = False, dml: bool = False
) -> bytes:
    pre = bytearray(_OCI_STATUS_FRAME_PREFIX_LEN)
    pre[0:2] = _OCI_STATUS_FRAME_HEADER
    struct.pack_into('<H', pre, _OCI_STATUS_FRAME_CURSOR_OFF, cursor_id)
    if row_producing:
        pre[_OCI_STATUS_FRAME_ROWS_OFF] = 0x02
    if dml:
        pre[_OCI_STATUS_FRAME_DML_OFF] = 0x01
    return bytes(pre)


_OCI_STATUS_FRAME_PREFIX = _oci_status_frame_prefix(row_producing=True)


def _oci_fetch_oer_header(sequence: int) -> bytes:
    # The fetch-terminator OER: a compact OER carrying ORA-01403 (no data found).
    return _oci_oer_short(
        sequence=sequence, command_type=oci.OCI_CMD_SELECT, category=2, error_code=1403
    )


# The one instance constant inside the end-of-fetch OER (§36) — the same
# `f6 31 0a` marker that recurs as `20 f6 31 0a` in _OCI_OER_ENVELOPE. Carried
# verbatim as capture ground truth; its meaning is unpinned, not decoded (§39.2).
_OCI_FETCH_CONST = bytes.fromhex('f6310a')


# The describe-only reply's trailing execute status (§36.3): the shared status
# preamble + a success OER. offset 20 carries a non-zero value under a success
# status — carried from the live capture; its meaning in the describe context is
# unclear, but it is fixed across captures.
def _oci_lob_describe_status(sequence: int) -> bytes:
    return _OCI_STATUS_FRAME_PREFIX + encode_oci_oer(
        oci.OCI_OER_STATUS_SUCCESS, sequence=sequence, error_pos=14
    )


# The reply for a statement that returns no rows — a PL/SQL block or DDL: a
# compact PL/SQL-block OER (category 1 = no rows), wrapped in the exec-reply's
# zero padding. Structure only; the SCN / counts a live reply carries are zero
# (#265).
def _oci_status_oer(sequence: int) -> bytes:
    return (
        b'\x00\x00\x00'
        + _oci_oer_short(sequence=sequence, command_type=oci.OCI_CMD_PLSQL, category=1)
        + b'\x00' * 6
    )


# The DML execute-status frame (§36.3): the 35-byte preamble (its cursor id
# `0x5be8` carried from the capture, plus the row-producing and DML markers) +
# the 136-byte OER + a 16-byte trailer. Unlike the describe/DDL/outbind statuses
# its OER embeds the touched row's physical **rowid** (offsets 27..40 within the
# OER, echoed byte-swapped in the trailer) — capture-specific, opaque to sqlplus
# (which renders "N rows created" from only the rowcount and command type). The
# rowcount (OER offset 8) and command type (OER offset 22) are patched per call.
_OCI_DML_FRAME_PREFIX = _oci_status_frame_prefix(0x5BE8, row_producing=True, dml=True)


# The captured touched-row rowid (OER offsets 27..40). FIXME: real physical row
# identity from the capture; carried, like the LOB LID (§14.6) — a synthetic
# value would need live 11g validation.
_OCI_DML_ROWID = bytes.fromhex('007fb5010001000000b1b4000000')


def _oci_dml_frame_trailer(rowid: bytes) -> bytes:
    # The 16-byte DML status trailer is NOT independent of the rowid: it splices
    # two of the rowid's 2-byte words back in byte-swapped — rowid[1:3] lands at
    # offset 6 (7f b5 → b5 7f) and rowid[9:11] at offset 12 (b1 b4 → b4 b1) —
    # inside an otherwise fixed frame. Both come from the same captured row, so
    # derive the trailer rather than store a second blob; the physical fields'
    # meaning stays unpinned.
    return (
        bytes([0x0D, 0x00, 0x0D, 0x01, 0x00, 0x01])
        + rowid[1:3][::-1]
        + bytes([0x00, 0x01, 0x00, 0x00])
        + rowid[9:11][::-1]
        + bytes([0x00, 0x00])
    )


_OCI_DML_FRAME_TRAILER = _oci_dml_frame_trailer(_OCI_DML_ROWID)


def _oci_dml_status_frame(sequence: int) -> bytes:
    # status 2 is the DML call status (not the fetch/exec 1); offset-20 carries a
    # non-zero value under it (the same murky field as the describe status, §36.1).
    oer = bytearray(encode_oci_oer(2, sequence=sequence, error_pos=12, command_type=0))
    oer[27 : 27 + len(_OCI_DML_ROWID)] = _OCI_DML_ROWID
    oer[80] = 0x0D  # carried row/SCN byte
    return _OCI_DML_FRAME_PREFIX + bytes(oer) + _OCI_DML_FRAME_TRAILER


# The DDL execute-status preamble (§36.3): the shared status prefix carrying a
# cursor id (`0x5beb` at offsets 4..5, carried from the capture) and — being a
# no-row statement — neither the row-producing nor the DML marker.
# encode_ddl_status_oci completes the frame with a success OER whose command type
# is the DDL verb's.
_OCI_DDL_FRAME_PREFIX = _oci_status_frame_prefix(0x5BEB)


# The sqlplus / thick-OCI reply to a PL/SQL block that assigned OUT binds — the
# ``VARIABLE v NUMBER`` / ``EXEC :v := 42`` flow. The client parked bind buffers
# and expects their values back: a ttc=0b01 message whose body is a fixed header
# (bind count at offset 4), one 0x10 define-marker per bind, then an RXD row
# (``0x07`` + one DALC per OUT value, each followed by a 2-byte per-bind return
# code) and a fixed status/OER tail. Reduced to structure from live 11g replies
# (single NUMBER, two NUMBERs, VARCHAR): the server pointer (@18), SCN and an
# internal sequence counter are instance-specific and zeroed; everything else is
# computed from the OUT values (#347).
def _oci_outbind_header(bind_count: int) -> bytes:
    """The 50-byte OCI OUT-bind reply header (#347): the TTC out-bind opcode
    (0b 01) and two fixed bytes, the bind count at offset 4, and the fixed 11.2
    identity bytes at offsets 10 and 28..29 (a row-buffer size). The rest is the
    instance state (server pointer, SCN, sequence) the Mirror leaves zeroed."""
    header = bytearray(50)
    header[0:4] = b'\x0b\x01\x05\xcc'
    header[4] = bind_count
    header[10] = 0x01
    header[28:30] = b'\xe8\x07'
    return bytes(header)


# The outbind (PL/SQL OUT-bind) reply's trailing execute status: the shared
# status preamble + a PL/SQL-block success OER. Unlike the describe/DDL statuses
# this reply does not echo the sequence at offset 49 (it stays 0), so that field
# is cleared after the envelope build.
def _oci_outbind_tail(sequence: int) -> bytes:
    oer = bytearray(
        encode_oci_oer(
            oci.OCI_OER_STATUS_SUCCESS,
            sequence=sequence,
            row_kind=oci.OCI_OER_ROW_KIND_LOB,
            command_type=oci.OCI_CMD_PLSQL,
        )
    )
    # FIXME: why this reply zeroes the offset-49 echo while the describe / DDL
    # statuses carry `sequence + 2` there is unknown (see §36.1).
    oer[49] = 0
    return _OCI_STATUS_FRAME_PREFIX + bytes(oer)


def _oci_tti_sta(call_status: int, value: int) -> bytes:
    """A small TTI_STA acknowledgement — a ``TTI_STA`` token, the OER call status
    (ub4 LE) and a ub2 value (row count / message length), carried from the
    capture. The commit and logoff acks sqlplus waits for share this shape."""
    return (
        bytes([TTI_STA])
        + call_status.to_bytes(4, 'little')
        + value.to_bytes(2, 'little')
    )


# A live commit reply. sqlplus sends a bare commit before the user's statement;
# this acknowledges it.
_OCI_COMMIT_STATUS = _oci_tti_sta(5, 0x12)


# sqlplus waits for this ack of its logoff before closing; without it the client
# sees an abrupt EOF and reports ORA-03113 on exit.
_OCI_LOGOFF_STATUS = _oci_tti_sta(1, 0)


def _oci_auth_trailer(sequence: int) -> bytes:
    """The 136-byte OER-shaped status block trailing an OCI auth key-value list.

    It is the same OER frame as :data:`_OCI_OER_ENVELOPE` (§36.1) with the
    auth-reply fields set: success status (offset 1), the reply sequence (offset
    5, echoed at offset 49 *as-is* — the return-status OER instead echoes it as
    ``+2``), and no command type. The sequence is the only thing distinguishing
    the challenge reply (2) from the result reply (3).
    """
    trailer = bytearray(_OCI_OER_ENVELOPE)
    trailer[1] = oci.OCI_OER_STATUS_SUCCESS
    trailer[5] = trailer[49] = sequence
    trailer[18] = trailer[22] = trailer[52] = 0
    return bytes(trailer)


_CHALLENGE_TRAILER = _oci_auth_trailer(2)
_RESULT_TRAILER = _oci_auth_trailer(3)


# --- Captured 11g handshake-identity blobs (opaque, staged here) ---


# --- the TTI_PRO capability block (thin PRO reply == sqlplus DTY reply) ---
# The block carries a count-prefixed array of 5-byte charset elements. Each element
# is ``<a> 03 <b> 03 <flag>``: two operand bytes, each followed by a constant 0x03
# tag, then a flag byte. The captured 11.2 server advertises ten elements — a hub
# operand (0x66) paired both directions with {0x40, 0x48, 0x52, 0x61, 0x1f}; every
# pair carries flag 0x01 except the forward 0x66->0x1f pair (0x08). The operands are
# the server's captured NLS charset-conversion codes, carried as ground truth (0x1f
# is charset 31, WE8ISO8859P1); the ratio semantics are not otherwise decoded, so
# the entries stay captured constants like the DTY table's conversion numbers.
_CHARSET_ELEM_SEP = 0x03  # constant tag following each operand in an element


def encode_charset_elements(entries: list) -> bytes:
    """Render the TTI_PRO charset-element array body — a flat concatenation of
    5-byte ``<a> 03 <b> 03 <flag>`` records (the caller prefixes the ub2 count).
    Inverse of :func:`decode_charset_elements`."""
    out = bytearray()
    for a, b, flag in entries:
        out += bytes([a, _CHARSET_ELEM_SEP, b, _CHARSET_ELEM_SEP, flag])
    return bytes(out)


def decode_charset_elements(body: bytes) -> list:
    """Parse a TTI_PRO charset-element array body into ``(a, b, flag)`` triples —
    the inverse of :func:`encode_charset_elements`. The two 0x03 separator tags are
    dropped."""
    return [(body[i], body[i + 2], body[i + 4]) for i in range(0, len(body), 5)]


_PRO_CHARSET_ENTRIES = [
    (0x66, 0x40, 1),
    (0x40, 0x66, 1),
    (0x66, 0x48, 1),
    (0x48, 0x66, 1),
    (0x66, 0x52, 1),
    (0x52, 0x66, 1),
    (0x66, 0x61, 1),
    (0x61, 0x66, 1),
    (0x66, 0x1F, 8),
    (0x1F, 0x66, 1),
]
_PRO_CHARSET_ELEMENTS = encode_charset_elements(_PRO_CHARSET_ENTRIES)


# The FDO (Fixed Data Object): a length-framed character-set descriptor. It ends
# with the server's charset pair, which a client locates inside the block at offset
# ``6 + fdo[5] + fdo[6]`` (the two section lengths) — how the reference clients read
# the national charset out of it. Layout (100 bytes):
#   u32 BE content length (block - 4) | 01 version | secA_len | secB_len |
#   50-byte per-datatype representation vector | 83 tag |
#   db charset (u16 BE) | national charset (u16 BE) | 03 tag | zero pad to 100.
# The two charset ids are the decoded fields (AL32UTF8 = DB, AL16UTF16 = national);
# the representation vector and the 0x83/0x03 frame tags are carried as captured
# ground truth — even the reference clients skip the vector rather than interpret it.
_FDO_SIZE = 100
_FDO_VERSION = 0x01
_FDO_SECTION_A = 0x24  # 36 — first section length (locates the charset pair, below)
_FDO_SECTION_B = 0x0F  # 15 — second section length
_FDO_CHARSET_TAG = 0x83  # marks the start of the trailing charset descriptor
_FDO_CHARSET_END = 0x03  # closes the charset descriptor
_FDO_TYPEREP = bytes.fromhex(  # 50-byte per-datatype representation vector (opaque)
    '050b0c030c0c0504050d0609070805050505050f05050505050a05050505050405060708'
    '0823472347081123081141b04700'
)


def _build_pro_fdo() -> bytes:
    """Assemble the 100-byte FDO from its length header, the opaque type-rep vector,
    and the named (DB, national) charset pair, zero-padded to size. The charset pair
    lands at offset ``6 + fdo[5] + fdo[6]`` so a client parses the national charset
    out of it exactly as the reference clients do."""
    body = (
        struct.pack('>I', _FDO_SIZE - 4)  # content length after this u32
        + bytes([_FDO_VERSION, _FDO_SECTION_A, _FDO_SECTION_B])
        + _FDO_TYPEREP
        + bytes([_FDO_CHARSET_TAG])
        + struct.pack('>H', AL32UTF8_CHARSET)  # DB charset
        + struct.pack('>H', AL16UTF16_CHARSET)  # national charset
        + bytes([_FDO_CHARSET_END])
    )
    return body + b'\x00' * (_FDO_SIZE - len(body))


_PRO_FDO = _build_pro_fdo()


# The 11g server's own capability vectors, modelled as {index: value} feature maps
# (like the client vectors in _COMPILE_CAPS / _RUNTIME_CAPS) rather than hex blobs.
# Named slots use the CCAP_* / RCAP_* indices; the slots seerdb has no name for are
# kept by numeric index for byte-parity (the client vectors carry the same). This is
# the *server's* advertised identity — the client negotiates the field version off
# _SERVER_COMPILE_CAPS[CCAP_FIELD_VERSION] (§4.2).
_SERVER_COMPILE_CAPS = _render_caps(
    (
        39,
        {
            CCAP_SQL_VERSION: 0x06,
            CCAP_LOGON_TYPES: 0x0F,
            CCAP_FEATURE_BACKPORT: 0x01,
            CCAP_FIELD_VERSION: FIELD_VERSION_11_2,  # 0x06
            CCAP_SERVER_DEFINE_CONV: 0x01,
            CCAP_DEQUEUE_WITH_SELECTOR: 0x01,
            CCAP_TTC1: 0x7F,
            CCAP_OCI1: 0xFF,
            CCAP_TDS_VERSION: 0x03,
            CCAP_RPC_VERSION: 0x0A,
            CCAP_RPC_SIG: 0x03,
            CCAP_DBF_VERSION: 0x01,
            CCAP_LOB: 0x7F,
            CCAP_TTC2: 0xFF,
            CCAP_UB2_DTY: 0x01,
            CCAP_OCI2: 0x3F,
            CCAP_CLIENT_FN: 0x06,
            CCAP_TTC3: 0x03,
            # Unnamed slots the 11.2 server sets; kept by index for byte-parity.
            1: 0x01,
            2: 0x01,
            3: 0x01,
            6: 0x01,
            10: 0x01,
            11: 0x01,
            12: 0x01,
            13: 0x01,
            14: 0x01,
            20: 0x03,
            24: 0x01,
            25: 0x7F,
            28: 0x06,
            29: 0x01,
            30: 0x01,
            32: 0x01,
            33: 0x03,
            36: 0x01,
            38: 0x02,
        },
    )
)


_SERVER_RUNTIME_CAPS = _render_caps(
    (
        7,
        {
            RCAP_COMPAT: RCAP_COMPAT_81,  # 0x02
            RCAP_TTC: RCAP_TTC_ZERO_COPY | 0x02,  # 0x03
            # Unnamed slots the 11.2 server sets; kept by index for byte-parity.
            1: 0x01,
            3: 0x01,
            4: 0x18,
        },
    )
)


# --- the thin DTY reply: the server's type-conversion table ---
# The server's type-conversion entries (the 913-byte body; the caller prepends
# TTI_DTY). Same old byte format as _DTY_8I's entries, rendered by encode_dty_table.
_SERVER_DTY_ENTRIES = [
    (1, 1, 1),
    (2, 2, 10),
    (8, 8, 1),
    (12, 12, 10),
    (23, 23, 1),
    (24, 24, 1),
    (25, 25, 1),
    (26, 26, 1),
    (27, 27, 1),
    (28, 28, 1),
    (29, 29, 1),
    (30, 30, 1),
    (31, 31, 1),
    (32, 32, 1),
    (33, 33, 1),
    (10, 10, 1),
    (11, 11, 1),
    (40, 40, 1),
    (41, 41, 1),
    (117, 117, 1),
    (120, 120, 1),
    (34, 34, 1),
    (35, 35, 1),
    (36, 36, 1),
    (37, 37, 1),
    (38, 38, 1),
    (42, 42, 1),
    (43, 43, 1),
    (44, 44, 1),
    (45, 45, 1),
    (46, 46, 1),
    (47, 47, 1),
    (48, 48, 1),
    (49, 49, 1),
    (50, 50, 1),
    (51, 51, 1),
    (52, 52, 1),
    (53, 53, 1),
    (54, 54, 1),
    (55, 55, 1),
    (56, 56, 1),
    (57, 57, 1),
    (59, 59, 1),
    (60, 60, 1),
    (61, 61, 1),
    (62, 62, 1),
    (63, 63, 1),
    (64, 64, 1),
    (65, 65, 1),
    (66, 66, 1),
    (67, 67, 1),
    (71, 71, 1),
    (72, 72, 1),
    (73, 73, 1),
    (75, 75, 1),
    (77, 77, 1),
    (78, 78, 1),
    (79, 79, 1),
    (80, 80, 1),
    (81, 81, 1),
    (82, 82, 1),
    (83, 83, 1),
    (84, 84, 1),
    (85, 85, 1),
    (86, 86, 1),
    (87, 87, 1),
    (88, 88, 1),
    (89, 89, 1),
    (90, 90, 1),
    (92, 92, 1),
    (93, 93, 1),
    (98, 98, 1),
    (99, 99, 1),
    (103, 103, 1),
    (107, 107, 1),
    (124, 124, 1),
    (125, 125, 1),
    (126, 126, 1),
    (127, 127, 1),
    (128, 128, 1),
    (129, 129, 1),
    (130, 130, 1),
    (131, 131, 1),
    (132, 132, 1),
    (133, 133, 1),
    (134, 134, 1),
    (135, 135, 1),
    (137, 137, 1),
    (138, 138, 1),
    (139, 139, 1),
    (140, 140, 1),
    (141, 141, 1),
    (142, 142, 1),
    (143, 143, 1),
    (144, 144, 1),
    (145, 145, 1),
    (148, 148, 1),
    (149, 149, 1),
    (150, 150, 1),
    (151, 151, 1),
    (157, 157, 1),
    (158, 158, 1),
    (159, 159, 1),
    (160, 160, 1),
    (161, 161, 1),
    (162, 162, 1),
    (163, 163, 1),
    (164, 164, 1),
    (165, 165, 1),
    (166, 166, 1),
    (167, 167, 1),
    (168, 168, 1),
    (169, 169, 1),
    (170, 170, 1),
    (171, 171, 1),
    (173, 173, 1),
    (174, 174, 1),
    (175, 175, 1),
    (176, 176, 1),
    (177, 177, 1),
    (193, 193, 1),
    (194, 194, 1),
    (198, 198, 1),
    (199, 199, 1),
    (200, 200, 1),
    (201, 201, 1),
    (202, 202, 1),
    (203, 203, 1),
    (204, 204, 1),
    (205, 205, 1),
    (206, 206, 1),
    (207, 207, 1),
    (210, 210, 1),
    (211, 211, 1),
    (212, 212, 1),
    (213, 213, 1),
    (214, 214, 1),
    (215, 215, 1),
    (216, 216, 1),
    (217, 217, 1),
    (218, 218, 1),
    (219, 219, 1),
    (220, 220, 1),
    (221, 221, 1),
    (222, 222, 1),
    (223, 223, 1),
    (224, 224, 1),
    (225, 225, 1),
    (226, 226, 1),
    (227, 227, 1),
    (228, 228, 1),
    (229, 229, 1),
    (230, 230, 1),
    (234, 234, 1),
    (235, 235, 1),
    (236, 236, 1),
    (237, 237, 1),
    (238, 238, 1),
    (239, 239, 1),
    (240, 240, 1),
    (242, 242, 1),
    (243, 243, 1),
    (244, 244, 1),
    (245, 245, 1),
    (246,),
    (253,),
    (254,),
    (3, 2, 10),
    (4, 2, 10),
    (5, 1, 1),
    (6, 2, 10),
    (7, 2, 10),
    (9, 1, 1),
    (13,),
    (14,),
    (15, 23, 1),
    (16,),
    (17,),
    (18,),
    (19,),
    (20,),
    (21,),
    (22,),
    (39, 120, 1),
    (58,),
    (68, 2, 10),
    (69,),
    (70,),
    (74,),
    (76,),
    (91, 2, 10),
    (94, 1, 1),
    (95, 23, 1),
    (96, 96, 1),
    (97, 96, 1),
    (100, 100, 1),
    (101, 101, 1),
    (102, 102, 1),
    (104,),
    (105,),
    (106, 106, 1),
    (108, 109, 1),
    (109, 109, 1),
    (110, 111, 1),
    (111, 111, 1),
    (112, 112, 1),
    (113, 113, 1),
    (114, 114, 1),
    (115, 115, 1),
    (116, 102, 1),
    (118,),
    (119,),
    (121,),
    (122,),
    (123,),
    (136,),
    (146, 146, 1),
    (147, 147, 1),
    (152, 2, 10),
    (153, 2, 10),
    (154, 2, 10),
    (155, 1, 1),
    (156, 12, 10),
    (172, 2, 10),
    (178, 178, 1),
    (179, 179, 1),
    (180, 180, 1),
    (181, 181, 1),
    (182, 182, 1),
    (183, 183, 1),
    (184,),
    (185,),
    (186,),
    (187,),
    (188,),
    (189,),
    (190,),
    (191,),
    (192,),
    (195,),
    (196,),
    (197,),
    (208, 208, 1),
    (209,),
    (231, 231, 1),
    (232,),
    (233, 233, 1),
    (241,),
]


_SERVER_DTY_TABLE = encode_dty_table(_SERVER_DTY_ENTRIES)  # 913-byte type table


# --- OCI LOB read round-trip (CLOB / BLOB SELECT, #405) ---
# STATUS: WORKING — sqlplus displays CLOB and BLOB values over the Mirror
# (single-packet and multi-packet content, session stays clean afterward). The
# load-bearing pieces, verified against live 11g out-of-line CLOB captures:
#   * the locator's size field is the content BYTE count (2× characters for a
#     CLOB, raw bytes for a BLOB), big-endian — NOT the character count the first
#     attempt used (the core unit bug);
#   * the LOB execute reply is a describe with a distinct 33-byte tail + LOB
#     status (encode_lob_describe_oci) and data_length 4000, NOT the ordinary
#     inline-row DCB tail — THE UNLOCK; with the wrong describe sqlplus rejects
#     even a byte-perfect locator row;
#   * the locator row is fetched (_oci_lob_rxh) and ends with a non-terminator
#     "more" OER (encode_lob_fetch_rows_oci); a following fetch draws the 1403;
#   * the READ reply's LOB_DATA uses 0xFF-byte chunks (matches 11g).
# The row value and the READ reply tail below share ONE generated locator
# (:func:`_oci_lob_locator`), so they stay mutually consistent. The reply shapes
# were reduced from a live 11g out-of-line CLOB read (2000 chars → 4000 bytes).
#
# KNOWN LIMITATION (follow-up): the read returns the WHOLE LOB regardless of the
# amount sqlplus requested in the TTI_LOBOPS call, so the client must read it in
# one go — works when SET LONGCHUNKSIZE covers the content, but a default-settings
# read (80-char chunks, looping) over-reads. Honoring the request's amount/offset
# for a proper read loop is the next step.
#
# A LOB column is not sent inline: the row carries an opaque locator, and sqlplus
# fetches the content with a separate TTI_LOBOPS READ (§14). The locator is opaque
# to sqlplus (it echoes it back verbatim in the READ), so the Mirror mints it from
# this one template, patching the content **byte** size (ub4 big-endian) that
# sqlplus reads to size its READ — a CLOB counts UTF-16 bytes (2× characters), a
# BLOB counts its raw bytes. The content never rides in the locator (out-of-line):
# it returns in the READ reply's LOB_DATA. A ub4-LE num_bytes frames the locator
# in the row; a NULL LOB is num_bytes 0, no READ.
# The body of the 105-byte persistent-LOB locator (offset 9 onward). Its physical
# **LOB Locator ID** — the object id, three segment DBAs and an SCN of a real LOB
# in the source database — is opaque to the client, which only echoes the locator
# on each LOB op. The Mirror has no such segment, so it emits a **synthetic LID of
# zeros**: verified live against sqlplus 11.2 over the Mirror, which reads the CLOB
# and BLOB content back correctly with the physical fields zeroed (drivers such as
# go-ora only interpret the header flag bits, never the LID). With the physical
# LID gone the CLOB and BLOB bodies are identical bar the charset id, so one
# template serves both; the charset id (offset 31, ub2 BE) is generated. The
# content byte-size slot (offset 91, ub4 BE) is patched per value.
_OCI_LOB_LOCATOR_BODY = bytes.fromhex(
    '00000001000000560000000100000001000000020002000000020000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000000001'
    '000000000000000000140500000000000fa000000000000200000000'
)

_OCI_LOB_CHARSET_ID_OFF = 31 - 9  # charset id ub2 BE, within the body
_OCI_LOB_CHARSET_ID_AL32UTF8 = 0x0369  # a CLOB's charset; a BLOB carries 0


def _oci_lob_locator(is_clob: bool) -> bytes:
    """The 105-byte persistent-LOB locator sqlplus binds and echoes (§14.6),
    generated field by field. The 9-byte header carries the LOB kind (charset
    form, flags, LOB type); the body is the shared structural template with the
    charset id set for a CLOB and a zeroed synthetic LID."""
    body = bytearray(_OCI_LOB_LOCATOR_BODY)
    if is_clob:
        struct.pack_into(
            '>H', body, _OCI_LOB_CHARSET_ID_OFF, _OCI_LOB_CHARSET_ID_AL32UTF8
        )
    header = bytes(
        [
            0x68,
            0x00,
            0x01,  # locator length + version
            0x02 if is_clob else 0x01,  # charset form (CLOB char / BLOB binary)
            0x0C,
            0x88 if is_clob else 0x08,  # flags — bit 0x80 = variable-width charset
            0x00,
            0x00,
            0x02 if is_clob else 0x01,  # LOB type
        ]
    )
    return header + bytes(body)


# The RXD value for a LOB column: a ub4 LE + ub2 LE length (both 106) then the
# locator. The content byte size at offset 97 is patched per value.
_OCI_LOB_ROW_VALUE = {
    is_clob: struct.pack('<I', 106) + struct.pack('<H', 106) + _oci_lob_locator(is_clob)
    for is_clob in (True, False)
}


def _oci_lob_read_tail(is_clob: bool, sequence: int) -> bytes:
    # The TTI_LOBOPS READ reply tail after the LOB_DATA content: a TTI_RPA (0x08
    # 0x00, the echoed locator, then the ub4 LE amount read — characters for a
    # CLOB, bytes for a BLOB) then the LOB-row OER call status. The echoed
    # locator's byte size (offset 93) and the amount (offset 107) are patched to
    # stay consistent with the content delivered. ``sequence`` is the live
    # per-session OER counter (§36) for the trailing status OER.
    oer = bytearray(
        encode_oci_oer(
            oci.OCI_OER_STATUS_SUCCESS,
            sequence=sequence,
            row_kind=oci.OCI_OER_ROW_KIND_LOB,
            command_type=0,
        )
    )
    oer[18] = 0  # FIXME: the LOB read-status OER zeroes offset 18 (see §36.1)
    amount = 2000 if is_clob else 4000
    return (
        b'\x08\x00'
        + _oci_lob_locator(is_clob)
        + struct.pack('<I', amount)
        + b'\x00' * 4
        + bytes(oer)
    )


# --- Mirror deadbeef/OCI codec (parse/describe/rows/status/LOB, #265) ---


_OCI_ALL8_CURSOR_OFF = 7  # ub4 LE; 0 = a new statement


_OCI_ALL8_SQLLEN3_OFF = 19  # ub4 LE = 3 x the SQL byte length


_OCI_ALL8_SQL_OFF = 196  # SQL text; the ub1 length prefix is the byte before it


def parse_exec_oci(payload: bytes) -> ExecRequest:
    """Parse a sqlplus / thick-OCI (deadbeef dialect) OALL8 execute (#265).

    The OCI counterpart of :func:`parse_exec`. Extracts the SQL text and cursor
    id from the fixed-shape OCI header. Scope: a single statement with no binds
    and SQL up to 253 bytes (the ub1 length prefix) — binds and chunked/long SQL
    are a follow-up, gated by the length cross-check below. Raises
    :class:`InterfaceError` if the message is not an OCI OALL8 in that shape.
    """
    if (
        len(payload) < _OCI_ALL8_SQL_OFF
        or payload[0] != TTI_FUN
        or payload[1] != TTI_ALL8
    ):
        raise InterfaceError('not an OCI OALL8 execute')
    # Validate the indicators where the thin form has 0x01 flags, so a
    # differently-shaped message errors rather than yielding a garbage SQL.
    for ind_off in (11, 27):
        if payload[ind_off : ind_off + 8] != oci.OCI_INDICATOR:
            raise InterfaceError(f'OCI OALL8: no indicator at offset {ind_off}')
    cursor = int.from_bytes(
        payload[_OCI_ALL8_CURSOR_OFF : _OCI_ALL8_CURSOR_OFF + 4], 'little'
    )
    marker = payload[_OCI_ALL8_SQL_OFF - 1]  # ub1 length prefix (0xFE = chunked)
    declared_len = (
        int.from_bytes(
            payload[_OCI_ALL8_SQLLEN3_OFF : _OCI_ALL8_SQLLEN3_OFF + 4], 'little'
        )
        // 3
    )
    if marker == 0xFE:
        # Long SQL — chunked from the marker: 0xFE, then <ub1 len><chunk> repeated
        # (a zero length, or the declared total, ends it).
        raw_sql = _read_chunked_sql(payload[_OCI_ALL8_SQL_OFF - 1 :], declared_len)
    elif marker == declared_len:
        raw_sql = payload[_OCI_ALL8_SQL_OFF : _OCI_ALL8_SQL_OFF + marker]
    else:
        # The two lengths disagree only for a bound statement (the bind section
        # shifts things) — out of this increment's scope, a clean error.
        raise InterfaceError('OCI OALL8: SQL length mismatch (binds not supported)')
    # sqlplus null-terminates its *internal* queries (the length counts the NUL);
    # a user-typed statement has none. Strip trailing NULs so the backend sees
    # clean SQL either way.
    sql = raw_sql.rstrip(b'\x00').decode('utf-8')
    bind_count = int.from_bytes(
        payload[_OCI_BIND_COUNT_OFF : _OCI_BIND_COUNT_OFF + 4], 'little'
    )
    binds: list = []
    bind_meta: list[tuple[int, int]] = []
    if bind_count and marker != 0xFE:
        binds, bind_meta = _parse_oci_binds(
            payload, _OCI_ALL8_SQL_OFF + marker, bind_count
        )
    return ExecRequest(
        sql=sql,
        cursor=cursor,
        bind_count=bind_count,
        fetch=0,
        binds=binds,
        bind_rows=[binds] if binds else [],
        bind_meta=bind_meta,
    )


# The bind count sits at this fixed ub4 in the OCI OALL8 header. After the SQL
# come an option array, one OAC type-descriptor per bind (each led by
# ``01 <TNS type> 03 00 00``), and an RXD row (``0x07`` + one DALC value per
# bind) — the same value framing the thin form uses (#265, #347).
_OCI_BIND_COUNT_OFF = 83


_OCI_OAC_MARKER = re.compile(rb'\x01(.)\x03\x00\x00')


_OCI_BIND_TYPES = frozenset(
    {
        TNS_TYPE_VARCHAR,
        TNS_TYPE_NUMBER,
        TNS_TYPE_DATE,
        TNS_TYPE_RAW,
        TNS_TYPE_CHAR,
        TNS_TYPE_TIMESTAMP,
        TNS_TYPE_TIMESTAMPTZ,
        TNS_TYPE_BFLOAT,
        TNS_TYPE_BDOUBLE,
    }
)


def _parse_oci_binds(
    payload: bytes, sql_end: int, bind_count: int
) -> tuple[list, list[tuple[int, int]]]:
    # Read the bind values AND their (tns_type, max_size) metadata from the OCI
    # bind section. Each bind's OAC marker (``01 <type> 03 00 00``) carries the TNS
    # type; the ub4 LE right after it is the bind's max buffer size (NUMBER 22,
    # VARCHAR2(20) 60, …), which a PL/SQL OUT bind needs so its return buffer is
    # sized correctly (#483). Returns ``(values, bind_meta)`` — bind_meta is the
    # per-bind (type, max_size) list the OUT-bind path wraps as BindVars.
    tail = payload[sql_end:]
    meta: list[tuple[int, int]] = []
    for match in _OCI_OAC_MARKER.finditer(tail):
        data_type = match.group(1)[0]
        if data_type in _OCI_BIND_TYPES:
            max_size = int.from_bytes(tail[match.end() : match.end() + 4], 'little')
            meta.append((data_type, max_size))
        if len(meta) == bind_count:
            break
    if len(meta) != bind_count:
        return [], []
    types = [t for t, _ in meta]
    # The RXD row is the 0x07 token whose following DALCs decode cleanly into one
    # value per bind — a position robust to 0x07 bytes appearing in the OAC area.
    for i, byte in enumerate(tail):
        if byte != TTI_RXD:
            continue
        rest = tail[i + 1 :]
        values: list = []
        try:
            for data_type in types:
                # An OUT bind (sqlplus `VARIABLE` / `EXEC :v := …`) has no input
                # value: direction is not on the wire, so sqlplus sends the 2-byte
                # placeholder `<escape> 01` in the value's slot (the escape char is
                # the wire's absent-value sentinel). Decode it as None so the OUT
                # bind is not fed a garbage input (its real value comes back from the
                # block); an ordinary IN value is a normal DALC.
                if len(rest) >= 2 and rest[0] == TNS_ESCAPE_CHAR:
                    values.append(None)
                    rest = rest[2:]
                    continue
                raw, rest = decode_dalc(rest)
                # The OCI (sqlplus) bind path doesn't carry a national char form;
                # decode ordinary char (csfrm 1) — no test client binds NCHAR here.
                values.append(_decode_bind_value(data_type, _CSFRM_DB, raw))
        except (IndexError, DataError):
            continue
        if len(values) == bind_count:
            return values, meta
    return [], []


def _oci_ub4(n: int) -> bytes:
    return int(n).to_bytes(4, 'little')


# The classic sqlplus / thick-OCI (deadbeef) describe (TTI_DCB) marshals the
# same per-column metadata as the thin form, but field-by-field in the OCI
# conventions: fixed 4-byte little-endian lengths, a fixed 49-byte pre-name
# block per column, then the ub1-prefixed name, then a 12-byte post-name block.
# Every meaningful field (type / precision / scale / length / charset / csfrm /
# max_size / null_ok / name) is computed; the opaque server-constant trailer
# (an embedded describe-timestamp and instance ids the client skips) is emitted
# as zeros — a real codec, not a captured template (#265). Field offsets within
# the 49-byte pre-name block, verified against live 11g describes of VARCHAR2,
# NUMBER, and DATE columns:
_OCI_DCB_PREAMBLE_LEN = 23  # cursor-uuid preamble (zeroed; the client skips it)


_OCI_DCB_COL_PRENAME = 48


_OCI_DCB_COL_POSTNAME = 13


# A char type carries a charset + form-of-use and sets the pre-name char flag.
# LONG (#407) and CLOB (#405) are character types (charset + form-of-use, like
# VARCHAR2); LONG RAW and BLOB are binary. LONG / LONG RAW stream inline, LOBs
# are fetched by locator — but neither has a fixed width, so a live 11g describe
# reports data_length / max_size / max-row-size all 0 for both.
_OCI_CHAR_TYPES = frozenset(
    {TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_LONG, TNS_TYPE_CLOB}
)


_OCI_LONG_TYPES = frozenset({TNS_TYPE_LONG, TNS_TYPE_LONGRAW})


_OCI_LOB_TYPES = frozenset({TNS_TYPE_CLOB, TNS_TYPE_BLOB})


# Types with no fixed row width: excluded from the column max size and the
# describe max-row-size (their value is a locator or an inline stream, not a
# fixed-width buffer).
_OCI_UNSIZED_TYPES = _OCI_LONG_TYPES | _OCI_LOB_TYPES


_OCI_DCB_CHAR_FLAG = 0x80
# Character-length-semantics flag (pre offset 15): set on a column whose declared
# length is a character count rather than a byte count. NCHAR / NVARCHAR2 are
# always character-semantic, and the flag tells sqlplus to size the column by the
# character max_size (e.g. NCHAR(5) -> width 5) instead of the wider UTF-16 byte
# buffer (data_length 10). Verified against a live 11g NCHAR describe (the one
# byte that differed).
_OCI_DCB_CHAR_SEMANTICS_OFF = 15
_OCI_DCB_CHAR_SEMANTICS_FLAG = 0x10


def _encode_dcb_column_oci(col: ColumnMeta, position: int, first: bool) -> bytes:
    pre = bytearray(_OCI_DCB_COL_PRENAME)
    pre[0] = 0x51 if first else 0x00  # a first-column marker byte
    pre[1] = 0x01
    pre[2] = col.data_type
    is_char = col.data_type in _OCI_CHAR_TYPES
    pre[3] = _OCI_DCB_CHAR_FLAG if is_char else 0x00
    pre[4] = col.precision & 0xFF
    pre[5] = col.scale & 0xFF  # signed byte (e.g. -127 for a NUMBER literal)
    pre[6:10] = _oci_ub4(col.data_length)
    if is_char and col.csfrm == _CSFRM_NCHAR:
        pre[_OCI_DCB_CHAR_SEMANTICS_OFF] = _OCI_DCB_CHAR_SEMANTICS_FLAG
    if is_char:
        pre[30:32] = int(col.charset).to_bytes(2, 'little')
        pre[32] = col.csfrm
    # A LONG / LONG RAW / LOB carries no fixed max size — the value is a locator or
    # an inline stream, unbounded — so a live 11g describe leaves this zero (like
    # the data length the backend already sets to 0). Only fixed-width columns fill
    # it (#405, #407).
    if col.data_type not in _OCI_UNSIZED_TYPES:
        pre[34:38] = _oci_ub4(col.max_size)
    pre[42] = col.null_ok
    pre[43] = len(col.name)
    pre[44:48] = _oci_ub4(len(col.name))
    name = bytes([len(col.name)]) + col.name
    # The post-name block is zeroed — a live 11g describe carries no column
    # position here (verified against the captured single-column reply).
    post = bytes(_OCI_DCB_COL_POSTNAME)
    return bytes(pre) + name + post


def encode_describe_oci(columns: list[ColumnMeta]) -> bytes:
    """Build the sqlplus / thick-OCI (deadbeef dialect) describe block (#265).

    The OCI counterpart of :func:`encode_describe`. Returns the TTC payload from
    the TTI_DCB token: a zeroed cursor-uuid preamble, the max-row-size and column
    count, one fixed-shape block per column, then a zeroed opaque trailer.
    """
    out = bytearray([TTI_DCB])
    out += _oci_ub4(_OCI_DCB_PREAMBLE_LEN) + bytes(_OCI_DCB_PREAMBLE_LEN)
    # Max row size: the thick/OCI client allocates a row buffer of this many
    # bytes, so it must cover the widest row — a zero here overflows and crashes
    # sqlplus (unlike the thin client, which skips the field). A LONG / LONG RAW /
    # LOB is a locator or an inline stream, unbounded, so it contributes nothing to
    # the fixed row buffer (its data_length is 0 anyway); it is excluded to match a
    # live 11g describe, which reports max-row-size 0 for such a result (#405, #407).
    out += _oci_ub4(
        sum(c.data_length for c in columns if c.data_type not in _OCI_UNSIZED_TYPES)
    )
    out += _oci_ub4(len(columns))
    for position, col in enumerate(columns, start=1):
        out += _encode_dcb_column_oci(col, position, first=(position == 1))
    return bytes(out)


# The two OCI execute-response trailers, reduced to their load-bearing structure
# by live bisection against sqlplus (#265): everything a real 11g reply carries
# here — a describe timestamp, the query SCN, assorted counts — is zeroable; only
# the field *framing* and a few structural constants matter (zeroing them
# segfaults sqlplus or draws ORA-03113). So both are computed as mostly-zero with
# those constants in place, not replayed from a capture.
_OCI_DCB_TAIL_LEN = 83


_OCI_DCB_DATE_LEN = 7  # describe-time DALC: length is load-bearing, value is not


_OCI_DCB_MARKER_OFF = 33


# The column count sits one byte past the marker; the client reads it to know how
# many values to expect in each row, so it is load-bearing for a multi-column
# result (verified: 1/2/3 across live 1/2/3-column describes).
_OCI_DCB_NUMCOLS_OFF = 37


# The execute return status (an OCI OER, offsets 32:65 of the status trailer):
# call status + the return marker sqlplus needs to accept the row set. Reproduced
# as a unit — the row-count fields inside are constant for the single-row replies
# handled so far; generalising it is a follow-up.
# The classic sqlplus / thick-OCI `DESCRIBE <object>` reply (TTI func 0x77). It is
# a dedicated describe message (NOT the query DCB) laid out as: a fixed preamble,
# the schema and table names (DALCs), a fixed header carrying a column-count field,
# one ~163-byte block per column, and a fixed trailer. Reverse-engineered by
# differential capture against live 11g (single-column NUMBER / VARCHAR / DATE
# describes differ in only 14 places; the multi-column layout adds one block per
# column) — see docs/PROTOCOL.md. The meaningful per-column fields (type, size,
# precision, scale, nullability, charset) are computed; the opaque fixed structure
# is carried as the four segment constants below. Unlike the query describe,
# sqlplus rejects (hangs on) a DESCRIBE reply whose describe timestamp / object id
# are zeroed, so the header carries the non-zero, valid values from the capture —
# the Mirror has no real object numbers and the fields are not rendered, so they
# are carried verbatim rather than synthesised.
_OCI_DESC_HDR_PRE = bytes.fromhex('0801000100000027010700000007787e09020c281b00000000')
_OCI_DESC_HDR_POST = bytes.fromhex(
    '44c50100000000000000000000010000007244c501000000000001000000be0100000027'
    '0b0700000007787e09020c281b0000000000000000000000000000000000000000000100'
    '00000b0102000000be0100000027000700000007787e09020c281b020000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000100000027090700000007787e09020c281b0200'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000010000'
)
_OCI_DESC_BLK = bytes.fromhex(
    '005c160002000100000001430a0201000000000000000000000000000000000000000000'
    '000000000000000000002400000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000'
)
_OCI_DESC_TRAILER = bytes.fromhex(
    '0000010004000000ca140001000000000900000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000405000000130001010000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000015000001000000360100'
    '0000000000000000000000000020f6310a00000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '0000000000'
)
# Meaningful-field offsets within the segments (differential-mapped).
_OCI_DESC_COLCOUNT_OFF = 76  # HDR_POST: column count + 1
_OCI_DESC_BLK_SIZE = 2  # BLK pre-name: data length (single byte)
_OCI_DESC_BLK_TYPE = 4  # BLK pre-name: TNS data type
_OCI_DESC_BLK_PRENAME = 6  # BLK: length before the column-name DALC
_OCI_DESC_POST_PREC = 0  # BLK post-name: precision
_OCI_DESC_POST_SCALE = 1  # BLK post-name: scale (NUMBER) / length (char)
_OCI_DESC_POST_NULL = 2  # BLK post-name: 1 nullable, 0 NOT NULL
_OCI_DESC_POST_CSLO = 15  # BLK post-name: charset ub2 LE (low byte)
_OCI_DESC_POST_CSHI = 16
_OCI_DESC_POST_CSFRM = 17
_OCI_DESC_BLK_CONT = 3  # BLK: `1` at (len - 3) on a non-last column, else `0`
_OCI_DESC_TR_COUNT = 2  # TRAILER: column count
_OCI_DESC_TR_OPAQUE = 8  # TRAILER: a type-dependent opaque byte (carried)
# Fixed-size types report a constant wire length in the describe (a NUMBER is
# always 22, a DATE 7, …) rather than the backend's display size; variable types
# (VARCHAR / CHAR / RAW) report their declared length.
_OCI_DESC_WIRE_SIZE = {
    TNS_TYPE_NUMBER: 22,
    TNS_TYPE_DATE: 7,
    TNS_TYPE_TIMESTAMP: 11,
    TNS_TYPE_TIMESTAMPTZ: 13,
}
# The opaque trailer byte, carried per column TNS type for a single-column reply;
# its derivation for a multi-column reply is unknown, so the observed value is
# carried (sqlplus does not render it). Extend the map as more types are captured.
_OCI_DESC_TR_OPAQUE_BY_TYPE = {
    TNS_TYPE_NUMBER: 0xCA,
    TNS_TYPE_VARCHAR: 0xDA,
    TNS_TYPE_DATE: 0x6A,
}
_OCI_DESC_TR_OPAQUE_MULTI = 0x62
# Character types carry a charset + csfrm; every other type reports charset 0.
_OCI_DESC_CHAR_TYPES = frozenset({TNS_TYPE_VARCHAR, TNS_TYPE_CHAR})
# A TIMESTAMP's fractional-seconds precision is the N in TIMESTAMP(N). The
# client carries it in the column's scale (its precision is 0), but a real
# 11g DESCRIBE reply reports it in the PRECISION field too (e.g. TIMESTAMP(6)
# -> precision 6, scale 6), and sqlplus renders TIMESTAMP(N) from precision.
# So the describe block mirrors the scale into precision for these types.
_OCI_DESC_TIMESTAMP_TYPES = frozenset(
    {TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPTZ, TNS_TYPE_TIMESTAMPLTZ}
)
# Every column block but the LAST carries a describe-timestamp entry (a fixed frame
# around a 7-byte date) in its post-name region — the last block leaves it zero.
# sqlplus hangs on a multi-column reply whose non-last blocks omit it, so it is
# patched in (a valid, carried date; the value is not rendered).
_OCI_DESC_TS_ENTRY = bytes.fromhex('0100000027090700000007787e09020c281b02')
_OCI_DESC_BLK_TS_OFF = 81  # offset of the entry within a block's post-name region


def _oci_desc_dalc(name: bytes) -> bytes:
    # The describe-reply name form: a ub4 LE char length, a ub1 byte length, then
    # the bytes. (Schema, table and column names all use it.)
    return struct.pack('<I', len(name)) + bytes([len(name)]) + name


def _oci_desc_precision_scale(col: ColumnMeta) -> tuple[int, int]:
    # The (precision, scale) bytes a DESCRIBE block reports, which don't always
    # match the column's own precision/scale — sqlplus renders the type's
    # parenthesised precisions from these two positions, and each temporal family
    # lays them out differently (verified against live 11g DESCRIBE captures):
    #   - NUMBER etc.: precision, scale as-is.
    #   - TIMESTAMP family: the fractional-seconds precision (carried in the
    #     column's scale) in BOTH fields — TIMESTAMP(6) -> 06 06.
    #   - INTERVAL YEAR TO MONTH: the leading-field (YEAR) precision, carried in
    #     the column's precision, in BOTH fields — YEAR(3) -> 03 03; sqlplus reads
    #     YEAR(N) from the scale byte.
    #   - INTERVAL DAY TO SECOND: swapped — precision byte = SECOND fractional
    #     precision (the column's scale), scale byte = DAY leading precision (the
    #     column's precision) — DAY(2) TO SECOND(6) -> 06 02.
    if col.data_type in _OCI_DESC_TIMESTAMP_TYPES:
        return col.scale, col.scale
    if col.data_type == TNS_TYPE_INTERVALYM:
        return col.precision, col.precision
    if col.data_type == TNS_TYPE_INTERVALDS:
        return col.scale, col.precision
    return col.precision, col.scale


def _oci_desc_block(col: ColumnMeta, *, last: bool) -> bytes:
    pre = bytearray(_OCI_DESC_BLK[:_OCI_DESC_BLK_PRENAME])
    is_char = col.data_type in _OCI_DESC_CHAR_TYPES
    national = is_char and col.csfrm == _CSFRM_NCHAR
    size = _OCI_DESC_WIRE_SIZE.get(col.data_type, col.max_size)
    if national:
        # NCHAR / NVARCHAR2: the size field is the UTF-16 byte length, which
        # sqlplus halves (via the 0x80 flag below) to the character count.
        size = col.data_length
    pre[_OCI_DESC_BLK_SIZE] = size & 0xFF
    pre[_OCI_DESC_BLK_TYPE] = col.data_type
    post = bytearray(_OCI_DESC_BLK[_OCI_DESC_BLK_PRENAME + 6 :])
    precision, scale = _oci_desc_precision_scale(col)
    post[_OCI_DESC_POST_PREC] = precision & 0xFF
    post[_OCI_DESC_POST_SCALE] = scale & 0xFF
    post[_OCI_DESC_POST_NULL] = 1 if col.null_ok else 0
    if is_char:
        post[_OCI_DESC_POST_CSLO] = col.charset & 0xFF
        post[_OCI_DESC_POST_CSHI] = (col.charset >> 8) & 0xFF
        post[_OCI_DESC_POST_CSFRM] = col.csfrm
        if national:
            # The national flag makes sqlplus halve the byte size to the declared
            # character count; the character length itself goes in the scale byte.
            post[_OCI_DESC_POST_PREC] = 0x80
            post[_OCI_DESC_POST_SCALE] = col.max_size & 0xFF
    if not last:
        # A non-last column carries a describe-timestamp entry in its post-name
        # region (the last column leaves it zero).
        off = _OCI_DESC_BLK_TS_OFF
        post[off : off + len(_OCI_DESC_TS_ENTRY)] = _OCI_DESC_TS_ENTRY
    block = bytes(pre) + _oci_desc_dalc(col.name) + bytes(post)
    if not last:
        # …and a `1` continuation flag 3 bytes before its end.
        marked = bytearray(block)
        marked[-_OCI_DESC_BLK_CONT] = 1
        block = bytes(marked)
    return block


def encode_describe_reply_oci(
    columns: list[ColumnMeta], *, schema: bytes, table: bytes
) -> bytes:
    """Build the sqlplus / thick-OCI ``DESCRIBE <object>`` reply (TTI 0x77).

    One column block per :class:`ColumnMeta`, framed by the fixed header (schema +
    table names, column count) and trailer. Meaningful fields are computed; the
    opaque structure and instance fields are carried (the latter zeroed). The
    trailer's OER sequence is a diagnostic counter the client discards (§36), so it
    is left at its carried value rather than threaded."""
    out = bytearray(_OCI_DESC_HDR_PRE)
    out += _oci_desc_dalc(schema) + _oci_desc_dalc(table)
    header_post = bytearray(_OCI_DESC_HDR_POST)
    header_post[_OCI_DESC_COLCOUNT_OFF] = (len(columns) + 1) & 0xFF
    out += header_post
    for index, col in enumerate(columns):
        out += _oci_desc_block(col, last=index == len(columns) - 1)
    trailer = bytearray(_OCI_DESC_TRAILER)
    trailer[_OCI_DESC_TR_COUNT] = len(columns) & 0xFF
    trailer[_OCI_DESC_TR_OPAQUE] = (
        _OCI_DESC_TR_OPAQUE_BY_TYPE.get(columns[0].data_type, _OCI_DESC_TR_OPAQUE_MULTI)
        if len(columns) == 1
        else _OCI_DESC_TR_OPAQUE_MULTI
    )
    out += trailer
    return bytes(out)


def parse_describe_oci(body: bytes) -> str:
    """Extract the object name from a sqlplus / thick-OCI ``DESCRIBE`` request
    (``03 77 … <ub4 flag> <ub1 namelen> <name>``). The name is the trailing
    length-prefixed token."""
    for i in range(len(body) - 2, 0, -1):
        namelen = body[i]
        if 0 < namelen < 128 and i + 1 + namelen == len(body):
            name = body[i + 1 : i + 1 + namelen]
            if all(c < 128 for c in name) and name.replace(b'_', b'').isalnum():
                return name.decode('ascii')
    raise InterfaceError('OCI DESCRIBE: could not find the object name')


_OCI_EXEC_OER_OFF = 32


_OCI_ROW_STATUS_LEN = 171


def _oci_dcb_tail(numcols: int) -> bytes:
    tail = bytearray(_OCI_DCB_TAIL_LEN)
    tail[1:5] = _oci_ub4(_OCI_DCB_DATE_LEN)  # describe-time DALC char length
    tail[5] = _OCI_DCB_DATE_LEN  # DALC byte length; the value stays zero
    off = _OCI_DCB_MARKER_OFF
    tail[off : off + len(_OCI_DCB_MARKER)] = _OCI_DCB_MARKER
    tail[_OCI_DCB_NUMCOLS_OFF] = numcols
    return bytes(tail)


# The execute reply for a LOB SELECT is a describe with NO row inline — sqlplus
# sets up its LOB define from it and fetches the locator rows separately. Instead
# of the 83-byte inline-row DCB tail it carries a 33-byte describe-timestamp tail
# (no DCB marker): the same describe-time DALC head as _oci_dcb_tail (a ub4 char
# length of 7 + the byte-length 7, the timestamp value itself zeroed), all zero
# except one ub4 the LOB describe carries at offset 17. That ub4 is NOT
# instance-specific (a real reply zeroes the timestamp / SCN but not this), so it
# is a stable structural value; its exact meaning is unpinned, carried from the
# live 11g CLOB describe capture (#405).
_OCI_LOB_DESCRIBE_TAIL_LEN = 33
_OCI_LOB_DESCRIBE_SIZE_OFF = 17
_OCI_LOB_DESCRIBE_SIZE = 8168  # 0x1fe8, ub4 LE — carried ground truth


def _oci_lob_describe_tail() -> bytes:
    tail = bytearray(_OCI_LOB_DESCRIBE_TAIL_LEN)
    tail[1:5] = _oci_ub4(_OCI_DCB_DATE_LEN)  # describe-time DALC char length
    tail[5] = _OCI_DCB_DATE_LEN  # DALC byte length; the value stays zero
    off = _OCI_LOB_DESCRIBE_SIZE_OFF
    tail[off : off + 4] = _oci_ub4(_OCI_LOB_DESCRIBE_SIZE)
    return bytes(tail)


_OCI_LOB_DESCRIBE_TAIL = _oci_lob_describe_tail()


# When the execute delivers fewer rows than the result holds, this byte in the
# status is non-zero — the client reads it as "more rows, issue a fetch" (0 =
# the cursor is already drained). The exact value is not load-bearing beyond
# non-zero; 0x1e is what a live reply carries.
_OCI_MORE_ROWS_OFF = 55


_OCI_MORE_ROWS_FLAG = 0x1E


def _oci_row_status(sequence: int, *, more: bool = False) -> bytes:
    status = bytearray(_OCI_ROW_STATUS_LEN)
    status[0:3] = b'\x08\x06\x00'  # return marker
    status[11] = 0x02  # a required sentinel
    exec_oer = _oci_exec_oer(sequence)
    off = _OCI_EXEC_OER_OFF
    status[off : off + len(exec_oer)] = exec_oer
    if more:
        status[_OCI_MORE_ROWS_OFF] = _OCI_MORE_ROWS_FLAG
    return bytes(status)


# The row-header (TTI_RXH) that leads a fetch batch: a small fixed frame plus the
# query SCN (zeroable). Reduced to its non-zero structure from a live fetch reply
# (#265, #351).
_OCI_RXH_LEN = 50


_OCI_RXH_NONZERO = {0: 0x06, 1: 0x01, 2: 0x02, 4: 0x02, 10: 0x0F}


def _oci_rxh() -> bytes:
    rxh = bytearray(_OCI_RXH_LEN)
    for off, value in _OCI_RXH_NONZERO.items():
        rxh[off] = value
    return bytes(rxh)


def encode_fetch_batch_oci(
    columns: list[ColumnMeta], rows: list[tuple], *, sequence: int
) -> bytes:
    """A sqlplus / thick-OCI fetch reply: RXH + one RXD per row + end-of-fetch.

    Used when the execute parked rows for follow-up fetches — the batch carries
    the next rows and, since the Mirror returns the remainder in one go, the
    ORA-01403 terminator (#351). ``sequence`` is the live per-session OER counter.
    """
    out = bytearray(_oci_rxh())
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_oci_value(v, col) for v, col in zip(row, columns)
        )
    out += encode_fetch_terminator_oci(sequence)
    return bytes(out)


def encode_reexec_row_oci(
    columns: list[ColumnMeta], rows: list[tuple], *, sequence: int, more: bool = False
) -> bytes:
    """The reply to a re-execute-to-fetch (a LONG / streamed column, #407).

    sqlplus describes the query, sets up its streaming define, then re-executes
    the cursor to pull the rows — one LONG row per reply, each led by a row header
    and ended with the row status (``more`` set while rows remain), then a final
    fetch draws the 1403 terminator. No describe (the client already has it).
    Matches a live 11g LONG re-execute / fetch reply."""
    out = bytearray(_oci_rxh())
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_oci_value(v, col) for v, col in zip(row, columns)
        )
    out += _oci_row_status(sequence, more=more)
    return bytes(out)


def encode_long_fetch_row_oci(
    columns: list[ColumnMeta], row: tuple, *, sequence: int
) -> bytes:
    """The fetch reply carrying one LONG row (#407): row header + the row, then a
    "more rows" OER status (not the execute row-status the re-execute reply uses,
    nor the 1403 terminator — a following empty fetch drains that)."""
    if len(row) != len(columns):
        raise InterfaceError('row width does not match the column count')
    out = bytearray(_oci_rxh())
    out += bytes([TTI_RXD]) + b''.join(
        _encode_oci_value(v, col) for v, col in zip(row, columns)
    )
    status = encode_oci_oer(
        oci.OCI_OER_STATUS_SUCCESS,
        sequence=sequence,
        row_kind=oci.OCI_OER_ROW_KIND_LONG,
    )
    return bytes(out) + status


def encode_error_oci(
    ora_code: int, message: str, *, sequence: int, error_pos: int | None = None
) -> bytes:
    """OCI error reply — an OER carrying ORA-<code>: <message>, connection intact.

    The deadbeef-dialect counterpart of :func:`encode_error`: a failing statement
    surfaces in sqlplus as the ORA error and the session stays usable. The error
    status (0x05) and frame differ from the end-of-fetch OER — a real error, not
    "cursor drained" — so the two must not be conflated (#265, #350).

    ``error_pos`` is the 0-based parse offset of the error in the statement —
    the column sqlplus draws its caret under. ``None`` keeps the captured
    default (``0x0E``); a backend that knows the real offset passes it so the
    caret lands correctly.
    """
    if error_pos is None:
        error_pos = 0x0E
    oer = encode_oci_oer(
        oci.OCI_OER_STATUS_ERROR,
        sequence=sequence,
        error_pos=error_pos,
        error_code=ora_code,
    )
    text = f'ORA-{ora_code:05d}: {message}\n'.encode('utf-8')
    return oer + bytes([len(text)]) + text


def encode_query_response_oci(
    columns: list[ColumnMeta], rows: list[tuple], *, sequence: int, more: bool = False
) -> bytes:
    """Assemble a sqlplus / thick-OCI SELECT execute response (#265).

    describe + DCB tail + one TTI_RXD per row + the status trailer. ``more=True``
    marks the result as not fully delivered, so sqlplus follows up with a fetch
    (see :func:`encode_fetch_batch_oci`); the trailers are computed, not blobs.
    ``sequence`` is the live per-session OER counter for the status trailer.
    """
    out = bytearray(encode_describe_oci(columns))
    out += _oci_dcb_tail(len(columns))
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_oci_value(v, col) for v, col in zip(row, columns)
        )
    out += _oci_row_status(sequence, more=more)
    return bytes(out)


def encode_lob_describe_oci(columns: list[ColumnMeta], *, sequence: int) -> bytes:
    """The execute reply for a LOB (CLOB/BLOB) SELECT (#405): the TTI_DCB block +
    a 33-byte describe tail + the LOB execute status — describe only, no row (the
    locator rows come on the follow-up fetch). Matching this exactly is what makes
    sqlplus set up its LOB define correctly and accept the locator row rather than
    break (an ordinary describe, with the inline-row DCB tail, is rejected).
    ``sequence`` is the live per-session OER counter for the execute status."""
    return (
        bytes(encode_describe_oci(columns))
        + _OCI_LOB_DESCRIBE_TAIL
        + _oci_lob_describe_status(sequence)
    )


def encode_status_oci(sequence: int) -> bytes:
    """OCI reply for a no-row statement (PL/SQL / DDL): success, nothing to fetch."""
    status = bytearray(_OCI_ROW_STATUS_LEN)
    status[0:3] = b'\x08\x06\x00'
    status[11] = 0x01
    status_oer = _oci_status_oer(sequence)
    off = _OCI_EXEC_OER_OFF
    status[off : off + len(status_oer)] = status_oer
    return bytes(status)


# The sqlplus PASSWORD success reply (OCIPasswordChange complete, #21): an empty
# RPA return-parameter envelope followed by an OER return-status token, from
# which sqlplus renders "Password changed". Its body is the shared
# :data:`_OCI_OER_ENVELOPE` — the same OER frame every OCI status carries,
# including the fixed 0x20f6310a instance marker — so it is built on that rather
# than stored as a second copy of the frame. Six bytes differ from the envelope;
# all are fixed values carried from the capture, so they are set by raw offset
# rather than through :func:`encode_oci_oer`'s named fields, whose meanings do
# not hold for this reply (the status byte reads the ERROR marker even though the
# change succeeded; offset 8 is not a LOB row-kind here).
#
# Verified byte-identical across FOUR independent live 11g password changes in
# separate sessions: the whole reply is a constant. There is no per-session
# counter — the offset-5 value and its offset-49 echo, live sequence fields in
# the query-path OERs, are fixed here — so the Mirror emits it verbatim (§36.1).
_OCI_RPA_EMPTY = bytes([TTI_RPA, 0, 0])  # RPA return with zero parameters


def _build_changepassword_status_oci() -> bytes:
    oer = bytearray(_OCI_OER_ENVELOPE)
    oer[1] = 0x05  # status byte (the ERROR marker, though the change succeeded)
    oer[5] = 0x13  # offset-5 field — a fixed value here, not a live sequence
    oer[8] = 0x01  # marker whose meaning is unpinned (§36.1)
    oer[18] = 0x00  # this reply zeroes the envelope's offset-18 marker (§36.1)
    oer[22] = 0x00  # command-type field: none
    oer[49] = 0x16  # offset-49 echo — a fixed value here, not sequence + 2
    return _OCI_RPA_EMPTY + bytes(oer)


_OCI_CHANGEPASSWORD_STATUS = _build_changepassword_status_oci()


def encode_changepassword_status_oci() -> bytes:
    """The sqlplus / thick-OCI reply that completes an OCIPasswordChange (#21)."""
    return _OCI_CHANGEPASSWORD_STATUS


# OCI DML execute-status reply (#348/#349). sqlplus renders the completion
# message ("N rows updated.") from two fields of this frame: the V$SQL **command
# type** at body offset 57 (= the embedded OER's offset 22) and the affected-row
# **count** (ub4 LE) at offset 43. The rest is the fixed execute-status frame
# around the embedded OER (SCN region, cursor/rowid trailer, the 0x20f6310a
# marker); unlike the describe/DDL/outbind statuses it carries live row/rowid
# data, so it is kept as one frame rather than built on _OCI_OER_ENVELOPE.
# Validated live — sqlplus prints the right verb and count for insert/update/
# delete. The frame is one live 11g INSERT reply with the capture-order session
# counters (offsets 3, 75, 186) zeroed, since the Mirror has no such sequence.
_OCI_DML_ROWCOUNT_OFF = 43


_OCI_CMD_TYPE_OFF = 57


# The Mirror's SQL-verb → V$SQL command-type mapping — response-generation policy
# over the shared oci.OCI_CMD_* vocabulary. sqlplus renders the completion message
# purely from the command type (docs/PROTOCOL.md §36).
_OCI_DML_CMD = {
    'INSERT': oci.OCI_CMD_INSERT,
    'UPDATE': oci.OCI_CMD_UPDATE,
    'DELETE': oci.OCI_CMD_DELETE,
}


# DDL / no-row statements, keyed by (verb, object). sqlplus prints e.g. "Index
# created.", "Table altered.", "View dropped." from the command type. Verbs with
# no object (GRANT/REVOKE) map on the verb alone. Verified live against sqlplus.
_OCI_DDL_COMMAND_TYPE = {
    ('CREATE', 'TABLE'): oci.OCI_CMD_CREATE_TABLE,
    ('CREATE', 'INDEX'): oci.OCI_CMD_CREATE_INDEX,
    ('CREATE', 'SEQUENCE'): oci.OCI_CMD_CREATE_SEQUENCE,
    ('CREATE', 'SYNONYM'): oci.OCI_CMD_CREATE_SYNONYM,
    ('CREATE', 'VIEW'): oci.OCI_CMD_CREATE_VIEW,
    ('ALTER', 'INDEX'): oci.OCI_CMD_ALTER_INDEX,
    ('ALTER', 'SEQUENCE'): oci.OCI_CMD_ALTER_SEQUENCE,
    ('ALTER', 'TABLE'): oci.OCI_CMD_ALTER_TABLE,
    ('DROP', 'INDEX'): oci.OCI_CMD_DROP_INDEX,
    ('DROP', 'TABLE'): oci.OCI_CMD_DROP_TABLE,
    ('DROP', 'SEQUENCE'): oci.OCI_CMD_DROP_SEQUENCE,
    ('DROP', 'SYNONYM'): oci.OCI_CMD_DROP_SYNONYM,
    ('DROP', 'VIEW'): oci.OCI_CMD_DROP_VIEW,
    ('LOCK', 'TABLE'): oci.OCI_CMD_LOCK_TABLE,
    ('TRUNCATE', 'TABLE'): oci.OCI_CMD_TRUNCATE_TABLE,
}


# Object-less verbs, and the object each bare verb falls back to.
_OCI_DDL_VERB_COMMAND_TYPE = {'GRANT': oci.OCI_CMD_GRANT, 'REVOKE': oci.OCI_CMD_REVOKE}


_OCI_DDL_VERB_DEFAULT_OBJECT = {
    'CREATE': 'TABLE',
    'ALTER': 'TABLE',
    'DROP': 'TABLE',
    'TRUNCATE': 'TABLE',
    'LOCK': 'TABLE',
}


def ddl_command_type(sql: str) -> int | None:
    """The V$SQL command type for a DDL / session statement, or None if it is not
    one the Mirror recognises (so it falls back to the generic no-row status).
    sqlplus turns this into the completion message ("Table created.", "Index
    dropped.", "Grant succeeded.", …)."""
    parts = sql.strip().upper().split()
    if not parts:
        return None
    verb = parts[0]
    if verb in _OCI_DDL_VERB_COMMAND_TYPE:
        return _OCI_DDL_VERB_COMMAND_TYPE[verb]
    if verb not in _OCI_DDL_VERB_DEFAULT_OBJECT:
        return None
    obj = parts[1] if len(parts) > 1 else _OCI_DDL_VERB_DEFAULT_OBJECT[verb]
    return _OCI_DDL_COMMAND_TYPE.get(
        (verb, obj), _OCI_DDL_COMMAND_TYPE[(verb, _OCI_DDL_VERB_DEFAULT_OBJECT[verb])]
    )


def encode_dml_status_oci(keyword: str, rowcount: int, *, sequence: int) -> bytes:
    """OCI reply for a DML — success carrying the affected-row count so sqlplus
    prints ``N rows created/updated/deleted``. ``keyword`` (INSERT/UPDATE/DELETE)
    selects the V$SQL command type; MERGE and anything else fall back to INSERT.
    ``sequence`` is the live per-session OER counter."""
    status = bytearray(_oci_dml_status_frame(sequence))
    status[_OCI_DML_ROWCOUNT_OFF : _OCI_DML_ROWCOUNT_OFF + 4] = rowcount.to_bytes(
        4, 'little'
    )
    status[_OCI_CMD_TYPE_OFF] = _OCI_DML_CMD.get(keyword, oci.OCI_CMD_INSERT)
    return bytes(status)


def encode_ddl_status_oci(command_type: int, *, sequence: int) -> bytes:
    """OCI reply for a DDL / no-row statement — success so sqlplus prints the
    matching message ("Table created.", "Index dropped.", "Table truncated.", …).
    ``command_type`` is the V$SQL command type (see :func:`ddl_command_type`);
    DDL affects no rows, so nothing but that field varies. ``sequence`` is the
    live per-session OER counter."""
    oer = bytearray(
        encode_oci_oer(
            oci.OCI_OER_STATUS_SUCCESS, sequence=sequence, command_type=command_type
        )
    )
    # FIXME: DDL sets offset 18 to 1 (query / PL-SQL leave the envelope's 2);
    # the field's meaning is unknown — carried from the capture.
    oer[18] = 1
    return _OCI_DDL_FRAME_PREFIX + bytes(oer)


_OCI_OUTBIND_DEFINE_MARKER = 0x10


_OCI_OUTBIND_RETCODE = b'\x00\x00'


def encode_out_bind_response_oci(values: list[object], *, sequence: int) -> bytes:
    """OCI reply returning a PL/SQL block's OUT bind values (``EXEC :v := ...``).

    ``values`` are the assigned OUT values in bind order; each is marshalled as a
    DALC (the same wire form as a fetched column) so the client reads it back into
    its bound buffer. The header/tail are computed structure, not blobs (#347).
    ``sequence`` is the live per-session OER counter for the status tail.
    """
    header = _oci_outbind_header(len(values))
    define_markers = bytes([_OCI_OUTBIND_DEFINE_MARKER]) * len(values)
    rxd = bytes([TTI_RXD]) + b''.join(
        encode_value(v, 0) + _OCI_OUTBIND_RETCODE for v in values
    )
    return header + define_markers + rxd + _oci_outbind_tail(sequence)


def encode_commit_status_oci() -> bytes:
    """OCI reply to a bare commit / rollback — a TTI_STA acknowledgement."""
    return _OCI_COMMIT_STATUS


def encode_logoff_status_oci() -> bytes:
    """OCI reply acknowledging a client logoff (TTI_LOGOFF)."""
    return _OCI_LOGOFF_STATUS


def _decode_describe_oci(payload: bytes) -> list[dict]:
    # A minimal reader for encode_describe_oci's own output — the thin client
    # can't parse the OCI describe, so this round-trips the meaningful fields to
    # prove the field layout is self-consistent (offline; sqlplus is the wire
    # conformance check).
    assert payload[0] == TTI_DCB
    plen = int.from_bytes(payload[1:5], 'little')
    body = payload[5 + plen :]
    numcols = int.from_bytes(body[4:8], 'little')
    cols = []
    off = 8
    for _ in range(numcols):
        pre = body[off : off + _OCI_DCB_COL_PRENAME]
        namelen = pre[43]
        name = body[
            off + _OCI_DCB_COL_PRENAME + 1 : off + _OCI_DCB_COL_PRENAME + 1 + namelen
        ]
        cols.append(
            {
                'data_type': pre[2],
                'precision': pre[4],
                'scale': pre[5] - 256 if pre[5] > 127 else pre[5],
                'data_length': int.from_bytes(pre[6:10], 'little'),
                'charset': int.from_bytes(pre[30:32], 'little'),
                'max_size': int.from_bytes(pre[34:38], 'little'),
                'null_ok': pre[43],
                'name': name,
            }
        )
        off += _OCI_DCB_COL_PRENAME + 1 + namelen + _OCI_DCB_COL_POSTNAME
    return cols


# --- OCI LONG / LONG RAW row value (#407) ---
# A LONG (type 8, character) or LONG RAW (type 24, binary) column is streamed
# inline in the RXD — no LOB locator. The value is always the chunked form
# (0xFE marker, then a run of <ub1 len><bytes> chunks terminated by a zero-length
# chunk) even when it fits one chunk, followed by a trailing ub4 indicator (0),
# reproduced from a live 11g capture. A NULL LONG is a single 0x00. Character LONG
# content is UTF-8, LONG RAW is raw bytes.
_OCI_LONG_CHUNK = 0xFC  # max bytes per inline LONG chunk


_OCI_LONG_TRAILER = bytes(4)  # trailing ub4 indicator (actual/return length = 0)


def encode_long_value_oci(value: object) -> bytes:
    """The RXD value for a LONG / LONG RAW column (#407): the content streamed
    inline as 0xFE-chunked bytes + a zero trailing indicator. NULL is an empty
    value (0x00) still followed by the trailing indicator. ``str`` content is
    UTF-8 (LONG), ``bytes`` is raw (LONG RAW)."""
    if value is None:
        return bytes([0]) + _OCI_LONG_TRAILER
    if isinstance(value, str):
        content = value.encode('utf-8')
    elif isinstance(value, (bytes, bytearray)):
        content = bytes(value)
    else:
        content = str(value).encode('utf-8')
    out = bytearray([0xFE])
    for start in range(0, len(content), _OCI_LONG_CHUNK):
        chunk = content[start : start + _OCI_LONG_CHUNK]
        out += bytes([len(chunk)]) + chunk
    out += bytes([0])  # zero-length chunk terminates the run
    return bytes(out) + _OCI_LONG_TRAILER


_OCI_LOB_ROW_SIZE_OFF = 97  # ub4 BE content byte size inside the row locator value


_OCI_LOB_TAIL_SIZE_OFF = 93  # ub4 BE byte size in the echoed locator


_OCI_LOB_TAIL_AMOUNT_OFF = 107  # ub4 LE amount read (characters for CLOB / bytes)


def _oci_lob_byte_size(value: object, is_clob: bool) -> int:
    # The LOB content byte count sqlplus reads from the locator: a CLOB is UTF-16
    # on the wire (2 bytes per character), a BLOB is its raw bytes.
    if is_clob:
        return len(str(value)) * 2
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    return len(str(value))


def encode_lob_locator_oci(value: object, is_clob: bool) -> bytes:
    """The RXD value for a LOB column (#405): a minted opaque locator carrying the
    content **byte** size so sqlplus issues a TTI_LOBOPS READ. NULL is a zero
    num_bytes and draws no read."""
    if value is None:
        return bytes([0])
    byte_size = _oci_lob_byte_size(value, is_clob)
    loc = bytearray(_OCI_LOB_ROW_VALUE[is_clob])
    loc[_OCI_LOB_ROW_SIZE_OFF : _OCI_LOB_ROW_SIZE_OFF + 4] = byte_size.to_bytes(
        4, 'big'
    )
    return bytes(loc)


def encode_lob_read_response_oci(
    content: bytes,
    amount: int,
    total_bytes: int | None = None,
    *,
    is_clob: bool = True,
    sequence: int,
) -> bytes:
    """The TTI_LOBOPS READ reply (#405): the LOB content slice (LOB_DATA) then the
    TTI_RPA + OER tail. ``content`` is the UTF-16BE (CLOB) / raw (BLOB) bytes read
    this call; ``amount`` is that read's count (characters for a CLOB, bytes for a
    BLOB); ``total_bytes`` is the whole LOB's byte size the echoed locator reports
    (defaults to this slice, for a single read-it-all call). ``is_clob`` selects
    the echoed-locator template (character vs binary, #406). ``sequence`` is the
    live per-session OER counter for the trailing status."""
    if total_bytes is None:
        total_bytes = len(content)
    tail = bytearray(_oci_lob_read_tail(is_clob, sequence))
    tail[_OCI_LOB_TAIL_SIZE_OFF : _OCI_LOB_TAIL_SIZE_OFF + 4] = total_bytes.to_bytes(
        4, 'big'
    )
    tail[_OCI_LOB_TAIL_AMOUNT_OFF : _OCI_LOB_TAIL_AMOUNT_OFF + 4] = amount.to_bytes(
        4, 'little'
    )
    return _oci_lob_data(content) + bytes(tail)


def oci_lob_contents(
    columns: list[ColumnMeta], rows: list[tuple]
) -> list[tuple[bytes, bool]]:
    """The (wire-content, is_clob) of each non-NULL LOB cell, row-major (#405).

    The order matches the locators :func:`_encode_oci_value` emits, so the session
    reads this queue in sequence as sqlplus issues TTI_LOBOPS calls. CLOB content
    is UTF-16BE (``is_clob`` True — offsets/amounts count characters, 2 bytes
    each); BLOB content is raw bytes (counts bytes). The session slices this per
    the offset/amount each read requests."""
    from seerdb.common.oson import encode_oson

    out: list[tuple[bytes, bool]] = []
    for row in rows:
        for value, col in zip(row, columns):
            if col.data_type not in _LOB_CONTENT_TYPES or value is None:
                continue
            if col.data_type == TNS_TYPE_CLOB:
                out.append((str(value).encode('utf-16-be'), True))
            elif col.data_type == TNS_TYPE_JSON:
                # A native JSON column reads back as a LOB whose content is the
                # value's OSON image; the client decodes it as JSON (#30/#50).
                # allow_wide so a > 255-key or > 64 KiB document re-encodes for
                # the client's decoder (the LOB read framing carries any size).
                out.append((encode_oson(value, allow_wide=True), False))
            elif col.data_type == TNS_TYPE_VECTOR:
                # A native VECTOR column reads back as a LOB whose content is the
                # value's binary image, re-encoded with the column's element
                # format so INT8 / BINARY stay integral and FLOAT64 keeps its
                # precision (#55).
                out.append((encode_vector(_vector_as(value, col.vector_format)), False))
            else:
                out.append((bytes(value), False))
    return out


_LOB_CONTENT_TYPES = _OCI_LOB_TYPES | {TNS_TYPE_JSON, TNS_TYPE_VECTOR}


def _encode_oci_value(value: object, col: ColumnMeta) -> bytes:
    # A row value in the OCI dialect: a LOB column emits its locator (content comes
    # later over TTI_LOBOPS, #405); a LONG / LONG RAW column streams inline via the
    # chunked form (#407); everything else is the ordinary inline DALC value.
    if col.data_type in _OCI_LOB_TYPES:
        return encode_lob_locator_oci(value, col.data_type == TNS_TYPE_CLOB)
    if col.data_type in _OCI_LONG_TYPES:
        return encode_long_value_oci(value)
    return encode_value(_national_wire_value(value, col), col.data_type)


# The OER status that trails a LOB locator row on the fetch — NOT the 1403
# terminator: the LOB content still has to come over TTI_LOBOPS, so the cursor is
# not drained (a following fetch after the LOBOPS reads draws the terminator,
# #405). The same OER envelope as the LONG-row status, marked LOB (§36).
def _oci_lob_fetch_status(sequence: int) -> bytes:
    return encode_oci_oer(
        oci.OCI_OER_STATUS_SUCCESS, sequence=sequence, row_kind=oci.OCI_OER_ROW_KIND_LOB
    )


# The row header that leads a LOB locator fetch differs from the ordinary fetch
# RXH — a live 11g LOB fetch carries this fixed frame (verified constant across
# CLOB sizes). Using the ordinary RXH makes sqlplus break on the locator row.
_OCI_LOB_RXH_NONZERO = {0: 0x06, 1: 0x01, 2: 0x22, 3: 0xFD, 4: 0x01, 10: 0x01}


def _oci_lob_rxh() -> bytes:
    rxh = bytearray(_OCI_RXH_LEN)
    for off, value in _OCI_LOB_RXH_NONZERO.items():
        rxh[off] = value
    return bytes(rxh)


def encode_lob_fetch_rows_oci(
    columns: list[ColumnMeta], rows: list[tuple], *, sequence: int
) -> bytes:
    """The fetch reply carrying LOB locator row(s) (#405): a row header + the rows,
    then a non-terminator OER status. The LOB content still comes over TTI_LOBOPS,
    so the cursor is not yet drained; a following fetch draws the 1403 terminator.
    ``sequence`` is the live per-session OER counter for the status."""
    out = bytearray(_oci_lob_rxh())
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_oci_value(v, col) for v, col in zip(row, columns)
        )
    return bytes(out) + _oci_lob_fetch_status(sequence)


def encode_dictionary_dty(Dictionary: dict) -> bytes:
    # TTI_DTY (Data Type Negotiation). Sent during the TTC handshake right
    # after TTI_PRO. Tells the server which native Oracle data types this
    # client understands and what wire representation it wants for each.
    #
    # On-wire structure (msgtype 2 = TNS_MSG_TYPE_DATA_TYPES):
    #
    #   TTI_DTY              1 byte   message token (== 2)
    #   charset_in           2 bytes  LE, NLS_LANGUAGE charset id (DB)
    #   charset_out          2 bytes  LE, NLS_NCHAR    charset id (client)
    #   flag                 1 byte   encoding flag (1 = standard)
    #   compile caps     1+N bytes  length byte + TNS_CCAP_* array
    #   runtime caps     1+M bytes  length byte + TNS_RCAP_* array
    #   identity table     980 bytes  `IdentityMap` — default "type N → repr N"
    #                                 for type ids 1..245 (245 × 4 bytes)
    #   override table     ~92 bytes  `TypeOverrides` — explicit non-identity
    #                                 mappings, terminated by `0 0`
    #
    # The capability arrays are built from named feature slots (see
    # `capability_arrays` above) and keyed on a target TTC field version; the
    # default (11.2) reproduces what seerdb has always sent. The datatype
    # tables don't vary with the user's query workload — python-oracledb
    # hard-codes the equivalent, and the OCI thick client builds it from a
    # static C table at link time; we emit it as a constant for the same reason.
    # The table form is version-gated below: 11g 1-byte vs 12c+ 2-byte.
    logger.debug('encode_dictionary_dty: %s', _redacted(Dictionary))
    Charset = struct.pack('<H', CharsetDict.get(Dictionary['req'], AL32UTF8_CHARSET))

    # Compile-time + runtime capability arrays, each emitted as a length byte
    # followed by the array (write_bytes_with_length in oracledb terms).
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    CompileCaps, RuntimeCaps = capability_arrays(FieldVersion)
    # End-of-response opt-in (#155/#132): when the server advertised EOR support
    # in its accept, set CCAP_TTC4's 0x20 bit so the server delimits every
    # response with the EOR (29) marker — the prerequisite for pipelining. Only
    # reached on a >= 318 server (older tiers never set supports_eor), and
    # guarded on the cap array being long enough.
    if Dictionary.get('supports_eor') and len(CompileCaps) > CCAP_TTC4:
        Caps = bytearray(CompileCaps)
        Caps[CCAP_TTC4] |= TNS_CCAP_END_OF_RESPONSE
        CompileCaps = bytes(Caps)
    CapabilityHeader = bytes([len(CompileCaps)]) + CompileCaps
    TableHeader = bytes([len(RuntimeCaps)]) + RuntimeCaps

    # Identity map: for type id N in 1..245, emit (N, N, 1, 0) — "I know
    # type N and want it on the wire as type N with format flag 1". This
    # is the default assertion; `TypeOverrides` (below) overrides
    # specific entries.
    IdentityMap = bytes(
        reduce(lambda y, z: y + z, [[]] + [[x, x, 1, 0] for x in range(1, 246)])
    )

    # Override table. Each entry is `(client_type, server_repr, format,
    # flags)` — when this client encounters data of type `client_type`,
    # negotiate `server_repr` as the wire representation with the given
    # format. Terminated by `0, 0`. Annotated against seerdb.common.tns_consts:
    #
    #   (2,  2, 10)   NUMBER   → NUMBER (extended precision format 10)
    #   (3,  2, 10)   INTEGER  → NUMBER
    #   (4,  2, 10)   FLOAT    → NUMBER
    #   (5,  1,  1)   STRING   → VARCHAR
    #   (6,  2, 10)   VARNUM   → NUMBER
    #   (7,  2, 10)   DECIMAL  → NUMBER
    #   (9,  1,  1)   VCS      → VARCHAR
    #   (12,12, 10)   DATE     → DATE (format 10)
    #   (15,23,  1)   VBI      → RAW
    #   (39,120, 1)              named-type / collection variant
    #   (91, 2, 10)              NUMBER variant
    #   (94, 1,  1)   CHARZ    → VARCHAR
    #   (95,23,  1)              RAW variant
    #   (96,96,  1)   CHAR     → CHAR
    #   (97,96,  1)   CHAR_VAR → CHAR
    #   (104,11, 1)   ROWID    → RID (universal rowid → physical)
    #   (108,109,1)   NAMEDTYP → ADT
    #   (110,111,1)              → REF
    #   (116,102,1)   RSET     → REFCURSOR
    #   (146,146,1)              fixed-id self-map
    #   (152..154,2,10)          extended NUMBER subtypes → NUMBER
    #   (155, 1, 1)              → VARCHAR
    #   (156,12, 10)             → DATE
    #   (172, 2, 10)             → NUMBER
    #   (209, 0,  3)  UROWID
    #
    # Single-pair entries like `(13, 0)` are unknown types we don't have
    # a name for in tns_consts; they're left in for byte-level parity
    # with what every other Oracle client sends.
    TypeOverrides = bytes(
        [
            2,
            2,
            10,
            0,
            3,
            2,
            10,
            0,
            4,
            2,
            10,
            0,
            5,
            1,
            1,
            0,
            6,
            2,
            10,
            0,
            7,
            2,
            10,
            0,
            9,
            1,
            1,
            0,
            12,
            12,
            10,
            0,
            13,
            0,
            14,
            0,
            15,
            23,
            1,
            0,
            16,
            0,
            17,
            0,
            18,
            0,
            19,
            0,
            20,
            0,
            21,
            0,
            22,
            0,
            39,
            120,
            1,
            0,
            58,
            0,
            68,
            2,
            10,
            0,
            69,
            0,
            70,
            0,
            74,
            0,
            6,
            0,
            91,
            2,
            10,
            0,
            94,
            1,
            1,
            0,
            95,
            23,
            1,
            0,
            96,
            96,
            1,
            0,
            97,
            96,
            1,
            0,
            104,
            11,
            1,
            0,
            105,
            0,
            108,
            109,
            1,
            0,
            110,
            111,
            1,
            0,
            116,
            102,
            1,
            0,
            118,
            0,
            119,
            0,
            121,
            0,
            122,
            0,
            123,
            0,
            136,
            0,
            146,
            146,
            1,
            0,
            147,
            0,
            152,
            2,
            10,
            0,
            153,
            2,
            10,
            0,
            154,
            2,
            10,
            0,
            155,
            1,
            1,
            0,
            156,
            12,
            10,
            0,
            172,
            2,
            10,
            0,
            209,
            0,
            3,
            0,
            0,  # terminator
        ]
    )
    # Datatype table: 12c+ (UB2_DTY) uses the uniform 2-byte-per-field table;
    # 11g uses the 1-byte form built above. The encoding flag follows suit
    # (oracledb sends 3 = MULTI_BYTE|CONV_LENGTH for 12c+, seerdb 1 for 11g).
    if FieldVersion >= FIELD_VERSION_12_1:
        DataTypeTable = _datatype_table_12c()
        Flag = 3
    else:
        DataTypeTable = IdentityMap + TypeOverrides
        Flag = 1
    # Same charset for IN (server-side) and OUT (client-side) negotiation.
    return (
        bytes([TTI_DTY])
        + Charset
        + Charset
        + bytes([Flag])
        + CapabilityHeader
        + TableHeader
        + DataTypeTable
    )


def _oac_rep_row(Rows: list) -> list:
    # For array DML, pick a representative value per column for the single OAC:
    # the one with the largest declared size (str/bytes byte length), so the
    # OAC's max-length covers every iteration. Fixed-size types (NUMBER, DATE,
    # ...) keep the first row's value.
    def _size(Value: object) -> int:
        if isinstance(Value, str):
            return len(Value.encode('utf-8'))
        if isinstance(Value, (bytes, bytearray)):
            return len(Value)
        return 0

    NumCols = len(Rows[0])
    Rep = []
    for J in range(NumCols):
        Best = Rows[0][J]
        BestSize = _size(Best)
        for R in Rows[1:]:
            S = _size(R[J])
            if S > BestSize:
                Best, BestSize = R[J], S
        Rep.append(Best)
    return Rep


def _long_bind_positions(Oac: list, MaxStringSize: int) -> frozenset:
    # The binds declared wider than the server takes in place. Their OAC makes
    # them LONG-class binds, whose values the server reads after the row's
    # others (docs/PROTOCOL.md 5.4). Read off the OAC actually sent, so the two
    # can never disagree. An associative-array bind (#122) is never LONG-class,
    # whatever its element size. Matches python-oracledb.
    Out = set()
    for Index, Token in enumerate(Oac):
        if isinstance(Token, Var) and Token.is_array:
            continue
        (_, MaxLen, *_rest) = decode_oac_fields(encode_token_oac(Token))
        if MaxLen > MaxStringSize:
            Out.add(Index)
    return frozenset(Out)


def has_long_class_bind(Bind: list, Batch: list, MaxStringSize: int) -> bool:
    """Whether this execute carries a bind declared wider than the server takes
    in place (docs/PROTOCOL.md 5.4). Such a statement must not be cursor-cached:
    a cached cursor re-executed after DDL on its table made a pre-12c server
    reuse the previous execution's LONG-class value for a NULL (#720)."""
    if not Bind:
        return False
    return bool(_long_bind_positions(_oac_rep_row([Bind] + Batch), MaxStringSize))


def _rxd_rows(Bind: list, Batch: list, ReturnBinds, LongBinds) -> list:
    # The rows whose values actually travel in the RXD tokens, each in the order
    # the server reads it. Every bind is described once in the OAC, but a
    # RETURNING ... INTO out-bind is filled by the server from the affected rows,
    # so it must not carry a value here -- in any iteration (#687). Sending one
    # made the server read the next iteration's first value as this one's tail
    # and reject the whole call as a malformed TTC packet. And a LONG-class
    # bind's value comes after the row's others: written in place, the server
    # took the next bind's value for it and the two silently swapped columns.
    def _row(R):
        Kept = [(I, V) for I, V in enumerate(R) if I not in ReturnBinds]
        return [V for I, V in Kept if I not in LongBinds] + [
            V for I, V in Kept if I in LongBinds
        ]

    return [_row(R) for R in [Bind] + Batch]


def encode_dictionary_exec(Dictionary: dict) -> bytes:
    # Publish the field version for the bind-OAC encoder (encode_token_raw).
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    _ENCODE_FIELD_VERSION.set(FieldVersion)
    Type = Dictionary['query']['type']
    Auto = Dictionary['query']['auto']
    Fetch = Dictionary['query']['fetch']
    ServerVersion = (
        b''
        if (Dictionary['query']['server_version'] >> 24) == 10
        else bytes([0, 0, 0, 0, 0])
    )
    Cursor = Dictionary['query']['cursor']
    Query = Dictionary['query']['query'].encode('utf-8')
    QueryLen = len(Query)
    QueryFlag = 1 if QueryLen > 0 else 0
    Bind = Dictionary['query']['bind']
    BindLen = len(Bind)
    BindFlag = 1 if (Cursor == 0) and (BindLen > 0) else 0
    # DML RETURNING ... INTO (#120): the positions of the OUT (return) binds.
    # All binds get an OAC, but only the non-return binds carry a value in the
    # RXD row (the server fills the return binds from the affected rows).
    ReturnBinds = Dictionary['query'].get('return_binds') or frozenset()
    Batch = Dictionary['query']['batch']
    # Batch is a list of *additional* rows (each a list of column values) for
    # array DML: the OAC describes the columns once (sized to the widest value
    # in each column, so a later row can't exceed the declared buffer), the
    # iteration count is 1 + len(Batch), and each row is sent as its own RXD
    # token after the OAC.
    BatchLen = len(Batch)
    Oac = _oac_rep_row([Bind] + Batch) if Bind else []
    # A PL/SQL block's values ride in place whatever their size; elsewhere a
    # LONG-class bind's value goes after the row's others (docs/PROTOCOL.md
    # 5.4). The threshold is the server's, read at connect; 4000 is pre-12c's.
    LongBinds = (
        frozenset()
        if Type == 'block'
        else _long_bind_positions(Oac, Dictionary.get('max_string_size', 4000))
    )
    Rows = [R for R in _rxd_rows(Bind, Batch, ReturnBinds, LongBinds) if R]
    Def = Dictionary['query']['def']
    DefLen = len(Def)
    DefFlag = 1 if DefLen > 0 else 0
    Tseq = Dictionary['seq']
    # Request pipelining (#158): a pipelined execute numbers itself 1..N so the
    # server tags each response with a matching TOKEN (33) marker. Ordinary
    # (non-pipelined) executes leave this 0 — encode_sb4(0) is the historical
    # single zero byte, so the bytes are unchanged.
    TokenNum = Dictionary.get('token_num', 0)

    if Cursor == 0:
        (Opt, LMax, Max, All8) = set_opts(Type, 1, BindFlag, BatchLen, Auto)
    elif Type == 'fetch':
        (Opt, LMax, Max, All8) = set_opts(Type, 0, DefFlag, 0, Fetch)
    elif Type == 'select':
        (Opt, LMax, Max, All8) = set_opts(Type, 0, 0, 0, Fetch)
    else:
        (Opt, LMax, Max, All8) = set_opts(Type, 0, 0, BatchLen, Auto)

    # Array-DML batch-error mode: with this exec option set, a per-row error
    # (e.g. a unique-constraint violation) no longer aborts the whole batch —
    # the server applies the good rows and returns the failures as the OER's
    # batch-error code/offset/message arrays (#18). Verified against an
    # oracledb-thin capture: it ORs 0x80000 into the leading Opt word.
    if Dictionary['query'].get('batcherrors'):
        Opt |= TNS_EXEC_OPTION_BATCH_ERRORS

    # Array-DML row counts (oracledb arraydmlrowcounts, #18): ask the server to
    # return a per-iteration affected-row count. This is a 12c+ feature (it
    # rides in the 12c+ OALL8 al8pidmlrc block below) and only meaningful for an
    # actual batch. Two coordinated request-side changes, both reverse-
    # engineered from an oracledb-thin capture: (1) al8i4[9] = 0xC000 here, and
    # (2) the al8pidmlrc pointer + iteration count in `Middle`. Omitting either
    # makes the server reject the execute as malformed (ORA-03137 kpoal8Check).
    ArrayDmlRowCounts = bool(
        Dictionary['query'].get('arraydmlrowcounts')
        and FieldVersion >= FIELD_VERSION_12_2
        and BatchLen > 0
    )
    if ArrayDmlRowCounts and len(All8) > 9:
        All8 = list(All8)
        All8[9] = TNS_AL8I4_ARRAY_DML_ROWCOUNTS

    # Implicit result sets (#121): opt in on PL/SQL block executes (12c+) by
    # setting TNS_EXEC_FLAGS_IMPLICIT_RESULTSET (0x8000) in al8i4[9]. Without it
    # a block calling DBMS_SQL.RETURN_RESULT fails with ORA-29481 ("implicit
    # results cannot be returned to client"). oracledb sets this on every
    # normal execute; scoping it to blocks keeps the DML/DDL paths untouched.
    if Type == 'block' and FieldVersion >= FIELD_VERSION_12_1 and len(All8) > 9:
        All8 = list(All8)
        All8[9] = All8[9] | 0x8000

    # 23ai (fv > 17, #89): the execute framing the server expects under field
    # version 24 differs from the legacy form in three spots, reverse-engineered
    # from an oracledb-thin fv24 capture (docs/PROTOCOL.md §20):
    #   - the prefetch-buffer-size field (LMax) must be 0, not the 0xffffffff
    #     long-fetch sentinel the first SELECT carries, or the server's stricter
    #     parse overflows (ORA-03120, two-task conversion integer overflow);
    #   - the exec-options word gains 0x40;
    #   - al8i4[9] (exec flags) gains 0x8000 (already implied by the array-DML
    #     0xC000 value, so only set it when that path didn't).
    if FieldVersion > FIELD_VERSION_23_1:
        if LMax == 0xFFFFFFFF:
            LMax = 0
        # The 0x40 options bit and al8i4[9] = 0x8000 are query-execute flags;
        # setting them on a DDL/DML execute makes the server reject it
        # (ORA-03137 kpoal8Check-5 [32768]).
        if Type in ('select', 'fetch'):
            Opt |= 0x40
            if not ArrayDmlRowCounts and len(All8) > 9:
                All8 = list(All8)
                All8[9] = 0x8000

    # Server-side scrollable cursor (#181): mark the cursor scrollable (and keep
    # it open past EOF) on the opening execute, and carry the scroll request
    # (orientation + 1-based position) on a scroll re-execute. al8i4[9] holds the
    # exec flags, al8i4[10] the orientation, al8i4[11] the position — validated
    # against a 23ai oracledb-thin capture (al8i4[9] reads 0x8082 = the 23ai
    # query flag | NO_CANCEL_ON_EOF | SCROLLABLE).
    Scroll = Dictionary['query'].get('scroll')  # (orient, pos) or None
    if (Dictionary['query'].get('scrollable') or Scroll) and len(All8) > 11:
        All8 = list(All8)
        All8[9] |= TNS_EXEC_FLAGS_SCROLLABLE | TNS_EXEC_FLAGS_NO_CANCEL_ON_EOF
        if Scroll:
            All8[10], All8[11] = Scroll
            # A scroll re-execute (open cursor, no new parse) is a FETCH-only
            # call: oracledb-thin sends exec options 0x8040, but set_opts forces
            # the EXECUTE bit (0x20) on for a Flag=0 select. Leaving it on makes
            # the server re-run the query and reset the result set, so the scroll
            # orientation positions from the top and every fetch returns empty
            # (#181). Clear it on a re-execute (Cursor != 0); the opening execute
            # (Cursor == 0) keeps PARSE+EXECUTE+FETCH (oracledb 0x8061).
            if Cursor != 0:
                Opt &= ~TNS_EXEC_OPTION_EXECUTE

    All8Len = len(All8)
    All8Flag = 1 if All8Len > 0 else 0
    All8s = reduce(lambda x, y: x + y, [encode_sb4(A) for A in All8])

    RowData = b''.join(encode_tokens_rxd(R, b'') for R in Rows)
    if BindLen == DefLen == 0:
        Tokens = b''
    elif DefLen == QueryLen == 0:
        # Cached-cursor re-execute: the server kept the OAC from the parse, so
        # only the row data travels.
        Tokens = RowData
    elif DefLen == 0:
        # Every bind described once, then one RXD row per iteration carrying
        # the values the server does not fill itself.
        Tokens = encode_tokens_oac(Oac, b'') + RowData
    elif BindLen == QueryLen == 0:
        Tokens = encode_tokens_oac(Def, b'')
    else:
        raise Exception('Unhandled tokens combination', Bind, Batch, Def, Query)

    Head = (
        _fun_header(TTI_ALL8, Tseq, FieldVersion, TokenNum)
        + encode_sb4(Opt)
        + encode_sb4(Cursor)
        + bytes([QueryFlag])
        + encode_sb4(QueryLen)
        + bytes([All8Flag])
        + encode_sb4(All8Len)
        + bytes([0, 0])
        + encode_sb4(LMax)
        + encode_sb4(Fetch)
        + encode_sb4(Max)
        + bytes([BindFlag])
        + encode_sb4(BindLen)
        + bytes([0, 0, 0, 0, 0])
        + bytes([DefFlag])
        + encode_sb4(DefLen)
    )

    if FieldVersion >= FIELD_VERSION_12_2:
        # 12c+ OALL8 carries extra al8 fields after the 11g header: the DML
        # row-count block, then (12.2+) the SQL-signature / SQL-id pointers and
        # (12.2_EXT1+) the chunk-id pointers — all zero/null for us. The SQL is
        # length-prefixed (write_bytes_with_length). Without these the server
        # reads the SQL/al8i4 array from the wrong offset and returns ORA-03120
        # (two-task conversion routine: integer overflow). See oracledb
        # execute.pyx _write_execute_message.
        Middle = bytes([0, 0, 1]) + bytes([0, 0, 0, 0, 0])  # reg_lsb .. reg_msb
        if ArrayDmlRowCounts:
            # al8pidmlrc = pointer(1) + ub4 iteration count + 1. The server
            # returns that many per-iteration row counts in the response RPA
            # region (#18). Matches oracledb byte-for-byte (e.g. 4 iters →
            # 01 01 04 01).
            Middle += bytes([1]) + encode_sb4(1 + BatchLen) + bytes([1])
        else:
            Middle += bytes([0, 0, 0])  # al8pidmlrc block
        Middle += bytes([0, 0, 0, 0, 0])  # 12.2 al8sqlsig / SQL id
        if FieldVersion >= FIELD_VERSION_12_2_EXT1:
            Middle += bytes([0, 0])  # 12.2_EXT1 chunk ids
        # The length-prefixed SQL is written only when there is SQL to parse. On
        # a no-parse re-execute (Cursor != 0, empty query — e.g. a #181 scroll
        # re-execute) oracledb omits the SQL bytes entirely; emitting the
        # zero-length prefix (a stray 0x00) shifts the server's read of the
        # al8i4 array by one byte and it rejects the call as malformed
        # (ORA-03137 [12316]).
        Sql = _bytes_with_length(Query) if QueryLen else b''
        return Head + Middle + Sql + All8s + Tokens

    return Head + bytes([0, 0, 1]) + ServerVersion + Query + All8s + Tokens


def encode_dictionary_fetch(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    Cursor = encode_sb4(Dictionary['cursor'])
    Fetch = encode_sb4(Dictionary['fetch'])
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    return _fun_header(TTI_FETCH, Tseq, FieldVersion) + Cursor + Fetch


# ---------------------------------------------------------------------------
# Oracle 9i (pre-10g, field version 2) query/fetch — the TTI_ALL7 dialect.
# A SELECT is a four-call sequence (docs/PROTOCOL.md §19), reverse-engineered
# from the Oracle JDBC thin driver against a live 9.2.0.4 server (#97). Gate
# every fv2 path on `field_version < FIELD_VERSION_10_2`.
# ---------------------------------------------------------------------------
_O7_DESCRIBE_FUNC = 0x62  # describe columns (RPA carries the metadata)
_O7_CLOSE_FUNC = 0x14  # close cursor


def encode_o7_open(Seq: int) -> bytes:
    # Call 0: OOPEN — allocate a server cursor. The server tracks it as the
    # "current" cursor for the subsequent parse/describe/execute/close (which
    # all carry cursor field 0). Without it the parse fails ORA-01001.
    return bytes([TTI_FUN, 0x02, Seq, 0x01, 0x00])


def _o7_bind_oac(Value: object) -> bytes:
    # fv2 bind descriptor (same 13/14-byte shape as a define entry): the
    # client's declared type for an input bind. Number → VARNUM(6); str →
    # VARCHAR sized 4000 (what JDBC declares); bytes → RAW; None defaults to a
    # 1-byte VARCHAR. charset 31, csfrm 1 (csfrm 0 for RAW). #100.
    #
    # A `Var` (an OUT / IN OUT bind, #102) declares its registered type and
    # return-buffer size instead: NUMBER rides as VARNUM(6)/22 like an inline
    # number; RAW carries csfrm 0; everything else uses the Var's size (VARCHAR
    # defaults to 32767, matching JDBC). The mode (IN/OUT/IN OUT) is NOT in the
    # OAC — the server infers it from the block and signals it in the bind
    # prompt; see decode_fv2_block_out.
    from seerdb.common.datatypes import Var

    # Char binds declare AL32UTF8 (csfrm 1) — the driver negotiates an AL32UTF8
    # session and sends UTF-8, which the 9i server converts to its DB charset —
    # or AL16UTF16 for national (csfrm 2) binds, which ride as UTF-16BE (see
    # encode_token_rxd). The charset field is ignored for non-char types. #174.
    def _oac(Type, MaxSize, Csfrm):
        if Type in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR):
            Charset = AL16UTF16_CHARSET if Csfrm == 2 else AL32UTF8_CHARSET
        else:
            Charset = 31  # ignored by the server for non-char types (NUMBER /
            # DATE / RAW / INTERVAL); keep the historical value
        return (
            bytes([Type, 0x01, 0, 0])
            + encode_sb4(MaxSize)
            + bytes([0, 0, 0, 0])
            + encode_sb4(Charset)
            + bytes([Csfrm])
        )

    if isinstance(Value, Var):
        VType = Value.dbtype.tns_type
        Vcsfrm = getattr(Value.dbtype, 'csfrm', 1)
        if VType == TNS_TYPE_NUMBER:
            Type, MaxSize, Csfrm = 0x06, 22, 1
        elif VType == TNS_TYPE_RAW:
            Type, MaxSize, Csfrm = TNS_TYPE_RAW, Value.size, 0
        else:
            Type, MaxSize, Csfrm = VType, Value.size, Vcsfrm
        return _oac(Type, MaxSize, Csfrm)
    if isinstance(Value, str):
        Type, MaxSize, Csfrm = TNS_TYPE_VARCHAR, 4000, 1
    elif isinstance(Value, (bytes, bytearray)):
        Type, MaxSize, Csfrm = TNS_TYPE_RAW, 2000, 0
    elif isinstance(Value, bool) or isinstance(Value, (int, float, Decimal)):
        Type, MaxSize, Csfrm = 0x06, 22, 1  # VARNUM
    elif isinstance(Value, datetime.datetime):
        # A datetime/date bind must declare the same Oracle temporal type the
        # value carries on the wire (encode_token_datetime emits 7/11/13 bytes),
        # else the server reads the binary value as a VARCHAR and the implicit
        # date conversion fails with ORA-01858 (#172). Mirror encode_token_oac:
        # tz-aware -> TIMESTAMPTZ(13); sub-second -> TIMESTAMP(11); else DATE(7).
        if Value.tzinfo is not None:
            Type, MaxSize, Csfrm = TNS_TYPE_TIMESTAMPTZ, 13, 0
        elif Value.microsecond > 0:
            Type, MaxSize, Csfrm = TNS_TYPE_TIMESTAMP, 11, 0
        else:
            Type, MaxSize, Csfrm = TNS_TYPE_DATE, 7, 0
    elif isinstance(Value, datetime.date):
        Type, MaxSize, Csfrm = TNS_TYPE_DATE, 7, 0
    elif isinstance(Value, datetime.timedelta):
        # INTERVAL DAY TO SECOND (#173): encode_token_rxd emits the 11-byte
        # interval; declare the matching type so the server does not read it as
        # a VARCHAR and fail with ORA-01867.
        Type, MaxSize, Csfrm = TNS_TYPE_INTERVALDS, 11, 0
    elif isinstance(Value, IntervalYM):
        Type, MaxSize, Csfrm = TNS_TYPE_INTERVALYM, 5, 0  # 5-byte YM interval
    elif Value is None:
        Type, MaxSize, Csfrm = TNS_TYPE_VARCHAR, 1, 1
    else:
        Type, MaxSize, Csfrm = TNS_TYPE_VARCHAR, 4000, 1
    return _oac(Type, MaxSize, Csfrm)


# The two fixed option blocks that frame the inline SQL in a TTI_ALL7 parse call
# (#100 SELECT/DML, #102 PL/SQL block) — the block between the SQL-length and the
# bind count, and the tail after the SQL. Both parse encoders share them verbatim.
# The individual bytes are opaque 9i framing, carried as captured ground truth
# (verified byte-for-byte against the 9i parse captures).
_O7_PARSE_MID = bytes([0, 0, 0x01, 0x01, 0x07, 0x01, 0x01, 0x02, 0, 0, 0])
_O7_PARSE_TAIL = bytes([0x01, 0x01, 0x01, 0x01, 0, 0, 0, 0, 0])


def _o7_bind_count(Binds: list) -> bytes:
    # The bind-count field that precedes the inline SQL: `01 01 <count>` with
    # binds, `00 00` without.
    return bytes([0x01, 0x01, len(Binds)]) if Binds else bytes([0, 0])


def encode_o7_parse(Seq: int, Sql: str, Binds: list | None = None) -> bytes:
    # Call 1: TTI_ALL7 parse. The SQL is carried inline, sb4-length-prefixed,
    # between two fixed option blocks. With input binds (#100) the option word
    # flips to 0x29, a bind-count field precedes the SQL, and each bind's OAC
    # plus the values (one RXD with all values) are appended after the SQL.
    Binds = Binds or []
    SqlBytes = Sql.encode('utf-8')
    Opt = 0x29 if Binds else 0x21
    Out = (
        bytes([TTI_FUN, TTI_ALL7, Seq, 0x02, 0x80, Opt, 0x01, 0x01, 0x01])
        + encode_sb4(len(SqlBytes))
        + _O7_PARSE_MID
        + _o7_bind_count(Binds)
        + SqlBytes
        + _O7_PARSE_TAIL
    )
    if Binds:
        Out += b''.join(_o7_bind_oac(V) for V in Binds)
        Out += encode_tokens_rxd(Binds, b'')
    return Out


def encode_o7_block(Seq: int, Sql: str, Binds: list | None = None) -> bytes:
    # Anonymous PL/SQL block parse-execute over TTI_ALL7 (#102, PROTOCOL §19.6).
    # Same framing as encode_o7_parse EXCEPT the option word: a block uses
    # `01 21` (no binds) / `02 04 29` (binds) where a SELECT/DML uses
    # `02 80 21` / `02 80 29` — the 0x8000 "values are inline" bit is NOT set,
    # so the server rejects DML opts on a block with ORA-00600. Consequently the
    # bind OACs are sent here but the VALUES are NOT appended inline; the server
    # answers with a "send the binds" prompt and the caller then sends the
    # values as a standalone RXD (encode_tokens_rxd). Verified byte-for-byte
    # against cap_9i_plsql_{noarg,inbind}.log.
    Binds = Binds or []
    SqlBytes = Sql.encode('utf-8')
    OptBytes = bytes([0x02, 0x04, 0x29]) if Binds else bytes([0x01, 0x21])
    Out = (
        bytes([TTI_FUN, TTI_ALL7, Seq])
        + OptBytes
        + bytes([0x01, 0x01, 0x01])
        + encode_sb4(len(SqlBytes))
        + _O7_PARSE_MID
        + _o7_bind_count(Binds)
        + SqlBytes
        + _O7_PARSE_TAIL
    )
    if Binds:
        # Bind OACs only — the values follow in a separate RXD frame after the
        # server's bind prompt (the 0x8000-inline path is not used for blocks).
        Out += b''.join(_o7_bind_oac(V) for V in Binds)
    return Out


def encode_o7_describe(Seq: int) -> bytes:
    # Call 2: fixed describe-columns request; response is the metadata RPA.
    return bytes(
        [
            TTI_FUN,
            _O7_DESCRIBE_FUNC,
            Seq,
            0x07,
            0x01,
            0x01,
            0,
            0,
            0x01,
            0x02,
            0x01,
            0x01,
        ]
    )


def _o7_define_entry(Col: dict) -> bytes:
    # One 13/14-byte define entry: the client's requested return type for a
    # column (built from the describe). deftype = VARNUM(6) for NUMBER, else the
    # column type; CHAR carries flag 0x21; NUMBER/DATE/TIMESTAMP use a fixed
    # buffer size, everything else the described max. charset defaults to 31
    # (the server DB charset JDBC requests) unless the column is national.
    Type = Col['data_type']
    Csfrm = Col.get('csfrm') or 0
    if Type == TNS_TYPE_NUMBER:
        DefType, MaxSize = 0x06, 22
    elif Type == TNS_TYPE_DATE:
        DefType, MaxSize = TNS_TYPE_DATE, 7
    elif Type in (TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPTZ, 181):
        DefType, MaxSize = Type, 13
    elif Type in (TNS_TYPE_RID, TNS_TYPE_ROWID, TNS_TYPE_UROWID):
        # Request ROWID as VARCHAR so the server returns its text form (what
        # JDBC does); the native ROWID return form desyncs the fv2 row stream
        # (ORA-01002). The value arrives as the familiar 18-char rowid string.
        DefType, MaxSize, Csfrm = TNS_TYPE_VARCHAR, 128, 0
    elif Type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW):
        # LONG / LONG RAW: request the native type with the 2 GiB max buffer
        # (as JDBC does); the value streams back in the chunked DALC form.
        DefType, MaxSize = Type, 0x7FFFFFFF
    else:
        DefType, MaxSize = Type, Col.get('max_size') or 0
    Flag = 0x21 if Type == TNS_TYPE_CHAR else 0x01
    Charset = Col.get('charset') or 31
    return (
        bytes([DefType, Flag, 0, 0])
        + encode_sb4(MaxSize)
        + bytes([0, 0, 0, 0])
        + encode_sb4(Charset)
        + bytes([Csfrm])
    )


def encode_o7_exec(Seq: int, Columns: list) -> bytes:
    # Call 3: TTI_ALL7 execute + fetch (option word 02 80 50), carrying a define
    # block (one entry per column) so the server returns the requested types.
    Head = bytes(
        [
            TTI_FUN,
            TTI_ALL7,
            Seq,
            0x02,
            0x80,
            0x50,
            0x01,
            0x01,
            0,
            0,
            0,
            0,
            0x01,
            0x01,
            0x07,
            0x01,
            0x01,
            0x02,
            0,
        ]
    )
    Defines = bytes(
        [0x01, 0x01, len(Columns), 0, 0, 0x01, 0x01, 0x01, 0x0A, 0, 0, 0, 0, 0]
    ) + b''.join(_o7_define_entry(C) for C in Columns)
    return Head + Defines


def encode_o7_close(Seq: int) -> bytes:
    # Call 4: close the cursor.
    return bytes([TTI_FUN, _O7_CLOSE_FUNC, Seq, 0x01, 0x01])


# ---------------------------------------------------------------------------
# fv2 (9i) LOB read — TTI_LOBOPS GETLEN + READ (PROTOCOL.md §19.5)
# ---------------------------------------------------------------------------
# 9i's TTI_LOBOPS request is far shorter than the modern (10g+) form, and JDBC
# issues it as a *pair* per LOB cell: first GETLEN to learn the content length,
# then READ to pull exactly that many chars (CLOB) / bytes (BLOB). The modern
# single-shot READ returns empty on 9i. The locator is `_read_lob_column`'s
# output (`00 <ub1 len><body>`); its leading byte is dropped and the rest
# (`<ub1 len><body>`) is sent verbatim. Every fv2 LOBOPS request shares the
# shape `03 60 <seq> 01 <sb4 locator-length> <op middle> <locator[1:]> <trailer>`
# — only the op-specific middle and trailer differ. Validated byte-for-byte
# against cap_9i_lobread.log (CLOB + BLOB GETLEN/READ) and cap_9i_bfile.log
# (BFILE FILE_OPEN/READ/CLOSE). (#102, PROTOCOL §19.5 / §19.8) The four op
# middles are generated by `_o7_lobop_mid` (with the other sb4 consumers, below).


def _encode_o7_lobop(Seq: int, Locator: bytes, Middle: bytes, Trailer: bytes) -> bytes:
    # Build a fv2 TTI_LOBOPS request. The source-locator length counts the full
    # `_read_lob_column` block (its leading byte plus the `<ub1 len><body>` that
    # goes on the wire); CLOB/BLOB locators are a fixed 86 bytes, BFILE locators
    # vary with the directory + file name, so it is computed rather than fixed.
    return (
        bytes([TTI_FUN, TTI_LOBOPS, Seq, 0x01])
        + encode_sb4(len(Locator))
        + Middle
        + Locator[1:]
        + Trailer
    )


def encode_o7_lob_getlen(Seq: int, Locator: bytes) -> bytes:
    # GETLEN: ask the server for the LOB's length. Trailer is a single 0x00
    # (no read amount). Response carries the amount — see decode_fv2_lob_getlen.
    return _encode_o7_lobop(Seq, Locator, _LOBOP_GETLEN_MID, bytes([0]))


def encode_o7_lob_read(Seq: int, Locator: bytes, Amount: int) -> bytes:
    # READ: pull `Amount` chars/bytes (the value GETLEN returned) starting at
    # offset 1. Response is `0e fe <chunks>` then an RPA + OER.
    return _encode_o7_lobop(Seq, Locator, _LOBOP_READ_MID, encode_sb4(Amount))


def encode_o7_bfile_open(Seq: int, Locator: bytes) -> bytes:
    # BFILE FILE_OPEN: open the external file read-only (trailer 01 0b = amount
    # pointer present + open mode 0x0b). The reply's RPA carries an *updated*
    # locator with the open flag set — GETLEN/READ/CLOSE must use that one
    # (decode_fv2_opened_locator). (#102, PROTOCOL §19.8)
    return _encode_o7_lobop(Seq, Locator, _LOBOP_FOPEN_MID, bytes.fromhex('010b'))


def encode_o7_bfile_close(Seq: int, Locator: bytes) -> bytes:
    # BFILE FILE_CLOSE: close the opened file (no trailer).
    return _encode_o7_lobop(Seq, Locator, _LOBOP_FCLOSE_MID, b'')


def decode_fv2_opened_locator(Packet: bytes) -> bytes | None:
    # Pull the opened BFILE locator out of a FILE_OPEN reply: TTI_RPA (08) 00
    # then `<ub1 len><body>` (the open-flagged locator), then `01 0b` + OER.
    # Returned in `_read_lob_column`'s full form (a leading 0x00 + the
    # `<ub1 len><body>`) so it feeds straight back into the LOBOPS encoders.
    if not Packet or Packet[0] != TTI_RPA or len(Packet) < 3:
        return None
    Olen = Packet[2]
    return bytes([0]) + bytes(Packet[2 : 3 + Olen])


def decode_fv2_lob_chunks(Data: bytes) -> tuple[bytes, bool]:
    # Parse the content of a 9i (fv2) TTI_LOBOPS READ reply: TTI_LOB (0e) then
    # 0xfe, then `<ub1 len><bytes>` chunks ending at a zero-length chunk; the
    # trailing RPA is ignored. Returns (content, complete). `complete` is False
    # when the zero-length terminator hasn't been reached yet (the content
    # spans more packets) — the caller appends the next packet and re-parses the
    # full accumulated buffer. Unlike modern (10g+) replies the fv2 READ reply
    # carries no `04 01 01` OER call-status (a single-row fetch happened to
    # include one; a multi-row fetch does not), so the zero-length chunk is the
    # only reliable terminator. (#102, PROTOCOL.md §19.5)
    if len(Data) < 2 or Data[0] != TTI_LOB:
        return (b'', False)
    # Data[1] is the 0xfe chunked marker; a non-chunked single value would be
    # `0e <len> <bytes>`, handled by treating Data[1] as the first chunk length.
    Pos = 2 if Data[1] == 0xFE else 1
    Content = b''
    while Pos < len(Data):
        ChunkLen = Data[Pos]
        if ChunkLen == 0:
            return (Content, True)  # zero-length chunk = end
        if Pos + 1 + ChunkLen > len(Data):
            break  # chunk split across packets
        Content += Data[Pos + 1 : Pos + 1 + ChunkLen]
        Pos += 1 + ChunkLen
    return (Content, False)


def decode_fv2_lob_getlen(Packet: bytes) -> int:
    # GETLEN response layout: TTI_RPA (08) 00 <ub1 loclen><locator echo>
    # <ub4 amount> TTI_OER. The amount is in chars for CLOB/NCLOB and bytes for
    # BLOB. Returns 0 on an unexpected shape (e.g. an empty LOB) so the caller
    # reads nothing rather than desyncing.
    if not Packet or Packet[0] != TTI_RPA:
        return 0
    Pos = 2  # skip RPA token + its 0x00
    if Pos >= len(Packet):
        return 0
    LocLen = Packet[Pos]
    Pos += 1 + LocLen  # skip the echoed locator
    if Pos >= len(Packet):
        return 0
    (Amount, _) = decode_ub4(Packet[Pos:])
    return Amount


def _decode_oac_fv2(Rest: bytes) -> tuple[dict, bytes]:
    # fv2 column descriptor = the modern decode_token_oac field order MINUS the
    # trailing Mxlc ub4 (a later addition). The leading DataType byte is the
    # standard Oracle type code (== TNS_TYPE_*), so existing value decoders are
    # reused. Returns a column dict shaped like decode_token_dcb's output.
    (DataType, Flag, Precision) = struct.unpack('>BBB', Rest[:3])
    Rest = Rest[3:]
    (DataScale, Rest) = decode_ub4(Rest)
    (MaxLen, Rest) = decode_ub4(Rest)
    (_Mal, Rest) = decode_ub4(Rest)
    (_Fl2, Rest) = decode_ub4(Rest)
    (_ToId, Rest) = decode_dalc(Rest)
    (_Vsn, Rest) = decode_ub4(Rest)
    (Charset, Rest) = decode_ub4(Rest)
    Csfrm = Rest[0]
    Rest = Rest[1:]
    Col = {
        'data_type': DataType,
        'data_length': MaxLen,
        'data_scale': DataScale,
        'precision': Precision,
        'max_size': MaxLen,
        'charset': Charset,
        'csfrm': Csfrm,
        'null_ok': 1,
        'domain_schema': None,
        'domain_name': None,
    }
    return (Col, Rest)


def decode_fv2_describe(Data: bytes) -> list[dict]:
    # Parse the TTI_RPA (0x08) answering the 0x62 describe-columns call into a
    # list of column dicts (docs/PROTOCOL.md §19.1). Layout:
    #   08 01 <numcols> then per column:
    #     <OAC-fv2> null_ok(1B) namelen_bytes(1B) ub4(namelen_chars) DALC(name) 00 00
    #
    # The first byte after the OAC is null_ok (0x00 = NOT NULL, 0x01 = nullable),
    # NOT part of the name length. The historic "two ub4 name-lengths" reading
    # only survived because every offline fixture was `SELECT <literal> AS name
    # FROM dual` — a literal is always nullable, so null_ok=0x01 read as a width-1
    # ub4 whose value happened to equal the name length. A real NOT-NULL column
    # sends null_ok=0x00, which decode_ub4 misreads as width-0/value-0 (one byte),
    # slipping the whole column stream and garbling the name (b'\x08USERNAM') — and
    # a multi-column NOT-NULL select then fails the fetch with ORA-03115. Read
    # null_ok + the 1-byte byte-length explicitly, then the genuine ub4 char-length.
    NumCols = Data[2]
    Rest = Data[3:]
    Columns = []
    for _ in range(NumCols):
        (Col, Rest) = _decode_oac_fv2(Rest)
        Col['null_ok'] = 0 if Rest[0] == 0 else 1  # 0x00 NOT NULL, 0x01 nullable
        Rest = Rest[2:]  # null_ok(1B) + namelen_bytes(1B)
        (_NlChars, Rest) = decode_ub4(Rest)  # name length in chars (ub4)
        (Name, Rest) = decode_dalc(Rest)
        Col['column_name'] = Name if isinstance(Name, bytes) else b''
        Columns.append(Col)
        # two-byte inter-column separator
        if len(Rest) >= 2 and Rest[0] == 0 and Rest[1] == 0:
            Rest = Rest[2:]
    return Columns


def _encode_8i_bind_oac(Value: object) -> bytes:
    # 25-byte 8i bind descriptor, mirroring the describe column OAC
    # (decode_8i_dcb_describe): data type, ub4be [flag 0x03 | max_size], 14 bytes
    # reserved, ub4be character set, reserved, csform. Reverse-engineered from a
    # live 9.2-client -> 8.1.7 bind trace (docs/PROTOCOL.md §19.11). max_size is
    # the largest value we may send / receive for this bind: 22 (the NUMBER max)
    # for numbers, 7 for DATE, and the value byte length for VARCHAR2 / RAW. An
    # OUT / IN OUT `Var` declares its registered type + return-buffer size (#362).
    from seerdb.common.datatypes import Var

    if isinstance(Value, Var):
        DType = Value.dbtype.tns_type
        if DType == 2:  # NUMBER
            Charset, Csform, MaxSize = 0, 0, 22
        elif DType in (1, 96):  # VARCHAR2, CHAR
            Charset, Csform, MaxSize = 31, Value.dbtype.csfrm, max(Value.size, 1)
        elif DType == 12:  # DATE
            Charset, Csform, MaxSize = 0, 0, 7
        else:
            Charset, Csform, MaxSize = 0, 0, max(Value.size, 1)
    elif Value is None:
        DType, Charset, Csform, MaxSize = 1, 31, 1, 1  # NULL rides as VARCHAR2(1)
    elif isinstance(Value, (bool, int, float, Decimal)):
        DType, Charset, Csform, MaxSize = 2, 0, 0, 22  # NUMBER
    elif isinstance(Value, (bytes, bytearray)):
        DType, Charset, Csform, MaxSize = 23, 0, 0, max(len(Value), 1)  # RAW
    elif isinstance(Value, (datetime.datetime, datetime.date)):
        DType, Charset, Csform, MaxSize = 12, 0, 0, 7  # DATE
    else:  # str (and anything else via its str() form) -> VARCHAR2
        DType, Charset, Csform = 1, 31, 1
        MaxSize = max(len(str(Value).encode('latin-1')), 1)
    # max_size rides as a 2-byte LITTLE-endian field at offset +4 (8i is x86):
    # `type, 0x03, 00, 00, <max_size LE16>, …`. For values <= 255 this is
    # byte-identical to a 3-byte big-endian field, which is why short binds
    # worked; at >= 256 the little-endian form is required — otherwise the 8i
    # server mis-reads the size and rejects the bind as a LONG value (ORA-01461).
    return (
        bytes([DType, 0x03, 0, 0])
        + min(MaxSize, 0xFFFF).to_bytes(2, 'little')
        + bytes(13)
        + Charset.to_bytes(4, 'big')
        + bytes([0, Csform])
    )


# A pure-OUT bind sends no input value: the 8i value section carries this fixed
# placeholder in the bind's slot (#362, captured verbatim).
_O8I_OUT_PLACEHOLDER = bytes([0xFD, 0x01])


def _encode_8i_bind_value(Value: object) -> bytes:
    # The bind value as a DALC (length-prefixed). Strings ride as WE8ISO8859P1
    # (latin-1), matching the 8i DB charset; everything else reuses the shared
    # value encoder (Oracle NUMBER, DATE, RAW, …). A pure-OUT `Var` sends the OUT
    # placeholder; an IN OUT `Var` (has_value) sends its input value inline.
    from seerdb.common.datatypes import Var

    if isinstance(Value, Var):
        return (
            _encode_8i_bind_value(Value._value)
            if Value.has_value
            else _O8I_OUT_PLACEHOLDER
        )
    if isinstance(Value, str):
        return encode_token_rxd(Value.encode('latin-1'))
    return encode_token_rxd(Value)


# The op-specific middles (25 bytes) of the 8i TTI_LOBOPS requests, captured
# verbatim from a 9.2-client -> 8.1.7 session (docs/PROTOCOL.md §19.15 / §19.17):
# the CLOB/BLOB READ, and the BFILE FILE_OPEN / GETLEN / FILE_CLOSE (#401). The
# op family shares one envelope; only the middle and trailer vary.
def _o8i_lobop_mid(
    operation: int, *, source_offset: int = 0, has_reply: int = 1
) -> bytes:
    """The 8i TTI_LOBOPS request middle — the same flag block as the fv2 one
    (:func:`_o7_lobop_mid`) but with the numeric fields as fixed ub4 LE rather
    than sb4: source offset at byte 5, the reply flag at 14, and the
    ``TNS_LOB_OP_*`` operation (ub4 LE) at 16."""
    mid = bytearray(25)
    struct.pack_into('<I', mid, 5, source_offset)
    mid[14] = has_reply
    struct.pack_into('<I', mid, 16, operation)
    return bytes(mid)


_O8I_LOBOP_READ_MID = _o8i_lobop_mid(TNS_LOB_OP_READ, source_offset=1)
_O8I_LOBOP_FOPEN_MID = _o8i_lobop_mid(TNS_LOB_OP_FILE_OPEN)
_O8I_LOBOP_GETLEN_MID = _o8i_lobop_mid(TNS_LOB_OP_GET_LENGTH)
_O8I_LOBOP_FCLOSE_MID = _o8i_lobop_mid(TNS_LOB_OP_FILE_CLOSE, has_reply=0)


def _encode_o8i_lobop(Seq: int, Locator: bytes, Middle: bytes, Trailer: bytes) -> bytes:
    # An 8i TTI_LOBOPS (0x60) request: `03 60 seq 01` + ub4-LE locator length +
    # the 25-byte op middle + the locator + an op-specific trailer. Lengths ride
    # LITTLE-endian (8i is x86). The whole envelope is captured ground truth.
    return (
        bytes([TTI_FUN, TTI_LOBOPS, Seq & 0xFF, 0x01])
        + len(Locator).to_bytes(4, 'little')
        + Middle
        + Locator
        + Trailer
    )


def encode_8i_lob_read(Seq: int, Locator: bytes, Amount: int) -> bytes:
    # 8i CLOB/BLOB/BFILE READ: unlike 9i's GETLEN + READ pair, 8i reads the value
    # in one call whose reply is the shared `0e fe <chunks> 00` LOB content
    # (decode_fv2_lob_chunks). `Amount` is chars for a CLOB, bytes for a BLOB /
    # BFILE; the trailer is the ub4-LE read amount.
    return _encode_o8i_lobop(
        Seq, Locator, _O8I_LOBOP_READ_MID, Amount.to_bytes(4, 'little')
    )


def encode_o8i_bfile_open(Seq: int, Locator: bytes) -> bytes:
    # 8i BFILE FILE_OPEN (#401): open the external file read-only. The trailer is
    # the ub4-LE open mode 0x0b (read-only). The reply's RPA carries an *updated*
    # locator with the open flag set — GETLEN / READ / CLOSE must use that one
    # (decode_fv2_opened_locator, shared with the 9i path). §19.17.
    return _encode_o8i_lobop(
        Seq, Locator, _O8I_LOBOP_FOPEN_MID, (0x0B).to_bytes(4, 'little')
    )


def encode_o8i_bfile_getlen(Seq: int, Locator: bytes) -> bytes:
    # 8i BFILE GETLEN (#401): ask for the file length. Trailer is a ub4-LE 0. The
    # reply carries the length as a ub4-LE after the locator (decode_o8i_bfile_getlen).
    return _encode_o8i_lobop(
        Seq, Locator, _O8I_LOBOP_GETLEN_MID, (0).to_bytes(4, 'little')
    )


def encode_o8i_bfile_close(Seq: int, Locator: bytes) -> bytes:
    # 8i BFILE FILE_CLOSE (#401): close the opened file. No trailer.
    return _encode_o8i_lobop(Seq, Locator, _O8I_LOBOP_FCLOSE_MID, b'')


def decode_o8i_bfile_getlen(Packet: bytes) -> int:
    # Pull the file length out of an 8i BFILE GETLEN reply (#401): TTI_RPA (08),
    # then the echoed `<ub1 len><body>` locator, then the ub4-LE length. The
    # locator's inner ub1 length sits at Packet[2], so the length starts at
    # 3 + that (the RPA byte + the leading 0 + the ub1-length-led body).
    if not Packet or Packet[0] != TTI_RPA or len(Packet) < 3:
        return 0
    off = 3 + Packet[2]
    return int.from_bytes(Packet[off : off + 4], 'little')


def decode_8i_block_out(Data: bytes, NumOut: int) -> list:
    # Decode the OUT / IN OUT return values from an 8i PL/SQL block reply
    # (docs/PROTOCOL.md §19.14). After the bind prompt (0x0b), the values ride a
    # single TTI_RXD (07) as `NumOut` × (DALC value + 2-byte trailer), in OUT-bind
    # position order. Returns the raw value bytes per OUT bind (None for empty /
    # NULL), decoded against each Var's declared type by the cursor.
    Rest = strip_fv2_bind_prompt(Data)
    OutValues: list = []
    if NumOut > 0 and Rest[:1] == bytes([TTI_RXD]):
        Rest = Rest[1:]
        for _ in range(NumOut):
            (Val, Rest) = decode_dalc(Rest)
            Rest = Rest[2:]  # sb2 indicator / return code
            OutValues.append(
                bytes(Val) if isinstance(Val, (bytes, bytearray)) and Val else None
            )
    return OutValues


# 8i statement-type codes (the OCI OCI_STMT_* family), carried at trailer offset
# +28 of the OALL8 and driving the whole option word. 0 = transaction control
# (COMMIT / ROLLBACK), which has no cursor.
O8I_STMT_SELECT = 1
O8I_STMT_UPDATE = 2
O8I_STMT_DELETE = 3
O8I_STMT_INSERT = 4
O8I_STMT_CREATE = 5
O8I_STMT_DROP = 6
O8I_STMT_ALTER = 7
O8I_STMT_BEGIN = 8
O8I_STMT_DECLARE = 9
O8I_STMT_TXN = 0

_O8I_STMT_TYPES = {
    'SELECT': O8I_STMT_SELECT,
    'UPDATE': O8I_STMT_UPDATE,
    'DELETE': O8I_STMT_DELETE,
    'INSERT': O8I_STMT_INSERT,
    'CREATE': O8I_STMT_CREATE,
    'DROP': O8I_STMT_DROP,
    'ALTER': O8I_STMT_ALTER,
    'TRUNCATE': O8I_STMT_CREATE,  # DDL, no rowcount; rides the CREATE code
    'BEGIN': O8I_STMT_BEGIN,
    'DECLARE': O8I_STMT_DECLARE,
}


def o8i_stmt_type(Head: str) -> int:
    # Map an upper-cased, stripped statement to its 8i OALL8 statement-type code.
    # COMMIT / ROLLBACK / SAVEPOINT / SET (transaction control) fall through to
    # O8I_STMT_TXN (0), which the encoder treats as a cursor-less statement.
    return _O8I_STMT_TYPES.get(Head.split(None, 1)[0] if Head else '', O8I_STMT_TXN)


def _encode_8i_oall8(Seq: int, Sql: bytes, StmtType: int, Binds: list) -> bytes:
    # The shared 8i OALL8 (TTI_ALL8, 0x5e) execute request (docs/PROTOCOL.md
    # §19.9, DML §19.12, binds §19.11). 8i CANNOT parse the modern (10g+) OALL8
    # this driver builds for every other tier — it answers that with an empty
    # packet and hangs up — so 8i needs this byte-compatible pre-10g form,
    # reverse-engineered from a live 9.2-client -> 8.1.7 trace. Everything about
    # the option word and trailer derives from `StmtType`:
    #   - option byte 0x21 base, + 0x40 for a query (SELECT fetches), + 0x08 with
    #     binds; the two option bytes after it are 0x80 0x00 for a cursor
    #     statement, 0x00 0x00 for txn control, and 0x00/0x04 0x04 for a PL/SQL
    #     block (the trailing 0x04 marks the block; the 0x04 before it flags binds)
    #   - trailer exec flag 0 for a query (execute is deferred to the fetch), 1
    #     otherwise; the statement type rides at +28.
    # The SQL length rides twice: an encode_sb4 count in the header, then the text
    # as a pre-10g chunked string (encode_chr — a plain length byte up to 64
    # bytes, else the 0xFE / 64-byte-chunk form). With binds the header carries
    # iteration count 1 + the bind count, and the bind section (all OACs, a 0x07
    # marker, then all values) follows the trailer. Pin the encode field version
    # to fv2 so encode_chr / encode_token_rxd take their pre-12c forms regardless
    # of any concurrent connection.
    NumBinds = len(Binds)
    IsQuery = StmtType == O8I_STMT_SELECT
    IsBlock = StmtType in (O8I_STMT_BEGIN, O8I_STMT_DECLARE)
    Token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_9_2)
    try:
        Option = 0x21 | (0x40 if IsQuery else 0) | (0x08 if NumBinds else 0)
        if IsBlock:
            Byte4, Byte5 = (0x04 if NumBinds else 0x00), 0x04
        else:
            Byte4, Byte5 = (0x80 if StmtType != O8I_STMT_TXN else 0x00), 0x00
        ExecFlag = 0 if IsQuery else 1
        Al8 = (
            bytes([0, 0, 0, 1, NumBinds, 0, 0, 0, 0, 0, 0, 0])  # iters=1, nbinds
            if NumBinds
            else bytes(12)
        )
        Message = (
            bytes([TTI_FUN, TTI_ALL8, Seq & 0xFF])
            + bytes([Option, Byte4, Byte5, 0, 0, 0, 0, 0])
            # SQL length: a 0x01 marker + a FIXED 4-byte LITTLE-endian count (8i
            # is x86). The earlier `encode_sb4` wrote a variable-width big-endian
            # field — byte-identical for a length <= 255 (`01 <len> 00 00 00`) but
            # one byte longer at >= 256, which shifted the whole request and the
            # server rejected it with ORA-01009 (#391).
            + bytes([0x01])
            + len(Sql).to_bytes(4, 'little')
            + bytes([0x01, 0x0C, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0x01, 0, 0, 0, 0])
            + Al8
            + bytes([0x01])
            + encode_chr(Sql.decode('latin-1'))  # SQL text (chunked if > 64 B)
            + bytes([0x01, 0, 0, 0, ExecFlag])
            + bytes(23)
            + bytes([StmtType])  # trailer +28: statement type
            + bytes(19)
        )
        if NumBinds:
            Oacs = [_encode_8i_bind_oac(Value) for Value in Binds]
            Message += b''.join(Oacs)
            Message += bytes([0x07])  # bind-value section marker
            # 8i applies the 10g+ rule too (docs/PROTOCOL.md 5.4, #714): a bind
            # declared wider than 4000 bytes is LONG-class and the server reads
            # its value after the row's others; written in place it swapped
            # columns with the next bind. The declared size is the OAC's
            # little-endian ub2 at +4. A PL/SQL block's values ride in place.
            Long = [
                not IsBlock and int.from_bytes(Oac[4:6], 'little') > 4000
                for Oac in Oacs
            ]
            for Value, IsLong in zip(Binds, Long):
                if not IsLong:
                    Message += _encode_8i_bind_value(Value)
            for Value, IsLong in zip(Binds, Long):
                if IsLong:
                    Message += _encode_8i_bind_value(Value)
        return Message
    finally:
        _ENCODE_FIELD_VERSION.reset(Token)


def encode_8i_oall8_query(Seq: int, Sql: bytes, Binds: list | None = None) -> bytes:
    # 8i SELECT (statement type 1); see _encode_8i_oall8.
    return _encode_8i_oall8(Seq, Sql, O8I_STMT_SELECT, Binds or [])


def encode_8i_oall8_dml(
    Seq: int, Sql: bytes, StmtType: int, Binds: list | None = None
) -> bytes:
    # 8i INSERT/UPDATE/DELETE/DDL and COMMIT/ROLLBACK (docs/PROTOCOL.md §19.12) —
    # the same OALL8 as a query but with no fetch; the affected-row count comes
    # back in the response OER (decode_8i_dml_response).
    return _encode_8i_oall8(Seq, Sql, StmtType, Binds or [])


def encode_8i_oall8_fetch(
    Seq: int, Cursor: int, Count: int, LongSize: int = 0x7FFFFFFF
) -> bytes:
    # Oracle 8i array fetch: the 9.2-era OALL8 (0x5e) with the fetch option
    # (0x40) and no SQL, pulling up to `Count` more rows from an open cursor
    # (docs/PROTOCOL.md §19.10). 8i's execute returns only the first row batch;
    # the client fetches the rest until a batch comes back empty (ORA-01403).
    # Reverse-engineered from the 9.2-client trace; fixed apart from the TTI
    # sequence byte, the cursor id, and two ub4 LITTLE-endian counts:
    #   - offset 31: the LONG fetch size — the maximum bytes of a LONG / LONG RAW
    #     column the server returns per row. 8i truncates the value to this size
    #     (it does NOT continue one LONG across fetch round trips), so the caller
    #     passes a large cap to read the whole value (#377). For a query with no
    #     LONG column it is just a prefetch hint. An earlier version wrote the row
    #     count here as big-endian, whose low byte landed on this field and capped
    #     every LONG at `fetch` bytes.
    #   - offset 49: the number of rows to return this call (1 when a LONG column
    #     is present — 8i forces single-row fetches for LONGs).
    Msg = bytearray(93)
    Msg[0:4] = bytes([TTI_FUN, TTI_ALL8, Seq & 0xFF, 0x40])
    Msg[4:8] = Cursor.to_bytes(4, 'big')
    Msg[16:18] = bytes([0x01, 0x0C])
    Msg[22] = 0x01
    Msg[31:35] = min(LongSize, 0xFFFFFFFF).to_bytes(4, 'little')  # LONG fetch size
    Msg[44] = 0x01
    Msg[49:53] = Count.to_bytes(4, 'little')  # rows to fetch
    Msg[73] = 0x01
    return bytes(Msg)


def decode_8i_cursor_id(Terminal: bytes) -> int:
    # The server-assigned cursor id, needed to drive the 8i fetch loop. It sits
    # at offset 11 of the response's post-row terminal — whether that terminal
    # opens with the 0x08 session-state piggyback (08 04 00 11 89 05 00 00 00 00
    # 00 <cid>) or goes straight to the 0x04 OER (04 01 00 00 00 00 00 00 00 00
    # 00 <cid>); the cursor id is a ub2 at [10:12] in both. Returns 0 when the
    # terminal is too short (an empty result set), which suppresses the fetch.
    if len(Terminal) < 12:
        return 0
    return int.from_bytes(Terminal[10:12], 'big')


def _decode_8i_rowid(DataType: int, Val: bytes) -> str | None:
    # Render an 8i ROWID / UROWID column value (#385). A physical ROWID (type 11)
    # is a fixed-width little-endian struct — data object (ub4), relative file
    # (ub2), an unused byte, block (ub4), slot (ub2) — rendered as the extended
    # base64 form (matches ROWIDTOCHAR). A UROWID (type 208, e.g. an
    # index-organized table's logical rowid) renders as the "*"-prefixed base64
    # form (urowid_to_string), the same as the 10g+ path.
    from seerdb.common.types import rowid_to_string, urowid_to_string

    if not Val:
        return None
    if DataType == 208:
        return urowid_to_string(Val)
    Obj = int.from_bytes(Val[0:4], 'little')
    File = int.from_bytes(Val[4:6], 'little')
    Block = int.from_bytes(Val[7:11], 'little')
    Slot = int.from_bytes(Val[11:13], 'little')
    return rowid_to_string(Obj, File, Block, Slot)


def decode_8i_exec_response(
    Data: bytes, Columns: list, PrevRow: list | None = None
) -> tuple[list, bytes, list | None]:
    # Decode an 8i execute/fetch row stream: repeated TTI_RXH (06) + TTI_RXD (07)
    # pairs, one row per RXD, terminated by the 0x08 piggyback / 0x04 OER
    # (docs/PROTOCOL.md §19.10). Unlike the 9i fv2 rows (decode_fv2_exec_response,
    # a 1-byte indicator), each 8i column value is a DALC followed by a FIXED
    # 4-byte trailer — an sb2 indicator + ub2 return code, both zero when the
    # value is present. A NULL column carries no value DALC at all: it is the
    # 4-byte `ff ff 00 00` (indicator -1) on its own. Values are WE8ISO8859P1
    # (latin-1); decode_value uses the column charset.
    #
    # 8i compresses duplicate columns: the RXH carries a column bit vector
    # (`ub1 length` then the vector, at offset 14) whose UNSET bits mark columns
    # that REPEAT the previous row and so carry no bytes in the following RXD
    # (LSB = column 0; an empty vector means every column is present). Since 8i
    # fetches one batch per round trip, a row can repeat a column from the last
    # row of the PREVIOUS batch, so the caller threads `PrevRow` in and the last
    # decoded row back out. Returns (rows, terminal, last_row) where `terminal`
    # is the bytes from the first post-row token (for the cursor id / EOF check).
    from seerdb.common.lob import LOB
    from seerdb.common.types import decode_value, reset_decode_8i, set_decode_8i

    # All 8i char data is WE8ISO8859P1 (latin-1); flag the decode so
    # decode_value picks Latin-1 rather than the UTF-8 / UTF-16 a modern session
    # would use (#366). Reset afterwards so the flag never leaks to other tiers.
    _FlagToken = set_decode_8i(True)
    Rows: list = []
    Rest = Data
    Last = PrevRow
    BitVec = b''
    try:
        while Rest:
            Token = Rest[0]
            if Token == TTI_RXH:
                # The bit vector is `ub1 len` + `len` bytes at offset 14; the RXD
                # (0x07) follows after a short trailer (skip up to it). An empty
                # vector (len 0) means all columns are present.
                VecLen = Rest[14] if len(Rest) > 14 else 0
                BitVec = bytes(Rest[15 : 15 + VecLen])
                Idx = 15 + VecLen
                while Idx < len(Rest) and Rest[Idx] not in (
                    TTI_RXD,
                    TTI_OER,
                    TTI_RPA,
                ):
                    Idx += 1
                Rest = Rest[Idx:]
            elif Token == TTI_RXD:
                Rest = Rest[1:]
                Row: list = []
                for ColIdx, Col in enumerate(Columns):
                    Present = not BitVec or bool(
                        (BitVec[ColIdx >> 3] >> (ColIdx & 7)) & 1
                    )
                    if not Present:
                        # Repeated column: reuse the previous row's value.
                        Row.append(
                            Last[ColIdx] if Last and ColIdx < len(Last) else None
                        )
                    elif Rest and Rest[0] == 0xFF:
                        # NULL column: sb2 indicator 0xFFFF + ub2 return code
                        # 0x0000, with no value DALC.
                        Rest = Rest[4:]
                        Row.append(None)
                    elif Col.get('data_type') in (112, 113, 114):
                        # LOB column (CLOB/BLOB/BFILE). A NULL LOB is ub4-LE
                        # num_bytes == 0 followed *directly* by the 4-byte trailer
                        # (sb2 indicator -1 + ub2 rc), with NO locator. A non-NULL
                        # cell — including an EMPTY_CLOB/EMPTY_BLOB — carries
                        # num_bytes == the locator length, then the DALC locator,
                        # then the trailer; it becomes a LOB the connection
                        # resolves after the fetch (_resolve_8i_lobs), an empty one
                        # reading back as ''/b''. Calling decode_dalc on a NULL
                        # cell (which has no locator) ate the indicator's first
                        # byte and desynced every later row (#387).
                        NumBytes = int.from_bytes(Rest[0:4], 'little')
                        Rest = Rest[4:]
                        if NumBytes == 0:
                            Rest = Rest[4:]  # sb2 indicator (-1) + ub2 rc
                            Row.append(None)
                        else:
                            (Locator, Rest) = decode_dalc(Rest)
                            Rest = Rest[4:]  # sb2 indicator + ub2 rc
                            Row.append(
                                LOB(Col['data_type'], bytes(Locator))
                                if not isinstance(Locator, list)
                                else None
                            )
                    elif Col.get('data_type') == 11:
                        # Physical ROWID (#385): a 1-byte reserved-size indicator
                        # (0 = NULL), then the FIXED 13-byte rowid struct (it is
                        # NOT a length-prefixed DALC), then the 4-byte trailer.
                        Indicator = Rest[0]
                        Rest = Rest[1:]
                        if Indicator == 0:
                            Rest = Rest[4:]  # trailer
                            Row.append(None)
                        else:
                            Struct = bytes(Rest[:13])
                            Rest = Rest[13 + 4 :]  # struct + trailer
                            Row.append(_decode_8i_rowid(11, Struct))
                    elif Col.get('data_type') == 208:
                        # UROWID (#385): a 1-byte indicator (0 = NULL), a reserved
                        # byte, a 1-byte body length, the logical-rowid body, then
                        # the 4-byte trailer.
                        Indicator = Rest[0]
                        if Indicator == 0:
                            Rest = Rest[1 + 4 :]
                            Row.append(None)
                        else:
                            BodyLen = Rest[2]
                            Body = bytes(Rest[3 : 3 + BodyLen])
                            Rest = Rest[3 + BodyLen + 4 :]  # header + body + trailer
                            Row.append(_decode_8i_rowid(208, Body))
                    else:
                        (Val, Rest) = decode_dalc(Rest)
                        Rest = Rest[4:]  # sb2 indicator (0) + ub2 return code (0)
                        Row.append(decode_value(Col, Val))
                Rows.append(Row)
                Last = Row
                BitVec = b''
            else:
                break
    finally:
        reset_decode_8i(_FlagToken)
    return (Rows, Rest, Last)


def _scan_ora_message(Data: bytes) -> tuple[int, str | None]:
    # Locate a server "ORA-NNNNN: ..." error in a response and return
    # (code, message), or (0, None) if there is none. Used for 8i non-query
    # responses, whose binary OER layout differs from 9i's — scanning the
    # human-readable text is layout-independent.
    Idx = Data.find(b'ORA-')
    if Idx < 0:
        return (0, None)
    Digits = Data[Idx + 4 : Idx + 9]
    if not Digits.isdigit():
        return (0, None)
    End = Data.find(b'\x00', Idx)
    Message = (
        Data[Idx : End if End >= 0 else len(Data)].decode('latin-1', 'replace').rstrip()
    )
    return (int(Digits), Message)


def decode_8i_dml_response(Data: bytes) -> tuple[int, int, str | None]:
    # Decode an 8i non-query (DML / DDL / transaction-control) response
    # (docs/PROTOCOL.md §19.12): a 0x08 RPA session-state piggyback (a fixed 23
    # bytes on 8i) then the OER, whose first field after the token is the
    # affected-row count as a LITTLE-endian ub4 (8i is x86 / Windows, so the
    # count rides native-endian — e.g. 300 = `2c 01 00 00`). Returns (rowcount,
    # ora_code, message); a server error is surfaced from the trailing
    # "ORA-NNNNN: ..." text so a failed statement raises instead of reporting a
    # bogus count.
    (ErrCode, Message) = _scan_ora_message(Data)
    Rest = Data[23:] if Data[:1] == bytes([TTI_RPA]) else Data
    RowCount = 0
    if not ErrCode and Rest[:1] == bytes([TTI_OER]):
        RowCount = int.from_bytes(Rest[1:5], 'little')
    return (RowCount, ErrCode, Message)


def decode_8i_dcb_describe(Data: bytes) -> tuple[list[dict], bytes]:
    # Oracle 8i answers the modern OALL8 (0x5e) execute with a TTI_DCB (0x10)
    # describe block whose header and per-column descriptors use FIXED-width
    # big-endian fields — NOT the ub1-length-prefixed ub4s the 10g+ DCB
    # (decode_token_dcb) expects. The modern decoder therefore reads num_columns
    # as 0 and desyncs, so 8i needs this dedicated parser. Reverse-engineered
    # from a live 9.2-client -> 8.1.7 SQL*Net trace (docs/PROTOCOL.md §19.9).
    # Returns (columns, rest) where `rest` begins at the fv2 row stream
    # (TTI_RXH / TTI_RXD / TTI_OER), which decode_fv2_exec_response consumes.
    #
    # Layout (offsets into the TTC payload):
    #   0        TTI_DCB (0x10)
    #   1        ub1 preamble length (0x19 = 25) — SCN + 7-byte date, skipped
    #   2..      preamble bytes
    #   header:  ub1 row width (sum of column widths, skipped)
    #            ub4be num_columns
    #            ub4be constant 0x33 (skipped)
    #   per column (num_columns times):
    #     +0      ub1  data type (1=VARCHAR2, 2=NUMBER, 96=CHAR, …)
    #     +1..+4  ub4be size field. For a NUMBER: `00 <precision> <scale sb1>
    #             <internal size 22>` (#386). For other types: bit31 = character
    #             flag, low 31 bits = max_size.
    #     +5..+18 14 reserved bytes (always 0 in captures)
    #     +19..22 ub4be character set id (31 = WE8ISO8859P1; 0 for NUMBER)
    #     +23     reserved (0)
    #     +24     ub1 csform (1 = character type, 0 = number)
    #     +25     ub1 null_ok (0 = NOT NULL, 1 = nullable)
    #     +26,+27 ub1 name length (twice)
    #     +28..31 ub4be name length
    #     +32..   name bytes (name length)
    #     +…      8-byte inter-column trailer (type-OID slot; 0 for scalar types)
    #   trailer  8i bytes-with-length current date: ub1 len, ub4be len, len bytes
    PreLen = Data[1]
    Off = 2 + PreLen  # skip the SCN/date preamble
    # Header: max row width, then num_columns — both LITTLE-endian ub4 (8i is
    # x86, so these ride native-endian; a wide row like a CLOB's 4000-byte width
    # is `a0 0f 00 00`). Then the constant 0x33 byte.
    Off += 4  # max row width (ub4 LE)
    NumCols = int.from_bytes(Data[Off : Off + 4], 'little')
    Off += 4
    Off += 1  # constant 0x33
    Columns: list[dict] = []
    for _ in range(NumCols):
        DataType = Data[Off]
        SizeField = int.from_bytes(Data[Off + 1 : Off + 5], 'big')
        if DataType == 2:
            # NUMBER family: the 4-byte size field packs `00 <precision>
            # <scale sb1> <internal size (22)>` — NOT a plain max_size (#386).
            # e.g. NUMBER(6,2) = `00 06 02 16`, NUMBER(38) = `00 26 00 16`.
            # Match the modern describe: max_size 0 (a NUMBER's display size is
            # derived from precision/scale), data_length = the 22-byte buffer.
            Precision = (SizeField >> 16) & 0xFF
            Scale = (SizeField >> 8) & 0xFF
            if Scale > 127:
                Scale -= 256  # scale is signed (e.g. NUMBER(5, -2))
            DataLength = SizeField & 0xFF
            MaxSize = 0
        else:
            Precision = 0
            Scale = 0
            MaxSize = SizeField & 0x7FFFFFFF  # bit31 is the character-type flag
            DataLength = MaxSize
        Charset = int.from_bytes(Data[Off + 19 : Off + 23], 'big')
        Csform = Data[Off + 24]
        NullOk = 0 if Data[Off + 25] == 0 else 1
        NameLen = int.from_bytes(Data[Off + 28 : Off + 32], 'big')
        Name = bytes(Data[Off + 32 : Off + 32 + NameLen])
        Columns.append(
            {
                'data_type': DataType,
                'data_length': DataLength,
                'data_scale': Scale,
                'precision': Precision,
                'max_size': MaxSize,
                'charset': Charset,
                'csfrm': Csform,
                'null_ok': NullOk,
                'domain_schema': None,
                'domain_name': None,
                'column_name': Name,
            }
        )
        Off += 32 + NameLen + 8  # descriptor + name + type-OID trailer
    # Describe trailer: the current date as an 8i bytes-with-length value
    # (ub1 len, ub4be len, data) — the same pre-10g coding the OSESSKEY login
    # uses. Skip it to land on the first row token (TTI_RXH / TTI_RXD).
    TLen = int.from_bytes(Data[Off + 1 : Off + 5], 'big')
    Off += 1 + 4 + TLen
    return (Columns, Data[Off:])


def _decode_fv2_oer(Rest: bytes) -> tuple[int, int, bytes]:
    # Minimal fv2 (9i) OER: the short pre-10g form. The exec+fetch terminates
    # with `04 <ub4 rows-this-fetch> <ub4 ORA code> …`; ORA-01403 ("no data
    # found") is the end-of-fetch marker, 0 is success (PROTOCOL.md §19.2). We
    # only need the status + error code; the message DALC trailing the fixed
    # middle is left to from_ora_code() in the caller.
    Rest = Rest[1:]  # OER token
    (RowsThisFetch, Rest) = decode_ub4(Rest)
    (ErrCode, Rest) = decode_ub4(Rest)
    return (RowsThisFetch, ErrCode, Rest)


def decode_fv2_oer_error(Packet: bytes) -> tuple[int, str | None]:
    # If `Packet` is a 9i OER token, return its (ora_code, message); otherwise
    # (0, None). Used to surface a parse/execute-time server error (e.g.
    # ORA-00942) with the server's own text instead of letting the caller march
    # on into a desync (#102). The human-readable "ORA-NNNNN: ..." is the
    # trailing length-prefixed string; the fixed middle fields between the error
    # code and it are version-specific, so locate the message as the final DALC
    # rather than walking every field.
    if not Packet or Packet[0] != TTI_OER:
        return (0, None)
    (_Rows, ErrCode, Rest) = _decode_fv2_oer(Packet)
    Message = None
    for I in range(len(Rest)):
        Length = Rest[I]
        if Length and I + 1 + Length == len(Rest):
            Message = bytes(Rest[I + 1 :]).decode('utf-8', errors='replace').rstrip()
            break
    return (ErrCode, Message)


def decode_fv2_exec_response(Data: bytes, Columns: list) -> tuple[list, int]:
    # Walk the fv2 (9i) execute+fetch response stream: TTI_RXH (06) then one
    # TTI_RXD (07) per row, terminated by the short TTI_OER (04). The 9i row
    # framing differs from 10g+: the RXH has no trailing bit-vector / rowid, and
    # each column value is a DALC blob followed by a 1-byte indicator. Row
    # values themselves use the version-independent §11 decoders. Returns
    # (rows, ora_code) where ora_code 1403 == end-of-fetch (PROTOCOL.md §19.2).
    from seerdb.common.lob import LOB
    from seerdb.common.types import decode_value

    Rows: list = []
    ErrCode = 0
    Rest = Data
    while Rest:
        Token = Rest[0]
        if Token == TTI_RXH:
            # token + 1B flags, then a run of small ub4 counts (numreq, iter,
            # numiters, buffer length, …). The count of trailing fields varies,
            # so consume ub4s until the next token appears. Safe because every
            # RXH field is a small value (width byte 0x00/0x01), never a token
            # byte (RXD 0x07 / OER 0x04 / RXH 0x06).
            Rest = Rest[2:]
            while Rest and Rest[0] not in (TTI_RXD, TTI_OER, TTI_RXH):
                (_, Rest) = decode_ub4(Rest)
        elif Token == TTI_RXD:
            Rest = Rest[1:]
            Row: list = []
            for Col in Columns:
                DataType = Col.get('data_type')
                if DataType in (112, 113, 114):
                    # CLOB / BLOB / BFILE. A present cell is a LOB locator (ub4
                    # num_bytes + DALC locator) followed by a 1-byte 0x00
                    # indicator; _read_lob_column extracts the locator and the
                    # connection round-trips it via TTI_LOBOPS (the fv2 dialect lob_read for
                    # CLOB/BLOB; bfile_read — FILE_OPEN/READ/CLOSE — for
                    # BFILE). A NULL LOB uses the scalar empty-value form instead
                    # — `00 81 01` (an empty DALC then the `81 01` null
                    # indicator). A present locator's num_bytes is always >= its
                    # minimum (first byte 0x01), so a leading 0x00 means NULL.
                    if Rest[:1] == b'\x00':
                        Rest = Rest[1:]  # empty DALC
                        if Rest[:1] == b'\x81':
                            Rest = Rest[2:]  # 81 01 null indicator
                        Row.append(None)
                    else:
                        (Locator, Rest) = _read_lob_column(Rest)
                        Rest = Rest[1:]  # present indicator (0x00)
                        Row.append(
                            LOB(DataType, Locator) if Locator is not None else None
                        )
                    continue
                # The value is a DALC; decode_dalc handles the 0xfe chunked form
                # that LONG / LONG RAW stream in (in batch fetch they arrive
                # inline as a plain chunked value, no trailing descriptor).
                (Val, Rest) = decode_dalc(Rest)
                # Per-column indicator: 0x00 = value present (one byte); 0x81 =
                # NULL, a two-byte (81 01) marker following an empty value.
                if Rest and Rest[0] == 0x81:
                    Rest = Rest[2:]
                    Row.append(None)
                elif DataType in (TNS_TYPE_RID, TNS_TYPE_ROWID, TNS_TYPE_UROWID):
                    # Defined as VARCHAR (see _o7_define_entry), so the value is
                    # already the rowid text — decode it directly, not via the
                    # native ROWID decoder.
                    Rest = Rest[1:]
                    Row.append(bytes(Val).decode('ascii', 'replace') if Val else None)
                else:
                    Rest = Rest[1:]
                    Row.append(decode_value(Col, Val))
            Rows.append(Row)
        elif Token == TTI_OER:
            (_, ErrCode, Rest) = _decode_fv2_oer(Rest)
            break
        else:
            break
    return (Rows, ErrCode)


def decode_fv2_dml_response(Data: bytes) -> tuple[int, int]:
    # 9i DML (INSERT/UPDATE/DELETE) over TTI_ALL7: a single parse-executes the
    # statement; the response is an RPA piggyback followed by the short OER
    # whose first field is the affected-row count and second the ORA code
    # (0 = success). Returns (rowcount, ora_code). #101.
    if not Data:
        return (0, 0)
    Rest = Data
    if Rest[0] == TTI_RPA:
        # Skip the RPA piggyback (same shape as decode_token_rpa_piggyback):
        # read the field count, consume exactly that many ub4s, skip alignment
        # zeros, leaving the stream on the trailing OER token. The count is the
        # only guide: a ub4's length byte can be any value up to 4, and the
        # first parameter is a counter that passes 2**24 as the instance ages,
        # at which point its length byte reads 0x04, the OER token. A loop that
        # stopped at a token-looking byte then took the counter for the status
        # and every successful DDL and DML on 9i raised a garbled negative
        # ORA code (#711).
        Rest = Rest[1:]
        (Num, Rest) = decode_ub4(Rest)
        for _ in range(max(Num, 0)):
            if not Rest:
                break
            (_, Rest) = decode_ub4(Rest)
        while Rest and Rest[0] == 0:
            Rest = Rest[1:]
    if Rest and Rest[0] == TTI_OER:
        (RowCount, ErrCode, _) = _decode_fv2_oer(Rest)
        return (RowCount, ErrCode)
    return (0, 0)


# Token that opens the 9i bind-values prompt the server sends after a PL/SQL
# block parse-execute carrying binds: `0b 05 01 <numbinds> 00 01 01 00` then one
# direction byte per bind (0x20 = IN, 0x10 = OUT, 0x30 = IN OUT). #102.
_FV2_BIND_PROMPT = 0x0B


def strip_fv2_bind_prompt(Data: bytes) -> bytes:
    # Drop a leading bind prompt, if present, returning the bytes that follow
    # (the OUT-value RXD + RPA + OER). A pure-OUT block's reply packs the prompt,
    # the return values and the call status together; an IN / IN OUT block sends
    # the prompt in its own packet (consumed before the values are sent), so this
    # is a no-op there. The prompt is `0b 05 01 <numbinds> 00 01 01 00` then a
    # direction section (bytes 0x00 / 0x10 / 0x20 / 0x30 — IN/OUT/IN OUT masks
    # and padding) whose exact length varies, so rather than computing it we scan
    # past the 8-byte fixed prefix to the first RXD (07) or RPA (08) token — the
    # prompt itself never contains either. (#102, PROTOCOL §19.7)
    if len(Data) >= 8 and Data[0] == _FV2_BIND_PROMPT:
        Pos = 8
        while Pos < len(Data) and Data[Pos] not in (TTI_RXD, TTI_RPA):
            Pos += 1
        return Data[Pos:]
    return Data


def decode_fv2_block_out(Data: bytes, NumOut: int) -> tuple[list, int, int]:
    # Parse a 9i PL/SQL block reply that returns OUT / IN OUT values (#102,
    # PROTOCOL §19.7). After any bind prompt is stripped, the reply is an
    # optional TTI_RXD (07) carrying `NumOut` × (DALC value + 1-byte indicator)
    # in OUT-bind position order, then the RPA + short OER. Returns
    # (out_values, rowcount, ora_code); out_values holds the raw value bytes per
    # OUT bind (None for a NULL OUT), to be decoded by the caller against each
    # Var's declared type.
    Rest = strip_fv2_bind_prompt(Data)
    OutValues: list = []
    if NumOut > 0 and Rest and Rest[0] == TTI_RXD:
        Rest = Rest[1:]
        for _ in range(NumOut):
            (Val, Rest) = decode_dalc(Rest)
            if Rest and Rest[0] == 0x81:  # 81 01 NULL indicator
                Rest = Rest[2:]
                OutValues.append(None)
            else:
                if Rest:
                    Rest = Rest[1:]  # present indicator (00)
                OutValues.append(
                    bytes(Val) if isinstance(Val, (bytes, bytearray)) and Val else None
                )
    (RowCount, ErrCode) = decode_fv2_dml_response(Rest)
    return (OutValues, RowCount, ErrCode)


def encode_dictionary_lobops(Dictionary: dict) -> bytes:
    # TTI_LOBOPS request. See docs/PROTOCOL.md §14 for the field layout.
    # This builds a READ request specifically (operation = 0x0002) since
    # that's all the driver currently issues; other opcodes plug into the
    # same shape by varying `operation` and the pointer flags.
    Tseq = Dictionary['seq']
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    LobHead = _fun_header(TTI_LOBOPS, Tseq, FieldVersion)
    if Dictionary.get('create_temp'):
        # CREATE_TEMP (op 0x0110, #91): allocate a session-duration temporary
        # LOB; the server returns the new locator in the response RPA. The body
        # is fixed (no source locator), captured verbatim from python-oracledb
        # on 21c — it differs between CLOB (type 0x70) and BLOB (type 0x71) in
        # the type-spec bytes, and both forms still end with the trailing sb4
        # 0x0369. 12c+ only; 11g rejects CREATE_TEMP.
        if Dictionary.get('is_blob'):
            Body = (
                bytes.fromhex('01012800010a00000100010201100000000171')
                + bytes(47)
                + bytes.fromhex('020369')
            )
        else:
            Body = (
                bytes.fromhex('01012800010a0000010001020110000001010170')
                + bytes(47)
                + bytes.fromhex('020369')
            )
        return LobHead + Body
    if Dictionary.get('operation') == TNS_LOB_OP_WRITE:
        # WRITE (op 0x0040, #91): push `data` into the LOB at `source_offset`.
        # Reverse-engineered from python-oracledb on 21c (small + 60 KB CLOB
        # writes, byte-for-byte). Differences from the READ shape above:
        #   * operation = 0x0040
        #   * the source-locator-length field counts the ub2 length prefix too
        #     (len + 2), and the locator is sent as <ub2 len><bytes> rather than
        #     raw — READ declares the bare length and sends the locator raw
        #   * the amount pointer is absent (no trailing sb4 amount); the payload
        #     is appended instead as a 0x0E marker + a chunked-bytes field:
        #       <ub1 len><data>                       when len <= 0xFC, else
        #       0xFE (<sb4 chunklen><chunk>)... <00>   (chunks <= 0x7FFF bytes)
        # CLOB data must already be UTF-16BE; BLOB data is raw bytes.
        Locator = Dictionary['locator']
        Data = Dictionary['data']
        SourceOffset = Dictionary.get('source_offset', 1)
        Out = LobHead
        Out += bytes([1])  # source pointer present
        Out += encode_sb4(len(Locator) + 2)  # source locator length (+ub2)
        Out += bytes([0])  # dest pointer absent
        Out += encode_sb4(0)  # dest_length
        Out += encode_sb4(0)  # short source offset
        Out += encode_sb4(0)  # short dest offset
        Out += bytes([0])  # charset pointer absent
        Out += bytes([0])  # short amount absent
        Out += bytes([0])  # null lob pointer absent
        Out += encode_sb4(TNS_LOB_OP_WRITE)  # operation code
        Out += bytes([0])  # scn array pointer absent
        Out += bytes([0])  # scn array length
        Out += encode_sb4(SourceOffset)  # source offset (ub8)
        Out += encode_sb4(0)  # dest offset (ub8)
        Out += bytes([0])  # amount pointer absent
        Out += struct.pack('>HHH', 0, 0, 0)  # three reserved ub16be slots
        Out += struct.pack('>H', len(Locator))  # ub2 locator length prefix
        Out += Locator
        Out += bytes([0x0E])  # WRITE-data marker
        if len(Data) <= 0xFC:
            Out += bytes([len(Data)]) + Data
        else:
            Out += bytes([0xFE])
            for K in range(0, len(Data), 0x7FFF):
                Chunk = Data[K : K + 0x7FFF]
                Out += encode_sb4(len(Chunk)) + Chunk
            Out += encode_sb4(0)  # zero-length terminator
        return Out
    if Dictionary.get('operation') in (TNS_LOB_OP_FILE_OPEN, TNS_LOB_OP_FILE_CLOSE):
        # BFILE open / close (#46). Same field block as READ but with source
        # offset 0 and no read amount. FILE_OPEN sets the amount pointer and
        # sends the open mode (sb4 0x0B = read-only) where READ sends the read
        # amount; FILE_CLOSE sends neither. The locator is ub2-length-prefixed
        # (declared len + 2), like every temp / BFILE LOBOPS. Reverse-engineered
        # from python-oracledb on 21c, byte-for-byte.
        Locator = Dictionary['locator']
        Operation = Dictionary['operation']
        IsOpen = Operation == TNS_LOB_OP_FILE_OPEN
        Out = LobHead
        Out += bytes([1])  # source pointer present
        Out += encode_sb4(len(Locator) + 2)  # source locator length (+ub2)
        Out += bytes([0])  # dest pointer absent
        Out += encode_sb4(0)  # dest_length
        Out += encode_sb4(0)  # short source offset
        Out += encode_sb4(0)  # short dest offset
        Out += bytes([0])  # charset pointer absent
        Out += bytes([0])  # short amount absent
        Out += bytes([0])  # null lob pointer absent
        Out += encode_sb4(Operation)  # operation code
        Out += bytes([0])  # scn array pointer absent
        Out += bytes([0])  # scn array length
        Out += encode_sb4(0)  # source offset (ub8)
        Out += encode_sb4(0)  # dest offset (ub8)
        Out += bytes([1 if IsOpen else 0])  # amount pointer (open mode)
        Out += struct.pack('>HHH', 0, 0, 0)  # three reserved ub16be slots
        Out += struct.pack('>H', len(Locator)) + Locator  # ub2-prefixed
        if IsOpen:
            Out += encode_sb4(0x0B)  # open mode: read-only
        return Out
    Locator = Dictionary['locator']
    # `amount` is in chars for CLOB / NCLOB and in bytes for BLOB / BFILE.
    # Don't pass the obvious-looking 0xFFFFFFFF "all" sentinel — XE 11g
    # quietly stops responding when given it (presumably Oracle tries to
    # allocate / range-check uint32-max and gets unhappy). 0x40000000
    # (= 1 GiB) is well over any real LOB we're likely to see while
    # staying inside signed-int32 territory, and the server returns just
    # the LOB's actual content rather than padding to the requested
    # ceiling.
    Amount = Dictionary.get('amount', 0x40000000)
    Operation = Dictionary.get('operation', TNS_LOB_OP_READ)
    SourceOffset = Dictionary.get('source_offset', 1)  # 1-based: start
    LocatorLen = len(Locator)

    Out = LobHead
    Out += bytes([1])  # source pointer present
    # Persistent-LOB locators read back correctly with the bare length + raw
    # locator. Temporary LOBs (#91) instead need the locator sent as a
    # ub2-length-prefixed field with the declared length counting that prefix
    # (len + 2) — exactly the form python-oracledb uses; without it a temp-LOB
    # read returns empty content. Switching persistent reads to the prefixed
    # form regresses them on 11g + 21c, so the prefix is opt-in per call.
    Prefixed = Dictionary.get('locator_prefixed', False)
    Out += encode_sb4(LocatorLen + 2 if Prefixed else LocatorLen)  # src loc len
    Out += bytes([0])  # dest pointer absent
    Out += encode_sb4(0)  # dest_length
    Out += encode_sb4(0)  # short source offset
    Out += encode_sb4(0)  # short dest offset
    Out += bytes([0])  # charset pointer absent
    Out += bytes([0])  # short amount absent
    Out += bytes([0])  # null lob pointer absent
    Out += encode_sb4(Operation)  # operation code
    Out += bytes([0])  # scn array pointer absent
    Out += bytes([0])  # scn array length
    Out += encode_sb4(SourceOffset)  # source offset (ub8; small fits sb4)
    Out += encode_sb4(0)  # dest offset (ub8)
    Out += bytes([1])  # amount pointer present
    Out += struct.pack('>HHH', 0, 0, 0)  # three reserved ub16be slots
    if Prefixed:
        Out += struct.pack('>H', LocatorLen) + Locator  # ub2-prefixed locator
    else:
        Out += Locator  # raw locator bytes (no DALC)
    Out += encode_sb4(Amount)  # amount to read
    return Out


def encode_dictionary_login(Dictionary: dict) -> bytes:
    # The CONNECT packet, in the protocol-version-319 ("large SDU" / end-of-
    # response era) layout (#155). seerdb previously sent version 313 to stay
    # below the EOR era; 319 is what a 23ai server needs to negotiate the
    # end-of-response framing that pipelining (#132) rides on. The header is
    # backward-compatible: 9i/10g/11g negotiate down (min(their_max, 319)) and
    # keep the legacy DATA framing, while a >=315 server switches to the 4-byte
    # ("large") packet length — see encode_packet/assemble_packet and the accept
    # handler that flips self._large_packets. The connect-data offset is 74 (the
    # legacy 58 plus the 16 trailing bytes: large SDU/TDU + connect flags).
    Sdu = Dictionary['sdu']
    PacketVersion = struct.pack('>H', 319)
    # Lowest compatible version we accept. The server negotiates
    # min(its_max, our PacketVersion); it REFUSES the connect if that is below
    # our floor. Oracle 9i's max protocol version is 312, so the 300 floor lets
    # 9i settle on 312 while newer servers negotiate up to 319 (#90).
    LowestCompatVersion = struct.pack('>H', 300)
    GSO = struct.pack('>H', 0x0401)  # global/service options
    SDU = struct.pack('>H', Sdu)
    TDU = struct.pack('>H', Sdu)
    ProtocolCharacteristics = struct.pack('>H', 0x4F98)
    MaxUnackPackets = bytes([0, 0])  # Max packets before ACK
    Endiannes = struct.pack('>h', 1)  # 1 in hardware byte order
    Data = encode_dictionary_description(Dictionary)
    DataLength = struct.pack('>H', len(Data))  # Connect Data length
    CDO = struct.pack('>H', 74)  # Connect Data offset (legacy 58 + 16 trailing)
    MaxConnDataRecv = bytes(4)  # Max connect data that can be received
    ANO = bytes([1, 1])  # advertise ANO (native encryption) capable (#437)
    Padding = bytes(24)
    # The 319-era trailing block before the connect data: 32-bit SDU and TDU,
    # then connect_flags_1 (0) and connect_flags_2 (1 = OOB check), per capture.
    Trailer = (
        struct.pack('>I', Sdu)
        + struct.pack('>I', Sdu)
        + struct.pack('>I', 0)
        + struct.pack('>I', 1)
    )
    return (
        PacketVersion
        + LowestCompatVersion
        + GSO
        + SDU
        + TDU
        + ProtocolCharacteristics
        + MaxUnackPackets
        + Endiannes
        + DataLength
        + CDO
        + MaxConnDataRecv
        + ANO
        + Padding
        + Trailer
        + Data
    )


def encode_dictionary_pig(Dictionary: dict) -> bytes:
    Request = Dictionary['req']  # single function-code byte (ping works)
    Tseq = Dictionary['seq']
    CursorsLen = encode_sb4(len(Dictionary['cursor']))
    Cursors = reduce(lambda x, y: x + y, [encode_sb4(C) for C in Dictionary['cursor']])
    return bytes([TTI_PFN, Request, Tseq, 1]) + CursorsLen + Cursors


def encode_dictionary_pro(Dictionary: dict) -> bytes:
    # TTI_PRO request: the descending TTC protocol-version vector (6..0) then a
    # NUL-terminated client self-identifier. A real Oracle client puts its
    # platform here (e.g. "x86_64/Linux"); we prefix a driver tag so the value is
    # informative and identifies seerdb, instead of the bare "python" we sent
    # before (#381). ASCII with a safe fallback — the field is a plain byte
    # string, and the server accepts an arbitrary length (verified 9i–23ai).
    Banner = f'seerdb {platform.machine()}/{platform.system()}'.encode(
        'ascii', 'replace'
    )
    return bytes([TTI_PRO, 6, 5, 4, 3, 2, 1, 0]) + Banner + bytes([0])


def encode_fast_auth(Pro: bytes, Dty: bytes, Sess: bytes) -> bytes:
    """Bundle the protocol, datatypes, and OSESSKEY (phase-one) messages into a
    single 23ai FAST_AUTH message (#89). Sending the legacy three messages
    separately is rejected with ORA-03146 once the client advertises a field
    version >= 18, so a fast-auth-capable server (it sets TNS_ACCEPT_FLAG_FAST_AUTH
    in the ACCEPT) gets this one packet instead. Layout reverse-engineered and
    byte-validated against a python-oracledb fv24 capture (docs/PROTOCOL.md §20):

        0x22 ver=1 SERVER_CONVERTS_CHARS flag2=0
        <PRO message>
        charset(ub2)=0  flag(ub1)=0  ncharset(ub2)=0
        ttc_field_version byte = FIELD_VERSION_19_1_EXT1
        <DTY message>            (its caps array still advertises the real fv)
        <OSESSKEY message>
    """
    return (
        bytes([TNS_MSG_TYPE_FAST_AUTH, 1, TNS_SERVER_CONVERTS_CHARS, 0])
        + Pro
        + b'\x00\x00\x00\x00\x00'
        + bytes([FIELD_VERSION_19_1_EXT1])
        + Dty
        + Sess
    )


def find_fast_auth_rpa(Body: bytes) -> int:
    """Return the offset of the auth-challenge TTI_RPA inside a bundled fast-auth
    response (PRO response + DTY response + RPA). The DTY datatype table contains
    0x08 bytes, so a naive token scan mis-hits; instead accept the first TTI_RPA
    whose decode yields the OSESSKEY challenge (a non-empty session key)."""
    for Off in range(len(Body)):
        if Body[Off] != TTI_RPA:
            continue
        try:
            Result = decode_token_rpa(Body[Off + 1 :], ())
        except Exception:
            continue
        if Result[0] == TTI_SESS and Result[1]:
            return Off
    return -1


def encode_dictionary_sess(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    Hostname = encode_kv(b'AUTH_MACHINE', socket.gethostname().encode('utf-8'))
    Pid = encode_kv(b'AUTH_PID', str(os.getpid()).encode('utf-8'))
    User = Dictionary['env']['user'].encode('utf-8')
    SID = encode_kv(b'AUTH_SID', Dictionary['env']['user'].encode('utf-8'))
    UserLen = encode_sb4(len(Dictionary['env']['user']))
    Role = Dictionary['env'].get('role', 0)
    Prelim = Dictionary['env'].get('prelim', 0)
    LogonMode = encode_sb4((Role * 32) | (Prelim * 128) | 1)
    AppName = encode_kv(
        b'AUTH_PROGRAM_NM',
        Dictionary['env'].get('app_name', 'seerdb').encode('utf-8'),
    )

    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    if FieldVersion >= FIELD_VERSION_12_1:
        # 12c+ OSESSKEY (python-oracledb auth.pyx _write_message phase one):
        # the username is length-prefixed (write_bytes_with_length) and the
        # pair count is 5, leading with AUTH_TERMINAL. 11g instead reads the
        # username by the earlier UserLen field and sends 4 pairs; sending the
        # 12c shape to 11g (or vice-versa) desyncs the server's parse.
        Terminal = encode_kv(b'AUTH_TERMINAL', b'unknown')
        UserField = bytes([len(User)]) + User
        return (
            bytes([TTI_FUN, TTI_SESS, Tseq, 1])
            + UserLen
            + LogonMode
            + bytes([1])
            + encode_sb4(5)
            + bytes([1, 1])
            + UserField
            + Terminal
            + AppName
            + Hostname
            + Pid
            + SID
        )

    return (
        bytes([TTI_FUN, TTI_SESS, Tseq, 1])
        + UserLen
        + LogonMode
        + bytes([1])
        + encode_sb4(4)
        + bytes([1, 1])
        + User
        + AppName
        + Hostname
        + Pid
        + SID
    )


# Pre-10g (9i) thin authentication uses O3LOGON: TTI_3LOGA (0x52) to fetch the
# session key, then TTI_3LOGON (0x51) to send the password (#90). The OSESSKEY
# path above (TTI_SESS) is what 10g+ thin clients and OCI use; 9i's field
# version 2 expects this older positional message instead. The two encoders
# below reproduce the Oracle JDBC thin driver's 9i messages byte-for-byte
# (verified — see tests/test_tns_encode.py). The terminal/machine/osuser/program
# strings are session metadata the server does not authenticate on, so we send
# the same values JDBC does; only the username and (phase two) the password vary.
# The session-metadata strings JDBC sends: terminal / machine / osuser / program.
_O3_TERMINAL, _O3_MACHINE, _O3_OSUSER, _O3_PROGRAM = (
    b'unknown',
    b'o9i',
    b'root',
    b'JDBC Thin Client',
)
_O3_ENV = _O3_TERMINAL + _O3_MACHINE + _O3_OSUSER + _O3_PROGRAM


# The header skeleton between the length fields and the string blob (captured from
# JDBC) bakes in those four string lengths, so generate it from them rather than
# from a blob — a `01 01 <len>` attribute for terminal/machine/osuser, `02 <len>`
# for program, then the program length once more, framed by phase-specific
# padding (the two encoders below differ only in that framing).
def _o3_mid(head_pad: int, tail: bytes) -> bytes:
    T, M, U = len(_O3_TERMINAL), len(_O3_MACHINE), len(_O3_OSUSER)
    P = len(_O3_PROGRAM)
    attrs = bytes([1, 1, T, 1, 1, M, 1, 1, U, 2, P, 0, 0, 0, 1, 1, P])
    return bytes(head_pad) + attrs + tail


_O3_MID1 = _o3_mid(6, bytes([0, 0, 0, 0, 1, 1, len(_O3_PROGRAM), 1]))  # TTI_3LOGA
_O3_MID2 = _o3_mid(4, bytes([0, 0, 0, 0, 0, 1, len(_O3_PROGRAM), 0]))  # TTI_3LOGON


def encode_o3logon_phase1(Seq: int, User: bytes) -> bytes:
    # TTI_3LOGA: request the session key. No password field.
    return (
        bytes([TTI_FUN, TTI_3LOGA, Seq, 1])
        + encode_sb4(len(User))
        + _O3_MID1
        + User
        + _O3_ENV
    )


def encode_o3logon_phase2(Seq: int, User: bytes, PwdField: bytes) -> bytes:
    # TTI_3LOGON: send the AUTH_PASSWORD (hex(DES blocks) + decimal pad count).
    return (
        bytes([TTI_FUN, TTI_3LOGON, Seq, 1])
        + encode_sb4(len(User))
        + bytes([1])
        + encode_sb4(len(PwdField))
        + _O3_MID2
        + User
        + PwdField
        + _O3_ENV
    )


# --- Oracle 8i (8.1.7) O3LOGON via the OSESSKEY/OAUTH envelope ---------------
# 8i uses the same DES O3LOGON *crypto* as 9i, but wraps it in the OSESSKEY
# (0x76) / OAUTH (0x73) function envelope with key-value AUTH_ pairs — NOT 9i's
# positional TTI_3LOGA/TTI_3LOGON. Sending 3LOGA to 8i draws a TTI_OER. The
# pre-10g key-value length coding is `ub1(len) ub4be(len) data`, then a ub4be
# padding word — distinct from the modern variable-length encode_sb4 form.
# Byte-for-byte reproduced from a live 9.2-client -> 8.1.7 capture
# (docs/PROTOCOL.md; ~/o8i/captures/cli8i_9.2_to_8i.trc).


def _kv8i(Key: bytes, Val: bytes) -> bytes:
    def field(Data: bytes) -> bytes:
        return (
            bytes([len(Data)]) + struct.pack('>I', len(Data)) + Data
            if Data
            else bytes([0])
        )

    return field(Key) + field(Val) + struct.pack('>I', 0)


def encode_o3logon_osesskey_phase1(
    Seq: int, User: bytes, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # TTI_FUN + OSESSKEY (0x76): request the session key. Carries the username
    # and informational AUTH_ pairs (program/machine/pid — session metadata the
    # server does not authenticate on). The pair count is a ub1 at offset 13.
    return (
        bytes([TTI_FUN, TTI_SESS, Seq, 1])
        + bytes([len(User)])
        + struct.pack('>I', 1)  # logon mode
        + struct.pack('>I', 1)
        + bytes([len(Pairs)])  # number of key-value pairs
        + struct.pack('>I', 1)
        + bytes([1])  # has-username
        + bytes([len(User)])
        + User
        + b''.join(_kv8i(k, v) for k, v in Pairs)
    )


def encode_o3logon_oauth_phase2(
    Seq: int, User: bytes, PwdField: bytes, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # TTI_FUN + OAUTH (0x73): send AUTH_PASSWORD (hex(DES blocks) + decimal pad
    # count) plus the informational pairs. Logon mode 0x105 marks phase two.
    return (
        bytes([TTI_FUN, TTI_AUTH, Seq, 1])
        + bytes([len(User)])
        + struct.pack('>I', 1)
        + bytes([1])
        + struct.pack('>I', 0x105)  # phase-two logon mode
        + struct.pack('>I', 1)
        + bytes([1])  # has-username
        + bytes([len(User)])
        + User
        + _kv8i(b'AUTH_PASSWORD', PwdField)
        + b''.join(_kv8i(k, v) for k, v in Pairs)
    )


def parse_8i_auth_sesskey(Packet: bytes) -> bytes:
    """Extract the 8-byte session key from an 8i OSESSKEY response RPA.

    The AUTH_SESSKEY value is a length-prefixed ASCII-hex string in the pre-10g
    key-value coding (``ub1 len``, ``ub4be len``, then the hex)."""
    from binascii import unhexlify

    from seerdb.common.exceptions import InterfaceError

    Idx = Packet.find(b'AUTH_SESSKEY')
    if Idx < 0:
        raise InterfaceError('8i OSESSKEY response carried no AUTH_SESSKEY')
    After = Packet[Idx + len(b'AUTH_SESSKEY') :]
    ValLen = After[0]  # ub1 length; the ub4be repeat follows in After[1:5]
    return unhexlify(After[5 : 5 + ValLen])


def encode_dictionary_spfp(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    return bytes([TTI_FUN, TTI_SPFP, Tseq, 1, 1, 100, 1, 1, 0, 0, 0, 0, 0])


def encode_dictionary_start(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    Request = encode_sb4(Dictionary['req'])
    return bytes([TTI_FUN, TTI_STRT, Tseq]) + Request + bytes([1])


def encode_dictionary_stop(Dictionary: dict) -> bytes:
    Tseq = Dictionary['seq']
    Request = encode_sb4(Dictionary['req'])
    return bytes([TTI_FUN, TTI_STOP, Tseq]) + Request + bytes([1])


def encode_dictionary_tran(Dictionary: dict) -> bytes:
    Request = Dictionary['req']
    Tseq = Dictionary['seq']
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    return _fun_header(Request, Tseq, FieldVersion)


##
## Decoders/Encoders for base types
##


def set_opts(
    Type: str, Flag: int, Id: int, Len: int, Param: int
) -> tuple[int, int, int, list[int]]:
    P0 = 32768
    P1 = (Id * 8) | (Param * 256)
    P2 = 0
    P3 = 2147483647  # 2^^31-1

    if Type == 'fetch':
        P1 = (Id * 16) | 64
        All8 = set_opts_all8(Flag, Param, 1)
    elif (Type == 'select') and (Flag == 0):
        P1 = (Id * 8) | 64
        All8 = set_opts_all8(Flag, Param, 1)
    elif (Type == 'select') and (Flag == 1):
        P1 = Id * 8
        P2 = 4294967295  # 2**32-1
        All8 = set_opts_all8(Flag, 0, 1)
    elif Type == 'change':
        All8 = set_opts_all8(Flag, 1 + Len, 0)
    elif Type == 'return':
        P0 = 1024
        All8 = set_opts_all8(Flag, 1, 0)
    elif Type == 'block':
        P0 = 1024
        P3 = 32760  # (2**15-1)^(2**3-1)
        All8 = set_opts_all8(Flag, 1, 0)
    else:
        raise Exception("Can't set opts", (Type, Flag, Id, Len, Param))

    # Opt = (Flag ^ 32 ^ P0) | P1  (^ binds tighter than |); verified across
    # SELECT / DML / PL/SQL-block / array-DML execs.
    return (Flag ^ 32 ^ P0 | P1, P2, P3, All8)


def set_opts_all8(Opts: int, Fetch: int, Type: int) -> list[int]:
    return [Opts, Fetch, 0, 0, 0, 0, 0, Type, 0, 0, 0, 0, 0]


def decode_ub4(Bytes: bytes) -> tuple[int, bytes]:
    # Variable-length integer (PROTOCOL.md §12.1): a length byte, then that many
    # big-endian magnitude bytes. The low 7 bits of the length byte are the
    # magnitude width (0..4 for a real ub4 / sb4); the high bit flags a negative
    # value (sign-magnitude, not two's complement). So -1 arrives as 0x81 0x01,
    # NUMBER scale -127 as 0x81 0x7f, and -256 as 0x82 0x01 0x00.
    Length = Bytes[0]
    Negative = bool(Length & 0x80)
    Width = Length & 0x7F
    if Width <= 4:
        Magnitude = int.from_bytes(Bytes[1 : Width + 1], 'big')
        Value = -Magnitude if Negative else Magnitude
        return (Value, Bytes[Width + 1 :])
    # Width 5..0x7f is not a valid 1..4-byte integer. In practice the only field
    # that reaches here is a raw ub2 / counter that decode_token_oer reads through
    # this function (its leading byte is frequently 5..255); the historic
    # behaviour is to consume exactly two bytes and return the negated second
    # byte. The value is always discarded there and the 2-byte consume keeps the
    # OER stream aligned for ordinary multi-row fetches. Keep it: a prior strict
    # version that raised here crashed plain
    # "SELECT level FROM dual CONNECT BY level <= 50" (#24).
    return (-Bytes[1], Bytes[2:])


def encode_sb4(Val: int) -> bytes:
    Bytes = struct.Struct('>I').pack(Val)
    match Val:
        case 0:
            return bytes([0])
        case v if v <= 0xFF:
            return bytes([1, Bytes[3]])
        case v if v <= 0xFFFF:
            return bytes([2, Bytes[2], Bytes[3]])
        case v if v <= 0xFFFFFF:
            return bytes([3, Bytes[1], Bytes[2], Bytes[3]])
        case v if v <= 0xFFFFFFFF:
            return bytes([4, Bytes[0], Bytes[1], Bytes[2], Bytes[3]])
    # Out of ub4 range (or negative); raise here rather than via `case _` so
    # every branch is a value-return for flow analysis.
    raise Exception("Can't encode value", Val)


# The end-of-fetch OER (ORA-01403 "no data found"): the OER return-status token
# terminating a fetch that returned all of its rows — the client reads the 1403
# status as "cursor drained" rather than an error. Built by _encode_oer (defined
# here, after encode_sb4, so the eager call resolves), not stored: dissecting the
# live 11g capture shows every byte is an ordinary OER field. call_status 1,
# rowcount 1 and cursor_id 1 carry meaning; seq 4, error_pos 14, sql_type 3 and
# call_number 7 are the specific values that terminator carried in the capture
# (their meaning for a no-data status is murky, so they are carried in their named
# OER slots, not invented). Consumed only by _terminator (a function), so its
# placement here is fine.
_END_OF_FETCH = _encode_oer(
    1,
    1403,
    1,
    b'ORA-01403: no data found\n',
    cursor_id=1,
    seq=4,
    error_pos=14,
    sql_type=3,
    call_number=7,
)


def _end_of_fetch() -> bytes:
    # The 11g terminator is the pinned constant; a 12.1+ client reads extra OER
    # fields, so re-encode it under the session's field version.
    if _ENCODE_FIELD_VERSION.get() < FIELD_VERSION_12_1:
        return _END_OF_FETCH
    return _encode_oer(
        1,
        1403,
        1,
        b'ORA-01403: no data found\n',
        cursor_id=1,
        seq=4,
        error_pos=14,
        sql_type=3,
        call_number=7,
    )


def _o7_lobop_mid(
    operation: int, *, source_offset: int = 0, has_reply: int = 1
) -> bytes:
    """The fv2 (9i) TTI_LOBOPS request middle (§19.5) — the flag block between the
    locator length and the locator, sb4-encoded (go-ora's LOB request layout):
    has-dest, dest length, source/dest offsets, charset-present, a reply flag
    (`1` except for FILE_CLOSE), null-o2u, the ``TNS_LOB_OP_*`` operation, has-scn,
    scn length. Only the operation, the read source offset and the reply flag
    vary. The 8i form is the same block with fixed-width fields (_o8i_lobop_mid)."""
    return (
        bytes([0])  # has_dest
        + encode_sb4(0)  # dest length
        + encode_sb4(source_offset)
        + encode_sb4(0)  # dest offset
        + bytes([0, has_reply, 0])  # charset-present, reply flag, null-o2u
        + encode_sb4(operation)
        + bytes([0])  # has_scn
        + encode_sb4(0)  # scn length
        + bytes([0])
    )


_LOBOP_GETLEN_MID = _o7_lobop_mid(TNS_LOB_OP_GET_LENGTH)
_LOBOP_READ_MID = _o7_lobop_mid(TNS_LOB_OP_READ, source_offset=1)
_LOBOP_FOPEN_MID = _o7_lobop_mid(TNS_LOB_OP_FILE_OPEN)
_LOBOP_FCLOSE_MID = _o7_lobop_mid(TNS_LOB_OP_FILE_CLOSE, has_reply=0)


# A physical ROWID (RID, type 11) reserves this many bytes on the wire — the
# present indicator the client reads to tell a real rowid (any non-zero,
# non-0xff value) from a NULL. The client only tests for 0 / 0xff, so the exact
# size is cosmetic; 10 is a physical rowid's structured length.
_RID_PRESENT = 0x0A
# The leading type tag of a logical/universal rowid (UROWID, type 208). The
# client strips it before rendering, so any value round-trips; 0x01 is the
# logical-rowid tag.
_UROWID_TAG = 0x01


def encode_rowid_value(Value: object) -> bytes:
    """The physical ROWID (RID, type 11) RXD value (#484), the inverse of
    :func:`_read_rowid_column`: a present-indicator byte then the structured rowid
    — data object / relative file / an unused field / block / slot, each a ub4.
    ``Value`` is the 18-char extended ROWID string; ``None`` (or empty) is a bare
    ``0x00`` indicator (NULL)."""
    from seerdb.common.types import string_to_rowid

    if Value is None or Value == '':
        return bytes([0])
    Obj, File, Block, Slot = string_to_rowid(str(Value))
    return (
        bytes([_RID_PRESENT])
        + encode_sb4(Obj)
        + encode_sb4(File)
        + encode_sb4(0)  # unused field between file and block
        + encode_sb4(Block)
        + encode_sb4(Slot)
    )


def encode_urowid_value(Value: object) -> bytes:
    """The UROWID (logical/universal rowid, type 208) RXD value (#484), the
    inverse of :func:`_read_urowid_column`: a ub4 byte count, a 1-byte length
    echo, then the rowid bytes (a leading type tag + the body). ``Value`` is the
    ``*``-prefixed base64 string; ``None`` (or empty) is a zero count (NULL)."""
    if Value is None or Value == '':
        return encode_sb4(0)
    Body = str(Value)[1:]  # drop the leading '*'
    Raw = base64.b64decode(Body + '=' * (-len(Body) % 4))
    Payload = bytes([_UROWID_TAG]) + Raw
    return encode_sb4(len(Payload)) + bytes([len(Payload)]) + Payload


# A thin (seerdb / oracledb-thin) LONG / LONG RAW value streams inline in the RXD
# — no LOB locator — as a value followed by TWO trailing ub4 indicators (actual /
# return lengths, 0 / 0 for an ordinary value), the inverse of :func:`_read_long_column`.
# The value is the 0xFE-chunked form (a run of <ub1 len><bytes> terminated by a
# zero-length chunk) even when it fits one chunk; a NULL is a bare 0x00 marker. The
# sqlplus / OCI dialect frames it with a single ub4 trailer instead. Character LONG
# content is UTF-8, LONG RAW is raw bytes. Chunks stay ≤ 253 bytes (the single-byte
# DALC boundary used throughout this codec).
_THIN_LONG_CHUNK = 253
_THIN_LONG_TRAILER = encode_sb4(0) + encode_sb4(0)  # two ub4 indicators (0, 0)


def encode_long_value_thin(Value: object) -> bytes:
    """The thin RXD value for a LONG / LONG RAW column (#484): the content streamed
    inline as 0xFE-chunked bytes (NULL is a bare 0x00), followed by the two zero
    trailing indicators :func:`_read_long_column` consumes."""
    if Value is None:
        return bytes([0]) + _THIN_LONG_TRAILER
    if isinstance(Value, str):
        Content = Value.encode('utf-8')
    elif isinstance(Value, (bytes, bytearray)):
        Content = bytes(Value)
    else:
        Content = str(Value).encode('utf-8')
    # 11g frames each inline LONG chunk with a single length byte; a 12.2+ client
    # reads a ub4 length per chunk (its _read_long_column), so chunk in the
    # session's negotiated version — the same split as the LOB read reply.
    wide = _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_2
    encode_len = encode_sb4 if wide else (lambda n: bytes([n]))
    Out = bytearray([0xFE])
    for Start in range(0, len(Content), _THIN_LONG_CHUNK):
        Chunk = Content[Start : Start + _THIN_LONG_CHUNK]
        Out += encode_len(len(Chunk)) + Chunk
    Out += encode_len(0)  # zero-length chunk terminates the run
    return bytes(Out) + _THIN_LONG_TRAILER


# The RXD value the Mirror mints for a thin LOB column: an opaque locator the
# client echoes back over TTI_LOBOPS, the content following in the read reply.
_THIN_LOB_LOCATOR = b'\x00seerdb-mirror-lob-locator-0000000000\x00'


def encode_lob_locator_thin() -> bytes:
    """The RXD value for a thin LOB column (#413): a minted opaque locator the
    client echoes back over TTI_LOBOPS. The content follows in the read reply."""
    return encode_sb4(len(_THIN_LOB_LOCATOR)) + _bytes_with_length(_THIN_LOB_LOCATOR)


def _encode_temporal(Value: datetime.date, DataType: int) -> bytes:
    # A temporal column has a fixed wire width fixed by its *type*, not by the
    # particular value — so we dispatch on the column's data_type rather than
    # letting encode_token_datetime() pick 7/11/13 bytes from the value. A plain
    # date is promoted to midnight of that day.
    Dt = (
        Value
        if isinstance(Value, datetime.datetime)
        else datetime.datetime(Value.year, Value.month, Value.day)
    )
    if DataType == TNS_TYPE_TIMESTAMPTZ:
        # 13 bytes: DATE prefix + nanoseconds + offset. Assume UTC if the value
        # carries no zone (a naive value in a TZ column).
        Aware = (
            Dt if Dt.tzinfo is not None else Dt.replace(tzinfo=datetime.timezone.utc)
        )
        return encode_token_datetime(Aware)
    if DataType == TNS_TYPE_TIMESTAMP:
        # 11 bytes always: DATE prefix + 4 BE nanosecond bytes (zero when the
        # value has no sub-second part), keeping the column a fixed width.
        Naive = Dt.replace(tzinfo=None)
        return _encode_date_prefix(Naive) + (Naive.microsecond * 1000).to_bytes(
            4, 'big'
        )
    # Oracle DATE: date + time to the second, 7 bytes. Sub-second and zone parts
    # are dropped (that is what DATE, as distinct from TIMESTAMP, means).
    return _encode_date_prefix(Dt.replace(microsecond=0, tzinfo=None))


def encode_value(Value: object, DataType: int) -> bytes:
    """A scalar column value as its RXD wire form — the inverse of
    :func:`~seerdb.common.types.decode_value`.

    Most types are a DALC (1-byte length + data): NULL is the empty DALC, text is
    UTF-8, a number is Oracle's base-100 NUMBER encoding, a datetime/date per the
    column's temporal type. ROWID / UROWID / LONG carry their own framing (a NULL
    still carries it, so they skip the bare-0x00 NULL path), and a LOB rides as a
    minted locator with its content following over TTI_LOBOPS."""
    from seerdb.common.exceptions import InterfaceError

    if DataType == TNS_TYPE_RID:
        return encode_rowid_value(Value)
    if DataType == TNS_TYPE_UROWID:
        return encode_urowid_value(Value)
    if DataType in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW):
        return encode_long_value_thin(Value)
    if Value is None:
        return bytes([0])
    if DataType == TNS_TYPE_REF:
        # An object REF (#119/#494) rides as a plain DALC of its opaque locator
        # bytes; the type identity travels in the describe, not the value.
        return _bytes_with_length(getattr(Value, 'bytes', b''))
    if DataType == TNS_TYPE_INTERVALDS and isinstance(Value, datetime.timedelta):
        return _bytes_with_length(encode_token_interval_ds(Value))
    if DataType == TNS_TYPE_INTERVALYM and isinstance(Value, IntervalYM):
        return _bytes_with_length(encode_token_interval_ym(Value))
    if DataType in (TNS_TYPE_CLOB, TNS_TYPE_BLOB, TNS_TYPE_JSON, TNS_TYPE_VECTOR):
        # A thin CLOB / BLOB / JSON / VECTOR value is delivered as an opaque
        # locator; the content follows over TTI_LOBOPS (#413). JSON content is the
        # OSON image, VECTOR the binary image (see oci_lob_contents).
        return encode_lob_locator_thin()
    if DataType == TNS_TYPE_BOOLEAN:
        # Native SQL BOOLEAN (23ai): a one-byte value, 0x01 for TRUE and 0x00 for
        # FALSE, which the client reads by its last byte (Data[-1] != 0). This must
        # come before the bool branch below — a bool encoded as a NUMBER would make
        # FALSE (NUMBER 0 -> 0x80) read back as TRUE.
        return _bytes_with_length(bytes([1 if Value else 0]))
    if isinstance(Value, bool):
        # No 11g BOOLEAN type; a bool is a NUMBER 0/1 (bool is an int subclass, so
        # match it before the int branch would silently swallow it).
        return _bytes_with_length(encode_token_num(int(Value)))
    if isinstance(Value, (int, float)):
        # A BINARY_FLOAT / BINARY_DOUBLE column carries the IEEE-754 value in
        # Oracle's order-preserving form, not base-100 NUMBER.
        if DataType == TNS_TYPE_BDOUBLE:
            return _bytes_with_length(encode_token_binary_double(float(Value)))
        if DataType == TNS_TYPE_BFLOAT:
            return _bytes_with_length(encode_token_binary_float(float(Value)))
        return _bytes_with_length(encode_token_num(Value))
    if isinstance(Value, Decimal):
        # NUMBER via the exact base-100 Decimal encoder: high-precision values
        # (beyond float's ~15 significant digits) round-trip unchanged.
        return _bytes_with_length(encode_token_decimal(Value))
    if isinstance(Value, datetime.date):
        # datetime is a date subclass, so this covers both; the column's data_type
        # decides DATE / TIMESTAMP / TIMESTAMPTZ width.
        return _bytes_with_length(_encode_temporal(Value, DataType))
    if isinstance(Value, (str, bytes)):
        # A VARCHAR2 / RAW column value: length-prefixed data, chunked when it
        # exceeds the single-byte length, honouring the negotiated field version.
        return encode_chr(Value)
    raise InterfaceError(f'unsupported column value type: {type(Value).__name__}')


def decode_dalc(Bytes: bytes) -> tuple[bytes | list, bytes]:
    # Data with Attached Length Code (PROTOCOL.md §12.2). 0x00 = empty,
    # 0xFF = null marker (no data follows), 0xFE = chunked, otherwise the
    # length byte is followed by that many data bytes. Both empty and null
    # are reported as [] here; callers that need the distinction look at the
    # enclosing bytes_with_length count.
    try:
        if Bytes[0] == 0 or Bytes[0] == 255:
            return ([], Bytes[1:])
        if Bytes[0] == 254:
            return decode_chr(Bytes)
        Length = Bytes[0]
        return (Bytes[1 : Length + 1], Bytes[Length + 1 :])
    except IndexError as Exc:
        # A truncated field (empty Bytes, or a chunk length in decode_chr that
        # runs past the buffer) indexes out of range; surface as DataError
        # rather than leaking a raw IndexError (#230).
        raise DataError('truncated DALC field') from Exc


def decode_chr(Bytes: bytes) -> tuple[bytes, bytes]:
    if Bytes[0] == 254:
        # LONG (chunked) value. 12c+ prefixes each chunk with a ub4 length and
        # ends with a zero-length chunk (same framing as _skip_chunked_bytes);
        # 11g uses a single length byte per chunk. The decode field version is
        # set by decode_packet for the current response.
        if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_2:
            Rest = Bytes[1:]
            Out = b''
            while True:
                (ChunkLen, Rest) = decode_ub4(Rest)
                if ChunkLen == 0:
                    return (Out, Rest)
                Out += Rest[:ChunkLen]
                Rest = Rest[ChunkLen:]
        j = 1
        i = Bytes[j]
        Out = b''
        while True:
            Out += Bytes[j + 1 : i + j + 1]
            if Bytes[i + j + 1] == 0:
                break
            j = i + j + 1
            i = Bytes[j]
        return (Out, Bytes[i + j + 1 + 1 :])
    else:
        return (Bytes[1 : Bytes[0] + 1], Bytes[Bytes[0] + 1 :])


def encode_chr(String: str | bytes) -> bytes:
    Bytes = String.encode('utf-8') if isinstance(String, str) else String
    if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_2:
        # 12c+ bind data follows write_bytes_with_length: a single length byte
        # for values up to 252 bytes, otherwise the 254 marker + ub4-prefixed
        # chunks.
        # 11g instead chunks anything over 64 bytes with single-byte lengths;
        # sending that to a 12c server desyncs it (ORA-03120 integer overflow).
        return _bytes_with_length(Bytes)
    Length = len(Bytes)
    if Length > 64:
        Out = b''
        i = 0
        while i < Length - 64:
            Out += bytes([64]) + Bytes[i : i + 64]
            i += 64
        return bytes([254]) + Out + bytes([Length - i]) + Bytes[i:] + bytes([0])

    return bytes([Length]) + Bytes


def decode_kv(
    Data: bytes, Num: int, Acc: list, Flags: dict | None = None
) -> tuple[list, bytes]:
    # Flags (optional) collects each pair's trailing number (its "flag") keyed by
    # key name — needed for AUTH_VFR_DATA, whose flag names the verifier type
    # (#311). Left None by default so existing callers are unchanged.
    if Num <= 0 or not Data:
        return (sorted(Acc), Data)

    def decode_to_bin(D):
        if D[0] == 0:
            return (bytes([0]), D[1:])
        else:
            (Size, R) = decode_ub4(D)
            if R[0] == Size:
                return (R[1 : 1 + Size], R[1 + Size :])
            elif R[0] == 254:
                return decode_chr(R)
            else:
                return decode_chr(R)

    (Key, R0) = decode_to_bin(Data)
    (Val, R1) = decode_to_bin(R0)
    if Flags is not None and R1:
        (Flag, _) = decode_ub4(R1)  # the per-pair number precedes the next pair
        Flags[Key] = Flag
    if Val == bytes([0]):
        Val = None
    NewAcc = Acc + [(Key, Val)]
    if not R1:
        return (sorted(NewAcc), R1)
    Skip = R1[0] + 1
    return decode_kv(R1[Skip:], Num - 1, NewAcc, Flags)


def encode_kv(Key: bytes, Val: bytes, Padding: int = 0) -> bytes:
    def encode_to_bin(Data):
        Size = len(Data)
        if Size == 0:
            return bytes([0])
        # ub4 total length + the value in write_bytes_with_length form: a 1-byte
        # length for short values, or the 254 chunked marker for values >= 254
        # (e.g. an RSA token signature, #125) — the single-byte length prefix the
        # old code used could not carry a value longer than 255 bytes.
        return encode_sb4(Size) + _bytes_with_length(Data)

    return encode_to_bin(Key) + encode_to_bin(Val) + encode_sb4(Padding)


def encode_tokens_rxd(Tokens: list, Binary: bytes) -> bytes:
    Out = bytes([TTI_RXD])
    for Token in Tokens:
        Out += encode_token_rxd(Token)
    return Binary + Out


def encode_tokens_oac(Tokens: list, Binary: bytes) -> bytes:
    # OAC descriptors are emitted bare here (no leading TTI_OAC token byte) —
    # that's what the server expects inside the ALL8 bind section.
    Out = b''
    for Token in Tokens:
        Out += encode_token_oac(Token)
    return Binary + Out


def exec_oac_signature(Bind: list, Batch: list) -> bytes:
    # The exact OAC bytes a fresh parse would send for these binds. Used as
    # part of the DML cursor-cache key: a cached cursor re-execute skips
    # re-sending the OAC, so the server keeps the bind buffer sizes (and types)
    # from the original parse. Reusing it for binds whose OAC differs — most
    # commonly a longer string than the first call sized for — overflows that
    # frozen buffer and the server rejects the value as a streamed LONG
    # (ORA-01461). Keying the cache on this signature turns such a call into a
    # cache miss, forcing a re-parse with a correctly-sized OAC.
    if not Bind:
        return b''
    if Batch:
        return encode_tokens_oac(_oac_rep_row([Bind] + Batch), b'')
    return encode_tokens_oac(Bind, b'')


# The declared types whose wire width differs from the one the value's own Python
# type would pick. A `Var` announces its declared type in the OAC, so the row data
# has to match it or the server measures the payload against the descriptor and
# rejects the pair (#701).
_DECLARED_TEMPORAL = (
    TNS_TYPE_DATE,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_TIMESTAMPLTZ,
)


def _declared_value_bytes(Value: object, DataType: int) -> bytes | None:
    """A bind's value encoded as the type its `Var` declared, or None.

    None means the declaration cannot disagree with the value: the Python type
    has one encoding whatever was declared, so the ordinary bind encoder --
    which knows about temp LOBs, objects, REFs, JSON and vectors -- keeps the
    value.

    Where they *can* disagree, the declaration wins, which is what the
    descriptor already promised the server and what python-oracledb does: a
    microsecond datetime declared DATE is truncated to the 7-byte form rather
    than widening the payload to an 11-byte TIMESTAMP the descriptor did not
    announce.
    """
    if Value is None:
        return None
    if isinstance(Value, datetime.date) and DataType in _DECLARED_TEMPORAL:
        return _bytes_with_length(_encode_temporal(Value, DataType))
    if isinstance(Value, (int, float)) and not isinstance(Value, bool):
        if DataType == TNS_TYPE_BDOUBLE:
            return _bytes_with_length(encode_token_binary_double(float(Value)))
        if DataType == TNS_TYPE_BFLOAT:
            return _bytes_with_length(encode_token_binary_float(float(Value)))
    return None


def encode_token_rxd(Token: object) -> bytes:
    if isinstance(Token, Var):
        # OUT / IN OUT bind: send the current value (NULL for an unseeded pure
        # OUT). The server writes the result back in the IOV response.
        if Token.is_array:
            # Associative-array bind (#122): a ub4 element count then each
            # element value, in order. Empty (count 0) for a pure-OUT array.
            Elements = cast(list, Token._value or [])
            Out = encode_sb4(len(Elements))
            for Element in Elements:
                Out += encode_token_rxd(Element)
            return Out
        if Token.dbtype.tns_type == TNS_TYPE_REFCURSOR:
            return bytes([1, 0])  # REF CURSOR slot placeholder
        if Token._value is None:
            return bytes([0])
        if getattr(Token.dbtype, 'csfrm', 1) == 2 and isinstance(Token._value, str):
            # National-charset bind (NVARCHAR2 / NCHAR, #174): the value rides as
            # AL16UTF16 (UTF-16 big-endian), independent of the DB charset.
            # encode_chr length-frames the raw bytes (it only re-encodes str).
            return encode_chr(Token._value.encode('utf-16-be'))
        Declared = _declared_value_bytes(Token._value, Token.dbtype.tns_type)
        if Declared is not None:
            return Declared
        return encode_token_rxd(Token._value)
    if isinstance(Token, TempLob):
        # Temp-LOB locator bind (#91): the LOB-descriptor prefix (shared with the
        # native VECTOR / JSON binds), a ub2 locator length, then the locator
        # bytes. Verified against python-oracledb on 21c.
        return (
            _TEMP_LOB_BIND_PREFIX
            + struct.pack('>H', len(Token.locator))
            + Token.locator
        )
    if Token is None:
        return bytes([0])
    from seerdb.common.dbobject import DbObject, DbRef

    if isinstance(Token, DbObject):
        # SQL OBJECT (ADT) bind (#116): the write_dbobject framing + image.
        return _encode_object_bind_value(Token)
    if isinstance(Token, DbRef):
        # REF bind (#139): the opaque locator, length-prefixed.
        return _encode_ref_bind_value(Token)
    if isinstance(Token, (dict, JSON)):
        # JSON bind: native OSON image (#70) when encodable, else the text cast
        # (#50). The OAC path in encode_token_oac makes the same choice.
        Image = _json_oson_image(Token)
        if Image is not None:
            return _native_lob_bind_value(Image)
        Token = _json_bind_text(Token)
    elif is_vector_bind(Token):
        # Native VECTOR bind on 23ai (#62): the OAC counterpart is
        # _VECTOR_BIND_OAC.
        return _native_lob_bind_value(encode_vector(Token))
    if isinstance(Token, bool):
        # Native SQL BOOLEAN bind on 23ai (#54): the value is a 2-byte DALC
        # `02 01 <0/1>` (TRUE = 01 01, FALSE = 01 00; captured from
        # python-oracledb). Pre-23ai servers have no BOOLEAN type, so fall back
        # to the historical NUMBER 0/1 binding there (bool is an int subclass).
        if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_23_1:
            return bytes([2, 1, 1 if Token else 0])
        Bytes = encode_token_num(int(Token))
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, int):
        Bytes = encode_token_num(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, Decimal):
        Bytes = encode_token_decimal(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, BinaryFloat):
        Bytes = encode_token_binary_float(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, BinaryDouble):
        Bytes = encode_token_binary_double(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, float):
        # NUMBER can't represent inf / nan; route the non-finite values to a
        # native BINARY_DOUBLE so they round-trip instead of blowing up the
        # base-100 encoder. Finite floats keep the historical NUMBER binding.
        if not math.isfinite(Token):
            Bytes = encode_token_binary_double(Token)
            return bytes([len(Bytes)]) + Bytes
        Bytes = encode_token_num(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, complex):
        Bytes = encode_token_num(cast(float, Token))
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, datetime.timedelta):
        Bytes = encode_token_interval_ds(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, IntervalYM):
        Bytes = encode_token_interval_ym(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, str):
        return encode_chr(Token)
    if isinstance(Token, (bytes, bytearray)):
        # RAW binds: hand the bytes through verbatim. The old code path
        # round-tripped them through utf-8 → utf-16be which corrupted
        # anything that wasn't ASCII (and outright failed on 0x80+ bytes).
        return encode_chr(bytes(Token))
    if isinstance(Token, RefCursorBind):
        return bytes([1, 0])
    if isinstance(Token, date):
        # Legacy seerdb.common.date.date with has_timestamp / timestamptz flags;
        # keep it on its own path so callers who built one explicitly still
        # get the bytes they expected.
        Bytes = encode_token_date(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, datetime.datetime):
        Bytes = encode_token_datetime(Token)
        return bytes([len(Bytes)]) + Bytes
    if isinstance(Token, datetime.date):
        Bytes = encode_token_datetime(
            datetime.datetime(Token.year, Token.month, Token.day)
        )
        return bytes([len(Bytes)]) + Bytes
    raise Exception('Unknown RXD token', Token)


# The cont-flag (a ub8 in the 12c OAC) that marks a large-value bind — set by the
# persistent/temporary LOB, native JSON and native VECTOR OACs alike.
_OAC_CONT_FLAG_LOB = 0x02000000


def _encode_native_lob_oac(DataType: int, Size: int) -> bytes:
    """The fixed 12c bind OAC that python-oracledb sends for a native large-value
    type — JSON (#70) and VECTOR (#62), both binary (charset/csfrm 0). Every
    field is known (§18.1): the datatype, the max size, the LOB cont-flag, and
    the same size again as the LOB-prefetch length. python-oracledb emits the two
    size fields as a **non-minimal** 4-byte ub4 (a leading zero is kept, e.g.
    VECTOR's 1 MiB is ``04 00 10 00 00``), so they are encoded fixed-width here to
    stay byte-identical to the capture rather than through the minimising
    :func:`encode_sb4`."""
    FixedSize = bytes([4]) + struct.pack('>I', Size)  # non-minimal 4-byte ub4
    return (
        bytes([DataType, 1, 0, 0])
        + FixedSize  # max data length
        + encode_sb4(0)  # max number of array elements
        + encode_sb4(_OAC_CONT_FLAG_LOB)  # cont flag (ub8)
        + encode_sb4(0)  # OID
        + encode_sb4(0)  # version
        + encode_sb4(0)  # charset id (ub2) — binary
        + bytes([0])  # character set form
        + FixedSize  # LOB prefetch length (= max size)
        + encode_sb4(0)  # oaccolid (12.2+)
    )


# Native JSON bind OAC (#70): type 119, 32 MiB max. Native VECTOR bind OAC (#62):
# type 127, 1 MiB max. Both were captured verbatim from python-oracledb (21c /
# 23ai); the capture is now reproduced field-by-field.
_JSON_BIND_OAC = _encode_native_lob_oac(TNS_TYPE_JSON, 0x02000000)  # 32 MiB
_VECTOR_BIND_OAC = _encode_native_lob_oac(TNS_TYPE_VECTOR, 0x00100000)  # 1 MiB


def encode_token_oac(Token: object) -> bytes:
    # The OAC field tells the server the maximum size we *might* send for
    # this bind. Oracle rejects with ORA-01461 ("can bind a LONG value only
    # for insert into a LONG column") if the actual value exceeds it, even
    # when the target is a CLOB / BLOB that could comfortably hold more.
    # 32767 = PL/SQL VARCHAR2 / RAW max, the largest the regular bind path
    # accepts on 11g; larger payloads need TTI_LOBOPS WRITE.
    if isinstance(Token, Var):
        # OAC is driven by the Var's declared type + size, NOT its (maybe NULL)
        # value, so a pure-OUT bind still announces the right type and a buffer
        # large enough for the server to return into.
        DT = Token.dbtype.tns_type
        # Associative-array bind (#122): the OAC declares the array capacity in
        # the max-num-elements field and sets the ARRAY flag (handled by A).
        A = Token.num_elements if Token.is_array else 0
        # National (csfrm 2) char Vars declare AL16UTF16 so encode_token_raw
        # sets csfrm 2 and the value rides as UTF-16BE (#174); ordinary char
        # Vars keep AL32UTF8.
        CharCs = (
            AL16UTF16_CHARSET
            if getattr(Token.dbtype, 'csfrm', 1) == 2
            else AL32UTF8_CHARSET
        )
        if DT == TNS_TYPE_NUMBER:
            return encode_token_raw(TNS_TYPE_NUMBER, 22, 0, 0, 0, A)
        if DT == TNS_TYPE_VARCHAR:
            return encode_token_raw(TNS_TYPE_VARCHAR, Token.size, 16, CharCs, 0, A)
        if DT == TNS_TYPE_CHAR:
            return encode_token_raw(TNS_TYPE_CHAR, Token.size, 16, CharCs, 0, A)
        if DT == TNS_TYPE_RAW:
            return encode_token_raw(TNS_TYPE_RAW, Token.size, 16, 0, 0, A)
        if DT == TNS_TYPE_DATE:
            return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0, A)
        if DT == TNS_TYPE_TIMESTAMP:
            return encode_token_raw(TNS_TYPE_TIMESTAMP, 11, 0, 0, 0, A)
        if DT == TNS_TYPE_TIMESTAMPTZ:
            return encode_token_raw(TNS_TYPE_TIMESTAMPTZ, 13, 0, 0, 0, A)
        if DT == TNS_TYPE_BFLOAT:
            return encode_token_raw(TNS_TYPE_BFLOAT, 4, 0, 0, 0, A)
        if DT == TNS_TYPE_BDOUBLE:
            return encode_token_raw(TNS_TYPE_BDOUBLE, 8, 0, 0, 0, A)
        if DT == TNS_TYPE_INTERVALDS:
            return encode_token_raw(TNS_TYPE_INTERVALDS, 11, 0, 0, 0, A)
        if DT == TNS_TYPE_INTERVALYM:
            return encode_token_raw(TNS_TYPE_INTERVALYM, 5, 0, 0, 0, A)
        if DT == TNS_TYPE_REFCURSOR:
            return encode_token_raw(TNS_TYPE_REFCURSOR, 1, 0, UTF8_CHARSET, 0)
        raise Exception('Unsupported Var OAC type', DT)
    if isinstance(Token, TempLob):
        # Temp-LOB locator bind (#91): a CLOB / BLOB OAC carrying the LOB
        # cont-flag 0x02000000 (the same flag the native VECTOR / JSON OACs
        # set). The announced length is the source value's byte budget. Built
        # explicitly because encode_token_raw zeroes the cont-flag.
        DT = TNS_TYPE_BLOB if Token.is_blob else TNS_TYPE_CLOB
        Charset = 0 if Token.is_blob else AL32UTF8_CHARSET
        Csfrm = 0 if Token.is_blob else 1
        return (
            bytes([DT, 1, 0, 0])
            + encode_sb4(Token.oac_size)
            + encode_sb4(0)  # max number of array elements
            + encode_sb4(0x02000000)  # cont flag (ub8) — LOB
            + encode_sb4(0)  # OID
            + encode_sb4(0)  # version
            + encode_sb4(Charset)  # charset id (ub2)
            + bytes([Csfrm])  # character set form
            + encode_sb4(0)  # LOB prefetch length
            + encode_sb4(0)
        )  # oaccolid (12.2+)
    if Token is None:
        # NULL value (0 bytes): a minimal VARCHAR OAC, again avoiding the
        # 32767 LONG-reorder swap when a NULL bind precedes another bind.
        return encode_token_raw(TNS_TYPE_VARCHAR, 1, 16, AL32UTF8_CHARSET, 0)
    from seerdb.common.dbobject import DbObject, DbRef

    if isinstance(Token, DbObject):
        # SQL OBJECT (ADT) bind OAC (#116): type 109 + the type's OID + version.
        return _encode_object_oac(Token)
    if isinstance(Token, DbRef):
        # REF bind OAC (#139): type 111 + the referenced type's OID.
        return _encode_ref_oac(Token)
    if isinstance(Token, (dict, JSON)):
        # JSON bind: a native JSON OAC (#70) when the value is OSON-encodable,
        # else the VARCHAR OAC for the text cast (#50). Must match the choice in
        # encode_token_rxd.
        if _json_oson_image(Token) is not None:
            return _JSON_BIND_OAC
        Token = _json_bind_text(Token)
    elif is_vector_bind(Token):
        # Native VECTOR bind on 23ai (#62): the fixed OAC python-oracledb sends
        # (built above). The image rides in encode_token_rxd.
        return _VECTOR_BIND_OAC
    if isinstance(Token, BinaryFloat):
        return encode_token_raw(TNS_TYPE_BFLOAT, 4, 0, 0, 0)
    if isinstance(Token, BinaryDouble):
        return encode_token_raw(TNS_TYPE_BDOUBLE, 8, 0, 0, 0)
    if isinstance(Token, float) and not math.isfinite(Token):
        # Non-finite floats (inf / nan) bind as native BINARY_DOUBLE — NUMBER
        # can't represent them (see encode_token_rxd).
        return encode_token_raw(TNS_TYPE_BDOUBLE, 8, 0, 0, 0)
    if isinstance(Token, bool):
        # Native BOOLEAN OAC on 23ai (#54): type 252, fixed size 4 (matches
        # python-oracledb's `fc 01 00 00 01 04 …`). Pre-23ai falls back to the
        # NUMBER OAC, pairing with the NUMBER value in encode_token_rxd.
        if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_23_1:
            return encode_token_raw(TNS_TYPE_BOOLEAN, 4, 0, 0, 0)
        return encode_token_raw(TNS_TYPE_NUMBER, 22, 0, 0, 0)
    if isinstance(Token, (int, float, complex, Decimal)):
        return encode_token_raw(TNS_TYPE_NUMBER, 22, 0, 0, 0)
    if isinstance(Token, datetime.timedelta):
        return encode_token_raw(TNS_TYPE_INTERVALDS, 11, 0, 0, 0)
    if isinstance(Token, IntervalYM):
        return encode_token_raw(TNS_TYPE_INTERVALYM, 5, 0, 0, 0)
    if isinstance(Token, str):
        # Size the OAC to the actual value, not a flat 32767: a VARCHAR bind
        # declared larger than the 4000-byte VARCHAR2 limit is treated by the
        # server as a streamed LONG and reordered after the following bind,
        # which silently swaps a string bind with the next one. A value over
        # 4000 bytes still gets the larger size (and the LONG handling) it
        # needs for the ~7 KiB regular-path CLOB case.
        return encode_token_raw(
            TNS_TYPE_VARCHAR,
            max(len(Token.encode('utf-8')), 1),
            16,
            AL32UTF8_CHARSET,
            0,
        )
    if isinstance(Token, (bytes, bytearray)):
        # Bind as RAW so arbitrary byte sequences (non-UTF8, control bytes,
        # 0x80+) round-trip verbatim into RAW / BLOB columns. Size to the
        # actual value (see the str case) to avoid the LONG-reorder swap.
        return encode_token_raw(TNS_TYPE_RAW, max(len(Token), 1), 16, 0, 0)
    if isinstance(Token, RefCursorBind):
        return encode_token_raw(TNS_TYPE_REFCURSOR, 1, 0, UTF8_CHARSET, 0)
    if isinstance(Token, date):
        if Token.has_timestamp and Token.timestamptz:
            return encode_token_raw(TNS_TYPE_TIMESTAMPTZ, 13, 0, 0, 0)
        if Token.has_timestamp:
            return encode_token_raw(TNS_TYPE_TIMESTAMP, 11, 0, 0, 0)
        return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0)
    if isinstance(Token, datetime.datetime):
        if Token.tzinfo is not None:
            return encode_token_raw(TNS_TYPE_TIMESTAMPTZ, 13, 0, 0, 0)
        if Token.microsecond > 0:
            return encode_token_raw(TNS_TYPE_TIMESTAMP, 11, 0, 0, 0)
        return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0)
    if isinstance(Token, datetime.date):
        return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0)
    raise Exception('Unknown OAC token', Token)


def encode_token_decimal(Value: Decimal) -> bytes:
    # Exact base-100 Oracle NUMBER encoding for a Decimal — no float detour, so a
    # value with more than ~15 significant digits round-trips unchanged (up to
    # Oracle's ~38-digit / 20 base-100 group limit). Zero and integral values
    # keep the fast paths; a non-finite Decimal (NaN / Inf) has no NUMBER form.
    if not Value.is_finite():
        raise DataError(f'cannot encode a non-finite NUMBER: {Value}')
    if Value == 0:
        return bytes([128])
    if Value == Value.to_integral_value():
        IntVal = int(Value)
        # The legacy integer encoder (lnxmin) caps at 20 base-100 groups, i.e.
        # |value| < 10**40. A larger integral NUMBER (valid up to ~1e125 as long
        # as it has <= 38 significant digits) falls through to the exact base-100
        # encoder below, which folds trailing-zero groups into the exponent.
        if -(10**40) < IntVal < 10**40:
            return encode_token_num(IntVal)

    Sign, Digits, Exp10 = Value.as_tuple()
    # is_finite() above rules out the 'n'/'N'/'F' exponent forms as_tuple() uses
    # for NaN / Infinity, so Exp10 is a plain int here.
    assert isinstance(Exp10, int)
    DigitStr = ''.join(map(str, Digits))
    # Decimal power of the most-significant digit, and the base-100 exponent of
    # the leading group (each group spans decimal powers 10**2N .. 10**(2N+1)).
    MsdPower = Exp10 + len(Digits) - 1
    Exponent = MsdPower // 2
    # The leading group's high decimal digit sits at power 2*Exponent+1; pad one
    # leading zero when the MSD is instead the low digit of its group.
    LeadPad = (2 * Exponent + 1) - MsdPower  # 0 or 1
    Aligned = '0' * LeadPad + DigitStr
    if len(Aligned) % 2:
        Aligned += '0'
    Pairs = [int(Aligned[I : I + 2]) for I in range(0, len(Aligned), 2)]

    # Oracle NUMBER holds at most 20 base-100 groups; round half-up on the 21st.
    MaxGroups = 20
    if len(Pairs) > MaxGroups:
        RoundUp = Pairs[MaxGroups] >= 50
        Pairs = Pairs[:MaxGroups]
        if RoundUp:
            I = MaxGroups - 1
            while I >= 0:
                Pairs[I] += 1
                if Pairs[I] < 100:
                    break
                Pairs[I] = 0
                I -= 1
            else:
                # Carried past the most-significant group (999… → 100…).
                Pairs = [1] + Pairs[: MaxGroups - 1]
                Exponent += 1
    # Trailing all-zero groups carry no value.
    while len(Pairs) > 1 and Pairs[-1] == 0:
        Pairs.pop()

    if Sign == 0:
        return bytes([Exponent + 193] + [P + 1 for P in Pairs])
    return bytes([(Exponent + 193) ^ 0xFF] + [101 - P for P in Pairs] + [102])


# --- SQL OBJECT (ADT) bind encode (#116) — the inverse of _read_object_column
# and the #115 image walk. Mirrors python-oracledb's write_dbobject /
# _get_packed_data / _pack_value / create_new_object.

_OBJ_IMAGE_FLAGS = 0x84  # IS_VERSION_81 (0x80) | NO_PREFIX_SEG (0x04)
_OBJ_IMAGE_FLAGS_COLLECTION = 0x88  # IS_VERSION_81 (0x80) | IS_COLLECTION (0x08)
_OBJ_IMAGE_VERSION = 1
_OBJ_TOP_LEVEL = 0x01
_OBJ_NULL_ATTR = 255  # TNS_NULL_LENGTH_INDICATOR
_OBJ_LONG_LEN = 254  # TNS_LONG_LENGTH_INDICATOR
_OBJ_MAX_SHORT_LEN = 245  # TNS_OBJ_MAX_SHORT_LENGTH
# toid wrapper for a new object: 00 22 (NON_NULL_OID | HAS_EXTENT_OID) + oid +
# the fixed extent OID (python-oracledb create_new_object).
_OBJ_TOID_PREFIX = bytes([0x00, 0x22, 0x02, 0x08])
_OBJ_EXTENT_OID = bytes.fromhex('00000000000000000000000000010001')


def _obj_write_length(Length: int) -> bytes:
    # python-oracledb DbObjectPickleBuffer.write_length.
    if Length <= _OBJ_MAX_SHORT_LEN:
        return bytes([Length])
    return bytes([_OBJ_LONG_LEN]) + struct.pack('>I', Length)


def _obj_two_lengths(Value: bytes) -> bytes:
    # write_bytes_with_two_lengths: a ub4 count, then (for a non-empty value)
    # the length-prefixed bytes. An empty value is just the zero count.
    if not Value:
        return encode_sb4(0)
    return encode_sb4(len(Value)) + _bytes_with_length(Value)


def _encode_object_attr(DataType: int, Charset: int, Value: Any) -> bytes:
    # The raw scalar bytes for one attribute — the same on-wire encoding the
    # column form uses, so the #115 decoders read it back. (No length prefix;
    # the caller adds the image write_length.)
    if DataType in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_LONG):
        if isinstance(Value, (bytes, bytearray)):
            return bytes(Value)
        # AL32UTF8 session -> UTF-8; the CharsetDict lookup was a no-op (it
        # keyed a name->id map by an int, see #236).
        return str(Value).encode('utf-8')
    if DataType == TNS_TYPE_NUMBER:
        if isinstance(Value, Decimal):
            return encode_token_decimal(Value)
        return encode_token_num(Value)
    if DataType in (TNS_TYPE_RAW, TNS_TYPE_LONGRAW):
        return bytes(Value)
    if DataType in (
        TNS_TYPE_DATE,
        TNS_TYPE_TIMESTAMP,
        TNS_TYPE_TIMESTAMPTZ,
        TNS_TYPE_TIMESTAMPLTZ,
    ):
        if isinstance(Value, date):
            return encode_token_date(Value)
        return encode_token_datetime(Value)
    if DataType == TNS_TYPE_BFLOAT:
        return encode_token_binary_float(Value)
    if DataType == TNS_TYPE_BDOUBLE:
        return encode_token_binary_double(Value)
    if DataType == TNS_TYPE_INTERVALDS:
        return encode_token_interval_ds(Value)
    if DataType == TNS_TYPE_INTERVALYM:
        return encode_token_interval_ym(Value)
    if isinstance(Value, (bytes, bytearray)):
        return bytes(Value)
    return str(Value).encode('utf-8')


def _encode_object_attr_field(DataType: int, Charset: int, Value: Any) -> bytes:
    # One image field: a single 0xFF for NULL, else the write_length-prefixed
    # raw scalar bytes.
    if Value is None:
        return bytes([_OBJ_NULL_ATTR])
    Raw = _encode_object_attr(DataType, Charset or AL32UTF8_CHARSET, Value)
    return _obj_write_length(len(Raw)) + Raw


def encode_object_image(Obj: 'DbObject') -> bytes:
    # Pack a DbObject into its image. For an object: header (flags, version,
    # long-form length backpatched) then each attribute length-prefixed in
    # declaration order. For a collection (#117/#118): the header also carries a
    # prefix segment (01 01), then a collection-flags byte, the element count,
    # and each element. A NULL field is a single 0xFF. Mirrors python-oracledb
    # _get_packed_data / write_header / _pack_data / _pack_value.
    Typ = Obj._dbtype
    if Typ is not None and Typ.is_collection:
        Element = Typ.element or {}
        Charset = Element.get('charset') or AL32UTF8_CHARSET
        DataType = Element.get('data_type')
        Body = bytes([0])  # collection flags
        Body += _obj_write_length(len(Obj._elements))
        for Value in Obj._elements:
            Body += _encode_object_attr_field(cast(int, DataType), Charset, Value)
        # Collection header = flags, version, long-form length, prefix seg (01 01).
        Total = 9 + len(Body)
        return (
            bytes([_OBJ_IMAGE_FLAGS_COLLECTION, _OBJ_IMAGE_VERSION, _OBJ_LONG_LEN])
            + struct.pack('>I', Total)
            + bytes([1, 1])
            + Body
        )
    Body = b''
    for Attr in Typ.attrs:
        Body += _encode_object_attr_field(
            Attr.get('data_type'),
            Attr.get('charset') or AL32UTF8_CHARSET,
            Obj._attrs.get(Attr['name']),
        )
    # Header length is written long-form (0xFE + ub4) and covers the whole image
    # (the 7-byte header included), matching python-oracledb write_header.
    Total = 7 + len(Body)
    return (
        bytes([_OBJ_IMAGE_FLAGS, _OBJ_IMAGE_VERSION, _OBJ_LONG_LEN])
        + struct.pack('>I', Total)
        + Body
    )


def _encode_object_bind_value(Obj: 'DbObject') -> bytes:
    # The bind value framing (python-oracledb write_dbobject): the constructed
    # toid, an empty object OID, zero snapshot/version, the image length, the
    # TOP_LEVEL flags, then the image.
    Typ = Obj._dbtype
    Toid = _OBJ_TOID_PREFIX + Typ.oid + _OBJ_EXTENT_OID
    Image = encode_object_image(Obj)
    return (
        _obj_two_lengths(Toid)
        + _obj_two_lengths(b'')  # object OID (empty for new)
        + encode_sb4(0)  # snapshot
        + encode_sb4(0)  # version
        + encode_sb4(len(Image))  # image length
        + encode_sb4(_OBJ_TOP_LEVEL)  # flags
        + _bytes_with_length(Image)
    )  # the image


def _encode_object_oac(Obj: 'DbObject') -> bytes:
    # The bind OAC for an object (type 109): the 12c+ metadata layout injecting
    # the type's 16-byte OID + version (precision/scale 0, no charset). Mirrors
    # python-oracledb _write_column_metadata's object branch. 12c+ only — pre-12c
    # object binds are gated in the cursor (no thin reference for that OAC).
    Typ = Obj._dbtype
    Image = encode_object_image(Obj)
    return (
        bytes([TNS_TYPE_ADT, 1, 0, 0])  # type, flag (USE_INDICATORS), p, s
        + encode_sb4(len(Image))  # buffer size
        + encode_sb4(0)  # max number of array elements
        + encode_sb4(0)  # cont flag (ub8)
        + _obj_two_lengths(Typ.oid)  # type OID (16 bytes)
        + encode_sb4(Typ.version)  # type version
        + encode_sb4(0)  # charset id (ub2)
        + bytes([0])  # character set form
        + encode_sb4(0)  # LOB prefetch length
        + encode_sb4(0)
    )  # oaccolid (12.2+)


# Fixed buffer size the REF bind OAC advertises (matches the Oracle JDBC thin
# reference capture; the locator is self-describing so the exact value is not
# load-bearing).
_REF_OAC_BUFFER_SIZE = 4000


def _encode_ref_oac(Ref: 'DbRef') -> bytes:
    # The bind OAC for a REF (type 111, #139). Same 12c+ ADT-style metadata as
    # _encode_object_oac but with the REF type code and the *referenced* type's
    # 16-byte OID. Byte-for-byte from the Oracle JDBC thin reference (oracledb
    # has no REF type, so JDBC is the only reference). The type OID is carried on
    # the DbRef from its describe (#119); without it we cannot build the OAC.
    if Ref.type_oid is None:
        from seerdb.common.exceptions import NotSupportedError

        raise NotSupportedError(
            'cannot bind a REF without its referenced type OID; the value must '
            'come from a fetched DbRef whose describe carried the type identity'
        )
    return (
        bytes([TNS_TYPE_REF, 3, 0, 0])  # type 111, flag, prec, scale
        + encode_sb4(_REF_OAC_BUFFER_SIZE)  # buffer size
        + encode_sb4(0)  # max number of array elements
        + encode_sb4(0)  # cont flag (ub8)
        + _obj_two_lengths(Ref.type_oid)  # referenced type OID (16 bytes)
        + encode_sb4(1)  # type version
        + encode_sb4(2)  # charset id (ub2) — per capture
        + bytes([0])  # character set form
        + encode_sb4(0)  # LOB prefetch length
        + encode_sb4(0)
    )  # oaccolid (12.2+)


def _encode_ref_bind_value(Ref: 'DbRef') -> bytes:
    # The bind value for a REF (#139): just the opaque locator, length-prefixed —
    # the exact inverse of the read path (decode_dalc). Confirmed against the
    # JDBC reference for both an INSERT and a DEREF bind.
    return _bytes_with_length(Ref.bytes)


# --- Advanced Queuing (#128) ---

# AQ JSON payload descriptor (#150): the fixed prefix before the ub2 image
# length / 22 zero bytes / encode_chr(OSON). RE'd from an oracledb-thin capture.
_AQ_JSON_DESCRIPTOR = bytes.fromhex('012800260004610800000001000000000000')


def _encode_sb4i(Val: int) -> bytes:
    # Signed ub4: non-negative via encode_sb4; negative as 0x80|width then the
    # big-endian magnitude (e.g. expiration -1 -> 81 01). Mirrors write_sb4.
    if Val >= 0:
        return encode_sb4(Val)
    Mag = (-Val).to_bytes(4, 'big').lstrip(b'\x00') or b'\x00'
    return bytes([0x80 | len(Mag)]) + Mag


def _aq_value_with_length(Value) -> bytes:
    # write_value_with_length: None -> ub4 0; else write_bytes_with_two_lengths.
    if Value is None:
        return encode_sb4(0)
    if isinstance(Value, str):
        Value = Value.encode('utf-8')
    return _obj_two_lengths(bytes(Value))


def _aq_kv_pair(Text, Binary, Keyword: int) -> bytes:
    # write_keyword_value_pair: the text value, the binary value, then the ub2
    # keyword (each value length-prefixed; None -> ub4 0).
    return (
        _aq_value_with_length(Text)
        + _aq_value_with_length(Binary)
        + encode_sb4(Keyword)
    )


def _aq_write_msg_props(Props, FieldVersion: int) -> bytes:
    # write_msg_props (aq_base): priority/delay/expiration, correlation,
    # attempts, exception queue, state, enqueue time, txn id, then the four
    # fixed agent/extension keyword-value pairs, user-property/cscn/dscn/flags,
    # and (at fv >= 21.1) a shard id. RE'd from python-oracledb.
    Out = encode_sb4(Props.priority)
    Out += encode_sb4(Props.delay)
    Out += _encode_sb4i(Props.expiration)
    Out += _aq_value_with_length(Props.correlation)
    Out += encode_sb4(0)  # number of attempts
    Out += _aq_value_with_length(Props.exceptionq)
    Out += encode_sb4(Props.state)
    Out += encode_sb4(0)  # enqueue time length
    Out += _aq_value_with_length(Props.enq_txn_id)
    Out += encode_sb4(4)  # number of extensions
    Out += bytes([0x0E])  # unknown extra byte
    Out += _aq_kv_pair(None, None, TNS_AQ_EXT_KEYWORD_AGENT_NAME)
    Out += _aq_kv_pair(None, None, TNS_AQ_EXT_KEYWORD_AGENT_ADDRESS)
    Out += _aq_kv_pair(None, b'\x00', TNS_AQ_EXT_KEYWORD_AGENT_PROTOCOL)
    Out += _aq_kv_pair(None, None, TNS_AQ_EXT_KEYWORD_ORIGINAL_MSGID)
    Out += encode_sb4(0)  # user property
    Out += encode_sb4(0)  # cscn
    Out += encode_sb4(0)  # dscn
    Out += encode_sb4(0)  # flags
    if FieldVersion >= FIELD_VERSION_21_1:
        Out += encode_sb4(0xFFFFFFFF)  # shard id
    return Out


def _aq_write_payload(Queue, Props) -> bytes:
    # The payload bytes: JSON (OSON), a SQL object image, or RAW bytes.
    if Queue.is_json:
        # JSON payload (#150): the OSON image wrapped in the AQ JSON descriptor
        # (fixed 18-byte prefix + ub2 image length + 22 zero bytes + the image
        # framed like RAW via encode_chr). RE'd from an oracledb-thin capture --
        # it's the native-LOB value form (#70) but with a slightly different
        # descriptor than VECTOR_BIND_DESCRIPTOR (no second 0x28 byte).
        from seerdb.common.oson import encode_oson

        Oson = encode_oson(Props.payload)
        # _bytes_with_length (the 12c+ single-byte/0xFE-chunked form) -- NOT
        # encode_chr, whose 11g branch chunks at 64 bytes when the encode field
        # version isn't set in this context and desyncs the server (ORA-03120).
        return (
            _AQ_JSON_DESCRIPTOR
            + len(Oson).to_bytes(2, 'big')
            + b'\x00' * 22
            + _bytes_with_length(Oson)
        )
    if Queue.payload_type is not None:
        return _encode_object_bind_value(Props.payload)
    Payload = Props.payload if Props.payload is not None else b''
    if isinstance(Payload, str):
        Payload = Payload.encode('utf-8')
    return bytes(Payload)


def encode_aq_enq(Seq: int, FieldVersion: int, Queue, Props) -> bytes:
    # AQ enqueue (TNS_FUNC_AQ_ENQ). RE'd from python-oracledb AqEnqMessage.
    QName = Queue.name.encode('utf-8')
    Out = _fun_header(TNS_FUNC_AQ_ENQ, Seq, FieldVersion)
    Out += bytes([1]) + encode_sb4(len(QName))  # queue name ptr + len
    Out += _aq_write_msg_props(Props, FieldVersion)
    if Props.recipients is None:
        Out += bytes([0]) + encode_sb4(0)  # recipients ptr + count
    else:
        Out += bytes([1]) + encode_sb4(3 * len(Props.recipients))
    Out += encode_sb4(Queue.enqoptions.visibility)
    Out += bytes([0]) + encode_sb4(0)  # relative message id ptr+len
    Out += encode_sb4(0)  # sequence deviation
    Out += bytes([1]) + encode_sb4(16)  # payload TOID ptr + len
    Out += encode_sb4(TNS_AQ_MESSAGE_VERSION)  # message version (ub2)
    if Queue.is_json:
        Out += bytes([0, 0]) + encode_sb4(0)  # payload 0, RAW 0, RAW len 0
    elif Queue.payload_type is not None:
        Out += bytes([1, 0]) + encode_sb4(0)  # payload 1, RAW 0, RAW len 0
    else:
        RawLen = len(Props.payload) if Props.payload is not None else 0
        Out += bytes([0, 1]) + encode_sb4(RawLen)  # payload 0, RAW 1, RAW len
    Out += bytes([1]) + encode_sb4(TNS_AQ_MESSAGE_ID_LENGTH)  # return msgid ptr+len
    EnqFlags = (
        TNS_KPD_AQ_BUFMSG
        if Queue.enqoptions.delivery_mode == TNS_AQ_MSG_BUFFERED
        else 0
    )
    Out += encode_sb4(EnqFlags)  # enqueue flags
    Out += bytes([0]) + encode_sb4(0)  # extensions 1 ptr + count
    Out += bytes([0]) + encode_sb4(0)  # extensions 2 ptr + count
    Out += bytes([0]) + encode_sb4(0)  # source sequence num ptr+len
    Out += bytes([0]) + encode_sb4(0)  # max sequence num ptr + len
    Out += bytes([0])  # output ack length
    Out += bytes([0]) + encode_sb4(0)  # correlation ptr + len
    Out += bytes([0]) + encode_sb4(0)  # sender name ptr + len
    Out += bytes([0]) + encode_sb4(0)  # sender address ptr + len
    Out += bytes([0])  # sender charset id ptr
    Out += bytes([0])  # sender ncharset id ptr
    if FieldVersion >= FIELD_VERSION_20_1:
        Out += bytes([1 if Queue.is_json else 0])  # JSON payload ptr
    # data section
    Out += _bytes_with_length(QName)
    Out += Queue.payload_toid  # 16-byte type OID (raw)
    Out += _aq_write_payload(Queue, Props)
    return Out


def encode_aq_deq(Seq: int, FieldVersion: int, Queue) -> bytes:
    # AQ dequeue (TNS_FUNC_AQ_DEQ). RE'd from python-oracledb AqDeqMessage.
    Opts = Queue.deqoptions
    QName = Queue.name.encode('utf-8')
    Out = _fun_header(TNS_FUNC_AQ_DEQ, Seq, FieldVersion)
    Out += bytes([1]) + encode_sb4(len(QName))  # queue name ptr + len
    Out += bytes([1, 1, 1, 1])  # msg props + recipient list ptrs
    Consumer = Opts.consumer_name.encode('utf-8') if Opts.consumer_name else None
    if Consumer is not None:
        Out += bytes([1]) + encode_sb4(len(Consumer))
    else:
        Out += bytes([0]) + encode_sb4(0)
    Out += _encode_sb4i(Opts.mode)
    Out += _encode_sb4i(Opts.navigation)
    Out += _encode_sb4i(Opts.visibility)
    Out += _encode_sb4i(Opts.wait)
    if Opts.msgid:
        Out += bytes([1]) + encode_sb4(TNS_AQ_MESSAGE_ID_LENGTH)
    else:
        Out += bytes([0]) + encode_sb4(0)
    Correlation = Opts.correlation.encode('utf-8') if Opts.correlation else None
    if Correlation is not None:
        Out += bytes([1]) + encode_sb4(len(Correlation))
    else:
        Out += bytes([0]) + encode_sb4(0)
    Out += bytes([1]) + encode_sb4(16)  # payload TOID ptr + len
    Out += encode_sb4(TNS_AQ_MESSAGE_VERSION)  # message version (ub2)
    Out += bytes([1])  # payload ptr
    Out += bytes([1]) + encode_sb4(TNS_AQ_MESSAGE_ID_LENGTH)  # return msgid ptr+len
    DeqFlags = 0
    if Opts.delivery_mode == TNS_AQ_MSG_BUFFERED:
        DeqFlags |= TNS_KPD_AQ_BUFMSG
    elif Opts.delivery_mode == TNS_AQ_MSG_PERSISTENT_OR_BUFFERED:
        DeqFlags |= TNS_KPD_AQ_EITHER
    Out += encode_sb4(DeqFlags)  # dequeue flags
    Condition = Opts.condition.encode('utf-8') if Opts.condition else None
    if Condition is not None:
        Out += bytes([1]) + encode_sb4(len(Condition))
    else:
        Out += bytes([0]) + encode_sb4(0)
    Out += bytes([0]) + encode_sb4(0)  # extensions ptr + count
    if FieldVersion >= FIELD_VERSION_20_1:
        Out += bytes([0])  # JSON payload ptr
    if FieldVersion >= FIELD_VERSION_21_1:
        Out += _encode_sb4i(-1)  # shard id
    # data section
    Out += _bytes_with_length(QName)
    if Consumer is not None:
        Out += _bytes_with_length(Consumer)
    if Opts.msgid:
        Out += bytes(Opts.msgid[:16]).ljust(16, b'\x00')
    if Correlation is not None:
        Out += _bytes_with_length(Correlation)
    Out += Queue.payload_toid  # 16-byte type OID (raw)
    if Condition is not None:
        Out += _bytes_with_length(Condition)
    return Out


def _aq_write_array_enq(Queue, PropsList, FieldVersion: int) -> bytes:
    QName = Queue.name.encode('utf-8')
    Flags = (
        TNS_KPD_AQ_BUFMSG
        if Queue.enqoptions.delivery_mode == TNS_AQ_MSG_BUFFERED
        else 0
    )
    Out = encode_sb4(0)  # relative msgid length
    Out += bytes([TTI_RXH])  # ROW_HEADER marker
    Out += _obj_two_lengths(QName)
    Out += Queue.payload_toid
    Out += encode_sb4(TNS_AQ_MESSAGE_VERSION)
    Out += encode_sb4(Flags)
    for Props in PropsList:
        Out += bytes([TTI_RXD])  # ROW_DATA marker
        Out += encode_sb4(Flags)  # aqi flags
        Out += _aq_write_msg_props(Props, FieldVersion)
        Out += encode_sb4(0)  # num recipients (None)
        Out += encode_sb4(Queue.enqoptions.visibility)
        Out += encode_sb4(0)  # relative message id
        Out += encode_sb4(0)  # sequence deviation
        if Queue.payload_type is None and not Queue.is_json:
            Out += encode_sb4(len(Props.payload))
        Out += _aq_write_payload(Queue, Props)
    Out += bytes([TTI_STA])  # STATUS marker
    return Out


def _aq_write_array_deq(Queue, PropsList, FieldVersion: int) -> bytes:
    Opts = Queue.deqoptions
    QName = Queue.name.encode('utf-8')
    Flags = 0
    if Opts.delivery_mode == TNS_AQ_MSG_BUFFERED:
        Flags |= TNS_KPD_AQ_BUFMSG
    elif Opts.delivery_mode == TNS_AQ_MSG_PERSISTENT_OR_BUFFERED:
        Flags |= TNS_KPD_AQ_EITHER
    Consumer = Opts.consumer_name.encode('utf-8') if Opts.consumer_name else None
    Correlation = Opts.correlation.encode('utf-8') if Opts.correlation else None
    Condition = Opts.condition.encode('utf-8') if Opts.condition else None
    Out = b''
    for Props in PropsList:
        Out += _obj_two_lengths(QName)
        Out += _aq_write_msg_props(Props, FieldVersion)
        Out += encode_sb4(0)  # num recipients
        Out += _aq_value_with_length(Consumer)
        Out += _encode_sb4i(Opts.mode)
        Out += _encode_sb4i(Opts.navigation)
        Out += _encode_sb4i(Opts.visibility)
        Out += _encode_sb4i(Opts.wait)
        Out += _aq_value_with_length(Opts.msgid)
        Out += _aq_value_with_length(Correlation)
        Out += _aq_value_with_length(Condition)
        Out += encode_sb4(0)  # extensions
        Out += encode_sb4(0)  # relative message id
        Out += encode_sb4(0)  # sequence deviation
        Out += _obj_two_lengths(Queue.payload_toid)
        Out += encode_sb4(TNS_AQ_MESSAGE_VERSION)
        Out += encode_sb4(0)  # payload length
        Out += encode_sb4(0)  # raw payload length
        Out += encode_sb4(0)
        Out += encode_sb4(Flags)
        Out += encode_sb4(0)  # extensions length
        Out += encode_sb4(0)  # source sequence length
    return Out


def encode_aq_array(
    Seq: int, FieldVersion: int, Queue, Operation: int, PropsList, NumIters: int
) -> bytes:
    # AQ array enqueue / dequeue (TNS_FUNC_ARRAY_AQ). RE'd from python-oracledb
    # AqArrayMessage. For dequeue PropsList is NumIters placeholder properties.
    Out = _fun_header(TNS_FUNC_ARRAY_AQ, Seq, FieldVersion)
    if Operation == TNS_AQ_ARRAY_ENQ:
        Out += bytes([0]) + encode_sb4(0)  # input params ptr + len
    else:
        Out += bytes([1]) + encode_sb4(NumIters)
    Out += encode_sb4(TNS_AQ_ARRAY_FLAGS_RETURN_MESSAGE_ID)
    if Operation == TNS_AQ_ARRAY_ENQ:
        Out += bytes([1, 0])  # output params ptr + len
    else:
        Out += bytes([1, 1])
    Out += _encode_sb4i(Operation)
    Out += bytes([1 if Operation == TNS_AQ_ARRAY_ENQ else 0])  # num iters ptr
    if FieldVersion >= FIELD_VERSION_21_1:
        Out += encode_sb4(0xFFFF)  # shard id
    if Operation == TNS_AQ_ARRAY_ENQ:
        Out += encode_sb4(NumIters)
        Out += _aq_write_array_enq(Queue, PropsList, FieldVersion)
    else:
        Out += _aq_write_array_deq(Queue, PropsList, FieldVersion)
    return Out


def encode_token_datetime(DT: datetime.datetime) -> bytes:
    # 7-byte DATE prefix is shared by all three temporal formats. TIMESTAMP
    # appends 4 BE bytes of nanoseconds. TIMESTAMP WITH TIME ZONE normalises
    # the wall clock to UTC, appends nanoseconds, then the offset bias bytes.
    if DT.tzinfo is not None:
        Utc = DT.astimezone(datetime.timezone.utc)
        Base = _encode_date_prefix(Utc)
        Nanos = (DT.microsecond * 1000).to_bytes(4, 'big')
        Offset = DT.utcoffset()
        assert Offset is not None
        Total = int(Offset.total_seconds() // 60)
        if Total < 0:
            HH, MM = divmod(-Total, 60)
            HH, MM = -HH, -MM
        else:
            HH, MM = divmod(Total, 60)
        return Base + Nanos + bytes([HH + 20, MM + 60])
    if DT.microsecond > 0:
        return _encode_date_prefix(DT) + (DT.microsecond * 1000).to_bytes(4, 'big')
    return _encode_date_prefix(DT)


def _encode_date_prefix(DT: datetime.datetime) -> bytes:
    return bytes(
        [
            DT.year // 100 + 100,
            DT.year % 100 + 100,
            DT.month,
            DT.day,
            DT.hour + 1,
            DT.minute + 1,
            DT.second + 1,
        ]
    )


def encode_token_date(Token: date) -> bytes:
    # Retained for any caller that still constructs the legacy seerdb.common.date.date
    # subclass. New code should pass a stdlib datetime.datetime instead.
    if Token.has_timestamp and Token.timestamptz:
        T = Token.set_timestamptz(Token.timestamptz)
        return (
            bytes(
                [
                    T.year // 100 + 100,
                    T.year % 100 + 100,
                    T.month,
                    T.day,
                    T.hour + 1,
                    T.minute + 1,
                    T.second + 1,
                ]
            )
            + (Token.microsecond * 1000).to_bytes(4, 'big')
            + bytes([Token.timestamptz // 3600 + 20, 60])
        )
    elif Token.has_timestamp:
        return bytes(
            [
                Token.year // 100 + 100,
                Token.year % 100 + 100,
                Token.month,
                Token.day,
                Token.hour + 1,
                Token.minute + 1,
                Token.second + 1,
            ]
        ) + (Token.microsecond * 1000).to_bytes(4, 'big')
    else:
        return bytes(
            [
                Token.year // 100 + 100,
                Token.year % 100 + 100,
                Token.month,
                Token.day,
                Token.hour + 1,
                Token.minute + 1,
                Token.second + 1,
            ]
        )


def encode_token_num(Token: int | float) -> bytes:
    if Token == 0:
        return bytes([128])
    elif isinstance(Token, int):
        # lnxmin handles at most 20 base-100 groups (|Token| < 10**40). Beyond
        # that, a valid Oracle NUMBER (up to ~1e125 with <= 38 significant
        # digits) needs its exponent to absorb trailing-zero groups, so defer to
        # the exact base-100 encoder rather than raising 'LnxMin cannot handle'.
        if -(10**40) < Token < 10**40:
            return bytes(lnxfmt(lnxmin(abs(Token), 1, []), Token))
        return encode_token_decimal(Decimal(Token))
    elif isinstance(Token, float):
        return bytes(lnxfmt(lnxren(abs(Token), 0), Token))
    else:
        raise Exception('Unhandled number token', Token)


def encode_token_binary_float(Value: float) -> bytes:
    # BINARY_FLOAT is a 32-bit IEEE-754 value stored in Oracle's order-
    # preserving form: for a positive number the sign bit is set, for a
    # negative number every bit is flipped. Decoding reverses this.
    Raw = struct.pack('>f', Value)
    if Raw[0] & 0x80:
        return bytes(B ^ 0xFF for B in Raw)
    return bytes([Raw[0] ^ 0x80]) + Raw[1:]


def encode_token_binary_double(Value: float) -> bytes:
    # BINARY_DOUBLE: same order-preserving transform as BINARY_FLOAT over the
    # 64-bit IEEE-754 representation.
    Raw = struct.pack('>d', Value)
    if Raw[0] & 0x80:
        return bytes(B ^ 0xFF for B in Raw)
    return bytes([Raw[0] ^ 0x80]) + Raw[1:]


def encode_token_interval_ds(TD: datetime.timedelta) -> bytes:
    # INTERVAL DAY TO SECOND: 4-byte days biased by 2**31, then hours / minutes
    # / seconds each biased by 60, then 4-byte nanoseconds biased by 2**31. All
    # fields share the interval's sign, so collapse the timedelta (which keeps
    # days negative but seconds/microseconds positive) to a single signed total
    # before splitting it back out.
    TotalUs = (TD.days * 86400 + TD.seconds) * 1_000_000 + TD.microseconds
    Negative = TotalUs < 0
    TotalUs = abs(TotalUs)
    Days, Rest = divmod(TotalUs, 86_400_000_000)
    Hours, Rest = divmod(Rest, 3_600_000_000)
    Minutes, Rest = divmod(Rest, 60_000_000)
    Seconds, Micros = divmod(Rest, 1_000_000)
    Nanos = Micros * 1000
    if Negative:
        Days, Hours, Minutes, Seconds, Nanos = (
            -Days,
            -Hours,
            -Minutes,
            -Seconds,
            -Nanos,
        )
    return (
        (Days + 2**31).to_bytes(4, 'big')
        + bytes([Hours + 60, Minutes + 60, Seconds + 60])
        + (Nanos + 2**31).to_bytes(4, 'big')
    )


def encode_token_interval_ym(IV: IntervalYM) -> bytes:
    # INTERVAL YEAR TO MONTH: 4-byte years biased by 2**31, then 1-byte months
    # biased by 60. IntervalYM has already normalised the two fields to share a
    # sign with abs(months) < 12.
    return (IV.years + 2**31).to_bytes(4, 'big') + bytes([IV.months + 60])


def encode_token_raw(
    DataType: int, Length: int, Flag: int, Charset: int, Max: int, Array: int = 0
) -> bytes:
    # Array > 0 marks a PL/SQL associative-array bind (#122): the flag gains
    # TNS_BIND_ARRAY (0x40) and the max-number-of-array-elements field carries
    # the array's declared capacity (0 for a scalar bind).
    FormOfUse = 2 if Charset == AL16UTF16_CHARSET else 1
    if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_2:
        # 12c+ bind OAC (oracledb _write_column_metadata): a fixed flag byte
        # (TNS_BIND_USE_INDICATORS = 1), a ub8 cont-flag, OID + version, the
        # bind charset as a ub2 (AL32UTF8 / AL16UTF16, 0 for non-char), the
        # csfrm byte, a LOB-prefetch length, and a trailing oaccolid ub4. The
        # 11g layout below is shorter/differently shaped and a 12c server
        # rejects it with ORA-03115 (unsupported network datatype).
        if Charset == 0:
            BindCharset, Csfrm = 0, 0
        elif Charset == AL16UTF16_CHARSET:
            BindCharset, Csfrm = AL16UTF16_CHARSET, 2
        else:
            BindCharset, Csfrm = AL32UTF8_CHARSET, 1
        FlagByte = 0x41 if Array else 1  # USE_INDICATORS | ARRAY
        return (
            bytes([DataType, FlagByte, 0, 0])
            + encode_sb4(Length)
            + encode_sb4(Array)  # max number of array elements
            + encode_sb4(0)  # cont flag (ub8)
            + encode_sb4(0)  # OID
            + encode_sb4(0)  # version
            + encode_sb4(BindCharset)  # charset id (ub2)
            + bytes([Csfrm])  # character set form
            + encode_sb4(0)  # LOB prefetch length
            + encode_sb4(0)
        )  # oaccolid (12.2+)
    FlagOut = (Flag | 0x40) if Array else Flag
    MaxOut = Array if Array else Max
    return (
        bytes([DataType, 3, 0, 0])
        + encode_sb4(Length)
        + bytes([0])
        + encode_sb4(FlagOut)
        + bytes([0, 0])
        + encode_sb4(Charset)
        + bytes([FormOfUse])
        + encode_sb4(MaxOut)
    )


##
## Some other specific transformation functions
##


def lnxmin(N: int, I: int, Acc: list[int]) -> list[int]:
    if N // 100 == 0:
        return lnxpak(([I - 1] + [N % 100] + Acc)[::-1])
    elif I < 20:
        return lnxmin(N // 100, I + 1, [N % 100] + Acc)
    else:
        raise Exception('LnxMin cannot handle this', N, I, Acc)


def lnxpak(List: list[int]) -> list[int]:
    i = 0
    while List[i] == 0:
        i += 1
    return List[: None if i == 0 else i - 1 : -1]


def lnxpak2(List: list[int], I: int) -> list[int]:
    if List == [100] and I == 8:
        return [100 - 1]
    elif len(List) > 1 and List[0] == 100 and I < 8:
        return lnxpak2([List[1] + 1] + List[2:], I + 1)
    else:
        return List


def lnxren(N: float, I: int) -> list[int]:
    if N < 1.0:
        return lnxren(N * 100.0, I - 1)
    elif N < 10.0:  # 1.0 <= N < 10.0 (the cascade guarantees ≥1.0)
        return lnxpak(([I] + lnxren4(N, 0, 1, []))[::-1])
    elif N < 100.0:  # 10.0 <= N < 100.0
        return lnxpak(([I] + lnxren4(N, 0, 0, []))[::-1])
    else:  # N >= 100.0
        return lnxren(N * 0.01, I + 1)


def lnxren4(N: float, I: int, J: int, Acc: list[int]) -> list[int]:
    if J == 0 and I == 8 and len(Acc) > 1:
        return lnxpak2([(Acc[0] + 5) // 10 * 10] + Acc[1:], 1)[::-1]
    elif J == 1 and I == 8 and len(Acc) > 1:
        return lnxpak2([Acc[0] + (Acc[0] // 50)] + Acc[1:], 1)[::-1]
    else:
        return lnxren4((N - int(N)) * 100.0, I + 1, J, [int(N)] + Acc)


def lnxfmt(List: list[int], Data: int | float) -> list[int]:
    if Data > 0:
        return [List[0] + 192 + 1] + list(map(lambda x: x + 1, List[1:]))
    elif Data < 0:
        return (
            [(List[0] + 192 + 1) ^ 255] + list(map(lambda x: 101 - x, List[1:])) + [102]
        )
    else:
        raise Exception('LnxFmt cannot handle zeroes', List, Data)
