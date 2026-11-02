# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import base64
import datetime
import platform
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import TYPE_CHECKING, Any, NamedTuple, cast

if TYPE_CHECKING:
    from seerdb.common.ano_session import AnoChannel
    from seerdb.common.dbobject import DbObject, DbRef
from functools import reduce

from seerdb.common import oci, wire_schema
from seerdb.common.crypto import (
    PBKDF2_SDER_COUNT,
    PBKDF2_VGEN_COUNT,
    VFR_11G_SHA1,
    encrypt_password,
    o5logon,
    server_proof,
    server_proof_padded,
)
from seerdb.common.datatypes import (
    JSON,
    BcDate,
    BFile,
    BinaryDouble,
    BinaryFloat,
    IntervalYM,
    RefCursorBind,
    TempLob,
    Var,
)
from seerdb.common.date import date
from seerdb.common.exceptions import (
    DataError,
    InterfaceError,
    NotSupportedError,
    Truncated,
)
from seerdb.common.sqltext import (
    bind_placeholders,
    is_plsql,
    returning_bind_positions,
)
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


# The VECTOR / JSON bind descriptor without its final byte: that byte is not part
# of the descriptor at all, it is the high byte of the image-length field which
# follows (#1008). Kept derived from the shared constant so the two cannot drift.
_VECTOR_BIND_DESCRIPTOR_HEAD = VECTOR_BIND_DESCRIPTOR[:-1]


def _native_lob_bind_value(image: bytes) -> bytes:
    # Native inline bind value for a LOB-backed type (VECTOR #62, JSON #70): a
    # fixed descriptor, the image length, 22 zero bytes, then the image framed
    # like RAW (encode_chr).
    #
    # The length is THREE bytes, not two. The descriptor below ends with a
    # constant 0x00 that is really this field's high byte, which is why a length
    # written as a ub2 encoded correctly for every image under 64 KiB and
    # overflowed above it -- a float64 VECTOR of more than ~8,000 dimensions
    # raised OverflowError before it ever reached the wire (#1008). Measured on
    # a live 23ai by binding the same column with a 4-dimension vector and a
    # 30,000-dimension one and aligning the two on the descriptor:
    #
    #   SMALL  ... 01 00 00 00 00 | 00 00 31 | 00 00 ...   image = 49
    #   LARGE  ... 01 00 00 00 00 | 03 a9 91 | 00 00 ...   image = 240,017
    #
    # Three bytes allows 16 MiB, past the 65,533-dimension maximum (a float64
    # vector that size is ~512 KB).
    return (
        _VECTOR_BIND_DESCRIPTOR_HEAD
        + len(image).to_bytes(3, 'big')
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


import contextlib
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
    CCAP_CLIENT_FN,
    CCAP_DBF_VERSION,
    CCAP_DEQUEUE_WITH_SELECTOR,
    CCAP_FEATURE_BACKPORT,
    CCAP_FEATURE_BACKPORT2,
    CCAP_FEATURE_BACKPORT2_END_USER_SEC,
    CCAP_FEATURE_BACKPORT2_TXN_PRIORITY,
    CCAP_FIELD_VERSION,
    CCAP_LOB,
    CCAP_LOB2,
    CCAP_LOGON_TYPES,
    CCAP_OCI1,
    CCAP_OCI2,
    CCAP_OCI3,
    CCAP_RPC_SIG,
    CCAP_RPC_VERSION,
    CCAP_SERVER_DEFINE_CONV,
    CCAP_SESS_SIGNATURE_VERSION,
    CCAP_SQL_VERSION,
    CCAP_TDS_VERSION,
    CCAP_TTC1,
    CCAP_TTC2,
    CCAP_TTC3,
    CCAP_TTC4,
    CCAP_TTC5,
    CCAP_UB2_DTY,
    CCAP_VECTOR_FEATURES,
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_SID,
    FIELD_VERSION_9_2,
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_12_2,
    FIELD_VERSION_12_2_EXT_1,
    FIELD_VERSION_19_1_EXT_1,
    FIELD_VERSION_20_1,
    FIELD_VERSION_21_1,
    FIELD_VERSION_23_1,
    FIELD_VERSION_23_1_EXT_1,
    ISO_LATIN_1_CHARSET,
    ORA_ARRAY_DML_ERRORS,
    ORA_LOB_ALREADY_OPENED,
    ORA_LOB_NOT_OPENED,
    ORA_NO_DATA_FOUND,
    RCAP_COMPAT,
    RCAP_COMPAT_81,
    RCAP_TTC,
    RCAP_TTC_32K,
    RCAP_TTC_ZERO_COPY,
    TNS_AL8I4_ARRAY_DML_ROWCOUNTS,
    TNS_APP_CONTEXT_FLAG_CLEAR,
    TNS_APP_CONTEXT_FLAG_SET,
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
    TNS_BIND_ARRAY,
    TNS_BIND_DIR_INPUT,
    TNS_BIND_USE_INDICATORS,
    TNS_CCAP_END_OF_RESPONSE,
    TNS_DATA,
    TNS_DATA_FLAGS_END_OF_RESPONSE,
    TNS_DATA_FLAGS_MORE,
    TNS_DATA_TYPE_ALTSESS,
    TNS_END_TO_END_ACTION,
    TNS_END_TO_END_CLIENT_IDENTIFIER,
    TNS_END_TO_END_CLIENT_INFO,
    TNS_END_TO_END_DBOP,
    TNS_END_TO_END_MODULE,
    TNS_EOCS_FLAGS_TXN_IN_PROGRESS,
    TNS_ESCAPE_CHAR,
    TNS_EXEC_FLAGS_DML_ROWCOUNTS,
    TNS_EXEC_FLAGS_IMPLICIT_RESULTSET,
    TNS_EXEC_FLAGS_NO_CANCEL_ON_EOF,
    TNS_EXEC_FLAGS_SCROLLABLE,
    TNS_EXEC_OPTION_BATCH_ERRORS,
    TNS_EXEC_OPTION_BIND,
    TNS_EXEC_OPTION_COMMIT_REEXECUTE,
    TNS_EXEC_OPTION_EXECUTE,
    TNS_EXEC_OPTION_FETCH,
    TNS_EXEC_OPTION_PARSE,
    TNS_FUNC_ALTER_SESSION,
    TNS_FUNC_APP_CONTEXT,
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
    TNS_KEYWORD_NUM_TXN_PRIORITY,
    TNS_KPD_AQ_BUFMSG,
    TNS_KPD_AQ_EITHER,
    TNS_LOB_OP_FILE_CLOSE,
    TNS_LOB_OP_FILE_EXISTS,
    TNS_LOB_OP_FILE_ISOPEN,
    TNS_LOB_OP_FILE_OPEN,
    TNS_LOB_OP_GET_LENGTH,
    TNS_LOB_OP_READ,
    TNS_LOB_OP_WRITE,
    TNS_LONG_LENGTH_INDICATOR,
    TNS_MAX_SHORT_LENGTH,
    TNS_MSG_TYPE_FAST_AUTH,
    TNS_NULL_LENGTH_INDICATOR,
    TNS_OER_WARN_COMPILATION_ERROR,
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
    TNS_TYPE_INT,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_JSON,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER,
    TNS_TYPE_OPAQUE,
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
    TTI_ALL7,
    TTI_ALL8,
    TTI_AUTH,
    TTI_BVC,
    TTI_DCB,
    TTI_DNY,
    TTI_DTY,
    TTI_END_OF_RESPONSE,
    TTI_EXEC,
    TTI_FETCH,
    TTI_FOB,
    TTI_FUN,
    TTI_IOV,
    TTI_IRD,
    TTI_KOD,
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
    TTI_VERSION,
    TTI_WRN,
    VERSION_11_2_0_2,
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
    vector_dimensions: int | None = None
    # The describe's vector-metadata flags byte. A VECTOR column that allows ANY
    # number of dimensions says so HERE, not by its count -- the count beside
    # the flag is 0 and means nothing, so a describe that drops the flag tells
    # the client the column holds zero-element vectors (#1013).
    vector_flags: int | None = None
    # The describe's uds-flags bits a client reads to decide how to decode the
    # value: is_json marks a native JSON column, is_oson a BLOB / CLOB holding an
    # OSON image (an `IS JSON FORMAT OSON` column). A client re-types an is_oson
    # column to LONG RAW and runs decode_oson over the bytes, so it must be
    # carried through the describe or the value surfaces as a raw LOB (#826).
    is_json: bool = False
    is_oson: bool = False
    # Set only when a cached cursor is re-executed and this column's type changed
    # to CLOB / BLOB under a describe that had said CHAR / VARCHAR / LONG (or RAW
    # / LONG RAW): the value then rides inline as LONG / LONG RAW instead of as a
    # locator, and this is the charset form its bytes use — the one the describe
    # being REPLACED carried, not this describe's own (#826). None everywhere
    # else, so an ordinary LOB column keeps its locator.
    inline_long_csfrm: int | None = None
    # A 23ai column's SQL domain and annotations (#1082): the domain's schema and
    # name, and the annotation map as (key, value) pairs, a name-only annotation
    # with an empty value. Empty for a column without them.
    domain_schema: bytes = b''
    domain_name: bytes = b''
    annotations: tuple[tuple[bytes, bytes], ...] = ()


# The describe's ub4 uds-flags bits (python-oracledb's TNS_UDS_FLAGS_*).
_UDS_FLAGS_IS_JSON = 0x00000100
_UDS_FLAGS_IS_OSON = 0x00000800


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
    # Per-bind capacity of a PL/SQL associative-array bind, 0 for a scalar
    # (#743). Such a bind's value is a list of elements, and its OUT value has
    # to come back as one.
    bind_arrays: list = field(default_factory=list)
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
    # The execute iteration count from al8i4[1] (1 + array-DML batch length).
    # A RETURNING statement whose binds are all clause-filled sends no RXD row,
    # so bind_rows is empty; this still says how many times it runs (#33).
    iterations: int = 1
    # `cursor.parse()`: PARSE without EXECUTE. The statement is parsed (and, for
    # a query, described) but NOT run, and it carries no bind values (#826).
    parse_only: bool = False
    # The DESCRIBE option, set alongside PARSE for a query -- the reply owes the
    # column metadata; a DML / PL/SQL parse owes only a success status.
    describe_only: bool = False
    # True when this request was synthesised from a plain re-execute (func 4)
    # rather than parsed from an OALL8. The two ask for the same work but are
    # answered differently where a PL/SQL block is concerned: an OALL8 is a full
    # execute message and its reply restates the bind IOV, a func-4 re-execute
    # cannot and its reply carries the row data alone (#1064).
    from_reexecute: bool = False
    # Per-column (tns_type, csfrm) from the define OACs, in column order — what
    # the client's own fetch variables are, sent on the re-execute that applies a
    # define (the DEFINE execute option). Empty on every other execute; a define
    # execute carries no binds, so this and ``bind_types`` never both fill (#826).
    define_types: list = field(default_factory=list)


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
    # A READ names the 1-based position it wants and how much, in the LOB's own
    # units -- characters for a CLOB, bytes for a BLOB (#903). A client reads a
    # large LOB in several passes, so serving the whole thing on the first read
    # leaves the rest unanswered. 0 amount means "whatever is there".
    offset: int = 1
    amount: int = 0


@dataclass(frozen=True)
class NestedCursor:
    """A nested-cursor CELL, once its rows are parked (#826).

    The session parks each row's cursor under an id of its own and leaves this in
    the cell; the row encoder writes the inline describe naming that id.
    """

    columns: list = field(default_factory=list)
    cursor_id: int = 0


@dataclass(frozen=True)
class ScalarOutBind:
    """A scalar PL/SQL OUT bind value + its declared type, for the IOV reply.

    ``csfrm`` is the bind's charset form. An NCHAR / NVARCHAR2 bind (csfrm 2)
    carries its text as UTF-16BE, exactly as a national column does in a row --
    sent as UTF-8 the client reads each pair of bytes as one character and
    'Called' comes back as '\u434d\u6c6c\u6564' (#826)."""

    value: object
    tns_type: int
    csfrm: int = _CSFRM_DB


@dataclass(frozen=True)
class ArrayOutBind:
    """A PL/SQL associative-array OUT bind's value: its elements, in order, with
    the bind's declared element type (#743). The reply carries the element
    count and then each element as a value plus a return code, the form the
    client's decoder reads for a bind it registered with ``arrayvar``. ``csfrm``
    carries the element charset form, as for a scalar."""

    values: list
    tns_type: int
    csfrm: int = _CSFRM_DB


@dataclass(frozen=True)
class RefCursorOutBind:
    """A REF CURSOR OUT bind: the nested result's columns and the cursor id the
    Mirror parked its rows on. The client drains that id with ``TTI_FETCH``."""

    columns: list[ColumnMeta]
    cursor_id: int


@dataclass(frozen=True)
class LobOutBind:
    """A LOB OUT bind in the OCI reply (#2015): the value a block assigned to a
    sqlplus ``CLOB`` / ``BLOB`` variable, and the id the Mirror keeps it under.
    It goes out as a locator naming that id, which sqlplus binds back to read
    the value."""

    value: object
    is_clob: bool
    lob_id: int


@dataclass(frozen=True)
class FetchRequest:
    """A parsed ``TTI_FETCH``: which cursor, and how many rows to return."""

    cursor: int
    fetch: int


@dataclass(frozen=True)
class ReexecuteRequest:
    """A parsed re-execute: run the statement a cursor already holds, again.

    The request names the cursor and carries no SQL -- that is the point of it,
    and why a cursor id has to identify one statement (#840).
    """

    cursor: int
    # The iteration count: the prefetch size for the fetch-carrying form (78),
    # the number of executions -- and of bind rows -- for the plain form (4).
    fetch: int
    options: int
    # One row of fresh values per execution, decoded with the bind types the
    # cursor was first executed with -- the request carries no OACs (#854).
    # Empty when the parser was given no types (a bind-less statement, or the
    # caller only wanted the header).
    bind_rows: list = field(default_factory=list)
    # options_2's commit bit: the client's autocommit, applied on success.
    autocommit: bool = False


# The TTC field version negotiated for the connection whose response we are
# currently decoding. Set by `decode_packet` at the top of each response and
# read by the version-gated token decoders (e.g. the 12c+ DCB column format).
# A ContextVar (not a parameter threaded through every decoder, nor a plain
# global) so concurrent async connections / sync threads each see their own
# value. Default 6 == FIELD_VERSION_11_2 (defined later); decoders only diverge
# from the 11g layout when this is >= a 12c+ field version.
_DECODE_FIELD_VERSION = contextvars.ContextVar('decode_field_version', default=6)
# The field version the server itself advertised, which can be higher than the
# negotiated one above. None means "the same as the negotiated one" (#1145).
_DECODE_SERVER_FIELD_VERSION: contextvars.ContextVar[int | None] = (
    contextvars.ContextVar('decode_server_field_version', default=None)
)

# Same idea for the *encode* side: the field version of the message currently
# being built, set by encode_dictionary_exec and read by encode_token_raw to
# pick the 11g vs 12c+ bind-OAC layout. Separate from the decode var so the two
# phases never interfere. Default 6 == FIELD_VERSION_11_2.
_ENCODE_FIELD_VERSION = contextvars.ContextVar('encode_field_version', default=6)
# The Mirror's side of _DECODE_SERVER_FIELD_VERSION: the version it presents,
# for the fields a server writes by its own release (#1145).
_ENCODE_SERVER_FIELD_VERSION: contextvars.ContextVar[int | None] = (
    contextvars.ContextVar('encode_server_field_version', default=None)
)
# The per-session OER end-to-end sequence number for the THIN reply path (#842).
# A real server advances this diagnostic counter on every reply; the thick/OCI
# path already does so via _OciSequence, while the thin path emitted the frozen
# value each captured status was reverse-engineered with, so every session
# repeated one number. Set per message by the Mirror's session loop, exactly as
# the field version is. No client validates the field -- the reference thin
# client reads it into nothing (`skip_ub2`) and seerdb's does not read it at all
# -- so the start value and step are the Mirror's response-generation policy,
# not a decoded Oracle rule.
_ENCODE_OER_SEQ = contextvars.ContextVar('encode_oer_seq', default=0)

# The sequence number of the OCI call currently being answered — the ub1 in the
# client's `03 <func> <seq>` header, after any piggybacks in front of it have
# been stripped (#884). A live server echoes it in the 136-byte OER's offset-49
# field, which is therefore NOT an echo of the server's own counter above: the
# two coincide only early in a session, before the client's sequence runs ahead
# of the server's. Set per message by the Mirror's OCI session loop. Like the
# counter it sits beside, no client validates it.
_ENCODE_OCI_CALL_SEQ = contextvars.ContextVar('encode_oci_call_seq', default=0)

# True while the session being replied to has an uncommitted transaction (#889).
# Every OER the Mirror builds then sets TXN_IN_PROGRESS in its call_status flag
# word, which is how a client learns it owes a rollback when it releases the
# connection to a pool or closes it. The Mirror reported a clear flag on every
# reply, so python-oracledb concluded there was nothing to roll back, skipped it,
# and the uncommitted DML kept its TM lock until the session finally died --
# blocking the next test's TRUNCATE with ORA-00054 across unrelated features.
# seerdb's own client never noticed: it rolls back unconditionally on close.
_ENCODE_TXN_IN_PROGRESS = contextvars.ContextVar(
    'encode_txn_in_progress', default=False
)

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


# Session state the server reports in a SYNC piggyback's keyword-value pairs,
# keyword -> text value (#1776): the transaction priority, keyword 204. While a
# connection decodes a reply it points this at a dict of its own, and the decoder
# records each pair there; otherwise it is None and the pairs are only walked, so
# one connection never sees another's.
_DECODE_SESSION_KEYWORDS: contextvars.ContextVar[dict[int, str | None] | None] = (
    contextvars.ContextVar('decode_session_keywords', default=None)
)


@contextlib.contextmanager
def recording_session_keywords(Sink: dict[int, str | None]) -> Iterator[None]:
    """Record the keyword-value pairs the replies decoded inside the block report
    into ``Sink``, keyword -> text value (#1776)."""
    Token = _DECODE_SESSION_KEYWORDS.set(Sink)
    try:
        yield
    finally:
        _DECODE_SESSION_KEYWORDS.reset(Token)


def _decode_sync_pairs(Rest: bytes) -> bytes:
    # A SYNC piggyback's body after its opcode, read by the `_SYNC` schema -- the
    # same one encode_sync_piggyback writes: the DTYs, then the keyword-value
    # pairs (a text value and a binary value, either of them empty, then the
    # keyword) and the overall flags. Each pair's text is recorded for the
    # connection, keyword -> text (None when the pair carried none). A pair's
    # value rides as a length-prefixed `value`, which under thin reads the same
    # bytes as decode_dalc for every form the server sends here; the empty and
    # null DALC markers (0x00 / 0xFF / 0xFD) fall under the `when length` guard,
    # which never reads the value when the length is zero. The schema wants the
    # `17 05` opcode the caller stripped, so it is put back.
    (Fields, Rest) = _SYNC_FROM_THIN(
        bytes((TTI_SVR_PIGGYBACK, TNS_SERVER_PIGGYBACK_SYNC)) + Rest
    )
    Sink = _DECODE_SESSION_KEYWORDS.get()
    if Sink is not None:
        for Pair in Fields['pairs']:
            Text = Pair.get('text')
            Sink[Pair['keyword']] = (
                None if Text is None else bytes(Text).decode('utf-8', 'replace')
            )
    return Rest


# DML RETURNING ... INTO (#120): the sorted return-bind positions for the next
# response, each with its TNS type when the bind declared one (#826), so the
# TTI_RXD decoder reads the out-bind return data (per bind: ub4 num_rows + per
# row a value + sb4 truncation length) instead of treating the RXD as query rows.
# Reset every execute.
_DECODE_RETURN_BINDS: contextvars.ContextVar[tuple[tuple[int, int | None], ...]] = (
    contextvars.ContextVar('decode_return_binds', default=())
)


def set_decode_return_binds(Positions, Types=None) -> None:
    """Arm return-bind decoding for the next response (#120). `Positions` is the
    set/list of 0-based OUT-bind positions, or empty/None to disarm.

    `Types` optionally maps a position to that bind's TNS type. It is needed only
    for the types whose returned value is NOT a plain DALC -- a JSON or VECTOR
    bind gets its binary image prefetched into the reply, ahead of a locator, the
    same framing such a column uses in a row (#826). Positions it does not name
    read as a DALC, which is every other type."""
    if not Positions:
        _DECODE_RETURN_BINDS.set(())
        return
    Lookup = dict(Types or {})
    _DECODE_RETURN_BINDS.set(tuple((Pos, Lookup.get(Pos)) for Pos in sorted(Positions)))


def return_bind_types(Bind, Positions) -> dict:
    """The TNS type of each return bind that declares one, by position (#826).

    Only a `Var` carries a declared type, and only the prefetched-image types
    change how the reply is read, so anything else is simply left out."""
    from seerdb.common.datatypes import Var

    if not Bind or not Positions:
        return {}
    return {
        Pos: Bind[Pos].dbtype.tns_type
        for Pos in Positions
        if Pos < len(Bind) and isinstance(Bind[Pos], Var)
    }


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


def ends_response(Packet: bytes) -> bool:
    # Whether the DATA packet at the start of ``Packet`` (header included) carries
    # the END_OF_RESPONSE data flag, which a server that negotiated end-of-response
    # framing sets on the last packet of every reply (#1845). The data flags
    # follow the 8-byte header in both header layouts.
    return bool(int.from_bytes(Packet[8:10], 'big') & TNS_DATA_FLAGS_END_OF_RESPONSE)


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


def decode_packet(
    Data: bytes,
    Acc: tuple,
    FieldVersion: int | None = None,
    ServerFieldVersion: int | None = None,
) -> tuple:
    # FieldVersion is passed only by the top-level caller (the connection's
    # response handler); recursive token decoders omit it and inherit the value
    # via the ContextVar set here. ServerFieldVersion likewise: what the server
    # advertised, for the few fields that follow its release (#1145).
    if FieldVersion is not None:
        _DECODE_FIELD_VERSION.set(FieldVersion)
        _DECODE_SERVER_FIELD_VERSION.set(ServerFieldVersion)
    # RXD (row data) and BVC (its bit vector) are the only tokens that repeat
    # proportional to the row count. Loop over them here instead of recursing per
    # row, so a large fetch batch cannot overflow Python's recursion limit (a
    # batch of a few hundred rows used to raise RecursionError). Every other token
    # appears O(1) times per response and dispatches (and may recurse) below with
    # bounded depth.
    while True:
        if not Data:
            # A reply ends with its terminal token; running out first means it
            # goes on in a packet not read yet (#1845).
            raise Truncated('reply ends before its terminal token')
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
    raise NotSupportedError(f'no decoder for response token {Token}')


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


def _chunk_length(Data: bytes) -> tuple[int, bytes]:
    # One chunk's length in a chunked (0xFE) value: a ub4 from 12.1, a single
    # byte before -- the rule _read_long_column and the UROWID reader follow.
    # Read as a ub4 on 10g / 11g, an object image past 252 bytes lost its
    # chunk boundaries: a 300-character attribute came back one character
    # long, and three LOB locators desynced the row (#1261).
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1:
        return decode_ub4(Data)
    return (Data[0], Data[1:])


def _skip_chunked_bytes(Data: bytes) -> bytes:
    # Mirrors oracledb's skip_bytes: 1-byte length, then either that many raw
    # bytes (length < 254), nothing (length == 255 NULL marker), or a chunked
    # sequence of length-prefixed segments terminated by a zero-length segment
    # (length == 254 LONG marker).
    Length = Data[0]
    if Length == TNS_LONG_LENGTH_INDICATOR:
        Rest = Data[1:]
        while True:
            (ChunkLen, Rest) = _chunk_length(Rest)
            if ChunkLen == 0:
                return Rest
            Rest = Rest[ChunkLen:]
    elif Length == TNS_NULL_LENGTH_INDICATOR:
        return Data[1:]
    else:
        return Data[1 + Length :]


def _read_chunked_bytes(Data: bytes) -> tuple[bytes, bytes]:
    # The value form _skip_chunked_bytes skips, but returning the bytes: a
    # 1-byte length then that many raw bytes (length < 254), nothing (255 NULL),
    # or a chunked length-prefixed sequence terminated by a zero-length chunk
    # (254).
    Length = Data[0]
    if Length == TNS_LONG_LENGTH_INDICATOR:
        Rest = Data[1:]
        Out = b''
        while True:
            (ChunkLen, Rest) = _chunk_length(Rest)
            if ChunkLen == 0:
                return (Out, Rest)
            Out += bytes(Rest[:ChunkLen])
            Rest = Rest[ChunkLen:]
    elif Length == TNS_NULL_LENGTH_INDICATOR:
        return (b'', Data[1:])
    else:
        return (bytes(Data[1 : 1 + Length]), Data[1 + Length :])


def _skip_bytes_with_length(Data: bytes) -> bytes:
    (NumBytes, Rest) = decode_ub4(Data)
    if NumBytes > 0:
        Rest = _skip_chunked_bytes(Rest)
    return Rest


class _ThinCodec:
    """The thin dialect's primitives (#2064): TTC's variable-width integers,
    and long values chunked as python-oracledb writes them."""

    name = 'thin'

    @staticmethod
    def n4(value: int) -> bytes:
        # The inverse of decode_ub4, negatives included: a scale of -127 reads
        # as `81 7f`, and encode_sb4 alone raised on it (#2299).
        return _encode_signed_sb4(value)

    n2 = n4

    @staticmethod
    def read_n4(data: bytes) -> tuple[int, bytes]:
        return decode_ub4(data)

    read_n2 = read_n4

    @staticmethod
    def value(data: bytes) -> bytes:
        # Inverse of `_skip_chunked_bytes` (oracledb write_bytes_with_length):
        # a 1-byte length + data for short values (<= 252 bytes), or the 254
        # LONG marker followed by length-prefixed chunks terminated by a
        # zero-length chunk -- a ub4 length from 12.1, a single byte before,
        # as an 11g server writes them and as _chunk_length reads them (#1261).
        if len(data) <= TNS_MAX_SHORT_LENGTH:
            return bytes([len(data)]) + data
        return _ThinCodec._chunked(data, 0x40)

    @staticmethod
    def lob(data: bytes) -> bytes:
        # LOB_DATA content in the negotiated version's chunk framing: always
        # the 0xFE-marked run of chunks, as Oracle sends it whatever the length
        # (#1970). 11g prefixes each chunk with a single length byte, a 12.1+
        # client reads a variable-width length (the ub4 form) per chunk -- the
        # same framing its own writer uses for a long bind -- and a zero
        # terminator. Empty content is a bare zero length.
        if not data:
            return b'\x00'
        return _ThinCodec._chunked(data, _OCI_LOB_CHUNK)

    @staticmethod
    def _chunked(data: bytes, size: int) -> bytes:
        wide = _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
        encode_len = encode_sb4 if wide else (lambda n: bytes([n]))
        out = bytearray([TNS_LONG_LENGTH_INDICATOR])
        for at in range(0, len(data), size):
            chunk = data[at : at + size]
            out += encode_len(len(chunk)) + chunk
        out += encode_len(0)
        return bytes(out)

    @staticmethod
    def read_value(data: bytes) -> tuple[bytes, bytes]:
        if data[0] != TNS_LONG_LENGTH_INDICATOR:
            return bytes(data[1 : 1 + data[0]]), data[1 + data[0] :]
        wide = _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
        data = data[1:]
        out = bytearray()
        while True:
            (length, data) = decode_ub4(data) if wide else (data[0], data[1:])
            if not length:
                return bytes(out), data
            out += data[:length]
            data = data[length:]

    read_lob = read_value

    @staticmethod
    def chr(data: str | bytes) -> bytes:
        # Text and RAW as thin frames them (encode_chr): from 12.1 as any value,
        # before it in 64-byte chunks past 64 bytes.
        return encode_chr(data)

    read_chr = read_value

    @staticmethod
    def long(data: bytes | None) -> bytes:
        # A LONG / LONG RAW cell (#484): chunked even when it fits one chunk,
        # 252 bytes at most, in the chunk framing of the negotiated version;
        # NULL a bare zero.
        return (
            b'\x00' if data is None else _ThinCodec._chunked(data, TNS_MAX_SHORT_LENGTH)
        )

    @staticmethod
    def read_long(data: bytes) -> tuple[bytes | None, bytes]:
        if data[0] == 0:
            return None, data[1:]
        return _ThinCodec.read_value(data)

    @staticmethod
    def scale(value: int) -> bytes:
        # One signed byte from 12.1; the 11g describe's variable-width signed
        # integer before.
        if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1:
            return bytes([value & 0xFF])
        return _encode_signed_sb4(value)

    @staticmethod
    def read_scale(data: bytes) -> tuple[int, bytes]:
        if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1:
            return int.from_bytes(data[:1], 'big', signed=True), data[1:]
        if data[0] & 0x80:
            size = data[0] & 0x7F
            return -int.from_bytes(data[1 : 1 + size], 'big'), data[1 + size :]
        return decode_ub4(data)

    @staticmethod
    def token(value: int | None) -> bytes:
        # A function call's token number, which thin sends from 23ai
        # (_fun_header) and not before, as read_token reads it: by the field
        # version, not by what the caller gives. Given a token below 23ai the
        # encoder wrote one, and its own decoder then misread the message.
        if _ENCODE_FIELD_VERSION.get() < FIELD_VERSION_23_1_EXT_1:
            return b''
        return encode_sb4(value or 0)

    @staticmethod
    def read_token(data: bytes) -> tuple[int | None, bytes]:
        if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_23_1_EXT_1:
            return decode_ub4(data)
        return None, data

    @staticmethod
    def ptr(value: bool) -> bytes:
        return b'\x01' if value else b'\x00'

    @staticmethod
    def read_ptr(data: bytes) -> tuple[bool, bytes]:
        # A message cut short here says so at the next count, which raises
        # Truncated, as a half-arrived one must (#1000).
        return bool(data[:1] != b'\x00' and data[:1]), data[1:]

    wn4 = n4
    read_wn4 = read_n4
    n8 = n4
    read_n8 = read_n4
    n1 = n4
    read_n1 = read_n4


def _oci_fixed(data: bytes, width: int, kind: str) -> bytes:
    # A fixed-width OCI field's bytes. One past the end of the message raises,
    # as the schema's big-endian kinds do: read as 0 or "absent", an exhausted
    # buffer let a count the message did not back decode empty items until the
    # count -- billions of them, before the password was checked (#2272).
    if len(data) < width:
        raise IndexError(f'{kind} past the end of the message')
    return data[:width]


class _OciCodec:
    """The OCI dialect's primitives (#2064), as sqlplus reads them: fixed-width
    little-endian integers, and long values in chunks with a ub1 length."""

    name = 'oci'

    @staticmethod
    def n4(value: int) -> bytes:
        return value.to_bytes(4, 'little')

    @staticmethod
    def n2(value: int) -> bytes:
        return value.to_bytes(2, 'little')

    @staticmethod
    def read_n4(data: bytes) -> tuple[int, bytes]:
        return int.from_bytes(_oci_fixed(data, 4, 'n4'), 'little'), data[4:]

    @staticmethod
    def read_n2(data: bytes) -> tuple[int, bytes]:
        return int.from_bytes(_oci_fixed(data, 2, 'n2'), 'little'), data[2:]

    @staticmethod
    def value(data: bytes) -> bytes:
        # A value as OCI frames it (#2042): a ub1 length, or past 252 bytes
        # 0xFE and chunks of up to 255 bytes, each with a ub1 length, ending at
        # a zero length -- as live 11g sends them (`fe ff` ... `00`). A server
        # that advertises BIG_CHUNK_CLR, as live 18c does, may send ub4 lengths
        # and chunks of up to 2000 bytes; the Mirror doesn't advertise it. The
        # thin form's variable-width chunk lengths, which sqlplus misreads,
        # hung it on a DBMS_OUTPUT.GET_LINES batch past 252 bytes.
        if len(data) <= TNS_MAX_SHORT_LENGTH:
            return bytes([len(data)]) + data
        return _OciCodec._chunked(data)

    @staticmethod
    def lob(data: bytes) -> bytes:
        # TTI_LOB content, the 11g form: Oracle sends content of ANY length
        # chunked, a 1-byte read included -- 0xFE, a run of <ub1 len><bytes>,
        # a zero-length chunk. A plain <len><data> is not a form it uses, and
        # lengths 253-255 cannot be one: those bytes are markers, so a 254-byte
        # read sent plain opened a chunked run at its first content byte and
        # hung the client (#1970). Empty content is a bare zero length.
        if not data:
            return b'\x00'
        return _OciCodec._chunked(data)

    @staticmethod
    def chr(data: str | bytes) -> bytes:
        # Text and RAW: as thin frames them up to 252 bytes, in OCI's chunks
        # past them -- the thin form's chunk lengths hung sqlplus on a
        # 300-character VARCHAR2 (#2053).
        raw = data.encode('utf-8') if isinstance(data, str) else data
        if len(raw) > TNS_MAX_SHORT_LENGTH:
            return _OciCodec._chunked(raw)
        return encode_chr(raw)

    @staticmethod
    def read_chr(data: bytes) -> tuple[bytes, bytes]:
        return _OciCodec.read_value(data)

    @staticmethod
    def long(data: bytes | None) -> bytes:
        # A LONG / LONG RAW cell (#407), chunked as thin's at 252 bytes.
        if data is None:
            return b'\x00'
        return _OciCodec._chunked(data, TNS_MAX_SHORT_LENGTH)

    @staticmethod
    def read_long(data: bytes) -> tuple[bytes | None, bytes]:
        if data[0] == 0:
            return None, data[1:]
        return _OciCodec.read_value(data)

    @staticmethod
    def scale(value: int) -> bytes:
        return bytes([value & 0xFF])

    @staticmethod
    def read_scale(data: bytes) -> tuple[int, bytes]:
        return int.from_bytes(_oci_fixed(data, 1, 'scale'), 'big', signed=True), data[
            1:
        ]

    @staticmethod
    def _chunked(data: bytes, size: int | None = None) -> bytes:
        size = size or _OCI_LOB_CHUNK
        out = bytearray([TNS_LONG_LENGTH_INDICATOR])
        for at in range(0, len(data), size):
            chunk = data[at : at + size]
            out += bytes([len(chunk)]) + chunk
        return bytes(out + b'\x00')

    @staticmethod
    def read_value(data: bytes) -> tuple[bytes, bytes]:
        if data[0] != TNS_LONG_LENGTH_INDICATOR:
            return bytes(data[1 : 1 + data[0]]), data[1 + data[0] :]
        data = data[1:]
        out = bytearray()
        while data[0]:
            out += data[1 : 1 + data[0]]
            data = data[1 + data[0] :]
        return bytes(out), data[1:]

    read_lob = read_value

    @staticmethod
    def token(value: int | None) -> bytes:
        # sqlplus speaks the 18c layout to a 12c+ server, which has none.
        return b''

    @staticmethod
    def read_token(data: bytes) -> tuple[int | None, bytes]:
        return None, data

    @staticmethod
    def ptr(value: bool) -> bytes:
        # The indicator stands for a pointer; sqlplus 10.2 sends the address.
        return oci.OCI_INDICATOR if value else bytes(8)

    @staticmethod
    def read_ptr(data: bytes) -> tuple[bool, bytes]:
        return oci.pointer_present(_oci_fixed(data, 8, 'ptr')), data[8:]

    wn4 = n4
    read_wn4 = read_n4

    @staticmethod
    def n8(value: int) -> bytes:
        return value.to_bytes(8, 'little')

    @staticmethod
    def read_n8(data: bytes) -> tuple[int, bytes]:
        return int.from_bytes(_oci_fixed(data, 8, 'n8'), 'little'), data[8:]

    @staticmethod
    def n1(value: int) -> bytes:
        return bytes([value & 0xFF])

    @staticmethod
    def read_n1(data: bytes) -> tuple[int, bytes]:
        if not data:
            raise IndexError('n1 past the end of the message')
        return data[0], data[1:]


class _OciWideCodec(_OciCodec):
    """The OCI dialect as an older sqlplus writes its OALL8 preamble (#866):
    five of its counts are ub8, where a modern one's are ub4."""

    @staticmethod
    def wn4(value: int) -> bytes:
        return value.to_bytes(8, 'little')

    @staticmethod
    def read_wn4(data: bytes) -> tuple[int, bytes]:
        return int.from_bytes(_oci_fixed(data, 8, 'wn4'), 'little'), data[8:]


class _O8iCodec(_OciCodec):
    """Oracle 8i's primitives (#2286): it reads a 9.2 OCI client's calls, with
    OCI's little-endian ub4 / ub2 integers but a one-byte pointer flag, and
    with ub4 where a 64-bit OCI client writes a ub8 count. Measured on 8.1.7
    for the close-cursors piggyback, which sqlplus 9.2 sends 8i as `03 69 <seq>
    01 <ub4 1> <ub4 cursor>`; the other primitives are OCI's until a message
    measures them (#2284)."""

    name = 'o8i'

    @staticmethod
    def ptr(value: bool) -> bytes:
        return b'\x01' if value else b'\x00'

    @staticmethod
    def read_ptr(data: bytes) -> tuple[bool, bytes]:
        return _oci_fixed(data, 1, 'ptr') != b'\x00', data[1:]

    @staticmethod
    def n8(value: int) -> bytes:
        return value.to_bytes(4, 'little')

    @staticmethod
    def read_n8(data: bytes) -> tuple[int, bytes]:
        return int.from_bytes(_oci_fixed(data, 4, 'n8'), 'little'), data[4:]

    # Text as thin frames it before 12.1, which the 8i request pins: a ub1
    # length up to 64 bytes, then 64-byte chunks with ub1 lengths (#2284).
    # OCI's own goes to 255-byte chunks past 252 bytes, which 8i does not read.
    chr = staticmethod(_ThinCodec.chr)

    @staticmethod
    def read_chr(data: bytes) -> tuple[bytes, bytes]:
        # Text as thin reads it, which 8.1.7 writes as before 12.1: a ub1
        # length, or 0xFE and chunks with ub1 lengths, to a zero one; a
        # 433-byte message comes as `fe ff`, 255 bytes, `b2`, 178 bytes, `00`
        # (#2284).
        wide = _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
        return _O8iCodec._read_whole(data, wide)

    @staticmethod
    def read_value(data: bytes) -> tuple[bytes, bytes]:
        # A value as OCI frames it, ub1 chunk lengths whatever the field version.
        return _O8iCodec._read_whole(data, False)

    @staticmethod
    def read_long(data: bytes) -> tuple[bytes | None, bytes]:
        # A LONG / LONG RAW cell's value: chunked however short, `fe 0a`, the
        # ten bytes, `00`, and a bare zero for NULL (#2284).
        if _oci_fixed(data, 1, 'long')[0] == 0:
            return None, data[1:]
        return _O8iCodec._read_whole(data, False)

    @staticmethod
    def _read_whole(data: bytes, wide: bool) -> tuple[bytes, bytes]:
        # A ub1 length and the bytes, or 0xFE and chunks to a zero length, ub4
        # lengths if `wide` else ub1. A reply ends in a field read so -- a
        # status in its message, a describe in its date -- and 8i marks no
        # packet as a reply's last (#2280), so a field cut short raises.
        def take(data: bytes, length: int) -> bytes:
            if len(data) < length:
                raise IndexError('value past the end of the message')
            return data[:length]

        if take(data, 1)[0] != TNS_LONG_LENGTH_INDICATOR:
            return take(data[1:], data[0]), data[1 + data[0] :]
        data = data[1:]
        out = bytearray()
        while True:
            if wide:
                (length, data) = decode_ub4(data)
            else:
                (length, data) = (take(data, 1)[0], data[1:])
            if not length:
                return bytes(out), data
            out += take(data, length)
            data = data[length:]


class _O9iCodec(_OciWideCodec):
    """A native 9.2 OCI client's primitives, as the experimental 9i OALL8 opt-in
    sends them (#798): OCI's, with the ub8 counts of a 64-bit client's OALL8
    preamble (_OciWideCodec), and text framed as thin frames it before 12.1 --
    the pre-10g 64-byte chunks 8i takes too, which a native 9.2 query of 161
    bytes carries (64, 64, 33). Proved byte for byte against the execute
    seerdb had built by hand from the 9.2 captures; the same schemas then serve
    8i (_O8iCodec) and 9.2, apart from their fields marked for one codec."""

    name = 'o9i'
    chr = staticmethod(_ThinCodec.chr)
    read_chr = staticmethod(_O8iCodec.read_chr)


_THIN = _ThinCodec()
_OCI = _OciCodec()
_OCI_WIDE = _OciWideCodec()
_O8I = _O8iCodec()
_O9I = _O9iCodec()
_bytes_with_length = _THIN.value
_oci_value_bytes = _OCI.value

# The messages both dialects write with the same fields (#2064), one schema
# each, compiled for each dialect once (seerdb.common.wire_schema).
# TTI_STA: the OER call status and the end-to-end sequence.
_STA: wire_schema.Schema = (
    ('const', bytes([TTI_STA])),
    ('n4', 'call_status'),
    ('n2', 'sequence'),
)
# A logoff's reply: the STA, and in thin the end-of-response marker.
_LOGOFF_REPLY: wire_schema.Schema = (
    *_STA,
    ('only', 'thin', (('const', bytes([TTI_END_OF_RESPONSE])),)),
)
# TTI_LOB: LOB_DATA.
_LOB_DATA: wire_schema.Schema = (('const', bytes([TTI_LOB])), ('lob', 'content'))
# The SYNC server piggyback (#1776, #2020): its DTYs, then keyword-value pairs,
# each a text value and a binary value, either of them empty, and its flags.
_SYNC_PAIR: wire_schema.Schema = (
    ('n4', 'text_length'),
    ('when', 'text_length', (('value', 'text'),)),
    ('n4', 'binary_length'),
    ('when', 'binary_length', (('value', 'binary'),)),
    ('n2', 'keyword'),
)
_SYNC: wire_schema.Schema = (
    ('const', bytes([TTI_SVR_PIGGYBACK, TNS_SERVER_PIGGYBACK_SYNC])),
    ('n2', 'dty_count'),
    ('u8', 'dty_length'),
    ('n4', 'pair_count'),
    ('u8', 'pairs_length'),
    ('each', 'pairs', 'pair_count', _SYNC_PAIR),
    ('n4', 'flags'),
)
# The per-iteration affected-row counts an array DML answers when the client
# asked for arraydmlrowcounts (#18/#859): the execute's return-parameters block
# (TTI_RPA), its four ordinary words (al8o4l, al8txl, key/value pairs,
# registration -- all empty here), then the count and one ub4 per iteration. A
# prefix: the OER that ends the response follows separately.
_ROWCOUNTS_BLOCK: wire_schema.Schema = (
    ('const', bytes([TTI_RPA])),
    ('n4', 'al8o4l'),
    ('n4', 'al8txl'),
    ('n4', 'key_value_pairs'),
    ('n4', 'registration'),
    ('n4', 'count'),
    ('each', 'counts', 'count', (('n4', 'value'),)),
)
# The CREATE_TEMP reply (#412/#846): the minted locator (a ub2 length then its
# bytes), the character set and a flags byte. A prefix -- the status OER that
# ends the response follows separately.
_CREATE_TEMP_RESPONSE: wire_schema.Schema = (
    ('const', bytes([TTI_RPA])),
    ('be2', 'locator_length'),
    ('bytes', 'locator', 'locator_length'),
    ('n4', 'charset'),
    ('u8', 'flags'),
)
# The TTI_IRD block a PL/SQL DBMS_SQL.RETURN_RESULT answers with (#121/#826): a
# count, then per result a preamble the client skips, the column describe body,
# and the server cursor id. The describe body is pre-encoded
# (`_encode_describe_body`), so it rides as a `raw` field and the schema encodes
# only.
_IMPLICIT_RESULTS: wire_schema.Schema = (
    ('const', bytes([TTI_IRD])),
    ('n4', 'count'),
    (
        'each',
        'results',
        'count',
        (
            ('value', 'preamble'),
            ('raw', 'describe'),
            ('n4', 'cursor_id'),
        ),
    ),
)
# The return-parameters block that reports a session-state change (a new
# CURRENT_SCHEMA, #973) back to the client: the al8o4l count and its six words
# (the SCN, the sequence, and four fixed), an eight-byte prefix tail, the single
# state entry (its count, key and type byte), and the new value as a ub4 length,
# a ub1 length and the name. The trailing entries (which differ for an edition
# change) follow separately.
_SESSION_STATE_RESPONSE: wire_schema.Schema = (
    ('const', bytes([TTI_RPA])),
    ('n4', 'al8o4l'),
    ('n4', 'scn'),
    ('n4', 'word_1'),
    ('n4', 'sequence'),
    ('n4', 'word_2'),
    ('n4', 'word_3'),
    ('n4', 'word_4'),
    ('bytes', 'prefix_tail', 8),
    ('u8', 'entry_count'),
    ('u8', 'key'),
    ('u8', 'entry_type'),
    ('n4', 'name_length'),
    ('u8', 'name_byte_length'),
    ('bytes', 'name', 'name_byte_length'),
)
# The TTI_PRO protocol-negotiation reply (PROTOCOL.md 4.1): the server's TTC
# version byte and a trailing zero, the NUL-terminated banner, the charset id
# and a flags byte, the charset-element array (a count then five bytes each),
# the FDO blob (a big-endian length then its bytes), and the two length-prefixed
# capability arrays. Its integers are fixed-width, not the codec's variable
# form, so every field is dialect-independent.
_PRO: wire_schema.Schema = (
    ('const', bytes([TTI_PRO])),
    ('u8', 'server_version'),
    ('pad', 1),
    ('cstr', 'banner'),
    ('le2', 'charset_id'),
    ('u8', 'server_flags'),
    ('le2', 'charset_count'),
    ('each', 'charset_elements', 'charset_count', (('bytes', 'element', 5),)),
    ('be2', 'fdo_length'),
    ('bytes', 'fdo', 'fdo_length'),
    ('u8', 'compile_caps_length'),
    ('bytes', 'compile_caps', 'compile_caps_length'),
    ('u8', 'runtime_caps_length'),
    ('bytes', 'runtime_caps', 'runtime_caps_length'),
)
# TTI_FETCH: the cursor and the rows the client has room for.
_FETCH: wire_schema.Schema = (
    ('const', bytes([TTI_FUN, TTI_FETCH])),
    ('u8', 'seq'),
    ('token', 'token_number'),
    ('n4', 'cursor'),
    ('n4', 'rows'),
)
# An execute by cursor id, TTI_EXEC (function 4), and the fetch-carrying form
# (78): the cursor, the iterations, two option words, then -- with binds -- an
# RXD row of values, which each dialect reads its own way.
_EXEC_BY_CURSOR: wire_schema.Schema = (
    ('const', bytes([TTI_FUN])),
    ('u8', 'function'),
    ('u8', 'seq'),
    ('token', 'token_number'),
    ('n4', 'cursor'),
    ('n4', 'iterations'),
    ('n4', 'options'),
    ('n4', 'options_2'),
)
# OALL8, the execute, through its define count (#2064): the same fields in
# both dialects, as python-oracledb writes them, measured against sqlplus 10.2,
# 11g, 18c and 23.26 captures. What follows the define count differs by form.
# In a wide OCI preamble one of prefetch_rows and max_long is the ub8; every
# sqlplus capture has 1 and 0 there, which can't tell which, and nothing reads
# them. A native 9.2 client's fetch tells (#798): its LONG cap, 23, is the ub8
# after a zero prefetch_rows, so max_long is the ub8, as the cap is 8i's
# max_long; the execute's 1 and 0 read the same either way.
_ALL8_HEAD: wire_schema.Schema = (
    ('const', bytes([TTI_FUN, TTI_ALL8])),
    ('u8', 'seq'),
    ('token', 'token_number'),
    ('n4', 'options'),
    ('n4', 'cursor'),
    ('ptr', 'sql_present'),
    ('wn4', 'sql_length'),
    ('ptr', 'al8i4_present'),
    ('wn4', 'al8i4_length'),
    ('ptr', 'al8o4'),
    ('ptr', 'al8o4l'),
    ('n4', 'prefetch_size'),
    ('n4', 'prefetch_rows'),
    ('wn4', 'max_long'),
    ('ptr', 'binds_present'),
    ('wn4', 'bind_count'),
    ('ptr', 'al8app'),
    ('ptr', 'al8txn'),
    ('ptr', 'al8txl'),
    ('ptr', 'al8kv'),
    ('ptr', 'al8kvl'),
    ('ptr', 'defines_present'),
    ('wn4', 'define_count'),
)
# Oracle 8i's OALL8 (#2284): the execute a 9.2 OCI client sends, as 8.1.7 reads
# it. The OALL8 head above through al8kvl -- 9.2 has no defines -- then the SQL
# text when there is one, then the al8i4 array of twelve ub4s. What the
# 9.2-client capture and every 8i request seerdb sends carry in it: [0] 1 for
# an execute and 0 for a fetch, [1] the execute flag for a statement (0 for a
# query, whose execute waits for its fetch) or the rows a fetch asks for, and
# [7] the statement type (O8I_STMT_*); the rest are 0.
#
# The same execute at a 9.2 server's 64-bit widths (_O9I, #798) carries the
# defines' pointer and count, which an 8.1.7 server does not read.
_O8I_ALL8: wire_schema.Schema = (
    *_ALL8_HEAD[:-2],
    ('only', 'o9i', _ALL8_HEAD[-2:]),
    ('when', 'sql_present', (('chr', 'sql'),)),
    *(('n4', f'al8i4_{i}') for i in range(12)),
)
# The end of a describe (TTI_DCB), and of a REF CURSOR's inline one: the
# describe time, four flags (dcbflag, dcbmdbz, dcbmnpr, dcbmxpr) and, from
# 11.2, the result cache's query key. Thin sends an empty date and key; OCI a
# lead byte, a 7-byte date in the two-length form (zero, as the Mirror leaves
# it) and the key's ub4 length. A LOB describe sets dcbmdbz (#405).
_DESCRIBE_TRAILER: wire_schema.Schema = (
    ('only', 'oci', (('u8', 'date_lead'), ('n4', 'date_length'))),
    ('value', 'date'),
    ('n4', 'dcbflag'),
    ('n4', 'dcbmdbz'),
    ('n4', 'dcbmnpr'),
    ('n4', 'dcbmxpr'),
    (
        'when',
        'has_query_key',
        (
            ('only', 'thin', (('value', 'query_key'),)),
            ('only', 'oci', (('n4', 'query_key_length'),)),
        ),
    ),
)
# A REF CURSOR OUT value (#483, #2014): a lead byte -- 0x01 in thin, 0x4c in
# OCI -- the cursor's describe, its id and the return code every OUT value
# ends on.
_REFCURSOR_OUT: wire_schema.Schema = (
    ('u8', 'lead'),
    ('raw', 'describe'),
    ('n4', 'cursor'),
    ('n2', 'return_code'),
)
# A LONG / LONG RAW cell: the content, then its trailing indicators -- the
# actual length and, in thin only, the return code -- zero for an ordinary
# value (#407, #484).
_LONG_CELL: wire_schema.Schema = (
    ('long', 'content'),
    ('n4', 'actual_length'),
    ('only', 'thin', (('n4', 'return_code'),)),
)
# A describe column (TTI_DCB), in thin's field order, which OCI keeps (#2064).
# OCI's own parts, measured against live 11g and 18c describes (#265, #1282,
# #2050):
# - a first-column marker and a lead byte (0x00 for a typed column, as in a
#   bind descriptor);
# - from the 12c band, two inserted 4-byte slots, ahead of the continuation
#   flags and of the character set;
# - in a plain column, zero runs a typed one lacks: six bytes behind the
#   version, one behind the form, and the oaccolid slot, which thin carries
#   from 12.2 and 18c fills on a character column;
# - one byte at the end.
# Thin's own: the column position, which OCI doesn't carry, and 23ai's domain,
# annotations and vector descriptor.
_DCB_COLUMN: wire_schema.Schema = (
    (
        'only',
        'oci',
        (
            ('u8', 'marker'),
            ('u8', 'lead'),
            # A typed column (XMLTYPE) leads 00, and has neither OCI's padding
            # nor the column id.
            ('derive', 'oci_plain', lambda v: v['lead'] == 1),
            ('derive', 'has_oaccolid', lambda v: v['lead'] == 1),
        ),
    ),
    ('u8', 'data_type'),
    ('u8', 'flags'),
    ('u8', 'precision'),
    ('scale', 'scale'),
    ('n4', 'buffer_size'),
    ('n4', 'max_array'),
    ('only', 'oci', (('when', 'oci_12c', (('const', bytes(4)),)),)),
    ('n4', 'cont_flags'),
    ('n4', 'toid_length'),
    ('when', 'toid_length', (('value', 'toid'),)),
    ('n2', 'version'),
    ('only', 'oci', (('when', 'oci_plain', (('const', bytes(6)),)),)),
    ('only', 'oci', (('when', 'oci_12c', (('const', bytes(4)),)),)),
    ('n2', 'charset'),
    ('u8', 'csfrm'),
    ('only', 'oci', (('when', 'oci_plain', (('const', bytes(1)),)),)),
    ('n4', 'max_size'),
    ('when', 'has_oaccolid', (('n4', 'oaccolid'),)),
    ('u8', 'null_ok'),
    ('u8', 'v7_name_length'),
    ('n4', 'name_length'),
    ('only', 'thin', (('when', 'name_length', (('value', 'name'),)),)),
    ('only', 'oci', (('value', 'name'),)),
    ('n4', 'type_schema_length'),
    ('when', 'type_schema_length', (('value', 'type_schema'),)),
    ('n4', 'type_name_length'),
    ('when', 'type_name_length', (('value', 'type_name'),)),
    ('only', 'thin', (('n4', 'position'),)),
    ('when', 'has_uds', (('n4', 'uds_flags'),)),
    ('only', 'oci', (('u8', 'reserved'),)),
    (
        'only',
        'thin',
        (
            (
                'when',
                'has_domain',
                (
                    ('n4', 'domain_schema_length'),
                    ('when', 'domain_schema_length', (('value', 'domain_schema'),)),
                    ('n4', 'domain_name_length'),
                    ('when', 'domain_name_length', (('value', 'domain_name'),)),
                ),
            ),
            (
                'when',
                'has_vector',
                (
                    ('raw', 'annotations'),
                    ('n4', 'vector_dimensions'),
                    ('u8', 'vector_format'),
                    ('u8', 'vector_flags'),
                ),
            ),
        ),
    ),
)
# A physical ROWID cell (#484, #2017): a lead byte -- thin's present
# indicator, OCI's length -- then the data object, relative file, block and
# row numbers, with an unused field behind the file in thin only.
_ROWID_CELL: wire_schema.Schema = (
    ('u8', 'lead'),
    ('n4', 'object'),
    ('n4', 'file'),
    ('only', 'thin', (('n4', 'unused'),)),
    ('n4', 'block'),
    ('n4', 'row'),
)
# A LOB column's cell (#405, #413, #853, #1287): the locator's length, then --
# for a client that reads them -- the LOB's size and chunk size, then the
# locator. NULL to OCI is the length at zero and nothing more.
_LOB_CELL: wire_schema.Schema = (
    ('n4', 'locator_length'),
    (
        'when',
        'locator_length',
        (
            ('when', 'has_metadata', (('n8', 'size'), ('n4', 'chunk_size'))),
            ('value', 'locator'),
        ),
    ),
)
# An object (ADT) value, a row cell's and an OUT bind's (#116, §40.4): a head
# each dialect writes its own way, then the image's length, the TOP_LEVEL flags
# and -- unless the value is NULL -- the image. Thin's head is the type id, an
# empty object OID, the snapshot and the version; OCI's is the type's REF and a
# lead of `01` and zeros (ten from a live 11g, eight from a live 18c).
_OBJECT_FRAME: wire_schema.Schema = (
    (
        'only',
        'thin',
        (
            ('n4', 'toid_length'),
            ('when', 'toid_length', (('value', 'toid'),)),
            ('n4', 'oid_length'),
            ('n4', 'snapshot'),
            ('n4', 'version'),
        ),
    ),
    ('only', 'oci', (('raw', 'type_ref'), ('raw', 'lead'))),
    ('n4', 'image_length'),
    ('n2', 'flags'),
    ('when', 'has_image', (('value', 'image'),)),
)
# The CLOSE_CURSORS (OCCA) piggyback (#191, #1517): the cursors a client
# frees, in front of its next call. Live 11g, sqlplus closing cursors 3 and 1:
# `11 69 11 | fe ff..ff | 02 00 00 00 00 00 00 00 | 03 00 00 00 01 00 00 00`.
_CLOSE_CURSORS: wire_schema.Schema = (
    ('const', bytes([TTI_MSG_TYPE_PIGGYBACK, TTI_OCCA])),
    ('u8', 'seq'),
    ('token', 'token_number'),
    ('ptr', 'cursors_present'),
    ('n8', 'count'),
    ('each', 'cursors', 'count', (('n4', 'cursor'),)),
)
# The head every piggyback message shares: the piggyback marker, the function
# code, the sequence, and -- from 23ai (fv >= 23.1 EXT 1) -- the ub8 request
# token (`_fun_header`'s, for piggybacks). The token is 0 for an ordinary
# piggyback and the call's own number in a pipelined burst (#132). The bespoke
# body of each piggyback follows; CLOSE_CURSORS bakes its own function into the
# const above and carries its cursor list, so it keeps its own schema.
_PIGGYBACK_HEAD: wire_schema.Schema = (
    ('const', bytes([TTI_MSG_TYPE_PIGGYBACK])),
    ('u8', 'func'),
    ('u8', 'seq'),
    ('token', 'token_number'),
)
# TTI_LOBOPS (96), the head every operation shares (#412, #2064): the source
# and destination locators' pointers and lengths, the short offsets, three
# pointer flags, the operation. OCI sends thin's fields with 8-byte pointers
# and ub4 counts, measured against sqlplus 10.2, 11g and 23.26 READs; sqlplus
# 11.2 writes the wide counts (wn4) as ub8, as it does in its OALL8 (#866,
# #2251). Two of the head's four are wide: the operation sits eight bytes later
# than in the narrow form, not sixteen. The source length is one, the only one
# those captures carry a value in. The other was taken for the destination
# length until a native 9.2 client's WRITE at offset 3 (#798) put the source
# offset straight after a ub4 destination length; so it is the destination
# offset, the one field left -- the earlier captures carry zero in both.
_LOBOPS_HEAD: wire_schema.Schema = (
    ('const', bytes([TTI_FUN, TTI_LOBOPS])),
    ('u8', 'seq'),
    ('token', 'token_number'),
    ('ptr', 'source_present'),
    ('wn4', 'source_length'),
    ('ptr', 'dest_present'),
    ('n4', 'dest_length'),
    ('n4', 'short_source_offset'),
    ('wn4', 'short_dest_offset'),
    ('ptr', 'charset_present'),
    ('ptr', 'short_amount_present'),
    ('ptr', 'null_lob_present'),
    ('wn4', 'operation'),
)
# A READ, after the head: the SCN array's pointer and length, the source and
# destination offsets, the amount's pointer, three array-LOB slots, then the
# source locator and -- if its pointer said so -- the amount.
_LOBOPS_READ: wire_schema.Schema = (
    *_LOBOPS_HEAD,
    ('ptr', 'scn_present'),
    ('wn4', 'scn_length'),
    ('n8', 'source_offset'),
    ('n8', 'dest_offset'),
    ('ptr', 'amount_present'),
    ('ptr', 'array_slot_1'),
    ('wn4', 'array_length_1'),
    ('ptr', 'array_slot_2'),
    ('wn4', 'array_length_2'),
    ('ptr', 'array_slot_3'),
    ('wn4', 'array_length_3'),
    ('bytes', 'locator', 'source_length'),
    ('when', 'amount_present', (('n8', 'amount'),)),
)
# Its reply: the content as LOB_DATA, then the return parameters -- the
# locator echoed and the amount read, in the LOB's own units -- then the
# status (#405, #413, #903).
_LOB_READ_REPLY: wire_schema.Schema = (
    ('raw', 'lob_data'),
    ('const', bytes([TTI_RPA])),
    ('raw', 'locator'),
    ('n8', 'amount'),
    ('raw', 'status'),
)
# A login's OSESSKEY or AUTH request (TTI_SESS 118 / TTI_AUTH 115, #2064): a
# pointer, the user's length, the mode, a pointer, the pair count, two
# pointers, the user, then the key-value pairs. sqlplus 10.2 and 11.2 send
# thin's fields with 8-byte pointers and ub4 lengths, declaring each length at
# three times the character count, a conversion buffer's worth; the value
# behind it carries the real one (#265, #1764). Their count is a ub4 in a ub8's
# slot, and its upper four bytes are left unset: 10.2 writes address bytes
# there and 11.2 whatever its buffer held, so they are skipped, never read as
# part of the count (#2249). Oracle 8i's OSESSKEY and OAUTH (#2284) are this
# head at the 8i codec's widths, the count a ub4 alone, and their pairs these;
# the replies an RPA, a ub2 pair count and the pairs (`_PRE10_AUTH_REPLY`).
# 9i's are this head thin-coded, the user raw (#2342). Not
# on the wire, so
# given to the decoder: whether a 23ai OAUTH carries its has-user pointer (thin
# only, detected by its first byte), and whether the user is length-prefixed
# (thin from 12.1, OCI always) or raw.
_AUTH_PAIR: wire_schema.Schema = (
    ('n4', 'key_length'),
    ('when', 'key_length', (('value', 'key'),)),
    ('n4', 'value_length'),
    ('when', 'value_length', (('value', 'value'),)),
    ('n4', 'flags'),
)
_AUTH_HEAD: wire_schema.Schema = (
    ('const', bytes([TTI_FUN])),
    ('u8', 'subtype'),
    ('u8', 'seq'),
    ('only', 'thin', (('when', 'has_user_ptr', (('n4', 'has_user'),)),)),
    ('ptr', 'pointer_1'),
    ('n4', 'user_length'),
    ('n4', 'mode'),
    ('ptr', 'pointer_2'),
    ('only', 'thin', (('n8', 'pair_count'),)),
    ('only', 'oci', (('n4', 'pair_count'), ('pad', 4))),
    ('only', 'o8i', (('n4', 'pair_count'),)),
    ('ptr', 'pointer_3'),
    ('ptr', 'pointer_4'),
    ('when', 'user_prefixed', (('value', 'user'),)),
    ('when', 'user_raw', (('bytes', 'user', 'user_length'),)),
)
# A bind's descriptor, its OAC (#116, #2064): thin's fields in thin's order.
# OCI's -- measured against sqlplus 10.2, 11.2 and 23.26 binding VARCHAR2,
# CHAR, NCHAR, NVARCHAR2, NUMBER, BINARY_FLOAT / DOUBLE, CLOB, NCLOB,
# REFCURSOR and GET_LINES' object -- are a describe column's without the column's
# own (_DCB_COLUMN): a lead byte (0x00 for a typed bind), the 12c band's two
# inserted slots, and in a plain bind the zero runs a typed one lacks and the
# oaccolid slot. 41 bytes for a plain bind before 12c, 49 from it; 47 and 55 for
# an object. OCI declares a character bind's length at its client buffer's
# size -- three bytes a character, two for NCHAR -- and its characters as max
# characters. Thin's oaccolid, from 12.2, its callers read.
_OAC: wire_schema.Schema = (
    ('only', 'oci', (('u8', 'lead'),)),
    ('u8', 'data_type'),
    ('derive', 'oci_plain', lambda v: v['data_type'] != TNS_TYPE_ADT),
    ('u8', 'flags'),
    ('u8', 'precision'),
    ('n1', 'scale'),
    ('n4', 'max_length'),
    ('n4', 'max_array'),
    ('only', 'oci', (('when', 'oci_12c', (('pad', 4),)),)),
    ('n4', 'cont_flags'),
    ('n4', 'toid_length'),
    ('when', 'toid_length', (('value', 'toid'),)),
    ('n2', 'version'),
    ('only', 'oci', (('when', 'oci_plain', (('pad', 6),)),)),
    ('only', 'oci', (('when', 'oci_12c', (('pad', 4),)),)),
    ('n2', 'charset'),
    ('u8', 'csfrm'),
    ('only', 'oci', (('when', 'oci_plain', (('pad', 1),)),)),
    ('n4', 'max_chars'),
    ('only', 'oci', (('when', 'oci_plain', (('n4', 'oaccolid'),)),)),
)
# Oracle 9i's bind descriptor and define entry (#2284): thin's OAC through its
# csfrm -- 9.2 has no max_chars -- at field version 2, without the fields only
# OCI writes. The four fields between the size and the charset are the array
# length, the continuation flags, the type's OID and its version: zeros but for
# an object, which names its type there as ojdbc14 does (#2258).
_O7_OAC: wire_schema.Schema = tuple(
    f for f in _OAC[: _OAC.index(('n4', 'max_chars'))] if f[0] not in ('only', 'derive')
)
# A 9i describe's column: the OAC above, then whether it takes NULLs (00 NOT
# NULL, 01 nullable), its name -- one byte of its length in bytes, which the
# server caps at 255, a ub4 of its length in characters, and the name -- and
# the schema and name of its type, each a ub4 length and the name when there is
# one. Only an object column has them, `01 03 03 PYO`, `01 06 06 TY2248` on
# 9.2.0.4 (#2258); every other column sends `00 00` there.
_O7_DESCRIBE_COLUMN: wire_schema.Schema = (
    *_O7_OAC,
    ('u8', 'null_ok'),
    ('u8', 'name_bytes'),
    ('n4', 'name_chars'),
    ('chr', 'name'),
    ('n4', 'type_schema_length'),
    ('when', 'type_schema_length', (('chr', 'type_schema'),)),
    ('n4', 'type_name_length'),
    ('when', 'type_name_length', (('chr', 'type_name'),)),
)
# The RPA answering the 0x62 describe call: a ub4 column count, `01 <n>` up
# to 255 and `02 01 2c` for 300 (#2306), then each column; the call's status
# follows.
_O7_DESCRIBE: wire_schema.Schema = (
    ('const', bytes([TTI_RPA])),
    ('n4', 'count'),
    ('each', 'columns', 'count', _O7_DESCRIBE_COLUMN),
)
# Oracle 8i's describe (#2284, PROTOCOL.md §19.10): the TTI_DCB 8.1.7 sends
# ahead of a query's rows. The head of 10g's (decode_token_dcb) -- the
# describe-info preamble, the max row size, the column count and, when there
# are columns, a byte (0x33) -- then 9i's columns at OCI's fixed widths, and
# the describe time, a ub4 length and the date; 10g's flags and query key
# are not there. Read from 14 describes of a live 8.1.7 with the rows next.
_O8I_DESCRIBE: wire_schema.Schema = (
    ('const', bytes([TTI_DCB])),
    ('value', 'preamble'),
    ('n4', 'max_row_size'),
    ('n4', 'count'),
    ('when', 'count', (('u8', 'reserved'),)),
    ('each', 'columns', 'count', _O7_DESCRIBE_COLUMN),
    ('n4', 'date_length'),
    ('when', 'date_length', (('value', 'date'),)),
)
# 8i's rows (#2284, PROTOCOL.md §19.10) are 9i's row header (`_O7_RXH` and
# `_O7_VECTORS`) at the 8i codec's widths -- the bit vector a ub4 length and
# a value, set in a fetch whose row repeats columns -- and then each cell: the
# value and a 4-byte trailer, an sb2 indicator (-1 NULL) and a ub2 return
# code. A NULL is the trailer alone, `ff ff 00 00`; a value's length byte is
# never 0xff, longer text coming in chunks. A LONG or LONG RAW comes chunked
# however short, and a NULL one as a bare zero with return code 1405. A LOB is
# a ub4 length and the locator, 0 and no locator for NULL; a ROWID a byte,
# 0x0e (0 for NULL), and the rowid at fixed widths, as in the status; a
# UROWID a ub2 length and the logical rowid. Read from 47 row streams of a
# live 8.1.7.
_O8I_CELL: wire_schema.Schema = (
    ('chr', 'value'),
    ('n2', 'indicator'),
    ('n2', 'return_code'),
)
_O8I_NULL_CELL: wire_schema.Schema = (('n2', 'indicator'), ('n2', 'return_code'))
_O8I_LONG_CELL: wire_schema.Schema = (
    ('long', 'value'),
    ('n2', 'indicator'),
    ('n2', 'return_code'),
)
# A 9.2 server sends a 9.2 client 8i's LOB, UROWID and ROWID cells without their
# indicator and return code (#798): a LOB's ub4 length and, when it is not zero,
# the locator; a UROWID's ub2 length and the rowid. Read live on 9.2.
_O9I_LOB_CELL: wire_schema.Schema = (
    ('n4', 'length'),
    ('when', 'length', (('value', 'locator'),)),
)
_O8I_LOB_CELL: wire_schema.Schema = (
    *_O9I_LOB_CELL,
    ('n2', 'indicator'),
    ('n2', 'return_code'),
)
# An object or collection column's cell in a 9.2 OALL8 row (#798): thin's object
# framing (_read_object_column) at fixed widths -- the type reference (36 bytes),
# the object OID and the snapshot, each a ub4 length and its bytes; a ub2
# version; a ub4 image length, zero for a NULL value; ub2 flags; then the packed
# image. Read from native_9i_objects.pcap: `24000000 24 <ref> 00000000 00000000
# 0000 0a000000 0100 0a 84010a02c102036f6e65` for PYO_O798_PT(1, 'one').
_O9I_OBJECT_CELL: wire_schema.Schema = (
    ('n4', 'toid_length'),
    ('when', 'toid_length', (('value', 'toid'),)),
    ('n4', 'oid_length'),
    ('when', 'oid_length', (('value', 'oid'),)),
    ('n4', 'snapshot_length'),
    ('when', 'snapshot_length', (('value', 'snapshot'),)),
    ('n2', 'version'),
    ('n4', 'image_length'),
    ('n2', 'flags'),
    ('when', 'image_length', (('value', 'image'),)),
)
# A rowid at fixed widths, as an 8i status and ROWID cell carry it (#1079): the
# data object, the file, a reserved byte, the block, the slot. A 9.2 server
# writes it to a 9.2 client aligned, the file and the slot each padded to four
# bytes (#798): a ROWID cell's 16 bytes, read live against ROWIDTOCHAR, and the
# status's.
_O8I_ROWID_FIELDS: wire_schema.Schema = (
    ('n4', 'rowid_object'),
    ('n2', 'rowid_file'),
    ('only', 'o8i', (('pad', 1),)),
    ('only', 'o9i', (('pad', 2),)),
    ('n4', 'rowid_block'),
    ('n2', 'rowid_slot'),
    ('only', 'o9i', (('pad', 2),)),
)
_O9I_ROWID_CELL: wire_schema.Schema = (
    ('u8', 'size'),
    ('when', 'size', _O8I_ROWID_FIELDS),
)
_O8I_ROWID_CELL: wire_schema.Schema = (
    *_O9I_ROWID_CELL,
    ('n2', 'indicator'),
    ('n2', 'return_code'),
)
_O9I_UROWID_CELL: wire_schema.Schema = (
    ('n2', 'length'),
    ('when', 'length', (('value', 'urowid'),)),
)
_O8I_UROWID_CELL: wire_schema.Schema = (
    *_O9I_UROWID_CELL,
    ('n2', 'indicator'),
    ('n2', 'return_code'),
)
# 8i's I/O vector, the "bind prompt" a PL/SQL block's reply opens with (#2284,
# PROTOCOL.md §19.14): 9i's (`_O7_IOV`) at the 8i codec's widths, but with its
# iterations a ub2 -- the binds are `iterations * 256 + requests`, 300 coming
# as `2c 00 01 00` (#2311) -- then the iterations this time, 1, and eight
# bytes zero in every reply measured, where the buffer length and the two
# vector lengths go; then one direction byte per bind, as on 9i. The values
# of the binds the block writes follow in a TTI_RXD, each a value and an sb2
# indicator (-1 for NULL), with no return code; an OUT bind the block never
# assigned is `ff` and the indicator 3105 (`ff 21 0c`), as 9i's is (#801).
# Read from 20 live 8.1.7 block replies with nothing left over.
_O8I_IOV: wire_schema.Schema = (
    ('const', bytes([TTI_IOV])),
    ('u8', 'flags'),
    ('n2', 'requests'),
    ('n2', 'iterations'),
    ('n4', 'iterations_this_time'),
    ('const', bytes(8)),
)
_O8I_OUT_CELL: wire_schema.Schema = (('chr', 'value'), ('n2', 'indicator'))
_O8I_OUT_UNASSIGNED: wire_schema.Schema = (
    ('const', b'\xff'),
    ('n2', 'indicator'),
)
# Oracle 9i's short status (PROTOCOL.md §19.2, #2284): the 10g+ OER without its
# call status and sequence number. The head runs to the rowid of the row a DML
# touched (#1079): row count, ORA code, the two array-error fields, cursor id,
# the error's offset in the SQL (#2263), then the SQL type, fatal flag, flags --
# a ub2, `00` when zero, as at 10g and 11g (#1995) -- cursor options, UPI
# parameter and warning flags, 0x20 for an object that compiled with errors
# (#2262), and the rowid: data object, file, a reserved byte, block, slot.
_O7_STATUS_HEAD: wire_schema.Schema = (
    ('const', bytes([TTI_OER])),
    ('n4', 'rows'),
    ('n4', 'code'),
    ('n4', 'array_error'),
    ('n4', 'array_error_2'),
    ('n4', 'cursor'),
    ('n4', 'position'),
    ('u8', 'sql_type'),
    ('u8', 'fatal'),
    ('n2', 'flags'),
    ('u8', 'cursor_options'),
    ('u8', 'upi_param'),
    ('u8', 'warnings'),
    ('n4', 'rowid_object'),
    ('n4', 'rowid_file'),
    ('pad', 1),
    ('n4', 'rowid_block'),
    ('n4', 'rowid_slot'),
)
# ... and the rest: OS error, statement and call numbers, padding, the
# iterations, the oerrdd, the arrays a `batcherrors` call collects -- each code
# and offset array a count and one value packing that many ub4s, the messages a
# count, an indicator and each message's length, text and two bytes (#2247) --
# and, when the code is set, the server's message, ORA-01403's too, which the
# server writes in chunks of 64 bytes past 64, as it writes text. Read from
# 57 live 9.2.0.4 statuses with nothing left over.
_O7_STATUS_TAIL: wire_schema.Schema = (
    ('n4', 'os_error'),
    ('u8', 'statement'),
    ('u8', 'call'),
    ('n2', 'padding'),
    ('n4', 'iterations'),
    ('n4', 'oerrdd_length'),
    ('when', 'oerrdd_length', (('value', 'oerrdd'),)),
    ('n4', 'batch_code_count'),
    ('when', 'batch_code_count', (('value', 'batch_codes'),)),
    ('n4', 'batch_offset_count'),
    ('when', 'batch_offset_count', (('value', 'batch_offsets'),)),
    ('n4', 'batch_message_count'),
    ('when', 'batch_message_count', (('u8', 'batch_message_indicator'),)),
    (
        'each',
        'batch_messages',
        'batch_message_count',
        (('n4', 'length'), ('when', 'length', (('chr', 'text'),)), ('pad', 2)),
    ),
    ('when', 'code', (('chr', 'message'),)),
)
# 9i's row header (#2284): flags, the number of columns requested, the
# iteration, the iterations the fetch asked for (10), the buffer length, then
# (`_O7_VECTORS`, shared with the I/O vector) the column bit vector and the rowid, each a ub4 length
# and the bytes: the 10g+ RXH. 9.2.0.4 sends seerdb both lengths, zero in every
# reply, repeated values or not; it sends ojdbc14 neither, the header ending
# at the buffer length and the first row's 07 straight after it (captured).
# A ub4 never opens with 07, and a 04 would be a bit vector of 2**24 bytes,
# so a row or the status there says the short form.
_O7_RXH: wire_schema.Schema = (
    ('const', bytes([TTI_RXH])),
    ('u8', 'flags'),
    ('n2', 'requests'),
    ('n2', 'iteration'),
    ('n2', 'iterations'),
    ('n2', 'buffer_length'),
)
_O7_VECTORS: wire_schema.Schema = (
    ('n4', 'bit_vector_length'),
    ('when', 'bit_vector_length', (('value', 'bit_vector'),)),
    ('n4', 'rowid_length'),
    ('when', 'rowid_length', (('value', 'rowid'),)),
)
# A 9i row's cell: the value, then its indicator, a signed ub4 -- 0 for a value,
# -1 (`81 01`) for NULL, which comes with an empty value; a long one comes in
# chunks of 64 bytes, as the server writes text. A LONG or LONG RAW comes
# chunked however short, and a NULL one is a bare zero (#102). A LOB's value is a
# ub4 length and, when it is not zero, the locator; a column described with no
# length sends the indicator alone (#1185).
_O7_CELL: wire_schema.Schema = (('chr', 'value'), ('n4', 'indicator'))
_O7_LOB_CELL: wire_schema.Schema = (
    ('n4', 'length'),
    ('when', 'length', (('value', 'locator'),)),
    ('n4', 'indicator'),
)
_O7_LONG_CELL: wire_schema.Schema = (('long', 'value'), ('n4', 'indicator'))
_O7_EMPTY_CELL: wire_schema.Schema = (('n4', 'indicator'),)
# The I/O vector (TTI_IOV) a 9i PL/SQL block's reply opens with, its "bind
# prompt" (#2284): python-oracledb's `_process_io_vector`, which 10g+ sends as
# well (PROTOCOL.md 6.5). Flags (5), the requests and the iterations, whose sum
# `iterations * 256 + requests` is the number of binds (#2311), the iterations
# this time (1), the buffer length, then `_O7_VECTORS` -- the lengths 9.2.0.4
# sends seerdb and not ojdbc14, as in the row header -- and one direction byte
# per bind, 0x10 OUT, 0x20 IN, 0x30 IN OUT, which `_o7_iov` reads.
_O7_IOV: wire_schema.Schema = (
    ('const', bytes([TTI_IOV])),
    ('u8', 'flags'),
    ('n2', 'requests'),
    ('n4', 'iterations'),
    ('n4', 'iterations_this_time'),
    ('n2', 'buffer_length'),
)
# A 9i TTI_LOBOPS request (#2284): the 10g+ head (`_LOBOPS_HEAD`) at field
# version 2, then the SCN array's pointer and length, the source locator
# whole -- a ub2 length and its body, the bytes `source_length` counts -- and
# the short amount when its pointer says so: a READ's or WRITE's count, TRIM's
# new length, OPEN's mode, FILE_OPEN's 0x0b, 0 for the sizes the reply fills
# in. 9i has no long offsets, no array slots and no amount pointer. Matches
# ojdbc14's GET_LENGTH, READ, WRITE, TRIM, OPEN, IS_OPEN, CLOSE and FILE_OPEN
# / FILE_CLOSE (#102, #2259). Read as an amount pointer and a value of the
# body, the locator's ub2 length looked the same up to a body of 252 bytes;
# past it, a BFILE's with a long file name, the value went out in chunks,
# and 9.2.0.4 refused the call with ORA-03120 (#2331). 8i's request is the
# same at the 8i codec's widths, byte for byte for every READ, FILE_OPEN,
# GET_LENGTH and FILE_CLOSE a live 8.1.7 session sends (#2284); in chunks, a
# long BFILE locator closed its session.
_O7_LOBOPS: wire_schema.Schema = (
    *_LOBOPS_HEAD,
    ('ptr', 'scn_present'),
    # A wide count, as in _LOBOPS_READ: a ub8 from a 64-bit 9.2 client (#798).
    ('wn4', 'scn_length'),
    ('bytes', 'locator', 'source_length'),
    ('when', 'short_amount_present', (('n4', 'short_amount'),)),
)
# Its reply, on 8i at the 8i codec's widths: the RPA, the locator as the
# server now has it (a ub2 length and
# the body; FILE_OPEN's has its open flag set, a WRITE's is updated), then the
# short amount if the request asked for one -- a GET_LENGTH's length, OPEN's
# mode -- and IS_OPEN's answer, 1 or 0, in the null-LOB field it set. CLOSE
# asks for neither and gets neither. The status follows. A 9.2 server answers a
# 9.2 client the same, but IS_OPEN in a single byte (#798, native_9i_lob_ops.pcap).
_O7_LOBOPS_REPLY: wire_schema.Schema = (
    ('const', bytes([TTI_RPA])),
    ('be2', 'locator_length'),
    ('bytes', 'locator', 'locator_length'),
    ('when', 'short_amount_present', (('n4', 'short_amount'),)),
    (
        'when',
        'null_lob_present',
        (
            ('only', 'thin', (('n4', 'flag'),)),
            ('only', 'o8i', (('n4', 'flag'),)),
            ('only', 'o9i', (('u8', 'flag'),)),
        ),
    ),
)
# The RPA in front of an 8i call's status (#2284): a ub2 count, four, and that
# many ub4s, the third the statement's cursor, as its status has it; then
# four bytes zero in every reply measured, the two ub2 lengths 10g sends
# there. 23 bytes on 8.1.7.
_O8I_RPA: wire_schema.Schema = (
    ('const', bytes([TTI_RPA])),
    ('n2', 'count'),
    ('each', 'parameters', 'count', (('n4', 'value'),)),
    ('pad', 4),
)
# Oracle 8i's status (PROTOCOL.md §19.12, #2284): the fields of 9i's short
# status (`_O7_STATUS_HEAD`, `_O7_STATUS_TAIL`) at fixed widths, as 8.1.7
# writes them, little-endian. A ub4 row count, the ORA code and the other
# ub2s, then single bytes: the SQL type, which is the command code (2 an
# INSERT, 47 a PL/SQL block), the fatal flag, flags, cursor options, UPI
# parameter and warnings -- 0x10 an UPDATE or DELETE with no WHERE, 0x20 a
# compile error, with 0x01 when any is set. The rowid follows (#1079), then
# the OS error, statement, call number, padding and iterations; the oerrdd, a
# ub2 length and the 13-byte rowid again after a DML; the counts of the three
# batch-error arrays, which 8i never fills (it has no array DML); and, when
# the code is set, the message. Read from 311 statuses of a live 8.1.7 with
# nothing left over.
_O8I_STATUS: wire_schema.Schema = (
    ('const', bytes([TTI_OER])),
    ('n4', 'rows'),
    ('n2', 'code'),
    ('n2', 'array_error'),
    ('n2', 'array_error_2'),
    ('n2', 'cursor'),
    ('n2', 'position'),
    ('u8', 'sql_type'),
    ('u8', 'fatal'),
    ('u8', 'flags'),
    ('u8', 'cursor_options'),
    ('u8', 'upi_param'),
    ('u8', 'warnings'),
    *_O8I_ROWID_FIELDS,
    ('n4', 'os_error'),
    ('u8', 'statement'),
    ('u8', 'call'),
    ('n2', 'padding'),
    ('n4', 'iterations'),
    ('n2', 'oerrdd_length'),
    ('when', 'oerrdd_length', (('value', 'oerrdd'),)),
    ('n4', 'batch_code_count'),
    ('n4', 'batch_offset_count'),
    ('n4', 'batch_message_count'),
    ('when', 'code', (('chr', 'message'),)),
)
_STA_OCI = wire_schema.compile_encoder(_STA, _OCI)
# The experimental 9i OALL8 describe (#792, #798): the OCI describe column
# (_DCB_COLUMN) without the byte 10g+ OCI has before each column and the one
# after it, behind the maximum row size, the column count and one byte (0x4b);
# then the start of the OCI trailer (_DESCRIBE_TRAILER) without its lead byte, a
# ub4 length (7) and the describe time, landing on the first row header or the
# status. A query's TTI_DCB carries it after a preamble; a REF CURSOR OUT bind
# carries it behind a lead byte (0x2c), with the cursor id, a ub2 indicator and a
# ub2 return code after it. Read from every live 9.2 describe the decode tests
# hold, and from native_9i_objects.pcap's typed columns: an object column's type
# name `0b 00 00 00 0b PYO_O798_PT` has a ub4 length, as on 10g, and the describe
# time follows it at once. Untyped columns alone also read as the type name's
# length a ub2 behind a reserved byte, which an object column disproved (#798).
_DCB_COLUMN_9I: wire_schema.Schema = tuple(
    (
        ('only', 'oci', tuple(_G for _G in _F[2] if _G != ('u8', 'marker')))
        if _F[:2] == ('only', 'oci') and ('u8', 'marker') in _F[2]
        else _F
    )
    for _F in _DCB_COLUMN
    if _F != ('only', 'oci', (('u8', 'reserved'),))
)
_O9I_DESCRIBE_BODY: wire_schema.Schema = (
    ('n4', 'max_row_size'),
    ('n4', 'count'),
    ('u8', 'columns_lead'),
    ('each', 'columns', 'count', _DCB_COLUMN_9I),
    ('n4', 'date_length'),
    ('value', 'date'),
)
_O9I_DESCRIBE: wire_schema.Schema = (
    ('const', bytes([TTI_DCB])),
    ('u8', 'preamble_length'),
    ('bytes', 'preamble', 'preamble_length'),
    *_O9I_DESCRIBE_BODY,
)
# A CURSOR(...) column's row cell is the same without the indicator and return
# code: `2c`, the describe, the cursor id, then the next cell or the RPA
# (native_9i_objects.pcap, #798).
_O9I_CURSOR_CELL: wire_schema.Schema = (
    ('u8', 'lead'),
    *_O9I_DESCRIBE_BODY,
    ('n4', 'cursor'),
)
_O9I_REFCURSOR_OUT: wire_schema.Schema = (
    *_O9I_CURSOR_CELL,
    ('n2', 'indicator'),
    ('n2', 'return_code'),
)
# The experimental 9i OALL8 bind prompt (#798): 8i's (_O8I_IOV) -- flags, the
# binds as a ub2 requests and a ub2 iterations (`iterations * 256 + requests`,
# 300 coming as `2c 00 01 00`, #2311), the iterations this time -- with a byte
# 8i lacks after the flags (5 for a block) and another, and 38 bytes where 8i
# has 8 (zero in a block's, not in a bound DML's), then one direction mask per
# bind. Read from every live 9.2 block reply the decode tests hold.
_O9I_IOV: wire_schema.Schema = (
    ('const', bytes([TTI_IOV])),
    ('u8', 'flags'),
    ('u8', 'kind'),
    ('bytes', 'opaque_3', 1),
    ('n2', 'requests'),
    ('n2', 'iterations'),
    ('n4', 'iterations_this_time'),
    ('bytes', 'opaque_12', 38),
    ('derive', 'binds', lambda v: v['iterations'] * 256 + v['requests']),
    ('bytes', 'directions', 'binds'),
)
# The experimental 9i OALL8 row header (#798), 50 bytes and two tails: the flags,
# the columns, the rows the call asked for, the length of the column bit vector
# that follows (a ub2 at 26 -- telling it from the byte after the header is not
# possible, three columns all sent being a vector of 0x07, the TTI_RXD token) and
# of the rowid after it (a ub2 at 42: SELECT ... FOR UPDATE sends the 13-byte
# rowid of the row it locks). Its other bytes are kept as they come: pointers and
# fields no capture has explained. Read from every live 9.2 row stream the decode
# tests hold.
_O9I_RXH: wire_schema.Schema = (
    ('const', bytes([TTI_RXH])),
    ('u8', 'flags'),
    ('bytes', 'opaque_2', 2),
    ('n4', 'columns'),
    ('n4', 'rows_asked'),
    ('bytes', 'opaque_12', 14),
    ('n2', 'vector_length'),
    ('bytes', 'opaque_28', 14),
    ('n2', 'rowid_length'),
    ('bytes', 'opaque_44', 6),
    ('bytes', 'vector', 'vector_length'),
    ('bytes', 'rowid', 'rowid_length'),
)
# The experimental 9i OALL8 status (#798): 8i's (_O8I_STATUS) from its row count
# through its warnings, behind the call status (a ub4: 2 a DML, 4 a describe-only
# execute, 5 a bound one's first parse) and a one-byte sequence the 10g+ OER
# carries there too, the rowid at a 9.2 client's alignment (_O8I_ROWID_FIELDS).
# Then OCI's own tail: the OS error, statement and
# call numbers, padding and iterations as on 8i, a fixed 310 (the constant 11g's
# OCI status carries at 56), the oerrdd's pointer and ub4 length, and the three
# batch-error arrays' pointers and counts; after them the oerrdd itself (a ub2
# size and the 13-byte rowid, as a DML leaves it), the arrays' values -- codes as
# ub2s, row offsets as ub4s, messages each a ub4 length, the text and six bytes
# -- and, when the code is set, the message. Read whole, nothing left, from every
# live 9.2 status the decode tests hold and every status in the native captures;
# a DML's, committed or not, bound or not, is 150 bytes with the oerrdd at 134.
_O9I_STATUS_HEAD: wire_schema.Schema = (
    _O8I_STATUS[0],
    ('n4', 'call_status'),
    ('u8', 'sequence'),
    *_O8I_STATUS[1 : _O8I_STATUS.index(('n4', 'os_error'))],
)
_O9I_STATUS: wire_schema.Schema = (
    *_O9I_STATUS_HEAD,
    ('n4', 'os_error'),
    ('u8', 'statement'),
    ('u8', 'call'),
    ('n2', 'padding'),
    ('n4', 'iterations'),
    ('n4', 'constant_310'),
    ('pad', 12),
    ('ptr', 'oerrdd_present'),
    ('n4', 'oerrdd_length'),
    ('pad', 4),
    ('ptr', 'batch_codes_present'),
    ('n4', 'batch_code_count'),
    ('pad', 4),
    ('ptr', 'batch_offsets_present'),
    ('n4', 'batch_offset_count'),
    ('pad', 4),
    ('ptr', 'batch_messages_present'),
    ('n4', 'batch_message_count'),
    ('pad', 4),
    ('when', 'oerrdd_length', (('n2', 'oerrdd_size'), ('value', 'oerrdd'))),
    ('each', 'batch_codes', 'batch_code_count', (('n2', 'code'),)),
    ('each', 'batch_offsets', 'batch_offset_count', (('n4', 'offset'),)),
    (
        'each',
        'batch_messages',
        'batch_message_count',
        (('n4', 'length'), ('chr', 'text'), ('pad', 6)),
    ),
    ('when', 'code', (('chr', 'message'),)),
)
_OAC_FROM_THIN = wire_schema.compile_decoder(_OAC, _THIN)
_OAC_FROM_OCI = wire_schema.compile_decoder(_OAC, _OCI)
_O7_OAC_THIN = wire_schema.compile_encoder(_O7_OAC, _THIN)
_O7_DESCRIBE_FROM_THIN = wire_schema.compile_decoder(_O7_DESCRIBE, _THIN)
_O7_STATUS_HEAD_FROM_THIN = wire_schema.compile_decoder(_O7_STATUS_HEAD, _THIN)
_O7_STATUS_TAIL_FROM_THIN = wire_schema.compile_decoder(_O7_STATUS_TAIL, _THIN)
# The 10g+ OER (TTI_OER return-status token, decode_token_oer): 9i's short
# status (`_O7_STATUS_HEAD`, `_O7_STATUS_TAIL`) with its two missing leading
# fields -- the call status and the end-to-end sequence number -- and the
# version conditionals 9i never meets. `flags` is a ub2 at 10g and 11g (#1995)
# and one byte from 12.1; the tail gains the extended ub4 error number and ub8
# rowcount 12c+ adds, and the ub4 sql type + ub4 server checksum 20.1+ adds,
# both read by the SERVER's release, not the negotiated one (#1145). The caller
# passes `flags_ub2` / `flags_u8` and `ext_12c` / `ext_20_1` in `given`. The
# message DALC stays out of the schema: it is read best-effort (an imprecise
# walk of a terminator's padding may leave it short, #849), so the schema reads
# only the frame and decode_token_oer reads the message from what is left.
_OER_HEAD: wire_schema.Schema = (
    _O7_STATUS_HEAD[0],
    ('n4', 'call_status'),
    ('n4', 'sequence'),
    *_O7_STATUS_HEAD[1:9],
    # `flags`, consumed but unread: a ub2 at 10g and 11g (`01 20` for a warning,
    # two bytes), one byte from 12.1 -- distinct names so each width round-trips
    # on its own (the warning bit is read later, as `warnings`).
    ('when', 'flags_ub2', (('n2', 'flags_wide'),)),
    ('when', 'flags_u8', (('u8', 'flags_narrow'),)),
    *_O7_STATUS_HEAD[10:],
)
_OER_TAIL: wire_schema.Schema = (
    *_O7_STATUS_TAIL[:-1],
    ('when', 'ext_12c', (('n4', 'ext_error_code'), ('n8', 'ext_rowcount'))),
    ('when', 'ext_20_1', (('n4', 'ext_sql_type'), ('n4', 'ext_checksum'))),
)
_OER_HEAD_FROM_THIN = wire_schema.compile_decoder(_OER_HEAD, _THIN)
_OER_TAIL_FROM_THIN = wire_schema.compile_decoder(_OER_TAIL, _THIN)
_O7_RXH_FROM_THIN = wire_schema.compile_decoder(_O7_RXH, _THIN)
_O7_RXH_THIN = wire_schema.compile_encoder(_O7_RXH, _THIN)
_O7_VECTORS_FROM_THIN = wire_schema.compile_decoder(_O7_VECTORS, _THIN)
_O7_VECTORS_THIN = wire_schema.compile_encoder(_O7_VECTORS, _THIN)
_O7_CELL_FROM_THIN = wire_schema.compile_decoder(_O7_CELL, _THIN)
_O7_LOB_CELL_FROM_THIN = wire_schema.compile_decoder(_O7_LOB_CELL, _THIN)
_O7_EMPTY_CELL_FROM_THIN = wire_schema.compile_decoder(_O7_EMPTY_CELL, _THIN)
_O7_LONG_CELL_FROM_THIN = wire_schema.compile_decoder(_O7_LONG_CELL, _THIN)
_O7_IOV_FROM_THIN = wire_schema.compile_decoder(_O7_IOV, _THIN)
_O7_LOBOPS_THIN = wire_schema.compile_encoder(_O7_LOBOPS, _THIN)
_O7_LOBOPS_REPLY_FROM_THIN = wire_schema.compile_decoder(_O7_LOBOPS_REPLY, _THIN)
_O7_LOBOPS_O8I = wire_schema.compile_encoder(_O7_LOBOPS, _O8I)
_O7_LOBOPS_REPLY_FROM_O8I = wire_schema.compile_decoder(_O7_LOBOPS_REPLY, _O8I)
_O8I_RPA_FROM_O8I = wire_schema.compile_decoder(_O8I_RPA, _O8I)
_O8I_STATUS_FROM_O8I = wire_schema.compile_decoder(_O8I_STATUS, _O8I)
_O8I_DESCRIBE_FROM_O8I = wire_schema.compile_decoder(_O8I_DESCRIBE, _O8I)
_O7_RXH_FROM_O8I = wire_schema.compile_decoder(_O7_RXH, _O8I)
_O7_VECTORS_FROM_O8I = wire_schema.compile_decoder(_O7_VECTORS, _O8I)
_O8I_CELL_FROM_O8I = wire_schema.compile_decoder(_O8I_CELL, _O8I)
_O8I_NULL_CELL_FROM_O8I = wire_schema.compile_decoder(_O8I_NULL_CELL, _O8I)
_O8I_LONG_CELL_FROM_O8I = wire_schema.compile_decoder(_O8I_LONG_CELL, _O8I)
_O8I_LOB_CELL_FROM_O8I = wire_schema.compile_decoder(_O8I_LOB_CELL, _O8I)
_O8I_ROWID_CELL_FROM_O8I = wire_schema.compile_decoder(_O8I_ROWID_CELL, _O8I)
_O8I_UROWID_CELL_FROM_O8I = wire_schema.compile_decoder(_O8I_UROWID_CELL, _O8I)
_O8I_IOV_FROM_O8I = wire_schema.compile_decoder(_O8I_IOV, _O8I)
_O8I_OUT_CELL_FROM_O8I = wire_schema.compile_decoder(_O8I_OUT_CELL, _O8I)
_O8I_OUT_UNASSIGNED_FROM_O8I = wire_schema.compile_decoder(_O8I_OUT_UNASSIGNED, _O8I)
_AUTH_HEAD_FROM_THIN = wire_schema.compile_decoder(_AUTH_HEAD, _THIN)
_AUTH_HEAD_THIN = wire_schema.compile_encoder(_AUTH_HEAD, _THIN)
_AUTH_HEAD_FROM_OCI = wire_schema.compile_decoder(_AUTH_HEAD, _OCI)
_AUTH_PAIR_OCI = wire_schema.compile_encoder(_AUTH_PAIR, _OCI)
_AUTH_FROM_OCI = wire_schema.compile_decoder(
    (*_AUTH_HEAD, ('each', 'pairs', 'pair_count', _AUTH_PAIR)), _OCI
)
_AUTH_O8I = wire_schema.compile_encoder(
    (*_AUTH_HEAD, ('each', 'pairs', 'pair_count', _AUTH_PAIR)), _O8I
)
_AUTH_THIN = wire_schema.compile_encoder(
    (*_AUTH_HEAD, ('each', 'pairs', 'pair_count', _AUTH_PAIR)), _THIN
)
# A pre-10g login reply (#2284, #2342): the RPA, a ub2 pair count --
# AUTH_SESSKEY alone at phase one, 22 pairs (8.1.7) or 23 (9.2.0.4) at phase
# two -- and the pairs; an empty value is a zero length and no value, as
# AUTH_CAPABILITY_TABLE's. The status follows. 8i's at the 8i codec's widths,
# 9i's thin-coded.
_PRE10_AUTH_REPLY: wire_schema.Schema = (
    ('const', bytes([TTI_RPA])),
    ('n2', 'pair_count'),
    ('each', 'pairs', 'pair_count', _AUTH_PAIR),
)
_PRE10_AUTH_REPLY_FROM_O8I = wire_schema.compile_decoder(_PRE10_AUTH_REPLY, _O8I)
_PRE10_AUTH_REPLY_FROM_THIN = wire_schema.compile_decoder(_PRE10_AUTH_REPLY, _THIN)


def decode_auth_head(
    payload: bytes, field_version: int
) -> tuple[dict[str, Any], bytes]:
    """A thin OSESSKEY or AUTH's head (_AUTH_HEAD), and the pairs behind it."""
    # At fv >= 23.1 EXT 1 the OAUTH (phase-two AUTH) header carries a `0`
    # has-user pointer byte before the `0x01` marker (PROTOCOL.md §20.3), which
    # the phase-one OSESSKEY does not -- so it is detected, not assumed by
    # subtype: the byte after the sequence is not the marker.
    prefixed = field_version >= FIELD_VERSION_12_1
    return _AUTH_HEAD_FROM_THIN(
        payload,
        {
            'has_user_ptr': field_version >= FIELD_VERSION_23_1_EXT_1
            and payload[3:4] != b'\x01',
            'user_prefixed': prefixed,
            'user_raw': not prefixed,
        },
    )


def encode_auth_pair_oci(key: bytes, value: bytes, flags: int = 0) -> bytes:
    """One key-value pair as the OCI login's request and reply carry it
    (_AUTH_PAIR), each length as long as its bytes."""
    return _AUTH_PAIR_OCI(
        {
            'key_length': len(key),
            'key': key,
            'value_length': len(value),
            'value': value,
            'flags': flags,
        }
    )


def decode_auth_oci_head(payload: bytes) -> dict[str, Any]:
    """An OCI OSESSKEY or AUTH's head (_AUTH_HEAD), its pairs left unread."""
    return _AUTH_HEAD_FROM_OCI(payload, {'user_prefixed': True, 'user_raw': False})[0]


def decode_auth_oci(payload: bytes) -> dict[str, Any]:
    """An OCI OSESSKEY or AUTH's fields and pairs (_AUTH_HEAD, _AUTH_PAIR)."""
    return _AUTH_FROM_OCI(payload, {'user_prefixed': True, 'user_raw': False})[0]


_LOBOPS_HEAD_FROM_THIN = wire_schema.compile_decoder(_LOBOPS_HEAD, _THIN)
_LOBOPS_HEAD_THIN = wire_schema.compile_encoder(_LOBOPS_HEAD, _THIN)
_LOBOPS_READ_FROM_OCI = wire_schema.compile_decoder(_LOBOPS_READ, _OCI)
_LOBOPS_READ_FROM_OCI_WIDE = wire_schema.compile_decoder(_LOBOPS_READ, _OCI_WIDE)
_LOB_READ_REPLY_THIN = wire_schema.compile_encoder(_LOB_READ_REPLY, _THIN)
_LOB_READ_REPLY_OCI = wire_schema.compile_encoder(_LOB_READ_REPLY, _OCI)
_CLOSE_CURSORS_THIN = wire_schema.compile_encoder(_CLOSE_CURSORS, _THIN)
_CLOSE_CURSORS_FROM_THIN = wire_schema.compile_decoder(_CLOSE_CURSORS, _THIN)
_PIGGYBACK_HEAD_THIN = wire_schema.compile_encoder(_PIGGYBACK_HEAD, _THIN)
_CLOSE_CURSORS_FROM_OCI = wire_schema.compile_decoder(_CLOSE_CURSORS, _OCI)
_CLOSE_CURSORS_O8I = wire_schema.compile_encoder(_CLOSE_CURSORS, _O8I)
_O8I_ALL8_O8I = wire_schema.compile_encoder(_O8I_ALL8, _O8I)
_O8I_ALL8_O9I = wire_schema.compile_encoder(_O8I_ALL8, _O9I)
_O9I_STATUS_FROM_O9I = wire_schema.compile_decoder(_O9I_STATUS, _O9I)
_O9I_STATUS_HEAD_FROM_O9I = wire_schema.compile_decoder(_O9I_STATUS_HEAD, _O9I)
# A 9.2 OUT bind's cell is 8i's row cell, its never-assigned one 8i's, and its
# LONG cell 8i's, at a 9.2 client's widths (#798).
_O8I_CELL_FROM_O9I = wire_schema.compile_decoder(_O8I_CELL, _O9I)
_O8I_OUT_UNASSIGNED_FROM_O9I = wire_schema.compile_decoder(_O8I_OUT_UNASSIGNED, _O9I)
_O8I_LONG_CELL_FROM_O9I = wire_schema.compile_decoder(_O8I_LONG_CELL, _O9I)
_O7_LOBOPS_REPLY_FROM_O9I = wire_schema.compile_decoder(_O7_LOBOPS_REPLY, _O9I)
# The session-state RPA ahead of a 9.2 status is 8i's (_O8I_RPA): five ub4s, the
# third the statement's cursor, and four bytes -- 27 (#798).
_O8I_RPA_FROM_O9I = wire_schema.compile_decoder(_O8I_RPA, _O9I)
_O9I_IOV_FROM_O9I = wire_schema.compile_decoder(_O9I_IOV, _O9I)
_O9I_RXH_FROM_O9I = wire_schema.compile_decoder(_O9I_RXH, _O9I)
_O9I_ROWID_CELL_FROM_O9I = wire_schema.compile_decoder(_O9I_ROWID_CELL, _O9I)
_O9I_LOB_CELL_FROM_O9I = wire_schema.compile_decoder(_O9I_LOB_CELL, _O9I)
_O9I_OBJECT_CELL_FROM_O9I = wire_schema.compile_decoder(_O9I_OBJECT_CELL, _O9I)
_O9I_UROWID_CELL_FROM_O9I = wire_schema.compile_decoder(_O9I_UROWID_CELL, _O9I)
# The describe's columns are the OCI dialect's own fields, read with its codec.
_O9I_DESCRIBE_FROM_OCI = wire_schema.compile_decoder(_O9I_DESCRIBE, _OCI)
_O9I_REFCURSOR_OUT_FROM_OCI = wire_schema.compile_decoder(_O9I_REFCURSOR_OUT, _OCI)
_O9I_CURSOR_CELL_FROM_OCI = wire_schema.compile_decoder(_O9I_CURSOR_CELL, _OCI)
_OAC_OCI = wire_schema.compile_encoder(_OAC, _OCI)
_O7_LOBOPS_O9I = wire_schema.compile_encoder(_O7_LOBOPS, _O9I)
_CLOSE_CURSORS_O9I = wire_schema.compile_encoder(_CLOSE_CURSORS, _O9I)
_OBJECT_FRAME_THIN = wire_schema.compile_encoder(_OBJECT_FRAME, _THIN)
_OBJECT_FRAME_OCI = wire_schema.compile_encoder(_OBJECT_FRAME, _OCI)
_LOB_CELL_THIN = wire_schema.compile_encoder(_LOB_CELL, _THIN)
_LOB_CELL_OCI = wire_schema.compile_encoder(_LOB_CELL, _OCI)
_ROWID_CELL_THIN = wire_schema.compile_encoder(_ROWID_CELL, _THIN)
_ROWID_CELL_OCI = wire_schema.compile_encoder(_ROWID_CELL, _OCI)
_ROWID_CELL_FROM_THIN = wire_schema.compile_decoder(_ROWID_CELL, _THIN)
_DCB_COLUMN_THIN = wire_schema.compile_encoder(_DCB_COLUMN, _THIN)
_DCB_COLUMN_OCI = wire_schema.compile_encoder(_DCB_COLUMN, _OCI)
_DCB_COLUMN_FROM_OCI = wire_schema.compile_decoder(_DCB_COLUMN, _OCI)
_DCB_COLUMN_FROM_THIN = wire_schema.compile_decoder(_DCB_COLUMN, _THIN)
_LONG_CELL_THIN = wire_schema.compile_encoder(_LONG_CELL, _THIN)
_LONG_CELL_OCI = wire_schema.compile_encoder(_LONG_CELL, _OCI)
_LONG_CELL_FROM_THIN = wire_schema.compile_decoder(_LONG_CELL, _THIN)


def _long_content(value: object) -> bytes | None:
    # A LONG cell's content: str as UTF-8 (LONG), bytes as they are (LONG RAW).
    if value is None or isinstance(value, (bytes, bytearray)):
        return None if value is None else bytes(value)
    return (value if isinstance(value, str) else str(value)).encode('utf-8')


_DESCRIBE_TRAILER_THIN = wire_schema.compile_encoder(_DESCRIBE_TRAILER, _THIN)
_DESCRIBE_TRAILER_OCI = wire_schema.compile_encoder(_DESCRIBE_TRAILER, _OCI)
_REFCURSOR_OUT_THIN = wire_schema.compile_encoder(_REFCURSOR_OUT, _THIN)
_REFCURSOR_OUT_OCI = wire_schema.compile_encoder(_REFCURSOR_OUT, _OCI)


def _describe_trailer(*, oci: bool, mdbz: int = 0) -> bytes:
    # The describe's trailer (_DESCRIBE_TRAILER) as the session's field version
    # has it, in either dialect.
    has_key = _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_11_2
    if not oci:
        return _DESCRIBE_TRAILER_THIN(
            {
                'date': b'',
                'dcbflag': 0,
                'dcbmdbz': mdbz,
                'dcbmnpr': 0,
                'dcbmxpr': 0,
                'has_query_key': has_key,
                'query_key': b'',
            }
        )
    return _DESCRIBE_TRAILER_OCI(
        {
            'date_lead': 0,
            'date_length': _OCI_DCB_DATE_LEN,
            'date': bytes(_OCI_DCB_DATE_LEN),
            'dcbflag': 0,
            'dcbmdbz': mdbz,
            'dcbmnpr': 0,
            'dcbmxpr': 0,
            'has_query_key': has_key,
            'query_key_length': 0,
        }
    )


_ALL8_HEAD_THIN = wire_schema.compile_encoder(_ALL8_HEAD, _THIN)
_ALL8_HEAD_FROM_THIN = wire_schema.compile_decoder(_ALL8_HEAD, _THIN)
_ALL8_HEAD_FROM_OCI = wire_schema.compile_decoder(_ALL8_HEAD, _OCI)
_ALL8_HEAD_FROM_OCI_WIDE = wire_schema.compile_decoder(_ALL8_HEAD, _OCI_WIDE)
_FETCH_THIN = wire_schema.compile_encoder(_FETCH, _THIN)
_FETCH_FROM_THIN = wire_schema.compile_decoder(_FETCH, _THIN)
_FETCH_FROM_OCI = wire_schema.compile_decoder(_FETCH, _OCI)
_EXEC_BY_CURSOR_FROM_THIN = wire_schema.compile_decoder(_EXEC_BY_CURSOR, _THIN)
_EXEC_BY_CURSOR_FROM_OCI = wire_schema.compile_decoder(_EXEC_BY_CURSOR, _OCI)
_LOGOFF_REPLY_THIN = wire_schema.compile_encoder(_LOGOFF_REPLY, _THIN)
_LOB_DATA_THIN = wire_schema.compile_encoder(_LOB_DATA, _THIN)
_LOB_DATA_OCI = wire_schema.compile_encoder(_LOB_DATA, _OCI)
_SYNC_THIN = wire_schema.compile_encoder(_SYNC, _THIN)
_SYNC_FROM_THIN = wire_schema.compile_decoder(_SYNC, _THIN)
_SYNC_OCI = wire_schema.compile_encoder(_SYNC, _OCI)
_ROWCOUNTS_BLOCK_THIN = wire_schema.compile_encoder(_ROWCOUNTS_BLOCK, _THIN)
_CREATE_TEMP_RESPONSE_THIN = wire_schema.compile_encoder(_CREATE_TEMP_RESPONSE, _THIN)
_IMPLICIT_RESULTS_THIN = wire_schema.compile_encoder(_IMPLICIT_RESULTS, _THIN)
_SESSION_STATE_RESPONSE_THIN = wire_schema.compile_encoder(
    _SESSION_STATE_RESPONSE, _THIN
)
_PRO_FROM_THIN = wire_schema.compile_decoder(_PRO, _THIN)
_SYNC_PAIR_OCI = wire_schema.compile_encoder(_SYNC_PAIR, _OCI)


def _sync_pairs(pairs: list[tuple[int, str]], slot: str) -> list[dict[str, Any]]:
    # The SYNC pairs' fields for (keyword, text) pairs: thin carries the value
    # as text, OCI -- as sqlplus reads it -- as binary (#2064).
    other = 'binary' if slot == 'text' else 'text'
    items = []
    for keyword, text in pairs:
        value = text.encode('utf-8')
        item: dict[str, Any] = {f'{slot}_length': len(value), f'{other}_length': 0}
        if value:
            item[slot] = value
        item['keyword'] = keyword
        items.append(item)
    return items


def _sync_fields(pairs: list[tuple[int, str]], slot: str) -> dict[str, Any]:
    # The SYNC piggyback's fields: one DTY and the two length bytes, constants
    # as 23ai and 18c send them, whatever the pairs.
    return {
        'dty_count': 1,
        'dty_length': 0x10,
        'pair_count': len(pairs),
        'pairs_length': 0x16,
        'pairs': _sync_pairs(pairs, slot),
        'flags': 0,
    }


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
    # Per-column metadata (_DCB_COLUMN), read with the thin decoder up to the
    # 23ai annotation map and vector descriptor, which stay here because the
    # annotations are a count sent twice around pointers (not a schema shape) and
    # the schema marks their slot with a raw field. The schema's version
    # conditionals ride in `given`: `oaccolid` follows max_size from 12.2, the
    # sb1 (not variable) scale and `oaccolid` are what 12c+ changed from 11g
    # (oracledb base.pyx _process_metadata); `uds flags` is an 11g addition a 10g
    # describe omits -- reading a phantom ub4 there desynced the row (#84, #826);
    # the SQL-domain schema and name are a 23c addition, each a DALC string, `00`
    # for no domain, not the plain ub4s that only survived the empty case (#53).
    FieldVersion = _DECODE_FIELD_VERSION.get()
    Given = {
        'has_oaccolid': FieldVersion >= FIELD_VERSION_12_2,
        'has_uds': FieldVersion >= FIELD_VERSION_11_2,
        'has_domain': FieldVersion >= FIELD_VERSION_23_1,
        # The annotation map and vector descriptor are read below, not by the
        # schema (its `annotations` is a raw slot), so its vector branch is off.
        'has_vector': False,
    }
    (Field, Rest) = _DCB_COLUMN_FROM_THIN(Rest, Given)
    DataType = Field['data_type']
    Precision = Field['precision']
    DataScale = Field['scale']
    BufferSize = Field['buffer_size']
    # An object (ADT, type 109) / collection column's 16-byte type OID, kept (not
    # skipped) so the row decoder can tie the value to its attribute layout (#115).
    TypeOid = Field.get('toid', b'')
    Charset = Field['charset']
    Csfrm = Field['csfrm']
    MaxSize = Field['max_size']
    NullOk = Field['null_ok']
    ColName = Field.get('name', b'')
    TypeSchema = Field.get('type_schema', b'')  # owner of the type (ADT)
    TypeName = Field.get('type_name', b'')  # the type's name (ADT)
    # `uds flags` bits mark a JSON / OSON column (#826); absent before 11g.
    UdsFlags = Field.get('uds_flags', 0)
    DomainSchema = Field.get('domain_schema', b'')
    DomainName = Field.get('domain_name', b'')
    Annotations = {}
    VecDims: int | None
    VecFormat: int | None
    VecFlags: int | None
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_23_1_EXT_1:  # 23ai (#89)
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
        'is_json': bool(UdsFlags & _UDS_FLAGS_IS_JSON),
        'is_oson': bool(UdsFlags & _UDS_FLAGS_IS_OSON),
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
    # 23ai describes a BOOLEAN column with length 1 (measured). A zero here tells
    # the client the column sends no bytes at all, and it then reads the value's
    # byte as the next column's type (#740).
    TNS_TYPE_BOOLEAN: 1,
    # ROWID / UROWID / object (ADT, which XMLType rides as) all carry data and
    # all reported 0 here, so a client read nothing for them and lost its place
    # in the row -- the same fault as BOOLEAN and VECTOR. Measured on live 23ai
    # (#887): a ROWID column describes as 1, a UROWID as 292, and an object
    # column as 2000, the same figure a plain object and an XMLType both report.
    TNS_TYPE_RID: 1,
    TNS_TYPE_UROWID: 292,
    TNS_TYPE_ADT: 2000,
    # 23ai describes a VECTOR column with length 8200, whatever the vector's
    # dimension or element format (measured: `02 20 08` in the describe of a
    # 3-element float32 column). Same failure mode as BOOLEAN above and the same
    # cost: with 0 here the reference client builds a fetch variable that reads
    # no bytes, consumes nothing from the row, and takes the following byte for
    # a message type (#887).
    TNS_TYPE_VECTOR: 8200,
    # A native JSON column measures the same 8200 on a live 23ai (`02 20 08` in
    # the describe), and costs the same when reported as 0: the reference client
    # reads no bytes for the column, so the OSON image the row carries is taken
    # for the next message (#826). The fourth time a zero here has bitten.
    TNS_TYPE_JSON: 8200,
    # A nested cursor column (`select ..., CURSOR(select ...)`) describes as 5
    # on a live 23ai. Zero here is the same trap as BOOLEAN, ROWID, VECTOR and
    # JSON before it -- the FIFTH time: the client reads no bytes for the
    # column and takes the value's first byte for the next token (#826).
    TNS_TYPE_REFCURSOR: 5,
    # A BFILE column describes as 530 on a live 23ai (measured against
    # `select BFILENAME('D','f.txt') from dual`, whose describe also carries
    # charset 0 / csfrm 0). Zero here is the same trap as BOOLEAN, ROWID,
    # VECTOR, JSON and REF CURSOR before it -- the SIXTH time: the reference
    # client reads no bytes for the column and takes the locator's first byte
    # for the next message type (#1102).
    TNS_TYPE_BFILE: 530,
}


# The types that carry a declared maximum size in a describe. Everything else
# reports 0 there, and a client uses that to decide whether the column HAS an
# internal size at all: the reference client returns `cursor.description`'s
# internal_size only when max_size is non-zero, so reporting a figure for a
# NUMBER or a DATE gives it a size where a live server gives it None (#905).
_DESCRIBE_SIZED_TYPES = frozenset(
    {
        TNS_TYPE_VARCHAR,
        TNS_TYPE_CHAR,
        TNS_TYPE_RAW,
        TNS_TYPE_LONG,
        TNS_TYPE_LONGRAW,
    }
)


def describe_max_size(col: ColumnMeta) -> int:
    """The maximum size to describe ``col`` with: its declared size for the types
    that have one, and 0 for every other type, matching a live server."""
    return col.max_size if col.data_type in _DESCRIBE_SIZED_TYPES else 0


def describe_wire_length(col: ColumnMeta) -> int:
    """The buffer length to describe ``col`` with.

    The backend's own figure when it has one, else the length a real server
    reports for that type. Zero survives only for a type where it is true.
    """
    if col.data_length:
        return col.data_length
    return _DESCRIBE_WIRE_LENGTH.get(col.data_type, 0)


# The describe types a CLOB may replace and still be served inline, and the ones
# a BLOB may. Outside these pairs a type change is an ordinary re-describe and the
# new type's own framing applies.
_INLINE_LONG_FROM = {
    TNS_TYPE_CLOB: frozenset({TNS_TYPE_CHAR, TNS_TYPE_VARCHAR, TNS_TYPE_LONG}),
    TNS_TYPE_BLOB: frozenset({TNS_TYPE_RAW, TNS_TYPE_LONGRAW}),
    # A VECTOR defined as character data is served as its TEXT form, inline,
    # instead of the binary image (#1107). Measured on 23ai: a client whose
    # output type handler asks for LONG gets `[16,[1,3,5],[1.0E+000,0,5.0E+000]]`.
    TNS_TYPE_VECTOR: frozenset({TNS_TYPE_CHAR, TNS_TYPE_VARCHAR, TNS_TYPE_LONG}),
    # And a JSON column the same way: the document as compact JSON text, not the
    # OSON image (#1106). Measured on 23ai: `{"name":"John","city":"Delhi"}`.
    TNS_TYPE_JSON: frozenset({TNS_TYPE_CHAR, TNS_TYPE_VARCHAR, TNS_TYPE_LONG}),
}


def json_as_text(value: object) -> str:
    """A JSON document as 23ai renders it for a character define (#1106).

    Compact -- no space after ``:`` or ``,`` -- which is what a live server
    sends, and what the client's own converter then parses.
    """
    import json

    return json.dumps(value, separators=(',', ':'), ensure_ascii=False)


def vector_as_text(value: 'SparseVector | Sequence') -> str:
    """A VECTOR's text form, as 23ai renders it for a character define (#1107).

    Dense is ``[e, e, ...]``, sparse ``[dims, [indices], [values]]``. An integer
    element (an INT8 vector) prints as an integer; a float element prints in
    scientific form with a three-digit exponent and at least one decimal
    (``1.0E+000``, ``2.5E-001``), except an exact zero, which prints bare.
    Measured against 23ai for INT8, FLOAT64 and sparse columns.
    """

    def element(item: object) -> str:
        if isinstance(item, int) and not isinstance(item, bool):
            return str(item)
        number = float(item)  # type: ignore[arg-type]
        if number == 0:
            return '0'
        (mantissa, _, exponent) = f'{number:.10E}'.partition('E')
        mantissa = mantissa.rstrip('0')
        if mantissa.endswith('.'):
            mantissa += '0'
        return f'{mantissa}E{exponent[0]}{int(exponent[1:]):03d}'

    if isinstance(value, SparseVector):
        indices = ','.join(str(int(i)) for i in value.indices)
        values = ','.join(element(v) for v in value.values)
        return f'[{value.num_dimensions},[{indices}],[{values}]]'
    return '[' + ','.join(element(v) for v in value) + ']'


def _effective_describe_type(col: ColumnMeta) -> int:
    # The type a client's fetch variable holds for ``col``. Normally the described
    # type -- but a column already being served inline as LONG stands in the
    # client as LONG (RAW), not as the LOB the describe named.
    if col.inline_long_csfrm is None:
        return col.data_type
    return TNS_TYPE_LONGRAW if col.data_type == TNS_TYPE_BLOB else TNS_TYPE_LONG


def inline_long_after_type_change(
    columns: list[ColumnMeta], previous: list[ColumnMeta]
) -> list[ColumnMeta]:
    """``columns``, with every column a cached cursor must keep serving inline.

    When a query is re-executed and a column's type has changed to CLOB or BLOB
    while the describe it replaces said CHAR / VARCHAR / LONG (or RAW / LONG RAW),
    a real server reports the new LOB type but still sends the value inline, as
    LONG (RAW) in the charset form the client already had -- the same shape a
    define of a LOB as string / bytes produces. The reference client relies on
    that: it rewrites such a column's fetch type itself and so asks for no LOB
    read. Mark those columns; :func:`_thin_column_value` then serves them inline
    and :func:`oci_lob_contents` queues nothing for them (#826).
    """
    # The charset form the client's variable holds, which for a column already
    # being served inline is the one it was given then -- not the LOB describe
    # that replaced it.
    return _mark_inline_long(
        columns,
        [
            (
                _effective_describe_type(col),
                col.csfrm if col.inline_long_csfrm is None else col.inline_long_csfrm,
            )
            for col in previous
        ],
    )


def inline_long_for_defines(
    columns: list[ColumnMeta], defines: Sequence[tuple[int, int]]
) -> list[ColumnMeta]:
    """``columns``, with every column the client's own define asks for inline.

    A client that fetches a LOB as string / bytes -- an ``outputtypehandler``
    returning a VARCHAR / RAW variable for a CLOB / BLOB column -- reads the
    describe, then re-executes with the DEFINE option and one OAC per column
    saying what it wants. Given LONG (RAW) there, a real server sends the value
    inline in the row instead of a locator, and the client issues no LOB read.
    ``defines`` is ``ExecRequest.define_types``, the ``(tns_type, csfrm)`` of each
    of those OACs (#826).
    """
    return _mark_inline_long(columns, defines)


def _mark_inline_long(
    columns: list[ColumnMeta], wanted: Sequence[tuple[int, int]]
) -> list[ColumnMeta]:
    # Mark each LOB column the client is going to read as LONG (RAW), carrying the
    # charset form its bytes must use. ``wanted`` is the (type, csfrm) the client
    # holds for each column, however it came to hold it.
    if not wanted:
        return columns
    out = list(columns)
    for i, col in enumerate(columns):
        if i >= len(wanted):
            break
        allowed = _INLINE_LONG_FROM.get(col.data_type)
        if allowed and wanted[i][0] in allowed:
            out[i] = replace(col, inline_long_csfrm=wanted[i][1])
    return out


def _encode_dcb_column(col: ColumnMeta, position: int) -> bytes:
    # Inverse of _decode_dcb_column (_DCB_COLUMN), in the layout the negotiated
    # field version's client reads: 12.1 carries the scale as one signed byte,
    # 12.2 adds the oaccolid, 11.2 the uds flags (a 10g describe ends the
    # column at its position, #84, #814), 23.1 the SQL domain and 23.1 EXT 1
    # (23ai fv24) the annotations and vector descriptor (§20.5). Fields the
    # client skips are well-formed zeros.
    field_version = _ENCODE_FIELD_VERSION.get()
    return _DCB_COLUMN_THIN(
        {
            'data_type': col.data_type,
            'flags': 0,
            'precision': col.precision & 0xFF,
            'scale': col.scale,
            'buffer_size': describe_wire_length(col),
            'max_array': 0,
            'cont_flags': 0,
            # For an ADT / REF column the referenced type's OID (#494).
            'toid_length': len(col.type_oid),
            'toid': col.type_oid,
            'version': 0,
            'charset': col.charset,
            'csfrm': col.csfrm,
            'max_size': describe_max_size(col),
            'has_oaccolid': field_version >= FIELD_VERSION_12_2,
            'oaccolid': 0,
            'null_ok': col.null_ok,
            'v7_name_length': 0,
            'name_length': len(col.name),
            'name': col.name,
            'type_schema_length': len(col.type_schema),  # an ADT's owner
            'type_schema': col.type_schema,
            'type_name_length': len(col.type_name),
            'type_name': col.type_name,
            'position': position,
            # The uds flags (11g) mark a JSON / OSON column (#826).
            'has_uds': field_version >= FIELD_VERSION_11_2,
            'uds_flags': (_UDS_FLAGS_IS_JSON if col.is_json else 0)
            | (_UDS_FLAGS_IS_OSON if col.is_oson else 0),
            'has_domain': field_version >= FIELD_VERSION_23_1,
            'domain_schema_length': len(col.domain_schema),
            'domain_schema': col.domain_schema,
            'domain_name_length': len(col.domain_name),
            'domain_name': col.domain_name,
            # The column's annotations (#1082) and a descriptor from its own
            # vector metadata. The flags byte is RELAYED, not zeroed: a flexible
            # column says it allows any dimensions there, and a zero told the
            # client it allows exactly none (#1013).
            'has_vector': field_version >= FIELD_VERSION_23_1_EXT_1,
            'annotations': _encode_annotations(col.annotations),
            'vector_dimensions': col.vector_dimensions or 0,
            'vector_format': (col.vector_format or 0) & 0xFF,
            'vector_flags': (col.vector_flags or 0) & 0xFF,
        }
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
    # The current date, four flags and, from 11g, the result cache's query key:
    # a 10g describe ends after the flags (#84, #814).
    return body + _describe_trailer(oci=False)


def _encode_annotations(annotations: tuple[tuple[bytes, bytes], ...]) -> bytes:
    # A column's annotation map, as a 23ai (fv >= 23.1 EXT 1) describe carries it: the
    # count, a pointer byte, the count again, a pointer byte, then per pair its
    # key, its value and a ub4 flags word, and a trailing ub4 flags. None is a
    # bare count of 0. The inverse of the client's reader (#89), which skips the
    # pointer bytes and flags, as python-oracledb's does (#1082).
    if not annotations:
        return encode_sb4(0)
    out = (
        encode_sb4(len(annotations)) + b'\x01' + encode_sb4(len(annotations)) + b'\x01'
    )
    for key, value in annotations:
        out += _str_with_length(key) + _str_with_length(value) + encode_sb4(0)
    return out + encode_sb4(0)


def encode_describe(columns: list[ColumnMeta]) -> bytes:
    """Build the describe (TTI_DCB) block for a result's columns — §19.1 (11g).

    Returns the TTC payload starting at the TTI_DCB token. The cursor-uuid
    preamble is empty (the client skips it); the row tokens are appended
    separately by the exec-response encoder.
    """
    preamble = _bytes_with_length(b'')  # cursor uuid / timestamp (skipped)
    return bytes([TTI_DCB]) + preamble + _encode_describe_body(columns)


def encode_implicit_results(results: list[tuple[list[ColumnMeta], int]]) -> bytes:
    """The TTI_IRD block for a PL/SQL block that called ``DBMS_SQL.RETURN_RESULT``.

    The inverse of :func:`decode_token_implicit` (#121, #826)::

        ub4 num_results
        per result:  ub1 len + that many bytes   (a preamble the client skips)
                     describe body               (the column metadata)
                     ub2 cursor id

    Each result is a server cursor the client fetches on demand, exactly like a
    REF CURSOR, so the caller must have parked its rows under that id first.
    """
    return _IMPLICIT_RESULTS_THIN(
        {
            'count': len(results),
            'results': [
                {
                    'preamble': b'',  # the length-prefixed preamble the client skips
                    'describe': _encode_describe_body(columns),
                    'cursor_id': cursor_id,
                }
                for columns, cursor_id in results
            ],
        }
    )


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
        out += encode_sb4(len(text)) + encode_chr(text) + bytes([0, 0])
    return bytes(out)


def _physical_rowid(rowid: str | None) -> tuple[int, int, int, int]:
    # The four OER rowid fields for a printable extended rowid: the inverse of
    # what the client renders them as (rowid_to_string). Anything that is not one
    # -- None, a logical '*...' UROWID -- is no rowid, all zero (#1077).
    from seerdb.common.types import _ROWID_ALPHABET, string_to_rowid

    if (
        rowid is None
        or len(rowid) != 18
        or not all(c in _ROWID_ALPHABET for c in rowid)
    ):
        return (0, 0, 0, 0)
    return string_to_rowid(rowid)


def _encode_oer(
    call_status: int,
    ora_code: int,
    rowcount: int,
    message: bytes,
    cursor_id: int = 0,
    batch_errors: list[tuple[int, int, str]] | None = None,
    *,
    seq: int | None = None,
    error_pos: int = 0,
    sql_type: int = 0,
    call_number: int = 0,
    warn_flags: int = 0,
    rowid: str | None = None,
) -> bytes:
    # An OER return-status token (§6.5, 11g) — the terminal of every response.
    # Rowid fields carry the last touched row's physical rowid when ``rowid`` is
    # one (#1077), zero otherwise -- block 0 reads as "no rowid"; call status, the ORA error number, the affected-row
    # count, the cursor id (for a mid-fetch "more rows" status), and the message
    # text carry meaning. ``batch_errors`` is (offset, code, message) per row that
    # failed in an array-DML batcherrors execute — the three arrays line up by
    # position (#18). ``seq`` / ``error_pos`` / ``sql_type`` / ``call_number`` are
    # the OER fields left zero by the ordinary error/status paths but non-zero in a
    # captured terminator (see :data:`_END_OF_FETCH`); they carry the captured
    # value there and default to zero everywhere else.
    # A caller that pins `seq` is reproducing a captured frame byte for byte;
    # everyone else gets the session's live counter (#842).
    if seq is None:
        seq = _ENCODE_OER_SEQ.get()
    # call_status is a flag word, so the transaction bit is OR'd into whatever
    # the caller asked for rather than replacing it (#889). The caller's value
    # says what this reply is; this bit says what the session is.
    if _ENCODE_TXN_IN_PROGRESS.get():
        call_status |= TNS_EOCS_FLAGS_TXN_IN_PROGRESS
    batch_errors = batch_errors or []
    (rowid_obj, rowid_file, rowid_block, rowid_slot) = _physical_rowid(rowid)
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
        + bytes(
            [sql_type, 0, 0, 0, 0, warn_flags]
        )  # sql_type, fatal, flags, opts, upi, warn
        + encode_sb4(rowid_obj)  # rowid data object number
        + encode_sb4(rowid_file)  # rowid relative file number
        + bytes(1)  # rowid reserved
        + encode_sb4(rowid_block)  # rowid block number
        + encode_sb4(rowid_slot)  # rowid slot number
        + encode_sb4(0)  # os error
        + bytes([0, call_number])  # statement number, call number
        + encode_sb4(0)  # padding
        + encode_sb4(1)  # successful iterations
        + _bytes_with_length(b'')  # oerrdd (logical rowid)
        + _encode_batch_ub4_array(codes)  # batch error codes
        + _encode_batch_ub4_array(offsets)  # batch error row offsets
        + _encode_batch_messages(messages)  # batch error messages
        + _oer_version_tail(ora_code, rowcount)
        + _oer_message(ora_code, message)
    )


def _oer_message(ora_code: int, message: bytes) -> bytes:
    # The message DALC, which a client reads ONLY when the error number is
    # nonzero: a value as thin frames one (_ThinCodec.value), chunked past 252
    # bytes in the field version's framing (#734) -- what OCI's message is in
    # its own (_oci_error_text, #2064).
    #
    # On SUCCESS, from 12.1, nothing at all is written. A 12.1+ client reads the
    # message only `if error_num != 0`, so the empty-length byte written here
    # before was a byte no client ever consumed. That was harmless while the OER
    # ended the response -- the client simply stopped. Under end-of-response
    # framing it does not stop there: it reads on for the marker, took that
    # 0x00 as the next message type, and failed every login with "unknown
    # protocol message type 0" (#1059). A real 23ai sends no such byte, or
    # python-oracledb would trip on it too. Below 12.1 the captured bytes stand,
    # and end-of-response cannot be negotiated there anyway.
    if not ora_code and _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1:
        return b''
    return _THIN.value(message)


def _oer_version_tail(ora_code: int, rowcount: int) -> bytes:
    # The fields a 12.1+ client reads between the batch-error arrays and the
    # message (its decode_token_oer): the extended error number and the ub8
    # rowcount, then from 20.1 a SQL type and a server checksum. 11g has none.
    # The last two follow the release the Mirror PRESENTS, as a real 21c / 23ai
    # sends them to a client that negotiated lower too (#1145).
    field_version = _ENCODE_FIELD_VERSION.get()
    if field_version < FIELD_VERSION_12_1:
        return b''
    tail = encode_sb4(ora_code) + encode_sb4(rowcount)
    # Never below the negotiated version: a server does not advertise less
    # than a session agrees on.
    server_field_version = max(_ENCODE_SERVER_FIELD_VERSION.get() or 0, field_version)
    if server_field_version >= FIELD_VERSION_20_1:
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

    # The row header is the 9i/10g+ row header the client reads back through the
    # `_O7_RXH` head and the `_O7_VECTORS` tail (#2361): one request, this fetch's
    # iteration count, no buffer, and -- the vectors -- no column-compression bit
    # vector and no rowid.
    header = _O7_RXH_THIN(
        {
            'flags': 0,
            'requests': 1,
            'iteration': 0,
            'iterations': fetch,
            'buffer_length': 0,
        }
    ) + _O7_VECTORS_THIN({'bit_vector_length': 0, 'rowid_length': 0})
    # A bytearray, not a `bytes` accumulator: `bytes += ` reallocates and copies
    # the whole buffer each row (O(n^2) for a large single batch — a fetch-all, a
    # scrollable open, or a pipelined prefetch); a bytearray extends in place
    # (O(n)). The OCI row encoders already do this.
    body = bytearray()
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        body += bytes([TTI_RXD]) + b''.join(
            _thin_column_value(v, col) for v, col in zip(row, columns)
        )
    return header + bytes(body)


# The cell types whose wire form is more than a DALC: a LOB-class locator, a
# prefetched image, an object image, a nested cursor, or a column a cached
# cursor is still reading inline as LONG. These are the ones worth tracing.
_FRAMED_CELL_TYPES = frozenset(
    (
        TNS_TYPE_VECTOR,
        TNS_TYPE_JSON,
        TNS_TYPE_REFCURSOR,
        TNS_TYPE_ADT,
        TNS_TYPE_CLOB,
        TNS_TYPE_BLOB,
        TNS_TYPE_BFILE,
    )
)


def _thin_column_value(value: object, col: 'ColumnMeta') -> bytes:
    # One row value for the thin path. A VECTOR (#887) or a native JSON column
    # (#826) carries its image inline; everything else goes through the type-only
    # encoder. The column is needed for the element format, so an INT8 or FLOAT64
    # vector keeps the width it was declared with rather than being re-encoded as
    # float32.
    if (
        col.data_type in _FRAMED_CELL_TYPES
        or col.is_oson
        or col.inline_long_csfrm is not None
    ) and logger.isEnabledFor(logging.DEBUG):
        # This runs per column per row, so the cheap structural test comes first
        # and `isEnabledFor` only for the cells that can actually be mis-framed.
        # A NUMBER or VARCHAR cell is a DALC and has never desynced a row; every
        # desync this codebase has had was a framed cell, and tracing only those
        # keeps an ordinary fetch's encode cost where it was. The fields logged
        # are exactly what the branches below dispatch on.
        logger.debug(
            'row encode: col=%s type=%s is_oson=%s inline_long=%s value=%s',
            col.name,
            col.data_type,
            col.is_oson,
            col.inline_long_csfrm,
            type(value).__name__,
        )
    if col.data_type == TNS_TYPE_VECTOR and value is not None:
        if col.inline_long_csfrm is not None:
            # The client's define asked for this vector as character data, so it
            # goes out as the text form inline, not the binary image (#1107).
            return encode_long_value_thin(
                vector_as_text(cast('SparseVector | Sequence', value))
            )
        return encode_prefetched_lob_value_thin(
            encode_vector(_vector_as(value, col.vector_format))
        )
    if col.data_type == TNS_TYPE_JSON and value is not None:
        if col.inline_long_csfrm is not None:
            # The client's define asked for this document as character data, so
            # it goes out as JSON text inline, not the OSON image (#1106).
            return encode_long_value_thin(json_as_text(value))
        # allow_wide so a > 255-key or > 64 KiB document still re-encodes for the
        # client's decoder -- the framing carries any size.
        from seerdb.common.oson import encode_oson

        return encode_prefetched_lob_value_thin(encode_oson(value, allow_wide=True))
    if col.data_type == TNS_TYPE_REFCURSOR and isinstance(value, NestedCursor):
        # A nested cursor column: its rows are already parked under cursor_id,
        # and the value is the inline describe naming it (#826).
        return encode_refcursor_column_value(value.columns, value.cursor_id)
    if col.data_type == TNS_TYPE_ADT:
        # A SQL object (ADT) column carries its own image framing, NULL included
        # (#116) — the bare-0x00 NULL path below would desync the row stream.
        return encode_object_column_value(value, col.type_oid)
    if col.is_oson and value is not None:
        # A BLOB / CLOB holding an OSON image. The client re-types such a column
        # to LONG RAW and runs decode_oson over the bytes, so the value rides
        # inline in the row rather than as a LOB locator -- a locator here is
        # read as LONG RAW and desyncs the row (#826).
        return encode_long_value_thin(value)
    if col.inline_long_csfrm is not None:
        # This column's type changed to CLOB / BLOB under a cached cursor whose
        # previous describe said CHAR / VARCHAR / LONG (or RAW / LONG RAW). A real
        # server keeps serving such a column the way the client still expects it --
        # inline as LONG / LONG RAW, in the OLD charset form -- even though the
        # describe reports the new LOB type; a locator here desyncs the row (#826).
        if isinstance(value, str) and col.inline_long_csfrm == _CSFRM_NCHAR:
            return encode_long_value_thin(value.encode('utf-16-be'))
        return encode_long_value_thin(value)
    if col.data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB) and value is not None:
        # Mint a unique locator and remember the content, so an object bind that
        # later carries this locator can recover it (#888). The read path is
        # order-based and ignores the locator, so this changes no reader; the log
        # is unset outside a Mirror session, keeping the fixed-locator behaviour.
        log = _LOB_EMIT_LOG.get()
        if log is not None:
            is_clob = col.data_type == TNS_TYPE_CLOB
            locator = log.record(value, is_clob)
            return encode_lob_locator_thin(
                _lob_value_size(value), with_metadata=True, locator=locator
            )
    if (
        describe_wire_length(col) == 0
        and col.data_type not in _ZERO_DESCRIBE_CARRIES_DATA
    ):
        # A plain-scalar column the describe gives a zero buffer size carries NO
        # bytes in the row — the reference client reads it as NULL-by-describe and
        # consumes nothing (the mirror image of the decoder's data-length-0 rule).
        # Emitting even the empty DALC a NULL would send desyncs the reader by one
        # byte per row; a metadata cursor's literal-NULL column (`get_type_shape`'s
        # attrs cursor, #888) and `SELECT NULL` both describe exactly this way.
        # LOB / LONG / ROWID / UROWID keep a zero describe length yet do carry
        # data, so they are excluded and fall through to their own framing below.
        return b''
    return encode_value(_national_wire_value(value, col), col.data_type)


def encode_error(
    ora_code: int,
    message: str,
    error_pos: int | None = None,
    *,
    rowcount: int = 0,
) -> bytes:
    """OER reporting an error: the client raises ``ORA-<code>: <message>`` and
    the connection stays usable. ``error_pos`` is the parse offset of the error
    (``None`` -> 0, no specific position).

    ``rowcount`` is what the call MANAGED before it failed. An executemany whose
    batch aborts part-way really did apply the earlier rows, and a real server
    reports how many in the same field a success reports its own count -- so a
    caller reading ``cursor.rowcount`` to decide what to retry is not told that
    nothing happened (#998)."""
    return _encode_oer(
        1, ora_code, rowcount, message.encode('utf-8'), error_pos=error_pos or 0
    )


def encode_status(
    rowcount: int = 0,
    cursor_id: int = 0,
    *,
    compilation_warning: bool = False,
    rowid: str | None = None,
) -> bytes:
    """OER reporting success for a non-query (DDL / DML), with the affected-row
    count. No describe, no rows — the client just sees the statement completed.
    A non-zero ``cursor_id`` lets the client's cursor cache remember the server
    handle and re-execute the same DML by id with an empty query (#80/#486).

    ``compilation_warning`` raises bit 0x20 of the warn byte: the statement
    CREATED a PL/SQL object that compiled with errors. The call succeeded and
    there is no error code to carry it, so this bit is the whole signal
    (§6.3a, #995).

    ``rowid`` is the last touched row's, which the client reports as
    ``cursor.lastrowid`` (#1077)."""
    return _encode_oer(
        0,
        0,
        rowcount,
        b'',
        cursor_id=cursor_id,
        warn_flags=(TNS_OER_WARN_COMPILATION_ERROR if compilation_warning else 0),
        rowid=rowid,
    )


def encode_status_with_rowcounts(
    rowcount: int, counts: list[int], *, cursor_id: int = 0
) -> bytes:
    """The DML success status when the client requested arraydmlrowcounts (#18):
    the per-iteration affected-row counts, then the ordinary status OER.

    The counts ride in the execute's **return-parameters block** (`TTI_RPA`,
    token 8), laid out the way a real server lays it out and the reference
    client reads it (#859)::

        08 | ub2 al8o4l count | count x ub4 | ub2 al8txl length | ub2 key/value
           pairs | ub2 registration length | ub4 rows | rows x ub8 | 04 ...

    The four leading words are the block's ordinary fields, all empty here; the
    row counts are the tail the server appends only when the execute set
    DML_ROWCOUNTS. A first cut of this reply framed the counts as a private
    `ub4 zero | ub4 count | count x ub4` shape instead. seerdb's own decoder
    happened to accept both -- it reads the leading word as a field count and
    skips zero bytes -- but the reference client reads the four words by name,
    took the count for the al8txl length, skipped that many bytes and parsed the
    values as key/value pairs until a length byte of 4 landed where it expected
    a ub2. The counts are ub8 on the wire; small values encode as the same
    length-prefixed bytes as a ub4, which is what encode_sb4 writes.

    Without the request the client never looks for the block, and a plain
    status is sent instead."""
    return encode_rowcounts_block(counts) + encode_status(rowcount, cursor_id=cursor_id)


def encode_rowcounts_block(counts: list[int]) -> bytes:
    """Just the per-iteration row-count block (`TTI_RPA`), without a status.

    It is a PREFIX, so it rides in front of whatever OER follows -- a success
    status, the ORA-24381 batcherrors summary, or the error that aborted the
    batch. A client that asked for arraydmlrowcounts is owed the counts in all
    three: the rows that applied applied, whatever happened after them (#1031).
    """
    return _ROWCOUNTS_BLOCK_THIN(
        {
            'al8o4l': 0,
            'al8txl': 0,
            'key_value_pairs': 0,
            'registration': 0,
            'count': len(counts),
            'counts': [{'value': c} for c in counts],
        }
    )


def encode_batch_errors_status(
    rowcount: int,
    batch_errors: list[tuple[int, int, str]],
    counts: list[int] | None = None,
) -> bytes:
    """OER for an array-DML ``batcherrors`` execute that collected per-row
    failures (#18): ORA-24381 with the (offset, code, message) arrays, and the
    affected-row count of the rows that applied. The client surfaces the errors
    through ``getbatcherrors()`` instead of raising.

    ``batcherrors`` and ``arraydmlrowcounts`` are not alternatives -- a client
    may ask for both on one execute, and then this reply owes the per-iteration
    counts as well (#1031)."""
    message = f'ORA-{ORA_ARRAY_DML_ERRORS:05d}: error(s) in array DML'.encode()
    prefix = encode_rowcounts_block(counts) if counts is not None else b''
    return prefix + _encode_oer(
        0, ORA_ARRAY_DML_ERRORS, rowcount, message, batch_errors=batch_errors
    )


def encode_more_rows(cursor_id: int) -> bytes:
    """Terminate a batch that did NOT drain the cursor: ``call_status = 1``, no
    error, and the cursor id — the client reads this as "more rows on cursor N"
    and issues ``TTI_FETCH`` for the rest (§5.2). The ``1403`` end-of-fetch
    (:data:`_END_OF_FETCH`) is sent only once the cursor is drained."""
    return _encode_oer(1, 0, 0, b'', cursor_id=cursor_id)


def _terminator(cursor_id: int, more: bool) -> bytes:
    # `more` reports an open cursor with rows still on it; the end-of-fetch
    # reports the cursor the (now drained) statement ran on. Both carry the id
    # so a client can re-execute the statement by it (#840). A zero id means the
    # caller minted none, and the captured 1 stands in.
    if more:
        return encode_more_rows(cursor_id)
    return _end_of_fetch(cursor_id or 1)


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
    TNS_BIND_DIR_INPUT_OUTPUT,
    TNS_BIND_DIR_OUTPUT,
    TNS_FETCH_ORIENTATION_FIRST,
    TNS_FETCH_ORIENTATION_LAST,
    TNS_LOB_OP_ARRAY,
    TNS_LOB_OP_CLOSE,
    TNS_LOB_OP_CREATE_TEMP,
    TNS_LOB_OP_FREE_TEMP,
    TNS_LOB_OP_GET_CHUNK_SIZE,
    TNS_LOB_OP_IS_OPEN,
    TNS_LOB_OP_OPEN,
    TNS_LOB_OP_TRIM,
    TNS_MAX_CONNECT_DATA,
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

# The DEFINE bit in the same word: this execute applies the client's own fetch
# variables and carries one define OAC per column in place of any binds (#826).
_EXEC_OPTION_DEFINE = 0x10

# PARSE asks the server to parse the statement; EXECUTE asks it to run it.
# A `cursor.parse()` sets PARSE and leaves EXECUTE clear -- and sends no bind
# values, so running it anyway fails with ORA-01008 (#826). For a query it
# also sets DESCRIBE, and the reply is the describe alone: no rows, and a
# plain success status rather than the end-of-fetch ORA-01403.
_EXEC_OPTION_PARSE = 0x01
_EXEC_OPTION_EXECUTE = 0x20
_EXEC_OPTION_DESCRIBE = 0x20000


def parse_options(options: int) -> tuple[bool, bool]:
    """``(parse_only, describe_only)`` for an execute's option word.

    The word is a bitmask of what this call is asking for, so what makes a
    ``cursor.parse()`` a parse is not the PARSE bit -- it is the **absence of
    EXECUTE**. Measured on a live 23ai, the two parses of one statement do not
    even agree on PARSE:

    ==================================  ========  =======================
    call                                options   note
    ==================================  ========  =======================
    ``parse()``, statement unseen       ``0x1``   PARSE
    ``parse()``, statement cached       ``0x0``   already parsed
    ``execute()``                       ``0x8029`` NOT_PLSQL|COMMIT|EXECUTE|PARSE
    define round-trip                   ``0x8010`` NOT_PLSQL|DEFINE
    ==================================  ========  =======================

    Reading the PARSE bit alone therefore missed the second parse of a
    statement, which ran instead: it carries no bind values, so the backend
    answered ORA-01008 (#984).

    Two other calls have no EXECUTE either and are NOT parses, so they are
    excluded by name: the DEFINE round-trip (``0x8010``), which is the client
    applying its fetch types and asking for the rows already parked (§14.5d),
    and a scroll re-execute (``0x8040``), which repositions an open cursor and
    must NOT set EXECUTE or the server would re-run the query from the top
    (§11.8). Calling either a parse would answer a bare status and strand the
    rows."""
    asks_for_work = (
        _EXEC_OPTION_EXECUTE  # run the statement
        | _EXEC_OPTION_DEFINE  # apply the client's fetch types, take the rows
        | TNS_EXEC_OPTION_FETCH  # fetch / reposition (a scroll re-execute)
    )
    return (
        not (options & asks_for_work),
        bool(options & _EXEC_OPTION_DESCRIBE),
    )


# A TTI_LOBOPS READ request carries the slice sqlplus wants: a 1-based source
# offset and an amount, both counts (characters for a CLOB, bytes for a BLOB).
# sqlplus loops over them (in SET LONGCHUNKSIZE-sized steps) until a read
# returns fewer than it asked for. It sends thin's fields (_LOBOPS_READ) in one
# of two widths, as it does its OALL8 (#866): sqlplus 23.26 (and 10.2) the
# narrow form, a 135-byte header before the locator (#1287), and sqlplus 11.2
# the wide one, 163 bytes (#2251). An indicator at 91 marks the narrow form:
# in the wide one that is where the offset sits, and no offset reads as
# `fe ff ff ff ff ff ff ff`.
_OCI_LOBOPS_NARROW_IND_OFF = 91
_OCI_LOBOPS_NARROW_HEADER = 135
_OCI_LOBOPS_WIDE_HEADER = 163


_OCI_LOB_CHUNK = 0xFF  # content bytes per 11g LOB_DATA chunk (matches live 11g)


def _oci_lob_data(content: bytes) -> bytes:
    # TTI_LOB content, the 11g form (_OciCodec.lob).
    return _LOB_DATA_OCI({'content': content})


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
    if data_type == TNS_TYPE_REFCURSOR:
        # A REF CURSOR bind: a ub4 COUNT then that many ub4 cursor ids -- not a
        # DALC (#1048). Read as one, the count's magnitude byte came back as the
        # value and the id was left in the stream, so a client binding an open
        # cursor was answered about whichever cursor happened to share that
        # number. The OUT form is a count of 1 holding the id 0, "open one for
        # me"; an IN bind carries the real id. Zero ids yields 0, the same
        # "nothing to reuse" answer.
        (count, after) = decode_ub4(after)
        cursor_id = 0
        for _ in range(count):
            (cursor_id, after) = decode_ub4(after)
        return cursor_id, after
    if data_type == TNS_TYPE_REF:
        # A REF bind (#139): the value is just the opaque locator (a DALC). Pair
        # it with the OID the OAC carried so the backend re-binds a DbRef with
        # the referenced type's identity (its bind OAC needs the 16-byte OID).
        from seerdb.common.dbobject import DbRef

        raw, after = decode_dalc(after)
        locator = bytes(raw) if not isinstance(raw, list) else b''
        return DbRef(locator, type_oid=toid or None), after
    if data_type == TNS_TYPE_ADT:
        # An object (ADT, #116/#888) bind: the value is the write_dbobject
        # framing (toid, object OID, snapshot, version, image length, flags,
        # packed image) — the same framing a fetched object column carries, so
        # _read_object_column reads it and hands back an ObjectImage placeholder
        # (or None for a NULL object). The OAC's 16-byte type OID is threaded in
        # so the backend can resolve the type and decode the image into a
        # DbObject to re-bind; a plain DALC read would mistake the toid's own
        # length prefix for the value length and desync.
        return _read_object_column(after, {'type_oid': toid})
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


def _skip_fun_header(payload: bytes, header: int = 3) -> bytes:
    # Bytes after a TTI function-message header (TTI_FUN, subtype, seq). At
    # fv >= 23.1 EXT 1 the header carries an extra ub8 token number (0 for an ordinary
    # call) after the sequence — oracledb's _write_function_code / PROTOCOL.md
    # §20.4 — present on every function message, so skip it too. Below fv 18
    # there is none, so this is the historical `payload[header:]`.
    rest = payload[header:]
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_23_1_EXT_1:
        _token, rest = decode_ub4(rest)
    return rest


def peek_exec_cursor(payload: bytes) -> tuple[int, bool]:
    """The cursor id and whether SQL is present, read from an OALL8 header without
    a full parse (#80/#486). A cached re-execute (cursor set, no SQL) carries no
    OACs, so the session uses this to supply the remembered bind types to
    :func:`parse_exec`. Returns ``(0, True)`` for anything that isn't an OALL8."""
    if len(payload) < 3 or payload[0] != TTI_FUN or payload[1] != TTI_ALL8:
        return (0, True)
    (head, _rest) = _ALL8_HEAD_FROM_THIN(payload)
    return (head['cursor'], head['sql_present'])


def _skip_exec_middle_12c(rest: bytes, field_version: int) -> bytes:
    # The 12.1+ OALL8 block between the fixed head and the SQL (the client's
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
    if field_version >= FIELD_VERSION_12_2:
        rest = rest[5:]  # al8sqlsig / SQL id
    if field_version >= FIELD_VERSION_12_2_EXT_1:
        rest = rest[2:]  # chunk ids
    return rest


def parse_exec(
    payload: bytes,
    bind_types: list | None = None,
    max_string_size: int = 4000,
    cached_plsql: bool = False,
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

    (head, rest) = _ALL8_HEAD_FROM_THIN(payload)
    options = head['options']
    autocommit = bool(options & _EXEC_OPTION_COMMIT)
    batcherrors = bool(options & TNS_EXEC_OPTION_BATCH_ERRORS)
    parse_only, describe_only = parse_options(options)
    (cursor, query_flag, query_len) = (
        head['cursor'],
        head['sql_present'],
        head['sql_length'],
    )
    (all8_len, fetch) = (head['al8i4_length'], head['prefetch_rows'])
    (bind_count, define_count) = (head['bind_count'], head['define_count'])

    field_version = _DECODE_FIELD_VERSION.get()
    if field_version >= FIELD_VERSION_12_1:
        # 12.1+ replaces the marker + server-version slot with the registration /
        # array-DML row-count block (and from 12.2 the SQL-signature one), and
        # length-prefixes the SQL (#1144).
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
    # The request is the DML_ROWCOUNTS bit alone. Testing the composite the
    # client sends (which also carries IMPLICIT_RESULTSET) matched EVERY execute
    # from the reference client, whose ordinary executes carry IMPLICIT_RESULTSET
    # on their own -- so a plain executemany was answered with a row-count block
    # it never asked for and could not parse (#859).
    arraydmlrowcounts = len(al8) > 9 and bool(al8[9] & TNS_EXEC_FLAGS_DML_ROWCOUNTS)
    scroll_orientation = al8[10] if len(al8) > 10 else 0
    scroll_position = al8[11] if len(al8) > 11 else 0
    # al8i4[1] is the execute iteration count (1 + array-DML batch length); a
    # plain execute is 1. It is the only record of how many iterations an
    # all-clause-filled RETURNING runs, whose rows carry no values (#33).
    #
    # For a QUERY that slot means something else entirely: the number of rows to
    # prefetch. al8i4[7] is the is-query flag, and the reference client writes the
    # fetch array size there whenever it re-executes a cursor it already has
    # (`arraysize`, 100 by default). Read as an iteration count that turned a
    # plain re-executed SELECT into a 100-iteration array DML, which ran no query
    # at all and answered with a row count (#826).
    is_query = bool(al8[7]) if len(al8) > 7 else False
    iterations = 1 if is_query else (al8[1] if len(al8) > 1 else 1)

    # A define execute (the DEFINE option) carries one OAC per column in place of
    # the binds -- the client's own fetch variables, telling the server what it
    # wants each column AS. The OACs sit exactly where a bind's would, and have
    # the same layout, so the bind decoder reads them (#826).
    define_types: list = []
    if options & _EXEC_OPTION_DEFINE and define_count:
        defines_rest = after
        for _ in range(define_count):
            data_type, _maxlen, _scale, _charset, csfrm, _toid, defines_rest = (
                decode_oac_fields(defines_rest)
            )
            if field_version >= FIELD_VERSION_12_2:
                # The 12.2+ OAC appends an oaccolid the shared decoder stops short
                # of -- consume it so the next define aligns.
                _, defines_rest = decode_ub4(defines_rest)
            define_types.append((data_type, csfrm))

    binds: list = []
    bind_rows: list = []
    bind_meta: list = []
    if bind_count > 0:
        # After the al8 array (already consumed above): one OAC (type descriptor)
        # per bind column, then one RXD row of values per array-DML iteration
        # (an ordinary single execute is just one row). A cached re-execute may
        # omit the OACs -- seerdb's own client does (#80/#486) -- and then the
        # remembered bind types are the only record of the format.
        #
        # "No SQL" does NOT imply "no OACs", though: the reference thin client
        # sends an empty-SQL execute that still carries them. Taking the caller's
        # remembered types on the strength of the empty-query flag left `after`
        # sitting on an OAC, so not one RXD row was found and the backend was
        # handed an execute with no bind values at all (ORA-01008, #859). Decide
        # from the wire instead: the descriptors are absent exactly when the bind
        # area already sits on a TTI_RXD row.
        # A cached re-execute carries no OACs, and no bind of one is an array
        # (#703). A PL/SQL block is cached too now (#1064), which is why the
        # directions matter below -- but only here, where the types come from
        # the record: a client that re-describes its binds sends OACs and a
        # value for every one of them, including the OUT positions.
        capacities: list[int] = []
        omits_oacs = not after or after[0] == TTI_RXD
        if bind_types is not None and omits_oacs:
            types = list(bind_types)
            capacities = [0] * len(types)
        else:
            types = []
            for _ in range(bind_count):
                capacities.append(_oac_array_capacity(after, field_version))
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
                elif field_version < FIELD_VERSION_12_1 and data_type in (
                    TNS_TYPE_CLOB,
                    TNS_TYPE_BLOB,
                ):
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
        # A native JSON / VECTOR bind is NOT LONG-class, however wide its OAC
        # says it is -- and it always says 32 MiB. It carries its own descriptor
        # framing and rides in place, so sorting it to the end swapped it with
        # every bind after it: the value landed in the following bind's slot and
        # that bind read the image's bytes as a NUMBER (#826). It went unnoticed
        # because a JSON bind is usually the last one, where the move is a no-op.
        # ...and whether this is a block cannot always be read off `sql`: a
        # cached re-execute carries none. Since a block got a cursor id of its
        # own (#1064) that case is real, and reading the empty statement as
        # "not PL/SQL" sorted a wide bind -- an object bind declares 16000 --
        # to the end of the row, so every value after it was read at the wrong
        # offset. The caller says what the cursor stands for.
        block = cached_plsql if not sql else is_plsql(sql)
        long_binds = frozenset(
            index
            for index, (data_type, _csfrm, maxlen, _toid) in enumerate(types)
            if maxlen > max_string_size
            and data_type not in _PREFETCHED_IMAGE_TYPES
            and not block
        )
        carried = [index for index in range(len(types)) if index not in return_binds]
        order = [index for index in carried if index not in long_binds] + [
            index for index in carried if index in long_binds
        ]
        bind_rows, after = _read_bind_rows(after, types, capacities, order)
        if bind_rows:
            binds = bind_rows[0]
        if bind_rows and len(bind_rows) < iterations:
            # The rows ran out before the iteration count did, so this message is
            # cut mid-array and the rest is in the next packet. Saying so lets the
            # Mirror grow the request; stopping here silently parsed a partial
            # array DML and left the continuation to be read as a new message
            # ("unhandled message type 7", #1097). A batch whose rows are ALL
            # empty carries no RXD at all and is not this case.
            raise Truncated(f'array DML: {len(bind_rows)} of {iterations} bind rows')
        # Per-bind (tns_type, max_size) — what a PL/SQL block's OUT binds need to
        # be registered on the backend with a correctly-sized buffer (#483).
        bind_meta = [(data_type, maxlen) for data_type, _csfrm, maxlen, _toid in types]
        bind_type_list = list(types)
    else:
        bind_type_list = []
        capacities = []
        return_binds = frozenset()

    return ExecRequest(
        sql=sql,
        cursor=cursor,
        bind_count=bind_count,
        fetch=fetch,
        binds=binds,
        bind_rows=bind_rows,
        bind_meta=bind_meta,
        bind_arrays=capacities,
        bind_types=bind_type_list,
        autocommit=autocommit,
        batcherrors=batcherrors,
        scrollable=scrollable,
        scroll_orientation=scroll_orientation,
        scroll_position=scroll_position,
        arraydmlrowcounts=arraydmlrowcounts,
        return_binds=return_binds,
        iterations=iterations,
        define_types=define_types,
        parse_only=parse_only,
        describe_only=describe_only,
    )


def _read_bind_rows(
    after: bytes, types: list, capacities: list[int], order: list[int]
) -> tuple[list, bytes]:
    # The RXD rows of an execute: each a TTI_RXD token then one value per bind
    # in `order` (the wire order -- LONG-class binds last, clause-filled
    # RETURNING binds absent, so a row keeps None at any position `order`
    # skips). Loops until the rows run out: executemany sends N, a plain
    # execute 1. Returns the rows and the bytes past them.
    bind_rows: list = []
    while after and after[0] == TTI_RXD:
        after = after[1:]
        row: list = [None] * len(types)
        for index in order:
            data_type, csfrm, _maxlen, toid = types[index]
            if capacities[index]:
                # An associative-array bind (#122/#743): a ub4 element count,
                # then each element as an ordinary value of the bind's type. A
                # pure-OUT array sends a count of 0.
                (count, after) = decode_ub4(after)
                elements = []
                for _ in range(count):
                    element, after = _read_bind_value(data_type, csfrm, after, toid)
                    elements.append(element)
                row[index] = elements
                continue
            row[index], after = _read_bind_value(data_type, csfrm, after, toid)
        bind_rows.append(row)
    return bind_rows, after


def _read_chunked_sql(data: bytes, total_len: int) -> tuple[bytes, int]:
    # `data` starts at the 0xFE chunk marker; collect <ub1 len><chunk> runs until
    # the declared total is reached or a zero-length chunk terminates it. Returns
    # the SQL and the offset in `data` just past the last chunk read (and past
    # the zero length, when that is what ended it), where a bound statement's
    # bind section is looked for (#2028).
    out = bytearray()
    i = 1  # skip the 0xFE marker
    while len(out) < total_len and i < len(data):
        chunk_len = data[i]
        i += 1
        if chunk_len == 0:
            break
        out += data[i : i + chunk_len]
        i += chunk_len
    return bytes(out[:total_len]), i


def _oci_lobops_narrow(body: bytes) -> bool:
    """Whether an OCI TTI_LOBOPS READ is in the narrow form (#1287): an
    indicator at 91 where the wide form has its offset. sqlplus 10.2 lays the
    request out the same way, but writes its pointers' own values where later
    clients write the indicator -- the offset at 75, the locator at 135, the
    amount after it, captured against Mirror-over-PG -- so a session at 10.2's
    field version reads it as narrow too (#2123)."""
    ind = _OCI_LOBOPS_NARROW_IND_OFF
    if body[ind : ind + 8] == oci.OCI_INDICATOR:
        return True
    return _DECODE_FIELD_VERSION.get() <= FIELD_VERSION_10_2 and any(
        body[ind : ind + 8]
    )


def parse_lobops_read(body: bytes) -> tuple[int, int]:
    """Extract ``(source_offset, amount)`` from an OCI TTI_LOBOPS READ (#405) —
    both 1-based counts (characters for a CLOB, bytes for a BLOB). A malformed /
    short request falls back to reading the whole LOB from the start."""
    read = _oci_lobops_read(body)
    if read is None:
        return 1, 2**31
    return max(read['source_offset'], 1), read['amount']


def _oci_lobops_read(body: bytes) -> dict[str, Any] | None:
    # An OCI TTI_LOBOPS READ's fields (_LOBOPS_READ) in whichever width it came,
    # or None for one too short to hold its locator and amount.
    if _oci_lobops_narrow(body):
        (decode, header) = (_LOBOPS_READ_FROM_OCI, _OCI_LOBOPS_NARROW_HEADER)
    else:
        (decode, header) = (_LOBOPS_READ_FROM_OCI_WIDE, _OCI_LOBOPS_WIDE_HEADER)
    if len(body) < header:
        return None
    try:
        (read, _rest) = decode(body)
    except IndexError:
        return None  # its amount, or its locator, runs past the end (#2272)
    if len(body) < header + read['source_length'] + 8:
        return None
    return read


def parse_lobops_locator(body: bytes) -> bytes | None:
    """The locator an OCI TTI_LOBOPS READ names, in either width, or None for a
    request too short to hold one: sqlplus 10.2 reads a CLOB variable's value
    this way, where later ones select it (#2123), and a row's LOBs are told
    apart by it (#1430, #2251)."""
    read = _oci_lobops_read(body)
    return None if read is None else read['locator']


def parse_lobops_slot(body: bytes) -> int | None:
    """The row slot the locator of an OCI TTI_LOBOPS READ names (#1430), or None
    for a request that carries none: one too short to hold a locator, or a
    locator minted without a slot."""
    region = parse_lobops_locator(body)
    locator = None if region is None else _oci_lob_locator_from(region)
    if locator is None or not locator['slot']:
        return None
    return locator['slot'] - 1


def encode_lob_read_response_thin(
    content: bytes, *, is_clob: bool = False, locator: bytes | None = None
) -> bytes:
    """The thin TTI_LOBOPS READ reply (#413): the whole LOB content as LOB_DATA,
    the return-parameter block naming the amount read, then a success OER.
    ``content`` is UTF-16BE for a CLOB, raw for a BLOB. ``locator`` is echoed
    back verbatim and defaults to the Mirror's column placeholder.

    The **amount** is in the LOB's own units -- characters for a CLOB, bytes for
    a BLOB -- which is why it cannot be inferred from the content length. Without
    this block a client falls back to counting the bytes it received, and a CLOB
    then reads back at twice its length, every character counted once per UTF-16
    byte (#903). seerdb's own client never noticed: it takes the content whole
    and does not consult the amount."""
    amount = len(content) // 2 if is_clob else len(content)
    # Defaulted here, not in the signature: _THIN_LOB_LOCATOR is defined further
    # down the module, and a default argument is evaluated at def time.
    echo = _THIN_LOB_LOCATOR if locator is None else locator
    return _LOB_READ_REPLY_THIN(
        {
            'lob_data': _lob_data_thin(content),
            # The locator rides RAW here, not length-prefixed: the client reads
            # back exactly as many bytes as the locator it sent, then the
            # amount. Which is why it has to be the locator the client ACTUALLY
            # sent for a temp LOB it created itself -- the placeholder is only
            # right for a column LOB the Mirror minted, where the client ignores
            # what comes back (#826).
            'locator': echo,
            'amount': amount,
            'status': _encode_oer(1, 0, 0, b''),
        }
    )


def _lob_data_thin(content: bytes) -> bytes:
    # LOB_DATA in the negotiated version's chunk framing (_ThinCodec.lob).
    return _LOB_DATA_THIN({'content': content})


# A temp LOB locator is 40 bytes on the wire: a ub2 length and 38 bytes. The
# length is not the Mirror's choice. The client allocates the locator buffer
# itself -- CREATE_TEMP asks for 0x28 = 40 -- and reads back exactly that many
# bytes, so a shorter locator leaves it reading the next field as locator and
# waiting on bytes that never come. A live 23ai returns 40.
_TEMP_LOB_LOCATOR_LEN = 38

# The max-data-length a temp-LOB bind OAC announces: python-oracledb's DB_TYPE
# buffer_size_factor for a LOB, 112 for both CLOB and BLOB, sent for every
# temp-LOB bind regardless of the value size. The server reads 0 here as "no
# LOB" and stores NULL, so this must be non-zero even for an empty LOB (#903).
_LOB_BIND_BUFFER_SIZE = 112


def mint_temp_lob_locator(index: int, is_blob: bool) -> bytes:
    """A unique opaque locator for the ``index``-th temp LOB of a session (#412).

    The value is echoed back verbatim on WRITE and on the bind, so it only has to
    be stable and distinct per temp LOB — the Mirror keys its buffer on it. It is
    padded to the length a real server uses, which is what the client expects to
    read (#846).

    Not quite opaque, though: two flag bytes of a CLOB locator steer how the
    reference client encodes everything it writes to (and reads from) the LOB.
    Flag byte 3 carries the **variable-length-charset** bit (``0x80``) and flag
    byte 4 the **little-endian** bit (``0x40``): the client writes UTF-16BE when
    the charset bit is set and the little-endian bit clear, UTF-16LE when both
    are set, and UTF-8 when the charset bit is clear (an NCLOB is UTF-16BE
    regardless, by its charset form). The Mirror decodes a temp CLOB as UTF-16BE,
    so the minted locator must present exactly that combination -- charset bit
    set, little-endian bit clear -- and a live 23ai's own temp CLOB locators do
    (flags ``82 08 80 03``). The Mirror's locator carried ASCII in those bytes:
    the charset bit was clear (client wrote UTF-8) and, once that was set, byte 4
    still held ``'d'`` (``0x64``), whose ``0x40`` made the client write UTF-16LE
    -- either way the UTF-16BE decode on the bind produced mojibake and the
    session died (#903). seerdb's own client is unaffected: it always writes
    UTF-16BE. The client reads the locator behind a ``ub2`` length prefix
    (:func:`encode_create_temp_response`), so its flag bytes 3 and 4 (offsets 6
    and 7 of what it holds) are offsets 4 and 5 of the minted value. A BLOB
    carries no charset and keeps both bytes untouched."""
    raw = bytearray(
        (
            _TEMP_LOB_LOCATOR_PREFIX
            + struct.pack('>I', index)
            + (b'\x01' if is_blob else b'\x00')
        ).ljust(_TEMP_LOB_LOCATOR_LEN, b'\x00')
    )
    if not is_blob:
        raw[_TEMP_LOB_LOC_OFFSET_FLAG_3] |= _THIN_LOB_LOC_FLAGS_VAR_LENGTH_CHARSET
        raw[_TEMP_LOB_LOC_OFFSET_FLAG_4] &= ~_THIN_LOB_LOC_FLAGS_LITTLE_ENDIAN
    return bytes(raw)


_TEMP_LOB_LOCATOR_PREFIX = b'\x00seerdb-mirror-temp-lob-'
# Client-side flag-byte offsets 6 and 7 (see _THIN_LOB_LOC_OFFSET_FLAG_3), less
# the ub2 length prefix the CREATE_TEMP reply puts in front of the minted bytes.
_TEMP_LOB_LOC_OFFSET_FLAG_3 = 4
_TEMP_LOB_LOC_OFFSET_FLAG_4 = 5
# The little-endian bit in flag byte 4: with the variable-length-charset bit set,
# it tells the client the CLOB rides UTF-16LE rather than UTF-16BE.
_THIN_LOB_LOC_FLAGS_LITTLE_ENDIAN = 0x40


def _decode_lobops_chunked(data: bytes) -> bytes:
    # The WRITE payload after the 0x0E marker: a single <ub1 len><bytes> when the
    # data is <= 0xFC bytes, else a 0xFE marker then <sb4 len><chunk> repeated
    # until a zero-length terminator (§14.2). Inverse of the client encoder.
    if not data:
        return b''
    if data[0] != TNS_LONG_LENGTH_INDICATOR:
        if len(data) < 1 + data[0]:
            raise Truncated(f'LOB write: {data[0]} bytes, {len(data) - 1} left')
        return data[1 : 1 + data[0]]
    rest = data[1:]
    out = bytearray()
    # The payload ends at a zero-length chunk, and only there. Running out of
    # bytes first used to return whatever had arrived as if it were the whole
    # value -- which is how a WRITE spanning TNS packets lost everything after
    # its first packet without a word (#848, #849).
    while True:
        chunk_len, rest = decode_ub4(rest)
        if chunk_len == 0:
            return bytes(out)
        if len(rest) < chunk_len:
            raise Truncated(f'LOB write chunk: {chunk_len} bytes, {len(rest)} left')
        out += rest[:chunk_len]
        rest = rest[chunk_len:]


# The opcodes the Mirror acknowledges with a content-free RPA+OER but does not
# yet act on (#417): OPEN / CLOSE bracket a write, TRIM truncates. Recognising
# them (instead of mis-routing to the READ path) is what keeps a programmatic
# client from desyncing. FREE_TEMP is handled apart (it drops the temp buffer).
# The value-returning form of GET_CHUNK_SIZE / TRIM is a #421 follow-up.
_LOBOPS_ACK_OPS = frozenset(
    {TNS_LOB_OP_OPEN, TNS_LOB_OP_CLOSE, TNS_LOB_OP_GET_CHUNK_SIZE}
)


def _lobops_state_locator(rest: bytes, source_loc_len: int) -> bytes:
    # The locator for the OPEN / CLOSE / IS_OPEN trio, which must agree on it
    # because one records a state the next reads back (#903/#887).
    #
    # Skipped by the DECLARED source length rather than a ub2 prefix, the same
    # way the READ path does it: the declared length spans the field in both
    # forms -- it is the locator's own size when the locator is raw (a column
    # LOB) and that size + 2 when it is ub2-prefixed (a temp LOB).
    rest = rest[2:]  # scn-array pointer + length
    _src_offset, rest = decode_ub4(rest)
    _dest_offset, rest = decode_ub4(rest)
    rest = rest[1:]  # amount pointer flag
    rest = rest[6:]  # three reserved ub2 array-LOB slots
    # No ub2 prefix to strip, and no guessing at whether there is one. The
    # client writes the locator RAW (`write_bytes`, which adds no length) and
    # declares `write_ub4(len(locator))` for the source length, so the declared
    # length IS the locator's -- exactly, for every op.
    #
    # An earlier version decided by looking at the bytes: strip two if the first
    # two read as len - 2. That is a coincidence, not a fact. A raw locator
    # whose opening bytes happen to hold that value lost two bytes that were
    # never a prefix, the echoed locator came back the wrong length, and the
    # client read past it -- DPY-5002. It survived an isolated run of the LOB
    # files and failed the moment the whole suite supplied other locators.
    return rest[:source_loc_len]


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


def _lobops_locator_and_tail(rest: bytes, source_loc_len: int) -> tuple[bytes, bytes]:
    # The locator field AND whatever follows it, for an op that carries a value
    # -- TRIM writes its new length there as a trailing ub4 (#826).
    #
    # By the declared source length, and the field is returned AS SENT, because
    # the reply echoes it verbatim. Reading a ub2 here instead mangles a COLUMN
    # locator, which is sent raw (#903/#887).
    rest = rest[2:]  # scn-array pointer + length
    _src_offset, rest = decode_ub4(rest)
    _dest_offset, rest = decode_ub4(rest)
    rest = rest[1:]  # amount pointer flag
    rest = rest[6:]  # three reserved ub2 array-LOB slots
    return rest[:source_loc_len], rest[source_loc_len:]


def parse_lobops_request(body: bytes) -> LobOpsRequest:
    """Classify a TTI_LOBOPS message (``body`` from ``read_packet``).

    CREATE_TEMP / WRITE drive the temp-LOB write flow (#412); FREE_TEMP releases a
    temp LOB and the OPEN / CLOSE / TRIM / GET_CHUNK_SIZE state ops are
    acknowledged (#417); anything else (a READ of an emitted column locator) is
    served by the #413 read path."""
    # The common request layout (§14.1, _LOBOPS_HEAD); then each operation's
    # own fields, to the ub2-prefixed locator (and, for a WRITE, the 0x0E
    # payload). CREATE_TEMP shares the layout up to the operation, so it is
    # classified there too. The declared source-locator-length equals the
    # locator byte count for a raw locator (a persistent / column-LOB op) and
    # that count + 2 for a ub2-length-prefixed one (a temp-LOB op), so skipping
    # this many bytes steps over the whole locator field either way.
    (head, rest) = _LOBOPS_HEAD_FROM_THIN(body)
    (source_loc_len, operation) = (head['source_length'], head['operation'])
    if operation == TNS_LOB_OP_CREATE_TEMP:
        # Classified by the OPERATION, not by the opening bytes. CREATE_TEMP used
        # to be recognised by the prefix 01 01 28, on the belief that no other
        # request could open that way. A WRITE can: it opens with a pointer flag
        # and then the locator length plus two, and a real-size 38-byte locator
        # makes that 01 01 28 exactly. The prefix only ever held because the
        # Mirror's own locators were short; sized like a real server's, every
        # WRITE became a second CREATE_TEMP and its bytes were lost (#846).
        # CLOB vs BLOB is the LOB type byte (0x70 / 0x71) in the fixed block.
        return LobOpsRequest(kind='create_temp', is_blob=0x71 in rest)
    if operation == TNS_LOB_OP_WRITE:
        rest = rest[2:]  # scn-array pointer + length
        # The 1-based position the write starts at. A client does not only
        # append: `lob.write(value, 1)` OVERWRITES from the start, so dropping
        # this put every write on the end (#903/#887).
        write_offset, rest = decode_ub4(rest)
        _dest_offset, rest = decode_ub4(rest)
        rest = rest[1:]  # amount pointer flag
        rest = rest[6:]  # three reserved ub2 array-LOB slots
        # The field as sent, by the declared source length -- which spans it in
        # both forms, so the payload after it starts in the same place either
        # way. A COLUMN LOB sends the locator RAW, and reading its first two
        # bytes as a ub2 length yielded a garbage key, so the write was filed
        # somewhere the following size() could not find (#903/#887).
        #
        # The REPLY must then echo this field verbatim (encode_lobops_echo).
        # Passing it to encode_lobops_ack instead prepends a second length --
        # 42 bytes where the client expects 40 -- which desynced 44 tests.
        locator = rest[:source_loc_len]
        rest = rest[source_loc_len:]
        if rest and rest[0] == 0x0E:
            rest = rest[1:]
        return LobOpsRequest(
            kind='write',
            locator=locator,
            payload=_decode_lobops_chunked(rest),
            offset=max(write_offset, 1),
        )
    if operation in _LOBOPS_FILE_KINDS:
        # A BFILE call: the locator carries the directory and file name, so the
        # server needs no state to answer one (#1102).
        #
        # FILE_OPEN also sends its mode as a trailing amount, which the reply
        # owes back, as a LOB's OPEN does (#1672).
        locator = _lobops_locator_after_operation(rest)
        tail = rest[2:]
        _, tail = decode_ub4(tail)
        _, tail = decode_ub4(tail)
        tail = tail[7 + 2 + len(locator) :]
        amount, _ = decode_ub4(tail) if tail else (0, b'')
        return LobOpsRequest(
            kind=_LOBOPS_FILE_KINDS[operation], locator=locator, amount=amount
        )
    if operation == TNS_LOB_OP_FREE_TEMP:
        return LobOpsRequest(
            kind='free_temp', locator=_lobops_locator_after_operation(rest)
        )
    if operation == TNS_LOB_OP_TRIM:
        # TRIM carries its new length as a trailing ub4 and is answered with that
        # length, exactly like GET_LENGTH -- not with a content-free ack, which is
        # what left `lob.trim()` desyncing (#826).
        locator, tail = _lobops_locator_and_tail(rest, source_loc_len)
        amount, _ = decode_ub4(tail) if tail else (0, b'')
        return LobOpsRequest(kind='trim', locator=locator, amount=amount)
    if operation == TNS_LOB_OP_GET_LENGTH:
        # `lob.size()`. It owes a real figure, so it cannot join the ack ops
        # above -- and it must not fall through to the column-read path, which
        # answers with a read reply and a placeholder locator (#826).
        return LobOpsRequest(
            kind='get_length', locator=_lobops_state_locator(rest, source_loc_len)
        )
    if operation == TNS_LOB_OP_IS_OPEN:
        # `lob.isopen()`. It owes a real answer, so like GET_LENGTH it cannot
        # join the ack ops -- and it must not reach the read path below, which
        # replies with a read shape the client walks off the end of (#903/#887).
        #
        # Skipped by the DECLARED source length, not by a ub2 prefix: a column
        # LOB carries its locator raw, and reading the first two locator bytes
        # as a length yields a garbage locator to echo back. The READ path below
        # draws the same distinction for the same reason (#903).
        return LobOpsRequest(
            kind='is_open', locator=_lobops_state_locator(rest, source_loc_len)
        )
    if operation in (TNS_LOB_OP_OPEN, TNS_LOB_OP_CLOSE):
        # Acknowledged like the ops below, but named apart so the server can
        # remember the open state IS_OPEN has to report back -- and extracted
        # the SAME way IS_OPEN extracts it, so the two agree on the key. They
        # did not: OPEN stripped a ub2 prefix unconditionally while IS_OPEN
        # skipped by the declared length, so on a raw column locator one of them
        # keyed on garbage and `isopen()` denied an open it had just accepted.
        field = _lobops_state_locator(rest, source_loc_len)
        # OPEN carries its MODE as the trailing amount, and the reply owes that
        # field back (encode_lobops_open_ack). CLOSE sends none.
        mode = 0
        if operation == TNS_LOB_OP_OPEN:
            tail = rest[2:]
            _s, tail = decode_ub4(tail)
            _d, tail = decode_ub4(tail)
            tail = tail[1:]
            tail = tail[6:]
            tail = tail[source_loc_len:]
            if tail:
                mode, _ = decode_ub4(tail)
        return LobOpsRequest(
            kind='open' if operation == TNS_LOB_OP_OPEN else 'close',
            locator=field,
            amount=mode,
        )
    if operation in _LOBOPS_ACK_OPS:
        return LobOpsRequest(kind='ack', locator=_lobops_locator_after_operation(rest))
    # READ (the #413 column-LOB read) and anything else fall through to the read
    # path — unchanged, so an unrecognised op behaves as before rather than worse.
    if operation == TNS_LOB_OP_READ:
        # Walk to the trailing ub8 amount the client writes last of all (#903).
        # A column-LOB READ sends the locator RAW (not ub2-length-prefixed the way
        # a temp op does), so the locator cannot be skipped by reading a length
        # prefix -- that read the first two locator bytes as a length, overshot,
        # and dropped every read to the "whole LOB from offset 1" fallback, which
        # served the wrong queue entry (#903). Skip it by the declared
        # source-locator-length instead, which spans the field in both forms.
        try:
            tail = rest[2:]  # scn-array pointer + length
            source_offset, tail = decode_ub4(tail)
            _dest_offset, tail = decode_ub4(tail)
            tail = tail[1:]  # amount pointer flag
            tail = tail[6:]  # three reserved ub2 array-LOB slots
            locator = tail[:source_loc_len]  # the locator, raw or ub2-prefixed
            tail = tail[source_loc_len:]
            amount, _ = decode_ub4(tail)
            return LobOpsRequest(
                kind='read',
                offset=max(source_offset, 1),
                amount=amount,
                locator=locator,
            )
        except (IndexError, struct.error, Truncated):
            # A shape this walk does not fit reads the LOB whole, as before.
            return LobOpsRequest(kind='read')
    return LobOpsRequest(kind='read')


# The flags byte a live 23ai sends after the character set. Clients skip it.
_CREATE_TEMP_FLAGS = 0x70


def encode_create_temp_response(locator: bytes) -> bytes:
    """The CREATE_TEMP reply (#412): the minted locator, its character set and a
    flags byte, closed by a status OER.

    Shape read off a live 23ai::

        08 | 00 26 <38 locator bytes> | 02 03 69 | 70 | 04 ... (OER)
             ub2 len + locator          charset    flags

    The reply used to stop after the locator. seerdb's own client reads the
    length-prefixed locator and nothing further, so it never noticed; a client
    that parses the whole reply reads the character set and flags, then keeps
    reading messages until a status ends the response -- and waited forever for
    one (#846). Same defect as the auth challenge that had no terminating OER
    (#830).
    """
    return _CREATE_TEMP_RESPONSE_THIN(
        {
            'locator_length': len(locator),
            'locator': locator,
            'charset': AL32UTF8_CHARSET,
            'flags': _CREATE_TEMP_FLAGS,
        }
    ) + _encode_oer(1, 0, 0, b'')


def encode_lobops_ack(locator: bytes) -> bytes:
    """A content-free TTI_LOBOPS reply: a TTI_RPA echoing the (ub2-prefixed)
    locator then a success OER. The client skips the locator via its length prefix
    and walks to the OER (``decode_lobops_oer``), so no real content is carried.
    Used for WRITE (#412) and for the FREE_TEMP / OPEN / CLOSE / TRIM /
    GET_CHUNK_SIZE state ops the Mirror acknowledges (#417)."""
    rpa = bytes([TTI_RPA]) + struct.pack('>H', len(locator)) + locator
    return rpa + _encode_oer(1, 0, 0, b'')


# The two errors a LOB's own open/close bracket raises, with the message text a
# live 23ai sends verbatim -- including ORA-22289's double space after
# "perform", which is the server's, not a typo here (#903/#887).
LOBOPS_ERR_ALREADY_OPEN = (
    ORA_LOB_ALREADY_OPENED,
    b'ORA-22293: LOB already opened in the same transaction\n',
)
LOBOPS_ERR_NOT_OPENED = (
    ORA_LOB_NOT_OPENED,
    b'ORA-22289: cannot perform  operation on an unopened file or LOB\n',
)


def encode_lobops_error(code: int, message: bytes) -> bytes:
    """A TTI_LOBOPS failure: a bare OER, with NO locator echo.

    Captured from 23ai -- a second ``lob.open()`` comes back as ``04 01 02 02 15
    43 00 02 57 15 …``: the OER token straight after the data flags, the ub4
    ``0x5715`` = 22293, then the text. A success carries the acknowledged
    locator first; a failure does not, so a reply built from
    :func:`encode_lobops_ack` with the code swapped in would desync."""
    return _encode_oer(1, code, 0, message)


def encode_lobops_is_open(locator: bytes, is_open: bool) -> bytes:
    """The IS_OPEN reply (#903/#887): the acknowledged locator, a ub1 flag, then
    a success OER.

    Shape established two ways, because one was not enough. Captured from a live
    23ai (``pkg`` LOB open/close round in python-oracledb's ``test_1904``), the
    two replies -- asked once while closed and once while open -- differ in
    THREE of 169 bytes, so the capture alone does not say which one is the
    answer. The reference client's own decoder settles it::

        if self.operation in (TNS_LOB_OP_IS_OPEN, ...):
            buf.read_ub1(&temp8)
            self.bool_flag = temp8 > 0

    It reads the echoed locator and then a single ub1: nonzero is open. The
    other two bytes that move are server-side state inside the locator, which
    the client copies over its own but does not consult here.

    A plain ack (no flag) is NOT a safe fallback -- the client reads the byte
    regardless, so it would take whatever follows and then desync.

    The locator field is echoed VERBATIM -- exactly the bytes the request
    carried, with nothing added. See :func:`encode_lobops_echo`."""
    return (
        bytes([TTI_RPA])
        + locator
        + bytes([1 if is_open else 0])
        + _encode_oer(1, 0, 0, b'')
    )


def encode_lobops_open_ack(locator_field: bytes, amount: int) -> bytes:
    """The OPEN reply: the echoed locator field, then the amount, then the OER.

    OPEN carries its MODE in the request's trailing amount, and the client reads
    an amount BACK for any op that sent one::

        elif self.send_amount:
            buf.read_sb8(&self.amount)

    so the reply owes that field. Leaving it out does not lose a value -- the
    client reads the OER's opening bytes as the amount instead and then desyncs
    (#903/#887).

    Confirmed by reply sizes on a live 23ai, which differ by exactly the field
    each op adds to the same echoed locator::

        CLOSE    168   locator only
        IS_OPEN  169   + ub1 flag
        OPEN     170   + the amount
    """
    return (
        bytes([TTI_RPA])
        + locator_field
        + encode_sb4(amount)
        + _encode_oer(1, 0, 0, b'')
    )


def encode_lobops_echo(locator_field: bytes) -> bytes:
    """A TTI_LOBOPS ack that echoes the locator field VERBATIM.

    The difference from :func:`encode_lobops_ack` is that nothing is prepended.
    A client reads the locator back with
    ``read_raw_bytes(len(its own locator))`` -- no length prefix is consumed --
    so the reply has to reproduce the field exactly as it arrived:

    - python-oracledb writes the locator raw and declares ``len(locator)`` as
      the source length, so the field IS the locator and the echo is raw;
    - a client that sends the ub2-prefixed form declares ``len + 2``, so the
      field carries its own prefix and echoing it verbatim reproduces that too.

    Echoing verbatim therefore serves both without the server having to decide
    which form it is looking at. Prepending a length unconditionally (what
    :func:`encode_lobops_ack` does) shifts every following byte for the first
    kind of client, which is what left ``lob.open()`` failing with
    ``DPY-5002: read integer of … too large`` (#903/#887)."""
    return bytes([TTI_RPA]) + locator_field + _encode_oer(1, 0, 0, b'')


def encode_lobops_length(locator: bytes, length: int) -> bytes:
    """The GET_LENGTH reply (#826): the acknowledged locator, then the LOB's
    current length, then a success OER.

    Shape read off a live 23ai -- the :func:`encode_lobops_ack` reply with a ub4
    length spliced in ahead of the status::

        08 | 00 26 <38 locator bytes> | 02 01 04 | 04 ... (OER)
             ub2 len + locator          ub4 260

    An empty LOB sends a ub4 zero (a bare ``00``), not an absent field. The
    length counts CHARACTERS for a CLOB and bytes for a BLOB, the same unit every
    other LOB call uses.

    Without this a GET_LENGTH fell through to the column-read path, which
    answered with a TTI_LOB read reply (token 0x0e) echoing a placeholder
    locator -- the wrong token and the wrong locator -- and the client desynced
    on the first ``lob.size()`` of anything it had created itself.
    """
    # Verbatim echo, like every other LOBOPS reply: the client reads the
    # locator with read_raw_bytes and consumes no length prefix (#903/#887).
    return bytes([TTI_RPA]) + locator + encode_sb4(length) + _encode_oer(1, 0, 0, b'')


def _encode_refcursor_out(bind: RefCursorOutBind) -> bytes:
    # A REF CURSOR OUT value in the IOV's RXD (#483/#84), the inverse of the
    # client's _read_refcursor_out: a 1-byte length, the inline describe body
    # (the same per-column DCB metadata a describe carries), the nested cursor
    # id, then the per-value return code.
    #
    # The trailer is the same ub4 return code (`actual_num_bytes`) that follows
    # every OUT-bind value, not a `0x01` marker: python-oracledb reads it with
    # `read_sb4` after the cursor id, so a `0x01` there is taken as a length-1
    # integer and swallows the next bind's first byte (#888). A zero return code
    # is one `0x00` byte, which the client's reader skips as its indicator all
    # the same, so both dialects stay in sync. A middle REF CURSOR OUT bind (the
    # object-type metadata cursor's `attrs_rc`) desynced every following bind.
    return _REFCURSOR_OUT_THIN(
        {
            'lead': 1,  # a length prefix the client skips
            'describe': _encode_describe_body(bind.columns),
            'cursor': bind.cursor_id,
            'return_code': 0,  # actual_num_bytes
        }
    )


def encode_refcursor_column_value(columns: list[ColumnMeta], cursor_id: int) -> bytes:
    """A nested-cursor COLUMN value in an RXD row (#826).

    `select ..., CURSOR(select ...) from ...` carries the same inline describe +
    cursor id an OUT bind does, but **without** the trailing return code an OUT
    bind ends on: in a row the next byte is the following row's TTI_RXD token.
    The reference client reads exactly `skip_ub1`, the describe body, then a ub2
    cursor id, and nothing after it.
    """
    return (
        bytes([1])  # length prefix (skipped by the client)
        + _encode_describe_body(columns)
        + encode_sb4(cursor_id)
    )


def encode_out_bind_response_thin(
    out_binds: list[ScalarOutBind | ArrayOutBind | RefCursorOutBind],
    directions: Sequence[int] = (),
    cursor_id: int = 0,
    implicit_results: bytes = b'',
) -> bytes:
    """The thin reply returning a PL/SQL block's OUT bind values (#483): a
    TTI_IOV vector + a TTI_RXD row of the values + a success OER.

    ``implicit_results`` is the TTI_IRD block of a block that also called
    ``DBMS_SQL.RETURN_RESULT`` (encode_implicit_results), which goes between
    the values and the status, as 23ai sends it (#2295).

    ``out_binds`` is one entry per bind, in bind order. ``cursor_id`` is the
    block's own server cursor, which a client needs before it will stop treating
    the statement as single-execute (#1064). ``directions`` is what the
    server reported for each (16 OUT, 32 IN, 48 IN OUT), which a backend can only
    know by asking one -- the wire carries no direction on the way in. Given
    them, an IN bind is reported IN and carries NO value, as a real server does;
    without them every bind is marked IN OUT and returns its value (#1064). Not
    OUT: a client re-executing the block sends no value for a bind it was told
    is pure OUT, and a bind that also took one input then ran NULL (#1363). IN
    OUT loses nothing -- a pure-OUT bind just sends a NULL. The client keeps only the
    positions it bound as a ``Var`` (``_assign_out_binds``). A scalar rides as a DALC + ub4 return code; a REF
    CURSOR rides as its inline describe + cursor id. The IOV header mirrors what
    ``_read_iov`` decodes: a flag, the bind count (num_requests + num_iters*256),
    the zeroed iter / buffer / bit-vector / rowid fields, then a direction byte
    per bind."""
    return (
        _encode_iov_header(len(out_binds), directions, 1)
        + _encode_out_bind_row_thin(out_binds, directions)
        + implicit_results
        + encode_status(0, cursor_id=cursor_id)
    )


def _encode_iov_header(count: int, directions: Sequence[int], iterations: int) -> bytes:
    # The TTI_IOV vector heading a block's reply, as ``_read_iov`` decodes it: a
    # flag, the bind count (num_requests + num_iters*256), how many iterations
    # this reply carries, the zeroed uac / bit-vector / rowid lengths, then one
    # direction byte per bind.
    num_requests, num_iters = count % 256, count // 256
    return (
        bytes([TTI_IOV, 0])  # token + flag
        + encode_sb4(num_requests)
        + encode_sb4(num_iters)
        + encode_sb4(iterations)
        + encode_sb4(0)  # uac buffer length
        + encode_sb4(0)  # fast-fetch bit vector length
        + encode_sb4(0)  # rowid length
        + bytes(
            directions[i] if i < len(directions) else TNS_BIND_DIR_INPUT_OUTPUT
            for i in range(count)
        )  # direction per bind
    )


def _encode_out_bind_row_thin(
    out_binds: Sequence[ScalarOutBind | ArrayOutBind | RefCursorOutBind],
    directions: Sequence[int] = (),
) -> bytes:
    # One iteration's OUT values: a TTI_RXD token then a value + return code for
    # each bind that returns one. Shared by the opening execute's reply and the
    # re-execute's, which sends one of these per iteration and nothing else.
    rxd = bytearray([TTI_RXD])
    for i, bind in enumerate(out_binds):
        if i < len(directions) and directions[i] == TNS_BIND_DIR_INPUT:
            # An IN bind carries no value back, which is why its direction has
            # to be right: a value here is read as the NEXT bind's (#1064).
            continue
        if isinstance(bind, RefCursorOutBind):
            rxd += _encode_refcursor_out(bind)
        elif isinstance(bind, ArrayOutBind):
            # ub4 element count, then each element as a value + return code.
            rxd += encode_sb4(len(bind.values))
            for element in bind.values:
                rxd += _encode_out_bind_value(
                    element, bind.tns_type, bind.csfrm
                ) + encode_sb4(0)
        else:
            rxd += _encode_out_bind_value(
                bind.value, bind.tns_type, bind.csfrm
            ) + encode_sb4(0)
    return bytes(rxd)


def encode_out_bind_reexecute_thin(
    iterations: Sequence[Sequence[ScalarOutBind | ArrayOutBind | RefCursorOutBind]],
    directions: Sequence[int] = (),
    cursor_id: int = 0,
    with_iov: bool = False,
) -> bytes:
    """The reply to a PL/SQL block re-executed by cursor id (#1064).

    One ``TTI_RXD`` per iteration, each carrying that iteration's OUT values,
    then the success OER.

    Whether an IOV heads it depends on which message asked, and both forms were
    captured off a live 23ai (§6.5c). A plain re-execute (func 4) gets **no
    IOV** -- the directions were settled by the execute that opened the cursor
    and this message cannot restate them. An ``executemany`` whose remaining four
    rows went that way is answered::

        07 02 c1 07 00 | 07 02 c1 16 00 | 07 02 c1 12 00 | 07 02 c1 2c 00 | 04 ...
        RXD  6     rc    RXD  21    rc    RXD  17    rc    RXD  43    rc    OER

    An OALL8 carrying a cursor id and no SQL is a full execute message, and its
    reply **does** carry the IOV, exactly as the opening execute's does.
    """
    head = b''
    if with_iov:
        head = _encode_iov_header(
            len(iterations[0]) if iterations else 0, directions, len(iterations)
        )
    return (
        head
        + b''.join(_encode_out_bind_row_thin(row, directions) for row in iterations)
        + encode_status(0, cursor_id=cursor_id)
    )


def _prefetched_image_value(value: object, tns_type: int) -> bytes:
    """A JSON or VECTOR value as the reply carries it: the IMAGE, prefetched,
    with the locator behind it (§22.1b).

    Neither type is ever fetched over TTI_LOBOPS -- the server puts the whole
    value in the reply and the client reads it there. Three carriers need this
    and each had to learn it separately: the column (#887), the RETURNING bind
    (§22.1c), and the OUT bind (#1010), which was still minting a locator."""
    if tns_type == TNS_TYPE_JSON:
        from seerdb.common.oson import encode_oson

        # allow_wide so a > 255-key or > 64 KiB document still re-encodes.
        return encode_prefetched_lob_value_thin(encode_oson(value, allow_wide=True))
    return encode_prefetched_lob_value_thin(encode_vector(value))


def _encode_out_bind_value(
    value: object, tns_type: int, csfrm: int = _CSFRM_DB
) -> bytes:
    # One scalar OUT-bind value for the IOV's RXD. A BINARY_INTEGER / PLS_INTEGER
    # OUT bind (``TNS_TYPE_INT``) rides as a NUMBER, not the native integer the
    # column form uses: the client reads ``DB_TYPE_BINARY_INTEGER`` as a NUMBER,
    # and a native ``encode_sb4`` would render 0 as an empty DALC that reads back
    # as NULL -- python-oracledb then rejects the object-type metadata call with
    # ``DPY-2035`` because its ``ret_val`` came back NULL rather than 0 (#888).
    if tns_type in _PREFETCHED_IMAGE_TYPES and value is not None:
        # A JSON or VECTOR OUT bind carries its IMAGE, prefetched into the
        # reply, not a locator to fetch it with -- the same framing the column
        # (#887) and RETURNING (§22.1b) carriers use, and the third of the three
        # to need saying so (#1010). Falling through to encode_value minted a
        # locator, 41 bytes whatever the value, and the client ran off the end
        # of it.
        return _prefetched_image_value(value, tns_type)
    if tns_type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW):
        # A LONG / LONG RAW OUT bind is a plain DALC, as a LONG return bind is
        # (§22) -- not the chunked form a LONG COLUMN takes in a row, which is
        # what encode_value gives it. Measured on 23ai, `begin :v := 'abc';
        # end;` with a LONG :v returns `03 61 62 63` and the return code; the
        # column form's chunk marker and trailing indicators desynced the
        # client, "unknown protocol message type 0" (#1458).
        if value is None:
            return bytes([0])
        payload = (
            bytes(value)
            if isinstance(value, (bytes, bytearray))
            else str(value).encode('utf-8')
        )
        return _bytes_with_length(payload)
    if tns_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
        # A LOB-class OUT bind's value is the LOB block, not a DALC (§6.5,
        # #979). This has to sit ahead of the national-charset branch: an NCLOB
        # OUT bind is a CLOB with csfrm 2, and encoding it as UTF-16BE text
        # would hand the LOB reader a DALC.
        return encode_lob_bind_block(value, is_clob=tns_type == TNS_TYPE_CLOB)
    if csfrm == _CSFRM_NCHAR and isinstance(value, str):
        # National character data travels as UTF-16BE, the same form a
        # national COLUMN uses in a row (_national_wire_value). #826.
        return _bytes_with_length(value.encode('utf-16-be'))
    if tns_type == TNS_TYPE_INT and isinstance(value, (int, float, Decimal)):
        value = int(value) if isinstance(value, Decimal) else value
        # Decimal counts: a backend reading a NUMBER hands one back by default,
        # and leaving it out sent the value down the native-integer path, where
        # a non-integral or negative value raised `struct.error` INSIDE the
        # encoder -- a crash, not an ORA error, so the session died (#1044).
        return _bytes_with_length(encode_token_num(value))
    if tns_type == TNS_TYPE_ADT:
        # An object (ADT) OUT-bind slot — e.g. the echoed object IN bind of a
        # callfunc/callproc. The client reads this position with the object
        # framing (read_dbobject), so it must carry the full frame even when the
        # value is None (an IN-only object whose OUT value the Mirror leaves
        # unset); a bare 0x00 DALC would desync the reader (#888).
        return encode_object_column_value(value)
    return encode_value(value, tns_type)


# The session-state reply (§20.6, #973). A server that changed a session
# attribute reports the new value back in the execute's return-parameters block,
# and that is where a client reads `connection.current_schema` from -- it never
# queries for it. Reconstructed from three live 23ai captures taken with schema
# names of different lengths, which separated the value from its frame.
#
# The words below are named for where they sit, not for what they mean: the
# capture pins their values but not their purpose. They are constant across
# every capture, including ones that changed a DIFFERENT attribute
# (nls_date_format, time_zone), which is what makes them frame rather than
# payload.
_STATE_AL8O4L_FIELDS = 6  # the leading al8o4l count
_STATE_LEAD = bytes.fromhex('040000000000010201020000000000')[:0]  # placeholder
# The frame either side of the entry list, byte for byte from the capture.
_STATE_PREFIX_TAIL = bytes.fromhex('0000001705010110')
_STATE_ENTRY_TYPE = 0x16  # the type byte every entry carries
_STATE_KEY_CURRENT_SCHEMA = 0x02
_STATE_KEY_EDITION = 0x01
# The two entries that always follow the changed value (keys 0xa8 / 0xa9). Their
# payloads move with the session -- they look like counters -- but nothing reads
# them back, and a reply that DROPS them is rejected by the client, so they are
# carried as captured. Everything after them is the ordinary status, which is
# generated: hardcoding the captured one froze its sequence number and the
# client waited for a reply that never matched.
_STATE_TRAILING_ENTRIES = bytes.fromhex('0001a8000104040000008801a900')
# An EDITION change carries a different trailing entry (key 0xac) -- captured the
# same way, by altering that one attribute on a live 23ai.
_STATE_TRAILING_ENTRIES_EDITION = bytes.fromhex('0001ac00')


def encode_session_state_response(
    schema: str,
    *,
    key: int = _STATE_KEY_CURRENT_SCHEMA,
    scn: int = 0x01B6FF73,
    seq: int = 2,
) -> bytes:
    """The reply that reports a new CURRENT_SCHEMA back to the client (#973).

    `alter session set current_schema = X` does not just succeed: the server
    answers with the return-parameters block carrying the new value, and the
    client updates `connection.current_schema` from it. Answering with a bare
    status leaves the client's attribute stale forever, because it never asks.

    The value rides as a ub4 length followed by a DALC that repeats it -- the
    same double-length shape the SET_SCHEMA piggyback uses in the other
    direction (§20.5).
    """
    name = schema.strip('"').upper().encode('utf-8')
    body = _SESSION_STATE_RESPONSE_THIN(
        {
            'al8o4l': _STATE_AL8O4L_FIELDS,
            'scn': scn,
            'word_1': 0,
            'sequence': seq,
            'word_2': 2,
            'word_3': 0,
            'word_4': 0,
            'prefix_tail': _STATE_PREFIX_TAIL,
            'entry_count': 1,
            'key': key,
            'entry_type': _STATE_ENTRY_TYPE,
            'name_length': len(name),
            'name_byte_length': len(name),
            'name': name,
        }
    )
    trailing = (
        _STATE_TRAILING_ENTRIES_EDITION
        if key == _STATE_KEY_EDITION
        else _STATE_TRAILING_ENTRIES
    )
    return body + trailing


def encode_returning_response(
    rowcount: int,
    iterations: list[list[tuple]],
    return_types: list[int],
    *,
    cursor_id: int = 0,
    max_sizes: list[int] | None = None,
) -> bytes:
    """The reply to a `DML ... RETURNING col INTO :b` execute (#689).

    One `TTI_RXD` per execute iteration, then the ordinary success status. A
    plain execute is one iteration; an array execute is one per row submitted,
    and an iteration that matched nothing still sends its record, with a zero
    count, so the client's positions stay aligned with the rows it sent
    (docs/PROTOCOL.md 22 and 22.1).

    Within a record the values are grouped **by bind, not by row**: for each
    return bind in bind order, the number of rows that iteration affected, then
    that many values, each a DALC followed by an sb4 **actual length** -- 0 when
    the value fitted the client's variable, -1 when it is NULL, its untruncated
    length when it did not fit (#1021). ``max_sizes`` is what the client
    declared for each return bind, and writing that field correctly is the only
    way to tell a client its variable was too small: a value longer than the
    buffer is cut to it and its real length written here, which is what a real
    server does. Without the sizes nothing is truncated and every length is 0 or
    -1 (#1023). ``iterations`` arrives the other way round, as the rows each
    iteration returned, so it is transposed here.

    A JSON or VECTOR bind is the exception to "each a DALC": its value comes back
    as the prefetched binary image with a locator behind it, the same framing such
    a column uses in a row (#826). A bare locator there is read as the metadata
    form and fails with ``DPY-5002``.
    """
    out = bytearray()
    for rows in iterations:
        out.append(TTI_RXD)
        for position, tns_type in enumerate(return_types):
            out += encode_sb4(len(rows))
            limit = (
                max_sizes[position]
                if max_sizes is not None and position < len(max_sizes)
                else 0
            )
            for row in rows:
                value = row[position] if position < len(row) else None
                value = _as_return_bind_type(value, tns_type)
                value, actual = _fit_returned_value(value, tns_type, limit)
                out += _returned_value(value, tns_type) + _encode_signed_sb4(actual)
    return bytes(out) + encode_status(rowcount, cursor_id=cursor_id)


def _as_return_bind_type(value: object, tns_type: int) -> object:
    # A returned value is the RETURN BIND's type, which need not be its column's:
    # `RETURNING IntCol INTO :v` with a VARCHAR :v gets the number as text, as
    # Oracle converts it -- TO_CHAR's default, so 0.5 is '.5' (#1501). The value
    # arrives as the column gave it, and encode_value goes by the value's own
    # type, so a number went out as NUMBER bytes in a VARCHAR and the client could
    # not decode it.
    if tns_type not in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR):
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return value
    text = format(Decimal(str(value)).normalize(), 'f')
    if '.' in text:
        text = text.rstrip('0').rstrip('.')
    if text.startswith('0.'):
        text = text[1:]
    elif text.startswith('-0.'):
        text = '-' + text[2:]
    return text


# The return-bind types whose declared size is a real client buffer, so a value
# longer than it is truncated rather than rejected. A NUMBER or DATE is fixed
# width and always fits; a LONG-class bind is unbounded; a LOB, OBJECT or
# JSON / VECTOR bind carries its own framing and its length field says nothing
# about a buffer (§22.1b-e).
_TRUNCATABLE_RETURN_TYPES = (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_RAW)


def _fit_returned_value(value: object, tns_type: int, limit: int) -> tuple:
    # One returned value cut to the client's declared buffer, with the actual
    # length that goes after it (#1023). -1 for a NULL, 0 for a value that
    # fitted, and the untruncated length for one that did not -- the client has
    # no other way to learn its variable was too small, and a Mirror that always
    # wrote 0 handed back half a string and called it an answer.
    if value is None:
        return (None, -1)
    if limit <= 0 or tns_type not in _TRUNCATABLE_RETURN_TYPES:
        return (value, 0)
    if isinstance(value, (bytes, bytearray)):
        return (bytes(value)[:limit], len(value)) if len(value) > limit else (value, 0)
    if isinstance(value, str):
        payload = value.encode('utf-8')
        if len(payload) <= limit:
            return (value, 0)
        # Cut on a character boundary: a buffer that splits a multi-byte
        # character would hand the client an undecodable tail.
        return (payload[:limit].decode('utf-8', 'ignore'), len(payload))
    return (value, 0)


def _returned_value(value: object, tns_type: int) -> bytes:
    # One RETURNING out-bind value. JSON and VECTOR carry their image inline, the
    # way the row encoder sends them (#826/#887); a CLOB / BLOB carries the LOB
    # block a fetched column carries; an OBJECT / collection carries the object
    # frame a column uses; everything else is a DALC.
    if tns_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
        # `RETURNING ClobCol INTO :b` (§22.1d, #987). Sent as a DALC the client
        # read the block length as the whole value and got an EMPTY string back
        # -- not an error, which is what makes this one worth a test: it was the
        # right shape and the wrong content.
        return encode_lob_bind_block(value, is_clob=tns_type == TNS_TYPE_CLOB)
    if tns_type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW):
        # A LONG return bind is a plain DALC -- NOT the 0xFE-chunked inline
        # framing a LONG COLUMN uses in a row, which is what encode_value would
        # give it. Measured on a live 23ai returning a CLOB column into a
        # DB_TYPE_LONG var, the whole reply is:
        #
        #   07 | 01 01 | 13 <19 bytes> | 00 | 08 ...
        #   ^RXD  ^rows   ^DALC          ^trunc
        #
        # The column framing adds a chunk marker and two trailing indicators, so
        # the client read those as the next field and the reply desynced on a
        # zero byte -- reported as "unknown protocol message type 0" (#987).
        if value is None:
            return bytes([0])
        payload = (
            bytes(value)
            if isinstance(value, (bytes, bytearray))
            else str(value).encode('utf-8')
        )
        return _bytes_with_length(payload)
    if tns_type == TNS_TYPE_ADT:
        # `RETURNING ObjectCol INTO :b`. Encoded as a DALC the value was asked
        # for a scalar wire form it has none of, and the Mirror answered
        # ORA-03115 "no wire encoding for a column value of type DbObject"
        # (#826). The TOID comes off the value's own type, as a column's does.
        return encode_object_column_value(value)
    if tns_type not in _PREFETCHED_IMAGE_TYPES or value is None:
        return encode_value(value, tns_type)
    return _prefetched_image_value(value, tns_type)


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
        # The message text is not decoration: a client reads the error number
        # first and only reads a message when it is non-zero, so a 1403 with an
        # empty message leaves it with None where a string must be (#893). Every
        # other end-of-fetch terminator carries the same text.
        return _encode_oer(
            0,
            ORA_NO_DATA_FOUND,
            server_rowcount,
            b'ORA-01403: no data found\n',
            cursor_id=cursor_id,
        )
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
    (fields, _rest) = _FETCH_FROM_THIN(payload)
    return FetchRequest(cursor=fields['cursor'], fetch=fields['rows'])


def parse_reexecute(
    payload: bytes,
    bind_types: list | None = None,
    max_string_size: int = 4000,
    bind_directions: Sequence[int] = (),
    cached_plsql: bool = False,
) -> ReexecuteRequest:
    """Parse a re-execute message: ``[TTI_FUN, func, seq]`` + ub4 cursor id +
    ub4 iterations + ub4 options + ub4 options, then -- when the statement has
    binds -- one ``TTI_RXD`` row of values per iteration.

    Layout taken from the reference thin client's writer rather than inferred,
    and confirmed against live 23ai captures. The fetch-carrying form (78) of a
    bind-less query is eleven bytes::

        03 4e 04 | 00 | 01 01 | 01 02 | 01 20 | 00
                 token  cursor  iters   opts_1  opts_2

    and the plain form (4) re-running ``INSERT ... VALUES (:1, :2)`` with
    ``(2, 'row2')`` is the same header and then the row (#854)::

        03 04 08 | 00 | 01 03 | 01 01 | 00 | 00 | 07 02 c1 03 04 72 6f 77 32
                 token  cursor  iters  opts   RXD  NUMBER 2   'row2'

    The rows carry **no OACs**: the values are typed by the OACs of the
    execute that opened the cursor, which the server is expected to remember.
    Pass them as ``bind_types`` (the ``(data_type, csfrm, max_size, toid)`` list
    :func:`parse_exec` exposes as ``ExecRequest.bind_types``) and the rows
    decode into ``bind_rows``; without them the rows are left unread. A bind
    declared wider than ``max_string_size`` is LONG-class and rides after the
    row's other values, as on the opening execute.

    ``bind_directions`` is what the server reported for the statement's binds
    the first time it ran (16 OUT, 32 IN, 48 IN OUT). It matters only for a
    PL/SQL block, whose pure-OUT binds send **no value** on a re-execute -- the
    client has nothing to send for them. Reading one anyway consumes the next
    bind's bytes and the row falls apart a position at a time. Ordinary DML has
    no OUT binds, so it passes nothing here and every bind carries a value.

    ``cached_plsql`` says the cursor stands for a block, which the message
    itself cannot say (it carries no statement). A block's LONG-class binds ride
    **in place** rather than last, and a block's binds are routinely wide -- a
    VARCHAR OUT bind declares 16000 -- so reading the row in the DML order put
    the first value second.

    ``iterations`` is the client's prefetch size for the fetch-carrying form, so
    it doubles as the batch size for the reply; for the plain form it is the
    number of executions, one bind row each.
    """
    if len(payload) < 3 or payload[0] != TTI_FUN:
        raise InterfaceError('not a re-execute')
    (fields, rest) = _EXEC_BY_CURSOR_FROM_THIN(payload)
    (cursor, iterations) = (fields['cursor'], fields['iterations'])
    (options, options_2) = (fields['options'], fields['options_2'])
    bind_rows: list = []
    if bind_types:
        types = list(bind_types)
        # A cached cursor carries no array binds and no clause-filled positions,
        # so every bind sends a value with the LONG-class ones last -- except a
        # PL/SQL block, whose pure-OUT binds send nothing at all and whose wide
        # binds ride in place (#1064). A position left out of `order` keeps None
        # in the row.
        long_binds = (
            []
            if cached_plsql
            else [
                i
                for i, (_t, _c, maxlen, _o) in enumerate(types)
                if maxlen > max_string_size
            ]
        )
        sends_value = [
            i
            for i in range(len(types))
            if i >= len(bind_directions) or bind_directions[i] != TNS_BIND_DIR_OUTPUT
        ]
        order = [i for i in sends_value if i not in long_binds] + [
            i for i in long_binds if i in sends_value
        ]
        bind_rows, _rest = _read_bind_rows(rest, types, [0] * len(types), order)
    return ReexecuteRequest(
        cursor=cursor,
        fetch=iterations,
        options=options,
        bind_rows=bind_rows,
        autocommit=bool(options_2 & TNS_EXEC_OPTION_COMMIT_REEXECUTE),
    )


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
        and not oci.pointer_present(payload[_OCI_ALL8_IND_OFF : _OCI_ALL8_IND_OFF + 8])
    )


# A re-execute by cursor id carries no SQL, and the thin al8i4 array starts where
# the SQL's length would be: its first element 0 (no parse), its second the rows
# the client has room for. sqlplus 23.26 fetching a REF CURSOR, 11g and 18c
# alike: `00 00 00 00 0f 00 00 00` there, 15 rows (#2014).
_OCI_REEXEC_ROWS_FROM_SQL = 3


def parse_reexecute_oci(payload: bytes) -> tuple[int, int]:
    """The cursor id and the number of rows an OCI re-execute asks for (#2014)."""
    if not is_reexecute_oci(payload):
        raise InterfaceError('not an OCI re-execute')
    (cursor, length_at) = _oci_all8_head(payload, sql_present=False)[:2]
    at = length_at + 1 + _OCI_REEXEC_ROWS_FROM_SQL
    if len(payload) < at + 4:
        raise InterfaceError('OCI re-execute: no fetch count')
    return cursor, int.from_bytes(payload[at : at + 4], 'little')


def parse_fetch_oci(payload: bytes) -> int:
    """How many rows an OCI ``TTI_FETCH`` asks for: `03 05 <seq>`, then the
    cursor id and the rows the client has room for, each a ub4 LE (live
    11g/18c: `03 05 0f 02 00 00 00 0f 00 00 00` asks cursor 2 for 15 rows).

    sqlplus sizes its fetch buffer to this count, so a reply carrying more rows
    than it asked for overruns that buffer and crashes it (#1284).
    """
    if len(payload) < 11 or payload[0] != TTI_FUN or payload[1] != TTI_FETCH:
        raise InterfaceError('not an OCI TTI_FETCH')
    return _FETCH_FROM_OCI(payload)[0]['rows']


def is_version_call_oci(payload: bytes) -> bool:
    """True if this is the sqlplus / thick-OCI post-login version request.

    The version call and the sqlplus ``PASSWORD`` changepassword both arrive as a
    TTI_80SES (``0x11 0x6b``) piggyback and share the same 15-byte prefix; they
    differ only in the wrapped TTI function (``0x3b`` version vs. ``TTI_AUTH``).
    Match the inner function too, so a piggybacked changepassword is not mistaken
    for the version request (and answered with the banner)."""
    return (
        payload[:2] == oci.OCI_PIGGYBACK_80SES
        and payload[_OCI_80SES_FIXED : _OCI_80SES_FIXED + 2] == b'\x03\x3b'
    )


def encode_version_banner_oci(banner: bytes, release: int = VERSION_11_2_0_2) -> bytes:
    """Build the sqlplus / thick-OCI version reply — the server's banner (#265).

    Returns the TTC payload from the TTI_RPA token: the banner as a DALC value
    (ub2 count + single ub1 chunk, since the banner is well under 254 bytes) and
    the trailer: the packed ``release``, which sqlplus prints for SHOW RELEASE
    (#2024), and the capability word.
    """
    return (
        bytes([TTI_RPA])
        + len(banner).to_bytes(2, 'little')
        + bytes([len(banner)])
        + banner
        + b'\x00'  # DALC terminator
        + _oci_version_trailer(release)
    )


# The classic sqlplus / thick-OCI OALL8 arrives wrapped in an OCCA (close-cursors)
# piggyback for every statement past the first: `0x11 0x69`, then a fixed prefix
# (seq, an 8-byte indicator, the cursor count in 8 bytes), one ub4 id per closed
# cursor, then the real TTI_FUN execute. Strip it so the execute can be parsed.
# Live 11g, sqlplus closing cursors 3 and 1:
#   11 69 11 | fe ff..ff | 02 00 00 00 00 00 00 00 | 03 00 00 00 01 00 00 00 | 03 5e
# Read as one 8-byte entry per cursor instead, a single cursor landed on the same
# byte and two cut 4 bytes into the call (#1517).
_OCI_PIGGYBACK = bytes([TTI_MSG_TYPE_PIGGYBACK, TTI_OCCA])


# The version call and sqlplus PASSWORD changepassword instead arrive wrapped in
# a TTI_80SES (0x11 0x6b) piggyback: a fixed 15-byte prefix (0x11 0x6b, a seq
# byte, and a 12-byte session-switch preamble) then the real TTI_FUN call. The
# preamble length is constant across captures (only the seq/count bytes vary), so
# the inner call always starts at offset 15.
_OCI_80SES_FIXED = 15


# The OCI object-type describe, function 92 (docs/PROTOCOL.md §40, #1411). An
# OCI client asks for a type by name or by REF; the reply is one or more records,
# each a pickled type-descriptor object (an instance of SYS.KOTTD / KOTTB / KOTAD,
# whose own descriptors are answered the same way). Fixed-width little-endian.
KOD_BY_NAME = 3
KOD_BY_REF = 4
_KOD_RECORD = b'\x0d\x01'
_KOD_BY_NAME_REPLY = b'\x0d\x02'
_KOD_NAME_OFF = 99  # after `03 5c <seq>`, the ub4 opcode and 92 zero bytes
_KOD_REF_LEN = 36


class KodRequest(NamedTuple):
    opcode: int
    schema: str | None
    name: str | None
    ref: bytes | None


class KodRecord(NamedTuple):
    """One described object: the id of its system type, its own id, its image."""

    type_id: bytes
    oid: bytes
    image: bytes


class KodReply(NamedTuple):
    # (schema, name, REF) of the by-name header; None for a by-REF reply.
    named: tuple[str, str, bytes] | None
    records: list[KodRecord]


def _kod_item(data: bytes, at: int) -> tuple[bytes, int]:
    # A ub4 LE length, then that many bytes.
    length = int.from_bytes(data[at : at + 4], 'little')
    end = at + 4 + length
    if end > len(data):
        raise Truncated(f'KOD item of {length} bytes runs off the end')
    return data[at + 4 : end], end


def _kod_text(data: bytes, at: int) -> tuple[str, int]:
    # A name: a ub4 count, then the ub1 length and the bytes again.
    size = data[at + 4]
    end = at + 5 + size
    return data[at + 5 : end].decode('utf-8'), end


def _kod_ref_id(ref: bytes) -> bytes:
    # A 36-byte REF item: `24 00`, a flags triple, the 16-byte id, 15 more bytes.
    if len(ref) != _KOD_REF_LEN:
        raise InterfaceError(f'KOD REF of {len(ref)} bytes, not {_KOD_REF_LEN}')
    return ref[5:21]


def _kod_dalc(data: bytes, at: int) -> tuple[bytes, int]:
    # A ub1 length, or 0xFE then ub1-length chunks ending in a zero one.
    first = data[at]
    if first != TNS_LONG_LENGTH_INDICATOR:
        return data[at + 1 : at + 1 + first], at + 1 + first
    at += 1
    out = bytearray()
    while True:
        size = data[at]
        at += 1
        if size == 0:
            return bytes(out), at
        out += data[at : at + size]
        at += size


def parse_kod_request(payload: bytes) -> KodRequest:
    """The type an OCI ``TTI_KOD`` call asks for (PROTOCOL.md §40.1)."""
    if len(payload) < 7 or payload[0] != TTI_FUN or payload[1] != TTI_KOD:
        raise InterfaceError('not a TTI_KOD call')
    opcode = int.from_bytes(payload[3:7], 'little')
    if opcode == KOD_BY_NAME:
        at = _KOD_NAME_OFF + 4
        # The schema's buffer length (3 x its characters), then the schema as a
        # ub1 length and its bytes -- absent when the buffer is empty, as for a
        # type of the user's own -- and four zero bytes. sqlplus names SYS for
        # an XMLTYPE column's type (#2050).
        schema_len = int.from_bytes(payload[at : at + 4], 'little')
        at += 4
        schema = None
        if schema_len:
            size = payload[at]
            schema = payload[at + 1 : at + 1 + size].decode('utf-8')
            at += 1 + size
        at += 4
        at += 4  # the name's buffer length, 3 x its characters
        name_len = payload[at]
        name = payload[at + 1 : at + 1 + name_len].decode('utf-8')
        return KodRequest(opcode, schema, name, None)
    if opcode == KOD_BY_REF:
        at = payload.index(b'\x24\x00\x00\x00\x24\x00', 7)
        (ref, _end) = _kod_item(payload, at)
        return KodRequest(opcode, None, None, ref)
    raise InterfaceError(f'KOD opcode {opcode} is not decoded yet')


def decode_kod_reply(payload: bytes) -> KodReply:
    """A ``TTI_KOD`` reply's header and records, up to the closing OER (§40.2)."""
    at = 0
    named = None
    if payload[:2] == _KOD_BY_NAME_REPLY:
        at = 6  # 0d 02, then a ub4 2
        (schema, at) = _kod_text(payload, at)
        at += 4
        (name, at) = _kod_text(payload, at)
        at += 1
        (ref, at) = _kod_item(payload, at)
        at += 2  # 01 00
        if payload[at : at + 4] == bytes(4):
            at += 4  # the 12c band's longer tail
        named = (schema, name, ref)
    records = []
    while payload[at : at + 2] == _KOD_RECORD:
        (type_ref, at) = _kod_item(payload, at + 2)
        at += 1
        (own_ref, at) = _kod_item(payload, at)
        at += 1
        if payload[at : at + 4] == _KOD_RECORD_DESC_12C[:4]:
            at += len(_KOD_RECORD_DESC_12C)  # the 12c band's bare descriptor
        else:
            (_desc, at) = _kod_item(payload, at)
        at += 3 + 4 + 2  # 00 01 00, the ub4 image length, 09 00
        (image, at) = _kod_dalc(payload, at)
        records.append(KodRecord(_kod_ref_id(type_ref), _kod_ref_id(own_ref), image))
    return KodReply(named, records)


def decode_kod_image(image: bytes) -> list[bytes | None]:
    """The attribute values of a type-descriptor image, in order (§40.3).

    The image is a pickled object: ``85 01``, its length (a ub1, or ``fe`` and a
    ub4 BE), then each value as a ub1 length, ``fe`` + ub4 BE, or ``ff`` for NULL.
    """
    at = 2
    at += 5 if image[at] == TNS_LONG_LENGTH_INDICATOR else 1
    values: list[bytes | None] = []
    while at < len(image):
        size = image[at]
        if size == TNS_NULL_LENGTH_INDICATOR:
            values.append(None)
            at += 1
        elif size == TNS_LONG_LENGTH_INDICATOR:
            size = int.from_bytes(image[at + 1 : at + 5], 'big')
            values.append(image[at + 5 : at + 5 + size])
            at += 5 + size
        else:
            values.append(image[at + 1 : at + 1 + size])
            at += 1 + size
    return values


# The ids of the system types whose instances describe a type (§40.3). They are
# the same in every database.
KOD_KOTTD = bytes(15) + b'\x01'
# A REF as KOD carries it (§40.2): `24 00`, a flags triple, the 16-byte id, then
# 15 bytes that were `00 x 13 01 00` in every capture. The metatypes' own records
# carry 0x12 in the flags, everything else 0x02.
_KOD_REF_FLAGS_SYSTEM = b'\x22\x12\x08'
_KOD_REF_FLAGS_USER = b'\x22\x02\x08'
_KOD_REF_TAIL = bytes(13) + b'\x01\x00'
# A record's 24-byte descriptor: `18 00`, three bytes that differed per session
# and stayed fixed within one -- fb b9 81, then fc 09 86, fc 09 87 ... across
# later captures, climbing like a counter -- then zeros. This is the value the
# sqlplus capture carried.
_KOD_RECORD_DESC = b'\x18\x00\xfb\xb9\x81' + bytes(19)
# In the 12c band the descriptor is a different 35 bytes -- `22 00 de ad be ef
# 00 01 00 22`, five zeros, three per-session bytes, zeros -- sent bare, with no
# length in front (sqlplus 23.26 against a live 18c). Sending the 11g form to a
# client in that band made it break the call off (#1411).
_KOD_RECORD_DESC_12C = bytes.fromhex('2200deadbeef000100220000000000694719') + bytes(17)
# The by-name header ends `01 00` in the 11g band, `01 00 00 00 00 00` in the 12c.
_KOD_NAMED_TAIL = b'\x01\x00'
_KOD_NAMED_TAIL_12C = b'\x01\x00' + bytes(4)
_KOD_IMAGE_FLAGS = 0x85  # a pickled object (§21.3)
_KOD_IMAGE_VERSION = 0x01


def _kod_ref(oid: bytes, *, system: bool) -> bytes:
    flags = _KOD_REF_FLAGS_SYSTEM if system else _KOD_REF_FLAGS_USER
    return b'\x24\x00' + flags + oid + _KOD_REF_TAIL


def _kod_item_bytes(data: bytes) -> bytes:
    return len(data).to_bytes(4, 'little') + data


def encode_kod_image(
    values: list[bytes | None], *, flags: int = _KOD_IMAGE_FLAGS
) -> bytes:
    """A type-descriptor image from its attribute values; :func:`decode_kod_image`
    reversed. Each value is a ub1 length, or ``fe`` + ub4 BE beyond 245 bytes,
    or ``ff`` for NULL; the length after ``85 01`` counts the whole image."""
    body = bytearray()
    for value in values:
        if value is None:
            body.append(TNS_NULL_LENGTH_INDICATOR)
        elif len(value) <= _OBJ_MAX_SHORT_LEN:
            body += bytes([len(value)]) + value
        else:
            body += bytes([TNS_LONG_LENGTH_INDICATOR]) + len(value).to_bytes(4, 'big')
            body += value
    total = 2 + 5 + len(body)
    return (
        bytes([flags, _KOD_IMAGE_VERSION, TNS_LONG_LENGTH_INDICATOR])
        + total.to_bytes(4, 'big')
        + bytes(body)
    )


def _kod_record(record: KodRecord) -> bytes:
    image = record.image
    framed = bytearray()
    if len(image) <= TNS_MAX_SHORT_LENGTH:
        framed += bytes([len(image)]) + image
    else:
        framed.append(TNS_LONG_LENGTH_INDICATOR)
        for at in range(0, len(image), 0xFF):
            chunk = image[at : at + 0xFF]
            framed += bytes([len(chunk)]) + chunk
        framed.append(0)
    return (
        _KOD_RECORD
        + _kod_item_bytes(_kod_ref(record.type_id, system=True))
        + b'\x01'
        + _kod_item_bytes(_kod_ref(record.oid, system=record.oid in _KOD_SYSTEM_VALUES))
        + record.type_id[-1:]
        + (
            _KOD_RECORD_DESC_12C
            if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
            else _kod_item_bytes(_KOD_RECORD_DESC)
        )
        + b'\x00\x01\x00'
        + len(image).to_bytes(4, 'little')
        + b'\x09\x00'
        + bytes(framed)
    )


def encode_kod_reply(records: list[KodRecord], *, sequence: int) -> bytes:
    """A by-REF ``TTI_KOD`` reply: the records, then the success OER (§40.2).

    Two of the OER's bytes follow the band: the row kind (offset 8) and offset
    52 are 1 from a live 11g and 0 from a live 18c."""
    wide = _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
    oer = encode_oci_oer(
        oci.OCI_OER_STATUS_SUCCESS,
        sequence=sequence,
        row_kind=oci.OCI_OER_ROW_KIND_NONE if wide else oci.OCI_OER_ROW_KIND_LOB,
        command_type=0,
        category=0,
        unpinned_52=0 if wide else 1,
    )
    return b''.join(_kod_record(r) for r in records) + oer


# SYS.KOTTD's description of itself, the answer to every client that has just
# been handed a type descriptor and asks how to read one (§40.3). Its values, in
# its own attribute order: a flags word, schema, name, version, the typecode
# (108, an object), its TDS, the null-image TDS, two unnamed ub2s and the REF of
# its attribute part. The TDS is ten leaves -- `0e`, three `07 00 1e 01 00 00`
# (VARCHAR(30)), `0d`, `11`, `11`, `0d`, `0d`, `09` -- one per attribute here.
# Captured from a live 11g; the same in every database.
_KOTTD_VALUES: list[bytes | None] = [
    bytes.fromhex('ae9a0001'),
    b'SYS',
    b'KOTTD',
    b'$8.0',
    (108).to_bytes(2, 'big'),
    bytes.fromhex(
        '0000003c26010001000a002900000000001f0e07001e01000007001e01000007001e01'
        '00000d11110d0d092a00070008000e0014001a001b001c001d001e001f'
    ),
    bytes.fromhex(
        '0000003026010001000b00290000000000111a1a1a1a1a1a1a1a1a1a1a2a0007000800'
        '09000a000b000c000d000e000f00100011'
    ),
    (0x16).to_bytes(2, 'big'),
    (1).to_bytes(2, 'big'),
    bytes.fromhex(
        '00220208ab9eebb9d66392fce040e50a194e468000000000000000000000000000010002'
    ),
]
# In the 12c band KOTTD's names are VARCHAR(128) -- the identifier length 12.2
# raised -- and its attribute part has another id; the rest is the same
# (sqlplus 23.26 against a live 18c).
_KOTTD_VALUES_12C: list[bytes | None] = [
    *_KOTTD_VALUES[:5],
    bytes.fromhex(
        '0000003c26010001000a002900000000001f0e070080010000070080010000070080'
        '0100000d11110d0d092a00070008000e0014001a001b001c001d001e001f'
    ),
    *_KOTTD_VALUES[6:9],
    bytes.fromhex(
        '00220208787d054056ed64c1e0530caae80aa10700000000000000000000000000010002'
    ),
]
_KOD_SYSTEM_VALUES: dict[bytes, list[bytes | None]] = {KOD_KOTTD: _KOTTD_VALUES}
_KOD_SYSTEM_VALUES_12C: dict[bytes, list[bytes | None]] = {KOD_KOTTD: _KOTTD_VALUES_12C}


# A user type's KOTTD values that do not depend on the type (§40.3): the flags
# word, the version string and the unnamed ub2 that was 1 for every type seen.
_KOD_TYPE_FLAGS = bytes.fromhex('ae9a0001')
_KOD_TYPE_VERSION = b'$8.0'
_KOD_TYPE_UB2 = (1).to_bytes(2, 'big')
# The typecode and the kind word, by kind: an object is typecode 108 with kind
# 0x0004; a collection is typecode 122, 0x8000 for a VARRAY, 0x0080 for a
# nested table. Captured from a live 11g for each kind.
_KOD_TYPECODES = {
    'object': (108, 0x0004),
    'varray': (122, 0x8000),
    'nested_table': (122, 0x0080),
}
# The REF an image carries to the type's next part: the part's id, flags and
# tail as in every capture.
_KOD_IMAGE_REF_HEAD = b'\x00\x22\x02\x08'
_KOD_IMAGE_REF_TAIL = bytes(13) + b'\x01\x00\x02'


def _kod_part_id(oid: bytes) -> bytes:
    # A type's parts carry its id with byte 5 counting up (§40.3); the first is
    # the one KOTTD's last attribute names.
    part = bytearray(oid)
    part[5] = (part[5] + 1) & 0xFF
    return bytes(part)


def kod_type_record(
    *, oid: bytes, schema: str, name: str, kind: str, tds: bytes, null_tds: bytes
) -> KodRecord:
    """A user type described as a SYS.KOTTD instance (§40.3)."""
    (typecode, kind_word) = _KOD_TYPECODES[kind]
    values: list[bytes | None] = [
        _KOD_TYPE_FLAGS,
        schema.encode('utf-8'),
        name.encode('utf-8'),
        _KOD_TYPE_VERSION,
        typecode.to_bytes(2, 'big'),
        tds,
        null_tds,
        kind_word.to_bytes(2, 'big'),
        _KOD_TYPE_UB2,
        _KOD_IMAGE_REF_HEAD + _kod_part_id(oid) + _KOD_IMAGE_REF_TAIL,
    ]
    return KodRecord(KOD_KOTTD, oid, encode_kod_image(values))


# SYS.XMLTYPE as a live server describes it to an OCI client by name (#2050):
# its own flags, version and typecode 58 (opaque), its TDS and null TDS, a kind
# word, and a REF to the type's version. The TDS is the same from 11g and 18c;
# the version is `$8.0` from 11g and `$VSN_1` from 18c, and the version's id is
# the database's own -- the Mirror carries the one each capture had.
_KOD_XMLTYPE_FLAGS = bytes.fromhex('ae9a0101')
_KOD_XMLTYPE_TDS = bytes.fromhex(
    '00000029260100010001ff2900000000001e1b000000193a2afd0000000d01000000'
    '0700000000000000090007'
)
_KOD_XMLTYPE_NULL_TDS = bytes.fromhex('00000012260100010001ff290000000000071a2a0007')
_KOD_XMLTYPE_KIND = bytes.fromhex('5000')
# Its image is flagged 0x84, where a user type's is 0x85 (§21.3).
_KOD_XMLTYPE_IMAGE_FLAGS = 0x84
_KOD_XMLTYPE_VERSION = (b'$8.0', bytes.fromhex('ab9eebb9da3692fce040e50a194e4680'))
_KOD_XMLTYPE_VERSION_12C = (
    b'$VSN_1',
    bytes.fromhex('787d0d2b1c4d6933e0530caae80a12fb'),
)


def kod_xmltype_record() -> KodRecord:
    """SYS.XMLTYPE described as a SYS.KOTTD instance (§40.3, #2050)."""
    (version, version_id) = (
        _KOD_XMLTYPE_VERSION_12C
        if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
        else _KOD_XMLTYPE_VERSION
    )
    values: list[bytes | None] = [
        _KOD_XMLTYPE_FLAGS,
        b'SYS',
        b'XMLTYPE',
        version,
        TNS_TYPE_OPAQUE.to_bytes(2, 'big'),
        _KOD_XMLTYPE_TDS,
        _KOD_XMLTYPE_NULL_TDS,
        _KOD_XMLTYPE_KIND,
        _KOD_TYPE_UB2,
        _KOD_IMAGE_REF_HEAD + version_id + _KOD_IMAGE_REF_TAIL,
    ]
    return KodRecord(
        KOD_KOTTD,
        _OCI_XMLTYPE_OID,
        encode_kod_image(values, flags=_KOD_XMLTYPE_IMAGE_FLAGS),
    )


def _kod_text_bytes(text: str) -> bytes:
    data = text.encode('utf-8')
    return len(data).to_bytes(4, 'little') + bytes([len(data)]) + data


def encode_kod_named_reply(
    *, schema: str, name: str, record: KodRecord, sequence: int
) -> bytes:
    """The reply to a by-name ``TTI_KOD`` describe (§40.2): the header naming the
    type as asked for -- under the CONNECTED user's schema, as 11g answers it --
    then the type's record and the success OER."""
    header = (
        _KOD_BY_NAME_REPLY
        + (2).to_bytes(4, 'little')
        + _kod_text_bytes(schema)
        + bytes(4)
        + _kod_text_bytes(name)
        + b'\x00'
        + _kod_item_bytes(_kod_ref(record.oid, system=False))
        + (
            _KOD_NAMED_TAIL_12C
            if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
            else _KOD_NAMED_TAIL
        )
    )
    return header + encode_kod_reply([record], sequence=sequence)


def kod_system_record(oid: bytes) -> KodRecord | None:
    """The record describing a system type, or None if it is not one the Mirror
    knows. Every type descriptor is an instance of SYS.KOTTD (§40.3)."""
    table = (
        _KOD_SYSTEM_VALUES_12C
        if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
        else _KOD_SYSTEM_VALUES
    )
    values = table.get(oid)
    if values is None:
        return None
    return KodRecord(KOD_KOTTD, oid, encode_kod_image(values))


def strip_oci_piggyback(body: bytes) -> bytes:
    """Return the real TTI_FUN call inside an OCI piggyback, or ``body`` unchanged.

    Handles both wrappers the thick-OCI client uses: the OCCA close-cursors
    piggyback (``0x11 0x69``) around every execute past the first, and the
    TTI_80SES (``0x11 0x6b``) piggyback around the version call and the
    changepassword (:func:`is_version_call_oci` splits those two apart)."""
    if body[:2] == _OCI_PIGGYBACK:
        return _CLOSE_CURSORS_FROM_OCI(body)[1]
    if body[:2] == oci.OCI_PIGGYBACK_80SES:
        return body[_OCI_80SES_FIXED:]
    return body


_OCI_END_OF_FETCH_MSG = b'ORA-01403: no data found\n'


# The OCI end-of-fetch terminator sqlplus reads after the execute's rows: an OER
# carrying ORA-01403 ("no data found"), which the client treats as "cursor
# drained" rather than an error (the thin path keeps the same thing as its
# captured _END_OF_FETCH). Reduced to structure by live bisection (#265): the
# row statuses' OER with the 1403 code and the 11g marker, then the message.
def encode_fetch_terminator_oci(sequence: int, *, rowcount: int = 0) -> bytes:
    """The sqlplus / thick-OCI end-of-fetch reply (ORA-01403 = cursor drained).

    ``rowcount`` is the rows the cursor delivered in all, which the 12c band's
    OER carries (#1282)."""
    oer = _oci_oer(
        {
            **_OCI_OER_ROWS,
            'sequence': sequence,
            'error_code': ORA_NO_DATA_FOUND,
            'marker': b'\x00' + _OCI_OER_MARKER[1:],
            'rowcount': rowcount,
        }
    )
    return oer + bytes([len(_OCI_END_OF_FETCH_MSG)]) + _OCI_END_OF_FETCH_MSG


# On the wire the auth-result values (session key, salt, proof) are
# uppercase-hex ASCII; the version defaults to the captured 11.2 release.


def encode_rpa_kv(pairs: list[tuple[bytes, bytes]] | list[tuple]) -> bytes:
    """A TTI_RPA payload carrying key-value pairs — the shared framing of every
    auth challenge / result RPA: the RPA token, the pair count, then each pair as
    a key-value. Decodes back through :func:`decode_token_rpa`.

    A pair is ``(key, value)`` and carries flag 1, or ``(key, value, flag)`` when
    the flag means something. The only pair whose flag a client reads is
    ``AUTH_VFR_DATA``, where it is the verifier type (#829) — everything else has
    always gone out as 1 and stays that way.
    """
    return (
        bytes([TTI_RPA])
        + encode_sb4(len(pairs))
        + b''.join(
            encode_kv(pair[0], pair[1], pair[2] if len(pair) > 2 else 1)
            for pair in pairs
        )
    )


def encode_token_result(
    *, session_id: int = 0, version_no: int = VERSION_11_2_0_2
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
    # AUTH_PBKDF2_CSK_SALT, present only for a 12.1+ client (#829). Its presence
    # is what selects the modern key derivation on both sides, so it doubles as
    # the flag for "this is a 12c-shaped challenge".
    derived_salt: bytes | None = None
    # The password verifier the challenge offers (AUTH_VFR_DATA's flag): the 11g
    # SHA-1 one, or the 12c SHA-2 one a modern sqlplus insists on (#1282). It
    # picks the key length on both sides -- 192 bits against 256.
    verifier_type: int = VFR_11G_SHA1


# The database identifier a real server puts on the challenge. It is opaque to
# the client -- nothing is checked against it -- so one captured constant serves
# every session. Defined here beside the challenge builders; the sqlplus/OCI
# challenge in seerdb/server/auth.py uses the same value.
AUTH_GLOBALLY_UNIQUE_DBID = b'2C55FD5F1FE1101DA2455B7A62312B1D'

# The session serial number a 12.1+ client reads out of the auth result. Like the
# session id it is server bookkeeping the client only echoes back, so the value
# captured from the live 11.2 server serves every session.
AUTH_SERIAL_NUM = 2021


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
    if challenge.derived_salt is None:
        return encode_rpa_kv(
            [
                (b'AUTH_SESSKEY', _hexval(challenge.auth_sesskey)),
                (b'AUTH_VFR_DATA', _hexval(challenge.salt)),
            ]
        )
    # 12.1+ (#829): the client picks its key-derivation scheme from what the
    # challenge carries, so the modern shape is six pairs, not two. The extra
    # salt (AUTH_PBKDF2_CSK_SALT) plus the two iteration counts select the PBKDF2
    # derivation; the counts go out as ASCII decimal, matching a live 21c.
    #
    # AUTH_VFR_DATA's flag is the verifier type and here it is decisive: the
    # Mirror keeps the 11g SHA-1 verifier it computes from the plaintext secret,
    # and a client seeing both salts would otherwise assume the 256-bit SHA-2
    # scheme and derive a different key. Flagging it SHA-1 selects the 192-bit
    # path that pairs an 11g verifier with the modern derivation.
    return (
        encode_rpa_kv(
            [
                (b'AUTH_SESSKEY', _hexval(challenge.auth_sesskey)),
                (b'AUTH_VFR_DATA', _hexval(challenge.salt), VFR_11G_SHA1),
                (b'AUTH_PBKDF2_CSK_SALT', _hexval(challenge.derived_salt)),
                (b'AUTH_PBKDF2_VGEN_COUNT', str(PBKDF2_VGEN_COUNT).encode('ascii')),
                (b'AUTH_PBKDF2_SDER_COUNT', str(PBKDF2_SDER_COUNT).encode('ascii')),
                (b'AUTH_GLOBALLY_UNIQUE_DBID\x00', AUTH_GLOBALLY_UNIQUE_DBID),
            ]
        )
        + encode_status()
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


# The session's max open cursors, reported to a thin client as
# AUTH_MAX_OPEN_CURSORS: it sizes the cursors-to-close array from this (a missing
# / zero value clamps to 1 and overruns). The value only has to be a sane ceiling;
# a live 23ai reports its open_cursors default, 300.
_AUTH_MAX_OPEN_CURSORS = 300


def encode_result(
    session_key: bytes,
    *,
    session_id: int = 0,
    serial_num: int = AUTH_SERIAL_NUM,
    version_no: int = VERSION_11_2_0_2,
    instance_name: str | None = None,
    db_name: str | None = None,
    db_domain: str | None = None,
    service_name: str | None = None,
    txn_priority: str | None = None,
) -> bytes:
    """The auth-result RPA payload — the server proof, version, and session id.

    Decodes back through ``decode_token_rpa`` as a ``TTI_AUTH`` result whose
    ``AUTH_SVR_RESPONSE`` the client's ``validate()`` accepts.

    The session identity is the session id and ``AUTH_SERIAL_NUM`` at every
    version: a real 11g sends the serial too, and a 12.1+ client reads session
    id, serial number and version number and raises on a missing key rather
    than defaulting. Without it a pre-12.1 client had no serial to name the
    session by (#1234).

    From 12.1 more changes (#829), none of which a pre-12.1 reply gets:

    - the proof is the 48-byte padded form, because a 12.1+ client checks for the
      marker at a fixed offset rather than anywhere in the plaintext;
    - ``AUTH_MAX_OPEN_CURSORS`` joins the reply — a thin client sizes the array it
      tracks cursors-to-close in from this value, clamping a missing / zero one
      to **1**, so the second cursor it tries to close overruns that array with
      ``IndexError: array assignment index out of range`` (the statement-cache
      path every ``executemany`` and cursor reuse drives). A live 23ai reports
      its ``open_cursors`` here (300);
    - a status OER closes the reply, as it closes the challenge (see
      :func:`encode_challenge` for why a client waits without one).
    """
    modern = _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
    proof = server_proof_padded(session_key) if modern else server_proof(session_key)
    pairs = [
        (b'AUTH_SVR_RESPONSE', _hexval(proof)),
        (b'AUTH_VERSION_NO', str(version_no).encode('ascii')),
        (b'AUTH_SESSION_ID', str(session_id).encode('ascii')),
        (b'AUTH_SERIAL_NUM', str(serial_num).encode('ascii')),
    ]
    if modern:
        pairs.append((b'AUTH_MAX_OPEN_CURSORS', str(_AUTH_MAX_OPEN_CURSORS).encode()))
    # The session's names, each sent only when the server knows it. A client
    # reads these ONLY from here, so leaving them out is what left
    # `connection.instance_name` and friends None (#826). The domain always
    # goes: a database with no domain sends AUTH_SC_DB_DOMAIN empty, on every
    # server from 10g to 26ai (#1820).
    # 21c and later send the unique name twice, the second as
    # AUTH_SC_REAL_DBUNIQUE_NAME -- the one python-oracledb 26's
    # `db_unique_name` reads, None without it (#1777).
    real_db_name = db_name if version_no >> 24 >= 21 else None
    for key, value in (
        (b'AUTH_INSTANCENAME', instance_name),
        (b'AUTH_SC_DBUNIQUE_NAME', db_name),
        (b'AUTH_SC_REAL_DBUNIQUE_NAME', real_db_name),
        (b'AUTH_SC_DB_DOMAIN', db_domain),
        (b'AUTH_SC_SERVICE_NAME', service_name),
    ):
        if value:
            pairs.append((key, value.encode('utf-8')))
        elif key == b'AUTH_SC_DB_DOMAIN':
            pairs.append((key, b''))
    payload = encode_rpa_kv(pairs)
    # The session's transaction priority, reported after the pairs as 23ai
    # reports it to a client that advertised the feature (#1779).
    if txn_priority is not None:
        payload += encode_sync_piggyback([(TNS_KEYWORD_NUM_TXN_PRIORITY, txn_priority)])
    if modern:
        payload += encode_status()
    return payload


def encode_sync_piggyback(pairs: list[tuple[int, str]]) -> bytes:
    """A SYNC server piggyback reporting session state as keyword-value pairs
    (keyword, text value): the inverse of the client's reading of it (#1776),
    for the Mirror (#1779). Laid out as 23ai sends it -- its DTY count and the two
    length bytes are constants there, whatever the pairs:
    ``17 05 01 01 10 01 01 16 01 03 03 6c 6f 77 00 01 cc 00`` reports keyword 204
    (transaction priority) = ``low``."""
    return _SYNC_THIN(_sync_fields(pairs, 'text'))


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
    # Recorded whenever the IOV carried directions at all, not only when some
    # bind is OUT: a block whose binds are ALL IN still reports them, and that is
    # the only place a caller can learn what the server decided (#1064). Every
    # consumer keys on the record's presence and tolerates an empty position
    # list, and a block's reply carries no rows for this to be mistaken for.
    if Directions:
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


def _object_bind_type(Bind: object) -> object | None:
    # The DbObjectType behind an object / collection bind whose OUT value the
    # server returns in the object framing rather than as a plain DALC, or None
    # when the bind is not one.
    #
    # TWO shapes reach here and both are ordinary use. `cursor.var(objtype)`
    # gives a Var (#888); `cursor.callproc(name, (3, obj))` passes the DbObject
    # ITSELF, which is how python-oracledb is normally called. Recognising only
    # the Var sent the bare object down the plain-DALC branch, where the object
    # frame's 36-byte toid was read as a length and the reply desynced two bytes
    # in, onto that toid's own `00 22 02 08` prefix -- reported as "no decoder
    # for response token 34", a number that came from the data (#1029).
    from seerdb.common.dbobject import DbObject

    if isinstance(Bind, Var):
        Type = Bind.dbtype
        return Type if getattr(Type, 'tns_type', None) == TNS_TYPE_ADT else None
    if isinstance(Bind, DbObject):
        # A DbObject built by DbObjectType.newobject() carries its type; one
        # decoded from a fetched row may not, and then there is nothing to
        # decode an OUT image against.
        return object.__getattribute__(Bind, '_dbtype')
    return None


def _is_object_bind(Bind: object) -> bool:
    # Whether this bind's OUT value arrives in the object framing (#888/#1029).
    return _object_bind_type(Bind) is not None


def _lob_bind_type(Bind: object) -> int | None:
    # The LOB-class TNS type an OUT value for this bind arrives as, or None when
    # the bind is not LOB-class (#978). Either a Var the caller typed
    # (cursor.var(DB_TYPE_CLOB / BLOB / NCLOB / JSON / VECTOR)), the temp-LOB
    # marker such a Var was promoted to on the way out (#902), or a RAW value
    # the caller passed that this client itself binds as a VECTOR (#1010).
    #
    # That last case exists because the Mirror cannot see bind direction on the
    # wire, so it marks every bind of a block OUT and echoes a value for each --
    # including a pure-IN one. The client discards the positions it did not bind
    # as a Var, but it still has to READ PAST them, and reading past a VECTOR
    # needs to know it is one. A real server marks such a bind IN and sends no
    # value at all, so this only ever arises behind a Mirror; decoding by the
    # type this client declared in its own OAC is right either way.
    if isinstance(Bind, TempLob):
        return TNS_TYPE_BLOB if Bind.is_blob else TNS_TYPE_CLOB
    if isinstance(Bind, Var) and Bind.dbtype.tns_type in _LOB_DATA_TYPES:
        return Bind.dbtype.tns_type
    if is_vector_bind(Bind):
        return TNS_TYPE_VECTOR
    return None


def _read_lob_bind_value(Rest: bytes, DataType: int) -> tuple[object, bytes]:
    """A LOB-class bind's returned value, WITHOUT the return code after it.

    The server sends the same block a fetched LOB column carries -- a ub4 block
    length, the locator's ub8 size and ub4 chunk size, then the locator itself
    (§22.1b) -- so it reads with the row reader rather than as a DALC. Read as a
    DALC the block length was taken for the whole value and the rest of the
    block left in the stream, where its next byte decoded as a response token
    (#978/#985).

    Both carriers of such a value use this -- an OUT / IN OUT bind (§6.5) and a
    DML RETURNING bind (§22.1c) -- but they disagree about what follows it, so
    the trailer is each caller's own business."""
    from seerdb.common.lob import LOB

    (Locator, Rest, Image) = _read_lob_column_full(
        Rest, inline_image=DataType in _PREFETCHED_IMAGE_TYPES
    )
    if Locator is None and Image is None:
        return (None, Rest)
    if Image is not None:
        return (LOB(DataType, Locator or b'', prefetched=Image), Rest)
    return (LOB(DataType, Locator or b''), Rest)


def _read_lob_out_bind(Rest: bytes, DataType: int) -> tuple[object, bytes]:
    # A LOB-class OUT / IN OUT bind: the value, then the per-value return code
    # every OUT bind carries (#978).
    (Value, Rest) = _read_lob_bind_value(Rest, DataType)
    (_, Rest) = decode_ub4(Rest)
    return (Value, Rest)


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
            elif _is_object_bind(Bind):
                # An object / collection OUT value: the read_dbobject framing
                # (an ObjectImage the cursor turns into a DbObject), then the
                # per-value return code (#888).
                oid = getattr(_object_bind_type(Bind), 'oid', b'')
                (ObjVal, Rest) = _read_object_column(Rest, {'type_oid': oid})
                (_, Rest) = decode_ub4(Rest)
                OutValues.append(ObjVal)
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
            elif (LobType := _lob_bind_type(Bind)) is not None:
                (LobValue, Rest) = _read_lob_out_bind(Rest, LobType)
                OutValues.append(LobValue)
            else:
                (Val, Rest) = decode_dalc(Rest)
                # The per-value return code is a variable-length integer, not a
                # fixed byte: a non-NULL value's code is ub4(0) = one 0x00 byte,
                # but a NULL value's is ub4(-1) = 0x81 0x01 (two bytes). Skipping
                # a fixed byte desynced the decoder on a NULL OUT bind.
                (_, Rest) = decode_ub4(Rest)
                OutValues.append(b'' if Val == [] else bytes(Val))
    return (Directions, OutValues, Rest)


def _read_refcursor_out(Rest: bytes, *, indicator: bool = True) -> tuple[dict, bytes]:
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
    if indicator:
        # An OUT bind's value ends with a per-value indicator byte. A nested
        # CURSOR COLUMN does not -- consuming one there swallows the next row's
        # TTI_RXD token, and the decoder reports it as an unknown response token
        # whose number is really the first byte of that row's data (#826).
        Rest = Rest[1:]
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


def _unpack_oer_ub4s(Blob: bytes, Count: int) -> list[int]:
    # The `Count` ub4 values a batch-error code or offset array packs
    # back-to-back in its DALC blob (the `_OER_TAIL` schema reads the blob whole
    # as a value; this reads the integers out of it).
    Buf = bytes(Blob)
    Values = []
    for _ in range(Count):
        (Value, Buf) = decode_ub4(Buf)
        Values.append(Value)
    return Values


def _oer_batch_errors(Tail: dict) -> list[dict]:
    # The {offset, code, message} list of an OER's batch-error arrays (array-DML
    # `batcherrors`, #18), from the `_OER_TAIL` schema's fields: error i hit row
    # offsets[i] with ORA-code codes[i] and text messages[i]. For a plain
    # statement all three counts are zero and the list is empty.
    Codes = _unpack_oer_ub4s(
        Tail.get('batch_codes', b''), Tail.get('batch_code_count', 0)
    )
    Offsets = _unpack_oer_ub4s(
        Tail.get('batch_offsets', b''), Tail.get('batch_offset_count', 0)
    )
    Messages = [
        bytes(M['text']).decode('utf-8', errors='replace').rstrip()
        if 'text' in M
        else ''
        for M in Tail.get('batch_messages', [])
    ]
    return [
        {
            'offset': Offsets[I] if I < len(Offsets) else None,
            'code': Codes[I] if I < len(Codes) else None,
            'message': Messages[I] if I < len(Messages) else None,
        }
        for I in range(max(len(Offsets), len(Codes), len(Messages)))
    ]


def decode_token_oer(Data: bytes, Acc: tuple) -> tuple:
    # OER ("Oracle Error" return-status TTC token; emitted at the end of every
    # server response — success or failure). It is 9i's short status
    # (`_O7_STATUS_HEAD`, `_O7_STATUS_TAIL`) with the call status and sequence
    # number it leads with and the version conditionals it meets, read as the
    # `_OER_HEAD` and `_OER_TAIL` schemas; the trailing length-prefixed message
    # ("ORA-NNNNN: ...") the server sets when the error number is non-zero is
    # read best-effort below, from what the frame leaves. Field order
    # cross-referenced with python-oracledb's _process_error_info.
    (Cursor, RowFormat, Rows) = Acc[:3]
    # Array-DML row counts threaded in by decode_token_rpa_piggyback (the RPA
    # carrying them precedes this OER); None for a normal execute (#18).
    RowCounts = Acc[4] if len(Acc) > 4 else None
    FieldVersion = _DECODE_FIELD_VERSION.get()
    # A server never advertises less than the session negotiated, so the higher
    # of the two is its release; that also keeps a value left over from an
    # earlier session in this context from lowering it. The one-byte (not ub2)
    # `flags` and the extended trailing fields both follow the server's release:
    # `flags` was a ub2 at 10g and 11g (`00` when zero, `01 20` when a warning
    # set it), one byte from 12.1, and reading it as one byte left 10g and 11g a
    # byte short (#1995); 12c+ adds the extended ub4 error number and ub8
    # rowcount, 20.1+ the ub4 sql type + ub4 server checksum, which a 21c/23ai
    # server sends a 12.1 session too, so reading past them by the negotiated
    # version lost every error message (#1145).
    ServerFieldVersion = max(_DECODE_SERVER_FIELD_VERSION.get() or 0, FieldVersion)
    Wide = FieldVersion >= FIELD_VERSION_12_1
    Given = {
        'flags_ub2': not Wide,
        'flags_u8': Wide,
        'ext_12c': Wide,
        'ext_20_1': Wide and ServerFieldVersion >= FIELD_VERSION_20_1,
    }
    (Head, Rest) = _OER_HEAD_FROM_THIN(Data, Given)
    (Tail, Rest) = _OER_TAIL_FROM_THIN(Rest, {**Given, **Head})
    # The "current row number" (`rows`) doubles as a DML's affected-row count on
    # 11g; 12c+ repeats it in the extended ub8 the tail skips. `position` is the
    # error's parse offset into the SQL, and `warnings` bit 0x20 marks a PL/SQL
    # object that compiled with errors -- the object exists and the call
    # succeeded, only this bit says anything is wrong (#993, #2262). The rowid is
    # the row a DML touched, in the physical-rowid layout a ROWID column uses.
    CallStatus = Head['call_status']
    RowCount = Head['rows']
    ErrCode = Head['code']
    CursorId = Head['cursor']
    ErrorPos = Head['position']
    WarnFlags = Head['warnings']
    (RowidObj, RowidFile, RowidBlock, RowidSlot) = (
        Head['rowid_object'],
        Head['rowid_file'],
        Head['rowid_block'],
        Head['rowid_slot'],
    )
    BatchErrors = _oer_batch_errors(Tail)
    Message = None
    if ErrCode != 0 and Rest:
        try:
            (Bytes, _) = decode_dalc(Rest)
        except (IndexError, Truncated):
            # Best-effort: the OER is the terminal token and its message is only
            # read for display, so a tail that does not cleanly yield a DALC
            # means "no message" rather than a failed response. This tolerance
            # predates the Truncated signal (#849) -- decode_dalc used to return
            # short bytes here silently, which the caller accepted -- and one
            # ORA-01403 end-of-fetch terminator relies on it: an imprecise walk
            # of the OER's padding/success-iters fields can leave the message
            # DALC a few bytes short. The values that matter (rowcount, error
            # code, cursor id, rowid) are all read above, before any drift.
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
        WarnFlags,
    )


def decode_lobops_locator(Packet: bytes) -> bytes | None:
    """The UPDATED locator a TTI_LOBOPS reply leads with, or ``None``.

    Every LOB call answers with the locator as the server now sees it, and a
    MUTATING call (WRITE / TRIM / OPEN / CLOSE) really does change it. Keeping
    the original meant the next read was served the pre-write value and the
    write looked like it had silently done nothing (#964) -- the same rule the
    BFILE path already follows for FILE_OPEN (§14.4)."""
    if not Packet or Packet[0] != TTI_RPA or len(Packet) < 3:
        return None
    Length = (Packet[1] << 8) | Packet[2]
    if Length <= 0 or 3 + Length > len(Packet):
        return None
    return bytes(Packet[3 : 3 + Length])


def decode_lobops_value(Packet: bytes) -> int | None:
    """The ``ub4`` a value-returning TTI_LOBOPS reply carries between the updated
    locator and the trailing OER — ``None`` when the reply has no such field.

    Captured from a live 23ai (§14.6): GET_LENGTH answers the LOB's length,
    GET_CHUNK_SIZE its chunk size (8060 there), TRIM the NEW length, and OPEN /
    CLOSE carry the field too (their value is not meaningful)::

        08 | ub2 112 | <112-byte updated locator> | 01 0b | 04 <OER>
             locator length                         ub4 = 11

    The locator is binary and can contain anything, so it is skipped by its
    declared length rather than scanned for — the same reason
    :func:`decode_lobops_oer` does."""
    if not Packet or Packet[0] != TTI_RPA or len(Packet) < 3:
        return None
    Pos = 3 + ((Packet[1] << 8) | Packet[2])
    if Pos >= len(Packet) or Packet[Pos] == TTI_OER:
        return None
    (Value, _Rest) = decode_ub4(Packet[Pos:])
    return Value


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


def _decode_oac_walk(Data: bytes) -> tuple:
    # Every OAC field in wire order, raw (_OAC): (DataType, Flg, DataScale,
    # MaxDataLength, Mal, Fl2, ToId, VSN, Charset, Csfrm, Mxlc, Rest). The
    # public decoders pick what they need from it. The type OID is written with
    # two lengths, a ub4 count then, only when non-empty, the length-prefixed
    # bytes (#139). A message that ends inside it must say "read more", not
    # raise: a big request spans several DATA packets, and the first parse runs
    # off the end by design (#1000).
    if len(Data) < 3:
        raise Truncated('OAC: header short')
    try:
        (f, rest) = _OAC_FROM_THIN(Data)
    except IndexError:
        raise Truncated('OAC: cut short') from None
    return (
        f['data_type'],
        f['flags'],
        f['scale'],
        f['max_length'],
        f['max_array'],
        f['cont_flags'],
        bytes(f.get('toid', b'')),
        f['version'],
        f['charset'],
        f['csfrm'],
        f['max_chars'],
        rest,
    )


def decode_oac_fields(Data: bytes) -> tuple[int, int, int, int, int, bytes, bytes]:
    # The full OAC field set, including the charset form (csfrm) byte the common
    # 5-tuple form skips, and the referenced type's OID (an object / REF bind,
    # #116/#139). csfrm distinguishes national char data (2 → AL16UTF16 /
    # UTF-16BE) from ordinary char data (1) — the server needs it to decode an
    # NCHAR / NVARCHAR bind (#484). Returns (DataType, MaxDataLength, DataScale,
    # Charset, Csfrm, ToId, Rest).
    (
        DataType,
        _Flg,
        DataScale,
        MaxDataLength,
        _Mal,
        _Fl2,
        ToId,
        _VSN,
        Charset,
        Csfrm,
        _Mxlc,
        Rest,
    ) = _decode_oac_walk(Data)
    return (DataType, MaxDataLength, DataScale, Charset, Csfrm, ToId, Rest)


# A PL/SQL associative-array bind's capacity (#122): where TNS_BIND_ARRAY is set,
# the max-array-size field of the 12.2+ OAC layout or the trailing field of the
# 11g one (the two places encode_token_raw writes it); 0 for a scalar bind.
def _oac_array_capacity(Data: bytes, field_version: int) -> int:
    (
        _DataType,
        Flg,
        _Scale,
        _MaxLen,
        Mal,
        Fl2,
        _ToId,
        _VSN,
        _Cs,
        _Csfrm,
        Mxlc,
        _Rest,
    ) = _decode_oac_walk(Data)
    if field_version >= FIELD_VERSION_12_1:
        return Mal if Flg & TNS_BIND_ARRAY else 0
    return Mxlc if Fl2 & TNS_BIND_ARRAY else 0


def decode_token_oac(Data: bytes, Acc: tuple) -> tuple[int, int, int, int, bytes]:
    (DataType, MaxDataLength, DataScale, Charset, _Csfrm, _ToId, Rest) = (
        decode_oac_fields(Data)
    )
    return (DataType, MaxDataLength, DataScale, Charset, Rest)


def _auth_int(Value: bytes | None) -> int | None:
    # A numeric login-reply value (sent as its decimal text), or None when the
    # reply does not carry it or it is not a number.
    if Value is None:
        return None
    try:
        return int(bytes(Value))
    except ValueError:
        return None


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
        # The session's SID and SERIAL#, as the numbers they are: the SID is the
        # one sys_context('userenv', 'sid') reports, and the pair is what
        # ALTER SYSTEM KILL SESSION names (#1218). A pre-10g reply has neither.
        SessId = _auth_int(dict(KVs).get(b'AUTH_SESSION_ID'))
        SerialNum = _auth_int(dict(KVs).get(b'AUTH_SERIAL_NUM'))
        # The database's unique name, SYS_CONTEXT('USERENV', 'DB_UNIQUE_NAME'):
        # 21c and later send AUTH_SC_REAL_DBUNIQUE_NAME, 10g to 18c only
        # AUTH_SC_DBUNIQUE_NAME, with the same value; 8i and 9i neither (#1774).
        Unique = dict(KVs).get(b'AUTH_SC_REAL_DBUNIQUE_NAME') or dict(KVs).get(
            b'AUTH_SC_DBUNIQUE_NAME'
        )
        DbUniqueName = bytes(Unique).decode('utf-8') if Unique else None
        # 23ai and later report session state after the pairs, as a SYNC
        # piggyback: the transaction priority the session starts at (#1776).
        if Rest1[:2] == bytes([TTI_SVR_PIGGYBACK, TNS_SERVER_PIGGYBACK_SYNC]):
            _decode_sync_pairs(Rest1[2:])
        return (TTI_AUTH, Resp, Ver, SessId, SerialNum, DbUniqueName)
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
    (Fields, _) = _PRO_FROM_THIN(Data)
    return {
        'server_version': Fields['server_version'],
        'banner': Fields['banner'],
        'compile_caps': Fields['compile_caps'],
        'runtime_caps': Fields['runtime_caps'],
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
        # Session state as keyword-value pairs: the transaction id of a
        # sessionless transaction (keyword 201, #133; seerdb tracks that flag
        # client-side) and the transaction priority (keyword 204, #1776), which
        # the connection takes from the recorded pairs.
        Rest = _decode_sync_pairs(Rest)
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
    # Walks past the execute's return-parameters block so the next decode_packet
    # call lands on the real status token (OER). Its fields, by name (#859):
    # `ub2 al8o4l count | count x ub4 | ub2 al8txl length (+bytes) | ub2 key/value
    # pairs (+pairs) | ub2 registration length (+bytes)`, then the optional
    # row-count tail below. From 10.2 up an execute's block is read by those
    # fields; the loose walk -- Num, then Num fields, then any zero bytes --
    # stays for 9i, whose Num over-counts, and for a block that has no trailing
    # fields at all (a changepassword reply is `08 00` and then its OER). The
    # loose walk only lands right while those trailing words are zero, and
    # 11g's reply to ALTER SESSION SET CURRENT_SCHEMA carries two key/value
    # pairs there (#1141).
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
    Exact = None if BreakOnToken else _skip_rpa_tail_fields(Rest)
    if Exact is not None:
        Rest = Exact
    else:
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


def _skip_rpa_tail_fields(Rest: bytes) -> bytes | None:
    # The three fields after the al8o4l words (#1141), or None when they are
    # not there to read -- the parse runs off the end, or does not land on what
    # follows a block (a token, the end, or an armed row-count tail). Each is a
    # ub2 count or length; zero is the usual case and a single 00 byte.
    try:
        (TxnLen, Rest) = decode_ub4(Rest)  # al8txl: transaction id, raw bytes
        Rest = Rest[TxnLen:]
        (Pairs, Rest) = decode_ub4(Rest)  # session-state key/value pairs
        for _ in range(Pairs):
            # A pair is `ub2 text length (+DALC) | ub2 binary length (+DALC) |
            # ub2 keyword`, as in the server piggyback. 11g reports a
            # CURRENT_SCHEMA change as two: the name under keyword 168, its id
            # under 169.
            (TextLen, Rest) = decode_ub4(Rest)
            if TextLen > 0:
                (_, Rest) = decode_dalc(Rest)
            (BinLen, Rest) = decode_ub4(Rest)
            if BinLen > 0:
                (_, Rest) = decode_dalc(Rest)
            (_, Rest) = decode_ub4(Rest)  # keyword number
        (RegLen, Rest) = decode_ub4(Rest)  # registration, raw bytes
    except (IndexError, Truncated):
        return None
    Rest = Rest[RegLen:]
    if not Rest or Rest[0] in _KNOWN_TTI_TOKENS or _DECODE_DML_ROWCOUNTS.get():
        return Rest
    return None


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
# The LOB-class types a server prefetches whole rather than handing over a bare
# locator: the binary image rides in the reply with the locator behind it, both
# in a row (see encode_prefetched_lob_value_thin) and in DML RETURNING out-bind
# data (#826/#887).
_PREFETCHED_IMAGE_TYPES = frozenset((TNS_TYPE_JSON, TNS_TYPE_VECTOR))
_ROWID_DATA_TYPES = frozenset((TNS_TYPE_RID,))
_UROWID_DATA_TYPES = frozenset((TNS_TYPE_UROWID,))
_LONG_DATA_TYPES = frozenset((TNS_TYPE_LONG, TNS_TYPE_LONGRAW))
# Types whose row value is carried even when the describe reports a zero buffer
# size: LOB-class (delivered over a define round-trip / TTI_LOBOPS), ROWID,
# UROWID and LONG all send bytes the reference client reads despite the zero.
# A plain scalar described with a zero length, by contrast, sends nothing (it is
# read as NULL-by-describe), so the row encoder skips it (see _thin_column_value,
# the mirror image of decode_token_rxd's data-length-0 rule).
_ZERO_DESCRIBE_CARRIES_DATA = (
    _LOB_DATA_TYPES | _ROWID_DATA_TYPES | _UROWID_DATA_TYPES | _LONG_DATA_TYPES
)


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
        ReturnLengths = []
        for _Pos, TnsType in ReturnPositions:
            (NumRows, Rest) = decode_ub4(Rest)
            Vals = []
            Lens = []
            for _Row in range(NumRows):
                if TnsType in _PREFETCHED_IMAGE_TYPES:
                    # A JSON / VECTOR bind's returned value is its binary image
                    # prefetched into the reply with a locator behind it, not a
                    # plain DALC -- the same framing the column uses in a row.
                    # Read as a DALC the locator was left in place and became the
                    # next field, so the response desynced on the token after it
                    # (#826).
                    (Val, Rest) = _read_lob_column(Rest, inline_image=True)
                elif TnsType in _LOB_DATA_TYPES:
                    # A CLOB / BLOB / NCLOB bind's returned value is the LOB
                    # block a fetched column carries (§22.1b), not a DALC --
                    # the same misunderstanding as the OUT bind above it (#978),
                    # reached through this reader instead (#985).
                    (Val, Rest) = _read_lob_bind_value(Rest, TnsType)
                elif TnsType == TNS_TYPE_ADT:
                    # An OBJECT / collection bind's returned value carries the
                    # object framing a column uses (§21.2 -- toid, object OID,
                    # snapshot, version, image gate, flags, image), not a DALC.
                    # Read as one, the constructed 36-byte toid was taken for a
                    # length and the reply desynced a couple of bytes in, landing
                    # on that toid's own `00 22 02 08` prefix and reporting it as
                    # "no decoder for response token 34" (#826).
                    (Val, Rest) = _read_object_column(Rest, {})
                else:
                    (Val, Rest) = decode_dalc(Rest)
                # The sb4 after the value is the value's ACTUAL length: 0 when
                # it fitted the client's variable, -1 when the value is NULL,
                # and the untruncated length when it did not fit. Discarding it
                # made a too-small RETURNING variable return a silently cut-down
                # value that looked like a correct answer (#1021). Kept here and
                # reported by the cursor, once the whole message has been read --
                # raising mid-decode would leave the rest of the response
                # unparsed and the session out of step.
                (Actual, Rest) = decode_ub4(Rest)
                Vals.append(Val)
                Lens.append(Actual)
            ReturnValues.append(Vals)
            ReturnLengths.append(Lens)
        Record = {
            'return_positions': [Pos for Pos, _T in ReturnPositions],
            'return_values': ReturnValues,
            'return_lengths': ReturnLengths,
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
                # A JSON or VECTOR column may arrive with its image already in
                # the row (§22.1b). Keep the image on the LOB so read() serves it
                # from there: the locator that rides behind it resolves to nothing
                # to fetch, so asking for the content returned empty and the
                # decoder rejected it as "not a VECTOR image" (#959).
                (Locator, Rest, Image) = _read_lob_column_full(
                    Rest, inline_image=DataType in _PREFETCHED_IMAGE_TYPES
                )
                if Image is not None:
                    Row.append(LOB(DataType, Locator or b'', prefetched=Image))
                    continue
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
            if DataType == TNS_TYPE_REFCURSOR:
                # A nested cursor -- `select ..., CURSOR(select ...) from ...`.
                # The value is the same inline describe + cursor id a REF CURSOR
                # OUT bind carries, so it reads with the same helper (#826).
                (Val, Rest) = _read_refcursor_out(Rest, indicator=False)
                Row.append(Val)
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


def _read_lob_column_full(
    Rest: bytes, *, inline_image: bool = False
) -> tuple[bytes | None, bytes, bytes | None]:
    """:func:`_read_lob_column` plus the prefetched image, when the value came in
    the two-field framing (§22.1b) rather than as a bare locator.

    The plain reader returns the IMAGE as the value in that case, which is what a
    RETURNING bind wants. A fetched column wants the other half too: the real
    locator to keep on the LOB, and the image to serve reads from, because there
    is nothing to fetch for it (#959)."""
    value, tail, image, locator = _read_lob_column_parts(Rest, inline_image)
    return (locator if image is not None else value, tail, image)


def _read_lob_column(
    Rest: bytes, *, inline_image: bool = False
) -> tuple[bytes | None, bytes]:
    value, tail, _image, _locator = _read_lob_column_parts(Rest, inline_image)
    return (value, tail)


def _read_lob_column_parts(
    Rest: bytes, inline_image: bool
) -> tuple[bytes | None, bytes, bytes | None, bytes | None]:
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
        return (None, Rest, None, None)
    if Rest[0] == 0x00:
        return (None, Rest[1:], None, None)
    (NumBytes, Body) = decode_ub4(Rest)
    if NumBytes <= 0 or not Body:
        # Defensive: malformed or unexpected layout. Surface what we have
        # rather than overrunning the buffer.
        return (bytes(Body), b'', None, None)
    # A CLOB / BLOB column may carry the locator's metadata -- a ub8 size and a
    # ub4 chunk size -- between the length and the locator itself (#853). A live
    # 23ai sends that form to the reference thin client and the bare form to
    # seerdb, for the same row; the Mirror always sends it (see
    # encode_lob_locator_thin). Both have to be read here.
    #
    # They are told apart by the byte after the length. In the bare form that is
    # the locator's own length prefix, which equals NumBytes (or 0xFE when the
    # block is chunked); in the metadata form it is the size's ub4 length
    # marker, at most 4. The two cannot collide for a real locator, which is 38
    # bytes at the smallest -- so the test is only applied when NumBytes says so,
    # and anything smaller keeps the bare reading.
    if NumBytes > 8 and Body[0] <= 8 and Body[0] != NumBytes:
        (_Size, Body) = decode_ub4(Body)
        (_ChunkSize, Body) = decode_ub4(Body)
    (Locator, Tail) = decode_dalc(Body)
    Image: bytes | None = None
    Behind: bytes | None = None
    if inline_image and Tail[:1] and Tail[0] == NumBytes:
        # A VECTOR or JSON column carries its image inline AND the locator behind
        # it (§22.1b): the first field just read is the image, and the locator
        # follows as a second DALC whose length is the `num_bytes` at the front.
        # Consume it, or it is read as the next column's value (#887). The length
        # check keeps this to the form that actually has two fields -- a server
        # that sends the bare locator alone leaves Tail elsewhere.
        (_Locator, Tail) = decode_dalc(Tail)
        if not isinstance(Locator, list):
            Image = bytes(Locator)
        if not isinstance(_Locator, list):
            Behind = bytes(_Locator)
    if logger.isEnabledFor(logging.DEBUG):
        # Guarded for the same reason as the encoder: per LOB cell, per row. The
        # pair that matters is `inline_image` (did the caller expect the
        # prefetched form) against `image` (was it actually there) -- a mismatch
        # is what desyncs a row or empties a read (#887/#826/#959).
        logger.debug(
            'row decode LOB: num_bytes=%s want_inline=%s image=%s locator=%s',
            NumBytes,
            inline_image,
            None if Image is None else len(Image),
            # In the two-field form the locator is the one BEHIND the image;
            # `Locator` still holds the image there, and reporting its length
            # twice would read as a locator that shrank to the image's size.
            len(Behind)
            if Behind is not None
            else (None if isinstance(Locator, list) else len(Locator)),
        )
    if isinstance(Locator, list):  # 0x00 / 0xFF DALC → empty / null
        return (None, Tail, Image, Behind)
    return (bytes(Locator), Tail, Image, Behind)


def _read_rowid_column(Rest: bytes) -> tuple[str | None, bytes]:
    # ROWID (TNS type 11) in RXD: a 1-byte present indicator (the size the
    # server reserved; 0 / 0xff means NULL) followed by a structured physical
    # rowid -- data object (ub4), relative file (ub2), an unused ub1, block
    # (ub4) and slot (ub2). Mirrors oracledb's read_rowid; the byte counts and
    # the base64 rendering were verified against ROWIDTOCHAR on a live XE row.
    from seerdb.common.types import rowid_to_string

    if not Rest:
        return (None, Rest)
    if Rest[0] in (0, 0xFF):
        # NULL: the one present/reserved-size byte, no body behind it.
        return (None, Rest[1:])
    (Cell, Rest) = _ROWID_CELL_FROM_THIN(Rest)  # lead + object/file/unused/block/row
    return (
        rowid_to_string(Cell['object'], Cell['file'], Cell['block'], Cell['row']),
        Rest,
    )


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
    if Rest[0] == TNS_LONG_LENGTH_INDICATOR:
        # A large UROWID rides chunked (0xFE marker), like a LONG value: an
        # index-organized table's rowid crosses the 252-byte short-length limit
        # (its raw form carries a physical guess plus the primary key). Reading it
        # as a single 1-byte-length block left the chunk-length prefix and the
        # zero terminator in the stream, desyncing the row -- the leftover 0xFE
        # then reached the token loop as "no decoder for response token 254"
        # (#904). Same framing as _read_long_column: ub4-length chunks on 12c+, a
        # single length byte per chunk before, both ending on a zero-length chunk.
        Rest = Rest[1:]
        Chunks = b''
        Wide = _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
        while Rest:
            if Wide:
                (ChunkLen, Rest) = decode_ub4(Rest)
            else:
                ChunkLen = Rest[0]
                Rest = Rest[1:]
            if ChunkLen == 0:
                break
            Chunks += bytes(Rest[:ChunkLen])
            Rest = Rest[ChunkLen:]
        return (urowid_to_string(Chunks), Rest)
    Rest = Rest[1:]  # 1-byte length echo (== NumBytes) for a short UROWID
    Value = bytes(Rest[:NumBytes])
    Rest = Rest[NumBytes:]
    return (urowid_to_string(Value), Rest)


def _read_long_column(Rest: bytes) -> tuple[bytes | None, bytes]:
    # LONG / LONG RAW in RXD (_LONG_CELL): the value -- NULL (a bare 0x00), a
    # short 1-byte-length body, or the 0xFE chunked form (a ub1 length per chunk
    # on 11g, a ub4 from 12.1, both ending on a zero length) -- then two trailing
    # ub4 indicators (the actual/return lengths; 0/0 for an ordinary value), read
    # whatever the value so the stream stays aligned. The `long` codec reads the
    # value; verified against live XE captures (NULL, single-chunk, 700-byte
    # multi-chunk, and LONG-not-last rows).
    if not Rest:
        return (None, Rest)
    (Cell, Rest) = _LONG_CELL_FROM_THIN(Rest)
    return (Cell['content'], Rest)


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
    # Row Transfer Header. The 10g+ form is the 9i row header read at thin's
    # variable-width integers: the head (`_O7_RXH` -- a flags byte and four
    # counts) and then the vectors (`_O7_VECTORS` -- the column bit vector and
    # the rowid, each a ub4 length and its bytes), the schemas the 9i and 8i
    # fetch paths already decode. Fields use Oracle's variable ub1/ub2/ub4
    # encoding (1-byte length prefix + value bytes), not the fixed 2-byte
    # big-endian layout an older version of this decoder assumed; see
    # python-oracledb's _process_row_header.
    (Cursor, RowFormat, Rows) = Acc[:3]
    (_, Rest) = _O7_RXH_FROM_THIN(Data)
    (Vectors, Rest) = _O7_VECTORS_FROM_THIN(Rest)
    # The row header can carry a column bit vector (oracledb's _get_bit_vector):
    # an unset bit means the column repeats the previous row's value and carries
    # no bytes in the following RXD. It must be passed to the RXD decoder, not
    # dropped — dropping it makes the RXD read the next token as a column value
    # and desync (a scroll re-execute that repositions onto a row whose value
    # equals the last one returned uses this compression, e.g. LAST after
    # fetching to EOF). #181.
    BitVec = Vectors.get('bit_vector')
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


def _encode_at_negotiated_version(Dictionary: dict) -> None:
    # A login-phase message carries long values (an encrypted password, a
    # verifier) in the chunked form, whose chunk width follows the field version
    # (#1261). Nothing on this path had set it: the width came from whatever an
    # earlier execute left, or the default. These go out after the protocol
    # negotiation, so the session's own version is the one to encode at.
    if Dictionary.get('field_version'):
        _ENCODE_FIELD_VERSION.set(Dictionary['field_version'])


def encode_dictionary_auth(Dictionary: dict) -> tuple[bytes, bytes]:
    _encode_at_negotiated_version(Dictionary)
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

    # DRCP (#130): a connection class and a session purity go out as given:
    # cclass -> AUTH_KPPL_CONN_CLASS, purity -> AUTH_KPPL_PURITY. Only
    # server_type='pooled' asks for a pooled server, and then a purity left at
    # its default is NEW. A class alone labels the session and requests nothing,
    # as in python-oracledb (#1990, #1977).
    CClass = Dictionary['env'].get('cclass')
    Purity = Dictionary['env'].get('purity', 0) or 0
    Pooled = Dictionary['env'].get('server_type') == 'pooled'
    if Pooled and Purity == 0:
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

    # At fv >= 23.1 EXT 1 (fast-auth / 23ai, #89) phase two follows python-oracledb
    # exactly: the username is NOT re-sent (has_user = 0, user length 0 — the
    # session is already established by OSESSKEY), and the OAUTH carries the
    # session-context pairs the server now requires. The legacy fv <= 23.1 path
    # re-sends the username and the minimal AUTH_PASSWORD/SESSKEY/SPEEDY_KEY set;
    # using either shape against the other desyncs the server's parse, surfacing
    # as ORA-03120 (two-task conversion: integer overflow). RE'd from an
    # oracledb-thin fv24 capture (docs/PROTOCOL.md §20).
    if FieldVersion >= FIELD_VERSION_23_1_EXT_1:
        # Phase two replicates python-oracledb's fv24 byte-for-byte: the has-user
        # field is present and 0 (`_AUTH_HEAD` has_user_ptr) followed by the usual
        # pointer, the logon mode gains 0x20000, the username is length-prefixed,
        # and the OAUTH carries the session-context pairs. RE'd from an
        # oracledb-thin fv24 capture (docs/PROTOCOL.md §20).
        HasUserPtr = True
        ModeInt = (Role * 32) | (Prelim * 128) | 1 | 256 | 0x20000
        UserPrefixed = True
        SessionKvs = _auth_session_kvs(Dictionary)
        NumPairs = (
            2 + SpeedyKeyInd + _auth_session_kv_count(Dictionary) + ProxyInd + DrcpInd
        )
    else:
        # 12c+ length-prefixes the username (write_bytes_with_length); 11g sends
        # it raw (read via the user-length field). Sending the raw form to 21c
        # makes it read the first username byte as a length and desync (ORA-03120).
        HasUserPtr = False
        ModeInt = (Role * 32) | (Prelim * 128) | 1 | 256
        UserPrefixed = FieldVersion >= FIELD_VERSION_12_1
        # Sync the session time zone to the client's UTC offset, the way oracledb
        # / OCI / sqlplus do (AUTH_ALTER_SESSION). Without it the session runs at
        # the server default, so CURRENT_TIMESTAMP / LOCALTIMESTAMP /
        # SESSIONTIMEZONE and TIMESTAMP WITH LOCAL TIME ZONE reflect the server's
        # zone, not the client's — a porting surprise (#307). Gated to 12c+: that
        # is where oracledb (thin, 12.1+) operates and the phase-two AUTH accepts
        # the extra pair; 10g / 11g have a stricter parse that desyncs on it, and
        # no oracledb reference to match. The fv >= 23.1 EXT 1 fast-auth path already
        # carries this via _auth_session_kvs.
        if FieldVersion >= FIELD_VERSION_12_1:
            SessionKvs = encode_kv(
                b'AUTH_ALTER_SESSION', _alter_session_clause(Dictionary), 1
            )
            NumPairs = 2 + SpeedyKeyInd + 1 + ProxyInd + DrcpInd
        else:
            SessionKvs = b''
            NumPairs = 2 + SpeedyKeyInd + ProxyInd + DrcpInd

    # The AUTH head (_AUTH_HEAD): the subtype and sequence, the has-user field
    # (fast-auth only) and four pointers, the user length and logon mode, the
    # pair count, and the username (length-prefixed from 12c, raw on 11g). The
    # already-serialised key/value pairs follow it.
    Head = _AUTH_HEAD_THIN(
        {
            'subtype': TTI_AUTH,
            'seq': Tseq,
            'has_user_ptr': HasUserPtr,
            'has_user': 0,
            'pointer_1': True,
            'user_length': len(User),
            'mode': ModeInt,
            'pointer_2': True,
            'pair_count': NumPairs,
            'pointer_3': True,
            'pointer_4': True,
            'user_prefixed': UserPrefixed,
            'user_raw': not UserPrefixed,
            'user': User,
        }
    )
    Data = Head + AuthPass + PBKDF2 + AuthSess + SessionKvs + ProxyKv + DrcpKv

    return (Data, ConnKey)


def encode_dictionary_token_auth(Dictionary: dict) -> bytes:
    """Build the token-auth AUTH message (#125).

    Token auth replaces the O5LOGON challenge/response entirely: there is no
    OSESSKEY, no session key, and no server proof. This is a single TTI_AUTH
    (func 0x73) message with no username, logon mode ``NoNewPass`` (0x1), and the
    key/value pairs carrying the token — ``AUTH_TOKEN`` always, plus
    ``AUTH_HEADER`` + ``AUTH_SIGNATURE`` for the OCI IAM (signed) variant — after
    the standard session-context pairs. The wire shape matches the ordinary AUTH
    header with the user fields zeroed.
    """
    Tseq = Dictionary['seq']
    Role = Dictionary['env'].get('role', 0)
    Prelim = Dictionary['env'].get('prelim', 0)
    # NoNewPass (0x1) only — no UserAndPass (0x100), since there is no password.
    Mode = encode_sb4((Role * 32) | (Prelim * 128) | 1)

    # Token auth is a 12.2+ feature: its long values (an RSA signature, a real
    # JWT) go out in the ub4-chunked form, whatever version login has reached --
    # the form the server side decodes them in (#1261).
    Token = _ENCODE_FIELD_VERSION.set(
        max(_ENCODE_FIELD_VERSION.get(), FIELD_VERSION_12_2)
    )
    try:
        Pairs = [encode_kv(b'AUTH_TOKEN', Dictionary['token'].encode('utf-8'))]
        Header = Dictionary.get('token_header')
        Signature = Dictionary.get('token_signature')
        if Header is not None and Signature is not None:
            Pairs.append(encode_kv(b'AUTH_HEADER', Header.encode('utf-8')))
            Pairs.append(encode_kv(b'AUTH_SIGNATURE', Signature.encode('utf-8')))
    finally:
        _ENCODE_FIELD_VERSION.reset(Token)
    SessionKvs = _auth_session_kvs(Dictionary)  # charset .. connect-string
    NumPairs = len(Pairs) + _auth_session_kv_count(Dictionary)

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
_CLIENT_VERSION = '3.5.0'


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


def _alter_session_clause(Dictionary: dict) -> bytes:
    # The login's ALTER SESSION: the time zone, and a transaction priority asked
    # for at connect, " TXN_PRIORITY='low'" as the reference client adds it
    # (#1776).
    Clause = _local_tz_clause()
    if Dictionary.get('txn_priority'):
        Priority = f" TXN_PRIORITY='{Dictionary['txn_priority']}'"
        Clause = Clause[:-1] + Priority.encode('utf-8') + b'\x00'
    return Clause


def _auth_session_kv_count(Dictionary: dict) -> int:
    """How many pairs :func:`_auth_session_kvs` will emit.

    The AUTH header DECLARES the pair count, so it has to be derived rather than
    written as a constant: adding the optional edition pair without counting it
    is answered ORA-03146 "invalid buffer length for TTC field", which names the
    buffer and not the count (#826).
    """
    return 5 + (1 if (Dictionary.get('env') or {}).get('edition') else 0)


def _edition_kv(Dictionary: dict) -> bytes:
    """``AUTH_ORA_EDITION`` when the caller asked for an edition, else nothing.

    `connect(edition=...)` selects an edition for the whole session, and it is a
    LOGIN-time choice -- it rides here rather than in a later ALTER SESSION
    (#826). Confirmed on the wire: the key appears in the AUTH only when the
    connect asked for one.
    """
    edition = (Dictionary.get('env') or {}).get('edition')
    if not edition:
        return b''
    return encode_kv(b'AUTH_ORA_EDITION', str(edition).encode('utf-8'))


def _client_driver_name(Dictionary: dict) -> str:
    """The banner this session reports as ``client_driver``.

    A caller may set it (``connect(driver_name=...)``, as python-oracledb allows)
    so an application can identify itself in ``v$session_connect_info``; left
    unset it is seerdb's own banner (#826).
    """
    declared = (Dictionary.get('env') or {}).get('driver_name')
    return declared if declared else f'seerdb thn : {_CLIENT_VERSION}'


def _auth_session_kvs(Dictionary: dict) -> bytes:
    """The session-context key/value pairs the OAUTH phase two must carry at
    fv >= 23.1 EXT 1 (#89): client charset, driver banner, packed version, the time-zone
    ALTER SESSION, and the connect descriptor."""
    Charset = struct.pack('<H', CharsetDict.get(Dictionary['req'], AL32UTF8_CHARSET))
    return (
        encode_kv(
            b'SESSION_CLIENT_CHARSET',
            str(int.from_bytes(Charset, 'little')).encode('utf-8'),
        )
        + encode_kv(
            b'SESSION_CLIENT_DRIVER_NAME',
            _client_driver_name(Dictionary).encode('utf-8'),
        )
        + encode_kv(
            b'SESSION_CLIENT_VERSION',
            str(_packed_client_version(_CLIENT_VERSION)).encode('utf-8'),
        )
        + _edition_kv(Dictionary)
        + encode_kv(b'AUTH_ALTER_SESSION', _alter_session_clause(Dictionary), 1)
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
    _encode_at_negotiated_version(Dictionary)
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
    # fv >= 23.1 EXT 1 (23ai, #89) needs the same header shape as the login phase two:
    # the extra leading pointer byte and the 0x20000 logon-mode bit (else the
    # server rejects the change with ORA-03120). See encode_dictionary_auth.
    if FieldVersion >= FIELD_VERSION_23_1_EXT_1:
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
    # Header for a TTI function-call message. 23ai (fv >= 23.1 EXT 1, #89) appends a
    # ub8 "token number" after the sequence number (oracledb's
    # _write_function_code at fv24) — present on every function message
    # (execute, fetch, commit/rollback, LOB ops, logoff, ...). Omitting it
    # desyncs the call: the server either rejects it (ORA-03146 / ORA-03120) or
    # never replies (read timeout). For an ordinary call the token is 0
    # (encode_sb4(0) == b"\x00", the historical single zero byte); request
    # pipelining (#132) numbers each piggybacked call 1..N so the server can tag
    # each response with a matching TOKEN (33) marker.
    if FieldVersion >= FIELD_VERSION_23_1_EXT_1:
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
    Out = _piggyback_head(TNS_FUNC_PIPELINE_BEGIN, Seq, FieldVersion, TokenNum)
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


def _piggyback_head(func: int, seq: int, field_version: int, token: int = 0) -> bytes:
    # The shared piggyback head (_PIGGYBACK_HEAD): marker, function, sequence,
    # and the 23ai request token (0 for an ordinary piggyback, the call's own
    # number in a pipelined burst). The token primitive reads the field version
    # from the context, so set it the way _fun_header takes it as a parameter.
    saved = _ENCODE_FIELD_VERSION.set(field_version)
    try:
        return _PIGGYBACK_HEAD_THIN({'func': func, 'seq': seq, 'token_number': token})
    finally:
        _ENCODE_FIELD_VERSION.reset(saved)


def encode_close_cursors_piggyback(Seq: int, FieldVersion: int, Cursors: list) -> bytes:
    """Build the CLOSE_CURSORS (OCCA, func 105) piggyback that frees a batch of
    server cursors (#191, _CLOSE_CURSORS). Rides in front of the next call's
    message; the server closes the listed cursors before processing that call.
    Mirrors oracledb's _write_close_cursors_piggyback -- note the ub8 token at
    fv24, which the older encode_dictionary_pig path omitted (it was never
    exercised on 12c+). The token goes by `FieldVersion`, the connection's."""
    Token = _ENCODE_FIELD_VERSION.set(FieldVersion)
    try:
        return _CLOSE_CURSORS_THIN(
            {
                'seq': Seq,
                'token_number': 0,
                'cursors_present': True,
                'count': len(Cursors),
                'cursors': [{'cursor': c} for c in Cursors],
            }
        )
    finally:
        _ENCODE_FIELD_VERSION.reset(Token)


def encode_8i_close_cursors(Seq: int, Cursors: list) -> bytes:
    """The close of `Cursors` on 8i, piggybacked in front of the next call
    (#2286). 8i keeps every statement's cursor open, a failed SELECT's too,
    until the client closes it; left open, a session ran out at open_cursors
    with ORA-01000. sqlplus 9.2 sends the same message as a call of its own."""
    return _CLOSE_CURSORS_O8I(
        {
            'seq': Seq & 0xFF,
            'token_number': None,
            'cursors_present': True,
            'count': len(Cursors),
            'cursors': [{'cursor': c} for c in Cursors],
        }
    )


def skip_close_cursors_piggyback(body: bytes) -> bytes:
    """What follows a thin CLOSE_CURSORS piggyback at the start of ``body``
    (_CLOSE_CURSORS): the Mirror keeps no cursor state to free."""
    return _CLOSE_CURSORS_FROM_THIN(body)[1]


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

    Out = _piggyback_head(TNS_FUNC_SET_END_TO_END_ATTR, Seq, FieldVersion)
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
    Out = _piggyback_head(TNS_FUNC_END_USER_SECURITY_CTX, Seq, FieldVersion)
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


def encode_app_context_piggyback(
    Seq: int, FieldVersion: int, Namespace: bytes, Entries: list[tuple[bytes, bytes]]
) -> bytes:
    """Build the application-context piggyback (func 154, #1775) for one
    namespace: set its ``Entries`` (key, value) pairs, or clear it when there
    are none. It rides in front of the next call's message once. Layout in
    docs/PROTOCOL.md; the zero byte before the namespace exists from field
    version 12.1, and a server reading at 11.2 or below (10g and 11g, or 23ai
    held there) rejects a piggyback that has it (ORA-03120)."""
    Out = _piggyback_head(TNS_FUNC_APP_CONTEXT, Seq, FieldVersion)
    Out += bytes([1]) + encode_sb4(len(Namespace))  # pointer, namespace length
    Out += bytes([1 if Entries else 0]) + encode_sb4(len(Entries))  # pointer, count
    Flags = TNS_APP_CONTEXT_FLAG_SET if Entries else TNS_APP_CONTEXT_FLAG_CLEAR
    Out += encode_sb4(Flags)  # ub2 flags
    if FieldVersion >= FIELD_VERSION_12_1:
        Out += bytes([0])
    Out += _bytes_with_length(Namespace)
    for Key, Value in Entries:
        Out += _obj_two_lengths(Key) + _obj_two_lengths(Value) + encode_sb4(0)
    return Out


def encode_alter_session_piggyback(Seq: int, FieldVersion: int, Priority: str) -> bytes:
    """Build the ALTER SESSION piggyback (func 204, #1776) that sets the session's
    transaction priority, the one setting it carries: ``TXN_PRIORITY`` as a
    single keyword-value pair whose flag is 1 for an empty value, which restores
    the default. It rides in front of the next call's message once. A server
    refuses it unless the client declared TNS_DATA_TYPE_ALTSESS. Layout in
    docs/PROTOCOL.md."""
    Out = _piggyback_head(TNS_FUNC_ALTER_SESSION, Seq, FieldVersion)
    Out += encode_sb4(0)  # flags
    Out += bytes([1]) + encode_sb4(1)  # pointer, one key-value pair
    Out += _obj_two_lengths(b'TXN_PRIORITY') + _obj_two_lengths(Priority.encode())
    Out += encode_sb4(0 if Priority else 1)
    return Out


def encode_session_state_piggyback(Seq: int, FieldVersion: int, State: int) -> bytes:
    """Build the session-state (request boundary) piggyback (func 176, #464).
    `State` is TNS_SESSION_STATE_REQUEST_BEGIN or _REQUEST_END; the explicit
    boundary bit is OR'd in. It rides in front of the next call's message and is
    one-shot (the caller clears the desired state after emitting it). Mirrors
    oracledb's _write_session_state_piggyback; byte layout in docs/PROTOCOL.md
    §35. Gated on the negotiated request-boundaries capability."""
    Out = _piggyback_head(TNS_FUNC_SESSION_STATE, Seq, FieldVersion)
    # ub8 (state | explicit-boundary); small values encode like ub4.
    Out += encode_sb4(State | TNS_SESSION_STATE_EXPLICIT_BOUNDARY)
    return Out


def encode_free_temp_lobs_piggyback(
    Seq: int, FieldVersion: int, Locators: list[bytes]
) -> bytes:
    """Build the close-temp-LOBs piggyback (func TTI_LOBOPS = 96, #852): a
    FREE_TEMP over an ARRAY of locators, which a client rides in front of its
    next call once temp LOBs it created have gone out of scope. Each locator is
    the ub2-length-prefixed form CREATE_TEMP handed out (40 bytes for a real
    server's 38). Mirrors oracledb's _write_close_temp_lobs_piggyback; byte
    layout in docs/PROTOCOL.md §14.5."""
    Out = _piggyback_head(TTI_LOBOPS, Seq, FieldVersion)
    Wire = b''.join(struct.pack('>H', len(L)) + L for L in Locators)
    Out += bytes([1]) + encode_sb4(len(Wire))  # pointer + total locator bytes
    Out += bytes([0]) + encode_sb4(0)  # dest locator pointer + length
    Out += encode_sb4(0) + encode_sb4(0)  # source locator pointer + length
    Out += bytes([0, 0, 0])  # source offset, dest offset, charset pointers
    Out += encode_sb4(TNS_LOB_OP_FREE_TEMP | TNS_LOB_OP_ARRAY)
    Out += bytes([0]) + encode_sb4(0)  # scn pointer + lobscn
    Out += encode_sb4(0) + encode_sb4(0) + bytes([0])  # lobscnl (ub8 ×2), flag
    Out += bytes([0]) + encode_sb4(0)  # the three array-LOB slots: a pointer
    Out += bytes([0]) + encode_sb4(0)  # byte and a ub4 length each (none is
    Out += bytes([0]) + encode_sb4(0)  # used; the locators just follow)
    return Out + Wire


def parse_free_temp_lobs_piggyback(rest: bytes) -> tuple[list[bytes], bytes]:
    """Walk a close-temp-LOBs piggyback from just past its header (the inverse
    of encode_free_temp_lobs_piggyback). Returns the freed locators, each
    without its ub2 length prefix, and the bytes after the piggyback.

    The layout is a FREE_TEMP request's fixed block with the ARRAY bit set on the
    operation and the locators concatenated after the array slots, `total` bytes
    of them; no count is sent, so the locators are split by their own length
    prefixes. Every scalar is zero on the wire (the ub8 SCNs included, which is
    why decode_ub4 can read them: a zero is a single byte in either width)."""
    rest = rest[1:]  # pointer
    total, rest = decode_ub4(rest)
    rest = rest[1:]  # dest locator pointer
    _, rest = decode_ub4(rest)  # dest locator length
    _, rest = decode_ub4(rest)  # source locator pointer
    _, rest = decode_ub4(rest)  # source locator length
    rest = rest[3:]  # source offset, dest offset, charset pointers
    _operation, rest = decode_ub4(rest)  # FREE_TEMP | ARRAY
    rest = rest[1:]  # scn pointer
    _, rest = decode_ub4(rest)  # lobscn
    _, rest = decode_ub4(rest)  # lobscnl
    _, rest = decode_ub4(rest)
    rest = rest[1:]
    for _ in range(3):  # the array-LOB slots: pointer byte + ub4 length
        rest = rest[1:]
        _, rest = decode_ub4(rest)
    if len(rest) < total:
        raise Truncated('close-temp-LOBs piggyback')
    wire, rest = rest[:total], rest[total:]
    locators = []
    while len(wire) >= 2:
        loc_len = struct.unpack('>H', wire[:2])[0]
        locators.append(wire[2 : 2 + loc_len])
        wire = wire[2 + loc_len :]
    return locators, rest


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
    if field_version >= FIELD_VERSION_23_1_EXT_1:
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
    # The server type the caller asked for, written as the reference client
    # writes it, (SERVER=dedicated|shared|pooled) (#1977), and only then: a
    # connection class or a purity requests no pooled server by itself (#1990).
    ServerType = Dictionary['env'].get('server_type')
    Drcp = b'(SERVER=' + ServerType.encode('ascii') + b')' if ServerType else b''
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
            CCAP_FEATURE_BACKPORT2: (
                CCAP_FEATURE_BACKPORT2_END_USER_SEC
                | CCAP_FEATURE_BACKPORT2_TXN_PRIORITY
            ),
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


def capability_arrays(
    field_version: int = FIELD_VERSION_11_2, oall8: bool = False
) -> tuple[bytes, bytes]:
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
        # The OALL8 opt-in advertises the two extra bytes instead (#716).
        if oall8:
            return _O3_OALL8_COMPILE_CAPS, _O3_OALL8_RUNTIME_CAPS
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

# The 9i OALL8 opt-in (#716, experimental): the capability vectors a native 9.2
# OCI client (sqlplus) sends, captured from the wire (tcpdump on the 9i bed,
# #790). The compile caps are NOT the minimal JDBC-thin vector the default 9i
# path uses -- the native client sends a *populated* vector, with the field
# version at CCAP_FIELD_VERSION (idx 7 = 2 = 9.2). The runtime caps carry the
# second byte that makes the server treat OALL8 as 64-bit (without it the server
# reads the 64-bit fields as 32-bit and raises ORA-03120). The earlier minimal
# vector logged in for a while but the server closes on it on the current bed;
# the captured native vector is what the 9.2 server actually negotiates.
#
# ONE deliberate deviation from the capture (#790): CCAP_LOGON_TYPES (idx 4) is
# forced to 0, not the native client's 0x05. 0x05 makes the 9.2 server issue a
# 16-byte session key whose OCI OAUTH proof is a non-standard DES variant we have
# not cracked (ruled out exhaustively against two live captures). With LOGON_TYPES
# = 0 the server falls back to the plain 8-byte DES O3LOGON key -- exactly what
# the thin 9i / 8i paths use -- so the existing crypto.o3logon authenticates. The
# 16-byte "thick" proof is a documented, accepted limitation, deferred as a
# someday-maybe; the rest of the OALL8 session (64-bit data dialect) is unchanged.
_O3_OALL8_COMPILE_CAPS = bytes(
    [
        0x06,
        0x01,
        0x01,
        0x01,
        0x00,  # CCAP_LOGON_TYPES: 0, not the native 0x05 -> 8-byte O3LOGON (#790)
        0x01,
        0x01,
        0x02,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x7F,
        0x0F,
        0x03,
        0x06,
        0x03,
        0x00,
    ]
)
_O3_OALL8_RUNTIME_CAPS = bytes([2, 1])
# A native 9.2 OCI client's TTI_DTY is *compact*: it sends no 980-byte identity
# type table (the server sends its table back instead), just this trailer after
# the capability arrays (captured, #790). The default path sends the full table.
_O3_OALL8_DTY_TRAILER = bytes(
    [0x80, 0x00, 0x00, 0x00, 0x3C, 0x3C, 0x3C, 0x80, 0x00, 0x00, 0x00]
)


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
    TNS_DATA_TYPE_ALTSESS,  # needed for the ALTER SESSION piggyback (#1776)
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


def _oci_version_trailer(release: int) -> bytes:
    """The packed-version + capability trailer sqlplus reads after the banner.
    The version is the high three bytes of Oracle's packed version word in
    little-endian order, then the capability word. Confirmed live: 10.2.0.5 →
    ``05 20 0a``, 11.2.0.2 → ``02 20 0b``, and in the 18c layout 18.4.0.0 →
    ``00 04 12``, 23.26.2.0 → ``20 1a 17`` (#2024)."""
    return release.to_bytes(4, 'big')[:3][::-1] + _OCI_VERSION_CAPS


# The OCI row header (TTI_RXH) that leads the rows: 50 bytes, the token and its
# flags then single bytes at fixed offsets, the rest zero. The query describe's
# tail, a fetch batch and a LOB-locator fetch each carry one with values of its
# own. Their meaning is unpinned: offset 4 is the describe's column count, and
# reads 2 in the fetch's and 1 in the LOB fetch's; the describe's `06 01 22`
# head is byte-identical in the 11g, 21c and 23ai replies (differential
# capture, 2026-09-07) and the client draws ORA-03113 if it is zeroed (§36,
# §39.2). Reduced to these from live replies (#265, #351, #405).
_OCI_RXH: wire_schema.Schema = (
    ('const', bytes([TTI_RXH])),
    ('u8', 'flags'),
    ('u8', 'unpinned_2'),
    ('u8', 'unpinned_3'),
    ('u8', 'unpinned_4'),
    ('pad', 5),
    ('u8', 'unpinned_10'),
    ('pad', 39),
)
_OCI_RXH_OCI = wire_schema.compile_encoder(_OCI_RXH, _OCI)
_OCI_RXH_FROM_OCI = wire_schema.compile_decoder(_OCI_RXH, _OCI)


def _oci_rxh_of(
    unpinned_2: int, unpinned_3: int, unpinned_4: int, unpinned_10: int
) -> bytes:
    return _OCI_RXH_OCI(
        {
            'flags': 0x01,
            'unpinned_2': unpinned_2,
            'unpinned_3': unpinned_3,
            'unpinned_4': unpinned_4,
            'unpinned_10': unpinned_10,
        }
    )


# The OCI OER return-status token (§36), reverse-engineered against live 11g:
# 136 bytes to 11g, 144 from the 12c band, which repeats the error number at
# offset 132 and adds a ub8 row count -- the fields a 12.1+ thin OER adds too,
# captured from 18c for every reply kind (#1282). Every OCI status ends on one.
# Its fields are fixed-width; one whose meaning is unpinned is named for its
# offset and carries the value each reply was captured with (§36.1).
#
# Differential capture (sqlplus through tools/capture_proxy.py against 11g, 21c
# and 23ai, 2026-09-07) settled two of them: the offset-56 ub2 0x0136 (310) and
# the offset-72 `20 f6 31 0a` marker are fixed 11g OER constants, byte-identical
# across every 11g reply (SELECT / DML / DDL / fetch) and absent from 21c and
# 23ai, which replace the whole trailer with a different one. So 310 is not the
# negotiated TTC protocol version (the earlier guess) (§39.2). The end-of-fetch
# OER carries the marker without its 0x20, and the row statuses neither.
_OCI_OER: wire_schema.Schema = (
    ('const', b'\x04'),
    ('u8', 'status'),  # SUCCESS 0x01, ERROR 0x05; 2 on a DML
    ('pad', 3),
    ('n2', 'sequence'),  # the end-to-end sequence
    ('const', b'\x01'),
    # 1 on a LOB / LONG-row status, 2 on a LONG; a DML carries its row count.
    ('n4', 'row_kind'),
    ('n4', 'error_code'),
    ('pad', 2),
    ('u8', 'category'),  # 2 row/value-producing, 1 DDL, 0 none
    ('pad', 1),
    ('u8', 'error_pos'),  # the column sqlplus draws its caret under
    ('pad', 1),
    ('u8', 'command_type'),  # the V$SQL command type
    ('pad', 4),
    ('u8', 'warn_flags'),  # 0x21: a PL/SQL object compiled with errors
    ('bytes', 'rowid', 13),  # a DML's touched row
    ('pad', 8),
    ('n2', 'call_sequence'),  # the answered call's own sequence
    ('pad', 1),
    ('u8', 'unpinned_52'),
    ('pad', 3),
    ('n2', 'unpinned_56'),
    ('pad', 14),
    ('bytes', 'marker', 4),
    ('pad', 4),
    ('u8', 'unpinned_80'),
    ('pad', 51),
    ('when', 'oci_12c', (('n4', 'ext_error_code'), ('n8', 'rowcount'))),
    ('when', 'oci_pre12c', (('pad', 4),)),
)
_OCI_OER_OCI = wire_schema.compile_encoder(_OCI_OER, _OCI)
_OCI_OER_FROM_OCI = wire_schema.compile_decoder(_OCI_OER, _OCI)
_OCI_OER_MARKER = bytes.fromhex('20f6310a')
# A statement's OER as a live 11g sends it: SELECT, with the 11g constants.
_OCI_OER_STATEMENT = {
    'status': 0,
    'sequence': 0,
    'row_kind': oci.OCI_OER_ROW_KIND_NONE,
    'error_code': 0,
    'category': 2,
    'error_pos': 0,
    'command_type': oci.OCI_CMD_SELECT,
    'warn_flags': 0,
    'rowid': bytes(13),
    'call_sequence': 0,
    'unpinned_52': 1,
    'unpinned_56': 0x0136,
    'marker': _OCI_OER_MARKER,
    'unpinned_80': 0,
    'rowcount': 0,
}
# The row statuses' and the end-of-fetch OER: a success over one row and
# nothing behind it, reduced to that by live bisection (#265).
_OCI_OER_ROWS = {
    **_OCI_OER_STATEMENT,
    'status': 1,
    'row_kind': oci.OCI_OER_ROW_KIND_LOB,
    'unpinned_52': 0,
    'unpinned_56': 0,
    'marker': bytes(4),
}


def _oci_oer(fields: dict, *, wide: bool | None = None) -> bytes:
    """An OCI OER (_OCI_OER) from ``fields``, in the band the session speaks
    unless ``wide`` says which."""
    if wide is None:
        wide = _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
    return _OCI_OER_OCI(
        {
            **fields,
            'ext_error_code': fields['error_code'],
            'oci_12c': wide,
            'oci_pre12c': not wide,
        }
    )


def encode_oci_oer(
    status: int,
    *,
    sequence: int,
    row_kind: int = oci.OCI_OER_ROW_KIND_NONE,
    error_pos: int = 0,
    error_code: int = 0,
    command_type: int = oci.OCI_CMD_SELECT,
    category: int | None = None,
    rowcount: int = 0,
    warn_flags: int = 0,
    unpinned_52: int = 1,
) -> bytes:
    """A statement's OCI OER return-status token (§36, _OCI_OER). ``status`` is
    SUCCESS (0x01) or ERROR (0x05); ``row_kind`` marks a LOB/LONG-row status;
    ``error_pos`` and ``error_code`` carry an ORA error; ``command_type`` is the
    V$SQL command type (SELECT by default). ``sequence`` is the OER's
    **end-to-end sequence number**. The caller appends the ``ORA-…`` message
    DALC for the error case.

    The field is a diagnostic/tracing counter, not a protocol-correctness field:
    both reference clients (thin and thick) read it and discard it — never
    validate, echo, or transmit it. The Mirror advances it with a real
    per-session counter (:class:`~seerdb.server.session._OciSequence`) so its
    replies look like a live server's rather than emitting the frozen value each
    status was captured with; the start/step is Mirror policy (§36.1)."""
    fields = {
        **_OCI_OER_STATEMENT,
        'status': status,
        'sequence': sequence,
        'row_kind': row_kind,
        # The error position is a single byte; a larger parse offset is clamped
        # rather than overflowing it (the caret then lands at the last column
        # it can express).
        'error_pos': min(max(error_pos, 0), 0xFF),
        'error_code': error_code,
        'command_type': command_type,
        # The statement category; 2 when not given.
        'category': 2 if category is None else category,
        # The sequence of the CALL being answered, not an echo of the counter
        # above: the client's own `03 <func> <seq>` byte, published by the OCI
        # session loop (§36.1). Decoded across every reply kind in one live 11g
        # session and confirmed on 10g; `sequence + 2` was a coincidence of the
        # early-session captures it was read off, where the two counters had not
        # yet diverged.
        'call_sequence': _ENCODE_OCI_CALL_SEQ.get(),
        'rowcount': rowcount,
        'warn_flags': warn_flags,
        'unpinned_52': unpinned_52,
    }
    return _oci_oer(fields)


# The 35-byte `08 06` OCI exec-status frame preamble, shared by the describe /
# outbind / DDL / DML statuses and the row statuses. It is all zero (the Mirror
# has no live per-statement session counters) but for the header, a ub2-LE
# **cursor id** (the DDL / DML statuses carry a live cursor id here; the others
# none), and two small marker bytes whose values track the statement kind but
# whose exact meaning is unpinned, carried from the capture: offset 11 is `0x02`
# on a value/row-producing status (describe / outbind / DML / rows), `0x01` on
# the no-row status and `0` on DDL; offset 15 is `0x01` on the DML status and
# `0` otherwise.
_OCI_STATUS_FRAME: wire_schema.Schema = (
    ('const', b'\x08\x06'),
    ('pad', 2),
    ('n2', 'cursor_id'),
    ('pad', 5),
    ('u8', 'statement_mark'),
    ('pad', 3),
    ('u8', 'dml_mark'),
    ('pad', 19),
)
_OCI_STATUS_FRAME_OCI = wire_schema.compile_encoder(_OCI_STATUS_FRAME, _OCI)


def _oci_status_frame_prefix(
    cursor_id: int = 0, *, row_producing: bool = False, dml: bool = False, mark: int = 0
) -> bytes:
    return _OCI_STATUS_FRAME_OCI(
        {
            'cursor_id': cursor_id,
            'statement_mark': 0x02 if row_producing else mark,
            'dml_mark': 0x01 if dml else 0,
        }
    )


_OCI_STATUS_FRAME_PREFIX = _oci_status_frame_prefix(row_producing=True)


# The describe-only reply's trailing execute status (§36.3): the shared status
# preamble + a success OER. offset 20 carries a non-zero value under a success
# status — carried from the live capture; its meaning in the describe context is
# unclear, but it is fixed across captures.
def _oci_lob_describe_status(sequence: int) -> bytes:
    return _OCI_STATUS_FRAME_PREFIX + encode_oci_oer(
        oci.OCI_OER_STATUS_SUCCESS, sequence=sequence, error_pos=14
    )


# The DML execute-status frame (§36.3): the 35-byte preamble (its cursor id
# `0x5be8` carried from the capture, plus the row-producing and DML markers) +
# the OER + a 16-byte trailer. Unlike the describe/DDL/outbind statuses its OER
# carries the touched row's physical **rowid**, echoed in the trailer --
# capture-specific, opaque to sqlplus (which renders "N rows created" from only
# the row count and command type).
_OCI_DML_FRAME_PREFIX = _oci_status_frame_prefix(0x5BE8, row_producing=True, dml=True)


# The captured touched-row rowid. FIXME: real physical row identity from the
# capture; carried, like the LOB LID (§14.6) — a synthetic value would need live
# 11g validation.
_OCI_DML_ROWID = bytes.fromhex('7fb5010001000000b1b4000000')


# The 16-byte DML status trailer is NOT independent of the rowid: it carries two
# of the rowid's big-endian words as ub2s -- the first at offset 6 (7f b5 →
# b5 7f) and the fifth at offset 12 (b1 b4 → b4 b1) -- inside an otherwise fixed
# frame. Both come from the same captured row; the physical fields' meaning
# stays unpinned.
_OCI_DML_TRAILER: wire_schema.Schema = (
    ('const', bytes.fromhex('0d000d010001')),
    ('n2', 'rowid_word_0'),
    ('const', bytes.fromhex('00010000')),
    ('n2', 'rowid_word_4'),
    ('const', bytes(2)),
)
_OCI_DML_TRAILER_OCI = wire_schema.compile_encoder(_OCI_DML_TRAILER, _OCI)


def _oci_dml_frame_trailer(rowid: bytes) -> bytes:
    return _OCI_DML_TRAILER_OCI(
        {
            'rowid_word_0': int.from_bytes(rowid[0:2], 'big'),
            'rowid_word_4': int.from_bytes(rowid[8:10], 'big'),
        }
    )


_OCI_DML_FRAME_TRAILER = _oci_dml_frame_trailer(_OCI_DML_ROWID)


def _oci_dml_status_frame(
    sequence: int, rowcount: int = 0, command_type: int = 0
) -> bytes:
    # status 2 is the DML call status (not the fetch/exec 1); offset-20 carries a
    # non-zero value under it (the same murky field as the describe status, §36.1).
    # The row count rides where other OERs put the row kind; from the 12c band
    # sqlplus reads it from the OER's ub8 row count instead (#1282).
    fields = {
        **_OCI_OER_STATEMENT,
        'status': 2,
        'sequence': sequence,
        'row_kind': rowcount,
        'error_pos': 12,
        'command_type': command_type,
        'rowid': _OCI_DML_ROWID,
        'call_sequence': _ENCODE_OCI_CALL_SEQ.get(),
        'unpinned_80': 0x0D,  # carried row/SCN byte
        'rowcount': rowcount,
    }
    return _OCI_DML_FRAME_PREFIX + _oci_oer(fields) + _OCI_DML_FRAME_TRAILER


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
_OCI_OUTBIND_HEADER: wire_schema.Schema = (
    ('const', bytes.fromhex('0b0105cc')),  # the TTC out-bind opcode, two fixed
    ('u8', 'bind_count'),
    ('pad', 5),
    ('const', b'\x01'),  # a fixed 11.2 identity byte
    ('pad', 17),
    ('n2', 'row_buffer_size'),
    ('pad', 20),
)
_OCI_OUTBIND_HEADER_OCI = wire_schema.compile_encoder(_OCI_OUTBIND_HEADER, _OCI)


def _oci_outbind_header(bind_count: int) -> bytes:
    """The 50-byte OCI OUT-bind reply header (#347): the TTC out-bind opcode and
    two fixed bytes, the bind count, and the fixed 11.2 identity bytes, a
    row-buffer size among them. The rest is the instance state (server pointer,
    SCN, sequence) the Mirror leaves zeroed."""
    return _OCI_OUTBIND_HEADER_OCI({'bind_count': bind_count, 'row_buffer_size': 2024})


# The outbind (PL/SQL OUT-bind) reply's trailing execute status: the shared
# status preamble + a PL/SQL-block success OER. It used to zero offset 49, on the
# reading that this reply alone did not echo the sequence; a live 11g capture of
# `begin :n := 42; end;` shows it carrying the call's sequence (11) like every
# other reply, so it now takes the shared builder unmodified (#884).
def _oci_outbind_tail(sequence: int) -> bytes:
    return _OCI_STATUS_FRAME_PREFIX + _oci_outbind_oer(sequence)


def _oci_outbind_oer(sequence: int) -> bytes:
    return encode_oci_oer(
        oci.OCI_OER_STATUS_SUCCESS,
        sequence=sequence,
        row_kind=oci.OCI_OER_ROW_KIND_LOB,
        command_type=oci.OCI_CMD_PLSQL,
    )


def _oci_tti_sta(call_status: int, sequence: int) -> bytes:
    """A small TTI_STA acknowledgement — a ``TTI_STA`` token, the OER call status
    (ub4 LE) and the OER **end-to-end sequence** (ub2 LE): the same free-running
    per-session server counter the full OER carries at offset 5 (§36), not a row
    count or a length. The commit and logoff acks sqlplus waits for share this
    shape."""
    return _STA_OCI({'call_status': call_status, 'sequence': sequence})


# The TTI_STA call status is the OER's flag word, NOT the OER status byte at
# offset 1 that OCI_OER_STATUS_SUCCESS / _ERROR name (they share the values 1 and
# 5 by coincidence). Live 10g and 11g both answer a commit with 5 and a logoff
# with 1; never gate behaviour on it (see the flag-word note in §36.1).
_OCI_STA_CALL_STATUS_COMMIT = 5
_OCI_STA_CALL_STATUS_LOGOFF = 1


# sqlplus waits for this ack of its logoff before closing; without it the client
# sees an abrupt EOF and reports ORA-03113 on exit. It is the one OCI reply that
# does NOT carry the session counter: a live server sends a literal 0 here, on
# both 10g and 11g, so this stays a constant (§36.2).
_OCI_LOGOFF_STATUS = _oci_tti_sta(_OCI_STA_CALL_STATUS_LOGOFF, 0)


def _oci_auth_trailer(sequence: int, *, wide: bool = False) -> bytes:
    """The OER-shaped status block trailing an OCI auth key-value list.

    It is the statement OER (_OCI_OER, §36.1) with the auth-reply fields set:
    success status, the reply sequence as the sequence and the call sequence
    alike, and no category or command type. The sequence is the only thing
    distinguishing the challenge reply (2) from the result reply (3). From 12.1
    it is 8 bytes longer, as every OER is (captured from 18c): sqlplus reads the
    12c-band length, and the 136-byte form leaves it short and the login stalls
    (#1282).
    """
    fields = {
        **_OCI_OER_STATEMENT,
        'status': oci.OCI_OER_STATUS_SUCCESS,
        'sequence': sequence,
        'call_sequence': sequence,
        'category': 0,
        'command_type': 0,
        'unpinned_52': 0,
    }
    return _oci_oer(fields, wide=wide)


_CHALLENGE_TRAILER = _oci_auth_trailer(2)
_RESULT_TRAILER = _oci_auth_trailer(3)
_CHALLENGE_TRAILER_12C = _oci_auth_trailer(2, wide=True)
_RESULT_TRAILER_12C = _oci_auth_trailer(3, wide=True)


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
# The persistent-LOB locator as a LOB cell carries it, 106 bytes: the ub2 BE
# length of what follows (104) -- whose high byte the cell writes as the zero
# ahead of the 105 bytes sqlplus echoes -- a version, the four flag bytes every
# locator has (the third's 0x80 the variable-width charset bit, as a thin
# client reads it), the LOB type, then the body. Its physical **LOB Locator ID**
# -- the object id, three segment DBAs and an SCN of a real LOB in the source
# database -- is opaque to the client, which only echoes the locator on each LOB
# op. The Mirror has no such segment, so it emits a **synthetic LID of zeros**:
# verified live against sqlplus 11.2 over the Mirror, which reads the CLOB and
# BLOB content back correctly with the physical fields zeroed (drivers such as
# go-ora only interpret the header flag bits, never the LID). With the physical
# LID gone the CLOB and BLOB bodies are identical bar the charset id, so one
# layout serves both. The LID's zero run carries the Mirror's own two names,
# which a client echoes without reading (§14.6): the LOB's row slot (#1430) and
# its sqlplus variable (#2015), each plus one so zero stays "none". The content
# byte size sqlplus sizes its READ by is a field too.
_OCI_LOB_LOCATOR: wire_schema.Schema = (
    ('be2', 'length'),
    ('be2', 'version'),
    ('u8', 'lob_kind'),  # 0x02 CLOB, 0x04 NCLOB, 0x01 BLOB
    ('u8', 'flags_2'),  # bit 0x40 = national form
    ('u8', 'flags_3'),  # bit 0x80 = variable-width charset (AL16UTF16 is fixed)
    ('u8', 'flags_4'),
    ('pad', 1),
    ('u8', 'lob_type'),
    ('const', bytes.fromhex('0000000100000056000000010000000100000002')),
    ('const', bytes.fromhex('0002')),
    ('be2', 'charset'),
    ('const', bytes.fromhex('0002')),
    ('pad', 5),
    ('be4', 'slot'),
    ('be4', 'lob_var'),
    ('pad', 25),
    ('const', bytes.fromhex('00000001')),
    ('pad', 9),
    ('const', bytes.fromhex('1405')),
    ('pad', 3),
    ('be4', 'byte_size'),
    ('pad', 5),
    ('const', b'\x02'),
    ('pad', 4),
)
_OCI_LOB_LOCATOR_OCI = wire_schema.compile_encoder(_OCI_LOB_LOCATOR, _OCI)
_OCI_LOB_LOCATOR_FROM_OCI = wire_schema.compile_decoder(_OCI_LOB_LOCATOR, _OCI)
# What sqlplus is told a minted LOB holds, until the cell says: 4000 bytes.
_OCI_LOB_TEMPLATE_SIZE = 4000


def _oci_lob_locator_fields(
    is_clob: bool,
    national: bool = False,
    *,
    slot: int | None = None,
    lob_var: int | None = None,
    byte_size: int = _OCI_LOB_TEMPLATE_SIZE,
) -> dict:
    """The fields of a persistent-LOB locator the Mirror mints (_OCI_LOB_LOCATOR).

    An NCLOB (``national``) is a CLOB whose header says so and whose charset is
    AL16UTF16, fixed width (§14.6). Measured against a live 11g: sqlplus refuses
    a CLOB-form locator under an NCLOB describe with ORA-24806."""
    national = is_clob and national
    return {
        'length': 104,
        'version': 1,
        'lob_kind': 0x04 if national else 0x02 if is_clob else 0x01,
        'flags_2': 0x4C if national else 0x0C,
        'flags_3': 0x88 if is_clob and not national else 0x08,
        'flags_4': 0,
        'lob_type': 0x02 if is_clob else 0x01,
        'charset': (AL16UTF16_CHARSET if national else AL32UTF8_CHARSET)
        if is_clob
        else 0,
        'slot': 0 if slot is None else slot + 1,
        'lob_var': 0 if lob_var is None else lob_var + 1,
        'byte_size': byte_size,
    }


def _oci_lob_locator_cell(
    is_clob: bool,
    national: bool = False,
    *,
    slot: int | None = None,
    lob_var: int | None = None,
    byte_size: int = _OCI_LOB_TEMPLATE_SIZE,
) -> bytes:
    # The locator with its length's zero high byte, as a cell carries it.
    return _OCI_LOB_LOCATOR_OCI(
        _oci_lob_locator_fields(
            is_clob, national, slot=slot, lob_var=lob_var, byte_size=byte_size
        )
    )


def _oci_lob_locator(is_clob: bool, national: bool = False) -> bytes:
    """The 105-byte persistent-LOB locator sqlplus binds and echoes (§14.6)."""
    return _oci_lob_locator_cell(is_clob, national)[1:]


# Which of a row's LOBs a locator names (#1430): sqlplus reads a row's LOBs
# interleaved -- a's first chunk, b's first, a's second -- and names each by the
# locator it echoes, so every LOB of a row needs its own. The slot (the LOB's
# column index, plus one so zero stays "none") rides four bytes of the
# template's all-zero run (locator offsets 35..75, inside the synthetic LID),
# which a client echoes without reading (§14.6).
def _oci_lob_locator_from(region: bytes) -> dict | None:
    # The fields of a locator the Mirror minted, found in an echoed region by
    # its length and version, or None.
    start = region.find(b'\x68\x00\x01', 0, 4)
    if start < 0:
        return None
    try:
        return _OCI_LOB_LOCATOR_FROM_OCI(b'\x00' + region[start:])[0]
    except (IndexError, ValueError):
        return None


def _oci_lob_read_status(sequence: int) -> bytes:
    # The status a TTI_LOBOPS READ reply ends on: the LOB-row OER call status.
    # ``sequence`` is the live per-session OER counter (§36).
    # FIXME: the LOB read-status OER has no category (see §36.1).
    return encode_oci_oer(
        oci.OCI_OER_STATUS_SUCCESS,
        sequence=sequence,
        row_kind=oci.OCI_OER_ROW_KIND_LOB,
        command_type=0,
        category=0,
    )


# --- Mirror deadbeef/OCI codec (parse/describe/rows/status/LOB, #265) ---


# The OALL8 preamble comes in two widths, and which one a client sends is fixed
# for the life of its connection (#866). Between the 8-byte pointer indicators
# sit scalar slots that an older sqlplus writes as ub8 and a modern one (23.26
# measured) writes as ub4. Five slots shrink by 4 bytes each, so the narrow
# preamble is 20 bytes shorter overall — but they are spread through the header,
# so each field behind them moves by a DIFFERENT amount (the running total of the
# slots ahead of it), not by one global shift:
#
#     field                 wide   narrow
#     cursor id (ub4)          7        7   (ahead of every shrinking slot)
#     3x SQL byte length      19       19
#     second indicator        27       23
#     bind count (ub4)        83       71
#     SQL text               196      176
#
# The indicators themselves stay 8 bytes wide in both, which is what makes the
# two forms tellable apart: the second one sits at 27 in the wide form and at 23
# in the narrow, and those two cannot both hold (the pattern starts with 0xFE and
# continues 0xFF, so an indicator at 23 puts 0xFF at 27). Detect the width from
# the wire rather than assume one: reading a narrow execute with the wide offsets
# lands 20 bytes past the SQL length prefix and reads the bind count off an
# indicator (0xFFFFFFFE) instead of the header.
_OCI_ALL8_IND2_OFF = 27  # second indicator, wide preamble
_OCI_ALL8_IND2_OFF_NARROW = 23  # ... and narrow: one shrinking slot sits ahead


class _OciAll8Form(NamedTuple):
    """One OCI preamble form: its header's decoder, through the define count
    (_ALL8_HEAD), and how many bytes follow it before the SQL's length byte."""

    decode: wire_schema.Decoder
    after_defines: int


# Behind the define count, wide and narrow alike, 48 bytes stand where thin
# writes its registration and SQL-signature fields.
_OCI_ALL8_WIDE = _OciAll8Form(_ALL8_HEAD_FROM_OCI_WIDE, 48)
_OCI_ALL8_NARROW = _OciAll8Form(_ALL8_HEAD_FROM_OCI, 48)

# From the 12c band the narrow preamble grows by 64 bytes there (eight more
# 8-byte slots, zero in every capture; sqlplus 23.26 against a live 18c, #1282).
# The width tests below still hold, and the inserted bytes are zeros a wire
# test could only guess at, so the session's field version says which form it
# is.
_OCI_ALL8_NARROW_12C = _OCI_ALL8_NARROW._replace(after_defines=48 + 64)

# sqlplus 10.2 sends the narrow preamble with 28 bytes fewer there, the SQL at
# 148 in every statement it sent to 10g and 11g (#1764). Its pointer fields hold
# addresses, not the indicator, and an address at 23 can leave bytes at 27 that
# look like one, so the session's field version says which form it is, as for
# the 12c growth.
_OCI_ALL8_10_2 = _OCI_ALL8_NARROW._replace(after_defines=48 - 28)


def _oci_all8_form(payload: bytes, *, sql_present: bool = True) -> _OciAll8Form:
    """Which OALL8 preamble form ``payload`` carries. Raises :class:`InterfaceError` when neither shape holds, so a
    differently-shaped message errors rather than yielding a garbage SQL.
    ``sql_present`` is False for a re-execute by cursor id, whose SQL pointer at
    offset 11 is absent; the second indicator still tells the width (#2014)."""
    if _DECODE_FIELD_VERSION.get() < FIELD_VERSION_11_2:
        pointers = (_OCI_ALL8_IND_OFF, _OCI_ALL8_IND2_OFF_NARROW)
        for ind in pointers if sql_present else pointers[1:]:
            if not oci.pointer_present(payload[ind : ind + 8]):
                raise InterfaceError(f'OCI OALL8: no pointer at offset {ind}')
        return _OCI_ALL8_10_2
    if (
        sql_present
        and payload[_OCI_ALL8_IND_OFF : _OCI_ALL8_IND_OFF + 8] != oci.OCI_INDICATOR
    ):
        raise InterfaceError(f'OCI OALL8: no indicator at offset {_OCI_ALL8_IND_OFF}')
    for ind2, layout in (
        (_OCI_ALL8_IND2_OFF, _OCI_ALL8_WIDE),
        (_OCI_ALL8_IND2_OFF_NARROW, _OCI_ALL8_NARROW),
    ):
        if payload[ind2 : ind2 + 8] == oci.OCI_INDICATOR:
            if (
                layout is _OCI_ALL8_NARROW
                and _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
            ):
                return _OCI_ALL8_NARROW_12C
            return layout
    raise InterfaceError(f'OCI OALL8: no indicator at offset {_OCI_ALL8_IND2_OFF}')


def _oci_all8_head(
    payload: bytes, *, sql_present: bool = True
) -> tuple[int, int, dict[str, Any]]:
    # An OCI OALL8's cursor id, where its SQL's length byte is, and its header
    # fields through the define count (_ALL8_HEAD), in its preamble's form.
    form = _oci_all8_form(payload, sql_present=sql_present)
    (head, rest) = form.decode(payload)
    length_at = len(payload) - len(rest) + form.after_defines
    return head['cursor'], length_at, head


def parse_exec_oci(payload: bytes) -> ExecRequest:
    """Parse a sqlplus / thick-OCI (deadbeef dialect) OALL8 execute (#265).

    The OCI counterpart of :func:`parse_exec`. Extracts the SQL text and cursor
    id from the fixed-shape OCI header, in either preamble width (see
    :func:`_oci_all8_form`). Scope: a single statement, its SQL either behind a
    ub1 length or chunked when longer, and its binds. Raises
    :class:`InterfaceError` if the message is not an OCI OALL8 in that shape, or
    carries binds of a form not read yet.
    """
    if len(payload) < 12 or payload[0] != TTI_FUN or payload[1] != TTI_ALL8:
        raise InterfaceError('not an OCI OALL8 execute')
    # Validate the indicators where the thin form has 0x01 flags, so a
    # differently-shaped message errors rather than yielding a garbage SQL.
    (cursor, length_at, head) = _oci_all8_head(payload)
    if len(payload) <= length_at:
        raise InterfaceError('not an OCI OALL8 execute')
    sql_off = length_at + 1
    # The options word carries the thin form's bits: sqlplus's SET AUTOCOMMIT ON
    # sets the commit bit and sends no COMMIT of its own, so the server commits
    # (sqlplus 10.2 and 23.26, #2011).
    options = head['options']
    marker = payload[length_at]  # ub1 length prefix (0xFE = chunked)
    # The SQL's length, measured for the client's character set: a client in
    # AL32UTF8, the database's own, sends the byte length; one in any other set
    # (UTF8, US7ASCII, ...) three times it, a conversion buffer's worth
    # (measured, sqlplus 23.26, #1427).
    declared = head['sql_length']
    if marker == TNS_LONG_LENGTH_INDICATOR:
        # Long SQL — chunked from the marker: 0xFE, then <ub1 len><chunk> repeated
        # until a zero length. The declared length is the byte length or three
        # times it, never less, so it only caps the read.
        raw_sql, chunks_len = _read_chunked_sql(payload[sql_off - 1 :], declared)
        sql_end = sql_off - 1 + chunks_len
    elif marker in (declared, declared // 3):
        # The byte length, as an AL32UTF8 client declares it, or a third of the
        # conversion-buffer length any other client declares (#1427).
        raw_sql = payload[sql_off : sql_off + marker]
        sql_end = sql_off + marker
    else:
        # The two lengths disagree only for a bound statement (the bind section
        # shifts things) — out of this increment's scope, a clean error.
        raise InterfaceError('OCI OALL8: SQL length mismatch (binds not supported)')
    # sqlplus null-terminates its *internal* queries (the length counts the NUL);
    # a user-typed statement has none. Strip trailing NULs so the backend sees
    # clean SQL either way.
    sql = raw_sql.rstrip(b'\x00').decode('utf-8')
    bind_count = head['bind_count']
    binds: list = []
    bind_meta: list[tuple[int, int]] = []
    bind_types: list[tuple[int, int, int, bytes]] = []
    if bind_count:
        # After a long statement too: sqlplus's SHOW ERRORS query is one (#2028).
        (binds, described) = _parse_oci_binds(
            payload, sql_end, bind_count, sql, head['al8i4_length']
        )
        bind_meta = [(t, size) for (t, size, _toid, _csfrm) in described]
        # An object / collection bind's type id rides here, as on the thin path,
        # so the backend can register a variable of its type (#1411).
        bind_types = [(t, csfrm, size, toid) for (t, size, toid, csfrm) in described]
    if bind_count and not bind_meta:
        # Binds the section could not be read for -- a type this path does not
        # parse, such as a collection. Run without them, the statement did
        # something else than asked, and the client got a status it could not
        # use (#1525). A clean error instead.
        raise InterfaceError(f'OCI OALL8: {bind_count} bind(s) of a form not read yet')
    return ExecRequest(
        sql=sql,
        cursor=cursor,
        bind_count=bind_count,
        fetch=0,
        binds=binds,
        bind_rows=[binds] if binds else [],
        bind_meta=bind_meta,
        bind_types=bind_types,
        autocommit=bool(options & _EXEC_OPTION_COMMIT),
    )


# The bind count sits at a fixed ub4 in the OCI OALL8 header, at whichever offset
# the preamble width puts it (:class:`_OciAll8Form`). After the SQL come an
# option array, one OAC type-descriptor per bind (each led by
# ``01 <TNS type> 03 00 00``), and an RXD row (``0x07`` + one DALC value per
# bind) — the same value framing the thin form uses (#265, #347). That bind
# section is read by scanning from the end of the SQL, so it needs no offset of
# its own and is the same in both widths.


# A placeholder whose name came earlier in the statement (`select :n, :n`): a
# descriptor of its own, flag 0x80 and size 0, but no value in the RXD row --
# it takes its name's first value (#2034). Captured from sqlplus 23.26.
_OCI_BIND_REPEAT_FLAG = 0x80
_OCI_BIND_REPEAT = -1  # a repeat's place in the descriptor list
# An object / collection IN value carrying nothing -- sqlplus's GET_LINES lines,
# a pure OUT: the type's REF, then these 15 bytes.
_OCI_ADT_EMPTY_TAIL = b'\x01' + bytes(12) + b'\x01\x00'
# ...which a pre-12c sqlplus (10.2, 11.2) writes with two more zeros (#1826).
_OCI_ADT_EMPTY_TAILS = (_OCI_ADT_EMPTY_TAIL, b'\x01' + bytes(14) + b'\x01\x00')


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
        # A sqlplus REFCURSOR variable, `01 66 01 00 00` and a ub4 size of 1; its
        # value is a cursor id, zero for one the block is to open (#2014).
        TNS_TYPE_REFCURSOR,
        # A sqlplus CLOB / BLOB variable, `01 70 01 00 00 50 00 00 00` for a
        # CLOB; its value is a locator (#2015).
        TNS_TYPE_CLOB,
        TNS_TYPE_BLOB,
    }
)


def _oci_read_value(data: bytes) -> tuple[bytes | list, bytes]:
    """An IN value as sqlplus sends it to the Mirror (#2053). Past 252 bytes it
    is 0xFE and chunks with ub1 lengths, ending at a zero one: the Mirror does
    not advertise BIG_CHUNK_CLR, and sqlplus sends ub4-length chunks only to a
    server that does (#2042). Read with the thin decoder, whose chunk lengths
    are ub4 in the 12c band, a 300-character VARCHAR2 lost its start. Anything
    else is an ordinary value."""
    if data[:1] != bytes([TNS_LONG_LENGTH_INDICATOR]):
        return decode_dalc(data)
    out = bytearray()
    at = 1
    while at < len(data):
        size = data[at]
        at += 1
        if not size:
            return bytes(out), data[at:]
        out += data[at : at + size]
        at += size
    raise DataError('OCI value: chunks run past the message')


def _oci_read_lob_bind(data: bytes) -> tuple[bytes | None, bytes]:
    # A LOB bind's value (#2015): a ub4 LE length, then the locator, zero length
    # for a NULL. The locator is a ub1 length and its bytes, or 0xFE and chunks
    # ending at a zero one -- sqlplus 23.26's unset 4000-byte buffer. Those chunk
    # lengths are fixed-width, but which width does not follow the field
    # version: a ub4 LE to a live 18c (`fe a0 0f 00 00`), a ub1 to 11g and to a
    # Mirror at the same field version as that 18c (`fe ff`). The length in front
    # says how long the locator is, so the reading that adds up to it is the one.
    if len(data) < 4:
        raise DataError('OCI LOB bind: no length')
    length = int.from_bytes(data[:4], 'little')
    data = data[4:]
    if not length:
        return None, data
    if not data:
        raise DataError('OCI LOB bind: no locator')
    if data[0] != TNS_LONG_LENGTH_INDICATOR:
        return data[1 : 1 + data[0]], data[1 + data[0] :]
    for width in (4, 1):
        out = bytearray()
        at = 1
        size = -1
        while at + width <= len(data):
            size = int.from_bytes(data[at : at + width], 'little')
            at += width
            if not size or len(out) + size > length:
                break
            out += data[at : at + size]
            at += size
        if size == 0 and len(out) == length:
            return bytes(out), data[at:]
    raise DataError('OCI LOB bind: chunks do not add up to its length')


def _oci_bind_descriptors(
    tail: bytes, bind_count: int
) -> tuple[list[tuple[int, int, bytes, int]], int]:
    # Each bind's (tns_type, max_size, toid, csfrm), in order, read from its
    # descriptor (_OAC), and where the descriptors end. A repeated name's
    # descriptor is ``_OCI_BIND_REPEAT`` (#2034). Empty for a bind of a type
    # this path does not read, or descriptors that do not hold.
    given = {'oci_12c': _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1}
    meta: list[tuple[int, int, bytes, int]] = []
    rest = tail
    for _ in range(bind_count):
        try:
            (oac, rest) = _OAC_FROM_OCI(rest, given)
        except (IndexError, DataError, Truncated):
            return [], 0
        csfrm = oac['csfrm'] or _CSFRM_DB
        if oac['flags'] & _OCI_BIND_REPEAT_FLAG:
            meta.append((_OCI_BIND_REPEAT, 0, b'', csfrm))
        elif oac['data_type'] == TNS_TYPE_ADT:
            toid = bytes(oac.get('toid', b''))
            meta.append((TNS_TYPE_ADT, oac['max_length'], toid, csfrm))
        elif oac['data_type'] in _OCI_BIND_TYPES:
            meta.append((oac['data_type'], oac['max_length'], b'', csfrm))
        else:
            return [], 0
    return meta, len(tail) - len(rest)


def _oci_adt_in_value(rest: bytes) -> bytes:
    # An object / collection IN value: its REF, then -- for one carrying
    # nothing, the only form seen -- the 15-byte empty tail. Anything else is not
    # read yet, and raising lets the statement be refused rather than run on a
    # guess (#1525).
    (_ref, after) = _kod_item(rest, 0)
    for tail in _OCI_ADT_EMPTY_TAILS:
        if rest[after : after + len(tail)] == tail:
            return rest[after + len(tail) :]
    raise DataError('an object bind value of a form not read yet')


def _oci_bind_rides_last(meta: tuple[int, int, bytes, int]) -> bool:
    # A char or RAW bind whose buffer is wider than 4000 bytes goes as a LONG
    # one, behind the others in the row.
    return meta[0] in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_RAW) and meta[1] > 4000


def _oci_bind_value(
    meta: tuple[int, int, bytes, int], rest: bytes
) -> tuple[object, bytes]:
    # One bind's value from the RXD row, and what follows it.
    (data_type, _size, _toid, csfrm) = meta
    # An OUT bind (sqlplus `VARIABLE` / `EXEC :v := …`) has no input value:
    # direction is not on the wire, so sqlplus sends the 2-byte placeholder
    # `<escape> 01` in the value's slot (the escape char is the wire's
    # absent-value sentinel). Decode it as None so the OUT bind is not fed a
    # garbage input (its real value comes back from the block); an ordinary IN
    # value is a normal DALC.
    if len(rest) >= 2 and rest[0] == TNS_ESCAPE_CHAR:
        return None, rest[2:]
    if data_type == TNS_TYPE_ADT:
        return None, _oci_adt_in_value(rest)
    if data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
        # A ub4 length, then the locator as a DALC: one the Mirror handed out,
        # or sqlplus's own unset 4000-byte buffer while the variable holds no
        # value (#2015). The session tells which.
        locator, rest = _oci_read_lob_bind(rest)
        if locator is None:
            return None, rest
        return TempLobRef(locator=locator, is_blob=data_type == TNS_TYPE_BLOB), rest
    raw, rest = _oci_read_value(rest)
    if data_type == TNS_TYPE_REFCURSOR:
        # A ub4 LE cursor id, zero when the block opens the cursor: then it is
        # an OUT bind like any other (#2014).
        return int.from_bytes(raw or b'', 'little') or None, rest
    if data_type == TNS_TYPE_NUMBER and isinstance(raw, bytes):
        # A pre-12c sqlplus sends an IN OUT NUMBER as its whole 22-byte buffer,
        # the number then zeros (#1826). No NUMBER ends in a zero byte -- its
        # digits are 1 to 100 and a negative ends in 0x66 -- so the padding is
        # cut.
        raw = raw.rstrip(b'\x00') or raw
    # The descriptor's form says which binds are national (UTF-16).
    return _decode_bind_value(data_type, csfrm, raw), rest


def _parse_oci_binds(
    payload: bytes, sql_end: int, bind_count: int, sql: str, al8i4_length: int
) -> tuple[list, list[tuple[int, int, bytes, int]]]:
    # Read the bind values AND their (tns_type, max_size) metadata from the OCI
    # bind section: behind the SQL, the al8i4 array (ub4s), one descriptor per
    # bind (_OAC), then the RXD row. A descriptor's max length is the bind's max
    # buffer size (NUMBER 22, VARCHAR2(20) 60, ...), which a PL/SQL OUT bind
    # needs so its return buffer is sized correctly (#483). Returns ``(values,
    # bind_meta)`` -- bind_meta is the per-bind (type, max_size, toid, csfrm)
    # list the OUT-bind path wraps as BindVars. A bind whose buffer is wider
    # than 4000 bytes rides last in the row, as thin's LONG-class ones do: sqlplus
    # 11.2 and 23.26 binding a VARCHAR2(4000) beside five others sent its value
    # after theirs, where it was read first and every value came out wrong.
    tail = payload[sql_end + 4 * al8i4_length :]
    (meta, row_at) = _oci_bind_descriptors(tail, bind_count)
    if len(meta) != bind_count:
        return [], []
    # A repeated name has a descriptor but no value; it takes its name's first
    # occurrence, found by the statement's placeholders in order (#2034).
    first: list[int] = list(range(bind_count))
    if any(t == _OCI_BIND_REPEAT for t, _s, _o, _c in meta):
        names = bind_placeholders(sql)
        if len(names) != bind_count:
            return [], []
        for i, name in enumerate(names):
            first[i] = names.index(name)
            if (meta[i][0] == _OCI_BIND_REPEAT) != (first[i] != i):
                return [], []
        meta = [meta[j] for j in first]
    carriers = [i for i in range(bind_count) if first[i] == i]
    wide = [i for i in carriers if _oci_bind_rides_last(meta[i])]
    order = [i for i in carriers if i not in wide] + wide
    # The RXD row, right behind the descriptors.
    if tail[row_at : row_at + 1] != bytes([TTI_RXD]):
        return [], []
    rest = tail[row_at + 1 :]
    read: dict[int, object] = {}
    try:
        for at in order:
            (read[at], rest) = _oci_bind_value(meta[at], rest)
    except (IndexError, DataError):
        return [], []
    return [read[first[i]] for i in range(bind_count)], meta


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


# From the 12c band each column is 8 bytes longer ahead of its name: 4 zero
# bytes ahead of the continuation flags (so the char-semantics flag moves from 15
# to 19) and 4 more ahead of the charset (30 to 38), measured against a live 18c
# for NUMBER, DATE, VARCHAR2, NCHAR and NVARCHAR2 columns (#1282; the
# oci_12c slots of _DCB_COLUMN). Two values change too: the first column's
# leading byte, and the oaccolid slot behind max_size, which 18c sets on a
# character column and 11g leaves zero; its meaning is unpinned, carried from
# the capture.
_OCI_DCB_FIRST_COL_11G = 0x51
_OCI_DCB_FIRST_COL_12C = 0x5C
_OCI_DCB_CHAR_12C_VALUE = 0x3FFE


# SYS.XMLTYPE as an OCI client is told it (#2050): a live 11g and 18c describe
# the column as type 58, an opaque type, where a thin client is told 109, with a
# data length of 2000 and the type's id, schema and name. The id is the same in
# every database.
_OCI_XMLTYPE_OID = bytes(13) + b'\x02\x01\x00'
_OCI_XMLTYPE_LENGTH = 2000
_OCI_XMLTYPE_VERSION = 1


def oci_is_xmltype(col: ColumnMeta) -> bool:
    return (
        col.data_type == TNS_TYPE_ADT
        and col.type_schema == b'SYS'
        and col.type_name == b'XMLTYPE'
    )


def _encode_dcb_column_oci(col: ColumnMeta, position: int, first: bool) -> bytes:
    # A describe column as sqlplus reads it (_DCB_COLUMN). SYS.XMLTYPE is the
    # one typed column (#2050): an opaque type, with the type's id, version,
    # schema and name.
    del position  # OCI's column carries none
    field_version = _ENCODE_FIELD_VERSION.get()
    wide = field_version >= FIELD_VERSION_12_1
    xmltype = oci_is_xmltype(col)
    is_char = col.data_type in _OCI_CHAR_TYPES
    marker = 0
    if first:
        marker = _OCI_DCB_FIRST_COL_12C if wide else _OCI_DCB_FIRST_COL_11G
    # A LONG / LONG RAW / LOB carries no fixed max size -- the value is a locator
    # or an inline stream, unbounded -- so a live 11g describe leaves it zero, as
    # it does the data length. Only fixed-width columns fill it (#405, #407).
    sized = col.data_type not in _OCI_UNSIZED_TYPES | _OCI_FIXED_WIDTH.keys()
    oid = _OCI_XMLTYPE_OID if xmltype else b''
    return _DCB_COLUMN_OCI(
        {
            'marker': marker,
            'lead': 0x00 if xmltype else 0x01,
            'data_type': TNS_TYPE_OPAQUE if xmltype else col.data_type,
            'flags': _OCI_DCB_CHAR_FLAG if is_char else 0,
            'precision': col.precision & 0xFF,
            'scale': col.scale,  # a signed byte (-127 for a NUMBER literal)
            # A backend that cannot size the column (the PEP 249 tuple reports
            # none for an interval or a ROWID) gets the length a live server
            # describes it with, as on the thin path (#2017).
            'buffer_size': _OCI_XMLTYPE_LENGTH
            if xmltype
            else _oci_describe_length(col),
            'max_array': 0,
            'oci_12c': wide,
            # Character-length semantics (#1282): sqlplus sizes an NCHAR or
            # NVARCHAR2 column by its character max size.
            'cont_flags': _OCI_DCB_CHAR_SEMANTICS_FLAG << 8
            if is_char and col.csfrm == _CSFRM_NCHAR
            else 0,
            'toid_length': len(oid),
            'toid': oid,
            'version': _OCI_XMLTYPE_VERSION if xmltype else 0,
            'oci_plain': not xmltype,
            'charset': int(col.charset) if is_char else 0,
            'csfrm': col.csfrm if is_char else 0,
            'max_size': col.max_size if sized and not xmltype else 0,
            # 18c sets it on a character column, 11g leaves it zero; its
            # meaning is unpinned, carried from the capture.
            'has_oaccolid': not xmltype,
            'oaccolid': _OCI_DCB_CHAR_12C_VALUE if wide and is_char else 0,
            'null_ok': col.null_ok,
            'v7_name_length': len(col.name),
            'name_length': len(col.name),
            'name': col.name,
            'type_schema_length': len(col.type_schema) if xmltype else 0,
            'type_schema': col.type_schema,
            'type_name_length': len(col.type_name) if xmltype else 0,
            'type_name': col.type_name,
            'has_uds': field_version >= FIELD_VERSION_11_2,
            'uds_flags': 0,
            'reserved': 0,
        }
    )


def encode_describe_oci(columns: list[ColumnMeta]) -> bytes:
    """Build the sqlplus / thick-OCI (deadbeef dialect) describe block (#265).

    The OCI counterpart of :func:`encode_describe`. Returns the TTC payload from
    the TTI_DCB token: a zeroed cursor-uuid preamble, the max-row-size and column
    count, one fixed-shape block per column, then a zeroed opaque trailer.
    """
    out = bytearray([TTI_DCB])
    # The preamble's length is a ub4, but a ub1 to sqlplus 10.2: 11g sends it
    # `10 17` and then the 23 bytes, where 11.2 gets `10 17 00 00 00` (#1764).
    if _ENCODE_FIELD_VERSION.get() < FIELD_VERSION_11_2:
        out += bytes([_OCI_DCB_PREAMBLE_LEN])
    else:
        out += _oci_ub4(_OCI_DCB_PREAMBLE_LEN)
    out += bytes(_OCI_DCB_PREAMBLE_LEN)
    return bytes(out) + _oci_describe_body(columns)


# The bytes sqlplus's row buffer needs for a column the backend gives no length:
# what a live 18c's max row size counts for each, a single-column SELECT apiece
# (#2017). Its describe gives each a length of 1, which would undersize the
# buffer, and a zero crashes sqlplus.
_OCI_ROW_BUFFER_LENGTH = {
    TNS_TYPE_INTERVALDS: 11,
    TNS_TYPE_INTERVALYM: 5,
    TNS_TYPE_RID: 16,
}


# BINARY_FLOAT and BINARY_DOUBLE are fixed-width: a live 18c describes each with
# length 1 and no max size, and counts its 4 or 8 bytes toward the max row size,
# whatever the backend says. A passthrough's PEP 249 tuple gives them their
# display size, 127, and sqlplus refused that column with ORA-03115 (#2018).
# TIMESTAMP WITH TIME ZONE likewise: length 1, 13 bytes (#2018).
_OCI_FIXED_WIDTH = {TNS_TYPE_BFLOAT: 4, TNS_TYPE_BDOUBLE: 8, TNS_TYPE_TIMESTAMPTZ: 13}


def _oci_describe_length(col: ColumnMeta) -> int:
    if col.data_type in _OCI_FIXED_WIDTH:
        return _DESCRIBE_WIRE_LENGTH[col.data_type]
    return describe_wire_length(col)


def _oci_row_buffer_length(col: ColumnMeta) -> int:
    if col.data_type in _OCI_FIXED_WIDTH:
        return _OCI_FIXED_WIDTH[col.data_type]
    if col.data_length:
        return col.data_length
    return _OCI_ROW_BUFFER_LENGTH.get(col.data_type, describe_wire_length(col))


def _oci_describe_body(columns: list[ColumnMeta]) -> bytes:
    # The describe from the max row size on: what a query's DCB carries after its
    # preamble, and a REF CURSOR's OUT value inline (#2014).
    out = bytearray()
    # Max row size: the thick/OCI client allocates a row buffer of this many
    # bytes, so it must cover the widest row — a zero here overflows and crashes
    # sqlplus (unlike the thin client, which skips the field). A LONG / LONG RAW /
    # LOB is a locator or an inline stream, unbounded, so it contributes nothing to
    # the fixed row buffer (its data_length is 0 anyway); it is excluded to match a
    # live 11g describe, which reports max-row-size 0 for such a result (#405, #407).
    out += _oci_ub4(
        sum(
            _oci_row_buffer_length(c)
            for c in columns
            if c.data_type not in _OCI_UNSIZED_TYPES and not oci_is_xmltype(c)
        )
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
_OCI_DCB_DATE_LEN = 7  # describe-time DALC: length is load-bearing, value is not


# The trailer's query-key length is an 11.2 field: 11g sends sqlplus 10.2
# `02000000 02000000 06...` with nothing between (#1764).


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
# The describe timestamp the DESCRIBE reply reports (the moment the dictionary row
# was analyzed). A real 7-byte Oracle DATE, GENERATED per reply from the current
# time (`_oci_desc_timestamp`): sqlplus does not render it but hangs if it is
# zeroed, so it must be a valid date — and there is no reason to freeze the
# capture's, so the Mirror reports "now", the truthful analyze time. It appears at
# several sites — the header (three times) and each non-last column block — each
# time behind a `27 <field-id>` tag as a describe-time DALC (`ub4 len 7 | ub1 len 7
# | date`); one generated value is threaded through them all per reply. The
# surrounding object / version numbers stay opaque, carried verbatim (§39.2).
def _oci_desc_timestamp() -> bytes:
    """The current time as the 7-byte Oracle DATE the DESCRIBE reply carries."""
    return _encode_temporal(datetime.datetime.now(), TNS_TYPE_DATE)


# The dictionary identity of the described object, from the live capture: the
# object id and the data-object (segment) id it reports, each a ub4 LE. They are
# real DBA_OBJECTS identities the Mirror does not have, so they are carried from
# the capture (a synthetic id would need live validation, like the DML rowid);
# naming them turns the header's recurring `be010000` / `44c50100` runs into
# "object id" / "data-object id" rather than opaque bytes (§39.2).
_OCI_DESC_OBJECT_ID = 446  # be 01 00 00
_OCI_DESC_DATA_OBJECT_ID = 116036  # 44 c5 01 00


# A DESCRIBE name (schema, table or column): a ub4 character length, a ub1 byte
# length, then the bytes.
def _oci_desc_name(field: str) -> wire_schema.Schema:
    return (
        ('n4', f'{field}_chars'),
        ('u8', f'{field}_length'),
        ('bytes', field, f'{field}_length'),
    )


# The describe-time entry: a `27 09` tag and the date as a describe-time DALC
# (`ub4 len 7 | ub1 len 7 | date`), then `02`.
_OCI_DESC_TS_ENTRY_PRE = bytes.fromhex('0100000027090700000007')


# The DESCRIBE reply's header: its fixed framing around three describe-time
# entries (`27 01` / `27 0b` / `27 00`), the schema and table names, the object
# numbers above and the column count plus one; the runs between are opaque
# object-metadata framing (differential-mapped). The 12c band inserts 8 zero
# bytes after the third entry's `02` (#1282).
_OCI_DESC_HEAD: wire_schema.Schema = (
    ('const', bytes.fromhex('0801000100000027010700000007')),
    ('bytes', 'time', 7),
    ('pad', 4),
    *_oci_desc_name('schema'),
    *_oci_desc_name('table'),
    ('n4', 'data_object_id'),
    ('const', bytes.fromhex('0000000000000000000100000072')),
    ('n4', 'data_object_id'),
    ('const', bytes.fromhex('0000000001000000')),
    ('n4', 'object_id'),
    ('const', bytes.fromhex('00270b0700000007')),
    ('bytes', 'time', 7),
    ('pad', 21),
    ('const', bytes.fromhex('010000000b01')),
    ('u8', 'column_count_plus_one'),
    ('pad', 3),
    ('n4', 'object_id'),
    ('const', bytes.fromhex('0027000700000007')),
    ('bytes', 'time', 7),
    ('const', b'\x02'),
    ('when', 'oci_12c', (('pad', 8),)),
    ('pad', 96),
    ('const', _OCI_DESC_TS_ENTRY_PRE),
    ('bytes', 'time', 7),
    ('const', b'\x02'),
    ('pad', 48),
    ('const', b'\x01'),
    ('pad', 2),
)
_OCI_DESC_HEAD_OCI = wire_schema.compile_encoder(_OCI_DESC_HEAD, _OCI)
_OCI_DESC_HEAD_FROM_OCI = wire_schema.compile_decoder(_OCI_DESC_HEAD, _OCI)


# One column's block: its length, type and name, then precision, scale,
# nullability, charset and form, a mark (0x24, 0x04 from 12c), and on every
# column but the last a describe-time entry and a `1` continuation flag 3
# bytes before its end. sqlplus hangs on a multi-column reply whose non-last
# blocks omit the entry. The lead byte reads 0x5c, 0x7a from 12c. sqlplus
# 10.2's block is a byte shorter, without the zero behind the mark, where the
# 12c form grows 20 zero bytes (#1282, #1764).
_OCI_DESC_BLOCK: wire_schema.Schema = (
    ('pad', 1),
    ('u8', 'lead'),
    ('u8', 'size'),  # the data length, a single byte
    ('pad', 1),
    ('u8', 'data_type'),
    ('pad', 1),
    *_oci_desc_name('name'),
    ('u8', 'precision'),
    ('u8', 'scale'),  # a NUMBER's scale, a char column's length
    ('u8', 'nullable'),
    ('pad', 12),
    ('n2', 'charset'),
    ('u8', 'csfrm'),
    ('pad', 16),
    ('u8', 'mark'),
    ('when', 'has_mark_zero', (('pad', 1),)),
    ('when', 'oci_12c', (('pad', 20),)),
    ('pad', 45),
    ('when', 'more', (('const', _OCI_DESC_TS_ENTRY_PRE), ('bytes', 'time', 7))),
    ('when', 'more', (('const', b'\x02'),)),
    ('when', 'last', (('pad', 19),)),
    ('pad', 48),
    ('u8', 'more'),
    ('pad', 2),
)
_OCI_DESC_BLOCK_OCI = wire_schema.compile_encoder(_OCI_DESC_BLOCK, _OCI)
_OCI_DESC_BLOCK_FROM_OCI = wire_schema.compile_decoder(_OCI_DESC_BLOCK, _OCI)

# The DESCRIBE reply's 257-byte trailer, decoded: a 121-byte describe-specific
# frame, then a standard OCI OER return status (the same envelope every other
# reply ends with, built by encode_oci_oer — its offset-56 `36 01` and offset-72
# `20 f6 31 0a` are the fixed 11g OER constants, §36). The frame is zero but for
# the column count, a type-dependent opaque byte and three carried values.
# sqlplus 10.2's is a byte shorter (#1764). From 12.1 it is 137 bytes: 8 zero
# bytes in front and 8 at the end, byte 4 reading 0x05 instead of 0x04 and the
# type-dependent bytes (8, 9, 11) left zero, as 18c leaves them (#1282).
_OCI_DESC_TRAILER_FRAME: wire_schema.Schema = (
    ('when', 'oci_12c', (('pad', 8),)),
    ('pad', 2),
    ('u8', 'column_count'),
    ('pad', 1),
    ('u8', 'unpinned_4'),
    ('pad', 3),
    ('u8', 'opaque'),
    ('u8', 'unpinned_9'),
    ('pad', 1),
    ('u8', 'unpinned_11'),
    ('pad', 4),
    ('const', b'\x09'),
    ('pad', 103),
    ('when', 'has_last_zero', (('pad', 1),)),
    ('when', 'oci_12c', (('pad', 8),)),
)
_OCI_DESC_TRAILER_FRAME_OCI = wire_schema.compile_encoder(_OCI_DESC_TRAILER_FRAME, _OCI)
# The OER's carried fields. The status byte is 0x05 — the value the execute
# path names OCI_OER_STATUS_ERROR — yet this is a *successful* DESCRIBE with
# error code 0, so it is carried as the describe's terminal status rather than
# asserted to be an error; its meaning on this path is unpinned. The sequence is
# the diagnostic counter the client discards (§36.1), left at its captured value
# rather than threaded through the session counter.
_OCI_DESC_STATUS = 0x05
_OCI_DESC_OER_SEQUENCE = 19
_OCI_DESC_OER_ROW_FIELD = 1  # offset 8, the dual row-kind / rowcount slot: one
_OCI_DESC_OER_CATEGORY = 0


def _oci_desc_trailer_frame(column_count: int, opaque: int) -> bytes:
    field_version = _ENCODE_FIELD_VERSION.get()
    wide = field_version >= FIELD_VERSION_12_1
    return _OCI_DESC_TRAILER_FRAME_OCI(
        {
            'oci_12c': wide,
            'column_count': column_count & 0xFF,
            'unpinned_4': _OCI_DESC_12C_TR_MARK if wide else 0x04,
            'opaque': 0 if wide else opaque,
            'unpinned_9': 0 if wide else 0x14,
            'unpinned_11': 0 if wide else 0x01,
            'has_last_zero': field_version >= FIELD_VERSION_11_2,
        }
    )


# The DESCRIBE reply at the 12c band (#1282), measured against a live 18c's
# describe of a NUMBER / VARCHAR2 / DATE table: the 11g reply with zero runs
# inserted in the header, each column block and the trailer frame, and three
# carried values changed (the schemas above say where). The OER behind the
# frame widens like every other (_OCI_OER). None of the changed values is
# decoded; they are carried from the capture.
_OCI_DESC_12C_TR_MARK = 0x05


def _oci_desc_trailer(column_count: int, opaque: int) -> bytes:
    # Built per reply, not once at import: the OER's offset-49 field carries the
    # sequence of the call being answered, which is only known per message
    # (#884). Freezing it at import would pin every DESCRIBE reply to whatever
    # the context held when the module loaded.
    return _oci_desc_trailer_frame(column_count, opaque) + encode_oci_oer(
        _OCI_DESC_STATUS,
        sequence=_OCI_DESC_OER_SEQUENCE,
        row_kind=_OCI_DESC_OER_ROW_FIELD,
        command_type=0,
        category=_OCI_DESC_OER_CATEGORY,
    )


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


def _oci_desc_block(col: ColumnMeta, *, last: bool, timestamp: bytes) -> bytes:
    field_version = _ENCODE_FIELD_VERSION.get()
    wide = field_version >= FIELD_VERSION_12_1
    is_char = col.data_type in _OCI_DESC_CHAR_TYPES
    national = is_char and col.csfrm == _CSFRM_NCHAR
    size = _OCI_DESC_WIRE_SIZE.get(col.data_type, col.max_size)
    precision, scale = _oci_desc_precision_scale(col)
    if national:
        # NCHAR / NVARCHAR2: the size field is the UTF-16 byte length, and the
        # national flag in the precision makes sqlplus halve it to the declared
        # character count; the character length itself goes in the scale.
        (size, precision, scale) = (col.data_length, 0x80, col.max_size)
    return _OCI_DESC_BLOCK_OCI(
        {
            'lead': 0x7A if wide else 0x5C,
            'size': size & 0xFF,
            'data_type': col.data_type,
            'name_chars': len(col.name),
            'name_length': len(col.name),
            'name': col.name,
            'precision': precision & 0xFF,
            'scale': scale & 0xFF,
            'nullable': 1 if col.null_ok else 0,
            'charset': col.charset if is_char else 0,
            'csfrm': col.csfrm if is_char else 0,
            'mark': 0x04 if wide else 0x24,
            'has_mark_zero': field_version >= FIELD_VERSION_11_2,
            'oci_12c': wide,
            'time': timestamp,
            'more': 0 if last else 1,
            'last': last,
        }
    )


def encode_describe_reply_oci(
    columns: list[ColumnMeta],
    *,
    schema: bytes,
    table: bytes,
    timestamp: bytes | None = None,
) -> bytes:
    """Build the sqlplus / thick-OCI ``DESCRIBE <object>`` reply (TTI 0x77).

    One column block per :class:`ColumnMeta`, framed by the fixed header (schema +
    table names, column count) and trailer. Meaningful fields are computed, the describe timestamp is generated
    (the current time), and the opaque object-metadata framing is carried. The
    trailer's OER sequence is a diagnostic counter the client discards (§36), so it
    is left at its carried value rather than threaded."""
    # One generated describe timestamp threaded through the header and every
    # block; a caller may pin it (the byte-for-byte capture test does).
    if timestamp is None:
        timestamp = _oci_desc_timestamp()
    out = bytearray(
        _OCI_DESC_HEAD_OCI(
            {
                'time': timestamp,
                'schema_chars': len(schema),
                'schema_length': len(schema),
                'schema': schema,
                'table_chars': len(table),
                'table_length': len(table),
                'table': table,
                'data_object_id': _OCI_DESC_DATA_OBJECT_ID,
                'object_id': _OCI_DESC_OBJECT_ID,
                'column_count_plus_one': (len(columns) + 1) & 0xFF,
                'oci_12c': _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1,
            }
        )
    )
    for index, col in enumerate(columns):
        out += _oci_desc_block(col, last=index == len(columns) - 1, timestamp=timestamp)
    opaque = (
        _OCI_DESC_TR_OPAQUE_BY_TYPE.get(columns[0].data_type, _OCI_DESC_TR_OPAQUE_MULTI)
        if len(columns) == 1
        else _OCI_DESC_TR_OPAQUE_MULTI
    )
    out += _oci_desc_trailer(len(columns), opaque)
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


def _oci_dcb_tail(numcols: int) -> bytes:
    # The describe's trailer (_DESCRIBE_TRAILER), then the row header the
    # inline row follows (_OCI_RXH), carrying the column count.
    return _describe_trailer(oci=True) + _oci_rxh_of(0x22, 0, numcols, 0)


# The execute reply for a LOB SELECT is a describe with NO row inline — sqlplus
# sets up its LOB define from it and fetches the locator rows separately. Instead
# of the 83-byte inline-row DCB tail it carries a 33-byte describe-timestamp tail
# (no DCB marker): the same describe-time DALC head as _oci_dcb_tail (a ub4 char
# length of 7 + the byte-length 7, the timestamp value itself zeroed), all zero
# except the ub4 dcbmdbz the LOB describe carries. That ub4 is NOT
# instance-specific (a real reply zeroes the timestamp / SCN but not this), so it
# is a stable structural value; its exact meaning is unpinned, carried from the
# live 11g CLOB describe capture (#405).
_OCI_LOB_DESCRIBE_SIZE = 8168  # 0x1fe8, ub4 LE — carried ground truth


def _oci_lob_describe_tail() -> bytes:
    # The describe's trailer (_DESCRIBE_TRAILER) alone, its dcbmdbz set.
    return _describe_trailer(oci=True, mdbz=_OCI_LOB_DESCRIBE_SIZE)


_OCI_LOB_DESCRIBE_TAIL = _oci_lob_describe_tail()


# When the execute delivers fewer rows than the result holds, the OER's error
# position byte is non-zero -- the client reads it as "more rows, issue a fetch"
# (0 = the cursor is already drained). The exact value is not load-bearing
# beyond non-zero; 0x1e is what a live reply carries.
_OCI_MORE_ROWS_FLAG = 0x1E


def _oci_row_status(sequence: int, *, more: bool = False, rowcount: int = 0) -> bytes:
    # The status frame (offset 11 a required sentinel), then the rows OER, which
    # the 12c band widens (#1282).
    return _OCI_STATUS_FRAME_PREFIX + _oci_oer(
        {
            **_OCI_OER_ROWS,
            'sequence': sequence,
            'error_pos': _OCI_MORE_ROWS_FLAG if more else 0,
            'rowcount': rowcount,
        }
    )


# The row-header (TTI_RXH) that leads a fetch batch: a small fixed frame plus the
# query SCN (zeroable). Reduced to its non-zero structure from a live fetch reply
# (#265, #351).
def _oci_rxh() -> bytes:
    return _oci_rxh_of(0x02, 0, 0x02, 0x0F)


def encode_fetch_batch_oci(
    columns: list[ColumnMeta], rows: list[tuple], *, sequence: int, more: bool = False
) -> bytes:
    """A sqlplus / thick-OCI fetch reply: RXH + one RXD per row + a status.

    Used when the execute parked rows for follow-up fetches (#351). The last batch
    ends with the ORA-01403 terminator. A batch with rows still to come
    (``more``) ends with a plain success status instead, as a live 11g's does, so
    the client fetches again (#1284). ``sequence`` is the live per-session OER
    counter.
    """
    out = bytearray(_oci_rxh())
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_oci_value(v, col, i) for i, (v, col) in enumerate(zip(row, columns))
        )
    if more:
        out += encode_oci_oer(oci.OCI_OER_STATUS_SUCCESS, sequence=sequence)
    else:
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
            _encode_oci_value(v, col, i) for i, (v, col) in enumerate(zip(row, columns))
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
        _encode_oci_value(v, col, i) for i, (v, col) in enumerate(zip(row, columns))
    )
    status = encode_oci_oer(
        oci.OCI_OER_STATUS_SUCCESS,
        sequence=sequence,
        row_kind=oci.OCI_OER_ROW_KIND_LONG,
    )
    return bytes(out) + status


def _oci_error_text(text: bytes) -> bytes:
    """An OCI error OER's message, length-prefixed.

    A value as OCI frames one (_OciCodec.value, #2064): up to 252 bytes a
    one-byte length; a longer one follows a 0xFE marker in chunks of up to 255
    bytes, each with a one-byte length, and ends with a zero-length chunk -- as
    a live 11g sends it (sqlplus 23.26, a 333-byte RAISE_APPLICATION_ERROR
    message: ``fe ff <255 bytes> 4e <78 bytes> 00``). A one-byte length could
    not hold a longer message at all: encoding it raised, and the session died
    (#1520).

    A live 18c sent the same message as one chunk with ub4 LE lengths instead
    (``fe 4d 01 00 00 <333 bytes> 00 00 00 00``). That is not the field version:
    the Mirror speaks 18c's to sqlplus, and sqlplus hangs on that form from the
    Mirror while it reads this one. It follows BIG_CHUNK_CLR, which 18c
    advertises and the Mirror does not (#2042), so the Mirror sends the form
    its own sessions read.
    """
    return _OCI.value(text)


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
    return oer + _oci_error_text(text)


def encode_login_refusal_oci(
    ora_code: int, message: str, *, call_sequence: int
) -> bytes:
    """The OER a live server refuses a sqlplus / thick-OCI login with (#1290).

    It follows the break / reset marker exchange, in place of the reply to the
    refused call (the AUTH, or the OSESSKEY for an unknown user), and carries
    the ORA error and its text. It is the error OER without the statement fields:
    a success status byte, no category, error position or command type, and the
    refused call's own sequence where the envelope echoes one. The 12c band
    widens it like every OER. Measured against a live 11g and 18c for a wrong
    password.
    """
    token = _ENCODE_OCI_CALL_SEQ.set(call_sequence)
    try:
        # The one byte a login refusal leaves zero that the statement OERs
        # carry as 0x01 is offset 52 (§36.1).
        oer = encode_oci_oer(
            oci.OCI_OER_STATUS_SUCCESS,
            sequence=0,
            error_code=ora_code,
            command_type=0,
            category=0,
            unpinned_52=0,
        )
    finally:
        _ENCODE_OCI_CALL_SEQ.reset(token)
    text = f'{message}\n'.encode('utf-8')
    return oer + _oci_error_text(text)


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
            _encode_oci_value(v, col, i) for i, (v, col) in enumerate(zip(row, columns))
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
        # Built per reply: its width follows the session's field version.
        + _oci_lob_describe_tail()
        + _oci_lob_describe_status(sequence)
    )


def encode_status_oci(sequence: int) -> bytes:
    """OCI reply for a no-row statement (PL/SQL / DDL): success, nothing to fetch."""
    # A PL/SQL-block OER, category 1 = no rows; its frame is marked 1.
    return _oci_status_frame_prefix(mark=0x01) + _oci_oer(
        {
            **_OCI_OER_ROWS,
            'sequence': sequence,
            'command_type': oci.OCI_CMD_PLSQL,
            'category': 1,
        }
    )


# The sqlplus PASSWORD success reply (OCIPasswordChange complete, #21): an empty
# RPA return-parameter envelope followed by an OER return-status token, from
# which sqlplus renders "Password changed". Its body is the statement OER
# (_OCI_OER) -- the same frame every OCI status carries, including the fixed
# 0x20f6310a instance marker -- with six fields of its own. All are fixed values
# carried from the capture; the names they have in a statement's OER do not hold
# for this reply (the status reads the ERROR marker even though the change
# succeeded; the row kind is not a LOB row's).
#
# Verified byte-identical across FOUR independent live 11g password changes in
# separate sessions: the whole reply is a constant. There is no per-session
# counter — the offset-5 value and its offset-49 echo, live sequence fields in
# the query-path OERs, are fixed here — so the Mirror emits it verbatim (§36.1).
_OCI_RPA_EMPTY = bytes([TTI_RPA, 0, 0])  # RPA return with zero parameters
_OCI_CHANGEPASSWORD_OER = {
    **_OCI_OER_STATEMENT,
    'status': 0x05,  # the ERROR marker, though the change succeeded
    'sequence': 0x13,  # a fixed value here, not a live sequence
    'row_kind': 0x01,  # its meaning here is unpinned (§36.1)
    'category': 0,
    'command_type': 0,
    'call_sequence': 0x16,  # a fixed value here
}


def encode_changepassword_status_oci() -> bytes:
    """The sqlplus / thick-OCI reply that completes an OCIPasswordChange (#21)."""
    return _OCI_RPA_EMPTY + _oci_oer(_OCI_CHANGEPASSWORD_OER)


# OCI DML execute-status reply (#348/#349). sqlplus renders the completion
# message ("N rows updated.") from two fields of its OER: the V$SQL **command
# type** and the affected-row **count**, which rides where other OERs put the
# row kind (_oci_dml_status_frame). Validated live — sqlplus prints the right
# verb and count for insert/update/delete. The frame is one live 11g INSERT
# reply with the capture-order session counters zeroed, since the Mirror has no
# such sequence.


# The Mirror's SQL-verb → V$SQL command-type mapping — response-generation policy
# over the shared oci.OCI_CMD_* vocabulary. sqlplus renders the completion message
# purely from the command type (docs/PROTOCOL.md §36).
_OCI_DML_CMD = {
    'INSERT': oci.OCI_CMD_INSERT,
    'UPDATE': oci.OCI_CMD_UPDATE,
    'DELETE': oci.OCI_CMD_DELETE,
}


# The words that may stand between a DDL verb and the object kind it names,
# which a V$SQLCOMMAND name leaves out: "CREATE OR REPLACE EDITIONABLE PROCEDURE"
# is a CREATE PROCEDURE, "CREATE UNIQUE INDEX" a CREATE INDEX, "DROP PUBLIC
# SYNONYM" a DROP SYNONYM (#2012).
_DDL_MODIFIERS = frozenset(
    {
        'OR',
        'REPLACE',
        'EDITIONABLE',
        'NONEDITIONABLE',
        'EDITIONING',
        'FORCE',
        'NOFORCE',
        'NO',
        'PUBLIC',
        'UNIQUE',
        'BITMAP',
        'MULTIVALUE',
        'GLOBAL',
        'PRIVATE',
        'TEMPORARY',
        'SHARED',
        'DUPLICATED',
        'AND',
        'RESOLVE',
        'COMPILE',
    }
)


# The verbs V$SQLCOMMAND lists under a name of their own.
_SQL_VERB_COMMAND_NAME = {
    'GRANT': 'GRANT OBJECT',
    'REVOKE': 'REVOKE OBJECT',
    'AUDIT': 'AUDIT OBJECT',
    'NOAUDIT': 'NOAUDIT OBJECT',
    'CALL': 'CALL METHOD',
}


# The longest V$SQLCOMMAND name, in words.
_SQL_COMMAND_MAX_WORDS = max(len(name.split()) for name in oci.SQL_COMMAND_TYPES)


# A bare DDL verb whose object is not one Oracle names falls back to the TABLE
# variant (#479).
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
    sqlplus turns this into the completion message ("Table created.", "Session
    altered.", "Procedure created.", …). The statement resolves by its longest
    leading phrase that V$SQLCOMMAND names, its modifiers skipped (#2012)."""
    words = re.split(r'[\s(;]+', sql.strip().upper(), maxsplit=12)
    words = [w for w in words if w]
    if not words:
        return None
    verb = words[0]
    if verb in _SQL_VERB_COMMAND_NAME and (
        len(words) < 3 or ' '.join(words[:3]) not in oci.SQL_COMMAND_TYPES
    ):
        return oci.SQL_COMMAND_TYPES[_SQL_VERB_COMMAND_NAME[verb]]
    rest = words[1:]
    while rest and rest[0] in _DDL_MODIFIERS:
        rest = rest[1:]
    phrase = [verb, *rest]
    for n in range(min(len(phrase), _SQL_COMMAND_MAX_WORDS), 0, -1):
        code = oci.SQL_COMMAND_TYPES.get(' '.join(phrase[:n]))
        if code is not None:
            return code
    if verb in _OCI_DDL_VERB_DEFAULT_OBJECT:
        return oci.SQL_COMMAND_TYPES[f'{verb} {_OCI_DDL_VERB_DEFAULT_OBJECT[verb]}']
    return None


def encode_dml_status_oci(keyword: str, rowcount: int, *, sequence: int) -> bytes:
    """OCI reply for a DML — success carrying the affected-row count so sqlplus
    prints ``N rows created/updated/deleted``. ``keyword`` (INSERT/UPDATE/DELETE)
    selects the V$SQL command type; MERGE and anything else fall back to INSERT.
    ``sequence`` is the live per-session OER counter."""
    return _oci_dml_status_frame(
        sequence, rowcount, _OCI_DML_CMD.get(keyword, oci.OCI_CMD_INSERT)
    )


# The OCI OER's warning flags (§36.1): `0x21` when a CREATE made a PL/SQL object
# that compiled with errors, `0` otherwise. The thin OER carries the same value in
# its last warn byte (§6.3a). Captured from sqlplus 23.26 against 11g and 18c, the
# same CREATE PROCEDURE compiled clean and broken: this byte is all that differs
# but for the counters.
_OCI_OER_WARN_COMPILATION = 0x21


# The NLS parameters an OCI SYNC piggyback reports, by the keyword number a
# live 18c gives each (#2020): one ALTER SESSION per parameter, the changed pair
# read off each reply. In the order it sends them, which matters: sqlplus
# applies them in turn, and a territory resets the formats it implies, so a
# date format sent before it is lost.
OCI_NLS_KEYWORDS = {
    'NLS_LANGUAGE': 16,
    'NLS_TERRITORY': 9,
    'NLS_CURRENCY': 0,
    'NLS_ISO_CURRENCY': 1,
    'NLS_NUMERIC_CHARACTERS': 2,
    'NLS_CHARACTERSET': 10,
    'NLS_CALENDAR': 12,
    'NLS_DATE_FORMAT': 7,
    'NLS_DATE_LANGUAGE': 8,
    'NLS_SORT': 11,
    'NLS_TIME_FORMAT': 57,
    'NLS_TIMESTAMP_FORMAT': 58,
    'NLS_TIME_TZ_FORMAT': 59,
    'NLS_TIMESTAMP_TZ_FORMAT': 60,
    'NLS_DUAL_CURRENCY': 52,
    'NLS_COMP': 50,
    'NLS_LENGTH_SEMANTICS': 61,
    'NLS_NCHAR_CONV_EXCP': 62,
}


# Where the session-state pairs sit in the DDL status frame below 11.2 (#2020).
_OCI_DDL_SESSION_STATE_OFF = 29


def _oci_session_pairs(pairs: list[tuple[int, str]], *, count_width: int) -> bytes:
    # The pairs as OCI writes them: a count, then each pair of the SYNC
    # piggyback's (_SYNC_PAIR) with its value as binary, and a ub4 of flags
    # last.
    items = _sync_pairs(pairs, 'binary')
    return (
        len(pairs).to_bytes(count_width, 'little')
        + b''.join([_SYNC_PAIR_OCI(item) for item in items])
        + bytes(4)
    )


def encode_sync_piggyback_oci(pairs: list[tuple[int, str]]) -> bytes:
    """The SYNC server piggyback in the OCI dialect (#2020): the thin form's
    fields, fixed-width, with each value in the pair's binary slot and its text
    slot empty (#2064) -- as a live 18c reports the session's NLS parameters
    after an ALTER SESSION SET NLS_..., by which sqlplus formats its DATE,
    TIMESTAMP and NUMBER columns."""
    return _SYNC_OCI(_sync_fields(pairs, 'binary'))


def encode_ddl_status_oci(
    command_type: int,
    *,
    sequence: int,
    compilation_warning: bool = False,
    session_pairs: list[tuple[int, str]] | None = None,
) -> bytes:
    """OCI reply for a DDL / no-row statement — success so sqlplus prints the
    matching message ("Table created.", "Index dropped.", "Table truncated.", …).
    ``command_type`` is the V$SQL command type (see :func:`ddl_command_type`);
    DDL affects no rows, so nothing but that field varies. ``sequence`` is the
    live per-session OER counter.

    ``compilation_warning`` says the statement created a PL/SQL object that
    compiled with errors; sqlplus then prints "Warning: Procedure created with
    compilation errors." and lets ``SHOW ERRORS`` look them up (#2013)."""
    oer = encode_oci_oer(
        oci.OCI_OER_STATUS_SUCCESS,
        sequence=sequence,
        command_type=command_type,
        # FIXME: DDL's category is 1 (query / PL-SQL leave 2); the field's
        # meaning is unknown -- carried from the capture.
        category=1,
        warn_flags=_OCI_OER_WARN_COMPILATION if compilation_warning else 0,
    )
    if not session_pairs:
        return _OCI_DDL_FRAME_PREFIX + bytes(oer)
    if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_11_2:
        # The session's NLS parameters, as a SYNC piggyback between the frame
        # and its OER, where a live 18c puts them (#2020).
        return (
            _OCI_DDL_FRAME_PREFIX
            + encode_sync_piggyback_oci(session_pairs)
            + bytes(oer)
        )
    # Below 11.2 they ride in the frame itself: its last six bytes are a ub2
    # count of pairs and a ub4 of flags, the pairs between them. A live 11g to
    # sqlplus 10.2 (#2020).
    return (
        _OCI_DDL_FRAME_PREFIX[:_OCI_DDL_SESSION_STATE_OFF]
        + _oci_session_pairs(session_pairs, count_width=2)
        + bytes(oer)
    )


_OCI_OUTBIND_DEFINE_MARKER = 0x10


_OCI_OUTBIND_RETCODE = b'\x00\x00'
_OCI_OUTBIND_NULL_RETCODE = b'\xff\xff'


# An object / collection OUT value in the OCI reply (PROTOCOL.md §40.4): the
# type's REF, `01` and zeros -- ten from a live 11g, eight from a live 18c -- the
# image's ub4 length, `01 00`, the image as a DALC, and no return code after it,
# unlike a scalar. sqlplus 23.26 reading DBMS_OUTPUT.GET_LINES's lines (#1411).
_OCI_OUTBIND_ADT_LEAD = b'\x01' + bytes(10)
_OCI_OUTBIND_ADT_LEAD_12C = b'\x01' + bytes(8)
# The marker before the values is each bind's DIRECTION, the masks the 9i bind
# prompt uses: 0x10 for a pure OUT, 0x30 for an IN OUT. GET_LINES answers `10 30`
# -- its lines are OUT, its count IN OUT -- and a lone OUT VARRAY `10`.
_OCI_OUTBIND_IN_OUT_MARKER = 0x30
_OCI_OUTBIND_ADT_IMAGE = b'\x01\x00'


def _oci_object_image(obj: 'DbObject') -> bytes:
    """An object's image as a live server sends it to an OCI client (§40.4).

    The pickle :func:`encode_object_image` writes, with two differences from
    sqlplus's captures (11g and 18c): the image length is one byte when it fits
    (``88 01 13 ...``) rather than always ``fe`` and four, and a collection's
    prefix segment carries its kind -- ``01 03`` for a VARRAY -- where that
    writes ``01 01``. python-oracledb reads either; these are what sqlplus was
    seen to get.
    """
    image = encode_object_image(obj)
    body = image[7:] if image[2] == TNS_LONG_LENGTH_INDICATOR else image[3:]
    typ = obj._dbtype
    if typ is not None and typ.is_collection and body[:2] == b'\x01\x01':
        body = bytes([1, typ.collection_type]) + body[2:]
    if 3 + len(body) <= _OBJ_MAX_SHORT_LEN:
        return bytes([image[0], image[1], 3 + len(body)]) + body
    return (
        bytes([image[0], image[1], TNS_LONG_LENGTH_INDICATOR])
        + (7 + len(body)).to_bytes(4, 'big')
        + body
    )


def _oci_out_object_value(value: object, toid: bytes) -> bytes:
    from seerdb.common.dbobject import DbObject

    if isinstance(value, DbObject):
        image = _oci_object_image(value)
    else:
        image = getattr(value, 'image', b'') or b''
    return _oci_object_frame(toid, image)


def _oci_object_frame(toid: bytes, image: bytes | None) -> bytes:
    # An object value as OCI frames it, an OUT bind's and a row cell's alike
    # (_OBJECT_FRAME). A NULL cell stops after the flags, its length 0 (#2050).
    return _OBJECT_FRAME_OCI(
        {
            'type_ref': _kod_item_bytes(_kod_ref(toid, system=False)),
            'lead': _OCI_OUTBIND_ADT_LEAD_12C
            if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
            else _OCI_OUTBIND_ADT_LEAD,
            'image_length': len(image or b''),
            'flags': _OBJ_TOP_LEVEL,
            'has_image': image is not None,
            'image': image,
        }
    )


# The flag word of an XMLTYPE image a live 11g and 18c send to sqlplus: STRING
# (0x04) and a 0x10 bit no reader acts on (#2050).
_OCI_XML_FLAGS = 0x14


def _oci_xmltype_value(value: object) -> bytes:
    # An XMLTYPE row cell to sqlplus (#2050): the document's image in the object
    # frame, under SYS.XMLTYPE's id.
    from seerdb.common.dbobject import encode_xmltype

    image = None if value is None else encode_xmltype(value, Flags=_OCI_XML_FLAGS)
    return _oci_object_frame(_OCI_XMLTYPE_OID, image)


# A REF CURSOR OUT value in the OCI reply (#2014): a lead byte, the cursor's
# describe from the max row size on, the describe-time tail, the cursor id (ub4)
# and the return code every OUT value ends on. The lead byte is 0x4c from 11g and
# 18c to sqlplus 10.2, 11.2 and 23.26 alike, whatever the cursor's columns; a 10g
# server sends 0x3c, but it is not what the Mirror presents.
_OCI_REFCURSOR_LEAD = 0x4C
# The describe-time tail is the describe's trailer (_DESCRIBE_TRAILER). A live
# server fills in the date, and for a DATE column one of the flags; the Mirror
# zeroes them, as it does in a query's own describe tail.


def _oci_refcursor_out_value(bind: RefCursorOutBind) -> bytes:
    return _REFCURSOR_OUT_OCI(
        {
            'lead': _OCI_REFCURSOR_LEAD,
            'describe': _oci_describe_body(bind.columns) + _describe_trailer(oci=True),
            'cursor': bind.cursor_id,
            'return_code': 0,
        }
    )


def _oci_lob_out_value(bind: LobOutBind) -> bytes:
    # The value as a LOB column's cell goes out, which sqlplus already reads,
    # naming the variable; then the return code every OUT value ends on.
    if bind.value is None:
        # A NULL: no locator, and the return code -1 a live server sends for
        # one (18c, `exec :vc := null`).
        return encode_lob_locator_oci(None, bind.is_clob) + _OCI_OUTBIND_NULL_RETCODE
    cell = encode_lob_locator_oci(bind.value, bind.is_clob, lob_var=bind.lob_id)
    return cell + _OCI_OUTBIND_RETCODE


def oci_lob_var_id(locator: bytes, is_blob: bool) -> int | None:
    """The sqlplus LOB variable a bound locator names, or None for a locator the
    Mirror did not hand out -- sqlplus's unset buffer among them (#2015)."""
    cell = b'\x00' + locator[-(len(_oci_lob_locator(not is_blob))) :]
    try:
        (bound, _rest) = _OCI_LOB_LOCATOR_FROM_OCI(cell)
    except (IndexError, ValueError):
        return None
    # A minted locator but for what a cell sets per value -- the content size
    # and the variable id -- and two of the flag bytes, of which sqlplus 23.26
    # clears bit 0x08 of the third when it binds the locator back (`0c 88`
    # returns `0c 80`).
    minted = _oci_lob_locator_fields(not is_blob)
    for name in ('byte_size', 'lob_var', 'flags_2', 'flags_3'):
        minted[name] = bound[name]
    if _OCI_LOB_LOCATOR_OCI(minted) != cell:
        return None
    return bound['lob_var'] - 1 if bound['lob_var'] else None


def encode_out_bind_response_oci(
    values: list[object],
    *,
    sequence: int,
    types: list[tuple[int, bytes]] | None = None,
    inputs: list[bool] | None = None,
    forms: list[int] | None = None,
) -> bytes:
    """OCI reply returning a PL/SQL block's OUT bind values (``EXEC :v := ...``).

    ``values`` are the assigned OUT values in bind order; each is marshalled as a
    DALC (the same wire form as a fetched column) so the client reads it back into
    its bound buffer. The header/tail are computed structure, not blobs (#347).
    ``sequence`` is the live per-session OER counter for the status tail.
    ``types`` is each bind's (tns type, type id): an object or collection bind
    (109) goes back in its own framing, its value the backend's image.
    ``inputs`` says which binds came in with a value -- IN OUT, not pure OUT --
    which the marker before the values reports. A :class:`RefCursorOutBind`
    value is a cursor the block opened, its rows parked under its id (#2014).
    ``forms`` is each bind's character set form, as its descriptor declared it.
    """
    types = types or [(0, b'')] * len(values)
    inputs = inputs or [False] * len(values)
    header = _oci_outbind_header(len(values))
    define_markers = bytes(
        _OCI_OUTBIND_IN_OUT_MARKER if given else _OCI_OUTBIND_DEFINE_MARKER
        for given in inputs
    )
    rxd = _oci_outbind_rxd(values, types, forms)
    return header + define_markers + rxd + _oci_outbind_tail(sequence)


def _oci_outbind_rxd(
    values: list[object],
    types: list[tuple[int, bytes]],
    forms: list[int] | None = None,
) -> bytes:
    # The OUT values as an RXD row, each in its own framing.
    forms = forms or [_CSFRM_DB] * len(values)
    return bytes([TTI_RXD]) + b''.join(
        _oci_out_object_value(v, toid)
        if t == TNS_TYPE_ADT
        else _oci_refcursor_out_value(v)
        if isinstance(v, RefCursorOutBind)
        else _oci_lob_out_value(v)
        if isinstance(v, LobOutBind)
        else _oci_scalar_out_value(v, form) + _OCI_OUTBIND_RETCODE
        for v, (t, toid), form in zip(values, types, forms)
    )


def _oci_scalar_out_value(value: object, form: int = _CSFRM_DB) -> bytes:
    # A scalar OUT value: text or bytes past 252 in OCI's own chunks
    # (_oci_value_bytes), not the thin form's -- a 300-character VARCHAR2
    # variable went out as `fe 01 40 ...` and sqlplus never read it (#2053).
    # A national bind's text is UTF-16BE, as a live 18c sends `EXEC :n := 'kl'`
    # for an NCHAR(5) (`0a 00 6b 00 6c 00 20 ...`): sent in the database
    # character set, sqlplus could not map it and held `?` (#2239).
    if form == _CSFRM_NCHAR and isinstance(value, str):
        value = value.encode('utf-16-be')
    if isinstance(value, (str, bytes)):
        raw = value.encode('utf-8') if isinstance(value, str) else value
        if len(raw) > TNS_MAX_SHORT_LENGTH:
            return _oci_value_bytes(raw)
    return encode_value(value, 0)


def parse_exec_by_cursor_oci(payload: bytes, types: list[int]) -> tuple[int, list]:
    """The cursor id and the IN values of an OCI ``TTI_EXEC`` (#2041), one per
    entry of ``types`` -- the TNS types of the binds that came in with a value,
    in order. sqlplus fetches SERVEROUTPUT's lines this way, DBMS_OUTPUT.
    GET_LINES re-executed for each batch after the first: the thin execute by
    cursor's fields (_EXEC_BY_CURSOR) at fixed width, its option words zero,
    then an RXD row of the values."""
    if len(payload) < 20 or payload[1] != TTI_EXEC:
        raise InterfaceError('not an OCI TTI_EXEC')
    (fields, rest) = _EXEC_BY_CURSOR_FROM_OCI(payload)
    cursor = fields['cursor']
    if not types:
        return cursor, []
    if rest[:1] != bytes([TTI_RXD]):
        raise InterfaceError('OCI TTI_EXEC: no value row')
    rest = rest[1:]
    values: list = []
    for data_type in types:
        raw, rest = decode_dalc(rest)
        if data_type == TNS_TYPE_NUMBER and isinstance(raw, bytes):
            raw = raw.rstrip(b'\x00') or raw  # a pre-12c sqlplus pads (#1826)
        values.append(_decode_bind_value(data_type, _CSFRM_DB, raw))
    return cursor, values


def encode_exec_by_cursor_reply_oci(
    values: list[object],
    *,
    sequence: int,
    types: list[tuple[int, bytes]],
    forms: list[int] | None = None,
) -> bytes:
    """The reply to an OCI ``TTI_EXEC`` (#2041): the OUT values as the first
    execute's reply carries them, and its OER, with neither the OUT-bind header
    nor the status frame -- a live 18c, sqlplus 23.26 fetching SERVEROUTPUT's
    second and third batch."""
    return _oci_outbind_rxd(values, types, forms) + _oci_outbind_oer(sequence)


def encode_commit_status_oci(sequence: int) -> bytes:
    """OCI reply to a bare commit / rollback — a TTI_STA acknowledgement carrying
    the session's OER sequence, like every other reply on this path (§36.2)."""
    return _oci_tti_sta(_OCI_STA_CALL_STATUS_COMMIT, sequence)


def encode_ping_status_oci(sequence: int) -> bytes:
    """OCI reply to a TTI_PING (#2036): a TTI_STA with call status 1 and the
    session's OER sequence, as a live 18c answers sqlplus's ping after a
    cancel (`09 01 00 00 00 2f fa`)."""
    return _oci_tti_sta(_OCI_STA_CALL_STATUS_LOGOFF, sequence)


def encode_logoff_status_oci() -> bytes:
    """OCI reply acknowledging a client logoff (TTI_LOGOFF)."""
    return _OCI_LOGOFF_STATUS


def encode_logoff_status_thin() -> bytes:
    """The thin reply to ``TTI_LOGOFF``: a ``TTI_STA`` status token (OER call
    status 1, end-to-end sequence 0) followed by the per-response
    ``END_OF_RESPONSE`` marker. The integers are the thin protocol's
    variable-length form, not the OCI fixed-width LE the sqlplus ack uses.

    python-oracledb 26.0.0's ``LogoffMessage`` sends ``LOGOFF`` and then **reads
    a reply** before closing; earlier clients closed the socket without reading,
    so the Mirror could return silently. Against 26.0.0 the silent close is an
    unexpected EOF -- ``DPY-4011``. A ``STATUS`` token does not by itself end a
    response for a client that negotiated end-of-response, so the marker is
    required; byte-identical to a live 23ai's logoff reply (``09 01 01 00 1d``)."""
    return _LOGOFF_REPLY_THIN({'call_status': 1, 'sequence': 0})


def _decode_describe_oci(payload: bytes) -> list[dict]:
    # The describe encode_describe_oci writes, read back by its own schema
    # (_DCB_COLUMN) at the session's field version: the thin client cannot parse
    # it, so the tests prove the layout holds together this way, and sqlplus is
    # the wire conformance check (#265). sqlplus 10.2's preamble length is a
    # ub1, and its columns carry no uds flags (#1764).
    field_version = _DECODE_FIELD_VERSION.get()
    if payload[:1] != bytes([TTI_DCB]):
        raise DataError('not an OCI describe')
    if field_version < FIELD_VERSION_11_2:
        body = payload[2 + payload[1] :]
    else:
        body = payload[5 + int.from_bytes(payload[1:5], 'little') :]
    count = int.from_bytes(body[4:8], 'little')
    given = {
        'oci_12c': field_version >= FIELD_VERSION_12_1,
        'has_uds': field_version >= FIELD_VERSION_11_2,
    }
    rest = body[8:]
    columns = []
    for _ in range(count):
        (column, rest) = _DCB_COLUMN_FROM_OCI(rest, given)
        columns.append(column)
    return columns


# --- OCI LONG / LONG RAW row value (#407) ---
# A LONG (type 8, character) or LONG RAW (type 24, binary) column is streamed
# inline in the RXD — no LOB locator. The value is always the chunked form
# (0xFE marker, then a run of <ub1 len><bytes> chunks terminated by a zero-length
# chunk) even when it fits one chunk, followed by a trailing ub4 indicator (0),
# reproduced from a live 11g capture. A NULL LONG is a single 0x00. Character LONG
# content is UTF-8, LONG RAW is raw bytes.


def encode_long_value_oci(value: object) -> bytes:
    """The RXD value for a LONG / LONG RAW column (#407): the content streamed
    inline as 0xFE-chunked bytes + a zero trailing indicator (_LONG_CELL). NULL
    is an empty value (0x00) still followed by the trailing indicator. ``str``
    content is UTF-8 (LONG), ``bytes`` is raw (LONG RAW)."""
    return _LONG_CELL_OCI({'content': _long_content(value), 'actual_length': 0})


# The LOB's length (ub8) and chunk size (ub4) a LOB column value carries between
# its locator length and the locator (#1287); the chunk size is 11g's.
_OCI_LOB_CHUNK_SIZE = 8132
_OCI_LOB_ROW_METADATA_LEN = 12

# Whether the sqlplus / thick-OCI client offered CCAP_LOB_12C, and so reads a LOB
# column value with the LOB's length and chunk size in it. Set per session at
# login from the client's own capabilities (#1287).
_ENCODE_OCI_LOB_12C: contextvars.ContextVar[bool] = contextvars.ContextVar(
    'encode_oci_lob_12c', default=False
)


def _oci_lob_byte_size(value: object, is_clob: bool) -> int:
    # The LOB content byte count sqlplus reads from the locator: a CLOB is UTF-16
    # on the wire (2 bytes per character), a BLOB is its raw bytes.
    if is_clob:
        return len(str(value)) * 2
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    return len(str(value))


def encode_lob_locator_oci(
    value: object,
    is_clob: bool,
    national: bool = False,
    slot: int | None = None,
    lob_var: int | None = None,
) -> bytes:
    """The RXD value for a LOB column (#405): a minted opaque locator carrying the
    content **byte** size so sqlplus issues a TTI_LOBOPS READ.

    The locator's length leads, as a fixed ub4 like every OCI length. A client
    that offered CCAP_LOB_12C (sqlplus 23.26) then reads the LOB's length (a ub8,
    characters for a CLOB) and its chunk size (a ub4) before the locator, and
    cannot parse the row without them; one that did not (sqlplus 11.2) reads
    the locator straight away and cannot parse it with them. A live 11g answers
    each in its own form (#1287). NULL is that leading length at zero, all four
    bytes of it, and draws no read. ``slot`` names the LOB among its row's
    (#1430), and ``lob_var`` the sqlplus variable it is bound to (#2015)."""
    if value is None:
        return _LOB_CELL_OCI({'locator_length': 0})
    locator = _oci_lob_locator_cell(
        is_clob,
        national,
        slot=slot,
        lob_var=lob_var,
        byte_size=_oci_lob_byte_size(value, is_clob),
    )
    return _LOB_CELL_OCI(
        {
            'locator_length': len(locator),
            'has_metadata': _ENCODE_OCI_LOB_12C.get(),
            'size': _lob_value_size(value),
            'chunk_size': _OCI_LOB_CHUNK_SIZE,
            'locator': locator,
        }
    )


def encode_lob_read_response_oci(
    content: bytes,
    amount: int,
    total_bytes: int | None = None,
    *,
    is_clob: bool = True,
    national: bool = False,
    slot: int | None = None,
    sequence: int,
) -> bytes:
    """The TTI_LOBOPS READ reply (#405, _LOB_READ_REPLY): the LOB content slice
    (LOB_DATA), the echoed locator and the amount, then the status.
    ``content`` is the UTF-16BE (CLOB) / raw (BLOB) bytes read this call;
    ``amount`` is that read's count (characters for a CLOB, bytes for a BLOB);
    ``total_bytes`` is the whole LOB's byte size the echoed locator reports
    (defaults to this slice, for a single read-it-all call). ``is_clob`` selects
    the echoed-locator template (character vs binary, #406), and ``national`` its
    NCLOB form (#1369). ``sequence`` is the live per-session OER counter for the
    trailing status."""
    if total_bytes is None:
        total_bytes = len(content)
    # The echoed locator as the row cell carries it, its byte size consistent
    # with the content.
    locator = _oci_lob_locator_cell(is_clob, national, slot=slot, byte_size=total_bytes)
    return _LOB_READ_REPLY_OCI(
        {
            'lob_data': _oci_lob_data(content),
            'locator': bytes(locator),
            'amount': amount,
            'status': _oci_lob_read_status(sequence),
        }
    )


def oci_lob_contents(
    columns: list[ColumnMeta], rows: list[tuple], *, for_oci: bool = False
) -> list[tuple[bytes, bool]]:
    """The (wire-content, is_clob) of each non-NULL LOB cell, row-major (#405).
    See :func:`_lob_queue`."""
    return [
        (content, is_clob) for content, is_clob, _ in _lob_queue(columns, rows, for_oci)
    ]


def oci_lob_reads(
    columns: list[ColumnMeta], rows: list[tuple]
) -> list[tuple[bytes, bool, bool]]:
    """The OCI (sqlplus) read queue: each non-NULL LOB cell's (wire-content,
    is_clob, national), row-major. An NCLOB's read reply echoes a national-form
    locator, as its row did (#1369)."""
    return _lob_queue(columns, rows, True)


def _lob_queue(
    columns: list[ColumnMeta], rows: list[tuple], for_oci: bool
) -> list[tuple[bytes, bool, bool]]:
    """The (wire-content, is_clob, national) of each non-NULL LOB cell, row-major.

    The order matches the locators :func:`_encode_oci_value` emits, so the session
    reads this queue in sequence as sqlplus issues TTI_LOBOPS calls. CLOB content
    is UTF-16BE (``is_clob`` True — offsets/amounts count characters, 2 bytes
    each); BLOB content is raw bytes (counts bytes). The session slices this per
    the offset/amount each read requests.

    ``for_oci`` picks the caller's path. The OCI (sqlplus) path reads every
    LOB-class column over TTI_LOBOPS and passes True. The thin path does not: it
    carries a JSON or VECTOR image in the row itself (see
    :func:`encode_prefetched_lob_value_thin`), so those columns draw no read, and
    queueing them would shift every later LOB's position (#826/#887)."""
    return [
        cell
        for row in rows
        for value, col in zip(row, columns)
        if (cell := _lob_cell(value, col, for_oci)) is not None
    ]


def oci_lob_row_cells(
    columns: list[ColumnMeta], row: tuple
) -> dict[int, tuple[bytes, bool, bool]]:
    """One row's LOB contents by column index -- the slot its locator carries --
    for the OCI (sqlplus) path, which reads a row's LOBs interleaved (#1430)."""
    return {
        index: cell
        for index, (value, col) in enumerate(zip(row, columns))
        if (cell := _lob_cell(value, col, True)) is not None
    }


def _lob_cell(
    value: Any, col: ColumnMeta, for_oci: bool
) -> tuple[bytes, bool, bool] | None:
    # One cell's (wire-content, is_clob, national), or None when it draws no read.
    from seerdb.common.oson import encode_oson

    if col.data_type not in _LOB_CONTENT_TYPES or value is None:
        return None
    if col.inline_long_csfrm is not None:
        # A column served inline as LONG / LONG RAW after a type change
        # under a cached cursor carries its content in the row, so the
        # client issues no TTI_LOBOPS read for it and an entry here would
        # shift every later LOB's position in the queue (#826).
        return None
    if col.is_oson:
        # An OSON-in-BLOB column carries its bytes in the row itself
        # (LONG RAW), so the client issues no TTI_LOBOPS read for it and
        # an entry here would shift every later LOB's position (#826) --
        # the same reason the inline VECTOR case below skips.
        return None
    if not for_oci and col.data_type in (TNS_TYPE_JSON, TNS_TYPE_VECTOR):
        # The thin path carries a JSON or VECTOR image in the row itself,
        # so it queues no content: a client that already has the value
        # issues no TTI_LOBOPS for it, and an entry here would shift every
        # later LOB's position in the queue (#887/#826).
        return None
    if col.data_type == TNS_TYPE_CLOB:
        national = col.csfrm == _CSFRM_NCHAR
        return (str(value).encode('utf-16-be'), True, national)
    if col.data_type == TNS_TYPE_JSON:
        # A native JSON column reads back as a LOB whose content is the
        # value's OSON image; the client decodes it as JSON (#30/#50).
        # allow_wide so a > 255-key or > 64 KiB document re-encodes for
        # the client's decoder (the LOB read framing carries any size).
        return (encode_oson(value, allow_wide=True), False, False)
    if col.data_type == TNS_TYPE_VECTOR:
        # A native VECTOR column reads back as a LOB whose content is the
        # value's binary image, re-encoded with the column's element
        # format so INT8 / BINARY stay integral and FLOAT64 keeps its
        # precision (#55).
        vector = encode_vector(_vector_as(value, col.vector_format))
        return (vector, False, False)
    return (bytes(value), False, False)


_LOB_CONTENT_TYPES = _OCI_LOB_TYPES | {TNS_TYPE_JSON, TNS_TYPE_VECTOR}


def _encode_oci_value(value: object, col: ColumnMeta, slot: int | None = None) -> bytes:
    # A row value in the OCI dialect: a LOB column emits its locator (content comes
    # later over TTI_LOBOPS, #405); a LONG / LONG RAW column streams inline via the
    # chunked form (#407); everything else is the ordinary inline DALC value.
    if col.data_type in _OCI_LOB_TYPES:
        return encode_lob_locator_oci(
            value, col.data_type == TNS_TYPE_CLOB, col.csfrm == _CSFRM_NCHAR, slot
        )
    if col.data_type in _OCI_LONG_TYPES:
        return encode_long_value_oci(value)
    if oci_is_xmltype(col):
        return _oci_xmltype_value(value)
    if col.data_type == TNS_TYPE_ADT:
        return encode_object_column_value(value, col.type_oid)
    if col.data_type == TNS_TYPE_RID and isinstance(value, str):
        # A value that is no physical rowid goes as the thin path sends it.
        if _physical_rowid(value) == (0, 0, 0, 0):
            return encode_value(value, TNS_TYPE_RID)
        return encode_rowid_value(value, _OCI)
    if (
        col.data_type == TNS_TYPE_TIMESTAMPTZ
        and isinstance(value, datetime.datetime)
        and _ENCODE_OCI_TSTZ_LOCAL.get()
    ):
        return _oci_timestamptz_value(value)
    return encode_value(_national_wire_value(value, col), col.data_type, _OCI)


# The flag a TIMESTAMP WITH TIME ZONE cell's offset-hour byte carries to OCI:
# the date and time before it are the wall clock at that offset, not UTC (#2018).
_OCI_TSTZ_LOCAL_FLAG = 0x40
# Whether this sqlplus reads that form. Which client gets it, measured against a
# live 11g (the server the Mirror's pre-12c OCI replies imitate): sqlplus 23.26
# does, and sqlplus 11.2 gets the thin form, the time in UTC and no flag. Sent
# the local form, sqlplus 11.2 printed 03:04 +02:00 as 21:04 +66:00. Set per
# session from the field version the client's own capability block names
# (12.1 or later); the capability bit the server keys on is not pinned down.
_ENCODE_OCI_TSTZ_LOCAL: contextvars.ContextVar[bool] = contextvars.ContextVar(
    'encode_oci_tstz_local', default=True
)


def _oci_timestamptz_value(value: datetime.datetime) -> bytes:
    # A TIMESTAMP WITH TIME ZONE cell as OCI reads it (#2018): the wall-clock
    # date and time, the nanoseconds, then the offset's hour + 20 with 0x40 set
    # and its minutes + 60. The thin form sends the time in UTC and no flag.
    # Live 18c to sqlplus 23.26: 2024-01-02 03:04:05.5 -05:30 is
    # `78 7c 01 02 04 05 06 1d cd 65 00 4f 1e`; 2024-01-01 00:30 +02:00 keeps its
    # own date, `78 7c 01 01 01 1f 01 00 00 00 00 56 3c`. A value with no zone is
    # taken as UTC, as on the thin path.
    aware = (
        value
        if value.tzinfo is not None
        else value.replace(tzinfo=datetime.timezone.utc)
    )
    offset = aware.utcoffset()
    assert offset is not None
    total = int(offset.total_seconds() // 60)
    hours, minutes = divmod(abs(total), 60)
    if total < 0:
        hours, minutes = -hours, -minutes
    image = (
        _encode_date_prefix(aware.replace(tzinfo=None))
        + (aware.microsecond * 1000).to_bytes(4, 'big')
        + bytes([(hours + 20) | _OCI_TSTZ_LOCAL_FLAG, minutes + 60])
    )
    return bytes([len(image)]) + image


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
def _oci_lob_rxh() -> bytes:
    return _oci_rxh_of(0x22, 0xFD, 0x01, 0x01)


def encode_lob_fetch_rows_oci(
    columns: list[ColumnMeta], rows: list[tuple], *, sequence: int
) -> bytes:
    """The fetch reply carrying LOB locator row(s) (#405): a row header + the rows,
    then a non-terminator OER status. The LOB content still comes over TTI_LOBOPS,
    so the cursor is not yet drained; a following fetch draws the 1403 terminator.
    ``sequence`` is the live per-session OER counter for the status. Each LOB's
    locator carries its column index, so a read names which of the row's LOBs it
    wants (#1430)."""
    out = bytearray(_oci_lob_rxh())
    for row in rows:
        if len(row) != len(columns):
            raise InterfaceError('row width does not match the column count')
        out += bytes([TTI_RXD]) + b''.join(
            _encode_oci_value(v, col, i) for i, (v, col) in enumerate(zip(row, columns))
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
    CompileCaps, RuntimeCaps = capability_arrays(
        FieldVersion, oall8=Dictionary.get('oall8', False)
    )
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

    # Native 9i OALL8 (#790): a native 9.2 OCI client sends a *compact* DTY --
    # the populated capability arrays followed by a short trailer and NO
    # 980-byte identity/override table (the server returns its own table in
    # reply). Sending the full thin-style table alongside the native caps is
    # what the 9.2 server closes the connection on. Flag 2 matches the capture.
    if Dictionary.get('oall8') and FieldVersion < FIELD_VERSION_10_2:
        return (
            bytes([TTI_DTY])
            + Charset
            + Charset
            + bytes([2])
            + CapabilityHeader
            + TableHeader
            + _O3_OALL8_DTY_TRAILER
        )

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


class _WideDateTime(datetime.datetime):
    """A datetime whose batch column is declared TIMESTAMP (#1098).

    The type is otherwise chosen per value -- DATE with no sub-second part,
    TIMESTAMP with one -- but an ARRAY bind has one OAC per column. A batch
    mixing the two was declared by one row and the server rejected the call
    with ORA-01483. Only the declaration widens: a whole-second row still goes
    out in the 7-byte form, as under any TIMESTAMP descriptor (#1337, #1805).
    """

    __slots__ = ()


class _WideBcDate(BcDate):
    """A date before year 1 whose batch column is declared TIMESTAMP, as
    :class:`_WideDateTime` for a ``datetime`` (#1804)."""

    __slots__ = ()


def _is_wide_datetime(DT: datetime.datetime | BcDate) -> bool:
    # Is this value bound as TIMESTAMP? True when it carries a sub-second part,
    # or when a batch widened the whole column to match (#1098).
    return DT.microsecond > 0 or isinstance(DT, (_WideDateTime, _WideBcDate))


def _widen_batch_datetimes(Rows: list) -> list:
    """Give every row of a temporal column the same wire width (#1098).

    A column holding both `2020-02-29` and `2020-02-29 23:59:59.123456` would
    otherwise send a 7-byte value under an 11-byte descriptor. Naive datetimes
    only: widening an aware one would mean inventing a zone for the others, and
    a mix of aware and naive in one column is a different question.
    """
    if len(Rows) < 2:
        return Rows
    widen = set()
    for J in range(len(Rows[0])):
        Column = [R[J] for R in Rows if isinstance(R[J], (datetime.datetime, BcDate))]
        if len(Column) < 2 or any(
            getattr(V, 'tzinfo', None) is not None for V in Column
        ):
            continue
        Widths = {V.microsecond > 0 for V in Column}
        if len(Widths) > 1:
            widen.add(J)
    if not widen:
        return Rows
    Out = []
    for R in Rows:
        Row = list(R)
        for J in widen:
            V = Row[J]
            if isinstance(V, datetime.datetime) and not isinstance(V, _WideDateTime):
                Row[J] = _WideDateTime(
                    V.year, V.month, V.day, V.hour, V.minute, V.second, V.microsecond
                )
            elif isinstance(V, BcDate) and not isinstance(V, _WideBcDate):
                Row[J] = _WideBcDate(
                    V.year, V.month, V.day, V.hour, V.minute, V.second, V.microsecond
                )
        Out.append(Row)
    return Out


def _oac_rep_row(Rows: list) -> list:
    # For array DML, pick a representative value per column for the single OAC:
    # a NON-NULL value (so the OAC carries the column's real TYPE) with the
    # largest declared size (str/bytes byte length, so the OAC's max-length
    # covers every iteration). A column that is NULL in the first row but holds a
    # value in a later one would otherwise take its type from the None -- a
    # minimal VARCHAR2 -- and the later value then overflowed it (ORA-01461, the
    # value exceeded the maximum VARCHAR2 length), which is exactly what a
    # DataFrame column with a leading NULL hits (#894). A column that is NULL in
    # every row keeps None (a VARCHAR2 NULL bind, as before).
    def _size(Value: object) -> int:
        if isinstance(Value, str):
            return len(Value.encode('utf-8'))
        if isinstance(Value, (bytes, bytearray)):
            return len(Value)
        return 0

    NumCols = len(Rows[0])
    Rep = []
    for J in range(NumCols):
        Best = None
        BestSize = -1
        for R in Rows:
            Value = R[J]
            if Value is None:
                continue
            S = _size(Value)
            if S > BestSize:
                Best, BestSize = Value, S
        Rep.append(Best if Best is not None else Rows[0][J])
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
        (DataType, MaxLen, *_rest) = decode_oac_fields(encode_token_oac(Token))
        if DataType in _PREFETCHED_IMAGE_TYPES:
            # A native JSON / VECTOR bind declares 32 MiB but is NOT LONG-class:
            # it carries its own descriptor framing and rides in place. Sorting it
            # to the end put it in the following bind's slot, which a real 23ai
            # rejects with ORA-24813 -- so `update t set j = :1 where id = :2`
            # failed while `insert into t values (:1, :2)` worked, the JSON bind
            # being last there and the move a no-op (#826).
            continue
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
    if Batch:
        # One wire width per temporal column, before anything is sized (#1098).
        Widened = _widen_batch_datetimes([Bind] + Batch)
        Bind, Batch = Widened[0], Widened[1:]
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
    # 12.1, matching the cursor's own gate. These two used to disagree -- the
    # cursor raised below 12.1 and the encoder set the flag only from 12.2 -- so
    # a 12.1 server was asked for nothing while the caller's request was
    # accepted, and getarraydmlrowcounts() answered [] rather than raising. An
    # empty list reads as "every iteration affected no rows", which is a worse
    # answer than the NotSupportedError it would have got on 11g (#1135).
    # python-oracledb gates the feature by version nowhere at all: it sets the
    # flag and lets the server answer.
    ArrayDmlRowCounts = bool(
        Dictionary['query'].get('arraydmlrowcounts')
        and FieldVersion >= FIELD_VERSION_12_1
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
        All8[9] = All8[9] | TNS_EXEC_FLAGS_IMPLICIT_RESULTSET

    # 23ai (fv >= 23.1 EXT 1, #89): the execute framing the server expects under field
    # version 24 differs from the legacy form in three spots, reverse-engineered
    # from an oracledb-thin fv24 capture (docs/PROTOCOL.md §20):
    #   - the prefetch-buffer-size field (LMax) must be 0, not the 0xffffffff
    #     long-fetch sentinel the first SELECT carries, or the server's stricter
    #     parse overflows (ORA-03120, two-task conversion integer overflow);
    #   - the exec-options word gains 0x40;
    #   - al8i4[9] (exec flags) gains 0x8000 (already implied by the array-DML
    #     0xC000 value, so only set it when that path didn't).
    if FieldVersion >= FIELD_VERSION_23_1_EXT_1:
        if LMax == 0xFFFFFFFF:
            LMax = 0
        # The 0x40 options bit and al8i4[9] = 0x8000 are query-execute flags;
        # setting them on a DDL/DML execute makes the server reject it
        # (ORA-03137 kpoal8Check-5 [32768]).
        if Type in ('select', 'fetch'):
            Opt |= TNS_EXEC_OPTION_FETCH
            if not ArrayDmlRowCounts and len(All8) > 9:
                All8 = list(All8)
                All8[9] = TNS_EXEC_FLAGS_IMPLICIT_RESULTSET

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

    # A fetch from a cursor the client holds no SQL for -- a nested cursor's or
    # a REF CURSOR's -- is the same FETCH-only call on its id (0x8040, as
    # oracledb-thin and OCI send it; #1462).
    if Dictionary['query'].get('fetch_only') and Cursor != 0:
        Opt &= ~TNS_EXEC_OPTION_EXECUTE

    # `cursor.parse()` (#1018): parse the statement, do NOT run it. What makes a
    # call a parse is the *absence* of EXECUTE, so the option word is set
    # outright rather than masked — every bit set_opts derived above (EXECUTE,
    # NOT_PLSQL, the commit bit, the fetch bits) describes work a parse does not
    # ask for. Measured against a live 23ai: a query parse sends 0x20001
    # (PARSE | DESCRIBE, and the reply is the describe alone), any other
    # statement 0x1.
    if Dictionary['query'].get('parse_only'):
        Opt = _EXEC_OPTION_PARSE | (_EXEC_OPTION_DESCRIBE if Type == 'select' else 0)
        # Two more query-execute fields have to come off with the EXECUTE bit,
        # both measured against a live 23ai by capturing the reference client's
        # own parse and diffing it against ours: the prefetch row count (1, not
        # the connection's `fetch`) and the 23ai query flag in al8i4[9], which
        # the fv24 branch above set because the statement is a SELECT. Leaving
        # either in place asks the server to fetch from a cursor the parse never
        # positioned, and it answers ORA-01002 (fetch out of sequence).
        Fetch = 1
        if len(All8) > 9:
            All8 = list(All8)
            All8[9] = 0

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

    # The OALL8 head from the _ALL8_HEAD schema (#2293). The al8o4 / al8app /
    # al8txn / al8txl / al8kv / al8kvl pointers are null, and al8o4l too; the
    # five flag fields are the 0/1 the ptr primitive writes as 00/01. Every
    # value is computed above exactly as before; only the layout moves to the
    # schema the Mirror already decodes this message with.
    Head = _ALL8_HEAD_THIN(
        {
            'seq': Tseq,
            'token_number': TokenNum,
            'options': Opt,
            'cursor': Cursor,
            'sql_present': QueryFlag,
            'sql_length': QueryLen,
            'al8i4_present': All8Flag,
            'al8i4_length': All8Len,
            'al8o4': False,
            'al8o4l': False,
            'prefetch_size': LMax,
            'prefetch_rows': Fetch,
            'max_long': Max,
            'binds_present': BindFlag,
            'bind_count': BindLen,
            'al8app': False,
            'al8txn': False,
            'al8txl': False,
            'al8kv': False,
            'al8kvl': False,
            'defines_present': DefFlag,
            'define_count': DefLen,
        }
    )

    if FieldVersion >= FIELD_VERSION_12_1:
        # 12c+ OALL8 carries extra al8 fields after the 11g header: the DML
        # row-count block from 12.1, then (12.2+) the SQL-signature / SQL-id
        # pointers and (12.2_EXT1+) the chunk-id pointers — all zero/null for
        # us. Gating the whole tail on 12.2 sent a 12.1 session the 11g shape,
        # and a real server refused every call ORA-03120 (#1144). The SQL is
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
        if FieldVersion >= FIELD_VERSION_12_2:
            Middle += bytes([0, 0, 0, 0, 0])  # 12.2 al8sqlsig / SQL id
        if FieldVersion >= FIELD_VERSION_12_2_EXT_1:
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
    # The token goes by the connection's field version, which the dictionary
    # carries.
    Token = _ENCODE_FIELD_VERSION.set(
        Dictionary.get('field_version', FIELD_VERSION_11_2)
    )
    try:
        return _FETCH_THIN(
            {
                'seq': Dictionary['seq'],
                'token_number': 0,
                'cursor': Dictionary['cursor'],
                'rows': Dictionary['fetch'],
            }
        )
    finally:
        _ENCODE_FIELD_VERSION.reset(Token)


# ---------------------------------------------------------------------------
# Oracle 9i (pre-10g, field version 2) query/fetch — the TTI_ALL7 dialect.
# A SELECT is a four-call sequence (docs/PROTOCOL.md §19), reverse-engineered
# from the Oracle JDBC thin driver against a live 9.2.0.4 server (#97). Gate
# every fv2 path on `field_version < FIELD_VERSION_10_2`.
# ---------------------------------------------------------------------------
_O7_CLOSE_FUNC = 0x14  # close cursor
_O7_FREE_FUNC = 0x08  # free it (#2261)


def encode_o7_open(Seq: int) -> bytes:
    # Call 0: OOPEN — allocate a server cursor. The server tracks it as the
    # "current" cursor for the subsequent parse/describe/execute/close (which
    # all carry cursor field 0). Without it the parse fails ORA-01001.
    return bytes([TTI_FUN, 0x02, Seq, 0x01, 0x00])


def _o7_oac(
    Type: int,
    MaxSize: int,
    Csfrm: int,
    Charset: int,
    Flags: int = 0x01,
    Toid: bytes = b'',
    Version: int = 0,
) -> bytes:
    # One 9i bind descriptor or define entry (_O7_OAC).
    return _O7_OAC_THIN(
        {
            'data_type': Type,
            'flags': Flags,
            'precision': 0,
            'scale': 0,
            'max_length': MaxSize,
            'max_array': 0,
            'cont_flags': 0,
            'toid_length': len(Toid),
            'toid': Toid,
            'version': Version,
            'charset': Charset,
            'csfrm': Csfrm,
        }
    )


def _o7_bind_oac(Value: object, Statement: bool = False) -> bytes:
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
    #
    # `Statement` says the bind belongs to a plain SQL statement rather than a
    # PL/SQL block, so a Var there is an IN bind whose type was declared
    # (setinputsizes) and needs no return buffer. That matters for CHAR: 9i
    # treats a CHAR bind as CHAR(max_size) and blank-pads the value to it, so a
    # declared CHAR sized by the Var's default came back padded to 2000 (#737).
    # Sized to the value it carries, the bind is the value (LENGTH(:x) agrees);
    # a SELECT-list `:x` is still typed at a width of 9i's own and padded to it.
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
        return _o7_oac(Type, MaxSize, Csfrm, Charset)

    if isinstance(Value, Var):
        VType = Value.dbtype.tns_type
        Vcsfrm = getattr(Value.dbtype, 'csfrm', 1)
        if VType == TNS_TYPE_NUMBER:
            Type, MaxSize, Csfrm = 0x06, 22, 1
        elif VType == TNS_TYPE_REFCURSOR:
            # A REF CURSOR is a one-byte cursor slot, as ojdbc14 declares it;
            # the block hands back the cursor's id (#2246).
            Type, MaxSize, Csfrm = TNS_TYPE_REFCURSOR, 1, 1
        elif VType == TNS_TYPE_RAW:
            Type, MaxSize, Csfrm = TNS_TYPE_RAW, Value.size, 0
        elif VType in (TNS_TYPE_RID, TNS_TYPE_UROWID):
            # A ROWID / UROWID Var binds as the rowid's text, as on 10g+
            # (encode_token_oac). Declared as its own type, 9i answered with a
            # garbled error and 8i dropped the session (#1399).
            Type, MaxSize, Csfrm = TNS_TYPE_VARCHAR, _MAX_UROWID_LENGTH, 1
        elif (
            VType == TNS_TYPE_CHAR and Statement and isinstance(Value.getvalue(0), str)
        ):
            Held = Value.getvalue(0)
            assert isinstance(Held, str)
            Encoding = 'utf-16-be' if Vcsfrm == 2 else 'utf-8'
            Type, MaxSize, Csfrm = VType, max(len(Held.encode(Encoding)), 1), Vcsfrm
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
        elif _is_wide_datetime(Value):  # or a batch widened its column (#1098)
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


# Nine bytes every TTI_ALL7 call carries after the SQL's length, the same in a
# parse, a block and an execute. Their fields are not known: they are carried
# as captured ground truth, verified byte for byte against ojdbc14's 9i calls.
_O7_ALL7_MID = bytes([0, 0, 0x01, 0x01, 0x07, 0x01, 0x01, 0x02, 0])
# The TTI_ALL7 call head (#2284), one layout for a parse, a PL/SQL block and an
# execute: the option word, the cursor, the SQL's pointer and length, the nine
# bytes above, the defines' pointer and count (an execute's columns), the
# binds' pointer and count, the SQL, then `01 01`, a count -- 1, an array
# DML's rows (ojdbc14's batches of 3 and 300 send `01 03` and `02 01 2c`,
# #2245), or an execute's 10 rows a fetch -- and five zero bytes. The binds'
# descriptors and values, or an execute's defines, follow it. The SQL's length
# counts characters (#2275), not the bytes the text takes, so the text has no
# length to decode it by and the schema only encodes.
_O7_ALL7: wire_schema.Schema = (
    ('const', bytes([TTI_FUN, TTI_ALL7])),
    ('u8', 'seq'),
    ('n4', 'options'),
    ('n4', 'cursor'),
    ('ptr', 'sql_present'),
    ('n4', 'sql_length'),
    ('const', _O7_ALL7_MID),
    ('ptr', 'defines_present'),
    ('n4', 'define_count'),
    ('ptr', 'binds_present'),
    ('n4', 'bind_count'),
    ('raw', 'sql'),
    ('const', b'\x01\x01'),
    ('n4', 'rows'),
    ('pad', 5),
)
# A call on a cursor by its id (#2284): the close (03 14) and the free (03 08).
_O7_CURSOR_CALL: wire_schema.Schema = (
    ('const', bytes([TTI_FUN])),
    ('u8', 'function'),
    ('u8', 'seq'),
    ('n4', 'cursor'),
)
_O7_ALL7_THIN = wire_schema.compile_encoder(_O7_ALL7, _THIN)
_O7_CURSOR_CALL_THIN = wire_schema.compile_encoder(_O7_CURSOR_CALL, _THIN)


def _o7_all7(
    Seq: int,
    Options: int,
    Cursor: int,
    Sql: str | None = None,
    Binds: int = 0,
    Defines: int | None = None,
    Rows: int = 1,
) -> bytes:
    # A TTI_ALL7 call head (_O7_ALL7). `Sql` None sends none: an execute, or a
    # re-execute by the cursor's id. `Defines` is an execute's column count,
    # its pointer present even for none, and None for a parse.
    return _O7_ALL7_THIN(
        {
            'seq': Seq,
            'options': Options,
            'cursor': Cursor,
            'sql_present': Sql is not None,
            'sql_length': _o7_sql_length(Sql) if Sql else 0,
            'defines_present': Defines is not None,
            'define_count': Defines or 0,
            'binds_present': bool(Binds),
            'bind_count': Binds,
            'sql': (Sql or '').encode('utf-8'),
            'rows': Rows,
        }
    )


def _o7_sql_length(Sql: str) -> int:
    # The SQL's length as 9i reads it: in characters, not the UTF-8 bytes that
    # carry it. Measured on 9.2.0.4 in seerdb's AL32UTF8 session (#2275): with
    # the byte count, `select 'caf\u00e9' from dual` (16 bytes, 15 characters)
    # left the server waiting for a 16th character, and the client hung. The
    # bed's database is single-byte, so the count could not be told apart from
    # bytes in a multibyte database charset there.
    return len(Sql)


def encode_o7_parse(
    Seq: int,
    Sql: str,
    Binds: list | None = None,
    Batch: list | None = None,
    BatchErrors: bool = False,
    Cursor: int = 1,
    Reexecute: bool = False,
) -> bytes:
    # Call 1: TTI_ALL7 parse. The SQL is carried inline, sb4-length-prefixed,
    # between two fixed option blocks. With input binds (#100) the option word
    # flips to 0x29, a bind-count field precedes the SQL, and each bind's OAC
    # plus the values (one RXD with all values) are appended after the SQL.
    # `Batch` holds an array DML's further rows (#2245): the tail counts every
    # row, the OACs describe the columns once, as the 10g+ path does, and each
    # row follows as its own RXD -- ojdbc14's executeBatch, one call however
    # many rows or packets.
    Binds = Binds or []
    Rows = _widen_batch_datetimes([Binds, *Batch]) if Batch else [Binds]
    # The option word is a ub4: 0x8021, 0x8029 with binds, and with the 10g+
    # batch-errors bit, which 9.2 honours too: it applies the good rows and
    # answers ORA-24381 with the failures (#2247).
    Opt = 0x8029 if Binds else 0x8021
    if BatchErrors:
        Opt |= TNS_EXEC_OPTION_BATCH_ERRORS
    # `Cursor` is the server cursor the call names, the ub4 after the option
    # word: the session's shared one for every statement seerdb does not cache,
    # which re-parses it (#2288), or the one OOPEN gave a cached statement
    # (#2261). Re-executing that one
    # clears the parse bit (0x8029 -> 0x8028) and sends no SQL, as ojdbc14's
    # statement cache does: the server keeps the parse and the defines.
    if Reexecute:
        Opt &= ~0x01
    Out = _o7_all7(
        Seq, Opt, Cursor, None if Reexecute else Sql, len(Binds), Rows=len(Rows)
    )
    if Binds:
        Oacs = [_o7_bind_oac(V, Statement=True) for V in _oac_rep_row(Rows)]
        Out += b''.join(Oacs)
        # 9i applies the LONG-class rule too (docs/PROTOCOL.md 5.4, #723): a
        # bind declared wider than 4000 bytes has its value read after the
        # row's others. The declared size is the descriptor's sb4 at +4; a
        # plain string is declared 4000 there and stays in place. A PL/SQL
        # block (encode_o7_block) keeps every value in place.
        Long = [decode_ub4(Oac[4:])[0] > 4000 for Oac in Oacs]
        for Row in Rows:
            Out += encode_tokens_rxd(
                [V for V, L in zip(Row, Long) if not L]
                + [V for V, L in zip(Row, Long) if L],
                b'',
            )
    return Out


def encode_o7_block(
    Seq: int, Sql: str, Binds: list | None = None, Cursor: int = 1
) -> bytes:
    # Anonymous PL/SQL block parse-execute over TTI_ALL7 (#102, PROTOCOL §19.6).
    # Same framing as encode_o7_parse EXCEPT the option word: a block uses
    # `01 21` (no binds) / `02 04 29` (binds) where a SELECT/DML uses
    # `02 80 21` / `02 80 29` — the 0x8000 "values are inline" bit is NOT set,
    # so the server rejects DML opts on a block with ORA-00600. Consequently the
    # bind OACs are sent here but the VALUES are NOT appended inline; the server
    # answers with a "send the binds" prompt and the caller then sends the
    # values as a standalone RXD (encode_tokens_rxd). Verified byte-for-byte
    # against cap_9i_plsql_{noarg,inbind}.log. `Cursor` is the server cursor,
    # an sb4 after the option word, then the SQL's pointer, as in a parse.
    Binds = Binds or []
    Out = _o7_all7(Seq, 0x0429 if Binds else 0x21, Cursor, Sql, len(Binds))
    if Binds:
        # Bind OACs only — the values follow in a separate RXD frame after the
        # server's bind prompt (the 0x8000-inline path is not used for blocks).
        Out += b''.join(_o7_bind_oac(V) for V in Binds)
    return Out


def encode_o7_describe(Seq: int, Cursor: int = 1) -> bytes:
    # Call 2: fixed describe-columns request; response is the metadata RPA.
    # `Cursor` is the server cursor's id, a ub4: the one OOPEN gave (1), or a
    # REF CURSOR a block returned, which ojdbc14 describes the same way (#2246).
    return (
        bytes([TTI_FUN, TTI_DNY, Seq, 0x07])  # describe columns (RPA: metadata)
        + encode_sb4(Cursor)
        + bytes([0, 0, 0x01, 0x02, 0x01, 0x01])
    )


def _o7_define_entry(Col: dict) -> bytes:
    # One 13/14-byte define entry: the client's requested return type for a
    # column (built from the describe). deftype = VARNUM(6) for NUMBER, else the
    # column type; CHAR carries flag 0x21; NUMBER/DATE/TIMESTAMP use a fixed
    # buffer size, everything else the described buffer. charset defaults to 31
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
        # (ORA-01002). The value arrives as the familiar 18-char rowid string;
        # a UROWID's text, an index-organized table's logical rowid, runs to
        # _MAX_UROWID_LENGTH, as the bind path has it. Defined at 128, a longer
        # one came back cut to 128 characters with no error (#2335).
        MaxSize = _MAX_UROWID_LENGTH if Type == TNS_TYPE_UROWID else 128
        DefType, Csfrm = TNS_TYPE_VARCHAR, 0
    elif Type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW):
        # LONG / LONG RAW: request the native type with the 2 GiB max buffer
        # (as JDBC does); the value streams back in the chunked DALC form.
        DefType, MaxSize = Type, 0x7FFFFFFF
    else:
        # The described buffer, in bytes: max_size is the declared size, an
        # NCHAR's in characters and a LOB's 0, as 10g's describe has it (#2326).
        DefType, MaxSize = Type, Col.get('data_length') or 0
    Flag = 0x21 if Type == TNS_TYPE_CHAR else 0x01
    Charset = Col.get('charset') or 31
    # An object names its type in the descriptor as ojdbc14 does: the
    # open-ended size, the TOID and version 1 (#2258).
    if Type == TNS_TYPE_ADT and Col.get('type_oid'):
        return _o7_oac(DefType, 0x7FFFFFFF, Csfrm, Charset, Flag, Col['type_oid'], 1)
    return _o7_oac(DefType, MaxSize, Csfrm, Charset, Flag)


def encode_o7_exec(Seq: int, Columns: list, Cursor: int = 1) -> bytes:
    # Call 3: TTI_ALL7 execute + fetch (option word 02 80 50), carrying a define
    # block (one entry per column) so the server returns the requested types.
    # `Cursor` as for encode_o7_describe (#2246).
    # The rows each fetch asks for: 10, as ojdbc14 asks.
    Head = _o7_all7(Seq, 0x8050, Cursor, Defines=len(Columns), Rows=10)
    return Head + b''.join(_o7_define_entry(C) for C in Columns)


def encode_o7_close(Seq: int, Cursor: int = 1) -> bytes:
    # Call 4: close the cursor (`Cursor` as for encode_o7_describe, #2246). It
    # stays parsed: a re-execute by its id still runs it (#2261).
    return _O7_CURSOR_CALL_THIN(
        {'function': _O7_CLOSE_FUNC, 'seq': Seq, 'cursor': Cursor}
    )


def encode_o7_free(Seq: int, Cursor: int) -> bytes:
    # Free a server cursor (03 08): after it, a re-execute of its id answers
    # ORA-01001. What a cached cursor gets when it is evicted or flushed (#2261).
    return _O7_CURSOR_CALL_THIN(
        {'function': _O7_FREE_FUNC, 'seq': Seq, 'cursor': Cursor}
    )


def encode_o7_version(Seq: int) -> bytes:
    # The server's release (03 3b), which the 9i login does not return: ojdbc14
    # asks for it once after login, with a 256-byte banner buffer (#2278).
    return bytes([TTI_FUN, TTI_VERSION, Seq, 1]) + encode_sb4(256) + bytes([1, 1])


def decode_fv2_version(Packet: bytes) -> int:
    # Its reply, `08 <ub2 banner length> <banner> <ub4 packed release>` then the
    # status; 0 for anything else, as a login that returned no version (#2278).
    if not Packet or Packet[0] != TTI_RPA:
        return 0
    (Length, Rest) = decode_ub4(Packet[1:])
    return decode_ub4(Rest[Length:])[0]


def decode_fv2_opened_cursor(Packet: bytes) -> int:
    # The id an OOPEN reply hands out: `08 <ub4 id> 09` (#2261).
    if not Packet or Packet[0] != TTI_RPA:
        return 0
    return decode_ub4(Packet[1:])[0]


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
# (BFILE FILE_OPEN/READ/CLOSE). (#102, PROTOCOL §19.5 / §19.8) The "middle" is
# the 10g+ head's fields and the "trailer" its short amount: `_O7_LOBOPS`.


# How a 9i LOB operation's request differs from GET_LENGTH's, captured from
# ojdbc14 on 9.2.0.4 (#2259): IS_OPEN and CLOSE ask no reply value, and
# IS_OPEN sets the null-LOB flag its answer comes back in; FILE_CLOSE asks
# none either.
_O7_LOBOP_FLAGS = {
    TNS_LOB_OP_IS_OPEN: {'short_amount_present': False, 'null_lob_present': True},
    TNS_LOB_OP_CLOSE: {'short_amount_present': False},
    TNS_LOB_OP_FILE_CLOSE: {'short_amount_present': False},
}


def _encode_o7_lobop(
    Seq: int,
    Locator: bytes,
    Operation: int,
    Offset: int = 0,
    Amount: int = 0,
    O8i: bool = False,
) -> bytes:
    # A 9i or 8i TTI_LOBOPS request from `_O7_LOBOPS`. The locator is as
    # fetched, a ub2 length and the body (`_read_lob_column`), and its length
    # counts both; CLOB/BLOB locators are 86 bytes, BFILE locators vary with
    # the directory and file name.
    Values = {
        'seq': Seq,
        'token_number': None,
        'source_present': True,
        'source_length': len(Locator),
        'dest_present': False,
        'dest_length': 0,
        'short_source_offset': Offset,
        'short_dest_offset': 0,
        'charset_present': False,
        'short_amount_present': True,
        'null_lob_present': False,
        'operation': Operation,
        'scn_present': False,
        'scn_length': 0,
        'locator': Locator,
        'short_amount': Amount,
    }
    Values.update(_O7_LOBOP_FLAGS.get(Operation, {}))
    return (_O7_LOBOPS_O8I if O8i else _O7_LOBOPS_THIN)(Values)


def encode_o7_lob_getlen(Seq: int, Locator: bytes) -> bytes:
    # GETLEN: ask the server for the LOB's length, which comes back in the
    # short amount -- see decode_fv2_lob_getlen.
    return _encode_o7_lobop(Seq, Locator, TNS_LOB_OP_GET_LENGTH)


def encode_o7_lob_read(Seq: int, Locator: bytes, Amount: int, Offset: int = 1) -> bytes:
    # READ: pull `Amount` chars/bytes from 1-based `Offset`. Response is
    # `0e fe <chunks>` then an RPA + OER.
    return encode_o7_lobop(Seq, Locator, TNS_LOB_OP_READ, Offset=Offset, Amount=Amount)


def encode_o7_lobop(
    Seq: int,
    Locator: bytes,
    Operation: int,
    *,
    Offset: int = 0,
    Amount: int = 0,
    Data: bytes | None = None,
) -> bytes:
    """A 9i TTI_LOBOPS request for `Operation` on `Locator` (#2259), with its
    source offset (READ and WRITE) and short amount (a READ's or WRITE's count,
    TRIM's new length, OPEN's mode, 0 for the sizes), and a WRITE's data behind
    it as TTI_LOB content."""
    Out = _encode_o7_lobop(Seq, Locator, Operation, Offset, Amount)
    if Data is not None:
        Out += bytes([TTI_LOB]) + _o7_lob_value(Data)
    return Out


def _o7_lob_value(Data: bytes) -> bytes:
    # A 9i WRITE's data as ojdbc14 sends it: a ub1 length and the bytes up to
    # 252, past that the 0xFE marker, ub1-length chunks of 252 and a zero.
    if len(Data) <= TNS_MAX_SHORT_LENGTH:
        return bytes([len(Data)]) + Data
    Out = bytearray([TNS_LONG_LENGTH_INDICATOR])
    for At in range(0, len(Data), TNS_MAX_SHORT_LENGTH):
        Chunk = Data[At : At + TNS_MAX_SHORT_LENGTH]
        Out += bytes([len(Chunk)]) + Chunk
    return bytes(Out + b'\x00')


def _o7_lobops_reply(
    Packet: bytes, Operation: int | None, O8i: bool = False
) -> dict | None:
    # A 9i or 8i LOB operation's reply, from `_O7_LOBOPS_REPLY` by what
    # `Operation`'s request asked for -- or, for None, its locator alone -- or
    # None for one that is not an RPA (an error's status) or too short.
    if not Packet or Packet[0] != TTI_RPA:
        return None
    if Operation is None:
        Given = {'short_amount_present': False, 'null_lob_present': False}
    else:
        Given = {'short_amount_present': True, 'null_lob_present': False}
        Given.update(_O7_LOBOP_FLAGS.get(Operation, {}))
    try:
        Decode = _O7_LOBOPS_REPLY_FROM_O8I if O8i else _O7_LOBOPS_REPLY_FROM_THIN
        return Decode(Packet, Given)[0]
    except (IndexError, Truncated, DataError):
        return None


def decode_fv2_lob_value(
    Packet: bytes, Operation: int = TNS_LOB_OP_GET_LENGTH
) -> tuple[int, bytes | None]:
    """A 9i LOB operation's reply value and the locator it echoes (#2259):
    the length for GET_LENGTH, the chunk size, the amount a WRITE wrote,
    OPEN's mode, IS_OPEN's 1 or 0, and 0 for CLOSE, which asks for none. The
    locator is the one later calls use -- a write updates it -- as its body,
    without its ub2 length, which LOB._refresh puts back on. Returned with
    it, the locator was prefixed twice and the next call answered
    ORA-22275."""
    Reply = _o7_lobops_reply(Packet, Operation)
    if Reply is None:
        return (0, None)
    return (Reply.get('short_amount', Reply.get('flag', 0)), Reply['locator'])


def encode_o7_bfile_open(Seq: int, Locator: bytes) -> bytes:
    # BFILE FILE_OPEN: open the external file read-only, mode 0x0b in the short
    # amount. The reply carries an *updated* locator with the open flag set —
    # GETLEN/READ/CLOSE must use that one (decode_fv2_opened_locator). (#102,
    # PROTOCOL §19.8)
    return _encode_o7_lobop(Seq, Locator, TNS_LOB_OP_FILE_OPEN, Amount=0x0B)


def encode_o7_bfile_close(Seq: int, Locator: bytes) -> bytes:
    # BFILE FILE_CLOSE: close the opened file; it asks no reply value.
    return _encode_o7_lobop(Seq, Locator, TNS_LOB_OP_FILE_CLOSE)


def decode_fv2_opened_locator(Packet: bytes) -> bytes | None:
    # The opened BFILE locator a FILE_OPEN reply carries, whole -- its ub2
    # length and body -- so it feeds straight back into the LOBOPS encoders.
    # 8i's reply opens the same way, its mode after it at the 8i codec's
    # width, so only the locator is read.
    Reply = _o7_lobops_reply(Packet, None)
    if Reply is None:
        return None
    return Reply['locator_length'].to_bytes(2, 'big') + Reply['locator']


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
    Pos = 2 if Data[1] == TNS_LONG_LENGTH_INDICATOR else 1
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
    # A GET_LENGTH reply's length, in chars for CLOB/NCLOB and bytes for BLOB,
    # from `_O7_LOBOPS_REPLY`. 0 on an unexpected shape (e.g. an empty LOB) so
    # the caller reads nothing rather than desyncing.
    return decode_fv2_lob_value(Packet, TNS_LOB_OP_GET_LENGTH)[0]


def _fv2_type_name(Name: bytes | None) -> str | None:
    return Name.decode('ascii', 'replace') if Name else None


def _o7_max_size(Oac: dict) -> int:
    # A pre-10g column's declared size, as 10g's describe sends it (the OAC's
    # max_chars, which 8i and 9i do not): a VARCHAR2's or CHAR's characters,
    # its buffer over two in AL16UTF16, and 0 for any other column. Its buffer
    # instead gave a DATE and a ROWID a size of 1, a LOB 4000 and a 9i NUMBER
    # 22, which cursor.description reported (#2326).
    if Oac['data_type'] not in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR):
        return 0
    if Oac['charset'] == AL16UTF16_CHARSET:
        return Oac['max_length'] // 2
    return Oac['max_length']


def decode_fv2_describe(Data: bytes) -> list[dict]:
    # The TTI_RPA (0x08) answering the 0x62 describe-columns call, as column
    # dicts shaped like decode_token_dcb's (docs/PROTOCOL.md §19.1), from
    # `_O7_DESCRIBE`. A reply without the RPA, a status refusing the call,
    # describes no columns, and the execute then raises its error.
    if not Data or Data[0] != TTI_RPA:
        return []
    Columns = []
    for Oac in _O7_DESCRIBE_FROM_THIN(Data)[0]['columns']:
        Col = {
            'data_type': Oac['data_type'],
            'data_length': Oac['max_length'],
            'data_scale': Oac['scale'],
            'precision': Oac['precision'],
            'max_size': _o7_max_size(Oac),
            'charset': Oac['charset'],
            'csfrm': Oac['csfrm'],
            'null_ok': 0 if Oac['null_ok'] == 0 else 1,
            'domain_schema': None,
            'domain_name': None,
            'column_name': Oac['name'],
        }
        if Oac['data_type'] in (TNS_TYPE_ADT, TNS_TYPE_REF):
            Col['type_oid'] = Oac.get('toid', b'')
            Col['type_schema'] = _fv2_type_name(Oac.get('type_schema'))
            Col['type_name'] = _fv2_type_name(Oac.get('type_name'))
        Columns.append(Col)
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
        elif DType in (TNS_TYPE_RID, TNS_TYPE_UROWID):
            # The rowid's text, as on 9i and 10g+; declared as its own type the
            # bind dropped the session (#1399).
            DType, Charset, Csform, MaxSize = 1, 31, 1, _MAX_UROWID_LENGTH
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


def encode_8i_lob_read(Seq: int, Locator: bytes, Amount: int) -> bytes:
    # 8i CLOB/BLOB/BFILE READ (`_O7_LOBOPS` at the 8i codec's widths, #2284):
    # unlike 9i's GETLEN + READ pair, 8i reads the value in one call from offset
    # 1, whose reply is the shared `0e fe <chunks> 00` LOB content
    # (decode_fv2_lob_chunks). `Amount` is chars for a CLOB, bytes for a BLOB /
    # BFILE.
    return _encode_o7_lobop(Seq, Locator, TNS_LOB_OP_READ, 1, Amount, O8i=True)


def encode_o8i_bfile_open(Seq: int, Locator: bytes) -> bytes:
    # 8i BFILE FILE_OPEN (#401): open the external file read-only, mode 0x0b in
    # the short amount. The reply's RPA carries an *updated* locator with the
    # open flag set -- GETLEN / READ / CLOSE must use that one
    # (decode_fv2_opened_locator, shared with the 9i path). §19.17.
    return _encode_o7_lobop(Seq, Locator, TNS_LOB_OP_FILE_OPEN, 0, 0x0B, O8i=True)


def encode_o8i_bfile_getlen(Seq: int, Locator: bytes) -> bytes:
    # 8i BFILE GETLEN (#401): ask for the file length, which the reply carries in
    # the short amount (decode_o8i_bfile_getlen).
    return _encode_o7_lobop(Seq, Locator, TNS_LOB_OP_GET_LENGTH, O8i=True)


def encode_o8i_bfile_close(Seq: int, Locator: bytes) -> bytes:
    # 8i BFILE FILE_CLOSE (#401): close the opened file; it asks for no amount.
    return _encode_o7_lobop(Seq, Locator, TNS_LOB_OP_FILE_CLOSE, O8i=True)


def decode_o8i_bfile_getlen(Packet: bytes) -> int:
    # The file length an 8i BFILE GETLEN reply carries (#401), its short amount
    # (`_O7_LOBOPS_REPLY` at the 8i codec's widths), or 0 for a reply of another
    # shape.
    Reply = _o7_lobops_reply(Packet, TNS_LOB_OP_GET_LENGTH, O8i=True)
    return Reply.get('short_amount', 0) if Reply else 0


def decode_8i_block_out(Data: bytes, NumOut: int) -> list:
    # Decode the OUT / IN OUT return values from an 8i PL/SQL block reply
    # (docs/PROTOCOL.md §19.14). After the I/O vector (`_O8I_IOV`), the values
    # ride a single TTI_RXD (07), `NumOut` cells (`_O8I_OUT_CELL`) in OUT-bind
    # position order. Returns the raw value bytes per OUT bind (None for empty /
    # NULL, and for one the block never assigned), decoded against each Var's
    # declared type by the cursor.
    return _decode_8i_block_values(Data, NumOut)[0]


def decode_8i_block_cursor(Data: bytes, NumOut: int) -> int:
    # The cursor an 8i PL/SQL block's reply names, from the status behind its
    # bind prompt and OUT values (#2286).
    return decode_8i_cursor_id(_decode_8i_block_values(Data, NumOut)[1])


def _decode_8i_block_values(Data: bytes, NumOut: int) -> tuple[list, bytes]:
    # The OUT values of an 8i block's reply and the status after them; a reply
    # without the I/O vector -- the status alone of a block that failed -- has
    # none.
    Iov = _o8i_iov(Data)
    Rest = Data if Iov is None else Iov[1]
    OutValues: list = []
    if NumOut > 0 and Rest[:1] == bytes([TTI_RXD]):
        Rest = Rest[1:]
        for _ in range(NumOut):
            if Rest[:1] == b'\xff':
                Rest = _O8I_OUT_UNASSIGNED_FROM_O8I(Rest)[1]
                OutValues.append(None)
                continue
            (Cell, Rest) = _O8I_OUT_CELL_FROM_O8I(Rest)
            OutValues.append(bytes(Cell['value']) or None)
    return OutValues, Rest


def o8i_block_complete(Data: bytes) -> bool:
    """Whether an 8i PL/SQL block's reply has arrived whole (#2334).

    8i caps each data packet at the SDU and marks none as a message's last, so
    a reply carrying long OUT values -- 4000 characters is three packets --
    arrives in pieces. It is whole once its I/O vector, the value of every bind
    the vector marks OUT, and a whole status (`o8i_terminal_complete`) are
    there; a block that failed sends the status alone. A reply that does not
    decode is taken as whole, for its readers to raise on."""
    Rest = Data
    if Rest[:1] == bytes([TTI_IOV]):
        try:
            (Iov, Rest) = _O8I_IOV_FROM_O8I(Rest)
        except IndexError:
            return False
        except (ValueError, DataError):
            return True
        Count = Iov['iterations'] * 256 + Iov['requests']
        if len(Rest) < Count:
            return False
        NumOut = sum(1 for Mask in Rest[:Count] if Mask & FV2_BIND_OUT)
        try:
            Rest = _decode_8i_block_values(Data, NumOut)[1]
        except (IndexError, Truncated):
            return False
        except (ValueError, DataError):
            return True
    return bool(Rest) and o8i_terminal_complete(Rest)


# 8i statement-type codes (the OCI OCI_STMT_* family), carried at trailer offset
# +28 of the OALL8 and driving the whole option word. 0 = transaction control
# (COMMIT / ROLLBACK), which 8i parses on a cursor of its own like any other
# statement (#2286).
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
        Option = (
            TNS_EXEC_OPTION_PARSE
            | TNS_EXEC_OPTION_EXECUTE
            | (TNS_EXEC_OPTION_FETCH if IsQuery else 0)
            | (TNS_EXEC_OPTION_BIND if NumBinds else 0)
        )
        if IsBlock:
            Byte4, Byte5 = (0x04 if NumBinds else 0x00), 0x04
        else:
            Byte4, Byte5 = (0x80 if StmtType != O8I_STMT_TXN else 0x00), 0x00
        ExecFlag = 0 if IsQuery else 1
        Message = _o8i_all8(
            Seq,
            options=Option | Byte4 << 8 | Byte5 << 16,
            # The SQL as the bytes its length counts: handed a str, the text
            # would go as UTF-8, and a Latin-1 character's two bytes made it
            # one longer than its count (ORA-00942, #2276).
            sql=Sql,
            prefetch_rows=1,
            bind_count=NumBinds,
            al8i4=(1, ExecFlag, StmtType),
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


def encode_8i_sql_text(Sql: str) -> bytes:
    """A statement's text as 8i takes it: WE8ISO8859P1, the session's charset.

    A character it cannot hold goes as the charset's replacement character,
    the inverted question mark, as the 9i server puts one for it (`žába`
    is `¿ába` there), rather than failing in the client (#2276)."""
    return ''.join(C if ord(C) < 0x100 else '\u00bf' for C in Sql).encode('latin-1')


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
    # sequence byte and three ub4 LITTLE-endian fields:
    #   - offset 7: the cursor id, after the ub4 option word (0x40, fetch). It
    #     was written big-endian at 4, which put a cursor below 256 on the same
    #     byte and any other into the option word (#2285).
    #   - offset 31: the LONG fetch size — the maximum bytes of a LONG / LONG RAW
    #     column the server returns per row. 8i truncates the value to this size
    #     (it does NOT continue one LONG across fetch round trips), so the caller
    #     passes a large cap to read the whole value (#377). For a query with no
    #     LONG column it is just a prefetch hint. An earlier version wrote the row
    #     count here as big-endian, whose low byte landed on this field and capped
    #     every LONG at `fetch` bytes.
    #   - offset 49: the number of rows to return this call (1 when a LONG column
    #     is present — 8i forces single-row fetches for LONGs).
    # Those are the OALL8 head's cursor and max_long and al8i4[1] (_O8I_ALL8).
    return _o8i_all8(
        Seq,
        options=TNS_EXEC_OPTION_FETCH,
        cursor=Cursor,
        max_long=min(LongSize, 0xFFFFFFFF),
        al8i4=(0, Count, O8I_STMT_SELECT),
    )


# The _O8I_ALL8 fields every 8i request carries the same: the pointers a 9.2
# client always sends -- al8i4 and its count of 12, al8o4l and al8kvl -- and
# the zeros. _o8i_all8 copies them and sets the rest.
_O8I_ALL8_FIXED: dict = {
    **{f'al8i4_{i}': 0 for i in range(12)},
    'token_number': None,
    'al8i4_present': True,
    'al8i4_length': 12,
    'al8o4': False,
    'al8o4l': True,
    'prefetch_size': 0,
    'al8app': False,
    'al8txn': False,
    'al8txl': False,
    'al8kv': False,
    'al8kvl': True,
}


def _o8i_all8(
    Seq: int,
    *,
    options: int,
    al8i4: tuple[int, int, int],
    cursor: int = 0,
    sql: bytes | None = None,
    prefetch_rows: int = 0,
    max_long: int = 0,
    bind_count: int = 0,
) -> bytes:
    # An 8i OALL8 head (_O8I_ALL8): the fields a 9.2 client sets and the
    # pointers it always sends -- al8i4 and its count of 12, al8o4l and al8kvl
    # -- with al8i4's [0], [1] and [7] (`al8i4`). `sql` is an execute's text,
    # present even when empty, and None for a fetch. The bind section, when
    # there is one, follows it.
    (first, second, statement) = al8i4
    values = dict(_O8I_ALL8_FIXED)
    values.update(
        al8i4_0=first,
        al8i4_1=second,
        al8i4_7=statement,
        seq=Seq & 0xFF,
        options=options,
        cursor=cursor,
        sql_present=sql is not None,
        sql_length=len(sql or b''),
        sql=sql,
        prefetch_rows=prefetch_rows,
        max_long=max_long,
        binds_present=bool(bind_count),
        bind_count=bind_count,
    )
    Token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_9_2)
    try:
        return _O8I_ALL8_O8I(values)
    finally:
        _ENCODE_FIELD_VERSION.reset(Token)


def _o8i_status(Data: bytes) -> dict | None:
    # The fields of an 8i reply's status (`_O8I_STATUS`), after the RPA in
    # front of it (`_O8I_RPA`), or None when the reply opens with neither. A
    # reply cut short of its status raises IndexError or Truncated.
    Rest = Data
    if Rest[:1] == bytes([TTI_RPA]):
        (_, Rest) = _O8I_RPA_FROM_O8I(Rest)
        if not Rest:
            raise Truncated('8i status: the RPA alone')
    if Rest[:1] != bytes([TTI_OER]):
        return None
    return _O8I_STATUS_FROM_O8I(Rest)[0]


def _o8i_status_or_none(Data: bytes) -> dict | None:
    # The status, or None for a reply without a whole one.
    try:
        return _o8i_status(Data)
    except (IndexError, DataError):
        return None


def _o8i_status_strict(Data: bytes) -> dict | None:
    # The status, or None for a reply that opens with neither an RPA nor a
    # status. One that does and does not decode raises: the old scan for
    # "ORA-" found an error in any bytes, and a reader that took such a reply
    # for "no error" would report a failed statement as done.
    try:
        return _o8i_status(Data)
    except IndexError as Exc:
        raise Truncated('8i status cut short') from Exc


def _encode_9i_oall8(
    Seq: int,
    Sql: bytes,
    StmtType: int,
    Binds: list,
    Batch: list | None = None,
    BatchErrors: bool = False,
) -> bytes:
    # The native 9i (9.2) OALL8 (TTI_ALL8, 0x5e) execute — the 64-bit form the
    # server accepts once the OALL8 opt-in caps are negotiated (#716). It is 8i's
    # execute (_O8I_ALL8) at a 9.2 client's widths (_O9I): 8-byte pointers and
    # counts, and the defines' pointer and count that 8i does not read (#798).
    # Proved byte for byte against the execute built here by hand from the native
    # 9.2 captures before (SELECT, DML, DDL, blocks, a chunked 150-byte text and
    # an array DML), and those captures against it apart from the heap-pointer
    # fields the server ignores.
    #
    # `Batch` holds an array DML's further rows (#798): the tail's iteration count
    # counts every row, the bind descriptors describe each column once (a value
    # wide enough for every row, _oac_rep_row), and each row follows as its own
    # TTI_RXD -- one call, as a native 9.2 OCI client's array execute sends it
    # (native_9i_array_dml.pcap). `BatchErrors` sets the batch-errors bit
    # (0x80000, option byte 5's 0x08): the server applies the good rows and
    # answers ORA-24381 with the failures.
    Rows = _widen_batch_datetimes([Binds, *Batch]) if Batch else [Binds]
    NumBinds = len(Binds)
    IsBlock = StmtType in (O8I_STMT_BEGIN, O8I_STMT_DECLARE)
    IsQuery = StmtType == O8I_STMT_SELECT
    # A SELECT adds the FETCH option so the execute reply carries the describe and
    # the first row batch (#792); the continuation fetches use the FETCH-only form
    # (encode_9i_oall8_fetch). Byte4 is 0x80 for a no-bind cursor statement --
    # SELECT and DML alike: its low bit is commit-on-success, so 0x81 made every
    # DML autocommit (another session saw an uncommitted row, and rollback was a
    # no-op). 0x80 is transactional, byte-verified against native 9.2 SELECT and
    # INSERT captures; the caller commits (#716/#792).
    Option = (
        TNS_EXEC_OPTION_PARSE
        | TNS_EXEC_OPTION_EXECUTE
        | (TNS_EXEC_OPTION_BIND if NumBinds else 0)
        | (TNS_EXEC_OPTION_FETCH if IsQuery else 0)
    )
    # Bytes 4-5 continue the option word (little-endian): 0x80 here is 0x8000,
    # "not PL/SQL", and a block's 0x05 / 0x04 carry 0x0100 -- commit on success --
    # and the PL/SQL bind bits. A bound DML sent the block form and so committed
    # the whole transaction, earlier statements too, where rollback should have
    # undone it; a native 9.2 OCI client sends bound and array DML as 0x80 / 0x00
    # (native_9i_array_dml.pcap), the same as an unbound one (#798).
    if IsBlock:
        Byte4 = 0x04 if NumBinds else 0x00
    else:
        Byte4 = 0x80
    Byte5 = 0x04 if IsBlock else (0x08 if BatchErrors else 0x00)
    # al8i4 [1] is the iteration count: 0 for a SELECT (the fetch rides the FETCH
    # option), else the rows the execute runs -- 1, or an array DML's count.
    # Byte-verified against the native 9.2 SELECT (native_9i_select.pcap), DML
    # (#716) and array DML (native_9i_array_dml.pcap, 3) captures.
    Values = dict(_O8I_ALL8_FIXED)
    Values.update(
        seq=Seq & 0xFF,
        options=Option | Byte4 << 8 | Byte5 << 16,
        cursor=0,
        sql_present=True,
        sql_length=len(Sql),
        sql=Sql,
        prefetch_rows=1,
        max_long=0,
        binds_present=bool(NumBinds),
        bind_count=NumBinds,
        defines_present=True,
        define_count=0,
        al8i4_0=1,
        al8i4_1=0 if IsQuery else len(Rows),
        al8i4_7=StmtType,
    )
    # The SQL text is a pre-10g chunked string (encode_chr at field version 2): a
    # plain length byte up to 64 bytes, else 0xFE, 64-byte chunks and a zero --
    # byte-verified against a native 9.2 161-byte query (chunks 64, 64, 33). A
    # single length byte, as written before, failed outright past 255 bytes.
    Token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_9_2)
    try:
        Message = _O8I_ALL8_O9I(Values)
        if NumBinds:
            Oacs = [_encode_9i_bind_oac(V) for V in _oac_rep_row(Rows)]
            Message += b''.join(Oacs)
            # The 9i LONG-class rule holds here too (#723): a statement's bind
            # declared wider than 4000 bytes has its value read after the row's
            # others -- a declared VARCHAR Var landed in the next column. The
            # declared size is the descriptor's max_length, a ub4 at +5. A PL/SQL
            # block keeps every value in place, as on the compact path.
            Long = [
                not IsBlock and int.from_bytes(Oac[5:9], 'little') > 4000
                for Oac in Oacs
            ]
            for Row in Rows:
                Message += bytes([0x07])
                for Value in [V for V, L in zip(Row, Long) if not L] + [
                    V for V, L in zip(Row, Long) if L
                ]:
                    Message += _encode_9i_bind_value(Value)
    finally:
        _ENCODE_FIELD_VERSION.reset(Token)
    return Message


def _encode_9i_bind_oac(Value: object) -> bytes:
    # The 9i OALL8 bind descriptor, 41 bytes: OCI's (_OAC), as a native 9.2
    # client writes it (#798) -- a lead byte, the TNS type, the flag (0x05 for an
    # OUT-capable Var, 0x01 otherwise), the max size (a ub4, then a zero max
    # array), the charset and form, the plain column's padding. The type and size must declare the
    # form the value goes in (_encode_9i_bind_value), as the thin 9i path's do
    # (#797): a sub-second datetime is a TIMESTAMP (11 bytes) and a tz-aware one a
    # TIMESTAMP WITH TIME ZONE (13) -- declared a DATE (7), the server refused it
    # with ORA-01483 -- a timedelta an INTERVAL DAY TO SECOND (11; read as text it
    # failed with ORA-01867) and an IntervalYM an INTERVAL YEAR TO MONTH (5). Text
    # rides in the session's UTF-8, so its size counts the UTF-8 bytes.
    from seerdb.common.datatypes import Var

    Flag = 0x01
    if isinstance(Value, Var) and Value.dbtype.tns_type in _DECLARED_WIDTHS:
        # A declared date / time type has its type's width, whatever the Var's
        # buffer: the value goes out in that form (_declared_value_bytes, #701).
        DType = Value.dbtype.tns_type
        (Size, Flag) = (_DECLARED_WIDTHS[DType], 0x05)
    elif isinstance(Value, Var) and Value.dbtype.tns_type in (
        TNS_TYPE_RID,
        TNS_TYPE_UROWID,
    ):
        # A ROWID / UROWID Var binds as the rowid's text, wide enough for a
        # logical one, as on the compact path (#1397); declared as itself, the
        # text bound back in drew ORA-01460 (#798).
        DType, Size, Flag = TNS_TYPE_VARCHAR, _MAX_UROWID_LENGTH, 0x05
    elif isinstance(Value, Var):
        DType, Size, Flag = Value.dbtype.tns_type, max(Value.size or 22, 1), 0x05
    elif isinstance(Value, (bool, int, float, Decimal)):
        DType, Size = 2, 22
    elif isinstance(Value, (bytes, bytearray)):
        DType, Size = TNS_TYPE_RAW, max(len(Value), 1)
    elif isinstance(Value, datetime.datetime):
        if Value.tzinfo is not None:
            DType, Size = TNS_TYPE_TIMESTAMPTZ, 13
        elif _is_wide_datetime(Value):
            DType, Size = TNS_TYPE_TIMESTAMP, 11
        else:
            DType, Size = TNS_TYPE_DATE, 7
    elif isinstance(Value, datetime.date):
        DType, Size = TNS_TYPE_DATE, 7
    elif isinstance(Value, datetime.timedelta):
        DType, Size = TNS_TYPE_INTERVALDS, 11
    elif isinstance(Value, IntervalYM):
        DType, Size = TNS_TYPE_INTERVALYM, 5
    else:
        DType, Size = TNS_TYPE_VARCHAR, max(len(str(Value).encode('utf-8')), 1)
    # A national bind declares AL16UTF16 and charset form 2 -- where a native
    # client's VARCHAR bind carries 31 / 1 (native_9i_array_dml.pcap) -- and its
    # value rides as UTF-16BE (#798; through the database charset it lost every
    # character Latin-1 lacks, as on the compact path, #174).
    National = _is_national_var(Value)
    return _OAC_OCI(
        {
            'lead': 1,
            'data_type': DType,
            'oci_plain': DType != TNS_TYPE_ADT,
            'flags': Flag,
            'precision': 0,
            'scale': 0,
            'max_length': Size,
            'max_array': 0,
            'oci_12c': False,
            'cont_flags': 0,
            'toid_length': 0,
            'version': 0,
            'charset': AL16UTF16_CHARSET if National else 0,
            'csfrm': 2 if National else 0,
            'max_chars': 0,
            'oaccolid': 0,
        }
    )


def _is_national_var(Value: object) -> bool:
    # A Var declared national (DB_TYPE_NVARCHAR / NCHAR / NCLOB): csfrm 2.
    from seerdb.common.datatypes import Var

    return isinstance(Value, Var) and getattr(Value.dbtype, 'csfrm', 1) == 2


# The wire width of each declared date / time bind type (_encode_9i_bind_oac).
_DECLARED_WIDTHS = {
    TNS_TYPE_DATE: 7,
    TNS_TYPE_TIMESTAMP: 11,
    TNS_TYPE_TIMESTAMPTZ: 13,
    TNS_TYPE_TIMESTAMPLTZ: 11,
}


def _encode_9i_bind_value(Value: object) -> bytes:
    # A 9i OALL8 bind value: the 8i form (_encode_8i_bind_value) except that text
    # goes in the session's charset, UTF-8 -- the native OALL8 session negotiates
    # the ordinary Unicode DTY, so latin-1 bytes reached a WE8ISO8859P1 database
    # as invalid UTF-8 and a bound 'é' arrived as NULL (#797).
    from seerdb.common.datatypes import Var

    if isinstance(Value, Var):
        if not Value.has_value:
            return _O8I_OUT_PLACEHOLDER
        if _is_national_var(Value) and isinstance(Value._value, str):
            # AL16UTF16, as its descriptor says (#798).
            return encode_token_rxd(Value._value.encode('utf-16-be'))
        # A declared type the value must be sent as -- a microsecond datetime
        # declared DATE goes out as a DATE (#701).
        Declared = _declared_value_bytes(Value._value, Value.dbtype.tns_type)
        if Declared is not None:
            return Declared
        return _encode_9i_bind_value(Value._value)
    if isinstance(Value, str):
        return encode_token_rxd(Value.encode('utf-8'))
    return encode_token_rxd(Value)


def encode_9i_sql_text(Sql: str) -> bytes:
    """A statement's text as a native 9i OALL8 session takes it: UTF-8, the
    session's negotiated charset (#797). The 8i form (encode_8i_sql_text) is
    latin-1, and a literal 'é' sent that way swallowed its closing quote as a
    UTF-8 lead byte (ORA-01756)."""
    return Sql.encode('utf-8')


def encode_9i_oall8_dml(
    Seq: int,
    Sql: bytes,
    StmtType: int,
    Binds: list | None = None,
    Batch: list | None = None,
    BatchErrors: bool = False,
) -> bytes:
    # 9i INSERT/UPDATE/DELETE/DDL and COMMIT/ROLLBACK over the native 64-bit
    # OALL8 (#716); the affected-row count comes back in the response OER
    # (decode_9i_oall8_dml_response). `Batch` holds an array DML's further rows
    # (#798).
    return _encode_9i_oall8(Seq, Sql, StmtType, Binds or [], Batch, BatchErrors)


def encode_9i_oall8_query(Seq: int, Sql: bytes, Binds: list | None = None) -> bytes:
    # 9i SELECT over the native 64-bit OALL8 (#792): the 64-bit execute with the
    # FETCH option set, so the reply carries the fv2 describe + the first row
    # batch; encode_9i_oall8_fetch pulls the rest. The reply is the shared fv2
    # DCB/RXD stream (8i and 9i are both field_version 2), so the dialect reuses
    # recv_rows to decode it.
    return _encode_9i_oall8(Seq, Sql, O8I_STMT_SELECT, Binds or [])


# The native 9i array-fetch (TTI_ALL8 0x5e, FETCH option, no SQL) — the 64-bit
# counterpart of encode_8i_oall8_fetch (#792). Byte-reproduced from a native 9.2
# SELECT capture (native_9i_select.pcap): a fixed 195-byte frame whose only
# varying fields are the seq, the cursor id (ub4le @7), the LONG / prefetch size
# (ub4le @67) and the rows-this-call count (ub4le @151). The 8-byte pointer slots
# carry the native client's heap addresses, which the server ignores, so the
# skeleton holds the non-null ``oci.OCI_INDICATOR`` sentinel instead.
def encode_9i_oall8_fetch(
    Seq: int, Cursor: int, Count: int, LongSize: int = 0x7FFFFFFF
) -> bytes:
    # Pull up to `Count` more rows from the open cursor (#792): 8i's fetch, the
    # execute's schema (_O8I_ALL8) with the fetch option and no SQL, at a 9.2
    # client's widths (#798) -- the cursor, the LONG cap in max_long, al8i4 [1]
    # the rows. `LongSize` caps a LONG / LONG RAW column's bytes per row (the
    # server does not continue a LONG across fetches), so the caller passes a
    # large value to read the whole one and forces Count=1, as 8i does (#377).
    # Option byte 5 is 0x04 on a single-row fetch (the LONG case) and 0x00
    # otherwise -- byte-verified against both fetches of native_9i_fetch_
    # arraysize2.pcap, as the 195-byte skeleton this replaces was.
    Values = dict(_O8I_ALL8_FIXED)
    Values.update(
        seq=Seq & 0xFF,
        options=TNS_EXEC_OPTION_FETCH | ((0x04 << 16) if Count == 1 else 0),
        cursor=Cursor,
        sql_present=False,
        sql_length=0,
        prefetch_rows=0,
        max_long=min(LongSize, 0xFFFFFFFF),
        binds_present=False,
        bind_count=0,
        defines_present=True,
        define_count=0,
        al8i4_0=0,
        al8i4_1=Count,
        al8i4_7=O8I_STMT_SELECT,
    )
    return _O8I_ALL8_O9I(Values)


def encode_9i_oall8_lobop(
    Seq: int,
    Locator: bytes,
    Operation: int,
    Offset: int = 0,
    Amount: int = 0,
    Data: bytes | None = None,
) -> bytes:
    # A TTI_LOBOPS (0x60) call on a native 9i OALL8 session (#795/#796): 8i's
    # _O7_LOBOPS at a 9.2 client's widths (#798) -- the 8i (32-bit) and thin-9i
    # envelopes both draw no reply here. Its head is 91 bytes: the source
    # pointer, the locator's length (a ub8), the 1-based offset, the amount and
    # null-LOB pointers, the operation (a ub8) and the SCN array's; then the
    # locator as fetched (a ub2 length and the body: 86 bytes for a CLOB / BLOB,
    # more for a BFILE) and, when the operation carries one, the ub4 short
    # amount. The pointers are the native client's heap addresses, which the
    # server ignores, so the non-null oci.OCI_INDICATOR stands in. Matches a
    # native 9.2 sqlplus CLOB READ (native_9i_clob_read.pcap) byte for byte, as
    # the hand-built head it replaces did; FILE_OPEN, GET_LENGTH and FILE_CLOSE
    # are live-verified on 9.2 (a BFILE read end to end). The LOB object's
    # calls (#798) match a native OCI client's (native_9i_lob_ops.pcap): the
    # amount is GET_LENGTH's / GET_CHUNK_SIZE's 0, OPEN's mode, TRIM's new length,
    # a WRITE's count; IS_OPEN and CLOSE carry none. A WRITE's `Data` follows as
    # TTI_LOB content, framed as the compact path frames it (`0e 03 58 59 5a`).
    Values = {
        'seq': Seq & 0xFF,
        'token_number': None,
        'source_present': True,
        'source_length': len(Locator),
        'dest_present': False,
        'dest_length': 0,
        'short_source_offset': Offset,
        'short_dest_offset': 0,
        'charset_present': False,
        'short_amount_present': True,
        'null_lob_present': False,
        'operation': Operation,
        'scn_present': False,
        'scn_length': 0,
        'locator': Locator,
        'short_amount': Amount & 0xFFFFFFFF,
    }
    Values.update(_O7_LOBOP_FLAGS.get(Operation, {}))
    Out = _O7_LOBOPS_O9I(Values)
    if Data is not None:
        Out += bytes([TTI_LOB]) + _o7_lob_value(Data)
    return Out


def decode_9i_oall8_lob_value(Data: bytes, Operation: int) -> tuple[int | None, bytes]:
    # A 9i OALL8 LOB call's reply (#798), 8i's (_O7_LOBOPS_REPLY) at a 9.2
    # client's widths: an RPA with the locator as the server now sees it (a ub2
    # big-endian length and the body, without the ub2 a fetched locator opens
    # with -- the LOB object puts it back, LOB._refresh; a WRITE updates it), then
    # the call's value -- a ub4 (GET_LENGTH's and GET_CHUNK_SIZE's size, OPEN's
    # mode, TRIM's new length, the amount a WRITE wrote), IS_OPEN's single byte,
    # CLOSE's nothing -- then the status. Read from a native 9.2 OCI client
    # (native_9i_lob_ops.pcap). Returns (value, locator); a reply that is a bare
    # status (an error) gives (None, b''), for the caller to raise.
    if Data[:1] != bytes([TTI_RPA]):
        return (None, b'')
    Flags = {'short_amount_present': True, 'null_lob_present': False}
    Flags.update(_O7_LOBOP_FLAGS.get(Operation, {}))
    (Reply, _) = _O7_LOBOPS_REPLY_FROM_O9I(Data, Flags)
    if Operation == TNS_LOB_OP_IS_OPEN:
        return (Reply['flag'], bytes(Reply['locator']))
    return (Reply.get('short_amount'), bytes(Reply['locator']))


def encode_9i_oall8_close_cursors(Seq: int, Cursors: list[int]) -> bytes:
    # The close of a finished cursor on a native 9i OALL8 session (#798),
    # piggybacked ahead of the next call as a native 9.2 OCI client sends it
    # (native_9i_array_dml.pcap): the shared CLOSE_CURSORS at a 9.2 client's
    # widths -- `11 69`, a seq, the array's pointer, the count as a ub8 and the
    # cursor id as a ub4. Without it every statement's cursor stayed open and a
    # session failed at open_cursors (ORA-01000 under ORA-00604 at the 299th
    # statement). The native client only ever closes one at a time, so each
    # cursor gets a piggyback of its own, each taking a seq (Seq on).
    return b''.join(
        _CLOSE_CURSORS_O9I(
            {
                'seq': (Seq + Offset) & 0xFF,
                'token_number': None,
                'cursors_present': True,
                'count': 1,
                'cursors': [{'cursor': Cursor & 0xFFFFFFFF}],
            }
        )
        for (Offset, Cursor) in enumerate(Cursors)
    )


def encode_9i_oall8_lob_read(
    Seq: int, Locator: bytes, Amount: int, Offset: int = 1
) -> bytes:
    # A CLOB / BLOB / BFILE READ on a native 9i OALL8 session (#795): like 8i, one
    # call with a large `Amount` reads the whole value (chars for a CLOB, bytes for
    # a BLOB / BFILE); the reply is the shared `0e fe <chunks> 00`
    # (decode_fv2_lob_chunks).
    return encode_9i_oall8_lobop(Seq, Locator, TNS_LOB_OP_READ, Offset, Amount)


# --- 9i native OALL8 SELECT reply decode (#792) ---
# The 9i OALL8 (0x5e) SELECT reply is OCI fixed-width framing -- not the thin
# variable-width form decode_packet reads -- in schemas shared with 8i where 8i
# has them (#798): the describe (_O9I_DESCRIBE), each row batch's header
# (_O9I_RXH), rows of value-only cells (a ub1 length + bytes, 0xFE-chunked past
# 252, 0xFF for NULL; 8i's LOB / UROWID / ROWID / LONG cells for those columns),
# a bit vector between rows (TTI_BVC: token + ub2 count + ceil(ncols/8) bytes, a
# clear bit meaning the column repeats the previous row), and the status
# (_O9I_STATUS) after the session-state RPA (_O8I_RPA). RE'd and live-verified
# against native_9i_select.pcap / native_9i_fetch_arraysize2.pcap.
_DESCRIBE_GIVEN = {'oci_12c': False, 'has_uds': False}


# The type codes a 9.2 OALL8 describe gives a typed column: the dictionary's
# (col$.type#) -- 58 an opaque type (XMLTYPE), 121 an object, 122 a nested table,
# 123 a VARRAY -- where thin describes each as TNS_TYPE_ADT, its type named beside
# it (native_9i_objects.pcap; XMLTYPE read live).
_O9I_OALL8_TYPED = frozenset((58, 121, 122, 123))


def _o9i_oall8_columns(Columns: list) -> list[dict]:
    # The describe's columns, shaped like decode_8i_dcb_describe's, so the shared
    # row and cursor machinery is unchanged. A typed column takes thin's type and
    # carries its type's identity, for the cursor to describe the type with.
    Out = []
    for Col in Columns:
        Typed = Col['data_type'] in _O9I_OALL8_TYPED
        Shaped = {
            'data_type': TNS_TYPE_ADT if Typed else Col['data_type'],
            'data_length': Col['buffer_size'],
            'data_scale': Col['scale'],
            'precision': Col['precision'],
            'max_size': Col['max_size'],
            'charset': Col['charset'],
            'csfrm': Col['csfrm'],
            'null_ok': 0 if Col['null_ok'] == 0 else 1,
            'domain_schema': None,
            'domain_name': None,
            'column_name': bytes(Col.get('name') or b'').decode('latin-1'),
        }
        if Typed:
            Shaped['type_oid'] = bytes(Col.get('toid') or b'')
            Shaped['type_schema'] = _fv2_type_name(Col.get('type_schema'))
            Shaped['type_name'] = _fv2_type_name(Col.get('type_name'))
        Out.append(Shaped)
    return Out


def decode_9i_oall8_describe(Data: bytes) -> tuple[list[dict], bytes]:
    # The 9i OALL8 TTI_DCB describe (_O9I_DESCRIBE) and the bytes after it (the
    # row stream / the status). A describe that runs off the end of a packet
    # raises Truncated for the reader to read on, as 8i's does (#1226).
    if Data[:1] != bytes([TTI_DCB]):
        raise DataError('not a 9i OALL8 describe')
    try:
        (Describe, Rest) = _O9I_DESCRIBE_FROM_OCI(Data, _DESCRIBE_GIVEN)
    except IndexError as Exc:
        raise Truncated(f'9i OALL8 describe: {Exc}') from Exc
    return (_o9i_oall8_columns(Describe['columns']), Rest)


def _o9i_oall8_cell(Data: bytes) -> tuple[bytes | None, bytes]:
    # One 9i OALL8 row cell: NULL (0xFF), else a value the OCI codec frames (a
    # ub1 length, or 0xFE-chunked past 252 bytes). Returns (raw-bytes-or-None,
    # rest). The caller turns the bytes into a Python value with the column.
    if Data[0] == 0xFF:
        return (None, Data[1:])
    return _OCI.read_value(Data)


def _o9i_oall8_object_cell(Col: dict, Data: bytes) -> tuple[object, bytes]:
    # An object or collection column's cell in a 9i OALL8 row (_O9I_OBJECT_CELL):
    # None for a NULL value (no image), else an ObjectImage the cursor turns into
    # a DbObject once it has described the type, as thin's (_read_object_column).
    from seerdb.common.dbobject import ObjectImage

    (Cell, Rest) = _O9I_OBJECT_CELL_FROM_O9I(Data)
    if not Cell['image_length']:
        return (None, Rest)
    return (
        ObjectImage(
            Col.get('type_oid', b''),
            Col.get('type_schema'),
            Col.get('type_name'),
            Col.get('charset'),
            bytes(Cell['image']),
        ),
        Rest,
    )


# The LOB columns whose 9i OALL8 row cell is a locator, not an inline value.
_O9I_OALL8_LOB_TYPES = frozenset((TNS_TYPE_CLOB, TNS_TYPE_BLOB, TNS_TYPE_BFILE))


def _o9i_oall8_lob_cell(Type: int, Data: bytes) -> tuple[object, bytes]:
    # A LOB column's cell in a 9i OALL8 row (#795): 8i's without its trailer
    # (_O9I_LOB_CELL) -- a ub4 locator size, then, when it is not zero, the
    # locator as a ub1-length value (a ub2 length and the body, 86 bytes for a
    # CLOB / BLOB). A NULL LOB is the zero size alone (reading a length byte after
    # it took the next row's token as one and desynced the stream); EMPTY_CLOB /
    # EMPTY_BLOB carry a real locator that reads back empty. Returns a LOB carrying
    # the locator, for the dialect to read (resolve_lobs) or hand back.
    from seerdb.common.lob import LOB

    (Cell, Rest) = _O9I_LOB_CELL_FROM_O9I(Data)
    if not Cell['length']:
        return (None, Rest)
    return (LOB(Type, bytes(Cell['locator'])), Rest)


def _o9i_oall8_rowid_cell(Data: bytes) -> tuple[str, bytes]:
    # A 9i OALL8 ROWID cell: 8i's without its trailer (_O9I_ROWID_CELL), a size
    # and the rowid at a 9.2 client's alignment (_O8I_ROWID_FIELDS: data object,
    # file, block, slot) -- 16 bytes, read live on 9.2 against ROWIDTOCHAR and
    # DBMS_ROWID's object / file / block / row -- rendered as the extended rowid
    # text. A NULL one is the 0xFF every NULL cell is, which the caller reads
    # first.
    from seerdb.common.types import rowid_to_string

    (Cell, Rest) = _O9I_ROWID_CELL_FROM_O9I(Data)
    return (
        rowid_to_string(
            Cell['rowid_object'],
            Cell['rowid_file'],
            Cell['rowid_block'],
            Cell['rowid_slot'],
        ),
        Rest,
    )


def _o9i_oall8_urowid_cell(Data: bytes) -> tuple[str | None, bytes]:
    # A 9i OALL8 UROWID cell: 8i's without its trailer (_O9I_UROWID_CELL) -- a
    # ub2 size and, when it is not zero, the rowid bytes (a type tag, then the
    # body) as an ordinary value, a ub1 length or 0xFE chunks past 252 bytes; a
    # NULL is the zero size alone. Read live on 9.2 for a physical rowid
    # (`0d00 0d 01...`) and an index-organized table's logical ones (`6c00 6c
    # 02...`, and a 409-byte one, `9901 fe ff... 9a... 00`).
    from seerdb.common.types import urowid_to_string

    (Cell, Rest) = _O9I_UROWID_CELL_FROM_O9I(Data)
    if not Cell['length']:
        return (None, Rest)
    return (urowid_to_string(bytes(Cell['urowid'])), Rest)


def decode_9i_oall8_exec_response(
    Data: bytes, Columns: list, PrevRow: list | None = None
) -> tuple[list, bytes, list | None]:
    # Decode a 9i OALL8 execute / fetch row stream (RXH + RXD + inter-row BVC) up
    # to the status, mirroring decode_8i_exec_response but at the OCI fixed widths
    # (the 50-byte RXH, value-only cells). Returns (rows, terminal, last_row); a
    # stream cut inside a header or a row raises Truncated for the reader to read
    # on. Values decode with the column's charset (decode_value), as the 9i thin
    # path does.
    from seerdb.common.types import decode_value

    Rows: list = []
    Rest = Data
    Last = PrevRow
    Vector: bytes | None = None
    try:
        while Rest:
            Token = Rest[0]
            if Token == TTI_RXH:
                # The row header (_O9I_RXH): its column bit vector, when it names
                # one, says which columns the first row sends; a FOR UPDATE's
                # rowid behind it is skipped, the columns carrying the row.
                (Header, Rest) = _O9I_RXH_FROM_O9I(Rest)
                Vector = bytes(Header['vector']) if Header['vector'] else None
            elif Token == TTI_BVC:
                # A bit vector for the NEXT row: token + ub2 count + the vector.
                Rest = Rest[1:]
                (_, Rest) = (int.from_bytes(Rest[:2], 'little'), Rest[2:])
                VecLen = (len(Columns) + 7) // 8
                Vector = bytes(Rest[:VecLen])
                Rest = Rest[VecLen:]
            elif Token == TTI_RXD:
                Rest = Rest[1:]
                Row: list = []
                for ColIdx, Col in enumerate(Columns):
                    if (
                        Vector is not None
                        and not (Vector[ColIdx >> 3] >> (ColIdx & 7)) & 1
                    ):
                        # Repeated column: reuse the previous row's value.
                        Row.append(
                            Last[ColIdx] if Last and ColIdx < len(Last) else None
                        )
                        continue
                    if Col.get('data_type') in _O9I_OALL8_LOB_TYPES:
                        (Lob, Rest) = _o9i_oall8_lob_cell(Col['data_type'], Rest)
                        Row.append(Lob)
                        continue
                    if Col.get('data_type') in _LONG_DATA_TYPES:
                        # A LONG / LONG RAW cell is 8i's (_O8I_LONG_CELL): the
                        # value -- 0xFE chunks, or a bare zero for NULL -- then a
                        # ub2 indicator and a ub2 return code: `fe 02 6869 00 0000
                        # 0000` for 'hi', `00 ffff 7d05` for NULL, read live on
                        # 9.2. Unread, the four bytes shifted every column after
                        # the LONG (#798).
                        (Cell, Rest) = _O8I_LONG_CELL_FROM_O9I(Rest)
                        Row.append(
                            None
                            if Cell['value'] is None
                            else decode_value(Col, bytes(Cell['value']))
                        )
                        continue
                    if (
                        Col.get('data_length', None) == 0
                        and Col.get('data_type') not in _LONG_DATA_TYPES
                    ):
                        # A column described with a zero data length -- `SELECT
                        # NULL` -- is always NULL and sends no cell at all, not
                        # even the 0xFF (the OALL8 form of #682 / #1185). A LONG
                        # is described with a zero length too, and does carry
                        # data.
                        Row.append(None)
                        continue
                    if Col.get('data_type') == TNS_TYPE_ADT:
                        (Value, Rest) = _o9i_oall8_object_cell(Col, Rest)
                        Row.append(Value)
                        continue
                    if Col.get('data_type') == TNS_TYPE_REFCURSOR:
                        # A CURSOR(...) column (_O9I_CURSOR_CELL): the nested
                        # cursor comes opened and described, as a REF CURSOR OUT
                        # bind's does -- (cursor id, columns), its rows for the
                        # dialect to fetch by that id.
                        (Cell, Rest) = _O9I_CURSOR_CELL_FROM_OCI(Rest, _DESCRIBE_GIVEN)
                        Row.append(
                            (Cell['cursor'], _o9i_oall8_columns(Cell['columns']))
                        )
                        continue
                    if Col.get('data_type') == TNS_TYPE_UROWID:
                        (Text, Rest) = _o9i_oall8_urowid_cell(Rest)
                        Row.append(Text)
                        continue
                    if Col.get('data_type') in (TNS_TYPE_RID, TNS_TYPE_ROWID) and (
                        Rest[0] != 0xFF
                    ):
                        (Text, Rest) = _o9i_oall8_rowid_cell(Rest)
                        Row.append(Text)
                        continue
                    (Raw, Rest) = _o9i_oall8_cell(Rest)
                    Row.append(None if Raw is None else decode_value(Col, Raw))
                Rows.append(Row)
                Last = Row
                Vector = None
            else:
                break
    except IndexError as Exc:
        raise Truncated(f'9i OALL8 rows: {Exc}') from Exc
    return (Rows, Rest, Last)


def _o9i_oall8_oer(Terminal: bytes) -> bytes:
    # The status OER (0x04) in a 9i OALL8 reply's terminal, past a leading TTI_RPA
    # (0x08) session-state piggyback, which is 8i's (_O8I_RPA, 27 bytes): read
    # through, so the OER is taken straight after it -- a first-parse RPA carries
    # value bytes that collide with the OER token, so scanning for a 0x04 could
    # land inside it. `Terminal` is the bytes from the RPA (a SELECT reply's
    # post-row tail) or from the OER itself; a caller with a leading TTI_IOV /
    # TTI_RXD strips those first.
    Rest = Terminal
    if Rest[:1] == bytes([TTI_RPA]):
        try:
            (_, After) = _O8I_RPA_FROM_O9I(Rest)
        except (IndexError, DataError):
            After = b''
        if After[:1] == bytes([TTI_OER]) and len(After) >= 5 and not any(After[2:5]):
            return After
    # No (or an unexpected) RPA: scan for the first 0x04 that begins a real OER head
    # (its leading call-type field is small, so the three bytes after it are zero).
    At = Rest.find(bytes([TTI_OER]))
    while At >= 0:
        if At + 5 <= len(Rest) and not any(Rest[At + 2 : At + 5]):
            return Rest[At:]
        At = Rest.find(bytes([TTI_OER]), At + 1)
    return b''


def decode_9i_oall8_cursor_id(Terminal: bytes) -> int:
    # The server cursor the fetch loop pulls more rows from, and the next call
    # closes: the status's cursor (_O9I_STATUS, a ub2). It rises per statement
    # until closed, so each open statement is fetched by its own id -- a fixed id
    # drew ORA-01002 on the second query. 0 when the terminal holds no whole
    # status (an error / empty result -- no fetch). Read as one byte it was right
    # for a session's first 255 statements: the 256th is `00 01` (#798).
    Status = _o9i_oall8_status_or_none(Terminal)
    return Status['cursor'] if Status else 0


def decode_9i_oall8_dml_response(
    Terminal: bytes, Applied: bool = False
) -> tuple[int, int, str | None]:
    # The affected-row count, ORA code and message a 9i OALL8 non-query (DML / DDL
    # / transaction-control) reply carries (#716): the status's rows -- where a
    # SELECT reply reports its batch size (UPDATE of 2 rows -> 2, INSERT / DELETE
    # -> 1, DDL / COMMIT -> 0; read live on 9.2) -- code and message. A failed
    # statement reports no count, unless `Applied`: an array DML that fails at a
    # row has applied the rows before it, and the status counts them (#798; 1 of
    # rows 4, 1-duplicate, 5 in native_9i_array_dml.pcap). Returns (rowcount, code,
    # message); raises Truncated if the status is cut short, for the reader to read
    # on.
    Status = decode_9i_oall8_status(Terminal)
    if Status is None:
        return (0, 0, None)
    Code = Status['code']
    return (0 if Code and not Applied else Status['rows'], Code, Status['message'])


def decode_9i_oall8_batch_errors(Terminal: bytes) -> list[dict]:
    # The per-row errors of a 9i OALL8 array DML in batch-errors mode (#798), as
    # {offset, code, message}, or [] for a status with none. The server applies
    # the good rows and answers ORA-24381 with the status's three arrays
    # (_O9I_STATUS): error i hit row offsets[i] with codes[i] and messages[i].
    # Read from native 9.2 statuses with one and with two failed rows
    # (native_9i_array_dml.pcap).
    Status = _o9i_oall8_status_or_none(Terminal)
    if not Status or Status['code'] != 24381 or 'batch_codes' not in Status:
        return []
    return [
        {
            'offset': Offset['offset'],
            'code': Code['code'],
            'message': bytes(Message['text']).decode('utf-8', 'replace').rstrip(),
        }
        for (Code, Offset, Message) in zip(
            Status['batch_codes'], Status['batch_offsets'], Status['batch_messages']
        )
    ]


def decode_9i_oall8_error_position(Terminal: bytes) -> int:
    # Where in the statement a 9i OALL8 status's error is (#798), the 0-based
    # character the server points at (#2263's field): the status's position -- 7
    # for `SELECT nosuchcol FROM dual`, read live on 9.2. 0 with no whole status.
    Status = _o9i_oall8_status_or_none(Terminal)
    return Status['position'] if Status else 0


def decode_9i_oall8_warn_flags(Terminal: bytes) -> int:
    # A 9i OALL8 status's warning flags (#798): bit 0x20 is a CREATE whose object
    # compiled with errors (0x21 live on 9.2 for a broken procedure, 0 for the same
    # one compiled clean), which the call otherwise reports as a success --
    # cursor.warning (#2262).
    Status = _o9i_oall8_status_or_none(Terminal)
    return Status['warnings'] if Status else 0


def decode_9i_oall8_dml_rowid(Terminal: bytes) -> str | None:
    # The rowid of the row a 9i OALL8 DML touched (#1079), or None: the status's
    # (_O9I_STATUS), read from native 9.2 INSERT and UPDATE replies, whose tail
    # repeats it as a physical UROWID. A status with no block (DDL, a failure) has
    # none; one that touched nothing keeps the previous statement's, which the
    # cursor sorts out by the row count, as on 8i / 9i.
    from seerdb.common.types import rowid_to_string

    Status = _o9i_oall8_status_or_none(Terminal)
    if not Status or Status['code'] or not Status['rowid_block']:
        return None
    return rowid_to_string(
        Status['rowid_object'],
        Status['rowid_file'],
        Status['rowid_block'],
        Status['rowid_slot'],
    )


def decode_9i_oall8_bind_directions(Data: bytes, NumBinds: int) -> list[int] | None:
    # The direction of each bind, from a 9i OALL8 block reply's IOV bind prompt
    # (_O9I_IOV), or None when the reply opens with none (a block that failed
    # answers with the bare status). One mask per bind in bind order, the masks
    # the compact path reads (0x10 OUT, 0x20 IN, 0x30 IN OUT;
    # decode_fv2_bind_directions): `10 10 20` live on 9.2 for `SELECT n, s INTO :n,
    # :s ... WHERE n = :k`. The prompt counts its binds itself; a count that is not
    # the call's is a prompt this reader does not know, and gives None.
    if Data[:1] != bytes([TTI_IOV]):
        return None
    try:
        (Iov, _) = _O9I_IOV_FROM_O9I(Data)
    except (IndexError, DataError):
        return None
    return list(Iov['directions']) if Iov['binds'] == NumBinds else None


def _o9i_oall8_refcursor_cell(Data: bytes) -> tuple[tuple[int, list], bytes]:
    # A REF CURSOR OUT bind's cell in a 9i OALL8 block reply (_O9I_REFCURSOR_OUT):
    # a lead byte (0x2c), the opened cursor's describe -- the body a query's
    # TTI_DCB carries -- its cursor id, and the indicator and return code. Read
    # live on 9.2 for `OPEN :1 FOR` two- and one-column queries (cursor 2, then
    # 4). Returns ((cursor id, columns), rest); the caller fetches the rows by
    # that id.
    (Cell, Rest) = _O9I_REFCURSOR_OUT_FROM_OCI(Data, _DESCRIBE_GIVEN)
    return ((Cell['cursor'], _o9i_oall8_columns(Cell['columns'])), Rest)


def decode_9i_oall8_block_out(
    Data: bytes, NumBinds: int, NumOut: int, Cursors: frozenset[int] = frozenset()
) -> tuple[list, int, int, str | None]:
    # The OUT / IN OUT values a 9i OALL8 PL/SQL block returns (#794). The reply is
    # the IOV bind prompt, then (when the block writes binds) a TTI_RXD carrying one
    # value-only cell per OUT bind -- each a ub1 length, that many value bytes, and
    # a ub4 indicator; a NULL OUT is a zero length. Then the RPA + OER status. The
    # IOV is a fixed 50-byte head plus one direction byte per bind, so the token
    # after it sits at offset 50 + NumBinds (live-verified for 1 and 3 binds).
    # Returns (out_values, rowcount, code, message); out_values holds the raw value
    # bytes per OUT bind (None for a NULL), for the caller to decode per Var type.
    # A block that fails at run time (a SELECT ... INTO matching nothing) answers
    # with the bare status, no IOV: skipping the IOV's length there landed past the
    # status and read the error as success.
    (OutValues, Rest) = _o9i_oall8_block_parts(Data, NumBinds, NumOut, Cursors)
    # `Rest` now sits on the RPA + OER, so read the status from there rather than
    # rescanning `Data` from the start -- the IOV and the OUT RXD hold value bytes
    # that collide with the OER token, which a from-the-start scan can land on
    # (a RETURNING run inside a statement sequence read a bogus code otherwise).
    (RowCount, Code, Message) = decode_9i_oall8_dml_response(Rest)
    return (OutValues, RowCount, Code, Message)


def decode_9i_oall8_block_cursor(
    Data: bytes, NumBinds: int, NumOut: int = 0, Cursors: frozenset[int] = frozenset()
) -> int:
    # The cursor a 9i OALL8 block reply's status names, for the close that follows
    # (#798), read past the IOV and the OUT values as decode_9i_oall8_block_out
    # reads the status: a scan from the start landed on a `04` inside a 300-bind
    # IOV, and closing that bogus cursor (256) drew ORA-00600 [12209] and lost the
    # session.
    return decode_9i_oall8_cursor_id(
        _o9i_oall8_block_parts(Data, NumBinds, NumOut, Cursors)[1]
    )


def _o9i_oall8_block_parts(
    Data: bytes, NumBinds: int, NumOut: int, Cursors: frozenset[int]
) -> tuple[list, bytes]:
    # A 9i OALL8 block reply's OUT values, and the bytes after them -- the RPA and
    # the status (decode_9i_oall8_block_out).
    Rest = Data
    if Data[:1] == bytes([TTI_IOV]):
        (_, Rest) = _O9I_IOV_FROM_O9I(Data)  # the bind prompt (_O9I_IOV)
    OutValues: list = []
    if NumOut > 0 and Rest[:1] == bytes([TTI_RXD]):
        Rest = Rest[1:]
        for Index in range(NumOut):
            Length = Rest[0]
            if Index in Cursors and Length not in (0, 0xFF):
                # A REF CURSOR: (cursor id, columns), its rows still to fetch.
                (Opened, Rest) = _o9i_oall8_refcursor_cell(Rest)
                OutValues.append(Opened)
                continue
            if Length == 0xFF:
                # An OUT bind the block never assigned (a RETURNING ... INTO that
                # matched no row): 8i's form (_O8I_OUT_UNASSIGNED), 0xFF and the
                # indicator 3105 -- `ff 210c`, the compact path's `ff 02 0c 21`
                # (#801). Reading a length and four bytes after it ran into the
                # status.
                (_, Rest) = _O8I_OUT_UNASSIGNED_FROM_O9I(Rest)
                OutValues.append(None)
                continue
            # 8i's row cell (_O8I_CELL): the value -- a ub1 length, or 0xFE and
            # chunks past 252 bytes (read as one length, a long OUT value kept its
            # chunk lengths) -- a ub2 indicator (-1 for NULL) and a ub2 return code
            # (1405).
            (Cell, Rest) = _O8I_CELL_FROM_O9I(Rest)
            OutValues.append(bytes(Cell['value']) if Cell['value'] else None)
    return (OutValues, Rest)


def decode_9i_oall8_status(Terminal: bytes) -> dict | None:
    # The ORA code and message a 9i OALL8 reply's status carries, with its rows,
    # or None for a terminal with no status. Raises Truncated if the status's
    # head is cut short, for the reader to read on.
    Status = _o9i_oall8_status_fields(Terminal)
    if Status is None:
        return None
    return {
        'code': Status['code'],
        'message': Status['message_text'],
        'rows': Status['rows'],
    }


def _o9i_oall8_status_or_none(Terminal: bytes) -> dict | None:
    # The status's fields, or None for one that is not there or cut short: the
    # field readers answer their default then, as they did reading offsets.
    try:
        return _o9i_oall8_status_fields(Terminal)
    except Truncated:
        return None


def _o9i_oall8_status_fields(Terminal: bytes) -> dict | None:
    # The fields of a 9i OALL8 reply's status (_O9I_STATUS), past any RPA ahead of
    # it, or None when the terminal holds none. A status whose tail does not read
    # -- a form no capture has shown yet -- gives its head's fields and its
    # message found by its text, as every status did before the schema, rather
    # than failing a reply the code could still be read from. `message_text` is
    # the message as str (or None). Raises Truncated if the head is cut short.
    Oer = _o9i_oall8_oer(Terminal)
    if not Oer:
        return None
    try:
        (Status, _) = _O9I_STATUS_FROM_O9I(Oer)
        Message = Status.get('message')
        Status['message_text'] = (
            bytes(Message).split(b'\x00')[0].rstrip(b'\n').decode('latin-1', 'replace')
            or None
            if Message
            else None
        )
        return Status
    except (IndexError, DataError):
        pass
    try:
        (Status, _) = _O9I_STATUS_HEAD_FROM_O9I(Oer)
    except (IndexError, DataError) as Exc:
        raise Truncated('9i OALL8 status cut short') from Exc
    Code = Status['code']
    Message = None
    # The message naming the code: a batch-errors status (ORA-24381) lists the
    # rows' own messages ahead of its own.
    At = Oer.find(f'ORA-{Code:05d}'.encode()) if Code else -1
    if At < 0:
        At = Oer.find(b'ORA-')
    if At > 0:
        Message = (
            bytes(Oer[At:]).split(b'\x00')[0].rstrip(b'\n').decode('latin-1', 'replace')
            or None
        )
    Status['message_text'] = Message
    return Status


def o9i_oall8_terminal_complete(Terminal: bytes) -> bool:
    # Whether a 9i OALL8 reply's post-row terminal has arrived whole (its OER head,
    # at least): a reply split mid-status is read on, as 8i's is (#2280).
    try:
        return decode_9i_oall8_status(Terminal) is not None
    except (IndexError, Truncated):
        return False


def decode_9i_oall8_terminal_error(Terminal: bytes) -> tuple[int, str | None]:
    # The ORA code and message a 9i OALL8 status carries, or (0, None). ORA-01403
    # (end of fetch) is not an error here -- the caller treats it as the fetch end.
    Status = decode_9i_oall8_status(Terminal)
    if not Status or not Status['code']:
        return (0, None)
    return (Status['code'], Status['message'])


def decode_8i_cursor_id(Terminal: bytes) -> int:
    # The server-assigned cursor id, which drives the 8i fetch loop and is
    # closed when its statement is done (#2286): the status's cursor, a
    # little-endian ub2, as its RPA's third parameter has it too. Read
    # big-endian it agreed below 256 and made 256 a 0, which ended the fetch
    # after one row (#2285): captured on 8.1.7, cursor 256 is `00 01`. 0 for a
    # reply with no whole status (an empty result set), which suppresses the
    # fetch, and for a statement refused at parse, which has none.
    Status = _o8i_status_or_none(Terminal)
    return Status['cursor'] if Status else 0


def o8i_terminal_complete(Terminal: bytes) -> bool:
    """Whether an 8i reply's post-row terminal has arrived whole (#2280).

    8i splits a long reply into packets at no fixed point and marks none as the
    last, and its status ends in zero fields, so a reply cut short a few bytes
    before its end would still decode by offsets. Its status (`_O8I_STATUS`)
    is whole when every field, the message too, has its bytes. A terminal that
    is not a status is taken as whole, as before."""
    try:
        _o8i_status(Terminal)
    except (IndexError, Truncated):
        return False
    except DataError:
        pass
    return True


def decode_8i_terminal_error(Terminal: bytes) -> tuple[int, str | None]:
    """The ORA code and message an 8i reply's status carries, or (0, None)
    for none (#2314): its code and, when that is set, the message that ends
    it. Captured on 8.1.7, a fetch failing with ORA-01476: code `c4 05`,
    message `24 ORA-01476: divisor is equal to zero\\n`. Text is latin-1
    (WE8ISO8859P1), as 8i's every value."""
    Status = _o8i_status_strict(Terminal)
    if not Status or not Status['code']:
        return (0, None)
    Message = bytes(Status['message']).decode('latin-1', 'replace').rstrip()
    return (Status['code'], Message or None)


# The 8i cells that are not a value and the trailer (`_o8i_located_cell`).
_O8I_LOCATED_CELLS = frozenset(
    (TNS_TYPE_CLOB, TNS_TYPE_BLOB, TNS_TYPE_BFILE, TNS_TYPE_RID, TNS_TYPE_UROWID)
)


def _o8i_located_cell(Type: int, Data: bytes) -> tuple[object, bytes]:
    # A LOB, ROWID or UROWID cell of an 8i row and the bytes after it: a LOB
    # the connection resolves after the fetch (_resolve_8i_lobs), an
    # EMPTY_CLOB reading back as ''; a ROWID the extended base64 form
    # ROWIDTOCHAR gives (#385); a UROWID the "*"-prefixed form of the 10g+
    # path. A NULL UROWID is a zero length, which a one-byte reading left a
    # byte behind, and the fetch then failed with ORA-01002 (#2328).
    from seerdb.common.lob import LOB
    from seerdb.common.types import rowid_to_string, urowid_to_string

    if Type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB, TNS_TYPE_BFILE):
        (Cell, Data) = _O8I_LOB_CELL_FROM_O8I(Data)
        return (LOB(Type, bytes(Cell['locator'])) if Cell['length'] else None, Data)
    if Type == TNS_TYPE_RID:
        (Cell, Data) = _O8I_ROWID_CELL_FROM_O8I(Data)
        if not Cell['size']:
            return (None, Data)
        Rowid = rowid_to_string(
            Cell['rowid_object'],
            Cell['rowid_file'],
            Cell['rowid_block'],
            Cell['rowid_slot'],
        )
        return (Rowid, Data)
    (Cell, Data) = _O8I_UROWID_CELL_FROM_O8I(Data)
    Body = Cell.get('urowid')
    return (urowid_to_string(bytes(Body)) if Body else None, Data)


def decode_8i_exec_response(
    Data: bytes, Columns: list, PrevRow: list | None = None
) -> tuple[list, bytes, list | None]:
    # Decode an 8i execute/fetch row stream (docs/PROTOCOL.md §19.10): row
    # headers (`_O7_RXH`, `_O7_VECTORS`) and rows (TTI_RXD), each a cell per
    # column (`_O8I_CELL` and the rest), up to the status. Values are WE8ISO8859P1
    # (latin-1); decode_value uses the column charset.
    #
    # 8i compresses duplicate columns: a row header's bit vector has a bit per
    # column, LSB first, and a column whose bit is clear REPEATS the previous
    # row and carries no cell in the row after it; a header with no vector
    # means every column is there. Since 8i fetches one batch per round trip,
    # a row can repeat a column from the last row of the PREVIOUS batch, so
    # the caller threads `PrevRow` in and the last decoded row back out.
    # Returns (rows, terminal, last_row) where `terminal` is the bytes from the
    # first token after the rows (for the cursor id / EOF check). A stream that
    # ends inside a header or a row raises Truncated, for the reader to read on.
    from seerdb.common.types import decode_value, reset_decode_8i, set_decode_8i

    # All 8i char data is WE8ISO8859P1 (latin-1); flag the decode so
    # decode_value picks Latin-1 rather than the UTF-8 / UTF-16 a modern session
    # would use (#366). Reset afterwards so the flag never leaks to other tiers.
    _FlagToken = set_decode_8i(True)
    Rows: list = []
    Rest = Data
    Last = PrevRow
    Vector = b''
    try:
        while Rest:
            if Rest[0] == TTI_RXH:
                (Header, Rest) = _O7_RXH_FROM_O8I(Rest)
                (Header, Rest) = _O7_VECTORS_FROM_O8I(Rest, Header)
                Vector = bytes(Header.get('bit_vector', b''))
            elif Rest[0] == TTI_RXD:
                Rest = Rest[1:]
                Row: list = []
                for ColIdx, Col in enumerate(Columns):
                    if Vector and not (Vector[ColIdx >> 3] >> (ColIdx & 7)) & 1:
                        # Repeated column: reuse the previous row's value.
                        Row.append(
                            Last[ColIdx] if Last and ColIdx < len(Last) else None
                        )
                        continue
                    Type = Col.get('data_type')
                    if Type in _O8I_LOCATED_CELLS:
                        (Value, Rest) = _o8i_located_cell(Type, Rest)
                    elif Rest[:1] == b'\xff':
                        # NULL: the trailer alone.
                        (Value, Rest) = (None, _O8I_NULL_CELL_FROM_O8I(Rest)[1])
                    else:
                        if Type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW):
                            (Cell, Rest) = _O8I_LONG_CELL_FROM_O8I(Rest)
                        else:
                            (Cell, Rest) = _O8I_CELL_FROM_O8I(Rest)
                        Value = decode_value(Col, Cell['value'])
                    Row.append(Value)
                Rows.append(Row)
                Last = Row
                Vector = b''
            else:
                break
    except IndexError as Exc:
        raise Truncated(f'8i rows: {Exc}') from Exc
    finally:
        reset_decode_8i(_FlagToken)
    return (Rows, Rest, Last)


def decode_8i_dml_response(Data: bytes) -> tuple[int, int, str | None]:
    # Decode an 8i non-query (DML / DDL / transaction-control) response
    # (docs/PROTOCOL.md §19.12): the RPA, then the status (`_O8I_STATUS`), whose
    # row count is the rows affected -- a LITTLE-endian ub4, as 8i's integers
    # are (300 = `2c 01 00 00`). Returns (rowcount, ora_code, message); a failed
    # statement reports no count, and its error is raised instead. A reply that
    # opens with neither, such as a PL/SQL block's prompt, reports none: 8i
    # answers a failed block with its status alone.
    Status = _o8i_status_strict(Data)
    if not Status:
        return (0, 0, None)
    (Code, Message) = decode_8i_terminal_error(Data)
    return (0 if Code else Status['rows'], Code, Message)


def decode_8i_dml_rowid(Data: bytes) -> str | None:
    """The rowid of the row an 8i DML touched, from its status, or None.

    The status's rowid (`_O8I_STATUS`), as on 9i (decode_fv2_dml_rowid): data
    object, file, a reserved byte, block, slot (#1079). Captured on 8.1.7:
    `31 1d 01 00 05 00 00 cf 00 00 00 02 00` for object 73009, file 5, block
    207, slot 2. As on 9i, the server leaves the previous statement's rowid in
    place when nothing was touched.
    """
    Status = _o8i_status_or_none(Data)
    if not Status or Status['code'] or not Status['rowid_block']:
        return None
    from seerdb.common.types import rowid_to_string

    return rowid_to_string(
        Status['rowid_object'],
        Status['rowid_file'],
        Status['rowid_block'],
        Status['rowid_slot'],
    )


def decode_8i_dcb_describe(Data: bytes) -> tuple[list[dict], bytes]:
    # Oracle 8i answers a query's OALL8 with a TTI_DCB (0x10) describe
    # (`_O8I_DESCRIBE`, docs/PROTOCOL.md §19.10), as column dicts shaped like
    # decode_token_dcb's, and the bytes after it: the row stream (TTI_RXH /
    # TTI_RXD) or the status, which decode_8i_exec_response consumes. A
    # column's data_length is its buffer, a ub4 -- read as one byte, a
    # VARCHAR2(4000) described as 160 (#2324) -- and its max_size the declared
    # size `_o7_max_size` gives, as on 9i. A describe wider than 8i's SDU
    # continues in the next packet with nothing saying so, and one that runs
    # off the end raises Truncated for the reader to read on (#1226).
    try:
        (Describe, Rest) = _O8I_DESCRIBE_FROM_O8I(Data)
    except IndexError as Exc:
        raise Truncated(f'8i describe: {Exc}') from Exc
    Columns: list[dict] = []
    for Oac in Describe['columns']:
        Scale = Oac['scale'] - 256 if Oac['scale'] > 127 else Oac['scale']
        Columns.append(
            {
                'data_type': Oac['data_type'],
                'data_length': Oac['max_length'],
                'data_scale': Scale,
                'precision': Oac['precision'],
                'max_size': _o7_max_size(Oac),
                'charset': Oac['charset'],
                'csfrm': Oac['csfrm'],
                'null_ok': 0 if Oac['null_ok'] == 0 else 1,
                'domain_schema': None,
                'domain_name': None,
                'column_name': Oac['name'],
            }
        )
    return (Columns, Rest)


def _o7_status(Data: bytes) -> dict | None:
    # The fields of a 9i reply's short status, from `_O7_STATUS_HEAD` and
    # `_O7_STATUS_TAIL`, after any RPA before it, or None for a reply without one
    # or too short to hold its head -- neither a rowid nor batch errors is worth
    # failing a DML over. The tail counts only when it ends where the status
    # does; otherwise the head stands alone, and only a batch-errors call and an
    # error's message need what follows.
    Rest = _skip_fv2_rpa(Data) if Data else b''
    if not Rest or Rest[0] != TTI_OER:
        return None
    try:
        (Status, Rest) = _O7_STATUS_HEAD_FROM_THIN(Rest)
    except (IndexError, Truncated, DataError):
        return None
    try:
        (Tail, Rest) = _O7_STATUS_TAIL_FROM_THIN(Rest, Status)
    except (IndexError, Truncated, DataError):
        return Status
    if not Rest:
        Status.update(Tail)
    return Status


def _fv2_message(Text: bytes) -> str | None:
    return bytes(Text).decode('utf-8', errors='replace').rstrip('\x00').rstrip() or None


def decode_fv2_oer_error(Packet: bytes) -> tuple[int, str | None]:
    # If `Packet` is a 9i OER token, return its (ora_code, message); otherwise
    # (0, None). Used to surface a parse/execute-time server error (e.g.
    # ORA-00942) with the server's own text instead of letting the caller march
    # on into a desync (#102). The message is the status's last field, read with
    # the rest of it (`_O7_STATUS_TAIL`); a long one comes in the 0xFE chunked
    # form, whose chunk lengths are not text (#810).
    if not Packet or Packet[0] != TTI_OER:
        return (0, None)
    Status = _o7_status(Packet)
    if Status is not None and 'message' in Status:
        return (Status['code'], _fv2_message(Status['message']))
    return _scan_fv2_message(Packet)


def _scan_fv2_message(Packet: bytes) -> tuple[int, str | None]:
    # A status the schema does not read whole: its code, and its message found
    # as the final DALC, the offset whose DALC consumes exactly the rest of the
    # packet -- the reading before #2284, kept for a reply that ends early.
    (ErrCode, Rest) = decode_ub4(decode_ub4(Packet[1:])[1])
    Fallback = None
    for I in range(len(Rest)):
        if not Rest[I]:
            continue
        try:
            (Value, Tail) = decode_dalc(Rest[I:])
        except DataError:
            continue
        if Tail or not Value:
            continue
        Text = bytes(Value).decode('utf-8', errors='replace').rstrip('\x00').rstrip()
        if not Text:
            continue
        # A server message opens with its own code, which makes for a decisive
        # check; anything else is kept only as a fallback.
        if Text.startswith(('ORA-', 'PLS-')):
            return (ErrCode, Text)
        if Fallback is None:
            Fallback = Text
    return (ErrCode, Fallback)


def decode_fv2_exec_response(Data: bytes, Columns: list) -> tuple[list, int]:
    # (rows, ora_code) of a 9i execute+fetch reply, as decode_fv2_exec_status
    # reads it.
    (Rows, ErrCode, _) = decode_fv2_exec_status(Data, Columns)
    return (Rows, ErrCode)


def decode_fv2_exec_status(Data: bytes, Columns: list) -> tuple[list, int, str | None]:
    # Walk the fv2 (9i) execute+fetch response stream: TTI_RXH (06) then one
    # TTI_RXD (07) per row, terminated by the short TTI_OER (04), each read from
    # its schema (#2284): `_O7_RXH`, then per column `_O7_CELL`, `_O7_LOB_CELL`
    # or `_O7_EMPTY_CELL`. Row values themselves use the version-independent
    # §11 decoders. Returns (rows, ora_code, message) where ora_code 1403 ==
    # end-of-fetch (PROTOCOL.md §19.2), and message is the status's text for an
    # error. Raised from the code alone, an error the fetch met -- ORA-01476 from
    # `SELECT 1/0` -- had no text (#2315).
    from seerdb.common.lob import LOB
    from seerdb.common.types import decode_value

    Rows: list = []
    ErrCode = 0
    Message = None
    Rest = Data
    while Rest:
        Token = Rest[0]
        if Token == TTI_RXH:
            (Header, Rest) = _O7_RXH_FROM_THIN(Rest)
            if Rest[:1] not in (bytes([TTI_RXD]), bytes([TTI_OER])):
                (Header, Rest) = _O7_VECTORS_FROM_THIN(Rest, Header)
            if Header.get('bit_vector_length'):
                # The column bit vector that compresses repeated values (#181).
                # 9.2.0.4 has sent none, repeated values or not; reading the
                # row without it would misread every value after the first
                # repeat, so a reply carrying one is refused.
                raise DataError('a 9i row header with a column bit vector')
        elif Token == TTI_RXD:
            Rest = Rest[1:]
            Row: list = []
            for Col in Columns:
                DataType = Col.get('data_type')
                if DataType in (112, 113, 114):
                    # CLOB / BLOB / BFILE: the locator's length, the locator,
                    # which the connection round-trips via TTI_LOBOPS (the fv2
                    # dialect's lob_read for CLOB/BLOB; bfile_read --
                    # FILE_OPEN/READ/CLOSE -- for BFILE), and the indicator. A
                    # NULL LOB is a zero length and the -1 indicator, `00 81 01`.
                    (Cell, Rest) = _O7_LOB_CELL_FROM_THIN(Rest)
                    Row.append(
                        LOB(DataType, Cell['locator'], charset=Col.get('charset'))
                        if Cell['length']
                        else None
                    )
                    continue
                if DataType == TNS_TYPE_ADT:
                    # An object (#2258): the 10g+ cell's framing -- type block,
                    # object OID, snapshot, version, image length, flags, the
                    # pickled image -- then the indicator. 9i's first field is
                    # a 36-byte type block, not the bare OID, so the OID is the
                    # describe's. A NULL carries the same framing with no image
                    # and the -1 indicator, `81 01` (captured on 9.2.0.4).
                    from seerdb.common.dbobject import ObjectImage

                    (Value, Rest) = _read_object_column(Rest, Col)
                    if isinstance(Value, ObjectImage) and Col.get('type_oid'):
                        Value.type_oid = Col['type_oid']
                    (_, Rest) = _O7_EMPTY_CELL_FROM_THIN(Rest)
                    Row.append(Value)
                    continue
                if (
                    Col.get('data_length', None) == 0
                    and DataType not in _LONG_DATA_TYPES
                ):
                    # A column described with a zero data length -- `SELECT NULL`
                    # -- is always NULL and sends no value at all, only the
                    # indicator (#1185). The 9i form of #682. A LONG is
                    # described with a zero length too, and does carry data.
                    (_, Rest) = _O7_EMPTY_CELL_FROM_THIN(Rest)
                    Row.append(None)
                    continue
                # The value, then the indicator. A LONG / LONG RAW streams in
                # the 0xfe chunked form (in batch fetch inline, no trailing
                # descriptor).
                if DataType in _LONG_DATA_TYPES:
                    (Cell, Rest) = _O7_LONG_CELL_FROM_THIN(Rest)
                else:
                    (Cell, Rest) = _O7_CELL_FROM_THIN(Rest)
                Val = Cell['value']
                if Cell['indicator'] == -1 or Val is None:
                    Row.append(None)
                elif DataType in (TNS_TYPE_RID, TNS_TYPE_ROWID, TNS_TYPE_UROWID):
                    # Defined as VARCHAR (see _o7_define_entry), so the value is
                    # already the rowid text — decode it directly, not via the
                    # native ROWID decoder.
                    Row.append(Val.decode('ascii', 'replace') if Val else None)
                else:
                    Row.append(decode_value(Col, Val))
            Rows.append(Row)
        elif Token == TTI_OER:
            (ErrCode, Message) = decode_fv2_oer_error(Rest)
            if ErrCode in (0, ORA_NO_DATA_FOUND):
                Message = None
            break
        else:
            break
    return (Rows, ErrCode, Message)


def decode_fv2_dml_response(Data: bytes) -> tuple[int, int]:
    # 9i DML (INSERT/UPDATE/DELETE) over TTI_ALL7: a single parse-executes the
    # statement; the response is an RPA piggyback followed by the short OER
    # whose first field is the affected-row count and second the ORA code
    # (0 = success). Returns (rowcount, ora_code). #101.
    Status = _o7_status(Data)
    return (0, 0) if Status is None else (Status['rows'], Status['code'])


def decode_fv2_dml_rowid(Data: bytes) -> str | None:
    """The rowid of the row a 9i DML touched, from its short status, or None.

    The fv2 short OER is the 10g+ one without its call status and end-to-end
    sequence number: row count, ORA code, the two array-error fields, cursor
    id and error position (ub4 each), six single bytes -- the SQL type first --
    and then the same physical rowid fields: data object, relative file, one
    reserved byte, block, slot (#1079, PROTOCOL.md 19.2). Captured on 9.2: an
    INSERT's reply carries `03 01 66 23 01 01 00 02 b9 12 01 02` for object
    91683, file 1, block 47378, slot 2. The server does not clear the field:
    a DDL or a DML that touched nothing carries the previous statement's
    rowid, which the zero row count lets the caller drop. None on an error or
    a reply too short to hold it -- a rowid is never worth failing a DML over.
    """
    Status = _fv2_status(Data)
    if Status is None or Status['code'] or not Status['block']:
        return None
    from seerdb.common.types import rowid_to_string

    return rowid_to_string(
        Status['object'], Status['file'], Status['block'], Status['slot']
    )


def decode_fv2_error_position(Data: bytes) -> int:
    """The 0-based offset in the SQL text of the error a 9i status reports,
    0 when there is none (#2263): the ub4 after the cursor id, as on 10g+.
    Measured on 9.2.0.4: `select 1 frm dual` answers ORA-00923 at 13 (`dual`),
    `select nosuch from dual` ORA-00904 at 7. 8i's status does not say (#719).
    """
    Status = _fv2_status(Data)
    return 0 if Status is None else Status['position']


def decode_fv2_warn_flags(Data: bytes) -> int:
    """The warning flags of a 9i status (#2262), 0 for a reply without one:
    bit 0x20 (TNS_OER_WARN_COMPILATION_ERROR) for a CREATE whose object
    compiled with errors, which the call otherwise reports as a success."""
    Status = _fv2_status(Data)
    return 0 if Status is None else Status['warnings']


def decode_fv2_batch_errors(Data: bytes) -> list[dict]:
    """The per-row errors a 9i array DML collected in `batcherrors` mode
    (#2247), as {offset, code, message}, or [] for a reply with none.

    9.2 honours the batch-errors option bit in a TTI_ALL7 call, applies the good
    rows, and answers ORA-24381 with the 10g+ OER's three arrays, behind the
    short status's iteration count and oerrdd. Captured: rows 1, 2, 1, 4, 5 into
    a primary key give one error, ORA-00001 at row index 2.
    """
    Status = _fv2_status(Data)
    return [] if Status is None else Status['batch_errors']


def _fv2_status(Data: bytes) -> dict | None:
    # The status fields the 9i DML readers above report, from `_o7_status`.
    Status = _o7_status(Data)
    if Status is None:
        return None
    return {
        'code': Status['code'],
        'object': Status['rowid_object'],
        'file': Status['rowid_file'],
        'block': Status['rowid_block'],
        'slot': Status['rowid_slot'],
        'position': Status['position'],
        'warnings': Status['warnings'],
        'batch_errors': _o7_batch_errors(Status),
    }


def _o7_batch_errors(Status: dict) -> list[dict]:
    # The per-row errors of a `batcherrors` call (#2247), from its status's
    # three arrays: error i hit row offsets[i] with codes[i] and messages[i].
    Codes = _o7_ub4s(Status.get('batch_codes', b''), Status.get('batch_code_count', 0))
    Offsets = _o7_ub4s(
        Status.get('batch_offsets', b''), Status.get('batch_offset_count', 0)
    )
    Messages = [
        _fv2_message(M.get('text', b'')) for M in Status.get('batch_messages', [])
    ]
    return [
        {
            'offset': Offsets[I] if I < len(Offsets) else None,
            'code': Codes[I] if I < len(Codes) else None,
            'message': Messages[I] if I < len(Messages) else None,
        }
        for I in range(max(len(Offsets), len(Codes), len(Messages)))
    ]


def _o7_ub4s(Blob: bytes, Count: int) -> list[int]:
    # The `Count` ub4s a batch-error array's value packs.
    Values = []
    for _ in range(Count):
        (Value, Blob) = decode_ub4(Blob)
        Values.append(Value)
    return Values


def _skip_fv2_rpa(Data: bytes) -> bytes:
    # The bytes after a 9i reply's leading RPA piggyback, or all of them when it
    # has none: the stream then sits on the OER token.
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
    return Rest


# The direction masks in a 9i bind prompt: OUT, IN, and both (IN OUT).
FV2_BIND_OUT = 0x10
FV2_BIND_IN = 0x20
_FV2_BIND_DIRECTIONS = (FV2_BIND_OUT, FV2_BIND_IN, FV2_BIND_OUT | FV2_BIND_IN)


def _o7_iov(Data: bytes) -> tuple[dict, bytes] | None:
    # A 9i reply's I/O vector, from `_O7_IOV`, its directions, and the bytes
    # after it, or None when `Data` does not open with one, or is too short to
    # hold the directions its count says.
    if Data[:1] != bytes([TTI_IOV]):
        return None
    try:
        (Iov, Rest) = _O7_IOV_FROM_THIN(Data)
        # A direction is never how a ub4 opens: there, the short form.
        if not Rest or Rest[0] not in _FV2_BIND_DIRECTIONS:
            (Iov, Rest) = _O7_VECTORS_FROM_THIN(Rest, Iov)
    except (IndexError, Truncated, DataError):
        return None
    Count = Iov['iterations'] * 256 + Iov['requests']
    if len(Rest) < Count:
        return None
    Iov['directions'] = bytes(Rest[:Count])
    return (Iov, Rest[Count:])


def _o8i_iov(Data: bytes) -> tuple[dict, bytes] | None:
    # An 8i reply's I/O vector (`_O8I_IOV`), its directions, and the bytes after
    # it, or None when `Data` does not open with one, or is too short to hold
    # the directions its count says.
    if Data[:1] != bytes([TTI_IOV]):
        return None
    try:
        (Iov, Rest) = _O8I_IOV_FROM_O8I(Data)
    except (IndexError, ValueError, DataError):
        # ValueError: the eight bytes are not zero, a vector not measured.
        return None
    Count = Iov['iterations'] * 256 + Iov['requests']
    if len(Rest) < Count:
        return None
    Iov['directions'] = bytes(Rest[:Count])
    return (Iov, Rest[Count:])


def decode_fv2_bind_directions(Data: bytes, O8i: bool = False) -> list[int] | None:
    """The direction of each bind, from a 9i or 8i bind prompt, or None if `Data`
    does not open with one (#1242).

    The prompt is the I/O vector, 9i's `_O7_IOV` and 8i's `_O8I_IOV`, then one
    mask per bind in bind order: 0x10 OUT, 0x20 IN, 0x30 IN OUT (PROTOCOL
    §19.7). Captured on 9i: `0b0501020001010000001020` is OUT, IN. The count is
    two fields, the requests and then the iterations, `iterations * 256 +
    requests`, a ub4 each on 9i (`01 02`, `00`) and a ub2 each on 8i (`02 00`,
    `00 00`). Read as the low byte alone, a block of 256 binds or more lost its
    directions and fell back to guessing them (#2311).
    """
    Iov = _o8i_iov(Data) if O8i else _o7_iov(Data)
    return None if Iov is None else list(Iov[0]['directions'])


# A 9i PL/SQL block reply marks an OUT bind the block never assigned with these
# four fixed bytes, in place of the usual DALC + indicator. Captured live: a
# `RETURNING ... INTO` whose statement matched no rows produces one per such
# bind, and two unassigned binds produce it twice in a row (#801).
_FV2_OUT_UNASSIGNED = bytes.fromhex('ff020c21')


def decode_fv2_block_out(Data: bytes, NumOut: int) -> tuple[list, int, int]:
    # Parse a 9i PL/SQL block reply that returns OUT / IN OUT values (#102,
    # PROTOCOL §19.7). After any bind prompt is stripped, the reply is an
    # optional TTI_RXD (07) carrying `NumOut` × (DALC value + 1-byte indicator)
    # in OUT-bind position order, then the RPA + short OER. Returns
    # (out_values, rowcount, ora_code); out_values holds the raw value bytes per
    # OUT bind (None for a NULL OUT), to be decoded by the caller against each
    # Var's declared type.
    Iov = _o7_iov(Data)
    Rest = Data if Iov is None else Iov[1]
    OutValues: list = []
    if NumOut > 0 and Rest and Rest[0] == TTI_RXD:
        Rest = Rest[1:]
        for _ in range(NumOut):
            if Rest[:4] == _FV2_OUT_UNASSIGNED:
                # The block never assigned this OUT bind, which is what a
                # `RETURNING ... INTO` that matched no rows produces. It is a
                # third form, distinct from a value (DALC + 00) and from an
                # explicitly assigned NULL (empty DALC + 81 01), and it is not
                # a DALC at all: reading it as one consumed the wrong number of
                # bytes and desynced every OUT bind after it (#801).
                Rest = Rest[4:]
                OutValues.append(None)
                continue
            # A value and its indicator, as in a row (`_O7_CELL`): -1 for NULL.
            (Cell, Rest) = _O7_CELL_FROM_THIN(Rest)
            OutValues.append(
                Cell['value'] if Cell['indicator'] != -1 and Cell['value'] else None
            )
    (RowCount, ErrCode) = decode_fv2_dml_response(Rest)
    return (OutValues, RowCount, ErrCode)


# The part of a CREATE_TEMP body every LOB type shares (#91, #1066).
_CREATE_TEMP_HEAD = bytes.fromhex('01012800010a00000100010201100000')


def _create_temp_body(is_blob: bool, csfrm: int = _CSFRM_DB) -> bytes:
    """A CREATE_TEMP body for a CLOB, NCLOB or BLOB (#1066).

    Captured from python-oracledb against a live 23ai (``createlob`` of each
    type) and diffed. After a shared head the three differ in exactly two places:

    ======  =================  ==============================
    type    charset form       trailing charset id (sb4)
    ======  =================  ==============================
    CLOB    ``01 01``          873 (AL32UTF8)
    NCLOB   ``01 02``          **2000 (AL16UTF16)**
    BLOB    ``00`` (none)      873
    ======  =================  ==============================

    The trailing field is the CHARSET, not a constant: this used to be two
    captured blobs ending in a fixed ``0x0369``, which is only right because
    nobody had created an NCLOB. Note the NCLOB's bind OAC does NOT follow it --
    that keeps charset 873 and differs only in its form (_encode_lob_bind_oac).
    Between them sit the LOB-type field (``01 70`` / ``01 71``) and 47 zero
    bytes, which are the same for all three."""
    if is_blob:
        form, lob_type, charset = b'\x00', TNS_TYPE_BLOB, AL32UTF8_CHARSET
    elif csfrm == _CSFRM_NCHAR:
        form, lob_type, charset = b'\x01\x02', TNS_TYPE_CLOB, AL16UTF16_CHARSET
    else:
        form, lob_type, charset = b'\x01\x01', TNS_TYPE_CLOB, AL32UTF8_CHARSET
    return (
        _CREATE_TEMP_HEAD
        + form
        + bytes([0x01, lob_type])
        + bytes(47)
        + encode_sb4(charset)
    )


def encode_dictionary_lobops(Dictionary: dict) -> bytes:
    # TTI_LOBOPS request. See docs/PROTOCOL.md §14 for the field layout.
    # This builds a READ request specifically (operation = 0x0002) since
    # that's all the driver currently issues; other opcodes plug into the
    # same shape by varying `operation` and the pointer flags.
    Tseq = Dictionary['seq']
    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    _ENCODE_FIELD_VERSION.set(FieldVersion)
    # LOB ops carry no request-pipelining token today, as the hand-built header
    # did (its token was always 0); the 23ai `token` field stays the zero byte.
    TokenNum = 0

    def _head(source_length: int, operation: int, *, null_lob: bool = False) -> bytes:
        # The request head every operation shares (_LOBOPS_HEAD): the source
        # locator (its length here, the bytes in the tail), no destination, no
        # charset and no short amount, then the operation. FILE_EXISTS alone sets
        # the null-lob pointer -- the field the server answers "is it null" into.
        return _LOBOPS_HEAD_THIN(
            {
                'seq': Tseq,
                'token_number': TokenNum,
                'source_present': True,
                'source_length': source_length,
                'dest_present': False,
                'dest_length': 0,
                'short_source_offset': 0,
                'short_dest_offset': 0,
                'charset_present': False,
                'short_amount_present': False,
                'null_lob_present': null_lob,
                'operation': operation,
            }
        )

    if Dictionary.get('create_temp'):
        # CREATE_TEMP (op 0x0110, #91): allocate a session-duration temporary
        # LOB; the server returns the new locator in the response RPA. 12c+ only;
        # 11g rejects CREATE_TEMP. Its body is its own shape, not the shared head.
        return _fun_header(TTI_LOBOPS, Tseq, FieldVersion) + _create_temp_body(
            bool(Dictionary.get('is_blob')), Dictionary.get('csfrm', _CSFRM_DB)
        )
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
        # A TEMP locator rides ub2-length-prefixed with the length counting the
        # prefix; a PERSISTENT (column) locator rides bare with its own length,
        # exactly the split READ already makes. Sending a column locator in the
        # temp form is answered ORA-22275 "invalid LOB locator specified" (#964).
        Prefixed = Dictionary.get('locator_prefixed', True)
        Out = _head(len(Locator) + 2 if Prefixed else len(Locator), TNS_LOB_OP_WRITE)
        Out += bytes([0])  # scn array pointer absent
        Out += bytes([0])  # scn array length
        Out += encode_sb4(SourceOffset)  # source offset (ub8)
        Out += encode_sb4(0)  # dest offset (ub8)
        Out += bytes([0])  # amount pointer absent
        Out += struct.pack('>HHH', 0, 0, 0)  # three reserved ub16be slots
        if Prefixed:
            Out += struct.pack('>H', len(Locator))  # ub2 locator length prefix
        Out += Locator
        Out += bytes([0x0E])  # WRITE-data marker
        if len(Data) <= TNS_MAX_SHORT_LENGTH:
            Out += bytes([len(Data)]) + Data
        else:
            Out += bytes([TNS_LONG_LENGTH_INDICATOR])
            for K in range(0, len(Data), 0x7FFF):
                Chunk = Data[K : K + 0x7FFF]
                Out += encode_sb4(len(Chunk)) + Chunk
            Out += encode_sb4(0)  # zero-length terminator
        return Out
    if Dictionary.get('operation') in (
        TNS_LOB_OP_FILE_OPEN,
        TNS_LOB_OP_FILE_CLOSE,
        TNS_LOB_OP_FILE_EXISTS,
    ):
        # BFILE open / close (#46) and exists (#1109). Same field block as READ
        # but with source offset 0 and no read amount. FILE_OPEN sets the amount
        # pointer and sends the open mode (sb4 0x0B = read-only) where READ sends
        # the read amount; FILE_CLOSE and FILE_EXISTS send neither. The locator is
        # ub2-length-prefixed (declared len + 2), like every temp / BFILE LOBOPS.
        # Reverse-engineered from python-oracledb on 21c and 23ai, byte-for-byte.
        #
        # FILE_EXISTS differs from the other two in ONE byte: it sets the
        # null-lob pointer, because the answer it asks for IS that field -- the
        # server writes "is this LOB null" back into it. Sending the READ shape
        # instead (pointer clear, an amount, source offset 1) is answered
        # `ORA-03137: malformed TTC packet from client rejected: [kpolob:lobnull
        # 0]`, which names the field outright.
        Locator = Dictionary['locator']
        Operation = Dictionary['operation']
        IsOpen = Operation == TNS_LOB_OP_FILE_OPEN
        Exists = Operation == TNS_LOB_OP_FILE_EXISTS
        # A BFILE locator as FETCHED leads with its own ub2 inner length, and
        # this branch re-adds that prefix -- so the body is what goes in. The
        # FILE_OPEN / FILE_CLOSE callers strip it themselves before calling; a
        # locator that arrives already stripped does not match the guard, so
        # doing it here as well is a no-op for them and saves every other caller
        # from having to know (#1109).
        if len(Locator) >= 2 and ((Locator[0] << 8) | Locator[1]) == len(Locator) - 2:
            Locator = Locator[2:]
        Out = _head(len(Locator) + 2, Operation, null_lob=Exists)
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
    # Persistent-LOB locators read back correctly with the bare length + raw
    # locator. Temporary LOBs (#91) instead need the locator sent as a
    # ub2-length-prefixed field with the declared length counting that prefix
    # (len + 2) — exactly the form python-oracledb uses; without it a temp-LOB
    # read returns empty content. Switching persistent reads to the prefixed
    # form regresses them on 11g + 21c, so the prefix is opt-in per call.
    Prefixed = Dictionary.get('locator_prefixed', False)
    Out = _head(LocatorLen + 2 if Prefixed else LocatorLen, Operation)
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


# Where the connect data starts in a CONNECT packet: the legacy 58 plus the
# 16 trailing bytes of the 319-era layout (large SDU/TDU + connect flags).
_CONNECT_DATA_OFFSET = 74


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
    CDO = struct.pack('>H', _CONNECT_DATA_OFFSET)
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


def split_connect(Data: bytes) -> tuple[bytes, bytes | None]:
    # A CONNECT body, split for the wire. A server reads at most
    # TNS_MAX_CONNECT_DATA bytes of connect data from the CONNECT packet; given
    # more, it waits for a DATA packet that never comes and the connect hangs
    # (10g to 23ai alike). A longer descriptor goes in a DATA packet straight
    # after the CONNECT, which keeps its stated length and offset but carries no
    # data. Returns the CONNECT body and that descriptor, or None (#1768).
    Offset = _CONNECT_DATA_OFFSET - 8
    if len(Data) - Offset <= TNS_MAX_CONNECT_DATA:
        return Data, None
    return Data[:Offset], Data[Offset:]


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
    # string, and the server accepts an arbitrary length on the thin TTI_ALL7
    # path (verified 9i–23ai).
    #
    # The native 9i OALL8 ("thick") path is the exception (#790): the 9.2 server
    # PARSES this banner to identify the client platform before it will complete
    # the data-type (TTI_DTY) negotiation. It expects an OCI-style banner —
    # "<machine>/<os> <version>", a recognised platform as the first token and a
    # short version token after a space. A banner it cannot parse (our "seerdb "
    # prefix pushes the platform to the second token; or no version token at all)
    # makes it silently stall after the DTY; an over-long version token makes it
    # drop the connection. Captured from a real 9.2 sqlplus login, the banner is
    # "x86_64/Linux 2.4.xx" — the "2.4.xx" is a fixed token Oracle's own client
    # reports, not the live kernel release, so we send that literal token and
    # keep the live machine/os. Measured gate: this is the SOLE reason native
    # OALL8 login stalled; connect-packet shape, ANO content and DTY charset were
    # each proven not to matter.
    if Dictionary.get('oall8'):
        Banner = f'{platform.machine()}/{platform.system()} 2.4.xx'.encode(
            'ascii', 'replace'
        )
    else:
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
        ttc_field_version byte = FIELD_VERSION_19_1_EXT_1
        <DTY message>            (its caps array still advertises the real fv)
        <OSESSKEY message>
    """
    return (
        bytes([TNS_MSG_TYPE_FAST_AUTH, 1, TNS_SERVER_CONVERTS_CHARS, 0])
        + Pro
        + b'\x00\x00\x00\x00\x00'
        + bytes([FIELD_VERSION_19_1_EXT_1])
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
    # A value over 252 bytes is chunked at the negotiated version's width, not
    # at whatever an earlier connection left in this context (#1816). Set for
    # this message only, so encoding it changes nothing for anyone else.
    Version = Dictionary.get('field_version')
    if not Version:
        return _encode_dictionary_sess(Dictionary)
    Token = _ENCODE_FIELD_VERSION.set(Version)
    try:
        return _encode_dictionary_sess(Dictionary)
    finally:
        _ENCODE_FIELD_VERSION.reset(Token)


def _encode_dictionary_sess(Dictionary: dict) -> bytes:
    # The session-identity pairs the server records in v$session: program,
    # machine, terminal and osuser. They are informational -- nothing
    # authenticates on them -- but a client can set each, and they are readable
    # ONLY through this message, so a caller's values have to travel here (#826).
    # Each falls back to what this process actually is.
    Env = Dictionary['env']
    Tseq = Dictionary['seq']
    Hostname = encode_kv(
        b'AUTH_MACHINE',
        (Env.get('machine') or socket.gethostname()).encode('utf-8'),
    )
    Pid = encode_kv(b'AUTH_PID', str(os.getpid()).encode('utf-8'))
    User = Env['user'].encode('utf-8')
    # AUTH_SID is what a server reports as v$session.osuser, not a session id.
    SID = encode_kv(b'AUTH_SID', (Env.get('osuser') or Env['user']).encode('utf-8'))
    UserLen = encode_sb4(len(Env['user']))
    Role = Env.get('role', 0)
    Prelim = Env.get('prelim', 0)
    LogonMode = encode_sb4((Role * 32) | (Prelim * 128) | 1)
    AppName = encode_kv(
        b'AUTH_PROGRAM_NM',
        (Env.get('program') or Env.get('app_name') or 'seerdb').encode('utf-8'),
    )

    FieldVersion = Dictionary.get('field_version', FIELD_VERSION_11_2)
    if FieldVersion >= FIELD_VERSION_12_1:
        # 12c+ OSESSKEY (python-oracledb auth.pyx _write_message phase one):
        # the username is length-prefixed (write_bytes_with_length) and the
        # pair count is 5, leading with AUTH_TERMINAL. 11g instead reads the
        # username by the earlier UserLen field and sends 4 pairs; sending the
        # 12c shape to 11g (or vice-versa) desyncs the server's parse.
        Terminal = encode_kv(
            b'AUTH_TERMINAL', (Env.get('terminal') or 'unknown').encode('utf-8')
        )
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


# --- Oracle 8i (8.1.7) O3LOGON via the OSESSKEY/OAUTH envelope ---------------
# 8i uses the same DES O3LOGON *crypto* as 9i, but wraps it in the OSESSKEY
# (0x76) / OAUTH (0x73) function envelope with key-value AUTH_ pairs -- NOT 9i's
# positional TTI_3LOGA/TTI_3LOGON. Sending 3LOGA to 8i draws a TTI_OER. The
# envelope is the 10g login's head and pairs (`_AUTH_HEAD`, `_AUTH_PAIR`) at the
# 8i codec's fixed little-endian widths (#2284): what read before as a ub1
# length and a big-endian ub4 repeat of it is a ub4 length and a value, a ub1
# length and the bytes. Reproduced byte for byte from a live 9.2-client -> 8.1.7
# capture (docs/PROTOCOL.md §19.8).


# The longest value an 8i key-value field can carry: its ub1 length stops at
# 252, as 253 to 255 are the TTC escape, long-form and NULL markers. Measured on
# 8.1.7: a 253- or 255-byte program name failed the login, a 254-byte one broke
# its reply, and anything longer cannot be written at all (#1773).
_O8I_INFO_VALUE_MAX = 252


def _o8i_info_pairs(Pairs: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    # The informational pairs cut to what the field can carry, on a UTF-8
    # character boundary. Nothing is lost that the server keeps: 8.1.7 stores the
    # first 64 characters of a program name, whatever was sent.
    return [
        (Key, Val[:_O8I_INFO_VALUE_MAX].decode('utf-8', 'ignore').encode('utf-8'))
        if len(Val) > _O8I_INFO_VALUE_MAX
        else (Key, Val)
        for Key, Val in Pairs
    ]


def _pre10_login(
    Subtype: int,
    Seq: int,
    User: bytes,
    Mode: int,
    Pairs: list[tuple[bytes, bytes]],
    O8i: bool = True,
) -> bytes:
    # A pre-10g OSESSKEY or OAUTH call (`_AUTH_HEAD` and `_AUTH_PAIR`): 8i's at
    # the 8i codec's widths, the user as a value; 9i's thin-coded, the user raw,
    # as a 10g client below 12.1 sends it (#2342). An empty value is a zero
    # length and no value, as 8.1.7 writes one; written as one zero byte, the
    # pair came out three bytes short and the login failed (#2344).
    return (_AUTH_O8I if O8i else _AUTH_THIN)(
        {
            'subtype': Subtype,
            'seq': Seq,
            'pointer_1': True,
            'user_length': len(User),
            'mode': Mode,
            'pointer_2': True,
            'pair_count': len(Pairs),
            'pointer_3': True,
            'pointer_4': True,
            'has_user_ptr': False,
            'user_prefixed': O8i,
            'user_raw': not O8i,
            'user': User,
            'pairs': [
                {
                    'key_length': len(Key),
                    'key': Key,
                    'value_length': len(Val),
                    'value': Val,
                    'flags': 0,
                }
                for Key, Val in Pairs
            ],
        }
    )


def encode_o3logon_osesskey_phase1(
    Seq: int, User: bytes, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # TTI_FUN + OSESSKEY (0x76), mode 1: request the session key. Carries the
    # username and informational AUTH_ pairs (program/machine/pid -- session
    # metadata the server does not authenticate on).
    return _pre10_login(TTI_SESS, Seq, User, 1, _o8i_info_pairs(Pairs))


def encode_o3logon_oauth_phase2(
    Seq: int, User: bytes, PwdField: bytes, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # TTI_FUN + OAUTH (0x73), mode 0x101: send AUTH_PASSWORD (hex(DES blocks) +
    # decimal pad count) plus the informational pairs. The count follows the
    # pairs; written as part of the mode, `00 00 01 05`, it held only while
    # they were five.
    return _pre10_login(
        TTI_AUTH,
        Seq,
        User,
        0x101,
        [(b'AUTH_PASSWORD', PwdField), *_o8i_info_pairs(Pairs)],
    )


def encode_o7_osesskey(
    Seq: int, User: bytes, Mode: int, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # Oracle 9i's O3LOGON phase one (#2342): OSESSKEY (0x76) thin-coded, the
    # user raw, and the session pairs a 10g client below 12.1 sends -- program,
    # machine, pid, osuser -- which 9.2.0.4 takes: its USERENV HOST is the
    # machine sent. JDBC thin's positional 3LOGA carried the strings of the
    # capture it was taken from behind a block not understood, so every 9i
    # session called itself `JDBC Thin Client` on `o9i`.
    return _pre10_login(TTI_SESS, Seq, User, Mode, Pairs, O8i=False)


def encode_o7_oauth(
    Seq: int, User: bytes, Mode: int, PwdField: bytes, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # 9i's phase two: OAUTH (0x73) thin-coded, AUTH_PASSWORD -- O3LOGON's DES
    # proof as 8i sends it, hex(DES blocks) + decimal pad count -- and the pairs.
    return _pre10_login(
        TTI_AUTH, Seq, User, Mode, [(b'AUTH_PASSWORD', PwdField), *Pairs], O8i=False
    )


def parse_8i_auth_sesskey(Packet: bytes, O8i: bool = True) -> bytes:
    """Extract the 8-byte session key from an 8i -- or, with `O8i` False, a 9i
    -- OSESSKEY response RPA.

    The AUTH_SESSKEY value is its ASCII hex (`_PRE10_AUTH_REPLY`)."""
    from binascii import unhexlify

    from seerdb.common.exceptions import InterfaceError

    Value = parse_8i_auth_value(Packet, b'AUTH_SESSKEY', O8i)
    if Value is None:
        raise InterfaceError('pre-10g OSESSKEY response carried no AUTH_SESSKEY')
    return unhexlify(Value)


def decode_8i_server_version(Packet: bytes) -> int:
    # The packed release an 8i phase-two login reply carries as AUTH_VERSION_NO,
    # or 0 when it does not (#2278).
    return _auth_int(parse_8i_auth_value(Packet, b'AUTH_VERSION_NO')) or 0


def parse_8i_auth_value(Packet: bytes, Key: bytes, O8i: bool = True) -> bytes | None:
    """One value of an 8i login reply (`_PRE10_AUTH_REPLY`), or with `O8i`
    False a 9i one, b'' for an empty one, or None when the reply lacks it or is
    not an RPA of pairs. The phase-two reply carries AUTH_VERSION_NO (#2278).
    Read before by searching for the key's name, a key sent with its NUL
    terminator, as the AUTH_NLS_ ones are, read as empty."""
    Decode = _PRE10_AUTH_REPLY_FROM_O8I if O8i else _PRE10_AUTH_REPLY_FROM_THIN
    try:
        Reply = Decode(Packet)[0]
    except (IndexError, ValueError, DataError):
        return None
    for Pair in Reply['pairs']:
        # 8.1.7 counts an AUTH_NLS_ key's NUL terminator in its length.
        if bytes(Pair.get('key', b'')).rstrip(b'\x00') == Key:
            return bytes(Pair.get('value', b''))
    return None


# --- 9i native OALL8 O3LOGON via the OSESSKEY/OAUTH envelope (#790) ----------
# The native 9.2 OALL8 ("thick") client marshals OSESSKEY (0x76) / OAUTH (0x73)
# as the OCI login call -- the shared _AUTH_HEAD and _AUTH_PAIR at OCI's widths
# (#798), as 8i's are at 8i's -- NOT 9i's positional thin-coded form (that is
# the compact path, which the 9.2 server stops accepting once the native
# data-type negotiation has run). What the hand-built frame called "a fixed
# preamble" is the first pointer slot, its "structural constant 3" the user's
# length, and the 0x2a of phase one the four bytes after the pair count that a
# native client leaves unset (#2249) -- the server reads them positionally and
# ignores them, as it ignores the pointers' values so long as they are non-null.
# The crypto is the SAME DES O3LOGON as the thin 9i / 8i paths (des_verifier +
# o3logon). Byte-reproduced from a live 9.2 sqlplus -> 9.2 capture apart from
# those. See also [[oall8-pro-banner-gate]].
_AUTH_OCI = wire_schema.compile_encoder(
    (*_AUTH_HEAD, ('each', 'pairs', 'pair_count', _AUTH_PAIR)), _OCI
)


def _oall8_auth(
    Subtype: int, Seq: int, User: bytes, Mode: int, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # An OCI OSESSKEY or OAUTH call (_AUTH_HEAD and its pairs at OCI's widths). An
    # empty value is a zero length and no value, as on 8i (#2344): a zero chunk
    # byte after it made the 9.2 server drop the login (#798).
    return _AUTH_OCI(
        {
            'subtype': Subtype,
            'seq': Seq,
            'pointer_1': True,
            'user_length': len(User),
            'mode': Mode,
            'pointer_2': True,
            'pair_count': len(Pairs),
            'pointer_3': True,
            'pointer_4': True,
            'user_prefixed': True,
            'user_raw': False,
            'user': User,
            'pairs': [
                {
                    'key_length': len(Key),
                    'key': Key,
                    'value_length': len(Value),
                    'value': Value,
                    'flags': 0,
                }
                for (Key, Value) in Pairs
            ],
        }
    )


def encode_oall8_osesskey_phase1(
    Seq: int, User: bytes, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # OSESSKEY (0x76) phase one: request the session key. Logon mode 1.
    return _oall8_auth(TTI_SESS, Seq, User, 1, _o8i_info_pairs(Pairs))


def encode_oall8_oauth_phase2(
    Seq: int, User: bytes, PwdField: bytes, Pairs: list[tuple[bytes, bytes]]
) -> bytes:
    # OAUTH (0x73) phase two: send AUTH_PASSWORD (hex(DES blocks) + decimal pad
    # count) plus the informational pairs. Logon mode 0x101 marks phase two.
    return _oall8_auth(
        TTI_AUTH,
        Seq,
        User,
        0x101,
        [(b'AUTH_PASSWORD', PwdField), *_o8i_info_pairs(Pairs)],
    )


def parse_oall8_auth_sesskey(Packet: bytes) -> bytes:
    """Extract the session key from a native 9.2 OSESSKEY response.

    The AUTH_SESSKEY value is a length-prefixed ASCII-hex string in the native
    DALC coding (``ub4le len``, ``ub1 len``, then the hex) -- the reverse field
    order of the 8i server's reply (see ``parse_8i_auth_sesskey``)."""
    from binascii import unhexlify

    from seerdb.common.exceptions import InterfaceError

    Idx = Packet.find(b'AUTH_SESSKEY')
    if Idx < 0:
        raise InterfaceError('9i OSESSKEY response carried no AUTH_SESSKEY')
    After = Packet[Idx + len(b'AUTH_SESSKEY') :]
    ValLen = After[4]  # ub1 chunk length; the ub4le repeat precedes it in [0:4]
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
    if not Bytes:
        raise Truncated('ub4: no length byte')
    Length = Bytes[0]
    Negative = bool(Length & 0x80)
    Width = Length & 0x7F
    if Width <= 4:
        # A slice past the end returns fewer bytes and a smaller number, not an
        # error, so a short buffer has to be caught before it is read (#849).
        if len(Bytes) < Width + 1:
            raise Truncated(f'ub4: {Width} magnitude bytes, {len(Bytes) - 1} left')
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
    # Only the length is checked here -- the lenient reading itself is untouched.
    if len(Bytes) < 2:
        raise Truncated('ub4: two-byte form cut short')
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
    raise NotSupportedError(
        f'no wire encoding for a value of type {type(Val).__name__}'
    )


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
    ORA_NO_DATA_FOUND,
    1,
    b'ORA-01403: no data found\n',
    cursor_id=1,
    seq=4,
    error_pos=14,
    sql_type=3,
    call_number=7,
)


def _end_of_fetch(cursor_id: int = 1) -> bytes:
    # The 11g terminator is the pinned constant; a 12.1+ client reads extra OER
    # fields, so re-encode it under the session's field version.
    #
    # ``cursor_id`` is the one field that varies. A client reads the server's
    # cursor id out of this OER and caches it against the statement, so a
    # terminator that always says 1 tells every query it is cursor 1 (#840). The
    # default keeps the captured value for callers with no cursor of their own.
    if (
        cursor_id == 1
        and _ENCODE_FIELD_VERSION.get() < FIELD_VERSION_12_1
        and not _ENCODE_TXN_IN_PROGRESS.get()
    ):
        # The pinned constant was built at import time, so it carries a clear
        # transaction flag; re-encode when the session has one open (#889).
        return _END_OF_FETCH
    return _encode_oer(
        1,
        ORA_NO_DATA_FOUND,
        1,
        b'ORA-01403: no data found\n',
        cursor_id=cursor_id,
        error_pos=14,
        sql_type=3,
        call_number=7,
    )


# A physical ROWID (RID, type 11) reserves this many bytes on the wire — the
# present indicator the client reads to tell a real rowid (any non-zero,
# non-0xff value) from a NULL. The client only tests for 0 / 0xff, so the exact
# size is cosmetic; 10 is a physical rowid's structured length.
_RID_PRESENT = 0x0A
# The leading type tag of a UROWID (type 208) value, which says what it holds.
# Captured from 23ai: 0x02 for a logical rowid (an index-organized table's), 0x01
# for a PHYSICAL rowid stored in a UROWID column. A client branches on it --
# python-oracledb renders a 0x01 value as an ordinary extended rowid -- so it is
# not cosmetic. Writing 0x01 for every value made python-oracledb read an IOT's
# logical rowid as a physical one, which then matched no row (#1087).
_UROWID_LOGICAL_TAG = 0x02
_UROWID_PHYSICAL_TAG = 0x01


def encode_rowid_value(
    Value: object, Codec: _ThinCodec | _OciCodec | None = None
) -> bytes:
    """The physical ROWID (RID, type 11) RXD value (#484), the inverse of
    :func:`_read_rowid_column` (_ROWID_CELL). ``Value`` is the 18-char extended
    ROWID string; ``None`` (or empty) is a bare ``0x00`` indicator (NULL). OCI
    reads it as 16 bytes, its fields each a ub4 LE (#2017): sqlplus 23.26
    against a live 18c, `26 0a 04 00 0c 00 00 00 8b 00 00 00 2b 01 00 00` is
    AABAomAAMAAAACLAEr, object 264742, file 12, block 139, row 299."""
    from seerdb.common.types import string_to_rowid

    if Value is None or Value == '':
        return bytes([0])
    (obj, file, block, row) = string_to_rowid(str(Value))
    fields = {'object': obj, 'file': file, 'block': block, 'row': row}
    if Codec is _OCI:
        return _ROWID_CELL_OCI(fields | {'lead': 16})
    return _ROWID_CELL_THIN(fields | {'lead': _RID_PRESENT, 'unused': 0})


def encode_urowid_value(Value: object) -> bytes:
    """The UROWID (logical/universal rowid, type 208) RXD value (#484), the
    inverse of :func:`_read_urowid_column`: a ub4 byte count, a 1-byte length
    echo, then the rowid bytes (a leading type tag + the body). ``Value`` is the
    printable rowid: the ``*``-prefixed base64 form of a logical rowid, or the
    18-character form of a physical one held in a UROWID column; ``None`` (or
    empty) is a zero count (NULL)."""
    if Value is None or Value == '':
        return encode_sb4(0)
    Text = str(Value)
    if Text.startswith('*'):
        Body = Text[1:]  # drop the leading '*'
        Raw = base64.b64decode(Body + '=' * (-len(Body) % 4))
        Payload = bytes([_UROWID_LOGICAL_TAG]) + Raw
    else:
        # A physical rowid: object (ub4), partition / file (ub2), block (ub4),
        # slot (ub2), big-endian, after its tag (#1087).
        from seerdb.common.types import string_to_rowid

        (Obj, File, Block, Slot) = string_to_rowid(Text)
        Payload = (
            bytes([_UROWID_PHYSICAL_TAG])
            + Obj.to_bytes(4, 'big')
            + File.to_bytes(2, 'big')
            + Block.to_bytes(4, 'big')
            + Slot.to_bytes(2, 'big')
        )
    if len(Payload) <= TNS_MAX_SHORT_LENGTH:
        return encode_sb4(len(Payload)) + bytes([len(Payload)]) + Payload
    # A large UROWID (an index-organized table's rowid) rides chunked, like a
    # LONG value: a single ub1 length cannot carry 253+ bytes and would collide
    # with the 0xFE / 0xFF markers. ub4 total, the 0xFE marker, then a run of
    # length-prefixed chunks (ub4 on 12c+, a single length byte before) closed by
    # a zero-length chunk -- the inverse of the chunked branch in
    # _read_urowid_column (#904). Without this the encoder raised on
    # bytes([>255]) and the Mirror could not return an IOT rowid at all.
    wide = _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
    encode_len = encode_sb4 if wide else (lambda n: bytes([n]))
    out = bytearray(encode_sb4(len(Payload)) + bytes([TNS_LONG_LENGTH_INDICATOR]))
    for start in range(0, len(Payload), TNS_MAX_SHORT_LENGTH):
        chunk = Payload[start : start + TNS_MAX_SHORT_LENGTH]
        out += encode_len(len(chunk)) + chunk
    out += encode_len(0)  # zero-length chunk terminates the run
    return bytes(out)


# A thin (seerdb / oracledb-thin) LONG / LONG RAW value streams inline in the RXD
# — no LOB locator — as a value followed by TWO trailing ub4 indicators (actual /
# return lengths, 0 / 0 for an ordinary value), the inverse of :func:`_read_long_column`.
# The value is the 0xFE-chunked form (a run of <ub1 len><bytes> terminated by a
# zero-length chunk) even when it fits one chunk; a NULL is a bare 0x00 marker. The
# sqlplus / OCI dialect frames it with a single ub4 trailer instead. Character LONG
# content is UTF-8, LONG RAW is raw bytes. Chunks stay within the single-length
# DALC boundary used throughout this codec.


def encode_long_value_thin(Value: object) -> bytes:
    """The thin RXD value for a LONG / LONG RAW column (#484): the content streamed
    inline as 0xFE-chunked bytes (NULL is a bare 0x00), followed by the two zero
    trailing indicators :func:`_read_long_column` consumes (_LONG_CELL)."""
    return _LONG_CELL_THIN(
        {'content': _long_content(Value), 'actual_length': 0, 'return_code': 0}
    )


# The RXD value the Mirror mints for a thin LOB column: an opaque locator the
# client echoes back over TTI_LOBOPS, the content following in the read reply.
# Flag byte 3 of a LOB locator carries the variable-length-charset bit. A client
# reads a CLOB as UTF-16 only when it is set and as UTF-8 otherwise, so the flat
# placeholder -- all zeros in the flag bytes -- told every client the UTF-16BE
# content it was about to receive was UTF-8, and each character came back twice
# (#903). seerdb's own client assumes UTF-16 and never looked, which is why only
# an independent client saw it.
_THIN_LOB_LOC_OFFSET_FLAG_3 = 6
_THIN_LOB_LOC_FLAGS_VAR_LENGTH_CHARSET = 0x80


def _thin_lob_locator() -> bytes:
    raw = bytearray(b'\x00seerdb-mirror-lob-locator-0000000000\x00')
    raw[_THIN_LOB_LOC_OFFSET_FLAG_3] |= _THIN_LOB_LOC_FLAGS_VAR_LENGTH_CHARSET
    return bytes(raw)


_THIN_LOB_LOCATOR = _thin_lob_locator()


def _thin_obj_lob_locator() -> bytes:
    # A LOB attribute inside an object image rides a locator distinct from a
    # top-level LOB column's, so the session can route its TTI_LOBOPS reads to the
    # persistent object-LOB queue rather than the transient column queue (which an
    # object type's post-describe get_type_shape queries would reset) (#888).
    raw = bytearray(b'\x00seerdb-mirror-obj-lob-locator-000000\x00')
    raw[_THIN_LOB_LOC_OFFSET_FLAG_3] |= _THIN_LOB_LOC_FLAGS_VAR_LENGTH_CHARSET
    return bytes(raw)


_THIN_OBJ_LOB_LOCATOR = _thin_obj_lob_locator()

# The counter slot of `_THIN_LOB_LOCATOR` (its trailing "0000000000"): a per-LOB
# index printed here makes each fetched column LOB's locator unique while keeping
# the byte layout the client accepts. Index 0 reproduces `_THIN_LOB_LOCATOR`.
_COLUMN_LOB_LOCATOR_PREFIX = b'\x00seerdb-mirror-lob-locator-'


def mint_column_lob_locator(index: int) -> bytes:
    """A fetched column LOB's locator, unique per session LOB (#888).

    The read path is row-major and ignores the locator, so uniqueness costs the
    reader nothing; it lets :class:`LobEmitLog` remember the content the Mirror
    served under each locator, so an object bind that later carries one can be
    resolved. Byte-for-byte `_THIN_LOB_LOCATOR` with the trailing counter set."""
    raw = bytearray(_COLUMN_LOB_LOCATOR_PREFIX + b'%010d' % (index % 10**10) + b'\x00')
    raw[_THIN_LOB_LOC_OFFSET_FLAG_3] |= _THIN_LOB_LOC_FLAGS_VAR_LENGTH_CHARSET
    return bytes(raw)


class LobEmitLog:
    """The content of each column LOB the Mirror emits in a session, keyed by the
    unique locator it minted for it (#888).

    A LOB fetched from the Mirror rides a locator the Mirror invented; when the
    client later binds that LOB into an object attribute it sends the locator
    back inside the image, and the Mirror has to turn it back into content (there
    is no live upstream LOB behind it). The read path stays order-based; this log
    exists only so a bind can recover what a fetch served. Content is the original
    value (``str`` for CLOB / NCLOB, ``bytes`` for BLOB), not the wire form."""

    def __init__(self) -> None:
        self._next = 0
        self.contents: dict[bytes, tuple[object, bool]] = {}

    def record(self, value: object, is_clob: bool) -> bytes:
        locator = mint_column_lob_locator(self._next)
        self._next += 1
        self.contents[locator] = (value, is_clob)
        return locator

    def content(self, locator: bytes) -> tuple[object, bool] | None:
        return self.contents.get(bytes(locator))


# The session's LOB emit log, set per session so `_thin_column_value` can mint a
# unique locator + remember the content of every column LOB it emits (#888).
_LOB_EMIT_LOG: contextvars.ContextVar[LobEmitLog | None] = contextvars.ContextVar(
    'lob_emit_log', default=None
)

# The chunk size a live 23ai reports alongside a LOB column locator. The client
# keeps it for its own chunking (`lob.getchunksize()`); any sane value works.
_THIN_LOB_CHUNK_SIZE = 8060


def _lob_value_size(Value: object) -> int:
    # The size a LOB column's locator metadata reports: characters for a CLOB,
    # bytes for a BLOB, matching what a live server reports for the same value.
    if isinstance(Value, str):
        return len(Value)
    if isinstance(Value, (bytes, bytearray, memoryview)):
        return len(bytes(Value))
    return 0


# The chunk size a live 23ai reports alongside a prefetched LOB-class column,
# measured identical across 3-, 5- and 16-element float32 VECTOR columns (#887)
# and on a JSON column (0x7f58 on the wire, #826).
_THIN_PREFETCH_CHUNK_SIZE = 32600


def encode_prefetched_lob_value_thin(image: bytes) -> bytes:
    """The RXD value for a thin JSON / VECTOR column: the binary image **inline**,
    followed by the locator, in the LOB column's metadata framing --
    ``ub4 locator length | ub8 size | ub4 chunk size | DALC image | DALC
    locator``. Both length-prefixed fields are there: the reference client reads
    the image and then reads the locator to discard it, so a reply that stops
    after the image leaves it consuming the next token as locator bytes.

    Neither type rides as a bare locator with its content following over
    TTI_LOBOPS, the way a CLOB or BLOB does -- the server prefetches the whole
    value into the row. Measured against a live 23ai: after a VECTOR or JSON
    SELECT the reference client issues **no** TTI_LOBOPS call at all, because it
    already has the value (its ``read_vector`` / ``read_oson`` read this framing
    and drop the locator). The Mirror used to mint a locator and wait to be asked
    for the content, so that client read the placeholder locator's bytes as the
    next token and died with `DPY-5000 ... unknown protocol message type`
    (#887 for VECTOR, #826 for JSON). seerdb's own client never noticed, because
    :func:`_read_lob_column` hands the "locator" straight to the decoder either
    way."""
    return (
        encode_sb4(len(_THIN_LOB_LOCATOR))
        + encode_sb4(len(image))
        + encode_sb4(_THIN_PREFETCH_CHUNK_SIZE)
        + _bytes_with_length(image)
        + _bytes_with_length(_THIN_LOB_LOCATOR)
    )


def encode_lob_bind_block(value: object, *, is_clob: bool) -> bytes:
    """The LOB block a BIND's value rides in, for a Mirror serving one.

    The block is the same one a fetched LOB column carries (§14.5b) -- a ub4
    length, the locator's ub8 size and ub4 chunk size, then the locator -- and a
    NULL LOB is the single byte ``0x00`` in place of it. Both bind carriers use
    it: an OUT / IN OUT bind (§6.5, #979) and a DML RETURNING bind (§22.1d,
    #987).

    The Mirror has no upstream locator to pass along -- a passthrough backend
    reads its upstream with ``fetch_lobs=False``, so the value arrives already
    materialised -- so it MINTS one and records the content against it in the
    session's :class:`LobEmitLog`, exactly as the column path does. The read the
    client then issues is answered from that log by locator, so nothing about
    the read path changes."""
    if value is None:
        return bytes([0])
    log = _LOB_EMIT_LOG.get()
    locator = log.record(value, is_clob) if log is not None else _THIN_LOB_LOCATOR
    return encode_lob_locator_thin(
        _lob_value_size(value), with_metadata=True, locator=locator
    )


def encode_lob_locator_thin(
    size: int = 0, *, with_metadata: bool = False, locator: bytes = _THIN_LOB_LOCATOR
) -> bytes:
    """The RXD value for a thin LOB column (#413): a minted opaque locator the
    client echoes back over TTI_LOBOPS. The content follows in the read reply.

    ``locator`` overrides the fixed session locator with a unique one so a bind
    that later carries it can be resolved to the content the Mirror served
    (:class:`LobEmitLog`, #888); the read path is order-based and ignores it.

    A CLOB / BLOB column carries the locator's **metadata** in front of it --
    ``ub4 locator length | ub8 size | ub4 chunk size | length-prefixed
    locator`` -- which is what the reference thin client reads, unconditionally,
    for every CLOB / BLOB / BFILE column. Without the two middle fields it takes
    the locator's own length prefix for the size and dies (`DPY-5002`, #853).
    Captured from a live 23ai for a 3000-byte BLOB: ``01 72 | 02 0b b8 |
    02 1f 7c | 72 <114 locator bytes>``.

    ``with_metadata=False`` keeps the bare ``ub4 length | locator`` form for the
    column types that are NOT read by that path -- JSON (`read_oson`) and VECTOR
    (`read_vector`) -- which would mis-decode the extra fields.

    Which form a real server sends is, as of #853, **not** something we can
    predict: a live 23ai sends the bare form to seerdb and the metadata form to
    the reference client, for the same row on the same connection settings, with
    byte-identical compile capabilities, runtime capabilities and DTY type table
    (321 entries), equivalent executes and the same prefetch. The switch was not
    found. The Mirror therefore always sends the metadata form for CLOB / BLOB,
    which is what the stricter reader demands, and :func:`_read_lob_column`
    accepts either so seerdb's own client reads the Mirror and a real server
    alike."""
    return _LOB_CELL_THIN(
        {
            'locator_length': len(locator),
            'has_metadata': with_metadata,
            'size': size,
            'chunk_size': _THIN_LOB_CHUNK_SIZE,
            'locator': locator,
        }
    )


def _encode_temporal(Value: datetime.date | BcDate, DataType: int) -> bytes:
    # A temporal column has a fixed wire width fixed by its *type*, not by the
    # particular value — so we dispatch on the column's data_type rather than
    # letting encode_token_datetime() pick 7/11/13 bytes from the value. A plain
    # date is promoted to midnight of that day.
    if isinstance(Value, BcDate):
        # A date before year 1, which no datetime can hold (#1071). Same layout;
        # only the century / year bytes go below their bias.
        if DataType == TNS_TYPE_TIMESTAMPTZ:
            raise DataError('a date before year 1 cannot be sent with a time zone')
        if DataType in (TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPLTZ):
            return _encode_date_prefix(Value) + (Value.microsecond * 1000).to_bytes(
                4, 'big'
            )
        return _encode_date_prefix(Value)
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
    if DataType in (TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPLTZ):
        # 11 bytes always: DATE prefix + 4 BE nanosecond bytes (zero when the
        # value has no sub-second part), keeping the column a fixed width.
        #
        # TIMESTAMP WITH LOCAL TIME ZONE is the SAME shape: it is normalised to
        # the session zone and carries no explicit offset, which is why its
        # describe length is 11 like a plain TIMESTAMP and unlike TZ's 13. Left
        # out of this branch it fell through to the DATE form below and silently
        # dropped the fractional seconds -- 22:30:02.5 came back 22:30:02, with
        # no error anywhere (#826).
        Naive = Dt.replace(tzinfo=None)
        return _encode_date_prefix(Naive) + (Naive.microsecond * 1000).to_bytes(
            4, 'big'
        )
    # Oracle DATE: date + time to the second, 7 bytes. Sub-second and zone parts
    # are dropped (that is what DATE, as distinct from TIMESTAMP, means).
    return _encode_date_prefix(Dt.replace(microsecond=0, tzinfo=None))


# The fixed block a BFILE locator carries between its length and the directory
# name. Captured from 23ai, identical for every BFILE (#1102).
_BFILE_LOCATOR_FIXED = bytes.fromhex('000108080000000100000000000000')


_LOBOPS_FILE_KINDS = {
    TNS_LOB_OP_FILE_OPEN: 'file_open',
    TNS_LOB_OP_FILE_CLOSE: 'file_close',
    TNS_LOB_OP_FILE_EXISTS: 'file_exists',
    TNS_LOB_OP_FILE_ISOPEN: 'file_isopen',
}


def encode_bfile_locator(Directory: str, Filename: str) -> bytes:
    """A BFILE locator naming ``Directory`` and ``Filename`` (#1102).

    The form 23ai sends, and the inverse of the client's reader: a ub2 of
    everything after it, the fixed block, then the two names each with a ub1
    length, separated by a zero byte::

        00 35 | 000108080000000100000000000000 | 0f 'PYO_MISSING_DIR' | 00 | 14 'pyo_missing_file.txt'
    """
    Dir = Directory.encode('ascii')
    File = Filename.encode('ascii')
    if len(Dir) > 255 or len(File) > 255:
        raise DataError('a BFILE directory or file name is longer than 255 bytes')
    Body = (
        _BFILE_LOCATOR_FIXED
        + bytes([len(Dir)])
        + Dir
        + bytes([0])
        + bytes([len(File)])
        + File
    )
    return len(Body).to_bytes(2, 'big') + Body


def decode_bfile_locator(Locator: bytes) -> tuple[str, str] | None:
    """The directory and file name a BFILE locator carries, or None (#1102).

    The Mirror needs no state to answer a FILE_* call: the names travel in the
    locator the client sends back. They are anchored on the fixed block rather
    than a fixed offset, because a locator arrives in more than one framing --
    as fetched it opens with its own ub2 inner length, while a client's LOBOPS
    request sends it from the fixed block onward.
    """
    at = Locator.find(_BFILE_LOCATOR_FIXED)
    if at < 0:
        return None
    pos = at + len(_BFILE_LOCATOR_FIXED)
    try:
        DirLen = Locator[pos]
        DirEnd = pos + 1 + DirLen
        FileLen = Locator[DirEnd + 1]
        FileEnd = DirEnd + 2 + FileLen
        if FileEnd > len(Locator):
            return None
        return (
            Locator[pos + 1 : DirEnd].decode('ascii'),
            Locator[DirEnd + 2 : FileEnd].decode('ascii'),
        )
    except (IndexError, UnicodeDecodeError):
        return None


def encode_value(
    Value: object, DataType: int, Codec: _ThinCodec | _OciCodec | None = None
) -> bytes:
    """A scalar column value as its RXD wire form — the inverse of
    :func:`~seerdb.common.types.decode_value`.

    Most types are a DALC (1-byte length + data): NULL is the empty DALC, text is
    UTF-8, a number is Oracle's base-100 NUMBER encoding, a datetime/date per the
    column's temporal type. ROWID / UROWID / LONG carry their own framing (a NULL
    still carries it, so they skip the bare-0x00 NULL path), and a LOB rides as a
    minted locator with its content following over TTI_LOBOPS.

    ``Codec`` frames the value as its dialect does (#2064), thin's by default."""
    Codec = Codec or _THIN

    if DataType == TNS_TYPE_BFILE:
        # A BFILE names a file on the server; the locator carries the two names
        # and the client asks about the file separately (#1102). It rides the
        # same framing as a CLOB / BLOB column -- the reference client reads
        # that one for every LOB-class column -- with the size left 0, since
        # nothing has opened the file at fetch time.
        if not isinstance(Value, BFile):
            return encode_sb4(0)
        # The BARE form -- ub4 length + the locator -- not the size / chunk-size
        # metadata a CLOB or BLOB carries. Captured from 23ai: `00000007 01 1a |
        # 1a <locator>` where a BLOB has `02 0b b8 | 02 1f 7c` between the two
        # (#1102).
        return encode_lob_locator_thin(
            locator=encode_bfile_locator(Value.directory, Value.filename)
        )
    if DataType == TNS_TYPE_RID:
        return encode_rowid_value(Value, Codec)
    if DataType == TNS_TYPE_UROWID:
        return encode_urowid_value(Value)
    if DataType in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW):
        return encode_long_value_thin(Value)
    if Value is None:
        return bytes([0])
    if DataType == TNS_TYPE_REF:
        # An object REF (#119/#494) rides as a plain DALC of its opaque locator
        # bytes; the type identity travels in the describe, not the value.
        return Codec.value(getattr(Value, 'bytes', b''))
    if DataType == TNS_TYPE_INTERVALDS and isinstance(Value, datetime.timedelta):
        return Codec.value(encode_token_interval_ds(Value))
    if DataType == TNS_TYPE_INTERVALYM and isinstance(Value, IntervalYM):
        return Codec.value(encode_token_interval_ym(Value))
    if DataType in (TNS_TYPE_CLOB, TNS_TYPE_BLOB, TNS_TYPE_JSON, TNS_TYPE_VECTOR):
        # A thin CLOB / BLOB / JSON / VECTOR value is delivered as an opaque
        # locator; the content follows over TTI_LOBOPS (#413). JSON content is the
        # OSON image, VECTOR the binary image (see oci_lob_contents).
        #
        # Only CLOB / BLOB carry the locator metadata: those are the types the
        # reference client reads with its LOB reader, while JSON and VECTOR go
        # through read_oson / read_vector, which would mis-decode it (#853).
        if DataType in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
            return encode_lob_locator_thin(_lob_value_size(Value), with_metadata=True)
        return encode_lob_locator_thin()
    if DataType == TNS_TYPE_INT and isinstance(Value, (int, float, Decimal)):
        # Oracle's native integer, not a base-100 NUMBER: the client reads it
        # with a 4-byte-max integer read, so a NUMBER encoding comes back as
        # "read integer of length 10 when expecting no more than 4" (#888).
        # A non-numeric value for this type falls through to the branches below
        # rather than raising -- bind leniency is deliberate here.
        return encode_sb4(int(Value))
    if DataType == TNS_TYPE_BOOLEAN:
        # Native SQL BOOLEAN (23ai): a one-byte value, 0x01 for TRUE and 0x00 for
        # FALSE, which the client reads by its last byte (Data[-1] != 0). This must
        # come before the bool branch below — a bool encoded as a NUMBER would make
        # FALSE (NUMBER 0 -> 0x80) read back as TRUE.
        return Codec.value(bytes([1 if Value else 0]))
    if isinstance(Value, bool):
        # No 11g BOOLEAN type; a bool is a NUMBER 0/1 (bool is an int subclass, so
        # match it before the int branch would silently swallow it).
        return Codec.value(encode_token_num(int(Value)))
    if isinstance(Value, (int, float)):
        # A BINARY_FLOAT / BINARY_DOUBLE column carries the IEEE-754 value in
        # Oracle's order-preserving form, not base-100 NUMBER.
        if DataType == TNS_TYPE_BDOUBLE:
            return Codec.value(encode_token_binary_double(float(Value)))
        if DataType == TNS_TYPE_BFLOAT:
            return Codec.value(encode_token_binary_float(float(Value)))
        return Codec.value(encode_token_num(Value))
    if isinstance(Value, Decimal):
        # NUMBER via the exact base-100 Decimal encoder: high-precision values
        # (beyond float's ~15 significant digits) round-trip unchanged.
        return Codec.value(encode_token_decimal(Value))
    if isinstance(Value, (datetime.date, BcDate)):
        # datetime is a date subclass, so this covers both; the column's data_type
        # decides DATE / TIMESTAMP / TIMESTAMPTZ width.
        return Codec.value(_encode_temporal(Value, DataType))
    if isinstance(Value, (str, bytes)):
        # A VARCHAR2 / RAW column value: length-prefixed data, chunked when it
        # exceeds the single-byte length, honouring the negotiated field version.
        return Codec.chr(Value)
    raise NotSupportedError(
        f'no wire encoding for a column value of type {type(Value).__name__}'
    )


def decode_dalc(Bytes: bytes) -> tuple[bytes | list, bytes]:
    # Data with Attached Length Code (PROTOCOL.md §12.2). 0x00 = empty,
    # 0xFF = null marker (no data follows), 0xFE = chunked, otherwise the
    # length byte is followed by that many data bytes. Both empty and null
    # are reported as [] here; callers that need the distinction look at the
    # enclosing bytes_with_length count.
    try:
        if Bytes[0] == 0 or Bytes[0] == 255:
            return ([], Bytes[1:])
        if Bytes[0] == TNS_LONG_LENGTH_INDICATOR:
            return decode_chr(Bytes)
        if Bytes[0] == TNS_ESCAPE_CHAR:
            # The wire's absent-value marker, NOT a length of 253. A bind whose
            # slot carries no inline value -- a pure-OUT bind, or a NULL of a
            # type with no inline form, such as the NULL BOOLEAN the reference
            # client sends -- fills it with the two-byte placeholder `FD 01`.
            # The three bytes above TNS_MAX_SHORT_LENGTH (252) are all markers:
            # 0xFF null, 0xFE chunked, and this one. The first two were honoured
            # here and this one was not, so it was read as a length and the
            # decoder asked for 253 bytes that had never been sent (#869) --
            # which made a complete message look truncated and hung the session
            # waiting for the rest of it (#868).
            #
            # Same reading as the OCI bind path and the 8i encoder's
            # _O8I_OUT_PLACEHOLDER, which have always known this shape.
            if len(Bytes) < 2:
                raise Truncated('DALC: absent-value marker cut short')
            return ([], Bytes[2:])
        Length = Bytes[0]
        if len(Bytes) < Length + 1:
            # The case the IndexError handler below never caught: a length byte
            # that promises more than remains slices quietly (#849).
            raise Truncated(f'DALC: {Length} bytes, {len(Bytes) - 1} left')
        return (Bytes[1 : Length + 1], Bytes[Length + 1 :])
    except IndexError as Exc:
        # A truncated field (empty Bytes, or a chunk length in decode_chr that
        # runs past the buffer) indexes out of range. It says Truncated, not a
        # bare DataError: a reader tells "incomplete, read on" from "complete but
        # bad" by this type (#849), and the Mirror grows a multi-packet request
        # only on Truncated -- a big array DML was refused as unparsable instead
        # (#1097). Truncated IS a DataError, so #230's rule still holds.
        raise Truncated('truncated DALC field') from Exc


def decode_chr(Bytes: bytes) -> tuple[bytes, bytes]:
    if not Bytes:
        raise Truncated('CHR: empty')
    if Bytes[0] == TNS_LONG_LENGTH_INDICATOR:
        # LONG (chunked) value. 12c+ prefixes each chunk with a ub4 length and
        # ends with a zero-length chunk (same framing as _skip_chunked_bytes);
        # 11g uses a single length byte per chunk. The decode field version is
        # set by decode_packet for the current response.
        if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1:
            Rest = Bytes[1:]
            Out = b''
            while True:
                (ChunkLen, Rest) = decode_ub4(Rest)
                if ChunkLen == 0:
                    return (Out, Rest)
                if len(Rest) < ChunkLen:
                    raise Truncated(f'chunk: {ChunkLen} bytes, {len(Rest)} left')
                Out += Rest[:ChunkLen]
                Rest = Rest[ChunkLen:]
        if len(Bytes) < 2:
            raise Truncated('chunked value: no first chunk length')
        j = 1
        i = Bytes[j]
        Out = b''
        while True:
            # Each chunk is followed by at least the next length byte (the 0
            # terminator on the last), so the chunk plus that byte must be there.
            if len(Bytes) < i + j + 2:
                raise Truncated(f'chunk: {i} bytes, {len(Bytes) - j - 1} left')
            Out += Bytes[j + 1 : i + j + 1]
            if Bytes[i + j + 1] == 0:
                break
            j = i + j + 1
            i = Bytes[j]
        return (Out, Bytes[i + j + 1 + 1 :])
    else:
        if len(Bytes) < Bytes[0] + 1:
            raise Truncated(f'CHR: {Bytes[0]} bytes, {len(Bytes) - 1} left')
        return (Bytes[1 : Bytes[0] + 1], Bytes[Bytes[0] + 1 :])


def encode_chr(String: str | bytes) -> bytes:
    Bytes = String.encode('utf-8') if isinstance(String, str) else String
    if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1:
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
        return (
            bytes([TNS_LONG_LENGTH_INDICATOR])
            + Out
            + bytes([Length - i])
            + Bytes[i:]
            + bytes([0])
        )

    return bytes([Length]) + Bytes


def _sorted_by_key(pairs: list) -> list:
    # The pairs in key order, each key's own in the order they came (a stable
    # sort by the key alone). Sorting whole (key, value) tuples put a repeated
    # key's values in value order, and the Mirror's reading of a login's
    # repeated application-context triples paired them up wrongly (#1582).
    return sorted(pairs, key=lambda pair: pair[0])


def decode_kv(
    Data: bytes, Num: int, Acc: list, Flags: dict | None = None
) -> tuple[list, bytes]:
    # Flags (optional) collects each pair's trailing number (its "flag") keyed by
    # key name — needed for AUTH_VFR_DATA, whose flag names the verifier type
    # (#311). Left None by default so existing callers are unchanged.
    if Num <= 0 or not Data:
        return (_sorted_by_key(Acc), Data)

    def decode_to_bin(D):
        if D[0] == 0:
            return (bytes([0]), D[1:])
        else:
            (Size, R) = decode_ub4(D)
            if R[0] == Size:
                return (R[1 : 1 + Size], R[1 + Size :])
            elif R[0] == TNS_LONG_LENGTH_INDICATOR:
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
        return (_sorted_by_key(NewAcc), R1)
    Skip = R1[0] + 1
    return decode_kv(R1[Skip:], Num - 1, NewAcc, Flags)


def encode_kv(Key: bytes, Val: bytes, Padding: int = 0) -> bytes:
    def encode_to_bin(Data):
        Size = len(Data)
        if Size == 0:
            return bytes([0])
        # ub4 total length + the value in write_bytes_with_length form: a 1-byte
        # length for short values, or the 254 chunked marker for values >= 253
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


def _encode_declared_temporal(Value: datetime.date | BcDate, DataType: int) -> bytes:
    """A date or time value as a bind of temporal type ``DataType`` carries it,
    without a length prefix: a declared scalar bind and an object attribute
    alike.

    The width is the type's, as in a column, except that a TIMESTAMP [WITH LOCAL
    TIME ZONE] with no fractional seconds goes out in the 7-byte DATE form, as
    python-oracledb sends it. The server does not read the two forms alike:
    declared LTZ, `trunc(ltz_column) = :midnight` matched the row sent as 7 bytes
    and nothing sent as 11 with a zero fraction (#1337)."""
    Encoded = _encode_temporal(Value, DataType)
    Whole = Encoded[7:] == bytes(4)
    if Whole and DataType in (TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPLTZ):
        return Encoded[:7]
    return Encoded


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
    if isinstance(Value, (datetime.date, BcDate)) and DataType in _DECLARED_TEMPORAL:
        return _bytes_with_length(_encode_declared_temporal(Value, DataType))
    if isinstance(Value, bool) and DataType == TNS_TYPE_NUMBER:
        # From 23.1 a bare bool goes out as a native BOOLEAN value, which a
        # NUMBER descriptor makes the server read as a non-zero NUMBER: False
        # was stored as TRUE (#1201). Declared NUMBER, it is the NUMBER 0 or 1,
        # as python-oracledb sends it.
        Bytes = encode_token_num(int(Value))
        return bytes([len(Bytes)]) + Bytes
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
            #
            # Each ELEMENT of a national array rides as AL16UTF16 too. The
            # charset form is a property of the BIND, not of the value, and an
            # element is encoded as a bare Python value -- so it never reached
            # the csfrm rule below and went out as UTF-8. The server read those
            # bytes as UTF-16BE and got a string of half the length, with no
            # error, because they are a perfectly valid if wrong string (#991).
            Elements = cast(list, Token._value or [])
            National = getattr(Token.dbtype, 'csfrm', 1) == _CSFRM_NCHAR
            Out = encode_sb4(len(Elements))
            for Element in Elements:
                if National and isinstance(Element, str):
                    Out += encode_chr(Element.encode('utf-16-be'))
                    continue
                Out += encode_token_rxd(Element)
            return Out
        if Token.dbtype.tns_type == TNS_TYPE_REFCURSOR:
            return _refcursor_bind_value(Token)
        if Token.dbtype.tns_type == TNS_TYPE_ADT:
            # Object / collection Var: a DbObject value binds as its write_dbobject
            # image; an unset / NULL Var sends the typed-NULL object frame (the
            # OAC's OID names the type), never the bare 0x00 a scalar NULL sends,
            # which the server would misread against read_dbobject (#888).
            if Token._value is None:
                return encode_object_column_value(None, Token.dbtype.oid)
            return _encode_object_bind_value(cast('DbObject', Token._value))
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
        # _vector_bind_oac.
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
        return _refcursor_bind_value(Token)
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
    if isinstance(Token, BcDate):
        # 11 bytes with a fraction, else the 7-byte form, which a TIMESTAMP
        # descriptor takes too (#1804, #1805).
        Kind = TNS_TYPE_TIMESTAMP if Token.microsecond else TNS_TYPE_DATE
        return _bytes_with_length(_encode_temporal(Token, Kind))
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
        + _oac_col_id()  # oaccolid (12.2+)
    )


# Native JSON bind OAC (#70): type 119, 32 MiB max. Native VECTOR bind OAC (#62):
# type 127, 1 MiB max. Both were captured verbatim from python-oracledb (21c /
# 23ai); the capture is now reproduced field-by-field. Built per bind, not once
# at import: the trailing oaccolid depends on the session's version, and 23ai
# serves VECTOR to a session that negotiated 12.1 / 12.2 as well (#1148).
def _json_bind_oac() -> bytes:
    return _encode_native_lob_oac(TNS_TYPE_JSON, 0x02000000)  # 32 MiB


def _vector_bind_oac() -> bytes:
    return _encode_native_lob_oac(TNS_TYPE_VECTOR, 0x00100000)  # 1 MiB


def _encode_lob_bind_oac(is_blob: bool, csfrm: int = _CSFRM_DB) -> bytes:
    """The CLOB / BLOB bind OAC: type 0x70 / 0x71 with the LOB cont-flag
    0x02000000 (the flag the native VECTOR / JSON OACs set too). Built explicitly
    because encode_token_raw zeroes the cont-flag.

    The max-data-length field is the LOB's fixed buffer-size factor (112 for both
    CLOB and BLOB, what python-oracledb announces for every LOB bind), NOT the
    value's byte budget: the server reads a length of 0 there as "no LOB here"
    and binds NULL, and a Var's declared size instead is rejected outright
    (ORA-03120, two-task integer overflow), which is why a declared CLOB / BLOB
    bind had no encoder until now (#902). The same OAC serves a temp-LOB locator
    bind (#91) and a declared CLOB / BLOB Var (#902); a Var's IN value is promoted
    to a temp LOB before it reaches the wire, so only its type matters here.

    An NCLOB is the CLOB OAC with charset form 2, and nothing else changes -- its
    charset id stays 873, measured against a live 23ai (#1066). That is NOT what
    its CREATE_TEMP does, which carries 2000 (_create_temp_body); the two were
    each captured, not inferred from the other."""
    return (
        bytes([TNS_TYPE_BLOB if is_blob else TNS_TYPE_CLOB, 1, 0, 0])
        + encode_sb4(_LOB_BIND_BUFFER_SIZE)  # max data length (fixed, not value)
        + encode_sb4(0)  # max number of array elements
        + encode_sb4(0x02000000)  # cont flag (ub8) — LOB
        + encode_sb4(0)  # OID
        + encode_sb4(0)  # version
        + encode_sb4(0 if is_blob else AL32UTF8_CHARSET)  # charset id (ub2)
        + bytes([0 if is_blob else csfrm])  # character set form
        + encode_sb4(0)  # LOB prefetch length
        + _oac_col_id()  # oaccolid (12.2+)
    )


# The OAC a REF CURSOR bind carries, IN or OUT alike -- the reference client
# sends the same one for both, and only the value after it differs (#1047).
# Buffer 4 and charset 0, not 1 and the DB charset: a cursor id is a number, not
# text. The narrower form worked for an OUT bind, where the server fills the
# slot itself and the declared size never has to hold anything; handing it an id
# to READ, the server sized its buffer from this and then waited for bytes that
# did not fit -- a HANG rather than an error.
def _refcursor_bind_oac() -> bytes:
    return encode_token_raw(TNS_TYPE_REFCURSOR, 4, 0, 0, 0)


def _refcursor_bind_value(Token: object) -> bytes:
    """A REF CURSOR bind's value: the server-side cursor id (#1047).

    Zero is the OUT form -- "open a cursor for me and tell me its id" -- and is
    what every REF CURSOR bind sent until now, because the id was hard-coded.
    A non-zero id is an IN bind handing the server a cursor it already has:
    `cursor.execute(plsql, rcursor=open_cursor)`, which a PL/SQL block declares
    as a plain `sys_refcursor` IN parameter and fetches from.

    The value is a **presence byte** then the id as a ub4. Captured from the
    reference client, which sends the SAME OAC either way and differs only
    here::

        07 00              OUT: RXD, then an absent value
        07 01 01 01 03     IN:  present, one of them, then ub4 3 -- the id

    The OUT form keeps its historical `01 00` spelling, which the server has
    accepted for years even though the reference client sends the barer `00`.
    Only the IN form is new, and it needs BOTH leading bytes: with the id alone
    the server sizes a value it never receives and waits -- a HANG, not an
    error, which is what makes a byte-for-byte capture the only way to find it.
    """
    CursorId = getattr(Token, 'id', 0) or 0
    if not CursorId:
        return bytes([1, 0])
    return bytes([1, 1]) + encode_sb4(CursorId)


# The longest universal rowid's text, which a ROWID / UROWID bind is sized for.
_MAX_UROWID_LENGTH = 5267


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
        if DT in (TNS_TYPE_RID, TNS_TYPE_UROWID):
            # A ROWID / UROWID Var binds as a VARCHAR of the longest universal
            # rowid, 5267 characters, and its value is the rowid's text -- what
            # the reference client sends, captured on 23ai. There is no bind form
            # of the binary rowid a fetch returns, so this raised (#1397).
            return encode_token_raw(
                TNS_TYPE_VARCHAR, _MAX_UROWID_LENGTH, 16, CharCs, 0, A
            )
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
            return _refcursor_bind_oac()
        if DT == TNS_TYPE_ADT:
            # An object / collection Var (cursor.var(objtype)): the object bind
            # OAC carrying the type's 16-byte OID + version, sized for the server
            # to return into. Pairs with a DbObject value or a typed NULL (#888).
            return _object_oac(
                Token.dbtype.oid, Token.dbtype.version, _OBJECT_OAC_BUFFER_SIZE
            )
        if DT == TNS_TYPE_BOOLEAN:
            # Native BOOLEAN Var, what setinputsizes(bool) / DB_TYPE_BOOLEAN
            # produces (#870). The same OAC a plain bool value already gets --
            # type 252, fixed size 4 -- and the same pre-23ai fallback to NUMBER,
            # which pairs with the NUMBER value encode_token_rxd writes there.
            # Only this Var path was missing, so binding a boolean through a Var
            # raised and, through the Mirror, surfaced as ORA-00600.
            if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_23_1:
                return encode_token_raw(TNS_TYPE_BOOLEAN, 4, 0, 0, 0, A)
            return encode_token_raw(TNS_TYPE_NUMBER, 22, 0, 0, 0, A)
        if DT in (TNS_TYPE_CLOB, TNS_TYPE_BLOB) and (
            _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1
        ):
            # A declared CLOB / BLOB Var (cursor.var / setinputsizes): the fixed
            # LOB bind OAC, not one sized from the Var (that overflows,
            # ORA-03120). A non-NULL IN value is promoted to a temp LOB before
            # encoding (Cursor._promote_lob_var_binds), so this OAC pairs either
            # with that locator or with a NULL value (a pure OUT / NULL bind).
            # 11g has no CREATE_TEMP for the promotion, so a CLOB / BLOB Var there
            # keeps raising below rather than emitting a bind it cannot back. #902.
            return _encode_lob_bind_oac(DT == TNS_TYPE_BLOB)
        if DT == TNS_TYPE_JSON:
            # The same OAC a JSON value binds with; only the Var path was
            # missing, so setinputsizes(DB_TYPE_JSON) raised (#902).
            return _json_bind_oac()
        if DT == TNS_TYPE_VECTOR:
            return _vector_bind_oac()
        if DT == TNS_TYPE_INT:
            # BINARY_INTEGER / PLS_INTEGER Var (#1044). Captured from the
            # reference client binding one as an OUT param: type 3, buffer 22 --
            # the NUMBER buffer, because the VALUE rides the wire as an Oracle
            # NUMBER. Only the declared TYPE differs, and it is what makes the
            # server truncate (`:v := 2.9` yields 2) and what resolves a call
            # overloaded on NUMBER vs BINARY_INTEGER.
            return encode_token_raw(TNS_TYPE_INT, 22, 0, 0, 0, A)
        if DT == TNS_TYPE_TIMESTAMPLTZ:
            # 11 bytes, like TIMESTAMP -- the local-time-zone variant carries no
            # extra offset on the wire, the session's zone supplies it.
            return encode_token_raw(TNS_TYPE_TIMESTAMPLTZ, 11, 0, 0, 0, A)
        if DT in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW):
            # LONG-class Var: the declared buffer, character for LONG and binary
            # for LONG RAW. The value itself still rides after the row
            # (see the LONG-bind note in encode_dictionary_exec).
            return encode_token_raw(
                DT, Token.size, 16, 0 if DT == TNS_TYPE_LONGRAW else CharCs, 0, A
            )
        raise NotSupportedError(
            f'no bind encoding for data type {DT}',
        )
    if isinstance(Token, TempLob):
        # Temp-LOB locator bind (#91): a CLOB / BLOB OAC carrying the LOB
        # cont-flag 0x02000000 (the same flag the native VECTOR / JSON OACs
        # set). Built explicitly because encode_token_raw zeroes the cont-flag.
        #
        # The max-data-length field is the LOB's fixed buffer-size factor, NOT
        # the source value's byte budget: python-oracledb announces its DB_TYPE
        # buffer_size_factor (112 for both CLOB and BLOB) for every temp-LOB
        # bind regardless of the value's size, and the server reads a length of
        # 0 as "no LOB here" and stores NULL. Announcing the value size worked
        # for a non-empty LOB (any non-zero length does) but bound an **empty**
        # temp LOB as NULL -- ORA-01400 on a NOT NULL column, and a silent NULL
        # otherwise (#903).
        return _encode_lob_bind_oac(Token.is_blob, getattr(Token, 'csfrm', _CSFRM_DB))
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
            return _json_bind_oac()
        Token = _json_bind_text(Token)
    elif is_vector_bind(Token):
        # Native VECTOR bind on 23ai (#62): the fixed OAC python-oracledb sends
        # (built above). The image rides in encode_token_rxd.
        return _vector_bind_oac()
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
        return _refcursor_bind_oac()
    if isinstance(Token, date):
        if Token.has_timestamp and Token.timestamptz:
            return encode_token_raw(TNS_TYPE_TIMESTAMPTZ, 13, 0, 0, 0)
        if Token.has_timestamp:
            return encode_token_raw(TNS_TYPE_TIMESTAMP, 11, 0, 0, 0)
        return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0)
    if isinstance(Token, datetime.datetime):
        if Token.tzinfo is not None:
            return encode_token_raw(TNS_TYPE_TIMESTAMPTZ, 13, 0, 0, 0)
        if _is_wide_datetime(Token):
            return encode_token_raw(TNS_TYPE_TIMESTAMP, 11, 0, 0, 0)
        return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0)
    if isinstance(Token, datetime.date):
        return encode_token_raw(TNS_TYPE_DATE, 7, 0, 0, 0)
    if isinstance(Token, BcDate):
        # A date before year 1 takes a datetime's undeclared type (#1804).
        if _is_wide_datetime(Token):
            return encode_token_raw(TNS_TYPE_TIMESTAMP, 11, 0, 0, 0)
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
_OBJ_MAX_SHORT_LEN = 245  # TNS_OBJ_MAX_SHORT_LENGTH
# toid wrapper for a new object: 00 22 (NON_NULL_OID | HAS_EXTENT_OID) + oid +
# the fixed extent OID (python-oracledb create_new_object).
_OBJ_TOID_PREFIX = bytes([0x00, 0x22, 0x02, 0x08])
_OBJ_EXTENT_OID = bytes.fromhex('00000000000000000000000000010001')


def _obj_write_length(Length: int) -> bytes:
    # python-oracledb DbObjectPickleBuffer.write_length.
    if Length <= _OBJ_MAX_SHORT_LEN:
        return bytes([Length])
    return bytes([TNS_LONG_LENGTH_INDICATOR]) + struct.pack('>I', Length)


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
        # A national attribute (NVARCHAR2 / NCHAR) is AL16UTF16 in the image,
        # as in a column (#1433); everything else is the AL32UTF8 session's.
        if Charset == AL16UTF16_CHARSET:
            return str(Value).encode('utf-16-be')
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
        # The attribute's type sets the width, not the value: a fraction sent
        # into a DATE attribute or a zone into a TIMESTAMP one was read as
        # something else, and a plain date crashed the bind (#1803).
        return _encode_declared_temporal(Value, DataType)
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
        return bytes([TNS_NULL_LENGTH_INDICATOR])
    if DataType in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
        from seerdb.common.lob import LOB

        if isinstance(Value, LOB):
            # A LOB bound into an object attribute: the image field is the
            # locator verbatim, which starts with its own ub2 length -- a fetched
            # one (`00 70` + 112 bytes) as much as a temp one (`00 26` + 38), both
            # captured against a live 23ai (#1260). A LOB's raw is that form
            # already; adding another ub2 made the server refuse it (ORA-22275).
            # Distinct from the fetch path below, whose value is content.
            return _obj_write_length(len(Value.raw)) + Value.raw
        # A LOB attribute the Mirror emits to an external client: it rides as a
        # minted locator the client reads back over TTI_LOBOPS. The value here is
        # the content, so it is not written inline -- only the locator is. In a
        # session each attribute LOB gets its own locator, recorded with its
        # content in the emit log as a column LOB's is, so a read is answered by
        # locator whatever the order, and a bind of it back resolves (#1262).
        # Without a log, the one shared locator and the attribute-order queue of
        # object_lob_contents (#888).
        log = _LOB_EMIT_LOG.get()
        if log is not None:
            locator = log.record(Value, DataType == TNS_TYPE_CLOB)
            return _obj_write_length(len(locator)) + locator
        return _obj_write_length(len(_THIN_OBJ_LOB_LOCATOR)) + _THIN_OBJ_LOB_LOCATOR
    Raw = _encode_object_attr(DataType, Charset or AL32UTF8_CHARSET, Value)
    return _obj_write_length(len(Raw)) + Raw


def encode_object_image(Obj: 'DbObject') -> bytes:
    # Pack a DbObject into its image, the inverse of dbobject.decode_object_image
    # and matching python-oracledb _pack_data / _pack_value. Recurses into nested
    # object / collection attributes: an object attribute of an object rides
    # inline (no header); a collection attribute, and any object / collection
    # inside a collection, is a length-prefixed full image; a NULL nested object
    # is the atomic-null 0xFD, a NULL collection 0xFF (#117/#118).
    return _encode_object_image(Obj, header=True)


def _encode_object_image(Obj: 'DbObject', *, header: bool) -> bytes:
    Typ = Obj._dbtype
    if Typ is not None and Typ.is_collection:
        from seerdb.common.dbobject import (
            _COLL_HAS_INDEXES,
            COLLECTION_PLSQL_INDEX_TABLE,
        )

        Element = Typ.element or {}
        index_table = Typ.collection_type == COLLECTION_PLSQL_INDEX_TABLE
        # A PL/SQL associative array sets the HAS_INDEXES collection flag (0x10)
        # and prefixes each element with its int32 key; a SQL VARRAY / nested
        # table clears the flag and carries bare elements (#888).
        Body = bytes([_COLL_HAS_INDEXES if index_table else 0])
        Body += _obj_write_length(len(Obj._elements))
        # The keys the value arrived with, when it came off the wire. A locally
        # built array has none, and then the key is the 1-based position -- but a
        # DECODED one must go back out under its OWN keys: an index-by table may
        # be keyed by any BINARY_INTEGER, and renumbering it 1..N hands the far
        # side a faithfully framed image full of wrong numbers (#1053).
        Keys = Obj._keys if index_table else None
        for Position, Value in enumerate(Obj._elements):
            if index_table:
                # Zero-based when the object carries no keys of its own: PL/SQL
                # written for these arrays indexes from 0, and a 1-based array
                # makes `a(0)` raise NO_DATA_FOUND (#1055).
                Key = Keys[Position] if Keys is not None else Position
                # SIGNED: the negative half of BINARY_INTEGER is ordinary (a live
                # 23ai sends -1048576 as ff f0 00 00). Packing '>I' agrees for
                # every key a dense 1..N array has and raises on a real one.
                Body += struct.pack('>i', Key)
            Body += _encode_object_member(Value, Element, in_collection=True)
        # Collection header = flags, version, long-form length, prefix seg (01 01).
        Total = 9 + len(Body)
        return (
            bytes(
                [
                    _OBJ_IMAGE_FLAGS_COLLECTION,
                    _OBJ_IMAGE_VERSION,
                    TNS_LONG_LENGTH_INDICATOR,
                ]
            )
            + struct.pack('>I', Total)
            + bytes([1, 1])
            + Body
        )
    Body = b''
    for Attr in Typ.attrs:
        Body += _encode_object_member(
            Obj._attrs.get(Attr['name']), Attr, in_collection=False
        )
    if not header:
        # A nested object attribute embeds its attributes inline, no header.
        return Body
    # Header length is written long-form (0xFE + ub4) and covers the whole image
    # (the 7-byte header included), matching python-oracledb write_header.
    Total = 7 + len(Body)
    return (
        bytes([_OBJ_IMAGE_FLAGS, _OBJ_IMAGE_VERSION, TNS_LONG_LENGTH_INDICATOR])
        + struct.pack('>I', Total)
        + Body
    )


def _encode_object_member(Value: object, Attr: dict, *, in_collection: bool) -> bytes:
    from seerdb.common.dbobject import (
        _IMAGE_INT32_TYPES,
        _OBJ_ATOMIC_NULL,
        DbObject,
        encode_image_int32,
        encode_xmltype,
        is_xml_type,
    )

    Nested = Attr.get('object_type')
    if Nested is not None and is_xml_type(Nested):
        # An XMLType attribute rides as a length-prefixed XMLType image; a NULL is
        # the 0xFF marker, not the atomic-null a normal nested object uses (#124).
        if Value is None:
            return bytes([TNS_NULL_LENGTH_INDICATOR])
        Image = encode_xmltype(Value)
        return _obj_write_length(len(Image)) + Image
    if Nested is not None and getattr(Nested, 'is_collection', False):
        if Value is None:
            return bytes([TNS_NULL_LENGTH_INDICATOR])
        Image = _encode_object_image(cast(DbObject, Value), header=True)
        return _obj_write_length(len(Image)) + Image
    if Nested is not None:
        if Value is None:
            return bytes([_OBJ_ATOMIC_NULL])
        if in_collection:
            Image = _encode_object_image(cast(DbObject, Value), header=True)
            return _obj_write_length(len(Image)) + Image
        # An object attribute of an object: its attributes inline, no header.
        return _encode_object_image(cast(DbObject, Value), header=False)
    if Attr.get('data_type') in _IMAGE_INT32_TYPES:
        # A BOOLEAN or PL/SQL integer member is a ub4 in the image (#1607).
        if Value is None:
            return bytes([TNS_NULL_LENGTH_INDICATOR])
        return encode_image_int32(cast(int, Value))
    return _encode_object_attr_field(
        cast(int, Attr.get('data_type')),
        Attr.get('charset') or AL32UTF8_CHARSET,
        Value,
    )


def object_lob_contents(
    columns: list[ColumnMeta], rows: list[tuple]
) -> list[tuple[bytes, bool]]:
    """The (wire-content, is_clob) of every LOB attribute embedded in an object
    (ADT) column of ``rows``, row-major then attribute-order — the order the
    external client reads them back over TTI_LOBOPS after decoding the images.

    These ride a **distinct** locator (:data:`_THIN_OBJ_LOB_LOCATOR`) and a
    session-persistent queue, kept apart from the top-level LOB queue: an object
    column's type has to be populated after the describe, and that runs several
    ``get_type_shape`` metadata queries which would otherwise reset a single
    shared queue before the client ever issued its LOB reads (#888)."""
    out: list[tuple[bytes, bool]] = []
    for row in rows:
        for value, col in zip(row, columns):
            if col.data_type == TNS_TYPE_ADT and value is not None:
                out.extend(_object_lob_contents(value))
    return out


def _object_lob_contents(Obj: object) -> list[tuple[bytes, bool]]:
    """The (wire-content, is_clob) of every non-NULL LOB attribute in an object
    (or collection) value, in the exact order :func:`_encode_object_image` emits
    their locators — so the session drains this queue as the client issues its
    TTI_LOBOPS reads for the LOBs it decoded out of the image (#888).

    CLOB / NCLOB content rides as UTF-16BE (``is_clob`` True, char-counted);
    BLOB content is raw bytes. A NULL attribute contributes nothing (its image
    field is the 0xFF null, which the client never reads as a LOB). Nested
    objects and collections are walked recursively, matching the encoder."""
    from seerdb.common.dbobject import DbObject

    if not isinstance(Obj, DbObject):
        return []
    Typ = Obj._dbtype
    out: list[tuple[bytes, bool]] = []
    if Typ is not None and Typ.is_collection:
        Element = Typ.element or {}
        for Value in Obj._elements:
            out += _member_lob_contents(Value, Element)
        return out
    if Typ is None:
        return out
    for Attr in Typ.attrs:
        out += _member_lob_contents(Obj._attrs.get(Attr['name']), Attr)
    return out


def _member_lob_contents(Value: object, Attr: dict) -> list[tuple[bytes, bool]]:
    # One attribute / element's LOB content, mirroring _encode_object_member: a
    # nested object / collection recurses; a scalar contributes only when it is a
    # non-NULL CLOB / BLOB.
    if Attr.get('object_type') is not None:
        return _object_lob_contents(Value) if Value is not None else []
    if Value is None:
        return []
    DataType = Attr.get('data_type')
    from seerdb.common.lob import LOB

    if isinstance(Value, LOB):
        # An upstream LOB bound into an object attribute carries a real locator
        # (its content is not the Mirror's to serve), so it queues nothing (#888).
        return []
    if DataType == TNS_TYPE_CLOB:
        return [(str(Value).encode('utf-16-be'), True)]
    if DataType == TNS_TYPE_BLOB:
        return [(bytes(cast('bytes', Value)), False)]
    return []


def _encode_object_frame(Toid: bytes, Image: bytes | None) -> bytes:
    # The frame every ADT value rides in, whatever the image inside it is
    # (_OBJECT_FRAME): the constructed toid, an empty object OID, zero
    # snapshot / version, the image length, the TOP_LEVEL flags, then the image
    # -- none for a NULL, whose length gate is zero (#116).
    return _OBJECT_FRAME_THIN(
        {
            'toid_length': len(Toid),
            'toid': Toid,
            'oid_length': 0,  # object OID (empty for new)
            'snapshot': 0,
            'version': 0,
            'image_length': len(Image or b''),
            'flags': _OBJ_TOP_LEVEL,
            'has_image': Image is not None,
            'image': Image,
        }
    )


def _encode_object_bind_value(Obj: 'DbObject') -> bytes:
    # The bind value framing (python-oracledb write_dbobject).
    Typ = Obj._dbtype
    return _encode_object_frame(
        _OBJ_TOID_PREFIX + Typ.oid + _OBJ_EXTENT_OID, encode_object_image(Obj)
    )


def encode_object_column_value(Value: object, TypeOid: bytes = b'') -> bytes:
    """The RXD wire form of a SQL object (ADT, type 109) column value — the
    inverse of :func:`_read_object_column`, matching python-oracledb
    ``write_dbobject``.

    A populated value reuses the object bind framing (``_encode_object_bind_value``):
    the constructed toid, an empty object OID, zero snapshot/version, the image
    length, the TOP_LEVEL flags, then the packed image. A NULL object still carries
    the whole frame with a zero image-length gate (and the column's type toid when
    known), exactly as Oracle does, so the row stream stays in sync — a bare 0x00
    DALC would desync the reader (#116).

    An **XMLType** column is an ADT by describe (type 109, `SYS.XMLTYPE`) but its
    value is a document, not an object: a backend hands it over as a `str`, since
    that is what every client surfaces it as. It rides the same frame with an XML
    image inside (§21.10) rather than a packed object image -- encoding it as an
    object asked a `str` for its `_dbtype` and took the session down with it
    (#826)."""
    if isinstance(Value, str):
        from seerdb.common.dbobject import encode_xmltype

        Toid = _OBJ_TOID_PREFIX + TypeOid + _OBJ_EXTENT_OID if TypeOid else b''
        return _encode_object_frame(Toid, encode_xmltype(Value))
    if Value is not None:
        return _encode_object_bind_value(cast('DbObject', Value))
    Toid = _OBJ_TOID_PREFIX + TypeOid + _OBJ_EXTENT_OID if TypeOid else b''
    return _encode_object_frame(Toid, None)


# Buffer size the OAC of an object OUT bind advertises when there is no value to
# size it from (a pure OUT / typed-NULL bind) — the same figure a fetched object
# column describes with (§21.1). The image is self-delimiting, so the exact value
# is not load-bearing for the read.
_OBJECT_OAC_BUFFER_SIZE = 2000


def _object_oac(oid: bytes, version: int, buffer_size: int) -> bytes:
    # The bind OAC for an object (type 109): the 12c+ metadata layout injecting
    # the type's 16-byte OID + version (precision/scale 0, no charset). Mirrors
    # python-oracledb _write_column_metadata's object branch. 12c+ only — pre-12c
    # object binds are gated in the cursor (no thin reference for that OAC).
    return (
        bytes([TNS_TYPE_ADT, 1, 0, 0])  # type, flag (USE_INDICATORS), p, s
        + encode_sb4(buffer_size)  # buffer size
        + encode_sb4(0)  # max number of array elements
        + encode_sb4(0)  # cont flag (ub8)
        + _obj_two_lengths(oid)  # type OID (16 bytes)
        + encode_sb4(version)  # type version
        + encode_sb4(0)  # charset id (ub2)
        + bytes([0])  # character set form
        + encode_sb4(0)  # LOB prefetch length
        + _oac_col_id()
    )  # oaccolid (12.2+)


def _encode_object_oac(Obj: 'DbObject') -> bytes:
    # A populated object value's bind OAC. The buffer size is 0, as
    # python-oracledb sends for every object bind: the image carries its own
    # length. It was the image length, which every server accepted too (#1806).
    Typ = Obj._dbtype
    return _object_oac(Typ.oid, Typ.version, 0)


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
        + _oac_col_id()
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
    # and (at fv >= 21.1) a shard id -- the layout python-oracledb sends.
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
    # AQ enqueue (TNS_FUNC_AQ_ENQ): the layout of python-oracledb's AqEnqMessage.
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
    # AQ dequeue (TNS_FUNC_AQ_DEQ): the layout of python-oracledb's AqDeqMessage.
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
    # AQ array enqueue / dequeue (TNS_FUNC_ARRAY_AQ): the layout of python-oracledb's
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
    # A zero fraction is the 7-byte form, even for a value whose batch is
    # declared TIMESTAMP (#1805).
    if DT.microsecond:
        return _encode_date_prefix(DT) + (DT.microsecond * 1000).to_bytes(4, 'big')
    return _encode_date_prefix(DT)


def _encode_date_prefix(DT: datetime.datetime | BcDate) -> bytes:
    # Century and year-of-century, each biased by 100. A BC year counts DOWN
    # from the bias: -4712 is century 53, year 88 (35 58), the inverse of what
    # decode_date reads (#1071).
    (Century, YearOfCentury) = divmod(abs(DT.year), 100)
    Sign = -1 if DT.year < 0 else 1
    return bytes(
        [
            Sign * Century + 100,
            Sign * YearOfCentury + 100,
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


def _oac_col_id() -> bytes:
    # The trailing `oaccolid` of a hand-built bind OAC. A 12.2+ server reads it
    # and a 12.1 one does not: sent to a 12.1 session it is one byte too many
    # and the server refuses the call (ORA-03106 / ORA-03120) (#1144). Below
    # 12.1 the byte stays, as it always has been sent there.
    field_version = _ENCODE_FIELD_VERSION.get()
    if FIELD_VERSION_12_1 <= field_version < FIELD_VERSION_12_2:
        return b''
    return encode_sb4(0)


def encode_token_raw(
    DataType: int, Length: int, Flag: int, Charset: int, Max: int, Array: int = 0
) -> bytes:
    # Array > 0 marks a PL/SQL associative-array bind (#122): the flag gains
    # TNS_BIND_ARRAY (0x40) and the max-number-of-array-elements field carries
    # the array's declared capacity (0 for a scalar bind).
    FormOfUse = 2 if Charset == AL16UTF16_CHARSET else 1
    if _ENCODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1:
        # 12c+ bind OAC (oracledb _write_column_metadata): a fixed flag byte
        # (TNS_BIND_USE_INDICATORS = 1), a ub8 cont-flag, OID + version, the
        # bind charset as a ub2 (AL32UTF8 / AL16UTF16, 0 for non-char), the
        # csfrm byte, a LOB-prefetch length, and -- from 12.2 only -- a
        # trailing oaccolid ub4. The 11g layout below is shorter/differently
        # shaped and a 12c server rejects it with ORA-03115 (unsupported network
        # datatype); a 12.1 session needs this one too, less the oaccolid
        # (#1144).
        if Charset == 0:
            BindCharset, Csfrm = 0, 0
        elif Charset == AL16UTF16_CHARSET:
            BindCharset, Csfrm = AL16UTF16_CHARSET, 2
        else:
            BindCharset, Csfrm = AL32UTF8_CHARSET, 1
        FlagByte = TNS_BIND_USE_INDICATORS | (TNS_BIND_ARRAY if Array else 0)
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
            + _oac_col_id()  # oaccolid (12.2+)
        )
    FlagOut = (Flag | TNS_BIND_ARRAY) if Array else Flag
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
