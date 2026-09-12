# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

from typing import TYPE_CHECKING, Any, Literal, cast

if TYPE_CHECKING:
    from seerdb.common.ano_session import AnoChannel
    from seerdb.common.dbobject import DbObjectType

import logging
import socket
import struct
import threading
import time
import uuid

from seerdb.client._conn_logic import (
    _ConnectionLogic,
    _pre10_tier_name_for,
    returning_block_error,
    returning_block_request,
    returning_block_result,
)
from seerdb.client.dialect import (
    CAP_ARRAY_DML,
    CAP_OWN_TXN,
    Dialect,
    O8iDialect,
)
from seerdb.common.crypto import validate
from seerdb.common.exceptions import (
    DatabaseError,
    InterfaceError,
    NotSupportedError,
    OperationalError,
)
from seerdb.common.sqltext import is_reusable_dml
from seerdb.common.tns import (
    _DTY_8I,
    assemble_packet,
    decode_packet,
    decode_token_pro,
    decode_token_rpa,
    encode_aq_array,
    encode_aq_deq,
    encode_aq_enq,
    encode_data_packet,
    encode_dictionary,
    encode_dictionary_auth,
    encode_fast_auth,
    encode_packet,
    encode_pipeline_begin,
    encode_pipeline_end,
    encode_tpc_change_state,
    encode_tpc_switch,
    exec_oac_signature,
    find_fast_auth_rpa,
    has_long_class_bind,
    max_string_size,
    set_decode_dml_rowcounts,
    set_decode_prev_row,
    set_decode_return_binds,
)
from seerdb.common.tns_consts import (
    CCAP_FIELD_VERSION,
    CONN_STATE_AUTH_NEGOTIATE,
    CONN_STATE_AUTHENTICATED,
    CONN_STATE_CONNECTED,
    CONN_STATE_DISCONNECTED,
    DEFAULT_SDU,
    FIELD_VERSION_9_2,
    FIELD_VERSION_10_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_12_2,
    FIELD_VERSION_21_1,
    FIELD_VERSION_23_1,
    FIELD_VERSION_23_4,
    MAX_SEQ_NUM,
    PURITY_DEFAULT,
    TNS_ACCEPT,
    TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE,
    TNS_CONNECT,
    TNS_DATA,
    TNS_DATA_FLAGS_BEGIN_PIPELINE,
    TNS_DATA_FLAGS_END_OF_REQUEST,
    TNS_DATA_FLAGS_EOF,
    TNS_DATA_FLAGS_MORE,
    TNS_FETCH_ORIENTATION_CURRENT,
    TNS_GSO_CAN_RECV_ATTENTION,
    TNS_MARKER,
    TNS_MARKER_TYPE_INTERRUPT,
    TNS_MARKER_TYPE_RESET,
    TNS_PIPELINE_MODE_CONTINUE_ON_ERROR,
    TNS_REDIRECT,
    TNS_REFUSE,
    TNS_RESEND,
    TNS_SESSION_STATE_REQUEST_END,
    TNS_SESSIONLESS_TXN_ID_MAX,
    TNS_TPC_SESSIONLESS_FORMAT_ID,
    TNS_TPC_TXN_ABORT,
    TNS_TPC_TXN_COMMIT,
    TNS_TPC_TXN_DETACH,
    TNS_TPC_TXN_PREPARE,
    TNS_TPC_TXN_START,
    TNS_TPC_TXN_STATE_ABORTED,
    TNS_TPC_TXN_STATE_COMMITTED,
    TNS_TPC_TXN_STATE_FORGOTTEN,
    TNS_TPC_TXN_STATE_READ_ONLY,
    TNS_TPC_TXN_STATE_REQUIRES_COMMIT,
    TNS_VERSION_MIN_LARGE_SDU,
    TNS_VERSION_MIN_OOB_CHECK,
    TPC_BEGIN_NEW,
    TPC_BEGIN_RESUME,
    TPC_END_NORMAL,
    TPC_TXN_FLAGS_SESSIONLESS,
    TTI_AUTH,
    TTI_DTY,
    TTI_FOB,
    TTI_OER,
    TTI_PRO,
    TTI_RPA,
    TTI_SESS,
    TTI_WRN,
    DictionaryType,
)

logger = logging.getLogger(__name__)

# Cap how many times we'll chase a TNS_REDIRECT during one login, so a
# misconfigured listener that redirects in a loop fails fast instead of
# spinning forever.
_MAX_REDIRECTS = 5

# When following a TNS_REDIRECT, the target may be a shared-server dispatcher or a
# dedicated-server process still binding its (often dynamic) port — connecting the
# instant the redirect arrives loses that spawn race with ConnectionRefused. Retry
# the redirect-follow connect a few times over ~1s. The INITIAL connect is never
# retried: a refused address the user handed us should fail fast. (#399)
_REDIRECT_CONNECT_ATTEMPTS = 10
_REDIRECT_CONNECT_DELAY = 0.1

# A pipelined fetchall (#158) can't interleave follow-up TTI_FETCH calls inside
# the burst, so its execute asks for a large prefetch to pull the whole result
# set inline; any overflow is drained serially once the burst is read.
_PIPELINE_FETCH_ALL_PREFETCH = 32760


def _format_version(Packed: int) -> str | None:
    # Oracle packs the release into a single integer: major (8 bits),
    # minor (4), update (8), patch (4), port-specific update (8). Verified
    # against product_component_version on XE 11.2.0.2.0 (0x0b200200).
    if not Packed:
        return None
    return '%d.%d.%d.%d.%d' % (
        (Packed >> 24) & 0xFF,
        (Packed >> 20) & 0x0F,
        (Packed >> 12) & 0xFF,
        (Packed >> 8) & 0x0F,
        Packed & 0xFF,
    )


import collections

# Global transaction identifier for two-phase commit (#131): a (format_id,
# global_transaction_id, branch_qualifier) triple, matching oracledb's Xid.
Xid = collections.namedtuple(
    'Xid', ['format_id', 'global_transaction_id', 'branch_qualifier']
)


def _raise_tpc_error(Packet: bytes) -> None:
    # A TPC op that failed comes back as a TTI_OER (not the RPA return params).
    # Pull the ORA code + message out of it and raise the matching exception.
    from seerdb.common.exceptions import from_ora_code
    from seerdb.common.tns import decode_packet

    try:
        Result = decode_packet(Packet, (None, None, []))
        Code = Result[1] if isinstance(Result, tuple) and len(Result) > 1 else 0
        Msg = Result[5] if isinstance(Result, tuple) and len(Result) > 5 else None
    except Exception:
        Code, Msg = 0, None
    if Code:
        raise from_ora_code(Code)(Msg or f'ORA-{Code:05d}', code=Code)
    raise DatabaseError(f'unexpected TPC response 0x{Packet[:1].hex()}')


def _decode_tpc_context(Packet: bytes) -> bytes:
    # TPC switch (begin) return parameters (#131): leads with the RPA token
    # (TTI_RPA = TNS_MSG_TYPE_PARAMETER), then an application value (ub4), a
    # context length (ub2), and the opaque transaction context bytes. RE'd from
    # a live 21c tpc_begin capture; the context is replayed on prepare/commit.
    from seerdb.common.tns import decode_ub4

    if not Packet:
        raise OperationalError('empty TPC response')
    if Packet[0] != TTI_RPA:
        _raise_tpc_error(Packet)
    Rest = Packet[1:]
    (_AppValue, Rest) = decode_ub4(Rest)
    (CtxLen, Rest) = decode_ub4(Rest)  # context length (ub2)
    return bytes(Rest[:CtxLen])


def _decode_aq_enq(Packet: bytes) -> bytes:
    # AQ enqueue return: the RPA token then the 16-byte message id (the trailing
    # ub2 extensions length is ignored). #128.
    from seerdb.common.tns_consts import TNS_AQ_MESSAGE_ID_LENGTH

    if not Packet:
        raise OperationalError('empty AQ enqueue response')
    if Packet[0] != TTI_RPA:
        _aq_raise(Packet)
    return bytes(Packet[1 : 1 + TNS_AQ_MESSAGE_ID_LENGTH])


import re as _re

_AQ_ORA_RE = _re.compile(rb'ORA-(\d{5}):\s*([^\x00\n]*)')

# A TNS_REFUSE body is an ASCII descriptor like
# ``(DESCRIPTION=(TMP=)(VSNNUM=0)(ERR=12514)(ERROR_STACK=(ERROR=(CODE=12514)...))``.
# Both ERR= and CODE= carry the listener's refusal reason (e.g. 12514 — the
# requested service is not registered).
_REFUSE_ERR_RE = _re.compile(rb'(?:ERR|CODE)=(\d+)')


def _parse_refuse_code(Packet: bytes) -> int | None:
    """Extract the ORA error code from a TNS_REFUSE body, or None if absent.

    Prefers the first non-zero code (some refuse bodies carry ``ERR=0`` with the
    real code in a later ``CODE=`` field)."""
    for Digits in _REFUSE_ERR_RE.findall(Packet):
        Code = int(Digits)
        if Code:
            return Code
    return None


def _aq_error_info(Packet: bytes):
    # Pull the ORA code + message out of an AQ error (TTI_OER) response. The OER
    # token layout varies a little across tiers, so the embedded "ORA-NNNNN:"
    # text is the reliable source.
    Match = _AQ_ORA_RE.search(bytes(Packet))
    if Match:
        return (int(Match.group(1)), Match.group(2).rstrip().decode('utf-8', 'replace'))
    return (0, None)


def _aq_oer_code(Packet: bytes) -> int:
    return _aq_error_info(Packet)[0]


def _aq_raise(Packet: bytes) -> None:
    from seerdb.common.exceptions import from_ora_code

    (Code, Msg) = _aq_error_info(Packet)
    if Code:
        raise from_ora_code(Code)(Msg or f'ORA-{Code:05d}', code=Code)
    raise DatabaseError(f'unexpected AQ response 0x{Packet[:1].hex()}')


def _aq_str(Rest: bytes) -> tuple:
    # read_bytes_with_length / read_str_with_length: a ub4 count, then (if
    # non-zero) the chunked data. Empty/null normalised to b"".
    from seerdb.common.tns import _read_str_with_length

    (Value, Rest) = _read_str_with_length(Rest)
    return (b'' if isinstance(Value, list) else bytes(Value), Rest)


def _aq_raw(Rest: bytes) -> tuple:
    # read_raw_bytes_and_length / read_bytes(): a single length byte then the
    # data (0xFE = chunked). Used for the enqueue-time date and the payload image.
    from seerdb.common.tns import decode_dalc

    (Value, Rest) = decode_dalc(Rest)
    return (b'' if isinstance(Value, list) else bytes(Value), Rest)


def _decode_aq_payload(Rest: bytes, queue):
    # Read the message payload (#128). For RAW the image is a length-prefixed
    # blob whose first 4 bytes are a header; for an object queue it's a packed
    # DbObject; for JSON it's OSON. Returns (payload, remaining_bytes).
    from seerdb.common.tns import decode_ub4

    if queue.payload_type is not None:
        from seerdb.common.dbobject import (
            DbObject,
            decode_collection_image,
            decode_object_image,
        )
        from seerdb.common.tns import _read_object_column
        from seerdb.common.tns_consts import AL32UTF8_CHARSET

        (Img, Rest) = _read_object_column(Rest, {})
        if Img is None:
            return (None, Rest)
        Img = cast(Any, Img)  # the decoded object image (has .image)
        Typ = queue.payload_type
        if Typ.is_collection:
            Elements = decode_collection_image(
                Img.image, Typ.element or {}, AL32UTF8_CHARSET
            )
            return (DbObject(Typ.name, elements=Elements, dbtype=Typ), Rest)
        Attrs = decode_object_image(Img.image, Typ.attrs, AL32UTF8_CHARSET)
        return (DbObject(Typ.name, Attrs, dbtype=Typ), Rest)
    (_toid, Rest) = _aq_str(Rest)
    (_oid, Rest) = _aq_str(Rest)
    (_snapshot, Rest) = _aq_str(Rest)
    (_version, Rest) = decode_ub4(Rest)  # skip_ub2 version no
    (image_length, Rest) = decode_ub4(Rest)
    (_flags, Rest) = decode_ub4(Rest)  # skip_ub2 flags
    if image_length > 0:
        (Image, Rest) = _aq_raw(Rest)
        Payload = bytes(Image[4:image_length])
        if queue.is_json:
            from seerdb.common.oson import decode_oson

            return (decode_oson(Payload), Rest)
        return (Payload, Rest)
    return (None if queue.is_json else b'', Rest)


def _decode_aq_deq(Packet: bytes, queue):
    # AQ dequeue return parameters (#128): RPA token then, when a message is
    # present, the message properties, recipients, payload, and 16-byte msgid.
    # An empty queue comes back as ORA-25228 (no messages) -> None. RE'd from a
    # live 21c capture; mirrors python-oracledb AqDeqMessage.
    from seerdb.client.aq import MessageProperties
    from seerdb.common.tns import decode_ub4

    if not Packet:
        return None
    if Packet[0] == TTI_OER:
        if _aq_oer_code(Packet) in (25228, 25254):  # no message available
            return None
        _aq_raise(Packet)
    Rest = Packet[1:]
    (NumBytes, Rest) = decode_ub4(Rest)
    if NumBytes == 0:
        return None
    Props = MessageProperties()
    Rest = _parse_aq_msg_props(Rest, Props, queue._connection.field_version)
    (_NumRecipients, Rest) = decode_ub4(Rest)
    (Props.payload, Rest) = _decode_aq_payload(Rest, queue)
    Props.msgid = bytes(Rest[:16])
    return Props


def _parse_aq_msg_props(Rest: bytes, Props, field_version: int) -> bytes:
    # The message-property fields shared by single dequeue and the array path
    # (#128): priority/delay/expiration, correlation, attempts, exception queue,
    # state, enqueue date, txn id, the keyword extensions, and the trailing
    # user-property/cscn/dscn/flags (+ shard at fv >= 21.1).
    from seerdb.common.tns import decode_ub4

    (Props.priority, Rest) = decode_ub4(Rest)
    (Props.delay, Rest) = decode_ub4(Rest)
    (Props.expiration, Rest) = decode_ub4(Rest)
    (Corr, Rest) = _aq_str(Rest)
    Props.correlation = Corr.decode('utf-8') if Corr else None
    (Props.num_attempts, Rest) = decode_ub4(Rest)
    (ExQ, Rest) = _aq_str(Rest)
    Props.exceptionq = ExQ.decode('utf-8') if ExQ else None
    (Props.state, Rest) = decode_ub4(Rest)
    (DateFlag, Rest) = decode_ub4(Rest)  # enqueue time
    if DateFlag > 0:
        (_DateBytes, Rest) = _aq_raw(Rest)
    (Props.enq_txn_id, Rest) = _aq_str(Rest)
    (NumExt, Rest) = decode_ub4(Rest)  # extensions
    if NumExt > 0:
        Rest = Rest[1:]  # skip_ub1
        for _ in range(NumExt):
            (_Text, Rest) = _aq_str(Rest)
            (_Bin, Rest) = _aq_str(Rest)
            (_Keyword, Rest) = decode_ub4(Rest)
    (_UserProps, Rest) = decode_ub4(Rest)
    (_Csn, Rest) = decode_ub4(Rest)
    (_Dsn, Rest) = decode_ub4(Rest)
    (_Flags, Rest) = decode_ub4(Rest)
    if field_version >= FIELD_VERSION_21_1:
        (_Shard, Rest) = decode_ub4(Rest)
    return Rest


def _decode_aq_array(Packet: bytes, queue, operation: int, props_list: list):
    # AQ array enqueue/dequeue return (#128). For enqueue the response carries a
    # block of concatenated 16-byte message ids assigned back to props_list; for
    # dequeue it carries num_iters messages (properties + payload + msgid). An
    # empty queue comes back as ORA-25228 -> []. Mirrors AqArrayMessage.
    from seerdb.client.aq import MessageProperties
    from seerdb.common.tns import decode_ub4
    from seerdb.common.tns_consts import TNS_AQ_ARRAY_ENQ

    if not Packet:
        return []
    if Packet[0] == TTI_OER:
        if _aq_oer_code(Packet) in (25228, 25254):
            return []
        _aq_raise(Packet)
    Rest = Packet[1:]
    FV = queue._connection.field_version
    (NumIters, Rest) = decode_ub4(Rest)
    Out = []
    for I in range(NumIters):
        Props = MessageProperties()
        (Flag, Rest) = decode_ub4(Rest)  # ub2 props-present
        if Flag > 0:
            Rest = Rest[1:]  # skip_ub1
            Rest = _parse_aq_msg_props(Rest, Props, FV)
        (_NumRecipients, Rest) = decode_ub4(Rest)
        (PayFlag, Rest) = decode_ub4(Rest)  # ub2 payload-present
        if PayFlag > 0:
            (Props.payload, Rest) = _decode_aq_payload(Rest, queue)
        (MsgId, Rest) = _aq_str(Rest)
        if operation == TNS_AQ_ARRAY_ENQ:
            for J, P in enumerate(props_list):
                P.msgid = bytes(MsgId[J * 16 : (J + 1) * 16])
        else:
            Props.msgid = bytes(MsgId)
        (ExtLen, Rest) = decode_ub4(Rest)  # ub2 extensions length
        (_Ack, Rest) = decode_ub4(Rest)  # ub2 output ack
        Out.append(Props)
    return props_list if operation == TNS_AQ_ARRAY_ENQ else Out


def _decode_tpc_state(Packet: bytes) -> int:
    # TPC change-state return (#131): the RPA token then a ub4 transaction state.
    from seerdb.common.tns import decode_ub4

    if not Packet:
        raise OperationalError('empty TPC response')
    if Packet[0] != TTI_RPA:
        _raise_tpc_error(Packet)
    (State, _) = decode_ub4(Packet[1:])
    return State


def _parse_accept_eor(version: int, packet: bytes) -> bool:
    # End-of-response negotiation (#155). The accept body (8-byte header already
    # stripped) is Ver/Opts then, for protocol version >= 318, an extended
    # flags2 uint32 at offset 33 (mirrors oracledb connect.pyx: skip 10, flags1,
    # skip 9, sdu(4), skip 5, flags2). The HAS_END_OF_RESPONSE bit means the
    # server will honour the EOR cap. Best-effort: any short/odd packet disables
    # EOR (the connection behaves exactly as it does without it).
    if version < TNS_VERSION_MIN_OOB_CHECK or len(packet) < 37:
        return False
    (flags2,) = struct.unpack('>I', packet[33:37])
    return bool(flags2 & TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE)


def _parse_accept_sdu(version: int, packet: bytes, legacy_sdu: int) -> int:
    # The negotiated SDU (#155). A >= 315 ("large SDU") accept carries the real
    # SDU as a uint32 at offset 24; below that it is the legacy 16-bit field the
    # caller already read from packet[4:6].
    if version >= TNS_VERSION_MIN_LARGE_SDU and len(packet) >= 28:
        (sdu,) = struct.unpack('>I', packet[24:28])
        if sdu > 0:
            return sdu
    return legacy_sdu


def _apply_rowfactory(rows, rowfactory):
    return [rowfactory(*r) for r in rows] if rowfactory else rows


# Negotiation cache (#438): a process-level map from a connection target to the
# field version a prior successful login negotiated on that server. When the
# opt-in `negotiation_cache` is set, a reconnect to a target already in the cache
# skips the bare PRO probe (which exists only to learn the field version) and
# goes straight to the fast-auth bundle — one round trip fewer, the win most
# visible for pools that churn connections. A stale entry (the server changed
# behind the same address) makes the cached-path handshake fail; that is caught
# in connect(), which invalidates the entry and retries a full negotiation. Only
# fast-auth (fv >= 18) servers are cached — older servers must negotiate down.
_NEGOTIATION_CACHE: dict[tuple[str, int, str], int] = {}
_NEGOTIATION_CACHE_LOCK = threading.Lock()


def _nego_cache_get(key: tuple[str, int, str]) -> int | None:
    with _NEGOTIATION_CACHE_LOCK:
        return _NEGOTIATION_CACHE.get(key)


def _nego_cache_put(key: tuple[str, int, str], field_version: int) -> None:
    with _NEGOTIATION_CACHE_LOCK:
        _NEGOTIATION_CACHE[key] = field_version


def _nego_cache_del(key: tuple[str, int, str]) -> None:
    with _NEGOTIATION_CACHE_LOCK:
        _NEGOTIATION_CACHE.pop(key, None)


# Oracle 9i (fv2 / TTI_ALL7) binds a value inline with no piecewise LONG/LOB
# send protocol, so a bind can be no larger than the SQL inline limits: 2000
# bytes for RAW (a `bytes` value) and 4000 bytes for VARCHAR2 (a `str` value).
# Past those, the 9i server either closes the connection mid-DML (BLOB target,
# leaving a zombie lock — #168/#169), raises ORA-00600 (CLOB), or ORA-01461.
# Reject such binds up front with a clean NotSupportedError so the connection
# survives and stays usable. (Streamed large LOB/LONG binds exist only on the
# fv4+ path.)
_FV2_MAX_RAW_BIND = 2000
_FV2_MAX_VARCHAR_BIND = 4000

# Oracle 8i data types LONG (8) and LONG RAW (24): fetched one row per round trip
# and truncated to the fetch request's long-size field (#377).


def _check_fv2_bind_sizes(Bind, Batch=None) -> None:
    from seerdb.common.exceptions import NotSupportedError

    Rows = [Bind] if Bind else []
    if Batch:
        Rows = Rows + list(Batch)
    for Row in Rows:
        Values = Row.values() if isinstance(Row, dict) else (Row or [])
        for Value in Values:
            if isinstance(Value, (bytes, bytearray)):
                if len(Value) > _FV2_MAX_RAW_BIND:
                    raise NotSupportedError(
                        f'Oracle 9i cannot bind a bytes value larger than '
                        f'{_FV2_MAX_RAW_BIND} bytes (got {len(Value)}); 9i has '
                        f'no streamed LOB/LONG bind path'
                    )
            elif isinstance(Value, str):
                if len(Value.encode('utf-8')) > _FV2_MAX_VARCHAR_BIND:
                    raise NotSupportedError(
                        f'Oracle 9i cannot bind a str value larger than '
                        f'{_FV2_MAX_VARCHAR_BIND} bytes (utf-8); 9i has no '
                        f'streamed LOB/LONG bind path'
                    )


def _run_pipeline_op(conn, cur, op, T):
    # Run a single pipeline operation on `cur` and return its PipelineOpResult
    # (#132, sync). The async connection has its own awaiting copy of this.
    from seerdb.client.pipeline import PipelineOpResult

    result = PipelineOpResult(op)
    params = op.parameters or []
    try:
        if op.op_type == T.EXECUTE:
            cur.execute(op.statement, params)
        elif op.op_type == T.EXECUTE_MANY:
            cur.executemany(op.statement, op.parameters)
        elif op.op_type == T.FETCH_ONE:
            cur.execute(op.statement, params)
            row = cur.fetchone()
            result.rows = _apply_rowfactory([] if row is None else [row], op.rowfactory)
            result.columns = cur.description
        elif op.op_type == T.FETCH_MANY:
            cur.execute(op.statement, params)
            result.rows = _apply_rowfactory(cur.fetchmany(op.num_rows), op.rowfactory)
            result.columns = cur.description
        elif op.op_type == T.FETCH_ALL:
            cur.execute(op.statement, params)
            result.rows = _apply_rowfactory(cur.fetchall(), op.rowfactory)
            result.columns = cur.description
        elif op.op_type == T.COMMIT:
            conn.commit()
        elif op.op_type == T.CALL_PROC:
            cur.callproc(op.name, params)
        elif op.op_type == T.CALL_FUNC:
            result.return_value = cur.callfunc(op.name, op.return_type, params)
    except DatabaseError as exc:
        result.error = exc
    return result


def _normalize_sessionless_txn_id(transaction_id) -> bytes:
    # Sessionless transactions (#133): the id goes in the gtrid slot of the
    # func-103 switch message. str -> UTF-8 bytes; None -> a fresh uuid4; max
    # 64 bytes (mirrors oracledb normalize_sessionless_transaction_id).
    if transaction_id is None:
        return uuid.uuid4().bytes
    if isinstance(transaction_id, str):
        transaction_id = transaction_id.encode()
    elif not isinstance(transaction_id, (bytes, bytearray)):
        raise TypeError('transaction_id must be str, bytes, or None')
    if len(transaction_id) > TNS_SESSIONLESS_TXN_ID_MAX:
        raise ValueError(f'transaction_id exceeds {TNS_SESSIONLESS_TXN_ID_MAX} bytes')
    return bytes(transaction_id)


def _split_proxy_user(user: str) -> tuple[str, str | None]:
    # Proxy auth (#126): `proxy_user[schema]` -> (proxy_user, schema). A plain
    # user name (or None) returns (user, None). Mirrors python-oracledb
    # parse_user: only a trailing [...] after a non-empty name counts.
    if user:
        Start = user.find('[')
        if Start > 0 and user.endswith(']'):
            return (user[:Start], user[Start + 1 : -1])
    return (user, None)


def _reject_sharding(shardingkey: object, supershardingkey: object) -> None:
    """Reject a sharding-key request with a clean NotSupportedError (#164).

    ``shardingkey`` / ``supershardingkey`` route a connection to a specific
    shard of a sharded database. Emitting them is an OCI-client capability —
    the routing lives below the thin wire protocol — so a pure-protocol thin
    driver cannot honour them; the reference thin driver rejects them for the
    same reason (verified live: the request never reaches the wire). The two
    parameters are accepted for API compatibility and raise here, so code
    ported from a thin driver gets the recognizable NotSupportedError rather
    than a TypeError on an unexpected keyword argument.
    """
    if shardingkey is not None or supershardingkey is not None:
        raise NotSupportedError(
            'sharding keys (shardingkey / supershardingkey) are not supported: '
            'routing to a database shard is available only through the '
            'OCI-based client'
        )


def _reject_cqn() -> None:
    """Reject a Continuous Query Notification request with NotSupportedError (#129).

    CQN registers a server-initiated subscription: the database opens a callback
    connection back to the client to push change / query notifications. Driving
    that callback channel is an OCI-client capability that sits outside the thin
    TTC/TNS request-response protocol, so a pure-protocol thin client cannot
    offer it — the reference thin driver rejects it for the same reason. The
    subscribe / unsubscribe methods exist for API compatibility and raise here,
    so code ported from a thin driver gets the recognizable NotSupportedError
    rather than an AttributeError on a missing method.
    """
    raise NotSupportedError(
        'Continuous Query Notification / server-initiated subscriptions are not '
        'supported: they require the OCI-based client'
    )


class OracleConnect(_ConnectionLogic):
    def __init__(
        self,
        host: str = 'localhost',
        port: int = 1521,
        user: str = '',
        password: str = '',
        sid: str = '',
        service_name: str = '',
        ssl: object = None,
        socket_options: object = None,
        timeout: int = 15000,
        autocommit: bool = True,
        fetch: int = 100,
        role: int = 0,
        prelim: int = 0,
        sdu: int = DEFAULT_SDU,
        charset: str = 'utf-8',
        app_name: str = 'seerdb',
        field_version: int = FIELD_VERSION_23_4,
        cclass: str | None = None,
        purity: int = PURITY_DEFAULT,
        wallet_location: str | None = None,
        wallet_password: str | None = None,
        config_dir: str | None = None,
        dsn: str | None = None,
        negotiation_cache: bool = False,
        access_token: object = None,
        shardingkey: object = None,
        supershardingkey: object = None,
    ):
        # Sharding keys are an OCI-only routing capability (#164); accept the
        # oracledb-compatible parameters but reject them with NotSupportedError.
        _reject_sharding(shardingkey, supershardingkey)
        # field_version is the highest TTC field version seerdb advertises;
        # the server negotiates it down (min(client, server)). The default is the
        # 23ai max (24), reached via fast-auth (#89) — older servers settle at
        # their own version and take the legacy handshake unchanged.
        self.host = host
        self.port = port
        # Proxy authentication (#126): a `proxy_user[schema]` user name means
        # authenticate as proxy_user but operate in `schema`'s context. Split it
        # here so the whole auth flow uses the real (proxy) user and the bracketed
        # schema is sent as the PROXY_CLIENT_NAME auth pair.
        (self.user, self.proxy_user) = _split_proxy_user(user)
        # DRCP (#130): a connection class + session purity request a pooled
        # server (the connect descriptor gains SERVER=POOLED and the auth carries
        # the AUTH_KPPL_* pairs).
        self.cclass = cclass
        self.purity = purity
        self.password = password
        self.sid = sid
        self.service_name = service_name
        self.ssl = ssl
        self.socket_options = socket_options
        self.conn_state = CONN_STATE_DISCONNECTED
        self.timeout = timeout
        self.autocommit = autocommit
        # Rows requested per fetch round-trip. 100 matches oracledb's effective
        # batch (its arraysize default), so a large fetchall drains in ~n/100
        # round-trips instead of n/15. Bounded well below the row decoder's
        # per-row recursion ceiling (a single batch of a few hundred rows would
        # overflow it), so it is not raised further here.
        self.fetch = fetch
        self.role = role
        self.sdu = sdu
        self.charset = charset
        self.prelim = prelim
        self.app_name = app_name
        # Token-based auth (#125): a JWT str (OAuth2) or (token, private_key)
        # (OCI IAM), resolved at connect time into the token + optional PEM key.
        self.access_token = access_token
        self._token_auth = False  # set once the token AUTH is sent

        # Wallet-based mutual TLS (#127). When a wallet is given, resolve the
        # DSN (if any) into host/port/service and build the client SSLContext
        # from the wallet identity; the expected server certificate DN is kept
        # for the post-handshake SSL_SERVER_DN_MATCH check in _wrap_socket_tls.
        self._wallet_server_dn: str | None = None
        if wallet_location is not None or config_dir is not None:
            self._apply_wallet(wallet_location, wallet_password, config_dir, dsn)

        self.sock: socket.socket | None = None
        self.seq = 1
        # Bytes received past a marker packet, held for the next recv() so a
        # coalesced break|reset|error is not lost (#45). Empty between calls.
        self._pending = b''
        # True while a server break/reset handshake is in progress: we answer a
        # server break with exactly ONE reset, then drain the server's terminal
        # reset (and any straggler markers) WITHOUT replying, matching
        # python-oracledb's 2:1 server:client marker ratio. Replying to every
        # marker — the old behaviour — ping-pongs into a reset storm that
        # discards real data (#45). Cleared when a real DATA packet arrives.
        self._in_break = False
        # Query cancellation / call_timeout (#123). _break_in_progress latches
        # while a client-initiated break (cancel/timeout) is outstanding so the
        # reader drains the server's interrupt response exactly once.
        self._break_in_progress = False
        self._call_timeout = 0  # ms; 0 = no timeout
        self._timed_out = False
        self._supports_oob = False  # set from the accept (#144)
        self._supports_eor = False  # end-of-response framing (#155/#132)
        self._large_packets = False  # 4-byte packet length (#155, ver >= 315)
        # The pre-10g wire dialect selected after login (sans-io generators driven
        # by _drive), or None for the modern 10g→23ai path (#369).
        self._dialect: Dialect | None = None
        # End-to-end application tracing (#183): current module / action /
        # client_identifier values, and the subset changed since the last flush
        # (sent as a SET_END_TO_END_ATTR piggyback in front of the next execute).
        self._e2e_values: dict = {}
        self._e2e_pending: dict = {}
        # End-user security context (#460): the OSON image once a context is set
        # (None otherwise), re-sent as a func-205 piggyback on every subsequent
        # call. The server's compile-cap array, kept to gate the feature.
        self._end_user_sec_context: bytes | None = None
        self._server_compile_caps: bytes = b''
        self._server_runtime_caps: bytes = b''
        # Request boundaries (#464): for pooled connections, the desired
        # session-state marker (REQUEST_BEGIN / _END, or 0 = none) sent as a
        # func-176 piggyback, and whether a logical request is currently open.
        self._session_state_desired: int = 0
        self._in_request: bool = False
        # Two-phase commit (#131): the opaque transaction context the server
        # returns from tpc_begin, replayed on prepare/commit/rollback/end.
        self._transaction_context: bytes | None = None
        # Sessionless transactions (#133): True between begin/resume and
        # suspend/commit/rollback. Tracked client-side; the server confirms via
        # a keyword-201 sync pair piggybacked on subsequent call responses.
        self._sessionless_txn_active = False
        self.conn_key: bytes | None = None
        # Native network encryption / data integrity (#437). Set by the ANO
        # negotiation after the accept when the server requires it; once active,
        # each TNS_DATA payload is encrypted + MAC'd on the way out and verified
        # on the way in. None (the common case) means plaintext TTC.
        self._ano: AnoChannel | None = None
        # Negotiation cache (#438): opt-in reconnect optimization; _used_nego_cache
        # records whether the current login took the cached (bare-PRO-skipping)
        # path, so connect() knows to invalidate + retry on a stale-cache failure.
        self.negotiation_cache = negotiation_cache
        self._used_nego_cache = False
        self._skip_nego_cache = False  # forced true on the invalidate-and-retry
        self.server_version = 0
        self.session_id = None
        # Negotiated TTC field version. Starts at the client's advertised max
        # (the field_version arg; 21.1 by default) and is lowered to the
        # server's during the PRO handshake — min(client, server), see
        # handle_login. Decoders use this to pick version-gated wire formats
        # (issue #27). Against 11g it negotiates back down to 6 (=11.2), so the
        # high default is transparent; pass field_version=FIELD_VERSION_11_2 to
        # force the legacy vector.
        self.field_version = field_version
        # The client's requested field version, kept so the negotiation-cache
        # retry can restore it before a full re-negotiation (#438).
        self._field_version_requested = field_version
        self.cursors: dict[int, int] = {}
        # Cursor cache: (SQL text, bind OAC signature) → server-side cursor
        # handle. Lets repeat `execute()` of the same SQL skip the parse step
        # on the server. The bind signature is part of the key because a cached
        # re-execute does not re-send the OAC, so the cursor may only be reused
        # for binds matching the size/type it was parsed with (see
        # exec_oac_signature). Capped to keep memory predictable; LRU eviction
        # via insertion order (Python's regular dict).
        self._cursor_cache: dict[tuple[str, bytes], int] = {}
        self._cursor_cache_max = 32
        # Server cursors awaiting close (#191). On 12c+ the cache is off so every
        # execute opens a fresh server cursor; once a call is fully drained that
        # cursor is dead weight, and never closing them trips ORA-01000. We batch
        # their handles here and close them with an OCCA piggyback in front of
        # the next call (so at most one such cursor is open at a time).
        self._cursors_to_close: list[int] = []
        # Ordered attribute layout per SQL object type (#115), keyed by
        # (owner, type_name). Populated on demand from ALL_TYPE_ATTRS the first
        # time an object of that type is fetched.
        self._object_type_cache: dict[tuple[str, str], 'DbObjectType'] = {}

    def _next_seq(self) -> int:
        seq = self.seq
        self.seq = self.seq % MAX_SEQ_NUM + 1
        return seq

    def state_to_dict(self, Type: DictionaryType) -> dict:
        return self._make_dict(Type)

    def _send_token_auth(self) -> None:
        # Token auth (#125): build and send the single token AUTH message. For
        # the OCI IAM variant (a private key was supplied) sign the request header
        # so the server can verify possession of the key that matches the token.
        from seerdb.common.tns import encode_dictionary_token_auth
        from seerdb.common.token_auth import (
            normalize_access_token,
            sign_token_header,
            token_auth_header,
        )

        (Token, PrivateKey) = normalize_access_token(self.access_token)
        Dict = self._make_dict(DictionaryType.description)
        Dict['token'] = Token
        if PrivateKey is not None:
            Service = self.service_name or self.sid or ''
            AuthHeader = token_auth_header(self.host, Service, self.port)
            Dict['token_header'] = AuthHeader
            Dict['token_signature'] = sign_token_header(AuthHeader, PrivateKey)
        self.send(TNS_DATA, encode_dictionary_token_auth(Dict))

    def _apply_socket_timeout(self) -> None:
        # Bound every blocking socket operation (connect / send / recv) by the
        # connection `timeout` (milliseconds). Without this the param was dead
        # and a server that went quiet — e.g. an XE session held by the
        # logon-storm throttle — wedged `recv` forever. A timeout of 0 / None
        # keeps the historical fully-blocking behaviour. The bound is per
        # socket operation, not per query: healthy data keeps each recv short,
        # so it only fires on a genuine stall.
        if self.sock is not None:
            self.sock.settimeout(self.timeout / 1000 if self.timeout else None)

    def _open_transport(self) -> None:
        # Open the TCP (and optional TLS) socket to the current host/port and
        # send the initial CONNECT. Shared by connect() and the TNS_REDIRECT
        # handler, which re-points host/port and re-opens against the address
        # the server handed back.
        # Following a redirect (self._redirects > 0), retry a refused connect —
        # the dispatcher / dedicated server may still be binding its port (#399).
        Attempts = _REDIRECT_CONNECT_ATTEMPTS if getattr(self, '_redirects', 0) else 1
        for Attempt in range(Attempts):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock = sock
            self._apply_socket_timeout()
            try:
                sock.connect((self.host, self.port))
                break
            except ConnectionRefusedError:
                sock.close()
                self.sock = None
                if Attempt + 1 >= Attempts:
                    raise
                time.sleep(_REDIRECT_CONNECT_DELAY)
        if self.ssl:
            try:
                sock = self._wrap_socket_tls(sock)
                self.sock = sock
                # The TLS handshake produced a fresh socket object; re-arm it.
                self._apply_socket_timeout()
            except BaseException:
                # If the TLS wrap fails (bad config, cert verification, etc.)
                # release the raw TCP socket before surfacing the error.
                try:
                    sock.close()
                finally:
                    self.sock = None
                raise
        Data = encode_dictionary(self._make_dict(DictionaryType.login))
        self.send(TNS_CONNECT, Data)

    def connect(self) -> bool:
        self._redirects = 0
        self._open_transport()
        try:
            result = self.handle_login()
        except ConnectionError as Exc:
            # A reset or broken pipe mid-handshake is the same failure as a
            # clean close, only reported differently by the OS depending on
            # timing. Surface it the same way instead of letting a raw socket
            # error out of connect() (#805).
            raise OperationalError(
                f'the server closed the connection during login ({Exc})'
            ) from Exc
        except OperationalError:
            # A connection-level failure on the cached (bare-PRO-skipping) path
            # most likely means the cached field version is stale (the server
            # changed). Invalidate and retry once with a full negotiation (#438).
            if self._used_nego_cache:
                self._retry_without_negotiation_cache()
                return True
            raise
        if result not in (0, None) and self._used_nego_cache:
            # handle_login reported a peer close on the cached path — same stale
            # -cache signal, without an exception.
            self._retry_without_negotiation_cache()
        return True

    def _retry_without_negotiation_cache(self) -> None:
        # Invalidate the stale entry, reset the per-connection handshake state to
        # its fresh values (a partial cached login left the sequence counter and
        # negotiated bits dirty), and run a full negotiation on a new socket.
        _nego_cache_del(self._nego_cache_key())
        self._used_nego_cache = False
        self._skip_nego_cache = True  # force the full negotiation this attempt
        self.disconnect()
        self.seq = 1
        self._pending = b''
        self._in_break = False
        self.conn_state = CONN_STATE_DISCONNECTED
        self.field_version = self._field_version_requested
        self._dialect = None
        self._ano = None
        self.conn_key = None
        self._o3_phase = 0
        self._open_transport()
        self.handle_login()

    def _wrap_socket_tls(self, RawSock: socket.socket) -> socket.socket:
        # Promote the freshly-connected TCP socket to TLS before any TNS bytes
        # are exchanged. The ``ssl`` constructor argument accepts:
        #
        #   True      — system trust store, hostname verification on
        #   dict      — keyword arguments forwarded to a default context:
        #                 ca_certs, certfile, keyfile, check_hostname,
        #                 verify_mode (ssl.CERT_NONE / CERT_REQUIRED), and
        #                 server_hostname (override the SNI hostname)
        #   SSLContext — used verbatim
        import ssl as _ssl

        Server = self.host
        if isinstance(self.ssl, _ssl.SSLContext):
            Ctx = self.ssl
        elif isinstance(self.ssl, dict):
            Opts = dict(self.ssl)
            Server = Opts.pop('server_hostname', Server)
            Ctx = _ssl.create_default_context(cafile=Opts.pop('ca_certs', None))
            Ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
            if 'check_hostname' in Opts:
                Ctx.check_hostname = bool(Opts.pop('check_hostname'))
            if 'verify_mode' in Opts:
                Ctx.verify_mode = Opts.pop('verify_mode')
            CertFile = Opts.pop('certfile', None)
            KeyFile = Opts.pop('keyfile', None)
            if CertFile:
                Ctx.load_cert_chain(CertFile, KeyFile)
            if Opts:
                raise ValueError(f'unknown ssl options: {sorted(Opts)}')
        else:
            Ctx = _ssl.create_default_context()
            Ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
        Wrapped = Ctx.wrap_socket(RawSock, server_hostname=Server)
        try:
            self._check_server_dn(Wrapped.getpeercert())
        except BaseException:
            Wrapped.close()
            raise
        return Wrapped

    def handle_login(self) -> int | None:
        # Iterative login state machine. Each round either: completes the
        # handshake (TTI_RPA → _handle_rpa), terminates (TNS_REFUSE /
        # unexpected / EOF), or sends the next request and loops to read
        # the server's reply. Was previously recursive — a few-round
        # handshake could approach Python's default recursion limit, and
        # an EOF during the handshake crashed unpacking `recv() → False`.
        while True:
            Received = self.recv(b'', b'')
            if Received is False:
                # Peer closed mid-handshake. Raise: returning a code here let a
                # dead socket out of connect() as a live connection, and the
                # failure only surfaced on the first statement, pointing at that
                # statement rather than at the login that actually failed (#805).
                logger.debug('handle_login: connection closed by peer')
                raise OperationalError(
                    'the server closed the connection during login (no reply to the last handshake packet)'
                )
            (Type, Packet) = Received
            if Type != TNS_MARKER:
                # A real packet ends any in-flight break/reset episode (#45).
                self._in_break = False
            match Type:
                case t if t == TNS_ACCEPT:
                    logger.debug('handle_login: accept')
                    # Extract negotiated SDU from the accept body
                    (Ver, Opts, Sdu) = struct.unpack('>Hhh', Packet[:6])
                    # 319-era accept (#155): a >= 315 server negotiates the
                    # large (32-bit) SDU and switches to 4-byte packet framing;
                    # a >= 318 server's flags2 carries the end-of-response bit.
                    self.sdu = _parse_accept_sdu(Ver, Packet, Sdu)
                    self._large_packets = Ver >= TNS_VERSION_MIN_LARGE_SDU
                    self._supports_eor = _parse_accept_eor(Ver, Packet)
                    # OOB break support (#144): the accept's global service
                    # options carry CAN_RECV_ATTENTION when the server can
                    # receive an out-of-band break. When set we prefer the OOB
                    # urgent byte (it interrupts a compute-bound server faster);
                    # otherwise we use the in-band INTERRUPT marker.
                    self._supports_oob = bool(Opts & TNS_GSO_CAN_RECV_ATTENTION)
                    self.conn_state = CONN_STATE_CONNECTED
                    logger.debug(
                        'handle_login: Ver=%s, Opts=%s, Sdu=%s', Ver, Opts, Sdu
                    )
                    # Native network encryption (#437): once the CONNECT
                    # advertised ANO-capable, a server that supports ANO expects
                    # the negotiation as the first post-accept packet — skipping
                    # it makes the server close on our PRO. Gate on the accept's
                    # ANO-supported flag exactly as a real client does: ACFL0
                    # (body offset 14) bit 0 set, bit 2 clear, ACFL1 bit 3 clear.
                    # The negotiation is plaintext and only activates the cipher
                    # if the server actually selects an encryption algorithm.
                    Acfl0 = Packet[14] if len(Packet) > 14 else 0
                    Acfl1 = Packet[15] if len(Packet) > 15 else 0
                    if (Acfl0 & 0x01) and not (Acfl0 & 0x04) and not (Acfl1 & 0x08):
                        self._negotiate_ano()
                    # Negotiation cache (#438): a prior login on this target
                    # recorded a fast-auth field version — skip the bare PRO probe
                    # (it exists only to learn that) and go straight to the bundle.
                    if self.negotiation_cache and not self._skip_nego_cache:
                        Cached = _nego_cache_get(self._nego_cache_key())
                        if Cached is not None and Cached > FIELD_VERSION_23_1:
                            self.field_version = Cached
                            self._used_nego_cache = True
                            logger.debug('handle_login: negotiation cache hit')
                            return self._fast_auth_login()
                    Data = encode_dictionary(self._make_dict(DictionaryType.pro))
                    self.send(TNS_DATA, Data)
                    continue
                case t if t == TNS_DATA:
                    match Packet[0]:
                        case p if p == TTI_PRO:
                            logger.debug('handle_login: recv PRO')
                            self._negotiate_capabilities(Packet)
                            if self.field_version > FIELD_VERSION_23_1:
                                # 23ai (#89): the negotiated field version is
                                # >= 18, where the legacy OSESSKEY is rejected
                                # (ORA-03146). Switch to the fast-auth bundle —
                                # the only path to fv >= 18, which is in turn the
                                # prerequisite for column annotations. The PRO
                                # exchange just done is harmlessly repeated inside
                                # the bundle. Only reached when the caller opts in
                                # with field_version >= 18 (default stays 21.1).
                                return self._fast_auth_login()
                            if isinstance(self._dialect, O8iDialect):
                                # 8i has no Unicode charset and predates ~37 data
                                # types, so it needs its own shorter DTY — the
                                # modern one draws ORA-03120 (§ _DTY_8I).
                                Data = _DTY_8I
                            else:
                                Data = encode_dictionary(
                                    self._make_dict(DictionaryType.dty)
                                )
                            self.send(TNS_DATA, Data)
                        case p if p == TTI_DTY:
                            logger.debug('handle_login: recv DTY')
                            if isinstance(self._dialect, O8iDialect):
                                # Oracle 8i: O3LOGON via the OSESSKEY envelope.
                                self._o3_phase = 1
                                self._send_8i_osesskey()
                            elif self.field_version < FIELD_VERSION_10_2:
                                # Pre-10g (9i, field version 2): O3LOGON thin
                                # auth — TTI_3LOGA fetches the session key (#90).
                                from seerdb.common.tns import encode_o3logon_phase1

                                self._o3_phase = 1
                                self.send(
                                    TNS_DATA,
                                    encode_o3logon_phase1(
                                        self._next_seq(), self.user.encode('utf-8')
                                    ),
                                )
                            elif self.access_token is not None:
                                # Token auth (#125): skip OSESSKEY entirely and
                                # send the single token AUTH message; the reply is
                                # the auth result (no challenge, no proof).
                                self._token_auth = True
                                self._send_token_auth()
                            else:
                                Data = encode_dictionary(
                                    self._make_dict(DictionaryType.sess)
                                )
                                self.send(TNS_DATA, Data)
                        case p if p == TTI_RPA:
                            logger.debug('handle_login: recv RPA')
                            if isinstance(self._dialect, O8iDialect):
                                # 8i O3LOGON: phase-1 RPA carries AUTH_SESSKEY ->
                                # send the proof; the phase-2 RPA (AUTH_VERSION_
                                # STRING) means authenticated (no server proof to
                                # validate on the pre-10g path).
                                if self._o3_phase == 1:
                                    self._send_8i_oauth_phase2(Packet)
                                    continue
                                self.conn_state = CONN_STATE_AUTHENTICATED
                                logger.debug('handle_login: authenticated (8i O3LOGON)')
                                return 0
                            if getattr(self, '_o3_phase', 0) == 1:
                                self._send_o3logon_phase2(Packet)
                                continue
                            return self._handle_rpa(Packet[1:])
                        case p if p == TTI_WRN:
                            logger.debug('handle_login: recv WRN %s', Packet[1:])
                        case p if p == TTI_OER:
                            # The server reports an auth-time failure (bad
                            # password, rejected password change, ...) as an OER
                            # token, sometimes preceded by a break marker.
                            # Decode it and raise rather than looping forever on
                            # an empty socket.
                            logger.debug('handle_login: recv OER')
                            from seerdb.common.exceptions import (
                                DatabaseError,
                                from_ora_code,
                            )
                            from seerdb.common.tns import decode_packet, decode_ub4

                            if getattr(self, '_o3_phase', 0) == 2:
                                # 9i's OER is shorter than the 11g+ form
                                # decode_token_oer expects (no batch-error
                                # arrays), so decode just the leading fields:
                                # call_status, seq, rowcount, then the ORA code.
                                Rest = Packet[1:]
                                for _ in range(3):
                                    (_, Rest) = decode_ub4(Rest)
                                (ErrCode, _) = decode_ub4(Rest)
                                Message = None
                            else:
                                # Via decode_packet so the negotiated field
                                # version is published for the version-gated
                                # OER decode.
                                Result = cast(
                                    tuple,
                                    decode_packet(
                                        Packet, (None, None, []), self.field_version
                                    ),
                                )
                                ErrCode = Result[1]
                                Message = Result[5] if len(Result) > 5 else None
                            if ErrCode and ErrCode not in (0, 1403):
                                raise from_ora_code(ErrCode)(
                                    Message or f'ORA-{ErrCode:05d}', code=ErrCode
                                )
                            if getattr(self, '_o3_phase', 0) == 2:
                                # O3LOGON phase two answered with a clean OER =
                                # authenticated (#90). No AUTH_SVR_RESPONSE to
                                # validate on the pre-10g path.
                                self.conn_state = CONN_STATE_AUTHENTICATED
                                logger.debug('handle_login: authenticated (O3LOGON)')
                                return 0
                            raise DatabaseError('authentication failed')
                        case _:
                            logger.debug('handle_login: unknown token %s', Packet[0])
                    continue
                case t if t == TNS_MARKER:
                    logger.debug('handle_login: marker')
                    # Single reset per break episode, then drain (#45) — never
                    # echo every marker, which storms the line.
                    if not self._in_break:
                        self.send(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
                        self._in_break = True
                    continue
                case t if t == TNS_REDIRECT:
                    from seerdb.common.tns import parse_redirect_address

                    (NewHost, NewPort) = parse_redirect_address(Packet)
                    if NewHost is None or NewPort is None:
                        logger.debug('handle_login: unparseable redirect %r', Packet)
                        raise OperationalError(
                            'the server sent a redirect this client could not parse'
                        )
                    self._redirects = getattr(self, '_redirects', 0) + 1
                    if self._redirects > _MAX_REDIRECTS:
                        raise OperationalError(
                            f'too many TNS redirects (> {_MAX_REDIRECTS})'
                        )
                    logger.debug('handle_login: redirect -> %s:%s', NewHost, NewPort)
                    # Reconnect to the address the server handed back and start
                    # the handshake over against it.
                    self.host, self.port = NewHost, NewPort
                    self.disconnect()
                    self._open_transport()
                    continue
                case t if t == TNS_REFUSE:
                    logger.debug('handle_login: refuse')
                    Code = _parse_refuse_code(Packet)
                    self.disconnect()
                    # A refusal is terminal — surface it instead of returning a
                    # half-open connection (sock=None) that only fails, opaquely,
                    # on the next call. The listener's ORA code (e.g. 12514, the
                    # service is not registered) is in the refuse body.
                    if Code:
                        from seerdb.common.exceptions import from_ora_code

                        raise from_ora_code(Code)(
                            f'ORA-{Code:05d}: connection refused by the listener',
                            code=Code,
                        )
                    raise OperationalError(
                        'connection refused by the listener during login'
                    )
                case t if t == TNS_RESEND:
                    logger.debug('handle_login: resend')
                    self.conn_state = CONN_STATE_AUTH_NEGOTIATE
                    Data = encode_dictionary(self._make_dict(DictionaryType.login))
                    self.send(TNS_CONNECT, Data)
                    continue
                case _:
                    logger.debug('handle_login: unexpected %s', Type)
                    raise OperationalError(
                        f'the server sent an unexpected packet type {Type} during login'
                    )

    def _fast_auth_login(self) -> int | None:
        # 23ai fast-auth (#89): send PRO, DTY and OSESSKEY bundled in one
        # FAST_AUTH packet (the field version was already negotiated to >= 18 in
        # _negotiate_capabilities). The server replies with the three responses
        # concatenated; pick out the auth-challenge RPA and hand it to the normal
        # phase-two path (_handle_rpa), which finishes the login exactly as the
        # legacy handshake does.
        Pro = encode_dictionary(self._make_dict(DictionaryType.pro))
        Dty = encode_dictionary(self._make_dict(DictionaryType.dty))
        Sess = encode_dictionary(self._make_dict(DictionaryType.sess))
        self.send(TNS_DATA, encode_fast_auth(Pro, Dty, Sess))
        Received = self._next_data_packet()
        if Received is False:
            logger.debug('fast_auth: connection closed by peer')
            return 1
        (Type, Packet) = Received
        Off = find_fast_auth_rpa(Packet) if Type == TNS_DATA else -1
        if Off < 0:
            logger.error(
                'fast_auth: no auth challenge in bundled reply (type=%s, head=%r)',
                Type,
                Packet[:16],
            )
            raise OperationalError('fast-auth handshake failed')
        return self._handle_rpa(Packet[Off + 1 :])

    def _negotiate_capabilities(self, Packet: bytes) -> None:
        # Parse the server's PRO response and lower our field version to the
        # server's if it is older — the effective version is min(client,
        # server), the same rule python-oracledb applies. Sent next in our DTY
        # so both sides agree. Best-effort: a parse failure must not break a
        # handshake that works today, so we keep the default on any error.
        try:
            Pro = decode_token_pro(Packet)
            Caps = Pro['compile_caps']
            self._server_compile_caps = Caps
            self._server_runtime_caps = Pro.get('runtime_caps') or b''
            if len(Caps) > CCAP_FIELD_VERSION:
                ServerFv = Caps[CCAP_FIELD_VERSION]
                self.field_version = min(self.field_version, ServerFv)
            # Oracle 8i (8.1.x) carries no caps in its PRO, so the field version
            # can't be negotiated down from the client default — pin it to 2 (as
            # 9i) so the O3LOGON path runs, not the 23ai fast-auth path. 8i also
            # speaks the OSESSKEY-envelope O3LOGON (not 9i's TTI_3LOGA), so flag
            # it for the login state machine.
            Banner = Pro.get('banner') or b''
            VerMatch = _re.search(rb'(\d+)\.\d+\.\d+', Banner)
            # 8i (banner "8.x") pins the field version to 2 (as 9i) so the O3LOGON
            # path runs, not the 23ai fast-auth path; the O8iDialect that
            # _select_dialect creates is thereafter the single dialect discriminator.
            is_8i = bool(VerMatch and VerMatch.group(1) == b'8')
            if is_8i:
                self.field_version = FIELD_VERSION_9_2
            logger.debug(
                'handle_login: PRO server_version=%s banner=%r field_version=%s',
                Pro['server_version'],
                Pro['banner'],
                self.field_version,
            )
            self._select_dialect(is_8i)
        except Exception:
            # Unknown PRO layout — keep the default field version (11.2).
            logger.debug('handle_login: could not parse PRO caps', exc_info=True)

    def _drive(self, gen: object) -> object:
        # Run a sans-io dialect generator (#369): a yielded Send(data) is written
        # as a TNS_DATA packet; a yielded RECV is answered with the next data
        # packet; the generator's return value is the result. Exceptions (ORA
        # errors) propagate. The async connection has the awaited twin of this.
        from seerdb.client.dialect import RECV, Send

        to_send: object = None
        try:
            while True:
                intent = gen.send(to_send)  # type: ignore[attr-defined]
                if intent is RECV:
                    to_send = self._next_data_packet()
                elif isinstance(intent, Send):
                    self.send(TNS_DATA, intent.data)
                    to_send = None
                else:  # pragma: no cover - defensive
                    raise TypeError(f'unknown dialect intent: {intent!r}')
        except StopIteration as done:
            return done.value

    def _handle_rpa(self, Data: bytes) -> int | None:
        Result = decode_token_rpa(Data, ())
        if Result[0] == TTI_SESS:
            # Auth challenge: (TTI_SESS, SessKey, Salt, DerivedSalt, Vgen, Sder, Vfr)
            (_, SessKey, Salt, DerivedSalt, VgenCount, SderCount, VerifierType) = Result
            logger.debug('handle_login: auth challenge received')
            self.conn_state = CONN_STATE_AUTH_NEGOTIATE
            Auth = {
                'sess': bytes.fromhex(SessKey.decode('utf-8')) if SessKey else None,
                'salt': bytes.fromhex(Salt.decode('utf-8')) if Salt else None,
                'derived_salt': bytes.fromhex(DerivedSalt.decode('utf-8'))
                if DerivedSalt
                else None,
                # Server PBKDF2 iteration counts (256-bit scheme), so the key
                # derivation matches a server with non-default counts (#309).
                'vgen_count': VgenCount,
                'sder_count': SderCount,
                # Verifier type (AUTH_VFR_DATA flag) — picks the key schedule for
                # a pre-SHA-2 account on a modern server (#311).
                'verifier_type': VerifierType,
            }
            (Data, ConnKey) = encode_dictionary_auth(
                self._make_dict(DictionaryType.auth, auth=Auth)
            )
            self.conn_key = ConnKey
            self.send(TNS_DATA, Data)
            return self.handle_login()
        elif Result[0] == TTI_AUTH:
            # Auth result: (TTI_AUTH, Resp, Ver, SessId)
            (_, Resp, Ver, SessId) = Result
            logger.debug('handle_login: auth result Ver=%s SessId=%s', Ver, SessId)
            if self._token_auth:
                # Token auth (#125): the server grants the session with no
                # O5LOGON server proof (there is no conn_key), so accept the
                # returned version + session id directly.
                self.server_version = Ver
                self.session_id = SessId
                self.conn_state = CONN_STATE_AUTHENTICATED
                logger.debug('handle_login: authenticated (token)')
                return 0
            assert self.conn_key is not None
            if validate(bytes.fromhex(Resp.decode('utf-8')), self.conn_key):
                self.server_version = Ver
                self.session_id = SessId
                self.conn_state = CONN_STATE_AUTHENTICATED
                logger.debug('handle_login: authenticated')
                # Negotiation cache (#438): record the fast-auth field version so
                # the next reconnect to this target can skip the bare PRO probe.
                if self.negotiation_cache and self.field_version > FIELD_VERSION_23_1:
                    _nego_cache_put(self._nego_cache_key(), self.field_version)
                return 0
            else:
                logger.error('handle_login: server validation failed')
                self.disconnect()
                return 1
        else:
            logger.error('handle_login: unexpected RPA result %s', Result[0])
            return 1

    def _send_o3logon_phase2(self, Packet: bytes) -> None:
        # O3LOGON phase two (#90): the TTI_3LOGA response RPA carries the
        # session key as a positional length-prefixed ASCII-hex string
        # (TTI_RPA, ub1 count, ub1 length, <hex>). Decrypt it with the account's
        # DES verifier to recover the plaintext session key, DES-encrypt the
        # zero-padded password under it, and send TTI_3LOGON with AUTH_PASSWORD
        # = upper-hex(cipher) + decimal(pad count).
        from binascii import hexlify, unhexlify

        from seerdb.common.crypto import des_verifier, o3logon
        from seerdb.common.tns import encode_o3logon_phase2

        Length = Packet[2]
        SessKey = unhexlify(Packet[3 : 3 + Length])
        UserB = self.user.encode('utf-8')
        PassB = self.password.encode('utf-8')
        Verifier = des_verifier(UserB, PassB)
        (AuthPass, _, _) = o3logon(SessKey, Verifier, PassB)
        PadCount = (8 - len(PassB) % 8) % 8
        PwdField = (hexlify(AuthPass).decode('ascii').upper() + str(PadCount)).encode(
            'ascii'
        )
        self._o3_phase = 2
        self.send(TNS_DATA, encode_o3logon_phase2(self._next_seq(), UserB, PwdField))

    def _auth_info_pairs(self) -> list:
        # Informational AUTH_ pairs the OSESSKEY/OAUTH calls carry — session
        # metadata (program/machine/pid) the server stores in v$session but does
        # not authenticate on.
        import os

        return [
            (b'AUTH_PROGRAM_NM', self.app_name.encode('utf-8')),
            (b'AUTH_MACHINE', socket.gethostname().encode('utf-8')),
            (b'AUTH_PID', str(os.getpid()).encode('utf-8')),
        ]

    def _send_8i_osesskey(self) -> None:
        # Oracle 8i O3LOGON phase one: OSESSKEY (0x76) with the username and the
        # informational pairs; the server replies with an AUTH_SESSKEY RPA.
        from seerdb.common.tns import encode_o3logon_osesskey_phase1

        self.send(
            TNS_DATA,
            encode_o3logon_osesskey_phase1(
                self._next_seq(), self.user.encode('utf-8'), self._auth_info_pairs()
            ),
        )

    def _send_8i_oauth_phase2(self, Packet: bytes) -> None:
        # Oracle 8i O3LOGON phase two: recover the session key from AUTH_SESSKEY,
        # DES-encrypt the password under it (the same crypto as the 9i path), and
        # send it as AUTH_PASSWORD in the OAUTH (0x73) call.
        from binascii import hexlify

        from seerdb.common.crypto import des_verifier, o3logon
        from seerdb.common.tns import (
            encode_o3logon_oauth_phase2,
            parse_8i_auth_sesskey,
        )

        SessKey = parse_8i_auth_sesskey(Packet)
        UserB = self.user.encode('utf-8')
        PassB = self.password.encode('utf-8')
        Verifier = des_verifier(UserB, PassB)
        (AuthPass, _, _) = o3logon(SessKey, Verifier, PassB)
        PadCount = (8 - len(PassB) % 8) % 8
        PwdField = (hexlify(AuthPass).decode('ascii').upper() + str(PadCount)).encode(
            'ascii'
        )
        self._o3_phase = 2
        self.send(
            TNS_DATA,
            encode_o3logon_oauth_phase2(
                self._next_seq(),
                UserB,
                PwdField,
                self._auth_info_pairs() + [(b'AUTH_ACL', b'8000')],
            ),
        )

    def execute(
        self,
        Query: str,
        Bind: list | None = None,
        Def: list | None = None,
        Batch: list | None = None,
        BatchErrors: bool = False,
        ArrayDmlRowCounts: bool = False,
        ReturnBinds=None,
        scrollable: bool = False,
        Prefetch: int | None = None,
    ) -> object:
        if Bind is None:
            Bind = []
        if Def is None:
            Def = []
        if Batch is None:
            Batch = []
        Head = Query.strip().upper()
        # A pre-10g dialect (9i / fv2 or 8i) speaks its own request dialect, not
        # the TTI_ALL8 the rest of execute() builds. It runs as sans-io generators
        # driven by _drive; the connection is a thin orchestrator (#369). Neither
        # tier carries an autocommit bit, so commit is explicit.
        if self._dialect is not None:
            _check_fv2_bind_sizes(Bind, Batch)
            if Batch and CAP_ARRAY_DML not in self._dialect.capabilities():
                # Array DML (executemany) would silently apply only the first row
                # on these tiers. Fail loudly instead of corrupting data (#168).
                from seerdb.common.exceptions import NotSupportedError

                raise NotSupportedError(
                    'executemany (array DML) is not supported on Oracle '
                    + _pre10_tier_name_for(self._dialect)
                )
            if Head.startswith('SELECT'):
                return self._drain_cursor(
                    self._drive(self._dialect.execute_query(Query, Bind, self.fetch))
                )
            if Head.startswith('BEGIN') or Head.startswith('DECLARE'):
                Result = self._drive(self._dialect.execute_block(Query, Bind))
            elif ReturnBinds:
                # Pre-10g DML ... RETURNING (#801). These servers refuse the
                # 10g+ request form -- 9i answers ORA-00439 for this client
                # type -- but they run the identical statement inside a PL/SQL
                # block, where the INTO targets are ordinary OUT binds, a form
                # they have always supported. So the clause costs no new wire
                # format, only a rewrite.
                Wrapped, BlockBind = returning_block_request(Query, Bind)
                try:
                    Raw = self._drive(self._dialect.execute_block(Wrapped, BlockBind))
                except DatabaseError as Exc:
                    raise returning_block_error(Exc) from None
                Result = returning_block_result(Raw, len(Bind))
            else:  # DML (INSERT/UPDATE/DELETE)
                Result = self._drive(self._dialect.execute_dml(Query, Bind))
            if self.autocommit:
                self.commit()
            return Result
        if Head.startswith('SELECT'):
            Type = 'select'
        elif Head.startswith('BEGIN') or Head.startswith('DECLARE'):
            # Anonymous PL/SQL block: uses the dedicated 'block' exec option
            # set (set_opts), not the DML 'change' path — otherwise the server
            # rejects a block carrying binds with ORA-00600 [12259].
            Type = 'block'
        else:
            Type = 'change'
        # Scrollable cursors only apply to queries (#181). A scrollable cursor
        # may still run DDL/DML (e.g. CREATE/INSERT before the SELECT); never put
        # scroll flags on a non-SELECT or skip draining it.
        if Type != 'select':
            scrollable = False
            Prefetch = None
        Auto = 1 if self.autocommit else 0
        # Cursor cache lookup: if we've executed this SQL before and the
        # server returned a non-zero cursor id, reuse that handle and
        # skip the parse step. Limited to DML for now — caching SELECT
        # would also need to remember the row format the server sent in
        # the DCB during the first parse (a cached SELECT doesn't get
        # a fresh DCB), and that's a wider change. `Def` (output
        # definitions) varying also breaks the cache contract.
        CachedCursor = 0
        CacheKey = None
        # The cursor cache reuses a server cursor handle and skips re-sending
        # the SQL/OAC. That 11g optimization doesn't translate to 12c+: a
        # cached re-execute there fails (ORA-01009 / ORA-03115) because the
        # server expects the binds (and OAC) declared every execute. Disable
        # the cache on 12c+ — each execute re-parses, which is correct, just
        # without the handle-reuse speedup.
        #
        # `Type == 'change'` is a catch-all for everything that is neither a
        # SELECT nor a block, so it covers DDL as well as DML — and DDL must
        # never be cached (#703). A CREATE or DROP does its work when the server
        # *parses* it, so a cached re-execute has nothing left to do: the server
        # reports success and the statement silently never happens.
        # DDL invalidates the server cursors this session holds, and so may a
        # PL/SQL block. A cached id re-executed afterwards made a pre-12c server
        # reuse the previous execution's value for a NULL LONG-class bind
        # (#720). Forget them all, closing them with the next call.
        if Type == 'block' or (Type == 'change' and not is_reusable_dml(Query)):
            self._cursors_to_close.extend(self._cursor_cache.values())
            self._cursor_cache.clear()
        if (
            Type == 'change'
            and is_reusable_dml(Query)
            and not Def
            and self.field_version < FIELD_VERSION_12_1
            # A statement with a LONG-class bind is never cached: DDL from
            # another session would leave the same stale buffer behind (#720).
            and not has_long_class_bind(
                Bind, Batch, max_string_size(self._server_runtime_caps)
            )
        ):
            CacheKey = (Query, exec_oac_signature(Bind, Batch))
            CachedCursor = self._cursor_cache.get(CacheKey, 0)
        SendQuery = '' if CachedCursor else Query
        QueryDict = {
            'type': Type,
            'auto': Auto,
            # A scrollable open prefetches only `Prefetch` rows (oracledb's
            # prefetchrows) so the cursor stays mid-stream — draining it to EOF
            # on the open breaks the subsequent scroll re-execute (#181).
            'fetch': self.fetch if Prefetch is None else Prefetch,
            'server_version': self.server_version,
            'cursor': CachedCursor,
            'query': SendQuery,
            'bind': Bind,
            'batch': Batch,
            'def': Def,
            'batcherrors': BatchErrors,
            'arraydmlrowcounts': ArrayDmlRowCounts,
            'return_binds': ReturnBinds or None,
            # Server-side scrollable cursor open (#181): mark the cursor
            # scrollable and position it at CURRENT (a describe-only open — the
            # rows come from later scroll_fetch re-executes).
            'scrollable': scrollable,
            'scroll': (TNS_FETCH_ORIENTATION_CURRENT, 1) if scrollable else None,
        }
        # Piggybacks in front of this execute (each gets a seq before the
        # execute's): close any drained server cursors queued from prior calls
        # (#191), then flush any pending end-to-end tracing change (#183).
        Pre = (
            self._flush_cursor_closes_bytes()
            + self._flush_end_to_end_bytes()
            + self._flush_end_user_sec_bytes()
            + self._flush_session_state_bytes()
        )
        Data = encode_dictionary(self._make_dict(DictionaryType.exec, query=QueryDict))
        self.send(TNS_DATA, Pre + Data)
        # Arm row-count extraction for this response only (#18).
        set_decode_dml_rowcounts(ArrayDmlRowCounts)
        # Arm RETURNING out-bind decoding for this response only (#120).
        set_decode_return_binds(ReturnBinds)
        # call_timeout (#123): a timer fires an out-of-band break if the call
        # runs too long; the server interrupts it (ORA-01013), which we remap to
        # a call-timeout error below.
        Timer = None
        if self._call_timeout:
            self._timed_out = False
            Timer = threading.Timer(self._call_timeout / 1000.0, self._on_call_timeout)
            Timer.start()
        try:
            # Seed the decoder with the bind list so the IOV decoder can tell a
            # REF CURSOR OUT bind from a scalar one.
            Result = self._handle_response((None, None, [], Bind))
        except Exception as exc:
            # If reusing a cached cursor blew up, drop it from the cache
            # so the next attempt re-parses from scratch.
            if CachedCursor and CacheKey is not None:
                self._cursor_cache.pop(CacheKey, None)
            if self._timed_out:
                raise OperationalError(
                    f'call timeout of {self._call_timeout} ms exceeded (ORA-03136)'
                ) from exc
            raise
        finally:
            if Timer is not None:
                Timer.cancel()
            self._break_in_progress = False
            self._timed_out = False
        # A cached cursor whose execute failed is gone on the server side: a
        # later re-execute of the same id answers ORA-01001 for the rest of the
        # connection, whatever the values (#709). Forget it, so the next execute
        # of this statement parses afresh. An Oracle error is an ordinary status
        # here, not an exception, so the except above never sees it. A batch
        # error (24381) leaves the cursor usable: the batch ran, some rows failed.
        if (
            CachedCursor
            and CacheKey is not None
            and isinstance(Result, tuple)
            and len(Result) >= 2
            and Result[1] not in (0, 1403, 24381)
        ):
            self._cursor_cache.pop(CacheKey, None)
        # Stash the cursor id the server returned so the next execute of
        # the same SQL can skip parsing. Same scoping as the lookup:
        # DML only, no Def overrides.
        Stored = False
        if (
            CacheKey is not None
            and Type == 'change'
            and not Def
            and isinstance(Result, tuple)
            and len(Result) >= 3
            and isinstance(Result[2], int)
            and Result[2] > 0
            and Result[1] in (0, 1403)
        ):
            # CacheKey is None whenever the cache is disabled for this execute
            # (12c+, where a cached re-execute fails) — gating the write on it
            # too keeps a stray {None: cursor_id} entry out of the cache (#80).
            CursorId = Result[2]
            # LRU bump: move the entry to the end on hit; evict the oldest
            # entry when the cache fills up.
            self._cursor_cache.pop(CacheKey, None)
            self._cursor_cache[CacheKey] = CursorId
            while len(self._cursor_cache) > self._cursor_cache_max:
                Oldest = next(iter(self._cursor_cache))
                self._cursor_cache.pop(Oldest, None)
            Stored = True
        if scrollable:
            # A scrollable open is describe-only: don't drain (the rows come from
            # scroll_fetch) and don't queue the cursor for close — it must stay
            # open for the scroll re-executes (#181). The cursor closes it when
            # the user closes / re-executes the cursor.
            return Result
        Drained = self._drain_cursor(Result)
        # Queue the statement's own server cursor for close unless it was cached
        # for reuse (#191). The result set is fully buffered by now, and this is
        # the main statement cursor — REF CURSOR / implicit-result cursors carry
        # their own distinct ids and are untouched.
        if (
            not Stored
            and isinstance(Drained, tuple)
            and len(Drained) >= 3
            and isinstance(Drained[2], int)
            and Drained[2] > 0
        ):
            self._cursors_to_close.append(Drained[2])
        return Drained

    def scroll_fetch(
        self,
        CursorId: int,
        Orientation: int,
        Position: int,
        RowFormat: list,
        Fetch: int | None = None,
        PrevRow: list | None = None,
    ) -> tuple:
        """Re-execute an open scrollable cursor (#181) with a fetch orientation
        and 1-based position, returning ``(rows, at_eof, server_rowcount)``. The
        response carries RXD rows but no DCB, so the prior RowFormat is seeded
        into the decoder (as fetch_more does). ``server_rowcount`` is the
        cursor's cumulative row position after this batch (the absolute row
        number of the last row returned) — the caller uses it to place the
        buffer (oracledb's ``_post_process_scroll``). A re-execute returning no
        rows means the scroll ran off the end (the cursor stays open thanks to
        NO_CANCEL_ON_EOF). ``Fetch`` overrides the prefetch row count for this
        batch (default: the connection's ``fetch``)."""
        QueryDict = {
            'type': 'select',
            'auto': 0,
            'fetch': self.fetch if Fetch is None else Fetch,
            'server_version': self.server_version,
            'cursor': CursorId,
            'query': '',
            'bind': [],
            'batch': [],
            'def': [],
            'batcherrors': None,
            'arraydmlrowcounts': None,
            'return_binds': None,
            'scrollable': True,
            'scroll': (Orientation, Position),
        }
        Pre = (
            self._flush_cursor_closes_bytes()
            + self._flush_end_to_end_bytes()
            + self._flush_end_user_sec_bytes()
            + self._flush_session_state_bytes()
        )
        Data = encode_dictionary(self._make_dict(DictionaryType.exec, query=QueryDict))
        self.send(TNS_DATA, Data if not Pre else Pre + Data)
        # Seed the prior batch's last row so a reused (bit-unset) column on the
        # first row of this re-execute resolves to its real value (#181).
        set_decode_prev_row(PrevRow)
        try:
            Result = self._handle_response((None, RowFormat, []))
        finally:
            set_decode_prev_row(None)
        if not isinstance(Result, tuple) or len(Result) < 6:
            return ([], True, 0)
        (_, OraCode, _, RetFormat, Rows, *_) = Result
        AtEof = (OraCode == 1403) or not Rows
        ServerRowCount = (
            RetFormat[0] if (isinstance(RetFormat, tuple) and RetFormat) else 0
        )
        return (list(Rows or []), AtEof, ServerRowCount)

    def _drain_cursor(self, Result: object) -> object:
        # The EXEC response either bundles all rows inline (small SELECTs,
        # all DDL/DML) or only returns column metadata and signals "more on
        # this cursor" via OER.call_status == 1. In the latter case the
        # client is expected to issue follow-up TTI_FETCH calls until the
        # server returns ORA-01403 (end-of-fetch). This applies to any
        # large result set and to *every* SELECT that touches a LOB column,
        # regardless of size — see docs/PROTOCOL.md §5.2.
        if not isinstance(Result, tuple) or len(Result) < 6:
            return Result
        (CallStatus, OraCode, CursorId, RetFormat, Rows, *Tail) = Result
        AllRows = list(Rows or [])
        RowFormat = None
        if (
            isinstance(RetFormat, tuple)
            and len(RetFormat) > 1
            and isinstance(RetFormat[1], list)
        ):
            RowFormat = RetFormat[1]
        # No row format means there's nothing further to fetch (DDL / DML
        # responses), and CursorId == 0 means no cursor to fetch from.
        # Fetch whenever the server has not signalled end-of-fetch, whatever
        # the call status. call_status is NOT a "more rows" flag: it reads 2
        # while a transaction is open, for an ordinary row as much as a LOB one.
        # Requiring 1 here meant that with autocommit off -- which is what
        # SQLAlchemy and any explicit transaction ask for -- a SELECT of a LOB
        # column whose row was still uncommitted returned no rows at all: the
        # server defers those rows to a FETCH (call_status 2, no 1403, nothing
        # inline) and the client never asked for them (#712).
        if RowFormat and CursorId and OraCode != 1403:
            try:
                while True:
                    # Bit-vector (BVC) duplicate-column detection is per fetch
                    # response, and each continuation batch decodes with an empty
                    # row list — so seed the last row fetched so far. Without it,
                    # a column the server elides as "same as previous row" in the
                    # first row of a continuation batch decodes as None instead of
                    # the carried value (#326).
                    set_decode_prev_row(AllRows[-1] if AllRows else None)
                    FetchResult = self.fetch_more(
                        CursorId, self.fetch, RowFormat=RowFormat
                    )
                    if not isinstance(FetchResult, tuple) or len(FetchResult) < 6:
                        break
                    (CallStatus, OraCode, _, _, MoreRows, *_) = FetchResult
                    if MoreRows:
                        AllRows.extend(MoreRows)
                    # ORA-01403 is the server saying "you've drained the cursor";
                    # call_status != 1 means the same thing via a different field.
                    # End of fetch, or a batch that brought nothing back --
                    # which also guarantees this loop terminates.
                    if OraCode == 1403 or not MoreRows:
                        break
            finally:
                set_decode_prev_row(None)
        # Hide the ORA-01403 sentinel from callers; it was an internal
        # protocol marker, not a user-visible error.
        if OraCode == 1403:
            OraCode = 0
        return (CallStatus, OraCode, CursorId, RetFormat, AllRows) + tuple(Tail)

    def fetch_more(
        self, CursorId: int, Rows: int | None = None, RowFormat: list | None = None
    ) -> object:
        # FETCH responses carry RXH / RXD / OER but no DCB — the column
        # metadata was already established during the original EXEC. Seed
        # the decoder Acc with the prior RowFormat so the per-row DALC
        # parser knows how many columns to read.
        if Rows is None:
            Rows = self.fetch
        Data = encode_dictionary(
            self._make_dict(DictionaryType.fetch, cursor=CursorId, fetch=Rows)
        )
        self.send(TNS_DATA, Data)
        return self._handle_response(Acc=(None, RowFormat, []))

    def fetch_all_rows(self, CursorId: int, RowFormat: list) -> list:
        # Drain a server cursor (e.g. a REF CURSOR returned by a procedure)
        # by issuing TTI_FETCH until the server signals end-of-fetch.
        AllRows: list = []
        try:
            while True:
                # Seed the last row so a BVC-reused column in the next batch's
                # first row copies the carried value, not None (#326).
                set_decode_prev_row(AllRows[-1] if AllRows else None)
                Result = self.fetch_more(CursorId, self.fetch, RowFormat=RowFormat)
                if not isinstance(Result, tuple) or len(Result) < 6:
                    break
                (CallStatus, OraCode, _, _, MoreRows, *_) = Result
                if MoreRows:
                    AllRows.extend(MoreRows)
                if OraCode == 1403 or not MoreRows:
                    break
        finally:
            set_decode_prev_row(None)
        return AllRows

    def lob_read(
        self, Locator: bytes, DataType: int, prefixed: bool = False
    ) -> str | bytes:
        # Send TTI_LOBOPS READ for the given locator and decode the response.
        # The response carries:
        #
        #   TNS_MSG_TYPE_LOB_DATA (= 14)  →  length-prefixed content chunk
        #   TTI_RPA                       →  return parameters (locator update +
        #                                    actual amount); we skip these
        #   TTI_OER                       →  end-of-call status
        #
        # CLOB / NCLOB content is sent as UTF-16BE on the wire; BLOB / BFILE
        # is raw bytes. We decode CLOB to `str` and surface BLOB as `bytes`.
        from seerdb.common.tns_consts import TNS_TYPE_CLOB

        Data = encode_dictionary(
            self._make_dict(
                DictionaryType.lobops, locator=Locator, locator_prefixed=prefixed
            )
        )
        self.send(TNS_DATA, Data)
        Content = self._read_lob_response()
        if DataType == TNS_TYPE_CLOB:
            return Content.decode('utf-16-be', errors='replace')
        return Content

    def gettype(self, name: str) -> 'DbObjectType':
        """Look up a SQL object type by name and return a ``DbObjectType``.

        ``name`` is the type name, optionally schema-qualified
        (``'ADDR_T'`` or ``'PYO.ADDR_T'``); an unqualified name resolves in the
        current schema. Use ``newobject()`` on the result to build a value to
        bind (#116). oracledb-compatible.
        """
        if '.' in name:
            Schema, _, TypeName = name.partition('.')
            Schema = (
                Schema.strip('"').upper() if '"' not in Schema else Schema.strip('"')
            )
        else:
            Schema, TypeName = None, name
        TypeName = TypeName.strip('"') if '"' in TypeName else TypeName.upper()
        Typ = self._describe_object_type(Schema, TypeName)
        if Typ is None or (not Typ.attrs and not Typ.is_collection):
            from seerdb.common.exceptions import DatabaseError

            raise DatabaseError(f'object type {name!r} not found')
        return Typ

    def _describe_object_type(
        self, schema: str | None, name: str | None
    ) -> 'DbObjectType | None':
        # Fetch a SQL object type's identity (16-byte OID + version) and ordered
        # attribute layout from the data dictionary, cached per connection keyed
        # by (owner, name). Used both by the row decoder (#115) and gett() /
        # bind (#116). When `schema` is None the type resolves in the current
        # schema (USER). A type the session can't see yields a handle with an
        # empty layout (the #115 read path tolerates that).
        if not name:
            return None
        from seerdb.common.dbobject import DbObjectType, type_name_to_tns

        Owner = schema
        if Owner is None:
            Result = self.execute('SELECT USER FROM dual')
            Rows = self._rows(Result)
            Owner = Rows[0][0] if Rows else None
        if not Owner:
            return None
        Key = (Owner, name)
        Cached = self._object_type_cache.get(Key)
        if Cached is not None:
            return Cached
        OidSQL = (
            'SELECT type_oid, typecode FROM all_types '
            'WHERE owner = :1 AND type_name = :2'
        )
        OidRes = self.execute(OidSQL, Bind=[Owner, name])
        OidRows = self._rows(OidRes)
        Oid = bytes(OidRows[0][0]) if OidRows and OidRows[0][0] else b''
        TypeCode = OidRows[0][1] if OidRows else None
        SQL = (
            'SELECT attr_name, attr_type_name, length, precision, scale '
            'FROM all_type_attrs '
            'WHERE owner = :1 AND type_name = :2 '
            'ORDER BY attr_no'
        )
        Result = self.execute(SQL, Bind=[Owner, name])
        Rows = self._rows(Result)
        Attrs = []
        for Row in Rows:
            TypeName = Row[1]
            Attrs.append(
                {
                    'name': Row[0],
                    'type_name': TypeName,
                    'data_type': type_name_to_tns(TypeName),
                    'charset': None,
                }
            )
        CollKW = self._collection_describe(Owner, name, TypeCode)
        # The OAC type version: the freshly-created/common case is 1; the server
        # validated this across 10g..23ai in the round-trip tests.
        Typ = DbObjectType(Owner, name, Oid, 1, Attrs, **CollKW)
        self._object_type_cache[Key] = Typ
        return Typ

    def _collection_describe(self, owner, name, typecode) -> dict:
        # For a collection type (#117/#118) read the single element type + kind
        # from ALL_COLL_TYPES. Returns the DbObjectType collection kwargs (empty
        # for a non-collection object type).
        if typecode != 'COLLECTION':
            return {}
        from seerdb.common.dbobject import (
            COLLECTION_NESTED_TABLE,
            COLLECTION_VARRAY,
            type_name_to_tns,
        )

        Res = self.execute(
            'SELECT coll_type, elem_type_name, length, precision, scale, '
            'upper_bound FROM all_coll_types WHERE owner = :1 AND type_name = :2',
            Bind=[owner, name],
        )
        Rows = self._rows(Res)
        if not Rows:
            return {'is_collection': True}
        (CollType, ElemType, _Len, _Prec, _Scale, Upper) = Rows[0][:6]
        return {
            'is_collection': True,
            'collection_type': (
                COLLECTION_VARRAY
                if CollType == 'VARYING ARRAY'
                else COLLECTION_NESTED_TABLE
            ),
            'element': {
                'name': 'element',
                'type_name': ElemType,
                'data_type': type_name_to_tns(ElemType),
                'charset': None,
            },
            'max_elements': int(Upper) if Upper else 0,
        }

    def _object_type_layout(self, schema: str | None, name: str | None) -> list:
        # The ordered attribute layout (#115 read path). Delegates to the type
        # describe so the OID/version/layout are fetched and cached once.
        Typ = self._describe_object_type(schema, name)
        return Typ.attrs if Typ is not None else []

    def create_temp_lob(self, is_blob: bool = False) -> bytes:
        # Create a session-duration temporary LOB on the server (TTI_LOBOPS
        # CREATE_TEMP, #91) and return its locator. Used to bind a large LOB
        # value into a PL/SQL locator parameter, where the streamed-LONG bind
        # path fails with ORA-01460. 12c+ only — 11g rejects CREATE_TEMP — so
        # callers gate on field_version. The response is a single TTI_RPA token
        # carrying the new locator: 0x08, ub2 length, then the locator bytes.
        from seerdb.common.tns_consts import TTI_RPA

        Data = encode_dictionary(
            self._make_dict(DictionaryType.lobops, create_temp=True, is_blob=is_blob)
        )
        self.send(TNS_DATA, Data)
        Received = self._next_data_packet(b'', b'')
        if Received is False:
            raise Exception('Connection closed during CREATE_TEMP')
        (_, Packet) = Received
        if not Packet or Packet[0] != TTI_RPA:
            raise Exception(
                'Unexpected CREATE_TEMP response', Packet[:8].hex() if Packet else None
            )
        LocLen = (Packet[1] << 8) | Packet[2]
        return Packet[3 : 3 + LocLen]

    def write_temp_lob(
        self, Locator: bytes, Data: str | bytes, is_blob: bool = False
    ) -> None:
        # Write `Data` into a (temporary) LOB via TTI_LOBOPS WRITE (op 0x0040,
        # #91), starting at offset 1. CLOB content goes on the wire as UTF-16BE;
        # BLOB content is raw bytes. The server answers with TTI_RPA (updated
        # locator + bytes written) followed by TTI_OER (call status); we walk to
        # the OER and raise on a real error. 12c+ only (paired with
        # create_temp_lob). The encoder chunks payloads > 0xFC bytes itself.
        from seerdb.common.tns_consts import TNS_LOB_OP_WRITE

        Payload = Data if is_blob else cast(str, Data).encode('utf-16-be')
        Dict = self._make_dict(
            DictionaryType.lobops,
            locator=Locator,
            data=Payload,
            operation=TNS_LOB_OP_WRITE,
        )
        self.send(TNS_DATA, encode_dictionary(Dict))
        self._confirm_lobops()

    def _confirm_lobops(self) -> None:
        # Drain a TTI_LOBOPS response that carries no content (WRITE / temp /
        # BFILE open-close ops): receive the RPA + OER packet and raise on a
        # non-zero ORA error.
        Received = self._next_data_packet(b'', b'')
        if Received is False:
            raise Exception('Connection closed during LOBOPS')
        self._raise_lobops_error(Received[1])

    def bfile_read_native(self, Locator: bytes) -> bytes:
        # Read a BFILE natively over TTI_LOBOPS (#46): FILE_OPEN -> READ ->
        # FILE_CLOSE, no PL/SQL helper. FILE_OPEN returns an *updated* locator
        # in its RPA (with the open flag set); READ / CLOSE must use that one —
        # a READ against the original locator returns empty bytes (the symptom
        # that originally blocked native BFILE support). The locator goes on the
        # wire ub2-length-prefixed (locator_prefixed), as for temp LOBs.
        from seerdb.common.tns_consts import (
            TNS_LOB_OP_FILE_CLOSE,
            TNS_LOB_OP_FILE_OPEN,
            TTI_RPA,
        )

        # A BFILE locator as fetched (LOB.raw) leads with its own ub2
        # inner-length; the encoder re-adds that prefix, so pass the body. The
        # FILE_OPEN response RPA already hands back the body form.
        if len(Locator) >= 2 and ((Locator[0] << 8) | Locator[1]) == len(Locator) - 2:
            Locator = Locator[2:]
        self.send(
            TNS_DATA,
            encode_dictionary(
                self._make_dict(
                    DictionaryType.lobops,
                    locator=Locator,
                    operation=TNS_LOB_OP_FILE_OPEN,
                )
            ),
        )
        Received = self._next_data_packet(b'', b'')
        if Received is False:
            raise Exception('Connection closed during BFILE FILE_OPEN')
        (_, Packet) = Received
        self._raise_lobops_error(Packet)
        if not Packet or Packet[0] != TTI_RPA:
            raise Exception(
                'Unexpected FILE_OPEN response', Packet[:8].hex() if Packet else None
            )
        OpenLen = (Packet[1] << 8) | Packet[2]
        Opened = Packet[3 : 3 + OpenLen]
        try:
            self.send(
                TNS_DATA,
                encode_dictionary(
                    self._make_dict(
                        DictionaryType.lobops, locator=Opened, locator_prefixed=True
                    )
                ),
            )
            Content = self._read_lob_response()
        finally:
            self.send(
                TNS_DATA,
                encode_dictionary(
                    self._make_dict(
                        DictionaryType.lobops,
                        locator=Opened,
                        operation=TNS_LOB_OP_FILE_CLOSE,
                    )
                ),
            )
            self._confirm_lobops()
        return Content

    def bfile_read(self, directory_name: str, file_name: str) -> bytes:
        # Read a BFILE by directory object + filename. Resolves the locator with
        # a SELECT BFILENAME and reads it natively over TTI_LOBOPS (#46) — the
        # cursor's LOB auto-resolve runs bfile_read_native under the hood. (This
        # used to install a PL/SQL DBMS_LOB helper; the native FILE_OPEN/READ/
        # FILE_CLOSE sequence removed that, along with its CREATE PROCEDURE
        # privilege requirement and schema side effects.)
        Cur = self.cursor()
        Cur.execute(
            'SELECT BFILENAME(:d, :f) FROM DUAL', {'d': directory_name, 'f': file_name}
        )
        return Cur.fetchone()[0]

    def _read_lob_response(self) -> bytes:
        # Walk the LOBOPS response packets, accumulating LOB_DATA chunks
        # until we hit the trailing OER. A LOBOPS response packet on 11g
        # carries: TTI_LOB (content) + TTI_RPA (updated locator) + TTI_OER
        # (call status). We pull the content out of the LOB chunk(s) and
        # use OER as the stop signal; everything between LOB and OER is
        # RPA-shaped metadata we don't need.
        from seerdb.common.tns_consts import TTI_LOB, TTI_OER

        Buffer = b''
        while True:
            # Same break/reset-aware receive as the main response path (#45):
            # a LOB read that gets cancelled mid-stream must complete the reset
            # handshake instead of echoing markers and dropping content.
            Received = self._next_data_packet(b'', b'')
            if Received is False:
                raise Exception('Connection closed during LOBOPS response')
            (Type, Packet) = Received
            if Type != TNS_DATA:
                raise Exception('Unexpected LOBOPS response type', Type)
            Pos = 0
            OerSeen = False
            while Pos < len(Packet):
                Token = Packet[Pos]
                if Token == TTI_LOB:
                    # Content chunk. Format: token + 1-byte length + data, or
                    # token + 0xFE + chunked sequence of <ub1 len><bytes>.
                    Pos += 1
                    if Pos >= len(Packet):
                        break
                    Length = Packet[Pos]
                    Pos += 1
                    if Length == 0:
                        continue
                    if Length == 0xFE:
                        # Chunked content. 12c+ prefixes each chunk with a ub4
                        # length (terminated by a zero-length chunk); 11g uses a
                        # single length byte per chunk.
                        if self.field_version >= FIELD_VERSION_12_2:
                            while Pos < len(Packet):
                                NLen = Packet[Pos]
                                Pos += 1
                                if NLen == 0:
                                    break
                                ChunkLen = int.from_bytes(
                                    Packet[Pos : Pos + NLen], 'big'
                                )
                                Pos += NLen
                                Buffer += Packet[Pos : Pos + ChunkLen]
                                Pos += ChunkLen
                        else:
                            while Pos < len(Packet):
                                ChunkLen = Packet[Pos]
                                Pos += 1
                                if ChunkLen == 0:
                                    break
                                Buffer += Packet[Pos : Pos + ChunkLen]
                                Pos += ChunkLen
                    else:
                        Buffer += Packet[Pos : Pos + Length]
                        Pos += Length
                elif Token == TTI_OER:
                    # End of call. Anything after is fluff.
                    OerSeen = True
                    break
                else:
                    # Likely TTI_RPA (0x08) carrying the updated locator and
                    # actual amount read — we don't decode it. Scan forward for
                    # the OER and stop. The OER opens with TTI_OER + call_status
                    # (ub4 len 1, then the value), then the end-to-end seq#
                    # whose length byte (the original 11g signature's 4th byte)
                    # varies per call. call_status is a flag word, not always 1:
                    # it reads 2 while a transaction is open (#712), so accept
                    # the low flag values as well as the historical `04 01 XX 01`
                    # form. Matching only `04 01 01` left the reader waiting for
                    # a packet that never came whenever autocommit was off.
                    Found = -1
                    for I in range(Pos, len(Packet) - 3):
                        if (
                            Packet[I] == TTI_OER
                            and Packet[I + 1] == 0x01
                            and (Packet[I + 2] < 0x10 or Packet[I + 3] == 0x01)
                        ):
                            Found = I
                            break
                    if Found >= 0:
                        Pos = Found
                        continue
                    # No OER in this packet — fall out and recv the next one.
                    break
            if OerSeen:
                return Buffer
            # Packet exhausted without hitting OER; loop and recv the next.

    def commit(self) -> None:
        if self._dialect is not None and CAP_OWN_TXN in self._dialect.capabilities():
            self._drive(self._dialect.txn_control('COMMIT'))  # 8i: OALL8 statement
            self._sessionless_txn_active = False
            return
        from seerdb.common.tns_consts import TTI_COMMIT

        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_COMMIT))
        self.send(TNS_DATA, Data)
        self._handle_response()
        # An ordinary commit ends an active sessionless transaction (#133); the
        # server confirms via a keyword-201 sync-unset pair on this response.
        self._sessionless_txn_active = False

    def rollback(self) -> None:
        if self._dialect is not None and CAP_OWN_TXN in self._dialect.capabilities():
            self._drive(self._dialect.txn_control('ROLLBACK'))
            self._sessionless_txn_active = False
            return
        from seerdb.common.tns_consts import TTI_ROLLBACK

        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_ROLLBACK))
        self.send(TNS_DATA, Data)
        self._handle_response()
        self._sessionless_txn_active = False

    def ping(self) -> None:
        if self.field_version < FIELD_VERSION_10_2:
            # Oracle 9i lacks the TTI_PING (func 147) message — it closes the
            # connection on receipt. Use a trivial round trip instead so ping
            # still validates the session (e.g. for pool health checks). (#168)
            self.execute("SELECT 'X' FROM dual")
            return
        from seerdb.common.tns_consts import TTI_PING

        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_PING))
        self.send(TNS_DATA, Data)
        self._handle_response()

    def changepassword(self, old_password: str, new_password: str) -> None:
        """Change the connected user's password (#21, oracledb-compatible).

        Sends a single TTI_AUTH password-change call on the live session,
        reusing the session key established at login (no re-handshake). On
        success the connection stays usable and its stored password is updated
        so a later reconnect / pool checkout uses the new one. A wrong
        `old_password` raises ORA-01017; a rejected new password (policy /
        verifier) raises e.g. ORA-28003.
        """
        from seerdb.common.exceptions import (
            InterfaceError,
            NotSupportedError,
            from_ora_code,
        )

        if self.field_version < FIELD_VERSION_10_2:
            # 9i changes a password via the O3LOGON-era exchange, not the single
            # TTI_AUTH this sends; gate it rather than break the session (#168).
            raise NotSupportedError('changepassword is not supported on Oracle 9i')
        if self.conn_state != CONN_STATE_AUTHENTICATED or self.conn_key is None:
            raise InterfaceError('changepassword requires an authenticated connection')
        Auth = {
            'conn_key': self.conn_key,
            'old_password': old_password,
            'new_password': new_password,
        }
        Data = encode_dictionary(self._make_dict(DictionaryType.chgpwd, auth=Auth))
        self.send(TNS_DATA, Data)
        Result = cast(tuple, self._handle_response())
        ErrCode = Result[1] if isinstance(Result, tuple) and len(Result) > 1 else 0
        if ErrCode and ErrCode not in (0, 1403):
            Message = Result[5] if len(Result) > 5 else None
            raise from_ora_code(ErrCode)(Message or f'ORA-{ErrCode:05d}', code=ErrCode)
        self.password = new_password

    def close(self) -> None:
        # Best-effort orderly shutdown, then always disconnect so the OS socket
        # gets reclaimed even if the server-side handshake has gone sideways.
        if self.conn_state == CONN_STATE_DISCONNECTED:
            return
        try:
            if self.conn_state == CONN_STATE_AUTHENTICATED:
                if not self.autocommit:
                    self.rollback()
                # Any server cursors still queued for close (#191) are freed by
                # the session teardown below — no explicit OCCA needed.
                # Logoff (the TTI_LOGOFF function call + its response)
                Data = encode_dictionary(self._make_dict(DictionaryType.close))
                self.send(TNS_DATA, Data)
                self._handle_response()
                # Final empty TNS_DATA packet with the EOF data flag, telling
                # the server to fully release the session. Without this the
                # session lingers server-side and accumulates over rapid
                # reconnect cycles. Format: 10-byte header (PacketSize,
                # PacketFlags, Type, Flags, DataFlags).
                if self.sock is not None:
                    self._sock.send(
                        struct.pack('>hhBBh', 10, 0, TNS_DATA, 0, TNS_DATA_FLAGS_EOF)
                    )
        except (OSError, Exception):
            # If the server already hung up or our state is out of sync, we
            # still want to release the local socket.
            pass
        finally:
            self.disconnect()

    def _handle_response(self, Acc: tuple | None = None) -> object:
        # Acc seeds the decoder context (Cursor, RowFormat, Rows). The
        # default `(None, None, [])` is right for any response that starts
        # with a DCB (which sets RowFormat for the subsequent RXDs). FETCH
        # responses skip the DCB and need the prior RowFormat passed in.
        from seerdb.common.tns import (
            FLUSH_OUT_BINDS,
            MAX_FLUSH_OUT_BINDS,
            decode_packet,
        )

        if Acc is None:
            Acc = (None, None, [])
        for _ in range(MAX_FLUSH_OUT_BINDS + 1):
            # Receive the next DATA packet, transparently completing any server
            # break/reset handshake (#45). _next_data_packet sends a single reset
            # per break episode and drains the rest, so a cancelled/errored call
            # no longer storms the line or discards the trailing error/result.
            Received = self._next_data_packet(b'', b'')
            if Received is False:
                raise Exception('Connection closed while awaiting response')
            (Type, Packet) = Received
            if Type != TNS_DATA:
                raise Exception('Unexpected response type', Type)
            Result = decode_packet(Packet, Acc, self.field_version)
            if Result != FLUSH_OUT_BINDS:
                return Result
            # A flush-out-binds request, not a result: echo the token back and
            # read on for the response it is standing in front of (§6.9, #697).
            self.send(TNS_DATA, bytes([TTI_FOB]))
        raise InterfaceError('server kept asking to flush out binds')

    def send(self, Type: int, Data: bytes | None) -> bool | None:
        # Iterative split-and-send. Was previously recursive, which blew
        # Python's default recursion limit on payloads big enough to
        # cross more than a few SDU boundaries (test_basic crashed with
        # RecursionError on the auth handshake).
        while Data is not None:
            if Type == TNS_DATA and self._ano is not None and self._ano.active:
                (Packet, Rest) = self._encode_ano_packet(Data)
            else:
                (Packet, Rest) = encode_packet(
                    Type, Data, self.sdu, self._large_packets
                )
            try:
                self._sock.send(Packet)
            except TimeoutError as exc:
                raise self._timeout_error('write') from exc
            Data = Rest
        logger.debug('Send OK')
        return True

    def _negotiate_ano(self) -> None:
        # Run the ANO negotiation (plaintext) after the accept, then activate the
        # per-packet cipher + MAC. See seerdb.common.ano / ano_session (#437).
        from seerdb.common import ano
        from seerdb.common.ano_session import AnoChannel

        Request = ano.encode_ano(
            [
                ano.supervisor_service(),
                ano.auth_service(),
                ano.encryption_service(
                    [
                        'RC4_40',
                        'RC4_56',
                        'RC4_128',
                        'RC4_256',
                        'DES56C',
                        'AES128',
                        'AES192',
                        'AES256',
                    ]
                ),
                ano.data_integrity_service(
                    ['MD5', 'SHA1', 'SHA512', 'SHA256', 'SHA384']
                ),
            ]
        )
        self.send(TNS_DATA, Request)
        Received = self.recv(b'', b'')
        if Received is False:
            raise OperationalError('ANO negotiation: connection closed by server')
        (_Type, Payload) = Received
        Response = ano.decode_container(Payload)
        ByType = {S['type']: S for S in Response['services']}
        EncId = ByType[ano.SERVICE_ENCRYPTION]['subpackets'][1][1]
        IntId = ByType[ano.SERVICE_DATA_INTEGRITY]['subpackets'][1][1]
        Integrity = ByType[ano.SERVICE_DATA_INTEGRITY]
        # A server that only *supports* ANO (encryption not required/configured)
        # selects the null algorithm and carries no Diffie-Hellman exchange in
        # its reply — the negotiation completes but the session stays plaintext
        # (go-ora activates no cipher when publicKey is empty). Leave self._ano
        # None so send()/recv() take the ordinary TTC path.
        if EncId == 0 or len(Integrity['subpackets']) < 8:
            logger.debug(
                'handle_login: ANO negotiated, no encryption selected (enc=%d)',
                EncId,
            )
            return
        (Gen, Prime, ServerPub, ServerIv) = ano.extract_dh_params(Integrity)
        Dh = ano.compute_dh(Gen, Prime, ServerPub)
        self.send(TNS_DATA, ano.dh_public_key_round(Dh.public_key))
        self._ano = AnoChannel(EncId, IntId, Dh.session_key, ServerIv)
        logger.debug('handle_login: ANO active (enc=%d integrity=%d)', EncId, IntId)

    def _timeout_error(self, op: str) -> OperationalError:
        return OperationalError(
            f'network {op} timed out after {self.timeout} ms (connection timeout)'
        )

    # --- Two-phase commit / XA (#131) ---

    def _tpc_request(self, Data: bytes) -> bytes:
        # Send a TPC function message and return the assembled response body
        # (the bytes after the leading token). The return parameters (context /
        # state) sit at the front, followed by the call-status OER.
        self.send(TNS_DATA, Data)
        Received = self._next_data_packet(b'', b'')
        if Received is False:
            raise OperationalError('connection closed during TPC operation')
        (_, Packet) = Received
        return Packet

    def tpc_begin(self, xid: Xid, flags: int = TPC_BEGIN_NEW, timeout: int = 0) -> None:
        """Begin a TPC (global) transaction branch identified by `xid`."""
        if self.field_version < FIELD_VERSION_12_1:
            from seerdb.common.exceptions import NotSupportedError

            raise NotSupportedError(
                'two-phase commit (TPC/XA) requires an Oracle 12.1+ server'
            )
        Data = encode_tpc_switch(
            self._next_seq(),
            self.field_version,
            TNS_TPC_TXN_START,
            xid,
            flags,
            timeout,
            None,
        )
        self._transaction_context = _decode_tpc_context(self._tpc_request(Data))

    def tpc_end(self, xid: Xid, flags: int = TPC_END_NORMAL) -> None:
        """Detach from the TPC transaction branch (end the local work)."""
        Data = encode_tpc_switch(
            self._next_seq(),
            self.field_version,
            TNS_TPC_TXN_DETACH,
            xid,
            flags,
            0,
            self._transaction_context,
        )
        self._tpc_request(Data)
        self._transaction_context = None

    def tpc_prepare(self, xid: Xid) -> bool:
        """Prepare the branch. Returns True if a commit is needed, False if the
        branch was read-only (nothing to commit)."""
        Data = encode_tpc_change_state(
            self._next_seq(),
            self.field_version,
            TNS_TPC_TXN_PREPARE,
            0,
            xid,
            0,
            self._transaction_context,
        )
        State = _decode_tpc_state(self._tpc_request(Data))
        if State == TNS_TPC_TXN_STATE_REQUIRES_COMMIT:
            return True
        if State == TNS_TPC_TXN_STATE_READ_ONLY:
            return False
        raise DatabaseError(f'unknown TPC transaction state {State}')

    def tpc_commit(self, xid: Xid, one_phase: bool = False) -> None:
        """Commit the branch. `one_phase` commits without a prior prepare."""
        State = (
            TNS_TPC_TXN_STATE_READ_ONLY if one_phase else TNS_TPC_TXN_STATE_COMMITTED
        )
        Data = encode_tpc_change_state(
            self._next_seq(),
            self.field_version,
            TNS_TPC_TXN_COMMIT,
            State,
            xid,
            0,
            self._transaction_context,
        )
        Result = _decode_tpc_state(self._tpc_request(Data))
        self._transaction_context = None
        Ok = (
            Result in (TNS_TPC_TXN_STATE_READ_ONLY, TNS_TPC_TXN_STATE_COMMITTED)
            if one_phase
            else Result == TNS_TPC_TXN_STATE_FORGOTTEN
        )
        if not Ok:
            raise DatabaseError(f'unexpected TPC commit state {Result}')

    def tpc_rollback(self, xid: Xid) -> None:
        """Roll back the branch."""
        Data = encode_tpc_change_state(
            self._next_seq(),
            self.field_version,
            TNS_TPC_TXN_ABORT,
            TNS_TPC_TXN_STATE_ABORTED,
            xid,
            0,
            self._transaction_context,
        )
        Result = _decode_tpc_state(self._tpc_request(Data))
        self._transaction_context = None
        if Result != TNS_TPC_TXN_STATE_ABORTED:
            raise DatabaseError(f'unexpected TPC rollback state {Result}')

    # --- Sessionless transactions (#133, 23ai) ---

    def _sessionless_switch(
        self, operation: int, transaction_id, flags: int, timeout: int
    ):
        # Send a func-103 switch carrying the magic sessionless format-id. The
        # txn id (gtrid) is only attached for start/resume; detach sends none.
        xid = None
        if transaction_id is not None:
            xid = Xid(TNS_TPC_SESSIONLESS_FORMAT_ID, transaction_id, b'')
        Data = encode_tpc_switch(
            self._next_seq(), self.field_version, operation, xid, flags, timeout, None
        )
        self._tpc_request(Data)

    def begin_sessionless_transaction(
        self, transaction_id=None, timeout: int = 60
    ) -> bytes:
        """Start a sessionless transaction. `transaction_id` (str/bytes, <=64
        bytes) defaults to a fresh uuid4; returns the id used. `timeout` is the
        seconds the server keeps the suspended transaction resumable."""
        self._check_sessionless_support()
        if self._sessionless_txn_active:
            raise DatabaseError('a sessionless transaction is already active')
        txnid = _normalize_sessionless_txn_id(transaction_id)
        self._sessionless_switch(
            TNS_TPC_TXN_START, txnid, TPC_BEGIN_NEW | TPC_TXN_FLAGS_SESSIONLESS, timeout
        )
        self._sessionless_txn_active = True
        return txnid

    def resume_sessionless_transaction(
        self, transaction_id, timeout: int = 60
    ) -> bytes:
        """Resume a previously suspended sessionless transaction (possibly on a
        different session). `transaction_id` is required; returns it."""
        self._check_sessionless_support()
        if self._sessionless_txn_active:
            raise DatabaseError('a sessionless transaction is already active')
        txnid = _normalize_sessionless_txn_id(transaction_id)
        self._sessionless_switch(
            TNS_TPC_TXN_START,
            txnid,
            TPC_BEGIN_RESUME | TPC_TXN_FLAGS_SESSIONLESS,
            timeout,
        )
        self._sessionless_txn_active = True
        return txnid

    def suspend_sessionless_transaction(self) -> None:
        """Suspend the active sessionless transaction so another session can
        resume it. The transaction's work is preserved (not committed)."""
        self._check_sessionless_support()
        if not self._sessionless_txn_active:
            raise DatabaseError('no sessionless transaction is active')
        self._sessionless_switch(TNS_TPC_TXN_DETACH, None, TPC_TXN_FLAGS_SESSIONLESS, 0)
        self._sessionless_txn_active = False

    # --- Request pipelining (#132) ---

    def run_pipeline(self, pipeline, continue_on_error: bool = False) -> list:
        """Run a Pipeline's queued operations and return a PipelineOpResult for
        each (#132/#158). The operations run in order; `continue_on_error`
        records a failing op's error and keeps going, otherwise the first error
        is raised after its result is recorded.

        On a 23ai server that negotiated end-of-response framing (#155) the
        execute/fetch ops are sent as one token-tagged burst and their
        responses read back in a single round trip (#158). Older servers — or a
        pipeline carrying ops the wire path does not cover (commit, callproc,
        callfunc) — fall back to running each op serially; the API, ordering and
        results are identical either way."""
        if self._pipeline_wire_eligible(pipeline):
            return self._run_pipeline_pipelined(pipeline, continue_on_error)
        from seerdb.client.pipeline import PipelineOpType as T

        results = []
        Cur = self.cursor()
        for Op in pipeline.operations:
            Result = _run_pipeline_op(self, Cur, Op, T)
            results.append(Result)
            if Result.error is not None and not continue_on_error:
                raise Result.error
        return results

    def _encode_pipeline_op(self, Op, TokenNum: int):
        # Build one pipelined op's exec request (token-tagged, no cursor cache)
        # and return (Data, Bind). FETCH ops set a prefetch large enough to pull
        # their rows inline in the execute response (the pipelined burst can't
        # interleave follow-up TTI_FETCH calls); any overflow is drained
        # serially after the burst.
        from seerdb.client.cursor import _resolve_parameters
        from seerdb.client.pipeline import PipelineOpType as T

        Bind = _resolve_parameters(Op.statement, Op.parameters)
        Batch = []
        if Op.op_type == T.EXECUTE_MANY:
            Rows = [_resolve_parameters(Op.statement, P) for P in (Op.parameters or [])]
            Bind = Rows[0] if Rows else []
            Batch = Rows[1:]
        Head = Op.statement.strip().upper()
        if Head.startswith('SELECT'):
            Type = 'select'
        elif Head.startswith('BEGIN') or Head.startswith('DECLARE'):
            Type = 'block'
        else:
            Type = 'change'
        if Op.op_type == T.FETCH_ONE:
            Fetch = 1
        elif Op.op_type == T.FETCH_MANY:
            Fetch = Op.num_rows or self.fetch
        elif Op.op_type == T.FETCH_ALL:
            Fetch = _PIPELINE_FETCH_ALL_PREFETCH
        else:
            Fetch = self.fetch
        QueryDict = {
            'type': Type,
            'auto': 1 if self.autocommit else 0,
            'fetch': Fetch,
            'server_version': self.server_version,
            'cursor': 0,
            'query': Op.statement,
            'bind': Bind,
            'batch': Batch,
            'def': [],
            'batcherrors': False,
            'arraydmlrowcounts': False,
            'return_binds': None,
        }
        Data = encode_dictionary(
            self._make_dict(DictionaryType.exec, query=QueryDict, token_num=TokenNum)
        )
        return (Data, Bind)

    def _pipeline_send_op(
        self, Data: bytes, FinalFlags: int, FirstFlags: int = 0
    ) -> None:
        # Send one pipelined op's request as DATA packet(s): an oversized op
        # fragments at the SDU with the 0x0020 "more" flag, the final fragment
        # carries FinalFlags (END_OF_REQUEST), and the very first packet of the
        # whole burst additionally carries FirstFlags (BEGIN_PIPELINE).
        BodyMax = self.sdu - 10
        First = True
        while len(Data) > BodyMax:
            Flags = TNS_DATA_FLAGS_MORE | (FirstFlags if First else 0)
            self._sock.send(
                encode_data_packet(Data[:BodyMax], Flags, self._large_packets)
            )
            Data = Data[BodyMax:]
            First = False
        Flags = FinalFlags | (FirstFlags if First else 0)
        self._sock.send(encode_data_packet(Data, Flags, self._large_packets))

    def _pipeline_recv_response(self) -> bytes:
        # Read exactly one op's response (TOKEN + body + EOR) as a single
        # response unit, buffering any following op responses in self._pending.
        # The connection's normal recv() coalesces consecutive complete packets
        # into one blob — fatal here, since each op response must be decoded on
        # its own — so the pipelined read assembles packets directly and stops
        # at the first response-final packet.
        Body = b''
        while True:
            if len(self._pending) >= 8:
                (Flag, Type, Chunk, Rest) = assemble_packet(
                    self._pending, self.sdu, self._large_packets
                )
                if Chunk is not None:
                    self._pending = Rest if Rest is not None else b''
                    if Type == TNS_MARKER:
                        # A pipelined op that errors makes the server interject a
                        # bare break marker (01 00 01) between op responses — but
                        # it does NOT wait for a reset and keeps streaming the
                        # remaining responses, so (unlike #45) skip the marker
                        # silently and read on to the erroring op's real response.
                        continue
                    Body += Chunk
                    if Flag:
                        return Body
                    continue
            More = self._sock.recv(self.sdu)
            if not More:
                raise OperationalError('connection closed during pipeline read')
            self._pending = self._pending + More

    def _run_pipeline_pipelined(self, pipeline, continue_on_error: bool) -> list:
        # The single-round-trip wire path (#158). Send a begin-pipeline
        # piggyback + every op (token 1..N, END_OF_REQUEST per op) + an
        # end-pipeline message as one burst, then read the N token-tagged
        # responses back-to-back. The wire always runs in CONTINUE_ON_ERROR
        # mode so the server returns a response for every op (no partial-burst
        # desync); the caller's abort semantics are enforced client-side.
        from seerdb.client.pipeline import PipelineOpResult
        from seerdb.client.pipeline import PipelineOpType as T

        Ops = pipeline.operations
        # Phase 1 — build the burst. The begin piggyback takes the first seq and
        # shares op 1's token; each op then claims its own seq via _make_dict.
        BeginSeq = self._next_seq()
        Built = [self._encode_pipeline_op(Op, K) for K, Op in enumerate(Ops, start=1)]
        EndSeq = self._next_seq()
        Begin = encode_pipeline_begin(
            BeginSeq, self.field_version, 1, TNS_PIPELINE_MODE_CONTINUE_ON_ERROR
        )
        # Phase 2 — send. First packet: begin + op 1 (BEGIN_PIPELINE |
        # END_OF_REQUEST); each later op: END_OF_REQUEST; then the ordinary
        # end-pipeline message (data flags 0).
        self._pipeline_send_op(
            Begin + Built[0][0],
            TNS_DATA_FLAGS_END_OF_REQUEST,
            FirstFlags=TNS_DATA_FLAGS_BEGIN_PIPELINE,
        )
        for Data, _Bind in Built[1:]:
            self._pipeline_send_op(Data, TNS_DATA_FLAGS_END_OF_REQUEST)
        self.send(TNS_DATA, encode_pipeline_end(EndSeq, self.field_version))
        # Phase 3 — read every op's response before any draining, so no
        # follow-up TTI_FETCH is interleaved with the queued responses.
        Raw = []
        for _Data, Bind in Built:
            Body = self._pipeline_recv_response()
            set_decode_dml_rowcounts(False)
            set_decode_return_binds(None)
            Raw.append(decode_packet(Body, (None, None, [], Bind), self.field_version))
        # The end-pipeline message (func 200) draws its own terminating
        # response after the N op responses; read and discard it so the next
        # call on this connection is not left reading a stale packet.
        self._pipeline_recv_response()
        # Phase 4 — the line is clean now; drain any query that signalled "more
        # rows" with serial TTI_FETCH calls, then interpret each result.
        Results = []
        FirstError = None
        Cur = self.cursor()
        for Op, (_Data, Bind), RawResult in zip(Ops, Built, Raw):
            Result = PipelineOpResult(Op)
            Results.append(Result)
            try:
                Drained = self._drain_cursor(RawResult)
                Cur._apply_result(Bind, Drained)
                if Op.op_type == T.FETCH_ONE:
                    Row = Cur.fetchone()
                    Result.rows = _apply_rowfactory(
                        [] if Row is None else [Row], Op.rowfactory
                    )
                    Result.columns = Cur.description
                elif Op.op_type == T.FETCH_MANY:
                    Result.rows = _apply_rowfactory(
                        Cur.fetchmany(Op.num_rows), Op.rowfactory
                    )
                    Result.columns = Cur.description
                elif Op.op_type == T.FETCH_ALL:
                    Result.rows = _apply_rowfactory(Cur.fetchall(), Op.rowfactory)
                    Result.columns = Cur.description
            except DatabaseError as exc:
                Result.error = exc
                if FirstError is None:
                    FirstError = exc
        if FirstError is not None and not continue_on_error:
            raise FirstError
        return Results

    # --- Advanced Queuing (#128) ---

    def queue(self, name: str, payload_type=None):
        """Return a Queue handle. payload_type is a DbObjectType (object-payload
        queue) or seerdb.JSON (JSON-payload queue); omit it for a RAW queue."""
        from seerdb.client.aq import Queue
        from seerdb.common.datatypes import JSON as _JSON
        from seerdb.common.exceptions import NotSupportedError

        if self.field_version < FIELD_VERSION_12_1:
            raise NotSupportedError('Advanced Queuing requires an Oracle 12.1+ server')
        if payload_type is _JSON:
            return Queue(self, name, payload_type=None, is_json=True)
        return Queue(self, name, payload_type=payload_type)

    def _aq_request(self, Data: bytes) -> bytes:
        self.send(TNS_DATA, Data)
        Received = self._next_data_packet(b'', b'')
        if Received is False:
            raise OperationalError('connection closed during AQ operation')
        (_, Packet) = Received
        return Packet

    def _aq_enq_one(self, queue, props) -> None:
        Data = encode_aq_enq(self._next_seq(), self.field_version, queue, props)
        props.msgid = _decode_aq_enq(self._aq_request(Data))

    def _aq_deq_one(self, queue):
        Data = encode_aq_deq(self._next_seq(), self.field_version, queue)
        return _decode_aq_deq(self._aq_request(Data), queue)

    def _aq_enq_many(self, queue, props_list) -> None:
        from seerdb.common.tns_consts import TNS_AQ_ARRAY_ENQ

        Data = encode_aq_array(
            self._next_seq(),
            self.field_version,
            queue,
            TNS_AQ_ARRAY_ENQ,
            props_list,
            len(props_list),
        )
        _decode_aq_array(self._aq_request(Data), queue, TNS_AQ_ARRAY_ENQ, props_list)

    def _aq_deq_many(self, queue, max_messages):
        from seerdb.client.aq import MessageProperties
        from seerdb.common.tns_consts import TNS_AQ_ARRAY_DEQ

        Placeholders = [MessageProperties() for _ in range(max_messages)]
        Data = encode_aq_array(
            self._next_seq(),
            self.field_version,
            queue,
            TNS_AQ_ARRAY_DEQ,
            Placeholders,
            max_messages,
        )
        return _decode_aq_array(
            self._aq_request(Data), queue, TNS_AQ_ARRAY_DEQ, Placeholders
        )

    def _send_break(self) -> None:
        # Interrupt the running call. Two paths, matching python-oracledb (#144):
        #   * when the server advertised attention support (CAN_RECV_ATTENTION in
        #     the accept, self._supports_oob) we send an out-of-band urgent byte
        #     -- the server's attention handler sees it immediately, even while
        #     compute-bound;
        #   * otherwise we send an in-band INTERRUPT marker packet (an ordinary
        #     packet the server's two-task layer polls for), which works on every
        #     tier and over any network path.
        # Either way the server interrupts the call and replies with break/reset
        # markers + ORA-01013, drained via the existing reset handshake (#45);
        # the connection resyncs and is reusable. #123 sent OOB unconditionally,
        # which silently did nothing against servers that don't advertise OOB.
        if self._break_in_progress or self.sock is None:
            return
        self._break_in_progress = True
        try:
            if self._supports_oob:
                self._sock.send(b'!', socket.MSG_OOB)
            else:
                (Packet, _) = encode_packet(
                    TNS_MARKER,
                    bytes([1, 0, TNS_MARKER_TYPE_INTERRUPT]),
                    self.sdu,
                    self._large_packets,
                )
                self._sock.send(Packet)
        except OSError:
            # Best-effort interrupt: if the socket is already gone the call we're
            # trying to break is dead anyway, so there's nothing to recover.
            pass

    @property
    def _sock(self) -> socket.socket:
        # The connected socket, narrowed non-None for the send/recv paths (it is
        # None only before connect() / after close()).
        if self.sock is None:
            raise InterfaceError('connection is not open')
        return self.sock

    def recv(self, Acc: bytes, Data: bytes) -> tuple[int, bytes] | Literal[False]:
        # Iterative receive + reassemble. Was previously recursive — for a
        # multi-KiB response (e.g. a LOB content fetch that spans many
        # SDU-sized TCP segments) the recursion depth blew the default
        # Python limit during the auth handshake on some setups.
        #
        # Seed from any bytes preserved past the previous marker (#45): a
        # server break/reset can arrive coalesced with the trailing error/LOB
        # DATA in one TCP read, so on a marker we keep `Rest` in self._pending
        # instead of dropping it, and drain it here before touching the socket.
        Acc = self._pending + Acc
        self._pending = b''
        while True:
            # Drain as many complete packets as `Acc` already contains
            # before going back to the socket for more bytes. Need at
            # least 8 bytes for a TNS header before assemble_packet can
            # do anything useful.
            while len(Acc) >= 8:
                (Flag, Type, Body, Rest) = assemble_packet(
                    Acc, self.sdu, self._large_packets
                )
                if Flag is True:
                    # A full packet was assembled, so type/body/rest are set.
                    assert Type is not None and Body is not None and Rest is not None
                    if Type == TNS_MARKER:
                        # Preserve everything after the marker (the coalesced
                        # reset / error DATA) for the next recv() rather than
                        # discarding it — the break state machine in
                        # _next_data_packet drives the reset handshake.
                        self._pending = Rest
                        return (TNS_MARKER, b'')
                    # Native network encryption (#437): each DATA packet's body
                    # is independently encrypted + MAC'd, so decrypt/verify per
                    # packet, before reassembly concatenates the plaintext.
                    if Type == TNS_DATA and self._ano is not None and self._ano.active:
                        Body = self._ano.unwrap(Body)
                    if Rest == b'':
                        return (Type, Data + Body)
                    Acc = Rest
                    Data = Data + Body
                    continue
                if Body is not None:
                    # Continuation fragment: Flag=False but a Body was
                    # extracted. Consume the body and keep reading; the
                    # next packet's header is in Rest (may be empty,
                    # in which case the outer loop will read more).
                    if self._ano is not None and self._ano.active:
                        Body = self._ano.unwrap(Body)
                    Acc = Rest or b''
                    Data = Data + Body
                    continue
                # Not enough bytes yet for a full packet — back to recv.
                break
            try:
                NetworkData = self._sock.recv(self.sdu)
            except TimeoutError as exc:
                raise self._timeout_error('read') from exc
            if not NetworkData:
                # Peer closed the connection.
                return False
            Acc = Acc + NetworkData

    def _next_data_packet(
        self, Acc: bytes = b'', Data: bytes = b''
    ) -> tuple[int, bytes] | Literal[False]:
        # Receive the next TNS_DATA packet, transparently completing a server
        # break/reset handshake (#45). The 21c server cancels an errored or
        # interrupted call by sending a break marker (01 00 01) followed by a
        # reset marker (01 00 02) and then the inline error/result DATA. A
        # correct client answers with exactly ONE reset and drains the rest;
        # python-oracledb does 2 server markers : 1 client reset. Replying to
        # every marker storms the line and discards real data. self._in_break
        # latches across recv() calls so we send at most one reset per break
        # episode, and is cleared when a real DATA packet arrives.
        while True:
            Received = self.recv(Acc, Data)
            if Received is False:
                return False
            (Type, Packet) = Received
            if Type != TNS_MARKER:
                self._in_break = False
                return (Type, Packet)
            if not self._in_break:
                self.send(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
                self._in_break = True
            # else: drain the server's terminal reset (and any straggler
            # markers) silently — do NOT reply, or the server replies again.

    def disconnect(self) -> None:
        if self.sock:
            # Half-close (SHUT_WR) flushes our pending writes (including the
            # EOF marker close() just queued) and tells the server we won't
            # send anything else, so it can complete session teardown before
            # the local socket goes away. Without this, the server can hold a
            # half-closed connection long enough that the next connect() trips
            # over Oracle XE's per-second new-connection rate limit (which
            # surfaces on the client as ORA-01013).
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except OSError:
                # The peer may have already closed its side; we still
                # close() the local socket immediately below.
                pass
            self.sock.close()
            self.sock = None
        self.conn_state = CONN_STATE_DISCONNECTED

    def cursor(self, scrollable: bool = False):
        # PEP 249 cursor factory. `scrollable` (oracledb parity, #161) opens a
        # scrollable cursor; seerdb buffers the result set so scroll() works
        # regardless, but the flag is accepted and surfaced for compatibility.
        from seerdb.client.cursor import Cursor

        return Cursor(self, scrollable=scrollable)

    def getSodaDatabase(self):
        """Return a `SodaDatabase` for document-store (SODA) access (#163).
        Raises NotSupportedError on a pre-18c server (no DBMS_SODA)."""
        from seerdb.client.soda import SodaDatabase, _check_soda_supported

        _check_soda_supported(self)
        return SodaDatabase(self)

    # --- End-to-end application tracing (#183) ---

    def _end_request(self) -> None:
        # Marks the end of a pooled logical request (#464). If a BEGIN was armed
        # but never flushed (no operation ran), just cancel it. Otherwise send a
        # REQUEST_END marker piggybacked on a rollback round-trip (mirrors
        # oracledb's _on_request_end_phase_one, which rolls back at request end).
        if not self._in_request:
            return
        if self._session_state_desired != 0:
            # BEGIN never rode a call — nothing was sent, so nothing to close.
            self._session_state_desired = 0
            self._in_request = False
            return
        self._session_state_desired = TNS_SESSION_STATE_REQUEST_END
        self._in_request = False
        from seerdb.common.tns_consts import TTI_ROLLBACK

        Pre = self._flush_session_state_bytes()
        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_ROLLBACK))
        self.send(TNS_DATA, Pre + Data)
        self._handle_response()

    def __enter__(self):
        if self.sock is None:
            self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
