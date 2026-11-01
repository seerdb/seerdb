# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Drive the server side of a login over a :class:`PacketStream`.

Sequences the 11g handshake and O5LOGON built up across the handshake/auth
modules, so a real client authenticates against the Mirror in either PRO
dialect — the thin ``TTI_PRO`` form (seerdb, python-oracledb thin) or the classic
``deadbeef``/OCI form (sqlplus, thick OCI), which runs an extra data-type round
and marshals auth from captured 11g templates (#265):

    CONNECT → ACCEPT → PRO → DTY → [TYPE] → OSESSKEY → challenge → AUTH → result

The Mirror holds account passwords in a configured credential map (Oracle
usernames match case-insensitively); a backend-mapped auth API comes later.
"""

from __future__ import annotations

import contextvars
import datetime
import functools
import hmac
import logging
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import replace
from secrets import token_bytes
from typing import NoReturn, ParamSpec, TypeVar

from seerdb.common.crypto import VFR_12C_SHA2, decrypt_password
from seerdb.common.dbobject import ObjectImage
from seerdb.common.exceptions import (
    DataError,
    InterfaceError,
    NotSupportedError,
    Truncated,
)
from seerdb.common.oci import (
    OCI_CMD_COMMIT,
    OCI_CMD_ROLLBACK,
    OCI_E2E_VALUES_OFF,
    OCI_E2E_VALUES_OFF_12C,
    strip_oci_e2e_piggyback,
)
from seerdb.common.sqltext import (
    altered_current_schema,
    altered_edition,
    is_plsql,
    is_reusable_dml,
    placeholder_count,
    plsql_bind_directions,
)
from seerdb.common.tns import (
    _CSFRM_DB,
    _DECODE_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    _ENCODE_OCI_CALL_SEQ,
    _ENCODE_OCI_LOB_12C,
    _ENCODE_OCI_TSTZ_LOCAL,
    _ENCODE_OER_SEQ,
    _ENCODE_SERVER_FIELD_VERSION,
    _ENCODE_TXN_IN_PROGRESS,
    _LOB_EMIT_LOG,
    _SERVER_RUNTIME_CAPS,
    _STATE_KEY_EDITION,
    _THIN_OBJ_LOB_LOCATOR,
    AUTH_SERIAL_NUM,
    LOBOPS_ERR_ALREADY_OPEN,
    LOBOPS_ERR_NOT_OPENED,
    OCI_NLS_KEYWORDS,
    ArrayOutBind,
    ColumnMeta,
    ExecRequest,
    FetchRequest,
    LobEmitLog,
    LobOpsRequest,
    LobOutBind,
    NestedCursor,
    ReexecuteRequest,
    RefCursorOutBind,
    ScalarOutBind,
    TempLobRef,
    ddl_command_type,
    decode_bfile_locator,
    decode_dalc,
    decode_ub4,
    encode_batch_errors_status,
    encode_challenge,
    encode_changepassword_status_oci,
    encode_commit_status_oci,
    encode_create_temp_response,
    encode_ddl_status_oci,
    encode_describe,
    encode_describe_reply_oci,
    encode_dml_status_oci,
    encode_error,
    encode_error_oci,
    encode_exec_by_cursor_reply_oci,
    encode_fetch_batch_oci,
    encode_fetch_response,
    encode_fetch_terminator_oci,
    encode_implicit_results,
    encode_kod_named_reply,
    encode_kod_reply,
    encode_lob_describe_oci,
    encode_lob_fetch_rows_oci,
    encode_lob_read_response_oci,
    encode_lob_read_response_thin,
    encode_lobops_ack,
    encode_lobops_echo,
    encode_lobops_error,
    encode_lobops_is_open,
    encode_lobops_length,
    encode_lobops_open_ack,
    encode_login_refusal_oci,
    encode_logoff_status_oci,
    encode_logoff_status_thin,
    encode_long_fetch_row_oci,
    encode_out_bind_reexecute_thin,
    encode_out_bind_response_oci,
    encode_out_bind_response_thin,
    encode_ping_status_oci,
    encode_query_response,
    encode_query_response_oci,
    encode_reexec_row_oci,
    encode_result,
    encode_returning_response,
    encode_rowcounts_block,
    encode_scroll_open_response,
    encode_scroll_response,
    encode_session_state_response,
    encode_status,
    encode_status_oci,
    encode_status_with_rowcounts,
    encode_sync_piggyback,
    encode_token_result,
    encode_version_banner_oci,
    inline_long_after_type_change,
    inline_long_for_defines,
    is_reexecute_oci,
    is_version_call_oci,
    kod_system_record,
    kod_type_record,
    kod_xmltype_record,
    max_string_size,
    mint_temp_lob_locator,
    object_lob_contents,
    oci_is_xmltype,
    oci_lob_contents,
    oci_lob_reads,
    oci_lob_row_cells,
    oci_lob_var_id,
    parse_describe_oci,
    parse_exec,
    parse_exec_by_cursor_oci,
    parse_exec_oci,
    parse_fetch,
    parse_fetch_oci,
    parse_free_temp_lobs_piggyback,
    parse_kod_request,
    parse_lobops_locator,
    parse_lobops_read,
    parse_lobops_request,
    parse_lobops_slot,
    parse_reexecute,
    parse_reexecute_oci,
    parse_tpc_switch,
    peek_exec_cursor,
    scroll_start_row,
    skip_close_cursors_piggyback,
    strip_oci_piggyback,
)
from seerdb.common.tns_consts import (
    CCAP_LOB,
    CCAP_LOB_12C,
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_18_1,
    FIELD_VERSION_23_1,
    FIELD_VERSION_23_1_EXT_1,
    ORA_INSUFFICIENT_PRIVILEGES,
    ORA_INTERNAL_ERROR,
    ORA_INVALID_CURSOR,
    ORA_INVALID_LOB_LOCATOR,
    ORA_INVALID_USERNAME_PASSWORD,
    ORA_NONEXISTENT_FILE,
    ORA_ORACLE_NOT_AVAILABLE,
    ORA_UNIQUE_CONSTRAINT_VIOLATED,
    ORA_UNSUPPORTED_NETWORK_DATATYPE,
    ORA_USER_REQUESTED_CANCEL,
    TNS_APP_CONTEXT_FLAG_CLEAR,
    TNS_BIND_DIR_INPUT,
    TNS_BIND_DIR_INPUT_OUTPUT,
    TNS_BIND_DIR_OUTPUT,
    TNS_CONNECT,
    TNS_DATA,
    TNS_DATA_FLAGS_END_OF_REQUEST,
    TNS_FUNC_ALTER_SESSION,
    TNS_FUNC_APP_CONTEXT,
    TNS_FUNC_PIPELINE_BEGIN,
    TNS_FUNC_PIPELINE_END,
    TNS_FUNC_REEXECUTE,
    TNS_FUNC_REEXECUTE_AND_FETCH,
    TNS_FUNC_SESSION_STATE,
    TNS_FUNC_SET_END_TO_END_ATTR,
    TNS_FUNC_SET_SCHEMA,
    TNS_FUNC_TPC_TXN_SWITCH,
    TNS_KEYWORD_NUM_TXN_PRIORITY,
    TNS_MARKER,
    TNS_MARKER_TYPE_BREAK,
    TNS_MARKER_TYPE_RESET,
    TNS_MSG_TYPE_FAST_AUTH,
    TNS_TYPE_BFILE,
    TNS_TYPE_BLOB,
    TNS_TYPE_CHAR,
    TNS_TYPE_CLOB,
    TNS_TYPE_JSON,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_REFCURSOR,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_VARCHAR,
    TNS_TYPE_VECTOR,
    TNS_VERSION_MIN_LARGE_SDU,
    TNS_VERSION_MIN_OOB_CHECK,
    TTI_ALL8,
    TTI_AUTH,
    TTI_COMMIT,
    TTI_DESCRIBE,
    TTI_EXEC,
    TTI_FETCH,
    TTI_FUN,
    TTI_KOD,
    TTI_LOBOPS,
    TTI_LOGOFF,
    TTI_MSG_TYPE_PIGGYBACK,
    TTI_OCCA,
    TTI_PING,
    TTI_ROLLBACK,
    TTI_STA,
)
from seerdb.server import lockout, stats
from seerdb.server.auth import (
    check_auth_complete,
    derive_conn_key,
    encode_challenge_oci,
    encode_result_oci,
    find_fast_auth_osesskey,
    is_token_auth,
    make_challenge,
    parse_auth_alter_session,
    parse_auth_app_context,
    parse_auth_connect_attrs,
    parse_auth_new_password,
    parse_auth_response,
    parse_auth_response_oci,
    parse_changepassword,
    parse_changepassword_oci,
    parse_client_identity,
    parse_osesskey,
    parse_osesskey_oci,
    parse_token_auth,
    verify_password,
)
from seerdb.server.backend import (
    Backend,
    BackendError,
    BindVar,
    BlobValue,
    Capability,
    ClobValue,
    CursorResult,
    LtzValue,
    Result,
    SessionInfo,
    UnsupportedFeature,
    VarcharValue,
)
from seerdb.server.framing import PacketStream
from seerdb.server.handshake import (
    client_compile_cap,
    client_field_version,
    client_sends_tz_file_version,
    connect_data_follows,
    encode_accept,
    encode_ano_null_reply,
    encode_dty_reply,
    encode_fast_auth_reply,
    encode_oci_dty_reply,
    encode_pro_reply,
    is_ano_negotiation,
    negotiated_tns_version,
    oci_field_version,
    opens_with_oci_ano,
    parse_connect,
    server_tns_version,
)
from seerdb.server.identity import IDENTITY_11_2, ServerIdentity, server_identity
from seerdb.server.redact import redact_passwords

_T = TypeVar('_T')
_P = ParamSpec('_P')


def _in_own_context(func: Callable[_P, _T]) -> Callable[_P, _T]:
    # Run a session in a copy of its caller's context (#1333). A session pins
    # its codec state -- the field version it decodes and encodes at, the OCI
    # call sequence -- in context variables. The server gives every connection a
    # fresh thread, but a caller that serves one session after another on the
    # same thread (a thread pool, a test) carried each session's state into the
    # next. A copy still starts from the caller's values.
    @functools.wraps(func)
    def run(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        return contextvars.copy_context().run(func, *args, **kwargs)

    return run


logger = logging.getLogger('seerdb.server')

# A fetch count of 0 or less means "no limit" — deliver the whole remainder.
_ALL_ROWS = 2**31


# How many leftover packets the Mirror will step over while looking for the
# message that should follow the DTY. A DTY is ~2.6 KiB and the smallest SDU a
# client may negotiate is 512, so six fragments is already the worst case; the
# cap exists so a client sending something else entirely still fails fast.
_LOGIN_MAX_CONTINUATIONS = 8
# How long a client has to finish logging in (GHSA-5827-wqfh-x2v3): between
# a client and the Mirror a login is a few round trips, never a wait on the
# client.
LOGIN_SECONDS = 60.0
# ORA-28000, a login to a name locked after too many failures (GHSA-742q-fjfr-w5x3).
ORA_ACCOUNT_LOCKED = 28000


def _expect_login_message(stream: PacketStream, what: str) -> bytes:
    """Read the next login message, stepping over any tail of the previous one.

    A client splits a message at the negotiated SDU, and the modern DATA_TYPES
    table is ~2642 bytes -- so every SDU below about 2650 cuts the DTY into two
    or more packets. The Mirror read one packet, answered the half it had, and
    then took the REMAINDER as the message that should have followed:

        InterfaceError: not a TTI_FUN message

    which the client saw as DPY-4011. It looked intermittent only because
    python-oracledb's test_1144 picks a random SDU; swept against the Mirror,
    every value up to 2646 failed and every value from 2743 up passed (#968).

    The tail is recognised by what it is NOT: every message the login path reads
    here -- OSESSKEY, the OCI type round, a token AUTH -- begins with TTI_FUN,
    and a fragment of a DATA_TYPES table does not. Measuring the fragment
    against the SDU instead does not work: the client flushes a packet as soon as
    the next field will not fit, so a fragment can stop a byte or two short of
    the capacity and "exactly full" never holds.
    """
    for _ in range(_LOGIN_MAX_CONTINUATIONS):
        body = _expect(stream, TNS_DATA, what)
        if body[:1] == bytes([TTI_FUN]):
            return body
    raise InterfaceError(f'no {what} arrived after the data-type negotiation')


def _expect(stream: PacketStream, want: int, what: str) -> bytes:
    received = stream.read_packet()
    if received is None:
        raise InterfaceError(f'client closed during login (expected {what})')
    packet_type, body = received
    if packet_type != want:
        raise InterfaceError(
            f'expected {what} (packet type {want}), got type {packet_type}'
        )
    return body


# The Mirror's algorithm preference, strongest first — intersected with what the
# client offered. Only the AES ciphers and SHA-2 checksums are implemented.
_SERVER_ENC_PREF = ('AES256', 'AES192', 'AES128')
_SERVER_INT_PREF = ('SHA256', 'SHA384', 'SHA512')


def _select_algorithm(
    offered: list[int], preference: tuple[str, ...], table: dict
) -> int:
    # The first of our preferences the client also offered; 0 (null) if none.
    offered_set = set(offered)
    for name in preference:
        if table[name] in offered_set:
            return table[name]
    return 0


def _negotiate_ano_server(
    stream: PacketStream, request_body: bytes, encryption: str
) -> None:
    # Server half of the ANO negotiation (#448). `request_body` is the client's
    # round-1 container (already read). Select a cipher per our stance; when one
    # is chosen, emit the DH exchange, take the client's public key, derive the
    # shared secret, and switch the stream to encrypted framing.
    from seerdb.common import ano
    from seerdb.common.ano_session import AnoChannel

    if encryption not in ('requested', 'required'):
        # Plaintext stance: the null-algorithm reply, session stays clear.
        stream.send_raw(encode_ano_null_reply(sdu=stream.sdu))
        return
    request = ano.decode_container(request_body)
    enc_id = _select_algorithm(
        ano.offered_algorithm_ids(request, ano.SERVICE_ENCRYPTION),
        _SERVER_ENC_PREF,
        ano.ENCRYPTION_ALGO_IDS,
    )
    if enc_id == 0:
        # The client offered nothing we implement. REQUIRED can't proceed;
        # REQUESTED falls back to plaintext.
        if encryption == 'required':
            raise InterfaceError('ANO: no mutually supported encryption algorithm')
        stream.send_raw(encode_ano_null_reply(sdu=stream.sdu))
        return
    int_id = _select_algorithm(
        ano.offered_algorithm_ids(request, ano.SERVICE_DATA_INTEGRITY),
        _SERVER_INT_PREF,
        ano.INTEGRITY_ALGO_IDS,
    )
    sdh = ano.server_dh_keypair()
    stream.write_packet(
        TNS_DATA, ano.encode_ano_response(enc_id, int_id, sdh.public_key)
    )
    round2 = stream.read_packet()
    if round2 is None:
        raise InterfaceError('client closed during ANO key exchange')
    (_type, r2_body) = round2
    client_pub = ano.client_public_key(ano.decode_container(r2_body))
    shared = sdh.derive(client_pub)
    stream.activate_ano(
        AnoChannel(enc_id, int_id, shared, ano.DH_SERVER_IV, ClientSide=False)
    )
    logger.debug(
        'handle_login (server): ANO active (enc=%d integrity=%d)', enc_id, int_id
    )


def _handle_token_login(
    stream: PacketStream, payload: bytes, token_public_key: bytes
) -> str:
    # Server half of token auth (#125): verify the OCI IAM request-header
    # signature (offline-checkable), then grant the session. The JWT itself is
    # validated by the real IAM service — the Mirror accepts it and labels the
    # session by its subject claim. Returns the username.
    from seerdb.common.token_auth import token_subject, verify_token_header

    token, header, signature = parse_token_auth(payload)
    if header is not None and signature is not None:
        if not verify_token_header(
            header.decode('utf-8'), signature.decode('utf-8'), token_public_key
        ):
            _deny_login(stream, 'token signature verification failed')
    stream.write_packet(TNS_DATA, encode_token_result())
    return token_subject(token.decode('utf-8')) or 'TOKEN_USER'


def _apply_new_password(
    backend: Backend, user: str, old_password: str, conn_key: bytes, cipher: bytes
) -> None:
    """Apply a password change the client sent along with its login (#826).

    Never raises. The login itself has already succeeded -- the proof was
    checked against the OLD password -- so a backend that cannot change
    passwords, or a change the server refuses, must not turn a good login into a
    failed one. The client learns the truth on its next connect, which is the
    same place a real server's refusal would show up.
    """
    change = getattr(backend, 'change_password', None)
    if change is None:
        logger.info('login carried a new password; backend cannot change it')
        return
    try:
        new_password = decrypt_password(conn_key, cipher).decode('utf-8')
    except Exception as exc:  # noqa: BLE001
        logger.info('login new password could not be decrypted: %s', exc)
        return
    try:
        # The OLD password is the account secret this login just authenticated
        # against, which the backend needs to drive the change (an upstream
        # ALTER USER ... REPLACE checks it).
        change(user, old_password, new_password)
    except Exception as exc:  # noqa: BLE001
        logger.info('login new password refused: %s', exc)
        return
    logger.info('password changed at login: %s', user)


def handle_login(
    stream: PacketStream,
    backend: Backend,
    *,
    encryption: str = 'accepted',
    token_public_key: bytes | None = None,
    field_version: int = FIELD_VERSION_11_2,
    min_field_version: int = FIELD_VERSION_10_2,
    tns_version: int | None = None,
    identity: 'ServerIdentity | None' = None,
) -> tuple[str, bool, bytes | None, int | None, int]:
    """Run the server side of the handshake + O5LOGON.

    Returns ``(username, is_sqlplus, conn_key, negotiated, session_id)`` — the
    second flag says whether
    the client speaks the classic sqlplus / thick-OCI (deadbeef) dialect, so the
    query loop can answer it in the right marshalling (#265); ``conn_key`` is the
    session key O5LOGON derived (``None`` for token auth), which the thin loop
    reuses to decrypt a later changepassword (#21/#486). ``negotiated`` is the
    field version the client settled on, and ``session_id`` the id the login
    reply reported (0 when the backend could not say), which keys the session's
    statistics (#1324).

    ``encryption`` is the Mirror's ANO stance (§33): ``'accepted'`` (default)
    stays plaintext unless the client forces it; ``'required'`` selects AES + a
    SHA-2 checksum and encrypts every DATA packet from PRO onward (#448).
    ``field_version`` is what the PRO reply advertises (default 11.2); a 12.1+
    thin client length-prefixes the username in its auth messages, so the same
    value drives the auth parsers.

    The O5LOGON secret comes from ``backend.authenticate(user)`` — auth lives
    with the backend, not the Mirror. Raises :class:`InterfaceError` on a
    protocol desync, an unknown/rejected user, or a client that gives up. A wrong
    password is not rejected here — the client's own ``validate()`` fails on the
    mismatched session key (mutual auth).
    """
    # --- Handshake (§2, §4.1/§4.2) ---
    # The release this session introduces itself as, in the auth result and (for
    # sqlplus) the banner. It follows the advertised field version unless the
    # backend declares its own identity — a backend may present a higher release
    # than its wire field version (e.g. report 12.1 to unlock the dialect's native
    # OFFSET/FETCH while keeping the 11.2 wire layout), since the client reads the
    # version only from this login banner, never the wire (#33).
    if identity is None:
        identity = server_identity(field_version)
    # The protocol version goes with the field version unless a caller pins it.
    if tns_version is None:
        tns_version = server_tns_version(field_version)
    connect = _expect(stream, TNS_CONNECT, 'CONNECT')
    # A descriptor over 230 bytes follows the CONNECT in a DATA packet of its
    # own; answering the bare CONNECT took that packet for the next handshake
    # step and the login stalled (#1769).
    if connect_data_follows(connect):
        connect += _expect(stream, TNS_DATA, 'connect data')
    request = parse_connect(connect)
    stream.send_raw(encode_accept(request, tns_version=tns_version))
    # Honour the SDU just negotiated in that ACCEPT. It was computed as
    # min(client, ours) and reported, but every later write still used the
    # LISTENER's own value, so a client that negotiated down was then sent
    # packets larger than the buffer it had sized from our own answer. seerdb's
    # client reads by the length header and tolerated it; the reference client
    # sizes a fixed buffer and the connection simply DIED -- DPY-4011, with
    # nothing in it to suggest the SDU (#826).
    stream.sdu = min(request.sdu, stream.sdu)
    # From protocol version 315 the post-ACCEPT DATA stream carries a 4-byte
    # packet length instead of the legacy 16-bit length + flags pair (§1.1). The
    # ACCEPT itself is still framed the legacy way — the switch takes effect for
    # everything after it — so flip the stream only once it has gone out.
    if negotiated_tns_version(request, tns_version) >= TNS_VERSION_MIN_LARGE_SDU:
        stream.large = True
    # End-of-response framing starts HERE, on the first DATA reply after the
    # ACCEPT that advertised it -- not after login, and not on the client's later
    # CCAP opt-in. A live 23ai sets data flags 0x2000 and a trailing 0x1d on its
    # very first DATA reply, the PRO answer, before the client has sent the DTY
    # that would carry the opt-in: the ACCEPT is the commitment. Turning it on
    # after login left the client waiting for a marker the handshake replies
    # never carried, and it hung before it could authenticate (#1059).
    if negotiated_tns_version(request, tns_version) >= TNS_VERSION_MIN_OOB_CHECK:
        stream.end_of_response = True
    # A modern thin client (seerdb/go-ora/oracledb) runs an ANO negotiation
    # before PRO now that our ACCEPT advertises ANO-capable (#437). Run the server
    # half (#448): select a cipher per our stance — or the null algorithm — and,
    # when a cipher is selected, run the DH exchange and switch the stream to
    # encrypted framing before reading the (now encrypted) PRO. The sqlplus/OCI
    # client's ANO uses a different version and is handled inline by the
    # `deadbeef` dialect path below, so it is left alone.
    first = _expect(stream, TNS_DATA, 'PRO')
    if is_ano_negotiation(first):
        _negotiate_ano_server(stream, first, encryption)
        first = _expect(stream, TNS_DATA, 'PRO')
    # A thin (oracledb/seerdb) client's first message is its PRO request, led by
    # TTI_PRO. sqlplus / thick OCI opens with one more round, an ANO negotiation
    # in a `deadbeef` container, and then sends the same PRO request and its own
    # form of the data-type round (#265, §4.1.1). Each reply below answers the
    # round it is named for.
    sqlplus = opens_with_oci_ano(first)
    if sqlplus:
        # sqlplus is served without end-of-response, whatever the ACCEPT said.
        # A live 23ai marks its replies to sqlplus only on the fast-auth path
        # (the reply to the bundle and after); the Mirror's OCI login is the
        # three-round one, and there sqlplus 23.26 refused a marked reply at
        # every step -- ORA-12699 on the first, then a break on each one after
        # -- and runs a whole session unmarked (#1822). Thin clients keep it:
        # they wait for the marker from the PRO answer on (#1059).
        stream.end_of_response = False
    if sqlplus:
        stream.send_raw(encode_ano_null_reply())  # its ANO round
    else:
        stream.send_raw(
            encode_pro_reply(
                field_version=field_version,
                txn_priority=_txn_priority_hooks(backend) is not None,
            )
        )
    # A thin client's DTY request, or sqlplus's PRO request.
    after_pro = _expect(stream, TNS_DATA, 'PRO' if sqlplus else 'DTY')
    # The client has already picked min(its own, what the PRO reply advertised)
    # and put the result in this packet's capability block, so the session's real
    # version is readable here rather than assumed (#816). None for the fast-auth
    # bundle, whose DTY does not arrive on its own, and for anything unparseable;
    # the caller then keeps its configured version, as before.
    negotiated = client_field_version(after_pro)
    # What this Mirror presents stays in force for the fields a server writes
    # by its own release, whatever the client negotiated (#1145).
    _ENCODE_SERVER_FIELD_VERSION.set(field_version)
    if negotiated is not None and negotiated != field_version:
        if negotiated < min_field_version:
            raise InterfaceError(
                f'client negotiated TTC field version {negotiated}, below the '
                f'{min_field_version} this Mirror serves (it presents '
                f'{field_version})'
            )
        # Adopt it here rather than after the handshake: the DTY reply and the
        # O5LOGON exchange that follow are themselves version-shaped, so a
        # client below the advertised version failed to authenticate at all
        # (ORA-01017) before it could reach a statement (#816).
        field_version = negotiated
    # Pin the codec to the session's version for the rest of the handshake. The
    # query loop does this per iteration, but login runs before it and builds
    # version-shaped bytes of its own -- the challenge's status OER carries an
    # extended error number and a ub8 rowcount from 12.1, and a SQL type and
    # checksum from 20.1. Left at the default 6, those fields are simply absent,
    # so a 12.1+ client reads past the end of the OER and waits for a
    # continuation that never comes (#829).
    _DECODE_FIELD_VERSION.set(field_version)
    _ENCODE_FIELD_VERSION.set(field_version)
    # 23ai fast-auth (§20): a client at field version >= 18 cannot use the legacy
    # three-message handshake (the server rejects it with ORA-03146), so after the
    # bare PRO it sends one FAST_AUTH packet bundling DTY + OSESSKEY. The DTY and
    # OSESSKEY replies then ride back together (below), not as separate rounds.
    fast_auth = after_pro[:1] == bytes([TNS_MSG_TYPE_FAST_AUTH])
    if fast_auth:
        offset = find_fast_auth_osesskey(after_pro, field_version)
        if offset < 0:
            raise InterfaceError('fast-auth bundle carried no OSESSKEY')
        osesskey = after_pro[offset:]
    else:
        # Legacy: answer the packet just read -- a thin client's DTY request, or
        # sqlplus's PRO request -- then, for sqlplus, its data-type round (a
        # `ttc=02` request, no type table) before OSESSKEY (#265).
        if sqlplus:
            stream.send_raw(encode_pro_reply(oci=True, field_version=field_version))
            capabilities = _expect(stream, TNS_DATA, 'DTY')
            stream.send_raw(
                encode_oci_dty_reply(
                    tz_file_version=client_sends_tz_file_version(capabilities)
                )
            )
            # sqlplus's data-type request carries the capability block that says
            # what the client reads.
            # Which LOB column form: the one with the LOB's length and chunk
            # size, if it offered CCAP_LOB_12C (#1287).
            lob_caps = client_compile_cap(capabilities, CCAP_LOB) or 0
            _ENCODE_OCI_LOB_12C.set(bool(lob_caps & CCAP_LOB_12C))
            # Which TIMESTAMP WITH TIME ZONE cell this sqlplus reads (#2018).
            _ENCODE_OCI_TSTZ_LOCAL.set(sqlplus_reads_local_tstz(capabilities))
            # Which release and banner its version call is answered with (#2024).
            _OCI_FULL_RELEASE.set(sqlplus_reads_full_release(capabilities))
            # And what version it speaks. sqlplus does not come down to what the
            # Mirror advertised, as a thin client does -- sqlplus 23.26 sends 27
            # -- but an OLDER one sends its own, lower, and must be served at
            # that: sqlplus 11.2 at a 12.1 Mirror cannot use the 12c-band login
            # and failed with ORA-28041 (#1291). A higher one keeps the Mirror's.
            spoken = sqlplus_field_version(
                capabilities, field_version, min_field_version
            )
            if spoken != field_version:
                field_version = negotiated = spoken
                _DECODE_FIELD_VERSION.set(field_version)
                _ENCODE_FIELD_VERSION.set(field_version)
        else:
            stream.send_raw(encode_dty_reply(field_version=field_version))
        osesskey = _expect_login_message(stream, 'OSESSKEY')

    # --- O5LOGON (§4) ---
    # The same mutual-auth crypto drives both dialects; only the wire marshalling
    # differs. The thin form carries each phase as an RPA payload
    # (write_packet); the deadbeef/OCI form (#265) exchanges full packets built
    # from captured 11g templates (send_raw), so sqlplus / thick OCI logs in too.
    # Token auth (#125): a thin client with an access token sends a single token
    # AUTH here instead of OSESSKEY. When the Mirror is configured to accept
    # tokens, verify the OCI IAM signature (offline-checkable) and grant the
    # session — there is no O5LOGON challenge, proof, or ConnKey.
    if token_public_key is not None and is_token_auth(osesskey):
        return (
            _handle_token_login(stream, osesskey, token_public_key),
            sqlplus,
            None,
            negotiated,
            0,
        )
    user = (
        parse_osesskey_oci(osesskey)
        if sqlplus
        else parse_osesskey(osesskey, field_version)
    ).decode('utf-8')
    # Hand the client's declared session identity to the backend BEFORE it
    # authenticates: that is where a passthrough opens its upstream connection,
    # and program / machine / terminal / osuser are login-time attributes there
    # too -- they cannot be set afterwards (#826). A backend without the hook, or
    # a client that declared nothing, simply skips this.
    if not sqlplus:
        identity_kvs = parse_client_identity(osesskey, field_version)
        set_identity = getattr(backend, 'set_client_identity', None)
        if identity_kvs and set_identity is not None:
            try:
                set_identity(identity_kvs)
            except Exception as exc:  # noqa: BLE001 - never fail a login over this
                logger.warning('backend refused the client identity: %s', exc)
    if lockout.is_locked(user):
        _deny_login(
            stream,
            f'locked: {user!r}',
            ora_code=ORA_ACCOUNT_LOCKED,
            message=f'ORA-{ORA_ACCOUNT_LOCKED:05d}: The account is locked.',
            sqlplus=sqlplus,
            call_sequence=osesskey[2] if sqlplus else 0,
        )
    secret = backend.authenticate(user)
    # A name that is no account's is challenged as an account's would be, with
    # a secret of its own that no password matches, and refused at the same
    # point with the same error, as Oracle refuses it: the answers tell no
    # account from no account (GHSA-742q-fjfr-w5x3).
    known = secret is not None
    if secret is None:
        secret = _decoy_secret(user)

    # The thin AUTH may omit AUTH_PASSWORD (bytes | None); the OCI AUTH always
    # carries it. Declare the wider type so both branches unpack cleanly.
    auth_password: bytes | None
    if sqlplus:
        # The OCI challenge template carries a 10-byte salt slot (thin uses 16).
        # Its shape follows the field version as the thin one does: 12.1+ gets the
        # PBKDF2 challenge, which a modern sqlplus insists on once the ACCEPT says
        # 12.1 or later (#1282); below that, the 11g one.
        # With it goes the 12c SHA-2 verifier, as a 12c-band server offers it
        # (captured from 18c); a modern sqlplus hangs up on the 11g one there.
        challenge = (
            make_challenge(
                secret.encode('utf-8'),
                field_version=field_version,
                verifier_type=VFR_12C_SHA2,
            )
            if field_version >= FIELD_VERSION_12_1
            else make_challenge(secret.encode('utf-8'), salt=token_bytes(10))
        )
        stream.send_raw(encode_challenge_oci(challenge))
        auth_body = _expect(stream, TNS_DATA, 'AUTH')
        _, client_sesskey, auth_password = parse_auth_response_oci(auth_body)
    else:
        # The thin challenge follows the session's field version: 12.1+ gets the
        # PBKDF2 shape and derivation, below that the 11g one (#829).
        challenge = make_challenge(secret.encode('utf-8'), field_version=field_version)
        # Fast-auth expects the challenge bundled with the PRO + DTY replies it
        # deferred; legacy sends the challenge on its own.
        if fast_auth:
            stream.write_packet(
                TNS_DATA,
                encode_fast_auth_reply(
                    encode_challenge(challenge),
                    field_version=field_version,
                    txn_priority=_txn_priority_hooks(backend) is not None,
                ),
            )
        else:
            stream.write_packet(TNS_DATA, encode_challenge(challenge))
        # A long AUTH spans packets at a small SDU (#1770): read it whole.
        whole = _complete_message(
            stream,
            _expect(stream, TNS_DATA, 'AUTH'),
            lambda body: check_auth_complete(body, field_version),
        )
        if whole is None:
            raise InterfaceError('the client never completed its AUTH')
        auth_body = whole
        _, client_sesskey, auth_password = parse_auth_response(auth_body, field_version)
        # A client may change the password AS IT CONNECTS (`newpassword=`); the
        # new one rides in this same AUTH rather than in a separate call (#826).
        new_password_cipher = parse_auth_new_password(auth_body, field_version)

    conn_key = derive_conn_key(challenge, client_sesskey)
    # Verify the client's password proof (AUTH_PASSWORD) against the account
    # secret — the server half of O5LOGON's mutual auth. Without it the Mirror
    # would serve any client that ignores the server proof it can't validate.
    if not known or not verify_password(
        conn_key, auth_password, secret.encode('utf-8')
    ):
        # Each failure in a row waits longer, and enough of them lock the
        # name (GHSA-742q-fjfr-w5x3).
        time.sleep(lockout.failed(user))
        _deny_login(
            stream,
            f'wrong password or no such user: {user!r}',
            sqlplus=sqlplus,
            call_sequence=auth_body[2] if sqlplus else 0,
        )
    lockout.succeeded(user)
    # The proof checked out, so a new password carried alongside it is a genuine
    # request from an authenticated user. Applying it here rather than ignoring
    # it is what makes `connect(newpassword=...)` mean anything: without this the
    # login succeeded, the password never changed, and the NEXT connect with the
    # new one was refused ORA-01017 -- a failure one step removed from its cause
    # (#826). A backend that cannot change passwords simply skips it.
    # Connect-time attributes that arrive ONLY in this AUTH -- the driver banner
    # and the edition. A backend that opens its own upstream session can use them
    # if it has deferred that connect until now; one that connected during
    # authenticate() cannot, and skips the hook. Either way the login stands
    # (#826).
    _open_backend_session(
        stream, backend, sqlplus, auth_body, field_version, request.service_name
    )

    # Application context the client declared at connect
    # (`connect(appcontext=[...])`). It arrives in this AUTH -- AFTER the backend
    # opened its upstream session during authenticate() -- so it is applied to
    # that open session rather than passed to the connect, which is where
    # DBMS_SESSION.SET_CONTEXT works anyway (#826).
    if not sqlplus:
        entries = parse_auth_app_context(auth_body, field_version)
        apply_ctx = getattr(backend, 'set_app_context', None)
        if entries and apply_ctx is not None:
            try:
                apply_ctx(entries)
            except Exception as exc:  # noqa: BLE001 - never fail a good login
                logger.info('application context refused: %s', exc)

    # The session settings the client asked for as it logged in -- from 12.1 the
    # time zone pinned to its own UTC offset. A real server runs the statement in
    # the new session before it answers, so SESSIONTIMEZONE reflects the client
    # from the first query. A backend without the hook keeps its own zone; a
    # refusal is logged, never a failed login.
    if not sqlplus:
        statement = parse_auth_alter_session(auth_body, field_version)
        alter_session = getattr(backend, 'alter_session', None)
        if statement and alter_session is not None:
            try:
                alter_session(statement)
            except Exception as exc:  # noqa: BLE001 - never fail a good login
                logger.info('login ALTER SESSION refused: %s', exc)
    if not sqlplus and new_password_cipher:
        _apply_new_password(backend, user, secret, conn_key, new_password_cipher)
    # The release the backend's session really runs on, where it can say (#2024).
    identity = _backend_identity(backend, identity)
    session_id = 0
    if sqlplus:
        stream.send_raw(
            encode_result_oci(conn_key, identity=identity, field_version=field_version)
        )
    else:
        # Report the session's REAL identity when the backend can say what it is.
        # A client reads session_id / serial_num / instance_name / db_name /
        # service_name only from this reply, never by querying, so a placeholder
        # here is wrong for the life of the connection (#826).
        info = _backend_session_info(backend)
        # The transaction priority the session starts at, reported where 23ai
        # reports it (#1779).
        reported = _backend_txn_priority(backend, field_version)
        stream.write_packet(
            TNS_DATA,
            encode_result(
                conn_key,
                version_no=identity.version_no,
                session_id=info.session_id,
                serial_num=info.serial_num or AUTH_SERIAL_NUM,
                instance_name=info.instance_name,
                db_name=info.db_name,
                db_domain=info.db_domain,
                # The service the client connected to, when the backend cannot
                # name one of its own (#1409).
                service_name=info.service_name or request.service_name,
                txn_priority=reported,
            ),
        )
        session_id = info.session_id
        hooks = _txn_priority_hooks(backend)
        if reported is not None and hooks is not None:
            stream.reply_prefix = _TxnPriorityReporter(hooks[0], reported)

    logger.info('login OK: %s', user)
    return user, sqlplus, conn_key, negotiated, session_id


def _inferred_directions(sql: str, count: int) -> tuple[int, ...]:
    # A block's bind directions when the backend cannot ask a server for them
    # (#1783), as plsql_bind_directions judges them conservatively; none at all
    # -- every bind IN OUT -- when it cannot judge. They matter beyond the
    # values: a client pipelining an executemany of a block with an IN OUT bind
    # re-executes it row by row and walks off its own bind rows, which 23ai
    # avoids by reporting a RETURNING's INTO target as OUT.
    directions = plsql_bind_directions(sql, count)
    if directions is None:
        return ()
    codes = {
        'IN': TNS_BIND_DIR_INPUT,
        'OUT': TNS_BIND_DIR_OUTPUT,
        'IN OUT': TNS_BIND_DIR_INPUT_OUTPUT,
    }
    return tuple(codes[d] for d in directions)


def _txn_priority_hooks(
    backend: Backend,
) -> tuple[Callable[[], str | None], Callable[[str], None]] | None:
    # A backend's transaction-priority hooks (#1779): `txn_priority()` reports
    # the session's priority, `set_txn_priority(value)` changes it ('' restores
    # the default). The Mirror advertises the feature only with both.
    get = getattr(backend, 'txn_priority', None)
    set_ = getattr(backend, 'set_txn_priority', None)
    return (get, set_) if callable(get) and callable(set_) else None


def _backend_txn_priority(backend: Backend, field_version: int) -> str | None:
    # The priority to report at login, or None when there is none to report: a
    # backend without the hooks, or a version below 23ai, which has no such thing.
    hooks = _txn_priority_hooks(backend)
    if hooks is None or field_version < FIELD_VERSION_23_1:
        return None
    try:
        return hooks[0]()
    except Exception as exc:  # noqa: BLE001 - never fail a good login
        logger.info('transaction priority not read: %s', exc)
        return None


class _TxnPriorityReporter:
    """The stream's reply prefix (#1779): a SYNC piggyback reporting the
    session's transaction priority whenever it differs from the last one
    reported -- an ALTER SESSION SET TXN_PRIORITY in the call being answered --
    and after every client change (:meth:`changed`), even to the same value, as
    23ai reports it: the client holds '' for a reset until the report comes."""

    def __init__(self, get: Callable[[], str | None], reported: str) -> None:
        self._get = get
        self._last: str | None = reported

    def changed(self) -> None:
        self._last = None

    def __call__(self) -> bytes:
        try:
            current = self._get()
        except Exception as exc:  # noqa: BLE001 - a reply must still go out
            logger.info('transaction priority not read: %s', exc)
            return b''
        if current is None or current == self._last:
            return b''
        self._last = current
        return encode_sync_piggyback([(TNS_KEYWORD_NUM_TXN_PRIORITY, current)])


def _backend_session_info(backend: Backend) -> SessionInfo:
    # What the backend says about its session, or an empty SessionInfo when it
    # cannot say. A backend that cannot report this is not a failure -- the reply
    # simply carries the placeholders it always did -- and neither is one that
    # raises trying: the login must not die over metadata.
    hook = getattr(backend, 'session_info', None)
    if hook is None:
        return SessionInfo()
    try:
        return hook()
    except Exception as exc:  # noqa: BLE001 - metadata must never fail a login
        logger.warning('backend could not report its session info: %s', exc)
        return SessionInfo()


def _login_failure_error(exc: Exception) -> dict:
    """The ORA code and message to report for a backend that could not open a
    session, when the credentials themselves were fine (#1006).

    An upstream driver's error already carries the server's own code -- a full
    database answers ORA-12516, a down one ORA-12541 -- and relaying it is what
    lets a client behind a passthrough Mirror see what a direct connection would
    have seen. Anything with no code of its own becomes ORA-01034: the server
    exists but has no session to give, which is true of every case that lands
    here."""
    code = getattr(exc, 'code', None)
    text = str(exc).strip()
    if isinstance(code, int) and code > 0 and text.startswith('ORA-'):
        return {'ora_code': code, 'message': text}
    return {
        'ora_code': ORA_ORACLE_NOT_AVAILABLE,
        'message': f'ORA-{ORA_ORACLE_NOT_AVAILABLE:05d}: the backend is not available',
    }


def _open_backend_session(
    stream: PacketStream,
    backend: Backend,
    sqlplus: bool,
    auth_body: bytes,
    field_version: int,
    service_name: str | None = None,
) -> None:
    """Let the backend open its session, now that the client's proof checked out.

    sqlplus opens one too. Its OCI AUTH is not read for the connect-time
    attributes, so it opens with none -- but it must open: a backend that
    connects upstream here (the passthrough) otherwise serves every sqlplus
    statement from no connection at all (#1289). A refusal fails the login.
    """
    connect_attrs = (
        {} if sqlplus else parse_auth_connect_attrs(auth_body, field_version)
    )
    # The service the client connected to, from its CONNECT descriptor: what a
    # session's USERENV SERVICE_NAME names, which a backend can only learn here
    # (#1409).
    if service_name:
        connect_attrs.setdefault('service_name', service_name)
    open_session = getattr(backend, 'open_session', None)
    if open_session is None:
        return
    # A sqlplus refusal names the call it refuses: the AUTH, `03 73 <seq>`.
    refused_call = auth_body[2] if sqlplus and len(auth_body) > 2 else 0
    try:
        open_session(connect_attrs)
    except BackendError as err:
        # The credentials verified; the BACKEND refused. Relay its own code, so
        # a client behind a passthrough sees what a direct connection would
        # have seen (#1006).
        _deny_login(
            stream,
            f'upstream session refused: {err.ora_message}',
            ora_code=err.ora_code,
            message=err.ora_message,
            sqlplus=sqlplus,
            call_sequence=refused_call,
        )
    except Exception as exc:  # noqa: BLE001
        _deny_login(
            stream,
            f'upstream session failed: {exc}',
            sqlplus=sqlplus,
            call_sequence=refused_call,
            **_login_failure_error(exc),
        )


# The lowest field version the Mirror serves sqlplus / thick OCI at: 10.2, as
# for a thin client (#814). sqlplus 10.2's type round, auth messages, execute,
# describe and DESCRIBE reply each have their own widths, which the OCI path
# follows by the session's version (#1764). An older sqlplus is refused.
_OCI_MIN_FIELD_VERSION = FIELD_VERSION_10_2


def sqlplus_reads_local_tstz(capabilities: bytes) -> bool:
    """Whether a sqlplus reads a TIMESTAMP WITH TIME ZONE cell as the wall clock
    with the 0x40 flag, from the capability block it sent (#2018).

    A live 11g sends that form to sqlplus 23.26 and the UTC form to sqlplus
    11.2, and the Mirror's pre-12c replies imitate 11g. Told apart here by the
    field version the client's own block names, 12.1 or later; the capability
    bit the server keys on is not pinned down. A block that cannot be read
    keeps the newer form."""
    spoken = client_field_version(capabilities)
    return spoken is None or spoken >= FIELD_VERSION_12_1


# Whether this sqlplus's version call is answered with the full release and
# banner_full, set per session at login (#2024).
_OCI_FULL_RELEASE: contextvars.ContextVar[bool] = contextvars.ContextVar(
    'oci_full_release', default=True
)


def sqlplus_reads_full_release(capabilities: bytes) -> bool:
    """Whether a sqlplus is told the server's full release and banner_full in
    its version call, from the capability block it sent (#2024).

    Measured against 18c, 21c and 23ai: sqlplus 23.26 is sent the full release
    (SHOW RELEASE 2326020000) and the two-line banner_full, sqlplus 11.2 the base
    release (2300000000) and the one-line banner. banner_full is 18c's, so the
    line is drawn at a client of 18.1 or later, by the field version its own
    block names; no client between 11.2 and 23.26 has been tried. A block that
    cannot be read keeps the newer form."""
    spoken = client_field_version(capabilities)
    return spoken is None or spoken >= FIELD_VERSION_18_1


def _backend_identity(backend: object, identity: ServerIdentity) -> ServerIdentity:
    # The release the backend's session runs on, or `identity` when it cannot
    # say. Asked after authenticate(), which opens a passthrough's upstream
    # session, so it is that server's own; metadata never fails a login.
    hook = getattr(backend, 'session_release', None)
    if hook is None:
        return identity
    try:
        return hook() or identity
    except Exception as exc:  # noqa: BLE001 - metadata must never fail a login
        logger.warning('backend could not report its release: %s', exc)
        return identity


def sqlplus_field_version(
    capabilities: bytes, field_version: int, min_field_version: int
) -> int:
    """The field version to serve a sqlplus / thick-OCI client at, from the
    capability block it sent (its DTY proper, the round after its TTI_PRO).

    sqlplus does not come down to what the Mirror advertised, as a thin client
    does -- sqlplus 23.26 sends 27 -- so a higher version keeps the Mirror's own.
    An older sqlplus sends its own, lower one, and is served at that: sqlplus
    11.2 at a 12.1 Mirror cannot use the 12c-band login (#1291). A block that
    cannot be read keeps the Mirror's version too.
    """
    spoken = client_field_version(capabilities)
    if spoken is None or spoken >= field_version:
        return field_version
    floor = max(min_field_version, _OCI_MIN_FIELD_VERSION)
    if spoken < floor:
        raise InterfaceError(
            f'sqlplus speaks TTC field version {spoken}, below the '
            f'{floor} this Mirror serves'
        )
    return spoken


# The key a name that is no account's gets its challenge's secret from, the
# same for that name on every attempt within the process.
_DECOY_KEY = token_bytes(32)


def _decoy_secret(user: str) -> str:
    return hmac.new(_DECOY_KEY, user.upper().encode('utf-8'), 'sha256').hexdigest()


def password_login(backend: Backend, user: str, password: str) -> None:
    """Log ``user`` in on ``backend`` with a plaintext ``password``, as
    :func:`handle_login` logs a TNS client in with its O5LOGON proof: a locked
    name is refused; an unknown one is checked against a decoy secret, so it is
    refused at the same point as a wrong password; each failure is delayed and
    counted toward the lock (GHSA-7xrq-88jc-3p3x); and a good login opens the
    backend's session, which in per-user mode makes it the user's own role
    (GHSA-382x-hhhq-35r3). The JSON query endpoint's login. Raises
    :class:`BackendError` with the ORA code a TNS client is refused with."""
    if lockout.is_locked(user):
        raise BackendError(
            'The account is locked.',
            ora_code=ORA_ACCOUNT_LOCKED,
        )
    secret = backend.authenticate(user)
    known = secret is not None
    if secret is None:
        secret = _decoy_secret(user)
    matches = hmac.compare_digest(secret.encode('utf-8'), password.encode('utf-8'))
    if not (known and matches):
        time.sleep(lockout.failed(user))
        raise BackendError(
            'invalid username/password; logon denied',
            ora_code=ORA_INVALID_USERNAME_PASSWORD,
        )
    lockout.succeeded(user)
    open_session = getattr(backend, 'open_session', None)
    if open_session is not None:
        open_session({})


def _deny_login(
    stream: PacketStream,
    reason: str,
    *,
    ora_code: int = ORA_INVALID_USERNAME_PASSWORD,
    message: str | None = None,
    sqlplus: bool = False,
    call_sequence: int = 0,
) -> NoReturn:
    # Reject a login the way Oracle does — an OER in place of the next auth
    # reply, which the client raises out of connect() — then drop the
    # connection. (Without this the client would connect() cleanly and fail
    # later.)
    #
    # The DEFAULT is ORA-01017, deliberately generic about user vs password the
    # way Oracle's own is. It must stay reserved for a credential that did not
    # verify. Sending it for anything else says the caller got their password
    # wrong when they did not: a full database (ORA-12516) reported that way
    # cost two separate investigations, because the one thing a client cannot do
    # with ORA-01017 is tell a bad password from a server that had no session to
    # give (#1006). Callers with a real reason pass it.
    text = message or (
        f'ORA-{ORA_INVALID_USERNAME_PASSWORD:05d}: '
        'invalid username/password; logon denied'
    )
    if sqlplus:
        # sqlplus reads a refusal in its own dialect, after the break / reset
        # marker exchange a live server opens it with. A thin OER is lost on it:
        # it saw only the connection close and reported ORA-03113 (#1290).
        stream.write_packet(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_BREAK]))
        stream.write_packet(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
        _await_reset_marker(stream)
        stream.write_packet(
            TNS_DATA,
            encode_login_refusal_oci(ora_code, text, call_sequence=call_sequence),
        )
    else:
        stream.write_packet(TNS_DATA, encode_error(ora_code, text))
    raise InterfaceError(f'authentication rejected — {reason}')


def _await_reset_marker(stream: PacketStream) -> None:
    # The client answers the server's break / reset with a reset of its own
    # before it reads what follows. Anything else it sends first is dropped.
    for _ in range(8):
        received = stream.read_packet()
        if received is None:
            return
        packet_type, body = received
        if packet_type == TNS_MARKER and body[-1:] == bytes([TNS_MARKER_TYPE_RESET]):
            return


class _IsolatedBackend:
    """Runs every backend call in a copy of the session's contextvars context.

    The codec keeps per-message state in context variables (the field version
    being decoded / encoded, the arraydmlrowcounts arming, ...), set by whichever
    side is currently coding a message in the thread. A backend that itself
    embeds a seerdb client — the passthrough relaying to a real Oracle — sets
    them to *its upstream's* field version on every call it makes, and left as
    is, that state would still be in the thread when the Mirror next decodes a
    client request or encodes a reply: in front of a 23ai upstream the Mirror
    decoded an 11g client's chunked LONG bind with the 12.2+ chunk framing and
    handed the backend a garbled value. Copying the context per call confines
    the backend's codec state to the call; the Mirror's own codec keeps running
    at the version it negotiated with the client.

    The five :class:`Backend` methods are delegated explicitly; the optional
    extensions the session probes with ``getattr`` (``execute_many``,
    ``change_password``, ...) resolve through ``__getattr__`` and are wrapped
    the same way, so a missing one still raises ``AttributeError`` as before.
    """

    def __init__(self, backend: Backend) -> None:
        self._backend = backend
        self.capabilities: frozenset[Capability] = getattr(
            backend, 'capabilities', frozenset()
        )

    def authenticate(self, username: str) -> str | None:
        return _isolated(self._backend.authenticate, username)

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        return _isolated(self._backend.execute, sql, binds)

    def commit(self) -> None:
        _isolated(self._backend.commit)

    def rollback(self) -> None:
        _isolated(self._backend.rollback)

    def close(self) -> None:
        _isolated(self._backend.close)

    def __getattr__(self, name: str) -> object:
        attr = getattr(self._backend, name)
        if callable(attr):
            return functools.partial(_isolated, attr)
        return attr


def _isolated(call: Callable[..., _T], *args: object, **kwargs: object) -> _T:
    return contextvars.copy_context().run(call, *args, **kwargs)


def _unreachable_call(body: bytes) -> str:
    """Name what stopped the dispatch, for the refusal message.

    Worth the specificity: "piggyback 152" points straight at
    ``TNS_FUNC_SET_SCHEMA`` and a missing handler, where a generic "bad message"
    would send a reader looking at the framing instead.
    """
    if len(body) >= 2 and body[0] == TTI_MSG_TYPE_PIGGYBACK:
        return f'piggyback {body[1]}'
    if not body:
        return 'an empty message'
    return f'message type {body[0]}'


def _backend_fault_error(exc: Exception) -> bytes:
    """The reply for an exception the backend let escape.

    A type the codec cannot represent is a **feature gap, not an internal
    fault**, and the difference costs a whole session. ORA-00600 is Oracle's
    internal-error code: clients treat it as fatal, so one unsupported bind tore
    the connection down and every later statement on it failed too -- 92 such
    gaps produced 114 dead-connection failures in one conformance run (#875).
    ORA-03115 is what every other unsupported path already answers (#832/#836):
    the statement fails, the session lives, and the next one runs.

    Anything that is not a NotSupportedError really is unexpected, and keeps
    ORA-00600 -- the point is to stop mislabelling gaps as crashes, not to stop
    reporting crashes.
    """
    if isinstance(exc, NotSupportedError):
        return encode_error(
            ORA_UNSUPPORTED_NETWORK_DATATYPE,
            f'ORA-{ORA_UNSUPPORTED_NETWORK_DATATYPE:05d}: unsupported network datatype or '
            f'representation ({exc})',
        )
    # Genuinely unexpected: report it as ORA-00600 rather than recurse. This
    # branch used to `return _backend_fault_error(exc)` -- an infinite self-call
    # that raised RecursionError and tore the connection down (DPY-4011), turning
    # every unexpected backend fault into a session-killing crash-loop instead of
    # a one-statement error the session survives.
    return encode_error(
        ORA_INTERNAL_ERROR, f'ORA-{ORA_INTERNAL_ERROR:05d}: backend error: {exc}'
    )


def _refuse_unhandled(stream: PacketStream, what: str) -> None:
    """Answer a call the Mirror cannot serve, instead of going quiet.

    Answering is not optional. The client has sent a call and is blocked reading
    its reply, so returning to the read loop leaves it waiting for something that
    never arrives -- for as long as it is willing to wait, which for an ordinary
    client is forever. A real server always answers, even when the answer is a
    refusal.

    The cost of not doing this was not one hung call but an unusable conformance
    run: every gap presented as an indefinite stall instead of a failure, so the
    suite could not reach the next test (#832, #836). ORA-03115 is the error a
    client already understands as "this server will not do that", and it leaves
    the session usable so the following statements still run.
    """
    logger.info('unhandled %s; refusing', what)
    stream.write_packet(
        TNS_DATA,
        encode_error(
            ORA_UNSUPPORTED_NETWORK_DATATYPE,
            f'ORA-{ORA_UNSUPPORTED_NETWORK_DATATYPE:05d}: unsupported network datatype or '
            f'representation ({what})',
        ),
    )


# What a server answers when a BFILE's DIRECTORY object or file is not there.
_ORA_BFILE_MISSING_TEXT = (
    f'ORA-{ORA_NONEXISTENT_FILE:05d}: '
    'non-existent directory or file for FILEOPEN operation'
)


# The OCI end-to-end tracing piggyback (func 135) modern sqlplus sends after
# login. Its own message prefix, unlike the OCCA / TTI_80SES wrappers that
# strip_oci_piggyback already unwraps (#825).
_OCI_PIGGYBACK_E2E = bytes([TTI_MSG_TYPE_PIGGYBACK, TNS_FUNC_SET_END_TO_END_ATTR])


def _answer_kod_oci(
    stream: PacketStream,
    backend: Backend,
    body: bytes,
    seq: '_OciSequence',
    user: str,
) -> None:
    """Answer an OCI object-type describe, ``TTI_KOD`` (PROTOCOL.md §40).

    Served: a type asked for by name, which the backend describes
    (``describe_type``), and a system type asked for by REF -- SYS.KOTTD, which a
    client asks for to learn how to read the descriptor it was just handed.
    Anything else is refused with ORA-03115, the session intact (#1411).
    """
    try:
        request = parse_kod_request(body)
    except InterfaceError:
        request = None
    if request is not None and (request.schema, request.name) == ('SYS', 'XMLTYPE'):
        # A system type, the same in every database: answered whatever the
        # backend, under the schema asked for, as a live server does (#2050).
        stream.write_packet(
            TNS_DATA,
            encode_kod_named_reply(
                schema='SYS',
                name='XMLTYPE',
                record=kod_xmltype_record(),
                sequence=seq.next(),
            ),
        )
        return
    describe_type = getattr(backend, 'describe_type', None)
    if request is not None and request.name is not None and describe_type:
        try:
            described = describe_type(request.name)
        except BackendError:
            described = None
        if described is not None:
            record = kod_type_record(
                oid=described.oid,
                schema=described.schema,
                name=described.name,
                kind=described.kind,
                tds=described.tds,
                null_tds=described.null_tds,
            )
            # The header names the type as asked for, under the connected user's
            # schema, as a live 11g answers it.
            stream.write_packet(
                TNS_DATA,
                encode_kod_named_reply(
                    schema=user.upper(),
                    name=request.name,
                    record=record,
                    sequence=seq.next(),
                ),
            )
            return
    if request is not None and request.ref is not None:
        system = kod_system_record(request.ref[5:21])
        if system is not None:
            stream.write_packet(
                TNS_DATA, encode_kod_reply([system], sequence=seq.next())
            )
            return
    _refuse_unhandled_oci(stream, f'OCI call {body[:2].hex()}', seq)


def _refuse_unhandled_oci(stream: PacketStream, what: str, seq: _OciSequence) -> None:
    """Refuse a thick/OCI call the Mirror cannot serve, keeping the session.

    The OCI counterpart of :func:`_refuse_unhandled`. The loop used to `return`
    here, which closes the connection: sqlplus renders that as ORA-03113 /
    ORA-03114 for every statement afterwards, indistinguishable from the server
    crashing, and one unimplemented call takes the whole session with it. An
    ORA-03115 in the dialect's own OER envelope leaves the connection intact.
    """
    logger.info('OCI: unhandled %s; refusing', what)
    stream.write_packet(
        TNS_DATA,
        encode_error_oci(
            ORA_UNSUPPORTED_NETWORK_DATATYPE,
            f'ORA-{ORA_UNSUPPORTED_NETWORK_DATATYPE:05d}: unsupported network datatype or '
            f'representation ({what})',
            sequence=seq.next(),
        ),
    )


@_in_own_context
def serve_session(
    stream: PacketStream,
    backend: Backend,
    *,
    encryption: str = 'accepted',
    token_public_key: bytes | None = None,
    field_version: int = FIELD_VERSION_11_2,
    min_field_version: int = FIELD_VERSION_10_2,
    tns_version: int | None = None,
) -> str:
    """Log a client in, then answer its queries until it disconnects.

    After :func:`handle_login`, each OALL8 execute is parsed, handed to
    ``backend.execute``, and answered with a describe + rows response — or, if
    the backend refuses (:class:`BackendError` / :class:`UnsupportedFeature`) or
    fails, with an ORA error that leaves the connection usable. A result set
    larger than the requested fetch count is returned in batches: the first on
    the execute, the rest on follow-up ``TTI_FETCH`` calls (:class:`_Cursors`
    holds the undelivered rows). A logoff (or EOF) ends the session and returns
    the authenticated username. ``encryption`` is the Mirror's ANO stance,
    forwarded to :func:`handle_login` (§33 / #448).

    The backend chooses the protocol version: if it declares ``field_version``
    (and optionally ``tns_version``), that is what the Mirror advertises, and the
    ``field_version`` argument here is only the fallback for a backend with no
    opinion. Read off the raw backend before it is wrapped.
    """
    declared_field_version = getattr(backend, 'field_version', None)
    if declared_field_version is not None:
        field_version = declared_field_version
    declared_tns_version = getattr(backend, 'tns_version', None)
    if declared_tns_version is not None:
        tns_version = declared_tns_version
    # A backend may present a server release independent of its wire field
    # version (read off the raw backend before it is wrapped).
    declared_identity = getattr(backend, 'server_identity', None)
    identity = declared_identity or server_identity(field_version)
    backend = _IsolatedBackend(backend)
    # A client has this long to log in, and may send only the small messages
    # a login needs until it has: a connection that stalls or floods before
    # authenticating is dropped (GHSA-5827-wqfh-x2v3).
    stream.settimeout(LOGIN_SECONDS)
    user, sqlplus, conn_key, negotiated, session_id = handle_login(
        stream,
        backend,
        encryption=encryption,
        token_public_key=token_public_key,
        field_version=field_version,
        min_field_version=min_field_version,
        tns_version=tns_version,
        identity=identity,
    )
    stream.settimeout(None)
    stream.allow_session_messages()
    identity = _backend_identity(backend, identity)
    advertised = field_version
    # Serve the session at the version the client actually negotiated, not the
    # one this Mirror advertises. A client above the advertised version comes
    # down to it and was already served; one below it used to be answered in the
    # advertised layout and failed on the first row, with an error naming
    # neither version (#816).
    if negotiated is not None and negotiated != field_version:
        logger.info(
            'serving field version %s (advertised %s)', negotiated, field_version
        )
        field_version = negotiated
    if sqlplus:
        return _serve_oci_session(
            stream, backend, user, conn_key, identity, field_version=field_version
        )
    stats.open_session(session_id)
    try:
        return _serve_thin_session(
            stream, backend, user, conn_key, session_id, field_version, advertised
        )
    finally:
        stats.close_session(session_id)


def _serve_thin_session(
    stream: PacketStream,
    backend: Backend,
    user: str,
    conn_key: bytes | None,
    session_id: int,
    field_version: int,
    advertised: int,
) -> str:
    # A logged-in thin client's calls, answered until its logoff or EOF; returns
    # the user. Every request it sends -- one call, however many packets carry it
    # -- is one round trip in the session's statistics (#1324), counted as it
    # arrives, before its reply goes out, so a reader never sees a reply whose
    # round trip is not yet counted.
    cursors = _Cursors()
    # LOB contents (wire bytes + is_clob) the current statement's rows carry, in
    # the order their locators went out; the thin client drains them with
    # TTI_LOBOPS reads (it reads each LOB whole, row-major) (#413).
    lobs: list[tuple[bytes, bool]] = []
    # The LOB a client is part-way through reading, kept across its several
    # TTI_LOBOPS passes (#903); None until the first read.
    current_lob: tuple[bytes, bool] | None = None
    # The LOB attributes embedded in the last object result's rows, on their own
    # persistent queue: an object type is populated after the describe, and that
    # runs get_type_shape queries that would reset the transient LOB queue before
    # the client ever reads them (#888). Reads route here by a distinct locator.
    object_lobs: list[tuple[bytes, bool]] = []
    current_object_lob: tuple[bytes, bool] | None = None
    temp_lobs = _TempLobs()
    # Every column LOB the Mirror emits is minted a unique locator and its content
    # remembered here, so a later object bind carrying that locator can be resolved
    # back to content (there is no live upstream LOB behind a Mirror locator). Set
    # on the ContextVar `_thin_column_value` reads while encoding rows (#888).
    lob_emit_log = LobEmitLog()
    _LOB_EMIT_LOG.set(lob_emit_log)
    # The thin reply path's OER sequence, advanced per message below (#842).
    oer_seq = 0
    while True:
        # The codec's per-message state defaults to 11g (and token auth leaves it
        # at 12.2); pin it to the field version this session negotiated so each
        # request is parsed and its reply built in that version's layouts. The
        # backend runs in a copied context, so its own client cannot disturb it.
        _DECODE_FIELD_VERSION.set(field_version)
        _ENCODE_FIELD_VERSION.set(field_version)
        _ENCODE_SERVER_FIELD_VERSION.set(advertised)
        # Advance the thin path's OER end-to-end sequence once per message, so a
        # session's replies carry a moving counter like a live server's instead
        # of repeating the value the captured statuses were decoded with (#842).
        # The thick/OCI loop has done this since it was written (_OciSequence);
        # this is the thin half. Captured from 23ai, consecutive replies differ
        # by one in exactly this field: 0x1816 then 0x1817.
        oer_seq = _next_reply_sequence(oer_seq)
        _ENCODE_OER_SEQ.set(oer_seq)
        received = stream.read_packet()
        if received is None:
            return user
        stats.add(session_id, stats.ROUND_TRIPS)
        packet_type, body = received
        if packet_type == TNS_MARKER:
            _answer_marker(stream, body)
            continue
        if packet_type != TNS_DATA:
            continue
        # A pipelined call is marked END_OF_REQUEST, and its reply must open with
        # the token the client put in its header (#1059). Read it before the
        # piggybacks are stripped: on the first call of a burst the header that
        # carries it is the PIPELINE_BEGIN piggyback's, which shares the call's
        # token. From 23.1 up the token rides right after the 3-byte header.
        stream.response_token = None
        if (
            stream.last_data_flags & TNS_DATA_FLAGS_END_OF_REQUEST
            and field_version >= FIELD_VERSION_23_1_EXT_1
            and len(body) > 3
        ):
            stream.response_token, _ = decode_ub4(body[3:])
        refused: list[BackendError] = []
        body = _skip_piggybacks(
            body, backend, temp_lobs, refused, stream.reply_prefix
        )  # CLOSE_CURSORS, …
        if refused and len(body) >= 2 and body[0] == TTI_FUN:
            # A piggyback the backend refused fails the call behind it, which a
            # real server then does not run (#1778).
            stream.write_packet(
                TNS_DATA, encode_error(refused[0].ora_code, refused[0].ora_message)
            )
            continue
        if len(body) < 2 or body[0] != TTI_FUN:
            # Piggyback processing could not reach a call. That is what happens
            # when the message leads with a piggyback the Mirror does not know:
            # _skip_piggybacks stops rather than guess its length (guessing would
            # desync the stream), so the call sitting behind it stays out of
            # reach. Leaving the message unparsed is right; dropping it without a
            # word is not -- the piggyback is only a PREFIX to a real call, and
            # the client is already blocked reading that call's reply (#836).
            _refuse_unhandled(stream, _unreachable_call(body))
            continue
        if body[1] == TNS_FUNC_PIPELINE_END:
            # Closes the burst. A live 23ai answers it with a bare status and
            # nothing else -- `09 01 01 00`, then the end-of-response marker --
            # and the client reads that one reply and discards it (#1059).
            stream.write_packet(TNS_DATA, bytes([TTI_STA, 1, 1, 0]))
            continue
        if body[1] == TTI_ALL8:
            # A cached-cursor re-execute (cursor set, no SQL) omits the OACs; hand
            # parse_exec the bind types the Mirror remembered for that cursor so
            # its RXD decodes (#80/#486).
            peek_cursor, peek_has_query = peek_exec_cursor(body)
            cached = bool(peek_cursor) and not peek_has_query
            cached_types = cursors.dml_bind_types(peek_cursor) if cached else None
            # A cached re-execute carries no statement, and whether the cursor
            # stands for a PL/SQL block decides where its wide binds sit in the
            # row -- in place for a block, last for anything else. Only the
            # Mirror knows, from what it parked for that id (#1064).
            cached_plsql = cached and is_plsql(cursors.dml_sql(peek_cursor) or '')
            max_size = max_string_size(_SERVER_RUNTIME_CAPS)
            completed = _complete_message(
                stream,
                body,
                lambda b: parse_exec(
                    b,
                    bind_types=cached_types,
                    max_string_size=max_size,
                    cached_plsql=cached_plsql,
                ),
            )
            if completed is None:  # answered already: it never completes
                continue
            body = completed
            request = _mark_ltz_binds(
                _resolve_temp_lob_binds(
                    parse_exec(
                        body,
                        bind_types=cached_types,
                        max_string_size=max_size,
                        cached_plsql=cached_plsql,
                    ),
                    temp_lobs,
                )
            )
            _attach_object_bind_lobs(request, lob_emit_log, temp_lobs)
            if request.scrollable:
                lobs = _answer_scroll(stream, backend, request, cursors)
            else:
                lobs = _answer_query(stream, backend, request, cursors, object_lobs)
        elif body[1] == TTI_LOBOPS:
            completed = _complete_message(stream, body, parse_lobops_request)
            if completed is None:
                continue
            body = completed
            lobs, current_lob, current_object_lob = _answer_lobops(
                stream,
                body,
                lobs,
                temp_lobs,
                current_lob,
                object_lobs,
                current_object_lob,
                lob_emit_log,
                backend,
            )
        elif body[1] == TNS_FUNC_REEXECUTE_AND_FETCH:
            # The rows carry no OACs -- the cursor's opening execute declared the
            # types -- so look those up from the header first, then read the
            # whole message with them, rows included, which can span packets
            # like any other bind data (#873, the same shape as #854's func 4).
            peeked = parse_reexecute(body).cursor
            cached_types = cursors.bind_types(peeked)
            cached_dirs = cursors.bind_directions(peeked)
            cached_plsql = is_plsql(cursors.dml_sql(peeked) or '')
            max_size = max_string_size(_SERVER_RUNTIME_CAPS)
            completed = _complete_message(
                stream,
                body,
                lambda b: parse_reexecute(
                    b,
                    bind_types=cached_types,
                    max_string_size=max_size,
                    bind_directions=cached_dirs,
                    cached_plsql=cached_plsql,
                ),
            )
            if completed is None:
                continue
            lobs = _answer_reexecute(
                stream,
                backend,
                parse_reexecute(
                    completed,
                    bind_types=cached_types,
                    max_string_size=max_size,
                    bind_directions=cached_dirs,
                    cached_plsql=cached_plsql,
                ),
                cursors,
            )
        elif body[1] == TNS_FUNC_REEXECUTE:
            # The plain re-execute (#854): the cursor's statement again with
            # fresh bind rows. The rows carry no OACs, so the types the cursor
            # was opened with are looked up first (the header names the cursor)
            # and then the whole message -- rows included, which can span
            # packets like any other bind data -- is read with them.
            completed = _complete_message(stream, body, parse_reexecute)
            if completed is None:
                continue
            body = completed
            peeked = parse_reexecute(body).cursor
            cached_types = cursors.bind_types(peeked)
            cached_dirs = cursors.bind_directions(peeked)
            cached_plsql = is_plsql(cursors.dml_sql(peeked) or '')
            max_size = max_string_size(_SERVER_RUNTIME_CAPS)
            completed = _complete_message(
                stream,
                body,
                lambda b: parse_reexecute(
                    b,
                    bind_types=cached_types,
                    max_string_size=max_size,
                    bind_directions=cached_dirs,
                    cached_plsql=cached_plsql,
                ),
            )
            if completed is None:
                continue
            body = completed
            reexecute = parse_reexecute(
                body,
                bind_types=cached_types,
                max_string_size=max_size,
                bind_directions=cached_dirs,
                cached_plsql=cached_plsql,
            )
            lobs = _answer_reexecute_binds(
                stream, backend, reexecute, cursors, temp_lobs
            )
        elif body[1] == TTI_FETCH:
            lobs += _answer_fetch(stream, parse_fetch(body), cursors)
        elif body[1] == TTI_COMMIT:
            _answer_txn(stream, backend, commit=True)
        elif body[1] == TTI_ROLLBACK:
            _answer_txn(stream, backend, commit=False)
        elif body[1] == TNS_FUNC_TPC_TXN_SWITCH:
            _answer_sessionless_switch(stream, backend, body, field_version)
        elif body[1] == TTI_PING:
            # A keepalive / pool health check (conn.ping()). RELAY it when the
            # backend can be pinged: answering locally makes the Mirror report
            # healthy while the database behind it is gone, which is the one
            # thing a health check exists to catch. A backend without the hook
            # keeps the local acknowledgement, and a refusal comes back as the
            # ORA error the client can act on (#826).
            ping = getattr(backend, 'ping', None)
            if ping is None:
                stream.write_packet(TNS_DATA, encode_status(0))
            else:
                try:
                    ping()
                except BackendError as err:
                    stream.write_packet(
                        TNS_DATA, encode_error(err.ora_code, err.ora_message)
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning('backend ping failed: %s', exc)
                    stream.write_packet(TNS_DATA, _backend_fault_error(exc))
                else:
                    stream.write_packet(TNS_DATA, encode_status(0))
        elif body[1] == TTI_AUTH:
            # A post-login TTI_AUTH is a password change (#21/#486): it reuses the
            # login session key, so decrypt the old / new passwords with conn_key
            # and drive the backend's password change.
            _answer_changepassword(stream, backend, body, conn_key, user, field_version)
        elif body[1] == TTI_LOGOFF:
            # A clean logoff commits what the session left open, as Oracle's does
            # (#1429). Then acknowledge it before ending the session.
            # python-oracledb 26.0.0 reads this reply and hits DPY-4011 on a
            # silent close; older clients closed without reading, so returning
            # silently used to do (#888).
            _commit_at_logoff(backend)
            stream.write_packet(TNS_DATA, encode_logoff_status_thin())
            return user
        else:
            # A TTC function the Mirror does not implement (#832).
            _refuse_unhandled(stream, f'TTC function {body[1]}')


@_in_own_context
def _serve_oci_session(
    stream: PacketStream,
    backend: Backend,
    user: str,
    conn_key: bytes | None = None,
    identity: ServerIdentity = IDENTITY_11_2,
    *,
    field_version: int = FIELD_VERSION_11_2,
) -> str:
    # The sqlplus / thick-OCI query loop (#265), built up one message shape at a
    # time. So far: the post-login version call (-> banner), the OCI execute
    # (-> describe + rows + status), and the follow-up fetch (-> end-of-fetch
    # terminator). The PL/SQL / setup-query calls sqlplus sends before the prompt
    # (piggyback-wrapped) are follow-ups; an unhandled call ends the session
    # cleanly rather than desyncing.
    # Rows a multi-row execute delivered only the first of; the rest wait here
    # for the follow-up fetch (the OCI analogue of the thin _Cursors).
    parked: tuple[list[ColumnMeta], list[tuple]] | None = None
    # The REF CURSORs blocks opened, by the id their OUT value named; sqlplus
    # re-executes each by that id to fetch its rows (#2014).
    ref_cursors = _OciRefCursors()
    # The values blocks assigned to sqlplus CLOB / BLOB variables, by the id the
    # locator each went out as names (#2015).
    lob_vars = _OciLobVars()
    # The last PL/SQL block that handed OUT values back, for sqlplus to run
    # again by cursor id with new IN values (#2041).
    blocks = _OciBlocks()
    # LOB contents (wire bytes + is_clob + national) the current statement's rows
    # carry, in the order their locators went out; sqlplus drains them with
    # TTI_LOBOPS reads, slicing the current LOB per each read's offset/amount (#405).
    lobs: list[tuple[bytes, bool, bool]] = []
    current_lob: tuple[bytes, bool, bool] | None = None
    # The same LOBs by the slot (column index) their locators carry, each column's
    # in row order, and the one each slot is reading: sqlplus reads a row's LOBs
    # interleaved and names each by its locator (#1430).
    slot_lobs: dict[int, list[tuple[bytes, bool, bool]]] = {}
    slot_current: dict[int, tuple[bytes, bool, bool]] = {}
    # The live per-session OER end-to-end sequence counter (§36); every OER-bearing
    # reply below draws its next value so the field advances like a real server's.
    seq = _OciSequence()
    # sqlplus lays out its requests and reads the replies in the layout of the
    # field version its handshake advertised, which from 12.1 is not the
    # session's own (#1282).
    oci_version = oci_field_version(field_version)
    while True:
        # Pinned per message, as the thin loop does: the backend runs in a copied
        # context, so nothing it does can move it.
        _DECODE_FIELD_VERSION.set(oci_version)
        _ENCODE_FIELD_VERSION.set(oci_version)
        received = stream.read_packet()
        if received is None:
            return user
        packet_type, body = received
        if packet_type == TNS_MARKER:
            # A break / reset marker: sqlplus cancelling a call (Ctrl-C), or
            # resynchronising after a reply it could not line up (#2036).
            _answer_marker_oci(stream, body, seq)
            continue
        if packet_type != TNS_DATA:
            continue
        if is_version_call_oci(body):
            # What sqlplus prints after "Connected to:" — the release this
            # session introduced itself as (naming the Mirror itself is a
            # separate discussion).
            banner, release = identity.version_reply(_OCI_FULL_RELEASE.get())
            stream.write_packet(TNS_DATA, encode_version_banner_oci(banner, release))
            continue
        # Every statement past the first arrives wrapped in an OCCA close-cursors
        # piggyback; unwrap it to reach the execute.
        body = strip_oci_piggyback(body)
        if body[:2] == _OCI_PIGGYBACK_E2E:
            # Modern sqlplus sends its end-to-end tracing attributes as a
            # piggyback right after login, and it is a PREFIX: a real call
            # follows in the same message. The thin loop walks its piggybacks;
            # this one never did, so the message fell through to the refusal at
            # the bottom -- which used to CLOSE the session, so sqlplus reported
            # ORA-03114 for every statement afterwards (#825).
            #
            # The walker checks its own landing and returns None rather than
            # guess, so a shape it does not know becomes a clean refusal instead
            # of a desynchronised stream.
            behind = strip_oci_e2e_piggyback(
                body,
                OCI_E2E_VALUES_OFF_12C
                if oci_version >= FIELD_VERSION_12_1
                else OCI_E2E_VALUES_OFF,
            )
            if behind is not None:
                body = behind
        if len(body) >= 3 and body[0] == TTI_FUN:
            # The OER's offset-49 field echoes the sequence of the CALL being
            # answered — this byte, after the piggybacks in front of it have been
            # stripped, never a piggyback's own (§36.1). Publish it for the
            # encoders the same way the thin path publishes its counter (#842).
            _ENCODE_OCI_CALL_SEQ.set(body[2])
        if len(body) >= 2 and body[0] == TTI_FUN:
            if body[1] == TTI_ALL8:
                streamed = (
                    ref_cursors.take_streamed(body) if is_reexecute_oci(body) else None
                )
                if streamed is not None:
                    # A REF CURSOR whose rows carry a LOB or LONG: they stream as
                    # a query's do, one row per call and each LOB's content over
                    # TTI_LOBOPS, from this re-execute on (#2033).
                    parked = streamed
                    (lobs, slot_lobs) = _oci_lob_queues(*streamed)
                    current_lob = None
                    slot_current = {}
                elif is_reexecute_oci(body) and ref_cursors.serve_reexecute(
                    stream, body, seq
                ):
                    continue
                if parked is not None and is_reexecute_oci(body):
                    # sqlplus re-executes the described cursor to pull LONG rows
                    # once its streaming define is set up. LONG rows stream one per
                    # reply: deliver the first now, re-park the rest for the
                    # follow-up fetches (#407). A LOB result with no rows answers
                    # the end of fetch, ORA-01403, as a live 11g does (#1428).
                    if not parked[1]:
                        stream.write_packet(
                            TNS_DATA, encode_fetch_terminator_oci(seq.next())
                        )
                        parked = None
                        continue
                    parked = _serve_oci_long_row(stream, parked, seq, reexecute=True)
                    continue
                parked, lobs, slot_lobs = _answer_query_oci(
                    stream, backend, body, seq, ref_cursors, lob_vars, blocks
                )
                current_lob = None
                slot_current = {}
                continue
            if body[1] == TTI_EXEC:
                # A block run again by cursor id, with new IN values: sqlplus
                # fetching SERVEROUTPUT's lines after the first batch (#2041).
                _answer_exec_by_cursor_oci(
                    stream, backend, body, seq, blocks, ref_cursors, lob_vars
                )
                continue
            if body[1] == TTI_PING:
                # sqlplus pings after a cancel, to see the session is alive
                # (#2036). Relayed when the backend can be pinged, as on the
                # thin path, and acknowledged as a live 18c does.
                _answer_ping_oci(stream, backend, seq)
                continue
            if body[1] == TTI_KOD:
                # An object-type describe (§40). sqlplus asks for a collection
                # type by name, then for SYS.KOTTD by REF to learn how to read
                # the answer; anything not served yet is refused as before.
                _answer_kod_oci(stream, backend, body, seq, user)
                continue
            if body[1] == TTI_DESCRIBE:
                # sqlplus `DESCRIBE <object>` — reply with the object's column
                # metadata (a dedicated describe message, not a query describe).
                _answer_describe_oci(stream, backend, body, seq, user)
                continue
            if body[1] == TTI_LOBOPS:
                # sqlplus reads a LOB column's content, looping over the LOB in
                # SET LONGCHUNKSIZE-sized slices. A read that starts at offset 1 is
                # the first read of the next LOB (row-major); later offsets continue
                # the current one. Serve exactly the slice requested so the client's
                # read loop terminates when a read returns less than it asked (#405).
                offset, amount = parse_lobops_read(body)
                slot = parse_lobops_slot(body)
                # A row LOB's locator names its slot; a variable's names none.
                variable = (
                    lob_vars.content(parse_lobops_locator(body))
                    if slot is None
                    else None
                )
                if variable is not None:
                    # A CLOB / BLOB variable's locator: sqlplus 10.2 reads the
                    # value this way to print it, where later ones select it
                    # (#2123).
                    (content, is_clob, national) = variable
                    slot = None
                elif slot is not None and slot in slot_lobs:
                    # The locator names its column: a read from the start takes
                    # that column's next LOB, a later one continues it, whatever
                    # was read in between (#1430).
                    if offset <= 1 or slot not in slot_current:
                        queue = slot_lobs[slot]
                        slot_current[slot] = (
                            queue.pop(0) if queue else (b'', True, False)
                        )
                    content, is_clob, national = slot_current[slot]
                else:
                    if offset <= 1 or current_lob is None:
                        current_lob = lobs.pop(0) if lobs else (b'', True, False)
                    content, is_clob, national = current_lob
                    slot = None
                unit = 2 if is_clob else 1  # bytes per counted unit (CLOB is UTF-16)
                total = len(content) // unit
                start = offset - 1
                count = max(0, min(amount, total - start))
                chunk = content[start * unit : (start + count) * unit]
                stream.write_packet(
                    TNS_DATA,
                    encode_lob_read_response_oci(
                        chunk,
                        count,
                        len(content),
                        is_clob=is_clob,
                        national=national,
                        slot=slot,
                        sequence=seq.next(),
                    ),
                )
                continue
            if body[1] == TTI_FETCH:
                if ref_cursors.serve_fetch(stream, body, seq):
                    pass
                elif parked is not None and _is_long_result(parked[0]):
                    # A LONG result drains one row per fetch (each with "more"),
                    # the last fetch drawing the 1403 terminator below (#407).
                    parked = _serve_oci_long_row(stream, parked, seq, reexecute=False)
                elif parked is not None and _is_lob_result(parked[0]):
                    # A LOB result streams ONE row per fetch (sqlplus reads that
                    # row's LOB locators over TTI_LOBOPS before fetching the next —
                    # delivering every row at once desyncs it once a row carries
                    # more than one LOB column). Each row ends with a non-terminator
                    # status; the final empty fetch draws the 1403 terminator. The
                    # row-major LOB queue drains in the order the locators go out (#405).
                    columns, rows = parked
                    stream.write_packet(
                        TNS_DATA,
                        encode_lob_fetch_rows_oci(
                            columns, rows[:1], sequence=seq.next()
                        ),
                    )
                    parked = (columns, rows[1:]) if len(rows) > 1 else None
                elif parked is not None:
                    # Never more rows than the fetch asked for: sqlplus sized its
                    # buffer to that count, and overrunning it crashes the client.
                    # The rest stays parked for the next fetch (#1284).
                    columns, rows = parked
                    count = max(1, parse_fetch_oci(body))
                    stream.write_packet(
                        TNS_DATA,
                        encode_fetch_batch_oci(
                            columns,
                            rows[:count],
                            sequence=seq.next(),
                            more=len(rows) > count,
                        ),
                    )
                    parked = (columns, rows[count:]) if len(rows) > count else None
                else:
                    # Nothing parked — the execute already delivered every row;
                    # the fetch just wants the end-of-fetch terminator (ORA-01403).
                    stream.write_packet(
                        TNS_DATA, encode_fetch_terminator_oci(seq.next())
                    )
                continue
            if body[1] in (TTI_COMMIT, TTI_ROLLBACK):
                _answer_txn_oci(stream, backend, seq, commit=body[1] == TTI_COMMIT)
                continue
            if body[1] == TTI_AUTH:
                # A post-login TTI_AUTH is a password change: sqlplus's PASSWORD
                # command (OCIPasswordChange), unwrapped from its TTI_80SES
                # piggyback above. It carries AUTH_PASSWORD (current) and
                # AUTH_NEWPASSWORD (new), the same pair as the thin changepassword.
                _answer_changepassword_oci(stream, backend, body, conn_key, user, seq)
                continue
            if body[1] == TTI_LOGOFF:
                # sqlplus's EXIT (EXITCOMMIT ON, the default) sends no COMMIT,
                # only this logoff, and relies on the server committing at it
                # (#1429).
                _commit_at_logoff(backend)
                stream.write_packet(TNS_DATA, encode_logoff_status_oci())
                return user
        # An OCI call the Mirror cannot serve is REFUSED, not answered by
        # hanging up. Closing the connection is what a client reads as
        # ORA-03113/03114 -- indistinguishable from a crash, and it takes the
        # whole session down for one unimplemented call. The thin loop was
        # taught this in #832/#836; the OCI loop keeps the session usable the
        # same way, so the statements after the gap still run.
        _refuse_unhandled_oci(stream, f'OCI call {body[:2].hex()}', seq)
        continue


_OCI_DML_KEYWORDS = ('INSERT', 'UPDATE', 'DELETE', 'MERGE')

# Transaction-control verbs typed as SQL statements (sqlplus sends a bare
# COMMIT / ROLLBACK through OCIStmtExecute, not OCITransCommit / -Rollback), so
# they reach the execute path rather than the TTI_COMMIT / TTI_ROLLBACK
# piggyback. Their V$SQL command types (captured live from 11g) make sqlplus
# render "Commit complete." / "Rollback complete." from the same no-row
# command-complete frame the DDL statuses use.
_OCI_TXN_COMMAND_TYPE = {'COMMIT': OCI_CMD_COMMIT, 'ROLLBACK': OCI_CMD_ROLLBACK}


def _is_long_result(columns: list[ColumnMeta]) -> bool:
    # A result that carries a LONG / LONG RAW column, which sqlplus streams one
    # row per reply over the re-execute / fetch flow (#407).
    return any(col.data_type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW) for col in columns)


def _defers_inline_rows(columns: list[ColumnMeta]) -> bool:
    # True when a result's columns force the rows out of the execute reply and
    # into a follow-up fetch. A real server does this for any LOB-class column,
    # and the reference client requires it: on reading such a describe it sets
    # "requires define / no prefetch" and stops expecting inline rows (#887).
    return any(
        col.data_type
        in (
            TNS_TYPE_CLOB,
            TNS_TYPE_BLOB,
            TNS_TYPE_JSON,
            TNS_TYPE_VECTOR,
            # A BFILE is LOB-class too: 23ai answers a `select BFILENAME(...)`
            # with a describe and no row, and the reference client reads
            # anything that follows as the next message (#1102).
            TNS_TYPE_BFILE,
        )
        and col.inline_long_csfrm is None
        for col in columns
    )


def _as_described(columns: list[ColumnMeta]) -> list[ColumnMeta]:
    # The columns as the describe puts them on the wire. inline_long_csfrm is a
    # decision about how this reply serves a value, not part of the metadata the
    # client is told, so two describes that differ only in it are the same.
    return [replace(col, inline_long_csfrm=None) for col in columns]


def _is_lob_result(columns: list[ColumnMeta]) -> bool:
    # A result that carries a CLOB / BLOB column, whose locator row is fetched with
    # a non-terminator status and whose content follows over TTI_LOBOPS (#405).
    return any(
        col.data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB)
        and col.inline_long_csfrm is None
        for col in columns
    )


def _serve_oci_long_row(
    stream: PacketStream,
    parked: tuple[list[ColumnMeta], list[tuple]],
    seq: '_OciSequence',
    *,
    reexecute: bool,
) -> tuple[list[ColumnMeta], list[tuple]] | None:
    # Deliver one LONG row and re-park the remainder (LONG streams a row per
    # reply). The re-execute reply ends with the execute row-status; a fetch reply
    # ends with the "more rows" OER status. Either way the drained state (None)
    # makes the next fetch return the 1403 terminator (#407).
    columns, rows = parked
    if reexecute:
        reply = encode_reexec_row_oci(
            columns, rows[:1], sequence=seq.next(), more=len(rows) > 1
        )
    else:
        reply = encode_long_fetch_row_oci(columns, rows[0], sequence=seq.next())
    stream.write_packet(TNS_DATA, reply)
    return (columns, rows[1:]) if len(rows) > 1 else None


def _commit_at_logoff(backend: Backend) -> None:
    # Oracle commits a session's open transaction when the client logs off
    # cleanly, and rolls it back only when the connection drops. Measured with
    # sqlplus 23.26 against a live 11g: `INSERT ...; exit` sends the INSERT and
    # then TTI_LOGOFF, no COMMIT, and the row is there afterwards. A client that
    # wants a rollback sends one first; python-oracledb and seerdb do when the
    # server says a transaction is open (#889). A commit that fails here cannot
    # be reported -- the client is leaving -- so it is logged and undone.
    try:
        backend.commit()
    except BackendError as exc:
        logger.warning('commit at logoff failed, rolling back: %s', exc)
        try:
            backend.rollback()
        except BackendError:
            pass  # the session is ending either way


def _mark_transaction(sql: str, autocommit: bool) -> None:
    """Record whether this statement left an uncommitted transaction open (#889).

    The OER's call_status flag word carries TXN_IN_PROGRESS, and a client reads
    it to decide whether releasing the connection to a pool (or closing it) owes
    a rollback. python-oracledb skips its rollback when the bit is clear, so a
    Mirror that never sets it leaves the DML holding its TM lock until the
    session dies — which is what blocked later statements with ORA-00054 across
    unrelated features.

    DML and PL/SQL open a transaction; autocommit closes it again straight away,
    as does an explicit commit / rollback. DDL commits implicitly. A query
    changes nothing, so it leaves the flag alone.
    """
    if autocommit:
        _ENCODE_TXN_IN_PROGRESS.set(False)
    elif is_reusable_dml(sql) or is_plsql(sql):
        _ENCODE_TXN_IN_PROGRESS.set(True)


# An ALTER SESSION that sets an NLS parameter (#2020).
_ALTER_SESSION_NLS = re.compile(r'\s*ALTER\s+SESSION\s+SET\s+NLS_', re.IGNORECASE)


def _oci_nls_pairs(backend: Backend) -> list[tuple[int, str]]:
    """The session's NLS parameters, for the reply to an NLS ALTER SESSION (#2020).

    A live server sends them all after an ALTER SESSION SET NLS_..., and sqlplus
    formats its DATE, TIMESTAMP and NUMBER columns by them -- it is sent a DATE's
    seven bytes and renders them itself. Without them `alter session set
    nls_date_format = 'YYYY-MM-DD'` changed nothing sqlplus printed. Read from
    the backend's NLS_SESSION_PARAMETERS, so a parameter another one implies (a
    territory's date format) is reported as the backend has it; nothing when the
    backend cannot say."""
    try:
        rows = backend.execute(
            'SELECT parameter, value FROM nls_session_parameters'
        ).rows
    except BackendError as err:
        logger.debug('NLS parameters for sqlplus: %s', err)
        return []
    values = {
        str(name).upper(): '' if value is None else str(value) for (name, value) in rows
    }
    # The character set is the database's, which the session view leaves out;
    # the Mirror speaks AL32UTF8.
    values.setdefault('NLS_CHARACTERSET', 'AL32UTF8')
    # In OCI_NLS_KEYWORDS's order, a live server's: a territory first, then
    # the formats that override what it implies.
    pairs = [
        (keyword, values[name])
        for (name, keyword) in OCI_NLS_KEYWORDS.items()
        if name in values
    ]
    return pairs


def _oci_no_row_status(
    sql: str,
    rowcount: int,
    seq: '_OciSequence',
    *,
    compilation_warning: bool = False,
    session_pairs: list[tuple[int, str]] | None = None,
) -> bytes:
    # Pick the OCI success reply for a statement that returned no columns, so
    # sqlplus renders the right message (#348 / #349): DML carries the affected row
    # count ("N rows created/updated/deleted"); DDL / session verbs (CREATE / DROP
    # / ALTER / TRUNCATE / GRANT / … on TABLE / INDEX / VIEW / SEQUENCE / …) carry a
    # V$SQL command type sqlplus turns into "Table created.", "Index dropped.",
    # "Table truncated.", "Grant succeeded.", etc.; anything else (PL/SQL blocks,
    # session bootstrap) gets the generic "PL/SQL procedure successfully completed".
    keyword = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ''
    if keyword in _OCI_DML_KEYWORDS:
        return encode_dml_status_oci(keyword, rowcount, sequence=seq.next())
    if keyword in _OCI_TXN_COMMAND_TYPE:
        return encode_ddl_status_oci(
            _OCI_TXN_COMMAND_TYPE[keyword], sequence=seq.next()
        )
    command_type = ddl_command_type(sql)
    if command_type is not None:
        # A CREATE whose PL/SQL object compiled with errors succeeds with a
        # warning, as on the thin path (#2013).
        return encode_ddl_status_oci(
            command_type,
            sequence=seq.next(),
            compilation_warning=compilation_warning,
            session_pairs=session_pairs,
        )
    return encode_status_oci(seq.next())


def _answer_query_oci(
    stream: PacketStream,
    backend: Backend,
    body: bytes,
    seq: '_OciSequence',
    ref_cursors: '_OciRefCursors | None' = None,
    lob_vars: '_OciLobVars | None' = None,
    blocks: '_OciBlocks | None' = None,
) -> tuple[
    tuple[list[ColumnMeta], list[tuple]] | None,
    list[tuple[bytes, bool, bool]],
    dict[int, list[tuple[bytes, bool, bool]]],
]:
    # Answer one sqlplus / thick-OCI execute. sqlplus fires a chain of setup
    # statements (PL/SQL blocks, PRODUCT_PRIVS selects) before the user's query;
    # each needs an acceptable reply or sqlplus never reaches the prompt. Returns
    # ``(parked, lobs, slot_lobs)``: the rows held for a follow-up fetch (or
    # None), the LOB contents the result's rows carry for the follow-up
    # TTI_LOBOPS reads, and the same by the slot each locator names (#1430).
    try:
        request = parse_exec_oci(body)
    except InterfaceError as err:
        # A shape the parser cannot read yet -- a re-execute by cursor id with no
        # SQL and nothing parked, or binds it does not know. It used to be
        # answered as a success without running anything, so the client took the
        # call as done: sqlplus kept re-executing DBMS_OUTPUT.GET_LINES, whose
        # line count never came back, until the session died (#1515). Refused,
        # the client sees the error and the session carries on. sqlplus's own
        # startup and everyday statements never reach here.
        _refuse_unhandled_oci(stream, f'OALL8: {err}', seq)
        return None, [], {}
    if lob_vars is None:
        lob_vars = _OciLobVars()
    if any(isinstance(value, TempLobRef) for value in request.binds):
        # A LOB variable's locator becomes the value it names (#2015).
        binds = [lob_vars.resolve(value) for value in request.binds]
        if not is_plsql(request.sql) and any(
            isinstance(value, TempLobRef) for value in binds
        ):
            # sqlplus's own buffer for a variable that holds nothing yet: a
            # block assigns it, anything else is refused as a live server does.
            stream.write_packet(
                TNS_DATA,
                encode_error_oci(
                    ORA_INVALID_LOB_LOCATOR,
                    'ORA-22275: invalid LOB locator specified',
                    sequence=seq.next(),
                ),
            )
            return None, [], {}
        binds = [None if isinstance(value, TempLobRef) else value for value in binds]
        request = replace(request, binds=binds, bind_rows=[binds])
    try:
        # A PL/SQL block (sqlplus VARIABLE / EXEC :v := …) hands its binds over as
        # BindVar so the backend registers them OUT-capable and returns the assigned
        # values — the wire carries no direction, so every bind goes over
        # OUT-capable (the same path the thin exec uses). A plain statement's binds
        # pass through unchanged, except a NULL, which goes over with its declared
        # type (#699).
        result = backend.execute(request.sql, _bind_vars(request))
        if request.autocommit:
            # SET AUTOCOMMIT ON: the client asked for a commit on success and
            # sends none of its own, then prints "Commit complete." (#2011). A
            # commit that fails is the statement's error, as on a live server.
            backend.commit()
    except BackendError as err:
        # A statement the backend can't run comes back as its ORA error, as a
        # live server's does, and the session continues. Only a SELECT's error
        # used to be relayed; every other failure was answered with a success
        # status, so sqlplus reported a failed CREATE as having worked (#1288).
        # sqlplus's startup is unaffected: its session comes up as before over
        # Mirror-over-PG and the SQLite example alike.
        stream.write_packet(
            TNS_DATA,
            encode_error_oci(
                err.ora_code,
                str(err),
                sequence=seq.next(),
                error_pos=_oci_error_pos(err),
            ),
        )
        return None, [], {}
    if result.out_binds:
        # A PL/SQL block that assigned OUT binds (sqlplus VARIABLE / EXEC) — return
        # the values so the client reads them back into its bound buffers.
        if blocks is not None:
            blocks.remember(request)
        if ref_cursors is None:
            ref_cursors = _OciRefCursors()
        stream.write_packet(
            TNS_DATA,
            encode_out_bind_response_oci(
                [
                    lob_vars.keep(ref_cursors.park(value), t)
                    for value, (t, _cs, _size, _toid) in zip(
                        result.out_binds, request.bind_types
                    )
                ],
                sequence=seq.next(),
                # Each bind's type -- an object / collection goes back in its
                # own framing -- and whether it came in with a value, which the
                # reply reports as its direction (#1411).
                types=[(t, toid) for (t, _cs, _size, toid) in request.bind_types]
                or None,
                # NCHAR / NVARCHAR2 text goes back as UTF-16BE (#2239).
                forms=[form for (_t, form, _size, _toid) in request.bind_types] or None,
                # A REFCURSOR comes in with a value, its zero cursor id, and a
                # live server reports it IN OUT (#2014).
                inputs=[
                    value is not None or t == TNS_TYPE_REFCURSOR
                    for value, (t, _cs, _size, _toid) in zip(
                        request.binds, request.bind_types
                    )
                ]
                or None,
            ),
        )
        return None, [], {}
    if not result.columns:
        stream.write_packet(
            TNS_DATA,
            _oci_no_row_status(
                request.sql,
                result.rowcount,
                seq,
                compilation_warning=result.compilation_warning,
                session_pairs=(
                    _oci_nls_pairs(backend)
                    if _ALTER_SESSION_NLS.match(request.sql)
                    else None
                ),
            ),
        )
        return None, [], {}
    rows = list(result.rows)
    (lobs, slot_lobs) = _oci_lob_queues(result.columns, rows)
    has_long = any(
        col.data_type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW) for col in result.columns
    )
    has_lob = any(
        col.data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB) for col in result.columns
    )
    # An XMLTYPE column too: a live server answers its execute with the
    # describe alone, as for a LOB, and sends the row on the fetch, after
    # sqlplus has described the type (#2050).
    if has_lob or any(oci_is_xmltype(col) for col in result.columns):
        # A LOB result: sqlplus sets up its LOB define from the describe, then
        # fetches the locator rows. The LOB describe reply has its own shape (a
        # 33-byte tail + a LOB execute status, not the ordinary inline-row DCB
        # tail) — matching it is what makes sqlplus accept the locator row rather
        # than break (#405). An empty result gets it too, as from a live 11g, and
        # is parked empty: the ordinary no-row reply read to sqlplus as a row
        # holding an uninitialized LOB (#1428).
        stream.write_packet(
            TNS_DATA, encode_lob_describe_oci(result.columns, sequence=seq.next())
        )
        return (result.columns, rows), lobs, slot_lobs
    if has_long and rows:
        # sqlplus fetches a LONG / LONG RAW row separately from the describe — it
        # sets up the streaming define buffer on the describe, then issues a fetch
        # — so deliver no row inline (an inline LONG row segfaults it): describe +
        # "more rows", then the row in the follow-up fetch (#407).
        stream.write_packet(
            TNS_DATA,
            encode_query_response_oci(
                result.columns, [], sequence=seq.next(), more=True
            ),
        )
        return (result.columns, rows), lobs, slot_lobs
    if len(rows) <= 1:
        # 0 or 1 row fits in the execute reply; sqlplus won't fetch further.
        stream.write_packet(
            TNS_DATA,
            encode_query_response_oci(result.columns, rows, sequence=seq.next()),
        )
        return None, lobs, slot_lobs
    # Deliver the first row now and park the rest — sqlplus reads the "more rows"
    # status and issues a fetch for the remainder.
    stream.write_packet(
        TNS_DATA,
        encode_query_response_oci(
            result.columns, rows[:1], sequence=seq.next(), more=True
        ),
    )
    return (result.columns, rows[1:]), lobs, slot_lobs


def _oci_lob_queues(
    columns: list[ColumnMeta], rows: list[tuple]
) -> tuple[list[tuple[bytes, bool, bool]], dict[int, list[tuple[bytes, bool, bool]]]]:
    # Every LOB cell across the whole result queues its content now, row-major, so
    # the follow-up TTI_LOBOPS reads drain it in the order the locators went out.
    # This is the OCI path, which reads JSON and VECTOR that way too -- unlike the
    # thin path, which carries their images in the row (#826/#887).
    lobs = oci_lob_reads(columns, rows)
    slot_lobs: dict[int, list[tuple[bytes, bool, bool]]] = {}
    for row in rows:
        for slot, cell in oci_lob_row_cells(columns, row).items():
            slot_lobs.setdefault(slot, []).append(cell)
    return (lobs, slot_lobs)


def _answer_describe_oci(
    stream: PacketStream, backend: Backend, body: bytes, seq: '_OciSequence', user: str
) -> None:
    # Serve a sqlplus `DESCRIBE <object>`: decode the object name, get its columns
    # from the backend with an empty-result SELECT (the describe carries only the
    # column metadata, no rows), and reply with the OCI describe message. A bad
    # name / missing object comes back as an ORA error so the session continues.
    try:
        name = parse_describe_oci(body)
        result = backend.execute(f'SELECT * FROM {name} WHERE 1 = 0')
    except (InterfaceError, BackendError) as err:
        code = getattr(err, 'ora_code', None) or 942
        stream.write_packet(
            TNS_DATA,
            encode_error_oci(
                code,
                str(err),
                sequence=seq.next(),
                error_pos=_oci_error_pos(err),
            ),
        )
        return
    reply = encode_describe_reply_oci(
        result.columns,
        schema=user.upper().encode('utf-8'),
        table=name.upper().encode('utf-8'),
    )
    stream.write_packet(TNS_DATA, reply)


def _apply_schema(backend: Backend | None, schema: bytes | list) -> None:
    """Apply a SET_SCHEMA piggyback to the backend (#837).

    Run as the statement rather than through a new backend method: every backend
    already handles ``ALTER SESSION SET CURRENT_SCHEMA``, because a client that
    cannot use the piggyback fast-path writes exactly that. The PostgreSQL
    example translates it to a ``search_path`` change (#759) and the passthrough
    forwards it upstream, so both work with no backend change at all.

    A failure is logged and swallowed on purpose. The piggyback rides on somebody
    else's call, and that call still deserves its answer -- turning a refused
    schema change into a failure of the statement it happened to travel with
    would be its own bug.
    """
    # decode_dalc reports both an empty and a null value as [], which is the
    # one case with nothing to apply.
    if backend is None or not isinstance(schema, bytes) or not schema:
        return
    name = schema.decode('utf-8', 'replace')
    try:
        backend.execute(f'ALTER SESSION SET CURRENT_SCHEMA = {name}')
    except Exception as exc:  # noqa: BLE001 - see the docstring
        logger.info('set current_schema %r refused by the backend: %s', name, exc)


def _answer_ping_oci(
    stream: PacketStream, backend: Backend, seq: '_OciSequence'
) -> None:
    ping = getattr(backend, 'ping', None)
    if ping is not None:
        try:
            ping()
        except BackendError as err:
            stream.write_packet(
                TNS_DATA, encode_error_oci(err.ora_code, str(err), sequence=seq.next())
            )
            return
    stream.write_packet(TNS_DATA, encode_ping_status_oci(seq.next()))


def _answer_marker_oci(stream: PacketStream, body: bytes, seq: '_OciSequence') -> None:
    """Close a sqlplus break episode as a live 18c does (#2036).

    Ctrl-C on a sqlplus 23.26 against a live 18c: the break goes out of band,
    then the client sends a reset marker, and the server answers with ONE reset
    and the ORA-01013 OER, after which the session carries on. Through the
    Mirror the interrupt arrives in band (a `03` marker) ahead of the reset.

    This loop used to answer every marker with a reset. The client's own reset
    then drew another, which it answered in turn, without end: the session hung
    and the log filled. Now an interrupt or break is answered with one reset
    and the client's reset is waited for, whatever it sends before it dropped,
    as the thin loop does (:func:`_answer_marker`); a lone reset gets the one
    reset. Either way the cancel's OER follows."""
    marker_type = body[2] if len(body) >= 3 else 0
    stream.write_packet(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
    if marker_type != TNS_MARKER_TYPE_RESET:
        _await_reset_marker(stream)
    stream.write_packet(
        TNS_DATA,
        encode_error_oci(
            ORA_USER_REQUESTED_CANCEL,
            # The text a live 18c sends sqlplus; the encoder adds the code.
            'user requested cancel of current operation',
            sequence=seq.next(),
            # A live 18c reports no position, so sqlplus puts its caret at 0.
            error_pos=0,
        ),
    )


def _answer_marker(stream: PacketStream, body: bytes) -> None:
    """Answer a break episode the way a real server does (#844).

    ``connection.cancel()`` does not interrupt anything the moment it is called.
    Without out-of-band support it cannot reach the server while the client is
    waiting on a reply, so it defers the break and sends it in-band once that
    reply arrives. Measured through the Mirror: the call was sent at 1.40s, its
    reply went out at 4.41s after a three-second sleep, and only THEN did the
    client send its markers. So there is never anything in flight to abandon by
    the time a marker arrives, and no need to try.

    What the client does need is the rest of the exchange, captured from 23ai:

        client -> MARKER 01 00 03   interrupt
        client -> MARKER 01 00 02   reset
        server -> MARKER 01 00 02   reset
        server -> DATA   OER        ORA-01013

    The thin loop used to drop every marker into its "not DATA, ignore it"
    branch, so the client waited forever. #836 audited that branch and spared it
    on the grounds that a marker needs no reply; that was wrong, and the OCI loop
    in this file had already learned it. A break is answered with a reset, and the
    client's own reset closes the episode with the cancel it asked for.
    """
    marker_type = body[2] if len(body) >= 3 else 0
    if marker_type != TNS_MARKER_TYPE_RESET:
        # An interrupt or break opens it: answer with a single reset, then wait
        # for the client's, dropping whatever it sent before it -- the request it
        # queued behind the interrupt gets the cancel as its answer, as a live
        # 26ai answers it (#1346). Answering that request in between left its
        # reply ahead of the cancel, one call out of step, and under encryption
        # sent with keys the client had already re-derived.
        stream.write_packet(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
        _await_reset_marker(stream)
    # The client's reset ends the episode: report the cancellation, which is what
    # it is now waiting to read. With encryption on, both sides re-derive their
    # integrity keystreams here -- the client did as it sent that reset -- so this
    # side must before the reply (#1346).
    stream.rederive_ano()
    stream.write_packet(
        TNS_DATA,
        encode_error(
            ORA_USER_REQUESTED_CANCEL,
            # The text a live 23ai sends, capitalised and full-stopped.
            f'ORA-{ORA_USER_REQUESTED_CANCEL:05d}: User requested cancel of current operation.',
        ),
    )


# How long to wait for a packet that continues a message already being parsed
# (#868). A genuine continuation is already in flight -- the client wrote the
# whole message in one call, so it arrives within milliseconds on any network
# the Mirror is reachable over -- which makes two seconds about a thousandfold
# margin. It is deliberately not larger: this timeout is paid in full by every
# request that can never be parsed, and at ten seconds a suite run spends more
# time waiting for messages that will never arrive than it does testing (the
# reference client's 16 boolean tests alone took 83 seconds of it).
_CONTINUATION_TIMEOUT = 2.0


def _complete_message(
    stream: PacketStream, body: bytes, parse: Callable[[bytes], object]
) -> bytes | None:
    """Return ``body`` grown until ``parse`` no longer reports it truncated (#848).

    A TTC message is a byte stream; TNS packets are only its transport, and a
    large one -- an OALL8 with sizeable inline binds, a LOB WRITE -- spans several
    DATA packets. python-oracledb sends those continuation packets with no MORE
    flag, so ``read_packet`` hands back only the first, and parsing it reads off
    the end. The primitives now say so by raising ``Truncated`` (#849) instead of
    returning short data, which is what lets this loop tell "read more" from
    "done".

    ``parse`` must be pure and free of side effects up to the point it raises --
    it is the request parser, called for its completeness check and then again by
    the handler on the returned body. That is the whole reason parse is separated
    from act here: a backend call must not run on half a message and then re-run
    when the rest arrives.

    A continuation packet is raw stream bytes with no TTC framing of its own, so
    its body appends directly after the first packet's (whose piggybacks were
    already stripped).

    Returns ``None`` when the message never completes, having already answered
    the client -- the caller drops the message and reads the next one.

    **The wait is bounded, and that is the point** (#868). ``Truncated`` means
    "the parser ran off the end", which a message cut by the transport and a
    decode fault inside a *complete* message produce alike: a NULL BOOLEAN bind
    made decode_dalc read the 0xFD escape marker as a length of 253 and ask for
    bytes that were never sent (#869). Waiting forever for them hung the session
    while the client blocked on its reply -- the silent hang #832/#836 removed,
    coming back through a different door, and one such wedge stalls an entire
    suite run. A real continuation is already in flight (the client wrote the
    whole message in one go), so a short wait separates the two cases, and a
    message that does not complete is refused like any other request the Mirror
    cannot serve. The invariant is that the Mirror never blocks indefinitely on
    a request it has begun parsing.
    """
    while True:
        try:
            parse(body)
            return body
        except Truncated as truncated:
            try:
                received = stream.read_packet(within=_CONTINUATION_TIMEOUT)
            except TimeoutError:
                _refuse_unhandled(stream, f'unparsable request ({truncated})')
                return None
            if received is None:
                raise InterfaceError('client closed mid-message') from None
            cont_type, cont_body = received
            if cont_type != TNS_DATA:
                raise InterfaceError(
                    f'expected a continuation DATA packet, got type {cont_type}'
                ) from None
            body = body + cont_body
        except InterfaceError:
            raise
        except Exception as exc:  # noqa: BLE001 - a parse fault must not desync
            # Reaching here is always a bug in a request parser: a message cut
            # by the transport says so with Truncated, and so should every other
            # shape of input the parser cannot walk. But a parse fault must not
            # KILL the session -- the Mirror's contract is that it never
            # desyncs, and an unhandled exception here took the whole connection
            # down with it (DPY-4011 on a ~1400-bind PL/SQL block, #1000). Log
            # loudly, answer the way any unservable call is answered, and let
            # the client carry on.
            logger.warning('request parse failed: %s', exc, exc_info=True)
            _refuse_unhandled(stream, f'unparsable request ({exc})')
            return None


def _skip_piggybacks(
    body: bytes,
    backend: Backend | None = None,
    temp_lobs: _TempLobs | None = None,
    refused: list[BackendError] | None = None,
    reporter: object = None,
) -> bytes:
    # A call can be preceded by piggybacks — CLOSE_CURSORS (105), which a client
    # sends to free the cursors it drained on the previous fetch, and, from 12.1
    # up, the end-to-end tracing attributes (135) and the request-boundary
    # session state (176). Each is walked by its own layout (a piggyback carries
    # no length) and the trailing function is served. The Mirror keeps no cursor
    # or request state, so those two are simply skipped; the tracing attributes
    # are handed to the backend (its optional set_end_to_end), so a session's
    # module / action / client identifier reach the database behind the Mirror
    # the way they would a real server; the close-temp-LOBs piggyback (96) drops
    # the named buffers from `temp_lobs`. An unknown piggyback is left in place,
    # so the caller ignores the message rather than mis-parsing it. An error the
    # backend raises applying an application context (#1778) goes in `refused`,
    # for the caller to fail the call with.
    while len(body) >= 3 and body[0] == TTI_MSG_TYPE_PIGGYBACK:
        func = body[1]
        rest = body[3:]  # skip the piggyback token, function code, sequence
        if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_23_1_EXT_1:
            _, rest = decode_ub4(rest)  # the fv24 ub8 token
        if func == TTI_OCCA:  # CLOSE_CURSORS
            rest = skip_close_cursors_piggyback(body)
        elif func == TNS_FUNC_SET_END_TO_END_ATTR:
            attrs, rest = _parse_end_to_end_piggyback(rest)
            apply = getattr(backend, 'set_end_to_end', None) if backend else None
            if apply is not None and attrs:
                apply(attrs)
        elif func == TNS_FUNC_SET_SCHEMA:
            # `connection.current_schema = x` (#837). A client does not send a
            # statement for this -- it holds the value and rides it out as a
            # piggyback on its next call, so the Mirror has to both consume the
            # bytes and apply the change, or the call behind it is unreachable.
            #
            # Layout read off a live 23ai, varying the name to separate the
            # fields: a constant flag byte, the length as a ub4, then the name as
            # a DALC that repeats it. Two length fields look redundant and are,
            # but both scale -- a 299-character name sends `02 01 2b` and then a
            # chunked (0xFE) DALC -- so neither can be assumed single-byte.
            rest = rest[1:]  # the constant flag
            _, rest = decode_ub4(rest)  # declared length, restated by the DALC
            schema, rest = decode_dalc(rest)
            _apply_schema(backend, schema)
        elif func == TNS_FUNC_SESSION_STATE:
            _, rest = decode_ub4(rest)  # the requested state (ignored)
        elif func == TNS_FUNC_ALTER_SESSION:
            # `connection.transaction_priority = x` (#1779): key-value pairs, of
            # which TXN_PRIORITY is the one a client sends; an empty value (pair
            # flag 1) restores the default. A refused value fails the call.
            pairs, rest = _parse_alter_session_piggyback(rest)
            hooks = _txn_priority_hooks(backend) if backend else None
            for key, value in pairs:
                if hooks is None or key.upper() != 'TXN_PRIORITY':
                    continue
                try:
                    hooks[1](value)
                except BackendError as err:
                    if refused is not None:
                        refused.append(err)
                else:
                    if isinstance(reporter, _TxnPriorityReporter):
                        reporter.changed()
        elif func == TNS_FUNC_APP_CONTEXT:
            # set_app_context() / clear_app_context() (#1778): one namespace per
            # piggyback, applied before the call; every one in the message is,
            # as 23ai applies a good namespace beside a refused one.
            namespace, values, rest = _parse_app_context_piggyback(rest)
            apply_ctx = getattr(backend, 'apply_app_context', None) if backend else None
            if apply_ctx is not None:
                try:
                    apply_ctx(namespace, values)
                except BackendError as err:
                    if refused is not None:
                        refused.append(err)
        elif func == TTI_LOBOPS:
            # Close-temp-LOBs (#852): a FREE_TEMP over an array of locators that
            # a client rides out once the temp LOBs it created have gone out of
            # scope -- on the call after any temp-LOB bind, in practice, so the
            # second large LOB insert of a session was the one that broke. The
            # counterpart of the FREE_TEMP call in _answer_lobops; a locator
            # the Mirror never saw written is simply not there to drop.
            freed, rest = parse_free_temp_lobs_piggyback(rest)
            if temp_lobs is not None:
                for locator in freed:
                    temp_lobs.free(locator)
        elif func == TNS_FUNC_PIPELINE_BEGIN:
            # Opens a pipelined burst (#1059). Layout after the common header
            # (encode_pipeline_begin): an sb4 0, a zero byte, then the error
            # mode. It shares the first call's token, which the caller has
            # already taken from the header for the reply. The Mirror answers
            # every call regardless of mode -- the reference client runs its
            # bursts in CONTINUE_ON_ERROR and enforces abort itself -- so the
            # mode is read past rather than acted on.
            _, rest = decode_ub4(rest)  # reserved sb4 0
            rest = rest[2:]  # a zero byte, then the pipeline mode
        else:
            break
        body = rest
    return body


def _parse_app_context_piggyback(
    rest: bytes,
) -> tuple[str, dict[str, str] | None, bytes]:
    # The func-154 body (the inverse of the client's encode_app_context_
    # piggyback, docs/PROTOCOL.md §41): pointer, namespace length, pointer,
    # entry count, flags, a zero byte from field version 12.1, the namespace,
    # then per entry its key and value (each with two lengths) and a ub4.
    # Returns the namespace, its values (None for a clear) and the rest.
    rest = rest[1:]  # pointer
    _, rest = decode_ub4(rest)  # namespace length, restated below
    rest = rest[1:]  # entries pointer
    count, rest = decode_ub4(rest)
    flags, rest = decode_ub4(rest)
    if _DECODE_FIELD_VERSION.get() >= FIELD_VERSION_12_1:
        rest = rest[1:]
    raw, rest = decode_dalc(rest)
    namespace = bytes(raw).decode('utf-8')
    values: dict[str, str] = {}
    for _ in range(count):
        key, rest = _two_lengths(rest)
        value, rest = _two_lengths(rest)
        _, rest = decode_ub4(rest)
        values[key] = value
    return namespace, None if flags & TNS_APP_CONTEXT_FLAG_CLEAR else values, rest


def _parse_alter_session_piggyback(
    rest: bytes,
) -> tuple[list[tuple[str, str]], bytes]:
    # The func-204 body (the inverse of the client's encode_alter_session_
    # piggyback, docs/PROTOCOL.md §42): flags, pointer, pair count, then per
    # pair its key and value (each with two lengths) and a flag.
    _, rest = decode_ub4(rest)  # flags
    rest = rest[1:]  # pointer
    count, rest = decode_ub4(rest)
    pairs: list[tuple[str, str]] = []
    for _ in range(count):
        key, rest = _two_lengths(rest)
        value, rest = _two_lengths(rest)
        _, rest = decode_ub4(rest)  # 1 for an empty value
        pairs.append((key, value))
    return pairs, rest


def _two_lengths(rest: bytes) -> tuple[str, bytes]:
    # A value written with two lengths: a ub4 count, then (when non-zero) the
    # bytes with their own length.
    length, rest = decode_ub4(rest)
    if not length:
        return '', rest
    raw, rest = decode_dalc(rest)
    return bytes(raw).decode('utf-8'), rest


def _parse_end_to_end_piggyback(rest: bytes) -> tuple[dict[str, str | None], bytes]:
    # The SET_END_TO_END_ATTR body (the inverse of the client's
    # encode_end_to_end_piggyback): two pointer bytes and the flags word, then
    # one (modified, length) header per attribute — client_identifier, module,
    # action, client_info, dbop — with the unsupported fixed slots between them,
    # then a length-prefixed value for every attribute that was set. Returns the
    # modified attributes (a cleared one — modified flag, no value — as None)
    # and the bytes after the piggyback.
    rest = rest[2:]  # cidnam / cidser pointers
    _, rest = decode_ub4(rest)  # flags
    attrs: dict[str, str | None] = {}
    with_value: list[str] = []
    for slot in (
        'client_identifier',
        'module',
        'action',
        'cideci',
        'cidcct',
        'client_info',
        'cidkstk',
        'cidktgt',
        'dbop',
    ):
        modified, rest = rest[0], rest[1:]
        length, rest = decode_ub4(rest)
        if modified and slot in _END_TO_END_ATTRS:
            attrs[slot] = None
            if length:
                with_value.append(slot)
    for slot in with_value:
        raw, rest = decode_dalc(rest)
        attrs[slot] = bytes(raw).decode('utf-8')
    return attrs, rest


_END_TO_END_ATTRS = frozenset(
    {'client_identifier', 'module', 'action', 'client_info', 'dbop'}
)


# REF CURSOR ids start clear of the fixed ids the Mirror's other OCI replies
# carry (0, 0x5be8, 0x5beb), so a re-execute of a statement's own cursor is never
# taken for one (#2014).
_OCI_REF_CURSOR_FIRST_ID = 0x100


class _OciBlocks:
    """The last PL/SQL block in a sqlplus session that handed OUT values back
    (#2041). sqlplus runs such a block again with TTI_EXEC, by the cursor id the
    reply named and with values for the binds that came in with one -- how it
    fetches SERVEROUTPUT's lines, DBMS_OUTPUT.GET_LINES once per batch. The
    Mirror names every statement's cursor 2, so the last block is the one."""

    def __init__(self) -> None:
        self.request: ExecRequest | None = None

    def remember(self, request: ExecRequest) -> None:
        self.request = request

    @staticmethod
    def given(request: ExecRequest) -> list[bool]:
        # Which binds came in with a value -- IN or IN OUT, not pure OUT.
        return [
            value is not None or t == TNS_TYPE_REFCURSOR
            for value, (t, _cs, _size, _toid) in zip(request.binds, request.bind_types)
        ]


def _answer_exec_by_cursor_oci(
    stream: PacketStream,
    backend: Backend,
    body: bytes,
    seq: '_OciSequence',
    blocks: _OciBlocks,
    ref_cursors: '_OciRefCursors',
    lob_vars: '_OciLobVars',
) -> None:
    # Run the remembered block again with the call's IN values, and answer with
    # its OUT values the way the first execute did, less the OUT-bind header and
    # the status frame, as a live 18c does (#2041).
    request = blocks.request
    if request is None:
        _refuse_unhandled_oci(stream, 'OCI call 0304: no block to run again', seq)
        return
    given = _OciBlocks.given(request)
    in_types = [t for (t, _cs, _size, _toid), g in zip(request.bind_types, given) if g]
    try:
        _cursor, values = parse_exec_by_cursor_oci(body, in_types)
    except (InterfaceError, DataError) as err:
        _refuse_unhandled_oci(stream, f'OCI call 0304: {err}', seq)
        return
    supplied = iter(values)
    binds = [next(supplied) if g else None for g in given]
    request = replace(request, binds=binds, bind_rows=[binds])
    try:
        result = backend.execute(request.sql, _bind_vars(request))
    except BackendError as err:
        stream.write_packet(
            TNS_DATA,
            encode_error_oci(
                err.ora_code,
                str(err),
                sequence=seq.next(),
                error_pos=_oci_error_pos(err),
            ),
        )
        return
    stream.write_packet(
        TNS_DATA,
        encode_exec_by_cursor_reply_oci(
            [
                lob_vars.keep(ref_cursors.park(value), t)
                for value, (t, _cs, _size, _toid) in zip(
                    result.out_binds, request.bind_types
                )
            ],
            sequence=seq.next(),
            types=[(t, toid) for (t, _cs, _size, toid) in request.bind_types],
            forms=[form for (_t, form, _size, _toid) in request.bind_types],
        ),
    )


class _OciLobVars:
    """The values PL/SQL blocks assigned to sqlplus CLOB / BLOB variables in one
    session (#2015).

    The OUT value goes back as a locator naming its id here; sqlplus binds that
    locator to read the variable (``PRINT`` runs ``SELECT :v FROM SYS.DUAL``)
    or to pass it on, and each time it resolves to the value. sqlplus's own
    buffer for a variable that holds nothing yet stays a TempLobRef, for the
    caller to tell apart."""

    def __init__(self) -> None:
        self._values: list[object] = []

    def keep(self, value: object, tns_type: int) -> object:
        if tns_type not in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
            return value
        is_clob = tns_type == TNS_TYPE_CLOB
        if value is None:
            return LobOutBind(value=None, is_clob=is_clob, lob_id=0)
        self._values.append(value)
        return LobOutBind(value=value, is_clob=is_clob, lob_id=len(self._values) - 1)

    def content(self, locator: bytes | None) -> tuple[bytes, bool, bool] | None:
        # A variable's value as a LOB read serves it -- UTF-16BE for a CLOB --
        # when `locator` is one the Mirror handed out (#2123), else None.
        for is_blob in (False, True):
            lob_id = oci_lob_var_id(locator, is_blob) if locator else None
            if lob_id is not None and lob_id < len(self._values):
                kept = self._values[lob_id]
                if is_blob:
                    return (
                        bytes(kept) if isinstance(kept, (bytes, bytearray)) else b'',
                        False,
                        False,
                    )
                text = kept if isinstance(kept, str) else str(kept)
                return (text.encode('utf-16-be'), True, False)
        return None

    def resolve(self, value: object) -> object:
        if not isinstance(value, TempLobRef):
            return value
        lob_id = oci_lob_var_id(value.locator, value.is_blob)
        if lob_id is None or lob_id >= len(self._values):
            # Not one the Mirror handed out: sqlplus's unset buffer.
            return value
        kept = self._values[lob_id]
        if value.is_blob:
            return BlobValue(kept if isinstance(kept, (bytes, bytearray)) else b'')
        return ClobValue(kept if isinstance(kept, str) else str(kept))


class _OciRefCursors:
    """The REF CURSORs PL/SQL blocks opened in one sqlplus session (#2014).

    A block's OUT value names a cursor id; sqlplus re-executes that id with no
    SQL to fetch the rows, and fetches again while rows remain. Each answer
    carries at most the rows the call has room for, since sqlplus sized its
    buffer to that count (#1284), and the last one ends the fetch."""

    def __init__(self) -> None:
        self._open: dict[int, tuple[list[ColumnMeta], list[tuple]]] = {}
        self._next_id = _OCI_REF_CURSOR_FIRST_ID

    def park(self, value: object) -> object:
        # A cursor the block opened becomes the OUT value naming it; one it
        # never opened has no columns and id 0, as on the thin path (#1016).
        if not isinstance(value, CursorResult):
            return value
        if not value.columns:
            return RefCursorOutBind(columns=[], cursor_id=0)
        cursor_id = self._next_id
        self._next_id += 1
        self._open[cursor_id] = (list(value.columns), list(value.rows))
        return RefCursorOutBind(columns=list(value.columns), cursor_id=cursor_id)

    def take_streamed(self, body: bytes) -> tuple[list[ColumnMeta], list[tuple]] | None:
        # A re-executed cursor whose rows carry a LOB or LONG, handed over whole:
        # those stream over calls of their own, as a query's do (#2033).
        cursor_id = int.from_bytes(body[7:11], 'little')
        opened = self._open.get(cursor_id)
        if opened is None or not (
            _is_lob_result(opened[0]) or _is_long_result(opened[0])
        ):
            return None
        del self._open[cursor_id]
        return opened

    def serve_reexecute(
        self, stream: PacketStream, body: bytes, seq: '_OciSequence'
    ) -> bool:
        cursor_id = int.from_bytes(body[7:11], 'little')
        if cursor_id not in self._open:
            return False
        _cursor_id, count = parse_reexecute_oci(body)
        self._serve(stream, cursor_id, count, seq)
        return True

    def serve_fetch(
        self, stream: PacketStream, body: bytes, seq: '_OciSequence'
    ) -> bool:
        cursor_id = int.from_bytes(body[3:7], 'little')
        if cursor_id not in self._open:
            return False
        self._serve(stream, cursor_id, parse_fetch_oci(body), seq)
        return True

    def _serve(
        self, stream: PacketStream, cursor_id: int, count: int, seq: '_OciSequence'
    ) -> None:
        columns, rows = self._open[cursor_id]
        count = max(1, count)
        more = len(rows) > count
        stream.write_packet(
            TNS_DATA,
            encode_fetch_batch_oci(
                columns, rows[:count], sequence=seq.next(), more=more
            ),
        )
        if more:
            self._open[cursor_id] = (columns, rows[count:])
        else:
            del self._open[cursor_id]


class _OciSequence:
    # The per-session OER end-to-end sequence number for the sqlplus / thick-OCI
    # reply path (§36). A real Oracle server advances this diagnostic counter on
    # every reply; the Mirror does the same with a live counter instead of emitting
    # the frozen value each captured status was reverse-engineered with, so a
    # session's replies look like a live server's rather than repeating one number.
    # The field is read-and-discarded by every client (both reference thin and
    # thick clients read it into a dead field or skip it outright — never validate,
    # echo, or transmit it), so the start value and +1-per-reply step are Mirror
    # response-generation policy, not a decoded Oracle rule. Starts at 1.
    def __init__(self) -> None:
        self._n = 1

    def next(self) -> int:
        n = self._n
        self._n = _next_reply_sequence(n)
        return n


def _next_reply_sequence(n: int) -> int:
    """The reply sequence after ``n``, wrapping as a 16-bit counter does.

    Both reply paths carry the sequence in a 16-bit field. Left to grow, the OCI
    path's 65,536th reply failed to encode and the session died; the thin path
    wrote a third byte a client reads as two (#1513)."""
    return (n + 1) & 0xFFFF


class _Cursors:
    # Undelivered rows for result sets not yet drained, keyed by a per-session
    # cursor id. A query whose result exceeds the requested fetch count parks the
    # remainder here and hands it out on later TTI_FETCH calls (the Mirror's only
    # cross-call state). Cursor ids start at 1 — 0 means "no cursor" on the wire.
    def __init__(self) -> None:
        self._next = 1
        self._open: dict[int, tuple[list[ColumnMeta], list[tuple]]] = {}
        # Scrollable cursors (#181/#485) keep their FULL materialised row set
        # keyed by cursor id and stay open across scroll re-executes (a scroll
        # can revisit any row), unlike `_open`, which hands out and forgets
        # batches. Shares the `_next` id space so ids never collide.
        self._scroll: dict[int, tuple[list[ColumnMeta], list[tuple]]] = {}
        # DML statement text + bind format keyed by the cursor id the Mirror
        # returns for it, so the client's cursor cache can re-execute by id with an
        # empty query and no OACs (the 11g parse-once optimization, #80/#486).
        # Shares the `_next` id space.
        self._dml: dict[int, tuple[str, list]] = {}
        # Query statement text + bind format keyed by the cursor id reported for
        # it, so a client that re-executes a query by id gets that query (#840)
        # and its fresh bind values decode (#854). Shares the `_next` id space.
        self._query: dict[int, tuple[str, list]] = {}
        # The bind directions reported for a PL/SQL block, by cursor id (#1064).
        # A re-execute of a block sends values only for the binds that take one,
        # so decoding its rows needs to know which positions those are -- the
        # bind format alone does not say. Empty for DML, whose binds are all IN.
        self._bind_directions: dict[int, tuple[int, ...]] = {}
        # The column describe last sent for a cursor id. On a re-execute the
        # client reuses the describe from the first execute and does not expect
        # another -- unless the statement's shape changed underneath it (a view
        # replaced with different column types, #826). Comparing the re-run's
        # columns against this decides whether the re-execute reply must carry a
        # fresh describe, the way a real server re-describes an invalidated cursor.
        self._describe: dict[int, list[ColumnMeta]] = {}
        # The defines a client applied to a cursor, by cursor id (#826). A define
        # is applied ONCE, on the round-trip that follows the first describe, and
        # then stands for the life of the cursor -- a re-execute carries none, so
        # without remembering them the Mirror reverted to locators and desynced a
        # client that was still reading the column as a string / bytes.
        self._defines: dict[int, list[tuple[int, int]]] = {}
        # How many rows have been handed out under each cursor id (#1048). A
        # client may bind an open cursor into a PL/SQL block, which then fetches
        # from where the client left off -- so serving that needs an upstream
        # cursor advanced by exactly this many rows, or the block reads rows the
        # client already has.
        self._delivered: dict[int, int] = {}

    def set_defines(self, cursor_id: int, define_types: Sequence) -> None:
        """Remember the defines applied to a cursor, if this execute carried
        any. An execute with no defines leaves the cursor's alone -- it is not a
        client withdrawing them, just an ordinary call."""
        if define_types:
            self._defines[cursor_id] = list(define_types)

    def defines(self, cursor_id: int) -> list[tuple[int, int]]:
        """The defines standing on a cursor, empty if it has none."""
        return self._defines.get(cursor_id, [])

    def open_query(
        self,
        sql: str,
        bind_types: Sequence = (),
        columns: Sequence[ColumnMeta] = (),
    ) -> int:
        # A cursor id for a query, minted even when the whole result fit and
        # there is nothing parked. The client caches the id against the statement
        # and re-executes by it, so every query needs one of its own -- sharing
        # the captured 1 told every query it was the same cursor (#840). The SQL
        # is kept because re-executing by id has to know what to run (#833), and
        # the describe because a re-execute has to tell whether the statement's
        # shape changed underneath the cached cursor (#826) -- a fully-delivered
        # result parks no rows, so this is the only record of what it looked like.
        cursor_id = self._next
        self._next += 1
        self._query[cursor_id] = (sql, list(bind_types))
        self._describe[cursor_id] = list(columns)
        return cursor_id

    def query_sql(self, cursor_id: int) -> str | None:
        """The statement behind a query cursor id, or None if unknown."""
        state = self._query.get(cursor_id)
        return state[0] if state is not None else None

    def bind_types(self, cursor_id: int) -> list | None:
        """The bind format a cursor -- DML or query -- was opened with, so a
        re-execute's OAC-less rows decode (#854); None if the id is unknown."""
        state = self._dml.get(cursor_id) or self._query.get(cursor_id)
        return state[1] if state is not None else None

    def set_bind_types(self, cursor_id: int, bind_types: list) -> None:
        """Refresh the bind format recorded against a cursor (#999).

        It was recorded once, at open, and an OAC-less re-execute decodes with
        it. But a client re-describes its binds mid-stream whenever their types
        change -- a column that was all-NULL in the first executemany batch and
        carries numbers in a later one -- and the next OAC-less execute then
        decoded those numbers with the original types. An execute carrying no
        OACs leaves the record alone; it is asking to reuse it, not replacing
        it."""
        if not bind_types:
            return
        for table in (self._dml, self._query):
            state = table.get(cursor_id)
            if state is not None:
                table[cursor_id] = (state[0], list(bind_types))

    def open_dml(self, sql: str, bind_types: list) -> int:
        cursor_id = self._next
        self._next += 1
        self._dml[cursor_id] = (sql, list(bind_types))
        return cursor_id

    def dml_sql(self, cursor_id: int) -> str | None:
        # The SQL a cached-cursor re-execute (cursor id set, empty query) refers
        # to, or None if the id isn't a known DML cursor.
        state = self._dml.get(cursor_id)
        return state[0] if state is not None else None

    def set_bind_directions(self, cursor_id: int, directions: Sequence[int]) -> None:
        """Record what the server reported for a block's binds (#1064).

        A backend that cannot know them reports none, and the cursor keeps no
        record -- a re-execute then reads a value for every bind, which is what
        a block with no OUT binds sends anyway."""
        if directions:
            self._bind_directions[cursor_id] = tuple(directions)

    def bind_directions(self, cursor_id: int) -> tuple[int, ...]:
        return self._bind_directions.get(cursor_id, ())

    def dml_bind_types(self, cursor_id: int) -> list | None:
        # The remembered bind format for a cached DML cursor, so its re-execute's
        # OAC-less RXD decodes; None if the id isn't a known DML cursor.
        state = self._dml.get(cursor_id)
        return state[1] if state is not None else None

    def open(
        self,
        columns: list[ColumnMeta],
        rows: list[tuple],
        *,
        sql: str | None = None,
        bind_types: Sequence = (),
        delivered: int = 0,
    ) -> int:
        # `sql` is the statement this cursor ran, recorded so a re-execute by id
        # knows what to run (#840), with the bind format its values came in (#854).
        # A REF CURSOR has no statement of its own and passes None.
        # `delivered` is how many rows already went out with the execute itself
        # -- they never pass through `take`, and a cursor bound into a PL/SQL
        # block has to resume after them (#1048).
        cursor_id = self._next
        self._next += 1
        self._open[cursor_id] = (columns, rows)
        self._describe[cursor_id] = columns
        self._delivered[cursor_id] = delivered
        if sql is not None:
            self._query[cursor_id] = (sql, list(bind_types))
        return cursor_id

    def reopen(
        self,
        cursor_id: int,
        columns: list[ColumnMeta],
        rows: list[tuple],
        *,
        sql: str,
    ) -> None:
        # Re-park a re-executed cursor under the id the client already holds,
        # rather than minting a new one: the client is not told about a new id on
        # a re-execute, so its follow-up fetches would address the old one (#833).
        # The bind format stays what the opening execute recorded.
        previous = self._query.get(cursor_id)
        self._query[cursor_id] = (sql, previous[1] if previous else [])
        self._describe[cursor_id] = columns
        if rows:
            self._open[cursor_id] = (columns, rows)
        else:
            self._open.pop(cursor_id, None)

    def open_scroll(
        self, columns: list[ColumnMeta], rows: list[tuple], *, sql: str | None = None
    ) -> int:
        cursor_id = self._next
        self._next += 1
        self._scroll[cursor_id] = (columns, list(rows))
        if sql is not None:
            # A scrollable cursor is one a client deliberately keeps OPEN, so it
            # is the likeliest kind to be bound into a PL/SQL block later --
            # recording its statement is what lets that bind be served (#1048).
            self._query[cursor_id] = (sql, [])
        return cursor_id

    def scroll_state(
        self, cursor_id: int
    ) -> tuple[list[ColumnMeta], list[tuple]] | None:
        # The (columns, all rows) of a kept-open scrollable cursor, or None if
        # the id isn't a scrollable cursor.
        return self._scroll.get(cursor_id)

    def take(self, cursor_id: int, count: int) -> tuple[list[ColumnMeta], list[tuple]]:
        # Return (columns, next batch) and either keep the remainder or, once the
        # cursor is drained, forget it. An unknown cursor yields an empty batch.
        state = self._open.get(cursor_id)
        if state is None:
            return [], []
        columns, remaining = state
        batch, rest = remaining[:count], remaining[count:]
        self._delivered[cursor_id] = self._delivered.get(cursor_id, 0) + len(batch)
        if rest:
            self._open[cursor_id] = (columns, rest)
        else:
            del self._open[cursor_id]
        return columns, batch

    def delivered(self, cursor_id: int) -> int:
        """How many rows have gone out under this cursor id (#1048)."""
        return self._delivered.get(cursor_id, 0)

    def note_delivered(self, cursor_id: int, count: int) -> None:
        """Record rows served outside `take` -- the batch that rides with an
        execute, and a scrollable open's own (#1048)."""
        self._delivered[cursor_id] = self._delivered.get(cursor_id, 0) + count

    def has(self, cursor_id: int) -> bool:
        return cursor_id in self._open

    def columns(self, cursor_id: int) -> list[ColumnMeta]:
        """The column metadata a parked cursor was opened with, empty if the id
        is not parked. Read without taking any rows, so a caller can decide how
        to answer before it commits to draining the cursor (#887)."""
        state = self._open.get(cursor_id)
        return state[0] if state is not None else []

    def describe_columns(self, cursor_id: int) -> list[ColumnMeta]:
        """The describe last sent for a cursor id, empty if unknown. Unlike
        :meth:`columns` this survives a fully-drained cursor, so a re-execute can
        tell whether the statement's column shape changed (#826)."""
        return self._describe.get(cursor_id, [])


class _TempLobs:
    # Bytes streamed into each session temp LOB via TTI_LOBOPS WRITE, keyed by the
    # locator the Mirror minted on CREATE_TEMP; resolved into the bind value on
    # the following execute (#412).
    #
    # Locators are numbered from a counter that only ever goes up -- NOT from the
    # number of live temp LOBs. Numbering them by the count reissues an index the
    # moment anything is freed, and the reissued locator collides with one still
    # in use: a client's third large-LOB statement minted the locator its second
    # was holding, overwrote that buffer, and then the close-temp-LOBs piggyback
    # riding on the third call freed the locator the third call was about to
    # bind, so the value arrived NULL (#857).
    def __init__(self) -> None:
        self._buffers: dict[bytes, bytearray] = {}
        self._is_blob: dict[bytes, bool] = {}
        self._next = 0
        # Locators this session has OPENed and not yet CLOSEd, for IS_OPEN to
        # report (#903/#887). Any locator, not just a temp one -- the LOB a
        # client opens is usually a column locator the Mirror emitted.
        self._open: set[bytes] = set()

    def mark_open(self, locator: bytes) -> None:
        self._open.add(bytes(locator))

    def mark_closed(self, locator: bytes) -> None:
        self._open.discard(bytes(locator))

    def is_open(self, locator: bytes) -> bool:
        """Whether this session opened ``locator`` and has not closed it.

        This is what the SESSION has been told, not what the database knows: a
        LOB opened by PL/SQL on the backend is invisible here. Faithful for the
        open/close bracket a client drives itself, which is what a LOB write
        actually uses; a Mirror that relayed the question upstream would be
        exact, and is worth doing if a caller ever needs it.
        """
        return bytes(locator) in self._open

    def mint(self, is_blob: bool) -> bytes:
        """A locator distinct from every other this session has handed out."""
        locator = mint_temp_lob_locator(self._next, is_blob)
        self._next += 1
        self._buffers[bytes(locator)] = bytearray()
        self._is_blob[bytes(locator)] = is_blob
        return locator

    def append(self, locator: bytes, payload: bytes) -> None:
        # Through resolve(), so a write lands on the buffer the LOB was minted
        # under whichever spelling of the locator the client sent (#903).
        key = self.resolve(locator) or bytes(locator)
        self._buffers.setdefault(key, bytearray()).extend(payload)

    def free(self, locator: bytes) -> None:
        # A client may free a locator the Mirror never saw written; that is fine,
        # and the index is still never reused.
        self._buffers.pop(bytes(locator), None)
        self._is_blob.pop(bytes(locator), None)

    def content(self, locator: bytes) -> bytes:
        key = self.resolve(locator)
        return bytes(self._buffers.get(key, b'')) if key else b''

    def truncate(self, locator: bytes, size: int) -> None:
        """Cut the temp LOB down to ``size`` bytes (TRIM, #826)."""
        key = self.resolve(locator)
        if key is not None:
            del self._buffers[key][size:]

    def resolve(self, locator: bytes) -> bytes | None:
        """The canonical key for ``locator``, or None if it is not a temp LOB.

        A temp-LOB op carries the locator ub2-length-prefixed, but a READ is
        parsed by the declared source length and keeps that prefix, so the same
        LOB arrives under two spellings. Try both rather than miss one (#826).
        """
        raw = bytes(locator)
        if raw in self._buffers:
            return raw
        stripped = raw[2:]
        return stripped if stripped in self._buffers else None

    def is_blob(self, locator: bytes) -> bool:
        """Whether this temp LOB is a BLOB. Unknown locators read as BLOB, which
        counts bytes -- the safer guess for something the Mirror did not mint."""
        key = self.resolve(locator)
        return self._is_blob.get(key, True) if key else True

    def contents_map(self) -> dict[bytes, tuple[object, bool]]:
        # Each live temp LOB's content as (value, is_clob) for an object bind to
        # resolve a LOB attribute set to a createlob temp LOB (#888). A CLOB rode
        # in over the wire as UTF-16BE (the minted locator says so), so decode it
        # back to str; a BLOB is raw bytes.
        out: dict[bytes, tuple[object, bool]] = {}
        for locator, buf in self._buffers.items():
            is_blob = self._is_blob.get(locator, False)
            if is_blob:
                out[locator] = (bytes(buf), False)
            else:
                out[locator] = (bytes(buf).decode('utf-16-be'), True)
        return out


def _emitted_lob(
    lob_emit_log: 'LobEmitLog | None', locator: bytes
) -> tuple[str | bytes, bool] | None:
    """The content the Mirror served under this column-LOB locator, if it is one.

    ``None`` for a temp-LOB locator, an object-LOB locator, or the fixed
    placeholder an OCI client sees -- those keep their own paths. The log is
    typed ``object`` because it holds whatever a backend produced, so anything
    that is not the str / bytes a LOB column yields is treated as not found
    rather than trusted into the framing code."""
    if lob_emit_log is None:
        return None
    # Try the locator as the client sent it, then without a leading 2-byte
    # wrapper. A COLUMN locator arrives exactly as the Mirror emitted it, but a
    # TEMP one is the Mirror's reply including the ub2 it was handed back in, so
    # the same LOB reaches here under two spellings -- the same reason
    # _TempLobs.resolve tries both (#826/#903).
    entry = lob_emit_log.content(locator)
    if entry is None and len(locator) > 2:
        entry = lob_emit_log.content(locator[2:])
    if entry is None:
        return None
    value, is_clob = entry
    if not isinstance(value, (str, bytes)):
        return None
    return (value, is_clob)


def _emit_log_key(lob_emit_log: 'LobEmitLog | None', locator: bytes) -> bytes | None:
    """Which spelling of ``locator`` the emit log is keyed by, or None.

    The companion to :func:`_emitted_lob`: that one answers *what* is stored,
    this one *where*, for the writes that have to update it in place.
    """
    if lob_emit_log is None:
        return None
    raw = bytes(locator)
    if lob_emit_log.content(raw) is not None:
        return raw
    if len(raw) > 2 and lob_emit_log.content(raw[2:]) is not None:
        return raw[2:]
    return None


def _answer_bfile(
    stream: PacketStream, backend: Backend | None, request: LobOpsRequest
) -> None:
    """Answer a BFILE call (#1102).

    The locator carries the directory and file name, so nothing is remembered
    between calls: each is answered by asking the backend about those two names.
    A backend with no BFILE hooks refuses the call the way any unservable one is
    refused, rather than claiming the file is missing -- "I cannot" and "it is
    not there" are different answers, and only the server knows the second.
    """
    names = decode_bfile_locator(request.locator)
    exists = getattr(backend, 'bfile_exists', None)
    if names is None or exists is None:
        _refuse_unhandled(stream, f'a BFILE {request.kind}')
        return
    (directory, filename) = names
    try:
        present = bool(exists(directory, filename))
    except BackendError as err:
        # The server's own answer -- ORA-22285 for a directory that does not
        # exist -- is what the client is asking for, so relay it.
        stream.write_packet(TNS_DATA, encode_error(err.ora_code, err.ora_message))
        return
    # The two boolean answers echo the locator FIELD, not the locator: the client
    # reads `len(locator)` raw bytes and then one ub1, and a BFILE locator's
    # length includes its own leading ub2 (§14.4d). `parse_lobops_request` hands
    # a BFILE op its locator with that ub2 stripped, and `encode_lobops_is_open`
    # echoes verbatim by design -- so the field came out two bytes short and the
    # client read the boolean from inside the locator, reporting a file that is
    # there as missing (#1120). FILE_OPEN / FILE_CLOSE below are unaffected:
    # `encode_lobops_ack` re-adds the prefix itself.
    field = len(request.locator).to_bytes(2, 'big') + request.locator
    if request.kind == 'file_exists':
        stream.write_packet(TNS_DATA, encode_lobops_is_open(field, present))
        return
    if request.kind == 'file_isopen':
        # Nothing is held open between calls, so it never reports open.
        stream.write_packet(TNS_DATA, encode_lobops_is_open(field, False))
        return
    if request.kind == 'file_open' and not present:
        stream.write_packet(
            TNS_DATA, encode_error(ORA_NONEXISTENT_FILE, _ORA_BFILE_MISSING_TEXT)
        )
        return
    if request.kind == 'file_open':
        # The locator back, which the client reuses for the READ that follows,
        # then the mode it sent: it reads an amount back for any op that sent
        # one, and without it took the OER's first byte for it and desynced
        # (#1672). 23ai also sets an open flag inside the locator; nothing is
        # held open here, so the locator goes back as it came.
        stream.write_packet(
            TNS_DATA,
            encode_lobops_open_ack(
                len(request.locator).to_bytes(2, 'big') + request.locator,
                request.amount,
            ),
        )
        return
    # FILE_CLOSE: the locator back.
    stream.write_packet(TNS_DATA, encode_lobops_ack(request.locator))


def _answer_bfile_content(
    stream: PacketStream,
    backend: Backend | None,
    request: LobOpsRequest,
    names: tuple[str, str],
) -> None:
    """A BFILE's length or bytes (#1672), as 23ai answers them: the shapes a
    BLOB's GET_LENGTH and READ answer in. The backend reads the file --
    ``bfile_length(directory, filename)`` and ``bfile_read(directory,
    filename, offset, amount)``, the offset 1-based and an amount of 0 or less
    the rest of the file. A backend without them refuses the call, as for any
    unservable one; its own error is relayed."""
    (directory, filename) = names
    reads = request.kind == 'read'
    hook = getattr(backend, 'bfile_read' if reads else 'bfile_length', None)
    if hook is None:
        _refuse_unhandled(stream, f'a BFILE {request.kind}')
        return
    try:
        if reads:
            data = hook(directory, filename, max(request.offset, 1), request.amount)
        else:
            length = hook(directory, filename)
    except BackendError as err:
        stream.write_packet(TNS_DATA, encode_error(err.ora_code, err.ora_message))
        return
    if reads:
        stream.write_packet(
            TNS_DATA,
            encode_lob_read_response_thin(data, is_clob=False, locator=request.locator),
        )
    else:
        stream.write_packet(TNS_DATA, encode_lobops_length(request.locator, length))


def _answer_lobops(
    stream: PacketStream,
    body: bytes,
    lobs: list[tuple[bytes, bool]],
    temp_lobs: _TempLobs,
    current_lob: tuple[bytes, bool] | None = None,
    object_lobs: list[tuple[bytes, bool]] | None = None,
    current_object_lob: tuple[bytes, bool] | None = None,
    lob_emit_log: LobEmitLog | None = None,
    backend: Backend | None = None,
) -> tuple[
    list[tuple[bytes, bool]],
    tuple[bytes, bool] | None,
    tuple[bytes, bool] | None,
]:
    # Dispatch a thin TTI_LOBOPS message. CREATE_TEMP / WRITE drive the temp-LOB
    # write flow (#412); FREE_TEMP / OPEN / CLOSE / TRIM / GET_CHUNK_SIZE are
    # acknowledged so a programmatic client doesn't desync (#417); a plain READ
    # drains the content of a column locator the Mirror emitted (#413). Returns
    # the (possibly shortened) column read queue and the current column / object
    # read cursors.
    request = parse_lobops_request(body)
    if request.kind in ('file_open', 'file_close', 'file_exists', 'file_isopen'):
        _answer_bfile(stream, backend, request)
        return lobs, current_lob, current_object_lob
    # GET_LENGTH / READ on a BFILE locator (#1672): the file's own length and
    # bytes, which only the backend can reach. Not one of the client's temp
    # LOBs nor a column LOB the Mirror emitted, so the queues below have
    # nothing for it, and answered another LOB's content or none.
    if (
        request.kind in ('get_length', 'read')
        and temp_lobs.resolve(request.locator) is None
        and _emitted_lob(lob_emit_log, request.locator) is None
        and (names := decode_bfile_locator(request.locator)) is not None
    ):
        _answer_bfile_content(stream, backend, request, names)
        return lobs, current_lob, current_object_lob
    if request.kind == 'create_temp':
        locator = temp_lobs.mint(request.is_blob)
        stream.write_packet(TNS_DATA, encode_create_temp_response(locator))
        return lobs, current_lob, current_object_lob
    if request.kind == 'write':
        # A write to a COLUMN LOB extends what the Mirror served under that
        # locator, so the emit log is what has to grow -- a size() afterwards
        # reads that log first and would otherwise keep reporting the length
        # the LOB had when it was fetched (#903/#887).
        emitted = _emitted_lob(lob_emit_log, request.locator)
        key = _emit_log_key(lob_emit_log, request.locator)
        if emitted is not None and lob_emit_log is not None and key is not None:
            (value, is_clob) = emitted
            # SPLICED at the write offset, not appended: `write(v, 1)`
            # overwrites from the start. The offset is in the LOB's own units --
            # characters for a CLOB, which is what the log already holds, while
            # the wire carries UTF-16BE.
            start = min(max(request.offset - 1, 0), len(value))
            merged: str | bytes
            if isinstance(value, str):
                text = request.payload.decode('utf-16-be', 'replace')
                merged = value[:start] + text + value[start + len(text) :]
            else:
                raw = request.payload
                merged = value[:start] + raw + value[start + len(raw) :]
            lob_emit_log.contents[key] = (merged, is_clob)
        else:
            # Append at the write offset the client streamed (it writes from the
            # start and appends, so a plain concat matches every real client).
            temp_lobs.append(request.locator, request.payload)
        # Verbatim: the locator is echoed exactly as the client sent it, prefix
        # and all. encode_lobops_ack would add a second length (#903/#887).
        stream.write_packet(TNS_DATA, encode_lobops_echo(request.locator))
        return lobs, current_lob, current_object_lob
    if request.kind == 'free_temp':
        # Release the temp LOB now rather than at session end.
        temp_lobs.free(request.locator)
        stream.write_packet(TNS_DATA, encode_lobops_ack(request.locator))
        return lobs, current_lob, current_object_lob
    if request.kind == 'trim':
        # A COLUMN LOB is truncated in the emit log, which is what serves its
        # length and content afterwards -- trimming only the temp store left
        # size() still reporting the untrimmed figure (#903/#887).
        trimmed = _emitted_lob(lob_emit_log, request.locator)
        trim_key = _emit_log_key(lob_emit_log, request.locator)
        if trimmed is not None and lob_emit_log is not None and trim_key is not None:
            (value, is_clob) = trimmed
            # request.amount is in the LOB's own units, which is what the log
            # holds: characters for a CLOB (a str), bytes for a BLOB.
            lob_emit_log.contents[trim_key] = (value[: request.amount], is_clob)
            stream.write_packet(
                TNS_DATA, encode_lobops_length(request.locator, request.amount)
            )
            return lobs, current_lob, current_object_lob
        # Truncate the temp LOB to the requested length and report the new one.
        # A CLOB counts CHARACTERS and its buffer is UTF-16BE, so two bytes each.
        unit = 1 if temp_lobs.is_blob(request.locator) else 2
        temp_lobs.truncate(request.locator, request.amount * unit)
        stream.write_packet(
            TNS_DATA, encode_lobops_length(request.locator, request.amount)
        )
        return lobs, current_lob, current_object_lob
    if request.kind == 'get_length':
        # `lob.size()`. A FETCHED column LOB is measured from what the Mirror
        # served under that locator: this used to consult the temp-LOB store
        # alone, which knows nothing about a column locator and so reported 0 --
        # every size() on a fetched LOB came back zero (#826).
        emitted = _emitted_lob(lob_emit_log, request.locator)
        if emitted is not None:
            # The log keeps the value in its own unit already -- a `str` for a
            # CLOB, whose length IS the character count the client asks for, and
            # `bytes` for a BLOB.
            value, _is_clob = emitted
            stream.write_packet(
                TNS_DATA, encode_lobops_length(request.locator, len(value))
            )
            return lobs, current_lob, current_object_lob
        # A temp LOB the client created is measured from what it has streamed
        # in; a CLOB counts CHARACTERS, and its buffer holds UTF-16BE, so two
        # bytes per character (#826).
        content = temp_lobs.content(request.locator)
        unit = 1 if temp_lobs.is_blob(request.locator) else 2
        stream.write_packet(
            TNS_DATA, encode_lobops_length(request.locator, len(content) // unit)
        )
        return lobs, current_lob, current_object_lob
    if request.kind in ('open', 'close'):
        # The state is remembered, because IS_OPEN has to report it back, and
        # because the bracket is not idempotent: a real server refuses a second
        # open and a close of something never opened. Acking those blindly told
        # the client an error it was testing for had not happened (#903/#887).
        already = temp_lobs.is_open(request.locator)
        if request.kind == 'open':
            if already:
                stream.write_packet(
                    TNS_DATA, encode_lobops_error(*LOBOPS_ERR_ALREADY_OPEN)
                )
                return lobs, current_lob, current_object_lob
            temp_lobs.mark_open(request.locator)
        else:
            if not already:
                stream.write_packet(
                    TNS_DATA, encode_lobops_error(*LOBOPS_ERR_NOT_OPENED)
                )
                return lobs, current_lob, current_object_lob
            temp_lobs.mark_closed(request.locator)
        # Echoed verbatim, not through encode_lobops_ack: the client reads the
        # locator back with read_raw_bytes and consumes no length prefix, so
        # prepending one shifts everything after it. OPEN additionally owes the
        # amount it sent -- it is the one op here with send_amount (#903/#887).
        stream.write_packet(
            TNS_DATA,
            encode_lobops_open_ack(request.locator, request.amount)
            if request.kind == 'open'
            else encode_lobops_echo(request.locator),
        )
        return lobs, current_lob, current_object_lob
    if request.kind == 'is_open':
        # `lob.isopen()`. It owes the ack reply PLUS a ub1 flag; answering with a
        # bare ack is not a safe fallback, because the client reads that byte
        # regardless and would take whatever follows it (#903/#887).
        stream.write_packet(
            TNS_DATA,
            encode_lobops_is_open(request.locator, temp_lobs.is_open(request.locator)),
        )
        return lobs, current_lob, current_object_lob
    if request.kind == 'ack':
        # TRIM / GET_CHUNK_SIZE: acknowledge with the content-free reply the
        # client accepts. The value-returning form (a real chunk size, applying
        # TRIM's length) is deferred (#421) — no test client needs it.
        stream.write_packet(TNS_DATA, encode_lobops_ack(request.locator))
        return lobs, current_lob, current_object_lob
    # A READ of an emitted column locator. The queue is row-major, matching the
    # order the locators went out (#413), but a client reads a large LOB in
    # several passes, so the entry stays until it is drained and each read is
    # served the slice it asked for (#903). A read at offset 1 starts the next
    # LOB; later offsets continue the current one -- the same rule the OCI loop
    # follows. A LOB attribute of an object rides a distinct locator and drains
    # the persistent object queue instead of the column one (#888).
    temp_key = temp_lobs.resolve(request.locator)
    if temp_key is not None:
        # A READ of a temp LOB the client created itself. Its content is what the
        # client streamed in, not an entry on the column queue -- serving that
        # queue here handed back another row's LOB, or nothing at all. The reply
        # must echo the client's OWN locator, not the column placeholder (#826).
        content = temp_lobs.content(temp_key)
        is_clob = not temp_lobs.is_blob(temp_key)
        unit = 2 if is_clob else 1
        total = len(content) // unit
        start = max(request.offset - 1, 0)
        count = (
            total - start if request.amount <= 0 else min(request.amount, total - start)
        )
        count = max(count, 0)
        stream.write_packet(
            TNS_DATA,
            encode_lob_read_response_thin(
                content[start * unit : (start + count) * unit],
                is_clob=is_clob,
                locator=request.locator,
            ),
        )
        return lobs, current_lob, current_object_lob
    emitted = _emitted_lob(lob_emit_log, request.locator)
    if emitted is not None:
        # A READ of a column LOB the Mirror emitted, answered from the content
        # it served under THAT locator. The queue below is row-major and assumes
        # the client reads every LOB exactly once in the order the locators went
        # out; a client that reads them in another order, twice, or not at all
        # got another row's content or nothing (#826). Every locator is unique
        # and its content is already recorded (#888), so the order stops
        # mattering.
        value, is_clob = emitted
        # A CLOB rides UTF-16BE on the wire and counts CHARACTERS, so the two
        # bytes per unit below are what make an offset/amount read land right.
        content = value.encode('utf-16-be') if isinstance(value, str) else value
        unit = 2 if is_clob else 1
        total = len(content) // unit
        start = max(request.offset - 1, 0)
        count = (
            total - start if request.amount <= 0 else min(request.amount, total - start)
        )
        count = max(count, 0)
        stream.write_packet(
            TNS_DATA,
            encode_lob_read_response_thin(
                content[start * unit : (start + count) * unit],
                is_clob=is_clob,
                locator=request.locator,
            ),
        )
        return lobs, current_lob, current_object_lob
    is_object = request.locator == _THIN_OBJ_LOB_LOCATOR
    queue = (object_lobs if object_lobs is not None else []) if is_object else lobs
    resume = current_object_lob if is_object else current_lob
    if request.offset <= 1 or not resume:
        current = queue.pop(0) if queue else (b'', True)
    else:
        current = resume
    content, is_clob = current
    unit = 2 if is_clob else 1  # bytes per counted unit (a CLOB rides UTF-16BE)
    total = len(content) // unit
    start = request.offset - 1
    count = total - start if request.amount <= 0 else min(request.amount, total - start)
    count = max(count, 0)
    slice_ = content[start * unit : (start + count) * unit]
    stream.write_packet(
        TNS_DATA, encode_lob_read_response_thin(slice_, is_clob=is_clob)
    )
    if is_object:
        return lobs, current_lob, current
    return lobs, current, current_object_lob


def _mark_ltz_binds(request: ExecRequest) -> ExecRequest:
    # A TIMESTAMP WITH LOCAL TIME ZONE bind decodes to the same naive datetime
    # a TIMESTAMP bind does, but Oracle reads the two in different zones, so
    # the backend is handed an LtzValue that says which it was (#1222). A NULL
    # stays None: an ordinary NULL arrives as a BindVar with its type already.
    ltz = {
        i
        for i, meta in enumerate(request.bind_meta)
        if meta and meta[0] == TNS_TYPE_TIMESTAMPLTZ
    }
    if not ltz:
        return request

    def mark(i: int, value: object) -> object:
        if i in ltz and type(value) is datetime.datetime:
            return LtzValue.of(value)
        return value

    rows = [[mark(i, v) for i, v in enumerate(row)] for row in request.bind_rows]
    binds = rows[0] if rows else [mark(i, v) for i, v in enumerate(request.binds)]
    return replace(request, binds=binds, bind_rows=rows)


def _resolve_temp_lob_binds(request: ExecRequest, temp_lobs: _TempLobs) -> ExecRequest:
    # Swap any temp-LOB locator bind for the bytes streamed into it over
    # TTI_LOBOPS WRITE, so the backend sees a str / bytes value (#412). A
    # CLOB's content is UTF-16BE on the wire -- the minted locator says so with
    # its variable-length-charset flag, which is what a client encodes by (see
    # mint_temp_lob_locator) -- and a BLOB's is raw.
    # An empty temp LOB is resolved to a typed bind, not a bare '' / b'': a
    # backend that binds the bare value stores NULL on an Oracle target (an empty
    # scalar is NULL there), losing the "empty, non-NULL LOB" the client meant.
    # Only meaningful on a single execute -- the array path takes plain values,
    # and an empty temp LOB in an executemany is not a real case -- so a batch
    # keeps the bare form.
    # Any other content is resolved to a ClobValue / BlobValue, a str / bytes
    # that still says it was a LOB, so a backend binding on to Oracle can bind a
    # LOB rather than a VARCHAR2 that refuses it past 32 KB (#1067).
    single = len(request.bind_rows) <= 1

    def resolve(value: object) -> object:
        if isinstance(value, TempLobRef):
            data = temp_lobs.content(value.locator)
            content: bytes | str = (
                BlobValue(data)
                if value.is_blob
                else ClobValue(data.decode('utf-16-be'))
            )
            if single and not content:
                return BindVar(
                    value=content,
                    tns_type=TNS_TYPE_BLOB if value.is_blob else TNS_TYPE_CLOB,
                    max_size=0,
                )
            return content
        return value

    if not any(isinstance(v, TempLobRef) for row in request.bind_rows for v in row):
        return request
    rows = [[resolve(v) for v in row] for row in request.bind_rows]
    return replace(request, binds=rows[0], bind_rows=rows)


def _run_returning(
    backend: Backend, sql: str, request: ExecRequest, cursors: _Cursors
) -> Result:
    # Hand a RETURNING statement to the backend with a BindVar standing in at
    # every position the clause fills, so the backend knows which binds it owes
    # values for and what type is wanted there (#689). A backend with no
    # execute_returning is told so plainly rather than left to mangle the reply.
    run = getattr(backend, 'execute_returning', None)
    if run is None:
        raise UnsupportedFeature('RETURNING is not supported by this backend')
    meta = request.bind_meta
    # A RETURNING statement whose binds are ALL filled by the clause (an empty
    # INSERT, a DELETE with no WHERE bind) carries no input row, so the client
    # sends none — but its al8i4 iteration count still says how many times it
    # runs (one for a plain execute, N for an array). Stand in that many all-None
    # rows so each iteration happens and owes its set of returned values (#33).
    source_rows = request.bind_rows or [
        [None] * request.bind_count for _ in range(request.iterations)
    ]
    # The per-bind type OID rides on bind_types as the 4th field, the same place
    # _bind_vars takes it from (#888). A RETURNING receiver for an object or
    # collection column needs it: without one the backend can only build an
    # untyped Var, and the server rejects the statement with ORA-00932 "expression
    # is of data type <SCHEMA>.<TYPE>, which is incompatible with expected data
    # type CHAR". The client does send it -- measured -- it was simply dropped
    # here (#826).
    toids = [(bt[3] if len(bt) > 3 else b'') for bt in (request.bind_types or [])]
    forms = [(bt[1] if len(bt) > 1 else _CSFRM_DB) for bt in (request.bind_types or [])]
    rows = [
        [
            BindVar(
                value=None,
                tns_type=meta[i][0],
                max_size=meta[i][1],
                csfrm=forms[i] if i < len(forms) else _CSFRM_DB,
                toid=toids[i] if i < len(toids) else b'',
            )
            if i in request.return_binds
            else _resolve_refcursor_in_value(
                backend, cursors, meta[i][0] if i < len(meta) else 0, value
            )
            for i, value in enumerate(row)
        ]
        for row in source_rows
    ]
    result = run(sql, rows)
    # One record per iteration is what the client reads positionally, so a
    # backend that reported fewer (or none) is padded rather than silently
    # shifting a later iteration's values onto an earlier one.
    returned = list(result.returned_rows)
    returned += [[] for _ in range(len(rows) - len(returned))]
    return Result(rowcount=result.rowcount, returned_rows=returned[: len(rows)])


def _attach_object_bind_lobs(
    request: ExecRequest, lob_emit_log: LobEmitLog, temp_lobs: _TempLobs
) -> None:
    # Give every object-image bind the content the Mirror served under each LOB
    # locator, so the backend can turn a LOB attribute the client set to a fetched
    # or a createlob temp LOB back into an upstream LOB (its locator points at the
    # Mirror, not a live upstream LOB) (#888). A no-op when nothing has been
    # served or bound. The map is attached by reference; the backend only reads.
    combined = dict(lob_emit_log.contents)
    combined.update(temp_lobs.contents_map())
    if not combined:
        return
    rows = list(request.bind_rows) if request.bind_rows else []
    for values in [request.binds, *rows]:
        for value in values or []:
            if isinstance(value, ObjectImage):
                value.lob_contents = combined


def _resolve_refcursor_in_binds(backend: Backend, cursors: _Cursors, binds: list):
    """Turn a REF CURSOR bind carrying a cursor **id** into an open cursor the
    backend can take (#1048).

    A client may hand a PL/SQL block a cursor the server already has, declared
    there as a plain ``sys_refcursor`` IN parameter. The id in the bind is one
    the MIRROR handed out, and the backend has never heard of it — so the
    statement behind it is re-opened on the backend and advanced by the rows
    already served under that id, leaving the block to resume exactly where the
    client stopped.

    A zero id is the ordinary OUT form ("open one for me") and is left alone. An
    id the Mirror cannot place — no statement recorded, or a backend with no
    ``open_ref_cursor`` — keeps its raw value, so the reply is the backend's own
    ORA error rather than a cursor positioned wrongly.
    """
    Out = []
    for bind in binds:
        if isinstance(bind, BindVar):
            resolved = _resolve_refcursor_in_value(
                backend, cursors, bind.tns_type, bind.value
            )
            bind = bind if resolved is bind.value else replace(bind, value=resolved)
        Out.append(bind)
    return Out


def _resolve_refcursor_in_value(
    backend: Backend, cursors: _Cursors, tns_type: int, value: object
) -> object:
    # One bind's worth of the rule above: a REF CURSOR position carrying a
    # non-zero cursor id becomes an open backend cursor, anything else is
    # returned untouched. Shared by the block path and the RETURNING path, which
    # build their bind lists differently but owe the same translation -- a REF
    # cursor can be bound into a plain SQL statement too, as an argument to a
    # PL/SQL function called from it.
    if tns_type != TNS_TYPE_REFCURSOR or not isinstance(value, int) or not value:
        return value
    Open = getattr(backend, 'open_ref_cursor', None)
    if Open is None:
        return value
    sql = cursors.query_sql(value)
    if not sql or placeholder_count(sql):
        # No statement recorded for that id, or one whose own binds this does
        # not have. Re-running it with the wrong values would be worse than not
        # running it, so leave the value alone and let the backend answer.
        return value
    return Open(sql, cursors.delivered(value))


def _bind_vars(request: ExecRequest) -> list:
    # Hand the backend each bind whose value alone cannot say what it is,
    # wrapped with the type the client declared for it. For a PL/SQL block that
    # is every bind: the wire carries no direction, so each goes over OUT-capable
    # with its type and return-buffer size (#483), and the client keeps only the
    # positions it bound as a Var. For any other statement it is a NULL bind: a
    # NULL carries no type, the client may have declared one (setinputsizes)
    # for exactly that reason, and a backend that cannot infer it has nothing
    # else to go on (#699). A character value carries the buffer size the client
    # declared, which Oracle describes a bind by (#2063). Any other value passes
    # through unchanged, as does everything on a shape mismatch.
    if not request.binds or len(request.bind_meta) != len(request.binds):
        return request.binds
    block = is_plsql(request.sql)
    arrays = request.bind_arrays or [0] * len(request.binds)
    # The per-bind type OID (an object / REF bind carries it in the OAC) rides on
    # bind_types as the 4th field; thread it so an object OUT / typed-NULL bind
    # keeps its type identity even when its value is None (#888).
    toids = [(bt[3] if len(bt) > 3 else b'') for bt in (request.bind_types or [])] or [
        b''
    ] * len(request.binds)
    # The charset form rides on bind_types as the 2nd field. A national bind is
    # the ordinary type plus csfrm 2, so a backend given tns_type alone binds
    # NVARCHAR2 as VARCHAR2 and a PL/SQL table of the former rejects it (#990).
    forms = [(bt[1] if len(bt) > 1 else _CSFRM_DB) for bt in (request.bind_types or [])]
    forms = forms or [_CSFRM_DB] * len(request.binds)
    return [
        BindVar(
            value=value,
            tns_type=tns_type,
            max_size=size,
            array_size=capacity,
            csfrm=csfrm,
            toid=toid,
        )
        if block or value is None
        else VarcharValue.of(value, size)
        if type(value) is str and tns_type in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR)
        else value
        for value, (tns_type, size), capacity, csfrm, toid in zip(
            request.binds, request.bind_meta, arrays, forms, toids
        )
    ]


def _park_nested_cursors(
    rows: list[tuple], columns: list[ColumnMeta], cursors: _Cursors
) -> list[tuple]:
    # Replace every CursorResult cell with a NestedCursor naming a freshly parked
    # cursor. A result with no cursor column returns untouched, so the ordinary
    # path allocates nothing (#826).
    positions = [
        index
        for index, col in enumerate(columns)
        if col.data_type == TNS_TYPE_REFCURSOR
    ]
    if not positions:
        return rows
    out = []
    for row in rows:
        cells = list(row)
        for index in positions:
            value = cells[index] if index < len(cells) else None
            if isinstance(value, CursorResult):
                # Recursive: a nested cursor may itself select a CURSOR(...)
                # column, so park ITS cursors before parking it (#826).
                inner = _park_nested_cursors(list(value.rows), value.columns, cursors)
                cells[index] = NestedCursor(
                    columns=value.columns,
                    cursor_id=cursors.open(value.columns, inner),
                )
        out.append(tuple(cells))
    return out


def _out_bind_entries(
    out_binds: list,
    bind_meta: list,
    cursors: _Cursors,
    bind_arrays: Sequence = (),
    bind_types: Sequence = (),
) -> list[ScalarOutBind | ArrayOutBind | RefCursorOutBind]:
    # Turn the backend's OUT bind values into IOV reply entries (#483). A scalar
    # rides with its declared type; an associative array as its element list
    # (#743); a REF CURSOR value (CursorResult) has its rows parked on a fresh
    # cursor id the client then drains with TTI_FETCH.
    entries: list[ScalarOutBind | ArrayOutBind | RefCursorOutBind] = []
    arrays = list(bind_arrays) or [0] * len(bind_meta)
    # The charset form per bind, from the OACs the client sent. A national
    # (NCHAR / NVARCHAR2) bind's text goes back as UTF-16BE, as it does in a row
    # -- sent as UTF-8 the client reads two bytes per character (#826).
    forms = [entry[1] for entry in bind_types] or [_CSFRM_DB] * len(bind_meta)
    for value, (tns_type, _size), capacity, csfrm in zip(
        out_binds, bind_meta, arrays, forms
    ):
        if value is None and tns_type == TNS_TYPE_REFCURSOR:
            # A REF CURSOR bind the client passed IN (#1048). The block fetched
            # from the cursor the Mirror opened for it and, as such a block
            # usually does, closed it -- so there is no result to park and the
            # backend reports nothing for the position. A real server answers
            # the shape #1016 established: no columns and cursor id 0, a closed
            # cursor. Left to the scalar branch below it goes out as a plain
            # NULL, which the client reads as the start of a REF CURSOR value
            # and then waits for a describe that never comes -- a HANG.
            entries.append(RefCursorOutBind(columns=[], cursor_id=0))
            continue
        if isinstance(value, CursorResult):
            # A REF cursor the block never OPENED is reported with cursor id 0
            # and no columns, and the client keys on the id: executing a ref
            # cursor whose id is 0, with no statement of its own, is what makes
            # it raise rather than hand back an empty result. Parking this one
            # like any other gave the caller a perfectly valid handle to a
            # cursor that does not exist, so a fetch returned nothing instead of
            # failing -- silently empty, which cannot be told from a cursor
            # opened over no rows (#1016).
            #
            # Zero columns is a sound signal: a REF cursor that really was
            # opened always describes at least one, because `open c for <query>`
            # requires a query.
            if not value.columns:
                entries.append(RefCursorOutBind(columns=[], cursor_id=0))
                continue
            # Its rows may hold cursors of their own -- a CURSOR(...) column --
            # each needing a parked cursor before the rows can be served (#1465).
            rows = _park_nested_cursors(list(value.rows), value.columns, cursors)
            cursor_id = cursors.open(value.columns, rows)
            entries.append(RefCursorOutBind(columns=value.columns, cursor_id=cursor_id))
        elif capacity:
            entries.append(
                ArrayOutBind(values=list(value or []), tns_type=tns_type, csfrm=csfrm)
            )
        else:
            entries.append(ScalarOutBind(value=value, tns_type=tns_type, csfrm=csfrm))
    return entries


def _answer_query(
    stream: PacketStream,
    backend: Backend,
    request: ExecRequest,
    cursors: _Cursors,
    object_lobs: list[tuple[bytes, bool]] | None = None,
) -> list[tuple[bytes, bool]]:
    # Run the query and reply. Any failure becomes an ORA error on a healthy
    # connection — the Mirror must never desync, so even a backend that leaks a
    # native exception is caught and reported rather than dropping the wire.
    # Returns the LOB contents the result's rows carry (row-major), which the thin
    # loop drains as the client issues its TTI_LOBOPS reads (#413).
    lobs: list[tuple[bytes, bool]] = []
    # Per-row failures collected in array-DML batcherrors mode (#18).
    batch_errors: list[tuple[int, int, str]] = []
    # The per-iteration affected-row counts, when the client asked for them
    # (arraydmlrowcounts). They ride in front of whatever reply follows -- a
    # success, the batcherrors summary, or the error that aborted the batch
    # (#1031).
    per_iteration: list[int] = []
    # Cursor cache (#80/#486): a re-execute carries the cached cursor id and an
    # empty query, so resolve the SQL the Mirror parked for that id and reuse the
    # id in the reply. A fresh statement runs its own SQL and is assigned a new id
    # below if it is DML.
    reused_id = request.cursor if (request.cursor and not request.sql) else 0
    sql = cursors.dml_sql(request.cursor) if reused_id else request.sql
    if sql is None and reused_id:
        # Not a DML cursor -- a QUERY cursor being re-executed. The reference
        # client does that for a LOB-class result: it reads the describe, marks
        # the statement "requires define", and re-executes by id with no SQL to
        # apply the define before any row arrives (#887). Resolve the query the
        # id stands for, or the empty statement reaches the backend as
        # ORA-01009.
        sql = cursors.query_sql(request.cursor)
    if sql is None:
        sql = request.sql
    # A cached cursor's recorded bind format is what an OAC-less re-execute
    # decodes with. Recorded once at open, it went stale as soon as the client
    # re-described its binds mid-stream (#999).
    if reused_id:
        cursors.set_bind_types(reused_id, request.bind_types)
    if (
        reused_id
        and cursors.has(reused_id)
        and (
            _defers_inline_rows(cursors.columns(reused_id))
            or (
                cursors.query_sql(reused_id) is None
                and cursors.dml_sql(reused_id) is None
            )
        )
    ):
        # Two cases serve parked rows on a re-execute rather than re-running SQL:
        #   * the define round-trip for a LOB-class result (#887): the first
        #     execute ran the query, sent the describe alone and parked every
        #     row; this call is the client applying its define and asking for
        #     them (re-running would lose the column metadata the reply needs);
        #   * a REF CURSOR OUT bind's nested cursor (#888): python-oracledb
        #     drains an attrs_rc-style cursor by re-executing its id with an
        #     empty statement, but the cursor has no statement of its own
        #     (`cursors.open(sql=None)`), so there is nothing to re-run and the
        #     empty query would reach the backend as ORA-01009.
        # A query that parked its remainder keeps its SQL, so it re-runs instead.
        # A REF CURSOR re-execute is a fresh open of that cursor, so the reply
        # carries the describe + rows (encode_query_response); the LOB define
        # round-trip already has the describe and takes only rows (#887/#888).
        is_refcursor = (
            cursors.query_sql(reused_id) is None and cursors.dml_sql(reused_id) is None
        )
        # This is an EXECUTE, so its fetch field is a PREFETCH and a zero there
        # means "send me no rows now" -- the same rule `_prefetch_batch` applies
        # to the opening execute (#856). Reading the zero as "all of them" made
        # the define round-trip deliver the whole result inline, so a client that
        # set prefetchrows = 0 decoded its values during execute() instead of on
        # the fetch it was waiting to issue (#1113). The rows stay parked and the
        # reply says `more`, so the client's TTI_FETCH collects them.
        # A REF CURSOR re-execute is a fresh open rather than a continuation, and
        # no capture says what a real server prefetches for one, so it keeps the
        # older reading until one does.
        if is_refcursor:
            count = request.fetch if request.fetch > 0 else _ALL_ROWS
        else:
            count = _ALL_ROWS if request.fetch < 0 else request.fetch
        columns_out, batch = cursors.take(reused_id, count)
        # Honour what the define actually asked for. A client fetching a LOB as
        # string / bytes defines the column as LONG (RAW), and a real server then
        # sends the value inline in the row instead of a locator -- which is why
        # such a client issues no TTI_LOBOPS read for it (#826). The define is
        # applied once and then STANDS, so remember it against the cursor: a
        # re-execute carries none and would otherwise revert to locators.
        cursors.set_defines(reused_id, request.define_types)
        columns_out = inline_long_for_defines(columns_out, cursors.defines(reused_id))
        # Queue the content of the LOB cells in the rows THIS reply delivers.
        # Returning the function-local (empty) list here wiped the queue the
        # opening execute had built, so every follow-up TTI_LOBOPS read found
        # nothing and handed the client an empty LOB (#903).
        lobs = oci_lob_contents(columns_out, batch)
        encode_reexecute = (
            encode_query_response if is_refcursor else encode_fetch_response
        )
        stream.write_packet(
            TNS_DATA,
            encode_reexecute(
                columns_out,
                batch,
                cursor_id=reused_id,
                more=cursors.has(reused_id),
            ),
        )
        return lobs
    # Which backend call a statement ends up in is the first thing worth knowing
    # when a reply is wrong, and it is not obvious from the SQL: a PL/SQL block
    # whose body happens to contain `RETURNING ... INTO` used to land in the
    # RETURNING path and hang there (#826). One line per statement, so no guard.
    logger.debug(
        'execute dispatch: parse_only=%s return_binds=%s iterations=%s '
        'bind_rows=%s cached_id=%s sql=%.60r',
        request.parse_only,
        sorted(request.return_binds) if request.return_binds else [],
        request.iterations,
        len(request.bind_rows),
        reused_id,
        redact_passwords(sql),
    )
    try:
        if request.parse_only:
            # `cursor.parse()`: parse the statement, do NOT run it (#826). It
            # carries no bind values, so running it anyway reached the backend as
            # ORA-01008 -- which is what every parse in the reference suite hit.
            # A query owes the describe (the DESCRIBE option rides with PARSE) and
            # a plain success status; a DML / PL/SQL parse owes the status alone.
            stream.write_packet(TNS_DATA, _answer_parse(backend, sql, request))
            return lobs
        if reused_id and is_plsql(sql):
            # A PL/SQL block re-executed by its cursor id (#1064). Once the block
            # has an id the client stops sending it one iteration at a time and
            # re-executes the remaining rows as one array call, with values for
            # the binds that take one and nothing for the rest. Captured off a
            # live 23ai, the reply is one TTI_RXD per iteration carrying that
            # iteration's OUT values -- and NO IOV: the directions were settled
            # by the opening execute and are not restated (§6.5c).
            lobs += _answer_block_reexecute(
                stream, backend, sql, request, cursors, reused_id
            )
            return lobs
        if request.return_binds:
            # DML ... RETURNING col INTO :b (#689). The reply owes one set of
            # returned values per iteration, so this cannot go through the
            # ordinary DML paths below, which report only a row count.
            result = _run_returning(backend, sql, request, cursors)
            if request.autocommit:
                backend.commit()
            _mark_transaction(sql, request.autocommit)
            stream.write_packet(
                TNS_DATA,
                encode_returning_response(
                    result.rowcount,
                    result.returned_rows,
                    [request.bind_meta[i][0] for i in sorted(request.return_binds)],
                    # What the client declared for each receiving variable. A
                    # value longer than its buffer is cut to it and its real
                    # length written after it, which is the only way a client
                    # learns its variable was too small (#1023).
                    max_sizes=[
                        request.bind_meta[i][1] for i in sorted(request.return_binds)
                    ],
                ),
            )
            return lobs
        # An array execute whose every row is empty (executemany of a no-bind
        # INSERT, [{}, {}, {}]) carries no TTI_RXD, so bind_rows is empty; its
        # al8i4 iteration count still says how many rows to apply (#33). Stand in
        # that many empty bind rows so the array path runs once per iteration.
        iter_rows = request.bind_rows or [[] for _ in range(request.iterations)]
        if len(iter_rows) > 1:
            # Array DML (executemany): apply each bind row and report the total
            # affected-row count — one execute message, one aggregated reply.
            execute_many = getattr(backend, 'execute_many', None)
            rowcounts = getattr(backend, 'execute_many_rowcounts', None)
            if (
                request.arraydmlrowcounts
                and rowcounts is not None
                and not request.batcherrors
            ):
                # The client asked for the per-iteration affected-row counts
                # (arraydmlrowcounts): get them from the backend and return them
                # in front of the status (#18). Same one-round-trip array DML.
                total, per_iter = rowcounts(sql, iter_rows)
                stream.write_packet(
                    TNS_DATA, encode_status_with_rowcounts(total, per_iter)
                )
                if request.autocommit:
                    backend.commit()
                return lobs
            if execute_many is not None and not request.batcherrors:
                # Fast path: hand the whole array to the backend so it can send it
                # in one round-trip (a per-row loop against a remote backend paid
                # its network latency once per row). A per-row failure aborts the
                # batch — exactly Oracle's non-batcherrors behaviour. batcherrors
                # keeps the per-row path below so each failure can be attributed.
                applied_many = execute_many(sql, iter_rows)
                # An int is the affected-row count; a Result also carries the
                # last row's rowid (#1077).
                result = (
                    applied_many
                    if isinstance(applied_many, Result)
                    else Result(rowcount=applied_many)
                )
            else:
                # Per row: needed for batcherrors (the good rows still apply and a
                # per-row failure is collected as (offset, code, message) rather
                # than aborting the batch), and the fallback for a backend that
                # offers no array path.
                affected = 0
                last_rowid = None
                for offset, row in enumerate(iter_rows):
                    try:
                        applied_row = backend.execute(sql, row)
                        applied = applied_row.rowcount
                        affected += applied
                        last_rowid = applied_row.last_rowid or last_rowid
                        per_iteration.append(applied)
                    except BackendError as err:
                        if not request.batcherrors:
                            # The rows before this one applied, and the client
                            # is told how many in the error's own rowcount
                            # field. Attaching it HERE rather than in a backend
                            # is what makes every backend report it, not just
                            # one that happens to track the count itself (#998).
                            err.rowcount = affected
                            err.row_counts = per_iteration
                            raise
                        # A row that failed affected nothing, and its slot still
                        # belongs in the counts -- they are per ITERATION, so
                        # dropping it would shift every count after it (#1031).
                        per_iteration.append(0)
                        batch_errors.append((offset, err.ora_code, err.ora_message))
                result = Result(rowcount=affected, last_rowid=last_rowid)
        else:
            result = backend.execute(
                sql, _resolve_refcursor_in_binds(backend, cursors, _bind_vars(request))
            )
        # Autocommit mode: the client set the commit-on-success option, so
        # persist this statement before replying (an explicit-transaction client
        # leaves the bit clear and drives commit/rollback itself).
        if request.autocommit:
            backend.commit()
        _mark_transaction(sql, request.autocommit)
        # Build the reply inside the same guard: encoding the result must honour
        # the never-desync contract too. A value the wire can't carry (e.g. a
        # backend that hands back a type the encoder has no branch for) raises
        # here, and that has to surface as a clean ORA error below — not escape
        # and drop the connection mid-response (#535).
        if batch_errors:
            # Array-DML batcherrors: ORA-24381 with the per-row failure arrays;
            # the client reads them from getbatcherrors() rather than raising.
            response = encode_batch_errors_status(
                result.rowcount,
                _order_batch_errors(batch_errors),
                per_iteration if request.arraydmlrowcounts else None,
            )
            stream.write_packet(TNS_DATA, response)
            return lobs
        # A PL/SQL block that called DBMS_SQL.RETURN_RESULT hands its result sets
        # back as a TTI_IRD block naming one server cursor per set, which the
        # client then fetches like a REF CURSOR (#121/#826). Park each set on a
        # cursor of its own first, so the fetches that follow find their rows.
        # A block with OUT binds as well sends both, its values first (#2295).
        implicit = b''
        if result.implicit_results:
            named = [
                (columns, cursors.open(columns, list(rows)))
                for columns, rows in result.implicit_results
            ]
            implicit = encode_implicit_results(named)
            if not result.out_binds:
                stream.write_packet(TNS_DATA, implicit + encode_status(0))
                return lobs
        # A PL/SQL block that assigned OUT binds returns them as an IOV vector
        # (the client keeps only its Var positions); this precedes the column /
        # status branches — a block carries neither rows nor a rowcount (#483).
        if result.out_binds:
            # The block gets a server cursor of its own, like any other reusable
            # statement. A client keeps a PL/SQL block in SINGLE-EXECUTE mode for
            # as long as its cursor id is 0 -- `requires_single_execute()` reads
            # exactly that -- because the IN/OUT split is only settled once the
            # block has run. Answering 0 forever made an executemany of a block
            # re-send every row as its own execute, which is merely slow until
            # the client pipelines, and then walks off the end of its own bind
            # array (#1064).
            block_id = reused_id or cursors.open_dml(sql, request.bind_types)
            directions = result.bind_directions or _inferred_directions(
                sql, len(result.out_binds)
            )
            # Remember the directions with the cursor: the re-execute that id
            # invites carries values only for the binds that send one (#1064).
            cursors.set_bind_directions(block_id, directions)
            response = encode_out_bind_response_thin(
                _out_bind_entries(
                    result.out_binds,
                    request.bind_meta,
                    cursors,
                    request.bind_arrays,
                    request.bind_types,
                ),
                directions,
                cursor_id=block_id,
                implicit_results=implicit,
            )
        # A query carries result columns (even with zero rows); a DDL/DML
        # statement carries none and gets a bare success status instead of a
        # describe — the client expects one or the other, not both.
        elif result.columns:
            rows = list(result.rows)
            # A define the client applied to this cursor still stands. It is sent
            # ONCE, on the round-trip after the first describe, and a re-execute
            # carries none -- so a re-run reverted to LOB-class handling: another
            # describe the client was not expecting, then a locator for a column
            # it reads as bytes. With the defines applied the columns are no
            # longer LOB-class to this client, which also stops the deferral
            # below (#826).
            standing_defines = cursors.defines(reused_id)
            columns = inline_long_for_defines(list(result.columns), standing_defines)
            # A nested-cursor cell (`select ..., CURSOR(select ...)`) arrives as a
            # whole result set. Park each one's rows under an id of its own and
            # leave a marker naming it, the way a REF CURSOR OUT bind is served --
            # the client fetches them by that id afterwards (#826).
            rows = _park_nested_cursors(rows, columns, cursors)
            # A LOB result's rows carry locators; the client reads their content
            # row-major over TTI_LOBOPS, so queue every cell's content in that
            # order for the loop to drain (#413).
            lobs = oci_lob_contents(columns, rows)
            # Object columns queue their embedded LOB attributes separately, on a
            # persistent queue routed by a distinct locator: populating an object
            # type after the describe runs get_type_shape queries that reset the
            # transient LOB queue before the client issues its reads (#888). A
            # metadata query carries no object LOBs, so it leaves the queue as-is.
            if object_lobs is not None:
                these_object_lobs = object_lob_contents(columns, rows)
                if these_object_lobs:
                    object_lobs[:] = these_object_lobs
            # Send the first `fetch` rows now; park any remainder on a cursor for
            # the client's follow-up TTI_FETCH calls. A result that fits is
            # delivered whole, ending with ORA-01403; a zero prefetch sends none
            # of it inline (#856).
            batch_size = _prefetch_batch(request.fetch, len(rows))
            if _defers_inline_rows(columns):
                # A result carrying a LOB-class column (CLOB / BLOB / JSON /
                # VECTOR) delivers NO rows in the execute reply, whatever the
                # client's prefetch asked for: the reference client marks such a
                # statement "requires define, no prefetch" the moment it reads
                # the describe, and then reads whatever follows the describe as
                # the next message rather than as row data (#887). A live server
                # does the same -- it defers even a single row this way (§11.9).
                batch_size = 0
            first, remaining = rows[:batch_size], rows[batch_size:]
            if remaining:
                cursor_id = cursors.open(
                    columns,
                    remaining,
                    sql=sql,
                    bind_types=request.bind_types,
                    delivered=len(first),
                )
                # A re-run mints a FRESH id, so the defines standing on the one
                # the client re-executed have to travel with it -- otherwise the
                # next re-execute finds none and reverts to LOB-class handling
                # (#826).
                cursors.set_defines(cursor_id, standing_defines)
                response = encode_query_response(
                    columns, first, cursor_id=cursor_id, more=True
                )
            else:
                # Mint an id even though nothing is parked: the terminator
                # reports it and the client caches it against this statement, so
                # a query with no leftover rows still needs an identity of its
                # own (#840).
                cursor_id = cursors.open_query(sql, request.bind_types, columns)
                cursors.set_defines(cursor_id, standing_defines)
                response = encode_query_response(columns, first, cursor_id=cursor_id)
        else:
            # DML / DDL success. Hand back a server cursor id (reused on a cached
            # re-execute, freshly minted otherwise) so the client's cursor cache
            # can re-run this DML by id (#80/#486). A PL/SQL block needs one for a
            # second reason: until it has an id, a client keeps re-sending the
            # block one iteration at a time (#1064).
            cursor_id = reused_id
            if not cursor_id:
                cursor_id = cursors.open_dml(sql, request.bind_types)
            # A CREATE whose PL/SQL object compiled with errors SUCCEEDS and
            # says so only through the OER's warn bit (§6.3a, #995).
            response = encode_status(
                result.rowcount,
                cursor_id=cursor_id,
                compilation_warning=result.compilation_warning,
                rowid=result.last_rowid,
            )
            # `alter session set current_schema = X` does not just succeed: the
            # server reports the new value back, and that is the ONLY place a
            # client learns it -- `connection.current_schema` never queries. A
            # bare status left the attribute stale for the life of the session
            # (#973).
            schema = altered_current_schema(sql)
            edition = altered_edition(sql)
            if schema is not None:
                response = encode_session_state_response(schema) + response
            elif edition is not None:
                response = (
                    encode_session_state_response(edition, key=_STATE_KEY_EDITION)
                    + response
                )
    except BackendError as err:
        logger.info('query refused: %s', err.ora_message)
        # An executemany that aborted part-way applied the earlier rows; report
        # how many, in the same field a success reports its count (#998) -- and
        # their per-iteration counts too when the client asked for those, or it
        # reads the mode as never enabled and learns nothing about the rows that
        # did apply (#1031).
        response = encode_error(
            err.ora_code, err.ora_message, err.error_offset, rowcount=err.rowcount
        )
        if err.row_counts:
            response = encode_rowcounts_block(err.row_counts) + response
    except Exception as exc:
        logger.warning('backend raised a non-ORA error: %s', exc)
        response = _backend_fault_error(exc)
    stream.write_packet(TNS_DATA, response)
    return lobs


# The error codes a real server reports in a SECOND pass over an array DML,
# after every other row error. Measured on a live 23ai with a batch failing on
# several codes at once, each ordering deliberately reversed against the row
# order:
#
#   dup@1 check@2 big@3 -> [(2, ORA-02290), (3, ORA-01438), (1, ORA-00001)]
#   dup@2        big@4  -> [(4, ORA-01438), (2, ORA-00001)]
#   dup@1        dup@3  -> [(1, ORA-00001), (3, ORA-00001)]
#
# So it is not an ordering on the codes: everything else comes in row order and
# the unique-constraint violations come after it, each group ascending. That is
# what index maintenance being a separate pass looks like from outside -- a
# column conversion (ORA-01438), a NOT NULL (ORA-01400) and even a CHECK
# constraint (ORA-02290) are evaluated with the row, while the unique index is
# updated afterwards. Only ORA-00001 was measured; a foreign key is presumably
# the same pass but is not claimed here.
_INDEX_PHASE_ERRORS = frozenset({ORA_UNIQUE_CONSTRAINT_VIOLATED})


def _order_batch_errors(
    errors: list[tuple[int, int, str]],
) -> list[tuple[int, int, str]]:
    # Put the index-phase failures after the rest, each keeping row order, the
    # way a real server reports them (#1031). The Mirror applies the rows one at
    # a time, so it collects every error in row order and has to re-group; the
    # sort is stable, which is what keeps each group ascending.
    return sorted(errors, key=lambda e: e[1] in _INDEX_PHASE_ERRORS)


def _answer_block_reexecute(
    stream: PacketStream,
    backend: Backend,
    sql: str,
    request: ExecRequest,
    cursors: _Cursors,
    cursor_id: int,
) -> list[tuple[bytes, bool]]:
    """Run a PL/SQL block re-executed by cursor id and reply (#1064).

    The client re-executes a block by id once the Mirror has given it one, and
    an ``executemany`` then sends the remaining rows as a single array call.
    Each iteration has to run on its own -- a block's OUT binds are per
    iteration, and a backend's array path reports a row count, not values -- so
    this loops, keeps each iteration's OUT binds, and answers with one TTI_RXD
    apiece.

    The directions recorded when the block first ran say which positions the
    rows carry a value for; the rest are None in every row and must not be
    handed to the backend as a bound NULL.
    """
    directions = cursors.bind_directions(cursor_id)
    # A block whose binds are ALL pure-OUT sends no row at all -- there is
    # nothing to put in one -- and a block with no binds sends none either; the
    # iteration count is all the message carries then (#33). Stand in a row of
    # the right width so every bind still reaches the backend as an OUT-capable
    # position, or the block runs with its placeholders unbound (ORA-01008).
    rows = request.bind_rows or [
        [None] * len(request.bind_meta) for _ in range(max(request.iterations, 1))
    ]
    iterations = []
    rowcount = 0
    lobs: list[tuple[bytes, bool]] = []
    for done, row in enumerate(rows):
        one = replace(request, sql=sql, binds=list(row), bind_rows=[list(row)])
        try:
            result = backend.execute(
                sql, _resolve_refcursor_in_binds(backend, cursors, _bind_vars(one))
            )
        except BackendError as err:
            # Which iteration failed is carried by the OER's rowcount field, and
            # it is the only way the client can say so: it reports the offset as
            # this count plus however many iterations it ran before sending this
            # message. Leaving it at zero blamed the first row for every failure
            # (#1064).
            err.rowcount = done
            raise
        rowcount += result.rowcount
        iterations.append(
            _out_bind_entries(
                result.out_binds,
                request.bind_meta,
                cursors,
                request.bind_arrays,
                request.bind_types,
            )
            if result.out_binds
            else []
        )
    if request.autocommit:
        backend.commit()
    _mark_transaction(sql, request.autocommit)
    if any(iterations):
        response = encode_out_bind_reexecute_thin(
            iterations,
            directions,
            cursor_id=cursor_id,
            with_iov=not request.from_reexecute,
        )
    else:
        # A block that assigns nothing owes only a status, as its first execute
        # does -- there is no IOV and no row data to carry.
        response = encode_status(rowcount, cursor_id=cursor_id)
    stream.write_packet(TNS_DATA, response)
    return lobs


def _answer_parse(backend: Backend, sql: str, request: ExecRequest) -> bytes:
    """The reply to a `cursor.parse()` — parse, never run (#826).

    A DML or PL/SQL parse owes a bare success status. A query parse also owes the
    describe, so its columns have to come from somewhere: a backend that can
    describe a statement without running it says so with a ``describe`` method,
    and otherwise the query is run with every bind NULL and its rows discarded.
    That is safe for a SELECT, which is the only shape that reaches the fallback,
    and it validates the statement the way a real parse does.

    A status is the whole reply for a non-query, and answering it from here is
    how every parse-time error used to be lost: nothing parsed the statement, so
    `returning IntCol into :ROWID` came back clean where a real server answers
    ORA-01745 (#1019). A backend that can validate a statement without running
    it says so with a ``parse`` method and gets asked. One that cannot keeps the
    bare status — the PostgreSQL and SQLite demos cannot parse Oracle SQL, and
    claiming a statement is good is the only answer they can give.
    """
    if not request.describe_only:
        parse = getattr(backend, 'parse', None)
        if parse is not None:
            parse(sql)
        return encode_status(0)
    describe = getattr(backend, 'describe', None)
    if describe is not None:
        columns = list(describe(sql))
    else:
        # A parse carries NO bind values, so request.bind_count is 0 however many
        # placeholders the statement has. Count them in the text instead, or the
        # fallback runs `where IntCol = :val` with nothing bound and the backend
        # answers the very ORA-01008 this branch exists to avoid.
        placeholders = placeholder_count(sql)
        columns = list(backend.execute(sql, [None] * placeholders).columns or [])
    # Describe + a plain success status, NOT encode_query_response: that ends a
    # batch with the end-of-fetch ORA-01403, and a parse fetched nothing.
    return encode_describe(columns) + encode_status(0)


def _answer_scroll(
    stream: PacketStream, backend: Backend, request: ExecRequest, cursors: _Cursors
) -> list[tuple[bytes, bool]]:
    # Serve a server-side scrollable cursor (#181/#485). Two shapes arrive on the
    # same SCROLLABLE-flagged execute: the opening execute (a new cursor, real
    # SQL) runs the query, parks the full result set, and returns describe + the
    # prefetched first batch; a scroll re-execute (an open scroll cursor id, no
    # SQL) repositions within the parked rows per the fetch orientation + 1-based
    # position and returns just that batch. The client places its buffer window
    # from the cumulative row number the terminator carries.
    state = cursors.scroll_state(request.cursor)
    if state is not None:
        # Reposition: slice the parked rows and reply with no describe.
        columns, rows = state
        total = len(rows)
        start = scroll_start_row(
            request.scroll_orientation, request.scroll_position, total
        )
        size = request.fetch if request.fetch > 0 else total
        if start < 1 or start > total:
            # Scrolled off either end: an empty batch ending in ORA-01403.
            stream.write_packet(
                TNS_DATA, encode_scroll_response([], [], server_rowcount=0, eof=True)
            )
            return []
        batch = rows[start - 1 : start - 1 + size]
        last_abs = start - 1 + len(batch)
        stream.write_packet(
            TNS_DATA,
            encode_scroll_response(
                columns, batch, server_rowcount=last_abs, eof=last_abs >= total
            ),
        )
        return oci_lob_contents(columns, batch)
    # Opening execute: run the query and park the whole result for later scrolls.
    try:
        result = backend.execute(request.sql, request.binds)
        if request.autocommit:
            backend.commit()
        _mark_transaction(request.sql, request.autocommit)
    except BackendError as err:
        logger.info('scrollable query refused: %s', err.ora_message)
        stream.write_packet(
            TNS_DATA, encode_error(err.ora_code, err.ora_message, err.error_offset)
        )
        return []
    except Exception as exc:
        logger.warning('backend raised a non-ORA error: %s', exc)
        stream.write_packet(TNS_DATA, _backend_fault_error(exc))
        return []
    columns = result.columns
    rows = _park_nested_cursors(list(result.rows), columns, cursors)
    cursor_id = cursors.open_scroll(columns, rows, sql=request.sql or None)
    size = _prefetch_batch(request.fetch, len(rows))
    batch = rows[:size]
    last_abs = len(batch)
    # The rows this open hands over are rows the client has; a block that later
    # binds this cursor resumes after them (#1048).
    cursors.note_delivered(cursor_id, last_abs)
    stream.write_packet(
        TNS_DATA,
        encode_scroll_open_response(
            columns,
            batch,
            cursor_id,
            server_rowcount=last_abs,
            eof=last_abs >= len(rows),
        ),
    )
    return oci_lob_contents(columns, batch)


def _answer_reexecute(
    stream: PacketStream,
    backend: Backend,
    request: ReexecuteRequest,
    cursors: _Cursors,
) -> list[tuple[bytes, bool]]:
    """Re-run the statement a cursor already holds and return its first batch.

    A client caches a statement against the cursor id the server reported and
    then re-executes by that id alone -- the request carries no SQL (#833). So
    this is an execute whose statement comes from the cursor, and a reply in the
    shape of a fetch: rows and a terminator, no describe, because the client
    established the column metadata on the first execute and does not expect it
    again.

    An id the Mirror does not know is answered with an empty batch rather than an
    error. That is what a drained cursor looks like, and it keeps a client that
    re-executes something the Mirror has forgotten moving instead of failing.
    """
    sql = cursors.query_sql(request.cursor)
    if sql is None:
        stream.write_packet(
            TNS_DATA, encode_fetch_response([], [], cursor_id=request.cursor)
        )
        return []
    try:
        # WITH the request's fresh bind values. This path used to run the
        # statement bare, which is right only for a query that has no binds --
        # what #833's tests happened to use. Re-executing `select ... :1` then
        # reached the backend with nothing bound and failed with ORA-01008, so
        # the second and every later iteration of a loop over one query died
        # (#873). The sibling func-4 path has carried its rows since #854; this
        # is the same for func 78.
        result = backend.execute(sql, request.bind_rows[0] if request.bind_rows else ())
    except BackendError as err:
        logger.info('re-execute refused: %s', err.ora_message)
        stream.write_packet(
            TNS_DATA, encode_error(err.ora_code, err.ora_message, err.error_offset)
        )
        return []
    except Exception as exc:  # noqa: BLE001 - never desync on a backend fault
        logger.warning('backend raised a non-ORA error: %s', exc)
        stream.write_packet(
            TNS_DATA,
            _backend_fault_error(exc),
        )
        return []
    # A column whose type changed to CLOB / BLOB under this cached cursor keeps
    # being served the way the client's variable still reads it -- inline as LONG
    # (RAW) rather than as a locator (#826). Apply that before anything reads the
    # columns, so the row encoder and the LOB queue agree on which cells are
    # inline. Read the prior describe first: reopen() below replaces it.
    previous = cursors.describe_columns(request.cursor)
    columns = inline_long_after_type_change(list(result.columns or []), previous)
    # A define the client applied to this cursor earlier still stands: it is sent
    # once, on the round-trip after the first describe, and a re-execute carries
    # none. Reverting to locators here desynced a client that was still reading
    # the column as a string / bytes (#826).
    columns = inline_long_for_defines(columns, cursors.defines(request.cursor))
    rows = _park_nested_cursors(list(result.rows), columns, cursors)
    lobs = oci_lob_contents(columns, rows) if columns else []
    # The request's iteration count is the client's prefetch size, so it is also
    # the batch size. Anything past it is parked on the SAME cursor id the client
    # already holds, so its follow-up fetches address the statement it just ran.
    batch_size = _prefetch_batch(request.fetch, len(rows))
    first, remaining = rows[:batch_size], rows[batch_size:]
    # A re-execute normally omits the describe -- the client kept it from the
    # first execute. But if the statement's column shape changed underneath the
    # cached cursor (a view replaced with different column types, #826), the
    # client would decode these rows with the stale describe; send a fresh one,
    # the way a real server re-describes an invalidated cursor. Compare on the
    # describe as the wire carries it: inline_long_csfrm is a serving decision
    # this reply just made, not a shape change the client needs telling about.
    redescribe = _as_described(columns) != _as_described(previous)
    cursors.reopen(request.cursor, columns, remaining, sql=sql)
    encode = encode_query_response if redescribe else encode_fetch_response
    stream.write_packet(
        TNS_DATA,
        encode(columns, first, cursor_id=request.cursor, more=bool(remaining)),
    )
    return lobs


def _answer_reexecute_binds(
    stream: PacketStream,
    backend: Backend,
    request: ReexecuteRequest,
    cursors: _Cursors,
    temp_lobs: _TempLobs,
) -> list[tuple[bytes, bool]]:
    """Re-run the statement a cursor holds with fresh bind rows (func 4, #854).

    This is what a client sends for every repeated execute of a statement whose
    bind types did not change -- the second iteration onward of a loop of
    inserts -- and for a query re-executed with prefetching off. It is an
    execute without a statement or OACs: the cursor supplies both, the message
    only the values. Captured off a live 23ai:

    - a DML cursor answers with the plain success status -- rowcount and the
      same cursor id -- exactly the OALL8 cached re-execute's reply, so the
      request is reshaped into that execute and served by its path (array rows,
      autocommit, temp-LOB binds and all);
    - a query cursor answers with the same status carrying rowcount 0 and no
      rows: the client drains them with TTI_FETCH, so every row is parked on
      the cursor.

    A cursor id the session does not hold is refused as ORA-01001. Answering
    "done, 0 rows" would lose a write the client believes was made.
    """
    types = cursors.bind_types(request.cursor) or []
    rows = request.bind_rows
    sql = cursors.dml_sql(request.cursor)
    if sql is not None:
        execute = ExecRequest(
            sql='',
            cursor=request.cursor,
            bind_count=len(types),
            fetch=0,
            binds=rows[0] if rows else [],
            bind_rows=rows,
            bind_meta=[(data_type, maxlen) for data_type, _c, maxlen, _o in types],
            bind_types=list(types),
            autocommit=request.autocommit,
            iterations=max(request.fetch, 1),
            from_reexecute=True,
        )
        return _answer_query(
            stream,
            backend,
            _mark_ltz_binds(_resolve_temp_lob_binds(execute, temp_lobs)),
            cursors,
        )
    sql = cursors.query_sql(request.cursor)
    if sql is None:
        stream.write_packet(
            TNS_DATA,
            encode_error(
                ORA_INVALID_CURSOR, f'ORA-{ORA_INVALID_CURSOR:05d}: invalid cursor'
            ),
        )
        return []
    try:
        result = backend.execute(sql, rows[0] if rows else [])
    except BackendError as err:
        logger.info('re-execute refused: %s', err.ora_message)
        stream.write_packet(
            TNS_DATA, encode_error(err.ora_code, err.ora_message, err.error_offset)
        )
        return []
    except Exception as exc:  # noqa: BLE001 - never desync on a backend fault
        logger.warning('backend raised a non-ORA error: %s', exc)
        stream.write_packet(
            TNS_DATA,
            _backend_fault_error(exc),
        )
        return []
    columns = list(result.columns or [])
    all_rows = list(result.rows)
    cursors.reopen(request.cursor, columns, all_rows, sql=sql)
    stream.write_packet(TNS_DATA, encode_status(0, cursor_id=request.cursor))
    return oci_lob_contents(columns, all_rows) if columns else []


def _prefetch_batch(fetch: int, total: int) -> int:
    """How many of ``total`` rows an EXECUTE reply carries inline (#856).

    The execute's fetch field is the client's **prefetch**, and a zero there
    means "send me no rows on the execute" -- the client has allocated no fetch
    buffer and will ask with ``TTI_FETCH`` -- not "send everything". Reading it
    the other way overruns the client's define array: the reference thin client
    dies inside its own row decoder (an ``IndexError`` in ``_process_row_data``)
    before it can turn the reply into an error anyone can read. A real 23ai
    answers a prefetch-0 execute with describe + status and no row data at all
    (captured: 149 bytes, not one ``TTI_RXD`` token in them).

    This is the *execute* rule only. A ``TTI_FETCH``, and a scroll that
    repositions, ask for rows now rather than declaring a prefetch, so a zero
    there keeps meaning "as many as there are".
    """
    return total if fetch < 0 else min(fetch, total)


def _answer_fetch(
    stream: PacketStream, request: FetchRequest, cursors: _Cursors
) -> list[tuple[bytes, bool]]:
    # Deliver the next batch of a parked result set. `take` hands back the
    # columns (the wire needs their types to encode values, though no describe is
    # sent) and the next `fetch` rows, dropping the cursor once it drains; `has`
    # then reports whether more remain. An unknown cursor yields an empty batch
    # terminated by ORA-01403.
    count = request.fetch if request.fetch > 0 else _ALL_ROWS
    columns, batch = cursors.take(request.cursor, count)
    # A define the client applied to this cursor still stands, and stands for the
    # life of the cursor. The rows were parked by the execute, BEFORE the define
    # existed -- a LOB-class result defers its rows, so the define arrives on the
    # round-trip after a describe-only reply -- and the re-execute that carried it
    # applied it only to the batch it served itself. Without applying it here too,
    # a result set larger than one batch carried two framings for the same column:
    # the first rows inline, every later row a locator the client was no longer
    # expecting, which it reports as an unknown message type whose number is the
    # locator's own length byte (#982).
    columns = inline_long_for_defines(columns, cursors.defines(request.cursor))
    # Queue the LOB content of the rows THIS batch delivers. A result too large
    # for one batch hands its later rows out here, and their locators are read
    # over TTI_LOBOPS like any other -- without this the queue held only the
    # rows the execute delivered and every later row's LOB read found nothing
    # (#903).
    lobs = oci_lob_contents(columns, batch) if columns else []
    response = encode_fetch_response(
        columns, batch, cursor_id=request.cursor, more=cursors.has(request.cursor)
    )
    stream.write_packet(TNS_DATA, response)
    return lobs


def _answer_changepassword(
    stream: PacketStream,
    backend: Backend,
    body: bytes,
    conn_key: bytes | None,
    user: str,
    field_version: int = FIELD_VERSION_11_2,
) -> None:
    # Handle a password change on the live session (#21/#486): the client sends a
    # TTI_AUTH reusing the login session key, with the current + new passwords
    # AES-encrypted under it. Decrypt them, drive the backend's change, and answer
    # with a success status (or an ORA error) — the session stays authenticated.
    change = getattr(backend, 'change_password', None)
    if conn_key is None or change is None:
        stream.write_packet(
            TNS_DATA,
            encode_error(
                ORA_INSUFFICIENT_PRIVILEGES,
                f'ORA-{ORA_INSUFFICIENT_PRIVILEGES:05d}: password change not supported',
            ),
        )
        return
    try:
        _user, old_cipher, new_cipher = parse_changepassword(body, field_version)
        old_password = decrypt_password(conn_key, old_cipher).decode('utf-8')
        new_password = decrypt_password(conn_key, new_cipher).decode('utf-8')
    except Exception as exc:
        logger.info('changepassword parse failed: %s', exc)
        stream.write_packet(
            TNS_DATA,
            encode_error(
                ORA_INVALID_USERNAME_PASSWORD,
                f'ORA-{ORA_INVALID_USERNAME_PASSWORD:05d}: invalid credential',
            ),
        )
        return
    try:
        change(user, old_password, new_password)
    except BackendError as err:
        stream.write_packet(TNS_DATA, encode_error(err.ora_code, err.ora_message))
        return
    except Exception as exc:
        logger.warning('backend raised a non-ORA error: %s', exc)
        stream.write_packet(TNS_DATA, _backend_fault_error(exc))
        return
    logger.info('password changed: %s', user)
    stream.write_packet(TNS_DATA, encode_status(0))


def _answer_changepassword_oci(
    stream: PacketStream,
    backend: Backend,
    body: bytes,
    conn_key: bytes | None,
    user: str,
    seq: '_OciSequence',
) -> None:
    # sqlplus PASSWORD (OCIPasswordChange): a TTI_AUTH (unwrapped from its
    # TTI_80SES piggyback by strip_oci_piggyback) carrying AUTH_PASSWORD (current)
    # and AUTH_NEWPASSWORD (new), each AES-encrypted under the login session key —
    # the same two fields as the thin changepassword, in the OCI marshalling.
    # Decrypt both, drive the backend change, and reply with a success status.
    change = getattr(backend, 'change_password', None)
    if conn_key is None or change is None:
        stream.write_packet(
            TNS_DATA,
            encode_error_oci(
                ORA_INSUFFICIENT_PRIVILEGES,
                f'ORA-{ORA_INSUFFICIENT_PRIVILEGES:05d}: password change not supported',
                sequence=seq.next(),
            ),
        )
        return
    try:
        _user, old_cipher, new_cipher = parse_changepassword_oci(body)
        old_password = decrypt_password(conn_key, old_cipher).decode('utf-8')
        new_password = decrypt_password(conn_key, new_cipher).decode('utf-8')
    except Exception as exc:
        logger.info('OCI changepassword parse failed: %s', exc)
        stream.write_packet(
            TNS_DATA,
            encode_error_oci(
                ORA_INVALID_USERNAME_PASSWORD,
                f'ORA-{ORA_INVALID_USERNAME_PASSWORD:05d}: invalid credential',
                sequence=seq.next(),
            ),
        )
        return
    try:
        change(user, old_password, new_password)
    except BackendError as err:
        stream.write_packet(
            TNS_DATA,
            encode_error_oci(err.ora_code, err.ora_message, sequence=seq.next()),
        )
        return
    except Exception as exc:
        logger.warning('backend raised a non-ORA error: %s', exc)
        stream.write_packet(
            TNS_DATA,
            encode_error_oci(
                ORA_INTERNAL_ERROR,
                f'ORA-{ORA_INTERNAL_ERROR:05d}: backend error: {exc}',
                sequence=seq.next(),
            ),
        )
        return
    logger.info('OCI password changed: %s', user)
    seq.next()  # advance the OER counter for parity even though the reply is fixed
    stream.write_packet(TNS_DATA, encode_changepassword_status_oci())


def _answer_txn(stream: PacketStream, backend: Backend, *, commit: bool) -> None:
    # Explicit transaction control: the client's commit() / rollback() each send
    # a bare function message and block for a reply. Drive the backend and answer
    # with a success status; a backend failure is reported as an ORA error rather
    # than dropped (same never-desync rule as the query path).
    try:
        if commit:
            backend.commit()
        else:
            backend.rollback()
        _ENCODE_TXN_IN_PROGRESS.set(False)
    except BackendError as err:
        response = encode_error(err.ora_code, err.ora_message)
    except Exception as exc:
        logger.warning('backend raised a non-ORA error: %s', exc)
        response = _backend_fault_error(exc)
    else:
        response = encode_status(0)
    stream.write_packet(TNS_DATA, response)


def _oci_error_pos(err: Exception) -> int:
    # Where sqlplus draws its `*` for a statement's error: the backend's
    # offset, or 0 when it has none, Oracle's place for an error that has no
    # place in the text, a constraint violation's (#2111). Left to the codec,
    # a missing one was a captured ORA-00942's 14, and every such error
    # pointed into the middle of its statement.
    offset = getattr(err, 'error_offset', None)
    return offset if isinstance(offset, int) else 0


def _answer_txn_oci(
    stream: PacketStream, backend: Backend, seq: _OciSequence, *, commit: bool
) -> None:
    # An OCI commit or rollback call (OCITransCommit / -Rollback): sqlplus 10.2
    # and 11.2 send one after each statement under SET AUTOCOMMIT ON, where
    # 23.26 sets the commit bit in the execute (#2011). It used to be answered
    # without running, so sqlplus printed "Commit complete." and a later
    # rollback took the row (#2102). As the thin loop's _answer_txn: drive the
    # backend, and a failure is the call's ORA error.
    try:
        if commit:
            backend.commit()
        else:
            backend.rollback()
        _ENCODE_TXN_IN_PROGRESS.set(False)
    except BackendError as err:
        response = encode_error_oci(err.ora_code, str(err), sequence=seq.next())
    except Exception as exc:  # noqa: BLE001 - the session survives it
        logger.warning('backend raised a non-ORA error: %s', exc)
        response = encode_error_oci(
            ORA_INTERNAL_ERROR,
            f'ORA-{ORA_INTERNAL_ERROR:05d}: backend error: {exc}',
            sequence=seq.next(),
        )
    else:
        response = encode_commit_status_oci(seq.next())
    stream.write_packet(TNS_DATA, response)


def _answer_sessionless_switch(
    stream: PacketStream, backend: Backend, body: bytes, field_version: int
) -> None:
    # A sessionless transaction begin / resume / suspend (TTI_FUN 103, a TPC
    # switch). Its commit and rollback take the ordinary TTI_COMMIT / TTI_ROLLBACK
    # path. Drive the backend's optional sessionless API and answer with a plain
    # status — the client discards the switch reply (it only checks the operation
    # did not error). A backend without the API still succeeds so the session
    # stays usable; the transaction just is not isolated on it.
    from seerdb.common.tns_consts import TNS_TPC_TXN_START, TPC_BEGIN_RESUME

    operation, flags, timeout, txn_id = parse_tpc_switch(body, field_version)
    try:
        if operation == TNS_TPC_TXN_START and flags & TPC_BEGIN_RESUME:
            resume = getattr(backend, 'sessionless_resume', None)
            if resume is not None:
                resume(txn_id, timeout)
        elif operation == TNS_TPC_TXN_START:
            begin = getattr(backend, 'sessionless_begin', None)
            if begin is not None:
                begin(txn_id, timeout)
        else:  # TNS_TPC_TXN_DETACH
            suspend = getattr(backend, 'sessionless_suspend', None)
            if suspend is not None:
                suspend()
    except BackendError as err:
        stream.write_packet(TNS_DATA, encode_error(err.ora_code, err.ora_message))
        return
    stream.write_packet(TNS_DATA, encode_status(0))
