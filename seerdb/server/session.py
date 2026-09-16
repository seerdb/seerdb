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
import functools
import logging
from collections.abc import Callable, Sequence
from dataclasses import replace
from secrets import token_bytes
from typing import NoReturn, TypeVar

from seerdb.common.crypto import decrypt_password
from seerdb.common.dbobject import ObjectImage
from seerdb.common.exceptions import InterfaceError, NotSupportedError, Truncated
from seerdb.common.oci import (
    OCI_CMD_COMMIT,
    OCI_CMD_ROLLBACK,
    strip_oci_e2e_piggyback,
)
from seerdb.common.sqltext import is_reusable_dml
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    _ENCODE_OCI_CALL_SEQ,
    _ENCODE_OER_SEQ,
    _ENCODE_TXN_IN_PROGRESS,
    _LOB_EMIT_LOG,
    _SERVER_RUNTIME_CAPS,
    _THIN_OBJ_LOB_LOCATOR,
    ArrayOutBind,
    ColumnMeta,
    ExecRequest,
    FetchRequest,
    LobEmitLog,
    ReexecuteRequest,
    RefCursorOutBind,
    ScalarOutBind,
    TempLobRef,
    ddl_command_type,
    decode_dalc,
    decode_ub4,
    encode_batch_errors_status,
    encode_challenge,
    encode_changepassword_status_oci,
    encode_commit_status_oci,
    encode_create_temp_response,
    encode_ddl_status_oci,
    encode_describe_reply_oci,
    encode_dml_status_oci,
    encode_error,
    encode_error_oci,
    encode_fetch_batch_oci,
    encode_fetch_response,
    encode_fetch_terminator_oci,
    encode_lob_describe_oci,
    encode_lob_fetch_rows_oci,
    encode_lob_read_response_oci,
    encode_lob_read_response_thin,
    encode_lobops_ack,
    encode_logoff_status_oci,
    encode_long_fetch_row_oci,
    encode_out_bind_response_oci,
    encode_out_bind_response_thin,
    encode_query_response,
    encode_query_response_oci,
    encode_reexec_row_oci,
    encode_result,
    encode_returning_response,
    encode_scroll_open_response,
    encode_scroll_response,
    encode_status,
    encode_status_oci,
    encode_status_with_rowcounts,
    encode_token_result,
    encode_version_banner_oci,
    is_reexecute_oci,
    is_version_call_oci,
    max_string_size,
    mint_temp_lob_locator,
    object_lob_contents,
    oci_lob_contents,
    parse_describe_oci,
    parse_exec,
    parse_exec_oci,
    parse_fetch,
    parse_free_temp_lobs_piggyback,
    parse_lobops_read,
    parse_lobops_request,
    parse_reexecute,
    parse_tpc_switch,
    peek_exec_cursor,
    scroll_start_row,
    strip_oci_piggyback,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_23_1,
    TNS_CONNECT,
    TNS_DATA,
    TNS_FUNC_REEXECUTE,
    TNS_FUNC_REEXECUTE_AND_FETCH,
    TNS_FUNC_SESSION_STATE,
    TNS_FUNC_SET_END_TO_END_ATTR,
    TNS_FUNC_SET_SCHEMA,
    TNS_FUNC_TPC_TXN_SWITCH,
    TNS_MARKER,
    TNS_MARKER_TYPE_RESET,
    TNS_MSG_TYPE_FAST_AUTH,
    TNS_TYPE_BLOB,
    TNS_TYPE_CLOB,
    TNS_TYPE_JSON,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_VECTOR,
    TNS_VERSION_MIN_LARGE_SDU,
    TTI_ALL8,
    TTI_AUTH,
    TTI_COMMIT,
    TTI_DESCRIBE,
    TTI_FETCH,
    TTI_FUN,
    TTI_LOBOPS,
    TTI_LOGOFF,
    TTI_MSG_TYPE_PIGGYBACK,
    TTI_OCCA,
    TTI_PING,
    TTI_ROLLBACK,
)
from seerdb.server.auth import (
    derive_conn_key,
    encode_challenge_oci,
    encode_result_oci,
    find_fast_auth_osesskey,
    is_token_auth,
    make_challenge,
    parse_auth_response,
    parse_auth_response_oci,
    parse_changepassword,
    parse_changepassword_oci,
    parse_osesskey,
    parse_osesskey_oci,
    parse_token_auth,
    verify_password,
)
from seerdb.server.backend import (
    Backend,
    BackendError,
    BindVar,
    Capability,
    CursorResult,
    Result,
    UnsupportedFeature,
)
from seerdb.server.framing import PacketStream
from seerdb.server.handshake import (
    client_field_version,
    encode_accept,
    encode_ano_null_reply,
    encode_dty_reply,
    encode_fast_auth_reply,
    encode_pro_reply,
    encode_type_reply_sqlplus,
    is_ano_negotiation,
    negotiated_tns_version,
    parse_connect,
    pro_is_sqlplus,
    server_tns_version,
)
from seerdb.server.identity import IDENTITY_11_2, ServerIdentity, server_identity

_T = TypeVar('_T')

logger = logging.getLogger('seerdb.server')

# A generic backend failure that leaked past the Backend contract still becomes
# a clean ORA error rather than a wire desync (ORA-00600, internal error).
_INTERNAL_ERROR = 600

# A fetch count of 0 or less means "no limit" — deliver the whole remainder.
_ALL_ROWS = 2**31


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


def handle_login(
    stream: PacketStream,
    backend: Backend,
    *,
    encryption: str = 'accepted',
    token_public_key: bytes | None = None,
    field_version: int = FIELD_VERSION_11_2,
    min_field_version: int = FIELD_VERSION_11_2,
    tns_version: int | None = None,
    identity: 'ServerIdentity | None' = None,
) -> tuple[str, bool, bytes | None, int | None]:
    """Run the server side of the handshake + O5LOGON.

    Returns ``(username, is_sqlplus, conn_key)`` — the second flag says whether
    the client speaks the classic sqlplus / thick-OCI (deadbeef) dialect, so the
    query loop can answer it in the right marshalling (#265); ``conn_key`` is the
    session key O5LOGON derived (``None`` for token auth), which the thin loop
    reuses to decrypt a later changepassword (#21/#486).

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
    request = parse_connect(_expect(stream, TNS_CONNECT, 'CONNECT'))
    stream.send_raw(encode_accept(request, tns_version=tns_version))
    # From protocol version 315 the post-ACCEPT DATA stream carries a 4-byte
    # packet length instead of the legacy 16-bit length + flags pair (§1.1). The
    # ACCEPT itself is still framed the legacy way — the switch takes effect for
    # everything after it — so flip the stream only once it has gone out.
    if negotiated_tns_version(request, tns_version) >= TNS_VERSION_MIN_LARGE_SDU:
        stream.large = True
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
    # A thin (oracledb/seerdb) client leads its PRO with TTI_PRO; classic
    # sqlplus / thick OCI leads with the `deadbeef` magic and needs the matching
    # reply dialect (#265). Decide on the PRO request and hold it for the DTY
    # reply so both halves speak one dialect.
    sqlplus = pro_is_sqlplus(first)
    stream.send_raw(encode_pro_reply(sqlplus=sqlplus, field_version=field_version))
    after_pro = _expect(stream, TNS_DATA, 'DTY')
    # The client has already picked min(its own, what the PRO reply advertised)
    # and put the result in this packet's capability block, so the session's real
    # version is readable here rather than assumed (#816). None for the fast-auth
    # bundle, whose DTY does not arrive on its own, and for anything unparseable;
    # the caller then keeps its configured version, as before.
    negotiated = client_field_version(after_pro)
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
        # Legacy: the packet just read is the DTY; answer it and read OSESSKEY next.
        stream.send_raw(encode_dty_reply(sqlplus=sqlplus, field_version=field_version))
        if sqlplus:
            # sqlplus / thick OCI runs a third data-type negotiation round after
            # DTY (a `ttc=02` request) before it sends OSESSKEY; a thin client
            # skips it (#265).
            _expect(stream, TNS_DATA, 'TYPE')
            stream.send_raw(encode_type_reply_sqlplus())
        osesskey = _expect(stream, TNS_DATA, 'OSESSKEY')

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
        )
    user = (
        parse_osesskey_oci(osesskey)
        if sqlplus
        else parse_osesskey(osesskey, field_version)
    ).decode('utf-8')
    secret = backend.authenticate(user)
    if secret is None:
        _deny_login(stream, f'unknown user: {user!r}')

    # The thin AUTH may omit AUTH_PASSWORD (bytes | None); the OCI AUTH always
    # carries it. Declare the wider type so both branches unpack cleanly.
    auth_password: bytes | None
    if sqlplus:
        # The OCI challenge template carries a 10-byte salt slot (thin uses 16).
        challenge = make_challenge(secret.encode('utf-8'), salt=token_bytes(10))
        stream.send_raw(encode_challenge_oci(challenge))
        _, client_sesskey, auth_password = parse_auth_response_oci(
            _expect(stream, TNS_DATA, 'AUTH')
        )
    else:
        # The thin challenge follows the session's field version: 12.1+ gets the
        # PBKDF2 shape and derivation, below that the 11g one (#829). The OCI
        # branch above stays 11g -- its dialect is pinned to the captured 11.2
        # identity.
        challenge = make_challenge(secret.encode('utf-8'), field_version=field_version)
        # Fast-auth expects the challenge bundled with the PRO + DTY replies it
        # deferred; legacy sends the challenge on its own.
        if fast_auth:
            stream.write_packet(
                TNS_DATA,
                encode_fast_auth_reply(
                    encode_challenge(challenge), field_version=field_version
                ),
            )
        else:
            stream.write_packet(TNS_DATA, encode_challenge(challenge))
        _, client_sesskey, auth_password = parse_auth_response(
            _expect(stream, TNS_DATA, 'AUTH'), field_version
        )

    conn_key = derive_conn_key(challenge, client_sesskey)
    # Verify the client's password proof (AUTH_PASSWORD) against the account
    # secret — the server half of O5LOGON's mutual auth. Without it the Mirror
    # would serve any client that ignores the server proof it can't validate.
    if not verify_password(conn_key, auth_password, secret.encode('utf-8')):
        _deny_login(stream, f'wrong password for user: {user!r}')
    if sqlplus:
        stream.send_raw(encode_result_oci(conn_key, identity=identity))
    else:
        stream.write_packet(
            TNS_DATA, encode_result(conn_key, version_no=identity.version_no)
        )

    logger.info('login OK: %s', user)
    return user, sqlplus, conn_key, negotiated


def _deny_login(stream: PacketStream, reason: str) -> NoReturn:
    # Reject a login the way Oracle does — an ORA-01017 OER in place of the next
    # auth reply, which the client raises out of connect() — then drop the
    # connection. (Without this the client would connect() cleanly and fail
    # later.) The message is deliberately generic (user vs password not
    # distinguished) as Oracle's ORA-01017 is.
    stream.write_packet(
        TNS_DATA,
        encode_error(1017, 'ORA-01017: invalid username/password; logon denied'),
    )
    raise InterfaceError(f'authentication rejected — {reason}')


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
            _ORA_UNSUPPORTED_CALL,
            f'ORA-{_ORA_UNSUPPORTED_CALL:05d}: unsupported network datatype or '
            f'representation ({exc})',
        )
    # Genuinely unexpected: report it as ORA-00600 rather than recurse. This
    # branch used to `return _backend_fault_error(exc)` -- an infinite self-call
    # that raised RecursionError and tore the connection down (DPY-4011), turning
    # every unexpected backend fault into a session-killing crash-loop instead of
    # a one-statement error the session survives.
    return encode_error(
        _INTERNAL_ERROR, f'ORA-{_INTERNAL_ERROR:05d}: backend error: {exc}'
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
            _ORA_UNSUPPORTED_CALL,
            f'ORA-{_ORA_UNSUPPORTED_CALL:05d}: unsupported network datatype or '
            f'representation ({what})',
        ),
    )


# ORA-03115 is what a client already reads as "this server will not do that".
# Used for a TTC function the Mirror does not implement, so the call is refused
# rather than left unanswered (#832).
_ORA_UNSUPPORTED_CALL = 3115


# The OCI end-to-end tracing piggyback (func 135) modern sqlplus sends after
# login. Its own message prefix, unlike the OCCA / TTI_80SES wrappers that
# strip_oci_piggyback already unwraps (#825).
_OCI_PIGGYBACK_E2E = bytes([TTI_MSG_TYPE_PIGGYBACK, TNS_FUNC_SET_END_TO_END_ATTR])


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
            _ORA_UNSUPPORTED_CALL,
            f'ORA-{_ORA_UNSUPPORTED_CALL:05d}: unsupported network datatype or '
            f'representation ({what})',
            sequence=seq.next(),
        ),
    )


def serve_session(
    stream: PacketStream,
    backend: Backend,
    *,
    encryption: str = 'accepted',
    token_public_key: bytes | None = None,
    field_version: int = FIELD_VERSION_11_2,
    min_field_version: int = FIELD_VERSION_11_2,
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
    user, sqlplus, conn_key, negotiated = handle_login(
        stream,
        backend,
        encryption=encryption,
        token_public_key=token_public_key,
        field_version=field_version,
        min_field_version=min_field_version,
        tns_version=tns_version,
        identity=identity,
    )
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
        return _serve_oci_session(stream, backend, user, conn_key, identity)
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
        # Advance the thin path's OER end-to-end sequence once per message, so a
        # session's replies carry a moving counter like a live server's instead
        # of repeating the value the captured statuses were decoded with (#842).
        # The thick/OCI loop has done this since it was written (_OciSequence);
        # this is the thin half. Captured from 23ai, consecutive replies differ
        # by one in exactly this field: 0x1816 then 0x1817.
        oer_seq += 1
        _ENCODE_OER_SEQ.set(oer_seq)
        received = stream.read_packet()
        if received is None:
            return user
        packet_type, body = received
        if packet_type == TNS_MARKER:
            _answer_marker(stream, body)
            continue
        if packet_type != TNS_DATA:
            continue
        body = _skip_piggybacks(body, backend, temp_lobs)  # CLOSE_CURSORS, …
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
        if body[1] == TTI_ALL8:
            # A cached-cursor re-execute (cursor set, no SQL) omits the OACs; hand
            # parse_exec the bind types the Mirror remembered for that cursor so
            # its RXD decodes (#80/#486).
            peek_cursor, peek_has_query = peek_exec_cursor(body)
            cached_types = (
                cursors.dml_bind_types(peek_cursor)
                if peek_cursor and not peek_has_query
                else None
            )
            max_size = max_string_size(_SERVER_RUNTIME_CAPS)
            completed = _complete_message(
                stream,
                body,
                lambda b: parse_exec(
                    b, bind_types=cached_types, max_string_size=max_size
                ),
            )
            if completed is None:  # answered already: it never completes
                continue
            body = completed
            request = _resolve_temp_lob_binds(
                parse_exec(body, bind_types=cached_types, max_string_size=max_size),
                temp_lobs,
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
            )
        elif body[1] == TNS_FUNC_REEXECUTE_AND_FETCH:
            # The rows carry no OACs -- the cursor's opening execute declared the
            # types -- so look those up from the header first, then read the
            # whole message with them, rows included, which can span packets
            # like any other bind data (#873, the same shape as #854's func 4).
            cached_types = cursors.bind_types(parse_reexecute(body).cursor)
            max_size = max_string_size(_SERVER_RUNTIME_CAPS)
            completed = _complete_message(
                stream,
                body,
                lambda b: parse_reexecute(
                    b, bind_types=cached_types, max_string_size=max_size
                ),
            )
            if completed is None:
                continue
            lobs = _answer_reexecute(
                stream,
                backend,
                parse_reexecute(
                    completed, bind_types=cached_types, max_string_size=max_size
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
            cached_types = cursors.bind_types(parse_reexecute(body).cursor)
            max_size = max_string_size(_SERVER_RUNTIME_CAPS)
            completed = _complete_message(
                stream,
                body,
                lambda b: parse_reexecute(
                    b, bind_types=cached_types, max_string_size=max_size
                ),
            )
            if completed is None:
                continue
            body = completed
            reexecute = parse_reexecute(
                body, bind_types=cached_types, max_string_size=max_size
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
            # A keepalive / pool health check (conn.ping()): no state to touch,
            # just acknowledge with a success status so the client round-trip
            # completes instead of hanging.
            stream.write_packet(TNS_DATA, encode_status(0))
        elif body[1] == TTI_AUTH:
            # A post-login TTI_AUTH is a password change (#21/#486): it reuses the
            # login session key, so decrypt the old / new passwords with conn_key
            # and drive the backend's password change.
            _answer_changepassword(stream, backend, body, conn_key, user, field_version)
        elif body[1] == TTI_LOGOFF:
            return user
        else:
            # A TTC function the Mirror does not implement (#832).
            _refuse_unhandled(stream, f'TTC function {body[1]}')


def _serve_oci_session(
    stream: PacketStream,
    backend: Backend,
    user: str,
    conn_key: bytes | None = None,
    identity: ServerIdentity = IDENTITY_11_2,
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
    # LOB contents (wire bytes + is_clob) the current statement's rows carry, in the
    # order their locators went out; sqlplus drains them with TTI_LOBOPS reads,
    # slicing the current LOB per each read's offset/amount (#405).
    lobs: list[tuple[bytes, bool]] = []
    current_lob: tuple[bytes, bool] | None = None
    # The live per-session OER end-to-end sequence counter (§36); every OER-bearing
    # reply below draws its next value so the field advances like a real server's.
    seq = _OciSequence()
    while True:
        received = stream.read_packet()
        if received is None:
            return user
        packet_type, body = received
        if packet_type == TNS_MARKER:
            # A break / reset marker. The client sends one to resynchronise the
            # line — after a cancelled call, or a reply it could not line up —
            # and then WAITS for the server's marker before saying anything
            # else. A real server always answers. This loop used to fall into
            # the "not DATA, ignore it" branch below, so the client sat there
            # until its own timeout with the session wedged. Answer with a
            # single reset: the client side replies once per break episode too,
            # because echoing every marker ping-pongs into a reset storm.
            stream.write_packet(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
            continue
        if packet_type != TNS_DATA:
            continue
        if is_version_call_oci(body):
            # What sqlplus prints after "Connected to:" — the release this
            # session introduced itself as (naming the Mirror itself is a
            # separate discussion).
            stream.write_packet(TNS_DATA, encode_version_banner_oci(identity.banner))
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
            behind = strip_oci_e2e_piggyback(body)
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
                if parked is not None and is_reexecute_oci(body):
                    # sqlplus re-executes the described cursor to pull LONG rows
                    # once its streaming define is set up. LONG rows stream one per
                    # reply: deliver the first now, re-park the rest for the
                    # follow-up fetches (#407).
                    parked = _serve_oci_long_row(stream, parked, seq, reexecute=True)
                    continue
                parked, lobs = _answer_query_oci(stream, backend, body, seq)
                current_lob = None
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
                if offset <= 1 or current_lob is None:
                    current_lob = lobs.pop(0) if lobs else (b'', True)
                content, is_clob = current_lob
                unit = 2 if is_clob else 1  # bytes per counted unit (CLOB is UTF-16)
                total = len(content) // unit
                start = offset - 1
                count = max(0, min(amount, total - start))
                chunk = content[start * unit : (start + count) * unit]
                stream.write_packet(
                    TNS_DATA,
                    encode_lob_read_response_oci(
                        chunk, count, len(content), is_clob=is_clob, sequence=seq.next()
                    ),
                )
                continue
            if body[1] == TTI_FETCH:
                if parked is not None and _is_long_result(parked[0]):
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
                    columns, rows = parked
                    stream.write_packet(
                        TNS_DATA,
                        encode_fetch_batch_oci(columns, rows, sequence=seq.next()),
                    )
                    parked = None
                else:
                    # Nothing parked — the execute already delivered every row;
                    # the fetch just wants the end-of-fetch terminator (ORA-01403).
                    stream.write_packet(
                        TNS_DATA, encode_fetch_terminator_oci(seq.next())
                    )
                continue
            if body[1] in (TTI_COMMIT, TTI_ROLLBACK):
                stream.write_packet(TNS_DATA, encode_commit_status_oci(seq.next()))
                continue
            if body[1] == TTI_AUTH:
                # A post-login TTI_AUTH is a password change: sqlplus's PASSWORD
                # command (OCIPasswordChange), unwrapped from its TTI_80SES
                # piggyback above. It carries AUTH_PASSWORD (current) and
                # AUTH_NEWPASSWORD (new), the same pair as the thin changepassword.
                _answer_changepassword_oci(stream, backend, body, conn_key, user, seq)
                continue
            if body[1] == TTI_LOGOFF:
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
        col.data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB, TNS_TYPE_JSON, TNS_TYPE_VECTOR)
        for col in columns
    )


def _is_lob_result(columns: list[ColumnMeta]) -> bool:
    # A result that carries a CLOB / BLOB column, whose locator row is fetched with
    # a non-terminator status and whose content follows over TTI_LOBOPS (#405).
    return any(col.data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB) for col in columns)


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
    elif is_reusable_dml(sql) or _is_plsql_block(sql):
        _ENCODE_TXN_IN_PROGRESS.set(True)


def _oci_no_row_status(sql: str, rowcount: int, seq: '_OciSequence') -> bytes:
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
        return encode_ddl_status_oci(command_type, sequence=seq.next())
    return encode_status_oci(seq.next())


def _answer_query_oci(
    stream: PacketStream, backend: Backend, body: bytes, seq: '_OciSequence'
) -> tuple[tuple[list[ColumnMeta], list[tuple]] | None, list[tuple[bytes, bool]]]:
    # Answer one sqlplus / thick-OCI execute. sqlplus fires a chain of setup
    # statements (PL/SQL blocks, PRODUCT_PRIVS selects) before the user's query;
    # each needs an acceptable reply or sqlplus never reaches the prompt. Returns
    # ``(parked, lobs)``: the rows held for a follow-up fetch (or None), and the
    # LOB contents the result's rows carry for the follow-up TTI_LOBOPS reads.
    try:
        request = parse_exec_oci(body)
    except InterfaceError:
        # A shape not parsed yet (e.g. a bound PL/SQL setup call) — acknowledge
        # success so sqlplus proceeds; the backend never sees it.
        stream.write_packet(TNS_DATA, encode_status_oci(seq.next()))
        return None, []
    try:
        # A PL/SQL block (sqlplus VARIABLE / EXEC :v := …) hands its binds over as
        # BindVar so the backend registers them OUT-capable and returns the assigned
        # values — the wire carries no direction, so every bind goes over
        # OUT-capable (the same path the thin exec uses). A plain statement's binds
        # pass through unchanged, except a NULL, which goes over with its declared
        # type (#699).
        result = backend.execute(request.sql, _bind_vars(request))
    except BackendError as err:
        # A statement the backend can't run. A failed SELECT (e.g. sqlplus's
        # PRODUCT_PRIVS lookup) must come back as an ORA error — sqlplus expects
        # a query reply for a query and tolerates the error — while a non-query
        # (PL/SQL / DDL it can't do) gets a success status so the session
        # continues.
        if request.sql.lstrip().upper().startswith('SELECT'):
            stream.write_packet(
                TNS_DATA,
                encode_error_oci(
                    err.ora_code,
                    str(err),
                    sequence=seq.next(),
                    error_pos=err.error_offset,
                ),
            )
        else:
            stream.write_packet(TNS_DATA, encode_status_oci(seq.next()))
        return None, []
    if result.out_binds:
        # A PL/SQL block that assigned OUT binds (sqlplus VARIABLE / EXEC) — return
        # the values so the client reads them back into its bound buffers.
        stream.write_packet(
            TNS_DATA,
            encode_out_bind_response_oci(result.out_binds, sequence=seq.next()),
        )
        return None, []
    if not result.columns:
        stream.write_packet(
            TNS_DATA, _oci_no_row_status(request.sql, result.rowcount, seq)
        )
        return None, []
    rows = list(result.rows)
    # Every LOB cell across the whole result queues its content now, row-major, so
    # the follow-up TTI_LOBOPS reads drain it in the order the locators went out.
    lobs = oci_lob_contents(result.columns, rows)
    has_long = any(
        col.data_type in (TNS_TYPE_LONG, TNS_TYPE_LONGRAW) for col in result.columns
    )
    has_lob = any(
        col.data_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB) for col in result.columns
    )
    if has_lob and rows:
        # A LOB result: sqlplus sets up its LOB define from the describe, then
        # fetches the locator rows. The LOB describe reply has its own shape (a
        # 33-byte tail + a LOB execute status, not the ordinary inline-row DCB
        # tail) — matching it is what makes sqlplus accept the locator row rather
        # than break (#405).
        stream.write_packet(
            TNS_DATA, encode_lob_describe_oci(result.columns, sequence=seq.next())
        )
        return (result.columns, rows), lobs
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
        return (result.columns, rows), lobs
    if len(rows) <= 1:
        # 0 or 1 row fits in the execute reply; sqlplus won't fetch further.
        stream.write_packet(
            TNS_DATA,
            encode_query_response_oci(result.columns, rows, sequence=seq.next()),
        )
        return None, lobs
    # Deliver the first row now and park the rest — sqlplus reads the "more rows"
    # status and issues a fetch for the remainder.
    stream.write_packet(
        TNS_DATA,
        encode_query_response_oci(
            result.columns, rows[:1], sequence=seq.next(), more=True
        ),
    )
    return (result.columns, rows[1:]), lobs


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
                error_pos=getattr(err, 'error_offset', None),
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


_ORA_USER_CANCEL = 1013  # ORA-01013: user requested cancel of current operation
_ORA_INVALID_CURSOR = 1001  # ORA-01001: a cursor id the session does not hold


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
    if marker_type == TNS_MARKER_TYPE_RESET:
        # The client's reset ends the episode: report the cancellation, which is
        # what it is now waiting to read.
        stream.write_packet(
            TNS_DATA,
            encode_error(
                _ORA_USER_CANCEL,
                # The text a live 23ai sends, capitalised and full-stopped.
                f'ORA-{_ORA_USER_CANCEL:05d}: User requested cancel of current '
                f'operation.',
            ),
        )
    else:
        # An interrupt or break opens it: answer with a single reset.
        stream.write_packet(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))


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


def _skip_piggybacks(
    body: bytes,
    backend: Backend | None = None,
    temp_lobs: _TempLobs | None = None,
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
    # so the caller ignores the message rather than mis-parsing it.
    while len(body) >= 3 and body[0] == TTI_MSG_TYPE_PIGGYBACK:
        func = body[1]
        rest = body[3:]  # skip the piggyback token, function code, sequence
        if _DECODE_FIELD_VERSION.get() > FIELD_VERSION_23_1:
            _, rest = decode_ub4(rest)  # the fv24 ub8 token
        if func == TTI_OCCA:  # CLOSE_CURSORS
            rest = rest[1:]  # pointer byte
            count, rest = decode_ub4(rest)
            for _ in range(count):
                _, rest = decode_ub4(rest)  # each closed cursor id (ignored)
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
        else:
            break
        body = rest
    return body


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
        self._n += 1
        return n


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

    def open_query(self, sql: str, bind_types: Sequence = ()) -> int:
        # A cursor id for a query, minted even when the whole result fit and
        # there is nothing parked. The client caches the id against the statement
        # and re-executes by it, so every query needs one of its own -- sharing
        # the captured 1 told every query it was the same cursor (#840). The SQL
        # is kept because re-executing by id has to know what to run (#833).
        cursor_id = self._next
        self._next += 1
        self._query[cursor_id] = (sql, list(bind_types))
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
    ) -> int:
        # `sql` is the statement this cursor ran, recorded so a re-execute by id
        # knows what to run (#840), with the bind format its values came in (#854).
        # A REF CURSOR has no statement of its own and passes None.
        cursor_id = self._next
        self._next += 1
        self._open[cursor_id] = (columns, rows)
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
        if rows:
            self._open[cursor_id] = (columns, rows)
        else:
            self._open.pop(cursor_id, None)

    def open_scroll(self, columns: list[ColumnMeta], rows: list[tuple]) -> int:
        cursor_id = self._next
        self._next += 1
        self._scroll[cursor_id] = (columns, list(rows))
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
        if rest:
            self._open[cursor_id] = (columns, rest)
        else:
            del self._open[cursor_id]
        return columns, batch

    def has(self, cursor_id: int) -> bool:
        return cursor_id in self._open

    def columns(self, cursor_id: int) -> list[ColumnMeta]:
        """The column metadata a parked cursor was opened with, empty if the id
        is not parked. Read without taking any rows, so a caller can decide how
        to answer before it commits to draining the cursor (#887)."""
        state = self._open.get(cursor_id)
        return state[0] if state is not None else []


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

    def mint(self, is_blob: bool) -> bytes:
        """A locator distinct from every other this session has handed out."""
        locator = mint_temp_lob_locator(self._next, is_blob)
        self._next += 1
        self._buffers[bytes(locator)] = bytearray()
        self._is_blob[bytes(locator)] = is_blob
        return locator

    def append(self, locator: bytes, payload: bytes) -> None:
        self._buffers.setdefault(bytes(locator), bytearray()).extend(payload)

    def free(self, locator: bytes) -> None:
        # A client may free a locator the Mirror never saw written; that is fine,
        # and the index is still never reused.
        self._buffers.pop(bytes(locator), None)
        self._is_blob.pop(bytes(locator), None)

    def content(self, locator: bytes) -> bytes:
        return bytes(self._buffers.get(bytes(locator), b''))

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


def _answer_lobops(
    stream: PacketStream,
    body: bytes,
    lobs: list[tuple[bytes, bool]],
    temp_lobs: _TempLobs,
    current_lob: tuple[bytes, bool] | None = None,
    object_lobs: list[tuple[bytes, bool]] | None = None,
    current_object_lob: tuple[bytes, bool] | None = None,
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
    if request.kind == 'create_temp':
        locator = temp_lobs.mint(request.is_blob)
        stream.write_packet(TNS_DATA, encode_create_temp_response(locator))
        return lobs, current_lob, current_object_lob
    if request.kind == 'write':
        # Append at the write offset the client streamed (it writes from the
        # start and appends, so a plain concat matches every real client).
        temp_lobs.append(request.locator, request.payload)
        stream.write_packet(TNS_DATA, encode_lobops_ack(request.locator))
        return lobs, current_lob, current_object_lob
    if request.kind == 'free_temp':
        # Release the temp LOB now rather than at session end.
        temp_lobs.free(request.locator)
        stream.write_packet(TNS_DATA, encode_lobops_ack(request.locator))
        return lobs, current_lob, current_object_lob
    if request.kind == 'ack':
        # OPEN / CLOSE / TRIM / GET_CHUNK_SIZE: acknowledge with the content-free
        # reply the client accepts. The value-returning form (a real chunk size,
        # applying TRIM's length) is deferred (#421) — no test client needs it.
        stream.write_packet(TNS_DATA, encode_lobops_ack(request.locator))
        return lobs, current_lob, current_object_lob
    # A READ of an emitted column locator. The queue is row-major, matching the
    # order the locators went out (#413), but a client reads a large LOB in
    # several passes, so the entry stays until it is drained and each read is
    # served the slice it asked for (#903). A read at offset 1 starts the next
    # LOB; later offsets continue the current one -- the same rule the OCI loop
    # follows. A LOB attribute of an object rides a distinct locator and drains
    # the persistent object queue instead of the column one (#888).
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


def _resolve_temp_lob_binds(request: ExecRequest, temp_lobs: _TempLobs) -> ExecRequest:
    # Swap any temp-LOB locator bind for the bytes streamed into it over
    # TTI_LOBOPS WRITE, so the backend sees a plain str / bytes value (#412). A
    # CLOB's content is UTF-16BE on the wire -- the minted locator says so with
    # its variable-length-charset flag, which is what a client encodes by (see
    # mint_temp_lob_locator) -- and a BLOB's is raw.
    # An empty temp LOB is resolved to a typed bind, not a bare '' / b'': a
    # backend that binds the bare value stores NULL on an Oracle target (an empty
    # scalar is NULL there), losing the "empty, non-NULL LOB" the client meant.
    # Only meaningful on a single execute -- the array path takes plain values,
    # and an empty temp LOB in an executemany is not a real case -- so a batch
    # keeps the bare form.
    single = len(request.bind_rows) <= 1

    def resolve(value: object) -> object:
        if isinstance(value, TempLobRef):
            data = temp_lobs.content(value.locator)
            content = data if value.is_blob else data.decode('utf-16-be')
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


def _run_returning(backend: Backend, sql: str, request: ExecRequest) -> Result:
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
    rows = [
        [
            BindVar(value=None, tns_type=meta[i][0], max_size=meta[i][1])
            if i in request.return_binds
            else value
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


def _is_plsql_block(sql: str) -> bool:
    head = sql.lstrip().upper()
    return head.startswith('BEGIN') or head.startswith('DECLARE')


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


def _bind_vars(request: ExecRequest) -> list:
    # Hand the backend each bind whose value alone cannot say what it is,
    # wrapped with the type the client declared for it. For a PL/SQL block that
    # is every bind: the wire carries no direction, so each goes over OUT-capable
    # with its type and return-buffer size (#483), and the client keeps only the
    # positions it bound as a Var. For any other statement it is a NULL bind: a
    # NULL carries no type, the client may have declared one (setinputsizes)
    # for exactly that reason, and a backend that cannot infer it has nothing
    # else to go on (#699). A non-NULL value passes through unchanged, as does
    # everything on a shape mismatch.
    if not request.binds or len(request.bind_meta) != len(request.binds):
        return request.binds
    block = _is_plsql_block(request.sql)
    arrays = request.bind_arrays or [0] * len(request.binds)
    # The per-bind type OID (an object / REF bind carries it in the OAC) rides on
    # bind_types as the 4th field; thread it so an object OUT / typed-NULL bind
    # keeps its type identity even when its value is None (#888).
    toids = [(bt[3] if len(bt) > 3 else b'') for bt in (request.bind_types or [])] or [
        b''
    ] * len(request.binds)
    return [
        BindVar(
            value=value,
            tns_type=tns_type,
            max_size=size,
            array_size=capacity,
            toid=toid,
        )
        if block or value is None
        else value
        for value, (tns_type, size), capacity, toid in zip(
            request.binds, request.bind_meta, arrays, toids
        )
    ]


def _out_bind_entries(
    out_binds: list, bind_meta: list, cursors: _Cursors, bind_arrays: Sequence = ()
) -> list[ScalarOutBind | ArrayOutBind | RefCursorOutBind]:
    # Turn the backend's OUT bind values into IOV reply entries (#483). A scalar
    # rides with its declared type; an associative array as its element list
    # (#743); a REF CURSOR value (CursorResult) has its rows parked on a fresh
    # cursor id the client then drains with TTI_FETCH.
    entries: list[ScalarOutBind | ArrayOutBind | RefCursorOutBind] = []
    arrays = list(bind_arrays) or [0] * len(bind_meta)
    for value, (tns_type, _size), capacity in zip(out_binds, bind_meta, arrays):
        if isinstance(value, CursorResult):
            cursor_id = cursors.open(value.columns, list(value.rows))
            entries.append(RefCursorOutBind(columns=value.columns, cursor_id=cursor_id))
        elif capacity:
            entries.append(ArrayOutBind(values=list(value or []), tns_type=tns_type))
        else:
            entries.append(ScalarOutBind(value=value, tns_type=tns_type))
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
        count = request.fetch if request.fetch > 0 else _ALL_ROWS
        columns_out, batch = cursors.take(reused_id, count)
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
    try:
        if request.return_binds:
            # DML ... RETURNING col INTO :b (#689). The reply owes one set of
            # returned values per iteration, so this cannot go through the
            # ordinary DML paths below, which report only a row count.
            result = _run_returning(backend, sql, request)
            if request.autocommit:
                backend.commit()
            _mark_transaction(sql, request.autocommit)
            stream.write_packet(
                TNS_DATA,
                encode_returning_response(
                    result.rowcount,
                    result.returned_rows,
                    [request.bind_meta[i][0] for i in sorted(request.return_binds)],
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
                result = Result(rowcount=execute_many(sql, iter_rows))
            else:
                # Per row: needed for batcherrors (the good rows still apply and a
                # per-row failure is collected as (offset, code, message) rather
                # than aborting the batch), and the fallback for a backend that
                # offers no array path.
                affected = 0
                for offset, row in enumerate(iter_rows):
                    try:
                        affected += backend.execute(sql, row).rowcount
                    except BackendError as err:
                        if not request.batcherrors:
                            raise
                        batch_errors.append((offset, err.ora_code, err.ora_message))
                result = Result(rowcount=affected)
        else:
            result = backend.execute(sql, _bind_vars(request))
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
            response = encode_batch_errors_status(result.rowcount, batch_errors)
            stream.write_packet(TNS_DATA, response)
            return lobs
        # A PL/SQL block that assigned OUT binds returns them as an IOV vector
        # (the client keeps only its Var positions); this precedes the column /
        # status branches — a block carries neither rows nor a rowcount (#483).
        if result.out_binds:
            response = encode_out_bind_response_thin(
                _out_bind_entries(
                    result.out_binds, request.bind_meta, cursors, request.bind_arrays
                )
            )
        # A query carries result columns (even with zero rows); a DDL/DML
        # statement carries none and gets a bare success status instead of a
        # describe — the client expects one or the other, not both.
        elif result.columns:
            rows = list(result.rows)
            # A LOB result's rows carry locators; the client reads their content
            # row-major over TTI_LOBOPS, so queue every cell's content in that
            # order for the loop to drain (#413).
            lobs = oci_lob_contents(result.columns, rows)
            # Object columns queue their embedded LOB attributes separately, on a
            # persistent queue routed by a distinct locator: populating an object
            # type after the describe runs get_type_shape queries that reset the
            # transient LOB queue before the client issues its reads (#888). A
            # metadata query carries no object LOBs, so it leaves the queue as-is.
            if object_lobs is not None:
                these_object_lobs = object_lob_contents(result.columns, rows)
                if these_object_lobs:
                    object_lobs[:] = these_object_lobs
            # Send the first `fetch` rows now; park any remainder on a cursor for
            # the client's follow-up TTI_FETCH calls. A result that fits is
            # delivered whole, ending with ORA-01403; a zero prefetch sends none
            # of it inline (#856).
            batch_size = _prefetch_batch(request.fetch, len(rows))
            if _defers_inline_rows(result.columns):
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
                    result.columns, remaining, sql=sql, bind_types=request.bind_types
                )
                response = encode_query_response(
                    result.columns, first, cursor_id=cursor_id, more=True
                )
            else:
                # Mint an id even though nothing is parked: the terminator
                # reports it and the client caches it against this statement, so
                # a query with no leftover rows still needs an identity of its
                # own (#840).
                response = encode_query_response(
                    result.columns,
                    first,
                    cursor_id=cursors.open_query(sql, request.bind_types),
                )
        else:
            # DML / DDL success. Hand back a server cursor id (reused on a cached
            # re-execute, freshly minted otherwise) so the client's cursor cache
            # can re-run this DML by id — but not for a PL/SQL block, which the
            # client never caches (#80/#486).
            cursor_id = reused_id
            if not cursor_id and not _is_plsql_block(sql):
                cursor_id = cursors.open_dml(sql, request.bind_types)
            response = encode_status(result.rowcount, cursor_id=cursor_id)
    except BackendError as err:
        logger.info('query refused: %s', err.ora_message)
        response = encode_error(err.ora_code, err.ora_message, err.error_offset)
    except Exception as exc:
        logger.warning('backend raised a non-ORA error: %s', exc)
        response = _backend_fault_error(exc)
    stream.write_packet(TNS_DATA, response)
    return lobs


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
    rows = list(result.rows)
    cursor_id = cursors.open_scroll(columns, rows)
    size = _prefetch_batch(request.fetch, len(rows))
    batch = rows[:size]
    last_abs = len(batch)
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
    columns = list(result.columns or [])
    rows = list(result.rows)
    lobs = oci_lob_contents(columns, rows) if columns else []
    # The request's iteration count is the client's prefetch size, so it is also
    # the batch size. Anything past it is parked on the SAME cursor id the client
    # already holds, so its follow-up fetches address the statement it just ran.
    batch_size = _prefetch_batch(request.fetch, len(rows))
    first, remaining = rows[:batch_size], rows[batch_size:]
    cursors.reopen(request.cursor, columns, remaining, sql=sql)
    stream.write_packet(
        TNS_DATA,
        encode_fetch_response(
            columns, first, cursor_id=request.cursor, more=bool(remaining)
        ),
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
        )
        return _answer_query(
            stream, backend, _resolve_temp_lob_binds(execute, temp_lobs), cursors
        )
    sql = cursors.query_sql(request.cursor)
    if sql is None:
        stream.write_packet(
            TNS_DATA, encode_error(_ORA_INVALID_CURSOR, 'ORA-01001: invalid cursor')
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


_CHANGE_PASSWORD_UNSUPPORTED = 1031  # ORA-01031: insufficient privileges


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
                _CHANGE_PASSWORD_UNSUPPORTED,
                'ORA-01031: password change not supported',
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
            TNS_DATA, encode_error(1017, 'ORA-01017: invalid credential')
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
                _CHANGE_PASSWORD_UNSUPPORTED,
                'ORA-01031: password change not supported',
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
                1017, 'ORA-01017: invalid credential', sequence=seq.next()
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
                _INTERNAL_ERROR, f'ORA-00600: backend error: {exc}', sequence=seq.next()
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
