# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Non-I/O connection logic shared by the sync and async connections (#553).

`OracleConnect` (sync) and `AsyncOracleConnect` (async) duplicate a large body
of methods whose logic contains no ``await`` and touches no socket — pure state
manipulation and wire-bytes assembly. The README's design intent is that "the
duplication is just the I/O layer", so those methods belong in one place.

`_ConnectionLogic` is a mixin holding that shared logic; both concrete
connection classes inherit it, so a single definition serves both and the
sync/async parity holds by construction. The mixin never does I/O itself: it
only reads the attributes the concrete ``__init__`` sets and calls the
concrete I/O methods, both declared below for the type checker.

This first slice covers the end-to-end tracing attributes (MODULE / ACTION /
CLIENT_IDENTIFIER / CLIENT_INFO / DBOP, #183/#184); further slices move more of
the pure methods here.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, TypeGuard

from seerdb.client.dialect import (
    Dialect,
    Fv2Dialect,
    Fv2Oall8Dialect,
    O8iDialect,
    Oci11Dialect,
)
from seerdb.client.enums import TransactionPriority
from seerdb.common.end_user_sec import EndUserSecurityContext
from seerdb.common.exceptions import NotSupportedError, ProgrammingError
from seerdb.common.tns import (
    encode_alter_session_piggyback,
    encode_ano_fragment,
    encode_app_context_piggyback,
    encode_close_cursors_piggyback,
    encode_dictionary,
    encode_end_to_end_piggyback,
    encode_end_user_sec_piggyback,
    encode_session_state_piggyback,
    max_string_size,
)
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    APP_CONTEXT_KEY_MAX_LEN,
    APP_CONTEXT_VALUE_MAX_LEN,
    CCAP_FEATURE_BACKPORT2,
    CCAP_FEATURE_BACKPORT2_END_USER_SEC,
    CCAP_FEATURE_BACKPORT2_TXN_PRIORITY,
    CCAP_FIELD_VERSION,
    CCAP_TTC4,
    CCAP_TTC4_EXPLICIT_BOUNDARY,
    CONN_STATE_AUTHENTICATED,
    FIELD_VERSION_10_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_23_1,
    ORA_ARRAY_DML_ERRORS,
    ORA_NO_DATA_FOUND,
    ORA_TOO_MANY_ROWS,
    RCAP_TTC,
    RCAP_TTC_SESSION_STATE_OPS,
    TNS_EOCS_FLAGS_TXN_IN_PROGRESS,
    TNS_KEYWORD_NUM_TXN_PRIORITY,
    TNS_SESSION_STATE_REQUEST_BEGIN,
    TNS_VERSION_11_2,
    DictionaryType,
)

# Errors after which the server has ended the session (#2456): it was killed
# (ORA-00028), is not logged on (ORA-01012), the instance is going down
# (ORA-01089, ORA-01092), the idle limit passed (ORA-02396), or the connection
# is lost (ORA-03113, ORA-03114, ORA-03135).
_SESSION_ENDED = frozenset({28, 1012, 1089, 1092, 2396, 3113, 3114, 3135})

if TYPE_CHECKING:
    from seerdb.client.connection import Xid
    from seerdb.common.ano_session import AnoChannel


class _ConnectionLogic:
    """Shared non-I/O logic for `OracleConnect` / `AsyncOracleConnect` (#553)."""

    # --- Provided by the concrete connection's __init__ / I/O layer. Declared
    # here (no runtime assignment) so the type checker resolves the references
    # in the pure methods below; the concrete classes own the real values.
    field_version: int
    ssl: object
    host: str
    port: int
    sid: str
    service_name: str
    user: str
    proxy_user: str | None
    password: str
    cclass: str | None
    purity: int
    server_type: str | None
    session_id: int | None
    serial_num: int | None
    _instance_name_requested: str
    expire_time: int
    socket_options: object
    conn_state: int
    timeout: int
    autocommit: bool
    fetch: int
    role: int
    charset: str
    prelim: int
    app_name: str
    program: str | None
    machine: str | None
    terminal: str | None
    osuser: str | None
    driver_name: str | None
    edition: str | None
    sdu: int
    _e2e_values: dict
    _e2e_pending: dict
    _cursors_to_close: list[int]
    _server_compile_caps: bytes
    _server_runtime_caps: bytes
    _end_user_sec_context: bytes | None
    _app_context: dict[str, dict[str, str]]
    _txn_priority_requested: str
    _txn_priority: str | None
    _txn_priority_pending: str | None
    _session_keywords: dict[int, str | None]
    _session_state_desired: int
    _in_request: bool
    _supports_eor: bool
    _timed_out: bool
    _dialect: Dialect | None
    _wallet_server_dn: str | None
    _large_packets: bool
    _ano: AnoChannel | None
    _call_timeout: int
    _cursor_cache: dict[tuple[str, bytes], int]
    _cursor_cache_max: int
    server_version: int
    max_identifier_length: int | None
    instance_name: str | None
    _call_status: list[int]

    if TYPE_CHECKING:

        def _socket_open(self) -> bool: ...

        def _next_seq(self) -> int: ...

        def _auth_info_pairs(self) -> list: ...

        def _send_break(self) -> None: ...

        def _arm_break_deadline(self) -> None: ...

    # --- Ping (#1095) -------------------------------------------------------

    @staticmethod
    def _raise_reply_error(Result: object) -> None:
        """Raise the ORA error a call's reply carries, if it carries one.

        A ping on a session the server has killed is answered with ORA-00028
        "session has been terminated" IN the reply; ping used to read the reply
        and drop it, so a killed session pinged healthy and a pool handed it out
        (python-oracledb raises there). Shared by the sync and async ping."""
        from seerdb.common.exceptions import from_ora_code

        # Only a decoded status carries an int code in slot 1. A clean reply can
        # come back in the (done, accumulator) shape instead, whose slot 1 is the
        # accumulator tuple -- not a code, and not an error.
        Code = Result[1] if isinstance(Result, tuple) and len(Result) > 1 else 0
        if isinstance(Code, int) and Code:
            Msg = Result[5] if isinstance(Result, tuple) and len(Result) > 5 else None
            raise from_ora_code(Code)(Msg or f'ORA-{Code:05d}', code=Code)

    def _pre10_login_error(self, Packet: bytes) -> tuple[int, str | None]:
        """The ORA code and message of the status refusing an 8i or 9i login,
        at either phase, read as that tier's status is (#2340): 8i's
        (`decode_8i_terminal_error`) or 9i's short one (`decode_fv2_oer_error`).
        Read in the 10g+ order -- call status, sequence, row count, code -- the
        code fell in a skipped field, a wrong password read as authenticated,
        and the next call drew ORA-01012 (9i) or an AssertionError (8i)."""
        from seerdb.common.tns import decode_8i_terminal_error, decode_fv2_oer_error

        if getattr(self, '_o3_oall8', False) or getattr(self, '_native11', False):
            # The native form's refusal, 9.2's or 11g's (#2466): an OCI OER
            # with the ORA message as text.
            return self._oall8_login_error(Packet)
        if isinstance(self._dialect, O8iDialect):
            return decode_8i_terminal_error(Packet)
        return decode_fv2_oer_error(Packet)

    @staticmethod
    def _oall8_login_error(Packet: bytes) -> tuple[int, str | None]:
        # The native 9i OALL8 login's OER (9.2 OCI path) uses neither the 9i-short
        # nor the 11g+ layout decode_packet knows, at either phase: an unknown
        # user is refused at the OSESSKEY, a wrong password at the OAUTH (#798;
        # the first read "authentication failed" with no code). Its ORA message
        # travels verbatim in the packet, so recover the code from the embedded
        # "ORA-NNNNN" text (a bad password surfaces ORA-01017); an OER with no
        # such text is a clean completion.
        Marker = Packet.find(b'ORA-')
        if Marker < 0:
            return (0, None)
        Digits = Packet[Marker + 4 : Marker + 9]
        ErrCode = int(Digits.decode('ascii', 'ignore') or 0)
        return (ErrCode, Packet[Marker:].split(b'\n')[0].decode('ascii', 'ignore'))

    def _oall8_osesskey(self) -> bytes:
        # Native 9i OALL8 O3LOGON phase one (#790): once the native data-type
        # negotiation has run, the 9.2 server expects the OCI OSESSKEY (0x76)
        # call frame; it answers with an AUTH_SESSKEY RPA in the native DALC
        # coding and drives the 8-byte O3LOGON proof (CCAP_LOGON_TYPES 0).
        # Shared by the sync and async logins.
        from seerdb.common.tns import encode_oall8_osesskey_phase1

        self._o3_oall8 = True
        self._o3_phase = 1
        return encode_oall8_osesskey_phase1(
            self._next_seq(), self.user.encode('utf-8'), self._auth_info_pairs()
        )

    def _oall8_oauth(self, Packet: bytes) -> bytes:
        # Native 9i OALL8 O3LOGON phase two: recover the session key, DES-encrypt
        # the password under it (the same crypto as the thin 9i / 8i paths), and
        # send it as AUTH_PASSWORD in the OAUTH (0x73) call. With CCAP_LOGON_TYPES
        # forced to 0 (_O3_OALL8_COMPILE_CAPS) the 9.2 server issues an 8-byte DES
        # session key, so AUTH_PASSWORD is the proof the thin TTI_3LOGON / 8i
        # paths send: upper-hex(DES cipher), then the decimal pad count (#790).
        from binascii import hexlify

        from seerdb.common.crypto import des_verifier, o3logon
        from seerdb.common.tns import (
            encode_oall8_oauth_phase2,
            parse_oall8_auth_sesskey,
        )

        SessKey = parse_oall8_auth_sesskey(Packet)
        UserB = self.user.encode('utf-8')
        PassB = self.password.encode('utf-8')
        (AuthPass, _, _) = o3logon(SessKey, des_verifier(UserB, PassB), PassB)
        PadCount = (8 - len(PassB) % 8) % 8
        PwdField = (hexlify(AuthPass).decode('ascii').upper() + str(PadCount)).encode(
            'ascii'
        )
        self._o3_phase = 2
        return encode_oall8_oauth_phase2(
            self._next_seq(),
            UserB,
            PwdField,
            self._auth_info_pairs() + [(b'AUTH_ACL', b'8000')],
        )

    # --- The 11g native login, for a pooled 11g session (#2466) -----------
    # 11g's DRCP serves a pooled session only to a client speaking the native
    # form (seerdb.common.tns, "The 11g native login"). The converted form logs
    # in but crashes the pooled server process on its second call, so a pooled
    # login to an 11g server speaks the native form throughout, and every call
    # not built in that form yet is refused before it is sent (_native11_refuse).

    def _native11_choose(self, AcceptVersion: int) -> None:
        # Decided at the ACCEPT, before the PRO, whose banner already differs:
        # a pooled login to a server answering 11g's protocol version. The
        # native form is the client machine's own, which seerdb takes to be
        # little-endian; refuse rather than send a big-endian one.
        import sys

        self._native11 = (
            self.server_type == 'pooled' and AcceptVersion == TNS_VERSION_11_2
        )
        if self._native11 and sys.byteorder != 'little':
            raise NotSupportedError(
                'a pooled connection to Oracle 11g needs a little-endian client'
            )

    def _native11_dty(self) -> bytes:
        from seerdb.common.tns import CharsetDict, encode_dty_oci11

        return encode_dty_oci11(CharsetDict.get(self.charset, AL32UTF8_CHARSET))

    def _native11_osesskey(self) -> bytes:
        from seerdb.common.tns import encode_osesskey_oci11

        return encode_osesskey_oci11(
            self._next_seq(),
            self.user.encode('utf-8'),
            self._o7_logon_mode(),
            self._o7_session_pairs(),
        )

    def _native11_auth(self, Auth: dict) -> tuple[bytes, bytes]:
        # The second phase: the O5LOGON proof and the DRCP pairs, as the
        # converted AUTH sends them below 12.1. Returns (message, ConnKey).
        from seerdb.common.tns import encode_auth_oci11

        return encode_auth_oci11(self._make_dict(DictionaryType.auth, auth=Auth), [])

    def _native11_session(self, SessionId: int, Serial: int) -> None:
        # The pooled session the server handed over: its own SID and SERIAL#,
        # as python-oracledb takes them from the session return.
        self.session_id = SessionId
        self.serial_num = Serial

    def _native11_call_status(self, Status: int) -> None:
        # A pooled 11g reply's call status, which transaction_in_progress reads.
        self._call_status[:] = [Status]

    def _native11_refuse(self) -> None:
        # Called by send() for every DATA packet: once a native session has
        # logged in, only what is built in the native form may go out -- the
        # dialect's calls (_drive marks them) and the session release. The
        # converted form would reach the pooled server, which aborts on it.
        if (
            getattr(self, '_native11', False)
            and self.conn_state == CONN_STATE_AUTHENTICATED
            and not getattr(self, '_native11_sending', False)
        ):
            raise NotSupportedError(
                'this call is not supported on a pooled Oracle 11g connection yet'
            )

    def _o7_logon_mode(self) -> int:
        # The logon mode a 9i OSESSKEY carries (#2342), as 10g+'s: the role's
        # and the preliminary connection's bits on the logon bit.
        return ((self.role or 0) * 32) | ((self.prelim or 0) * 128) | 1

    def _o7_session_pairs(self) -> list[tuple[bytes, bytes]]:
        # The session pairs a 9i login sends (#2342), those of a 10g+ login below
        # 12.1 and from the same settings: program, machine, pid and osuser
        # (AUTH_SID, which servers report as v$session.osuser).
        import os
        import socket

        return [
            (b'AUTH_PROGRAM_NM', (self.program or self.app_name or 'seerdb').encode()),
            (b'AUTH_MACHINE', (self.machine or socket.gethostname()).encode()),
            (b'AUTH_PID', str(os.getpid()).encode()),
            (b'AUTH_SID', (self.osuser or self.user).encode()),
        ]

    # --- Temporary LOBs (#1066) ----------------------------------------------

    def _createlob_form(self, lob_type) -> tuple[int, int]:
        """The (TNS type, charset form) a ``createlob(lob_type)`` builds, after
        checking the server can make one at all. Shared by the sync and async
        ``createlob`` so the two cannot disagree about what is allowed.

        CLOB, NCLOB and BLOB only -- the three a temp LOB can be. An NCLOB is a
        CLOB (type 112) with charset form 2, so the form has to come from the
        requested type: taking the TNS type alone would quietly make a CLOB."""
        from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_CLOB

        tns_type = getattr(lob_type, 'tns_type', None)
        if tns_type not in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
            raise ProgrammingError(
                f'createlob() needs DB_TYPE_CLOB, DB_TYPE_NCLOB or DB_TYPE_BLOB, '
                f'not {lob_type!r}'
            )
        if not temp_lobs_available(self):
            # The temp LOB it sits on is a CREATE_TEMP, which 11g's converted
            # form refuses (#91); a pooled 11g session makes its own (#2466).
            raise NotSupportedError(
                'createlob() requires an Oracle 12.1+ server (it makes a server '
                'temporary LOB, which older servers refuse)'
            )
        return (tns_type, lob_type.csfrm)

    # --- End-to-end tracing attributes (#183/#184) -------------------------

    def _set_e2e(self, name: str, value) -> None:
        # Record a new end-to-end attribute value and mark it to flush before
        # the next execute (oracledb sends only what changed). The
        # SET_END_TO_END_ATTR piggyback (func 135) is a 12c+ message — a pre-12c
        # server closes the connection on it — so gate it (oracledb thin is
        # itself 12.1+ only). #183.
        if self.field_version < FIELD_VERSION_12_1:
            raise NotSupportedError(
                'end-to-end tracing attributes require an Oracle 12.1+ server'
            )
        self._e2e_values[name] = value
        self._e2e_pending[name] = value

    def _pending_e2e_with_module_action(self) -> dict:
        # The server rejects a module update that does not also carry action
        # (Oracle's SET_MODULE always sets both — a module-only piggyback is
        # ORA-03137). So when module flushes, send action too, at its current
        # value (None -> empty), matching oracledb. #184.
        Pending = dict(self._e2e_pending)
        if 'module' in Pending and 'action' not in Pending:
            Pending['action'] = self._e2e_values.get('action')
        return Pending

    def _flush_end_to_end_bytes(self) -> bytes:
        # Build the SET_END_TO_END_ATTR piggyback for the attributes changed
        # since the last flush, then clear the pending set. Empty when nothing
        # changed. Allocate the piggyback's seq here so it precedes the execute.
        if not self._e2e_pending:
            return b''
        Pending = self._pending_e2e_with_module_action()
        Seq = self._next_seq()
        Bytes = encode_end_to_end_piggyback(Seq, self.field_version, Pending)
        self._e2e_pending = {}
        return Bytes

    @property
    def module(self):
        """The session's MODULE for end-to-end tracing (V$SESSION.MODULE /
        SYS_CONTEXT('USERENV','MODULE')). Set it before running a statement;
        the change is sent with the next execute. oracledb-compatible (#183)."""
        return self._e2e_values.get('module')

    @module.setter
    def module(self, value) -> None:
        self._set_e2e('module', value)

    @property
    def action(self):
        """The session's ACTION for end-to-end tracing (#183)."""
        return self._e2e_values.get('action')

    @action.setter
    def action(self, value) -> None:
        self._set_e2e('action', value)

    @property
    def client_identifier(self):
        """The session's CLIENT_IDENTIFIER for end-to-end tracing (#183)."""
        return self._e2e_values.get('client_identifier')

    @client_identifier.setter
    def client_identifier(self, value) -> None:
        self._set_e2e('client_identifier', value)

    @property
    def clientinfo(self):
        """The session's CLIENT_INFO for end-to-end tracing
        (SYS_CONTEXT('USERENV','CLIENT_INFO')); oracledb-compatible (#184)."""
        return self._e2e_values.get('client_info')

    @clientinfo.setter
    def clientinfo(self, value) -> None:
        self._set_e2e('client_info', value)

    @property
    def dbop(self):
        """The session's database operation for monitoring (DBMS_SQL_MONITOR /
        SYS_CONTEXT('USERENV','DBOP')); oracledb-compatible (#184)."""
        return self._e2e_values.get('dbop')

    @dbop.setter
    def dbop(self, value) -> None:
        self._set_e2e('dbop', value)

    # --- Session-state piggybacks (#191/#460/#464) -------------------------
    # Each rides in front of the next call; its seq is allocated here so it
    # precedes the call's. All are pure builders — the concrete class does the
    # actual send.

    def _flush_cursor_closes_bytes(self) -> bytes:
        # Build an OCCA (close-cursors) piggyback for the server cursors queued
        # for close (#191), then clear the queue. Empty when nothing is queued.
        if not self._cursors_to_close:
            return b''
        Seq = self._next_seq()
        Data = encode_close_cursors_piggyback(
            Seq, self.field_version, self._cursors_to_close
        )
        self._cursors_to_close = []
        return Data

    def _server_field_version(self) -> int:
        # The field version the SERVER advertised, before negotiating down.
        # Some reply fields follow the server's own release, not the version
        # the session agreed on: a 20.1+ server ends every OER with a SQL type
        # and a checksum even when a client negotiated 12.1 (#1145).
        Caps = self._server_compile_caps
        if len(Caps) > CCAP_FIELD_VERSION:
            return Caps[CCAP_FIELD_VERSION]
        return self.field_version

    def _supports_end_user_sec(self) -> bool:
        # The server advertises end-user security context via a compile-cap bit
        # (#460).
        Caps = self._server_compile_caps
        return len(Caps) > CCAP_FEATURE_BACKPORT2 and bool(
            Caps[CCAP_FEATURE_BACKPORT2] & CCAP_FEATURE_BACKPORT2_END_USER_SEC
        )

    def _supports_txn_priority(self) -> bool:
        # The server advertises transaction priority via a compile-cap bit, 23ai
        # and later (#1776).
        Caps = self._server_compile_caps
        return len(Caps) > CCAP_FEATURE_BACKPORT2 and bool(
            Caps[CCAP_FEATURE_BACKPORT2] & CCAP_FEATURE_BACKPORT2_TXN_PRIORITY
        )

    def _login_txn_priority(self) -> str:
        # The priority the login's ALTER SESSION asks for (#1776). Only for a
        # server with the feature -- another rejects the whole statement, and so
        # the login; connect() refuses that case once logged in. Before the
        # server's capabilities are known (the 23ai fast-auth login) it goes.
        if self._server_compile_caps and not self._supports_txn_priority():
            return ''
        return self._txn_priority_requested

    def _apply_keepalive(self, Sock: socket.socket) -> None:
        # expire_time (#2456): TCP keepalive, the first probe after that many
        # minutes of quiet, as python-oracledb enables it; the probes' spacing
        # and count stay the system's. A platform without the idle option still
        # gets keepalive at its own default.
        if self.expire_time <= 0:
            return
        Sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        Idle = getattr(socket, 'TCP_KEEPIDLE', None) or getattr(
            socket, 'TCP_KEEPALIVE', None
        )
        if Idle is not None:
            Sock.setsockopt(socket.IPPROTO_TCP, Idle, self.expire_time * 60)

    def tpc_forget(self, xid: Xid) -> None:
        """Not supported: python-oracledb's thin mode refuses it too (DPY-3001,
        thick mode only), so there is no thin form to follow (#2457). A server
        sent the forget operation the way the other state changes go refuses it
        as a malformed packet (ORA-03137). Forget a heuristically completed
        branch with DBMS_TRANSACTION.PURGE_LOST_DB_ENTRY instead."""
        raise NotSupportedError(
            'tpc_forget is not supported: python-oracledb supports it only in '
            'thick mode, and the thin protocol form is not known'
        )

    def _absorb_identity(self, Identity: dict) -> None:
        # What the login reply says about the server (#2456): the longest
        # identifier it takes (None where it doesn't say, as before 12.2) and
        # its instance's name.
        self.max_identifier_length = Identity.get('max_identifier_length')
        self.instance_name = Identity.get('instance_name')

    @property
    def transaction_in_progress(self) -> bool:
        """Whether the session has a transaction open, as the server said in
        its last reply (the TXN_IN_PROGRESS bit of the call status, #2456).
        Not available before Oracle 10g, whose replies seerdb doesn't read it
        from."""
        if self.field_version < FIELD_VERSION_10_2:
            raise NotSupportedError(
                'transaction_in_progress is not available before Oracle 10g'
            )
        return bool(
            self._call_status and self._call_status[0] & TNS_EOCS_FLAGS_TXN_IN_PROGRESS
        )

    def is_healthy(self) -> bool:
        """Whether the connection is usable, without a round trip (#2456).

        False once it is closed, its socket has failed or the server closed
        it, or the server's last reply ended the session (a killed session,
        an instance shutting down, a lost connection). A session ended
        server-side without a word, by a firewall or a kill not yet reported,
        only shows on the next call: use ``ping()`` to find out for sure."""
        if self.conn_state != CONN_STATE_AUTHENTICATED:
            return False
        if self._call_status[1:2] and self._call_status[1] in _SESSION_ENDED:
            return False
        return self._socket_open()

    def _absorb_session_keywords(self) -> None:
        # Take the session state the last reply reported (#1776).
        Keywords = self._session_keywords
        if TNS_KEYWORD_NUM_TXN_PRIORITY in Keywords:
            self._txn_priority = Keywords[TNS_KEYWORD_NUM_TXN_PRIORITY]
        Keywords.clear()

    def _require_txn_priority(self) -> None:
        if not self._supports_txn_priority():
            raise NotSupportedError(
                'the database does not support transaction priority '
                '(requires Oracle 23ai or later)'
            )

    @property
    def transaction_priority(self) -> TransactionPriority | None:
        """The session's priority for 23ai's priority transactions (#1776), as
        the server last reported it: at login, after a change, and after an
        ``ALTER SESSION SET TXN_PRIORITY``. Setting it sends the change with the
        next call; ``''``, ``None`` or ``TransactionPriority.DEFAULT`` restores the
        database's default. NotSupportedError before 23ai."""
        self._require_txn_priority()
        if not self._txn_priority:
            return None
        return TransactionPriority[self._txn_priority.upper()]

    @transaction_priority.setter
    def transaction_priority(self, value: str | TransactionPriority | None) -> None:
        Priority = _transaction_priority(value)
        self._require_txn_priority()
        self._txn_priority = Priority.value
        self._txn_priority_pending = Priority.value

    def _flush_alter_session_bytes(self) -> bytes:
        # One-shot ALTER SESSION piggyback for a changed priority (#1776).
        if self._txn_priority_pending is None:
            return b''
        Bytes = encode_alter_session_piggyback(
            self._next_seq(), self.field_version, self._txn_priority_pending
        )
        self._txn_priority_pending = None
        return Bytes

    def _flush_end_user_sec_bytes(self) -> bytes:
        # func-205 piggyback re-sent in front of every call while a context is
        # set (#460). Empty when none is set.
        if self._end_user_sec_context is None:
            return b''
        Seq = self._next_seq()
        return encode_end_user_sec_piggyback(
            Seq, self.field_version, self._end_user_sec_context
        )

    def set_end_user_security_context(self, context: EndUserSecurityContext) -> None:
        """Attach an end-user security context to the connection (#460).

        Once set, the context is sent (as a func-205 piggyback) in front of every
        subsequent database operation until :meth:`clear_end_user_security_context`
        is called. Build ``context`` with
        :func:`seerdb.create_end_user_security_context`.

        The reference thin client restricts this feature to TLS (tcps)
        transports and to servers that advertise it (Oracle 26ai and later), and
        seerdb mirrors both guards.
        """
        if not isinstance(context, EndUserSecurityContext):
            raise TypeError('expecting an EndUserSecurityContext instance')
        if not self.ssl:
            raise ProgrammingError(
                'end_user_security_context requires use of the tcps protocol'
            )
        if not self._supports_end_user_sec():
            raise NotSupportedError(
                'the database does not support end-user security context '
                '(requires Oracle 26ai or later)'
            )
        self._end_user_sec_context = context.oson_bytes

    def clear_end_user_security_context(self) -> None:
        """Clear any end-user security context previously set on the connection
        (#460), reverting to operations without an attached context."""
        self._end_user_sec_context = None

    def _take_app_context(self) -> dict:
        # What changed since the last call, for a dialect that sends it itself
        # (a pooled 11g session's, #2466), and forgotten as it is sent.
        (Changed, self._app_context) = (self._app_context, {})
        return Changed

    def _flush_app_context_bytes(self) -> bytes:
        # One func-154 piggyback per namespace changed since the last call
        # (#1775), each sent once. Empty when nothing changed.
        Out = b''
        for Namespace, Entries in self._app_context.items():
            Out += encode_app_context_piggyback(
                self._next_seq(),
                self.field_version,
                Namespace.encode('utf-8'),
                [(K.encode('utf-8'), V.encode('utf-8')) for K, V in Entries.items()],
            )
        self._app_context = {}
        return Out

    def _check_app_context(self, namespace: str) -> None:
        if not isinstance(namespace, str) or not namespace:
            raise ValueError('application context namespace must be a non-empty string')
        # 8i and 9i accept the piggyback and ignore it, so a context set there
        # would silently never take effect (#1775).
        if self.field_version < FIELD_VERSION_10_2:
            raise NotSupportedError('application context requires Oracle 10g or later')

    def set_app_context(self, namespace: str, **values: str) -> None:
        """Set attributes of an application context namespace (#1775), as
        ``DBMS_SESSION.SET_CONTEXT`` would, without a round trip of its own: the
        change is sent with the next call. Repeated calls before that call
        accumulate. ``CLIENTCONTEXT`` is the namespace any session may set;
        another needs a context created for it, and the next call fails with
        ORA-28267 when the session may not set it."""
        self._check_app_context(namespace)
        if not values:
            raise ValueError(
                'application context must contain at least one key/value pair'
            )
        for Key, Value in values.items():
            if not isinstance(Value, str):
                raise TypeError('application context values must be strings')
            for What, Text, Limit in (
                ('key', Key, APP_CONTEXT_KEY_MAX_LEN),
                ('value', Value, APP_CONTEXT_VALUE_MAX_LEN),
            ):
                Length = len(Text.encode('utf-8'))
                if Length > Limit:
                    raise ValueError(
                        f'application context {What} length ({Length} bytes) '
                        f'exceeds the maximum allowed ({Limit} bytes)'
                    )
        self._app_context.setdefault(namespace, {}).update(values)

    def clear_app_context(self, namespace: str) -> None:
        """Clear every attribute of an application context namespace (#1775), as
        ``DBMS_SESSION.CLEAR_CONTEXT`` would; sent with the next call, and
        replacing any attributes set for it since the last one."""
        self._check_app_context(namespace)
        self._app_context[namespace] = {}

    def _supports_request_boundaries(self) -> bool:
        # Explicit request boundaries need a compile-cap bit AND a runtime-cap
        # bit (#464).
        Cc = self._server_compile_caps
        Rc = self._server_runtime_caps
        return (
            len(Cc) > CCAP_TTC4
            and bool(Cc[CCAP_TTC4] & CCAP_TTC4_EXPLICIT_BOUNDARY)
            and len(Rc) > RCAP_TTC
            and bool(Rc[RCAP_TTC] & RCAP_TTC_SESSION_STATE_OPS)
        )

    def _flush_session_state_bytes(self) -> bytes:
        # One-shot request-boundary piggyback (#464). Empty when nothing armed.
        if self._session_state_desired == 0:
            return b''
        Seq = self._next_seq()
        Data = encode_session_state_piggyback(
            Seq, self.field_version, self._session_state_desired
        )
        self._session_state_desired = 0
        return Data

    def _begin_request(self) -> None:
        # Arm a REQUEST_BEGIN marker for a pooled logical request (#464).
        if self._supports_request_boundaries():
            self._session_state_desired = TNS_SESSION_STATE_REQUEST_BEGIN
            self._in_request = True

    def _fetch_by_execute_bytes(self, CursorId: int) -> bytes:
        # One batch from a cursor the client holds no SQL for -- a nested
        # cursor's or a REF CURSOR's -- as a FETCH-only OALL8 on its id, which
        # is how oracledb-thin and OCI fetch one. A TTI_FETCH works on 23ai, but
        # 10g-21c answer it with each CURSOR column of the rows cut to its id,
        # with no inline describe, so a cursor nested in one is unreadable
        # (#1462). No piggybacks, as a TTI_FETCH carries none: the cursor-close
        # queue may hold this cursor's parent, and closing the parent first
        # closes this one too.
        Query = {
            'type': 'select',
            'auto': 0,
            'fetch': self.fetch,
            'server_version': self.server_version,
            'cursor': CursorId,
            'query': '',
            'bind': [],
            'batch': [],
            'def': [],
            'batcherrors': None,
            'arraydmlrowcounts': None,
            'return_binds': None,
            'fetch_only': True,
        }
        return encode_dictionary(self._make_dict(DictionaryType.exec, query=Query))

    # --- Request-dictionary builder ----------------------------------------

    def _make_dict(self, Type: DictionaryType, **extra) -> dict:
        d = {
            'env': {
                'host': self.host,
                'port': self.port,
                'user': self.user,
                'proxy_user': self.proxy_user,
                'cclass': self.cclass,
                'purity': self.purity,
                'server_type': self.server_type,
                'instance_name': self._instance_name_requested,
                'expire_time': self.expire_time,
                'password': self.password,
                'sid': self.sid,
                'service_name': self.service_name,
                'ssl': self.ssl,
                'socket_options': self.socket_options,
                'conn_state': self.conn_state,
                'timeout': self.timeout,
                'autocommit': self.autocommit,
                'fetch': self.fetch,
                'role': self.role,
                'charset': self.charset,
                'prelim': self.prelim,
                'app_name': self.app_name,
                # The banner reported as v$session_connect_info.client_driver.
                # None keeps seerdb's own (#826).
                'driver_name': self.driver_name,
                'edition': self.edition,
                # Session identity recorded in v$session (#826). Each is
                # None unless the caller set it, and encode_dictionary_sess
                # falls back to what this process actually is.
                'program': self.program,
                'machine': self.machine,
                'terminal': self.terminal,
                'osuser': self.osuser,
            },
            'sdu': self.sdu,
            'type': Type,
            'req': self.charset,
            'seq': self._next_seq(),
            'field_version': self.field_version,
            'oall8': getattr(self, '_oall8', False),
            # The native 11g login (#2466) sends the OCI banner in its PRO.
            'oci_banner': getattr(self, '_native11', False),
            'max_string_size': max_string_size(self._server_runtime_caps),
            'supports_eor': self._supports_eor,
            # The priority the login's ALTER SESSION asks for (#1776).
            'txn_priority': self._login_txn_priority(),
        }
        d.update(extra)
        return d

    # --- TLS wallet / ANO encryption helpers -------------------------------

    def _apply_wallet(
        self,
        WalletLocation: str | None,
        WalletPassword: str | None,
        ConfigDir: str | None,
        Dsn: str | None,
    ) -> None:
        # Resolve an Oracle wallet into connect parameters + a client SSLContext
        # (#127). Imported lazily so the `cryptography` dependency is only needed
        # when a wallet connection is actually requested.
        from seerdb.client import wallet as _wallet

        Location = WalletLocation or ConfigDir
        if not Location:
            raise _wallet.WalletError('wallet_location or config_dir is required')
        Wal = _wallet.open_wallet(Location, WalletPassword, Dsn)
        Info = Wal.connect
        if Info is not None:
            # What the alias names wins over host / port / service_name passed
            # beside it, as in python-oracledb and as an Easy Connect dsn does
            # (#1975, #1972).
            self.host = Info.host
            self.port = Info.port
            if Info.service_name:
                (self.service_name, self.sid) = (Info.service_name, '')
            elif Info.sid:
                (self.service_name, self.sid) = ('', Info.sid)
            if Info.dn_match and Info.server_dn:
                self._wallet_server_dn = Info.server_dn
        self.ssl = _wallet.build_client_context(Wal)

    def _check_server_dn(self, PeerCert: dict | None) -> None:
        # Oracle SSL_SERVER_DN_MATCH (#127): the server is authenticated by its
        # certificate subject DN, not its hostname. The chain was already
        # verified by the TLS stack against the wallet CA; here we assert the DN.
        if self._wallet_server_dn is None:
            return
        import ssl as _ssl

        from seerdb.client import wallet as _wallet

        if not _wallet.server_dn_matches(self._wallet_server_dn, PeerCert):
            raise _ssl.SSLError(
                f'server certificate DN does not match {self._wallet_server_dn!r}'
            )

    def _encode_ano_packet(self, Data: bytes) -> tuple[bytes, bytes | None]:
        # One encrypted TNS_DATA fragment (#437); shared with the Mirror's
        # PacketStream._write_data_ano via encode_ano_fragment.
        assert self._ano is not None  # only called while the ANO cipher is active
        return encode_ano_fragment(Data, self.sdu, self._ano, self._large_packets)

    def _rederive_ano_after_reset(self) -> None:
        # The client answered the server's break with its reset marker: an
        # in-band error report. The server re-derives its data-integrity
        # keystreams at this point and so must we, before the error that follows
        # is unwrapped; otherwise that packet fails its MAC and the session is
        # lost at its first error (#1345, PROTOCOL.md 33.6).
        if self._ano is not None:
            self._ano.rederive()

    # --- Capability / dialect / misc pure helpers --------------------------

    def _nego_cache_key(self) -> tuple[str, int, str]:
        # Identify the connection target for the negotiation cache (#438).
        return (self.host, self.port, self.service_name or self.sid or '')

    def _select_dialect(self, is_8i: bool = False) -> None:
        # Pick the wire dialect once the negotiated version is final — the single
        # discriminator the rest of the driver reads (#369). 8i and 9i both
        # advertise fv2, so the 8i banner (passed in) is what tells them apart;
        # modern (10g->23ai) keeps _dialect None and takes the TTI_ALL8 path.
        if is_8i:
            self._dialect = O8iDialect(self._next_seq)
        elif getattr(self, '_native11', False):
            # A pooled 11g session speaks the native form throughout (#2466).
            self._dialect = Oci11Dialect(
                self._next_seq,
                self._native11_session,
                self._native11_call_status,
                self._take_app_context,
            )
        elif self.field_version < FIELD_VERSION_10_2:
            # The 9i OALL8 opt-in (#716) speaks the native 64-bit request form;
            # the default 9i path speaks the compact TTI_ALL7.
            self._dialect = (
                Fv2Oall8Dialect(self._next_seq)
                if getattr(self, '_oall8', False)
                else Fv2Dialect()
            )
        else:
            self._dialect = None

    def _fv2_raise_for_error(self, Packet: bytes) -> None:
        # Thin delegate to the shared colorless helper — still used by the inline
        # 8i methods until they migrate to a dialect (#369).
        from seerdb.client.dialect import fv2_raise_for_error

        fv2_raise_for_error(Packet)

    def _check_sessionless_support(self) -> None:
        if self.field_version < FIELD_VERSION_23_1:
            raise NotSupportedError(
                'sessionless transactions require an Oracle 23ai+ server'
            )

    def _pipeline_wire_eligible(self, pipeline) -> bool:
        # The single-round-trip wire path (#158) needs end-of-response framing
        # (23ai) and covers only the exec-family ops, whose token framing is
        # verified against a capture. A pipeline with a commit / callproc /
        # callfunc op runs serially instead (correct results, no optimisation).
        from seerdb.client.pipeline import PipelineOpType as T

        WireOps = (T.EXECUTE, T.EXECUTE_MANY, T.FETCH_ONE, T.FETCH_MANY, T.FETCH_ALL)
        if not self._supports_eor or not pipeline.operations:
            return False
        return all(Op.op_type in WireOps for Op in pipeline.operations)

    def _on_call_timeout(self) -> None:
        # call_timeout timer callback: flag the timeout and break the call. A
        # server that does not answer the break within call_timeout again has
        # the connection dropped, as python-oracledb drops it (#1570).
        self._timed_out = True
        self._send_break()
        self._arm_break_deadline()

    # --- Statement cache / call-timeout / cancel ---------------------------

    @property
    def stmtcachesize(self) -> int:
        """Number of server-side cursors kept in the statement cache (PEP 249
        extension / oracledb-compatible). Setting it smaller evicts the oldest
        entries immediately; 0 disables caching."""
        return self._cursor_cache_max

    @stmtcachesize.setter
    def stmtcachesize(self, value: int) -> None:
        self._cursor_cache_max = max(0, int(value))
        while len(self._cursor_cache) > self._cursor_cache_max:
            Oldest = next(iter(self._cursor_cache))
            self._cursor_cache.pop(Oldest, None)

    @property
    def call_timeout(self) -> int:
        """Per-call timeout in milliseconds (0 = none). A call that runs longer
        is interrupted with an in-band break and raises a timeout error
        (#123/#144, oracledb-compatible)."""
        return self._call_timeout

    @call_timeout.setter
    def call_timeout(self, value: int) -> None:
        self._call_timeout = max(0, int(value or 0))

    def cancel(self) -> None:
        """Interrupt the call currently executing on this connection (#123/#144).

        Sends a break (an out-of-band urgent byte when the server advertised
        attention support, otherwise an in-band INTERRUPT marker); the thread
        blocked in the call drains the server's interrupt response and raises
        ORA-01013. Safe to call from another thread (e.g. a timer/signal)."""
        self._send_break()

    @property
    def version(self) -> str | None:
        """Server version as a dotted release string (e.g. '11.2.0.2.0'), or
        None before authentication. Decoded from the packed AUTH_VERSION_NO the
        server returns at logon; oracledb-compatible."""
        # Lazy import: _format_version lives in connection.py, which imports
        # this mixin — a module-level import would be circular.
        from seerdb.client.connection import _format_version

        return _format_version(self.server_version)

    def xid(self, format_id: int, global_transaction_id, branch_qualifier) -> Xid:
        """Build a global transaction id (Xid) for the TPC methods."""
        from seerdb.client.connection import Xid

        return Xid(format_id, global_transaction_id, branch_qualifier)

    def subscribe(self, *args: object, **kwargs: object) -> None:
        """Register a Continuous Query Notification subscription — not supported
        (#129). Accepts any arguments for API compatibility and raises
        NotSupportedError; see ``_reject_cqn``."""
        from seerdb.client.connection import _reject_cqn

        _reject_cqn()

    def unsubscribe(self, *args: object, **kwargs: object) -> None:
        """Remove a CQN subscription — not supported (#129); the counterpart to
        ``subscribe``, raising NotSupportedError for the same reason."""
        from seerdb.client.connection import _reject_cqn

        _reject_cqn()

    def _rows(self, result: object) -> list:
        # The row block of an execute() result (execute is typed `object`); [] if
        # the result carries no rows.
        return (
            result[4]
            if isinstance(result, tuple) and len(result) > 4 and result[4]
            else []
        )

    def msgproperties(
        self,
        payload=None,
        correlation=None,
        delay=0,
        expiration=-1,
        priority=0,
        exceptionq=None,
        recipients=None,
    ):
        """Build a MessageProperties for enqueue."""
        from seerdb.client.aq import MessageProperties

        return MessageProperties(
            payload=payload,
            correlation=correlation,
            delay=delay,
            expiration=expiration,
            priority=priority,
            exceptionq=exceptionq,
            recipients=recipients,
        )

    def dialect_serves_lobs(self) -> bool:
        """Whether this session's pre-10g dialect serves a LOB object's calls
        itself -- 9i's LOBOPS form, persistent-LOB writes included (#2259)."""
        return dialect_lob_objects(getattr(self, '_dialect', None))

    def _raise_lobops_error(self, Packet: bytes) -> None:
        # Decode the OER trailing a content-free LOBOPS response and raise on a
        # real ORA error. decode_lobops_oer skips the RPA's binary locator and
        # matches the OER regardless of call status (which is 5, not 1,
        # immediately after a PL/SQL execute — the case that desynced the temp
        # LOB write following a temp-LOB-bind exec).
        from seerdb.common.exceptions import from_ora_code
        from seerdb.common.tns import decode_lobops_oer

        (ErrCode, Message) = decode_lobops_oer(Packet, self.field_version)
        if ErrCode and ErrCode not in (0, ORA_NO_DATA_FOUND):
            raise from_ora_code(ErrCode)(Message or f'ORA-{ErrCode:05d}', code=ErrCode)


def _pre10_tier_name_for(Dialect) -> str:
    """``8i`` or ``9i`` for a pre-10g dialect, so a refusal names the real server.

    Both tiers negotiate TTC field version 2, so the version alone cannot tell
    them apart and a hard-coded "Oracle 9i" in a message is wrong half the time.
    """
    from seerdb.client.dialect import O8iDialect, Oci11Dialect

    if isinstance(Dialect, Oci11Dialect):
        return '11g (a pooled connection)'
    return '8i' if isinstance(Dialect, O8iDialect) else '9i'


def dialect_lob_objects(Dialect) -> 'TypeGuard[Fv2Dialect]':
    """Whether a pre-10g dialect serves a LOB object's calls itself (9i, #2259)."""
    from seerdb.client.dialect import CAP_LOB_OBJECT

    return Dialect is not None and CAP_LOB_OBJECT in Dialect.capabilities()


def dialect_temp_lobs(Dialect) -> 'TypeGuard[Oci11Dialect]':
    """Whether a pre-12c dialect makes a temporary LOB itself (a pooled 11g
    session, #2466), so a LOB Var's value binds through one as on 12c+."""
    from seerdb.client.dialect import CAP_TEMP_LOB

    return Dialect is not None and CAP_TEMP_LOB in Dialect.capabilities()


def dialect_parses(Dialect) -> 'TypeGuard[Oci11Dialect]':
    """Whether a pre-10g dialect serves cursor.parse() in its own form (a
    pooled 11g session, #2466)."""
    from seerdb.client.dialect import CAP_PARSE

    return Dialect is not None and CAP_PARSE in Dialect.capabilities()


def dialect_pings(Dialect) -> 'TypeGuard[Oci11Dialect]':
    """Whether a pre-10g dialect serves connection.ping() in its own form (a
    pooled 11g session, #2466)."""
    from seerdb.client.dialect import CAP_PING

    return Dialect is not None and CAP_PING in Dialect.capabilities()


def native_returning(Dialect, Bind, ReturnBinds) -> 'TypeGuard[Oci11Dialect]':
    """Whether a pre-10g dialect runs this DML's RETURNING ... INTO as itself (a
    pooled 11g session, #2466) rather than as the PL/SQL block 8i and 9i take.
    A LOB target keeps the block, which serves it; its native form is not
    measured."""
    from seerdb.client.dialect import CAP_RETURNING
    from seerdb.common.datatypes import Var
    from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_CLOB

    if Dialect is None or CAP_RETURNING not in Dialect.capabilities():
        return False
    return not any(
        isinstance(Bind[Pos], Var)
        and Bind[Pos].dbtype.tns_type in (TNS_TYPE_CLOB, TNS_TYPE_BLOB)
        for Pos in ReturnBinds
        if Pos < len(Bind)
    )


def dialect_scrolls(Dialect) -> 'TypeGuard[Oci11Dialect]':
    """Whether a pre-10g dialect serves a server-side scrollable cursor in its
    own form (a pooled 11g session, #2466)."""
    from seerdb.client.dialect import CAP_SCROLL

    return Dialect is not None and CAP_SCROLL in Dialect.capabilities()


def temp_lobs_available(Conn) -> bool:
    """Whether the connection can make a temporary LOB to bind: 12c+, or a
    dialect that makes one itself."""
    from seerdb.common.tns_consts import FIELD_VERSION_12_1

    return getattr(Conn, 'field_version', 0) >= FIELD_VERSION_12_1 or (
        dialect_temp_lobs(getattr(Conn, '_dialect', None))
    )


def pre10_dml_applied(Result: object, BatchErrors: bool) -> bool:
    """Whether a pre-10g DML's result is one autocommit commits.

    Its error comes back in the result for the cursor to raise, and then there
    is nothing to commit -- except in `batcherrors` mode, where ORA-24381 says
    the good rows were applied and the failures are listed (#2247), and they
    commit as on 10g+.
    """
    Code = Result[1] if isinstance(Result, tuple) else 0
    return not Code or (BatchErrors and Code == ORA_ARRAY_DML_ERRORS)


def refuse_pre10_batch(Dialect, Head: str, ReturnBinds, BatchErrors: bool) -> None:
    """Refuse an executemany a pre-10g tier cannot run as array DML.

    9i takes a plain INSERT / UPDATE / DELETE batch in one TTI_ALL7 call
    (#2245), batch errors included (#2247); 8i takes none. Anything else would
    apply only the first row and silently drop the rest (#168), so it is
    refused: an array RETURNING, and a batch of a query or a PL/SQL block.
    """
    from seerdb.client.dialect import CAP_ARRAY_DML

    Tier = 'Oracle ' + _pre10_tier_name_for(Dialect)
    if CAP_ARRAY_DML not in Dialect.capabilities():
        raise NotSupportedError(f'executemany (array DML) is not supported on {Tier}')
    if ReturnBinds:
        raise NotSupportedError(f'an array DML RETURNING is not supported on {Tier}')
    if Head.startswith(('SELECT', 'BEGIN', 'DECLARE')):
        raise NotSupportedError(
            f'executemany of a query or PL/SQL block is not supported on {Tier}'
        )


def returning_block_request(Query: str, Bind: list) -> tuple[str, list]:
    """A pre-10g ``DML ... RETURNING ... INTO`` rewritten as a block request (#801).

    Returns the wrapped SQL and the bind list with one appended OUT bind that
    receives ``SQL%ROWCOUNT``; :func:`returning_block_result` takes it back out.

    Each INTO target goes in as an empty copy of its variable. It only
    receives, but the block's binds say IN OUT for a variable that holds a
    value -- and one that received from an earlier RETURNING holds the LIST of
    returned values, which 8i then tried to send as its input and could not
    encode (#1390). The values still land in the caller's variable: they are
    assigned through the caller's own bind list.
    """
    import copy

    from seerdb.common.datatypes import Var
    from seerdb.common.sqltext import returning_bind_positions, wrap_returning_in_block

    Wrapped, _Name = wrap_returning_in_block(Query)
    Targets = returning_bind_positions(Query, len(Bind))
    Block = []
    for Pos, Value in enumerate(Bind):
        if Pos in Targets and isinstance(Value, Var):
            Value = copy.copy(Value)
            Value._value = [] if Value.is_array else None
            Value.has_value = False
            Value._iteration_values = None
        Block.append(Value)
    return Wrapped, Block + [Var(int)]


def returning_block_result(Result, NumBinds: int):
    """Make the block's reply look like a native DML RETURNING reply.

    Two things have to be corrected before the cursor sees it.

    The row count: a PL/SQL block reports its own execution -- measured as 1
    however many rows the DML touched -- so the real figure rides in the extra
    bind :func:`returning_block_request` appended, and is lifted into the slot
    every other statement's row count lives in.

    The shape: a native RETURNING bind hands back **a list, one entry per
    affected row** (``[2]``, ``[None]`` when the row's value is NULL, or ``[]``
    when nothing matched), which is what python-oracledb does and what callers
    on 10g+ already see. Read as a PL/SQL OUT bind it would arrive as a bare
    scalar instead, so the same code would need writing twice to be portable
    across tiers. Re-label the record as the
    return record the cursor's native path decodes, and the tiers agree.

    The block form binds at most one row -- Oracle raises ORA-01422 for more, as
    it does anywhere else -- so each list holds one value or none.
    """
    from decimal import Decimal

    from seerdb.common.types import TNS_TYPE_NUMBER, decode_value

    if not isinstance(Result, tuple) or len(Result) < 5:
        return Result
    Rows = Result[4]
    if not Rows or not isinstance(Rows[0], dict) or 'out_positions' not in Rows[0]:
        return Result
    Record = Rows[0]
    RowCount = None
    ReturnPositions: list = []
    Raws: list = []
    for Pos, Raw in zip(
        Record.get('out_positions') or [], Record.get('out_values') or []
    ):
        if Pos == NumBinds:  # the appended SQL%ROWCOUNT bind
            Decoded = decode_value({'data_type': TNS_TYPE_NUMBER}, Raw or None)
            if isinstance(Decoded, (int, float, Decimal)):
                RowCount = int(Decoded)
            continue
        ReturnPositions.append(Pos)
        Raws.append(Raw)
    # An empty OUT value means one of two things, and they are not the same
    # answer: the statement matched no row, or it matched one whose returned
    # value is NULL. Collapsing both into [] reported a NULL RETURNING as "no
    # rows returned", where 10g+ gives [None] (#1022). The rowcount the rewrite
    # already appends tells them apart -- which is why the values are built
    # after the loop, since that bind comes last.
    Matched = bool(RowCount)
    ReturnValues = [[Raw] if Raw else ([None] if Matched else []) for Raw in Raws]
    NewRecord = {'return_positions': ReturnPositions, 'return_values': ReturnValues}
    Meta = Result[3][1] if isinstance(Result[3], tuple) and len(Result[3]) > 1 else None
    return Result[:3] + ((RowCount, Meta), [NewRecord]) + Result[5:]


def returning_block_error(Error):
    """Explain a pre-10g RETURNING failure that is really a shape limitation.

    A statement matching several rows is the one case where the block rewrite
    and the native path genuinely differ: 10g+ hands back every returned row,
    while the block binds scalars and Oracle answers ORA-01422. Left alone that
    surfaces as a bare "ORA-01422" with nothing to connect it to the tier, so
    translate it; any other error is returned untouched for the caller to raise.
    """
    from seerdb.common.exceptions import NotSupportedError

    if getattr(Error, 'code', None) != ORA_TOO_MANY_ROWS:
        return Error
    return NotSupportedError(
        'a DML ... RETURNING ... INTO that affects more than one row needs an '
        'Oracle 10g+ server: below 10g the statement runs as a PL/SQL block, '
        'whose scalar INTO targets can take a single row (ORA-01422). Restrict '
        'the statement to one row, or read the rows back with a SELECT.'
    )


def _transaction_priority(value: object) -> TransactionPriority:
    """A transaction priority given as a TransactionPriority, its name in any
    case, ``''`` or ``None`` (the default), as python-oracledb accepts it (#1776)."""
    if isinstance(value, TransactionPriority):
        return value
    if value is None or value == '':
        return TransactionPriority.DEFAULT
    if isinstance(value, str):
        try:
            return TransactionPriority[value.upper()]
        except KeyError:
            pass
        raise ValueError(f'invalid transaction priority: {value!r}')
    raise TypeError('value must be from the enumeration seerdb.TransactionPriority')
