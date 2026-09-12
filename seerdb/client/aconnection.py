# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Async-native counterpart to `seerdb.client.connection.OracleConnect`.

Shares the pure protocol code in `seerdb.common.tns` (encode_packet,
assemble_packet, decode_packet, the encoders/decoders for every
TTI token) — those are byte-in / decoded-out and don't care which
transport drives them. The duplication here is just the I/O layer
and the connection-level state machine: TCP/TLS via
`asyncio.open_connection`, and `async def` versions of `send`,
`recv`, `handle_login`, `execute`, `fetch_more`.

Why not a thin sync wrapper around this async code: see the
discussion in the README on architecture choices. Calling
`asyncio.run()` from a sync API explodes inside any context that
already has a running event loop (web frameworks, Jupyter), and
the `nest_asyncio` workarounds are fragile. Two native paths are
cleaner.
"""

import asyncio
import logging
import socket
import struct
from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from seerdb.common.ano_session import AnoChannel
    from seerdb.common.dbobject import DbObjectType

from seerdb.client._conn_logic import (
    _ConnectionLogic,
    _pre10_tier_name_for,
    returning_block_error,
    returning_block_request,
    returning_block_result,
)
from seerdb.client.connection import (
    _MAX_REDIRECTS,
    _REDIRECT_CONNECT_ATTEMPTS,
    _REDIRECT_CONNECT_DELAY,
    Xid,
    _decode_tpc_context,
    _decode_tpc_state,
    _normalize_sessionless_txn_id,
    _parse_accept_eor,
    _parse_accept_sdu,
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
    FLUSH_OUT_BINDS,
    MAX_FLUSH_OUT_BINDS,
    assemble_packet,
    decode_packet,
    decode_token_pro,
    decode_token_rpa,
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
    FIELD_VERSION_10_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_12_2,
    FIELD_VERSION_23_1,
    FIELD_VERSION_23_4,
    PURITY_DEFAULT,
    TNS_ACCEPT,
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
    TPC_BEGIN_NEW,
    TPC_BEGIN_RESUME,
    TPC_END_NORMAL,
    TPC_TXN_FLAGS_SESSIONLESS,
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


class AsyncOracleConnect(_ConnectionLogic):
    """Async equivalent of `OracleConnect`. Same constructor surface so
    pool / cursor / app code can swap one for the other given an
    appropriate sync vs async caller."""

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
        from seerdb.client.connection import _reject_sharding

        _reject_sharding(shardingkey, supershardingkey)
        # Negotiation cache (#438): opt-in reconnect optimization, sharing the
        # process-level cache with the sync connection.
        self.negotiation_cache = negotiation_cache
        self._used_nego_cache = False
        self._skip_nego_cache = False
        self.host = host
        self.port = port
        # Proxy auth (#126): split proxy_user[schema] (see OracleConnect).
        from seerdb.client.connection import _split_proxy_user

        (self.user, self.proxy_user) = _split_proxy_user(user)
        self.cclass = cclass  # DRCP (#130)
        self.purity = purity
        self.password = password
        self.sid = sid
        self.service_name = service_name
        self.ssl = ssl
        self.socket_options = socket_options
        self.conn_state = CONN_STATE_DISCONNECTED
        self.timeout = timeout
        self.autocommit = autocommit
        self.fetch = fetch
        self.role = role
        self.sdu = sdu
        self.charset = charset
        self.prelim = prelim
        self.app_name = app_name
        # Token auth (#125), resolved at connect time.
        self.access_token = access_token
        self._token_auth = False

        # Wallet-based mutual TLS (#127); see OracleConnect for the full note.
        # The DN check runs in _open_transport once the TLS handshake completes.
        self._wallet_server_dn: str | None = None
        if wallet_location is not None or config_dir is not None:
            self._apply_wallet(wallet_location, wallet_password, config_dir, dsn)

        # asyncio StreamReader / StreamWriter pair, set by `connect()`.
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.seq = 1
        # Break/reset state, mirrors OracleConnect (#45): bytes held past a
        # marker for the next recv(), and a latch so we answer a server break
        # with exactly one reset then drain the rest silently (2:1 ratio).
        self._pending = b''
        self._in_break = False
        # Query cancellation / call_timeout (#123), mirrors OracleConnect.
        self._break_in_progress = False
        self._call_timeout = 0
        self._timed_out = False
        self._supports_oob = False  # set from the accept (#144)
        self._supports_eor = False  # end-of-response (#155/#132)
        self._large_packets = False  # 4-byte framing (#155, >=315)
        # Pre-10g wire dialect selected after login (sans-io, driven by _drive),
        # or None for the modern path (#369).
        self._dialect: Dialect | None = None
        self._e2e_values: dict = {}  # end-to-end tracing (#183)
        self._e2e_pending: dict = {}
        # End-user security context (#460): OSON image once set, re-sent as a
        # func-205 piggyback on every call; server caps kept to gate the feature.
        self._end_user_sec_context: bytes | None = None
        self._server_compile_caps: bytes = b''
        self._server_runtime_caps: bytes = b''
        # Request boundaries (#464): pooled session-state marker + in-request flag.
        self._session_state_desired: int = 0
        self._in_request: bool = False
        self._transaction_context: bytes | None = None  # two-phase commit (#131)
        self._sessionless_txn_active = False  # sessionless txns (#133)
        # Native network encryption / data integrity (#437). Set by the ANO
        # negotiation after the accept; once active each TNS_DATA payload is
        # encrypted + MAC'd on the wire. None (the common case) means plaintext.
        self._ano: AnoChannel | None = None
        self.conn_key: bytes | None = None
        self.server_version = 0
        self.session_id = None
        # Negotiated TTC field version; see OracleConnect for the full note.
        self.field_version = field_version
        self._field_version_requested = field_version  # for the nego-cache retry
        self.cursors: dict[int, int] = {}
        # Cursor cache — same shape as the sync `OracleConnect`. DML only.
        # Keyed on (SQL, bind OAC signature); see OracleConnect for why the
        # bind signature has to be part of the key.
        self._cursor_cache: dict[tuple[str, bytes], int] = {}
        self._cursor_cache_max = 32
        self._cursors_to_close: list[int] = []  # drained cursors to free (#191)
        # Ordered attribute layout per SQL object type (#115), keyed by
        # (owner, type_name); see OracleConnect._object_type_layout.
        self._object_type_cache: dict[tuple[str, str], 'DbObjectType'] = {}

    # ----- bookkeeping shared with the sync class -----
    # These are copy-pasted from connection.py rather than imported via a
    # mixin because the sync class also has them and any future divergence
    # (timeouts, async-only fields) should stay local to each side.

    def _next_seq(self) -> int:
        from seerdb.common.tns_consts import MAX_SEQ_NUM

        seq = self.seq
        self.seq = self.seq % MAX_SEQ_NUM + 1
        return seq

    async def _send_token_auth(self) -> None:
        # Async port of OracleConnect._send_token_auth (#125).
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
        await self.send(TNS_DATA, encode_dictionary_token_auth(Dict))

    # ----- I/O primitives -----

    async def _open_transport(self) -> None:
        # Open the TCP (optionally TLS) socket to the current host/port and send
        # the initial CONNECT. Shared by connect() and the TNS_REDIRECT handler.
        SslArg = self._ssl_kwarg()
        # Force IPv4 to match the sync path. asyncio.open_connection
        # otherwise defers to getaddrinfo's default ordering, which
        # often hands back ::1 first; some Oracle listener configs
        # only bind IPv4 and silently drop IPv6 connects.
        Loop = asyncio.get_running_loop()
        # Following a redirect (self._redirects > 0), retry a refused connect —
        # the dispatcher / dedicated server may still be binding its port (#399).
        Attempts = _REDIRECT_CONNECT_ATTEMPTS if getattr(self, '_redirects', 0) else 1
        for Attempt in range(Attempts):
            Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            Sock.setblocking(False)
            try:
                await Loop.sock_connect(Sock, (self.host, self.port))
                break
            except ConnectionRefusedError:
                Sock.close()
                if Attempt + 1 >= Attempts:
                    raise
                await asyncio.sleep(_REDIRECT_CONNECT_DELAY)
        self._reader, self._writer = await asyncio.open_connection(
            sock=Sock,
            ssl=SslArg,
            server_hostname=self.host if SslArg else None,
        )
        if SslArg is not None:
            SslObj = self._writer.get_extra_info('ssl_object')
            try:
                self._check_server_dn(SslObj.getpeercert() if SslObj else None)
            except BaseException:
                self._writer.close()
                raise
        Data = encode_dictionary(self._make_dict(DictionaryType.login))
        await self.send(TNS_CONNECT, Data)

    async def connect(self) -> bool:
        """Open the TCP (optionally TLS) connection and run the
        TNS / TTC / O5LOGON handshake."""
        self._redirects = 0
        await self._open_transport()
        try:
            result = await self.handle_login()
        except ConnectionError as Exc:
            # See the sync twin (#805).
            raise OperationalError(
                f'the server closed the connection during login ({Exc})'
            ) from Exc
        except OperationalError:
            # Stale negotiation cache (#438): invalidate and retry with a full
            # negotiation. Mirror of OracleConnect.connect.
            if self._used_nego_cache:
                await self._retry_without_negotiation_cache()
                return True
            raise
        if result not in (0, None) and self._used_nego_cache:
            await self._retry_without_negotiation_cache()
        return True

    async def _retry_without_negotiation_cache(self) -> None:
        from seerdb.client.connection import _nego_cache_del

        _nego_cache_del(self._nego_cache_key())
        self._used_nego_cache = False
        self._skip_nego_cache = True
        await self.disconnect()
        self.seq = 1
        self._pending = b''
        self._in_break = False
        self.conn_state = CONN_STATE_DISCONNECTED
        self.field_version = self._field_version_requested
        self._dialect = None
        self._ano = None
        self.conn_key = None
        self._o3_phase = 0
        await self._open_transport()
        await self.handle_login()

    def _ssl_kwarg(self):
        """Resolve `self.ssl` into something `asyncio.open_connection`
        accepts (None / True / SSLContext)."""
        if not self.ssl:
            return None
        import ssl as _ssl

        if isinstance(self.ssl, _ssl.SSLContext):
            return self.ssl
        if isinstance(self.ssl, dict):
            Opts = dict(self.ssl)
            Opts.pop('server_hostname', None)  # not for asyncio kwarg
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
            return Ctx
        return True

    async def send(self, Type: int, Data: bytes | None) -> None:
        """Iterative split-and-send; mirrors `OracleConnect.send`."""
        while Data is not None:
            if Type == TNS_DATA and self._ano is not None and self._ano.active:
                (Packet, Rest) = self._encode_ano_packet(Data)
            else:
                (Packet, Rest) = encode_packet(
                    Type, Data, self.sdu, self._large_packets
                )
            self._wr.write(Packet)
            Data = Rest
        await self._wr.drain()
        logger.debug('Send OK (async)')

    @property
    def _wr(self) -> asyncio.StreamWriter:
        if self._writer is None:
            raise InterfaceError('connection is not open')
        return self._writer

    @property
    def _rd(self) -> asyncio.StreamReader:
        if self._reader is None:
            raise InterfaceError('connection is not open')
        return self._reader

    async def recv(self, Acc: bytes, Data: bytes) -> tuple[int, bytes] | Literal[False]:
        """Same packet-reassembly state machine as `OracleConnect.recv`,
        but awaiting the StreamReader instead of `sock.recv`. Seeds from and
        preserves into self._pending so a coalesced break|reset|error is not
        dropped (#45)."""
        Acc = self._pending + Acc
        self._pending = b''
        while True:
            while len(Acc) >= 8:
                (Flag, Type, Body, Rest) = assemble_packet(
                    Acc, self.sdu, self._large_packets
                )
                if Flag is True:
                    # A full packet was assembled, so type/body/rest are set.
                    assert Type is not None and Body is not None and Rest is not None
                    if Type == TNS_MARKER:
                        self._pending = Rest
                        return (TNS_MARKER, b'')
                    # Native network encryption (#437): each DATA packet's body is
                    # independently encrypted + MAC'd, so decrypt/verify per packet
                    # before reassembly concatenates the plaintext.
                    if Type == TNS_DATA and self._ano is not None and self._ano.active:
                        Body = self._ano.unwrap(Body)
                    if Rest == b'':
                        return (Type, Data + Body)
                    Acc = Rest
                    Data = Data + Body
                    continue
                if Body is not None:
                    if self._ano is not None and self._ano.active:
                        Body = self._ano.unwrap(Body)
                    Acc = Rest or b''
                    Data = Data + Body
                    continue
                break
            try:
                if self.timeout:
                    NetworkData = await asyncio.wait_for(
                        self._rd.read(self.sdu), self.timeout / 1000
                    )
                else:
                    NetworkData = await self._rd.read(self.sdu)
            except asyncio.IncompleteReadError:
                return False
            except (asyncio.TimeoutError, TimeoutError) as exc:
                from seerdb.common.exceptions import OperationalError

                raise OperationalError(
                    f'network read timed out after {self.timeout} ms '
                    f'(connection timeout)'
                ) from exc
            if not NetworkData:
                return False
            Acc = Acc + NetworkData

    async def _next_data_packet(
        self, Acc: bytes = b'', Data: bytes = b''
    ) -> tuple[int, bytes] | Literal[False]:
        """Async port of `OracleConnect._next_data_packet` (#45): receive the
        next DATA packet, answering a server break with a single reset and
        draining the rest (the server's terminal reset) silently."""
        while True:
            Received = await self.recv(Acc, Data)
            if Received is False:
                return False
            (Type, Packet) = Received
            if Type != TNS_MARKER:
                self._in_break = False
                return (Type, Packet)
            if not self._in_break:
                await self.send(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
                self._in_break = True

    # ----- login state machine -----

    async def handle_login(self) -> int | None:
        """Async port of `OracleConnect.handle_login`."""
        while True:
            Received = await self.recv(b'', b'')
            if Received is False:
                # See the sync twin: a dead socket used to leave connect() as a
                # live connection (#805).
                logger.debug('handle_login (async): peer closed')
                raise OperationalError(
                    'the server closed the connection during login (no reply to the last handshake packet)'
                )
            (Type, Packet) = Received
            if Type != TNS_MARKER:
                self._in_break = False
            match Type:
                case t if t == TNS_ACCEPT:
                    (Ver, Opts, Sdu) = struct.unpack('>Hhh', Packet[:6])
                    # 319-era accept (#155): large SDU / 4-byte framing at
                    # version >= 315, end-of-response bit at >= 318.
                    self.sdu = _parse_accept_sdu(Ver, Packet, Sdu)
                    self._large_packets = Ver >= TNS_VERSION_MIN_LARGE_SDU
                    self._supports_eor = _parse_accept_eor(Ver, Packet)
                    self._supports_oob = bool(  # OOB break (#144)
                        Opts & TNS_GSO_CAN_RECV_ATTENTION
                    )
                    self.conn_state = CONN_STATE_CONNECTED
                    # Native network encryption (#437): negotiate ANO whenever the
                    # server advertises support (ACFL0 bit 0 set, bit 2 clear,
                    # ACFL1 bit 3 clear) — the CONNECT advertised ANO-capable, so a
                    # supporting server expects the negotiation before PRO. Mirror
                    # of OracleConnect.handle_login.
                    Acfl0 = Packet[14] if len(Packet) > 14 else 0
                    Acfl1 = Packet[15] if len(Packet) > 15 else 0
                    if (Acfl0 & 0x01) and not (Acfl0 & 0x04) and not (Acfl1 & 0x08):
                        await self._negotiate_ano()
                    # Negotiation cache (#438): skip the bare PRO probe on a
                    # reconnect to a target with a cached fast-auth field version.
                    if self.negotiation_cache and not self._skip_nego_cache:
                        from seerdb.client.connection import _nego_cache_get

                        Cached = _nego_cache_get(self._nego_cache_key())
                        if Cached is not None and Cached > FIELD_VERSION_23_1:
                            self.field_version = Cached
                            self._used_nego_cache = True
                            return await self._fast_auth_login()
                    Data = encode_dictionary(self._make_dict(DictionaryType.pro))
                    await self.send(TNS_DATA, Data)
                    continue
                case t if t == TNS_DATA:
                    match Packet[0]:
                        case p if p == TTI_PRO:
                            self._negotiate_capabilities(Packet)
                            if self.field_version > FIELD_VERSION_23_1:
                                # 23ai (#89): fv >= 18 needs the fast-auth bundle
                                # (the legacy OSESSKEY is rejected). See the sync
                                # OracleConnect._fast_auth_login.
                                return await self._fast_auth_login()
                            if isinstance(self._dialect, O8iDialect):
                                # 8i needs its own shorter DTY (§ _DTY_8I).
                                Data = _DTY_8I
                            else:
                                Data = encode_dictionary(
                                    self._make_dict(DictionaryType.dty)
                                )
                            await self.send(TNS_DATA, Data)
                        case p if p == TTI_DTY:
                            if isinstance(self._dialect, O8iDialect):
                                # Oracle 8i: O3LOGON via the OSESSKEY envelope.
                                self._o3_phase = 1
                                await self._send_8i_osesskey()
                            elif self.field_version < FIELD_VERSION_10_2:
                                # Pre-10g (9i): O3LOGON thin auth (#90). Async
                                # port of OracleConnect's branch.
                                from seerdb.common.tns import encode_o3logon_phase1

                                self._o3_phase = 1
                                await self.send(
                                    TNS_DATA,
                                    encode_o3logon_phase1(
                                        self._next_seq(), self.user.encode('utf-8')
                                    ),
                                )
                            elif self.access_token is not None:
                                # Token auth (#125): skip OSESSKEY, send the token
                                # AUTH; the reply is the auth result (no proof).
                                self._token_auth = True
                                await self._send_token_auth()
                            else:
                                Data = encode_dictionary(
                                    self._make_dict(DictionaryType.sess)
                                )
                                await self.send(TNS_DATA, Data)
                        case p if p == TTI_RPA:
                            if isinstance(self._dialect, O8iDialect):
                                # 8i O3LOGON: phase-1 RPA (AUTH_SESSKEY) -> send the
                                # proof; the phase-2 RPA means authenticated.
                                if self._o3_phase == 1:
                                    await self._send_8i_oauth_phase2(Packet)
                                    continue
                                self.conn_state = CONN_STATE_AUTHENTICATED
                                return 0
                            if getattr(self, '_o3_phase', 0) == 1:
                                await self._send_o3logon_phase2(Packet)
                                continue
                            return await self._handle_rpa(Packet[1:])
                        case p if p == TTI_WRN:
                            logger.debug('handle_login: recv WRN %s', Packet[1:])
                        case p if p == TTI_OER:
                            from seerdb.common.exceptions import (
                                DatabaseError,
                                from_ora_code,
                            )
                            from seerdb.common.tns import decode_packet, decode_ub4

                            if getattr(self, '_o3_phase', 0) == 2:
                                # 9i's OER is the short pre-10g form: skip
                                # call_status, seq, rowcount, then the ORA code.
                                Rest = Packet[1:]
                                for _ in range(3):
                                    (_, Rest) = decode_ub4(Rest)
                                (ErrCode, _) = decode_ub4(Rest)
                                Message = None
                            else:
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
                                self.conn_state = CONN_STATE_AUTHENTICATED
                                return 0
                            raise DatabaseError('authentication failed')
                        case _:
                            logger.debug('handle_login: unknown token %s', Packet[0])
                    continue
                case t if t == TNS_MARKER:
                    # Single reset per break episode, then drain (#45).
                    if not self._in_break:
                        await self.send(
                            TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET])
                        )
                        self._in_break = True
                    continue
                case t if t == TNS_REDIRECT:
                    from seerdb.common.tns import parse_redirect_address

                    (NewHost, NewPort) = parse_redirect_address(Packet)
                    if NewHost is None or NewPort is None:
                        raise OperationalError(
                            'the server sent a redirect this client could not parse'
                        )
                    self._redirects = getattr(self, '_redirects', 0) + 1
                    if self._redirects > _MAX_REDIRECTS:
                        raise OperationalError(
                            f'too many TNS redirects (> {_MAX_REDIRECTS})'
                        )
                    self.host, self.port = NewHost, NewPort
                    await self.disconnect()
                    await self._open_transport()
                    continue
                case t if t == TNS_REFUSE:
                    # Mirror OracleConnect: a refusal is terminal, so raise the
                    # listener's ORA error rather than return a half-open
                    # connection. See connection.py for the full note.
                    from seerdb.client.connection import _parse_refuse_code

                    Code = _parse_refuse_code(Packet)
                    await self.disconnect()
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
                    self.conn_state = CONN_STATE_AUTH_NEGOTIATE
                    Data = encode_dictionary(self._make_dict(DictionaryType.login))
                    await self.send(TNS_CONNECT, Data)
                    continue
                case _:
                    logger.debug('handle_login (async): unexpected %s', Type)
                    raise OperationalError(
                        f'the server sent an unexpected packet type {Type} during login'
                    )

    async def _negotiate_ano(self) -> None:
        # Async port of OracleConnect._negotiate_ano (#437): run the plaintext ANO
        # negotiation after the accept, then activate the per-packet cipher + MAC.
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
        await self.send(TNS_DATA, Request)
        Received = await self.recv(b'', b'')
        if Received is False:
            raise OperationalError('ANO negotiation: connection closed by server')
        (_Type, Payload) = Received
        Response = ano.decode_container(Payload)
        ByType = {S['type']: S for S in Response['services']}
        EncId = ByType[ano.SERVICE_ENCRYPTION]['subpackets'][1][1]
        IntId = ByType[ano.SERVICE_DATA_INTEGRITY]['subpackets'][1][1]
        Integrity = ByType[ano.SERVICE_DATA_INTEGRITY]
        # A server that only *supports* ANO (encryption not required) selects the
        # null algorithm and carries no DH — negotiation done, session plaintext.
        if EncId == 0 or len(Integrity['subpackets']) < 8:
            logger.debug(
                'handle_login (async): ANO negotiated, no encryption selected (enc=%d)',
                EncId,
            )
            return
        (Gen, Prime, ServerPub, ServerIv) = ano.extract_dh_params(Integrity)
        Dh = ano.compute_dh(Gen, Prime, ServerPub)
        await self.send(TNS_DATA, ano.dh_public_key_round(Dh.public_key))
        self._ano = AnoChannel(EncId, IntId, Dh.session_key, ServerIv)
        logger.debug(
            'handle_login (async): ANO active (enc=%d integrity=%d)', EncId, IntId
        )

    async def _fast_auth_login(self) -> int | None:
        # Async port of OracleConnect._fast_auth_login (23ai fast-auth, #89):
        # send PRO + DTY + OSESSKEY bundled in one FAST_AUTH packet, then hand the
        # auth-challenge RPA out of the bundled reply to the phase-two path.
        Pro = encode_dictionary(self._make_dict(DictionaryType.pro))
        Dty = encode_dictionary(self._make_dict(DictionaryType.dty))
        Sess = encode_dictionary(self._make_dict(DictionaryType.sess))
        await self.send(TNS_DATA, encode_fast_auth(Pro, Dty, Sess))
        Received = await self._next_data_packet()
        if Received is False:
            logger.debug('fast_auth (async): connection closed by peer')
            return 1
        (Type, Packet) = Received
        Off = find_fast_auth_rpa(Packet) if Type == TNS_DATA else -1
        if Off < 0:
            from seerdb.common.exceptions import OperationalError

            logger.error('fast_auth (async): no auth challenge in bundled reply')
            raise OperationalError('fast-auth handshake failed')
        return await self._handle_rpa(Packet[Off + 1 :])

    def _negotiate_capabilities(self, Packet: bytes) -> None:
        # Parse the server's PRO response and lower the field version to the
        # server's if older — min(client, server). See OracleConnect for the
        # full rationale. Best-effort: keep the default on any parse error.
        import re

        from seerdb.common.tns_consts import FIELD_VERSION_9_2

        try:
            Pro = decode_token_pro(Packet)
            Caps = Pro['compile_caps']
            self._server_compile_caps = Caps
            self._server_runtime_caps = Pro.get('runtime_caps') or b''
            if len(Caps) > CCAP_FIELD_VERSION:
                self.field_version = min(self.field_version, Caps[CCAP_FIELD_VERSION])
            # Oracle 8i carries no caps in its PRO: pin the field version to 2 and
            # flag 8i so the OSESSKEY-envelope O3LOGON path runs (see the sync
            # OracleConnect._negotiate_capabilities).
            Banner = Pro.get('banner') or b''
            VerMatch = re.search(rb'(\d+)\.\d+\.\d+', Banner)
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
            logger.debug('handle_login: could not parse PRO caps', exc_info=True)

    async def _drive(self, gen: object) -> object:
        # Async twin of OracleConnect._drive (#369): run a sans-io dialect
        # generator, awaiting the real send / receive. Send(data) -> a TNS_DATA
        # packet; RECV -> the next data packet; return value is the result.
        from seerdb.client.dialect import RECV, Send

        to_send: object = None
        try:
            while True:
                intent = gen.send(to_send)  # type: ignore[attr-defined]
                if intent is RECV:
                    to_send = await self._next_data_packet()
                elif isinstance(intent, Send):
                    await self.send(TNS_DATA, intent.data)
                    to_send = None
                else:  # pragma: no cover - defensive
                    raise TypeError(f'unknown dialect intent: {intent!r}')
        except StopIteration as done:
            return done.value

    async def _handle_rpa(self, Data: bytes) -> int | None:
        from seerdb.common.tns_consts import TTI_AUTH

        Result = decode_token_rpa(Data, ())
        if Result[0] == TTI_SESS:
            # First RPA: auth challenge from the server.
            (_, SessKey, Salt, DerivedSalt, VgenCount, SderCount, VerifierType) = Result
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
            (Data2, ConnKey) = encode_dictionary_auth(
                self._make_dict(DictionaryType.auth, auth=Auth)
            )
            self.conn_key = ConnKey
            await self.send(TNS_DATA, Data2)
            # Server's second RPA carries the auth result — re-enter the
            # login loop so it gets routed through the right state.
            return await self.handle_login()
        elif Result[0] == TTI_AUTH:
            # Second RPA: auth result.
            (_, Resp, Ver, SessId) = Result
            if self._token_auth:
                # Token auth (#125): no server proof / ConnKey; accept directly.
                self.server_version = Ver
                self.session_id = SessId
                self.conn_state = CONN_STATE_AUTHENTICATED
                return 0
            assert self.conn_key is not None
            if validate(bytes.fromhex(Resp.decode('utf-8')), self.conn_key):
                self.server_version = Ver
                self.session_id = SessId
                self.conn_state = CONN_STATE_AUTHENTICATED
                if self.negotiation_cache and self.field_version > FIELD_VERSION_23_1:
                    from seerdb.client.connection import _nego_cache_put

                    _nego_cache_put(self._nego_cache_key(), self.field_version)
                return 0
            await self.disconnect()
            return 1
        return 1

    # ----- response handling -----

    async def _handle_response(self, Acc: tuple | None = None) -> object:
        if Acc is None:
            Acc = (None, None, [])
        for _ in range(MAX_FLUSH_OUT_BINDS + 1):
            Received = await self._next_data_packet(b'', b'')
            if Received is False:
                raise InterfaceError('connection closed while awaiting response')
            (Type, Packet) = Received
            if Type != TNS_DATA:
                raise Exception('Unexpected response type', Type)
            Result = decode_packet(Packet, Acc, self.field_version)
            if Result != FLUSH_OUT_BINDS:
                return Result
            # A flush-out-binds request, not a result: echo the token back and
            # read on for the response it is standing in front of (§6.9, #697).
            await self.send(TNS_DATA, bytes([TTI_FOB]))
        raise InterfaceError('server kept asking to flush out binds')

    # ----- execute / fetch (kept minimal for the first cut) -----

    async def execute(
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
        """Same shape as `OracleConnect.execute` but async.

        Cursor caching for DML works the same way as in the sync path —
        the cache is on `self`, keyed by SQL text."""
        if Bind is None:
            Bind = []
        if Def is None:
            Def = []
        if Batch is None:
            Batch = []
        Head = Query.strip().upper()
        # A pre-10g dialect (9i / fv2 or 8i) runs as sans-io generators driven by
        # the async _drive; the connection is a thin orchestrator (#369). Neither
        # tier carries an autocommit bit, so commit is explicit.
        if self._dialect is not None:
            from seerdb.client.connection import _check_fv2_bind_sizes

            _check_fv2_bind_sizes(Bind, Batch)
            if Batch and CAP_ARRAY_DML not in self._dialect.capabilities():
                from seerdb.common.exceptions import NotSupportedError

                raise NotSupportedError(
                    'executemany (array DML) is not supported on Oracle '
                    + _pre10_tier_name_for(self._dialect)
                )
            if Head.startswith('SELECT'):
                return await self._drain_cursor(
                    await self._drive(
                        self._dialect.execute_query(Query, Bind, self.fetch)
                    )
                )
            if Head.startswith('BEGIN') or Head.startswith('DECLARE'):
                Result = await self._drive(self._dialect.execute_block(Query, Bind))
            elif ReturnBinds:
                # Pre-10g DML ... RETURNING (#801) -- see the sync twin.
                Wrapped, BlockBind = returning_block_request(Query, Bind)
                try:
                    Raw = await self._drive(
                        self._dialect.execute_block(Wrapped, BlockBind)
                    )
                except DatabaseError as Exc:
                    raise returning_block_error(Exc) from None
                Result = returning_block_result(Raw, len(Bind))
            else:  # DML (INSERT/UPDATE/DELETE)
                Result = await self._drive(self._dialect.execute_dml(Query, Bind))
            if self.autocommit:
                await self.commit()
            return Result
        if Head.startswith('SELECT'):
            Type = 'select'
        elif Head.startswith('BEGIN') or Head.startswith('DECLARE'):
            # Anonymous PL/SQL block: dedicated 'block' exec option set, not the
            # DML 'change' path (else ORA-00600 [12259]). Mirrors the sync path.
            Type = 'block'
        else:
            Type = 'change'
        # Scrollable cursors only apply to queries (#181); never flag a non-SELECT.
        if Type != 'select':
            scrollable = False
            Prefetch = None
        CachedCursor = 0
        CacheKey = None
        # The cursor cache reuses a parsed handle and skips re-sending the
        # SQL/OAC — an 11g optimization that doesn't translate to 12c+, where a
        # cached re-execute fails (ORA-01009 / ORA-03115) because the server
        # expects the binds/OAC declared every execute. Disable on 12c+ (mirrors
        # the sync OracleConnect.execute guard).
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
            'auto': 1 if self.autocommit else 0,
            # Scrollable open prefetches only `Prefetch` rows so the cursor stays
            # mid-stream (#181), as in the sync path.
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
            # Server-side scrollable cursor open (#181): mark scrollable + open
            # at CURRENT (describe-only — rows come from scroll_fetch).
            'scrollable': scrollable,
            'scroll': (TNS_FETCH_ORIENTATION_CURRENT, 1) if scrollable else None,
        }
        Pre = (
            self._flush_cursor_closes_bytes()  # close drained cursors (#191)
            + self._flush_end_to_end_bytes()  # tracing piggyback (#183)
            + self._flush_end_user_sec_bytes()  # end-user security ctx (#460)
            + self._flush_session_state_bytes()  # request boundary (#464)
        )
        Data = encode_dictionary(self._make_dict(DictionaryType.exec, query=QueryDict))
        await self.send(TNS_DATA, Pre + Data)
        # Arm row-count extraction for this response only (#18).
        set_decode_dml_rowcounts(ArrayDmlRowCounts)
        # Arm RETURNING out-bind decoding for this response only (#120).
        set_decode_return_binds(ReturnBinds)
        # call_timeout (#123): schedule a break if the call runs too long; the
        # read coroutine then receives the server's interrupt (ORA-01013), which
        # we remap to a call-timeout error.
        Timer = None
        if self._call_timeout:
            self._timed_out = False
            Timer = asyncio.get_running_loop().call_later(
                self._call_timeout / 1000.0, self._on_call_timeout
            )
        try:
            # Seed the decoder with the binds so the IOV decoder can tell a
            # REF CURSOR OUT bind from a scalar one.
            Result = await self._handle_response((None, None, [], Bind))
        except Exception as exc:
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
            # Gate the write on CacheKey too so 12c+ (cache disabled) never
            # parks a stray {None: cursor_id} entry (#80); mirrors the sync fix.
            CursorId = Result[2]
            self._cursor_cache.pop(CacheKey, None)
            self._cursor_cache[CacheKey] = CursorId
            while len(self._cursor_cache) > self._cursor_cache_max:
                Oldest = next(iter(self._cursor_cache))
                self._cursor_cache.pop(Oldest, None)
            Stored = True
        if scrollable:
            # A scrollable open is describe-only: don't drain (rows come from
            # scroll_fetch) and don't queue the cursor for close — it must stay
            # open for the scroll re-executes (#181). The cursor frees it on
            # close / re-execute.
            return Result
        Drained = await self._drain_cursor(Result)
        # Queue the statement's own server cursor for close unless cached (#191).
        if (
            not Stored
            and isinstance(Drained, tuple)
            and len(Drained) >= 3
            and isinstance(Drained[2], int)
            and Drained[2] > 0
        ):
            self._cursors_to_close.append(Drained[2])
        return Drained

    async def _send_o3logon_phase2(self, Packet: bytes) -> None:
        # Async port of OracleConnect._send_o3logon_phase2 (#90): decrypt the
        # session key from the TTI_3LOGA RPA with the account DES verifier,
        # DES-encrypt the zero-padded password, send TTI_3LOGON.
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
        await self.send(
            TNS_DATA, encode_o3logon_phase2(self._next_seq(), UserB, PwdField)
        )

    def _auth_info_pairs(self) -> list:
        # Async port of OracleConnect._auth_info_pairs (#244): informational
        # AUTH_ pairs the OSESSKEY / OAUTH calls carry (no I/O).
        import os
        import socket

        return [
            (b'AUTH_PROGRAM_NM', self.app_name.encode('utf-8')),
            (b'AUTH_MACHINE', socket.gethostname().encode('utf-8')),
            (b'AUTH_PID', str(os.getpid()).encode('utf-8')),
        ]

    async def _send_8i_osesskey(self) -> None:
        # Async port of OracleConnect._send_8i_osesskey: O3LOGON phase one, the
        # OSESSKEY (0x76) call carrying the username + informational pairs.
        from seerdb.common.tns import encode_o3logon_osesskey_phase1

        await self.send(
            TNS_DATA,
            encode_o3logon_osesskey_phase1(
                self._next_seq(), self.user.encode('utf-8'), self._auth_info_pairs()
            ),
        )

    async def _send_8i_oauth_phase2(self, Packet: bytes) -> None:
        # Async port of OracleConnect._send_8i_oauth_phase2: recover AUTH_SESSKEY,
        # DES-encrypt the password (same crypto as 9i), send it as AUTH_PASSWORD
        # in the OAUTH (0x73) call.
        from binascii import hexlify

        from seerdb.common.crypto import des_verifier, o3logon
        from seerdb.common.tns import encode_o3logon_oauth_phase2, parse_8i_auth_sesskey

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
        await self.send(
            TNS_DATA,
            encode_o3logon_oauth_phase2(
                self._next_seq(),
                UserB,
                PwdField,
                self._auth_info_pairs() + [(b'AUTH_ACL', b'8000')],
            ),
        )

    async def _drain_cursor(self, Result: object) -> object:
        """Mirror of the sync drain loop: pulls follow-up FETCH packets
        when the server signals more rows pending."""
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
                    # Seed the last row so a BVC-reused column in the next
                    # continuation batch's first row copies the carried value
                    # rather than decoding as None (#326; sync parity).
                    set_decode_prev_row(AllRows[-1] if AllRows else None)
                    FetchResult = await self.fetch_more(
                        CursorId, self.fetch, RowFormat=RowFormat
                    )
                    if not isinstance(FetchResult, tuple) or len(FetchResult) < 6:
                        break
                    (CallStatus, OraCode, _, _, MoreRows, *_) = FetchResult
                    if MoreRows:
                        AllRows.extend(MoreRows)
                    # End of fetch, or a batch that brought nothing back --
                    # which also guarantees this loop terminates.
                    if OraCode == 1403 or not MoreRows:
                        break
            finally:
                set_decode_prev_row(None)
        if OraCode == 1403:
            OraCode = 0
        return (CallStatus, OraCode, CursorId, RetFormat, AllRows) + tuple(Tail)

    async def fetch_more(
        self, CursorId: int, Rows: int | None = None, RowFormat: list | None = None
    ) -> object:
        if Rows is None:
            Rows = self.fetch
        Data = encode_dictionary(
            self._make_dict(DictionaryType.fetch, cursor=CursorId, fetch=Rows)
        )
        await self.send(TNS_DATA, Data)
        return await self._handle_response(Acc=(None, RowFormat, []))

    async def scroll_fetch(
        self,
        CursorId: int,
        Orientation: int,
        Position: int,
        RowFormat: list,
        Fetch: int | None = None,
        PrevRow: list | None = None,
    ) -> tuple:
        """Async twin of ``OracleConnect.scroll_fetch`` (#181): re-execute an
        open scrollable cursor with a fetch orientation + 1-based position,
        returning ``(rows, at_eof, server_rowcount)``."""
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
        await self.send(TNS_DATA, Pre + Data)
        set_decode_prev_row(PrevRow)  # reused-column fallback for row 1 (#181)
        try:
            Result = await self._handle_response((None, RowFormat, []))
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

    async def fetch_all_rows(self, CursorId: int, RowFormat: list) -> list:
        # Async drain of a server cursor (e.g. a REF CURSOR). Mirrors
        # OracleConnect.fetch_all_rows.
        AllRows: list = []
        try:
            while True:
                # Seed the last row so a BVC-reused column in the next batch's
                # first row copies the carried value, not None (#326; sync parity).
                set_decode_prev_row(AllRows[-1] if AllRows else None)
                Result = await self.fetch_more(
                    CursorId, self.fetch, RowFormat=RowFormat
                )
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

    # ----- LOB read (async mirror of `OracleConnect.lob_read`) -----

    async def lob_read(
        self, Locator: bytes, DataType: int, prefixed: bool = False
    ) -> str | bytes:
        """Async port of the sync `lob_read`. See its docstring for
        the wire format we walk through. `prefixed` opts into the
        ub2-length-prefixed locator form required for temp LOBs (#91)."""
        from seerdb.common.tns_consts import TNS_TYPE_CLOB

        Data = encode_dictionary(
            self._make_dict(
                DictionaryType.lobops, locator=Locator, locator_prefixed=prefixed
            )
        )
        await self.send(TNS_DATA, Data)
        Content = await self._read_lob_response()
        if DataType == TNS_TYPE_CLOB:
            return Content.decode('utf-16-be', errors='replace')
        return Content

    async def gettype(self, name: str) -> 'DbObjectType':
        """Async port of `OracleConnect.gettype` (#116): look up a SQL object
        type by (optionally schema-qualified) name and return a DbObjectType."""
        if '.' in name:
            Schema, _, TypeName = name.partition('.')
            Schema = Schema.strip('"') if '"' in Schema else Schema.upper()
        else:
            Schema, TypeName = None, name
        TypeName = TypeName.strip('"') if '"' in TypeName else TypeName.upper()
        Typ = await self._describe_object_type(Schema, TypeName)
        if Typ is None or (not Typ.attrs and not Typ.is_collection):
            from seerdb.common.exceptions import DatabaseError

            raise DatabaseError(f'object type {name!r} not found')
        return Typ

    async def _describe_object_type(
        self, schema: str | None, name: str | None
    ) -> 'DbObjectType | None':
        """Async port of `OracleConnect._describe_object_type` (#115/#116):
        the type's 16-byte OID + version + ordered attribute layout, cached."""
        if not name:
            return None
        from seerdb.common.dbobject import DbObjectType, type_name_to_tns

        Owner = schema
        if Owner is None:
            Result = await self.execute('SELECT USER FROM dual')
            Rows = self._rows(Result)
            Owner = Rows[0][0] if Rows else None
        if not Owner:
            return None
        Key = (Owner, name)
        Cached = self._object_type_cache.get(Key)
        if Cached is not None:
            return Cached
        OidRes = await self.execute(
            'SELECT type_oid, typecode FROM all_types '
            'WHERE owner = :1 AND type_name = :2',
            Bind=[Owner, name],
        )
        OidRows = self._rows(OidRes)
        Oid = bytes(OidRows[0][0]) if OidRows and OidRows[0][0] else b''
        TypeCode = OidRows[0][1] if OidRows else None
        Result = await self.execute(
            'SELECT attr_name, attr_type_name, length, precision, scale '
            'FROM all_type_attrs WHERE owner = :1 AND type_name = :2 '
            'ORDER BY attr_no',
            Bind=[Owner, name],
        )
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
        CollKW = await self._collection_describe(Owner, name, TypeCode)
        Typ = DbObjectType(Owner, name, Oid, 1, Attrs, **CollKW)
        self._object_type_cache[Key] = Typ
        return Typ

    async def _collection_describe(self, owner, name, typecode) -> dict:
        """Async port of `OracleConnect._collection_describe` (#117/#118)."""
        if typecode != 'COLLECTION':
            return {}
        from seerdb.common.dbobject import (
            COLLECTION_NESTED_TABLE,
            COLLECTION_VARRAY,
            type_name_to_tns,
        )

        Res = await self.execute(
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

    async def _object_type_layout(self, schema: str | None, name: str | None) -> list:
        """The ordered attribute layout (#115 read path), via the type describe."""
        Typ = await self._describe_object_type(schema, name)
        return Typ.attrs if Typ is not None else []

    async def create_temp_lob(self, is_blob: bool = False) -> bytes:
        """Async port of the sync `create_temp_lob` (#91). Allocates a
        session-duration temporary LOB and returns its locator. 12c+ only."""
        from seerdb.common.tns_consts import TTI_RPA

        Data = encode_dictionary(
            self._make_dict(DictionaryType.lobops, create_temp=True, is_blob=is_blob)
        )
        await self.send(TNS_DATA, Data)
        Received = await self._next_data_packet(b'', b'')
        if Received is False:
            raise Exception('Connection closed during CREATE_TEMP')
        (_, Packet) = Received
        if not Packet or Packet[0] != TTI_RPA:
            raise Exception(
                'Unexpected CREATE_TEMP response', Packet[:8].hex() if Packet else None
            )
        LocLen = (Packet[1] << 8) | Packet[2]
        return Packet[3 : 3 + LocLen]

    async def write_temp_lob(
        self, Locator: bytes, Data: str | bytes, is_blob: bool = False
    ) -> None:
        """Async port of the sync `write_temp_lob` (#91)."""
        from seerdb.common.tns_consts import TNS_LOB_OP_WRITE

        Payload = Data if is_blob else cast(str, Data).encode('utf-16-be')
        Dict = self._make_dict(
            DictionaryType.lobops,
            locator=Locator,
            data=Payload,
            operation=TNS_LOB_OP_WRITE,
        )
        await self.send(TNS_DATA, encode_dictionary(Dict))
        await self._confirm_lobops()

    async def _confirm_lobops(self) -> None:
        """Async port of the sync `_confirm_lobops`: receive a content-free
        LOBOPS response (WRITE / temp / BFILE open-close) and raise on a
        non-zero OER."""
        Received = await self._next_data_packet(b'', b'')
        if Received is False:
            raise Exception('Connection closed during LOBOPS')
        self._raise_lobops_error(Received[1])

    async def bfile_read_native(self, Locator: bytes) -> bytes:
        """Async port of the sync `bfile_read_native` (#46): FILE_OPEN ->
        READ -> FILE_CLOSE over TTI_LOBOPS, using the open-flagged locator the
        server returns from FILE_OPEN."""
        from seerdb.common.tns_consts import (
            TNS_LOB_OP_FILE_CLOSE,
            TNS_LOB_OP_FILE_OPEN,
            TTI_RPA,
        )

        # See the sync bfile_read_native: strip LOB.raw's leading ub2
        # inner-length so the encoder's prefix isn't doubled.
        if len(Locator) >= 2 and ((Locator[0] << 8) | Locator[1]) == len(Locator) - 2:
            Locator = Locator[2:]
        await self.send(
            TNS_DATA,
            encode_dictionary(
                self._make_dict(
                    DictionaryType.lobops,
                    locator=Locator,
                    operation=TNS_LOB_OP_FILE_OPEN,
                )
            ),
        )
        Received = await self._next_data_packet(b'', b'')
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
            await self.send(
                TNS_DATA,
                encode_dictionary(
                    self._make_dict(
                        DictionaryType.lobops, locator=Opened, locator_prefixed=True
                    )
                ),
            )
            Content = await self._read_lob_response()
        finally:
            await self.send(
                TNS_DATA,
                encode_dictionary(
                    self._make_dict(
                        DictionaryType.lobops,
                        locator=Opened,
                        operation=TNS_LOB_OP_FILE_CLOSE,
                    )
                ),
            )
            await self._confirm_lobops()
        return Content

    async def bfile_read(self, directory_name: str, file_name: str) -> bytes:
        """Read a BFILE by directory object + filename. Resolves the locator
        with a `SELECT BFILENAME` and reads it natively (#46); the cursor's LOB
        auto-resolve runs `bfile_read_native` under the hood."""
        Cur = self.cursor()
        await Cur.execute(
            'SELECT BFILENAME(:d, :f) FROM DUAL', {'d': directory_name, 'f': file_name}
        )
        Row = await Cur.fetchone()
        return Row[0]

    async def _read_lob_response(self) -> bytes:
        """Async port of the sync `_read_lob_response`. Same token
        walk; everything between TTI_LOB content and TTI_OER is RPA
        metadata we don't decode."""
        from seerdb.common.tns_consts import TTI_LOB, TTI_OER

        Buffer = b''
        while True:
            Received = await self._next_data_packet(b'', b'')
            if Received is False:
                raise InterfaceError('connection closed during LOBOPS response')
            (Type, Packet) = Received
            if Type != TNS_DATA:
                raise Exception('Unexpected LOBOPS response type', Type)
            Pos = 0
            OerSeen = False
            while Pos < len(Packet):
                Token = Packet[Pos]
                if Token == TTI_LOB:
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
                        # single length byte per chunk. Without the 12c+ branch
                        # the chunk lengths misparse and the LOB read desyncs,
                        # hanging the next recv (mirrors the sync handler).
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
                    OerSeen = True
                    break
                else:
                    # Likely TTI_RPA carrying the updated locator/amount — skip
                    # to the trailing OER. Match the stable `04 01 01` prefix as
                    # well as the historical `04 01 XX 01` form (mirrors sync;
                    # 12c+ uses the former, so missing it hangs the read).
                    # call_status is a flag word, not always 1: it reads 2 while
                    # a transaction is open and 5 after a PL/SQL execute (#712).
                    # Accept any small value; matching only `04 01 01` left the
                    # reader waiting for a packet that never came with autocommit off.
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
                    break
            if OerSeen:
                return Buffer

    # ----- transaction control -----

    async def commit(self) -> None:
        if self._dialect is not None and CAP_OWN_TXN in self._dialect.capabilities():
            await self._drive(self._dialect.txn_control('COMMIT'))  # 8i: OALL8 stmt
            self._sessionless_txn_active = False
            return
        from seerdb.common.tns_consts import TTI_COMMIT

        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_COMMIT))
        await self.send(TNS_DATA, Data)
        await self._handle_response()
        # An ordinary commit ends an active sessionless transaction (#133).
        self._sessionless_txn_active = False

    async def rollback(self) -> None:
        if self._dialect is not None and CAP_OWN_TXN in self._dialect.capabilities():
            await self._drive(self._dialect.txn_control('ROLLBACK'))
            self._sessionless_txn_active = False
            return
        from seerdb.common.tns_consts import TTI_ROLLBACK

        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_ROLLBACK))
        await self.send(TNS_DATA, Data)
        await self._handle_response()
        self._sessionless_txn_active = False

    async def ping(self) -> None:
        if self.field_version < FIELD_VERSION_10_2:
            # 9i lacks TTI_PING (func 147); use a trivial round trip (#168).
            await self.execute("SELECT 'X' FROM dual")
            return
        from seerdb.common.tns_consts import TTI_PING

        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_PING))
        await self.send(TNS_DATA, Data)
        await self._handle_response()

    async def changepassword(self, old_password: str, new_password: str) -> None:
        """Change the connected user's password (#21). Async mirror of
        `OracleConnect.changepassword` — same single TTI_AUTH password-change
        call reusing the login session key, same error behaviour."""
        from seerdb.common.exceptions import from_ora_code

        if self.field_version < FIELD_VERSION_10_2:
            raise NotSupportedError(
                'changepassword is not supported on Oracle 9i'
            )  # (#168)
        if self.conn_state != CONN_STATE_AUTHENTICATED or self.conn_key is None:
            raise InterfaceError('changepassword requires an authenticated connection')
        Auth = {
            'conn_key': self.conn_key,
            'old_password': old_password,
            'new_password': new_password,
        }
        Data = encode_dictionary(self._make_dict(DictionaryType.chgpwd, auth=Auth))
        await self.send(TNS_DATA, Data)
        Result = cast(tuple, await self._handle_response())
        ErrCode = Result[1] if isinstance(Result, tuple) and len(Result) > 1 else 0
        if ErrCode and ErrCode not in (0, 1403):
            Message = Result[5] if len(Result) > 5 else None
            raise from_ora_code(ErrCode)(Message or f'ORA-{ErrCode:05d}', code=ErrCode)
        self.password = new_password

    # ----- teardown -----

    def _send_break(self) -> None:
        # In-band INTERRUPT marker break (#144), the async port of OracleConnect.
        # Written straight to the StreamWriter's underlying socket so it flushes
        # immediately regardless of the event loop being parked in the call's
        # read; asyncio wraps it in a TransportSocket that forbids send(), so we
        # reach the real socket via its private _sock. Supersedes the OOB-only
        # break from #123 (see OracleConnect._send_break).
        if self._break_in_progress or self._writer is None:
            return
        self._break_in_progress = True
        Sock = self._writer.get_extra_info('socket')
        Raw = getattr(Sock, '_sock', None) if Sock is not None else None
        Target = Raw if Raw is not None and hasattr(Raw, 'send') else Sock
        if Target is not None and hasattr(Target, 'send'):
            try:
                if self._supports_oob:
                    Target.send(b'!', socket.MSG_OOB)
                else:
                    (Packet, _) = encode_packet(
                        TNS_MARKER,
                        bytes([1, 0, TNS_MARKER_TYPE_INTERRUPT]),
                        self.sdu,
                        self._large_packets,
                    )
                    Target.send(Packet)
            except OSError:
                # Best-effort interrupt (see sync OracleConnect): a dead socket
                # means the call being broken is already gone.
                pass

    # --- Two-phase commit / XA (#131), async port of OracleConnect ---

    async def _tpc_request(self, Data: bytes) -> bytes:
        await self.send(TNS_DATA, Data)
        Received = await self._next_data_packet(b'', b'')
        if Received is False:
            raise OperationalError('connection closed during TPC operation')
        (_, Packet) = Received
        return Packet

    async def tpc_begin(
        self, xid: Xid, flags: int = TPC_BEGIN_NEW, timeout: int = 0
    ) -> None:
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
        self._transaction_context = _decode_tpc_context(await self._tpc_request(Data))

    async def tpc_end(self, xid: Xid, flags: int = TPC_END_NORMAL) -> None:
        Data = encode_tpc_switch(
            self._next_seq(),
            self.field_version,
            TNS_TPC_TXN_DETACH,
            xid,
            flags,
            0,
            self._transaction_context,
        )
        await self._tpc_request(Data)
        self._transaction_context = None

    async def tpc_prepare(self, xid: Xid) -> bool:
        Data = encode_tpc_change_state(
            self._next_seq(),
            self.field_version,
            TNS_TPC_TXN_PREPARE,
            0,
            xid,
            0,
            self._transaction_context,
        )
        State = _decode_tpc_state(await self._tpc_request(Data))
        if State == TNS_TPC_TXN_STATE_REQUIRES_COMMIT:
            return True
        if State == TNS_TPC_TXN_STATE_READ_ONLY:
            return False
        raise DatabaseError(f'unknown TPC transaction state {State}')

    async def tpc_commit(self, xid: Xid, one_phase: bool = False) -> None:
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
        Result = _decode_tpc_state(await self._tpc_request(Data))
        self._transaction_context = None
        Ok = (
            Result in (TNS_TPC_TXN_STATE_READ_ONLY, TNS_TPC_TXN_STATE_COMMITTED)
            if one_phase
            else Result == TNS_TPC_TXN_STATE_FORGOTTEN
        )
        if not Ok:
            raise DatabaseError(f'unexpected TPC commit state {Result}')

    async def tpc_rollback(self, xid: Xid) -> None:
        Data = encode_tpc_change_state(
            self._next_seq(),
            self.field_version,
            TNS_TPC_TXN_ABORT,
            TNS_TPC_TXN_STATE_ABORTED,
            xid,
            0,
            self._transaction_context,
        )
        Result = _decode_tpc_state(await self._tpc_request(Data))
        self._transaction_context = None
        if Result != TNS_TPC_TXN_STATE_ABORTED:
            raise DatabaseError(f'unexpected TPC rollback state {Result}')

    # --- Sessionless transactions (#133, 23ai), async port ---

    async def _sessionless_switch(
        self, operation: int, transaction_id, flags: int, timeout: int
    ):
        xid = None
        if transaction_id is not None:
            xid = Xid(TNS_TPC_SESSIONLESS_FORMAT_ID, transaction_id, b'')
        Data = encode_tpc_switch(
            self._next_seq(), self.field_version, operation, xid, flags, timeout, None
        )
        await self._tpc_request(Data)

    async def begin_sessionless_transaction(
        self, transaction_id=None, timeout: int = 60
    ) -> bytes:
        """Start a sessionless transaction. `transaction_id` (str/bytes, <=64
        bytes) defaults to a fresh uuid4; returns the id used. `timeout` is the
        seconds the server keeps the suspended transaction resumable."""
        self._check_sessionless_support()
        if self._sessionless_txn_active:
            raise DatabaseError('a sessionless transaction is already active')
        txnid = _normalize_sessionless_txn_id(transaction_id)
        await self._sessionless_switch(
            TNS_TPC_TXN_START, txnid, TPC_BEGIN_NEW | TPC_TXN_FLAGS_SESSIONLESS, timeout
        )
        self._sessionless_txn_active = True
        return txnid

    async def resume_sessionless_transaction(
        self, transaction_id, timeout: int = 60
    ) -> bytes:
        """Resume a previously suspended sessionless transaction (possibly on a
        different session). `transaction_id` is required; returns it."""
        self._check_sessionless_support()
        if self._sessionless_txn_active:
            raise DatabaseError('a sessionless transaction is already active')
        txnid = _normalize_sessionless_txn_id(transaction_id)
        await self._sessionless_switch(
            TNS_TPC_TXN_START,
            txnid,
            TPC_BEGIN_RESUME | TPC_TXN_FLAGS_SESSIONLESS,
            timeout,
        )
        self._sessionless_txn_active = True
        return txnid

    async def suspend_sessionless_transaction(self) -> None:
        """Suspend the active sessionless transaction so another session can
        resume it. The transaction's work is preserved (not committed)."""
        self._check_sessionless_support()
        if not self._sessionless_txn_active:
            raise DatabaseError('no sessionless transaction is active')
        await self._sessionless_switch(
            TNS_TPC_TXN_DETACH, None, TPC_TXN_FLAGS_SESSIONLESS, 0
        )
        self._sessionless_txn_active = False

    # --- Request pipelining (#132), async port ---

    def _encode_pipeline_op(self, Op, TokenNum: int):
        # Async copy of OracleConnect._encode_pipeline_op (#158).
        from seerdb.client.connection import _PIPELINE_FETCH_ALL_PREFETCH
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

    async def _pipeline_send_op(
        self, Data: bytes, FinalFlags: int, FirstFlags: int = 0
    ) -> None:
        # Async copy of OracleConnect._pipeline_send_op (#158).
        BodyMax = self.sdu - 10
        First = True
        while len(Data) > BodyMax:
            Flags = TNS_DATA_FLAGS_MORE | (FirstFlags if First else 0)
            self._wr.write(
                encode_data_packet(Data[:BodyMax], Flags, self._large_packets)
            )
            Data = Data[BodyMax:]
            First = False
        Flags = FinalFlags | (FirstFlags if First else 0)
        self._wr.write(encode_data_packet(Data, Flags, self._large_packets))

    async def _pipeline_recv_response(self) -> bytes:
        # Async copy of OracleConnect._pipeline_recv_response (#158): read one
        # op's response (TOKEN + body + EOR) as a single response unit without
        # the coalescing recv() does, skipping any interjected break marker.
        Body = b''
        while True:
            if len(self._pending) >= 8:
                (Flag, Type, Chunk, Rest) = assemble_packet(
                    self._pending, self.sdu, self._large_packets
                )
                if Chunk is not None:
                    self._pending = Rest if Rest is not None else b''
                    if Type == TNS_MARKER:
                        continue
                    Body += Chunk
                    if Flag:
                        return Body
                    continue
            More = await self._rd.read(self.sdu)
            if not More:
                from seerdb.common.exceptions import OperationalError

                raise OperationalError('connection closed during pipeline read')
            self._pending = self._pending + More

    async def _run_pipeline_pipelined(self, pipeline, continue_on_error: bool) -> list:
        # Async copy of OracleConnect._run_pipeline_pipelined (#158).
        from seerdb.client.connection import _apply_rowfactory
        from seerdb.client.pipeline import PipelineOpResult
        from seerdb.client.pipeline import PipelineOpType as T

        Ops = pipeline.operations
        BeginSeq = self._next_seq()
        Built = [self._encode_pipeline_op(Op, K) for K, Op in enumerate(Ops, start=1)]
        EndSeq = self._next_seq()
        Begin = encode_pipeline_begin(
            BeginSeq, self.field_version, 1, TNS_PIPELINE_MODE_CONTINUE_ON_ERROR
        )
        await self._pipeline_send_op(
            Begin + Built[0][0],
            TNS_DATA_FLAGS_END_OF_REQUEST,
            FirstFlags=TNS_DATA_FLAGS_BEGIN_PIPELINE,
        )
        for Data, _Bind in Built[1:]:
            await self._pipeline_send_op(Data, TNS_DATA_FLAGS_END_OF_REQUEST)
        await self.send(TNS_DATA, encode_pipeline_end(EndSeq, self.field_version))
        await self._wr.drain()
        Raw = []
        for _Data, Bind in Built:
            Body = await self._pipeline_recv_response()
            set_decode_dml_rowcounts(False)
            set_decode_return_binds(None)
            Raw.append(decode_packet(Body, (None, None, [], Bind), self.field_version))
        # Discard the trailing end-pipeline (func 200) response.
        await self._pipeline_recv_response()
        Results = []
        FirstError = None
        Cur = self.cursor()
        for Op, (_Data, Bind), RawResult in zip(Ops, Built, Raw):
            Result = PipelineOpResult(Op)
            Results.append(Result)
            try:
                Drained = await self._drain_cursor(RawResult)
                await Cur._apply_result(Bind, Drained)
                if Op.op_type == T.FETCH_ONE:
                    Row = await Cur.fetchone()
                    Result.rows = _apply_rowfactory(
                        [] if Row is None else [Row], Op.rowfactory
                    )
                    Result.columns = Cur.description
                elif Op.op_type == T.FETCH_MANY:
                    Result.rows = _apply_rowfactory(
                        await Cur.fetchmany(Op.num_rows), Op.rowfactory
                    )
                    Result.columns = Cur.description
                elif Op.op_type == T.FETCH_ALL:
                    Result.rows = _apply_rowfactory(await Cur.fetchall(), Op.rowfactory)
                    Result.columns = Cur.description
            except DatabaseError as exc:
                Result.error = exc
                if FirstError is None:
                    FirstError = exc
        if FirstError is not None and not continue_on_error:
            raise FirstError
        return Results

    async def run_pipeline(self, pipeline, continue_on_error: bool = False) -> list:
        """Async port of OracleConnect.run_pipeline (#132/#158): run the queued
        operations in order and return a PipelineOpResult for each. On 23ai
        (EOR framing) the exec-family ops run as one token-tagged round trip;
        otherwise each op runs serially with identical results."""
        if self._pipeline_wire_eligible(pipeline):
            return await self._run_pipeline_pipelined(pipeline, continue_on_error)
        from seerdb.client.connection import _apply_rowfactory
        from seerdb.client.pipeline import PipelineOpResult
        from seerdb.client.pipeline import PipelineOpType as T

        results = []
        Cur = self.cursor()
        for Op in pipeline.operations:
            Result = PipelineOpResult(Op)
            results.append(Result)
            params = Op.parameters or []
            try:
                if Op.op_type == T.EXECUTE:
                    await Cur.execute(Op.statement, params)
                elif Op.op_type == T.EXECUTE_MANY:
                    await Cur.executemany(Op.statement, Op.parameters)
                elif Op.op_type == T.FETCH_ONE:
                    await Cur.execute(Op.statement, params)
                    row = await Cur.fetchone()
                    Result.rows = _apply_rowfactory(
                        [] if row is None else [row], Op.rowfactory
                    )
                    Result.columns = Cur.description
                elif Op.op_type == T.FETCH_MANY:
                    await Cur.execute(Op.statement, params)
                    Result.rows = _apply_rowfactory(
                        await Cur.fetchmany(Op.num_rows), Op.rowfactory
                    )
                    Result.columns = Cur.description
                elif Op.op_type == T.FETCH_ALL:
                    await Cur.execute(Op.statement, params)
                    Result.rows = _apply_rowfactory(await Cur.fetchall(), Op.rowfactory)
                    Result.columns = Cur.description
                elif Op.op_type == T.COMMIT:
                    await self.commit()
                elif Op.op_type == T.CALL_PROC:
                    await Cur.callproc(Op.name, params)
                elif Op.op_type == T.CALL_FUNC:
                    Result.return_value = await Cur.callfunc(
                        Op.name, Op.return_type, params
                    )
            except DatabaseError as exc:
                Result.error = exc
                if not continue_on_error:
                    raise
        return results

    # --- Advanced Queuing (#128), async port ---

    def queue(self, name: str, payload_type=None):
        from seerdb.client.aq import AsyncQueue
        from seerdb.common.datatypes import JSON as _JSON

        if self.field_version < FIELD_VERSION_12_1:
            raise NotSupportedError('Advanced Queuing requires an Oracle 12.1+ server')
        if payload_type is _JSON:
            return AsyncQueue(self, name, payload_type=None, is_json=True)
        return AsyncQueue(self, name, payload_type=payload_type)

    async def _aq_request(self, Data: bytes) -> bytes:
        await self.send(TNS_DATA, Data)
        Received = await self._next_data_packet(b'', b'')
        if Received is False:
            raise OperationalError('connection closed during AQ operation')
        (_, Packet) = Received
        return Packet

    async def _aq_enq_one(self, queue, props) -> None:
        from seerdb.client.connection import _decode_aq_enq
        from seerdb.common.tns import encode_aq_enq

        Data = encode_aq_enq(self._next_seq(), self.field_version, queue, props)
        props.msgid = _decode_aq_enq(await self._aq_request(Data))

    async def _aq_deq_one(self, queue):
        from seerdb.client.connection import _decode_aq_deq
        from seerdb.common.tns import encode_aq_deq

        Data = encode_aq_deq(self._next_seq(), self.field_version, queue)
        return _decode_aq_deq(await self._aq_request(Data), queue)

    async def _aq_enq_many(self, queue, props_list) -> None:
        from seerdb.client.connection import _decode_aq_array
        from seerdb.common.tns import encode_aq_array
        from seerdb.common.tns_consts import TNS_AQ_ARRAY_ENQ

        Data = encode_aq_array(
            self._next_seq(),
            self.field_version,
            queue,
            TNS_AQ_ARRAY_ENQ,
            props_list,
            len(props_list),
        )
        _decode_aq_array(
            await self._aq_request(Data), queue, TNS_AQ_ARRAY_ENQ, props_list
        )

    async def _aq_deq_many(self, queue, max_messages):
        from seerdb.client.aq import MessageProperties
        from seerdb.client.connection import _decode_aq_array
        from seerdb.common.tns import encode_aq_array
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
            await self._aq_request(Data), queue, TNS_AQ_ARRAY_DEQ, Placeholders
        )

    async def close(self) -> None:
        """Roll back, log off and release the session (§10), then close the writer."""
        # Best-effort orderly shutdown, then always disconnect so the socket
        # gets reclaimed even if the server-side handshake has gone sideways.
        if self.conn_state == CONN_STATE_DISCONNECTED or self._writer is None:
            return
        try:
            if self.conn_state == CONN_STATE_AUTHENTICATED:
                if not self.autocommit:
                    await self.rollback()
                # Logoff (the TTI_LOGOFF function call + its response).
                Data = encode_dictionary(self._make_dict(DictionaryType.close))
                await self.send(TNS_DATA, Data)
                await self._handle_response()
                # Final empty TNS_DATA packet with the EOF data flag, telling the
                # server to fully release the session (mirrors OracleConnect.close,
                # §10). Without it the session lingers server-side and accumulates
                # over rapid reconnect cycles. Format: 10-byte header (PacketSize,
                # PacketFlags, Type, Flags, DataFlags).
                self._wr.write(
                    struct.pack('>hhBBh', 10, 0, TNS_DATA, 0, TNS_DATA_FLAGS_EOF)
                )
                await self._wr.drain()
        except Exception:
            # Best-effort teardown: if the server already hung up or our state
            # is out of sync, we still want to release the local socket below.
            pass
        await self.disconnect()

    async def disconnect(self) -> None:
        if self._writer is not None:
            try:
                if self._writer.can_write_eof():
                    self._writer.write_eof()
            except (OSError, AttributeError):
                # The transport may not support EOF or may already be
                # closed; proceed straight to close() either way.
                pass
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError:
                # The socket may already be torn down by the peer; the
                # writer is being discarded regardless.
                pass
            self._writer = None
            self._reader = None

    # ----- factory (cursor created lazily in step 2) -----

    def cursor(self, scrollable: bool = False):
        """Returns an `AsyncCursor` bound to this connection. `scrollable`
        (oracledb parity, #161) is accepted and surfaced; scroll() works
        regardless since seerdb buffers the result set."""
        # Lazy import to avoid a circular dep with acursor importing us.
        from seerdb.client.acursor import AsyncCursor

        return AsyncCursor(self, scrollable=scrollable)

    def getSodaDatabase(self):
        """Return an `AsyncSodaDatabase` for document-store (SODA) access (#163).
        Raises NotSupportedError on a pre-18c server. The factory is synchronous
        (like oracledb); the collection/document operations are coroutines."""
        from seerdb.client.soda import AsyncSodaDatabase, _check_soda_supported

        _check_soda_supported(self)
        return AsyncSodaDatabase(self)

    # --- End-to-end application tracing (#183), async port ---

    async def _end_request(self) -> None:
        # End a pooled logical request (#464): cancel an unflushed BEGIN, else
        # send REQUEST_END on a rollback. See OracleConnect._end_request.
        if not self._in_request:
            return
        if self._session_state_desired != 0:
            self._session_state_desired = 0
            self._in_request = False
            return
        self._session_state_desired = TNS_SESSION_STATE_REQUEST_END
        self._in_request = False
        from seerdb.common.tns_consts import TTI_ROLLBACK

        Pre = self._flush_session_state_bytes()
        Data = encode_dictionary(self._make_dict(DictionaryType.tran, req=TTI_ROLLBACK))
        await self.send(TNS_DATA, Pre + Data)
        await self._handle_response()

    # ----- async context manager -----

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()
