# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A live seerdb client logs into the Mirror end-to-end.

The Mirror's own client is an independent implementation of the same protocol,
so a successful login exercises the whole server login path (handshake +
O5LOGON) against a real client.
"""

from __future__ import annotations

import base64
import datetime
import socket
import threading
import zlib
from dataclasses import replace
from typing import Any

import pytest
from test_server_handshake import _SPLIT_CONNECT, _SPLIT_CONNECT_DATA

import seerdb
from seerdb.common.exceptions import InterfaceError, Truncated
from seerdb.common.tns import ColumnMeta
from seerdb.common.tns_consts import (
    FIELD_VERSION_12_2,
    FIELD_VERSION_21_1,
    FIELD_VERSION_23_4,
    TNS_ACCEPT,
    TNS_DATA,
    TNS_TYPE_CHAR,
    TNS_TYPE_NUMBER,
    TNS_TYPE_VARCHAR,
    TTI_END_OF_RESPONSE,
    TTI_FUN,
    TTI_MSG_TYPE_PIGGYBACK,
    TTI_PRO,
    VERSION_11_2_0_2,
    VERSION_12_1_0_2,
    VERSION_12_2_0_1,
    VERSION_23_26_2_0,
)
from seerdb.server import stats
from seerdb.server.backend import (
    Capability,
    CursorResult,
    Result,
    SessionInfo,
    UnsupportedFeature,
    credential_lookup,
)
from seerdb.server.framing import PacketStream
from seerdb.server.session import handle_login, serve_session

_CREDS = {'PYO': 'pyo123'}


class _DualBackend:
    # A trivial Backend: DUAL returns 'X'; anything else is refused with a clean
    # ORA error (so the Mirror answers, never desyncs).
    capabilities: frozenset[Capability] = frozenset()

    def authenticate(self, username: str) -> str | None:
        return credential_lookup(_CREDS, username)

    def execute(self, sql: str, binds=()) -> Result:
        if 'dual' in sql.lower():
            col = ColumnMeta(
                name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
            )
            return Result(columns=[col], rows=[('X',)])
        raise UnsupportedFeature(f'the DUAL backend only knows DUAL: {sql!r}')

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass

    def set_end_to_end(self, attrs: dict) -> None:
        # Record what the Mirror hands over from a tracing piggyback.
        self.tracing = {**getattr(self, 'tracing', {}), **attrs}

    def sessionless_begin(self, transaction_id: bytes, timeout: int) -> None:
        self.sessionless: tuple[str, bytes | None, int] = (
            'begin',
            transaction_id,
            timeout,
        )

    def sessionless_resume(self, transaction_id: bytes, timeout: int) -> None:
        self.sessionless = ('resume', transaction_id, timeout)

    def sessionless_suspend(self) -> None:
        self.sessionless = ('suspend', None, 0)


def _run_mirror(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    stream = PacketStream(conn)
    try:
        (result['user'], _sqlplus, _conn_key, result['fv'], _sid) = handle_login(
            stream, _DualBackend()
        )
        # Block on the client's logoff / EOF so the socket stays open until the
        # client has read the auth result and returned from connect().
        stream.read_packet()
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


# The client's PRO that follows the ACCEPT in the same capture, in the large
# (4-byte length) framing a 23ai presentation negotiates.
_SPLIT_CONNECT_PRO = bytes.fromhex(
    '0000001d060000000000010600707974686f6e2d6f7261636c65646200'
)


def test_login_reads_a_descriptor_sent_after_the_connect() -> None:
    # A descriptor over 230 bytes arrives in a DATA packet after the CONNECT.
    # The Mirror answered the bare CONNECT, then took that packet for the PRO
    # and the login stalled (#1769). Now the PRO is answered as the PRO.
    server, client = socket.socketpair()
    client.sendall(_SPLIT_CONNECT + _SPLIT_CONNECT_DATA + _SPLIT_CONNECT_PRO)
    result: dict = {}

    def run() -> None:
        try:
            handle_login(
                PacketStream(server), _DualBackend(), field_version=FIELD_VERSION_23_4
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
            result['error'] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    def recv_exact(n: int) -> bytes:
        data = b''
        while len(data) < n:
            chunk = client.recv(n - len(data))
            assert chunk, 'the Mirror hung up'
            data += chunk
        return data

    try:
        client.settimeout(5)
        # The ACCEPT keeps the legacy 2-byte length; the reply after it does not.
        head = recv_exact(2)
        accept = head + recv_exact(int.from_bytes(head, 'big') - 2)
        assert accept[4] == TNS_ACCEPT
        head = recv_exact(4)
        reply = head + recv_exact(int.from_bytes(head, 'big') - 4)
        assert reply[4] == TNS_DATA
        assert reply[10] == TTI_PRO
    finally:
        client.close()
        thread.join(5)
        server.close()
    # The client hung up after the PRO answer, so the login ends there.
    assert isinstance(result.get('error'), InterfaceError)


def test_live_seerdb_login() -> None:
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(target=_run_mirror, args=(listen, result), daemon=True)
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        # A live connection whose field version negotiated down to 11g (6).
        assert conn is not None
        assert conn.field_version == 6
        assert conn.server_version == VERSION_11_2_0_2
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert result.get('user') == 'PYO'


def test_login_steps_over_a_split_data_types_message() -> None:
    # A client splits a message at the negotiated SDU, and the modern
    # DATA_TYPES table is ~2642 bytes -- so every SDU below about 2650 cuts the
    # DTY into two packets or more. The Mirror answered the first half and then
    # read the REMAINDER as the OSESSKEY that should have followed, which the
    # client saw as DPY-4011 (#968).
    #
    # The tail here is a REAL DTY, sliced where a 1024-byte SDU would cut it.
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, encode_dictionary_dty
    from seerdb.common.tns_consts import TNS_DATA, TTI_FUN
    from seerdb.server.session import _expect_login_message

    token = _ENCODE_FIELD_VERSION.set(24)
    try:
        dty = encode_dictionary_dty({'req': 'AL32UTF8', 'seq': 1, 'field_version': 24})
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    tail = dty[1014:]  # what a second packet would carry at sdu=1024
    assert tail[:1] != bytes([TTI_FUN])  # ...and it is not mistakable for one
    osesskey = bytes([TTI_FUN, 0x76]) + b'\x00' * 8

    class _Stream:
        def __init__(self, packets):
            self.packets = list(packets)

        def read_packet(self):
            return (TNS_DATA, self.packets.pop(0))

    stream: Any = _Stream([tail, osesskey])
    assert _expect_login_message(stream, 'OSESSKEY') == osesskey
    # A login that was NOT split still costs exactly one read.
    stream = _Stream([osesskey])
    assert _expect_login_message(stream, 'OSESSKEY') == osesskey
    assert stream.packets == []


def _run_mirror_session(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(PacketStream(conn), _DualBackend())
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


class _BadOutBindBackend(_DualBackend):
    # A PL/SQL block returns an OUT-bind value the wire cannot encode (a bare
    # object has no _encode_value branch), standing in for a backend that hands
    # back a value the Mirror can't represent — e.g. an INTERVAL YEAR TO MONTH that
    # a foreign backend surfaces as a plain timedelta. Everything else behaves like
    # _DualBackend.
    def execute(self, sql: str, binds=()) -> Result:
        if sql.lstrip().upper().startswith('BEGIN'):
            return Result(out_binds=[object()])
        return super().execute(sql, binds)


def _run_bad_out_bind_session(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(PacketStream(conn), _BadOutBindBackend())
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def _run_mirror_login_at(listen: socket.socket, result: dict, version: int) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(
            PacketStream(conn), _DualBackend(), field_version=version
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


@pytest.mark.parametrize('version', [7, 8, 16, 17])  # 12.1, 12.2, 21c, 23ai
def test_live_seerdb_login_at_a_higher_field_version(version: int) -> None:
    # A Mirror advertising a 12c+ field version: the real client negotiates to it
    # and logs in — a 12.1+ client length-prefixes the username in OSESSKEY /
    # AUTH, which the auth parsers must honour for that version. The O5LOGON
    # crypto itself is the same 11g SHA-1 verifier scheme at every version.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_login_at, args=(listen, result, version), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        assert conn.field_version == version
        # …and the query round-trip in that version's request / describe / OER
        # layouts, with and without a bind (12.2+ reshapes all three).
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        assert cursor.fetchone() == ('X',)
        cursor.execute('select :b from dual', ['abc'])
        assert cursor.fetchone() == ('X',)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert result.get('user') == 'PYO'


class _AlterSessionBackend(_DualBackend):
    """Records the ALTER SESSION a client sends with its login; optionally
    refuses it, to show a refusal never fails the login."""

    def __init__(self, refuse: bool = False) -> None:
        super().__init__()
        self.statements: list[str] = []
        self.refuse = refuse

    def alter_session(self, statement: str) -> None:
        self.statements.append(statement)
        if self.refuse:
            raise RuntimeError('refused')


def _login_with(backend: _DualBackend, version: int) -> dict:
    # Serve one real seerdb login at `version` against `backend`, and run one
    # query so the session is known to be usable.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    result: dict = {}

    def serve() -> None:
        conn, _ = listen.accept()
        try:
            result['user'] = serve_session(
                PacketStream(conn), backend, field_version=version
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
            result['error'] = exc
        finally:
            conn.close()

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    conn = seerdb.connect(
        host='127.0.0.1',
        port=listen.getsockname()[1],
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        result['row'] = cursor.fetchone()
    finally:
        conn.close()
        server.join(timeout=5)
        listen.close()
    return result


@pytest.mark.parametrize('version', [6, 7, 8, 17])  # 11.2, 12.1, 12.2, 23ai
def test_the_login_time_zone_reaches_the_backend(version: int) -> None:
    # From 12.1 a client pins the session time zone to its own UTC offset in the
    # login AUTH (AUTH_ALTER_SESSION); the Mirror hands that statement to the
    # backend's alter_session hook. An 11.2 client sends none.
    backend = _AlterSessionBackend()
    result = _login_with(backend, version)
    assert result['row'] == ('X',)
    if version < 7:
        assert backend.statements == []
    else:
        (statement,) = backend.statements
        assert statement.startswith("ALTER SESSION SET TIME_ZONE='")
        assert not statement.endswith('\x00')


def test_a_refused_login_time_zone_does_not_fail_the_login() -> None:
    backend = _AlterSessionBackend(refuse=True)
    result = _login_with(backend, 7)
    assert len(backend.statements) == 1
    assert result['row'] == ('X',)


class _Present12cBackend(_DualBackend):
    # Declares a server identity (12.1) independent of its wire field version, which
    # stays the 11.2 default -- the decoupling a PostgreSQL-backed Mirror uses to get
    # the dialect's native OFFSET/FETCH without changing the wire (#33).
    from seerdb.server.identity import IDENTITY_12_1

    server_identity = IDENTITY_12_1


def _run_present_12c_session(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(PacketStream(conn), _Present12cBackend())
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def test_backend_presents_a_release_above_its_wire_version() -> None:
    # A backend that declares server_identity is introduced at that release while the
    # wire still negotiates its (lower) field version: the client reads the version
    # from the login banner, so conn.version is 12.1 though the wire is 11.2 (fv 6).
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_present_12c_session, args=(listen, result), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        # Reported release is 12.1.0.2.0, but the negotiated wire is still 11.2 (fv 6).
        assert conn.server_version == VERSION_12_1_0_2
        assert conn.field_version == 6
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert result.get('user') == 'PYO'


class _RecordingArrayBackend(_DualBackend):
    # Counts the INSERTs it is handed, so a test can see how many iterations of an
    # array execute actually reached the backend.
    def __init__(self) -> None:
        self.inserts: list = []

    def execute(self, sql: str, binds=()) -> Result:
        if 'insert' in sql.lower():
            self.inserts.append(list(binds))
            return Result(rowcount=1)
        return super().execute(sql, binds)


def _run_recording_session(
    listen: socket.socket, result: dict, backend: _RecordingArrayBackend
) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(PacketStream(conn), backend)
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def test_empty_row_array_execute_runs_once_per_iteration() -> None:
    # executemany of a no-bind INSERT ([[], [], []]) sends no TTI_RXD row data, only
    # the al8i4 iteration count; the Mirror must still apply it once per iteration
    # rather than collapsing it to a single execute (#33).
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    backend = _RecordingArrayBackend()
    server = threading.Thread(
        target=_run_recording_session, args=(listen, result, backend), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        cursor = conn.cursor()
        cursor.executemany('INSERT INTO t (id) VALUES (1)', [[], [], []])
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    # All three empty iterations reached the backend, not just one.
    assert len(backend.inserts) == 3


def test_an_ltz_bind_reaches_the_backend_marked_as_one() -> None:
    # A TIMESTAMP WITH LOCAL TIME ZONE bind and a TIMESTAMP bind decode to the same
    # naive datetime; the backend is told which was which, since Oracle reads them
    # in different zones (#1222). Once, again (the re-execute) and as an array.
    from seerdb.server import LtzValue

    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    backend = _RecordingArrayBackend()
    server = threading.Thread(
        target=_run_recording_session, args=(listen, result, backend), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    value = datetime.datetime(2026, 9, 25, 13, 45, 6, 123456)
    sql = 'INSERT INTO t (ltz, ts) VALUES (:1, :2)'
    try:
        cursor = conn.cursor()
        for _ in range(2):
            cursor.setinputsizes(seerdb.DB_TYPE_TIMESTAMP_LTZ, seerdb.DB_TYPE_TIMESTAMP)
            cursor.execute(sql, [value, value])
        cursor.setinputsizes(seerdb.DB_TYPE_TIMESTAMP_LTZ, seerdb.DB_TYPE_TIMESTAMP)
        cursor.executemany(sql, [[value, value], [None, value]])
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    rows = backend.inserts
    assert len(rows) == 4
    for ltz, ts in rows[:3]:
        assert type(ltz) is LtzValue and ltz == value
        assert type(ts) is datetime.datetime and ts == value
    assert rows[3][0] is None


def test_mark_ltz_binds_leaves_nulls_and_other_types_alone() -> None:
    # Only a non-NULL datetime at an LTZ position is marked; a NULL, a BindVar
    # (which says its type itself) and every other position are left as they are.
    from seerdb.common.tns import ExecRequest
    from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPLTZ
    from seerdb.server import BindVar, LtzValue
    from seerdb.server.session import _mark_ltz_binds

    value = datetime.datetime(2026, 9, 25, 13, 45, 6)
    null = BindVar(value=None, tns_type=TNS_TYPE_TIMESTAMPLTZ, max_size=11)
    row = [value, value, None, null]
    request = ExecRequest(
        'insert into t values (:1, :2, :3, :4)',
        0,
        4,
        0,
        binds=row,
        bind_rows=[row],
        bind_meta=[
            (TNS_TYPE_TIMESTAMPLTZ, 11),
            (TNS_TYPE_TIMESTAMP, 11),
            (TNS_TYPE_TIMESTAMPLTZ, 11),
            (TNS_TYPE_TIMESTAMPLTZ, 11),
        ],
    )
    marked = _mark_ltz_binds(request)
    assert [type(v) for v in marked.binds] == [
        LtzValue,
        datetime.datetime,
        type(None),
        BindVar,
    ]
    assert marked.bind_rows == [marked.binds]
    no_ltz = replace(request, bind_meta=[(TNS_TYPE_TIMESTAMP, 11)] * 4)
    assert _mark_ltz_binds(no_ltz) is no_ltz


def _exec_body() -> bytes:
    from seerdb.common.tns import encode_dictionary_exec

    return encode_dictionary_exec(
        {
            'field_version': 17,
            'seq': 5,
            'query': {
                'type': 'select',
                'auto': 0,
                'fetch': 15,
                'server_version': 0,
                'cursor': 0,
                'query': 'select * from dual',
                'bind': [],
                'batch': [],
                'def': [],
                'batcherrors': None,
                'arraydmlrowcounts': None,
                'return_binds': None,
                'scrollable': False,
                'scroll': None,
            },
        }
    )


@pytest.mark.parametrize(
    'attrs',
    [
        {'module': 'm'},
        {
            'client_identifier': 'c',
            'module': 'mod',
            'action': 'a',
            'client_info': 'i',
            'dbop': 'd',
        },
        {'module': None, 'action': 'act'},  # a cleared attribute carries no value
        {'client_info': 'x' * 300},  # a long value rides the chunked DALC form
    ],
)
def test_skip_piggybacks_walks_the_12c_tracing_and_session_state(attrs: dict) -> None:
    # The 12.1+ client puts the end-to-end tracing (135) and request-boundary
    # session-state (176) piggybacks in front of a call; the Mirror keeps no such
    # state and must land exactly on the call that follows.
    from seerdb.common.tns import (
        _DECODE_FIELD_VERSION,
        encode_close_cursors_piggyback,
        encode_end_to_end_piggyback,
        encode_session_state_piggyback,
    )
    from seerdb.server.session import _skip_piggybacks

    body = _exec_body()
    token = _DECODE_FIELD_VERSION.set(17)
    try:
        e2e = encode_end_to_end_piggyback(4, 17, attrs)
        state = encode_session_state_piggyback(4, 17, 0x44)
        close = encode_close_cursors_piggyback(4, 17, [3, 9])
        backend = _DualBackend()
        assert _skip_piggybacks(e2e + body, backend) == body
        # …and the attributes (a cleared one as None) reach the backend.
        assert backend.tracing == dict(attrs)
        assert _skip_piggybacks(state + body) == body
        assert _skip_piggybacks(close + e2e + state + body) == body
        # an unknown piggyback is left in place, as before
        assert (
            _skip_piggybacks(bytes([0x11, 0xCD, 4]) + body)
            == bytes([0x11, 0xCD, 4]) + body
        )
    finally:
        _DECODE_FIELD_VERSION.reset(token)


class _ContextBackend(_DualBackend):
    # Records what apply_app_context is handed; refuses any namespace but
    # CLIENTCONTEXT, as 23ai does one the session may not set.
    def __init__(self) -> None:
        super().__init__()
        self.applied: list = []

    def apply_app_context(self, namespace, values):
        from seerdb.server.backend import BackendError

        if namespace != 'CLIENTCONTEXT':
            raise BackendError('Invalid NameSpace Value', ora_code=28267)
        self.applied.append((namespace, values))


@pytest.mark.parametrize('field_version', [6, 7, 24])
def test_skip_piggybacks_applies_an_app_context(field_version: int) -> None:
    # set_app_context() / clear_app_context() ride the next call as func 154
    # (#1778). Below field version 12.1 the piggyback has no zero byte before the
    # namespace; both forms land on the call and reach the backend, a clear as
    # None.
    from seerdb.common.tns import _DECODE_FIELD_VERSION, encode_app_context_piggyback
    from seerdb.server.session import _skip_piggybacks

    body = _exec_body()
    token = _DECODE_FIELD_VERSION.set(field_version)
    try:
        set_ = encode_app_context_piggyback(
            4, field_version, b'CLIENTCONTEXT', [(b'ATTR1', b'VALUE1'), (b'ATTR2', b'')]
        )
        clear = encode_app_context_piggyback(5, field_version, b'CLIENTCONTEXT', [])
        backend = _ContextBackend()
        refused: list = []
        assert _skip_piggybacks(set_ + clear + body, backend, None, refused) == body
        assert backend.applied == [
            ('CLIENTCONTEXT', {'ATTR1': 'VALUE1', 'ATTR2': ''}),
            ('CLIENTCONTEXT', None),
        ]
        assert refused == []
    finally:
        _DECODE_FIELD_VERSION.reset(token)


def test_skip_piggybacks_reports_a_refused_app_context() -> None:
    # A namespace the session may not set fails the call behind it; a good one
    # in the same message is still applied, as 23ai does (#1778).
    from seerdb.common.tns import _DECODE_FIELD_VERSION, encode_app_context_piggyback
    from seerdb.server.session import _skip_piggybacks

    body = _exec_body()
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        good = encode_app_context_piggyback(4, 24, b'CLIENTCONTEXT', [(b'A', b'1')])
        bad = encode_app_context_piggyback(
            5, 24, b'NOT_A_VALID_NAMESPACE', [(b'a', b'v')]
        )
        backend = _ContextBackend()
        refused: list = []
        assert _skip_piggybacks(good + bad + body, backend, None, refused) == body
        assert backend.applied == [('CLIENTCONTEXT', {'A': '1'})]
        assert [err.ora_code for err in refused] == [28267]
    finally:
        _DECODE_FIELD_VERSION.reset(token)


class _PriorityBackend(_DualBackend):
    # Transaction priority as session state; refuses 'urgent' (#1779).
    def __init__(self) -> None:
        super().__init__()
        self.priority = 'HIGH'

    def txn_priority(self):
        return self.priority

    def set_txn_priority(self, value):
        from seerdb.server.backend import BackendError

        if value == 'urgent':
            raise BackendError('invalid value', ora_code=96)
        self.priority = value or 'HIGH'


def test_skip_piggybacks_sets_the_transaction_priority() -> None:
    # `connection.transaction_priority = x` rides the next call as func 204
    # (#1779): the value reaches the backend, an empty one restores the default,
    # a refused one fails the call, and each accepted one is reported.
    from seerdb.common.tns import _DECODE_FIELD_VERSION, encode_alter_session_piggyback
    from seerdb.server.session import _skip_piggybacks, _TxnPriorityReporter

    body = _exec_body()
    backend = _PriorityBackend()
    reporter = _TxnPriorityReporter(backend.txn_priority, 'HIGH')
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        refused: list = []
        low = encode_alter_session_piggyback(4, 24, 'low')
        assert _skip_piggybacks(low + body, backend, None, refused, reporter) == body
        assert backend.priority == 'low' and refused == []
        assert reporter().endswith(
            bytes.fromhex('0103036c6f7700 01cc 00'.replace(' ', ''))
        )
        reset = encode_alter_session_piggyback(5, 24, '')
        assert _skip_piggybacks(reset + body, backend, None, refused, reporter) == body
        assert backend.priority == 'HIGH'
        bad = encode_alter_session_piggyback(6, 24, 'urgent')
        assert _skip_piggybacks(bad + body, backend, None, refused, reporter) == body
        assert [err.ora_code for err in refused] == [96]
    finally:
        _DECODE_FIELD_VERSION.reset(token)


def test_the_priority_reporter_reports_changes_and_every_client_set() -> None:
    # A change the call made (an ALTER SESSION in SQL) is reported once; a client
    # set is reported even when the value stays the same -- the client holds ''
    # for a reset until the server's report replaces it (#1779).
    from seerdb.common.tns import encode_sync_piggyback
    from seerdb.common.tns_consts import TNS_KEYWORD_NUM_TXN_PRIORITY
    from seerdb.server.session import _TxnPriorityReporter

    backend = _PriorityBackend()
    reporter = _TxnPriorityReporter(backend.txn_priority, 'HIGH')
    assert reporter() == b''
    backend.priority = 'MEDIUM'
    assert reporter() == encode_sync_piggyback(
        [(TNS_KEYWORD_NUM_TXN_PRIORITY, 'MEDIUM')]
    )
    assert reporter() == b''
    reporter.changed()
    assert reporter() == encode_sync_piggyback(
        [(TNS_KEYWORD_NUM_TXN_PRIORITY, 'MEDIUM')]
    )


def test_the_23ai_caps_advertise_transaction_priority() -> None:
    # Bit 0x01 of FEATURE_BACKPORT2 (byte 45) when presenting 23ai with a backend
    # that has the hooks; the 11.2 vector grows to reach it, zero between (#1779).
    from seerdb.common.tns import _SERVER_RUNTIME_CAPS
    from seerdb.common.tns_consts import FIELD_VERSION_12_1, FIELD_VERSION_23_4
    from seerdb.server.handshake import build_caps_block_reply

    plain = build_caps_block_reply(FIELD_VERSION_23_4)
    with_bit = build_caps_block_reply(FIELD_VERSION_23_4, txn_priority=True)
    assert len(with_bit) == len(plain) + 7
    end = len(with_bit) - len(_SERVER_RUNTIME_CAPS) - 1  # before the runtime caps
    caps = with_bit[end - 46 : end]
    assert with_bit[end - 47] == 46  # the compile caps' length byte
    assert caps[45] == 0x01 and caps[39:45] == bytes(6)
    assert build_caps_block_reply(FIELD_VERSION_12_1, txn_priority=True) == (
        build_caps_block_reply(FIELD_VERSION_12_1)
    )


def test_the_login_reply_reports_the_priority() -> None:
    # 23ai reports the session's priority after the reply's pairs, as keyword 204
    # of a SYNC piggyback; seerdb's client reads it from there (#1779).
    from seerdb.common.tns import (
        decode_token_rpa,
        encode_result,
        recording_session_keywords,
    )
    from seerdb.common.tns_consts import TNS_KEYWORD_NUM_TXN_PRIORITY

    payload = encode_result(bytes(24), txn_priority='HIGH')
    sink: dict = {}
    with recording_session_keywords(sink):
        decode_token_rpa(payload[1:], ())
    assert sink == {TNS_KEYWORD_NUM_TXN_PRIORITY: 'HIGH'}


# The close-temp-LOBs piggyback a thin client sent a live 23ai in front of its
# second large-LOB insert (fv24: the ub8 token follows the sequence byte): a
# FREE_TEMP | ARRAY over one 40-byte (ub2-prefixed) locator, then `03 04 ...`, the
# re-execute it rides on.
_CLOSE_TEMP_LOBS_23AI = bytes.fromhex(
    '11 60 0a 00 01 01 28 00 00 00 00 00 00 00 04 00 08 01 11 00 00 00 00 00'
    '00 00 00 00 00 00 00 26 00 01 81 08 00 03 00 01 6a 51 00 00 00 67 00 00 00'
    '01 00 00 00 0a 00 00 00 01 00 00 1a ab 82 f1 00 00 00 01 00 00'
)


@pytest.mark.parametrize('field_version', [17, 24])
def test_skip_piggybacks_frees_the_closed_temp_lobs(field_version: int) -> None:
    # A client that let its temp LOB objects go out of scope frees them on its
    # next call as a piggyback (func 96, #852) rather than a FREE_TEMP call of
    # their own. The Mirror has to walk it -- it used to stop there, and the
    # second large-LOB insert of every session was refused -- and it drops the
    # buffers, as the FREE_TEMP call does.
    from seerdb.common.tns import (
        _DECODE_FIELD_VERSION,
        encode_free_temp_lobs_piggyback,
        parse_free_temp_lobs_piggyback,
    )
    from seerdb.server.session import _skip_piggybacks, _TempLobs

    body = _exec_body()
    temp_lobs = _TempLobs()
    first, second, kept = (temp_lobs.mint(True) for _ in range(3))
    temp_lobs.append(first, b'a')
    temp_lobs.append(second, b'b')
    token = _DECODE_FIELD_VERSION.set(field_version)
    try:
        free = encode_free_temp_lobs_piggyback(4, field_version, [first, second])
        assert _skip_piggybacks(free + body, None, temp_lobs) == body
        assert (temp_lobs.content(first), temp_lobs.content(second)) == (b'', b'')
        # A locator the Mirror never saw (a client can free what it never wrote)
        # is not an error, and nothing else is disturbed.
        stray = encode_free_temp_lobs_piggyback(4, field_version, [first])
        assert _skip_piggybacks(stray + body, None, temp_lobs) == body
        assert temp_lobs.content(kept) == b''
        # An empty array walks too.
        assert (
            _skip_piggybacks(
                encode_free_temp_lobs_piggyback(4, field_version, []) + body
            )
            == body
        )
    finally:
        _DECODE_FIELD_VERSION.reset(token)

    # The parser lands on the call behind the live 23ai bytes, and the encoder
    # reproduces them from the captured locator -- to the byte, except that the
    # client writes the operation ub4 at full width (04 00 08 01 11) where
    # encode_sb4 compacts it (03 08 01 11); same value, so compare parsed.
    locator = _CLOSE_TEMP_LOBS_23AI[-38:]
    freed, rest = parse_free_temp_lobs_piggyback(_CLOSE_TEMP_LOBS_23AI[4:] + body)
    assert freed == [locator]
    assert rest == body
    mine = encode_free_temp_lobs_piggyback(10, 24, [locator])
    assert mine[:14] == _CLOSE_TEMP_LOBS_23AI[:14]
    assert mine[-51:] == _CLOSE_TEMP_LOBS_23AI[-51:]
    assert parse_free_temp_lobs_piggyback(mine[4:] + body) == (freed, body)
    # …and a piggyback cut short is reported, not mis-read as a call.
    with pytest.raises(Truncated):
        parse_free_temp_lobs_piggyback(_CLOSE_TEMP_LOBS_23AI[4:-1])


def test_live_seerdb_tracing_attributes_at_a_higher_field_version() -> None:
    # A real 23ai-negotiated client sets tracing attributes; the next execute
    # carries the SET_END_TO_END_ATTR piggyback, and the query still answers.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]
    result: dict = {}
    backend = _DualBackend()

    def run() -> None:
        conn, _ = listen.accept()
        try:
            result['user'] = serve_session(
                PacketStream(conn), backend, field_version=17
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
            result['error'] = exc
        finally:
            conn.close()

    server = threading.Thread(target=run, daemon=True)
    server.start()
    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        conn.module = 'seerdb-test'
        conn.client_identifier = 'tracer'
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        assert cursor.fetchone() == ('X',)
        assert backend.tracing == {
            'module': 'seerdb-test',
            'action': None,
            'client_identifier': 'tracer',
        }
        conn.module = None  # a clear rides the next call too
        cursor.execute('select * from dual')
        assert cursor.fetchone() == ('X',)
        assert backend.tracing['module'] is None
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')


def test_live_seerdb_sessionless_transaction_at_23ai() -> None:
    # A real 23ai-negotiated client begins a sessionless transaction, runs a
    # statement, suspends it, and each TPC switch reaches the backend.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]
    result: dict = {}
    backend = _DualBackend()

    def run() -> None:
        conn, _ = listen.accept()
        try:
            result['user'] = serve_session(
                PacketStream(conn), backend, field_version=17
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
            result['error'] = exc
        finally:
            conn.close()

    server = threading.Thread(target=run, daemon=True)
    server.start()
    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        txnid = conn.begin_sessionless_transaction('sl-live', timeout=45)
        assert backend.sessionless == ('begin', txnid, 45)
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        assert cursor.fetchone() == ('X',)
        conn.suspend_sessionless_transaction()
        assert backend.sessionless[0] == 'suspend'
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')


def test_live_seerdb_dual_query() -> None:
    # The 2.1.0 capstone: a real client runs SELECT * FROM DUAL against the
    # Mirror (no Oracle, no Postgres) and gets the DUMMY 'X' row back.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_session, args=(listen, result), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        row = cursor.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('X',)


def test_live_seerdb_ping() -> None:
    # A real client's ping() (keepalive / pool health check) round-trips against
    # the Mirror and the session stays usable for a following query.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_session, args=(listen, result), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        conn.ping()  # must not hang
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        row = cursor.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('X',)


def test_unsupported_query_errors_but_keeps_connection() -> None:
    # The cardinal rule: a refused query is an ORA error on a HEALTHY
    # connection — never a desync. After the error, the connection still works.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_session, args=(listen, result), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        cursor = conn.cursor()
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            cursor.execute('select * from something_the_backend_refuses')
        assert 'ORA-03001' in str(excinfo.value)
        # The connection survived the error — a valid query still works.
        cursor.execute('select * from dual')
        row = cursor.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('X',)


def test_unencodable_out_bind_errors_but_keeps_connection() -> None:
    # The never-desync rule extends to encoding the reply: a backend that returns
    # an OUT-bind value the wire can't carry must surface a clean ORA error on a
    # HEALTHY connection, not drop it mid-response. The OUT-bind encode step used
    # to run outside the guard, so it desynced (#535).
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_bad_out_bind_session, args=(listen, result), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        cursor = conn.cursor()
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            cursor.callproc('P', [cursor.var(seerdb.DB_TYPE_NUMBER)])
        # ORA-03115, not ORA-00600: a value the wire cannot carry is a feature
        # gap, and ORA-00600 is Oracle's INTERNAL-error code, which real clients
        # treat as fatal -- so reporting it here killed the session the rest of
        # this test is about proving survives (#875).
        assert 'ORA-03115' in str(excinfo.value)
        # The connection survived the encoding failure — a valid query still works.
        cursor.execute('select * from dual')
        row = cursor.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('X',)


def test_free_temp_drops_the_buffer_and_state_ops_ack() -> None:
    # A programmatic client's FREE_TEMP releases the temp LOB (the Mirror drops
    # its buffer) and OPEN / CLOSE / TRIM / GET_CHUNK_SIZE are acknowledged rather
    # than mis-routed to the read path — no desync (#417). Driven at the handler
    # level: no client in the matrix sends these against the Mirror.
    import struct

    from seerdb.common.tns import _fun_header, decode_lobops_oer, encode_sb4
    from seerdb.common.tns_consts import (
        FIELD_VERSION_11_2,
        TNS_DATA,
        TNS_LOB_OP_FREE_TEMP,
        TNS_LOB_OP_OPEN,
        TTI_LOBOPS,
    )
    from seerdb.server.session import _answer_lobops

    def op_request(operation: int, locator: bytes) -> bytes:
        body = _fun_header(TTI_LOBOPS, 1, FIELD_VERSION_11_2)
        body += bytes([1]) + encode_sb4(len(locator) + 2) + bytes([0])
        body += encode_sb4(0) * 3 + bytes([0, 0, 0]) + encode_sb4(operation)
        body += bytes([0, 0]) + encode_sb4(0) * 2 + bytes([0])
        body += struct.pack('>HHH', 0, 0, 0)
        body += struct.pack('>H', len(locator)) + locator
        return body

    class _FakeStream:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def write_packet(self, packet_type: int, body: bytes) -> None:
            assert packet_type == TNS_DATA
            self.sent.append(body)

    from seerdb.server.session import _TempLobs

    temp_lobs = _TempLobs()
    locator = temp_lobs.mint(is_blob=True)
    temp_lobs.append(locator, b'written-bytes')
    stream: Any = _FakeStream()

    # FREE_TEMP drops the buffer and replies with a success ack.
    _answer_lobops(stream, op_request(TNS_LOB_OP_FREE_TEMP, locator), [], temp_lobs)
    assert temp_lobs.content(locator) == b''
    assert decode_lobops_oer(stream.sent[-1], 6)[0] in (0, 1403)

    # A state op (OPEN) is acknowledged, buffer untouched, no desync.
    temp_lobs.append(locator, b'x')
    _answer_lobops(stream, op_request(TNS_LOB_OP_OPEN, locator), [], temp_lobs)
    assert temp_lobs.content(locator) == b'x'  # OPEN doesn't free
    assert decode_lobops_oer(stream.sent[-1], 6)[0] in (0, 1403)


def _lobops_request(operation: int, locator: bytes, **extra) -> bytes:
    """A real TTI_LOBOPS request, built with the client's own encoder.

    Hand-rolling the body here silently produced one with an EMPTY locator
    field, which every locator-keyed assertion would then have passed or failed
    for the wrong reason."""
    from seerdb.common.tns import encode_dictionary_lobops

    return encode_dictionary_lobops(
        {'seq': 1, 'locator': locator, 'operation': operation, **extra}
    )


class _CollectingStream:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def write_packet(self, packet_type: int, body: bytes) -> None:
        from seerdb.common.tns_consts import TNS_DATA

        assert packet_type == TNS_DATA
        self.sent.append(body)


def test_a_column_lob_read_is_answered_by_its_own_locator() -> None:
    # A fetched column LOB is read by the locator the Mirror minted for it, not
    # by arrival order. The old path popped a row-major queue, which is only
    # right when the client reads every LOB exactly once in the order the
    # locators went out. Read them in any other order -- which the reference
    # client does -- and each got another row's content, or nothing at all once
    # the queue ran dry (#826).
    from seerdb.common.tns import LobEmitLog
    from seerdb.common.tns_consts import TNS_LOB_OP_READ
    from seerdb.server.session import _answer_lobops, _TempLobs

    log = LobEmitLog()
    first = log.record(b'first-row-content', is_clob=False)
    second = log.record(b'second-row-content', is_clob=False)
    assert first != second  # each emitted LOB gets its own locator (#888)

    stream: Any = _CollectingStream()

    def read(locator: bytes) -> bytes:
        # The row-major queue is primed with a decoy. Anything answered from it
        # rather than from the locator shows up as this content, which is what
        # the old path would hand back for every one of these reads.
        _answer_lobops(
            stream,
            _lobops_request(TNS_LOB_OP_READ, locator),
            [(b'decoy-from-the-queue', False)],
            _TempLobs(),
            lob_emit_log=log,
        )
        return stream.sent[-1]

    # The SECOND one first: order must not matter, and the queue is empty
    # throughout, so on master both of these come back with no content.
    reply = read(second)
    assert b'second-row-content' in reply
    assert b'first-row-content' not in reply
    assert b'decoy-from-the-queue' not in reply
    assert b'first-row-content' in read(first)
    # Re-reading one already read still works -- there is no queue to exhaust.
    assert b'second-row-content' in read(second)


def test_a_column_lob_reports_its_own_size_not_zero() -> None:
    # `lob.size()` on a FETCHED LOB consulted the temp-LOB store, which knows
    # nothing about a column locator, so every such size() came back 0 (#826).
    from seerdb.common.tns import LobEmitLog, decode_ub4
    from seerdb.common.tns_consts import TNS_LOB_OP_GET_LENGTH
    from seerdb.server.session import _answer_lobops, _TempLobs

    log = LobEmitLog()
    # A CLOB counts CHARACTERS: the log keeps the `str`, so a multi-byte
    # character must not inflate the answer the way its UTF-16BE buffer would.
    clob = log.record('caf\u00e9' + 'x' * 96, is_clob=True)
    blob = log.record(b'\x00' * 250, is_clob=False)
    stream: Any = _CollectingStream()

    def length_of(locator: bytes) -> int:
        # The locator goes RAW, and the reply echoes it VERBATIM. This fixture
        # used to send it ub2-prefixed, on the #826 reading that GET_LENGTH
        # differed from READ. It does not: a real Oracle locator OPENS with its
        # own 2-byte length (`00 70` for a 114-byte one), which reads exactly
        # like a framing prefix and is not one. Stripping it and re-adding a
        # prefix happens to reproduce the bytes for such a locator, which is why
        # the mistake survived -- and corrupts any locator whose first two bytes
        # are something else, such as the Mirror's own (#903/#887).
        _answer_lobops(
            stream,
            _lobops_request(TNS_LOB_OP_GET_LENGTH, locator, locator_prefixed=False),
            [],
            _TempLobs(),
            lob_emit_log=log,
        )
        # The reply is the echoed locator then a ub4 length (§14): skip the
        # verbatim locator echo -- no length prefix -- and read what follows.
        body = stream.sent[-1]
        head = 1 + len(locator)
        return decode_ub4(body[head:])[0]

    assert length_of(clob) == 100
    assert length_of(blob) == 250


# --- PL/SQL OUT-bind helpers (#483) --------------------------------------------


@pytest.mark.parametrize(
    'sql',
    [
        'BEGIN p(:1); END;',
        '  declare x number; begin null; end;',
        '-- fill it\nBEGIN INSERT INTO t VALUES (1); END;',
        '/* fill it */ DECLARE x NUMBER; BEGIN NULL; END;',
    ],
)
def test_a_plsql_block_opens_a_transaction(sql: str) -> None:
    # A PL/SQL block opens a transaction, and the reply must say so, or a client
    # that trusts the flag skips its rollback (#889). A block may start with a
    # comment: the Mirror took one for something else and left the flag clear,
    # where the server sets it (#1172).
    from seerdb.common.tns import _ENCODE_TXN_IN_PROGRESS
    from seerdb.server.session import _mark_transaction

    token = _ENCODE_TXN_IN_PROGRESS.set(False)
    try:
        _mark_transaction(sql, autocommit=False)
        assert _ENCODE_TXN_IN_PROGRESS.get() is True
    finally:
        _ENCODE_TXN_IN_PROGRESS.reset(token)


def test_a_query_leaves_the_transaction_flag_alone() -> None:
    from seerdb.common.tns import _ENCODE_TXN_IN_PROGRESS
    from seerdb.server.session import _mark_transaction

    token = _ENCODE_TXN_IN_PROGRESS.set(False)
    try:
        _mark_transaction('-- rows\nSELECT 1 FROM dual', autocommit=False)
        assert _ENCODE_TXN_IN_PROGRESS.get() is False
    finally:
        _ENCODE_TXN_IN_PROGRESS.reset(token)


def test_bind_vars_wraps_block_binds_with_type_and_size() -> None:
    from seerdb.common.tns import ExecRequest
    from seerdb.common.tns_consts import (
        TNS_TYPE_NUMBER,
        TNS_TYPE_REFCURSOR,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server.backend import BindVar
    from seerdb.server.session import _bind_vars

    block = ExecRequest(
        sql='BEGIN p(:1, :2); END;',
        cursor=0,
        bind_count=2,
        fetch=0,
        binds=[7, None],
        bind_meta=[(TNS_TYPE_NUMBER, 22), (TNS_TYPE_VARCHAR, 32767)],
    )
    wrapped = _bind_vars(block)
    assert all(isinstance(b, BindVar) for b in wrapped)
    assert [b.array_size for b in wrapped] == [0, 0]  # scalars
    assert (wrapped[0].value, wrapped[0].tns_type, wrapped[0].max_size) == (
        7,
        TNS_TYPE_NUMBER,
        22,
    )
    assert wrapped[1].max_size == 32767  # the OUT VARCHAR buffer size

    # A non-block statement passes its plain values through unchanged.
    dml = ExecRequest(
        sql='INSERT INTO t VALUES (:1)',
        cursor=0,
        bind_count=1,
        fetch=0,
        binds=[7],
        bind_meta=[(TNS_TYPE_NUMBER, 22)],
    )
    assert _bind_vars(dml) == [7]

    # A REF CURSOR bind also rides the OUT path — the backend opens the cursor
    # and its rows come back on a parked cursor id (#483).
    refc = ExecRequest(
        sql='BEGIN p(:1); END;',
        cursor=0,
        bind_count=1,
        fetch=0,
        binds=[None],
        bind_meta=[(TNS_TYPE_REFCURSOR, 1)],
    )
    wrapped_rc = _bind_vars(refc)
    assert len(wrapped_rc) == 1
    assert wrapped_rc[0].tns_type == TNS_TYPE_REFCURSOR


def test_bind_vars_carries_an_array_binds_capacity() -> None:
    # An associative-array bind's elements and capacity reach the backend (#743).
    from seerdb.common.tns import ExecRequest
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.session import _bind_vars

    block = ExecRequest(
        sql='BEGIN p(:1, :2); END;',
        cursor=0,
        bind_count=2,
        fetch=0,
        binds=[[1, 2], []],
        bind_meta=[(TNS_TYPE_NUMBER, 22), (TNS_TYPE_NUMBER, 22)],
        bind_arrays=[10, 4],
    )
    wrapped = _bind_vars(block)
    assert [(b.value, b.array_size) for b in wrapped] == [([1, 2], 10), ([], 4)]


def test_bind_vars_wraps_only_a_null_of_an_ordinary_statement() -> None:
    # A NULL bind carries no type of its own, so it goes over with the type the
    # client declared for it; a value goes over bare (#699).
    from seerdb.common.tns import ExecRequest
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar
    from seerdb.server.session import _bind_vars

    select = ExecRequest(
        sql='SELECT id FROM t WHERE CASE WHEN :1 IS NOT NULL THEN :1 ELSE d END = :2',
        cursor=0,
        bind_count=2,
        fetch=0,
        binds=[None, 'x'],
        bind_meta=[(TNS_TYPE_NUMBER, 22), (TNS_TYPE_VARCHAR, 32)],
    )
    wrapped = _bind_vars(select)
    assert wrapped[1] == 'x'
    assert isinstance(wrapped[0], BindVar)
    assert (wrapped[0].value, wrapped[0].tns_type) == (None, TNS_TYPE_NUMBER)
    # A shape mismatch passes everything through untouched.
    mismatched = ExecRequest(
        sql=select.sql,
        cursor=0,
        bind_count=2,
        fetch=0,
        binds=[None, 'x'],
        bind_meta=[(TNS_TYPE_NUMBER, 22)],
    )
    assert _bind_vars(mismatched) == [None, 'x']


def test_bind_vars_marks_a_character_value_with_its_declared_size() -> None:
    # Oracle describes a character bind, and a concatenation over one, by the
    # buffer the client declared, so the size goes over with the value (#2063).
    # A CLOB's content and a value of any other type stay as they are.
    from seerdb.common.tns import ExecRequest
    from seerdb.common.tns_consts import (
        TNS_TYPE_CHAR,
        TNS_TYPE_NUMBER,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server.backend import ClobValue, VarcharValue
    from seerdb.server.session import _bind_vars

    clob = ClobValue('c')
    select = ExecRequest(
        sql='SELECT :1 || :2 || :3 || :4 FROM dual',
        cursor=0,
        bind_count=4,
        fetch=0,
        binds=['abc', 'd', clob, 5],
        bind_meta=[
            (TNS_TYPE_VARCHAR, 1012),
            (TNS_TYPE_CHAR, 4),
            (TNS_TYPE_VARCHAR, 4),
            (TNS_TYPE_NUMBER, 22),
        ],
    )
    wrapped = _bind_vars(select)
    assert wrapped == ['abc', 'd', 'c', 5]
    assert [type(v) for v in wrapped] == [VarcharValue, VarcharValue, ClobValue, int]
    assert [v.max_size for v in wrapped[:2]] == [1012, 4]
    assert wrapped[2] is clob


def test_oci_sequence_advances_per_reply() -> None:
    # The per-session OER end-to-end sequence counter yields a fresh, advancing
    # value on each call, starting at 1 — the Mirror threads seq.next() into every
    # OCI status reply so the field advances like a real server's instead of
    # repeating the frozen capture constant (§36).
    from seerdb.common.tns import encode_status_oci
    from seerdb.server.session import _OciSequence

    seq = _OciSequence()
    assert [seq.next() for _ in range(4)] == [1, 2, 3, 4]

    # Threading one counter through consecutive status replies advances the OER
    # sequence byte (frame offset 40: the compact OER sits at offset 32 with three
    # leading pad bytes, and the sequence is at the OER's own offset 5) reply over
    # reply — and nothing else in the frame changes.
    seq2 = _OciSequence()
    first = encode_status_oci(seq2.next())
    second = encode_status_oci(seq2.next())
    assert first[40] == 1
    assert second[40] == 2
    assert [i for i in range(len(first)) if first[i] != second[i]] == [40]


# --- sqlplus PASSWORD / OCI changepassword (#21) ------------------------------


def _oci_changepassword_frame(
    conn_key: bytes, user: bytes, old: str, new: str
) -> bytes:
    """Build a synthetic OCI (deadbeef) changepassword TTI_AUTH, as sqlplus's
    PASSWORD sends inside its TTI_80SES piggyback (unwrapped): AUTH_PASSWORD
    (current) + AUTH_NEWPASSWORD (new), each hex(AES-cipher under conn_key)."""
    from seerdb.common import oci
    from seerdb.common.crypto import encrypt_password
    from seerdb.server.auth import encode_kv_oci

    ind = oci.OCI_INDICATOR
    # The login AUTH's head (tns._AUTH_HEAD): TTI_FUN + AUTH subtype, a pointer,
    # the user's length declared at three times its characters and the mode, a
    # pointer, the ub8 pair count, two pointers, the user as a value -- as
    # sqlplus's login AUTH carries them; no changepassword capture survives.
    header = (
        b'\x03\x73\x00'
        + ind
        + (3 * len(user)).to_bytes(4, 'little')
        + bytes(4)
        + ind
        + (2).to_bytes(8, 'little')
        + ind
        + ind
        + bytes([len(user)])
        + user
    )
    old_hex = encrypt_password(conn_key, old.encode()).hex().upper().encode()
    new_hex = encrypt_password(conn_key, new.encode()).hex().upper().encode()
    return (
        header
        + encode_kv_oci(b'AUTH_PASSWORD', old_hex)
        + encode_kv_oci(b'AUTH_NEWPASSWORD', new_hex)
    )


def test_is_version_call_oci_distinguishes_changepassword() -> None:
    # The version call and the changepassword both arrive as a TTI_80SES
    # (0x11 0x6b) piggyback with the same 15-byte prefix; only the wrapped TTI
    # function differs (0x3b version vs. TTI_AUTH). is_version_call_oci must key
    # on the inner function, else a changepassword is answered with the banner.
    from seerdb.common.tns import is_version_call_oci, strip_oci_piggyback

    prefix = bytes.fromhex('116b043b000000e507000001000000')
    version = prefix + bytes.fromhex('033b') + b'\x00' * 4
    change = prefix + bytes.fromhex('0373') + b'\x00' * 4
    assert is_version_call_oci(version)
    assert not is_version_call_oci(change)
    # strip_oci_piggyback unwraps the TTI_80SES wrapper to the inner TTI_FUN call.
    assert strip_oci_piggyback(change)[:2] == bytes.fromhex('0373')
    assert strip_oci_piggyback(version)[:2] == bytes.fromhex('033b')


def test_oci_changepassword_decrypts_and_applies() -> None:
    from seerdb.common.tns import encode_changepassword_status_oci
    from seerdb.server.auth import parse_changepassword_oci
    from seerdb.server.session import _answer_changepassword_oci

    conn_key = bytes(range(24))
    frame = _oci_changepassword_frame(conn_key, b'PWTEST', 'oldpw', 'newpw')

    # The parser recovers the two ciphertexts (un-hexed).
    from seerdb.common.crypto import encrypt_password

    user, old_c, new_c = parse_changepassword_oci(frame)
    assert user == b'PWTEST'
    assert old_c == encrypt_password(conn_key, b'oldpw')
    assert new_c == encrypt_password(conn_key, b'newpw')

    calls: list = []

    class _Backend:
        def change_password(self, u: str, old: str, new: str) -> None:
            calls.append((u, old, new))

    class _Stream:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def write_packet(self, ptype: int, body: bytes) -> None:
            self.sent.append(body)

    class _Seq:
        def next(self) -> int:
            return 1

    stream: Any = _Stream()
    backend: Any = _Backend()
    seq: Any = _Seq()
    _answer_changepassword_oci(stream, backend, frame, conn_key, 'PWTEST', seq)
    # decrypted the pair and drove the backend change, then acked with the
    # OCIPasswordChange success frame sqlplus renders as "Password changed".
    assert calls == [('PWTEST', 'oldpw', 'newpw')]
    assert stream.sent[-1] == encode_changepassword_status_oci()


def test_oci_changepassword_unsupported_backend_replies_ora_error() -> None:
    from seerdb.server.session import _answer_changepassword_oci

    conn_key = bytes(range(24))
    frame = _oci_changepassword_frame(conn_key, b'PWTEST', 'oldpw', 'newpw')

    class _Stream:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        def write_packet(self, ptype: int, body: bytes) -> None:
            self.sent.append(body)

    class _Seq:
        def next(self) -> int:
            return 1

    stream: Any = _Stream()
    # A backend with no change_password: reply with an ORA error, never desync.
    no_change_password: Any = object()
    seq: Any = _Seq()
    _answer_changepassword_oci(
        stream, no_change_password, frame, conn_key, 'PWTEST', seq
    )
    assert stream.sent, 'must answer even when unsupported'
    assert b'ORA-01031' in stream.sent[-1]


class _LeakyBackend(_DualBackend):
    # A backend that embeds a seerdb client talking to a NEWER Oracle (the
    # passthrough in front of a 23ai) leaves the codec's field-version context
    # variables at the upstream's version after every call — decode_packet /
    # encode_dictionary_exec set them per message in the calling thread. This
    # stand-in does exactly that on each execute and records the binds it got.
    def __init__(self) -> None:
        self.binds: list = []

    def execute(self, sql: str, binds=()) -> Result:
        from seerdb.common.tns import _DECODE_FIELD_VERSION, _ENCODE_FIELD_VERSION
        from seerdb.common.tns_consts import FIELD_VERSION_23_1

        self.binds.append(list(binds))
        _DECODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
        _ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
        if sql.lstrip().upper().startswith('INSERT'):
            return Result(rowcount=1)
        return super().execute(sql, binds)


def test_backend_codec_context_does_not_leak_into_the_session() -> None:
    # A 32K+ string bind goes out in the 11g chunked LONG layout. If the backend's
    # own codec state (field version 23ai) leaked into the session thread, the
    # Mirror would decode the client's 11g chunks with the 12.2+ framing and hand
    # the backend a garbled value (observed live: 51951 chars for 51200, first
    # character dropped). The backend must see the client's exact value.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    backend = _LeakyBackend()
    result: dict = {}

    def run() -> None:
        conn, _ = listen.accept()
        try:
            result['user'] = serve_session(PacketStream(conn), backend)
        except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
            result['error'] = exc
        finally:
            conn.close()

    server = threading.Thread(target=run, daemon=True)
    server.start()

    text = '0123456789abcdef' * (50 * 1024 // 16)  # 51200 chars, chunked on the wire
    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        cursor = conn.cursor()
        cursor.execute('select * from dual')  # the backend pollutes the context
        cursor.execute('INSERT INTO t (c) VALUES (:c)', {'c': text})
        cursor.execute('select * from dual')  # and the response path still works
        row = cursor.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('X',)
    assert backend.binds[1] == [text]


# The end-to-end tracing piggyback modern sqlplus sends immediately after login,
# captured live (sqlplus 23.26, field version 6): the 0x11 0x87 header, a fixed
# block whose marshalled fields include client pointer values, the module name
# "SQL*Plus" as its only set value, and then the real call -- 03 0e, a commit.
_OCI_E2E_PIGGYBACK_SQLPLUS = bytes.fromhex(
    '1187020000000000000000000000000000000018000000000000000000000000'
    '0000000000000000000000feffffffffffffff18000000000000002806734615'
    '5600000000000000000000000000000000000000000000000001000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000853514c2a506c7573030e03'
)


def test_oci_tracing_piggyback_is_walked_to_the_call_behind_it() -> None:
    # Modern sqlplus bundles its tracing attributes as a piggyback in FRONT of a
    # real call. The OCI loop stripped only the close-cursors and TTI_80SES
    # wrappers, so this one fell through and the session was closed on the
    # client -- sqlplus then reported ORA-03114 for every statement (#825).
    #
    # Its thick-OCI block is not decoded: only one live sample exists and
    # several layouts fit it. The walker reads the length-prefixed values and
    # then CHECKS its landing, returning None rather than guessing, so an
    # unknown shape becomes a refusal instead of a desynchronised stream.
    from seerdb.common.oci import strip_oci_e2e_piggyback
    from seerdb.common.tns_consts import TTI_COMMIT, TTI_FUN

    behind = strip_oci_e2e_piggyback(_OCI_E2E_PIGGYBACK_SQLPLUS)
    assert behind == bytes([TTI_FUN, TTI_COMMIT, 3])

    # A shape it cannot walk is reported, never guessed at: a block whose values
    # run off the end, and one that never reaches a TTI_FUN.
    assert strip_oci_e2e_piggyback(_OCI_E2E_PIGGYBACK_SQLPLUS[:145]) is None
    assert strip_oci_e2e_piggyback(bytes([0x11, 0x87]) + bytes(200)) is None


def test_oci_loop_refuses_an_unknown_call_instead_of_closing_the_session() -> None:
    # The OCI loop used to `return` on any call it did not implement, which
    # closes the connection: sqlplus renders that as ORA-03113 / ORA-03114 for
    # everything afterwards, indistinguishable from the server crashing, and one
    # unimplemented call takes the whole session with it. The thin loop was
    # taught to refuse in #832/#836; this is the same rule for the thick one.
    from seerdb.common.tns_consts import TNS_DATA
    from seerdb.server.session import _serve_oci_session

    unknown = bytes([TTI_FUN, 0xFA, 1])  # a function the Mirror does not serve

    class _Stream:
        def __init__(self) -> None:
            self.inbox = [(TNS_DATA, unknown), (TNS_DATA, unknown), None]
            self.sent: list[tuple[int, bytes]] = []

        def read_packet(self, **_kw):
            return self.inbox.pop(0)

        def write_packet(self, ptype: int, body: bytes, **_kw) -> None:
            self.sent.append((ptype, body))

    stream: Any = _Stream()
    backend: Any = object()
    assert _serve_oci_session(stream, backend, 'PYO') == 'PYO'
    # BOTH calls were answered -- the session survived the first refusal, which
    # is the whole point -- and each answer names the error the client knows.
    assert len(stream.sent) == 2
    for _ptype, body in stream.sent:
        assert b'ORA-03115' in body


def test_oci_commit_and_rollback_calls_run_on_the_backend() -> None:
    # sqlplus 10.2 and 11.2 send an OCI commit call (03 0e, captured against
    # 11g) after each statement under SET AUTOCOMMIT ON. It was acknowledged
    # without running, so sqlplus printed "Commit complete." and a later
    # rollback took the row (#2102). Each call now runs, and a backend failure
    # is the call's error rather than a success.
    from seerdb.common.tns import encode_commit_status_oci
    from seerdb.common.tns_consts import TNS_DATA, TTI_COMMIT, TTI_ROLLBACK
    from seerdb.server.backend import BackendError
    from seerdb.server.session import _serve_oci_session

    calls = [
        bytes([TTI_FUN, TTI_COMMIT, 3]),
        bytes([TTI_FUN, TTI_ROLLBACK, 4]),
        bytes([TTI_FUN, TTI_COMMIT, 5]),
    ]

    class _Stream:
        def __init__(self) -> None:
            self.inbox = [(TNS_DATA, call) for call in calls] + [None]
            self.sent: list[bytes] = []

        def read_packet(self, **_kw):
            return self.inbox.pop(0)

        def write_packet(self, _ptype: int, body: bytes, **_kw) -> None:
            self.sent.append(body)

    class _Backend:
        def __init__(self) -> None:
            self.ran: list[str] = []

        def commit(self) -> None:
            self.ran.append('commit')
            if len(self.ran) == 3:
                raise BackendError('ORA-02091: transaction rolled back', ora_code=2091)

        def rollback(self) -> None:
            self.ran.append('rollback')

    stream: Any = _Stream()
    backend: Any = _Backend()
    assert _serve_oci_session(stream, backend, 'PYO') == 'PYO'
    assert backend.ran == ['commit', 'rollback', 'commit']
    assert stream.sent[:2] == [encode_commit_status_oci(1), encode_commit_status_oci(2)]
    assert b'ORA-02091' in stream.sent[2]


def test_an_error_with_no_position_points_sqlplus_at_column_0() -> None:
    # A backend error with no offset went to sqlplus as the captured 14, so
    # every such error's `*` stood in the middle of its statement (#2111).
    # Oracle's place for an error that has none is 0.
    from seerdb.server.backend import BackendError
    from seerdb.server.session import _oci_error_pos

    assert _oci_error_pos(BackendError('x', ora_code=1)) == 0
    assert _oci_error_pos(BackendError('x', ora_code=955, error_offset=13)) == 13
    assert _oci_error_pos(RuntimeError('no offset at all')) == 0


# sqlplus 23.26 re-executing DBMS_OUTPUT.GET_LINES by cursor id, with no SQL,
# as captured against Mirror-over-PG (#1411 / #1515).
_OCI_REEXECUTE_GET_LINES = bytes.fromhex(
    '035e012004040001000000000000000000000000000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000001000000000000000000000000'
    '0000000000000000000000080000000000000000800000000000000000000000'
    '000000070000000002c102'
)


def test_oci_loop_refuses_a_call_it_cannot_parse() -> None:
    # A re-execute by cursor id with nothing parked does not parse, and it was
    # answered as a success without running anything. sqlplus then re-executed
    # GET_LINES 65,529 times, never getting its line count back (#1515). Refused,
    # the client sees an error, the backend is never handed a guess, and the
    # session carries on.
    from seerdb.common.tns_consts import TNS_DATA
    from seerdb.server.session import _serve_oci_session

    class _Stream:
        def __init__(self) -> None:
            self.inbox = [
                (TNS_DATA, _OCI_REEXECUTE_GET_LINES),
                (TNS_DATA, _OCI_REEXECUTE_GET_LINES),
                None,
            ]
            self.sent: list[tuple[int, bytes]] = []

        def read_packet(self, **_kw):
            return self.inbox.pop(0)

        def write_packet(self, ptype: int, body: bytes, **_kw) -> None:
            self.sent.append((ptype, body))

    class _NoBackend:
        def execute(self, *_args, **_kw):
            raise AssertionError('an unparsed call reached the backend')

    stream: Any = _Stream()
    backend: Any = _NoBackend()
    assert _serve_oci_session(stream, backend, 'PYO') == 'PYO'
    assert len(stream.sent) == 2
    for _ptype, body in stream.sent:
        assert b'ORA-03115' in body


# sqlplus 23.26 calling DBMS_OUTPUT.GET_LINES with :LINES bound as the
# DBMSOUTPUT_LINESARRAY collection (type 109), captured against a live 18c (#1411).
_OCI_GET_LINES_COLLECTION_BIND = bytes.fromhex(
    '035e102904040000000000feffffffffffffff9c000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000100000000000000fe'
    'ffffffffffffff020000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000034424547494e2044424d535f4f55545055'
    '542e4745545f4c494e4553283a4c494e45532c203a4e554d4c494e4553293b20'
    '454e443b01000000010000000000000000000000000000000000000000000000'
    '080000000000000000800000000000000000000000000000006d000000d00700'
    '000000000000000000000000001000000010787d0d2b19c46933e0530caae80a'
    '12fb010000000000000000000000000102030000160000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '07240000002400220208787d0d2b19c46933e0530caae80a12fb000000000000'
    '00000000000000010001000000000000000000000000010002c110'
)


def test_the_get_lines_collection_bind_is_read() -> None:
    # sqlplus binds DBMS_OUTPUT.GET_LINES's lines as DBMSOUTPUT_LINESARRAY: a
    # collection (109) carrying the type's id, its IN value empty, and the count
    # as an IN NUMBER (#1411). Both binds are read, the collection's type id
    # riding on bind_types for the backend.
    from seerdb.common.tns import _DECODE_FIELD_VERSION, parse_exec_oci
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1, TNS_TYPE_ADT

    token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        request = parse_exec_oci(_OCI_GET_LINES_COLLECTION_BIND)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert request.binds == [None, 15]
    assert request.bind_meta == [(TNS_TYPE_ADT, 2000), (2, 22)]
    toid = bytes.fromhex('787d0d2b19c46933e0530caae80a12fb')
    assert [bt[3] for bt in request.bind_types] == [toid, b'']


# sqlplus 23.26 asking a live 18c for SERVEROUTPUT's second batch (#2041):
# TTI_EXEC by cursor id 4 (the id the first reply's status frame named), one
# iteration, and an RXD row with the one bind that came in with a value,
# :NUMLINES = 15.
_OCI_EXEC_GET_LINES = bytes.fromhex('030411040000000100000000000000000000000702c110')


def test_an_exec_by_cursor_names_its_cursor_and_in_values() -> None:
    from seerdb.common.tns import parse_exec_by_cursor_oci
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER

    assert parse_exec_by_cursor_oci(_OCI_EXEC_GET_LINES, [TNS_TYPE_NUMBER]) == (4, [15])


def test_get_lines_runs_again_by_cursor_for_each_batch() -> None:
    # After the first GET_LINES, sqlplus fetches the next batch by cursor id;
    # it was refused, and SERVEROUTPUT stopped after 30 lines (#2041). The block
    # runs again with the new count, and the reply is its OUT values and OER --
    # no OUT-bind header, no status frame, as a live 18c answers.
    from types import SimpleNamespace

    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1, TNS_DATA
    from seerdb.server.session import _serve_oci_session

    class _GetLines(_OciCountingBackend):
        def __init__(self) -> None:
            super().__init__()
            self.binds: list = []

        def execute(self, sql: str, binds=()) -> Result:
            self.calls.append(sql)
            self.binds.append([getattr(b, 'value', b) for b in binds])
            return Result(out_binds=[SimpleNamespace(image=b'\x01\x02'), 15])

    stream: Any = _OciOneCallStream(_OCI_GET_LINES_COLLECTION_BIND)
    stream.inbox[1:1] = [(TNS_DATA, _OCI_EXEC_GET_LINES)]
    backend: Any = _GetLines()
    _serve_oci_session(stream, backend, 'PYO', field_version=FIELD_VERSION_18_1_EXT_1)
    first, again = stream.sent
    assert first[:2] == b'\x0b\x01'  # the OUT-bind reply
    assert len(backend.calls) == 2 and backend.calls[0] == backend.calls[1]
    assert backend.binds[1] == [None, 15]
    assert again[0] == 0x07  # the values straight away
    assert b'\x0b\x01\x05' not in again and b'\x08\x06\x00' not in again
    assert again[again.index(b'\x02\xc1\x10\x00\x00') + 5] == 0x04  # then the OER


def test_a_statement_whose_binds_are_not_read_is_refused() -> None:
    # A bind the section cannot be read for -- here the same collection bind
    # with an IN value of a form not read yet -- used to come back as no binds,
    # and the statement ran without them, so the client got a status it could
    # not use. It is refused instead, and the session carries on (#1525).
    from seerdb.common.exceptions import InterfaceError
    from seerdb.common.tns import _DECODE_FIELD_VERSION, parse_exec_oci
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1

    empty_tail = b'\x01' + bytes(12) + b'\x01\x00'
    assert _OCI_GET_LINES_COLLECTION_BIND.count(empty_tail) == 1
    unread = _OCI_GET_LINES_COLLECTION_BIND.replace(
        empty_tail, b'\x02' + empty_tail[1:]
    )
    token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        with pytest.raises(InterfaceError, match='bind'):
            parse_exec_oci(unread)
    finally:
        _DECODE_FIELD_VERSION.reset(token)


# sqlplus 23.26's SHOW ERRORS query after a create that compiled with errors,
# through a Mirror, its piggyback stripped (#2028). The SQL is longer than 252
# bytes, so it is chunked, and its one bind's descriptor carries the flag byte
# 0x20.
_OCI_SHOW_ERRORS_QUERY = bytes.fromhex(
    '035e066980000000000000feffffffffffffff57030000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000100000000000000fe'
    'ffffffffffffff010000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000feff53454c45435420544f5f4348415228'
    '4c494e45297c7c272f277c7c544f5f4348415228504f534954494f4e2920224c'
    '494e452f434f4c222c205445585420224552524f52222046524f4d20414c4c5f'
    '4552524f5253204120574845524520412e4e414d45203d205550504552283a4e'
    '4d42494e445f53484f575f4f424a2920414e4420412e54595045203d20275052'
    '4f4345445552452720414e4420412e4f574e4552203d202853454c4543542028'
    '5359535f434f4e54455854282755534552454e56272c202743555252454e545f'
    '534348454d412729292046524f4d205359532e4455414c29204f524445522042'
    '59204c494e452c20504f534954494f4e1e2c204154545249425554452c204d45'
    '53534147455f4e554d4245520000000001000000000000000000000000000000'
    '0000000000000000000000000100000000000000008000000000000000000000'
    '0000000001012000001800000000000000000000000000000000000000000000'
    '000000000000000000690301000000000000000000070873705f6332303133'
)


def test_a_long_bound_statement_is_read() -> None:
    # Binds were read only after a short statement, so this one was refused
    # with ORA-03115 and SHOW ERRORS failed (#2028).
    from seerdb.common.tns import _DECODE_FIELD_VERSION, parse_exec_oci
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1, TNS_TYPE_VARCHAR

    token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        request = parse_exec_oci(_OCI_SHOW_ERRORS_QUERY)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert len(request.sql) > 252
    assert request.sql.startswith('SELECT ')
    assert 'A.NAME = UPPER(:NMBIND_SHOW_OBJ)' in request.sql
    assert request.sql.endswith('ORDER BY LINE, POSITION, ATTRIBUTE, MESSAGE_NUMBER')
    assert request.binds == ['sp_c2013']
    assert request.bind_meta == [(TNS_TYPE_VARCHAR, 24)]


# sqlplus 23.26 selecting a variable twice, `select :n a, :n b from dual`, and
# a repeat after another name, `select :s a, :n b, :s c from dual`, captured
# against 18c (#2034). A repeat has a descriptor of its own, `01 01 80 00 00`
# and a zero size, and no value in the RXD row.
_OCI_REPEATED_BIND = bytes.fromhex(
    '035e0d6980000000000000feffffffffffffff51000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000100000000000000fe'
    'ffffffffffffff020000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000001b73656c656374203a6e20612c203a6e20'
    '622066726f6d206475616c010000000000000000000000000000000000000000'
    '0000000000000001000000000000000080000000000000000000000000000001'
    '0203000016000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000001018000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000702c108'
)
_OCI_REPEAT_AFTER_ANOTHER = bytes.fromhex(
    '035e126980000000000000feffffffffffffff63000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000100000000000000fe'
    'ffffffffffffff030000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000002173656c656374203a7320612c203a6e20'
    '622c203a7320632066726f6d206475616c010000000000000000000000000000'
    '0000000000000000000000000001000000000000000080000000000000000000'
    '000000000001010300001e000000000000000000000000000000000000000000'
    '0000000000000000000069030100000000000000000001020300001600000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000001018000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000007017802c108'
)


def test_a_repeated_bind_name_takes_its_first_value() -> None:
    # Refused with "2 bind(s) of a form not read yet" (#2034). Each placeholder
    # gets a value and a type, a repeat its name's first, as a thin client
    # sends them for a SQL statement.
    from seerdb.common.tns import _DECODE_FIELD_VERSION, parse_exec_oci
    from seerdb.common.tns_consts import (
        FIELD_VERSION_18_1_EXT_1,
        TNS_TYPE_NUMBER,
        TNS_TYPE_VARCHAR,
    )

    token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        twice = parse_exec_oci(_OCI_REPEATED_BIND)
        after = parse_exec_oci(_OCI_REPEAT_AFTER_ANOTHER)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert twice.sql == 'select :n a, :n b from dual'
    assert twice.binds == [7, 7]
    assert twice.bind_meta == [(TNS_TYPE_NUMBER, 22)] * 2
    assert after.sql == 'select :s a, :n b, :s c from dual'
    assert after.binds == ['x', 7, 'x']
    assert after.bind_meta == [
        (TNS_TYPE_VARCHAR, 30),
        (TNS_TYPE_NUMBER, 22),
        (TNS_TYPE_VARCHAR, 30),
    ]


def test_a_repeat_the_statement_does_not_name_is_refused() -> None:
    # A repeat descriptor where the statement repeats no name: the values
    # cannot be placed, so the request is refused rather than guessed at.
    from seerdb.common.tns import _DECODE_FIELD_VERSION, parse_exec_oci
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1

    sql = b'select :n a, :n b from dual'
    unnamed = _OCI_REPEATED_BIND.replace(sql, sql.replace(b':n b', b':m b'))
    token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        with pytest.raises(InterfaceError, match='bind'):
            parse_exec_oci(unnamed)
    finally:
        _DECODE_FIELD_VERSION.reset(token)


def test_oci_loop_answers_a_break_marker() -> None:
    """A break / reset marker gets a marker back, not silence.

    The thick-OCI client sends one to resynchronise the line and then blocks
    until the server answers; ignoring it wedged the session until the client
    timed out.
    """
    from seerdb.common.tns_consts import TNS_MARKER, TNS_MARKER_TYPE_RESET
    from seerdb.server.session import _serve_oci_session

    class _Stream:
        def __init__(self) -> None:
            self.inbox = [(TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET])), None]
            self.sent: list[tuple[int, bytes]] = []

        def read_packet(self, **_kw):
            return self.inbox.pop(0)

        def write_packet(self, ptype: int, body: bytes, **_kw) -> None:
            self.sent.append((ptype, body))

    stream: Any = _Stream()
    backend: Any = object()
    assert _serve_oci_session(stream, backend, 'PYO') == 'PYO'
    # One reset marker -- replying to every marker ping-pongs the two ends into
    # a reset storm -- and then the cancel's OER, as a live 18c sends it (#2036).
    from seerdb.common.tns_consts import TNS_DATA

    (reset, cancel) = stream.sent
    assert reset == (TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
    assert cancel[0] == TNS_DATA and b'ORA-01013' in cancel[1]


# sqlplus 23.26's execute of a 30-row query, then its two follow-up fetches,
# captured against a live 11g (piggyback-wrapped, as every statement past the
# first arrives). Each fetch asks cursor 2 for 15 rows (#1284).
_OCI_EXEC_30_ROWS = bytes.fromhex(
    '11690dfeffffffffffffff010000000000000001000000035e0e618000000000'
    '0000feffffffffffffffbd000000feffffffffffffff0d000000feffffffffff'
    'fffffeffffffffffffff00000000010000000000000000000000000000000000'
    '00000000000000000000feffffffffffffff0000000000000000feffffffffff'
    'fffffefffffffffffffffeffffffffffffff0000000000000000feffffffffff'
    'fffffeffffffffffffff00000000000000000000000000000000000000000000'
    '0000000000003f73656c656374206c6576656c206e2c20277827207c7c206c65'
    '76656c20732066726f6d206475616c20636f6e6e656374206279206c6576656c'
    '203c3d2033300100000000000000000000000000000000000000000000000000'
    '0000010000000000000000800000000000000000000000000000'
)
_OCI_FETCH_15_ROWS = (
    bytes.fromhex('03050f020000000f000000'),
    bytes.fromhex('030510020000000f000000'),
)


def test_oci_fetch_serves_no_more_rows_than_it_asked_for() -> None:
    # sqlplus sizes its fetch buffer to the row count it asks for. The Mirror
    # used to answer the first fetch with every parked row at once, which
    # overruns that buffer and crashes sqlplus on any result of more than 16
    # rows (the execute's 1 + one fetch's 15). A live 11g answers 1, then 15,
    # then the last 14 with the end of fetch, and so must the Mirror (#1284).
    from seerdb.common.tns import parse_fetch_oci
    from seerdb.common.tns_consts import TNS_DATA
    from seerdb.server.session import _serve_oci_session

    assert [parse_fetch_oci(f) for f in _OCI_FETCH_15_ROWS] == [15, 15]
    col = ColumnMeta(name=b'S', data_type=TNS_TYPE_VARCHAR, data_length=3, max_size=3)

    class _Rows:
        capabilities: frozenset[Capability] = frozenset()

        def execute(self, sql: str, binds=()) -> Result:
            return Result(columns=[col], rows=[(f'r{n:02}',) for n in range(1, 31)])

    class _Stream:
        def __init__(self) -> None:
            self.inbox = [
                (TNS_DATA, _OCI_EXEC_30_ROWS),
                *((TNS_DATA, f) for f in _OCI_FETCH_15_ROWS),
                None,
            ]
            self.sent: list[bytes] = []

        def read_packet(self, **_kw):
            return self.inbox.pop(0)

        def write_packet(self, _ptype: int, body: bytes, **_kw) -> None:
            self.sent.append(body)

    stream: Any = _Stream()
    backend: Any = _Rows()
    _serve_oci_session(stream, backend, 'PYO')
    served = [
        [n for n in range(1, 31) if f'r{n:02}'.encode() in reply]
        for reply in stream.sent
    ]
    assert served == [[1], list(range(2, 17)), list(range(17, 31))]
    # Only the last batch ends the fetch; the first leaves rows to come.
    assert [b'ORA-01403' in reply for reply in stream.sent[1:]] == [False, True]


# sqlplus 23.26's `select c from t1428` (c a CLOB, the table empty), then the
# re-execute it sends once its LOB define is set up, captured against a live 11g.
_OCI_EXEC_EMPTY_LOB = bytes.fromhex(
    '035e0b6180000000000000feffffffffffffff39000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000001373656c65637420632066726f6d207431'
    '3432380100000000000000000000000000000000000000000000000000000001'
    '0000000000000000800000000000000000000000000000'
)
_OCI_REEXEC_EMPTY_LOB = bytes.fromhex(
    '035e0c5000000001000000000000000000000000000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000000000005000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0100000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '000000000000000000000000000000000000000f000000000000000000000000'
    '0000000000000000000000010000000000000000000000000000000000000000'
    '0000000170010000500000000000000000000002000000000000000000000000'
    '690301000000000000000000'
)


def test_oci_an_empty_lob_result_ends_its_fetch() -> None:
    # A LOB select that returns no rows gets the LOB describe and then, on the
    # re-execute, the end of fetch -- ORA-01403 -- as from a live 11g. The Mirror
    # gave it the ordinary no-row reply and the re-execute a plain success, and
    # sqlplus printed a row holding an uninitialized LOB (SP2-1504) (#1428).
    from seerdb.common.tns import (
        _OCI_LOB_DESCRIBE_TAIL,
        encode_describe_oci,
        is_reexecute_oci,
    )
    from seerdb.common.tns_consts import TNS_DATA, TNS_TYPE_CLOB
    from seerdb.server.session import _serve_oci_session

    assert is_reexecute_oci(_OCI_REEXEC_EMPTY_LOB)
    col = ColumnMeta(name=b'C', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0)

    class _Empty:
        capabilities: frozenset[Capability] = frozenset()

        def execute(self, sql: str, binds=()) -> Result:
            return Result(columns=[col], rows=[])

    class _Stream:
        def __init__(self) -> None:
            self.inbox = [
                (TNS_DATA, _OCI_EXEC_EMPTY_LOB),
                (TNS_DATA, _OCI_REEXEC_EMPTY_LOB),
                None,
            ]
            self.sent: list[bytes] = []

        def read_packet(self, **_kw):
            return self.inbox.pop(0)

        def write_packet(self, _ptype: int, body: bytes, **_kw) -> None:
            self.sent.append(body)

    stream: Any = _Stream()
    backend: Any = _Empty()
    _serve_oci_session(stream, backend, 'PYO')
    assert len(stream.sent) == 2
    describe, end = stream.sent
    # The LOB describe: the column's describe, then the LOB-specific tail (the
    # live sequence number in the status after it is the session's).
    lob_describe = bytes(encode_describe_oci([col])) + _OCI_LOB_DESCRIBE_TAIL
    assert describe.startswith(lob_describe)
    assert b'ORA-01403' not in describe
    assert b'ORA-01403' in end


# sqlplus 23.26's `create table t1282 (...)`, captured against a live 11g
# (piggyback-wrapped, as every statement past the first arrives).
_OCI_EXEC_CREATE_TABLE = bytes.fromhex(
    '116913feffffffffffffff010000000000000001000000035e14218000000000'
    '0000feffffffffffffffa2000000feffffffffffffff0d000000feffffffffff'
    'fffffeffffffffffffff00000000010000000000000000000000000000000000'
    '00000000000000000000feffffffffffffff0000000000000000feffffffffff'
    'fffffefffffffffffffffeffffffffffffff0000000000000000feffffffffff'
    'fffffeffffffffffffff00000000000000000000000000000000000000000000'
    '00000000000036637265617465207461626c6520743132383220286964206e75'
    '6d6265722c2073207661726368617232283230292c2064206461746529010000'
    '0001000000000000000000000000000000000000000000000005000000000000'
    '0000800000000000000000000000000000'
)


def test_oci_relays_a_failed_ddl_as_its_error() -> None:
    # A statement the backend refuses must reach sqlplus as its ORA error, as a
    # live server's does. Only a SELECT's error used to be relayed: anything
    # else got a plain success, so a CREATE of an existing table printed "PL/SQL
    # procedure successfully completed" (#1288).
    from seerdb.common.tns_consts import TNS_DATA
    from seerdb.server.backend import BackendError
    from seerdb.server.session import _serve_oci_session

    class _Exists:
        capabilities: frozenset[Capability] = frozenset()

        def execute(self, sql: str, binds=()) -> Result:
            assert sql.startswith('create table t1282')
            raise BackendError(
                'name is already used by an existing object', ora_code=955
            )

    class _Stream:
        def __init__(self) -> None:
            self.inbox = [(TNS_DATA, _OCI_EXEC_CREATE_TABLE), None]
            self.sent: list[bytes] = []

        def read_packet(self, **_kw):
            return self.inbox.pop(0)

        def write_packet(self, _ptype: int, body: bytes, **_kw) -> None:
            self.sent.append(body)

    stream: Any = _Stream()
    backend: Any = _Exists()
    _serve_oci_session(stream, backend, 'PYO')
    [reply] = stream.sent
    assert b'ORA-00955: name is already used by an existing object' in reply


# sqlplus 23.26's `insert into sp_ac values (4242)` under SET AUTOCOMMIT ON,
# captured against a live 11g. With autocommit off it sends the same bytes with
# 0x80 at offset 4: the commit bit (0x100) of the options word at offset 3 is
# the only difference, and no COMMIT call follows either way (#2011).
_OCI_EXEC_INSERT_AUTOCOMMIT = bytes.fromhex(
    '035e0b2181000000000000feffffffffffffff5d000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000001f696e7365727420696e746f2073705f61'
    '632076616c756573202834323432290100000001000000000000000000000000'
    '0000000000000000000000040000000000000000800000000000000000000000'
    '000000'
)
_OCI_EXEC_INSERT = (
    _OCI_EXEC_INSERT_AUTOCOMMIT[:4] + b'\x80' + _OCI_EXEC_INSERT_AUTOCOMMIT[5:]
)


class _OciOneCallStream:
    def __init__(self, body: bytes) -> None:
        from seerdb.common.tns_consts import TNS_DATA

        self.inbox = [(TNS_DATA, body), None]
        self.sent: list[bytes] = []

    def read_packet(self, **_kw):
        return self.inbox.pop(0)

    def write_packet(self, _ptype: int, body: bytes, **_kw) -> None:
        self.sent.append(body)


class _OciCountingBackend:
    capabilities: frozenset[Capability] = frozenset()

    def __init__(self, commit_error: Exception | None = None) -> None:
        self.calls: list[str] = []
        self.commit_error = commit_error

    def execute(self, sql: str, binds=()) -> Result:
        self.calls.append(sql)
        return Result(rowcount=1)

    def commit(self) -> None:
        self.calls.append('COMMIT')
        if self.commit_error is not None:
            raise self.commit_error

    def rollback(self) -> None:
        self.calls.append('ROLLBACK')


def test_oci_parses_the_autocommit_bit() -> None:
    from seerdb.common.tns import parse_exec_oci

    assert parse_exec_oci(_OCI_EXEC_INSERT_AUTOCOMMIT).autocommit
    assert not parse_exec_oci(_OCI_EXEC_INSERT).autocommit
    assert parse_exec_oci(_OCI_EXEC_INSERT).sql == 'insert into sp_ac values (4242)'


@pytest.mark.parametrize(
    ('body', 'committed'),
    [(_OCI_EXEC_INSERT_AUTOCOMMIT, True), (_OCI_EXEC_INSERT, False)],
    ids=['autocommit', 'no-autocommit'],
)
def test_oci_autocommit_commits_the_statement(body: bytes, committed: bool) -> None:
    # sqlplus's SET AUTOCOMMIT ON asks the server to commit each statement and
    # prints "Commit complete." without sending a COMMIT. Ignoring the bit left
    # the row uncommitted, so a later ROLLBACK lost it (#2011). The session's
    # end is a dropped connection here, which commits nothing.
    from seerdb.server.session import _serve_oci_session

    stream: Any = _OciOneCallStream(body)
    backend: Any = _OciCountingBackend()
    _serve_oci_session(stream, backend, 'PYO')
    expected = ['insert into sp_ac values (4242)'] + (['COMMIT'] if committed else [])
    assert backend.calls == expected
    [reply] = stream.sent
    assert b'ORA-' not in reply


def test_oci_autocommit_relays_a_failed_commit() -> None:
    # A commit that fails (a deferred constraint) is the statement's error, as on
    # a live server, not a success sqlplus reports as committed.
    from seerdb.server.backend import BackendError
    from seerdb.server.session import _serve_oci_session

    stream: Any = _OciOneCallStream(_OCI_EXEC_INSERT_AUTOCOMMIT)
    backend: Any = _OciCountingBackend(
        BackendError('transaction rolled back', ora_code=2091)
    )
    _serve_oci_session(stream, backend, 'PYO')
    [reply] = stream.sent
    assert b'ORA-02091' in reply


# sqlplus 23.26's `create or replace procedure sp_c2013 as begin nosuch; end;`
# and a live 11g's reply, which sqlplus prints as "Warning: Procedure created
# with compilation errors." (#2013).
_OCI_EXEC_CREATE_BROKEN = bytes.fromhex(
    '035e0b2180000000000000feffffffffffffffae000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000010000000000000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000003a637265617465206f72207265706c6163'
    '652070726f6365647572652073705f633230313320617320626567696e206e6f'
    '737563683b20656e643b01000000010000000000000000000000000000000000'
    '000000000000050000000000000000800000000000000000000000000000'
)
_OCI_CREATE_BROKEN_REPLY = bytes.fromhex(
    '0806002aaa230100000000010000000000000000000000000000000000000000'
    '0000000401000000080001000000000000000000000100000018000000002100'
    '00000000000000000000000000000000000000000b0000010000003601000000'
    '000000000000000000000020f6310a0000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000'
)
_OCI_STATUS_PREFIX_LEN = 35
_OCI_OER_SEQUENCE = slice(5, 7)


class _OciCompileBackend(_OciCountingBackend):
    def __init__(self, compilation_warning: bool) -> None:
        super().__init__()
        self.compilation_warning = compilation_warning

    def execute(self, sql: str, binds=()) -> Result:
        self.calls.append(sql)
        return Result(compilation_warning=self.compilation_warning)


def _oci_reply_oer(reply: bytes) -> bytearray:
    oer = bytearray(reply[_OCI_STATUS_PREFIX_LEN:])
    oer[_OCI_OER_SEQUENCE] = bytes(2)
    return oer


def test_oci_create_with_compilation_errors_warns() -> None:
    # The create succeeds; only the OER's warning byte says the object does not
    # compile. Without it sqlplus printed "Procedure created." (#2013). The OER
    # is the live server's but for its sequence counter.
    from seerdb.server.session import _serve_oci_session

    stream: Any = _OciOneCallStream(_OCI_EXEC_CREATE_BROKEN)
    backend: Any = _OciCompileBackend(True)
    _serve_oci_session(stream, backend, 'PYO')
    [reply] = stream.sent
    assert _oci_reply_oer(reply) == _oci_reply_oer(_OCI_CREATE_BROKEN_REPLY)


def test_oci_clean_create_does_not_warn() -> None:
    from seerdb.server.session import _serve_oci_session

    stream: Any = _OciOneCallStream(_OCI_EXEC_CREATE_BROKEN)
    backend: Any = _OciCompileBackend(False)
    _serve_oci_session(stream, backend, 'PYO')
    [reply] = stream.sent
    oer = _oci_reply_oer(reply)
    assert oer[27] == 0
    oer[27] = _OCI_CREATE_BROKEN_REPLY[_OCI_STATUS_PREFIX_LEN + 27]
    assert oer == _oci_reply_oer(_OCI_CREATE_BROKEN_REPLY)


# sqlplus 23.26's REFCURSOR flow against a live 18c (#2014): `variable rc
# refcursor`, then `begin open :rc for select 1 as id, 'a' as name from dual
# union all select 2, 'bb' from dual; end;` and `print rc`. The block binds :rc
# as type 102 with a zero cursor id; the server's OUT value names cursor 3, and
# sqlplus re-executes cursor 3 with no SQL and room for 15 rows.
_OCI_EXEC_OPEN_REFCURSOR = bytes.fromhex(
    '035e0b2904040000000000feffffffffffffff23010000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000100000000000000fe'
    'ffffffffffffff010000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000061626567696e206f70656e203a72632066'
    '6f722073656c65637420312061732069642c20276127206173206e616d652066'
    '726f6d206475616c20756e696f6e20616c6c2073656c65637420322c20276262'
    '272066726f6d206475616c3b20656e643b010000000100000000000000000000'
    '0000000000000000000000000008000000000000000080000000000000000000'
    '0000000000016601000001000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000070400000000'
)
_OCI_OPEN_REFCURSOR_REPLY = bytes.fromhex(
    '0b0105c3010000000000010000000000000000000000000000000000a52d6e7f'
    '0000a0c3a52d6e7f0000000057930000000030074c04000000020000005c0102'
    '0000810200000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000102020000000249440000000000000000'
    '0000000000000101800000020000000000000000000000000000000000000000'
    '00000000000000000000006903010002000000fe3f0000010404000000044e41'
    '4d4500000000000000000100000000000700000007000000000a200800000000'
    '00000000000000000000000000000000030000000000080600dba2ab00000000'
    '000100000000000000000000000000000000000000000000000401000000717b'
    '0101000000000000000000010000002f00000000000000000000000000000000'
    '000000000000000000000b000001000000360100000000000000000000000000'
    '00407e60346e7f00000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000100000000000000'
)
_OCI_REEXEC_REFCURSOR = bytes.fromhex(
    '035e0d4000000003000000000000000000000000000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff00000000000000000300000000'
    '00000000000000000000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000f000000000000000000000000'
    '0000000000000000000000010000000000000000000000000000000000000000'
    '000000'
)
# The same re-execute from sqlplus 10.2 (cursor 1) and 11.2 (cursor 2), both
# against a live 11g: the narrow 10.2 preamble and the wide one.
_OCI_REEXEC_REFCURSOR_10_2 = bytes.fromhex(
    '035e17400000000100000000000000000000000000000034431033000000000d'
    '0000000000000000000000684310330000000000000000000000000300000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000006a43103300000000c85d1233000000000000000000'
    '00000000000000000000008043103300000000000000000f0000000000000000'
    '0000000000000000000000000000000100000000000000000000000000000000'
    '00000000000000'
)
_OCI_REEXEC_REFCURSOR_11_2 = bytes.fromhex(
    '035e17400000000200000000000000000000000000000000000000feffffffff'
    'ffffff0d00000000000000fefffffffffffffffeffffffffffffff0000000000'
    '0000000300000000000000000000000000000000000000000000000000000000'
    '000000feffffffffffffff0000000000000000fefffffffffffffffeffffffff'
    'ffffffd86a923a000000000000000000000000fefffffffffffffffeffffffff'
    'ffffff0000000000000000000000000000000000000000000000000000000000'
    '000000000000000f000000000000000000000000000000000000000000000001'
    '0000000000000000000000000000000000000000000000'
)
_REFCURSOR_COLUMNS = [
    ColumnMeta(name=b'ID', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22),
    ColumnMeta(name=b'NAME', data_type=TNS_TYPE_CHAR, data_length=2, max_size=2),
]


def _at_field_version(fv: int, fn, *args):
    from seerdb.common.tns import _DECODE_FIELD_VERSION, _ENCODE_FIELD_VERSION

    decode = _DECODE_FIELD_VERSION.set(fv)
    encode = _ENCODE_FIELD_VERSION.set(fv)
    try:
        return fn(*args)
    finally:
        _ENCODE_FIELD_VERSION.reset(encode)
        _DECODE_FIELD_VERSION.reset(decode)


def test_a_refcursor_bind_is_read() -> None:
    # The bind used to be refused, ORA-03115 (#2014). Its zero cursor id makes
    # it an OUT bind for the block to open.
    from seerdb.common.tns import parse_exec_oci
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1, TNS_TYPE_REFCURSOR

    request = _at_field_version(
        FIELD_VERSION_18_1_EXT_1, parse_exec_oci, _OCI_EXEC_OPEN_REFCURSOR
    )
    assert request.sql.startswith('begin open :rc for select 1 as id')
    assert request.binds == [None]
    assert request.bind_meta == [(TNS_TYPE_REFCURSOR, 1)]


@pytest.mark.parametrize(
    ('body', 'field_version', 'cursor'),
    [
        (_OCI_REEXEC_REFCURSOR, 'FIELD_VERSION_18_1_EXT_1', 3),
        (_OCI_REEXEC_REFCURSOR_11_2, 'FIELD_VERSION_11_2', 2),
        (_OCI_REEXEC_REFCURSOR_10_2, 'FIELD_VERSION_10_2', 1),
    ],
    ids=['23.26', '11.2', '10.2'],
)
def test_a_reexecute_names_its_cursor_and_fetch_count(
    body: bytes, field_version: str, cursor: int
) -> None:
    from seerdb.common import tns_consts
    from seerdb.common.tns import parse_reexecute_oci

    fv = getattr(tns_consts, field_version)
    assert _at_field_version(fv, parse_reexecute_oci, body) == (cursor, 15)


def test_the_refcursor_out_value_matches_the_live_reply() -> None:
    # The value's frame -- lead byte, describe-time tail, cursor id, return code
    # -- is the live server's, with the date the Mirror zeroes. The describe in
    # between is the Mirror's own, the one its queries carry.
    from seerdb.common.tns import (
        RefCursorOutBind,
        _oci_describe_body,
        encode_out_bind_response_oci,
    )
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1

    live = _OCI_OPEN_REFCURSOR_REPLY[52:]
    live = live[: live.find(bytes.fromhex('080600'))]
    live_tail = bytearray(live[live.find(bytes.fromhex('0700000007')) - 1 :])
    live_tail[6:13] = bytes(7)  # the describe-time date

    bind = RefCursorOutBind(columns=_REFCURSOR_COLUMNS, cursor_id=3)
    reply = _at_field_version(
        FIELD_VERSION_18_1_EXT_1,
        lambda: encode_out_bind_response_oci([bind], sequence=1, inputs=[True]),
    )
    body = _at_field_version(
        FIELD_VERSION_18_1_EXT_1, _oci_describe_body, _REFCURSOR_COLUMNS
    )
    value = reply[52:]
    assert reply[50:52] == _OCI_OPEN_REFCURSOR_REPLY[50:52]  # IN OUT, then RXD
    assert value[0] == live[0] == 0x4C
    assert value[1 : 1 + len(body)] == body
    assert value[1 + len(body) : 1 + len(body) + len(live_tail)] == live_tail


class _OciRefCursorBackend(_OciCountingBackend):
    def __init__(self, rows: int) -> None:
        super().__init__()
        self.rows = [(n, 'r') for n in range(1, rows + 1)]

    def execute(self, sql: str, binds=()) -> Result:
        self.calls.append(sql)
        return Result(
            out_binds=[CursorResult(columns=_REFCURSOR_COLUMNS, rows=self.rows)]
        )


def _oci_fetch(cursor: int, rows: int) -> bytes:
    return b'\x03\x05\x10' + cursor.to_bytes(4, 'little') + rows.to_bytes(4, 'little')


def test_print_refcursor_fetches_its_rows() -> None:
    # The block's reply names a cursor; sqlplus re-executes it for as many rows
    # as it has room for, then fetches the rest. 40 rows go out as 15, 15, 10,
    # the last answer ending the fetch.
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1, TNS_DATA
    from seerdb.server.session import _OCI_REF_CURSOR_FIRST_ID, _serve_oci_session

    cursor = _OCI_REF_CURSOR_FIRST_ID
    reexec = bytearray(_OCI_REEXEC_REFCURSOR)
    reexec[7:11] = cursor.to_bytes(4, 'little')
    stream: Any = _OciOneCallStream(_OCI_EXEC_OPEN_REFCURSOR)
    stream.inbox[1:1] = [
        (TNS_DATA, bytes(reexec)),
        (TNS_DATA, _oci_fetch(cursor, 15)),
        (TNS_DATA, _oci_fetch(cursor, 15)),
    ]
    backend: Any = _OciRefCursorBackend(40)
    _serve_oci_session(stream, backend, 'PYO', field_version=FIELD_VERSION_18_1_EXT_1)
    opened, first, second, last = stream.sent
    assert cursor.to_bytes(4, 'little') + b'\x00\x00\x08\x06' in opened
    assert [reply.count(b'\x07\x02\xc1') for reply in (first, second, last)] == [
        15,
        15,
        10,
    ]
    assert b'ORA-01403' not in first + second
    assert b'ORA-01403' in last


def test_a_drained_refcursor_is_forgotten() -> None:
    # A re-execute of a cursor already drained is not served from it again.
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1, TNS_DATA
    from seerdb.server.session import _OCI_REF_CURSOR_FIRST_ID, _serve_oci_session

    reexec = bytearray(_OCI_REEXEC_REFCURSOR)
    reexec[7:11] = _OCI_REF_CURSOR_FIRST_ID.to_bytes(4, 'little')
    stream: Any = _OciOneCallStream(_OCI_EXEC_OPEN_REFCURSOR)
    stream.inbox[1:1] = [(TNS_DATA, bytes(reexec)), (TNS_DATA, bytes(reexec))]
    backend: Any = _OciRefCursorBackend(2)
    _serve_oci_session(stream, backend, 'PYO', field_version=FIELD_VERSION_18_1_EXT_1)
    _opened, served, again = stream.sent
    assert served.count(b'\x07\x02\xc1') == 2
    assert b'\x07\x02\xc1' not in again


# sqlplus 23.26 reading a REF CURSOR's CLOB from a live 18c (#2033): a TTI_LOBOPS
# read from offset 1 for 80 characters, the locator the row carried.
_OCI_REFCURSOR_LOB_READ = bytes.fromhex(
    '03600efeffffffffffffff280000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000200000000'
    '000000000000000000000001000000000000000400000000000000feffffffff'
    'ffffff0000000000000000000000000000000000000000000000000000000000'
    '0000000000000000260000c20880000002459f00000113000000010369000a00'
    '0000000002f0bc50a70000000000005000000000000000'
)


def test_a_refcursor_with_a_lob_column_streams_its_rows() -> None:
    # Its rows were refused, ORA-03115: sent the plain way they hung sqlplus
    # (#2014). They stream as a query's do: the re-execute answers the first
    # row, its CLOB's content follows the read, the fetch answers the next row,
    # and the last fetch ends it (#2033).
    from seerdb.common.tns_consts import (
        FIELD_VERSION_18_1_EXT_1,
        TNS_DATA,
        TNS_TYPE_CLOB,
    )
    from seerdb.server.session import _OCI_REF_CURSOR_FIRST_ID, _serve_oci_session

    clob = ColumnMeta(name=b'C', data_type=TNS_TYPE_CLOB, data_length=4000, max_size=0)

    class _LobCursor(_OciCountingBackend):
        def execute(self, sql: str, binds=()) -> Result:
            return Result(
                out_binds=[CursorResult(columns=[clob], rows=[('hello',), ('again',)])]
            )

    cursor = _OCI_REF_CURSOR_FIRST_ID
    reexec = bytearray(_OCI_REEXEC_REFCURSOR)
    reexec[7:11] = cursor.to_bytes(4, 'little')
    stream: Any = _OciOneCallStream(_OCI_EXEC_OPEN_REFCURSOR)
    stream.inbox[1:1] = [
        (TNS_DATA, bytes(reexec)),
        (TNS_DATA, _OCI_REFCURSOR_LOB_READ),
        (TNS_DATA, _oci_fetch(cursor, 15)),
        (TNS_DATA, _OCI_REFCURSOR_LOB_READ),
        (TNS_DATA, _oci_fetch(cursor, 15)),
    ]
    backend: Any = _LobCursor()
    _serve_oci_session(stream, backend, 'PYO', field_version=FIELD_VERSION_18_1_EXT_1)
    opened, first, hello, second, again, last = stream.sent
    assert b'ORA-03115' not in opened
    assert cursor.to_bytes(4, 'little') + b'\x00\x00\x08\x06' in opened
    assert 'hello'.encode('utf-16-be') in hello
    assert 'again'.encode('utf-16-be') in again
    assert b'ORA-01403' not in first + second
    assert b'ORA-01403' in last


def test_a_refcursor_with_a_long_column_streams_a_row_per_call() -> None:
    # A LONG streams a row per call too: the re-execute answers the first, each
    # fetch the next, and the fetch after the last ends it (#2033).
    from seerdb.common.tns_consts import (
        FIELD_VERSION_18_1_EXT_1,
        TNS_DATA,
        TNS_TYPE_LONG,
    )
    from seerdb.server.session import _OCI_REF_CURSOR_FIRST_ID, _serve_oci_session

    long_col = ColumnMeta(name=b'T', data_type=TNS_TYPE_LONG, data_length=0, max_size=0)

    class _LongCursor(_OciCountingBackend):
        def execute(self, sql: str, binds=()) -> Result:
            return Result(
                out_binds=[
                    CursorResult(
                        columns=[long_col], rows=[('text one',), ('text two',)]
                    )
                ]
            )

    cursor = _OCI_REF_CURSOR_FIRST_ID
    reexec = bytearray(_OCI_REEXEC_REFCURSOR)
    reexec[7:11] = cursor.to_bytes(4, 'little')
    stream: Any = _OciOneCallStream(_OCI_EXEC_OPEN_REFCURSOR)
    stream.inbox[1:1] = [
        (TNS_DATA, bytes(reexec)),
        (TNS_DATA, _oci_fetch(cursor, 15)),
        (TNS_DATA, _oci_fetch(cursor, 15)),
    ]
    backend: Any = _LongCursor()
    _serve_oci_session(stream, backend, 'PYO', field_version=FIELD_VERSION_18_1_EXT_1)
    opened, first, second, last = stream.sent
    assert b'ORA-03115' not in opened
    assert b'text one' in first and b'text two' not in first
    assert b'text two' in second
    assert b'ORA-01403' not in first + second
    assert b'ORA-01403' in last


# sqlplus 23.26's CLOB variable against a live 18c (#2015): `variable vc clob`,
# `exec :vc := 'clob var'`, then `print vc`, which binds the locator the block
# handed back in `SELECT :vc vc FROM SYS.DUAL`. While the variable holds nothing
# its bind is sqlplus's own 4000-byte buffer, and once it holds NULL just a zero
# length. The exec and the unset print each carry that 4000-byte buffer, so
# they are kept compressed.
_OCI_EXEC_ASSIGN_CLOB = zlib.decompress(
    base64.b64decode(
        'eNpjjuPVZGFhAIF//yEgConNi8SG0SC1jAwMKHpgfGQxdD42cxhwmE8rIOfk6u7pp2BVlqxgZaugnpyTn6RQllikbq3g6udizcWI5DV0wAFjNKCKMxYAdQSgijGha85kRhjLvoAf6GkQwT8PyJVgGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwQADANjiZcQ='
    )
)
_OCI_SELECT_UNSET_CLOB = zlib.decompress(
    base64.b64decode(
        'eNpjjuPNbGAAg3//ISAEic2LxIbRILWMDKh6YHxkMXQ+NnMYcJhPKyAT7Orj6hyiYFWWrABEbkH+vgrBkcF6LqGOPgyMeDTC5RrQxAuAMgGoYkzomjOZEUazL+AHehlE8M8DciUYRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMMAAALiXZgI='
    )
)
# The same exec through a Mirror, at the field version that 18c speaks: the
# buffer's chunk lengths are a ub1 here, not a ub4.
_OCI_EXEC_ASSIGN_CLOB_VIA_MIRROR = zlib.decompress(
    base64.b64decode(
        'eNpjjmPTZGFhAIF//yEgConNi8SG0SC1jAwMKHpgfGQxdD42cxhwmE8rIOfk6u7pp2BVlqxgZaugnpyTn6RQllikbq3g6udizcWI5DV0wAFjNKCKMxYAdQSgijGha85kRhjLvoAf5Gn+eQwjGfxnYBj1/6j/R/0/6v9R/4/6f9T/o/4f9f+o/0f9P+r/Uf+PALB+qDkYACHLdJY='
    )
)
_OCI_SELECT_NULL_CLOB = bytes.fromhex(
    '035e126980000000000000feffffffffffffff54000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000100000000000000fe'
    'ffffffffffffff010000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000001c53454c454354203a7663207663204652'
    '4f4d205359532e4455414c000100000000000000000000000000000000000000'
    '0000000000000000010000000000000000800000000000000000000000000000'
    '0170010000500000000000000000000000000000020000000000000000000000'
    '00000000006903010000000000000000000700000000'
)
# The live reply to `exec :vc := null`: the OUT-bind header, the IN OUT marker
# and RXD, then the NULL -- a zero length and the return code -1.
_OCI_ASSIGN_NULL_CLOB_REPLY = bytes.fromhex(
    '0b01056101000000000001000000000000000000000000000000000011aebb7f'
    '0000186111aebb7f00000000799400000000100700000000ffff080600d90eac'
    '0000000000010000000000000000000000000000000000000000000000040100'
    '0000a9950101000000000000000000010000002f000000000000000000000000'
    '0000000000000000000000000000100000010000003601000000000000000000'
    '0000000000401ec8b4bb7f000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '00000000000100000000000000'
)
# `print vc` through a Mirror, binding the locator the Mirror handed back.
_OCI_SELECT_MIRROR_CLOB = bytes.fromhex(
    '035e086980000000000000feffffffffffffff54000000feffffffffffffff0d'
    '000000fefffffffffffffffeffffffffffffff000000000100000000000000fe'
    'ffffffffffffff010000000000000000000000feffffffffffffff0000000000'
    '000000fefffffffffffffffefffffffffffffffeffffffffffffff0000000000'
    '000000fefffffffffffffffeffffffffffffff00000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000001c53454c454354203a7663207663204652'
    '4f4d205359532e4455414c000100000000000000000000000000000000000000'
    '0000000000000000010000000000000000800000000000000000000000000000'
    '0170010000500000000000000000000000000000020000000000000000000000'
    '0000000000690301000000000000000000076a0000006a00680001020c800000'
    '0200000001000000560000000100000001000000020002036900020000000000'
    '0000000000000002000000000000000000000000000000000000000000000000'
    '0000000001000000000000000000140500000000000010000000000002000000'
    '00'
)


class _OciClobBackend(_OciCountingBackend):
    def __init__(self, value: object) -> None:
        super().__init__()
        self.value = value
        self.binds: list = []

    def execute(self, sql: str, binds=()) -> Result:
        self.calls.append(sql)
        self.binds.append(list(binds))
        if sql.lstrip().upper().startswith('BEGIN'):
            return Result(out_binds=[self.value])
        return Result(rowcount=0)


def test_a_clob_variable_bind_is_read() -> None:
    # The bind used to be refused, ORA-03115 (#2015). Its value is a locator:
    # sqlplus's unset buffer here, or a zero length for a NULL.
    from seerdb.common.tns import TempLobRef, parse_exec_oci
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1, TNS_TYPE_CLOB

    request = _at_field_version(
        FIELD_VERSION_18_1_EXT_1, parse_exec_oci, _OCI_EXEC_ASSIGN_CLOB
    )
    assert request.sql.startswith("BEGIN :vc := 'clob var';")
    assert request.bind_meta == [(TNS_TYPE_CLOB, 80)]
    [unset] = request.binds
    assert isinstance(unset, TempLobRef) and len(unset.locator) == 4000
    # Through a Mirror the buffer's chunk lengths are a ub1, and it is the same
    # 4000 bytes.
    via_mirror = _at_field_version(
        FIELD_VERSION_18_1_EXT_1, parse_exec_oci, _OCI_EXEC_ASSIGN_CLOB_VIA_MIRROR
    )
    [unset] = via_mirror.binds
    assert isinstance(unset, TempLobRef) and len(unset.locator) == 4000
    null = _at_field_version(
        FIELD_VERSION_18_1_EXT_1, parse_exec_oci, _OCI_SELECT_NULL_CLOB
    )
    assert null.binds == [None]


def test_a_null_clob_out_value_matches_the_live_reply() -> None:
    from seerdb.common.tns import LobOutBind, encode_out_bind_response_oci
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1

    reply = _at_field_version(
        FIELD_VERSION_18_1_EXT_1,
        lambda: encode_out_bind_response_oci(
            [LobOutBind(value=None, is_clob=True, lob_id=0)],
            sequence=1,
            inputs=[False],
        ),
    )
    assert reply[50:58] == _OCI_ASSIGN_NULL_CLOB_REPLY[50:58]  # 10 07 00000000 ffff


def _oci_sent_locator(reply: bytes) -> bytes:
    # The locator the OUT value carries, as sqlplus binds it back: the ub2 and
    # the locator after the 12c LOB metadata, with the flag bit it clears.
    value = reply[52:]
    locator = bytearray(value[4 + 12 + 1 : 4 + 12 + 1 + 106])
    locator[1 + 5] &= ~0x08
    return bytes(locator)


def test_print_binds_the_value_the_block_assigned() -> None:
    # The OUT value is a locator naming the value; `print vc` binds it, and the
    # backend is handed the value as a CLOB (#2015).
    from seerdb.common.tns import _ENCODE_OCI_LOB_12C
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1, TNS_DATA
    from seerdb.server.backend import ClobValue
    from seerdb.server.session import _serve_oci_session

    first: Any = _OciOneCallStream(_OCI_EXEC_ASSIGN_CLOB)
    backend: Any = _OciClobBackend('clob var')
    token = _ENCODE_OCI_LOB_12C.set(True)
    try:
        _serve_oci_session(
            first, backend, 'PYO', field_version=FIELD_VERSION_18_1_EXT_1
        )
    finally:
        _ENCODE_OCI_LOB_12C.reset(token)
    [reply] = first.sent
    locator = _oci_sent_locator(reply)
    # Replay the print the Mirror's own locator went into.
    select = bytearray(_OCI_SELECT_MIRROR_CLOB)
    at = select.rfind(b'\x6a\x00\x68')
    select[at + 1 : at + 1 + 106] = locator
    stream: Any = _OciOneCallStream(_OCI_EXEC_ASSIGN_CLOB)
    stream.inbox[1:1] = [(TNS_DATA, bytes(select))]
    backend = _OciClobBackend('clob var')
    token = _ENCODE_OCI_LOB_12C.set(True)
    try:
        _serve_oci_session(
            stream, backend, 'PYO', field_version=FIELD_VERSION_18_1_EXT_1
        )
    finally:
        _ENCODE_OCI_LOB_12C.reset(token)
    assert backend.calls[1] == 'SELECT :vc vc FROM SYS.DUAL'
    [bound] = backend.binds[1]
    assert isinstance(bound, ClobValue) and bound == 'clob var'


def test_printing_an_unset_clob_variable_is_refused() -> None:
    # sqlplus's own buffer names no value; outside a block a live server
    # refuses it with ORA-22275.
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1
    from seerdb.server.session import _serve_oci_session

    stream: Any = _OciOneCallStream(_OCI_SELECT_UNSET_CLOB)
    backend: Any = _OciClobBackend(None)
    _serve_oci_session(stream, backend, 'PYO', field_version=FIELD_VERSION_18_1_EXT_1)
    [reply] = stream.sent
    assert b'ORA-22275' in reply
    assert backend.calls == []


# The SYNC piggyback a live 18c sends sqlplus 23.26 after `alter session set
# nls_date_format = 'YYYY-MM-DD'` (#2020): the session's NLS parameters, in
# this order, each a fixed-width pair. sqlplus formats DATE, TIMESTAMP and
# NUMBER columns by them; without it the ALTER changed nothing it printed.
_OCI_LIVE_NLS_PIGGYBACK = bytes.fromhex(
    '17050100101200000016000000000800000008414d45524943414e1000000000'
    '000700000007414d455249434109000000000001000000012400000000000007'
    '00000007414d455249434101000000000002000000022e2c0200000000000800'
    '000008414c3332555446380a00000000000900000009475245474f5249414e0c'
    '00000000000a0000000a595959592d4d4d2d4444070000000000080000000841'
    '4d45524943414e080000000000060000000642494e4152590b00000000000e00'
    '00000e48482e4d492e535358464620414d390000000000180000001844442d4d'
    '4f4e2d52522048482e4d492e535358464620414d3a0000000000120000001248'
    '482e4d492e535358464620414d20545a523b00000000001c0000001c44442d4d'
    '4f4e2d52522048482e4d492e535358464620414d20545a523c00000000000100'
    '00000124340000000000060000000642494e4152593200000000000400000004'
    '425954453d0000000000050000000546414c53453e0000000000'
)
_LIVE_NLS_SESSION = [
    ('NLS_LANGUAGE', 'AMERICAN'),
    ('NLS_TERRITORY', 'AMERICA'),
    ('NLS_CURRENCY', '$'),
    ('NLS_ISO_CURRENCY', 'AMERICA'),
    ('NLS_NUMERIC_CHARACTERS', '.,'),
    ('NLS_CALENDAR', 'GREGORIAN'),
    ('NLS_DATE_FORMAT', 'YYYY-MM-DD'),
    ('NLS_DATE_LANGUAGE', 'AMERICAN'),
    ('NLS_SORT', 'BINARY'),
    ('NLS_TIME_FORMAT', 'HH.MI.SSXFF AM'),
    ('NLS_TIMESTAMP_FORMAT', 'DD-MON-RR HH.MI.SSXFF AM'),
    ('NLS_TIME_TZ_FORMAT', 'HH.MI.SSXFF AM TZR'),
    ('NLS_TIMESTAMP_TZ_FORMAT', 'DD-MON-RR HH.MI.SSXFF AM TZR'),
    ('NLS_DUAL_CURRENCY', '$'),
    ('NLS_COMP', 'BINARY'),
    ('NLS_LENGTH_SEMANTICS', 'BYTE'),
    ('NLS_NCHAR_CONV_EXCP', 'FALSE'),
]


class _OciNlsBackend(_OciCountingBackend):
    def execute(self, sql: str, binds=()) -> Result:
        self.calls.append(sql)
        if 'nls_session_parameters' in sql:
            # Not in the live order: the reply puts them in it.
            return Result(
                columns=[_REFCURSOR_COLUMNS[1], _REFCURSOR_COLUMNS[1]],
                rows=list(reversed(_LIVE_NLS_SESSION)),
            )
        return Result()


def _oci_alter_session(sql: str) -> bytes:
    # The captured sqlplus OALL8 of a short statement, its SQL swapped.
    body = bytearray(_OCI_EXEC_INSERT)
    old = b'insert into sp_ac values (4242)'
    at = body.index(old)
    body[at - 1] = len(sql)
    body[at : at + len(old)] = sql.encode()
    body[19:23] = len(sql).to_bytes(4, 'little')
    return bytes(body)


def test_the_nls_piggyback_matches_the_live_one() -> None:
    from seerdb.common.tns import OCI_NLS_KEYWORDS, encode_sync_piggyback_oci

    values = dict(_LIVE_NLS_SESSION, NLS_CHARACTERSET='AL32UTF8')
    pairs = [(kw, values[name]) for (name, kw) in OCI_NLS_KEYWORDS.items()]
    assert encode_sync_piggyback_oci(pairs) == _OCI_LIVE_NLS_PIGGYBACK


@pytest.mark.parametrize(
    ('sql', 'reported'),
    [
        ("alter session set nls_date_format = 'YYYY-MM-DD'", True),
        ("ALTER SESSION SET NLS_TERRITORY = 'GERMANY'", True),
        ('alter session set current_schema = pyo', False),
    ],
)
def test_an_nls_alter_session_reports_the_session_parameters(sql, reported) -> None:
    from seerdb.server.session import _serve_oci_session

    stream: Any = _OciOneCallStream(_oci_alter_session(sql))
    backend: Any = _OciNlsBackend()
    _serve_oci_session(stream, backend, 'PYO')
    [reply] = stream.sent
    assert (_OCI_LIVE_NLS_PIGGYBACK in reply) is reported
    if reported:
        # Between the status frame and its OER, as a live 18c puts it.
        assert reply.index(_OCI_LIVE_NLS_PIGGYBACK) == 35
        assert reply[35 + len(_OCI_LIVE_NLS_PIGGYBACK)] == 0x04


# The same parameters as a live 11g reports them to sqlplus 10.2 (#2020): not a
# piggyback but inside the status frame, from byte 29, a ub2 count of pairs,
# the pairs, then a ub4 of flags.
_OCI_LIVE_NLS_10_2 = bytes.fromhex(
    '1200000000000800000008414d45524943414e1000000000000700000007414d'
    '45524943410900000000000100000001240000000000000700000007414d4552'
    '49434101000000000002000000022e2c0200000000000800000008414c333255'
    '5446380a00000000000900000009475245474f5249414e0c00000000000a0000'
    '000a595959592d4d4d2d44440700000000000800000008414d45524943414e08'
    '0000000000060000000642494e4152590b00000000000e0000000e48482e4d49'
    '2e535358464620414d390000000000180000001844442d4d4f4e2d5252204848'
    '2e4d492e535358464620414d3a0000000000120000001248482e4d492e535358'
    '464620414d20545a523b00000000001c0000001c44442d4d4f4e2d5252204848'
    '2e4d492e535358464620414d20545a523c000000000001000000012434000000'
    '0000060000000642494e4152593200000000000400000004425954453d000000'
    '0000050000000546414c53453e0000000000'
)


def test_sqlplus_10_2_gets_the_nls_parameters_in_the_frame() -> None:
    from seerdb.common.tns import (
        _ENCODE_FIELD_VERSION,
        OCI_NLS_KEYWORDS,
        encode_ddl_status_oci,
    )
    from seerdb.common.tns_consts import FIELD_VERSION_10_2

    values = dict(_LIVE_NLS_SESSION, NLS_CHARACTERSET='AL32UTF8')
    pairs = [(kw, values[name]) for (name, kw) in OCI_NLS_KEYWORDS.items()]
    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_10_2)
    try:
        reply = encode_ddl_status_oci(42, sequence=1, session_pairs=pairs)
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    assert reply[29 : 29 + len(_OCI_LIVE_NLS_10_2)] == _OCI_LIVE_NLS_10_2
    assert reply[29 + len(_OCI_LIVE_NLS_10_2)] == 0x04  # the OER follows


# A DBMS_OUTPUT.GET_LINES image as a live 11g frames it to sqlplus 23.26
# (#2042), compressed: three 200-character lines, 615 bytes, in 255-byte
# chunks with ub1 lengths, ending at a zero length. A server that does not
# advertise BIG_CHUNK_CLR in its compile capabilities -- 11g, the Mirror --
# frames every value this way, whatever the field version; a live 18c, which
# does, sends ub4-length chunks of up to 2000 bytes instead, and then reads
# them back that way too.
_OCI_LIVE_IMAGE_11G = zlib.decompress(
    base64.b64decode('eNr797+D8R8DA1M6IzMDy4nyquEBSPDI/2HjE/JAJr188p8BAECuJqs=')
)


def _unchunk(framed: bytes) -> bytes:
    data, at = b'', 1
    while size := framed[at]:
        data += framed[at + 1 : at + 1 + size]
        at += 1 + size
    return data


@pytest.mark.parametrize(
    'field_version', ['FIELD_VERSION_11_2', 'FIELD_VERSION_18_1_EXT_1']
)
def test_a_long_oci_value_is_chunked_as_a_live_11g_does(field_version: str) -> None:
    # In the 12c band the thin form's chunks have ub4 lengths, which sqlplus
    # reads only from a server advertising BIG_CHUNK_CLR, and it hung; below
    # 12.1 they are already the ub1 ones.
    from seerdb.common import tns_consts
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, _oci_value_bytes

    image = _unchunk(_OCI_LIVE_IMAGE_11G)
    assert len(image) == 615
    token = _ENCODE_FIELD_VERSION.set(getattr(tns_consts, field_version))
    try:
        assert _oci_value_bytes(image) == _OCI_LIVE_IMAGE_11G
    finally:
        _ENCODE_FIELD_VERSION.reset(token)


# sqlplus 23.26 printing a 300-character VARCHAR2 variable through a Mirror
# (#2053): `SELECT :v v FROM SYS.DUAL`, the value as an IN bind in 255-byte
# chunks with ub1 lengths -- `fe ff` ... `00` -- since the Mirror does not
# advertise big chunks. Its piggyback is still on, as the session strips it.
_OCI_SELECT_LONG_VARCHAR = zlib.decompress(
    base64.b64decode(
        'eNpjjmPLbGAAg3//IcAPic2LxIbRILWMDKh6YHxkMXQ+NnMYcJhPKyAV7Orj6hyiYFWmUKbgFuTvqxAcGaznEurow8CIRxtcrgFNnJGZgeGBHn47M5kRRrP/+19YNKKBLkmqGQD8E+oc'
    )
)


def test_a_long_in_value_is_read_in_ub1_chunks() -> None:
    # Read with the thin decoder, whose chunk lengths are ub4 in the 12c band,
    # it lost its start and arrived short.
    from seerdb.common.tns import parse_exec_oci, strip_oci_piggyback
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1

    request = _at_field_version(
        FIELD_VERSION_18_1_EXT_1,
        parse_exec_oci,
        strip_oci_piggyback(_OCI_SELECT_LONG_VARCHAR),
    )
    assert request.binds == ['q' + 'r' * 299]


@pytest.mark.parametrize('size', [253, 300, 3000])
def test_a_long_out_value_and_row_cell_go_in_ub1_chunks(size: int) -> None:
    # An OUT value and a row cell past 252 bytes went in the thin form's
    # chunks, ub4 lengths in the 12c band, and sqlplus hung on them (#2053).
    from seerdb.common.tns import (
        _ENCODE_FIELD_VERSION,
        _encode_oci_value,
        _oci_scalar_out_value,
        _oci_value_bytes,
    )
    from seerdb.common.tns_consts import FIELD_VERSION_18_1_EXT_1, TNS_TYPE_VARCHAR

    text = 'x' * size
    col = ColumnMeta(
        name=b'V', data_type=TNS_TYPE_VARCHAR, data_length=4000, max_size=4000
    )
    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_18_1_EXT_1)
    try:
        framed = _oci_value_bytes(text.encode())
        assert framed[0] == 0xFE and framed[1] == min(size, 255) and framed[-1] == 0
        assert _oci_scalar_out_value(text) == framed
        assert _encode_oci_value(text, col) == framed
        # A short value keeps its one-byte length.
        assert _encode_oci_value('short', col) == b'\x05short'
    finally:
        _ENCODE_FIELD_VERSION.reset(token)


class _OciMarkerStream:
    # Feeds the OCI loop packets of any type and records what it sends back.
    def __init__(self, inbox: list) -> None:
        self.inbox = [*inbox, None]
        self.sent: list[tuple[int, bytes]] = []

    def read_packet(self, **_kw):
        return self.inbox.pop(0)

    def write_packet(self, ptype: int, body: bytes, **_kw) -> None:
        self.sent.append((ptype, body))


@pytest.mark.parametrize(
    'markers',
    [
        # Through the Mirror the interrupt comes in band ahead of the reset.
        [b'\x01\x00\x03', b'\x01\x00\x02'],
        # To a live 18c the break goes out of band and only the reset arrives.
        [b'\x01\x00\x02'],
    ],
    ids=['interrupt-then-reset', 'reset-only'],
)
def test_a_sqlplus_cancel_gets_one_reset_and_the_cancel(markers: list) -> None:
    # Every marker used to draw a reset, the client answered each, and the two
    # sides exchanged resets without end (#2036). A live 18c answers with one
    # reset and ORA-01013, and the session carries on.
    from seerdb.common.tns_consts import TNS_DATA, TNS_MARKER
    from seerdb.server.session import _serve_oci_session

    ping = (TNS_DATA, bytes.fromhex('03930c'))
    stream: Any = _OciMarkerStream([*((TNS_MARKER, m) for m in markers), ping])
    backend: Any = _OciCountingBackend()
    _serve_oci_session(stream, backend, 'PYO')
    (reset, cancel, pong) = stream.sent
    assert reset == (TNS_MARKER, b'\x01\x00\x02')
    assert cancel[0] == TNS_DATA
    assert cancel[1][12:16] == (1013).to_bytes(4, 'little')
    assert b'ORA-01013: user requested cancel of current operation' in cancel[1]
    assert b'ORA-01013: ORA-01013' not in cancel[1]
    # And the ping sqlplus sends after it: a TTI_STA, as a live 18c answers.
    assert pong[0] == TNS_DATA and pong[1][:5] == b'\x09\x01\x00\x00\x00'


# The capability block each sqlplus sends (its DTY proper, one round after its
# TTI_PRO): sqlplus 23.26 and sqlplus 11.2.0.2, captured against live 11g.
_SQLPLUS_23_CAPABILITIES = bytes.fromhex(
    '0269036903023706010101ef0f011b010101010101017fff031003030101ff01'
    'ffff010e0101ff01060cf6097f050fff0d0b00ff030000000000070202040d02'
    '010000180087000300000000800000003c3c3c800000000000002bd007'
)
_SQLPLUS_11_CAPABILITIES = bytes.fromhex(
    '02690369030227060101010f010106010101010101017fff030a030301007f01'
    '7fff010601013f010306000103020702010000180003800000003c3c3c800000'
    '000000000ed007'
)


def test_sqlplus_is_served_at_the_version_it_speaks() -> None:
    # sqlplus 11.2 speaks field version 6. A 12.1 Mirror answered it with the
    # 12c-band login anyway, which it cannot use (ORA-28041, #1291). sqlplus
    # 23.26 sends 27, above anything the Mirror advertises, and keeps its version.
    from seerdb.common.tns_consts import (
        FIELD_VERSION_11_2,
        FIELD_VERSION_12_1,
        FIELD_VERSION_23_1,
    )
    from seerdb.server.session import sqlplus_field_version

    low = FIELD_VERSION_11_2
    assert sqlplus_field_version(_SQLPLUS_11_CAPABILITIES, FIELD_VERSION_12_1, low) == (
        FIELD_VERSION_11_2
    )
    assert sqlplus_field_version(_SQLPLUS_23_CAPABILITIES, FIELD_VERSION_12_1, low) == (
        FIELD_VERSION_12_1
    )
    assert sqlplus_field_version(_SQLPLUS_23_CAPABILITIES, FIELD_VERSION_23_1, low) == (
        FIELD_VERSION_23_1
    )
    # Below what the Mirror serves at all, it is refused, as a thin client is.
    with pytest.raises(InterfaceError):
        sqlplus_field_version(_SQLPLUS_11_CAPABILITIES, FIELD_VERSION_12_1, 7)
    # An unreadable block keeps the Mirror's version.
    assert sqlplus_field_version(b'', FIELD_VERSION_12_1, low) == FIELD_VERSION_12_1


# sqlplus 10.2 reading its CLOB variable with a LOB read, captured against
# Mirror-over-PG (#2123): the narrow layout, its pointers' own values where a
# later sqlplus writes the indicator.
_OCI_LOB_READ_10_2 = bytes.fromhex(
    '036006e812a23c000000006a000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000002000000000000000000000000'
    '0000000100000000000000040000000000000080e3a13c00000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000680001020c880000'
    '020000000100000056000000010000000100000002000203690002000000000000000000'
    '000000010000000000000000000000000000000000000000000000000000000001000000'
    '000000000000140500000000000010000000000002000000005000000000000000'
)


def test_sqlplus_10_2_reads_a_clob_variable_with_a_lob_read() -> None:
    # sqlplus 10.2 prints a CLOB variable by reading its locator, where later
    # ones select it, and printed it empty: its LOB read did not parse, and the
    # read was not served from the variable (#2123). At 10.2's field version
    # it reads as the narrow form; its locator names the variable.
    from seerdb.common.tns import (
        _DECODE_FIELD_VERSION,
        parse_lobops_locator,
        parse_lobops_read,
    )
    from seerdb.common.tns_consts import FIELD_VERSION_10_2, TNS_TYPE_CLOB
    from seerdb.server.session import _OciLobVars

    assert parse_lobops_locator(_OCI_LOB_READ_10_2) is None  # at a later version
    token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_10_2)
    try:
        assert parse_lobops_read(_OCI_LOB_READ_10_2) == (1, 80)
        locator = parse_lobops_locator(_OCI_LOB_READ_10_2)
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    assert locator is not None and len(locator) == 106
    lob_vars = _OciLobVars()
    lob_vars.keep('clob var', TNS_TYPE_CLOB)
    assert lob_vars.content(locator) == ('clob var'.encode('utf-16-be'), True, False)
    assert _OciLobVars().content(locator) is None
    assert lob_vars.content(None) is None


def test_which_sqlplus_reads_the_local_timestamp_with_time_zone_form() -> None:
    # A live 11g sends sqlplus 23.26 the wall-clock cell with the 0x40 flag and
    # sqlplus 11.2 the UTC one; given the flagged cell, sqlplus 11.2 printed
    # 03:04 +02:00 as 21:04 +66:00 (#2018).
    from seerdb.server.session import sqlplus_reads_local_tstz

    assert sqlplus_reads_local_tstz(_SQLPLUS_23_CAPABILITIES)
    assert not sqlplus_reads_local_tstz(_SQLPLUS_11_CAPABILITIES)
    assert sqlplus_reads_local_tstz(b'')


def test_which_sqlplus_is_told_the_full_release() -> None:
    # 18c, 21c and 23ai tell sqlplus 23.26 the full release and banner_full,
    # and sqlplus 11.2 the base release and the banner (#2024).
    from seerdb.server.session import sqlplus_reads_full_release

    assert sqlplus_reads_full_release(_SQLPLUS_23_CAPABILITIES)
    assert not sqlplus_reads_full_release(_SQLPLUS_11_CAPABILITIES)
    assert sqlplus_reads_full_release(b'')


def test_a_backend_names_the_release_its_session_runs_on() -> None:
    # A passthrough's session runs on the upstream, whose release the Mirror
    # presents (#2024). A backend without the hook, one that cannot say and one
    # that fails keep the identity the field version gave.
    from seerdb.server.identity import IDENTITY_11_2, IDENTITY_23
    from seerdb.server.session import _backend_identity

    class Names:
        def session_release(self):
            return IDENTITY_23

    class CannotSay:
        def session_release(self):
            return None

    class Fails:
        def session_release(self):
            raise RuntimeError('no upstream')

    assert _backend_identity(Names(), IDENTITY_11_2) is IDENTITY_23
    assert _backend_identity(CannotSay(), IDENTITY_11_2) is IDENTITY_11_2
    assert _backend_identity(Fails(), IDENTITY_11_2) is IDENTITY_11_2
    assert _backend_identity(object(), IDENTITY_11_2) is IDENTITY_11_2


def test_an_older_sqlplus_gets_the_utc_timestamp_with_time_zone_cell() -> None:
    from seerdb.common.tns import (
        _ENCODE_OCI_TSTZ_LOCAL,
        _encode_oci_value,
        encode_value,
    )
    from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMPTZ

    col = ColumnMeta(
        name=b'TZ', data_type=TNS_TYPE_TIMESTAMPTZ, data_length=13, max_size=13
    )
    value = datetime.datetime(
        2024, 1, 2, 3, 4, 5, tzinfo=datetime.timezone(datetime.timedelta(hours=2))
    )
    token = _ENCODE_OCI_TSTZ_LOCAL.set(False)
    try:
        # 11g to sqlplus 11.2: 01:04 UTC, the offset with no flag.
        thin = encode_value(value, TNS_TYPE_TIMESTAMPTZ)
        assert _encode_oci_value(value, col) == thin
        assert thin[-2:] == b'\x16\x3c'
    finally:
        _ENCODE_OCI_TSTZ_LOCAL.reset(token)
    assert _encode_oci_value(value, col)[-2:] == b'\x56\x3c'


# sqlplus 10.2.0.5's DTY capability block (field version 4), captured from its
# login to the 10.2.0.5 server through tools/capture_proxy.py (#814).
_SQLPLUS_10_CAPABILITIES = bytes.fromhex(
    '02690369030224060101010d01010401010101010101ffff0308030301003f01'
    '473f010201010301000001050201000018800000003c3c3c80000000d007'
)


def test_sqlplus_10g_is_served_at_its_own_version() -> None:
    # sqlplus 10.2 speaks field version 4 and is served at it, as a thin 10g
    # client is (#814, #1764). The caller's floor still holds: a Mirror that
    # serves from 11.2 refuses it by name rather than failing mid-login.
    from seerdb.common.tns_consts import (
        FIELD_VERSION_10_2,
        FIELD_VERSION_11_2,
        FIELD_VERSION_12_1,
    )
    from seerdb.server.session import sqlplus_field_version

    assert (
        sqlplus_field_version(
            _SQLPLUS_10_CAPABILITIES, FIELD_VERSION_12_1, FIELD_VERSION_10_2
        )
        == FIELD_VERSION_10_2
    )
    with pytest.raises(InterfaceError, match='field version 4'):
        sqlplus_field_version(
            _SQLPLUS_10_CAPABILITIES, FIELD_VERSION_12_1, FIELD_VERSION_11_2
        )


# The opening of a sqlplus 23.26 login to a Mirror presenting 23ai, captured
# through tools/capture_proxy.py (#1822); the client's host and user names in
# the CONNECT are replaced by neutral ones of the same length.
_SQLPLUS_23_CONNECT = bytes.fromhex(
    '010d0000010000000140012c0c412000ffff7f080000010000c3004a000014004141035c'
    '000000000000000000000000000000000000000000000000200000200000000000000000'
    '0001284445534352495054494f4e3d28434f4e4e4543545f444154413d28534552564943'
    '455f4e414d453d584529284349443d2850524f4752414d3d73716c706c757340636c6965'
    '6e74312928484f53543d636c69656e74312928555345523d7573657231292928434f4e4e'
    '454354494f4e5f49443d586266464658786a567a72675a5964597070615844773d3d2929'
    '28414444524553533d2850524f544f434f4c3d7463702928484f53543d3132372e302e30'
    '2e312928504f52543d3135363137292929'
)
_SQLPLUS_23_ANO = bytes.fromhex(
    '00000096062000000000deadbeef008c0000000000040000040003000000000004000517'
    '1a300000080001002c573ab87e497900120001deadbeef00030000000400040001000100'
    '02000100030000000000040005171a300000020003e0e100020006fcff00020002000000'
    '0000040005171a3000000400010011100f000300020000000000040005171a3000000500'
    '010005040603'
)
_SQLPLUS_23_PRO = bytes.fromhex(
    '000000240600000000000108070605007838365f36342f4c696e757820322e342e787800'
)


def _recv_packet(sock: socket.socket, large: bool) -> bytes:
    # One TNS packet: the 2-byte length of the legacy header, or the 4-byte one
    # a >= 315 session switches to after the ACCEPT.
    head = b''
    while len(head) < 8:
        head += sock.recv(8 - len(head))
    length = int.from_bytes(head[:4] if large else head[:2], 'big')
    body = b''
    while len(head) + len(body) < length:
        body += sock.recv(length - len(head) - len(body))
    return head + body


def test_sqlplus_is_served_without_end_of_response() -> None:
    # A Mirror presenting 23ai advertises end-of-response in its ACCEPT, and a
    # thin client waits for the marker from the PRO answer on (#1059). sqlplus
    # 23.26 refused it on every login reply -- ORA-12699 on the first -- so
    # its replies go out unmarked: data flags 0, no trailing 0x1d (#1822).
    from seerdb.common.tns_consts import TNS_DATA_FLAGS_END_OF_RESPONSE
    from seerdb.server.handshake import TNS_VERSION_23_1

    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_at_tns_version,
        args=(listen, result, TNS_VERSION_23_1),
        daemon=True,
    )
    server.start()
    client = socket.create_connection(listen.getsockname(), timeout=10)
    try:
        client.sendall(_SQLPLUS_23_CONNECT)
        accept = _recv_packet(client, large=False)
        assert accept[4] == TNS_ACCEPT
        for request in (_SQLPLUS_23_ANO, _SQLPLUS_23_PRO):
            client.sendall(request)
            reply = _recv_packet(client, large=True)
            assert reply[4] == TNS_DATA
            flags = int.from_bytes(reply[8:10], 'big')
            assert not flags & TNS_DATA_FLAGS_END_OF_RESPONSE, reply.hex()
            assert reply[-1] != TTI_END_OF_RESPONSE, reply.hex()
    finally:
        client.close()
        server.join(timeout=10)
        listen.close()


def _run_mirror_at_tns_version(listen: socket.socket, result: dict, tns: int) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(
            PacketStream(conn), _DualBackend(), field_version=8, tns_version=tns
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def test_live_seerdb_over_large_sdu_framing() -> None:
    """A 12.2 Mirror frames the DATA stream with the 4-byte packet length.

    The version alone drives it: at >= 315 both ends switch after the ACCEPT, so
    a login plus a query round-trip here proves the server's read and write paths
    agree with the real client's on the wider header.
    """
    from seerdb.server.handshake import TNS_VERSION_12_2

    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_at_tns_version,
        args=(listen, result, TNS_VERSION_12_2),
        daemon=True,
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        assert conn._large_packets is True, 'client must switch to the 4-byte header'
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        assert cursor.fetchone() == ('X',)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')


def _run_mirror_identity_at(listen: socket.socket, result: dict, version: int) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(
            PacketStream(conn), _DualBackend(), field_version=version
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


@pytest.mark.parametrize(
    ('version', 'expected'), [(6, '11.2.0.2.0'), (8, '12.2.0.1.0')]
)
def test_live_client_reads_the_release_for_the_field_version(
    version: int, expected: str
) -> None:
    """A real client's connection.version reflects what the Mirror advertises.

    The release rides in the login result as AUTH_VERSION_NO, so this proves the
    identity reaches the wire rather than only the table that builds it.
    """
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_identity_at, args=(listen, result, version), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        assert conn.version == expected
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')


@pytest.mark.parametrize(('version', 'expected'), [(6, b'11g'), (8, b'12c')])
def test_oci_banner_follows_the_advertised_release(
    version: int, expected: bytes
) -> None:
    """sqlplus's "Connected to:" banner reports the release, not a fixed 11g one.

    Driven offline through the OCI loop: a version call in, the banner reply out.
    """
    from seerdb.common import oci
    from seerdb.common.tns import _OCI_80SES_FIXED
    from seerdb.server.identity import server_identity
    from seerdb.server.session import _serve_oci_session

    version_call = oci.OCI_PIGGYBACK_80SES + bytes(_OCI_80SES_FIXED - 2) + b'\x03\x3b'

    class _Stream:
        def __init__(self) -> None:
            self.inbox = [(TNS_DATA, version_call), None]
            self.sent: list[bytes] = []

        def read_packet(self, **_kw):
            return self.inbox.pop(0)

        def write_packet(self, ptype: int, body: bytes, **_kw) -> None:
            self.sent.append(body)

    stream: Any = _Stream()
    backend: Any = object()
    _serve_oci_session(stream, backend, 'PYO', None, server_identity(version))
    assert stream.sent, 'the version call must be answered with a banner'
    assert expected in stream.sent[0]


class _VersionedBackend(_DualBackend):
    # A backend that declares the protocol version it presents, the way the
    # PostgreSQL demo pins 11.2 and a passthrough presents its target's release.
    field_version = FIELD_VERSION_12_2


def _run_mirror_versioned_backend(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    try:
        # No field_version argument: the backend's declaration must drive it.
        result['user'] = serve_session(PacketStream(conn), _VersionedBackend())
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def test_backend_declared_field_version_drives_the_session() -> None:
    # The backend, not the serve() flag, chooses the advertised version: a
    # _VersionedBackend pinning 12.2 makes a live client negotiate to 12.2 and
    # read the 12.2 release, though serve_session was given no field_version.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]
    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_versioned_backend, args=(listen, result), daemon=True
    )
    server.start()
    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        assert conn.field_version == FIELD_VERSION_12_2
        assert conn.server_version == VERSION_12_2_0_1
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        assert cursor.fetchone() == ('X',)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')
    assert result.get('user') == 'PYO'


class _FastAuthBackend(_DualBackend):
    # Declares a 23ai field version, so a live client negotiates fv 24 and logs in
    # through the 23ai FAST_AUTH bundle rather than the legacy three messages.
    field_version = FIELD_VERSION_23_4


def _run_mirror_fast_auth(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(PacketStream(conn), _FastAuthBackend())
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def test_live_seerdb_fast_auth_login_at_23ai() -> None:
    # 23ai server-side fast-auth (§20): a real client at field version 24 cannot
    # use the legacy OSESSKEY handshake, so it sends one FAST_AUTH packet bundling
    # PRO + DTY + OSESSKEY. The Mirror unbundles it, replies with the three
    # responses concatenated, and finishes O5LOGON — the client logs in and reads
    # the 23ai release. (The fv 24 query path is a separate increment.)
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]
    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_fast_auth, args=(listen, result), daemon=True
    )
    server.start()
    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        assert conn.field_version == FIELD_VERSION_23_4
        assert conn.server_version == VERSION_23_26_2_0
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')
    assert result.get('user') == 'PYO'


class _Fv16Backend(_DualBackend):
    field_version = FIELD_VERSION_21_1  # 21c


def test_passthrough_detect_version_reads_the_negotiated_version() -> None:
    # The passthrough auto-detects its target's release by probing it once
    # (OraclePassthroughBackend.detect_version). Point it at a Mirror advertising
    # 21c (fv 16) and it reads that back — the value it then presents to its own
    # clients so a Mirror in front of a real 21c server is 21c.

    from seerdb.server.backends.passthrough import OraclePassthroughBackend

    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    def run() -> None:
        conn, _ = listen.accept()
        try:
            serve_session(PacketStream(conn), _Fv16Backend())
        except Exception:  # noqa: BLE001 - the probe just logs in and disconnects
            pass
        finally:
            conn.close()

    server = threading.Thread(target=run, daemon=True)
    server.start()
    try:
        version = OraclePassthroughBackend.detect_version(
            '127.0.0.1', port, 'XE', 'PYO', 'pyo123', timeout=5000
        )
        assert version == FIELD_VERSION_21_1
    finally:
        server.join(timeout=5)
        listen.close()

    # An unreachable target probes to None (the caller falls back to the default).
    assert (
        OraclePassthroughBackend.detect_version(
            '127.0.0.1', 1, 'XE', 'PYO', 'pyo123', timeout=1000
        )
        is None
    )


def test_unimplemented_ttc_function_is_refused_not_ignored() -> None:
    # The cardinal rule again, one layer down: a call the Mirror does not
    # implement must be ANSWERED. The dispatch chain used to have no else, so an
    # unknown TTC function fell through to the next read and the client blocked
    # forever waiting for a reply that was never coming (#832). A hang is the
    # worst possible failure here -- it stalls whatever is driving the session
    # rather than failing one call -- so this asserts the refusal arrives, and
    # arrives quickly.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_session, args=(listen, result), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        # A function code no client sends, on purpose: this test used a real
        # unimplemented function twice (78 until #833 implemented it, then 4
        # until #854 did) and each time it quietly stopped testing anything
        # until someone noticed. The refusal path is the same for any code.
        conn.send(TNS_DATA, bytes([TTI_FUN, 250]) + bytes(8))
        received = conn._next_data_packet()
        assert received is not False, 'the Mirror answered nothing -- it hung'
        assert b'ORA-03115' in received[1]
        # ... and the session is still usable, exactly as after any other error.
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        row = cursor.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert row == ('X',)


def test_unhandled_piggyback_is_refused_not_dropped() -> None:
    # The sibling of the test above (#836). _skip_piggybacks stops on a piggyback
    # it does not know rather than guess its length -- guessing would desync the
    # stream -- which left the dispatch unable to reach the call behind it. The
    # message was then dropped silently and the client blocked forever, because a
    # piggyback is only a PREFIX to a real call whose reply is already awaited.
    #
    # Refusing keeps the stream in sync, so the session answers the next
    # statement normally. (A real client that set a connection attribute will
    # re-send the same piggyback on every call, so ITS connection stays unusable
    # until the piggyback is implemented -- but that is the client holding a
    # pending attribute, not a desync here.)
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]

    result: dict = {}
    server = threading.Thread(
        target=_run_mirror_session, args=(listen, result), daemon=True
    )
    server.start()

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        # 205 is the end-user security context piggyback: real, tcps-only, and
        # deliberately not handled here -- so it stands in for "a piggyback the
        # Mirror does not know". (This test used SET_SCHEMA until #837
        # implemented it; the example has to be one that is still unhandled, or
        # the test quietly stops testing anything.)
        conn.send(TNS_DATA, bytes([TTI_MSG_TYPE_PIGGYBACK, 205]) + bytes(8))
        received = conn._next_data_packet()
        assert received is not False, 'the Mirror answered nothing -- it hung'
        assert b'ORA-03115' in received[1]
        # The refusal names the piggyback, so the gap is identifiable from the
        # error alone rather than needing a packet capture.
        assert b'piggyback 205' in received[1]
        # The stream is still in sync: an ordinary statement runs.
        cursor = conn.cursor()
        cursor.execute('select * from dual')
        row = cursor.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert row == ('X',)


def test_each_query_gets_its_own_cursor_id() -> None:
    # A client reads the server's cursor id out of the reply terminator and
    # caches it against the statement, then re-executes by that id. The
    # terminator was a replayed 11g capture with cursor_id=1 baked in, so every
    # query in a session claimed to be cursor 1 -- and a re-execute by id would
    # have run whichever statement was most recently called 1 (#840).
    #
    # Asserted through _Cursors rather than the wire: the ids are what must
    # differ, and the terminator merely carries them.
    from seerdb.server.session import _Cursors

    cursors = _Cursors()
    first = cursors.open_query('select 7 from dual')
    second = cursors.open_query('select 42 from dual')
    assert first != second
    assert cursors.query_sql(first) == 'select 7 from dual'
    assert cursors.query_sql(second) == 'select 42 from dual'
    # An id nobody minted resolves to nothing, rather than to a stale statement.
    assert cursors.query_sql(9999) is None
    # A parked result keeps its statement too, so draining it and re-executing
    # by the same id stay consistent.
    parked = cursors.open([], [(1,)], sql='select 99 from dual')
    assert cursors.query_sql(parked) == 'select 99 from dual'
    assert parked not in (first, second)


def test_the_end_of_fetch_terminator_carries_the_cursor_id() -> None:
    # The captured 11g terminator stays byte-identical when the caller has no
    # cursor of its own, so nothing changes for the paths that never had one;
    # a real id changes only that field.
    from seerdb.common.tns import _ENCODE_OER_SEQ, _END_OF_FETCH, _end_of_fetch

    assert _end_of_fetch() == _END_OF_FETCH
    assert _end_of_fetch(1) == _END_OF_FETCH

    # Pinned to the sequence the capture was taken at, a real cursor id changes
    # that field and nothing else -- the terminator keeps its captured shape.
    token = _ENCODE_OER_SEQ.set(4)
    try:
        assert _end_of_fetch(7) != _END_OF_FETCH
        assert len(_end_of_fetch(7)) == len(_END_OF_FETCH)
    finally:
        _ENCODE_OER_SEQ.reset(token)


def test_the_reply_sequence_wraps_at_16_bits() -> None:
    # Both reply paths carry the sequence in a 16-bit field. The OCI counter
    # never wrapped, so a sqlplus session died on its 65,536th reply, unable to
    # encode it (#1513); the thin one would have grown a third byte.
    from seerdb.common.tns import encode_status_oci
    from seerdb.server.session import _next_reply_sequence, _OciSequence

    assert _next_reply_sequence(0xFFFE) == 0xFFFF
    assert _next_reply_sequence(0xFFFF) == 0
    seq = _OciSequence()
    seq._n = 0xFFFF
    assert [seq.next() for _ in range(3)] == [0xFFFF, 0, 1]
    seq._n = 0xFFFF
    encode_status_oci(seq.next())
    encode_status_oci(seq.next())  # raised struct.error past 65535


def test_the_thin_terminator_advances_its_oer_sequence() -> None:
    # The thin reply path used to emit the frozen sequence every captured status
    # was decoded with, so a whole session repeated one number while the
    # thick/OCI path advanced a real counter (#842). The field is diagnostic --
    # no client validates it -- so what is asserted is that it MOVES and that it
    # reaches the wire, not any particular value.
    from seerdb.common.tns import _ENCODE_OER_SEQ, _end_of_fetch, encode_status

    seen = set()
    for n in (1, 2, 3):
        token = _ENCODE_OER_SEQ.set(n)
        try:
            seen.add((encode_status(1, cursor_id=9), _end_of_fetch(7)))
        finally:
            _ENCODE_OER_SEQ.reset(token)
    # Three sequence values, three distinct pairs of encoded replies.
    assert len(seen) == 3

    # A caller that pins `seq` is reproducing a captured frame and is unaffected
    # by the session counter -- that is what keeps _END_OF_FETCH verbatim.
    from seerdb.common.tns import _encode_oer

    token = _ENCODE_OER_SEQ.set(99)
    try:
        assert _encode_oer(1, 0, 0, b'', seq=4) == _encode_oer(1, 0, 0, b'', seq=4)
        assert _encode_oer(1, 0, 0, b'', seq=4) != _encode_oer(1, 0, 0, b'')
    finally:
        _ENCODE_OER_SEQ.reset(token)


def test_reexecute_runs_the_cursors_own_statement() -> None:
    # A re-execute names a cursor and carries no SQL, so it can only be served if
    # the cursor identifies one statement (#833, on top of #840). The danger this
    # guards is not a crash but a WRONG ANSWER: re-executing cursor 2 must run
    # cursor 2's query, not whatever ran most recently.
    from seerdb.common.tns import _DECODE_FIELD_VERSION, parse_reexecute
    from seerdb.server.session import _Cursors

    cursors = _Cursors()
    first = cursors.open_query('select 7 from dual')
    second = cursors.open_query('select 42 from dual')
    assert cursors.query_sql(first) == 'select 7 from dual'
    assert cursors.query_sql(second) == 'select 42 from dual'

    # The request layout, byte-for-byte from a live 23ai capture: cursor 1,
    # two iterations, options 0x20. It only decodes at the field version the
    # session negotiated -- the fv24 token ahead of the fields shifts everything
    # by one byte -- so the parse is version-sensitive and worth pinning.
    raw = bytes.fromhex('034e040001010102012000')
    _DECODE_FIELD_VERSION.set(24)
    request = parse_reexecute(raw)
    assert (request.cursor, request.fetch, request.options) == (1, 2, 0x20)

    # Re-parking under the SAME id: the client is never told a new one, so its
    # follow-up fetches would otherwise address a cursor it does not hold.
    cursors.reopen(first, [], [(7,), (8,)], sql='select 7 from dual')
    assert cursors.has(first)
    assert cursors.query_sql(first) == 'select 7 from dual'
    # Draining it leaves the statement resolvable, so a later re-execute still
    # knows what to run.
    cursors.take(first, 99)
    assert cursors.query_sql(first) == 'select 7 from dual'


def test_parse_reexecute_decodes_fresh_bind_rows_by_the_cached_types() -> None:
    # The plain re-execute (func 4, #854) carries one RXD row per execution and
    # no OACs: the values are typed by the execute that opened the cursor. Three
    # requests byte-for-byte from a live 23ai (fv24, so the ub8 token follows
    # the sequence byte), each with the bind types its opening execute declared.
    from seerdb.common.tns import _DECODE_FIELD_VERSION, parse_reexecute
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR

    number = (TNS_TYPE_NUMBER, 1, 22, b'')
    text = (TNS_TYPE_VARCHAR, 1, 20, b'')
    insert = bytes.fromhex('03 04 08 00 01 03 01 01 00 00 07 02 c1 03 04 72 6f 77 32')
    update = bytes.fromhex('03 04 0b 00 01 05 01 01 00 00 07 01 79 02 c1 06')
    select = bytes.fromhex('03 04 0d 00 01 04 01 01 00 00 07 02 c1 04')
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        # INSERT ... VALUES (:1, :2) re-run with (2, 'row2') on cursor 3.
        request = parse_reexecute(insert, bind_types=[number, text])
        assert (request.cursor, request.fetch, request.autocommit) == (3, 1, False)
        assert request.bind_rows == [[2, 'row2']]
        # UPDATE ... SET s = :1 WHERE id > :2 with ('y', 5): the row follows the
        # bind order, not the type.
        request = parse_reexecute(update, bind_types=[text, number])
        assert request.cursor == 5
        assert request.bind_rows == [['y', 5]]
        # A query re-executed with prefetching off is the same message.
        request = parse_reexecute(select, bind_types=[number])
        assert (request.cursor, request.bind_rows) == (4, [[3]])
        # Without the types only the header is read -- what the dispatch does
        # first, to learn which cursor's types to look up.
        assert parse_reexecute(insert).cursor == 3
        assert parse_reexecute(insert).bind_rows == []
        # executemany's second run: `iterations` executions, one row each; and
        # options_2 bit 0 is the client's autocommit.
        two = insert[:6] + bytes.fromhex('01 02 00 01 01') + insert[10:] + insert[10:]
        request = parse_reexecute(two, bind_types=[number, text])
        assert (request.fetch, request.autocommit) == (2, True)
        assert request.bind_rows == [[2, 'row2'], [2, 'row2']]
        # A row cut short is reported, so the spanning reader fetches the rest.
        with pytest.raises(Truncated):
            parse_reexecute(insert[:-2], bind_types=[number, text])
    finally:
        _DECODE_FIELD_VERSION.reset(token)


def test_a_zero_prefetch_execute_sends_no_rows_but_parks_them() -> None:
    # An execute's fetch field is the client's PREFETCH, and a zero there means
    # "send me no rows on the execute" -- the client has allocated no fetch
    # buffer and will ask with TTI_FETCH. Reading it as "send everything"
    # overran the reference thin client's define array and killed it inside its
    # own row decoder (IndexError in _process_row_data), before the reply could
    # become an error anyone could read (#856). A real 23ai answers a prefetch-0
    # execute with describe + status and no row data at all.
    from seerdb.common.tns import ExecRequest, encode_query_response
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.session import _answer_query, _Cursors, _prefetch_batch

    column = ColumnMeta(
        name=b'ID', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22
    )

    class _Rows:
        capabilities: frozenset = frozenset()

        def execute(self, sql: str, binds=()) -> Result:
            return Result(columns=[column], rows=[(1,), (2,), (3,)])

        def commit(self) -> None:
            pass

    class _Stream:
        def __init__(self) -> None:
            self.sent: list[tuple[int, bytes]] = []

        def write_packet(self, packet_type: int, body: bytes) -> None:
            self.sent.append((packet_type, body))

    def run(fetch: int) -> tuple[Any, Any]:
        stream: Any = _Stream()
        cursors = _Cursors()
        request = ExecRequest(
            sql='select id from t', cursor=0, bind_count=0, fetch=fetch
        )
        _answer_query(stream, _Rows(), request, cursors)  # type: ignore[arg-type]
        return stream, cursors

    # Prefetch 0: describe and a "more rows on cursor 1" terminator, not one row.
    stream, cursors = run(0)
    assert stream.sent == [
        (TNS_DATA, encode_query_response([column], [], cursor_id=1, more=True))
    ]
    # ...and every row waits on the cursor the terminator named, so the client's
    # TTI_FETCH gets them. They are delivered, not dropped.
    _columns, parked = cursors.take(1, 10)
    assert parked == [(1,), (2,), (3,)]

    # A positive prefetch is untouched: that many inline, the rest parked.
    stream, cursors = run(2)
    assert stream.sent == [
        (
            TNS_DATA,
            encode_query_response([column], [(1,), (2,)], cursor_id=1, more=True),
        )
    ]
    assert cursors.take(1, 10)[1] == [(3,)]

    # The rule itself, at its edges: a zero keeps nothing back for later only
    # because the caller parks it; a prefetch wider than the result is clamped.
    assert _prefetch_batch(0, 3) == 0
    assert _prefetch_batch(2, 3) == 2
    assert _prefetch_batch(99, 3) == 3


def test_a_freed_temp_lob_never_hands_its_locator_to_the_next_one() -> None:
    # Locators used to be numbered by the COUNT of live temp LOBs, so freeing one
    # reissued its index and the next CREATE_TEMP collided with a locator still
    # in use (#857). Replay of the live sequence that exposed it -- a third large
    # LOB insert on one connection:
    #
    #   insert 1  mint L0
    #   insert 2  mint L1, then the close-temp-LOBs piggyback frees L0
    #   insert 3  mint ... -> handed back L1 under the count, overwriting the
    #             buffer insert 2 was holding; the piggyback riding on insert 3
    #             then freed the locator insert 3 was about to bind, and the
    #             value reached the backend as NULL (ORA-01400).
    from seerdb.server.session import _TempLobs

    temp_lobs = _TempLobs()
    first = temp_lobs.mint(is_blob=True)
    second = temp_lobs.mint(is_blob=True)
    temp_lobs.append(second, b'insert-2-payload')
    temp_lobs.free(first)  # the piggyback riding on insert 2

    third = temp_lobs.mint(is_blob=True)
    assert third not in (first, second)
    # The live buffer is untouched -- the collision used to reset it to empty.
    assert temp_lobs.content(second) == b'insert-2-payload'
    temp_lobs.append(third, b'insert-3-payload')
    assert temp_lobs.content(third) == b'insert-3-payload'
    assert temp_lobs.content(second) == b'insert-2-payload'

    # The index keeps climbing however much is freed: reuse is what caused the
    # collision, so nothing may bring it back, including freeing everything.
    for locator in (second, third):
        temp_lobs.free(locator)
    minted = [temp_lobs.mint(is_blob=False) for _ in range(3)]
    assert len(set(minted + [first, second, third])) == 6
    # Freeing a locator the Mirror never saw is still not an error.
    temp_lobs.free(b'never-minted')
    assert temp_lobs.content(b'never-minted') == b''


def test_a_break_episode_is_answered_with_reset_then_cancel() -> None:
    # connection.cancel() sends its break in-band AFTER the call's reply arrives
    # (no out-of-band support is advertised), then waits. The thin loop dropped
    # every marker into its "not DATA, ignore it" branch, so the client waited
    # forever (#844). A real 23ai answers the episode like this:
    #
    #     client -> MARKER 01 00 03   interrupt
    #     client -> MARKER 01 00 02   reset
    #     server -> MARKER 01 00 02   reset
    #     server -> DATA   OER        ORA-01013
    from seerdb.common.tns_consts import TNS_MARKER, TNS_MARKER_TYPE_RESET
    from seerdb.server.session import _answer_marker

    class _FakeStream:
        def __init__(self, inbox: list) -> None:
            self.inbox = inbox
            self.sent: list[tuple[int, bytes]] = []
            self.rederived = 0

        def read_packet(self, **_kw):
            return self.inbox.pop(0) if self.inbox else None

        def write_packet(self, packet_type: int, body: bytes) -> None:
            self.sent.append((packet_type, body))

        def rederive_ano(self) -> None:
            self.rederived += 1

    # The interrupt opens the episode and draws a reset; the Mirror then waits
    # for the client's reset -- dropping the request the client queued behind
    # its interrupt, which gets the cancel as its answer (#1346) -- and only
    # then reports the cancel, which is what the client is waiting to read.
    queued = (TNS_DATA, bytes([3, 0x5E, 1]))
    client_reset = (TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
    stream: Any = _FakeStream([queued, client_reset])
    _answer_marker(stream, bytes([1, 0, 3]))
    assert stream.sent[0] == (TNS_MARKER, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
    packet_type, body = stream.sent[-1]
    assert packet_type == TNS_DATA
    assert b'ORA-01013' in body
    assert b'User requested cancel of current operation.' in body
    assert stream.inbox == []  # the queued request was dropped
    # Exactly one reset for the whole episode: echoing each marker would
    # ping-pong the two sides into a reset storm. And one re-derivation of the
    # integrity keystreams, before the cancel goes out (#1346).
    assert sum(1 for t, _ in stream.sent if t == TNS_MARKER) == 1
    assert stream.rederived == 1

    # A client that sent its reset along with its interrupt: the reset is
    # already waiting, and closes the episode the same way.
    stream = _FakeStream([])
    _answer_marker(stream, bytes([1, 0, TNS_MARKER_TYPE_RESET]))
    assert [t for t, _ in stream.sent] == [TNS_DATA]
    assert stream.rederived == 1


def test_complete_message_reassembles_a_spanning_request() -> None:
    # A TTC message can span several TNS packets with no continuation flag, so
    # read_packet hands back only the first and parsing it runs off the end. The
    # loop reads more packets until the parser stops reporting Truncated (#848).
    from seerdb.server.session import _complete_message

    # A stream that yields a message in three DATA packets.
    parts = [b'\x03\x60\x00\x01', b'aaaa', b'bbbb-END']

    class _Stream:
        max_message = 1 << 20

        def __init__(self) -> None:
            self.reads = 0

        def read_packet(self, **_kw):
            self.reads += 1
            # parts[0] is the caller's `body`; hand out parts[1:] on demand.
            return (TNS_DATA, parts[self.reads])

    # parse() is truncated until the assembled body ends with the sentinel; it is
    # pure, so the loop may call it repeatedly with no side effect.
    def parse(b: bytes) -> object:
        if not b.endswith(b'-END'):
            raise Truncated('need the rest')
        return b

    stream: Any = _Stream()
    full = _complete_message(stream, parts[0], parse)
    assert full == b''.join(parts)
    assert stream.reads == 2  # exactly the two continuation packets, no more


def test_complete_message_holds_a_message_to_the_streams_limit() -> None:
    # GHSA-vxvf-jx7x-rcx8: a message grown here, outside the framer's own
    # reassembly, is held to the framer's limit -- a login's before the client
    # has authenticated -- and the connection is dropped past it, as the
    # framer drops one.
    from seerdb.server.framing import ProtocolLimitError
    from seerdb.server.session import _complete_message

    class _Stream:
        max_message = 64 * 1024

        def __init__(self) -> None:
            self.reads = 0

        def read_packet(self, **_kw):
            self.reads += 1
            return (TNS_DATA, b'\x00' * 8192)

    def never_whole(_body: bytes) -> object:
        raise Truncated('need the rest')

    stream: Any = _Stream()
    with pytest.raises(ProtocolLimitError):
        _complete_message(stream, b'\x03\x73\x01', never_whole)
    assert stream.reads == 8


def test_complete_message_returns_a_single_packet_untouched() -> None:
    # The common case: the message fits one packet, parse succeeds first try, and
    # the stream is never touched.
    from seerdb.server.session import _complete_message

    class _Stream:
        def read_packet(self, **_kw):  # pragma: no cover - must not be called
            raise AssertionError('read_packet called for a complete message')

    stream: Any = _Stream()
    body = b'\x03\x60\x00\x01whole'
    assert _complete_message(stream, body, lambda b: b) is body


def test_complete_message_refuses_a_message_that_never_completes() -> None:
    # `Truncated` means "the parser ran off the end", which a message cut by the
    # transport and a DECODE FAULT inside a complete message produce alike. The
    # reader used to wait for a continuation either way, so a fault hung the
    # session while the client blocked on its reply -- the silent hang #832/#836
    # removed, back through another door, and one wedge stalls a whole suite run
    # (#868; the fault that found it was a NULL BOOLEAN bind, #869).
    #
    # A real continuation is already in flight, so the wait is bounded: when it
    # expires the request is refused like any other the Mirror cannot serve, and
    # the session stays usable.
    from seerdb.common.exceptions import Truncated
    from seerdb.common.tns_consts import TNS_DATA
    from seerdb.server.session import _complete_message

    class _Stream:
        def __init__(self) -> None:
            self.sent: list[tuple[int, bytes]] = []
            self.waits: list[float | None] = []

        def read_packet(self, *, within: float | None = None):
            # Nothing more is coming -- exactly what a decode fault looks like.
            self.waits.append(within)
            raise TimeoutError

        def write_packet(self, packet_type: int, body: bytes) -> None:
            self.sent.append((packet_type, body))

    stream: Any = _Stream()
    answer = _complete_message(
        stream,
        b'\x03\x5eunparsable',
        lambda b: (_ for _ in ()).throw(Truncated('DALC: 253 bytes, 1 left')),
    )
    # It gives up rather than blocking...
    assert answer is None
    # ...having BOUNDED the wait (the whole point -- an unbounded read here is
    # the hang), and having answered the client, which is still waiting.
    assert stream.waits and all(w is not None for w in stream.waits)
    assert len(stream.sent) == 1
    packet_type, body = stream.sent[0]
    assert packet_type == TNS_DATA
    assert b'ORA-03115' in body
    # The refusal names what could not be read, so the gap is identifiable from
    # the error alone rather than needing a packet capture.
    assert b'DALC: 253 bytes, 1 left' in body


def test_complete_message_raises_when_the_client_vanishes_mid_message() -> None:
    # A half-sent message whose rest never arrives must fail, not spin: read_packet
    # returning None (EOF) becomes a clean InterfaceError.
    from seerdb.common.exceptions import Truncated
    from seerdb.server.session import _complete_message

    class _Stream:
        def read_packet(self, **_kw):
            return None

    stream: Any = _Stream()
    with pytest.raises(InterfaceError):
        _complete_message(
            stream, b'\x03\x60partial', lambda b: (_ for _ in ()).throw(Truncated('x'))
        )


def test_backend_fault_error_reports_ora600_without_recursing() -> None:
    # An exception the backend lets escape must become a one-statement error the
    # session survives, not a crash. A NotSupportedError is a feature gap ->
    # ORA-03115; anything else is genuinely unexpected -> ORA-00600. The
    # non-NotSupportedError branch used to `return _backend_fault_error(exc)`,
    # an infinite self-call that raised RecursionError and tore the connection
    # down (DPY-4011) for every unexpected fault (#904 follow-up).
    from seerdb.common.exceptions import NotSupportedError
    from seerdb.server.session import _backend_fault_error

    gap = _backend_fault_error(NotSupportedError('no wire encoding for X'))
    assert b'ORA-03115' in gap

    # A ValueError (e.g. an encoder raising on a bad length) must not recurse.
    fault = _backend_fault_error(ValueError('encoded number data too long'))
    assert b'ORA-00600' in fault
    assert b'encoded number data too long' in fault


def test_a_login_failure_reports_why_it_failed() -> None:
    # ORA-01017 is reserved for a credential that did not verify. It used to be
    # sent for EVERY login-time failure, including ones where the password was
    # perfectly good and the server simply had no session to give -- a full
    # database (ORA-12516) reported as "invalid username/password". The one
    # thing a client cannot do with that is tell the two apart, and it cost two
    # investigations before the Mirror's own log gave it away (#1006).
    from seerdb.common.exceptions import InterfaceError
    from seerdb.common.tns import decode_token_oer
    from seerdb.server.session import _deny_login

    def reported(**kw) -> tuple:
        stream: Any = _CollectingStream()
        try:
            _deny_login(stream, 'reason', **kw)
        except InterfaceError:
            pass
        decoded = decode_token_oer(stream.sent[0], (0, [], []))
        return (decoded[1], decoded[5])

    # A credential that did not verify still says so, and still says it the way
    # Oracle does -- without distinguishing user from password.
    code, message = reported()
    assert code == 1017
    assert 'invalid username/password' in message

    # A backend that refused says what the BACKEND said, so a client behind a
    # passthrough sees what a direct connection would have seen.
    assert reported(
        ora_code=12516, message='ORA-12516: connection refused by the listener'
    ) == (12516, 'ORA-12516: connection refused by the listener')


def test_a_backend_failure_keeps_its_own_ora_code() -> None:
    # Where the code comes from: an upstream driver's error already carries the
    # server's own, and relaying it is the whole point. Anything without one
    # becomes ORA-01034 -- the server exists but has no session to give, which
    # is true of every case that lands here (#1006).
    import seerdb
    from seerdb.server.session import _login_failure_error

    upstream = seerdb.DatabaseError(
        'ORA-12516: connection refused by the listener', code=12516
    )
    assert _login_failure_error(upstream) == {
        'ora_code': 12516,
        'message': 'ORA-12516: connection refused by the listener',
    }

    # A socket error has no ORA code to relay, and inventing a specific one
    # would be a different lie from the one this fixes.
    fallback = _login_failure_error(OSError('connection refused'))
    assert fallback['ora_code'] == 1034
    assert fallback['message'].startswith('ORA-01034:')


def test_a_parse_fault_refuses_the_call_instead_of_killing_the_session() -> None:
    # A message cut by the transport says so with Truncated, and _complete_message
    # waits for the rest. Anything ELSE a parser raises is a bug in that parser --
    # but it must not take the connection down with it: the Mirror's contract is
    # that it never desyncs, and an unhandled exception here killed the whole
    # session (#1000). Answer the way any unservable call is answered, and let
    # the client carry on.
    from seerdb.server.session import _complete_message

    stream: Any = _CollectingStream()

    def exploding_parse(body: bytes) -> object:
        raise ValueError('a parser bug, not a short message')

    assert _complete_message(stream, b'anything', exploding_parse) is None
    # The client was ANSWERED -- the failure mode this replaces was silence.
    assert stream.sent, 'a parse fault left the client with no reply'


def test_a_cursors_bind_format_is_refreshed_when_the_client_redescribes() -> None:
    # An OAC-less re-execute decodes its rows with the bind format recorded
    # against the cursor. That was recorded once, at open -- so when a client
    # re-describes its binds mid-stream, the NEXT OAC-less execute still decoded
    # with the original types. A column that is all-NULL in the first
    # executemany batch and carries numbers in a later one is exactly that: the
    # numbers came back as their raw NUMBER bytes read as text, and the upstream
    # answered ORA-01722 (#999).
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
    from seerdb.server.session import _Cursors

    cursors = _Cursors()
    opened = [(TNS_TYPE_VARCHAR, 1, 40, b'')]
    cursor_id = cursors.open_dml('insert into t (a, b) values (:1, :2)', opened)
    assert cursors.bind_types(cursor_id) == opened

    redescribed = [(TNS_TYPE_NUMBER, 1, 22, b'')]
    cursors.set_bind_types(cursor_id, redescribed)
    assert cursors.bind_types(cursor_id) == redescribed

    # An execute carrying NO OACs is asking to reuse the format, not to clear
    # it -- the same rule a define follows.
    cursors.set_bind_types(cursor_id, [])
    assert cursors.bind_types(cursor_id) == redescribed

    # The statement the cursor stands for is untouched by any of this.
    assert cursors.dml_sql(cursor_id) == 'insert into t (a, b) values (:1, :2)'


def test_a_define_stands_for_the_life_of_the_cursor() -> None:
    # A client applies a define ONCE, on the round-trip that follows the first
    # describe, and it then stands: every later execute of that cursor carries
    # none. A server that forgets reverts to LOB-class handling -- another
    # describe the client is not expecting, then a locator for a column it is
    # reading as a string or bytes, and the row stream desyncs (#826).
    from seerdb.common.tns_consts import TNS_TYPE_LONG
    from seerdb.server.session import _Cursors

    cursors = _Cursors()
    cursor_id = cursors.open_query('select ClobCol from TestClobs')
    assert cursors.defines(cursor_id) == []
    cursors.set_defines(cursor_id, [(TNS_TYPE_LONG, 1)])
    assert cursors.defines(cursor_id) == [(TNS_TYPE_LONG, 1)]
    # An execute carrying no defines is an ordinary call, NOT the client
    # withdrawing them.
    cursors.set_defines(cursor_id, [])
    assert cursors.defines(cursor_id) == [(TNS_TYPE_LONG, 1)]
    # An id nobody defined has none, rather than inheriting a neighbour's.
    assert cursors.defines(cursor_id + 1) == []


def test_a_later_fetch_honours_the_define_too() -> None:
    # The rows of a LOB-class result are parked by the EXECUTE, before the define
    # exists: such a result defers its rows, so the client gets a describe-only
    # reply and sends the define on the round-trip after it. The re-execute that
    # carries the define applied it only to the batch it served itself, so a
    # result larger than one batch went out in two framings -- the first rows
    # inline, every later row a locator the client was no longer expecting. It
    # reported that as an unknown message type whose number was the locator's own
    # length byte, which is why it read as a decoder gap (#982).
    from seerdb.common.tns import ColumnMeta
    from seerdb.common.tns_consts import TNS_TYPE_CLOB, TNS_TYPE_LONG
    from seerdb.server.session import FetchRequest, _answer_fetch, _Cursors

    columns = [
        ColumnMeta(
            name=b'CLOBCOL',
            data_type=TNS_TYPE_CLOB,
            data_length=4000,
            max_size=4000,
            csfrm=1,
        )
    ]
    cursors = _Cursors()
    cursor_id = cursors.open(columns, [('first',), ('second',)])
    cursors.set_defines(cursor_id, [(TNS_TYPE_LONG, 1)])

    stream: Any = _CollectingStream()
    lobs = _answer_fetch(stream, FetchRequest(cursor=cursor_id, fetch=1), cursors)
    # Served inline, so there is no locator and nothing queued for a LOB read --
    # a client that defined the column as LONG issues none.
    assert lobs == []
    assert b'first' in stream.sent[0]

    # And the SAME again for the batch after it, which is the half that used to
    # revert.
    stream = _CollectingStream()
    lobs = _answer_fetch(stream, FetchRequest(cursor=cursor_id, fetch=1), cursors)
    assert lobs == []
    assert b'second' in stream.sent[0]


def test_defines_travel_to_the_id_a_re_run_mints() -> None:
    # Re-running a cached query mints a FRESH cursor id and reports that, so the
    # defines standing on the id the client re-executed have to travel with it.
    # Without that the next re-execute found none and desynced on the third
    # execute of a statement, not the second -- which is what made it look like a
    # bind-type problem rather than a lost define (#826).
    from seerdb.common.tns_consts import TNS_TYPE_LONG
    from seerdb.server.session import _Cursors

    cursors = _Cursors()
    first = cursors.open_query('select ClobCol from TestClobs')
    cursors.set_defines(first, [(TNS_TYPE_LONG, 1)])
    second = cursors.open_query('select ClobCol from TestClobs')
    assert second != first
    cursors.set_defines(second, cursors.defines(first))
    assert cursors.defines(second) == [(TNS_TYPE_LONG, 1)]


def test_parse_reexecute_of_a_block_skips_out_binds_and_keeps_wide_ones_in_place() -> (
    None
):
    # A PL/SQL block gets a server cursor id like any other statement (#1064),
    # and the client then re-executes it by that id. Two things separate such a
    # re-execute from a DML one, and both are visible in this capture of
    # `callproc("proc_Test2", ("hi", 5), {"a_OutValue": out_var})` re-run
    # against a live 23ai:
    #
    #   03 04 07 00 | 01 03 | 01 01 | 00 | 00 | 07 | 02 68 69 | 02 c1 06
    #               cursor 3  1 iter  opts  opts  RXD  'hi'      5
    #
    #   * the third bind is pure OUT and carries NO value -- the client has
    #     nothing to send for it (its writer drops every TNS_BIND_DIR_OUTPUT
    #     bind), so the row has two values for three binds;
    #   * the first bind is a VARCHAR OUT declaring 16000, far past
    #     max_string_size, yet it rides FIRST. A block's LONG-class binds stay in
    #     place; only DML sorts them last. Reading this row the DML way put 'hi'
    #     in the NUMBER's slot.
    from seerdb.common.tns import _DECODE_FIELD_VERSION, parse_reexecute
    from seerdb.common.tns_consts import (
        TNS_BIND_DIR_INPUT,
        TNS_BIND_DIR_INPUT_OUTPUT,
        TNS_BIND_DIR_OUTPUT,
        TNS_TYPE_BOOLEAN,
        TNS_TYPE_NUMBER,
        TNS_TYPE_VARCHAR,
    )

    raw = bytes.fromhex('030407000103010100000702686902c106')
    types = [
        (TNS_TYPE_VARCHAR, 1, 16000, b''),
        (TNS_TYPE_NUMBER, 0, 22, b''),
        (TNS_TYPE_BOOLEAN, 0, 4, b''),
    ]
    directions = (
        TNS_BIND_DIR_INPUT,
        TNS_BIND_DIR_INPUT_OUTPUT,
        TNS_BIND_DIR_OUTPUT,
    )
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        request = parse_reexecute(
            raw, bind_types=types, bind_directions=directions, cached_plsql=True
        )
        assert request.cursor == 3
        # The OUT position keeps None, so the row still lines up with bind_meta.
        assert request.bind_rows == [['hi', 5, None]]
    finally:
        _DECODE_FIELD_VERSION.reset(token)


def test_parse_reexecute_of_a_block_reads_every_iteration() -> None:
    # An executemany of a block sends its first row as a full execute (the
    # client keeps a block single-execute until it has a cursor id) and the rest
    # as ONE array re-execute. Captured off a live 23ai for
    # `executemany(block, [(31, 'Test 31'), (6, 'Test 6'), ...])`: cursor 5, four
    # iterations, four RXD rows, and no value for the OUT bind in any of them.
    from seerdb.common.tns import _DECODE_FIELD_VERSION, parse_reexecute
    from seerdb.common.tns_consts import (
        TNS_BIND_DIR_INPUT,
        TNS_BIND_DIR_OUTPUT,
        TNS_TYPE_NUMBER,
        TNS_TYPE_VARCHAR,
    )

    raw = bytes.fromhex(
        '03040600010501040000'  # FUN, func 4, seq, token, cursor 5, 4 iters, opts
        '0702c10706546573742036'  # RXD  6, 'Test 6'
        '0702c1160754657374203231'  # RXD 21, 'Test 21'
        '0702c1120754657374203137'  # RXD 17, 'Test 17'
        '0702c12c0754657374203433'  # RXD 43, 'Test 43'
    )
    types = [
        (TNS_TYPE_NUMBER, 0, 22, b''),
        (TNS_TYPE_VARCHAR, 1, 100, b''),
        (TNS_TYPE_NUMBER, 0, 22, b''),
    ]
    directions = (TNS_BIND_DIR_INPUT, TNS_BIND_DIR_INPUT, TNS_BIND_DIR_OUTPUT)
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        request = parse_reexecute(
            raw, bind_types=types, bind_directions=directions, cached_plsql=True
        )
        assert (request.cursor, request.fetch) == (5, 4)
        assert request.bind_rows == [
            [6, 'Test 6', None],
            [21, 'Test 21', None],
            [17, 'Test 17', None],
            [43, 'Test 43', None],
        ]
    finally:
        _DECODE_FIELD_VERSION.reset(token)


def test_a_block_reexecute_reply_is_one_rxd_per_iteration() -> None:
    # The reply the capture above drew, byte for byte: one TTI_RXD per
    # iteration carrying that iteration's OUT value and its return code, then
    # the success OER. No IOV -- a plain re-execute cannot restate the bind
    # directions, and the server does not (#1064).
    from seerdb.common.tns import ScalarOutBind, encode_out_bind_reexecute_thin
    from seerdb.common.tns_consts import (
        TNS_BIND_DIR_INPUT,
        TNS_BIND_DIR_OUTPUT,
        TNS_TYPE_NUMBER,
    )

    directions = (TNS_BIND_DIR_INPUT, TNS_BIND_DIR_INPUT, TNS_BIND_DIR_OUTPUT)

    def row(value: int) -> list:
        return [
            ScalarOutBind(value=None, tns_type=TNS_TYPE_NUMBER, csfrm=0),
            ScalarOutBind(value=None, tns_type=TNS_TYPE_NUMBER, csfrm=0),
            ScalarOutBind(value=value, tns_type=TNS_TYPE_NUMBER, csfrm=0),
        ]

    reply = encode_out_bind_reexecute_thin(
        [row(6), row(21), row(17), row(43)], directions, cursor_id=5
    )
    assert reply.startswith(bytes.fromhex('0702c107000702c116000702c112000702c12c00'))
    # An OALL8 carrying a cursor id and no SQL is a full execute message, so its
    # reply DOES restate the IOV -- captured that way too.
    with_iov = encode_out_bind_reexecute_thin(
        [row(6)], directions, cursor_id=5, with_iov=True
    )
    assert with_iov.startswith(bytes.fromhex('0b00'))
    assert bytes(directions) in with_iov


def test_parse_exec_keeps_a_cached_blocks_wide_bind_in_place() -> None:
    # The same in-place rule on the OALL8 path. A cached execute carries no
    # statement, so `is_plsql` has nothing to read and the Mirror has to say
    # what the cursor stands for. Captured off a live 23ai: a block re-executed
    # by id whose first bind is an object collection (declared 16000). Read as
    # DML it is sorted last and the 16-byte type OID lands in the NUMBER's slot.
    from seerdb.common.exceptions import DataError
    from seerdb.common.tns import _DECODE_FIELD_VERSION, parse_exec

    raw = bytes.fromhex(
        '035e07000204280101000001010d0000000101047fffffff010109000000000000000000'
        '010000000000000000000000000000000001010000000000000002800000000003010000'
        '0116000000000000000001010000023e800000000002036901000017010000020fa00000'
        '000000000000030100000116000000000000000017010000020fa0000000000000000066'
        '0100000104000000000000000001010000023e800000000002036901000001010000023e'
        '800000000002036901000001010000023e80000000000203690100000701801e22505954'
        '484f4e54455354222e225544545f4f424a454354415252415922105beac3196b130427e0'
        '639600a8c0a49702c102ef000000eb26020001001700290000000000b406008107003c01'
        '000001000a01000007007882000001001482000013001006000006000005000500050025'
        '2d021506170621061d1d1e2706008107003c010000281b0000005afb2afd000000622601'
        '00010001ff290000000000571c0000001d0000000a032a1b00000023fafd0000003c0000'
        '001c260100010002002900000000000f06008107003c0100002a0007000a000000182601'
        '0001000300290000000000091a1a1a2a00070008000900070007000a00100016001c0022'
        '00250028002b002d002f003100320033003400360038003a003b003c003e004100480101'
        '0105000a505954484f4e544553540a5544545f4f424a454354'
    )
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        request = parse_exec(raw, cached_plsql=True)
        assert request.bind_count == 9
        assert request.binds[1] == '"PYTHONTEST"."UDT_OBJECTARRAY"'
        with pytest.raises(DataError):
            parse_exec(raw)
    finally:
        _DECODE_FIELD_VERSION.reset(token)


# --- pipelining and end-of-response (#1059) ----------------------------------


@pytest.mark.parametrize('field_version', [24, 17])
def test_skip_piggybacks_steps_over_pipeline_begin(field_version: int) -> None:
    # The PIPELINE_BEGIN piggyback (199) opens a pipelined burst and rides in
    # front of its first call, sharing that call's token. It must be walked,
    # not refused: an unknown piggyback leaves the call unreachable, and the
    # Mirror used to answer the whole burst ORA-03115 (piggyback 199).
    from seerdb.common.tns import _DECODE_FIELD_VERSION, encode_pipeline_begin
    from seerdb.common.tns_consts import TNS_PIPELINE_MODE_CONTINUE_ON_ERROR
    from seerdb.server.session import _skip_piggybacks

    body = _exec_body()
    token = _DECODE_FIELD_VERSION.set(field_version)
    try:
        begin = encode_pipeline_begin(
            3, field_version, 1, TNS_PIPELINE_MODE_CONTINUE_ON_ERROR
        )
        assert _skip_piggybacks(begin + body) == body
    finally:
        _DECODE_FIELD_VERSION.reset(token)


def test_a_success_oer_carries_no_message_from_12_1() -> None:
    # A 12.1+ client reads the message only `if error_num != 0`. The empty
    # length byte written on success was never consumed -- harmless while the
    # OER ended the response, and "unknown protocol message type 0" on every
    # login once end-of-response framing made the client read on past it.
    #
    # Asserted on _oer_message rather than on the whole OER: every earlier field
    # of a success status is zero too, so the OER ends in a long zero run and a
    # suffix check cannot tell whether that one byte is present.
    from seerdb.common.tns import _ENCODE_FIELD_VERSION, _oer_message
    from seerdb.common.tns_consts import FIELD_VERSION_11_2, FIELD_VERSION_12_1

    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_12_1)
    try:
        assert _oer_message(0, b'') == b''  # success: nothing at all
        assert _oer_message(942, b'ORA-00942: x') != b''  # an error keeps it
    finally:
        _ENCODE_FIELD_VERSION.reset(token)
    token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
    try:
        # Below 12.1 the captured bytes stand, empty length included.
        assert _oer_message(0, b'') == b'\x00'
    finally:
        _ENCODE_FIELD_VERSION.reset(token)


class _NumberedBackend(_DualBackend):
    # _DualBackend reporting a session id at login, as a real backend's
    # session_info() does, so the Mirror tracks the session's statistics.
    session_id = 4321

    def session_info(self) -> SessionInfo:
        return SessionInfo(session_id=self.session_id)


def test_a_session_counts_its_round_trips() -> None:
    # Each call the client makes is one round trip in the session's statistics,
    # counted by the Mirror, which alone sees the wire (#1324). The session is
    # tracked under the id its login reported, from login to its end.
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    port = listen.getsockname()[1]
    result: dict = {}

    def serve() -> None:
        conn, _ = listen.accept()
        try:
            result['user'] = serve_session(PacketStream(conn), _NumberedBackend())
        finally:
            conn.close()

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    sid = _NumberedBackend.session_id

    def round_trips() -> int:
        return stats.snapshot()[sid][stats.ROUND_TRIPS]

    conn = seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
    )
    try:
        before = round_trips()
        conn.ping()
        assert round_trips() - before == 1
        conn.commit()
        assert round_trips() - before == 2
    finally:
        conn.close()
        server.join(5)
        listen.close()
    assert sid not in stats.snapshot()  # untracked once the session ended


def test_a_session_leaves_its_callers_context_alone() -> None:
    # A session pins its codec state in context variables -- here the OCI call
    # sequence each request carries (byte 2, 1 below). Served on a thread that
    # serves another session next (a thread pool, a test), it carried that state
    # into the next one; run in its own copy of the context, it leaves the
    # caller's as it was (#1333).
    from seerdb.common.tns import _ENCODE_OCI_CALL_SEQ
    from seerdb.common.tns_consts import TNS_DATA
    from seerdb.server.session import _serve_oci_session

    class _Stream:
        def __init__(self) -> None:
            self.inbox = [(TNS_DATA, bytes([TTI_FUN, 0xFA, 1])), None]

        def read_packet(self, **_kw):
            return self.inbox.pop(0)

        def write_packet(self, ptype: int, body: bytes, **_kw) -> None:
            pass

    stream: Any = _Stream()
    backend: Any = object()
    token = _ENCODE_OCI_CALL_SEQ.set(7)
    try:
        assert _serve_oci_session(stream, backend, 'PYO') == 'PYO'
        assert _ENCODE_OCI_CALL_SEQ.get() == 7
    finally:
        _ENCODE_OCI_CALL_SEQ.reset(token)
