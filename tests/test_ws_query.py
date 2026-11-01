# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Mirror's thin JSON-over-WebSocket query endpoint (#2371), MVP.

All offline: an in-process WsServer(protocol='query') over a backend, driven by
a plain `websockets` client (not the seerdb client — this endpoint is JSON, not
TNS). Covers login, SELECT, positional binds, DML rowcount, commit/rollback,
rich-type serialization, errors, the origin allow-list, and wss.
"""

from __future__ import annotations

import datetime
import json
import os
import ssl as ssl_mod
import threading
from collections.abc import Iterator
from decimal import Decimal
from typing import Any

import pytest

from seerdb.common.tns_consts import (
    TNS_TYPE_DATE,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_VARCHAR,
)
from seerdb.server import ColumnMeta, Result, UnsupportedFeature, credential_lookup
from seerdb.server.backend import Capability
from seerdb.server.launcher import _tls_context

pytest.importorskip('websockets')

from seerdb.server.ws_service import WsServer  # noqa: E402

_WALLET = os.path.join(os.path.dirname(__file__), 'fixtures', 'wallet')
_CA = os.path.join(_WALLET, 'ca_cert.pem')
_CERT = os.path.join(_WALLET, 'server_cert.pem')
_KEY = os.path.join(_WALLET, 'server_key.pem')


class _QueryBackend:
    capabilities: frozenset[Capability] = frozenset()

    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False

    def authenticate(self, username: str) -> str | None:
        return credential_lookup({'PYO': 'pyo123'}, username)

    def execute(self, sql: str, binds=()) -> Result:
        text = sql.strip().lower()
        if 'types' in text:
            cols = [
                ColumnMeta(
                    name=b'N', data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22
                ),
                ColumnMeta(
                    name=b'D', data_type=TNS_TYPE_DATE, data_length=7, max_size=7
                ),
                ColumnMeta(
                    name=b'R', data_type=TNS_TYPE_RAW, data_length=4, max_size=4
                ),
            ]
            row = (
                Decimal('123.450'),
                datetime.datetime(2024, 1, 2, 3, 4, 5),
                b'\x01\x02\xff',
            )
            return Result(columns=cols, rows=[row])
        if 'echo' in text:
            col = ColumnMeta(
                name=b'V', data_type=TNS_TYPE_VARCHAR, data_length=40, max_size=40
            )
            return Result(columns=[col], rows=[(binds[0] if binds else None,)])
        if 'dual' in text:
            col = ColumnMeta(
                name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
            )
            return Result(columns=[col], rows=[('X',)])
        if text.startswith(('insert', 'update', 'delete')):
            return Result(rowcount=3)
        raise UnsupportedFeature(sql)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _fresh_lockout(monkeypatch) -> None:
    # The failed-login counts are the process's: each test starts with none,
    # and a failure is not delayed.
    from seerdb.server import lockout

    monkeypatch.setattr(lockout, '_failures', {})
    monkeypatch.setattr(lockout, '_DELAY_STEP', 0.0)


def _serve(backend_factory: Any = _QueryBackend, **extra) -> Iterator[WsServer]:
    server = WsServer(
        host='127.0.0.1',
        port=0,
        backend_factory=backend_factory,
        protocol='query',
        **extra,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.close()
        thread.join(timeout=5)


@pytest.fixture
def query_mirror() -> Iterator[WsServer]:
    yield from _serve()


def _connect(port: int, ssl: Any = None):
    from websockets.sync.client import connect

    scheme = 'wss' if ssl else 'ws'
    return connect(f'{scheme}://127.0.0.1:{port}/', ssl=ssl, open_timeout=15)


def _rpc(ws: Any, request: dict) -> dict:
    ws.send(json.dumps(request))
    return json.loads(ws.recv())


def _login(ws: Any, user: str = 'PYO', password: str = 'pyo123') -> dict:
    return _rpc(ws, {'type': 'login', 'user': user, 'password': password})


# --------------------------------------------------------------------------- #


def test_login_then_select(query_mirror: WsServer) -> None:
    ws = _connect(query_mirror.port)
    try:
        assert _login(ws)['type'] == 'login_ok'
        reply = _rpc(ws, {'type': 'query', 'id': 1, 'sql': 'select * from dual'})
        assert reply['type'] == 'result'
        assert reply['id'] == 1
        assert reply['columns'] == [{'name': 'DUMMY', 'type': 'VARCHAR2'}]
        assert reply['rows'] == [['X']]
        assert reply['rowcount'] == 0
    finally:
        ws.close()


def test_positional_bind(query_mirror: WsServer) -> None:
    ws = _connect(query_mirror.port)
    try:
        _login(ws)
        reply = _rpc(ws, {'type': 'query', 'sql': 'select :1 from echo', 'binds': [42]})
        assert reply['rows'] == [[42]]
    finally:
        ws.close()


def test_dml_returns_rowcount(query_mirror: WsServer) -> None:
    ws = _connect(query_mirror.port)
    try:
        _login(ws)
        reply = _rpc(ws, {'type': 'query', 'sql': 'update t set x = 1'})
        assert reply['columns'] == [] and reply['rows'] == [] and reply['rowcount'] == 3
    finally:
        ws.close()


def test_commit_and_rollback(query_mirror: WsServer) -> None:
    ws = _connect(query_mirror.port)
    try:
        _login(ws)
        assert _rpc(ws, {'type': 'commit'})['type'] == 'ok'
        assert _rpc(ws, {'type': 'rollback'})['type'] == 'ok'
    finally:
        ws.close()


def test_rich_types_serialize(query_mirror: WsServer) -> None:
    ws = _connect(query_mirror.port)
    try:
        _login(ws)
        reply = _rpc(ws, {'type': 'query', 'sql': 'select types'})
        (number, when, raw) = reply['rows'][0]
        assert number == '123.450'  # Decimal -> string, precision kept
        assert when == '2024-01-02T03:04:05'  # datetime -> ISO-8601
        assert raw == 'AQL/'  # b'\x01\x02\xff' -> base64
        assert [c['type'] for c in reply['columns']] == ['NUMBER', 'DATE', 'RAW']
    finally:
        ws.close()


def test_unsupported_sql_is_a_statement_error(query_mirror: WsServer) -> None:
    ws = _connect(query_mirror.port)
    try:
        _login(ws)
        reply = _rpc(ws, {'type': 'query', 'id': 9, 'sql': 'select * from nope'})
        assert reply['type'] == 'error'
        assert reply['id'] == 9
        assert reply['code'] == 'UNSUPPORTED'
        # the session survives a statement error
        assert (
            _rpc(ws, {'type': 'query', 'sql': 'select * from dual'})['type'] == 'result'
        )
    finally:
        ws.close()


def test_named_binds_rejected(query_mirror: WsServer) -> None:
    ws = _connect(query_mirror.port)
    try:
        _login(ws)
        reply = _rpc(
            ws, {'type': 'query', 'sql': 'select :a from echo', 'binds': {'a': 1}}
        )
        assert reply['type'] == 'error' and reply['code'] == 'UNSUPPORTED'
    finally:
        ws.close()


def test_bad_credentials_rejected(query_mirror: WsServer) -> None:
    ws = _connect(query_mirror.port)
    try:
        reply = _login(ws, password='wrong')
        assert reply['type'] == 'error' and reply['code'] == 'AUTH'
    finally:
        ws.close()


def test_first_message_must_be_login(query_mirror: WsServer) -> None:
    ws = _connect(query_mirror.port)
    try:
        reply = _rpc(ws, {'type': 'query', 'sql': 'select * from dual'})
        assert reply['type'] == 'error' and reply['code'] == 'PROTOCOL'
    finally:
        ws.close()


# --------------------------------------------------------------------------- #
# the login takes a TNS login's steps
# --------------------------------------------------------------------------- #


def _login_once(port: int, user: str, password: str) -> dict:
    ws = _connect(port)
    try:
        return _login(ws, user, password)
    finally:
        ws.close()


def test_an_unknown_user_is_refused_as_a_wrong_password_is(
    query_mirror: WsServer,
) -> None:
    # GHSA-7xrq-88jc-3p3x: the same answer, so it tells no account apart.
    unknown = _login_once(query_mirror.port, 'NO_SUCH_USER', 'x')
    wrong = _login_once(query_mirror.port, 'PYO', 'wrong')
    assert (
        unknown
        == wrong
        == {
            'type': 'error',
            'code': 'AUTH',
            'message': 'ORA-01017: invalid username/password; logon denied',
        }
    )


def test_failed_logins_lock_a_name(query_mirror: WsServer, monkeypatch) -> None:
    # GHSA-7xrq-88jc-3p3x: the query endpoint counts failures toward the lock
    # the TNS login keeps, and refuses a locked name, ORA-28000.
    from seerdb.server import lockout

    monkeypatch.setattr(lockout, '_attempts', 3)
    for _ in range(3):
        assert _login_once(query_mirror.port, 'PYO', 'wrong')['message'].startswith(
            'ORA-01017'
        )
    assert lockout.is_locked('PYO')
    reply = _login_once(query_mirror.port, 'PYO', 'pyo123')
    assert reply['code'] == 'AUTH' and reply['message'].startswith('ORA-28000')
    lockout.unlock('PYO')
    assert _login_once(query_mirror.port, 'PYO', 'pyo123') == {'type': 'login_ok'}


class _SessionBackend(_QueryBackend):
    opened: list[dict] = []

    def open_session(self, connect_attrs: dict) -> None:
        self.opened.append(connect_attrs)


def test_a_login_opens_the_backends_session() -> None:
    # GHSA-382x-hhhq-35r3: as after a TNS login, the backend's session is
    # opened -- where per-user mode makes it the user's own role -- before any
    # statement runs.
    _SessionBackend.opened = []
    for server in _serve(_SessionBackend):
        assert _login_once(server.port, 'PYO', 'wrong')['code'] == 'AUTH'
        assert _SessionBackend.opened == []
        assert _login_once(server.port, 'PYO', 'pyo123') == {'type': 'login_ok'}
        assert _SessionBackend.opened == [{}]


def test_a_client_that_never_logs_in_is_dropped(
    query_mirror: WsServer, monkeypatch
) -> None:
    # GHSA-wgc5-xh4h-3hhr: within the time a TNS login has.
    from websockets.exceptions import ConnectionClosed

    from seerdb.server import session

    monkeypatch.setattr(session, 'LOGIN_SECONDS', 0.5)
    ws = _connect(query_mirror.port)
    try:
        with pytest.raises(ConnectionClosed):
            ws.recv(timeout=10)
    finally:
        ws.close()


def test_a_large_message_is_refused_before_login_and_taken_after(
    query_mirror: WsServer,
) -> None:
    # GHSA-wgc5-xh4h-3hhr: websockets holds a whole message before the
    # endpoint reads it, so its cap is a login's until the client has logged
    # in, and a session's after.
    from websockets.exceptions import ConnectionClosed

    padding = ' ' * (2 << 20)
    ws = _connect(query_mirror.port)
    try:
        ws.send(json.dumps({'type': 'login', 'user': 'PYO', 'password': padding}))
        with pytest.raises(ConnectionClosed) as closed:
            ws.recv(timeout=10)
        assert closed.value.rcvd is not None and closed.value.rcvd.code == 1009
    finally:
        ws.close()
    ws = _connect(query_mirror.port)
    try:
        assert _login(ws)['type'] == 'login_ok'
        reply = _rpc(ws, {'type': 'query', 'sql': f'select * from dual{padding}'})
        assert reply['rows'] == [['X']]
    finally:
        ws.close()


# --------------------------------------------------------------------------- #
# origin allow-list and wss
# --------------------------------------------------------------------------- #


@pytest.fixture
def origin_guarded() -> Iterator[WsServer]:
    yield from _serve(allowed_origins=['https://ok.example'])


def test_disallowed_origin_rejected(origin_guarded: WsServer) -> None:
    from websockets.exceptions import InvalidStatus
    from websockets.sync.client import connect

    with pytest.raises(InvalidStatus):
        connect(
            f'ws://127.0.0.1:{origin_guarded.port}/',
            additional_headers={'Origin': 'https://evil.example'},
            open_timeout=15,
        )


@pytest.fixture
def wss_query_mirror() -> Iterator[WsServer]:
    yield from _serve(ssl_context=_tls_context(_CERT, _KEY, ''))


def test_the_wss_listener_issues_no_session_tickets(
    wss_query_mirror: WsServer,
) -> None:
    # A TLS 1.3 session ticket raced websockets' sync client's request (#2385).
    sock = wss_query_mirror._server.socket
    assert isinstance(sock, ssl_mod.SSLSocket)
    assert sock.context.num_tickets == 0


def test_wss_connects_every_time(wss_query_mirror: WsServer) -> None:
    # Sixty connects in a row, each opening and logging in. With session tickets
    # about one in twenty lost its request and waited out the server's 10 s open
    # timeout (#2385); sixty in a row passed about one run in twenty.
    ctx = ssl_mod.create_default_context(cafile=_CA)
    ctx.check_hostname = False  # fixture cert carries no 127.0.0.1 name
    for _ in range(60):
        ws = _connect(wss_query_mirror.port, ssl=ctx)
        try:
            assert _login(ws)['type'] == 'login_ok'
        finally:
            ws.close()


def test_query_over_wss(wss_query_mirror: WsServer) -> None:
    ctx = ssl_mod.create_default_context(cafile=_CA)
    ctx.check_hostname = False  # fixture cert carries no 127.0.0.1 name
    ws = _connect(wss_query_mirror.port, ssl=ctx)
    try:
        assert _login(ws)['type'] == 'login_ok'
        assert _rpc(ws, {'type': 'query', 'sql': 'select * from dual'})['rows'] == [
            ['X']
        ]
    finally:
        ws.close()
