# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Mirror's WebSocket listener (#1989), driven by the client's ws/wss
transport (#1988). All offline: an in-process WsServer over a _DualBackend.

* a client connects over ws:// and runs a query, sync and async;
* a client connects over wss:// (the Mirror's own TLS) and runs a query;
* the origin allow-list rejects a disallowed browser Origin at the handshake,
  while a non-browser client (no Origin) still connects.
"""

from __future__ import annotations

import asyncio
import os
import threading
from collections.abc import Iterator

import pytest

import seerdb
from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
from seerdb.server import ColumnMeta, Result, UnsupportedFeature, credential_lookup
from seerdb.server.backend import Capability
from seerdb.server.launcher import _tls_context

pytest.importorskip('websockets')

from seerdb.server.ws_service import WsServer  # noqa: E402

_WALLET = os.path.join(os.path.dirname(__file__), 'fixtures', 'wallet')
_CA = os.path.join(_WALLET, 'ca_cert.pem')
_CERT = os.path.join(_WALLET, 'server_cert.pem')
_KEY = os.path.join(_WALLET, 'server_key.pem')


class _DualBackend:
    capabilities: frozenset[Capability] = frozenset()

    def authenticate(self, username: str) -> str | None:
        return credential_lookup({'PYO': 'pyo123'}, username)

    def execute(self, sql: str, binds=()) -> Result:
        if 'dual' in sql.lower():
            col = ColumnMeta(
                name=b'DUMMY', data_type=TNS_TYPE_VARCHAR, data_length=1, max_size=1
            )
            return Result(columns=[col], rows=[('X',)])
        raise UnsupportedFeature(sql)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass


def _serve(**extra) -> Iterator[WsServer]:
    server = WsServer(host='127.0.0.1', port=0, backend_factory=_DualBackend, **extra)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.close()
        thread.join(timeout=5)


@pytest.fixture
def ws_mirror() -> Iterator[WsServer]:
    yield from _serve()


@pytest.fixture
def wss_mirror() -> Iterator[WsServer]:
    # Server-auth TLS only: no CA, so the Mirror does not demand a client cert
    # (passing a CA would turn on mutual TLS). The client trusts the CA below.
    yield from _serve(ssl_context=_tls_context(_CERT, _KEY, ''))


def _kwargs(**extra) -> dict:
    return {'user': 'PYO', 'password': 'pyo123', 'timeout': 15000, **extra}


# --------------------------------------------------------------------------- #
# ws:// (plain)
# --------------------------------------------------------------------------- #


def test_a_client_runs_sql_over_ws(ws_mirror: WsServer) -> None:
    conn = seerdb.connect(**_kwargs(dsn=f'ws://127.0.0.1:{ws_mirror.port}/XE'))
    try:
        cur = conn.cursor()
        cur.execute('select * from dual')
        assert cur.fetchone() == ('X',)
    finally:
        conn.close()


def test_a_large_message_is_refused_before_login(ws_mirror: WsServer) -> None:
    # GHSA-wgc5-xh4h-3hhr: websockets holds a whole message before the TNS
    # framer reads any of it, so its cap is a login's until the session has
    # logged in, as the framer's is.
    from websockets.exceptions import ConnectionClosed
    from websockets.sync.client import connect

    ws = connect(f'ws://127.0.0.1:{ws_mirror.port}/', open_timeout=15)
    try:
        ws.send(b'\x00' * (2 << 20))
        with pytest.raises(ConnectionClosed) as closed:
            ws.recv(timeout=10)
        assert closed.value.rcvd is not None and closed.value.rcvd.code == 1009
    finally:
        ws.close()


def test_the_message_cap_rises_with_the_framers_after_login() -> None:
    # GHSA-wgc5-xh4h-3hhr: once the session has logged in, the WebSocket's
    # own cap goes up to the framer's, so a client that sends a large message
    # in one piece is served as before.
    from types import SimpleNamespace
    from typing import Any, cast

    from seerdb.common.ws_transport import WsSocket
    from seerdb.server.framing import (
        PRE_LOGIN_MESSAGE_LIMIT,
        SESSION_MESSAGE_LIMIT,
        PacketStream,
    )

    conn = SimpleNamespace(protocol=SimpleNamespace(max_size=PRE_LOGIN_MESSAGE_LIMIT))
    stream = PacketStream(cast(Any, WsSocket(conn)))
    assert stream.max_message == PRE_LOGIN_MESSAGE_LIMIT
    stream.allow_session_messages()
    assert stream.max_message == SESSION_MESSAGE_LIMIT
    assert conn.protocol.max_size == SESSION_MESSAGE_LIMIT


def test_an_async_client_runs_sql_over_ws(ws_mirror: WsServer) -> None:
    async def run() -> tuple:
        conn = await seerdb.connect_async(
            **_kwargs(dsn=f'ws://127.0.0.1:{ws_mirror.port}/XE')
        )
        async with conn:
            cur = conn.cursor()
            await cur.execute('select * from dual')
            return await cur.fetchone()

    assert asyncio.run(run()) == ('X',)


# --------------------------------------------------------------------------- #
# wss:// (the Mirror's own TLS)
# --------------------------------------------------------------------------- #


def test_a_client_runs_sql_over_wss(wss_mirror: WsServer) -> None:
    conn = seerdb.connect(
        **_kwargs(
            dsn=f'wss://127.0.0.1:{wss_mirror.port}/XE',
            # Trust the fixture CA; the fixture cert carries no 127.0.0.1 name,
            # so skip the hostname match -- the chain is still verified.
            ssl={'ca_certs': _CA, 'check_hostname': False},
        )
    )
    try:
        cur = conn.cursor()
        cur.execute('select * from dual')
        assert cur.fetchone() == ('X',)
    finally:
        conn.close()


def test_an_async_client_runs_sql_over_wss(wss_mirror: WsServer) -> None:
    async def run() -> tuple:
        conn = await seerdb.connect_async(
            **_kwargs(
                dsn=f'wss://127.0.0.1:{wss_mirror.port}/XE',
                ssl={'ca_certs': _CA, 'check_hostname': False},
            )
        )
        async with conn:
            cur = conn.cursor()
            await cur.execute('select * from dual')
            return await cur.fetchone()

    assert asyncio.run(run()) == ('X',)


# --------------------------------------------------------------------------- #
# the origin allow-list (CSWSH defence)
# --------------------------------------------------------------------------- #


@pytest.fixture
def origin_guarded_mirror() -> Iterator[WsServer]:
    yield from _serve(allowed_origins=['https://ok.example'])


def test_a_disallowed_origin_is_rejected_at_the_handshake(
    origin_guarded_mirror: WsServer,
) -> None:
    from websockets.exceptions import InvalidStatus
    from websockets.sync.client import connect

    with pytest.raises(InvalidStatus):
        connect(
            f'ws://127.0.0.1:{origin_guarded_mirror.port}/',
            additional_headers={'Origin': 'https://evil.example'},
            open_timeout=5,
        )


def test_a_non_browser_client_still_connects_with_an_allow_list(
    origin_guarded_mirror: WsServer,
) -> None:
    # The seerdb client is not a browser and sends no Origin, so the allow-list
    # (which admits no-Origin clients) lets it through.
    conn = seerdb.connect(
        **_kwargs(dsn=f'ws://127.0.0.1:{origin_guarded_mirror.port}/XE')
    )
    try:
        cur = conn.cursor()
        cur.execute('select * from dual')
        assert cur.fetchone() == ('X',)
    finally:
        conn.close()
