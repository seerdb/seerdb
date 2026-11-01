# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Mirror's thin JSON-over-WebSocket query endpoint (#2371), a seerdb
extension and an MVP.

A browser or Node tool runs SQL without a TNS codec: it sends JSON over a
WebSocket **text** frame and gets rows back. The endpoint drives the **same**
:class:`~seerdb.server.backend.Backend` the TNS path does
(``authenticate`` / ``execute`` / ``commit`` / ``rollback``), one layer above
TNS/TTC, so there is no second wire codec. It is served by
:class:`seerdb.server.ws_service.WsServer` with ``protocol='query'``.

Protocol (one JSON object per WS text message, request/response)::

    -> {"type":"login","user":"PYO","password":"pyo123"}
    <- {"type":"login_ok"}
    -> {"type":"query","id":7,"sql":"select 1 from dual","binds":[]}
    <- {"type":"result","id":7,"columns":[{"name":"...","type":"NUMBER"}],
        "rows":[[1]],"rowcount":1}
    -> {"type":"commit"} | {"type":"rollback"}     <- {"type":"ok"}
    <- {"type":"error","id":7,"code":"UNSUPPORTED","message":"..."}

Auth: :func:`seerdb.server.session.password_login`, which takes a TNS login's
steps -- the lock after failed logins, the backend's session opened -- with the
password compared constant-time to the account's secret. Unlike TNS O5LOGON the client
sends its plaintext password, protected by ``wss://`` TLS -- acceptable under
the Mirror's operator-controlled threat model (behind VPN/firewall), and the
agreed MVP. One statement in flight at a time; binds are a positional JSON list
of scalars. Non-scalar values (LOBs, REF CURSORs, OUT binds) are out of MVP
scope.
"""

from __future__ import annotations

import base64
import datetime
import decimal
import json
import logging
from typing import TYPE_CHECKING, Any

from seerdb.common.exceptions import NotSupportedError
from seerdb.common.tns_consts import (
    TNS_TYPE_BDOUBLE,
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
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_ROWID,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
    TNS_TYPE_VECTOR,
)
from seerdb.server.backend import BackendError, UnsupportedFeature
from seerdb.server.framing import SESSION_MESSAGE_LIMIT

if TYPE_CHECKING:
    from seerdb.server.backend import Backend, Result

logger = logging.getLogger('seerdb.server')

# A readable name per TNS type code for the result's column metadata; an
# unmapped code falls back to its number.
_TYPE_NAMES: dict[int, str] = {
    TNS_TYPE_VARCHAR: 'VARCHAR2',
    TNS_TYPE_CHAR: 'CHAR',
    TNS_TYPE_NUMBER: 'NUMBER',
    TNS_TYPE_DATE: 'DATE',
    TNS_TYPE_TIMESTAMP: 'TIMESTAMP',
    TNS_TYPE_TIMESTAMPTZ: 'TIMESTAMP WITH TIME ZONE',
    TNS_TYPE_TIMESTAMPLTZ: 'TIMESTAMP WITH LOCAL TIME ZONE',
    TNS_TYPE_INTERVALYM: 'INTERVAL YEAR TO MONTH',
    TNS_TYPE_INTERVALDS: 'INTERVAL DAY TO SECOND',
    TNS_TYPE_RAW: 'RAW',
    TNS_TYPE_LONG: 'LONG',
    TNS_TYPE_ROWID: 'ROWID',
    TNS_TYPE_CLOB: 'CLOB',
    TNS_TYPE_BLOB: 'BLOB',
    TNS_TYPE_BFLOAT: 'BINARY_FLOAT',
    TNS_TYPE_BDOUBLE: 'BINARY_DOUBLE',
    TNS_TYPE_BOOLEAN: 'BOOLEAN',
    TNS_TYPE_JSON: 'JSON',
    TNS_TYPE_VECTOR: 'VECTOR',
}


def _json_default(value: Any) -> Any:
    # Encode the DB values json cannot represent natively. NUMBER rides as a
    # string so a 38-digit value keeps its precision; dates/timestamps as
    # ISO-8601; RAW/BLOB as base64. Anything else is stringified rather than
    # failing the whole result.
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, datetime.timedelta):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(value)).decode('ascii')
    return str(value)


def _column_name(name: Any) -> str:
    if isinstance(name, (bytes, bytearray)):
        return bytes(name).decode('utf-8', 'replace')
    return str(name)


def _result_payload(result: Result, request_id: Any) -> dict[str, Any]:
    return {
        'type': 'result',
        'id': request_id,
        'columns': [
            {
                'name': _column_name(c.name),
                'type': _TYPE_NAMES.get(c.data_type, str(c.data_type)),
            }
            for c in result.columns
        ],
        'rows': result.rows,
        'rowcount': result.rowcount,
    }


def _binds(raw: Any) -> tuple:
    # MVP: a positional list of scalars. Named (dict) binds are a richer-API
    # follow-up; reject them clearly rather than guessing a bind order.
    if raw is None:
        return ()
    if isinstance(raw, list):
        return tuple(raw)
    if isinstance(raw, dict):
        raise NotSupportedError(
            'named binds are not supported yet; use a positional list'
        )
    raise NotSupportedError('binds must be a JSON list of scalar values')


def _error_payload(request_id: Any, exc: Exception) -> dict[str, Any]:
    code = (
        'UNSUPPORTED'
        if isinstance(exc, (NotSupportedError, UnsupportedFeature))
        else 'ERROR'
    )
    return {'type': 'error', 'id': request_id, 'code': code, 'message': str(exc)}


def _send(conn: Any, payload: dict[str, Any]) -> None:
    conn.send(json.dumps(payload, default=_json_default))


def _parse(message: Any) -> dict[str, Any]:
    if isinstance(message, (bytes, bytearray)):
        message = bytes(message).decode('utf-8', 'replace')
    obj = json.loads(message)
    if not isinstance(obj, dict):
        raise ValueError('each message must be a JSON object')
    return obj


def serve_query_session(conn: Any, backend: Backend) -> str | None:
    """Run one JSON-over-WebSocket query session on ``conn`` against ``backend``.

    Logs the client in first (plaintext password over the wss TLS, as a TNS
    login does otherwise), then serves query / commit / rollback
    until the client disconnects. Returns the logged-in user for the caller's
    log, or None if the session never authenticated. Backend calls run through
    the same per-call context isolation the TNS path uses."""
    from websockets.exceptions import ConnectionClosed

    from seerdb.server.session import LOGIN_SECONDS, _IsolatedBackend, password_login

    be = _IsolatedBackend(backend)

    # Login must come first, and within the time a TNS login has
    # (GHSA-wgc5-xh4h-3hhr).
    try:
        login = _parse(conn.recv(timeout=LOGIN_SECONDS))
    except (ConnectionClosed, TimeoutError):
        return None
    except (ValueError, json.JSONDecodeError) as exc:
        _send(conn, _error_payload(None, ValueError(f'bad login message: {exc}')))
        return None
    if login.get('type') != 'login':
        _send(
            conn,
            {
                'type': 'error',
                'code': 'PROTOCOL',
                'message': 'first message must be a login',
            },
        )
        return None
    username = str(login.get('user', ''))
    password = str(login.get('password', ''))
    # As a TNS login: locked names refused, failures delayed and counted, and
    # the backend's session opened (GHSA-382x-hhhq-35r3, GHSA-7xrq-88jc-3p3x).
    try:
        password_login(be, username, password)
    except BackendError as exc:
        _send(conn, {'type': 'error', 'code': 'AUTH', 'message': exc.ora_message})
        return None
    # A logged-in session's statements may be as large as a TNS session's.
    conn.protocol.max_size = SESSION_MESSAGE_LIMIT
    _send(conn, {'type': 'login_ok'})

    # Query / transaction loop.
    while True:
        try:
            request = _parse(conn.recv())
        except ConnectionClosed:
            break
        except (ValueError, json.JSONDecodeError) as exc:
            _send(conn, _error_payload(None, ValueError(f'bad message: {exc}')))
            continue
        kind = request.get('type')
        request_id = request.get('id')
        try:
            if kind == 'query':
                sql = request.get('sql')
                if not isinstance(sql, str) or not sql:
                    raise ValueError('query needs a non-empty "sql" string')
                result = be.execute(sql, _binds(request.get('binds')))
                _send(conn, _result_payload(result, request_id))
            elif kind == 'commit':
                be.commit()
                _send(conn, {'type': 'ok', 'id': request_id})
            elif kind == 'rollback':
                be.rollback()
                _send(conn, {'type': 'ok', 'id': request_id})
            else:
                _send(
                    conn,
                    {
                        'type': 'error',
                        'id': request_id,
                        'code': 'PROTOCOL',
                        'message': f'unknown message type {kind!r}',
                    },
                )
        except ConnectionClosed:
            break
        except (
            Exception
        ) as exc:  # a backend/SQL error fails the statement, not the session
            _send(conn, _error_payload(request_id, exc))
    return username
