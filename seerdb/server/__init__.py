# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server side of the TNS/TTC protocol — the "Mirror".

seerdb is a *client*: it decodes what an Oracle server puts on the wire. This
subpackage is the inverse — it *answers* that protocol for real Oracle clients
(sqlplus, python-oracledb, SeerODBC), so a non-Oracle backend (e.g. SQLite or
PostgreSQL) can sit behind it.

**An initial implementation, a technology preview until general
availability.** The Mirror ships with seerdb (``pip install "seerdb[mirror]"``)
to be tried, not yet run in production. Until general availability it stays
outside the semantic-versioning promise the client (DB-API 2.0) surface keeps:
its API, its command line and its behaviour may change in any release, a minor
or patch one included. ``__provisional__`` says so to
code, and a Mirror logs it when it starts serving. Treat
:func:`~seerdb.server.service.serve` / :class:`~seerdb.server.service.Server`
and everything under ``seerdb.server`` accordingly.

A live client logs in and runs SQL end-to-end against a pluggable
:class:`~seerdb.server.backend.Backend`: the handshake, O5LOGON auth (both the
thin and the sqlplus/OCI dialects), describe, rows, bind variables, DML / DDL,
transactions, batched fetch, and LOBs. ``seerdb-mirror`` (or ``python -m
seerdb.server``) starts one from the command line; ``seerdb-mirror observe`` runs
the observation listener that decodes and logs what a client puts on the wire.
"""

from __future__ import annotations

#: The Mirror is a technology preview: outside the version promise the client
#: keeps.
__provisional__ = True

from seerdb.common.datatypes import BcDate, BFile
from seerdb.common.tns import (
    ColumnMeta,
    ExecRequest,
    FetchRequest,
    encode_describe,
    encode_error,
    encode_fetch_response,
    encode_more_rows,
    encode_query_response,
    encode_rows,
    encode_status,
    parse_exec,
    parse_fetch,
)
from seerdb.server.backend import (
    Backend,
    BackendError,
    BinaryDoubleValue,
    BinaryFloatValue,
    BindVar,
    BlobValue,
    Capability,
    ClobValue,
    Credentials,
    CursorResult,
    DateValue,
    LtzValue,
    Result,
    UnsupportedFeature,
    VarcharValue,
    as_declared_type,
    credential_lookup,
)
from seerdb.server.framing import PacketStream
from seerdb.server.handshake import (
    ConnectRequest,
    encode_accept,
    encode_dty_reply,
    encode_pro_reply,
    parse_connect,
)
from seerdb.server.listener import Listener
from seerdb.server.service import BackendFactory, Server, serve
from seerdb.server.session import handle_login, serve_session
from seerdb.server.ws_query import serve_query_session
from seerdb.server.ws_service import WsServer, serve_ws

__all__ = [
    'BFile',
    'BcDate',
    'Backend',
    'BackendError',
    'BackendFactory',
    'BinaryDoubleValue',
    'BinaryFloatValue',
    'BindVar',
    'BlobValue',
    'Capability',
    'ClobValue',
    'ColumnMeta',
    'ConnectRequest',
    'Credentials',
    'CursorResult',
    'ExecRequest',
    'FetchRequest',
    'Listener',
    'DateValue',
    'LtzValue',
    'PacketStream',
    'Result',
    'Server',
    'UnsupportedFeature',
    'VarcharValue',
    'WsServer',
    'as_declared_type',
    'credential_lookup',
    'encode_accept',
    'encode_describe',
    'encode_error',
    'encode_dty_reply',
    'encode_fetch_response',
    'encode_more_rows',
    'encode_pro_reply',
    'encode_query_response',
    'encode_rows',
    'encode_status',
    'handle_login',
    'parse_connect',
    'parse_exec',
    'parse_fetch',
    'serve',
    'serve_session',
    'serve_query_session',
    'serve_ws',
]
