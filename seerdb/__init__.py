# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# PEP 249 (DB-API 2.0) module-level attributes.
apilevel = '2.0'
threadsafety = 1  # threads may share the module, not connections
paramstyle = 'named'  # bind variables not yet wired through Cursor

from typing import TYPE_CHECKING

from seerdb.client.aconnection import AsyncOracleConnect
from seerdb.client.apool import AsyncPool, AsyncPooledConnection
from seerdb.client.aq import DeqOptions, EnqOptions, MessageProperties, Queue
from seerdb.client.connection import OracleConnect, Xid
from seerdb.client.cursor import FetchInfo
from seerdb.client.defaults import Defaults, defaults
from seerdb.client.enums import TransactionPriority
from seerdb.client.pipeline import (
    Pipeline,
    PipelineOp,
    PipelineOpResult,
    PipelineOpType,
    create_pipeline,
)
from seerdb.client.pool import (
    POOL_GETMODE_FORCEGET,
    POOL_GETMODE_NOWAIT,
    POOL_GETMODE_TIMEDWAIT,
    POOL_GETMODE_WAIT,
    Pool,
    PooledConnection,
    get_pool,
    named_pool,
    settle_pool_alias,
    take_pool_alias,
)
from seerdb.client.sqlnames import enquote_literal, enquote_name, is_simple_sql_name
from seerdb.common.datatypes import (
    BINARY,
    CURSOR,
    DATETIME,
    DB_TYPE_BFILE,
    DB_TYPE_BINARY_DOUBLE,
    DB_TYPE_BINARY_FLOAT,
    DB_TYPE_BINARY_INTEGER,
    DB_TYPE_BLOB,
    DB_TYPE_BOOLEAN,
    DB_TYPE_CHAR,
    DB_TYPE_CLOB,
    DB_TYPE_CURSOR,
    DB_TYPE_DATE,
    DB_TYPE_INTERVAL_DS,
    DB_TYPE_INTERVAL_YM,
    DB_TYPE_JSON,
    DB_TYPE_LONG,
    DB_TYPE_LONG_RAW,
    DB_TYPE_NCHAR,
    DB_TYPE_NCLOB,
    DB_TYPE_NUMBER,
    DB_TYPE_NVARCHAR,
    DB_TYPE_OBJECT,
    DB_TYPE_RAW,
    DB_TYPE_ROWID,
    DB_TYPE_TIMESTAMP,
    DB_TYPE_TIMESTAMP_LTZ,
    DB_TYPE_TIMESTAMP_TZ,
    DB_TYPE_UROWID,
    DB_TYPE_VARCHAR,
    DB_TYPE_VECTOR,
    DB_TYPE_XMLTYPE,
    JSON,
    NUMBER,
    ROWID,
    STRING,
    Binary,
    BinaryDouble,
    BinaryFloat,
    Date,
    DateFromTicks,
    IntervalYM,
    Time,
    TimeFromTicks,
    Timestamp,
    TimestampFromTicks,
    Var,
)
from seerdb.common.dbobject import DbObject, DbObjectType, DbRef
from seerdb.common.end_user_sec import (
    EndUserSecurityContext,
    create_end_user_security_context,
)
from seerdb.common.exceptions import (
    DatabaseError,
    DataError,
    Error,
    IntegrityError,
    InterfaceError,
    InternalError,
    NotSupportedError,
    OperationalError,
    ProgrammingError,
    Warning,
)
from seerdb.common.tns import _CLIENT_VERSION as __version__
from seerdb.common.tns_consts import (
    PURITY_DEFAULT,
    PURITY_NEW,
    PURITY_SELF,
    TPC_BEGIN_JOIN,
    TPC_BEGIN_NEW,
    TPC_BEGIN_PROMOTE,
    TPC_BEGIN_RESUME,
    TPC_END_NORMAL,
    TPC_END_SUSPEND,
)
from seerdb.common.vector import SparseVector

if TYPE_CHECKING:
    # Type-checker view only. At runtime `seerdb.serve` / `seerdb.Server` are
    # resolved lazily by __getattr__ below, so importing seerdb never loads
    # the Mirror.
    from seerdb.server import Server, serve  # noqa: F401 (runtime: __getattr__)


def _alias_only(pool_alias: str, args: tuple, kwargs: dict) -> None:
    # A connection from a named pool takes the pool's settings: anything else
    # given would be ignored, so it is refused. python-oracledb ignores it.
    if args or kwargs:
        raise ProgrammingError(
            'connect(pool_alias=...) takes no other arguments: the pool '
            f'"{pool_alias}" sets them'
        )


def connect(*args, pool_alias: str | None = None, **kwargs):
    """PEP 249 connect() factory. Returns a connected OracleConnect.

    With ``pool_alias``, takes a connection from the pool created with that
    alias instead (#2459): its `close()` hands it back to the pool."""
    if pool_alias is not None:
        _alias_only(pool_alias, args, kwargs)
        Named = named_pool(pool_alias, Pool)
        return PooledConnection(Named, Named.acquire()._conn)
    Conn = OracleConnect(*args, **kwargs)
    Conn.connect()
    return Conn


async def connect_async(*args, pool_alias: str | None = None, **kwargs):
    """Async counterpart to `connect()`. Returns a connected
    `AsyncOracleConnect`. Same constructor arguments as `connect`, and
    ``pool_alias`` takes a connection from a named `AsyncPool`."""
    if pool_alias is not None:
        _alias_only(pool_alias, args, kwargs)
        Named = named_pool(pool_alias, AsyncPool)
        return AsyncPooledConnection(Named, await Named._acquire_one())
    Conn = AsyncOracleConnect(*args, **kwargs)
    await Conn.connect()
    return Conn


async def create_pool_async(
    *args, pool_alias: str | None = None, **kwargs
) -> AsyncPool:
    """Create an `AsyncPool` and pre-warm `min` connections.

    Same keyword arguments as `create_pool` (plus the regular
    `seerdb.connect()` kwargs forwarded to each pooled connection).
    """
    if pool_alias is not None:
        take_pool_alias(pool_alias)
    try:
        Pool_ = AsyncPool(*args, **kwargs)
        await Pool_.prewarm()
    except BaseException:
        if pool_alias is not None:
            settle_pool_alias(pool_alias, None)
        raise
    if pool_alias is not None:
        settle_pool_alias(pool_alias, Pool_)
    return Pool_


def create_pool(*args, pool_alias: str | None = None, **kwargs) -> Pool:
    """Create a `Pool` of authenticated connections.

    All `seerdb.connect()` keyword arguments are accepted and forwarded
    to each pooled connection. Pool-specific knobs:

      - ``min`` / ``max`` (default 1 / 4): bounds on the pool size.
      - ``increment`` (default 1): how aggressively the pool grows
        (reserved for future load-aware behaviour; currently grows by
        one connection at a time on demand).
      - ``timeout`` (default 30s): how long `acquire()` blocks when the
        pool is at `max` before raising `InterfaceError`. `None` waits
        forever. Unlike python-oracledb's `timeout`, it is not about
        idle connections; `max_idle_session` is.
      - ``getmode``: what `acquire()` does at `max`, overriding `timeout`:
        ``POOL_GETMODE_WAIT`` waits, ``POOL_GETMODE_NOWAIT`` raises at
        once, ``POOL_GETMODE_TIMEDWAIT`` waits up to ``wait_timeout``
        milliseconds, ``POOL_GETMODE_FORCEGET`` opens a connection past
        `max`, closed again on release.
      - ``ping_interval`` (default 60s): a free connection idle this
        long gets a ``SELECT 1 FROM DUAL`` health-check on the next
        acquire. Negative disables it, 0 checks on every acquire.
      - ``idle_timeout`` / ``health_check``: the older spelling of
        ``ping_interval`` (`None` / `False` disable the check); give one
        or the other.
      - ``max_lifetime_session`` (default 0, no limit): seconds a
        connection may live; an older one is closed on acquire or
        release, never while in use.
      - ``max_idle_session`` (default 0, no limit): seconds a free
        connection above `min` may stay idle. Checked on acquire and
        release; the pool has no background thread.
      - ``session_callback``: called as ``callback(connection, None)`` the
        first time each connection is handed out, to set its session up
        once; awaited on an `AsyncPool` when it returns an awaitable. If it
        raises, the connection goes back to the pool and the next caller to
        get it runs the callback again. The second argument is the requested
        tag, which seerdb does not have.
      - ``pool_alias``: a name `seerdb.get_pool()` returns the pool by, and
        `seerdb.connect(pool_alias=...)` takes a connection from it with.
        Closing the pool frees the name.
    """
    if pool_alias is not None:
        take_pool_alias(pool_alias)
    try:
        Pool_ = Pool(*args, **kwargs)
    except BaseException:
        if pool_alias is not None:
            settle_pool_alias(pool_alias, None)
        raise
    if pool_alias is not None:
        settle_pool_alias(pool_alias, Pool_)
    return Pool_


# The Mirror server API (`seerdb.serve` / `seerdb.Server`) is resolved on first
# access rather than imported eagerly, so `import seerdb` never pulls in
# seerdb.server: a client pays nothing for the Mirror shipping beside it.
_LAZY = frozenset({'serve', 'Server'})


def __getattr__(name: str):
    if name in _LAZY:
        from seerdb import server

        return getattr(server, name)
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')


__all__ = [
    '__version__',
    'apilevel',
    'threadsafety',
    'paramstyle',
    'connect',
    'connect_async',
    'POOL_GETMODE_FORCEGET',
    'POOL_GETMODE_NOWAIT',
    'POOL_GETMODE_TIMEDWAIT',
    'POOL_GETMODE_WAIT',
    'create_pool',
    'create_pool_async',
    'get_pool',
    'OracleConnect',
    'AsyncOracleConnect',
    'Pool',
    'AsyncPool',
    'BinaryFloat',
    'BinaryDouble',
    'IntervalYM',
    'JSON',
    'SparseVector',
    'FetchInfo',
    'Defaults',
    'defaults',
    'Var',
    'DbObject',
    'DbObjectType',
    'DbRef',
    'Xid',
    'enquote_literal',
    'enquote_name',
    'is_simple_sql_name',
    'Queue',
    'MessageProperties',
    'EnqOptions',
    'DeqOptions',
    'Pipeline',
    'PipelineOp',
    'PipelineOpResult',
    'PipelineOpType',
    'TransactionPriority',
    'create_pipeline',
    'create_end_user_security_context',
    'EndUserSecurityContext',
    'TPC_BEGIN_NEW',
    'TPC_BEGIN_JOIN',
    'TPC_BEGIN_RESUME',
    'TPC_BEGIN_PROMOTE',
    'TPC_END_NORMAL',
    'TPC_END_SUSPEND',
    'PURITY_DEFAULT',
    'PURITY_NEW',
    'PURITY_SELF',
    'NUMBER',
    'STRING',
    # The rest of the PEP 249 module interface (#683).
    'BINARY',
    'DATETIME',
    'ROWID',
    'Binary',
    'Date',
    'DateFromTicks',
    'Time',
    'TimeFromTicks',
    'Timestamp',
    'TimestampFromTicks',
    'DB_TYPE_NUMBER',
    'DB_TYPE_VARCHAR',
    'DB_TYPE_NVARCHAR',
    'DB_TYPE_NCHAR',
    'DB_TYPE_RAW',
    'DB_TYPE_DATE',
    'CURSOR',
    'DB_TYPE_CURSOR',
    'DB_TYPE_TIMESTAMP',
    'DB_TYPE_TIMESTAMP_TZ',
    'DB_TYPE_BINARY_FLOAT',
    'DB_TYPE_BINARY_DOUBLE',
    'DB_TYPE_BINARY_INTEGER',
    'DB_TYPE_INTERVAL_DS',
    'DB_TYPE_INTERVAL_YM',
    'DB_TYPE_CHAR',
    'DB_TYPE_LONG',
    'DB_TYPE_LONG_RAW',
    'DB_TYPE_ROWID',
    'DB_TYPE_UROWID',
    'DB_TYPE_CLOB',
    'DB_TYPE_NCLOB',
    'DB_TYPE_BLOB',
    'DB_TYPE_TIMESTAMP_LTZ',
    'DB_TYPE_JSON',
    'DB_TYPE_BOOLEAN',
    'DB_TYPE_VECTOR',
    'DB_TYPE_OBJECT',
    'DB_TYPE_BFILE',
    'DB_TYPE_XMLTYPE',
    'Warning',
    'Error',
    'InterfaceError',
    'DatabaseError',
    'DataError',
    'OperationalError',
    'IntegrityError',
    'InternalError',
    'ProgrammingError',
    'NotSupportedError',
]
