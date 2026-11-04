# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# PEP 249 (DB-API 2.0) module-level attributes.
apilevel = '2.0'
threadsafety = 1  # threads may share the module, not connections
paramstyle = 'named'  # bind variables not yet wired through Cursor

from typing import TYPE_CHECKING

from seerdb.client.aconnection import AsyncOracleConnect
from seerdb.client.apool import AsyncPool
from seerdb.client.aq import DeqOptions, EnqOptions, MessageProperties, Queue
from seerdb.client.connection import OracleConnect, Xid
from seerdb.client.cursor import FetchInfo
from seerdb.client.enums import TransactionPriority
from seerdb.client.pipeline import (
    Pipeline,
    PipelineOp,
    PipelineOpResult,
    PipelineOpType,
    create_pipeline,
)
from seerdb.client.pool import Pool
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


def connect(*args, **kwargs) -> OracleConnect:
    """PEP 249 connect() factory. Returns a connected OracleConnect."""
    Conn = OracleConnect(*args, **kwargs)
    Conn.connect()
    return Conn


async def connect_async(*args, **kwargs) -> AsyncOracleConnect:
    """Async counterpart to `connect()`. Returns a connected
    `AsyncOracleConnect`. Same constructor arguments as `connect`."""
    Conn = AsyncOracleConnect(*args, **kwargs)
    await Conn.connect()
    return Conn


async def create_pool_async(*args, **kwargs) -> AsyncPool:
    """Create an `AsyncPool` and pre-warm `min` connections.

    Same keyword arguments as `create_pool` (plus the regular
    `seerdb.connect()` kwargs forwarded to each pooled connection).
    """
    Pool_ = AsyncPool(*args, **kwargs)
    await Pool_.prewarm()
    return Pool_


def create_pool(*args, **kwargs) -> Pool:
    """Create a `Pool` of authenticated connections.

    All `seerdb.connect()` keyword arguments are accepted and forwarded
    to each pooled connection. Pool-specific knobs:

      - ``min`` / ``max`` (default 1 / 4): bounds on the pool size.
      - ``increment`` (default 1): how aggressively the pool grows
        (reserved for future load-aware behaviour; currently grows by
        one connection at a time on demand).
      - ``timeout`` (default 30s): how long `acquire()` blocks when the
        pool is at `max` before raising `InterfaceError`. `None` waits
        forever.
      - ``idle_timeout`` (default 60s): a free connection idle this
        long gets a ``SELECT 1 FROM DUAL`` health-check on the next
        acquire. `None` disables the check.
      - ``health_check`` (default True): set False to skip pings
        entirely.
    """
    return Pool(*args, **kwargs)


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
    'create_pool',
    'create_pool_async',
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
