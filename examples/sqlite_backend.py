# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A SQLite backend for the Mirror — stdlib only, the reference Backend.

Point a Mirror at a SQLite database and thin-dialect Oracle clients (seerdb,
SeerODBC) can run real SQL against it. SQLite's permissive typing accepts
Oracle-ish DDL (``NUMBER``, ``VARCHAR2(n)``) via type affinity, so plain tables
"just work". SQLite carries no static column types, so the Mirror infers each
result column's Oracle type from its values.

This lives outside ``seerdb`` core (it is only a demo/adapter), but adds no
dependency — ``sqlite3`` is in the standard library.
"""

from __future__ import annotations

import datetime
import re
import sqlite3
from collections.abc import Sequence
from decimal import Decimal

# Oracle numbered/named binds (:1, :name) → SQLite positional '?'. The negative
# lookbehind leaves any '::' cast untouched.
_ORACLE_BIND = re.compile(r'(?<!:):\w+')

from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    ORA_INVALID_SQL_STATEMENT,
    TNS_TYPE_BLOB,
    TNS_TYPE_CLOB,
    TNS_TYPE_DATE,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_VARCHAR,
)

# A simple single-table SELECT, for looking a column's declared type back up.
# SQLite infers a result column's Oracle type from its value, which can't tell a
# LONG from a VARCHAR2 or a CLOB from either (all text), nor a BLOB from a RAW
# (both bytes) — so for these the backend consults the table's declared types.
# A LONG / LONG RAW streams inline (#407); a CLOB / BLOB is fetched over the
# TTI_LOBOPS locator path (#405). Keying off the declared type (not the value
# size) keeps a plain VARCHAR2 / RAW value inline for thin clients, which have no
# Mirror-side LOB emit yet.
_SELECT_FROM = re.compile(r'\bfrom\s+"?(\w+)"?', re.IGNORECASE)
_DECLARED_STREAMED_TYPES = {
    'LONG': (TNS_TYPE_LONG, 0),
    'LONG RAW': (TNS_TYPE_LONGRAW, 0),
    'CLOB': (TNS_TYPE_CLOB, 4000),  # a LOB describes with data_length 4000
    'BLOB': (TNS_TYPE_BLOB, 4000),
}
from seerdb.common.sqltext import strip_returning_into
from seerdb.server import (
    BackendError,
    BindVar,
    Capability,
    ColumnMeta,
    Credentials,
    DateValue,
    Result,
    credential_lookup,
)


def _adapt_int(value: int) -> int | float:
    # SQLite's INTEGER is 64-bit; an in-range int stays exact, a larger one (an
    # Oracle NUMBER can hold ~38 digits) falls back to REAL.
    if -(2**63) <= value < 2**63:
        return value
    return float(value)


# SQLite stores no real temporal type, so DATE/TIMESTAMP survive a round trip
# only if we (de)serialise them ourselves. The stdlib's built-in date/timestamp
# adapters are deprecated (3.12) and gone in newer Python, so register explicit
# ISO-8601 ones — module-global, matching sqlite3's own registry scope. A
# TIMESTAMP column round-trips microseconds; a DATE column keeps day precision.
def _register_codecs() -> None:
    sqlite3.register_adapter(datetime.date, datetime.date.isoformat)
    sqlite3.register_adapter(datetime.datetime, lambda dt: dt.isoformat(sep=' '))
    # A DATE bind is a DateValue, a datetime that says so; sqlite3 looks an
    # adapter up by the exact type, so it needs one of its own.
    sqlite3.register_adapter(DateValue, lambda dt: dt.isoformat(sep=' '))
    # A DATE bind arrives over the wire as a midnight datetime, so a DATE column
    # may hold 'YYYY-MM-DD HH:MM:SS'; keep only the date part (leading 10 chars).
    sqlite3.register_converter(
        'date', lambda blob: datetime.date.fromisoformat(blob.decode()[:10])
    )
    sqlite3.register_converter(
        'timestamp', lambda blob: datetime.datetime.fromisoformat(blob.decode())
    )
    # A fractional NUMBER bind decodes to a Decimal, which sqlite3 refuses
    # natively. SQLite has no exact-decimal storage class, so bind it as REAL
    # (float) — the same lossy-but-numeric form this backend already infers for
    # NUMBER columns. Integral NUMBERs arrive as int and need no adapter.
    sqlite3.register_adapter(Decimal, float)
    # An Oracle NUMBER integer beyond SQLite's 64-bit INTEGER range can't be
    # stored as one; _adapt_int keeps in-range ints exact and spills larger ones
    # to REAL (lossy, like Decimal) rather than leaking sqlite3's "int too large"
    # as an ORA-00600.
    sqlite3.register_adapter(int, _adapt_int)


_register_codecs()


def _column_meta(name: str, values: list, declared: str | None = None) -> ColumnMeta:
    # Infer an Oracle column type from the first non-NULL value. Oracle folds
    # unquoted identifiers to upper-case, so match that on the name.
    ident = name.upper().encode('utf-8')
    # A LONG / LONG RAW (streamed, #407) or CLOB / BLOB (LOB locator, #405) can't
    # be told from a VARCHAR2 / RAW by its value, so honour the declared type when
    # the SELECT let us recover it. A LOB describes with data_length 4000; a LONG
    # with 0 (unbounded); both leave max_size 0.
    streamed = _DECLARED_STREAMED_TYPES.get((declared or '').upper())
    if streamed is not None:
        data_type, data_length = streamed
        return ColumnMeta(
            name=ident, data_type=data_type, data_length=data_length, max_size=0
        )
    sample = next((v for v in values if v is not None), None)
    if isinstance(sample, bool):
        # bool is an int subclass; a NUMBER either way, matched first for clarity.
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22
        )
    if isinstance(sample, (int, float)):
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_NUMBER, data_length=22, max_size=22
        )
    if isinstance(sample, datetime.datetime):
        # datetime is a date subclass, so match it before the plain-date branch:
        # a declared TIMESTAMP column keeps its time-of-day and sub-second parts.
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_TIMESTAMP, data_length=11, max_size=11
        )
    if isinstance(sample, datetime.date):
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_DATE, data_length=7, max_size=7
        )
    if isinstance(sample, bytes):
        width = max((len(v) for v in values if isinstance(v, bytes)), default=1)
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_RAW, data_length=width, max_size=width
        )
    width = max((len(str(v)) for v in values if v is not None), default=1)
    return ColumnMeta(
        name=ident, data_type=TNS_TYPE_VARCHAR, data_length=width, max_size=width
    )


class SqliteBackend:
    """A :class:`~seerdb.server.Backend` over a stdlib ``sqlite3`` connection.

    One instance per Mirror session. Use ``:memory:`` for an isolated
    per-session database, or a file path to share and persist data across
    sessions. ``credentials`` (username → password) is the login store the
    Mirror authenticates clients against — auth lives with the backend.
    """

    capabilities = frozenset({Capability.TRANSACTIONS})
    # This demo presents 11.2: it cannot back the 12c+/23ai wire formats a higher
    # advertised version would invite a client to request, so it pins the floor
    # the whole conformance suite is baselined at (the Mirror honours this).
    field_version = FIELD_VERSION_11_2

    def __init__(
        self, database: str = ':memory:', *, credentials: Credentials | None = None
    ) -> None:
        # PARSE_DECLTYPES turns a column declared DATE / TIMESTAMP back into a
        # datetime.date / datetime.datetime via the converters registered above.
        self._conn = sqlite3.connect(database, detect_types=sqlite3.PARSE_DECLTYPES)
        self._credentials = credentials or {}

    def authenticate(self, username: str) -> str | None:
        return credential_lookup(self._credentials, username)

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        if binds:
            sql = _ORACLE_BIND.sub('?', sql)
        # A typed NULL arrives as a BindVar (#699); SQLite types a value, not a
        # placeholder, so the declaration has nothing to say here.
        values = tuple(b.value if isinstance(b, BindVar) else b for b in binds)
        try:
            cursor = self._conn.execute(sql, values)
        except sqlite3.Error as exc:
            # A SQLite failure surfaces as a clean ORA error — never a desync.
            raise BackendError(str(exc), ora_code=ORA_INVALID_SQL_STATEMENT) from exc
        if cursor.description is None:
            # DDL / DML: no result set, just an affected-row count.
            return Result(rowcount=max(cursor.rowcount, 0))
        rows = cursor.fetchall()
        declared = self._declared_types(sql)
        columns = [
            _column_meta(
                description[0],
                [row[index] for row in rows],
                declared.get(description[0].upper()),
            )
            for index, description in enumerate(cursor.description)
        ]
        return Result(columns=columns, rows=rows)

    def execute_returning(self, sql: str, rows: Sequence[Sequence]) -> Result:
        # DML ... RETURNING col INTO :b (#689). SQLite has the feature from 3.35
        # but spells it without the INTO part, handing the columns back as rows
        # rather than assigning them to binds, so the clause is trimmed to the
        # form it knows and the rows are read.
        #
        # The binds the clause fills carry no value and are dropped: their
        # placeholders are gone from the trimmed text.
        statement = _ORACLE_BIND.sub('?', strip_returning_into(sql))
        returned: list[list[tuple]] = []
        affected = 0
        for row in rows:
            values = tuple(v for v in row if not isinstance(v, BindVar))
            try:
                cursor = self._conn.execute(statement, values)
                iteration = list(cursor.fetchall())
            except sqlite3.Error as exc:
                raise BackendError(
                    str(exc), ora_code=ORA_INVALID_SQL_STATEMENT
                ) from exc
            returned.append(iteration)
            # A RETURNING statement gives back one row per row it changed, so the
            # count is the rows read rather than a separate report.
            affected += len(iteration)
        return Result(rowcount=affected, returned_rows=returned)

    def _declared_types(self, sql: str) -> dict[str, str]:
        # Map result column name (upper-case) -> declared SQLite type, for a plain
        # single-table SELECT, so a LONG / LONG RAW column can be typed from the
        # schema rather than its value (#407). Joins/subqueries are skipped — the
        # column-to-table mapping is ambiguous there.
        lowered = sql.lower()
        if not lowered.lstrip().startswith('select') or ' join ' in lowered:
            return {}
        match = _SELECT_FROM.search(sql)
        if not match:
            return {}
        try:
            info = self._conn.execute(
                f'PRAGMA table_info("{match.group(1)}")'
            ).fetchall()
        except sqlite3.Error:
            # An expression/derived source with no such table — nothing to map.
            return {}
        return {row[1].upper(): (row[2] or '') for row in info}

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()
