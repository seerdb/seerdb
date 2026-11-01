# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A live client runs real SQL against a PostgreSQL-backed Mirror.

Skips cleanly when psycopg is not installed or no PostgreSQL is reachable
(``MIRROR_PG`` overrides the connection string), so CI without a database just
skips — the same pattern as the live-Oracle integration tests.
"""

from __future__ import annotations

import array
import contextlib
import datetime
import os
import re
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterator
from decimal import Decimal
from typing import Any, TypeVar, cast

import pytest

import seerdb
from seerdb.common.vector import SparseVector
from seerdb.server import PacketStream, serve_session

psycopg = pytest.importorskip('psycopg')
from psycopg.conninfo import make_conninfo  # noqa: E402

from seerdb.server.accounts import _ACCOUNTS_READY  # noqa: E402
from seerdb.server.backends.postgres import (  # noqa: E402
    _DICTIONARY_STAMP,
    _HELPER_FUNCTIONS_DDL,
    _IS_DDL,
    _NO_OP,
    _REF_SELECT,
    _ROUTINE_MARK,
    OraInterval,
    PostgresBackend,
    _backend_error,
    _bc_date_loader,
    _bind_slots,
    _call_argument_error,
    _call_arguments,
    _checked_error_rows,
    _column_annotations,
    _computed_column_types,
    _declared_columns,
    _idioms_and_rules,
    _interval_leaf,
    _iot_primary_key,
    _object_column_meta,
    _object_type_oid,
    _occurrence_binds,
    _oracle_reference,
    _package_rights,
    _parse_out_assignments,
    _pg_oid_of,
    _refused_orafce,
    _reject_nonfinite_vectors,
    _reject_unsupported_ddl_types,
    _several_statements,
    _strip_leading_comments,
    _tds_scalar,
    _through_synonyms,
    _to_interval_ym,
    _translate_admin,
    _translate_binds,
    _translate_connect_by,
    _translate_ddl,
    _translate_idioms,
    _translate_json_constructor_values,
    _translate_plsql_block,
    _translate_routine_ddl,
    _translate_routine_types,
    _translate_signed_year,
    _translate_vector_functions,
    _txn_priority_setting,
    _typed_datetime_operands,
    _urowid_expression,
)

_T = TypeVar('_T')


def _present(value: _T | None) -> _T:
    # What the test set up is there: a type it created, a member it declared.
    assert value is not None
    return value


def _fetched_row(cursor: Any) -> tuple[Any, ...]:
    # The one row a query that always answers returns.
    row = cursor.fetchone()
    assert row is not None
    return row


class _FakePgError(Exception):
    def __init__(self, sqlstate: str, message: str) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


def test_an_unknown_type_is_invalid_datatype_unless_dropped() -> None:
    # A type PostgreSQL does not know: ORA-00902 in a query, but still the
    # missing-object code a best-effort DROP TYPE swallows (#1329).
    missing = _FakePgError('42704', 'type "no_such_type" does not exist')
    query = 'SELECT CAST(1 AS no_such_type) FROM dual'
    err = _backend_error(missing, original=query, translated=query)
    assert err.ora_code == 902
    assert 'invalid datatype' in str(err)
    drop = 'DROP TYPE no_such_type'
    assert _backend_error(missing, original=drop, translated=drop).ora_code == 942


def test_a_query_cast_to_an_oracle_type_is_translated() -> None:
    # The DDL type rewrites never see a query, so its casts are translated
    # here; an alias of the same name is left alone (#1329).
    assert _translate_idioms(
        'SELECT CAST(:1 AS NUMBER(15)), CAST(x AS raw(16)), '
        'CAST(y AS BINARY_DOUBLE), CAST(z AS binary_float ) FROM t'
    ) == (
        'SELECT CAST(:1 AS numeric(15)), CAST(x AS bytea), '
        'CAST(y AS double precision), CAST(z AS real ) FROM t'
    )
    assert _translate_idioms('SELECT d AS binary_double FROM t') == (
        'SELECT d AS binary_double FROM t'
    )


def test_an_outer_join_operator_is_lowered_and_noted() -> None:
    # The parsed transpiler (#1865) lowers Oracle's (+) to an ANSI LEFT JOIN
    # through the idiom pipeline, and notes the rule for the translation report
    # (#1557) exactly as the regex rules do.
    translated, rules = _idioms_and_rules(
        'SELECT e.ename, d.dname FROM emp e, dept d WHERE e.deptno = d.deptno(+)'
    )
    assert translated == (
        'SELECT e.ename, d.dname FROM emp e LEFT JOIN dept d ON e.deptno = d.deptno'
    )
    assert 'outer-join' in rules
    # A statement with no (+) is untouched and notes nothing.
    assert (
        _idioms_and_rules('SELECT * FROM emp e, dept d WHERE e.deptno = d.deptno')[1]
        == ()
    )


def test_an_outer_join_returns_the_rows_oracle_would() -> None:
    # The semantic proof of the (+) lowering (#1865): a left outer join keeps
    # every row of the preserved table, null-extending the optional side where
    # it has no match -- so the unmatched parent row comes back with NULLs, and
    # an inner join's absence of it would be wrong.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE emp1865 (ename VARCHAR2(10), deptno NUMBER)')
        backend.execute('CREATE TABLE dept1865 (deptno NUMBER, dname VARCHAR2(10))')
        try:
            backend.execute("INSERT INTO dept1865 VALUES (10, 'SALES')")
            backend.execute("INSERT INTO emp1865 VALUES ('ALICE', 10)")
            backend.execute("INSERT INTO emp1865 VALUES ('BOB', 20)")  # no dept
            rows = backend.execute(
                'SELECT e.ename, d.dname FROM emp1865 e, dept1865 d '
                'WHERE e.deptno = d.deptno(+) ORDER BY e.ename'
            ).rows
            # BOB's department does not exist, so (+) null-extends it; an inner
            # join would drop BOB entirely.
            assert rows == [('ALICE', 'SALES'), ('BOB', None)]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE emp1865')
            backend.execute('DROP TABLE dept1865')
    finally:
        backend.close()


def test_backend_error_uses_oracle_canonical_text_for_mapped_code() -> None:
    # A mapped code with a canonical Oracle phrasing gets it, so a client matching
    # on the Oracle text behaves — ORA-00942 is "table or view does not exist", not
    # PostgreSQL's "relation … does not exist" (#529).
    err = _backend_error(_FakePgError('42P01', 'relation "nope" does not exist'))
    assert err.ora_code == 942
    assert 'table or view' in str(err) and 'does not exist' in str(err)
    # A mapped code with no canonical text keeps PostgreSQL's message (its English
    # varies by Oracle version), still under the right code.
    num = _backend_error(_FakePgError('22P02', 'invalid input syntax for type numeric'))
    assert num.ora_code == 1722
    assert 'invalid input syntax' in str(num)
    # An unmapped SQLSTATE falls back to ORA-00900 with PostgreSQL's message.
    other = _backend_error(_FakePgError('XX000', 'internal error'))
    assert other.ora_code == 900
    # A foreign-key violation surfaces ORA-02291 (parent key not found), the code
    # an app catches for referential integrity (#761).
    fk = _backend_error(
        _FakePgError('23503', 'insert or update violates foreign key constraint')
    )
    assert fk.ora_code == 2291


# --- DDL type translation (#500) — a pure function, no live PostgreSQL needed ---


@pytest.mark.parametrize(
    ('sql', 'offset'),
    [
        ('update dual set dummy = dummy where 1 = 0', 7),
        ("update sys.dual set dummy = 'Y'", 11),
        ('delete from dual where 1 = 0', 12),
        ('delete dual where 1 = 0', 7),
        ("insert into dual values ('Y')", 12),
        (
            'merge into dual d using (select 1 x from dual) s on (1 = 0) '
            "when not matched then insert values ('Y')",
            11,
        ),
    ],
)
def test_dml_on_dual_is_refused_as_oracle_refuses_it(sql: str, offset: int) -> None:
    # It failed on the tableoid the DML rewrite reads back, DUAL being a view
    # here; 18c answers a user ORA-01031 at DUAL's name (#2084).
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        with pytest.raises(BackendError) as raised:
            backend.execute(sql)
        assert (raised.value.ora_code, raised.value.error_offset) == (1031, offset)
        assert backend.execute('SELECT dummy FROM dual').rows == [('X',)]
    finally:
        backend.close()


def test_dml_through_a_view_reaches_its_table() -> None:
    # INSERT, UPDATE and DELETE through a view failed on the tableoid the DML
    # rewrite reads back, which a view has none of (#2202). 23ai's: each
    # changes the table's row; a view gives no ROWID here, its table's heap
    # address not being one PostgreSQL returns through it.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2202 (id NUMBER, v VARCHAR2(5))')
        backend.execute('CREATE VIEW v2202 AS SELECT * FROM t2202')
        try:
            assert backend.execute("INSERT INTO v2202 VALUES (1, 'a')").rowcount == 1
            assert backend.execute("UPDATE v2202 SET v = 'b'").rowcount == 1
            assert backend.execute('SELECT id, v FROM t2202').rows == [(1, 'b')]
            assert backend.execute('DELETE FROM v2202 WHERE id = 1').rowcount == 1
            inserted = backend.execute("INSERT INTO t2202 VALUES (2, 'c')")
            assert inserted.last_rowid is not None
        finally:
            backend.rollback()
            backend.execute('DROP VIEW v2202')
            backend.execute('DROP TABLE t2202')
    finally:
        backend.close()


def test_a_dropped_tables_views_stay_invalid_until_it_is_back() -> None:
    # A DROP TABLE under a view failed: `cannot drop table because other
    # objects depend on it` (#2201). 23ai's: the table goes, the views over
    # it -- and over them -- stay INVALID, ORA-04063 `view "PYO.V" has
    # errors`, and are VALID again once the table is back; DROP VIEW of one
    # drops it.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))

    def states() -> list:
        return backend.execute(
            'SELECT object_name, status FROM user_objects '
            "WHERE object_name IN ('V2201', 'W2201') ORDER BY 1"
        ).rows

    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2201 (id NUMBER)')
        backend.execute('CREATE VIEW v2201 AS SELECT * FROM t2201')
        backend.execute('CREATE VIEW w2201 AS SELECT id FROM v2201')
        try:
            backend.execute('DROP TABLE t2201')
            assert states() == [('V2201', 'INVALID'), ('W2201', 'INVALID')]
            with pytest.raises(BackendError) as raised:
                backend.execute('SELECT * FROM w2201')
            assert (raised.value.ora_code, str(raised.value)) == (
                4063,
                'view "PYO.W2201" has errors',
            )
            backend.execute('CREATE TABLE t2201 (id NUMBER)')
            backend.execute('INSERT INTO t2201 VALUES (1)')
            assert backend.execute('SELECT id FROM w2201').rows == [(1,)]
            assert states() == [('V2201', 'VALID'), ('W2201', 'VALID')]
            backend.execute('DROP TABLE t2201')
            backend.execute('DROP VIEW w2201')
            assert states() == [('V2201', 'INVALID')]
        finally:
            backend.rollback()
            for leftover in ('VIEW w2201', 'VIEW v2201', 'TABLE t2201'):
                with contextlib.suppress(BackendError):
                    backend.execute(f'DROP {leftover}')
    finally:
        backend.close()


def test_backend_error_relays_the_parse_position_as_the_offset() -> None:
    # PostgreSQL's 1-based statement_position becomes Oracle's 0-based offset, but
    # only where the dialect rewrite left the prefix before the error untouched.
    class _Diag:
        def __init__(self, position: str | None) -> None:
            self.statement_position = position

    class _PgError(_FakePgError):
        def __init__(self, position: str | None) -> None:
            super().__init__('42703', 'column "nonexistent_col" does not exist')
            self.diag = _Diag(position)

    original = 'SELECT nonexistent_col'
    # Same prefix: relay (position 8 -> offset 7, the column's start).
    err = _backend_error(_PgError('8'), original=original, translated=original)
    assert err.ora_code == 904
    assert err.error_offset == 7
    # A rewrite that changed the text before the error (an inserted space, so
    # PostgreSQL now sees the column at position 9): no offset rather than a
    # misplaced one.
    err = _backend_error(
        _PgError('9'), original=original, translated='SELECT  nonexistent_col'
    )
    assert err.error_offset is None
    # No position reported, or none of the texts: no offset.
    assert (
        _backend_error(
            _PgError(None), original=original, translated=original
        ).error_offset
        is None
    )
    assert _backend_error(_PgError('8')).error_offset is None


@pytest.mark.parametrize(
    ('sql', 'message', 'position', 'offset'),
    [
        ('drop table nosuch purge', 'table "nosuch" does not exist', None, 11),
        ('drop table pyo.nosuch', 'table "nosuch" does not exist', None, 15),
        ('drop table "NOSUCH"', 'table "NOSUCH" does not exist', None, 11),
        ('drop sequence nosuch', 'sequence "nosuch" does not exist', None, 14),
        ('drop view nosuch', 'view "nosuch" does not exist', None, 0),
        ('select * from pyo.nosuch', 'relation "pyo.nosuch" does not exist', '15', 18),
        ('select * from nosuch', 'relation "nosuch" does not exist', '15', 14),
    ],
)
def test_a_missing_object_is_pointed_at_by_its_name(
    sql: str, message: str, position: str | None, offset: int
) -> None:
    # Where 18c points: at the name, past a schema, and at 0 for a DROP VIEW.
    # PostgreSQL gives a DROP no position, and a qualified name the schema's;
    # sqlplus drew its caret where the default put it (#2021).
    class _Diag:
        def __init__(self) -> None:
            self.statement_position = position
            self.message_primary = message

    class _PgError(_FakePgError):
        def __init__(self) -> None:
            super().__init__('42P01', message)
            self.diag = _Diag()

    err = _backend_error(_PgError(), original=sql, translated=sql)
    assert err.error_offset == offset


@pytest.mark.parametrize(
    ('sql', 'message', 'position', 'offset'),
    [
        ('drop sequence nosuch', 'sequence "nosuch" does not exist', None, 14),
        (
            'select nosuch.nextval from dual',
            'relation "nosuch" does not exist',
            '16',
            7,
        ),
        (
            'select nosuch.currval from dual',
            'relation "nosuch" does not exist',
            '16',
            7,
        ),
        (
            'alter sequence nosuch increment by 2',
            'relation "nosuch" does not exist',
            None,
            0,
        ),
        (
            'select pyo.nosuch.nextval from dual',
            'relation "pyo.nosuch" does not exist',
            '16',
            11,
        ),
    ],
)
def test_a_missing_sequence_is_ora_02289(
    sql: str, message: str, position: str | None, offset: int
) -> None:
    # PostgreSQL's 42P01 is ORA-00942 for every relation; Oracle says a
    # sequence does not exist, and points at its name as 18c does, NEXTVAL or
    # not, and at 0 for an ALTER SEQUENCE (#2073).
    class _Diag:
        def __init__(self) -> None:
            self.statement_position = position
            self.message_primary = message

    class _PgError(_FakePgError):
        def __init__(self) -> None:
            super().__init__('42P01', message)
            self.diag = _Diag()

    translated = sql.replace('nosuch.nextval', "nextval('nosuch')")
    err = _backend_error(_PgError(), original=sql, translated=translated)
    assert (err.ora_code, err.error_offset) == (2289, offset)
    assert str(err) == 'sequence does not exist'


def test_a_missing_table_read_as_a_qualifier_stays_ora_00942() -> None:
    # A name followed by a dot that is not NEXTVAL / CURRVAL is a schema or a
    # table qualifier, and the relation a table.
    class _PgError(_FakePgError):
        def __init__(self) -> None:
            super().__init__('42P01', 'relation "nosuch" does not exist')

    sql = 'select nosuch.x from nosuch'
    assert _backend_error(_PgError(), original=sql, translated=sql).ora_code == 942


@pytest.mark.parametrize(
    ('sql', 'message', 'position', 'text'),
    [
        (
            'select nosuchcol from dual',
            'column "nosuchcol" does not exist',
            '8',
            '"NOSUCHCOL"',
        ),
        (
            'select d.nosuch from dual d',
            'column d.nosuch does not exist',
            '8',
            '"D"."NOSUCH"',
        ),
        (
            'select "MixedCase" from dual',
            'column "MixedCase" does not exist',
            '8',
            '"MixedCase"',
        ),
        (
            'select 1 from dual order by nosuch',
            'column "nosuch" does not exist',
            '29',
            '"NOSUCH"',
        ),
        (
            'select sys.dual.nosuch from sys.dual',
            'column dual.nosuch does not exist',
            '8',
            '"SYS"."DUAL"."NOSUCH"',
        ),
        # No position to read the statement at: the message's name.
        ('select nosuch from dual', 'column "nosuch" does not exist', None, '"NOSUCH"'),
    ],
)
def test_an_unknown_column_is_named_as_oracle_names_it(
    sql: str, message: str, position: str | None, text: str
) -> None:
    # Oracle names the identifier as the statement has it, each part quoted
    # and an unquoted one upper-cased, where PostgreSQL said `column "x" does
    # not exist` and its LINE context came along (#2072). Measured on 18c.
    class _Diag:
        def __init__(self) -> None:
            self.statement_position = position
            self.message_primary = message

    class _PgError(_FakePgError):
        def __init__(self) -> None:
            super().__init__('42703', f'{message}\nLINE 1: {sql}\n       ^')
            self.diag = _Diag()

    err = _backend_error(_PgError(), original=sql, translated=sql)
    assert err.ora_code == 904
    assert str(err) == f'{text}: invalid identifier'


def test_dbms_lob_substr_reads_as_oracle_reads_it() -> None:
    # DBMS_LOB.SUBSTR did not exist (#2056). Measured on 18c: `amount` from
    # `offset`, both truncated, by default 32767 from 1; NULL for an amount
    # below 1 or past 32767, an offset below 1 or past the end; a CLOB's
    # VARCHAR2(4000), a BLOB's RAW(2000).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        clob = "TO_CLOB('hello world')"
        cases = {
            f'DBMS_LOB.SUBSTR({clob}, 5, 1)': 'hello',
            f'DBMS_LOB.SUBSTR({clob}, 5, 7)': 'world',
            f'DBMS_LOB.SUBSTR({clob})': 'hello world',
            f'DBMS_LOB.SUBSTR({clob}, 100, 7)': 'world',
            f'DBMS_LOB.SUBSTR({clob}, 3, 20)': None,
            f'DBMS_LOB.SUBSTR({clob}, 0, 1)': None,
            f'DBMS_LOB.SUBSTR({clob}, 3, 0)': None,
            f'DBMS_LOB.SUBSTR({clob}, 32768, 1)': None,
            f'DBMS_LOB.SUBSTR({clob}, 2.7, 1.2)': 'he',
        }
        for call, expected in cases.items():
            result = backend.execute(f'SELECT {call} r FROM dual')
            assert result.rows == [(expected,)], call
            assert result.columns[0].data_length == 4000
        raw = backend.execute(
            "SELECT DBMS_LOB.SUBSTR(TO_BLOB(HEXTORAW('0102030405')), 2, 2) r FROM dual"
        )
        assert raw.rows == [(b'\x02\x03',)]
        assert raw.columns[0].data_length == 2000
    finally:
        backend.close()


def test_lob_substr_items_are_whole_items_only() -> None:
    from seerdb.server.backends.postgres import _lob_substr_items

    assert _lob_substr_items(
        'select dbms_lob.substr(c, 1) a, dbms_lob.substr(c) || 1, x from t'
    ) == {0}
    assert _lob_substr_items('select * from t') == set()


def test_the_sqlplus_product_profile_is_there_and_empty() -> None:
    # sqlplus 10.2 and 11.2 read SYSTEM.PRODUCT_PRIVS at login, which did not
    # exist, so every session opened with ORA-00942 and "Product user profile
    # information not loaded!" (#2107). This is their query, as captured; the
    # profile restricts nothing, so it has no rows.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        result = backend.execute(
            'SELECT ATTRIBUTE,SCOPE,NUMERIC_VALUE,CHAR_VALUE,DATE_VALUE '
            "FROM SYSTEM.PRODUCT_PRIVS WHERE (UPPER('SQL*Plus') LIKE UPPER(PRODUCT)) "
            'AND (USER LIKE USERID)'
        )
        assert result.rows == []
        assert [c.name for c in result.columns] == [
            b'ATTRIBUTE',
            b'SCOPE',
            b'NUMERIC_VALUE',
            b'CHAR_VALUE',
            b'DATE_VALUE',
        ]
    finally:
        backend.close()


def test_a_value_too_large_names_its_column_and_points_at_it() -> None:
    # ORA-12899 carried PostgreSQL's `value too long for type character
    # varying(3)`, naming no column, at no position (#2137). Oracle's, in every
    # release, names the column, the value's length in bytes and the column's,
    # and points at the value -- a bind at its name. Measured on 23ai.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2137 (id NUMBER, n VARCHAR2(3), m VARCHAR2(5), k NUMBER(3))'
        )
        try:
            backend.execute("INSERT INTO t2137 VALUES (1, 'a', 'b', 1)")
            for statement, binds, column, actual, maximum, offset in (
                ("insert into t2137 values (2, 'abcd', 'x', 1)", [], 'N', 4, 3, 29),
                ("insert into t2137 (m, n) values ('toolong', 'a')", [], 'M', 7, 5, 33),
                ("insert into t2137 values (3, :1, 'x', 1)", ['abcdef'], 'N', 6, 3, 30),
                ("update t2137 set n = 'abcdef' where id = 1", [], 'N', 6, 3, 21),
                ("update t2137 set m = 'b', n = :1", ['wxyz'], 'N', 4, 3, 31),
                ("insert into t2137 values (4, 'é€ab', 'x', 1)", [], 'N', 7, 3, 29),
                (
                    "insert into t2137 select 5, 'abcd', 'x', 1 from dual",
                    [],
                    'N',
                    4,
                    3,
                    28,
                ),
            ):
                with pytest.raises(BackendError) as raised:
                    backend.execute(statement, binds)
                assert (
                    raised.value.ora_code,
                    str(raised.value),
                    raised.value.error_offset,
                ) == (
                    12899,
                    f'value too large for column "PYO"."T2137"."{column}" '
                    f'(actual: {actual}, maximum: {maximum})',
                    offset,
                ), statement
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2137')
    finally:
        backend.close()


def test_an_insert_select_literal_converts_to_its_columns_type() -> None:
    # An INSERT ... SELECT's string literal for a NUMBER or a DATE column
    # failed: PostgreSQL types it as character and assigns that to neither
    # (#2150). Oracle converts it -- a DATE by NLS_DATE_FORMAT. Measured on
    # 23ai, as are the rows below.
    import datetime

    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2150 (id NUMBER, k NUMBER, i INTEGER, d DATE)')
        try:
            for statement in (
                "insert into t2150 select 1, '5', null, null from dual",
                "insert into t2150 (id, k) select 2, '7' from dual",
                "insert into t2150 (id, i) select 3, '42' from dual",
                "insert into t2150 (id, d) select 4, '06-MAY-24' from dual",
                "insert into t2150 (id, k, i) select 5, '8', '9' from dual",
            ):
                assert backend.execute(statement).rowcount == 1, statement
            assert (
                backend.execute(
                    "insert into t2150 select 6, 'abc', null, null from dual where 1 = 0"
                ).rowcount
                == 0
            )
            with pytest.raises(BackendError) as raised:
                backend.execute("insert into t2150 (id, k) select 7, 'x' from dual")
            assert raised.value.ora_code == 1722
            assert backend.execute('SELECT * FROM t2150 ORDER BY id').rows == [
                (1, 5, None, None),
                (2, 7, None, None),
                (3, None, 42, None),
                (4, None, None, datetime.datetime(2024, 5, 6)),
                (5, 8, 9, None),
            ]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2150')
    finally:
        backend.close()


def test_a_value_that_is_no_number_fails_only_on_a_row() -> None:
    # A comparison or an assignment with a value that is no number failed on
    # an empty table: PostgreSQL converts it as it plans, where Oracle converts
    # it for each row (#2143). Measured on 23ai: each succeeds on the empty
    # table, and fails with ORA-01722 once a row is there.
    from seerdb.server.backend import BackendError
    from seerdb.server.backends.postgres import _late_number

    assert _late_number("select * from t where k = 'abc'", [], 'abc') == (
        "select * from t where k = sys.ora_late_number('abc')"
    )
    assert _late_number('select * from t where k = :1', ['abc'], 'abc') == (
        'select * from t where k = sys.ora_late_number(:1)'
    )
    assert (
        _late_number("select * from t where k = sys.ora_late_number('abc')", [], 'abc')
        is None
    )
    assert _late_number("create table t (x number default 'abc')", [], 'abc') is None
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2143 (id NUMBER, k NUMBER)')
        try:
            cases: tuple[tuple[str, list[object]], ...] = (
                ("select * from t2143 where k = 'abc'", []),
                ('select * from t2143 where k = :1', ['abc']),
                ("update t2143 set k = 'abc'", []),
                ("delete from t2143 where k = 'abc'", []),
                ("select count(*) from t2143 where k in ('1', 'x')", []),
            )
            for statement, binds in cases:
                backend.execute(statement, binds)
            backend.execute('INSERT INTO t2143 VALUES (1, 1)')
            for statement, binds in cases:
                with pytest.raises(BackendError) as raised:
                    backend.execute(statement, binds)
                assert raised.value.ora_code == 1722, statement
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2143')
    finally:
        backend.close()


def test_a_unique_violation_is_worded_as_oracle_words_it() -> None:
    # ORA-00001 carried PostgreSQL's `duplicate key value violates unique
    # constraint` and its DETAIL line (#2120). Before 23ai Oracle's names the
    # constraint; 23ai's names the table and columns too, and gives the row's
    # values on an ORA-03301 line, a character value quoted, its own quote as
    # it is. Measured on 23ai.
    from seerdb.server.backend import BackendError

    for presents, expected in (
        (
            '23ai',
            [
                'unique constraint (PYO.SYS_C#######) violated on table PYO.T2120 '
                'columns (ID)\nORA-03301: (ORA-00001 details) row with column '
                'values (ID:1) already exists',
                'unique constraint (PYO.U2120) violated on table PYO.T2120 '
                'columns (N, K)\nORA-03301: (ORA-00001 details) row with column '
                "values (N:'a'b', K:2) already exists",
            ],
        ),
        (
            '12.1',
            [
                'unique constraint (PYO.SYS_C#######) violated',
                'unique constraint (PYO.U2120) violated',
            ],
        ),
    ):
        backend = PostgresBackend(
            _CONNINFO, credentials=dict(_CREDS), presents=presents
        )
        try:
            backend.authenticate('PYO')
            backend.open_session({})
            backend.execute(
                'CREATE TABLE t2120 (id NUMBER PRIMARY KEY, n VARCHAR2(10), '
                'k NUMBER, CONSTRAINT u2120 UNIQUE (n, k))'
            )
            try:
                backend.execute("INSERT INTO t2120 VALUES (1, 'a''b', 2)")
                got = []
                for statement in (
                    "INSERT INTO t2120 VALUES (1, 'x', 3)",
                    "INSERT INTO t2120 VALUES (2, 'a''b', 2)",
                ):
                    with pytest.raises(BackendError) as raised:
                        backend.execute(statement)
                    assert raised.value.ora_code == 1
                    got.append(str(raised.value))
                # The primary key Oracle names, SYS_C and seven digits (#2141).
                assert [
                    re.sub(r'SYS_C\d{7}', 'SYS_C#######', g) for g in got
                ] == expected
                # An array's error keeps the rows it applied before it failed:
                # only the words change (#998).
                with pytest.raises(BackendError) as raised:
                    backend.execute_many(
                        "INSERT INTO t2120 VALUES (:1, 'r', :1)",
                        [[10], [20], [30], [20], [50]],
                    )
                assert raised.value.rowcount == 3
                assert str(raised.value).startswith(expected[0][:17])
            finally:
                backend.rollback()
                backend.execute('DROP TABLE t2120')
        finally:
            backend.close()


def test_an_unnamed_constraint_is_named_as_oracle_names_it() -> None:
    # An unnamed constraint had PostgreSQL's name, T_PKEY or T_U_KEY, in the
    # dictionary and in ORA-00001 (#2141). 23ai names each PRIMARY KEY,
    # UNIQUE, CHECK and REFERENCES the DDL leaves unnamed SYS_C and seven
    # digits, inline or not, in CREATE TABLE and ALTER TABLE ... ADD; a key's
    # index has its name. A named one, and a FOREIGN KEY's REFERENCES, keep
    # theirs.
    from seerdb.server.backend import BackendError
    from seerdb.server.backends.postgres import _unnamed_constraints

    sql = (
        'create table t (a number primary key, b number constraint nb unique, '
        "c varchar2(5) check (c <> 'unique'), foreign key (a) references p (id))"
    )
    assert [sql[at : at + 7] for at in _unnamed_constraints(sql)] == [
        'primary',
        'check (',
        'foreign',
    ]
    assert _unnamed_constraints('alter table t drop primary key') == []
    assert _unnamed_constraints('create table t2 as select * from t') == []
    generated = re.compile(r'SYS_C\d{7}$')
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE p2141 (id NUMBER PRIMARY KEY)')
        backend.execute(
            'CREATE TABLE t2141 (id NUMBER, u VARCHAR2(5) UNIQUE, '
            'c NUMBER CHECK (c > 0), r NUMBER REFERENCES p2141, k NUMBER, '
            'CONSTRAINT named_2141 UNIQUE (k), PRIMARY KEY (id))'
        )
        try:
            backend.execute('ALTER TABLE t2141 ADD (z NUMBER)')
            backend.execute('ALTER TABLE t2141 ADD UNIQUE (z)')
            rows = backend.execute(
                'SELECT constraint_name, constraint_type FROM user_constraints '
                "WHERE table_name = 'T2141' AND lower(constraint_name) NOT LIKE '%not_null'"
            ).rows
            assert sorted(t for n, t in rows if generated.match(n)) == [
                'C',
                'P',
                'R',
                'U',
                'U',
            ]
            assert [n for n, _t in rows if not generated.match(n)] == ['NAMED_2141']
            indexes = {
                n
                for (n,) in backend.execute(
                    "SELECT index_name FROM all_indexes WHERE owner = 'PYO' "
                    "AND table_name = 'T2141'"
                ).rows
            }
            keys = {n for n, t in rows if t in ('P', 'U')}
            assert indexes == keys
            backend.execute("INSERT INTO t2141 (id, u) VALUES (1, 'a')")
            with pytest.raises(BackendError) as raised:
                backend.execute("INSERT INTO t2141 (id, u) VALUES (2, 'a')")
            named = re.search(r'\(PYO\.(\w+)\)', str(raised.value))
            assert named is not None and generated.match(named.group(1))
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2141')
            backend.execute('DROP TABLE p2141')
    finally:
        backend.close()


def test_a_unique_violation_shows_a_date_in_the_session_format() -> None:
    # A DATE on the ORA-03301 line printed as PostgreSQL prints it,
    # `D:2024-01-02 13:14:15` (#2141). Measured on 23ai: it follows the
    # session's NLS_DATE_FORMAT, `D:02-JAN-24` by default.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2141 (d DATE, n NUMBER, PRIMARY KEY (d, n))')
        try:
            insert = (
                "INSERT INTO t2141 VALUES (TO_DATE('2024-01-02 13:14:15', "
                "'YYYY-MM-DD HH24:MI:SS'), 1)"
            )
            backend.execute(insert)
            for setting, shown in (
                (None, 'D:02-JAN-24, N:1'),
                ("'YYYY-MM-DD HH24:MI:SS'", 'D:2024-01-02 13:14:15, N:1'),
            ):
                if setting:
                    backend.execute(f'ALTER SESSION SET NLS_DATE_FORMAT = {setting}')
                with pytest.raises(BackendError) as raised:
                    backend.execute(insert)
                assert str(raised.value).endswith(
                    f'row with column values ({shown}) already exists'
                ), setting
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2141')
    finally:
        backend.close()


def test_a_unique_violation_shows_a_timestamp_in_the_session_format() -> None:
    # A TIMESTAMP on the ORA-03301 line printed as PostgreSQL prints it,
    # `TS:2024-01-02 13:14:15.5` (#2162). Measured on 23ai: it follows the
    # session's NLS_TIMESTAMP_FORMAT, FF at the column's precision.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2162u (ts TIMESTAMP, t3 TIMESTAMP(3), PRIMARY KEY (ts, t3))'
        )
        try:
            insert = (
                "INSERT INTO t2162u VALUES (TIMESTAMP '2024-01-02 13:14:15.5', "
                "TIMESTAMP '2024-01-02 13:14:15.25')"
            )
            backend.execute(insert)
            for setting, shown in (
                (
                    None,
                    'TS:02-JAN-24 01.14.15.500000 PM, T3:02-JAN-24 01.14.15.250 PM',
                ),
                (
                    "'YYYY-MM-DD HH24:MI:SSXFF'",
                    'TS:2024-01-02 13:14:15.500000, T3:2024-01-02 13:14:15.250',
                ),
            ):
                if setting:
                    backend.execute(
                        f'ALTER SESSION SET NLS_TIMESTAMP_FORMAT = {setting}'
                    )
                with pytest.raises(BackendError) as raised:
                    backend.execute(insert)
                assert str(raised.value).endswith(
                    f'row with column values ({shown}) already exists'
                ), setting
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2162u')
    finally:
        backend.close()


def test_an_invalid_number_is_worded_and_placed_as_oracle_does() -> None:
    # ORA-01722 carried PostgreSQL's `invalid input syntax for type numeric`
    # (#2136), and TO_NUMBER('x') no position (#2126). 23ai names the first
    # character that cannot be in a number and gives the value on an ORA-03302
    # line; earlier releases say `invalid number`. Both point at the literal.
    # Measured on 23ai.
    from seerdb.server.backend import BackendError

    cases = (
        ("select to_number('x') from dual", 'x', 'x', 17),
        ("select to_number('12z') from dual", 'z', '12z', 17),
        ("select to_number('1,5') from dual", ',', '1,5', 17),
        ("insert into t2136 values ('x1', 1)", 'x', 'x1', 26),
        ("select 1 + 'q' from dual", 'q', 'q', 11),
    )
    for presents in ('23ai', '12.1'):
        backend = PostgresBackend(
            _CONNINFO, credentials=dict(_CREDS), presents=presents
        )
        try:
            backend.authenticate('PYO')
            backend.open_session({})
            backend.execute('CREATE TABLE t2136 (id NUMBER, k NUMBER)')
            try:
                for statement, bad, value, offset in cases:
                    with pytest.raises(BackendError) as raised:
                        backend.execute(statement)
                    expected = (
                        f"unable to convert string value containing '{bad}' to a "
                        'number: \nORA-03302: (ORA-01722 details) invalid string '
                        f'value: {value}'
                        if presents == '23ai'
                        else 'invalid number'
                    )
                    assert (
                        raised.value.ora_code,
                        str(raised.value),
                        raised.value.error_offset,
                    ) == (1722, expected, offset), (presents, statement)
            finally:
                backend.rollback()
                backend.execute('DROP TABLE t2136')
        finally:
            backend.close()


def test_a_missing_table_is_named_as_23ai_names_it() -> None:
    # 23ai's ORA-00942 names the table or view, schema and all, where the
    # statement may name neither; earlier releases' does not (#2110). ORA-00955
    # is Oracle's text in every release, where PostgreSQL's named the relation.
    # Measured on 23ai.
    from seerdb.server.backend import BackendError

    for presents, missing in (
        ('23ai', 'table or view "{}"."{}" does not exist'),
        ('12.1', 'table or view does not exist'),
    ):
        backend = PostgresBackend(
            _CONNINFO, credentials=dict(_CREDS), presents=presents
        )
        try:
            backend.authenticate('PYO')
            backend.open_session({})
            for statement, schema, name in (
                ('SELECT * FROM no_such_2110', 'PYO', 'NO_SUCH_2110'),
                ('SELECT * FROM sys.no_such_2110', 'SYS', 'NO_SUCH_2110'),
                ('SELECT * FROM "MixedCase2110"', 'PYO', 'MixedCase2110'),
                ('DROP TABLE no_such_2110', 'PYO', 'NO_SUCH_2110'),
            ):
                with pytest.raises(BackendError) as raised:
                    backend.execute(statement)
                assert raised.value.ora_code == 942
                assert str(raised.value) == missing.format(schema, name), statement
            backend.execute('CREATE TABLE t_dup2110 (x NUMBER)')
            try:
                with pytest.raises(BackendError) as raised:
                    backend.execute('CREATE TABLE t_dup2110 (x NUMBER)')
                assert raised.value.ora_code == 955
                assert str(raised.value) == 'name is already used by an existing object'
            finally:
                backend.execute('DROP TABLE t_dup2110')
        finally:
            backend.close()


def test_an_error_with_no_postgresql_position_is_placed_as_23ai_places_it() -> None:
    # PostgreSQL gives no position for these, and sqlplus drew its `*` at a
    # fixed column (#2111). 23ai points an ORA-00955 at the name the CREATE
    # gives and an ORA-01476 at the first `/`, past a literal's; a constraint's
    # error has none, which the session sends as 0.
    from seerdb.server.backends.postgres import _placed_offset

    assert _placed_offset(955, 'create table t2111 (x number)') == 13
    assert _placed_offset(955, 'CREATE OR REPLACE VIEW v2111 AS SELECT 1 x') == 23
    assert _placed_offset(955, 'create unique index i2111 on t(x)') == 20
    assert _placed_offset(1476, 'select 1/0 from dual') == 8
    assert _placed_offset(1476, 'select id, 10/(id-1) from t2111') == 13
    assert _placed_offset(1476, "select '/' || 1/0 from dual") == 15
    assert _placed_offset(1476, 'select /* a/b */ 1/0 from dual') == 18
    assert _placed_offset(1, 'insert into t values (1)') is None


def test_user_source_lists_a_units_source_by_line() -> None:
    # USER_SOURCE was orafce's, and empty for the Mirror's routines; there was
    # no ALL_SOURCE (#2172). Measured on 23ai: the source from its keyword on,
    # a row a line, each but the last ending in its newline; a unit created
    # with compilation errors keeps it, and a DROP takes it.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE OR REPLACE PROCEDURE s2172 AS\nBEGIN\n  NULL;\nEND;')
        backend.execute('CREATE OR REPLACE PACKAGE p2172 AS\n  x NUMBER;\nEND p2172;')
        assert backend.execute(
            'CREATE OR REPLACE PROCEDURE i2172 AS BEGIN nosuch; END;'
        ).compilation_warning
        try:
            assert backend.execute(
                'SELECT name, type, line, text, origin_con_id FROM user_source '
                "WHERE name IN ('S2172', 'P2172', 'I2172') ORDER BY name, line"
            ).rows == [
                ('I2172', 'PROCEDURE', 1, 'PROCEDURE i2172 AS BEGIN nosuch; END;', 0),
                ('P2172', 'PACKAGE', 1, 'PACKAGE p2172 AS\n', 0),
                ('P2172', 'PACKAGE', 2, '  x NUMBER;\n', 0),
                ('P2172', 'PACKAGE', 3, 'END p2172;', 0),
                ('S2172', 'PROCEDURE', 1, 'PROCEDURE s2172 AS\n', 0),
                ('S2172', 'PROCEDURE', 2, 'BEGIN\n', 0),
                ('S2172', 'PROCEDURE', 3, '  NULL;\n', 0),
                ('S2172', 'PROCEDURE', 4, 'END;', 0),
            ]
            assert backend.execute(
                "SELECT owner, count(*) FROM all_source WHERE name = 'S2172' "
                'GROUP BY owner'
            ).rows == [('PYO', 4)]
        finally:
            for unit in ('PROCEDURE s2172', 'PACKAGE p2172', 'PROCEDURE i2172'):
                backend.execute(f'DROP {unit}')
        assert backend.execute(
            "SELECT count(*) FROM user_source WHERE name IN ('S2172', 'P2172', 'I2172')"
        ).rows == [(0,)]
    finally:
        backend.close()


def test_all_errors_lists_an_invalid_objects_error() -> None:
    # sqlplus's SHOW ERRORS reads ALL_ERRORS, which did not exist (#2060). A
    # CREATE that does not compile lists its error at the line and column
    # Oracle counts from the object's keyword -- 18c says 1/31 for P2060 and 4/1
    # for the second, and this name is a character longer -- while
    # the object stays INVALID; a CREATE that compiles, or a DROP, lists none.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    query = (
        'SELECT name, type, sequence, line, position, attribute FROM all_errors '
        "WHERE name LIKE 'P_2060%' ORDER BY name"
    )
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        assert backend.execute(
            'CREATE OR REPLACE PROCEDURE p_2060 AS BEGIN NULL END;'
        ).compilation_warning
        assert backend.execute(
            'CREATE OR REPLACE PROCEDURE p_2060b AS\nBEGIN\n  NULL\nEND;'
        ).compilation_warning
        assert backend.execute(query).rows == [
            ('P_2060', 'PROCEDURE', 1, 1, 32, 'ERROR'),
            ('P_2060B', 'PROCEDURE', 1, 4, 1, 'ERROR'),
        ]
        assert backend.execute(
            "SELECT name, line FROM user_errors WHERE name LIKE 'P_2060%' ORDER BY name"
        ).rows == [('P_2060', 1), ('P_2060B', 4)]
        backend.execute('CREATE OR REPLACE PROCEDURE p_2060 AS BEGIN NULL; END;')
        backend.execute('DROP PROCEDURE p_2060b')
        assert backend.execute(query).rows == []
    finally:
        for name in ('p_2060', 'p_2060b'):
            try:
                backend.execute(f'DROP PROCEDURE {name}')
            except Exception:
                pass
        backend.close()


def test_iot_primary_key_is_read_from_organization_index_ddl() -> None:
    # Inline and constraint forms; a heap table or an IOT without a recognised
    # key registers nothing.
    assert _iot_primary_key(
        'CREATE TABLE t (id NUMBER PRIMARY KEY, v VARCHAR2(20)) ORGANIZATION INDEX'
    ) == ('T', ['id'])
    assert _iot_primary_key(
        'create table s.t2 (a number, b number, primary key (a, b)) organization index'
    ) == ('T2', ['a', 'b'])
    assert _iot_primary_key('CREATE TABLE t (id NUMBER PRIMARY KEY)') is None
    assert _iot_primary_key('CREATE TABLE t (id NUMBER) ORGANIZATION INDEX') is None


def test_iot_rowid_renders_a_star_prefixed_logical_rowid() -> None:
    # The registered IOT's ROWID becomes '*' || base64(primary key), the same
    # expression on a SELECT and on a WHERE ROWID = :bind; a heap table's ROWID
    # is left alone for the generic ctid rewrite.
    backend = PostgresBackend.__new__(PostgresBackend)
    backend._iot_pk = {'T': ['id']}
    expr = _urowid_expression(['id'])
    assert expr.startswith("('*' || encode(")
    assert (
        backend._rewrite_iot_rowid('SELECT ROWID, id FROM t')
        == f'SELECT {expr}, id FROM t'
    )
    assert (
        backend._rewrite_iot_rowid('SELECT id FROM t WHERE ROWID = :r')
        == f'SELECT id FROM t WHERE {expr} = :r'
    )
    assert (
        backend._rewrite_iot_rowid('SELECT ROWID FROM heap') == 'SELECT ROWID FROM heap'
    )


def test_a_bare_call_statement_is_made_one_plpgsql_runs() -> None:
    # PL/pgSQL has no bare call statement: a function called for its effect is
    # PERFORM f(...), a procedure CALL p(...) (#1533). Only statements that are a
    # call to something PostgreSQL has; strings, comments, assignments and
    # PL/SQL's own statements are left alone.
    from seerdb.server.backends.postgres import _perform_bare_calls

    kinds = {'dbms_output.put_line': 'f', 'p': 'p', 'dbms_output.enable': 'f'}

    def kind(name: str) -> str | None:
        return kinds.get(name.lower())

    cases = (
        (
            " dbms_output.put_line('a; b(1);'); dbms_output.put_line('two'); ",
            " PERFORM dbms_output.put_line('a; b(1);'); "
            "PERFORM dbms_output.put_line('two'); ",
        ),
        (
            ' x := f(1); -- p(2);\n p(3); unknown(4); ',
            ' x := f(1); -- p(2);\n CALL p(3); unknown(4); ',
        ),
        (
            " IF x > 1 THEN dbms_output.put_line('y'); ELSE p; END IF; ",
            " IF x > 1 THEN PERFORM dbms_output.put_line('y'); ELSE CALL p(); END IF; ",
        ),
        (
            ' FOR i IN 1..3 LOOP dbms_output.put_line(i); END LOOP; NULL; ',
            ' FOR i IN 1..3 LOOP PERFORM dbms_output.put_line(i); END LOOP; NULL; ',
        ),
        (
            ' DBMS_OUTPUT.ENABLE; /* p(9); */ RAISE no_data_found; ',
            ' PERFORM DBMS_OUTPUT.ENABLE(); /* p(9); */ RAISE no_data_found; ',
        ),
    )
    for body, want in cases:
        assert _perform_bare_calls(body, kind) == want


def test_a_block_calling_put_line_twice_runs() -> None:
    # sqlplus `set serveroutput on`, a block of two PUT_LINEs: it failed to
    # compile as a DO block, a bare function call not being a PL/pgSQL statement
    # (#1533). Both lines arrive.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('BEGIN DBMS_OUTPUT.ENABLE(NULL); END;', [])
        backend.execute(
            "BEGIN DBMS_OUTPUT.PUT_LINE('one'); DBMS_OUTPUT.PUT_LINE('two'); END;", []
        )
        lines = [
            backend.execute(
                'BEGIN DBMS_OUTPUT.GET_LINE(:1, :2); END;',
                [
                    BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=32767),
                    BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22),
                ],
            ).out_binds
            for _ in range(3)
        ]
        assert lines == [['one', 0], ['two', 0], [None, 1]]
    finally:
        backend.close()


def test_translate_ddl_maps_create_table_column_types() -> None:
    sent = _translate_ddl(
        'CREATE TABLE t (id NUMBER(10,2), v VARCHAR2(20), d DATE, '
        'r RAW(16), c CLOB, b BLOB, ts TIMESTAMP WITH TIME ZONE, '
        'f BINARY_FLOAT, g BINARY_DOUBLE)'
    )
    assert 'numeric(10,2)' in sent
    assert 'varchar(20)' in sent
    assert 'd ora_date' in sent  # DATE keeps its time-of-day, as a domain (#1316)
    assert 'r bytea' in sent  # RAW(16) → bytea (size dropped)
    assert 'c ora_clob' in sent  # CLOB → domain over text, so empty ≠ NULL (#534)
    assert 'b ora_blob' in sent  # BLOB → domain over bytea (#534)
    assert 'ts ora_tstz' in sent  # WITH TIME ZONE preserves the offset (#519)
    assert 'f real' in sent and 'g double precision' in sent
    assert 'NUMBER' not in sent and 'VARCHAR2' not in sent
    # FLOAT[(b)], REAL and DOUBLE PRECISION are NUMBERs, not binary floats (#1384).
    sent = _translate_ddl(
        'CREATE TABLE t (a FLOAT, b FLOAT(10), c REAL, d DOUBLE PRECISION, '
        'e BINARY_DOUBLE)'
    )
    assert sent == (
        'CREATE TABLE t (a numeric, b numeric, c numeric, d numeric, '
        'e double precision); CREATE OR REPLACE TRIGGER ora_float_round BEFORE '
        'INSERT OR UPDATE ON t FOR EACH ROW EXECUTE FUNCTION sys.ora_float_round()'
    )
    # Rounded by b, which the trigger reads (#1422); so is a column an ALTER
    # adds or makes FLOAT, and a table with none has no trigger.
    assert _translate_ddl('ALTER TABLE t MODIFY (n FLOAT(5))').endswith(
        'ON t FOR EACH ROW EXECUTE FUNCTION sys.ora_float_round()'
    )
    assert 'TRIGGER' not in _translate_ddl('CREATE TABLE t (e BINARY_FLOAT)')
    # So are an object's attributes, their declarations recorded (#1423).
    assert 'AS (r numeric, f numeric, g double precision)' in _translate_ddl(
        'CREATE TYPE o AS OBJECT (r REAL, f FLOAT, g BINARY_DOUBLE)'
    )


def test_translate_ddl_maps_a_number_of_any_precision() -> None:
    # NUMBER(*) is a plain NUMBER and NUMBER(*, s) a NUMBER(38, s) (#1443).
    assert (
        _translate_ddl(
            'CREATE TABLE t (d NUMBER(*, 0), e NUMBER(*), f number( * ,-2), g NUMBER(5,2))'
        )
        == 'CREATE TABLE t (d numeric(38, 0), e numeric, f numeric(38, -2), g numeric(5,2))'
    )


def test_translate_ddl_maps_object_type_to_composite() -> None:
    # CREATE TYPE ... AS OBJECT (attrs) → a PostgreSQL composite type, the OBJECT
    # keyword dropped and the attribute types mapped like a table's columns (#139).
    sent = _translate_ddl(
        'CREATE TYPE PYORACLE_REF_PERSON AS OBJECT (id NUMBER, name VARCHAR2(40))'
    )
    assert 'AS OBJECT' not in sent and 'OBJECT' not in sent
    assert 'AS (id numeric, name varchar(40))' in sent
    assert 'PYORACLE_REF_PERSON' in sent  # the type name is untouched


def test_translate_ddl_maps_a_ref_column_to_its_companion_type() -> None:
    # A `REF <type>` column holds the type's `<type>$ref` companion -- the object
    # table's oid and the row's stable id -- which sys.deref() resolves (#1127).
    # A column merely NAMED `ref` is left alone.
    assert _translate_ddl('CREATE TABLE t (id NUMBER, r REF person_t)') == (
        'CREATE TABLE t (id numeric, r person_t$ref)'
    )
    assert (
        _translate_ddl('CREATE TABLE t (ref NUMBER)') == 'CREATE TABLE t (ref numeric)'
    )


def test_an_object_type_brings_its_ref_companions() -> None:
    out = _translate_ddl('CREATE TYPE person_t AS OBJECT (id NUMBER)')
    assert out.startswith('CREATE TYPE person_t AS (id numeric); ')
    assert 'CREATE TYPE person_t$ref AS (tab oid, id uuid)' in out
    # Its sys.deref() overload, made as the installer for the session's own
    # type (#1857).
    assert (
        "SELECT sys.ora_make_deref('person_t$ref'::regtype, 'person_t'::regtype)" in out
    )
    # Dropped first, without CASCADE: a REF column still holding the type keeps
    # the drop refused, as Oracle's ORA-02303 does.
    drop = _translate_ddl('DROP TYPE person_t')
    assert drop.endswith('; DROP TYPE person_t')
    assert 'CASCADE' not in drop


def test_an_object_table_is_an_ordinary_table_with_a_hidden_object_id() -> None:
    # A typed table cannot take the stable row id a REF needs, so an object
    # table is the type's columns plus `sys_nc_oid$`, recorded with its type.
    out = _translate_ddl('CREATE TABLE people OF person_t')
    assert out.startswith(
        'CREATE TABLE people (LIKE person_t, "sys_nc_oid$" uuid NOT NULL '
        'DEFAULT gen_random_uuid() UNIQUE); '
    )
    assert "INSERT INTO sys.ora_object_tables VALUES ('people'::regclass" in out


def test_a_whole_lob_call_item_is_a_lob_column() -> None:
    # PostgreSQL describes a computed domain value by its base type, so a select
    # list item that is one LOB call is typed from the call itself (#1351).
    from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_CLOB

    assert _computed_column_types(
        'SELECT id, to_clob(\'a, b\') AS c, sys.empty_blob(), EMPTY_CLOB() "x" FROM t'
    ) == {1: TNS_TYPE_CLOB, 2: TNS_TYPE_BLOB, 3: TNS_TYPE_CLOB}
    # A call inside an expression, a star list whose positions are the expanded
    # columns', and a statement that is not a SELECT map nothing.
    # An IntervalYM bind as the translation writes it is YEAR TO MONTH (#1401).
    from seerdb.common.tns_consts import TNS_TYPE_INTERVALYM

    assert _computed_column_types(
        'SELECT make_interval(months => %(p1)s) v, n FROM t'
    ) == {0: TNS_TYPE_INTERVALYM}
    assert _computed_column_types("SELECT to_clob('a') || 'b' FROM dual") == {}
    assert _computed_column_types("SELECT *, to_clob('a') FROM t") == {}
    assert _computed_column_types("INSERT INTO t VALUES (to_clob('a'))") == {}


def test_declared_columns_record_what_postgresql_keeps_less_of() -> None:
    # What sys.ora_columns records from a DDL (#1386): a RAW(n)'s length, None for
    # a type it records nothing for, no constraint as a column, and a MODIFY that
    # changes no type left out so the column's record survives it.
    assert _declared_columns(
        'CREATE TABLE t (id NUMBER, r RAW(30), "Q" raw (5), CONSTRAINT pk PRIMARY KEY (id))'
    ) == ('t', {'id': None, 'r': ('RAW', 30, None, None), 'Q': ('RAW', 5, None, None)})
    assert _declared_columns('ALTER TABLE s.t ADD (a RAW(8), b DATE)') == (
        's.t',
        {'a': ('RAW', 8, None, None), 'b': None},
    )
    assert _declared_columns('ALTER TABLE t MODIFY (r NOT NULL, q VARCHAR2(10))') == (
        't',
        {'q': None},
    )
    assert _declared_columns('CREATE TABLE t (l LONG, longer NUMBER)') == (
        't',
        {'l': ('LONG', 0, None, None), 'longer': None},
    )
    assert _declared_columns('CREATE TABLE t (r long  raw NOT NULL)') == (
        't',
        {'r': ('LONG RAW', 0, None, None)},
    )
    assert _declared_columns(
        'CREATE TABLE t (a INTERVAL DAY TO SECOND, b interval day (3) to second(2), '
        'c INTERVAL YEAR TO MONTH NOT NULL, d INTERVAL YEAR(4) TO MONTH)'
    ) == (
        't',
        {
            'a': ('INTERVAL DAY(2) TO SECOND(6)', 11, 2, 6),
            'b': ('INTERVAL DAY(3) TO SECOND(2)', 11, 3, 2),
            'c': ('INTERVAL YEAR(2) TO MONTH', 5, 2, 0),
            'd': ('INTERVAL YEAR(4) TO MONTH', 5, 4, 0),
        },
    )
    assert _declared_columns(
        'CREATE TABLE t (a FLOAT, b float (10), c REAL, d DOUBLE  PRECISION, '
        'e BINARY_FLOAT, f FLOATING)'
    ) == (
        't',
        {
            'a': ('FLOAT', 22, 126, None),
            'b': ('FLOAT', 22, 10, None),
            'c': ('FLOAT', 22, 63, None),
            'd': ('FLOAT', 22, 126, None),
            'e': None,
            'f': None,
        },
    )
    assert _declared_columns('CREATE TABLE t (n NCLOB, c CLOB, nclobby NUMBER)') == (
        't',
        {'n': ('NCLOB', 4000, None, None), 'c': None, 'nclobby': None},
    )
    # An object type's attributes, as a table's columns (#1431).
    assert _declared_columns(
        'CREATE OR REPLACE TYPE s.o FORCE AS OBJECT (n NCLOB, c CLOB, r RAW(4))'
    ) == (
        's.o',
        {'n': ('NCLOB', 4000, None, None), 'c': None, 'r': ('RAW', 4, None, None)},
    )
    assert _declared_columns('CREATE TYPE l AS TABLE OF NCLOB') is None
    assert _declared_columns(
        'CREATE TABLE t (v NVARCHAR2(20), w nvarchar2 (5 CHAR), x VARCHAR2(9))'
    ) == (
        't',
        {
            'v': ('NVARCHAR2', 40, None, None),
            'w': ('NVARCHAR2', 10, None, None),
            'x': None,
        },
    )
    assert _declared_columns('CREATE TABLE t (n NCHAR(5), m nchar, c CHAR(3))') == (
        't',
        {'n': ('NCHAR', 10, None, None), 'm': ('NCHAR', 2, None, None), 'c': None},
    )
    assert _declared_columns('DROP TABLE t') is None


def test_a_national_cast_is_found_in_the_select_list() -> None:
    # The select-list casts to NVARCHAR2(n) / NCHAR[(n)], each with its n, from
    # the Oracle statement (#1440); one inside an expression is not the item.
    from seerdb.server.backends.postgres import _computed_national_columns

    assert _computed_national_columns(
        "SELECT CAST('X' AS VARCHAR2(1)), CAST(SUBSTR(a, 1, 2) AS NVARCHAR2(5)) k, "
        'cast(b as nchar), CAST(c AS NCHAR(3)) AS d FROM t'
    ) == {1: 5, 2: 1, 3: 3}
    assert (
        _computed_national_columns("SELECT CAST(a AS NVARCHAR2(5)) || 'x' FROM t") == {}
    )
    assert _computed_national_columns('SELECT * FROM t') == {}
    # A national literal is NCHAR of its length, as 23ai describes it (#1586);
    # a plain literal is not national, nor is one inside an expression.
    assert _computed_national_columns(
        "SELECT n'xyz', 'abc', N'it''s' AS q, N'a' || 'b' FROM dual"
    ) == {0: 3, 2: 4}


def test_an_unaliased_expression_is_named_by_its_text() -> None:
    # Oracle names an unaliased computed select item by its own text, every
    # space dropped and the rest upper-cased -- its literals and comments too;
    # a pseudo-column by its name; a column or an aliased item keeps its name
    # (#1449). The names are 23ai's.
    from seerdb.server.backends.postgres import _expression_names

    assert _expression_names(
        "SELECT length( 'ab' ), upper(a), 1 + 2, 'lit', 'a b', n'x' FROM t"
    ) == {
        0: "LENGTH('AB')",
        1: 'UPPER(A)',
        2: '1+2',
        3: "'LIT'",
        4: "'AB'",
        5: "N'X'",
    }
    assert _expression_names(
        'SELECT nvl(substr(a, 1, 2), \'x\'), t.n + 1, "Mixed" + 1, n, t.a, (n), '
        '"Mixed" FROM t'
    ) == {0: "NVL(SUBSTR(A,1,2),'X')", 1: 'T.N+1', 2: '"MIXED"+1'}
    assert _expression_names(
        "SELECT sysdate - sysdate, n * 2 /* c */, n\n +\n 3, 'It''s', count(*) FROM t"
    ) == {
        0: 'SYSDATE-SYSDATE',
        1: 'N*2/*C*/',
        2: 'N+3',
        3: "'IT''S'",
        4: 'COUNT(*)',
    }
    assert _expression_names('SELECT n AS al, n "Q", n x, sysdate, user FROM t') == {
        3: 'SYSDATE',
        4: 'USER',
    }
    assert _expression_names('SELECT * FROM t') == {}


def test_a_constant_select_item_is_found() -> None:
    # Oracle folds a select item of literals, operators and calls of literals,
    # and a NUMBER one describes with precision 0 and scale -127; one computed
    # from a column, a bind, a pseudo-column, a subquery or an aggregate has
    # neither (#1444). The positions match 23ai's describes.
    from seerdb.server.backends.postgres import _constant_items

    assert _constant_items('SELECT 1, 1.5, -2, 1e3 FROM dual') == {0, 1, 2, 3}
    assert _constant_items('SELECT 1 + 1, count(*), 1 AS one, 2 "Two" FROM dual') == {
        0,
        2,
        3,
    }
    assert _constant_items(
        "SELECT n + 1, abs(-1), round(p), mod(5, 2), length('ab'), nvl(n, 0), "
        '(SELECT 1 FROM dual) FROM t'
    ) == {1, 3, 4}
    assert _constant_items('SELECT rownum, level, :1, sysdate, n x FROM t') == set()
    assert _constant_items('SELECT * FROM t') == set()


def test_a_select_lists_readings_are_kept_per_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The describe reads a query's select list six ways on every call, each a
    # pass of the tokenizer; each reading depends on the text alone, so it is
    # kept per text (#1884). A long text is read every time.
    import seerdb.server.backends.postgres as pg

    passes: list[str] = []
    real = pg._top_level_words

    def counted(text: str, *args: Any, **kwargs: Any) -> Any:
        passes.append(text)
        return real(text, *args, **kwargs)

    monkeypatch.setattr(pg, '_top_level_words', counted)
    readings = (
        pg._computed_column_types,
        pg._computed_national_columns,
        pg._computed_vector_columns,
        pg._constant_items,
        pg._constructor_items,
        pg._expression_names,
    )
    sql = "SELECT n + 1, CAST(a AS NVARCHAR2(5)), t_arr(1), 'x' FROM t1884k"
    first = [reading(sql) for reading in readings]
    assert len(passes) >= len(readings)
    passes.clear()
    assert [reading(sql) for reading in readings] == first
    assert passes == []
    long = sql + ' WHERE ' + ' AND '.join(['n = 1'] * 2000)
    for reading in readings:
        reading(long)
    passes.clear()
    assert [reading(long) for reading in readings] == [
        reading(sql) for reading in readings
    ]
    assert len(passes) >= len(readings)


def test_a_one_element_constructor_is_spelt_as_a_call() -> None:
    # `name('x')` for a collection type: PostgreSQL reads it as a cast to the
    # type, so it is spelt `name(VARIADIC ARRAY['x'])` (#1435). Other calls,
    # unknown names and a call through an alias are left alone.
    from seerdb.server.backends.postgres import _spell_one_element_constructors

    names = frozenset({'l', 'pyo.l'})
    assert _spell_one_element_constructors("INSERT INTO t VALUES (L('a'))", names) == (
        "INSERT INTO t VALUES (L(VARIADIC ARRAY['a']))"
    )
    assert _spell_one_element_constructors("SELECT pyo.l(N'z') FROM t", names) == (
        "SELECT pyo.l(VARIADIC ARRAY[N'z']) FROM t"
    )
    for sql in (
        "SELECT l('a', 'b'), l(), upper('x') FROM t",
        "SELECT x.l('a') FROM t x",
    ):
        assert _spell_one_element_constructors(sql, names) == sql


def test_a_block_with_binds_becomes_a_do_block() -> None:
    # Each bind becomes a typed local, initialised with its value, whose value
    # the block leaves in a setting before it ends -- a REF CURSOR's its portal
    # name (#1456, #1459). Bind names are found, and replaced, past literals.
    from seerdb.server.backends.postgres import _bind_block, _bind_names, _replace_binds

    block = "BEGIN OPEN :c FOR SELECT ':x' FROM t WHERE k BETWEEN :a AND :b; END;"
    assert _bind_names(block) == ['c', 'a', 'b']
    assert _replace_binds(block, {'a': '2'}) == (
        "BEGIN OPEN :c FOR SELECT ':x' FROM t WHERE k BETWEEN 2 AND :b; END;"
    )
    out = _bind_block(
        block,
        {
            'c': (0, 'refcursor', 'NULL'),
            'a': (1, 'numeric', '2'),
            'b': (2, 'numeric', '4'),
        },
    )
    assert out.startswith('DO $$ DECLARE')
    assert 'mirror_bind_0 refcursor := NULL;' in out
    assert 'mirror_bind_1 numeric := 2;' in out
    assert (
        "OPEN mirror_bind_0 FOR SELECT ':x' FROM t WHERE k BETWEEN mirror_bind_1 AND mirror_bind_2;"
        in out
    )
    assert (
        "set_config('mirror.block_bind_0', CASE WHEN mirror_bind_0 IS NULL THEN '' "
        in out
    )
    declared = _bind_block(
        'DECLARE t NUMBER; BEGIN t := :1; :2 := t * 2; END;',
        {'1': (0, 'numeric', '21'), '2': (1, 'numeric', 'NULL')},
    )
    assert 't numeric;' in declared and 'mirror_bind_1 := t * 2;' in declared


def test_delete_without_from_gains_it() -> None:
    # Oracle's `DELETE t` is PostgreSQL's `DELETE FROM t` (#1407); a DELETE that
    # has its FROM, and a word that merely starts with delete, are left alone.
    assert _translate_idioms('DELETE t WHERE n = 1') == 'DELETE FROM t WHERE n = 1'
    assert _translate_idioms('delete /*+ x */ "T"') == 'delete /*+ x */ FROM "T"'
    assert _translate_idioms('DELETE FROM t') == 'DELETE FROM t'
    assert _translate_idioms('SELECT deleted FROM t') == 'SELECT deleted FROM t'


def test_deref_becomes_a_parenthesised_sys_deref() -> None:
    assert _translate_idioms('SELECT id, DEREF(r).name FROM t') == (
        'SELECT id, (sys.deref(r)).name FROM t'
    )
    assert _translate_idioms('SELECT DEREF(:1).name FROM dual') == (
        'SELECT (sys.deref(:1)).name FROM dual'
    )


def test_attribute_access_through_an_alias_is_a_field_selection() -> None:
    # Oracle's alias.column.attribute is PostgreSQL's (alias.column).attribute
    # (#1434); a bare select item is named as Oracle names it, the path but the
    # alias; an UPDATE's SET target is column.attribute. A path not headed by
    # a correlation name is schema.table.column, and a method call is left be.
    assert _translate_idioms(
        'SELECT x.o.v, x.n.s.v, LENGTH(x.o.v), x.o.v AS w FROM t x '
        "WHERE x.o.v = 'a' ORDER BY x.o.id"
    ) == (
        'SELECT (x.o).v AS "O.V", ((x.n).s).v AS "N.S.V", LENGTH((x.o).v), '
        "(x.o).v AS w FROM t x WHERE (x.o).v = 'a' ORDER BY (x.o).id"
    )
    assert _translate_idioms("UPDATE t x SET x.o.v = 'b', k = x.o.id") == (
        "UPDATE t x SET o.v = 'b', k = (x.o).id"
    )
    assert _translate_idioms('SELECT s.t.c FROM s.t') == 'SELECT s.t.c FROM s.t'
    assert _translate_idioms('SELECT x.o.m() FROM t x') == 'SELECT x.o.m() FROM t x'


def test_an_object_attribute_reads_and_writes_through_an_alias() -> None:
    # SELECT, WHERE, ORDER BY and UPDATE through alias.column.attribute, a
    # nested object's too; the rows and names are 23ai's (#1434).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TYPE o1434 AS OBJECT (id NUMBER, v VARCHAR2(10))')
        backend.execute('CREATE TYPE o1434n AS OBJECT (k NUMBER, sub o1434)')
        backend.execute('CREATE TABLE t1434 (k NUMBER, o o1434, n o1434n)')
        backend.execute(
            "INSERT INTO t1434 VALUES (1, o1434(1, 'abc'), o1434n(5, o1434(7, 'deep')))"
        )
        backend.execute("INSERT INTO t1434 VALUES (2, o1434(2, 'xyz'), NULL)")
        result = backend.execute(
            'SELECT x.o.v, x.n.sub.v FROM t1434 x ORDER BY x.o.id DESC'
        )
        assert [column.name for column in result.columns] == [b'O.V', b'N.SUB.V']
        assert [tuple(row) for row in result.rows] == [('xyz', None), ('abc', 'deep')]
        backend.execute(
            "UPDATE t1434 x SET x.o.v = 'new', x.n.sub.v = 'nest' WHERE x.o.id = 1"
        )
        result = backend.execute(
            "SELECT x.o.v, x.n.sub.v FROM t1434 x WHERE x.o.v = 'new'"
        )
        assert [tuple(row) for row in result.rows] == [('new', 'nest')]
    finally:
        backend.rollback()
        for statement in ('DROP TABLE t1434', 'DROP TYPE o1434n', 'DROP TYPE o1434'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_numbered_placeholders_take_values_in_order_of_appearance() -> None:
    # A block's bind values fill its placeholders in the order they first
    # appear, whatever their numbers (#1380); a repeat, a `::` cast and a
    # literal or comment are no new placeholder.
    assert _bind_slots('BEGIN p(:3, c => :1, b => :2); END;') == {3: 0, 1: 1, 2: 2}
    assert _bind_slots("BEGIN :2 := f(:1, :2, ':9', x::int); -- :8\nEND;") == {
        2: 0,
        1: 1,
    }


def test_call_arguments_keep_their_names() -> None:
    # Each argument as (parameter name, bind): the name is what binds it to its
    # parameter, whatever order the call lists them in (#1377). Anything but a
    # plain bind leaves the call to the positional path.
    assert _call_arguments(':1, a_OutValue => :3, A_X=>:2') == [
        (None, 1),
        ('a_outvalue', 3),
        ('a_x', 2),
    ]
    assert _call_arguments('') == []
    assert _call_arguments(":1, 'literal'") is None
    assert _call_arguments('a => :1 + 1') is None


def test_a_call_argument_list_oracle_would_not_compile_is_ora_06550() -> None:
    # A name given twice (PLS-00703), or more arguments than the routine has
    # parameters (PLS-00306), is Oracle's compile error at the routine's name,
    # never an IndexError that ends the session (#1368).
    block = 'begin proc_Test(:1, :2, a_InValue => :3, a_OutValue => :4); end;'
    params = ['a_invalue', 'a_inoutvalue', 'a_outvalue']
    # a_InValue is the first positional argument AND named, as python-oracledb's
    # callproc('proc_Test', ('hi', 5), {'a_InValue': 'hi', ...}) sends it; 23ai
    # answers PLS-00703 although there is one argument too many as well.
    twice = _call_argument_error(
        block, 'proc_Test', ':1, :2, a_InValue => :3, a_OutValue => :4', params
    )
    assert twice is not None and twice.ora_code == 6550
    assert twice.ora_message == (
        'ORA-06550: line 1, column 7:\n'
        'PLS-00703: multiple instances of named argument in list'
    )
    extra = _call_argument_error(
        'BEGIN\n  pkg.p(:1, :2); END;', 'pkg.p', ':1, :2', ['a']
    )
    assert extra is not None and extra.ora_message == (
        'ORA-06550: line 2, column 3:\n'
        "PLS-00306: wrong number or types of arguments in call to 'P'"
    )
    # A call Oracle accepts, and one whose signature is unknown, pass.
    assert (
        _call_argument_error(block, 'proc_Test', ':1, a_outvalue => :2', params) is None
    )
    assert _call_argument_error(block, 'proc_Test', ':1, :2, :3, :4', None) is None
    # With no signature, two named arguments of one name are still caught.
    assert _call_argument_error(block, 'f', 'a => :1, A => :2', None) is not None


def test_dbms_debug_jdwp_calls_gain_their_parentheses() -> None:
    # Oracle calls them bare; PostgreSQL would read a bare one as a column (#1355).
    assert _translate_idioms(
        'SELECT DBMS_DEBUG_JDWP.CURRENT_SESSION_ID, '
        'dbms_debug_jdwp.current_session_serial() FROM dual'
    ) == (
        'SELECT dbms_debug_jdwp.CURRENT_SESSION_ID(), '
        'dbms_debug_jdwp.current_session_serial() FROM dual'
    )


def test_a_ref_survives_update_and_vacuum_full() -> None:
    # The point of the hidden object id: an UPDATE and a VACUUM FULL both move
    # the row physically (its ctid), and a stored REF still reaches it.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        for stmt in (
            'DROP TABLE t_refkeep',
            'DROP TABLE t_refpeople',
            'DROP TYPE t_refperson',
        ):
            try:
                backend.execute(stmt)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        backend.execute(
            'CREATE TYPE t_refperson AS OBJECT (id NUMBER, name VARCHAR2(40))'
        )
        backend.execute('CREATE TABLE t_refpeople OF t_refperson')
        backend.execute("INSERT INTO t_refpeople VALUES (1, 'Alice')")
        backend.execute('CREATE TABLE t_refkeep (id NUMBER, r REF t_refperson)')
        (ref,) = backend.execute(
            'SELECT REF(p) FROM t_refpeople p WHERE p.id = 1'
        ).rows[0]
        assert ref.type_name == 'T_REFPERSON'
        backend.execute('INSERT INTO t_refkeep (id, r) VALUES (:1, :2)', [100, ref])
        backend.execute("UPDATE t_refpeople SET name = 'Alicia' WHERE id = 1")
        backend.commit()
        backend._conn.autocommit = True
        backend._conn.execute('VACUUM FULL t_refpeople')
        backend._conn.autocommit = False
        rows = backend.execute(
            'SELECT id, DEREF(r).name FROM t_refkeep WHERE id = 100'
        ).rows
        assert rows == [(100, 'Alicia')]
        assert backend.execute('SELECT DEREF(:1).name FROM dual', [ref]).rows == [
            ('Alicia',)
        ]
        for stmt in (
            'DROP TABLE t_refkeep',
            'DROP TABLE t_refpeople',
            'DROP TYPE t_refperson',
        ):
            backend.execute(stmt)
        backend.commit()
    finally:
        backend.close()


def test_a_name_postgresql_reserves_is_quoted() -> None:
    # A name PostgreSQL reserves and Oracle does not is quoted, lower case
    # (#1595): where declared or listed for an INSERT, after a dot, and bare where
    # what follows shows a name. Oracle's own words and PostgreSQL's keywords in
    # their places are left be.
    from seerdb.server.backends.postgres import _quote_reserved_names as quote

    assert quote(
        'CREATE TABLE i (inner NUMBER, end NUMBER, primary NUMBER, '
        'CONSTRAINT pk PRIMARY KEY (inner))'
    ) == (
        'CREATE TABLE i ("inner" NUMBER, "end" NUMBER, "primary" NUMBER, '
        'CONSTRAINT pk PRIMARY KEY ("inner"))'
    )
    assert quote('CREATE TYPE o AS OBJECT (window NUMBER, analyse NUMBER)') == (
        'CREATE TYPE o AS OBJECT ("window" NUMBER, "analyse" NUMBER)'
    )
    assert quote('INSERT INTO i (inner, end) VALUES (1, :limit)') == (
        'INSERT INTO i ("inner", "end") VALUES (1, :limit)'
    )
    assert quote('SELECT inner, x.end FROM i x WHERE limit = 1 ORDER BY window') == (
        'SELECT "inner", x."end" FROM i x WHERE "limit" = 1 ORDER BY "window"'
    )
    for sql in (
        'SELECT a.x FROM a LEFT OUTER JOIN b ON a.k = b.k NATURAL JOIN c',
        'SELECT x FROM t ORDER BY x OFFSET 5 ROWS FETCH FIRST 3 ROWS ONLY',
        'BEGIN FETCH c BULK COLLECT INTO v LIMIT l_batch; END;',
        "SELECT CASE WHEN n > 1 THEN 'inner' END, CURRENT_DATE FROM dual",
        'ANALYZE TABLE t COMPUTE STATISTICS',
    ):
        assert quote(sql) == sql


def test_a_column_named_as_postgresql_reserves_round_trips() -> None:
    # A table and an object type whose names PostgreSQL reserves, created,
    # written, updated and read as 23ai does (#1595).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TABLE i1595 (inner NUMBER, window VARCHAR2(5), limit NUMBER, '
            'end NUMBER)'
        )
        backend.execute(
            "INSERT INTO i1595 (inner, window, limit, end) VALUES (1, 'w', 2, 3)"
        )
        backend.execute('UPDATE i1595 SET limit = limit + 1 WHERE inner = 1')
        result = backend.execute(
            'SELECT inner, window, limit, x.end FROM i1595 x ORDER BY window'
        )
        assert [column.name for column in result.columns] == [
            b'INNER',
            b'WINDOW',
            b'LIMIT',
            b'END',
        ]
        assert [tuple(row) for row in result.rows] == [(1, 'w', 3, 3)]
        backend.execute('CREATE TYPE oi1595 AS OBJECT (inner NUMBER, window NUMBER)')
        (row,) = backend.execute('SELECT oi1595(1, 2) FROM dual').rows
        assert (row[0].INNER, row[0].WINDOW) == (1, 2)
    finally:
        backend.rollback()
        for statement in ('DROP TABLE i1595', 'DROP TYPE oi1595'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_ref_select_matches_the_object_ref_fetch() -> None:
    # `SELECT REF(alias) FROM table alias [rest]` is recognised so the backend can
    # stand in the ctid + report the object type; the alias inside REF() must match
    # the table alias (#139).
    m = _REF_SELECT.match('SELECT REF(p) FROM PYORACLE_REF_PEOPLE p WHERE p.id = 1')
    assert m is not None
    assert m.group(1) == 'p' and m.group(2) == 'PYORACLE_REF_PEOPLE'
    assert m.group(3) == 'p' and m.group(4).strip() == 'WHERE p.id = 1'
    # A DEREF select (the 12c+ path) is not a REF fetch.
    assert _REF_SELECT.match('SELECT DEREF(r).name FROM t') is None


def test_translate_ddl_maps_interval_year_to_month_to_domain() -> None:
    # INTERVAL YEAR TO MONTH → the ora_intervalym domain (so the read path can tell
    # it from a DAY TO SECOND interval), while DAY TO SECOND stays a plain interval
    # (#504).
    sent = _translate_ddl(
        'CREATE TABLE t (ym INTERVAL YEAR(4) TO MONTH, ds INTERVAL DAY TO SECOND)'
    )
    assert 'ym ora_intervalym' in sent
    assert 'ds interval' in sent and 'ds ora_intervalym' not in sent


def test_translate_binds_wraps_interval_ym_as_make_interval() -> None:
    # An IntervalYM bind can't be sent as-is (psycopg has no dumper), so it becomes
    # make_interval(months => N) with N the whole-month count — 3y7m → 43, and a
    # negative -1y2m → -14 (IntervalYM normalises the sign) (#504).
    sql, params = _translate_binds(
        'INSERT INTO t VALUES (:1)', [seerdb.IntervalYM(3, 7)]
    )
    assert sql == 'INSERT INTO t VALUES (make_interval(months => %(b1)s))'
    assert params == {'b1': 43}
    _sql, neg = _translate_binds(
        'INSERT INTO t VALUES (:1)', [seerdb.IntervalYM(-1, -2)]
    )
    assert neg == {'b1': -14}


def test_translate_binds_skips_colon_in_quoted_identifier() -> None:
    # A ':' inside a double-quoted identifier (a column named "col:ons") is part of
    # the name, not a bind; the scanner copies the quoted region verbatim so the
    # real binds keep their values and positions (DifficultParametersTest).
    sql, params = _translate_binds(
        'INSERT INTO t (id, "col:ons") VALUES (:id, :v)', [1, 'x']
    )
    assert sql == 'INSERT INTO t (id, "col:ons") VALUES (%(id)s, %(v)s)'
    assert params == {'id': 1, 'v': 'x'}


def test_translate_binds_preserves_doubled_quotes() -> None:
    # A doubled quote is an escaped quote that stays inside the region -- '' in a
    # string literal and "" in an identifier -- so the copied SQL stays valid.
    lit, _ = _translate_binds("SELECT 'a''b' FROM t WHERE x = :v", ['z'])
    assert lit == "SELECT 'a''b' FROM t WHERE x = %(v)s"
    ident, _ = _translate_binds('SELECT "a""b", :v FROM t', ['z'])
    assert ident == 'SELECT "a""b", %(v)s FROM t'


def test_translate_binds_escapes_literal_percent() -> None:
    # psycopg reads a bound query as a format string, so a literal % (a LIKE
    # pattern, or a column name) must be doubled or it looks like a broken
    # placeholder; the generated %(name)s placeholders stay single.
    sql, params = _translate_binds(
        "SELECT id FROM t WHERE data LIKE '%' || :d || '%' ESCAPE '/'", ['b/%cde']
    )
    assert sql == "SELECT id FROM t WHERE data LIKE '%%' || %(d)s || '%%' ESCAPE '/'"
    assert params == {'d': 'b/%cde'}
    # A % inside a (double-quoted) identifier is doubled too.
    ident_sql, _ = _translate_binds(
        'INSERT INTO t (id, "%pct") VALUES (:id, :v)', [1, 'n']
    )
    assert ident_sql == 'INSERT INTO t (id, "%%pct") VALUES (%(id)s, %(v)s)'


def test_to_interval_ym_from_ora_interval() -> None:
    # An OraInterval (a timedelta carrying the whole-month count) → an IntervalYM;
    # IntervalYM normalises the split and shares the sign (#504). A None passes.
    empty = datetime.timedelta()
    assert _to_interval_ym(OraInterval(months=43, td=empty)) == seerdb.IntervalYM(3, 7)
    assert _to_interval_ym(OraInterval(months=-14, td=empty)) == seerdb.IntervalYM(
        -1, -2
    )
    assert _to_interval_ym(None) is None
    # A DAY TO SECOND interval carries months == 0 and keeps its exact duration, so
    # it is still a real timedelta the INTERVALDS encode path handles unchanged.
    ds = OraInterval(months=0, td=datetime.timedelta(days=2, seconds=11045))
    assert isinstance(ds, datetime.timedelta)
    assert ds == datetime.timedelta(days=2, seconds=11045)
    assert _to_interval_ym(ds) == seerdb.IntervalYM(0, 0)


def test_translate_ddl_time_zone_variants() -> None:
    # WITH LOCAL TIME ZONE normalises like PostgreSQL timestamptz; plain WITH TIME
    # ZONE preserves the entered offset, so it maps to the ora_tstz composite (#519).
    sent = _translate_ddl(
        'CREATE TABLE t (a TIMESTAMP WITH LOCAL TIME ZONE, '
        'b TIMESTAMP WITH TIME ZONE, c TIMESTAMP)'
    )
    assert 'a timestamptz' in sent
    assert 'b ora_tstz' in sent
    assert 'c timestamp' in sent and 'c ora_tstz' not in sent


def test_a_signed_year_format_is_given_a_postgresql_meaning() -> None:
    # PostgreSQL knows no S in SYYYY: reading it dropped the sign (4712 BC came
    # back AD), writing it printed a literal S (#1063). A parse loses the S --
    # PostgreSQL's YYYY reads -4712 as 4712 BC -- and a print goes to the helper
    # that writes the sign itself.
    assert (
        _translate_signed_year("SELECT TO_DATE('-4712-01-01', 'SYYYY-MM-DD') FROM dual")
        == "SELECT TO_DATE('-4712-01-01', 'YYYY-MM-DD') FROM dual"
    )
    assert _translate_signed_year(
        "SELECT TO_CHAR(TO_DATE('-4712-01-01', 'SYYYY-MM-DD'), 'SYYYY-MM-DD') FROM dual"
    ) == (
        "SELECT ora_to_char_signed(TO_DATE('-4712-01-01', 'YYYY-MM-DD'), "
        "'SYYYY-MM-DD') FROM dual"
    )
    assert _translate_signed_year("SELECT to_timestamp(:1, 'syyyy-mm-dd') FROM t") == (
        "SELECT to_timestamp(:1, 'YYYY-mm-dd') FROM t"
    )


def test_a_signed_year_rewrite_leaves_everything_else_alone() -> None:
    for sql in (
        "SELECT TO_CHAR(d, 'YYYY-MM-DD') FROM t",  # no signed year
        'SELECT TO_CHAR(d, :fmt) FROM t',  # a format that is not a literal
        "SELECT 'TO_DATE(x, ''SYYYY'')' FROM dual",  # inside a string literal
        "SELECT my_to_date(x, 'SYYYY') FROM t",  # another function's name
        "SELECT TO_DATE('x', 'SYYYY'",  # never closes
    ):
        assert _translate_signed_year(sql) == sql, sql


def test_a_bc_value_loads_as_a_bcdate() -> None:
    # psycopg refuses a year before 1; the backend's loaders fall back to the
    # BcDate the Mirror can serve (#1063). Everything else stays psycopg's.
    from psycopg.types.datetime import DateLoader, TimestampLoader

    from seerdb.server import BcDate

    date_loader = _bc_date_loader(DateLoader)(1082)
    stamp_loader = _bc_date_loader(TimestampLoader)(1114)
    assert date_loader.load(b'4712-01-01 BC') == BcDate(-4712, 1, 1)
    assert stamp_loader.load(b'0044-03-15 12:30:45.1234 BC') == BcDate(
        -44, 3, 15, 12, 30, 45, 123400
    )
    assert date_loader.load(b'2024-06-15') == datetime.date(2024, 6, 15)


def test_translate_idioms_rewrites_connect_by_level_row_generator() -> None:
    # FROM dual CONNECT BY LEVEL <= N maps to generate_series aliased `level`, so a
    # bare LEVEL in the select list resolves to its column (#531).
    simple = _translate_idioms('SELECT LEVEL FROM dual CONNECT BY LEVEL <= 5')
    assert simple == 'SELECT LEVEL FROM generate_series(1, 5) AS level'
    multi = _translate_idioms(
        'SELECT 42 AS k, LEVEL AS n FROM dual CONNECT BY LEVEL <= 200'
    )
    assert multi == 'SELECT 42 AS k, LEVEL AS n FROM generate_series(1, 200) AS level'
    # ROWNUM counts the generator's rows as LEVEL does, `< n` is n - 1 rows, and
    # n may be a bind, taken as Oracle compares a NUMBER with it; a ROWNUM in a
    # string stays (#1558).
    assert _translate_idioms(
        "SELECT 'rownum' || ROWNUM AS id FROM dual CONNECT BY ROWNUM <= :1"
    ) == (
        "SELECT 'rownum' || level AS id "
        'FROM generate_series(1, floor((:1)::numeric)::bigint) AS level'
    )
    assert _translate_idioms('SELECT LEVEL FROM dual CONNECT BY LEVEL < 4') == (
        'SELECT LEVEL FROM generate_series(1, 3) AS level'
    )
    assert _translate_idioms('SELECT count(*) FROM dual CONNECT BY ROWNUM < :n') == (
        'SELECT count(*) FROM generate_series(1, ceil((:n)::numeric)::bigint - 1) '
        'AS level'
    )


def test_translate_idioms_rewrites_decode_to_case() -> None:
    # orafce's decode resolves no untyped or mixed arguments; a CASE takes both,
    # and IS NOT DISTINCT FROM matches NULL with NULL as DECODE does (#822).
    assert _translate_idioms("SELECT decode('a', 'a', 'A', 'z') FROM dual") == (
        "SELECT CASE WHEN ('a') IS NOT DISTINCT FROM ('a') THEN 'A' ELSE 'z' END "
        'FROM dual'
    )
    assert _translate_idioms('SELECT DECODE(x, 1, 1, 2, 4) FROM t') == (
        'SELECT CASE WHEN (x) IS NOT DISTINCT FROM (1) THEN 1 '
        'WHEN (x) IS NOT DISTINCT FROM (2) THEN 4 END FROM t'
    )
    # Arguments are split at the top level only, and a nested DECODE is
    # rewritten too.
    assert _translate_idioms(
        "SELECT decode(decode(x, 1, f(a, b), 'y,z'), 'y,z', 0, 1) FROM t"
    ) == (
        'SELECT CASE WHEN (CASE WHEN (x) IS NOT DISTINCT FROM (1) THEN f(a, b) '
        "ELSE 'y,z' END) IS NOT DISTINCT FROM ('y,z') THEN 0 ELSE 1 END FROM t"
    )
    # PostgreSQL's own decode(data, format), a qualified call, another
    # function's name and a string are left alone.
    for untouched in (
        "SELECT decode(v, 'hex') FROM t",
        'SELECT pg_catalog.decode(a, b, c) FROM t',
        'SELECT my_decode(a, b, c) FROM t',
        "SELECT x FROM t WHERE c = 'decode(a, b, c)'",
    ):
        assert _translate_idioms(untouched) == untouched


def test_translate_idioms_rewrites_minus_to_except() -> None:
    # Oracle's MINUS set operator is PostgreSQL's EXCEPT; the SQLAlchemy Oracle
    # dialect's get_table_names query uses MINUS (#759).
    out = _translate_idioms('SELECT a FROM t MINUS SELECT b FROM u')
    assert out == 'SELECT a FROM t EXCEPT SELECT b FROM u'


def test_translate_ddl_strips_char_byte_length_semantics() -> None:
    # Oracle's VARCHAR2(20 CHAR) / CHAR(1 BYTE) length semantics — the CHAR/BYTE
    # qualifier PostgreSQL has no syntax for; dropped so it is a plain length (#759).
    out = _translate_ddl('CREATE TABLE t (a VARCHAR2(20 CHAR), b CHAR(1 BYTE))')
    assert '(20 CHAR)' not in out and '(1 BYTE)' not in out.upper()
    assert 'varchar(20)' in out and 'char(1)' in out.lower()


def test_translate_ddl_rewrites_create_sequence_keywords() -> None:
    # Oracle's NOMINVALUE / NOMAXVALUE / NOCYCLE are single words PostgreSQL spells
    # as two; NOCACHE has no PostgreSQL equal (minimum cache is 1) and ORDER /
    # NOORDER is a RAC hint with none, so it is dropped. Shared clauses pass through.
    out = _translate_ddl(
        'CREATE SEQUENCE s NOMINVALUE NOMAXVALUE NOCYCLE NOCACHE NOORDER'
    )
    assert out == 'CREATE SEQUENCE s NO MINVALUE NO MAXVALUE NO CYCLE CACHE 1'
    assert (
        _translate_ddl('CREATE SEQUENCE s START WITH 5 INCREMENT BY 2 CACHE 20')
        == 'CREATE SEQUENCE s START WITH 5 INCREMENT BY 2 CACHE 20'
    )


def test_translate_idioms_rewrites_sequence_pseudocolumns() -> None:
    # Oracle's seq.nextval / seq.currval are PostgreSQL nextval('seq') / currval('seq').
    assert (
        _translate_idioms('INSERT INTO t (id) VALUES (my_seq.nextval)')
        == "INSERT INTO t (id) VALUES (nextval('my_seq'))"
    )
    assert (
        _translate_idioms('SELECT my_seq.currval FROM dual')
        == "SELECT currval('my_seq') FROM dual"
    )


def test_translate_idioms_rewrites_cast_string_type() -> None:
    # A CAST to an Oracle string type in DML is translated like a column type: the
    # VARCHAR2/NVARCHAR2 keyword becomes varchar and the CHAR/BYTE length qualifier
    # is dropped (the column-type rewrites only fire on CREATE TABLE).
    assert (
        _translate_idioms('INSERT INTO t (x) VALUES (CAST(:v AS VARCHAR2(50 CHAR)))')
        == 'INSERT INTO t (x) VALUES (CAST(:v AS varchar(50)))'
    )
    assert (
        _translate_idioms('SELECT CAST(x AS NVARCHAR2(10)) FROM t')
        == 'SELECT CAST(x AS varchar(10)) FROM t'
    )


def test_translate_idioms_parenthesizes_offset_fetch_expression() -> None:
    # The 12c dialect's OFFSET/FETCH: PostgreSQL accepts only a restricted expression
    # before ROWS, so a bare `OFFSET 1 + 2 ROWS` is a syntax error. Wrap the operand
    # in parentheses (a bare literal or bind is already fine, the parens are harmless).
    assert (
        _translate_idioms(
            'SELECT x FROM t ORDER BY x OFFSET 1 + 2 ROWS FETCH FIRST 3 ROWS ONLY'
        )
        == 'SELECT x FROM t ORDER BY x OFFSET (1 + 2) ROWS FETCH FIRST (3) ROWS ONLY'
    )
    assert (
        _translate_idioms('SELECT x FROM t ORDER BY x OFFSET :o ROWS')
        == 'SELECT x FROM t ORDER BY x OFFSET (:o) ROWS'
    )


def test_drop_table_purge_is_a_plain_drop() -> None:
    # PostgreSQL has no recycle bin, so DROP TABLE already purges (#1207); a
    # table merely called that is left alone.
    assert _translate_ddl('DROP TABLE t PURGE') == 'DROP TABLE t'
    assert _translate_ddl('drop table s.t purge') == 'drop table s.t'
    assert _translate_ddl('DROP TABLE purge') == 'DROP TABLE purge'


def test_table_compression_is_dropped() -> None:
    # A storage hint with no PostgreSQL equal (#1182); only the table clause
    # goes, so a column that happens to be called that survives.
    for clause in ('nocompress', 'COMPRESS', 'compress basic', 'ROW STORE COMPRESS'):
        assert _translate_ddl(f'CREATE TABLE t (id NUMBER, l LONG) {clause}') == (
            'CREATE TABLE t (id numeric, l text)'
        )
    kept = _translate_ddl('CREATE TABLE t (id NUMBER, "COMPRESS" NUMBER)')
    assert kept == 'CREATE TABLE t (id numeric, "COMPRESS" numeric)'


def _type_ddl(sql: str) -> str:
    # What _translate_ddl makes of type DDL, without the constructors a
    # collection type now comes with, or the constructor drop ahead of a DROP
    # TYPE: those have their own test (#1206).
    translated = re.sub(
        r'DO \$\$ DECLARE f regprocedure;.*?END \$\$; ', '', _translate_ddl(sql)
    )
    translated = translated.split('; DO $$ DECLARE t regtype')[0]
    return translated.split('; CREATE OR REPLACE FUNCTION')[0]


def test_a_collection_type_comes_with_its_constructors() -> None:
    # `t(e1, e2, …)` and the empty `t()`, made with the type, and dropped
    # with it: DROP TYPE and the drop inside CREATE OR REPLACE TYPE remove
    # the functions named as the type and returning it first (#1206).
    made = _translate_ddl('create type s.a as varray(3) of number')
    assert 'CREATE OR REPLACE FUNCTION s.a(VARIADIC numeric[]) RETURNS s.a' in made
    assert 'CREATE OR REPLACE FUNCTION s.a() RETURNS s.a' in made
    assert 'FUNCTION s.t(VARIADIC numeric[])' in _translate_ddl(
        'CREATE TYPE s.t AS TABLE OF NUMBER'
    )
    dropped = _translate_ddl('DROP TYPE s.a')
    assert dropped.startswith('DO $$') and dropped.endswith('; DROP TYPE s.a')
    assert "to_regtype('s.a')" in dropped
    # An object type's constructor is built from the catalog once the type
    # exists, one argument per attribute.
    obj = _translate_ddl('CREATE TYPE s.o AS OBJECT (a NUMBER, b VARCHAR2(5));')
    assert obj.startswith('CREATE TYPE s.o AS (a numeric, b varchar(5)); ')
    assert obj.index('; CREATE TYPE s.o$ref') < obj.index('; DO $$ DECLARE t regtype')
    assert "to_regtype('s.o')" in obj and 'SELECT ROW(%s)::%s' in obj
    replaced = _translate_ddl('CREATE OR REPLACE TYPE s.a AS VARRAY(3) OF NUMBER')
    assert replaced.startswith('DO $$') and '; DROP TYPE IF EXISTS s.a; ' in replaced


def test_a_replaced_type_is_dropped_and_created() -> None:
    # PostgreSQL has no CREATE OR REPLACE TYPE; the old type goes, without
    # CASCADE, and the new one is translated as a plain CREATE TYPE (#1197). The
    # REF companions of an object type depend on it, so they go first when they
    # exist, and a replaced object type gets new ones (#1127).
    companions_first = (
        "DO $$ BEGIN IF to_regtype('s.o$ref') IS NOT NULL THEN "
        "PERFORM sys.ora_drop_deref(to_regtype('s.o$ref')); DROP TYPE s.o$ref; "
        'END IF; END $$'
        '; DROP TYPE IF EXISTS s.o; CREATE TYPE s.o AS (a numeric)'
    )
    replaced_object = _type_ddl('CREATE OR REPLACE TYPE s.o AS OBJECT (a NUMBER)')
    assert replaced_object.startswith(companions_first)
    assert '; CREATE TYPE s.o$ref AS (tab oid, id uuid)' in replaced_object
    assert _type_ddl('create or replace type s.v as varray(4) of number;').endswith(
        '; DROP TYPE IF EXISTS s.v; CREATE DOMAIN s.v AS numeric[] '
        'CHECK (VALUE IS NULL OR array_length(VALUE, 1) <= 4)'
    )
    assert _type_ddl('create or replace type s.t\n    as table of s.o;').endswith(
        '; DROP TYPE IF EXISTS s.t; CREATE DOMAIN s.t AS s.o[]'
    )
    # FORCE is not translated.
    forced = 'CREATE OR REPLACE TYPE s.o FORCE AS OBJECT (a NUMBER)'
    assert not _type_ddl(forced).startswith(('DROP TYPE', 'DO $$'))
    # A type something depends on is refused as Oracle refuses it; the same
    # SQLSTATE on another statement keeps the generic code.
    held = _FakePgError('2BP01', 'cannot drop type s.o because other objects depend')
    assert _backend_error(held, original='DROP TYPE s.o').ora_code == 2303
    replaced = 'CREATE OR REPLACE TYPE s.o AS OBJECT (a NUMBER)'
    assert _backend_error(held, original=replaced).ora_code == 2303
    assert _backend_error(held, original='DROP TABLE t').ora_code != 2303


def test_a_nested_table_type_becomes_an_unbounded_array_domain() -> None:
    # A nested table has no maximum size, so no CHECK (#1194); the element type
    # is mapped as a column's, and may be another collection type.
    assert _type_ddl('create type s.t as table of number;') == (
        'CREATE DOMAIN s.t AS numeric[]'
    )
    assert _type_ddl('CREATE TYPE s.v AS TABLE OF VARCHAR2(20)') == (
        'CREATE DOMAIN s.v AS varchar(20)[]'
    )
    assert _type_ddl('create type s.tt\n    as table of s.t;') == (
        'CREATE DOMAIN s.tt AS s.t[]'
    )


def test_nested_table_storage_clauses_are_dropped() -> None:
    # One clause per nested-table column, with or without RETURN AS (#1253).
    ddl = (
        'CREATE TABLE t (id NUMBER, v s.nt, "W" s.nt) '
        'NESTED TABLE v STORE AS t_v '
        'nested table "W" store as s.t_w return as locator'
    )
    assert _translate_ddl(ddl) == 'CREATE TABLE t (id numeric, v s.nt, "W" s.nt)'
    # The storage table's own properties, a collection of collections' inner
    # clause among them, go with it; quoted parentheses do not count (#1275).
    nested = (
        'CREATE TABLE t (c s.tt) NESTED TABLE c STORE AS t_nt '
        '(NESTED TABLE COLUMN_VALUE STORE AS t_nti) RETURN AS VALUE'
    )
    assert _translate_ddl(nested) == 'CREATE TABLE t (c s.tt)'
    quoted = "CREATE TABLE t (c s.nt) NESTED TABLE c STORE AS t_nt (COMMENT 'a (b')"
    assert _translate_ddl(quoted) == 'CREATE TABLE t (c s.nt)'


def test_a_varray_type_becomes_a_bounded_array_domain() -> None:
    # The bound rides in a CHECK; a script's trailing `;`, which Oracle accepts
    # on type DDL, stays out of the element type.
    bounded = (
        'CREATE DOMAIN s.a AS numeric[] '
        'CHECK (VALUE IS NULL OR array_length(VALUE, 1) <= 10)'
    )
    assert _type_ddl('create type s.a as varray(10) of number') == bounded
    assert _type_ddl('create type s.a as varray(10) of number;') == bounded
    assert _type_ddl('create type s.o as\n    varray(10) of s.sub;') == (
        'CREATE DOMAIN s.o AS s.sub[] '
        'CHECK (VALUE IS NULL OR array_length(VALUE, 1) <= 10)'
    )


def test_leading_comments_are_dropped_before_the_statement_is_recognised() -> None:
    # Every rewrite recognises a statement by its first word, so a comment ahead
    # of it has to go first. A hint INSIDE the statement is left alone, and an
    # unterminated comment is not guessed at.
    assert _strip_leading_comments('-- make it\nCREATE TABLE t (n NUMBER)') == (
        'CREATE TABLE t (n NUMBER)'
    )
    assert _strip_leading_comments('/* a */ -- b\n  SELECT 1 FROM dual') == (
        'SELECT 1 FROM dual'
    )
    assert _strip_leading_comments('SELECT /*+ hint */ 1 FROM dual') == (
        'SELECT /*+ hint */ 1 FROM dual'
    )
    assert _strip_leading_comments('/* unterminated SELECT 1') == (
        '/* unterminated SELECT 1'
    )


def test_a_replaced_view_falls_back_to_drop_and_create() -> None:
    # PostgreSQL's OR REPLACE refuses to change a view column's type, or to drop
    # or rename one; Oracle's replaces the view. The replacement is tried as
    # written and only that refusal drops the view -- plainly, not CASCADE.
    out = _translate_ddl('CREATE OR REPLACE FORCE VIEW s.v AS SELECT 1 c FROM dual')
    assert out.startswith(
        'DO $$ BEGIN EXECUTE $seerdb_view$CREATE OR REPLACE VIEW s.v '
    )
    assert 'EXCEPTION WHEN invalid_table_definition THEN' in out
    assert 'DROP VIEW s.v$seerdb_view$' in out
    assert 'CASCADE' not in out and 'FORCE' not in out
    # A plain CREATE VIEW is left as it was.
    assert _translate_ddl('CREATE VIEW v AS SELECT 1 x FROM dual') == (
        'CREATE VIEW v AS SELECT 1 x FROM dual'
    )


def test_translate_admin_maps_session_user_and_index() -> None:
    # Oracle session/user admin → PostgreSQL: schema resolution is search_path, a
    # user is a schema, and grants/tablespace admin no-op; a schema-qualified index
    # name loses the qualifier (#759).
    # `sys` precedes `oracle` because both define `user_tables`-style views and the
    # dictionary's has to win; orafce's answers with raw lower-case names, so a
    # session could not find the table it had just created (#818).
    assert (
        _translate_admin('ALTER SESSION SET CURRENT_SCHEMA = TEST_SCHEMA')
        == 'SET search_path TO test_schema, public, sys, oracle, pg_catalog, pg_temp'
    )
    assert (
        _translate_admin('CREATE USER test_schema IDENTIFIED BY secret')
        == 'CREATE SCHEMA IF NOT EXISTS test_schema'
    )
    assert _translate_admin('GRANT CREATE SESSION TO test_schema') == _NO_OP
    assert (
        _translate_admin('CREATE INDEX test_schema.ix1 ON test_schema.t (c)')
        == 'CREATE INDEX ix1 ON test_schema.t (c)'
    )


def test_a_session_formats_dates_by_its_nls_date_format() -> None:
    # TO_CHAR of a DATE with no format follows the session's NLS_DATE_FORMAT
    # (#1616): Oracle's DD-MON-RR from the start, then what ALTER SESSION set,
    # which NLS_SESSION_PARAMETERS reports. RR prints as YY does. The values
    # are 23ai's.
    assert _translate_admin("ALTER SESSION SET NLS_DATE_FORMAT = 'DD-MON-RRRR'") == (
        "SET orafce.nls_date_format = 'DD-MON-YYYY'; "
        "SET seerdb.nls_date_format = 'DD-MON-RRRR'"
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    date = "TO_DATE('2000-12-15 07:03', 'YYYY-MM-DD HH24:MI')"
    try:
        backend.authenticate('pyo')

        def session_format() -> str:
            return backend.execute(
                'SELECT value FROM nls_session_parameters '
                "WHERE parameter = 'NLS_DATE_FORMAT'"
            ).rows[0][0]

        assert backend.execute(f'SELECT TO_CHAR({date}) FROM dual').rows == [
            ('15-DEC-00',)
        ]
        assert session_format() == 'DD-MON-RR'
        backend.execute("ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD HH24:MI'")
        assert backend.execute(f'SELECT TO_CHAR({date}) FROM dual').rows == [
            ('2000-12-15 07:03',)
        ]
        assert session_format() == 'YYYY-MM-DD HH24:MI'
        # An ALTER SESSION outlives a rollback, as Oracle's does.
        backend.rollback()
        assert session_format() == 'YYYY-MM-DD HH24:MI'
    finally:
        backend.rollback()
        backend.close()


def test_a_datetime_converted_to_text_follows_the_sessions_nls_formats() -> None:
    # A DATE or TIMESTAMP made text without a format -- by ||, CONCAT or
    # TO_CHAR(x) -- came out as PostgreSQL's text, and TO_CHAR(ts) as a DATE
    # (#2162). 23ai's, d at 13:14:15 and each TIMESTAMP at 13:14:15.5: a DATE
    # in NLS_DATE_FORMAT, a TIMESTAMP in NLS_TIMESTAMP_FORMAT, FF as many
    # digits as its precision, and no radix point at precision 0.
    assert _translate_admin(
        "ALTER SESSION SET NLS_TIMESTAMP_FORMAT = 'RR-MM-DD HH24:MI:SSXFF'"
    ) == (
        "SET seerdb.nls_timestamp_print = 'YY-MM-DD HH24:MI:SSXFF'; "
        "SET seerdb.nls_timestamp_format = 'RR-MM-DD HH24:MI:SSXFF'"
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2162 (d DATE, ts TIMESTAMP, ts3 TIMESTAMP(3), '
            'ts0 TIMESTAMP(0))'
        )
        try:
            backend.execute(
                "INSERT INTO t2162 VALUES (TIMESTAMP '2024-01-02 13:14:15', "
                "TIMESTAMP '2024-01-02 13:14:15.5', TIMESTAMP '2024-01-02 13:14:15.5', "
                "TIMESTAMP '2024-01-02 13:14:15')"
            )
            assert backend.execute(
                "SELECT d || 'x', to_char(t.ts), ts || 'x', concat(ts3, 'x'), "
                "'x' || ts0 FROM t2162 t"
            ).rows == [
                (
                    '02-JAN-24x',
                    '02-JAN-24 01.14.15.500000 PM',
                    '02-JAN-24 01.14.15.500000 PMx',
                    '02-JAN-24 01.14.15.500 PMx',
                    'x02-JAN-24 01.14.15 PM',
                )
            ]
            backend.execute(
                "ALTER SESSION SET NLS_TIMESTAMP_FORMAT = 'YYYY-MM-DD HH24:MI:SSXFF'"
            )
            assert backend.execute("SELECT ts || 'x' FROM t2162").rows == [
                ('2024-01-02 13:14:15.500000x',)
            ]
            assert backend.execute(
                'SELECT value FROM nls_session_parameters '
                "WHERE parameter = 'NLS_TIMESTAMP_FORMAT'"
            ).rows == [('YYYY-MM-DD HH24:MI:SSXFF',)]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2162')
    finally:
        backend.close()


def test_a_datetime_whose_text_says_its_type_follows_the_nls_formats() -> None:
    # A DATE or TIMESTAMP literal, SYSDATE, TO_DATE and CAST made text came out
    # as PostgreSQL's (#2162). 23ai's: a TIMESTAMP literal at precision 9, a
    # CAST at its own; one with a zone is a TIMESTAMP WITH TIME ZONE.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        assert backend.execute(
            "SELECT DATE '2024-01-02' || 'x', "
            "'x' || TIMESTAMP '2024-01-02 13:14:15.5', "
            "to_char(TIMESTAMP '2024-01-02 13:14:15.5'), "
            "concat(TIMESTAMP '2024-01-02 13:14:15', 'x'), "
            "to_date('2024-01-02', 'YYYY-MM-DD') || 'x', "
            "CAST(TIMESTAMP '2024-01-02 13:14:15.5' AS TIMESTAMP(3)) || 'x', "
            "length(sysdate || 'x') FROM dual"
        ).rows == [
            (
                '02-JAN-24x',
                'x02-JAN-24 01.14.15.500000000 PM',
                '02-JAN-24 01.14.15.500000000 PM',
                '02-JAN-24 01.14.15.000000000 PMx',
                '02-JAN-24x',
                '02-JAN-24 01.14.15.500 PMx',
                10,
            )
        ]
        assert [
            found[2:]
            for found in _typed_datetime_operands(
                "SELECT TIMESTAMP '2024-01-02 13:14:15 +01:00' || 'x' FROM dual"
            )
        ] == [('sys.ora_tstz_text', 9)]
    finally:
        backend.close()


def test_a_datetime_cast_to_a_character_type_follows_the_nls_formats() -> None:
    # CAST(x AS VARCHAR2(n)) of a DATE or TIMESTAMP gave PostgreSQL's text
    # (#2162). 23ai's, d at 13:14:15 and each TIMESTAMP at 13:14:15.5: as ||
    # gives it, a CHAR blank-padded to its length.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2162c (d DATE, ts TIMESTAMP, t3 TIMESTAMP(3))')
        try:
            backend.execute(
                "INSERT INTO t2162c VALUES (TIMESTAMP '2024-01-02 13:14:15', "
                "TIMESTAMP '2024-01-02 13:14:15.5', TIMESTAMP '2024-01-02 13:14:15.5')"
            )
            assert backend.execute(
                'SELECT CAST(d AS VARCHAR2(30)), CAST(ts AS VARCHAR2(40)), '
                'CAST(t3 AS VARCHAR(40)), CAST(d AS CHAR(12)), '
                "CAST(DATE '2024-01-02' AS VARCHAR2(20)) FROM t2162c"
            ).rows == [
                (
                    '02-JAN-24',
                    '02-JAN-24 01.14.15.500000 PM',
                    '02-JAN-24 01.14.15.500 PM',
                    '02-JAN-24   ',
                    '02-JAN-24',
                )
            ]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2162c')
    finally:
        backend.close()


def test_a_datetime_assigned_to_a_character_column_follows_the_nls_formats() -> None:
    # A DATE or TIMESTAMP that an UPDATE or INSERT stored in a VARCHAR2 column
    # was PostgreSQL's text (#2162). 23ai's: the session's NLS format, FF at
    # the value's precision, by SET, by an INSERT's query or VALUES, with or
    # without a column list. A DATE column given a DATE stays one.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2162a (d DATE, ts TIMESTAMP, t3 TIMESTAMP(3), '
            'v VARCHAR2(40), d2 DATE)'
        )
        try:
            backend.execute(
                "INSERT INTO t2162a (d, ts, t3) VALUES (TIMESTAMP '2024-01-02 13:14:15', "
                "TIMESTAMP '2024-01-02 13:14:15.5', TIMESTAMP '2024-01-02 13:14:15.5')"
            )

            def stored() -> list:
                return backend.execute('SELECT v FROM t2162a WHERE d IS NOT NULL').rows

            backend.execute('UPDATE t2162a SET v = d, d2 = d')
            assert stored() == [('02-JAN-24',)]
            backend.execute('UPDATE t2162a SET v = ts')
            assert stored() == [('02-JAN-24 01.14.15.500000 PM',)]
            backend.execute("UPDATE t2162a SET v = DATE '2024-01-03'")
            assert stored() == [('03-JAN-24',)]
            backend.execute('INSERT INTO t2162a (v) SELECT t3 FROM t2162a')
            backend.execute(
                "INSERT INTO t2162a VALUES (NULL, NULL, NULL, DATE '2024-01-04', NULL)"
            )
            assert sorted(
                backend.execute('SELECT v FROM t2162a WHERE d IS NULL').rows
            ) == [('02-JAN-24 01.14.15.500 PM',), ('04-JAN-24',)]
            assert backend.execute(
                "SELECT to_char(d2, 'YYYY-MM-DD HH24:MI:SS') FROM t2162a "
                'WHERE d IS NOT NULL'
            ).rows == [('2024-01-02 13:14:15',)]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2162a')
    finally:
        backend.close()


def test_a_zoned_timestamp_made_text_follows_the_nls_formats() -> None:
    # A TIMESTAMP WITH TIME ZONE made text was the composite that holds it,
    # `("2024-01-02 16:14:15.5+05",7200)`, and TO_CHAR(tz) failed; a WITH
    # LOCAL TIME ZONE one was PostgreSQL's text (#2162). 23ai's, the session
    # at +05:00: WITH TIME ZONE in NLS_TIMESTAMP_TZ_FORMAT at its own offset,
    # WITH LOCAL TIME ZONE in NLS_TIMESTAMP_FORMAT at the session's zone.
    assert _translate_admin(
        "ALTER SESSION SET NLS_TIMESTAMP_TZ_FORMAT = 'RR-MM-DD TZH:TZM'"
    ) == (
        "SET seerdb.nls_timestamp_tz_print = 'YY-MM-DD TZH:TZM'; "
        "SET seerdb.nls_timestamp_tz_format = 'RR-MM-DD TZH:TZM'"
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute("ALTER SESSION SET TIME_ZONE = '+05:00'")
        backend.execute(
            'CREATE TABLE t2162z (tz TIMESTAMP WITH TIME ZONE, '
            'tz3 TIMESTAMP(3) WITH TIME ZONE, lz TIMESTAMP WITH LOCAL TIME ZONE)'
        )
        try:
            value = "TIMESTAMP '2024-01-02 13:14:15.5 +02:00'"
            backend.execute(f'INSERT INTO t2162z VALUES ({value}, {value}, {value})')
            assert backend.execute(
                "SELECT tz || 'x', concat(tz3, 'x'), lz || 'x', to_char(tz), "
                "CAST(tz AS VARCHAR2(60)), TIMESTAMP '2024-01-02 13:14:15 -05:30' "
                "|| 'x' FROM t2162z"
            ).rows == [
                (
                    '02-JAN-24 01.14.15.500000 PM +02:00x',
                    '02-JAN-24 01.14.15.500 PM +02:00x',
                    '02-JAN-24 04.14.15.500000 PMx',
                    '02-JAN-24 01.14.15.500000 PM +02:00',
                    '02-JAN-24 01.14.15.500000 PM +02:00',
                    '02-JAN-24 01.14.15.000000000 PM -05:30x',
                )
            ]
            backend.execute(
                'ALTER SESSION SET NLS_TIMESTAMP_TZ_FORMAT = '
                "'YYYY-MM-DD HH24:MI:SSXFF TZH:TZM'"
            )
            assert backend.execute("SELECT tz || 'x' FROM t2162z").rows == [
                ('2024-01-02 13:14:15.500000 +02:00x',)
            ]
            assert backend.execute(
                'SELECT value FROM nls_session_parameters '
                "WHERE parameter = 'NLS_TIMESTAMP_TZ_FORMAT'"
            ).rows == [('YYYY-MM-DD HH24:MI:SSXFF TZH:TZM',)]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2162z')
    finally:
        backend.close()


def test_a_computed_datetime_made_text_follows_the_nls_formats() -> None:
    # A computed DATE or TIMESTAMP made text was PostgreSQL's text (#2162).
    # 23ai's, d at 13:14:15 and each TIMESTAMP at 13:14:15.5: a DATE with a
    # number or an interval, a TIMESTAMP with a number and TRUNC / ADD_MONTHS
    # of either are DATEs; a TIMESTAMP with an interval a TIMESTAMP(9); NVL
    # and MAX keep their operand's type; a difference stays a number.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2162g (d DATE, ts TIMESTAMP, t3 TIMESTAMP(3), '
            'v VARCHAR2(40))'
        )
        try:
            backend.execute(
                "INSERT INTO t2162g (d, ts, t3) VALUES (TIMESTAMP '2024-01-02 13:14:15', "
                "TIMESTAMP '2024-01-02 13:14:15.5', TIMESTAMP '2024-01-02 13:14:15.5')"
            )
            for item, shown in (
                ('(d + 1)', '03-JAN-24'),
                ("(d + interval '1' hour)", '02-JAN-24'),
                ('(ts + 1)', '03-JAN-24'),
                ("(t3 + interval '1' day)", '03-JAN-24 01.14.15.500000000 PM'),
                ('add_months(d, 1)', '02-FEB-24'),
                ('trunc(ts)', '02-JAN-24'),
                ('nvl(ts, ts)', '02-JAN-24 01.14.15.500000 PM'),
                ('max(t3)', '02-JAN-24 01.14.15.500 PM'),
                ("(date '2024-01-02' + 1)", '03-JAN-24'),
                ('(d - d)', '0'),
            ):
                assert backend.execute(f"SELECT {item} || 'x' FROM t2162g").rows == [
                    (shown + 'x',)
                ], item
            backend.execute('UPDATE t2162g SET v = d + 1')
            assert backend.execute('SELECT v FROM t2162g').rows == [('03-JAN-24',)]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2162g')
    finally:
        backend.close()


def test_translate_admin_sets_the_session_time_zone_without_inverting_it() -> None:
    # A 12.1+ client sends ALTER SESSION SET TIME_ZONE at login. PostgreSQL reads
    # a bare offset as POSIX and INVERTS it (`SET TIME ZONE '+05:30'` runs at
    # -05:30), so the offset goes in as an explicit POSIX spec -- and is also
    # kept in Oracle's spelling, which SESSIONTIMEZONE reports back.
    assert _translate_admin("ALTER SESSION SET TIME_ZONE='+05:30'") == (
        "DO $$ BEGIN PERFORM set_config('TimeZone', '<+05:30>-05:30', false); "
        "PERFORM set_config('seerdb.time_zone', '+05:30', false); END $$"
    )
    # A single-digit hour is Oracle's to normalise; a negative sub-hour offset
    # keeps its sign.
    assert _translate_admin("alter session set time_zone = '-0:30'") == (
        "DO $$ BEGIN PERFORM set_config('TimeZone', '<-00:30>+00:30', false); "
        "PERFORM set_config('seerdb.time_zone', '-00:30', false); END $$"
    )
    # A region name means the same thing to both, and is echoed as given.
    assert _translate_admin("ALTER SESSION SET TIME_ZONE='Europe/Moscow'") == (
        "DO $$ BEGIN PERFORM set_config('TimeZone', 'Europe/Moscow', false); "
        "PERFORM set_config('seerdb.time_zone', 'Europe/Moscow', false); END $$"
    )
    # Any other ALTER SESSION is still the harmless no-op it was.
    assert _translate_admin("ALTER SESSION SET NLS_SORT='BINARY'") == _NO_OP


def test_sessiontimezone_reads_the_zone_the_session_was_given() -> None:
    # The Oracle spelling ALTER SESSION stored, or before any was set the
    # session's own offset in Oracle's `+hh:mm` form.
    assert _translate_idioms('SELECT sessiontimezone FROM dual') == (
        "SELECT coalesce(nullif(current_setting('seerdb.time_zone', true), ''), "
        "to_char(now(), 'TZH:TZM')) FROM dual"
    )
    # An ordinary statement is passed through untouched.
    assert _translate_admin('SELECT 1 FROM dual') == 'SELECT 1 FROM dual'


def test_to_char_prints_a_timestamp_fraction_as_oracle_does() -> None:
    # X, FF and FF7-FF9 printed as written, `SSXFF` as `15XFF` (#2167).
    # Measured on 23ai, a TIMESTAMP at 13:14:15.5: FFn n digits truncated, FF
    # the precision's, X the radix point; FX and quoted text stay themselves.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2167 (ts TIMESTAMP)')
        try:
            backend.execute(
                "INSERT INTO t2167 VALUES (TIMESTAMP '2024-01-02 13:14:15.5')"
            )
            for fmt, printed in (
                ('DD-MON-RR HH.MI.SSXFF AM', '02-JAN-24 01.14.15.500000 PM'),
                ('SS.FF', '15.500000'),
                ('SS.FF9', '15.500000000'),
                ('SS.FF1', '15.5'),
                ('SS.ff3', '15.500'),
                ('SSX', '15.'),
                ('SS"X"FF', '15X500000'),
                ('FXDD-MON-YYYY', '02-JAN-2024'),
                ('YYYY-MM-DD"T"HH24:MI:SS', '2024-01-02T13:14:15'),
            ):
                result = backend.execute(f"SELECT to_char(ts, '{fmt}') FROM t2167")
                assert result.rows == [(printed,)], fmt
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2167')
    finally:
        backend.close()


def test_to_char_prints_ff_at_the_values_own_precision() -> None:
    # FF printed six digits whatever the TIMESTAMP's precision (#2167). 23ai's,
    # each at 13:14:15.5 but ts0 at 13:14:15: a column's own precision, X left
    # out at 0, 9 for a literal or a TIMESTAMP with an interval, n for a CAST
    # to TIMESTAMP(n), MAX its column's.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2167p (ts TIMESTAMP, ts3 TIMESTAMP(3), ts0 TIMESTAMP(0))'
        )
        try:
            backend.execute(
                "INSERT INTO t2167p VALUES (TIMESTAMP '2024-01-02 13:14:15.5', "
                "TIMESTAMP '2024-01-02 13:14:15.5', TIMESTAMP '2024-01-02 13:14:15')"
            )
            assert backend.execute(
                "SELECT to_char(ts, 'SS.FF'), to_char(ts3, 'SS.FF'), "
                "to_char(t.ts0, 'SS.FF'), to_char(ts0, 'SSXFF'), "
                "to_char(ts3, 'SS\"X\"FF'), to_char(ts0, 'SS.FF3'), "
                "to_char(TIMESTAMP '2024-01-02 13:14:15.5', 'SS.FF'), "
                "to_char(ts3 + interval '1' day, 'SS.FF'), "
                "to_char(CAST(ts AS TIMESTAMP(2)), 'SS.FF') FROM t2167p t"
            ).rows == [
                (
                    '15.500000',
                    '15.500',
                    '15.',
                    '15',
                    '15X500',
                    '15.000',
                    '15.500000000',
                    '15.500000000',
                    '15.50',
                )
            ]
            assert backend.execute(
                "SELECT to_char(max(ts3), 'SS.FF') FROM t2167p"
            ).rows == [('15.500',)]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2167p')
    finally:
        backend.close()


def test_translate_idioms_rewrites_offset_bearing_timestamp_literal() -> None:
    # TIMESTAMP '<ts> ±HH:MM' is a WITH TIME ZONE value — build the composite so
    # the offset survives, rather than PostgreSQL's WITHOUT-time-zone parse dropping
    # it. A literal with no offset is an ordinary timestamp, left untouched (#519).
    with_offset = _translate_idioms("v := TIMESTAMP '2026-06-07 13:14:15.5 +02:00'")
    assert (
        "ROW(TIMESTAMPTZ '2026-06-07 13:14:15.5 +02:00', 7200)::ora_tstz" in with_offset
    )
    negative = _translate_idioms("TIMESTAMP '2026-05-23 10:11:12.345678 -05:30'")
    assert '-19800)::ora_tstz' in negative  # -(5*3600 + 30*60)
    plain = _translate_idioms("TIMESTAMP '2026-06-07 13:14:15.5'")
    assert plain == "TIMESTAMP '2026-06-07 13:14:15.5'"


def test_numtoyminterval_and_to_yminterval_are_year_to_month() -> None:
    # NUMTOYMINTERVAL did not exist (#2153), and TO_YMINTERVAL described as
    # DAY TO SECOND, its months read as days (#2152). Measured on 23ai: n
    # months, or n years of twelve, rounded half up; any other unit ORA-01760.
    from seerdb.common.datatypes import IntervalYM
    from seerdb.common.tns_consts import TNS_TYPE_INTERVALYM
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        for expression, expected in (
            ("numtoyminterval(14, 'MONTH')", IntervalYM(1, 2)),
            ("numtoyminterval(1.5, 'YEAR')", IntervalYM(1, 6)),
            ("numtoyminterval(14.6, 'MONTH')", IntervalYM(1, 3)),
            ("numtoyminterval(14.4, 'month')", IntervalYM(1, 2)),
            ("numtoyminterval(-14, 'MONTH')", IntervalYM(-1, -2)),
            ("numtoyminterval(1.99, 'YEAR')", IntervalYM(2, 0)),
            ("numtoyminterval(null, 'YEAR')", None),
            ("to_yminterval('1-2')", IntervalYM(1, 2)),
            ("to_yminterval('P1Y2M') x", IntervalYM(1, 2)),
        ):
            result = backend.execute(f'SELECT {expression} FROM dual')
            assert result.columns[0].data_type == TNS_TYPE_INTERVALYM, expression
            assert result.rows == [(expected,)], expression
        with pytest.raises(BackendError) as raised:
            backend.execute("SELECT numtoyminterval(1, 'DAY') FROM dual")
        assert raised.value.ora_code == 1760
    finally:
        backend.close()


def test_arithmetic_on_a_year_to_month_column_is_year_to_month() -> None:
    # `iym + iym` described as DAY TO SECOND, its months read as days (#2152):
    # PostgreSQL reports a computed value of the domain by its base type.
    # Measured on 23ai: arithmetic and SUM / AVG over a YEAR TO MONTH column
    # are INTERVAL YEAR(9) TO MONTH; DAY TO SECOND stays DAY TO SECOND.
    from seerdb.common.datatypes import IntervalYM
    from seerdb.common.tns_consts import TNS_TYPE_INTERVALDS, TNS_TYPE_INTERVALYM
    from seerdb.server.backends.postgres import _column_operands

    assert _column_operands("x.iym + sum(t.i2) * 2 || 'iym'") == ['x.iym', 't.i2']
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2152 (iym INTERVAL YEAR(4) TO MONTH, '
            'i2 INTERVAL YEAR(2) TO MONTH, ids INTERVAL DAY TO SECOND)'
        )
        try:
            backend.execute(
                "INSERT INTO t2152 VALUES (INTERVAL '1-2' YEAR TO MONTH, "
                "INTERVAL '3-4' YEAR TO MONTH, INTERVAL '1 0:0:0' DAY TO SECOND)"
            )
            for expression, expected in (
                ('iym + iym', IntervalYM(2, 4)),
                ('iym - i2', IntervalYM(-2, -2)),
                ('2 * iym', IntervalYM(2, 4)),
                ('iym / 2', IntervalYM(0, 7)),
                ('(x.iym + x.iym) * 2', IntervalYM(4, 8)),
                ('t2152.i2 + iym d', IntervalYM(4, 6)),
                ('sum(iym)', IntervalYM(1, 2)),
                ('avg(i2)', IntervalYM(3, 4)),
            ):
                source = 't2152 x' if 'x.' in expression else 't2152'
                result = backend.execute(f'SELECT {expression} FROM {source}')
                assert result.columns[0].data_type == TNS_TYPE_INTERVALYM, expression
                assert result.columns[0].precision == 9, expression
                assert result.rows == [(expected,)], expression
            result = backend.execute('SELECT ids + ids FROM t2152')
            assert result.columns[0].data_type == TNS_TYPE_INTERVALDS
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2152')
    finally:
        backend.close()


def test_datetime_arithmetic_describes_as_its_operands_say() -> None:
    # A DATE or TIMESTAMP plus an interval described as TIMESTAMP(6), as did
    # MAX(d) (#2160): PostgreSQL computes a timestamp. Measured on 23ai: a
    # DATE operand keeps a DATE, its fraction dropped; a TIMESTAMP one makes a
    # TIMESTAMP(9); MAX / MIN keep the column's type and precision.
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_DATE, TNS_TYPE_TIMESTAMP
    from seerdb.server.backends.postgres import _datetime_result

    assert _datetime_result('cast(d AS timestamp) + iym', ['DATE']) == (None, None)
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2160 (d DATE, ts TIMESTAMP, ts3 TIMESTAMP(3), '
            'iym INTERVAL YEAR(4) TO MONTH, ids INTERVAL DAY(3) TO SECOND(2))'
        )
        try:
            backend.execute(
                "INSERT INTO t2160 VALUES (TO_DATE('2020-01-31 10:00:00', "
                "'YYYY-MM-DD HH24:MI:SS'), TIMESTAMP '2020-01-31 10:00:00.5', "
                "TIMESTAMP '2020-01-31 10:00:00.5', INTERVAL '1-2' YEAR TO MONTH, "
                "INTERVAL '1 2:03:04.5' DAY TO SECOND)"
            )
            for expression, kind, scale, value in (
                ('d + iym', TNS_TYPE_DATE, 0, datetime.datetime(2021, 3, 31, 10)),
                ('iym + x.d', TNS_TYPE_DATE, 0, datetime.datetime(2021, 3, 31, 10)),
                ('d + ids', TNS_TYPE_DATE, 0, datetime.datetime(2020, 2, 1, 12, 3, 4)),
                (
                    'd - ids',
                    TNS_TYPE_DATE,
                    0,
                    datetime.datetime(2020, 1, 30, 7, 56, 55),
                ),
                ('max(d) m', TNS_TYPE_DATE, 0, datetime.datetime(2020, 1, 31, 10)),
                (
                    'ts3 + iym',
                    TNS_TYPE_TIMESTAMP,
                    9,
                    datetime.datetime(2021, 3, 31, 10, 0, 0, 500000),
                ),
                (
                    'ts - ids',
                    TNS_TYPE_TIMESTAMP,
                    9,
                    datetime.datetime(2020, 1, 30, 7, 56, 56),
                ),
                (
                    'max(ts3)',
                    TNS_TYPE_TIMESTAMP,
                    3,
                    datetime.datetime(2020, 1, 31, 10, 0, 0, 500000),
                ),
            ):
                source = 't2160 x' if 'x.' in expression else 't2160'
                result = backend.execute(f'SELECT {expression} FROM {source}')
                (column,) = result.columns
                assert (column.data_type, column.scale) == (kind, scale), expression
                assert result.rows == [(value,)], expression
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2160')
    finally:
        backend.close()


def test_translate_idioms_negates_whole_day_to_second_interval() -> None:
    # Oracle's leading `-` negates the whole DAY TO SECOND interval; PostgreSQL
    # applies it only to the days, so lift it to a unary minus on the literal (#520).
    neg = _translate_idioms(
        "INSERT INTO t VALUES (INTERVAL '-0 00:00:01.5' DAY TO SECOND)"
    )
    assert "(- INTERVAL '0 00:00:01.5' DAY TO SECOND)" in neg
    # The seconds' precision rides along, the leading field's goes, which
    # PostgreSQL's syntax has no place for (#2108); a positive literal is left
    # untouched.
    prec = _translate_idioms("p := INTERVAL '-1 02:03:04.5' DAY(4) TO SECOND(6)")
    assert "- INTERVAL '1 02:03:04.5' DAY TO SECOND(6)" in prec
    pos = _translate_idioms("INTERVAL '5 04:03:02.123456' DAY TO SECOND")
    assert pos == "INTERVAL '5 04:03:02.123456' DAY TO SECOND"


def test_a_computed_interval_has_oracles_precisions() -> None:
    # A computed interval described with precision and scale 0 (#2139).
    # Oracle gives every one a leading precision of 9, and a DAY TO SECOND
    # 6 fractional digits for a difference of timestamps, 9 for the rest. A
    # column and a literal keep their own. Measured on 23ai.
    from seerdb.server.backends.postgres import _top_level_subtraction

    assert _top_level_subtraction('ts - ts')
    assert _top_level_subtraction('(a + b) - c x')
    assert not _top_level_subtraction('-ts')
    assert not _top_level_subtraction("numtodsinterval(1 - 2, 'DAY')")
    assert not _top_level_subtraction("'a-b'")
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2139 (ts TIMESTAMP, ids INTERVAL DAY(3) TO SECOND(2))'
        )
        try:
            for expression, expected in (
                ('systimestamp - systimestamp', (9, 6)),
                ('ts - ts', (9, 6)),
                ("numtodsinterval(1.5, 'DAY')", (9, 9)),
                ("interval '1' day + interval '2' hour", (9, 9)),
                ('ids * 2', (9, 9)),
                ("to_dsinterval('1 02:03:04')", (9, 9)),
                ('ids', (3, 2)),
                ("interval '2 03:04:05' day to second", (2, 6)),
            ):
                (column,) = backend.execute(f'SELECT {expression} FROM t2139').columns
                assert (column.precision, column.scale) == expected, expression
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2139')
    finally:
        backend.close()


def test_an_interval_literal_is_oracles() -> None:
    # A YEAR TO MONTH literal is one, with its months, where it was a DAY TO
    # SECOND of 425 days; a leading precision PostgreSQL's syntax refuses goes;
    # a literal item describes with the precisions 23ai gives it (#2108).
    from seerdb.common.datatypes import IntervalYM
    from seerdb.common.tns_consts import TNS_TYPE_INTERVALDS, TNS_TYPE_INTERVALYM
    from seerdb.server.backends.postgres import _interval_literal_items

    assert _translate_idioms("SELECT INTERVAL '1-2' YEAR TO MONTH FROM dual") == (
        "SELECT (INTERVAL '1-2' YEAR TO MONTH)::ora_intervalym FROM dual"
    )
    assert _translate_idioms("SELECT interval '7' month(3) FROM dual") == (
        "SELECT (INTERVAL '7' MONTH)::ora_intervalym FROM dual"
    )
    assert _translate_idioms(
        "SELECT INTERVAL '123 03:04:05.12' DAY(3) TO SECOND(2) FROM dual"
    ) == ("SELECT INTERVAL '123 03:04:05.12' DAY TO SECOND(2) FROM dual")
    assert _translate_idioms("SELECT INTERVAL '5.25' SECOND(3,2) FROM dual") == (
        "SELECT INTERVAL '5.25' SECOND(2) FROM dual"
    )
    assert _interval_literal_items(
        "SELECT INTERVAL '2 03:04:05' DAY TO SECOND, INTERVAL '1-2' YEAR(3) "
        "TO MONTH a, INTERVAL '5' MINUTE(3), INTERVAL '5.25' SECOND(3,2) AS s, "
        "INTERVAL '2 03:04:05' DAY TO SECOND(3), INTERVAL '5' HOUR, "
        "INTERVAL '5' DAY + 1, x FROM dual"
    ) == {0: (2, 6), 1: (3, 0), 2: (3, 0), 3: (3, 2), 4: (2, 3), 5: (2, 0)}
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        result = backend.execute(
            "SELECT INTERVAL '2 03:04:05' DAY TO SECOND ids, "
            "INTERVAL '1-2' YEAR TO MONTH iym, INTERVAL '-1-2' YEAR TO MONTH n, "
            "INTERVAL '123 03:04:05.12' DAY(3) TO SECOND(2) d3 FROM dual"
        )
        assert [(c.data_type, c.precision, c.scale) for c in result.columns] == [
            (TNS_TYPE_INTERVALDS, 2, 6),
            (TNS_TYPE_INTERVALYM, 2, 0),
            (TNS_TYPE_INTERVALYM, 2, 0),
            (TNS_TYPE_INTERVALDS, 3, 2),
        ]
        assert result.rows[0][1:3] == (IntervalYM(1, 2), IntervalYM(-1, -2))
        assert result.rows[0][3] == datetime.timedelta(
            days=123, hours=3, minutes=4, seconds=5.12
        )
    finally:
        backend.close()


# A NUMBER's text as 23ai writes it, for TO_CHAR(n) and in a concatenation
# (#2146): no leading zero, no trailing ones, 40 characters at most --
# rounded, else scientific, the mantissa filling the 40.
_ORACLE_NUMBER_TEXT = (
    ('1.50', '1.5'),
    ('0.5', '.5'),
    ('-0.5', '-.5'),
    ('-12.340', '-12.34'),
    ('0', '0'),
    ('1e21', '1000000000000000000000'),
    ('1e39', '1000000000000000000000000000000000000000'),
    ('1e40', '1.0000000000000000000000000000000000E+40'),
    ('-1e39', '-1.000000000000000000000000000000000E+39'),
    ('1e125', '1.000000000000000000000000000000000E+125'),
    ('-1e-130', '-1.00000000000000000000000000000000E-130'),
    ('1e-39', '.000000000000000000000000000000000000001'),
    ('1e-40', '1.0000000000000000000000000000000000E-40'),
    ('1.23456789e-30', '.00000000000000000000000000000123456789'),
    ('1.23456789e-35', '1.2345678900000000000000000000000000E-35'),
    (
        '123456789012345678901234567890123456789012',
        '1.2345678901234567890123456789012346E+41',
    ),
    ('1/3', '.333333333333333333333333333333333333333'),
    ('-1/3', '-.33333333333333333333333333333333333333'),
    ('2/3', '.666666666666666666666666666666666666667'),
)


@pytest.mark.parametrize(('expression', 'text'), _ORACLE_NUMBER_TEXT)
def test_a_number_is_written_out_as_oracle_writes_it(expression, text) -> None:
    # PostgreSQL's text of a numeric kept its scale and its leading zero and
    # never went scientific: `1.50 || 'x'` was `1.50x` (#2146).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        assert backend.execute(
            f"SELECT TO_CHAR({expression}), {expression} || 'x', "
            f"CONCAT('x', {expression}) FROM dual"
        ).rows == [(text, text + 'x', 'x' + text)]
    finally:
        backend.close()


def test_translate_binds_wraps_aware_datetime_as_composite() -> None:
    # An aware datetime bind carries a WITH TIME ZONE value: it becomes a ROW cast
    # with the offset in seconds alongside the instant, so the offset round-trips
    # rather than being normalised to UTC by a bare timestamptz bind (#519).
    tz = datetime.timezone(datetime.timedelta(hours=-5, minutes=-30))
    value = datetime.datetime(2026, 5, 23, 10, 11, 12, 345678, tzinfo=tz)
    sql, params = _translate_binds('INSERT INTO t VALUES (:1)', [value])
    assert sql == 'INSERT INTO t VALUES (ROW(%(b1)s, %(b1__off)s)::ora_tstz)'
    assert params['b1'] is value
    assert params['b1__off'] == -19800
    # A naive datetime (or any non-aware value) binds plainly, no composite wrap.
    naive = datetime.datetime(2026, 5, 23, 10, 11, 12)
    sql2, params2 = _translate_binds('INSERT INTO t VALUES (:1)', [naive])
    assert sql2 == 'INSERT INTO t VALUES (%(b1)s)'
    assert '__off' not in ''.join(params2)


def test_translate_ddl_maps_lob_types_to_domains() -> None:
    # CLOB / NCLOB / BLOB become ora_clob / ora_blob domains so the read path can
    # tell a LOB from a plain VARCHAR2 / RAW and keep empty distinct from NULL
    # (#534). LONG / LONG RAW / RAW are not LOBs and stay text / bytea.
    sent = _translate_ddl(
        'CREATE TABLE t (a CLOB, b NCLOB, c BLOB, d LONG, e LONG RAW, f RAW(8))'
    )
    assert 'a ora_clob' in sent
    assert 'b ora_clob' in sent
    assert 'c ora_blob' in sent
    assert 'd text' in sent
    assert 'e bytea' in sent and 'f bytea' in sent
    assert 'ora_clob' not in sent.split('d text')[1]  # LONG isn't a LOB domain


def test_translate_ddl_drops_organization_index_and_global_temporary() -> None:
    iot = _translate_ddl('CREATE TABLE t (id NUMBER PRIMARY KEY) ORGANIZATION INDEX')
    assert 'ORGANIZATION INDEX' not in iot
    gtt = _translate_ddl(
        'CREATE GLOBAL TEMPORARY TABLE g (id NUMBER) ON COMMIT PRESERVE ROWS'
    )
    assert 'GLOBAL TEMPORARY' not in gtt and 'TEMPORARY TABLE' in gtt


def test_is_ddl_classifies_auto_committing_statements() -> None:
    # Oracle auto-commits DDL, so these are committed after they run (#532)…
    for sql in (
        'CREATE TABLE t (id NUMBER)',
        'CREATE OR REPLACE PROCEDURE p AS BEGIN NULL; END;',
        'DROP TABLE t',
        'ALTER TABLE t ADD (v VARCHAR2(10))',
        'TRUNCATE TABLE t',
        '  create index i on t (id)',
    ):
        assert _IS_DDL.match(sql) is not None
    # …while DML / queries stay under the client's own transaction control.
    for sql in (
        'INSERT INTO t VALUES (1)',
        'UPDATE t SET id = 2',
        'DELETE FROM t',
        'SELECT * FROM t',
        'BEGIN p(:1); END;',
    ):
        assert _IS_DDL.match(sql) is None


def test_translate_plsql_block_wraps_anonymous_declare_block() -> None:
    # A bind-less DECLARE … BEGIN … END block becomes DO $$ … $$ with the declared
    # local types mapped (VARCHAR2 → varchar); the body rides along (#533).
    out = _translate_plsql_block(
        "DECLARE v VARCHAR2(32767); BEGIN v := RPAD('X', 10, 'X'); "
        'INSERT INTO t VALUES (1, v); END;'
    )
    assert out.startswith('DO $$ DECLARE v varchar(32767); BEGIN ')
    assert out.endswith('END $$')
    assert 'INSERT INTO t VALUES (1, v);' in out
    # A bare BEGIN … END (no DECLARE) is wrapped too; a NUMBER local maps to numeric.
    numeric = _translate_plsql_block('DECLARE n NUMBER; BEGIN n := 1; END;')
    assert numeric.startswith('DO $$ DECLARE n numeric; BEGIN ')
    # A bare BEGIN with no END (transaction control) is left alone.
    assert _translate_plsql_block('BEGIN') == 'BEGIN'


def test_translate_plsql_block_hoists_local_functions() -> None:
    # Each local function becomes a pg_temp function ahead of the DO block, and a
    # call to one -- from the block or another local function -- is qualified
    # (#1322). END IF / END LOOP / END CASE / CASE ... END inside a body close no
    # BEGIN, and a keyword inside a string literal is text.
    out = _translate_plsql_block(
        'DECLARE t VARCHAR2(10);\n'
        '  FUNCTION f(a NUMBER) RETURN VARCHAR2 IS\n'
        "    s VARCHAR2(9) := 'begin';\n"
        '  BEGIN\n'
        '    IF a > 0 THEN s := g(a); END IF;\n'
        '    FOR i IN 1..a LOOP NULL; END LOOP;\n'
        "    RETURN CASE WHEN a > 1 THEN s ELSE 'end' END;\n"
        '  END f;\n'
        '  FUNCTION g(a NUMBER) RETURN VARCHAR2 IS BEGIN\n'
        '    CASE a WHEN 1 THEN NULL; ELSE NULL; END CASE;\n'
        '    RETURN to_char(a);\n'
        '  END;\n'
        "BEGIN t := f(2); INSERT INTO x VALUES (t, 'f(1)'); END;"
    )
    hoisted, block = out.split(' DO ')
    assert hoisted.startswith('DROP FUNCTION IF EXISTS pg_temp.f; ')
    assert 'CREATE FUNCTION pg_temp.f(a numeric) RETURNS varchar ' in out
    assert "DECLARE s varchar(9) := 'begin'; BEGIN" in out
    assert 's := pg_temp.g(a); END IF;' in out
    assert "ELSE 'end' END; END $f$;" in out
    assert 'CREATE FUNCTION pg_temp.g(a numeric) RETURNS varchar ' in out
    assert block == (
        '$$ DECLARE t varchar(10); BEGIN t := pg_temp.f(2); '
        "INSERT INTO x VALUES (t, 'f(1)'); END $$"
    )


def test_translate_plsql_block_leaves_a_local_procedure_alone() -> None:
    # A local PROCEDURE isn't hoisted (#1322): the block keeps its plain DO
    # translation, which PostgreSQL then refuses.
    sql = 'DECLARE PROCEDURE p IS BEGIN NULL; END; BEGIN p; END;'
    assert _translate_plsql_block(sql).startswith('DO $$ DECLARE PROCEDURE p')
    # Non-block SQL passes through untouched.
    assert _translate_plsql_block('SELECT 1') == 'SELECT 1'


def test_translate_ddl_leaves_non_create_table_unchanged() -> None:
    # Only CREATE TABLE is rewritten — a DATE literal / type keyword elsewhere
    # (DML, a query) must pass through verbatim.
    for sql in (
        "INSERT INTO t (d) VALUES (DATE '2020-01-01')",
        'SELECT id, v FROM t',
        'UPDATE t SET v = :1 WHERE id = :2',
    ):
        assert _translate_ddl(sql) == sql


@pytest.mark.parametrize(
    ('declared', 'leaf'),
    [
        # An INTERVAL attribute's TDS leaf, as 23ai describes each (#1781).
        ('INTERVAL DAY(2) TO SECOND(6)', '180a0602'),
        ('INTERVAL DAY(7) TO SECOND(9)', '180a0907'),
        ('INTERVAL YEAR(2) TO MONTH', '18070002'),
        ('INTERVAL YEAR(3) TO MONTH', '18070003'),
    ],
)
def test_an_interval_attribute_leaf(declared: str, leaf: str) -> None:
    found = _interval_leaf(declared)
    assert found is not None
    assert found.code.hex() == leaf
    assert found.newer  # it makes the TDS a version-2 one, as on 23ai


def test_an_undeclared_interval_has_oracles_default_precisions() -> None:
    assert _interval_leaf('NUMBER') is None
    (ds, ds_name) = _tds_scalar('interval', -1)
    (ym, ym_name) = _tds_scalar('ora_intervalym', -1)
    assert (ds.code.hex(), ds_name) == ('180a0602', 'INTERVAL DAY TO SECOND')
    assert (ym.code.hex(), ym_name) == ('18070002', 'INTERVAL YEAR TO MONTH')


@pytest.mark.parametrize(
    ('value', 'code'),
    [
        # Measured on 23ai (#1782): a dense vector's infinity is ORA-51807, its
        # NaN ORA-51805; a sparse vector's either is ORA-51805 (#1709).
        (array.array('d', [1.0, float('inf')]), 51807),
        (array.array('f', [float('-inf'), 1.0]), 51807),
        (array.array('d', [float('nan'), 1.0]), 51805),
        (SparseVector(4, [1], array.array('d', [float('inf')])), 51805),
        (SparseVector(4, [1], array.array('f', [float('nan')])), 51805),
    ],
)
def test_a_nonfinite_vector_is_refused(value, code: int) -> None:
    from seerdb.server.backend import BackendError

    with pytest.raises(BackendError) as raised:
        _reject_nonfinite_vectors([1, value])
    assert raised.value.ora_code == code


def test_finite_vectors_and_other_binds_pass() -> None:
    _reject_nonfinite_vectors(
        [array.array('d', [1.0, -2.5]), array.array('b', [1, -1]), 'x', 3.5, None]
    )


@pytest.mark.parametrize(
    ('sql', 'expected'),
    [
        # Bare, Oracle takes it in upper case; quoted, as written (#1779).
        ('ALTER SESSION SET TXN_PRIORITY = medium', ('MEDIUM', None)),
        ("alter session set txn_priority = 'Low'", ('Low', None)),
        # A 12.1+ client's login puts it beside the time zone, which stays.
        (
            "ALTER SESSION SET TIME_ZONE='+02:00' TXN_PRIORITY='medium'",
            ('medium', "ALTER SESSION SET TIME_ZONE='+02:00'"),
        ),
        ("ALTER SESSION SET TIME_ZONE='+02:00'", None),
        ('SELECT txn_priority FROM t', None),
    ],
)
def test_txn_priority_setting(sql: str, expected) -> None:
    assert _txn_priority_setting(sql) == expected


@pytest.mark.parametrize(
    ('sql', 'shown'),
    [
        ('ALTER SESSION SET TXN_PRIORITY = urgent', 'URGENT'),
        ("ALTER SESSION SET TXN_PRIORITY = ''", ''),
    ],
)
def test_txn_priority_setting_refuses_a_bad_value(sql: str, shown: str) -> None:
    # ORA-00096 as 23ai words it, the value as it took it.
    from seerdb.server.backend import BackendError

    with pytest.raises(BackendError) as raised:
        _txn_priority_setting(sql)
    assert raised.value.ora_code == 96
    assert (
        f'invalid value {shown} for parameter txn_priority' in raised.value.ora_message
    )


_CONNINFO = os.environ.get(
    'MIRROR_PG', 'host=127.0.0.1 port=5433 user=pyo password=pyo123 dbname=mirror'
)
_CREDS = {'PYO': 'pyo123'}


def _pg_reachable() -> bool:
    try:
        psycopg.connect(_CONNINFO, connect_timeout=2).close()
    except Exception:
        return False
    return True


pytestmark = pytest.mark.skipif(not _pg_reachable(), reason='no PostgreSQL reachable')


def _serve(listen: socket.socket, result: dict) -> None:
    conn, _ = listen.accept()
    try:
        result['user'] = serve_session(
            PacketStream(conn), PostgresBackend(_CONNINFO, credentials=_CREDS)
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
        result['error'] = exc
    finally:
        conn.close()


def _start_mirror() -> tuple[socket.socket, threading.Thread, dict]:
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    result: dict = {}
    server = threading.Thread(target=_serve, args=(listen, result), daemon=True)
    server.start()
    return listen, server, result


def _connect(port: int):
    # A generous socket read timeout (per recv). The backing PostgreSQL may be
    # remote (MIRROR_PG points off-box), and the Mirror runs an array-DML as one
    # round-trip per row against it, so a 500-row executemany can take several
    # seconds over a LAN — well past the old 5 s. 20 s clears that with margin
    # while still failing fast on a genuinely hung server.
    return seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=20000,
    )


def test_real_sql_round_trip_postgres() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_mirror')
        cur.execute(
            'create table t_mirror (id integer, name varchar(20), score numeric)'
        )
        cur.execute("insert into t_mirror values (1, 'alice', 9.5)")
        cur.execute("insert into t_mirror values (2, 'bob', -3)")
        cur.execute('select id, name, score from t_mirror order by id')
        rows = cur.fetchall()
        cur.execute('drop table t_mirror')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rows == [(1, 'alice', Decimal('9.5')), (2, 'bob', -3)]


def test_a_rowid_describes_as_a_rowid() -> None:
    # The ROWID pseudo-column, and a ROWID or UROWID column, described as a
    # VARCHAR2 -- their text here -- where 18c describes each as itself (#2083).
    from seerdb.common.tns_consts import TNS_TYPE_RID, TNS_TYPE_UROWID

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        try:
            backend.execute('CREATE TABLE t_2083 (r ROWID, u UROWID, a NUMBER)')
            backend.execute('INSERT INTO t_2083 (a) VALUES (1)')
            result = backend.execute(
                'SELECT r, u, ROWID, t.rowid q, ROWIDTOCHAR(ROWID) c FROM t_2083 t'
            )
            assert [c.data_type for c in result.columns] == [
                TNS_TYPE_RID,
                TNS_TYPE_UROWID,
                TNS_TYPE_RID,
                TNS_TYPE_RID,
                1,
            ]
        finally:
            backend.execute('DROP TABLE t_2083 PURGE')
        dual = backend.execute('SELECT ROWID FROM dual')
        assert dual.columns[0].data_type == TNS_TYPE_RID
    finally:
        backend.close()


def test_a_login_opens_no_transaction_and_its_settings_outlast_a_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A login's settings are committed at once, so a rollback cannot undo them
    # (#1188, #1409, #1620). They now run in autocommit, each login step one
    # round trip with no BEGIN or COMMIT around it (#1914): no statement of the
    # login runs inside a transaction. After a rollback the session is still
    # the login's: its user, its schema, its service.
    sent: list[tuple[str, bool]] = []
    execute = psycopg.Cursor.execute

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        sent.append((str(query), cursor.connection.autocommit))
        return execute(cursor, query, *args, **kwargs)

    # The first login of a process looks the installation up, once (#1871).
    listen, server, result = _start_mirror()
    _connect(listen.getsockname()[1]).close()
    server.join(timeout=5)
    listen.close()
    listen, server, result = _start_mirror()
    monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
    conn = _connect(listen.getsockname()[1])
    monkeypatch.undo()
    try:
        assert sent
        assert [query for query, autocommit in sent if not autocommit] == []
        conn.autocommit = False
        cur = conn.cursor()
        cur.execute('create table t_login1914 (n number)')
        cur.execute('insert into t_login1914 values (1)')
        conn.rollback()
        cur.execute(
            "select sys_context('userenv', 'session_user'), "
            "sys_context('userenv', 'current_schema'), "
            "sys_context('userenv', 'service_name') from dual"
        )
        row = cur.fetchone()
        cur.execute('drop table t_login1914')
    finally:
        monkeypatch.undo()
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('PYO', 'PYO', 'XE')


def test_a_role_writes_only_the_records_of_what_it_owns() -> None:
    # Row-level security on the Mirror's records (#1857): a role that is not
    # the installer reads every record, but writes only those of the tables,
    # packages and session that are its own. Another's record it cannot add,
    # change or delete; one whose object is gone it may delete; a DBA's
    # record -- a proxy grant -- it cannot write at all.
    PostgresBackend(_CONNINFO, credentials=_CREDS).close()
    role = f'rls_probe_{os.getpid()}'
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    tables = (
        'sys.ora_quoted_names, sys.ora_packages, sys.ora_sessions, sys.ora_proxy_grants'
    )
    try:
        admin.execute(f'CREATE ROLE {role}')
        admin.execute(f'GRANT USAGE ON SCHEMA sys TO {role}')
        admin.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {tables} TO {role}')
        admin.execute(f'CREATE SCHEMA {role} AUTHORIZATION {role}')
        admin.execute(f'CREATE TABLE {role}.mine (a int)')
        admin.execute(f'ALTER TABLE {role}.mine OWNER TO {role}')
        admin.execute(f'CREATE TABLE public.{role}_other (a int)')
        (mine,) = admin.execute(f"SELECT '{role}.mine'::regclass::oid").fetchone()
        (other,) = admin.execute(
            f"SELECT 'public.{role}_other'::regclass::oid"
        ).fetchone()
        # The installer's own writes are not bound by the policies.
        admin.execute(
            'INSERT INTO sys.ora_quoted_names VALUES (%s, 1), (0, 1)', (other,)
        )
        with psycopg.connect(_CONNINFO, autocommit=True) as conn:
            conn.execute(f'SET ROLE {role}')
            conn.execute('INSERT INTO sys.ora_quoted_names VALUES (%s, 1)', (mine,))
            assert conn.execute(
                'SELECT count(*) FROM sys.ora_quoted_names WHERE relid IN (%s, %s)',
                (mine, other),
            ).fetchone() == (2,)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(
                    'INSERT INTO sys.ora_quoted_names VALUES (%s, 2)', (other,)
                )
            assert (
                conn.execute(
                    'UPDATE sys.ora_quoted_names SET attnum = 3 WHERE relid = %s',
                    (other,),
                ).rowcount
                == 0
            )
            assert (
                conn.execute(
                    'DELETE FROM sys.ora_quoted_names WHERE relid = %s', (other,)
                ).rowcount
                == 0
            )
            # Relation 0 is none: its record is an orphan's.
            assert (
                conn.execute(
                    'DELETE FROM sys.ora_quoted_names WHERE relid = 0'
                ).rowcount
                == 1
            )
            conn.execute("INSERT INTO sys.ora_packages VALUES (%s, 'X', '')", (role,))
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("INSERT INTO sys.ora_packages VALUES ('sys', 'X', '')")
            conn.execute(
                'INSERT INTO sys.ora_sessions (pid) VALUES (pg_backend_pid()) '
                'ON CONFLICT (pid) DO UPDATE SET username = NULL'
            )
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(
                    'INSERT INTO sys.ora_sessions (pid) '
                    'SELECT pg_backend_pid() + 1000000'
                )
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("INSERT INTO sys.ora_proxy_grants VALUES ('A', 'B')")
            conn.execute('DELETE FROM sys.ora_sessions WHERE pid = pg_backend_pid()')
    finally:
        admin.execute(
            f'DELETE FROM sys.ora_quoted_names WHERE relid IN '
            f"(to_regclass('{role}.mine'), to_regclass('public.{role}_other'), 0)"
        )
        admin.execute('DELETE FROM sys.ora_packages WHERE name = %s', (role,))
        admin.execute(f'DROP TABLE IF EXISTS public.{role}_other')
        admin.execute(f'DROP SCHEMA IF EXISTS {role} CASCADE')
        if admin.execute(
            'SELECT 1 FROM pg_roles WHERE rolname = %s', (role,)
        ).fetchone():
            admin.execute(f'DROP OWNED BY {role}')
            admin.execute(f'DROP ROLE {role}')
        admin.close()


def test_the_dictionary_lists_what_the_sessions_role_may_reach() -> None:
    # Oracle's ALL_* views list what the user owns or holds a privilege on
    # (#1857); PostgreSQL's catalogs show every role everything. A role sees
    # the table, index, routine and type it was granted, and not the others.
    PostgresBackend(_CONNINFO, credentials=_CREDS).close()
    role = f'reach_probe_{os.getpid()}'
    granted, hidden = f'{role}_granted', f'{role}_hidden'
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    # The views, and the record of grants ALL_TYPES reads with the session's
    # rights (#1621).
    views = (
        'sys.all_objects, sys.all_indexes, sys.all_tab_comments, sys.all_types, '
        'sys.ora_grants'
    )
    try:
        admin.execute(f'CREATE ROLE {role}')
        admin.execute(f'GRANT USAGE ON SCHEMA sys TO {role}')
        admin.execute(f'GRANT SELECT ON {views} TO {role}')
        for name in (granted, hidden):
            admin.execute(f'CREATE TABLE public.{name} (a int PRIMARY KEY)')
            admin.execute(
                f'CREATE FUNCTION public.{name}_f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$'
            )
            admin.execute(f'REVOKE EXECUTE ON FUNCTION public.{name}_f() FROM PUBLIC')
            admin.execute(
                f"COMMENT ON FUNCTION public.{name}_f() IS '{_ROUTINE_MARK}VALID'"
            )
            admin.execute(f'CREATE TYPE public.{name}_t AS (a int)')
            admin.execute(f'REVOKE USAGE ON TYPE public.{name}_t FROM PUBLIC')
        admin.execute(f'GRANT SELECT ON public.{granted} TO {role}')
        admin.execute(f'GRANT EXECUTE ON FUNCTION public.{granted}_f() TO {role}')
        admin.execute(f'GRANT USAGE ON TYPE public.{granted}_t TO {role}')
        with psycopg.connect(_CONNINFO, autocommit=True) as conn:
            conn.execute(f'SET ROLE {role}')

            def names(query: str) -> set[str]:
                return {
                    row[0].lower() for row in conn.execute(query, (f'{role.upper()}%',))
                }

            assert names(
                'SELECT object_name FROM sys.all_objects WHERE object_name LIKE %s'
            ) == {granted, f'{granted}_pkey', f'{granted}_f', f'{granted}_t'}
            assert names(
                'SELECT index_name FROM sys.all_indexes WHERE index_name LIKE %s'
            ) == {f'{granted}_pkey'}
            assert names(
                'SELECT table_name FROM sys.all_tab_comments WHERE table_name LIKE %s'
            ) == {granted}
            assert names(
                'SELECT type_name FROM sys.all_types WHERE type_name LIKE %s'
            ) == {f'{granted}_t'}
    finally:
        for name in (granted, hidden):
            admin.execute(f'DROP TABLE IF EXISTS public.{name}')
            admin.execute(f'DROP FUNCTION IF EXISTS public.{name}_f()')
            admin.execute(f'DROP TYPE IF EXISTS public.{name}_t')
        if admin.execute(
            'SELECT 1 FROM pg_roles WHERE rolname = %s', (role,)
        ).fetchone():
            admin.execute(f'DROP OWNED BY {role}')
            admin.execute(f'DROP ROLE {role}')
        admin.close()


def test_the_users_group_may_use_every_schema_the_installation_makes() -> None:
    # A user's role reaches the installation through its group (#1857): every
    # schema the backend creates for it must be in the group's grants.
    import inspect

    from seerdb.server.backends import postgres as postgres_backend

    made = {
        name.lower()
        for name in re.findall(
            r'CREATE SCHEMA IF NOT EXISTS ([a-z_]+)',
            inspect.getsource(postgres_backend),
            re.IGNORECASE,
        )
    }
    assert made == set(postgres_backend._INSTALLED_SCHEMAS)


@contextlib.contextmanager
def _per_user_mirror(
    conninfo: str, admin: str, presents: str = '12.1', native_sql: bool = False
) -> Iterator[Callable[..., Any]]:
    # A Mirror in per-user mode (#1857) over `conninfo`, with one configured
    # account, `admin`, serving each connection on a thread of its own; yields
    # the login function. Sessions that failed are reported as it ends.
    from seerdb.server.backends import postgres as postgres_backend

    auth = f'{conninfo} application_name=auth1857'
    _ACCOUNTS_READY.discard(auth)
    postgres_backend._USER_GROUP_READY.pop(conninfo, None)
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.bind(('127.0.0.1', 0))
    listen.listen(8)
    errors: list[BaseException] = []

    def serve_one(conn: socket.socket) -> None:
        try:
            backend = PostgresBackend(
                conninfo,
                credentials={admin.upper(): 'adm123'},
                auth_conninfo=auth,
                per_user_roles=True,
                presents=presents,
                native_sql=native_sql,
            )
            try:
                serve_session(
                    PacketStream(conn), backend, field_version=backend.field_version
                )
            finally:
                backend.close()
        except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
            errors.append(exc)
        finally:
            conn.close()

    def accept() -> None:
        while True:
            try:
                conn, _ = listen.accept()
            except OSError:
                return
            threading.Thread(target=serve_one, args=(conn,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    port = listen.getsockname()[1]

    def login(user: str, password: str) -> Any:
        return seerdb.connect(
            host='127.0.0.1',
            port=port,
            user=user,
            password=password,
            service_name='XE',
            timeout=20000,
        )

    try:
        yield login
    finally:
        listen.close()
    assert errors == []


def _drop_mirror_roles(pg: Any, *names: str) -> None:
    # The roles per-user mode made for `names` (#1857), once their sessions are
    # gone, with their schemas and accounts.
    for name in names:
        pg.execute(f'DROP SCHEMA IF EXISTS {name} CASCADE')
        if pg.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', (name,)).fetchone():
            _wait_sessions_gone(pg, name)
            pg.execute(f'DROP OWNED BY {name} CASCADE')
            pg.execute(f'DROP ROLE {name}')
        if pg.execute("SELECT to_regclass('seerdb_auth.accounts')").fetchone()[0]:
            pg.execute(
                'DELETE FROM seerdb_auth.accounts WHERE username = %s', (name.upper(),)
            )


def _wait_sessions_gone(pg: Any, role: str) -> None:
    for _ in range(50):
        if not pg.execute(
            'SELECT 1 FROM pg_stat_activity WHERE usename = %s', (role,)
        ).fetchone():
            return
        time.sleep(0.1)


def _users_kept_apart(
    login: Callable[..., Any], pg: Any, admin: str, user: str
) -> None:
    # What per-user mode promises (#1857): each session is its user's own
    # role; a user it creates sees only what is its own, makes an object type
    # of its own, and may not run a DBA's statement. A user with a session
    # open is not dropped (ORA-01940); once it has none, DROP USER takes its
    # role.
    adm = login(admin, 'adm123')
    cur = adm.cursor()
    cur.execute('create table secret (n number)')
    cur.execute(f'create user {user} identified by pw123')
    session = login(user, 'pw123')
    mine = session.cursor()
    mine.execute('create table mine (a number)')
    mine.execute('insert into mine values (1)')
    mine.execute('select a from mine')
    assert mine.fetchall() == [(1,)]
    mine.execute('create type mine_t as object (n number)')
    mine.execute('drop type mine_t')
    assert pg.execute(
        'SELECT usename FROM pg_stat_activity WHERE usename IN (%s, %s) '
        'ORDER BY usename',
        (admin, user),
    ).fetchall() == [(admin,), (user,)]
    for statement, code in (
        (f'select * from {admin}.secret', 942),
        ('create user pu_evil identified by x', 1031),
        ("create directory pu_dir as '/tmp'", 1031),
    ):
        with pytest.raises(seerdb.DatabaseError) as raised:
            mine.execute(statement)
        assert raised.value.code == code, statement
    mine.execute("select count(*) from all_objects where object_name = 'SECRET'")
    assert mine.fetchall() == [(0,)]
    with pytest.raises(seerdb.DatabaseError) as raised:
        cur.execute(f'drop user {user} cascade')
    assert str(raised.value) == (
        'ORA-01940: cannot drop a user who is currently connected'
    )
    session.close()
    _wait_sessions_gone(pg, user)
    cur.execute(f'drop user {user} cascade')
    assert (
        pg.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', (user,)).fetchone()
        is None
    )
    cur.execute('drop table secret')
    adm.close()


def test_a_public_synonym_needs_create_on_postgresqls_public_schema() -> None:
    # CREATE / DROP PUBLIC SYNONYM need a system privilege the Mirror does
    # not model; CREATE on PostgreSQL's public schema, where the synonym's
    # view goes, stands for it (#2179): without it ORA-01031, as 23ai answers
    # a user without CREATE PUBLIC SYNONYM, and with it the record is the
    # user's to write under per-user mode's row-level security (#1857).
    admin, user = f'ps_adm_{os.getpid()}', f'ps_user_{os.getpid()}'
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    try:
        with _per_user_mirror(_CONNINFO, admin) as login:
            adm = login(admin, 'adm123')
            adm.cursor().execute(f'create user {user} identified by pw123')
            session = login(user, 'pw123')
            # Both closed whatever fails: an open session holds the locks
            # that dropping its role waits for.
            try:
                mine = session.cursor()
                mine.execute('create table ps_t (id number)')
                mine.execute('insert into ps_t values (1)')
                with pytest.raises(seerdb.DatabaseError) as raised:
                    mine.execute('create public synonym ps_p for ps_t')
                assert raised.value.code == 1031
                pg.execute(f'GRANT CREATE ON SCHEMA public TO {user}')
                try:
                    mine.execute('create public synonym ps_p for ps_t')
                    mine.execute(
                        'select table_owner, table_name from all_synonyms '
                        "where owner = 'PUBLIC' and synonym_name = 'PS_P'"
                    )
                    assert mine.fetchall() == [(user.upper(), 'PS_T')]
                    mine.execute('select id from ps_p')
                    assert mine.fetchall() == [(1,)]
                    mine.execute('drop public synonym ps_p')
                finally:
                    pg.execute(f'REVOKE CREATE ON SCHEMA public FROM {user}')
                mine.execute('drop table ps_t')
            finally:
                session.close()
                adm.close()
    finally:
        _drop_mirror_roles(pg, user, admin)
        pg.close()


def test_per_user_roles_keep_the_users_apart() -> None:
    admin, user = f'pu_adm_{os.getpid()}', f'pu_user_{os.getpid()}'
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    try:
        with _per_user_mirror(_CONNINFO, admin) as login:
            _users_kept_apart(login, pg, admin, user)
            # A role that is no member of the group -- made with another
            # installation's grants, say -- is made one again as it logs in.
            group = f'{pg.info.user}_mirror_users'
            pg.execute(f'REVOKE {group} FROM {admin}')
            again = login(admin, 'adm123')
            again.cursor().execute('select count(*) from all_objects')
            again.close()
            assert pg.execute(
                "SELECT pg_has_role(%s, %s, 'MEMBER')", (admin, group)
            ).fetchone() == (True,)
    finally:
        _drop_mirror_roles(pg, user, admin)
        pg.close()


def test_a_callers_temporary_table_stands_in_for_no_definers_table() -> None:
    # A definer-rights routine reads its owner's table, and the DDL log's
    # trigger PostgreSQL's catalog, whatever temporary tables the caller has
    # of their names: the temporary schema is last on every path
    # (GHSA-24v6-492m-6mg7).
    pid = os.getpid()
    admin = f'tt_adm_{pid}'
    (owner, caller) = (f'tt_a_{pid}', f'tt_b_{pid}')
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    opened: list[Any] = []
    try:
        with _per_user_mirror(_CONNINFO, admin, native_sql=True) as base:

            def login(name: str, password: str = 'pw123') -> Any:
                opened.append(base(name, password))
                return opened[-1]

            adm = login(admin, 'adm123').cursor()
            for name in (owner, caller):
                adm.execute(f'create user {name} identified by pw123')
            cur = login(owner).cursor()
            cur.execute('create table tt_cfg (v varchar2(20))')
            cur.execute("insert into tt_cfg values ('real')")
            cur.connection.commit()
            cur.execute(
                'create or replace function tt_get return varchar2 is r varchar2(20); '
                'begin select v into r from tt_cfg; return r; end;'
            )
            cur.execute(f'grant execute on tt_get to {caller}')
            other = login(caller).cursor()
            other.execute(
                'create global temporary table tt_cfg (v varchar2(20)) '
                'on commit preserve rows'
            )
            other.execute("insert into tt_cfg values ('fake')")
            other.execute("alter session set seerdb_dialect = 'postgres'")
            other.execute(
                "DO $$ BEGIN EXECUTE format('GRANT SELECT ON pg_temp.tt_cfg TO %I', "
                f"'{owner}'); END $$"
            )
            other.execute(
                'CREATE TEMP TABLE pg_roles AS SELECT * FROM pg_catalog.pg_roles'
            )
            other.execute(
                'INSERT INTO pg_temp.pg_roles (oid, rolname) '
                'VALUES (CAST(1 AS oid), CAST(current_user AS name))'
            )
            other.execute(
                'CREATE TEMP TABLE pg_namespace AS SELECT * FROM pg_catalog.pg_namespace'
            )
            other.execute(
                "UPDATE pg_temp.pg_namespace SET nspowner = CAST(1 AS oid) WHERE nspname = 'sys'"
            )
            other.execute("alter session set seerdb_dialect = 'oracle'")
            other.connection.commit()
            other.execute(f'select {owner}.tt_get() from dual')
            assert other.fetchall() == [('real',)]
            # The session's own unqualified name is still its temporary table.
            other.execute('select v from tt_cfg')
            assert other.fetchall() == [('fake',)]
            other.execute(
                "select set_config('seerdb.installing', 'on', false) from dual"
            )
            logged = pg.execute('SELECT count(*) FROM sys.ora_ddl_log').fetchone()
            other.execute('create table tt_t (n number)')
            if (
                logged is not None
                and pg.execute(
                    "SELECT 1 FROM pg_event_trigger WHERE evtname = 'ora_ddl_log'"
                ).fetchone()
            ):
                assert (
                    pg.execute('SELECT count(*) FROM sys.ora_ddl_log').fetchone()[0]
                    > logged[0]
                )
    finally:
        for session in opened:
            with contextlib.suppress(Exception):
                session.close()
        _drop_mirror_roles(pg, caller, owner, admin)
        pg.close()


def test_a_users_group_reads_no_dbas_record() -> None:
    # The group every per-user role is in reads the dictionary, but not a
    # DBA's records: the proxy grants, nor who each open proxy session's proxy
    # is, which a session asks of sys.ora_session_proxy() for its own
    # (GHSA-6qw5-v992-69fx).
    admin = f'gp_adm_{os.getpid()}'
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    try:
        with _per_user_mirror(_CONNINFO, admin) as login:
            session = login(admin, 'adm123')
            cur = session.cursor()
            cur.execute("select sys_context('userenv', 'proxy_user') from dual")
            assert cur.fetchall() == [(None,)]
            session.close()
        group = f'{pg.info.user}_mirror_users'
        for table in ('sys.ora_session_proxies', 'sys.ora_proxy_grants'):
            assert pg.execute(
                "SELECT has_table_privilege(%s, %s, 'SELECT')", (group, table)
            ).fetchone() == (False,)
        assert pg.execute(
            "SELECT has_table_privilege(%s, 'sys.ora_sessions', 'SELECT')", (group,)
        ).fetchone() == (True,)
    finally:
        _drop_mirror_roles(pg, admin)
        pg.close()


def test_a_system_privilege_lets_a_user_run_a_dbas_statement() -> None:
    # GRANT of a system privilege or the DBA role (#1936): it lets a user run
    # the DBA's statement it names, as on Oracle; it is granted on only by an
    # administrator, a DBA, or a holder WITH ADMIN OPTION; USER_SYS_PRIVS,
    # USER_ROLE_PRIVS and the SESSION_ views list it; DROP USER takes it.
    pid = os.getpid()
    admin = f'sp_adm_{pid}'
    (user, other, made) = (f'sp_a_{pid}', f'sp_b_{pid}', f'sp_c_{pid}')
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    opened: list[Any] = []
    try:
        with _per_user_mirror(_CONNINFO, admin) as base:

            def login(name: str, password: str = 'pw123') -> Any:
                opened.append(base(name, password))
                return opened[-1]

            adm = login(admin, 'adm123').cursor()
            for name in (user, other):
                adm.execute(f'create user {name} identified by pw123')
            cur = login(user).cursor()
            theirs = login(other).cursor()

            def refused(cursor: Any, statement: str, code: str) -> None:
                with pytest.raises(seerdb.DatabaseError, match=code):
                    cursor.execute(statement)

            refused(cur, f'create user {made} identified by pw123', 'ORA-01031')
            adm.execute(f'grant create user to {user}')
            cur.execute('select privilege, admin_option from user_sys_privs')
            assert cur.fetchall() == [('CREATE USER', 'NO')]
            cur.execute('select privilege from session_privs')
            assert cur.fetchall() == [('CREATE USER',)]
            cur.execute(f'create user {made} identified by pw123')
            # Granting it on needs ADMIN OPTION.
            refused(cur, f'grant create user to {other}', 'ORA-01031')
            adm.execute(f'grant create user to {user} with admin option')
            cur.execute(f'grant create user to {other}')
            theirs.execute('select privilege, admin_option from user_sys_privs')
            assert theirs.fetchall() == [('CREATE USER', 'NO')]
            # A REVOKE takes it, and doesn't cascade, as on Oracle.
            adm.execute(f'revoke create user from {user}')
            refused(cur, f'drop user {made}', 'ORA-01031')
            refused(adm, f'revoke create user from {user}', 'ORA-01952')
            theirs.execute('select count(*) from user_sys_privs')
            assert theirs.fetchall() == [(1,)]
            # The DBA role holds every modelled privilege, and grants any.
            adm.execute(f'grant dba to {user}')
            cur.execute('select granted_role, admin_option from user_role_privs')
            assert cur.fetchall() == [('DBA', 'NO')]
            cur.execute('select role from session_roles')
            assert cur.fetchall() == [('DBA',)]
            cur.execute('select count(*) from session_privs')
            assert cur.fetchall() == [(8,)]
            cur.execute(f'alter user {other} account unlock')
            cur.execute(f'grant drop user to {other}')
            theirs.execute(f'drop user {made}')
            refused(adm, f'revoke dba from {other}', 'ORA-01951')
            refused(adm, 'grant create user to nobody_here', 'ORA-01917')
            refused(adm, f'grant drop user, drop user to {other}', 'ORA-01711')
            # A privilege the Mirror doesn't model is the no-op it was.
            theirs.execute(f'grant create session, connect to {user}')
            for session in opened[1:]:
                session.close()
            _wait_sessions_gone(pg, other)
            adm.execute(f'drop user {other} cascade')
            assert pg.execute(
                'SELECT count(*) FROM sys.ora_sys_privs WHERE grantee = %s',
                (other.upper(),),
            ).fetchone() == (0,)
    finally:
        for session in opened:
            with contextlib.suppress(Exception):
                session.close()
        pg.execute(
            'DELETE FROM sys.ora_sys_privs WHERE grantee = ANY(%s)',
            ([n.upper() for n in (user, other, made)],),
        )
        _drop_mirror_roles(pg, made, other, user, admin)
        pg.close()


def test_an_administrator_or_a_dba_reads_the_dba_views() -> None:
    # In per-user mode the DBA's views are an administrator's to read, and a
    # DBA's (#2223): a configured account's role reads them, a user's doesn't
    # until GRANT DBA, at once in its open session, and not after REVOKE.
    pid = os.getpid()
    admin = f'dv_adm_{pid}'
    user = f'dv_a_{pid}'
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    opened: list[Any] = []
    try:
        with _per_user_mirror(_CONNINFO, admin) as base:

            def login(name: str, password: str = 'pw123') -> Any:
                opened.append(base(name, password))
                return opened[-1]

            adm = login(admin, 'adm123').cursor()
            adm.execute(f'create user {user} identified by pw123')
            for view in ('dba_sys_privs', 'dba_role_privs', 'proxy_users'):
                adm.execute(f'select count(*) from {view}')
            cur = login(user).cursor()
            with pytest.raises(seerdb.DatabaseError):
                cur.execute('select count(*) from dba_sys_privs')
            adm.execute(f'grant dba to {user}')
            cur.execute(
                'select granted_role from dba_role_privs where grantee = :1',
                [user.upper()],
            )
            assert cur.fetchall() == [('DBA',)]
            adm.execute(f'revoke dba from {user}')
            with pytest.raises(seerdb.DatabaseError):
                cur.execute('select count(*) from dba_role_privs')
    finally:
        for session in opened:
            with contextlib.suppress(Exception):
                session.close()
        pg.execute('DELETE FROM sys.ora_sys_privs WHERE grantee = %s', (user.upper(),))
        _drop_mirror_roles(pg, user, admin)
        pg.close()


def test_a_system_privilege_is_recorded_in_single_role_mode() -> None:
    # In single-role mode anyone may run a DBA's statement, so a GRANT of a
    # system privilege enforces nothing, but it is recorded and listed, as
    # object grants are (#1936).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})

        def rows(sql: str) -> list:
            return backend.execute(sql).rows

        try:
            backend.execute('GRANT ALTER SYSTEM TO pyo WITH ADMIN OPTION')
            assert rows(
                'SELECT privilege, admin_option FROM user_sys_privs '
                "WHERE privilege = 'ALTER SYSTEM'"
            ) == [('ALTER SYSTEM', 'YES')]
            assert rows(
                "SELECT grantee FROM dba_sys_privs WHERE privilege = 'ALTER SYSTEM'"
            ) == [('PYO',)]
            assert rows('SELECT privilege FROM session_privs') == [('ALTER SYSTEM',)]
        finally:
            backend.execute('REVOKE ALTER SYSTEM FROM pyo')
        assert rows('SELECT count(*) FROM user_sys_privs') == [(0,)]
    finally:
        backend.close()


def test_per_user_roles_with_an_installer_that_is_no_superuser() -> None:
    # As a deployment runs it (#1857): the Mirror's role owns its database and
    # may make roles, but is no superuser; a superuser made the extensions.
    pid = os.getpid()
    (installer, database) = (f'pu_inst_{pid}', f'pu_db_{pid}')
    admin, user = f'pu_iadm_{pid}', f'pu_iuser_{pid}'
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    conninfo = make_conninfo(
        _CONNINFO, user=installer, password='inst123', dbname=database
    )
    try:
        pg.execute(f"CREATE ROLE {installer} LOGIN CREATEROLE PASSWORD 'inst123'")
        pg.execute(f'CREATE DATABASE {database} OWNER {installer}')
        with psycopg.connect(
            make_conninfo(_CONNINFO, dbname=database), autocommit=True
        ) as fresh:
            fresh.execute('CREATE EXTENSION orafce')
            fresh.execute('CREATE EXTENSION vector')
        with psycopg.connect(conninfo, autocommit=True) as inst:
            with _per_user_mirror(conninfo, admin) as login:
                _users_kept_apart(login, inst, admin, user)
            _drop_mirror_roles(inst, user, admin)
    finally:
        pg.execute(f'DROP DATABASE IF EXISTS {database} WITH (FORCE)')
        for role in (user, admin, f'{installer}_mirror_users', installer):
            pg.execute(f'DROP ROLE IF EXISTS {role}')
        pg.close()


@pytest.mark.parametrize('presents', ['12.1', '23ai'])
def test_per_user_roles_enforce_object_grants(presents: str) -> None:
    # Object privileges between users, as 23ai has them (#1858): none, and
    # another user's table is not there; one, and the others are missing by
    # name; a grant is the owner's to make, or a WITH GRANT OPTION holder's,
    # and a revoke only of what one granted, cascading down the chain.
    pid = os.getpid()
    admin = f'og_adm_{pid}'
    (owner, user, third) = (f'og_own_{pid}', f'og_b_{pid}', f'og_c_{pid}')
    pg = psycopg.connect(_CONNINFO, autocommit=True)

    def code(cursor: Any, statement: str) -> str:
        with pytest.raises(seerdb.DatabaseError) as raised:
            cursor.execute(statement)
        return str(raised.value)

    # Every session this test opens, closed however it ends: an open one
    # holds locks the roles' cleanup would wait on for ever.
    opened: list[Any] = []
    try:
        with _per_user_mirror(_CONNINFO, admin, presents) as base:

            def login(name: str, password: str) -> Any:
                opened.append(base(name, password))
                return opened[-1]

            adm = login(admin, 'adm123')
            for name in (owner, user, third):
                adm.cursor().execute(f'create user {name} identified by pw123')
            a = login(owner, 'pw123').cursor()
            b = login(user, 'pw123').cursor()
            c = login(third, 'pw123').cursor()
            a.execute('create table t (id number)')
            a.execute('insert into t values (1)')
            a.execute('commit')
            a.execute('create sequence s')
            a.execute('create procedure p as begin null; end;')
            t = f'{owner}.t'
            o = owner.upper()

            def missing(privilege: str) -> str:
                # 23ai names the privilege; 12.1 says ORA-01031.
                if presents == '12.1':
                    return 'ORA-01031: insufficient privileges'
                return f'ORA-41900: missing {privilege} privilege on "{o}"."T"'

            assert code(b, f'select * from {t}').startswith('ORA-00942')
            assert code(b, f'insert into {t} values (9)').startswith('ORA-00942')
            assert code(b, f'select {owner}.s.nextval from dual').startswith(
                'ORA-00942'
            )
            a.execute(f'grant select on t to {user}')
            b.execute(f'select id from {t}')
            assert b.fetchall() == [(1,)]
            assert code(b, f'insert into {t} values (9)') == missing('INSERT')
            assert code(b, f'grant select on {t} to {third}').startswith('ORA-01031')
            a.execute(f'revoke select on t from {user}')
            a.execute(f'grant insert on t to {user}')
            assert code(b, f'select * from {t}') == missing('READ')
            b.execute(f'insert into {t} values (2)')
            b.execute('rollback')
            a.execute(f'revoke insert on t from {user}')
            assert code(b, f'select * from {t}').startswith('ORA-00942')
            a.execute(f'grant select on s to {user}')
            b.execute(f'select {owner}.s.nextval from dual')
            assert b.fetchall() == [(1,)]
            assert code(b, f'begin {owner}.p; end;').startswith('ORA-')
            a.execute(f'grant execute on p to {user}')
            b.execute(f'begin {owner}.p; end;')
            # A replace keeps the grant, as Oracle's does.
            a.execute('create or replace procedure p as begin null; end;')
            b.execute(f'begin {owner}.p; end;')
            # A's procedure runs with A's rights (#1945): B, holding nothing on
            # A's table, writes it through the procedure; one with AUTHID
            # CURRENT_USER runs with B's, and the table is not there for it.
            a.execute('create table w (n number)')
            a.execute('create procedure pw as begin insert into w values (1); end;')
            a.execute(
                'create procedure pi authid current_user as '
                f'begin insert into {owner}.w values (2); end;'
            )
            a.execute(f'grant execute on pw to {user}')
            a.execute(f'grant execute on pi to {user}')
            b.execute(f'begin {owner}.pw; end;')
            b.execute('commit')
            assert code(b, f'begin {owner}.pi; end;').startswith('ORA-00942')
            a.execute('select n from w')
            assert a.fetchall() == [(1,)]
            a.execute('drop procedure pi')
            a.execute('drop procedure pw')
            a.execute('drop table w')
            a.execute(f'grant all on t to {user} with grant option')
            b.execute(f'grant select on {t} to {third}')
            c.execute(f'select count(*) from {t}')
            assert c.fetchall() == [(1,)]
            # Each user's role reads the views of its grants.
            c.execute(
                "select grantor, privilege from user_tab_privs_recd where table_name = 'T'"
            )
            assert c.fetchall() == [(user.upper(), 'SELECT')]
            assert code(a, f'revoke select on t from {third}').startswith('ORA-01927')
            a.execute(f'revoke all on t from {user}')
            assert code(c, f'select * from {t}').startswith('ORA-00942')
            assert pg.execute(
                'SELECT count(*) FROM sys.ora_grants WHERE owner = %s '
                "AND object_name = 'T'",
                (o,),
            ).fetchone() == (0,)
            a.execute('grant select on t to public')
            c.execute(f'select count(*) from {t}')
            assert c.fetchall() == [(1,)]
            a.execute('revoke select on t from public')
            for statement, expected in (
                (f'grant select on t to nobody_{pid}', 'ORA-01917'),
                (f'grant execute on t to {user}', 'ORA-02224'),
                (f'grant insert on s to {user}', 'ORA-02205'),
                (f'grant select on p to {user}', 'ORA-02225'),
                (f'grant select on not_there to {user}', 'ORA-00942'),
                (f'grant frobnicate on t to {user}', 'ORA-00990'),
                (f'grant select, select on t to {user}', 'ORA-01711'),
                (f'grant select on t to {user}, {user}', 'ORA-01700'),
                (f'revoke select on t from {user}', 'ORA-01927'),
            ):
                assert code(a, statement).startswith(expected), statement
            a.execute(f'grant select on t to {user}')
            a.execute('drop table t')
            assert pg.execute(
                'SELECT count(*) FROM sys.ora_grants WHERE owner = %s', (o,)
            ).fetchone() == (2,)
            for cursor in (a, b, c):
                cursor.connection.close()
            for name in (owner, user, third):
                _wait_sessions_gone(pg, name)
                adm.cursor().execute(f'drop user {name} cascade')
            adm.close()
            assert pg.execute(
                'SELECT count(*) FROM sys.ora_grants WHERE owner = %s', (o,)
            ).fetchone() == (0,)
    finally:
        for session in opened:
            with contextlib.suppress(Exception):
                session.close()
        _drop_mirror_roles(pg, owner, user, third, admin)
        pg.close()


@pytest.mark.parametrize('presents', ['12.1', '23ai'])
def test_per_user_roles_enforce_column_grants(presents: str) -> None:
    # Column grants between users, as 23ai and 21c have them (#1946): INSERT,
    # UPDATE and REFERENCES by column, used only on those columns; an UPDATE
    # or DELETE that may write but not read names SELECT as missing; a REVOKE
    # by column is refused, a revoke of the whole privilege takes its column
    # grants, its cascade what was granted on, and DROP COLUMN its column's.
    pid = os.getpid()
    admin = f'cg_adm_{pid}'
    (owner, user, third) = (f'cg_own_{pid}', f'cg_b_{pid}', f'cg_c_{pid}')
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    opened: list[Any] = []

    def code(cursor: Any, statement: str) -> str:
        with pytest.raises(seerdb.DatabaseError) as raised:
            cursor.execute(statement)
        return str(raised.value)

    try:
        with _per_user_mirror(_CONNINFO, admin, presents) as base:

            def login(name: str, password: str) -> Any:
                opened.append(base(name, password))
                return opened[-1]

            adm = login(admin, 'adm123')
            for name in (owner, user, third):
                adm.cursor().execute(f'create user {name} identified by pw123')
            a = login(owner, 'pw123').cursor()
            b = login(user, 'pw123').cursor()
            c = login(third, 'pw123').cursor()
            a.execute('create table t (id number primary key, c1 number, c2 number)')
            a.execute('insert into t values (1, 10, 20)')
            a.execute('commit')
            t = f'{owner}.t'
            o = owner.upper()

            def missing(privilege: str) -> str:
                if presents == '12.1':
                    return 'ORA-01031: insufficient privileges'
                return f'ORA-41900: missing {privilege} privilege on "{o}"."T"'

            a.execute(f'grant insert (id, c1) on t to {user}')
            b.execute(f'insert into {t} (id, c1) values (2, 11)')
            assert code(b, f'insert into {t} (id, c2) values (3, 21)') == missing(
                'INSERT'
            )
            assert code(b, f'select * from {t}') == missing('READ')
            b.execute('rollback')
            a.execute(f'grant update (c1) on t to {user}')
            b.execute(f'update {t} set c1 = 99')
            assert code(b, f'update {t} set c2 = 99') == missing('UPDATE')
            assert code(b, f'update {t} set c1 = 5 where id = 1') == missing('SELECT')
            b.execute('rollback')
            a.execute(f'grant delete on t to {user}')
            assert code(b, f'delete from {t} where id = 1') == missing('SELECT')
            b.execute(f'delete from {t}')
            b.execute('rollback')
            a.execute(f'revoke delete on t from {user}')
            for statement, expected in (
                (f'grant select (c1) on t to {user}', 'ORA-00969'),
                (f'grant delete (c1) on t to {user}', 'ORA-00969'),
                (f'grant all (c1) on t to {user}', 'ORA-00969'),
                (f'grant update (nope) on t to {user}', 'ORA-00904: "NOPE"'),
                (f'grant update (c1, c1) on t to {user}', 'ORA-00957'),
                (f'revoke update (c1) on t from {user}', 'ORA-01750'),
            ):
                assert code(a, statement).startswith(expected), statement
            # A column grant WITH GRANT OPTION passes on; revoking the whole
            # privilege takes it, and what was passed on.
            a.execute(f'grant update (c2) on t to {user} with grant option')
            b.execute(f'grant update (c2) on {t} to {third}')
            c.execute(f'update {t} set c2 = 7')
            c.execute('rollback')
            c.execute(
                'select grantor, column_name, privilege from user_col_privs_recd '
                "where table_name = 'T'"
            )
            assert c.fetchall() == [(user.upper(), 'C2', 'UPDATE')]
            a.execute(f'revoke update on t from {user}')
            assert code(c, f'update {t} set c2 = 7').startswith('ORA-00942')
            assert code(b, f'update {t} set c1 = 7') == missing('UPDATE')
            # Held only by column, INSERT revokes from the whole table.
            a.execute(f'revoke insert on t from {user}')
            assert code(b, f'insert into {t} (id, c1) values (4, 1)').startswith(
                'ORA-00942'
            )
            a.execute(f'grant select, references (id), update (c1, c2) on t to {user}')
            a.execute(
                'select privilege, column_name from user_col_privs '
                "where table_name = 'T' order by 1, 2"
            )
            assert a.fetchall() == [
                ('REFERENCES', 'ID'),
                ('UPDATE', 'C1'),
                ('UPDATE', 'C2'),
            ]
            a.execute('alter table t drop column c1')
            a.execute(
                'select privilege, column_name from user_col_privs '
                "where table_name = 'T' order by 1, 2"
            )
            assert a.fetchall() == [('REFERENCES', 'ID'), ('UPDATE', 'C2')]
            a.execute('drop table t')
            assert pg.execute(
                'SELECT count(*) FROM sys.ora_col_grants WHERE owner = %s', (o,)
            ).fetchone() == (0,)
            for session in opened[1:]:
                session.close()
            for name in (owner, user, third):
                _wait_sessions_gone(pg, name)
                adm.cursor().execute(f'drop user {name} cascade')
    finally:
        for session in opened:
            with contextlib.suppress(Exception):
                session.close()
        _drop_mirror_roles(pg, owner, user, third, admin)
        pg.close()


def test_a_per_user_login_connects_to_postgresql_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Once the process has set the installation and the users' group up, a
    # per-user login connects to PostgreSQL once, straight as its user's role,
    # not first as the installer (#1939). A proxy login, whose target is known
    # only later, still goes the installer's way, and runs as the target's.
    from seerdb.server.backends import postgres as postgres_backend

    pid = os.getpid()
    admin = f'oc_adm_{pid}'
    (user, target) = (f'oc_b_{pid}', f'oc_t_{pid}')
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    opened: list[Any] = []
    connects: list[str] = []
    connect = postgres_backend._CountedConnection.connect

    def counted(conninfo: str, **kwargs: Any) -> Any:
        connects.append(conninfo)
        return connect(conninfo, **kwargs)

    try:
        with _per_user_mirror(_CONNINFO, admin) as base:

            def login(name: str, password: str) -> Any:
                opened.append(base(name, password))
                return opened[-1]

            adm = login(admin, 'adm123').cursor()
            for name in (user, target):
                adm.execute(f'create user {name} identified by pw123')
            adm.execute(f'alter user {target} grant connect through {user}')
            monkeypatch.setattr(postgres_backend._CountedConnection, 'connect', counted)
            session = login(user, 'pw123')
            cursor = session.cursor()
            cursor.execute(
                "select user, sys_context('userenv', 'current_user') from dual"
            )
            assert cursor.fetchall() == [(user.upper(), user.upper())]
            assert len(connects) == 1
            assert f'user={user}' in connects[0]
            proxied = login(f'{user}[{target}]', 'pw123').cursor()
            proxied.execute(
                "select user, sys_context('userenv', 'proxy_user'), "
                "sys_context('userenv', 'current_user') from dual"
            )
            assert proxied.fetchall() == [
                (target.upper(), user.upper(), target.upper())
            ]
            for session in opened[1:]:
                session.close()
            for name in (target, user):
                _wait_sessions_gone(pg, name)
                adm.execute(f'drop user {name} cascade')
    finally:
        for session in opened:
            with contextlib.suppress(Exception):
                session.close()
        _drop_mirror_roles(pg, user, target, admin)
        pg.close()


def test_the_records_are_upgraded_in_order_and_a_newer_database_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The records' data version (#1862): a fresh database is stamped with this
    # release's; a newer release runs each step from there once, in order, and
    # records how far it got; a release older than the database, or newer than
    # its baseline allows, refuses it before installing anything; and once
    # adoption is off (GA), a preview database with no version is refused.
    from seerdb.server.backend import UnsupportedFeature
    from seerdb.server.backends import postgres as postgres_backend

    database = f'dv_{os.getpid()}'
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    conninfo = make_conninfo(_CONNINFO, dbname=database)

    def recorded() -> tuple[str | None, int | None]:
        with psycopg.connect(conninfo) as conn:
            row = conn.execute(
                "SELECT obj_description(to_regclass('sys.ora_data_version'), "
                "'pg_class'), (SELECT count(*) FROM pg_class WHERE relname = 'dv_step')"
            ).fetchone()
            assert row is not None
            steps = None
            if row[1]:
                counted = conn.execute('SELECT count(*) FROM sys.dv_step').fetchone()
                steps = counted[0] if counted else None
            return (row[0], steps)

    try:
        pg.execute(f'CREATE DATABASE {database}')
        with psycopg.connect(conninfo, autocommit=True) as fresh:
            fresh.execute('CREATE EXTENSION orafce')
            fresh.execute('CREATE EXTENSION vector')
        PostgresBackend(conninfo, credentials=dict(_CREDS)).close()
        assert recorded() == ('1', None)
        steps = (
            (2, 'CREATE TABLE IF NOT EXISTS sys.dv_step (n int)'),
            (
                3,
                'INSERT INTO sys.dv_step SELECT 3 WHERE NOT EXISTS (SELECT 1 FROM sys.dv_step)',
            ),
        )
        monkeypatch.setattr(postgres_backend, '_DATA_VERSION', 3)
        monkeypatch.setattr(postgres_backend, '_DATA_UPGRADES', steps)
        PostgresBackend(conninfo, credentials=dict(_CREDS)).close()
        assert recorded() == ('3', 1)
        PostgresBackend(conninfo, credentials=dict(_CREDS)).close()
        assert recorded() == ('3', 1)
        monkeypatch.setattr(postgres_backend, '_DATA_VERSION', 2)
        with pytest.raises(UnsupportedFeature, match='set up by a newer seerdb'):
            PostgresBackend(conninfo, credentials=dict(_CREDS))
        monkeypatch.setattr(postgres_backend, '_DATA_VERSION', 5)
        monkeypatch.setattr(postgres_backend, '_DATA_BASELINE', 4)
        with pytest.raises(UnsupportedFeature, match='older than this release'):
            PostgresBackend(conninfo, credentials=dict(_CREDS))
        assert recorded() == ('3', 1)
        monkeypatch.setattr(postgres_backend, '_DATA_VERSION', 3)
        monkeypatch.setattr(postgres_backend, '_DATA_BASELINE', 1)
        monkeypatch.setattr(postgres_backend, '_ADOPT_UNVERSIONED', False)
        with psycopg.connect(conninfo, autocommit=True) as conn:
            conn.execute('DROP TABLE sys.ora_data_version')
        with pytest.raises(UnsupportedFeature, match='preview release'):
            PostgresBackend(conninfo, credentials=dict(_CREDS))
        # A fresh database, which has no dictionary yet, is stamped anyway.
        assert postgres_backend._refused_data_version(None, False) is None
    finally:
        pg.execute(f'DROP DATABASE IF EXISTS {database} WITH (FORCE)')
        pg.close()


def test_a_per_user_session_cannot_forge_who_it_is() -> None:
    # The session's user, its proxy, and whether its DDL is the installer's
    # unlogged setup come from what a client cannot change in per-user mode:
    # its own role, the installer's record of its proxy, the installer's
    # name (GHSA-336m-cp9c-m2fw). A session setting is any client's to set.
    pid = os.getpid()
    admin = f'sid_adm_{pid}'
    (user, other) = (f'sid_b_{pid}', f'sid_o_{pid}')
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    opened: list[Any] = []
    try:
        with _per_user_mirror(_CONNINFO, admin) as base:

            def login(name: str, password: str) -> Any:
                opened.append(base(name, password))
                return opened[-1]

            adm = login(admin, 'adm123').cursor()
            for name in (user, other):
                adm.execute(f'create user {name} identified by pw123')
            adm.execute(f'alter user {other} grant connect through {user}')
            cur = login(user, 'pw123').cursor()
            cur.execute(
                f"select set_config('seerdb.session_user', '{other.upper()}', false), "
                f"set_config('seerdb.proxy_user', '{admin.upper()}', false) from dual"
            )
            cur.execute(
                "select user, sys_context('userenv', 'session_user'), "
                "sys_context('userenv', 'proxy_user') from dual"
            )
            assert cur.fetchall() == [(user.upper(), user.upper(), None)]
            # A proxy login's proxy is the installer's record.
            proxied = login(f'{user}[{other}]', 'pw123').cursor()
            proxied.execute(
                f"select set_config('seerdb.proxy_user', '{admin.upper()}', false) from dual"
            )
            proxied.execute(
                "select user, sys_context('userenv', 'proxy_user') from dual"
            )
            assert proxied.fetchall() == [(other.upper(), user.upper())]
            # A user's DDL is logged, whatever its session says.
            logged = pg.execute('SELECT count(*) FROM sys.ora_ddl_log').fetchone()
            cur.execute("select set_config('seerdb.installing', 'on', false) from dual")
            cur.execute('create table sid_t (n number)')
            if (
                logged is not None
                and pg.execute(
                    "SELECT 1 FROM pg_event_trigger WHERE evtname = 'ora_ddl_log'"
                ).fetchone()
            ):
                assert (
                    pg.execute('SELECT count(*) FROM sys.ora_ddl_log').fetchone()[0]
                    > logged[0]
                )
            for session in opened[1:]:
                session.close()
            for name in (other, user):
                _wait_sessions_gone(pg, name)
                adm.execute(f'drop user {name} cascade')
    finally:
        for session in opened:
            with contextlib.suppress(Exception):
                session.close()
        _drop_mirror_roles(pg, user, other, admin)
        pg.close()


def test_a_users_invalid_view_record_runs_in_no_other_session() -> None:
    # A view a DROP left INVALID is made again from its record by a session of
    # its schema's owner only (GHSA-jf99-3g55-98cc). The record is the user's
    # to write, so its text is what that user could run anyway; another
    # user's session, though it may create in the schema, never runs it.
    pid = os.getpid()
    admin = f'iv_adm_{pid}'
    (user, other) = (f'iv_a_{pid}', f'iv_b_{pid}')
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    opened: list[Any] = []
    try:
        with _per_user_mirror(_CONNINFO, admin, native_sql=True) as base:

            def login(name: str, password: str = 'pw123') -> Any:
                opened.append(base(name, password))
                return opened[-1]

            adm = login(admin, 'adm123').cursor()
            for name in (user, other):
                adm.execute(f'create user {name} identified by pw123')
            cur = login(user).cursor()
            cur.execute('create table iv_seen (who varchar2(64))')
            cur.execute("alter session set seerdb_dialect = 'postgres'")
            cur.execute(f'GRANT INSERT ON iv_seen TO {other}')
            cur.execute(f'GRANT USAGE, CREATE ON SCHEMA {user} TO {other}')
            cur.execute("alter session set seerdb_dialect = 'oracle'")
            cur.execute(
                f"insert into sys.ora_invalid_views values ('{user}', 'iv_v', "
                f"'SELECT 1 AS n; INSERT INTO {user}.iv_seen SELECT current_user')"
            )
            cur.connection.commit()
            login(other).cursor().execute('create table iv_t (n number)')
            assert pg.execute(f'SELECT who FROM {user}.iv_seen').fetchall() == []
            assert pg.execute(f"SELECT to_regclass('{user}.iv_v')").fetchone() == (
                None,
            )
    finally:
        for session in opened:
            with contextlib.suppress(Exception):
                session.close()
        pg.execute('DELETE FROM sys.ora_invalid_views WHERE schema_name = %s', (user,))
        _drop_mirror_roles(pg, other, user, admin)
        pg.close()


def test_another_users_package_is_not_this_users_to_create_or_drop() -> None:
    # A package's records are its owner's to write, and dropping or
    # compiling its body runs their text: another user's CREATE or DROP of
    # it, or of its body, is ORA-01031, before anything runs
    # (GHSA-qmx7-qr2x-76r7). Its owner's are as they were.
    pid = os.getpid()
    admin = f'pk_adm_{pid}'
    (user, other) = (f'pk_a_{pid}', f'pk_b_{pid}')
    package = f'pk_pkg_{pid}'
    pg = psycopg.connect(_CONNINFO, autocommit=True)
    opened: list[Any] = []
    try:
        with _per_user_mirror(_CONNINFO, admin) as base:

            def login(name: str, password: str = 'pw123') -> Any:
                opened.append(base(name, password))
                return opened[-1]

            adm = login(admin, 'adm123').cursor()
            for name in (user, other):
                adm.execute(f'create user {name} identified by pw123')
            cur = login(user).cursor()
            cur.execute('create table pk_seen (who varchar2(64))')
            cur.execute(f'grant insert on pk_seen to {other}')
            cur.execute(f'create or replace package {package} as x number := 1; end;')
            cur.execute(
                f"update sys.ora_packages set stubs = 'INSERT INTO {user}.pk_seen "
                f"SELECT current_user' where name = '{package}'"
            )
            cur.connection.commit()
            theirs = login(other).cursor()
            for statement in (
                f'drop package body {package}',
                f'drop package {package}',
                f'create or replace package body {package} as begin null; end;',
                f'create or replace package {package} as y number := 2; end;',
            ):
                with pytest.raises(seerdb.DatabaseError, match='ORA-01031'):
                    theirs.execute(statement)
            assert pg.execute(f'SELECT who FROM {user}.pk_seen').fetchall() == []
            cur.execute(
                f"update sys.ora_packages set stubs = '' where name = '{package}'"
            )
            cur.connection.commit()
            cur.execute(f'drop package {package}')
            assert (
                pg.execute(
                    'SELECT 1 FROM pg_namespace WHERE nspname = %s', (package,)
                ).fetchone()
                is None
            )
    finally:
        for session in opened:
            with contextlib.suppress(Exception):
                session.close()
        pg.execute(f'DROP SCHEMA IF EXISTS {package} CASCADE')
        pg.execute('DELETE FROM sys.ora_packages WHERE name = %s', (package,))
        _drop_mirror_roles(pg, other, user, admin)
        pg.close()


def test_a_users_role_is_made_with_a_verifier_not_its_password() -> None:
    # A per-user role's password reaches PostgreSQL as a SCRAM verifier the
    # Mirror computes, which a server logging its DDL writes down instead of
    # the password (GHSA-27rj-h7p6-pmqf). The role logs in with the password.
    from psycopg import sql

    from seerdb.server.backends.postgres import _scram_verifier

    role = f'scram_probe_{os.getpid()}'
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    try:
        verifier = _scram_verifier('Pw-for-the-probe')
        assert verifier.startswith('SCRAM-SHA-256$4096:')
        assert 'Pw-for-the-probe' not in verifier
        admin.execute(
            sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(
                sql.Identifier(role), sql.Literal(verifier)
            )
        )
        with psycopg.connect(
            make_conninfo(_CONNINFO, user=role, password='Pw-for-the-probe')
        ) as conn:
            assert conn.execute('SELECT current_user').fetchone() == (role,)
        stored = admin.execute(
            'SELECT rolpassword FROM pg_authid WHERE rolname = %s', (role,)
        ).fetchone()
        if stored is not None:
            assert stored[0] == verifier
    finally:
        admin.execute(f'DROP ROLE IF EXISTS {role}')
        admin.close()


def test_a_profiled_mirror_records_each_statement_over_postgresql(
    tmp_path: Any,
) -> None:
    # A migration profile over PostgreSQL (#1881): each statement a client
    # runs through the Mirror, by fingerprint, with the statements the backend
    # sent PostgreSQL for it, its time split between waiting on PostgreSQL and
    # the Mirror's own, and the PostgreSQL text it ran as. An error is counted
    # by its ORA code; an array insert counts its rows.
    from seerdb.server.profile import Profile, ProfilingBackend

    profile = Profile(str(tmp_path / 'profile.json'), 'PostgreSQL')
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.bind(('127.0.0.1', 0))
    listen.listen(1)
    result: dict = {}

    def serve() -> None:
        conn, _ = listen.accept()
        backend = ProfilingBackend(
            PostgresBackend(_CONNINFO, credentials=_CREDS), profile
        )
        try:
            result['user'] = serve_session(PacketStream(conn), backend)
        except Exception as exc:  # noqa: BLE001 - surfaced to the test thread
            result['error'] = exc
        finally:
            backend.close()
            conn.close()

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_prof1881')
        cur.execute('create table t_prof1881 (n number)')
        cur.executemany('insert into t_prof1881 values (:1)', [(1,), (2,), (3,)])
        for n in (1, 2):
            cur.execute('select sysdate, n from t_prof1881 where n = :1', [n])
            cur.fetchall()
        with pytest.raises(seerdb.DatabaseError):
            cur.execute('select * from no_such_table_1881')
        cur.execute('drop table t_prof1881')
        # A block the Mirror answers without translating anything has no
        # PostgreSQL text: not the drop's before it (#1931).
        out = cur.var(int)
        cur.execute('begin :1 := :2; end;', [out, 5])
    finally:
        conn.close()
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')
    statements = {s['fingerprint']: s for s in profile.snapshot()['statements']}
    query = statements['SELECT SYSDATE,N FROM T_PROF1881 WHERE N=?']
    assert (query['calls'], query['rows_out']) == (2, 2)
    assert query['backend']['statements_per_call'] >= 1
    assert query['backend']['database_ms'] > 0
    assert 'localtimestamp' in query['translated']
    insert = statements['INSERT INTO T_PROF1881 VALUES(?)']
    assert (insert['kinds'], insert['rows_in']) == ({'executemany': 1}, 3)
    assert statements['SELECT * FROM NO_SUCH_TABLE_1881']['errors'] == {'ORA-00942': 1}
    assert 'DROP' in statements['DROP TABLE T_PROF1881']['translated'].upper()
    assert 'translated' not in statements['BEGIN ?:=?;END']
    assert profile.snapshot()['sessions_ended'] == 1


def test_a_refused_commit_is_ora_02091() -> None:
    # PostgreSQL checks a deferred constraint at COMMIT and rolls back; the
    # client gets Oracle's ORA-02091 over the constraint's own ORA-00001, not a
    # backend fault (#1789), and the session carries on.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_defer')
        cur.execute(
            'create table t_defer (id number constraint t_defer_pk primary key '
            'deferrable initially deferred)'
        )
        conn.autocommit = False
        cur.execute('insert into t_defer values (1)')
        cur.execute('insert into t_defer values (1)')
        with pytest.raises(seerdb.DatabaseError) as raised:
            conn.commit()
        cur.execute('select count(*) from t_defer')
        rows = cur.fetchall()
        cur.execute('insert into t_defer values (2)')
        conn.commit()
        cur.execute('drop table t_defer')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert raised.value.code == 2091
    assert str(raised.value).startswith(
        'ORA-02091: transaction rolled back\nORA-00001: '
    )
    assert rows == [(0,)]


def test_unsupported_pg_type_is_an_ora_error() -> None:
    # A column type the Mirror can't yet represent (timestamp) is refused with a
    # clean ORA-03001 — the connection stays usable, per the capabilities design.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            cur.execute("select '[]'::json")  # json isn't mapped yet
        assert 'ORA-03001' in str(excinfo.value)
        cur.execute('select 7 as n')
        rows = cur.fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rows == [(7,)]


def test_date_and_timestamp_columns() -> None:
    # Each temporal PostgreSQL type maps to the Oracle type of matching
    # precision: date → DATE (day), timestamp → TIMESTAMP (sub-second),
    # timestamptz → TIMESTAMP WITH LOCAL TIME ZONE, the instant in the database
    # time zone (#1208).
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute("select date '2020-12-31' as d")
        date_value = cur.fetchone()[0]
        cur.execute("select timestamp '2024-01-15 13:30:45.123456' as ts")
        ts_value = cur.fetchone()[0]
        cur.execute("select timestamptz '2024-06-01 09:00:00+02' as tz")
        tz_value = cur.fetchone()[0]
        tz_type = cur.description[0][1]
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    # DATE keeps day precision (midnight of that day).
    assert date_value == datetime.datetime(2020, 12, 31, 0, 0)
    # TIMESTAMP keeps the microseconds.
    assert ts_value == datetime.datetime(2024, 1, 15, 13, 30, 45, 123456)
    # LTZ is naive: the instant 07:00Z in the database zone, UTC.
    assert tz_type is seerdb.DB_TYPE_TIMESTAMP_LTZ
    assert tz_value == datetime.datetime(2024, 6, 1, 7, 0, 0)


def test_interval_day_to_second_column() -> None:
    # A PostgreSQL `interval` (oid 1186) maps to Oracle INTERVAL DAY TO SECOND
    # (#501): psycopg returns a timedelta, which the Mirror encodes as INTERVALDS
    # and the client decodes back to the same timedelta.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute("select interval '5 3:2:1.5' as v")
        value = cur.fetchone()[0]
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert value == datetime.timedelta(
        days=5, hours=3, minutes=2, seconds=1, microseconds=500000
    )


def test_high_precision_numeric() -> None:
    # PostgreSQL numeric returns a Decimal; the Mirror's exact base-100 encoder
    # carries all of it, well past float's ~15 significant digits.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute(
            'select 1.234567890123456789::numeric as a,'
            ' 123456789012345678901234567890::numeric as b,'
            ' (-9999999999.9999999999)::numeric as c'
        )
        row = cur.fetchone()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == (
        Decimal('1.234567890123456789'),
        Decimal('123456789012345678901234567890'),
        Decimal('-9999999999.9999999999'),
    )


def test_a_quotient_keeps_oracles_digits() -> None:
    # Oracle keeps a quotient to 20 base-100 digits, rounded half away from
    # zero: 40 significant digits for 1/3, 39 for 10/7, where PostgreSQL keeps
    # 16 to 20 (#1598). Integers, decimals and a column alike; the values are
    # 23ai's. A zero divisor is still ORA-01476.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        (row,) = backend.execute(
            'SELECT 1/3, -2/3, 10/7, 1e30/3, 0.00001/3, 1/999999, 5/2, '
            '123456789/0.003 FROM dual'
        ).rows
        assert list(row) == [
            Decimal('0.' + '3' * 40),
            Decimal('-0.' + '6' * 39 + '7'),
            Decimal('1.42857142857142857142857142857142857143'),
            Decimal('333333333333333333333333333333.3333333333'),
            Decimal('0.00000' + '3' * 39),
            Decimal('0.' + '000001' * 7),
            Decimal('2.5'),
            Decimal('41152263000'),
        ]
        backend.execute('CREATE TABLE dv1598 (n NUMBER)')
        backend.execute('INSERT INTO dv1598 VALUES (100)')
        (row,) = backend.execute('SELECT n / 7 FROM dv1598').rows
        assert row[0] == Decimal('14.28571428571428571428571428571428571429')
        with pytest.raises(BackendError) as exc:
            backend.execute('SELECT n / 0 FROM dv1598')
        assert exc.value.ora_code == 1476
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE dv1598')
        except Exception:
            backend.rollback()


def test_binary_float_and_double_columns() -> None:
    # PostgreSQL float4 / float8 map to Oracle BINARY_FLOAT / BINARY_DOUBLE
    # (Python float, IEEE-exact), while numeric stays NUMBER (Decimal).

    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute(
            'select 3.5::float8 as d, 1.5::float4 as f,'
            ' (-2.25)::float8 as neg, 9.9::numeric(3,1) as amt'
        )
        row = cur.fetchone()
        types = [d[1] for d in cur.description]
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == (3.5, 1.5, -2.25, Decimal('9.9'))
    assert isinstance(row[0], float) and isinstance(row[1], float)
    # description type_code is the seerdb.DB_TYPE_* object (oracledb parity).
    assert types[0] == seerdb.DB_TYPE_BINARY_DOUBLE
    assert types[1] == seerdb.DB_TYPE_BINARY_FLOAT


def test_batched_fetch_large_row_count_postgres() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_batch')
        cur.execute('create table t_batch (n integer)')
        cur.executemany('insert into t_batch values (:1)', [(i,) for i in range(500)])
        cur.execute('select n from t_batch order by n')
        first = cur.fetchmany(10)
        rest = cur.fetchall()
        cur.execute('select count(*) from t_batch')
        count = cur.fetchone()[0]
        cur.execute('drop table t_batch')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert [r[0] for r in first] == list(range(10))
    assert [r[0] for r in first] + [r[0] for r in rest] == list(range(500))
    assert count == 500


def test_number_precision_and_scale_in_description() -> None:
    # A PostgreSQL numeric(p, s) column surfaces its precision/scale in
    # cursor.description; an unconstrained integer reports None/None (oracledb
    # parity: precision/scale are None unless one of them is set).
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('select 123.45::numeric(10,2) as amt, 7::int as n')
        cur.fetchall()
        description = cur.description
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    # description tuple: (name, type, display, internal, precision, scale, null_ok)
    amt, n = description[0], description[1]
    assert (amt[4], amt[5]) == (10, 2)
    assert (n[4], n[5]) == (None, None)


def test_executemany_array_dml_postgres() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_many')
        cur.execute('create table t_many (id integer, name varchar(20))')
        cur.executemany(
            'insert into t_many values (:1, :2)',
            [(1, 'a'), (2, 'b'), (3, 'c'), (4, 'd')],
        )
        rowcount = cur.rowcount
        cur.execute('select id, name from t_many order by id')
        rows = cur.fetchall()
        cur.execute('drop table t_many')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rowcount == 4
    assert rows == [(1, 'a'), (2, 'b'), (3, 'c'), (4, 'd')]


def test_executemany_failure_aborts_batch_and_keeps_session_postgres() -> None:
    # A plain (non-batcherrors) array DML runs through the backend's own
    # executemany. A row that fails mid-batch stops the batch there and leaves
    # the session usable for the next statement, never desyncing. As on Oracle
    # (measured on 23ai), only the failing row is undone: the rows before it
    # stay, and the error's rowcount says how many (#1365).
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_manyfail')
        cur.execute('create table t_manyfail (id integer primary key)')
        with pytest.raises(seerdb.DatabaseError):
            # The third row duplicates the first key — the batch aborts.
            cur.executemany('insert into t_manyfail values (:1)', [(1,), (2,), (1,)])
        reported = cur.rowcount
        # The session survived, with the two good rows applied.
        cur.execute('select count(*) from t_manyfail')
        remaining = cur.fetchone()[0]
        cur.execute('drop table t_manyfail')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert (remaining, reported) == (2, 2)


def test_fractional_number_bind_postgres() -> None:
    # psycopg maps a Decimal bind straight to numeric; the exact value survives
    # (the SQLite backend takes a lossy REAL path — this is the exact one).
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_dec')
        cur.execute('create table t_dec (id integer, v numeric)')
        cur.execute('insert into t_dec values (:1, :2)', [1, Decimal('3.14159')])
        cur.execute('insert into t_dec values (:1, :2)', [2, 2.5])
        cur.execute('select v from t_dec order by id')
        rows = cur.fetchall()
        cur.execute('drop table t_dec')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rows == [(Decimal('3.14159'),), (Decimal('2.5'),)]


def _connect_no_autocommit(port: int):
    return seerdb.connect(
        host='127.0.0.1',
        port=port,
        user='PYO',
        password='pyo123',
        service_name='XE',
        timeout=5000,
        autocommit=False,
    )


def test_commit_and_rollback_postgres() -> None:
    listen, server, result = _start_mirror()
    conn = _connect_no_autocommit(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_txn')
        conn.commit()
        cur.execute('create table t_txn (n integer)')
        conn.commit()
        cur.execute('insert into t_txn values (1)')
        cur.execute('insert into t_txn values (2)')
        conn.rollback()
        cur.execute('select n from t_txn')
        after_rollback = cur.fetchall()
        cur.execute('insert into t_txn values (3)')
        conn.commit()
        cur.execute('select n from t_txn order by n')
        after_commit = cur.fetchall()
        cur.execute('drop table t_txn')
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert after_rollback == []
    assert after_commit == [(3,)]


def test_statement_error_keeps_the_transaction() -> None:
    # A failed statement rolls back only itself (via the per-statement SAVEPOINT):
    # the connection stays usable and earlier uncommitted work survives — Oracle's
    # statement-level model, not PostgreSQL's abort-the-whole-transaction default.
    listen, server, result = _start_mirror()
    conn = _connect_no_autocommit(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_iso')
        conn.commit()
        cur.execute('create table t_iso (n integer)')
        conn.commit()
        cur.execute('insert into t_iso values (10)')  # good, uncommitted
        with pytest.raises(seerdb.DatabaseError):
            cur.execute('insert into t_iso values (no_such_column)')  # PG error
        cur.execute('insert into t_iso values (20)')  # connection still usable
        conn.commit()
        cur.execute('select n from t_iso order by n')
        rows = cur.fetchall()
        cur.execute('drop table t_iso')
        conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert rows == [(10,), (20,)]  # the pre-error row was not rolled back


def test_execute_pipelined_and_sequential_agree() -> None:
    # The pipelined path (SAVEPOINT + statement + RELEASE in one round-trip) and
    # the sequential fallback (three round-trips, for libpq < 14) must produce the
    # same results and the same statement-level error isolation. Drive the backend
    # directly, forcing each path, so the fallback is exercised even where libpq is
    # new enough that the Mirror always pipelines.
    from seerdb.server import BackendError
    from seerdb.server.backends.postgres import PostgresBackend

    for use_pipeline in (True, False):
        backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
        backend._use_pipeline = use_pipeline
        try:
            backend.execute('drop table if exists t_paths')
            backend.execute('create table t_paths (n integer)')
            assert backend.execute('insert into t_paths values (1)').rowcount == 1
            backend.execute('insert into t_paths values (2)')  # prior, uncommitted
            # A failing statement rolls back only itself, prior work survives.
            with pytest.raises(BackendError):
                backend.execute('insert into t_paths values (no_such_column)')
            backend.execute('insert into t_paths values (3)')  # still usable
            result = backend.execute('select n from t_paths order by n')
            assert [r[0] for r in result.rows] == [1, 2, 3], use_pipeline
            backend.execute('drop table t_paths')
            backend.commit()
        finally:
            backend.close()


def test_bind_variables_postgres() -> None:
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_bind')
        cur.execute('create table t_bind (id integer, name varchar(20))')
        cur.execute('insert into t_bind values (:1, :2)', [1, 'alice'])
        cur.execute('insert into t_bind values (:1, :2)', [2, 'bob'])
        cur.execute('select name from t_bind where id = :1', [2])
        row = cur.fetchone()
        cur.execute('drop table t_bind')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert row == ('bob',)


# --- Oracle SQL idiom / function translation (#502) — pure, no live PG needed --


def test_an_orafce_before_4_17_is_refused() -> None:
    # 4.17 ships UTL_RAW, HEXTORAW and RAWTOHEX, which the backend no longer
    # installs (#800). A database without orafce is not refused.
    for version in ('4.17', '4.17.1', '4.18', '5.0'):
        assert _refused_orafce(version) is None
    assert _refused_orafce(None) is None
    for version in ('4.16', '4.10', '3.25'):
        refused = _refused_orafce(version)
        assert refused is not None
        assert f'orafce {version} is installed' in refused
        assert 'ALTER EXTENSION orafce UPDATE' in refused


def test_helper_functions_ddl_defines_the_scalar_helpers() -> None:
    # The Oracle scalar functions orafce doesn't cover are installed as real
    # PostgreSQL functions (#513) instead of rewritten per call site, so those
    # call sites resolve directly. Each is defined idempotently (CREATE OR
    # REPLACE) and returns the LOB domains where appropriate.
    for name in (
        'empty_clob',
        'empty_blob',
        'from_tz',
        'rowidtochar',
        'ora_to_char_signed',
        'sys.ora_rowid_b64',
        'sys.ora_rowid',
        'ora_systimestamp',
        'ora_current_timestamp',
        'ora_tstz_instant',
        'ora_tstz_local',
        'ora_tstz_cmp',
        'ora_tstz_eq',
        'ora_tstz_hash',
        'ora_ltz_add_days',
        'ora_tstz_add_days',
        'ora_div',
        'power',
    ):
        assert f'FUNCTION {name}(' in _HELPER_FUNCTIONS_DDL
    # 47, ora_div (#1361) and power (#1362) for each of the nine pairs of
    # integer types, sys.ora_to_raw's two overloads (#1496), sys.ora_raw_fits
    # (#1415), sys.ora_float_round (#1422), sys.ora_numeric_div (#1598),
    # sys.ora_package_unusable (#1605), sys.ora_is_json's two (#1614) and
    # sys.ora_commit_request (#1630), sys.ora_rr_shift and the two
    # sys.ora_rr_year (#1638), sys.ora_plsql_call and sys.ora_ndf_to_null
    # (#1612), ora_boolean_number (#1705), the SQL/JSON helpers: the two
    # sys.ora_json, six sys.ora_json_scalar and sys.ora_json_serialize (#1707),
    # the four BOOLEAN / number comparisons behind = and <> (#1743), and
    # PL/SQL's sys.ora_plsql_pad with its rpad / lpad (#2061), and the three
    # two-argument concat (#2093), sys.ora_late's two (#2138),
    # sys.ora_number_text, sys.ora_text and to_char(numeric) (#2146), and
    # sys.ora_late_number (#2143), and numtoyminterval (#2153), and
    # sys.ora_to_char and to_char(timestamp, text) (#2167), and
    # sys.ora_plsql_number_text with DBMS_OUTPUT's PUT_LINE and PUT of a
    # number (#2181), and sys.ora_datetime_text, sys.ora_zone_text,
    # sys.ora_tstz_text, sys.ora_ltz_text and sys.ora_computed_text (#2162).
    assert _HELPER_FUNCTIONS_DDL.count('CREATE OR REPLACE FUNCTION') == 114
    # HEXTORAW / RAWTOHEX are orafce's (#800).
    assert 'FUNCTION hextoraw(' not in _HELPER_FUNCTIONS_DDL
    assert 'FUNCTION rawtohex(' not in _HELPER_FUNCTIONS_DDL
    assert 'FUNCTION sys.ora_to_raw(text)' in _HELPER_FUNCTIONS_DDL
    assert 'FUNCTION sys.ora_to_raw(bytea)' in _HELPER_FUNCTIONS_DDL
    # Oracle's conversion functions orafce lacks, one overload per argument
    # type a caller passes.
    for name in (
        'to_binary_float',
        'to_binary_double',
        'to_dsinterval',
        'to_yminterval',
        'to_blob',
        'to_nclob',
    ):
        assert f'FUNCTION {name}(' in _HELPER_FUNCTIONS_DDL
    # rowidtochar is the identity on the text the ROWID pseudo-column rewrites
    # to, so ROWIDTOCHAR(ROWID) equals ROWID.
    assert 'FUNCTION rowidtochar(text) RETURNS text' in _HELPER_FUNCTIONS_DDL
    # empty_clob / empty_blob hand back the domain types, so a value stored
    # through one is recognised as a LOB on read-back rather than a plain string.
    assert 'RETURNS ora_clob' in _HELPER_FUNCTIONS_DDL
    assert 'RETURNS ora_blob' in _HELPER_FUNCTIONS_DDL
    # Oracle's RAWTOHEX yields upper-case hex (PostgreSQL's encode is lower-case).
    assert 'upper(encode(' in _HELPER_FUNCTIONS_DDL
    # from_tz returns the ora_tstz composite (not a plain timestamptz), so a named
    # region's DST-correct offset round-trips into a WITH TIME ZONE column; it is
    # STABLE, since a named region's offset depends on the tz database.
    assert 'FUNCTION from_tz(timestamp, text) RETURNS ora_tstz' in _HELPER_FUNCTIONS_DDL
    assert 'AT TIME ZONE' in _HELPER_FUNCTIONS_DDL
    from_tz_body = _HELPER_FUNCTIONS_DDL.split('from_tz', 1)[1].split(
        'CREATE OR REPLACE', 1
    )[0]
    assert 'IMMUTABLE' not in from_tz_body


def test_xmlelement_takes_its_name_after_name() -> None:
    # PostgreSQL's XMLELEMENT takes the element name after NAME; Oracle's
    # usual spelling leaves it out, and folds an unquoted name to upper case
    # (#1554). A name already after NAME is left alone.
    assert _translate_idioms('SELECT XMLElement("IntCol", IntCol) FROM t') == (
        'SELECT XMLELEMENT(NAME "IntCol", IntCol) FROM t'
    )
    assert _translate_idioms('SELECT xmlelement ( Emp, 5) FROM dual') == (
        'SELECT XMLELEMENT(NAME "EMP", 5) FROM dual'
    )
    assert _translate_idioms('SELECT XMLElement(NAME "A", 1) FROM dual') == (
        'SELECT XMLElement(NAME "A", 1) FROM dual'
    )
    assert _translate_idioms(
        'SELECT XMLElement("A", XMLElement("B", 2)) FROM dual'
    ) == ('SELECT XMLELEMENT(NAME "A", XMLELEMENT(NAME "B", 2)) FROM dual')


def test_translate_idioms_functions_and_literals() -> None:
    assert _translate_idioms('SELECT SYSDATE') == 'SELECT localtimestamp(0)::ora_date'
    # HEXTORAW / RAWTOHEX, EMPTY_CLOB / EMPTY_BLOB and FROM_TZ are installed as
    # real PostgreSQL functions (_HELPER_FUNCTIONS_DDL), so their call sites
    # resolve directly and pass through the idiom translation unchanged — just
    # like the orafce-provided DECODE / TO_CHAR do.
    # NVL is the exception: orafce's four overloads are ambiguous for the untyped
    # literals an application actually writes, so it becomes the native COALESCE,
    # which means the same for two arguments (#819). NVL2 keeps its own name --
    # the pattern needs `(` right after NVL, so it does not catch NVL2.
    assert _translate_idioms("SELECT NVL(:v, 'x')") == "SELECT COALESCE(:v, 'x')"
    assert _translate_idioms("SELECT nvl (NULL, 'ok')") == "SELECT COALESCE(NULL, 'ok')"
    assert _translate_idioms("SELECT NVL2(:v, 'y', 'n')") == "SELECT NVL2(:v, 'y', 'n')"
    assert _translate_idioms("SELECT HEXTORAW('DEADBEEF')") == (
        "SELECT HEXTORAW('DEADBEEF')"
    )
    assert _translate_idioms('INSERT INTO t VALUES (EMPTY_CLOB())') == (
        'INSERT INTO t VALUES (EMPTY_CLOB())'
    )
    assert (
        _translate_idioms(
            "SELECT FROM_TZ(TIMESTAMP '2024-01-15 12:00:00', 'US/Eastern')"
        )
        == "SELECT FROM_TZ(TIMESTAMP '2024-01-15 12:00:00', 'US/Eastern')"
    )


def test_a_rowid_column_type_is_text_and_a_dml_reports_its_rowid() -> None:
    # A ROWID / UROWID column holds a rowid's text; the pseudo-column rewrite
    # used to reach the column TYPE and fail the CREATE. `SELECT ROWID` in a
    # CREATE TABLE ... AS SELECT is not a column definition and is left alone.
    assert _translate_ddl('CREATE TABLE t (n NUMBER, r ROWID, u UROWID)') == (
        'CREATE TABLE t (n numeric, r ora_rowid, u varchar(4000))'
    )
    assert 'varchar' not in _translate_ddl('CREATE TABLE t AS SELECT ROWID FROM s')
    # A UROWID(n) holds n bytes at most (#1906).
    assert _translate_ddl('CREATE TABLE t (u UROWID ( 100 ))') == (
        'CREATE TABLE t (u varchar(100))'
    )


def test_a_quoted_column_name_keeps_its_column_type() -> None:
    # A quoted column name (#1876): its ROWID, UROWID, BFILE, JSON or REF type
    # is the column's, as an unquoted name's is, not left to the ROWID
    # pseudo-column rewrite or as Oracle's spelling, which PostgreSQL refuses.
    assert _translate_ddl(
        'CREATE TABLE t (n NUMBER, "Rr" ROWID, "u v" UROWID, "F" BFILE, "J" JSON)'
    ) == (
        'CREATE TABLE t (n numeric, "Rr" ora_rowid, "u v" varchar(4000), '
        '"F" ora_bfile, "J" jsonb)'
    )
    assert _translate_ddl('CREATE TABLE t ("Rf" REF person_t)') == (
        'CREATE TABLE t ("Rf" person_t$ref)'
    )


def test_a_rowid_renders_as_the_client_renders_it() -> None:
    # The backend's sys.ora_rowid and the client's rowid_to_string must agree,
    # or a lastrowid the Mirror reports would never match a SELECT ROWID. The
    # block is one past the ctid's: a client takes block 0 for "no rowid".
    from seerdb.common.types import rowid_to_string

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        (got,) = _fetched_row(
            backend._conn.execute("SELECT sys.ora_rowid(16384, '(12,3)'::tid)")
        )
        assert got == rowid_to_string(16384, 1, 13, 3)
    finally:
        backend.close()


def test_a_dmls_rowid_is_the_rowid_a_query_selects() -> None:
    # A DML's last rowid is encoded by the backend from the row's table and
    # ctid (#1879), a query's ROWID by sys.ora_rowid: both name the same row,
    # for one statement and for the last row of a batch.
    from seerdb.server.backend import Result

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))

    def selected(n: int) -> object:
        rows = backend.execute('SELECT ROWID FROM dr1879t WHERE n = :1', [n]).rows
        return rows[0][0]

    try:
        backend.execute('CREATE TABLE dr1879t (n NUMBER, s VARCHAR2(10))')
        one = backend.execute("INSERT INTO dr1879t VALUES (1, 'a')")
        assert one.last_rowid == selected(1)
        batch = backend.execute_many(
            'INSERT INTO dr1879t VALUES (:1, :2)', [(n, 'b') for n in range(2, 400)]
        )
        assert isinstance(batch, Result)
        assert (batch.rowcount, batch.last_rowid) == (398, selected(399))
        moved = backend.execute("UPDATE dr1879t SET s = 'c' WHERE n = 250")
        assert moved.last_rowid == selected(250)
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE dr1879t')
        except Exception:
            backend.rollback()


def test_unqualified_names_resolve_in_the_login_users_schema() -> None:
    # Oracle starts a session in the login user's schema, so a table created as
    # user.t is found as plain t (#1188). A user without a schema gets one at
    # login, as every Oracle user has one (#1751), so its objects are its own
    # rather than PUBLIC's.
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    admin.execute('DROP SCHEMA IF EXISTS pyo_login CASCADE')
    admin.execute('DROP SCHEMA IF EXISTS pyo_no_schema CASCADE')
    admin.execute('CREATE SCHEMA pyo_login')
    admin.execute('CREATE TABLE pyo_login.pyo_login_t (n integer)')
    admin.execute('INSERT INTO pyo_login.pyo_login_t VALUES (7)')
    creds = {'PYO_LOGIN': 'x', 'PYO_NO_SCHEMA': 'y'}
    backend = PostgresBackend(_CONNINFO, credentials=creds)
    other = PostgresBackend(_CONNINFO, credentials=creds)
    try:
        assert backend.authenticate('PYO_LOGIN') == 'x'
        assert backend.execute('SELECT n FROM pyo_login_t').rows == [(7,)]
        (schema,) = _fetched_row(backend._conn.execute('SELECT current_schema()'))
        assert schema == 'pyo_login'
        assert other.authenticate('PYO_NO_SCHEMA') == 'y'
        (schema,) = _fetched_row(other._conn.execute('SELECT current_schema()'))
        assert schema == 'pyo_no_schema'
    finally:
        backend.close()
        other.close()
        admin.execute('DROP SCHEMA pyo_login CASCADE')
        admin.execute('DROP SCHEMA IF EXISTS pyo_no_schema CASCADE')
        admin.close()


def test_a_query_leaves_no_lock_behind() -> None:
    # An Oracle query takes no table lock; a PostgreSQL read keeps one until its
    # transaction ends, which blocked another session's TRUNCATE for ever
    # (#1190). A transaction that has written, or holds a client savepoint,
    # stays open.
    reader = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    other = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        reader.execute('CREATE TABLE pyo_read_lock (n NUMBER)')
        other._conn.execute("SET lock_timeout = '2s'")
        other._conn.commit()
        reader.execute('SELECT n FROM pyo_read_lock')
        other.execute('TRUNCATE TABLE pyo_read_lock')
        reader.execute('INSERT INTO pyo_read_lock VALUES (1)')
        reader.execute('SELECT n FROM pyo_read_lock')
        idle = psycopg.pq.TransactionStatus.INTRANS
        assert reader._conn.info.transaction_status == idle
        reader.rollback()
        reader.execute('SAVEPOINT pyo_sp')
        reader.execute('SELECT n FROM pyo_read_lock')
        reader.execute('ROLLBACK TO SAVEPOINT pyo_sp')
        reader.rollback()
    finally:
        reader.execute('DROP TABLE pyo_read_lock')
        reader.close()
        other.close()


def test_releasing_read_locks_costs_no_round_trip_of_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A query with no transaction open runs with none around it (#1916): one
    # pipeline in autocommit, no BEGIN, no COMMIT, and no question whether it
    # wrote -- its implicit transaction ends, read locks and all (#1190), at
    # the pipeline's end. Inside an open transaction a query still reads that
    # answer in its own pipeline (#1869), and the transaction stays open for
    # the write in it. A table's first query reads its columns into the schema
    # model after the pipeline, so it asks again: the table's query is run
    # once first.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    backend.execute('SELECT :1 FROM dual', [0])
    sent: list[tuple[str, bool]] = []
    commits: list[str] = []
    execute = psycopg.Cursor.execute
    commit = psycopg.Connection.commit
    off = psycopg.pq.PipelineStatus.OFF
    idle = psycopg.pq.TransactionStatus.IDLE

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        pipelined = cursor.connection.pgconn.pipeline_status != off
        sent.append((str(query), pipelined))
        return execute(cursor, query, *args, **kwargs)

    def committed(connection: Any) -> None:
        if connection.pgconn.transaction_status != idle:
            commits.append('commit')
        commit(connection)

    monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
    monkeypatch.setattr(psycopg.Connection, 'commit', committed)
    try:
        for n in range(3):
            backend.execute('SELECT :1 FROM dual', [n])
        assert [q for q, _p in sent if 'pg_current_xact_id_if_assigned' in q] == []
        assert commits == []
        assert all(p for _q, p in sent)
        assert backend._conn.info.transaction_status == idle
        backend.execute('CREATE TABLE rl1916t (n NUMBER)')
        backend.execute('SELECT n FROM rl1916t')
        sent.clear()
        backend.execute('INSERT INTO rl1916t VALUES (1)')
        backend.execute('SELECT n FROM rl1916t')
        asked = [p for q, p in sent if 'pg_current_xact_id_if_assigned' in q]
        assert asked == [True, True]
        assert backend._conn.info.transaction_status != idle
    finally:
        monkeypatch.undo()
        backend.rollback()
        backend.execute('DROP TABLE IF EXISTS rl1916t')
        backend.close()


def test_a_query_with_no_transaction_keeps_what_needs_one() -> None:
    # A query run with no transaction around it (#1916) is only one that
    # needs none: SELECT ... FOR UPDATE keeps its row locks in a transaction
    # until the commit, as Oracle's does, and a REF CURSOR a query returns --
    # from a function or a CURSOR(...) item -- is drained from its portal
    # before the transaction ends. A query that fails leaves no transaction.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    idle = psycopg.pq.TransactionStatus.IDLE
    try:
        backend.execute('CREATE TABLE ql1916t (n NUMBER)')
        backend.execute('INSERT INTO ql1916t VALUES (1)')
        backend.commit()
        backend.execute('SELECT n FROM ql1916t FOR UPDATE')
        assert backend._conn.info.transaction_status != idle
        backend.rollback()
        backend.execute(
            'CREATE OR REPLACE FUNCTION ql1916f RETURN SYS_REFCURSOR AS '
            'c SYS_REFCURSOR; BEGIN OPEN c FOR SELECT 7 AS n FROM dual; '
            'RETURN c; END;'
        )
        (cell,) = backend.execute('SELECT ql1916f() AS c FROM dual').rows[0]
        assert cell.rows == [(7,)]
        (cell,) = backend.execute('SELECT CURSOR(SELECT 8 FROM dual) FROM dual').rows[0]
        assert cell.rows == [(8,)]
        with pytest.raises(BackendError):
            backend.execute('SELECT 1 / 0 FROM dual')
        assert backend._conn.info.transaction_status == idle
        assert backend.execute('SELECT n FROM ql1916t').rows == [(1,)]
    finally:
        backend.rollback()
        for statement in ('DROP FUNCTION ql1916f', 'DROP TABLE ql1916t'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()
        backend.close()


def test_a_query_failing_as_it_is_prepared_leaves_no_stale_statement() -> None:
    # psycopg prepares a statement on its fifth run (#1885). A query with no
    # transaction open runs in a pipeline of its own (#1916), and one that
    # failed as psycopg prepared it, first in that pipeline, left psycopg
    # sure it had a statement the server never kept: the next run was
    # 'prepared statement "_pg3_0" does not exist' (test_integration's
    # test_error_then_large_lob_stays_synced). Each run still fails as
    # itself, and the query between them still works.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE ps1916t (id NUMBER, c VARCHAR2(10))')
        backend.execute("INSERT INTO ps1916t VALUES (1, 'x')")
        backend.commit()
        for _ in range(8):
            with pytest.raises(BackendError) as raised:
                backend.execute('SELECT * FROM ps1916_no_such_table')
            assert raised.value.ora_code == 942
            assert backend.execute('SELECT c FROM ps1916t WHERE id = 1').rows == [
                ('x',)
            ]
    finally:
        backend.rollback()
        backend.execute('DROP TABLE IF EXISTS ps1916t')
        backend.close()


def test_a_select_into_as_the_first_statement_keeps_its_savepoint() -> None:
    # A session's first statement a SELECT ... INTO :b (#2103): the query's
    # catalog reads ran in autocommit with the call's savepoint waiting, which
    # went with them and met no transaction. sqlplus lost its session
    # (ORA-03113), a thin client got ORA-00600. The savepoint now waits for the
    # query itself, against DUAL and against a table alike.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.backend import BindVar

    def session() -> PostgresBackend:
        backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
        backend.authenticate('PYO')
        backend.open_session({})
        return backend

    setup = session()
    try:
        setup.execute('CREATE TABLE t_into2103 (n NUMBER)')
        setup.execute('INSERT INTO t_into2103 VALUES (7)')
        setup.commit()
        got = []
        for block in (
            'begin select count(*) into :1 from dual; end;',
            'begin select n into :1 from t_into2103; end;',
        ):
            backend = session()
            try:
                result = backend.execute(block, [BindVar(None, TNS_TYPE_NUMBER, 22)])
                got.append(result.out_binds[0])
                assert backend.execute('SELECT 1 FROM dual').rows == [(1,)]
            finally:
                backend.close()
        assert got == [1, 7]
    finally:
        setup.rollback()
        setup.execute('DROP TABLE t_into2103')
        setup.close()


def test_a_call_right_after_a_commit_keeps_its_savepoint() -> None:
    # A PL/SQL call's savepoint rides with its first statement (#1875). With
    # no transaction open that statement may be a query, which must still run
    # in a transaction for the savepoint (#1916): a SELECT ... INTO :b right
    # after a commit and an array insert was ORA-00900, "SAVEPOINT can only be
    # used in transaction blocks", as python-oracledb's test_3405 found.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        conn.autocommit = False
        cur = conn.cursor()
        cur.execute('drop table if exists t_call1916')
        cur.execute('create table t_call1916 (n number)')
        cur.execute('truncate table t_call1916')
        cur.executemany('insert into t_call1916 values (:1)', [(4,), (5,)])
        conn.commit()
        out = cur.var(seerdb.ROWID)
        cur.execute(
            'begin select rowid into :1 from t_call1916 where n = 5; end;', [out]
        )
        got = out.getvalue()
        cur.execute('select rowid from t_call1916 where n = 5')
        (expected,) = cur.fetchone()
        cur.execute('drop table t_call1916')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert got == expected


def test_a_write_opens_its_transaction_in_its_own_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A write with no transaction open sends its BEGIN with it, first in its
    # pipeline (#1915), not as psycopg's own, which syncs: one round trip.
    # The transaction then lasts as Oracle's does, until the commit or the
    # rollback, which hand the connection back to psycopg's transactions. A
    # write that fails leaves its transaction for the next one; a rollback
    # takes them all.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    sent: list[tuple[str, bool]] = []
    execute = psycopg.Cursor.execute
    off = psycopg.pq.PipelineStatus.OFF
    idle = psycopg.pq.TransactionStatus.IDLE

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        sent.append((str(query), cursor.connection.pgconn.pipeline_status != off))
        return execute(cursor, query, *args, **kwargs)

    def count() -> int:
        (n,) = _fetched_row(backend._conn.execute('SELECT count(*) FROM tx1915t'))
        return int(n)

    try:
        backend.execute('CREATE TABLE tx1915t (n NUMBER PRIMARY KEY)')
        # A table's first statement reads its columns as it is translated,
        # which opens the transaction before the pipeline: one first.
        backend.execute('INSERT INTO tx1915t VALUES (0)')
        backend.rollback()
        monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
        backend.execute('INSERT INTO tx1915t VALUES (1)')
        monkeypatch.undo()
        assert [piped for q, piped in sent if q == 'BEGIN'] == [True]
        assert backend._conn.info.transaction_status != idle
        backend.commit()
        assert not backend._conn.autocommit
        assert count() == 1
        backend._conn.commit()
        # A failing first write keeps its transaction for the next one.
        with pytest.raises(BackendError):
            backend.execute('INSERT INTO tx1915t VALUES (1)')
        backend.execute('INSERT INTO tx1915t VALUES (2)')
        backend.rollback()
        assert not backend._conn.autocommit
        assert count() == 1
        backend._conn.commit()
        # One a routine's COMMIT ended is handed back at the next call.
        backend.execute('INSERT INTO tx1915t VALUES (3)')
        backend._conn.execute('COMMIT')
        assert backend._conn.autocommit
        backend.execute('SELECT 1 FROM dual')
        assert not backend._conn.autocommit
        assert count() == 2
    finally:
        monkeypatch.undo()
        backend.rollback()
        backend.execute('DROP TABLE IF EXISTS tx1915t')
        backend.close()


def test_a_write_after_the_pipeline_keeps_its_transaction() -> None:
    # The pipeline's answer is stale once another statement has run: a REF
    # CURSOR fetch can run a function that writes. Committing on the stale
    # answer would commit that write behind the client's back (#1869).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE pyo_stale_unwritten (n NUMBER)')
        backend.execute('SELECT n FROM pyo_stale_unwritten')
        backend._conn.execute('SELECT 1')  # opens the transaction again
        backend._conn.unwritten_at = (True, backend._conn.statements)
        backend._conn.execute('INSERT INTO pyo_stale_unwritten VALUES (1)')
        backend._release_read_locks()
        backend.rollback()
        rows = backend.execute('SELECT n FROM pyo_stale_unwritten').rows
        assert rows == []
    finally:
        backend.rollback()
        backend.execute('DROP TABLE pyo_stale_unwritten')
        backend.close()


def test_a_column_name_folds_as_oracle_folds_it() -> None:
    # A legal unquoted lower-case name came from an unquoted one; anything else
    # was quoted and is kept (#1204). A reserved word could only be quoted.
    from seerdb.server.backends.postgres import _oracle_column_name

    assert _oracle_column_name('all_lowercase') == 'ALL_LOWERCASE'
    assert _oracle_column_name('a$b#1') == 'A$B#1'
    for kept in ('MixedCase', 'ALL_UPPERCASE_QUOTED', 'select', '_x', 'two words'):
        assert _oracle_column_name(kept) == kept


def test_a_quoted_lower_case_column_keeps_its_name() -> None:
    # PostgreSQL stores "abc" as it stores an unquoted abc, so the backend records
    # the quoted one at CREATE TABLE and reports it as Oracle does (#1204) --
    # also to a session that was already open before the table existed.
    early = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    creator = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        creator.execute(
            'CREATE TABLE pyo_quoted_names (id NUMBER, all_lowercase NUMBER, '
            '"MixedCase" NUMBER, "all_lowercase_quoted" NUMBER, '
            '"ALL_UPPERCASE_QUOTED" NUMBER)'
        )
        expected = [
            b'ID',
            b'ALL_LOWERCASE',
            b'MixedCase',
            b'all_lowercase_quoted',
            b'ALL_UPPERCASE_QUOTED',
        ]
        for backend in (creator, early):
            result = backend.execute('SELECT * FROM pyo_quoted_names')
            assert [c.name for c in result.columns] == expected
        # A computed column has no table behind it and keeps the rule.
        result = creator.execute('SELECT 1 AS "lower_alias" FROM dual')
        assert [c.name for c in result.columns] == [b'LOWER_ALIAS']
        # The dictionary names them so too, a constraint's and an index's
        # columns as well (#1599).
        creator.execute(
            'ALTER TABLE pyo_quoted_names ADD CONSTRAINT pyo_qn_uk '
            'UNIQUE ("all_lowercase_quoted")'
        )
        creator.execute('CREATE INDEX pyo_qn_ix ON pyo_quoted_names ("MixedCase")')
        result = creator.execute(
            'SELECT column_name FROM user_tab_columns '
            "WHERE table_name = 'PYO_QUOTED_NAMES' ORDER BY column_id"
        )
        assert [row[0].encode() for row in result.rows] == expected
        for view in ('all_cons_columns', 'all_ind_columns'):
            result = creator.execute(
                f"SELECT column_name FROM {view} WHERE table_name = 'PYO_QUOTED_NAMES'"
            )
            assert sorted(row[0] for row in result.rows) == (
                ['all_lowercase_quoted']
                if view == 'all_cons_columns'
                else ['MixedCase', 'all_lowercase_quoted']
            )
    finally:
        creator.execute('DROP TABLE pyo_quoted_names')
        creator.close()
        early.close()


def test_ddl_on_a_locked_table_fails_as_oracle_does() -> None:
    # Oracle's DDL does not wait for another session's lock: ORA-00054 (#1191).
    # The bounded wait lives and dies with the DDL's own savepoint, so the
    # session's later statements wait as before.
    from seerdb.server import BackendError

    holder = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    ddl = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        holder.execute('CREATE TABLE pyo_ddl_nowait (n NUMBER)')
        holder.execute('INSERT INTO pyo_ddl_nowait VALUES (1)')
        with pytest.raises(BackendError) as exc:
            ddl.execute('TRUNCATE TABLE pyo_ddl_nowait')
        assert exc.value.ora_code == 54
        (timeout,) = _fetched_row(ddl._conn.execute('SHOW lock_timeout'))
        assert timeout == '0'
        holder.rollback()
        ddl.execute('TRUNCATE TABLE pyo_ddl_nowait')
    finally:
        holder.rollback()
        holder.execute('DROP TABLE pyo_ddl_nowait')
        holder.close()
        ddl.close()


def test_a_block_reads_its_binds_back_in_its_own_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A block's binds (#1456, #1459) are read back by one query, in the
    # block's own pipeline (#1917): one round trip, not one more per bind. An
    # error the block raises is still its own ORA code, and the session goes
    # on.
    import decimal

    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
    from seerdb.server import BackendError, BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    sent: list[tuple[str, bool]] = []
    execute = psycopg.Cursor.execute
    off = psycopg.pq.PipelineStatus.OFF

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        piped = cursor.connection.pgconn.pipeline_status != off
        sent.append((str(query), piped))
        return execute(cursor, query, *args, **kwargs)

    try:
        monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
        out = backend.execute(
            "begin :1 := 2; :2 := :1 * 3; :3 := 'x' || :2; end;",
            [
                BindVar(None, TNS_TYPE_NUMBER, 22),
                BindVar(None, TNS_TYPE_NUMBER, 22),
                BindVar(None, TNS_TYPE_VARCHAR, 10),
            ],
        ).out_binds
        assert [int(v) if isinstance(v, decimal.Decimal) else v for v in out] == [
            2,
            6,
            'x6',
        ]
        block = [
            (q, piped) for q, piped in sent if 'DO ' in q or 'current_setting' in q
        ]
        assert len(block) == 2 and all(piped for _q, piped in block)
        assert block[1][0].count('current_setting') == 3
        with pytest.raises(BackendError) as raised:
            backend.execute(
                "begin :1 := 1; raise_application_error(-20001, 'boom'); end;",
                [BindVar(None, TNS_TYPE_NUMBER, 22)],
            )
        assert raised.value.ora_code == 20001
        assert backend.execute('SELECT 1 FROM dual').rows == [(1,)]
    finally:
        monkeypatch.undo()
        backend.rollback()
        backend.close()


def test_a_block_returning_several_rows_into_a_bind_is_ora_01422() -> None:
    # PL/SQL's single-row RETURNING INTO found two rows (#1209).
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server import BackendError
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE pyo_block_returning (id NUMBER, n NUMBER)')
        backend.execute('INSERT INTO pyo_block_returning VALUES (1, 10)')
        backend.execute('INSERT INTO pyo_block_returning VALUES (1, 11)')
        binds = [
            BindVar(value=20, tns_type=TNS_TYPE_NUMBER, max_size=22),
            BindVar(value=1, tns_type=TNS_TYPE_NUMBER, max_size=22),
            BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22),
        ]
        with pytest.raises(BackendError) as exc:
            backend.execute(
                'BEGIN UPDATE pyo_block_returning SET n = :1 WHERE id = :2 '
                'RETURNING n INTO :3; END;',
                binds,
            )
        assert exc.value.ora_code == 1422
    finally:
        backend.rollback()
        backend.execute('DROP TABLE pyo_block_returning')
        backend.close()


def test_session_info_names_the_backend_and_sql_agrees() -> None:
    # The login reply's SID is the backend's pid, and sys_context says the same;
    # the serial is the one ora_serial gives that pid (#1212).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        info = backend.session_info()
        (pid, sid, serial) = _fetched_row(
            backend._conn.execute(
                "SELECT pg_backend_pid(), sys.sys_context('userenv', 'sid'), "
                'sys.ora_serial(pg_backend_pid())'
            )
        )
        assert info.session_id == pid == int(sid)
        assert info.serial_num == serial > 0
        assert info.db_name == info.instance_name
    finally:
        backend.close()


def test_v_session_shows_what_the_login_declared() -> None:
    # The login hooks' values land in this session's v$session and
    # v$session_connect_info rows, found by comparing the NUMBER sid with the
    # VARCHAR2 sys_context gives, as Oracle converts it (#1212).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.set_client_identity(
            {'program': 'p', 'machine': 'm', 'terminal': 't', 'osuser': 'o'}
        )
        backend.authenticate('PYO')
        backend.open_session({'driver_name': 'd'})
        backend.session_info()
        where = "WHERE sid = sys_context('userenv', 'sid')"
        assert backend.execute(
            f'SELECT program, machine, terminal, osuser, username FROM v$session {where}'
        ).rows == [('p', 'm', 't', 'o', 'PYO')]
        assert backend.execute(
            f'SELECT client_driver FROM v$session_connect_info {where}'
        ).rows == [('d',)]
    finally:
        backend.close()


def test_kill_session_ends_only_the_session_named() -> None:
    # KILL SESSION ends the backend with that SID while its serial still matches;
    # a stale serial, the caller's own session or a malformed ID fail as Oracle's
    # do (#1212). The kill returns once the victim's backend is gone, and every
    # call the victim makes then answers ORA-00028, as a killed Oracle session's
    # does (#1367).
    from seerdb.server import BackendError

    killer = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    victim = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        info = victim.session_info()
        own = killer.session_info()
        for session, code in (
            ('1,2,3,4', 26),
            (f'{info.session_id},{info.serial_num + 1}', 30),
            (f'{own.session_id},{own.serial_num}', 27),
        ):
            with pytest.raises(BackendError) as caught:
                killer.execute(f"ALTER SYSTEM KILL SESSION '{session}'")
            assert caught.value.ora_code == code
        killer.execute(
            f"alter system kill session '{info.session_id},{info.serial_num}' immediate"
        )
        assert victim.closed
        for call in (
            lambda: victim.execute('SELECT 1 FROM dual'),
            victim.commit,
            victim.ping,
        ):
            with pytest.raises(BackendError) as caught:
                call()
            assert caught.value.ora_code == 28
        assert killer.execute('SELECT 1 FROM dual').rows == [(1,)]
        killer.ping()  # a live session's ping is quiet
    finally:
        killer.close()
        victim.close()


def test_an_identifier_containing_a_hash_is_quoted() -> None:
    # PostgreSQL has no `#` in an unquoted name; quote it in the lower case an
    # unquoted name is stored in, and leave literals, quoted names, comments and
    # bind names alone (#1249).
    from seerdb.server.backends.postgres import _quote_hash_identifiers as quote

    assert quote('SELECT sid, serial# FROM v$session') == (
        'SELECT sid, "serial#" FROM v$session'
    )
    assert quote('CREATE TABLE t (OBJ# NUMBER)') == 'CREATE TABLE t ("obj#" NUMBER)'
    untouched = """SELECT 'a#b', "Obj#" FROM t WHERE x = :b# -- c#\n/* d# */"""
    assert quote(untouched) == untouched
    assert quote('SELECT 1 FROM dual') == 'SELECT 1 FROM dual'


# --- DBMS_PICKLER.GET_TYPE_SHAPE (#1134) -----------------------------------------

# The TDS real 23ai returned for each type (type_shape capture, 2026-09-25), the
# ground truth the encoder has to reproduce. The DDL of each is in the shapes
# below; the OIDs inside are not in a TDS, so these bytes are the server's own.
_CAPTURED_TDS = {
    'PYO_TS_SUB': '0000001426010001000100290000000000090600812a0007',
    'PYO_TS_ALL': '0000007926020001001600290000000000440600810605020609000600000500050a07003c01000001000a01000007003c820000010008820000130010252d0215061503170621061d1d1e27060081282a0007000a000d0010001300150017001d00230029002f003200330034003500370039003b003d003e003f0041',
    'PYO_TS_VARRAY': '0000001e260100010001ff290000000000131c0000001d0000000a032a0600810007',
    'PYO_TS_TABLE_V': '00000021260100010001ff290000000000161c0000001d00000000022a0700140100000007',
    'PYO_TS_TABLE_O': '00000057260100010001ff2900000000004c1c0000001d00000000022a1b00000023fafd000000310000001426010001000100290000000000090600812a00070000001526010001000200290000000000081a1a2a000700080007',
    'PYO_TS_VARRAY_O': '00000057260100010001ff2900000000004c1c0000001d00000003032a1b00000023fafd000000310000001426010001000100290000000000090600812a00070000001526010001000200290000000000081a1a2a000700080007',
    'PYO_T2_NUM2': '00000019260100010002002900000000000c0600810600812a0007000a',
    'PYO_T2_VC': '0000001c260100010002002900000000000f0700140100000604002a0007000d',
    'PYO_T2_TS': '00000013260200010001002900000000000815062a0007',
    'PYO_T2_BF': '000000122602000100010029000000000007252a0007',
    'PYO_T2_CL': '0000001226010001000100290000000000071d2a0007',
    'PYO_T2_DT': '000000122601000100010029000000000007022a0007',
    'PYO_T2_EMB': '00000020260100010003002900000000001106008127060081060081282a0007000b000e',
    'PYO_T2_TAB_VC': '00000062260100010001ff290000000000571c0000001d00000000022a1b00000023fafd0000003c0000001c260100010002002900000000000f0700140100000604002a0007000d0000001826010001000300290000000000091a1a1a2a0007000800090007',
    'PYO_T2_VA_NUM2': '0000005f260100010001ff290000000000541c0000001d00000005032a1b00000023fafd0000003900000019260100010002002900000000000c0600810600812a0007000a0000001826010001000300290000000000091a1a1a2a0007000800090007',
    'PYO_T2_TN': '0000001e260100010001ff290000000000131c0000001d00000000022a0600810007',
    'PYO_T2_TTN': '00000044260100010001ff290000000000391c0000001d00000000022a1b00000023fbfd0000001e260100010001ff290000000000131c0000001d00000000022a06008100070007',
    'PYO_T2_VTN': '00000044260100010001ff290000000000391c0000001d00000004032a1b00000023fbfd0000001e260100010001ff290000000000131c0000001d00000000022a06008100070007',
    'PYO_T2_TAB_EMB': '0000006e260100010001ff290000000000631c0000001d00000000022a1b00000023fafd0000004800000020260100010003002900000000001106008127060081060081282a0007000b000e00000020260100010005002900000000000d1a1a271a1a1a282a00070008000a000b000c0007',
    'PYO_T3_ARR': '00000057260100010001ff2900000000004c1c0000001d0000000a032a1b00000023fafd000000310000001426010001000100290000000000090600812a00070000001526010001000200290000000000081a1a2a000700080007',
    'PYO_T3_OBJ': '000000ab260100010004002900000000009a0600811b00000028fb1b00000084fb0700050100002afd00000057260100010001ff2900000000004c1c0000001d0000000a032a1b00000023fafd000000310000001426010001000100290000000000090600812a00070000001526010001000200290000000000081a1a2a000700080007fd0000001e260100010001ff290000000000131c0000001d00000000022a06008100070007000a00100016',
}


def _captured_shapes() -> dict:
    from seerdb.server.backends.postgres import _tds_chars, _tds_number, _tds_timestamp
    from seerdb.server.backends.postgres import _TdsCollection as C
    from seerdb.server.backends.postgres import _TdsLeaf as L
    from seerdb.server.backends.postgres import _TdsObject as _O

    def O(*attrs):  # noqa: N802 -- a constructor, as the encoder's types read
        return _O(tuple(attrs))

    N = _tds_number()
    V20 = _tds_chars(0x07, 20, False)
    SUB = O(N)
    NUM2 = O(N, N)
    VC = O(V20, _tds_number(4, 0))
    EMB = O(N, NUM2)
    TN = C(False, 0, N)
    ARR3 = C(True, 10, SUB)
    return {
        'PYO_TS_SUB': SUB,
        'PYO_TS_ALL': O(
            N,
            _tds_number(5, 2),
            _tds_number(9, 0),
            _tds_number(0, 0),
            L(b'\x05\x00'),
            L(b'\x05\x0a'),
            _tds_chars(0x07, 60, False),
            _tds_chars(0x01, 10, False),
            _tds_chars(0x07, 60, True),
            _tds_chars(0x01, 8, True),
            L(b'\x13\x00\x10'),
            L(b'\x25', newer=True),
            L(b'\x2d', newer=True),
            L(b'\x02'),
            _tds_timestamp(0x15, 6),
            _tds_timestamp(0x15, 3),
            _tds_timestamp(0x17, 6),
            _tds_timestamp(0x21, 6),
            L(b'\x1d'),
            L(b'\x1d'),
            L(b'\x1e'),
            SUB,
        ),
        'PYO_TS_VARRAY': C(True, 10, N),
        'PYO_TS_TABLE_V': C(False, 0, V20),
        'PYO_TS_TABLE_O': C(False, 0, SUB),
        'PYO_TS_VARRAY_O': C(True, 3, SUB),
        'PYO_T2_NUM2': NUM2,
        'PYO_T2_VC': VC,
        'PYO_T2_TS': O(_tds_timestamp(0x15, 6)),
        'PYO_T2_BF': O(L(b'\x25', newer=True)),
        'PYO_T2_CL': O(L(b'\x1d')),
        'PYO_T2_DT': O(L(b'\x02')),
        'PYO_T2_EMB': EMB,
        'PYO_T2_TAB_VC': C(False, 0, VC),
        'PYO_T2_VA_NUM2': C(True, 5, NUM2),
        'PYO_T2_TN': TN,
        'PYO_T2_TTN': C(False, 0, TN),
        'PYO_T2_VTN': C(True, 4, TN),
        'PYO_T2_TAB_EMB': C(False, 0, EMB),
        'PYO_T3_ARR': ARR3,
        'PYO_T3_OBJ': O(N, ARR3, C(False, 0, N), _tds_chars(0x07, 5, False)),
    }


def test_the_tds_encoder_reproduces_what_23ai_sends() -> None:
    # Byte for byte, header, embedded objects, references, null images and the
    # index table included, for every captured object and collection type.
    from seerdb.server.backends.postgres import _tds

    shapes = _captured_shapes()
    assert set(shapes) == set(_CAPTURED_TDS)
    for name, shape in shapes.items():
        assert _tds(shape).hex() == _CAPTURED_TDS[name], name


_TYPE_SHAPE_SQL = """
        declare
            t_Instantiable              varchar2(3);
            t_SuperTypeOwner            varchar2(128);
            t_SuperTypeName             varchar2(128);
            t_SubTypeRefCursor          sys_refcursor;
            t_Pos                       pls_integer;
        begin
            :ret_val := dbms_pickler.get_type_shape(:full_name, :oid,
                :version, :tds, t_Instantiable, t_SuperTypeOwner,
                t_SuperTypeName, :attrs_rc, t_SubTypeRefCursor);
            :package_name := null;
        end;"""


def test_get_type_shape_is_answered_from_the_catalog() -> None:
    # python-oracledb's type-metadata block, answered whole: the OID, the TDS,
    # the attribute cursor, the type's own schema and name -- and 1001 for a
    # type that does not exist, as GET_TYPE_SHAPE returns it.
    from seerdb.common.tns_consts import (
        TNS_TYPE_NUMBER,
        TNS_TYPE_RAW,
        TNS_TYPE_REFCURSOR,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server.backend import BindVar
    from seerdb.server.backends.postgres import _tds

    admin = psycopg.connect(_CONNINFO, autocommit=True)
    admin.execute('DROP SCHEMA IF EXISTS pyo_shape CASCADE')
    admin.execute('CREATE SCHEMA pyo_shape')
    backend = PostgresBackend(_CONNINFO, credentials={'PYO_SHAPE': 'x'})
    try:
        backend.authenticate('PYO_SHAPE')
        backend.execute('CREATE TYPE pyo_shape_sub AS OBJECT (a NUMBER)')
        backend.execute('CREATE TYPE pyo_shape_arr AS VARRAY(10) OF pyo_shape_sub')
        backend.execute(
            'CREATE TYPE pyo_shape_obj AS OBJECT '
            '(n NUMBER(5,2), v VARCHAR2(20), arr pyo_shape_arr)'
        )

        def shape(full_name: str) -> list:
            binds = [
                BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=4),
                BindVar(value=full_name, tns_type=TNS_TYPE_VARCHAR, max_size=128),
                BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=16),
                BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=4),
                BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=32767),
                BindVar(value=None, tns_type=TNS_TYPE_REFCURSOR, max_size=1),
                BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=128),
            ]
            return backend.execute(_TYPE_SHAPE_SQL, binds).out_binds

        (ret_val, _full, oid, version, tds, attrs, package) = shape(
            'PYO_SHAPE.PYO_SHAPE_OBJ'
        )
        assert (ret_val, version, package) == (0, 1, None)
        assert len(oid) == 16
        from seerdb.server.backends.postgres import (
            _tds_chars,
            _tds_number,
            _TdsCollection,
            _TdsObject,
        )

        sub = _TdsObject((_tds_number(),))
        assert tds == _tds(
            _TdsObject(
                (
                    _tds_number(5, 2),
                    _tds_chars(0x07, 20, False),
                    _TdsCollection(True, 10, sub),
                )
            )
        )
        assert [r[1:5] for r in attrs.rows] == [
            ('N', 1, 'NUMBER', None),
            ('V', 2, 'VARCHAR2', None),
            ('ARR', 3, 'PYO_SHAPE_ARR', 'PYO_SHAPE'),
        ]
        # A collection has no attributes; unqualified resolves in the schema.
        (ret_val, _f, _o, _v, tds, attrs, _p) = shape('PYO_SHAPE_ARR')
        assert ret_val == 0 and attrs.rows == []
        assert tds == _tds(_TdsCollection(True, 10, sub))
        (ret_val, _f, oid, _v, tds, _a, _p) = shape('PYO_SHAPE.NO_SUCH_TYPE')
        assert (ret_val, oid, tds) == (1001, None, None)
    finally:
        backend.close()
        admin.execute('DROP SCHEMA pyo_shape CASCADE')
        admin.close()


def test_a_package_types_declaration_is_read_for_its_metadata() -> None:
    # A record's fields and a collection's element as 23ai's dictionary lists
    # them (#1607): a built-in's name, length and character set -- an NVARCHAR2
    # counted in characters -- a PL/SQL integer by its PL/SQL name, another of
    # the package's types by package, a SUBTYPE by what it stands for.
    from seerdb.server.backends.postgres import _PackageMember, _plsql_type_meta

    siblings: dict[str, dict] = {}

    def read(kind: str, name: str, definition: str) -> dict | None:
        meta = _plsql_type_meta(
            'pk', _PackageMember(kind, name, None, None, definition), siblings
        )
        siblings[name.upper()] = meta or {}
        return meta

    record = read(
        'TYPE',
        'r',
        'RECORD (n NUMBER, s VARCHAR2(30), d DATE, t TIMESTAMP, '
        'b BOOLEAN, i PLS_INTEGER)',
    )
    assert record is not None
    assert (record['typecode'], record['attributes'], record['contains_plsql']) == (
        'PL/SQL RECORD',
        6,
        'YES',
    )
    assert [(f['name'], f['type']) for f in record['attrs']][:2] == [
        ('N', {'named': False, 'package': None, 'name': 'NUMBER', 'precision': None}),
        (
            'S',
            {
                'named': False, 'package': None, 'name': 'VARCHAR2', 'length': 30,
                'charset': 'CHAR_CS', 'char_used': 'B',
            },
        ),
    ]  # fmt: skip
    assert record['attrs'][5]['type']['name'] == 'PL/SQL PLS INTEGER'
    unicode = read('TYPE', 'u', 'TABLE OF NVARCHAR2(100) INDEX BY BINARY_INTEGER')
    assert unicode is not None
    assert (unicode['coll_type'], unicode['index_by'], unicode['contains_plsql']) == (
        'PL/SQL INDEX TABLE',
        'BINARY_INTEGER',
        'NO',
    )
    assert unicode['elem'] == {
        'named': False, 'package': None, 'name': 'NVARCHAR2', 'length': 100,
        'charset': 'NCHAR_CS', 'char_used': 'C',
    }  # fmt: skip
    records = read('TYPE', 'a', 'TABLE OF r INDEX BY BINARY_INTEGER')
    assert records is not None
    assert records['elem'] == {'named': True, 'package': 'PK', 'name': 'R'}
    read('SUBTYPE', 'w', 'TestTempTable%ROWTYPE')
    rows = read('TYPE', 'c', 'TABLE OF w INDEX BY BINARY_INTEGER')
    assert rows is not None
    assert rows['elem'] == {
        'named': True,
        'package': None,
        'name': 'TESTTEMPTABLE%ROWTYPE',
    }
    assert rows['contains_plsql'] == 'YES'


def test_a_package_types_metadata_is_oracles() -> None:
    # A client's type lookup of a package's types answered as 23ai answers it
    # (#1607): the TDS byte for byte -- an index-by table kind 1, an index-by
    # table of a record with a timestamp version 2 -- the attribute cursor, the
    # type's own package, and the ALL_PLSQL_* views' rows. The bytes and rows
    # are 23ai's, for the same declarations in python-oracledb's test schema.
    from seerdb.common.tns_consts import (
        TNS_TYPE_NUMBER,
        TNS_TYPE_RAW,
        TNS_TYPE_REFCURSOR,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE OR REPLACE PACKAGE pyo.pm1607 AS\n'
            '  TYPE udt_Record IS RECORD (NumberValue NUMBER, StringValue VARCHAR2(30), '
            'DateValue DATE, TimestampValue TIMESTAMP, BooleanValue BOOLEAN, '
            'PlsIntegerValue PLS_INTEGER, BinaryIntegerValue BINARY_INTEGER);\n'
            '  TYPE udt_RecordArray IS TABLE OF udt_Record INDEX BY BINARY_INTEGER;\n'
            '  TYPE udt_UnicodeList IS TABLE OF NVARCHAR2(100) INDEX BY BINARY_INTEGER;\n'
            '  TYPE udt_BooleanList IS TABLE OF BOOLEAN INDEX BY BINARY_INTEGER;\n'
            '  TYPE udt_Inner IS RECORD (Attr1 NUMBER, Attr2 NUMBER);\n'
            '  TYPE udt_Outer IS RECORD (Inner1 udt_Inner, Inner2 udt_Inner);\nEND;'
        )

        def shape(full_name: str) -> list:
            binds = [
                BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=4),
                BindVar(value=full_name, tns_type=TNS_TYPE_VARCHAR, max_size=128),
                BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=16),
                BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=4),
                BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=32767),
                BindVar(value=None, tns_type=TNS_TYPE_REFCURSOR, max_size=1),
                BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=128),
            ]
            return backend.execute(_TYPE_SHAPE_SQL, binds).out_binds

        captured = {
            'UDT_RECORD': '0000002c260200010007002900000000001506008107001e010000021506'
            '0808082a0007000a00100011001300140015',
            'UDT_RECORDARRAY': '00000081260200010001ff290000000000761c0000001d000000'
            '00012a1b00000023fafd0000005b0000002c260200010007002900000000001506'
            '008107001e0100000215060808082a0007000a0010001100130014001500000027'
            '260100010008002900000000000e1a1a1a1a1a1a1a1a2a000700080009000a000b'
            '000c000d000e0007',
            'UDT_UNICODELIST': '00000021260100010001ff290000000000161c0000001d0000'
            '0000012a0700c88200000007',
            'UDT_BOOLEANLIST': '0000001c260100010001ff290000000000111c0000001d0000'
            '0000012a080007',
            'UDT_OUTER': '000000272601000100040029000000000016270600810600812827060'
            '081060081282a0008000b00100013',
        }
        for name, tds in captured.items():
            (ret_val, _f, oid, version, got, _attrs, package) = shape(
                f'"PYO"."PM1607"."{name}"'
            )
            assert (ret_val, version, package, len(oid)) == (0, 1, 'PM1607', 16), name
            assert got.hex() == tds, name
        attrs = shape('"PYO"."PM1607"."UDT_RECORD"')[5].rows
        assert [r[1:6] + r[7:] for r in attrs] == [
            ('NUMBERVALUE', 1, 'NUMBER', None, None, 'YES', None, None),
            ('STRINGVALUE', 2, 'VARCHAR2', None, None, 'YES', None, None),
            ('DATEVALUE', 3, 'DATE', None, None, 'YES', None, None),
            ('TIMESTAMPVALUE', 4, 'TIMESTAMP', None, None, 'YES', None, None),
            ('BOOLEANVALUE', 5, 'BOOLEAN', None, None, 'YES', None, None),
            ('PLSINTEGERVALUE', 6, 'PL/SQL PLS INTEGER', None, None, 'YES', None, None),
            (
                'BINARYINTEGERVALUE', 7, 'PL/SQL BINARY INTEGER', None, None, 'YES',
                None, None,
            ),
        ]  # fmt: skip
        assert [r[6][-1] for r in attrs] == [0x0F, 0x19, 0x08, 0x3D, 0x2E, 0x33, 0x32]
        (element,) = shape('"PYO"."PM1607"."UDT_RECORDARRAY"')[5].rows
        assert element[1:6] + element[7:] == (
            None,
            1,
            'UDT_RECORD',
            'PYO',
            'PM1607',
            None,
            None,
            None,
        )
        assert backend.execute(
            'SELECT type_name, typecode, attributes, contains_plsql '
            "FROM all_plsql_types WHERE package_name = 'PM1607' ORDER BY type_name"
        ).rows == [
            ('UDT_BOOLEANLIST', 'COLLECTION', 0, 'NO'),
            ('UDT_INNER', 'PL/SQL RECORD', 2, 'NO'),
            ('UDT_OUTER', 'PL/SQL RECORD', 2, 'YES'),
            ('UDT_RECORD', 'PL/SQL RECORD', 7, 'YES'),
            ('UDT_RECORDARRAY', 'COLLECTION', 0, 'YES'),
            ('UDT_UNICODELIST', 'COLLECTION', 0, 'NO'),
        ]
        assert backend.execute(
            'SELECT type_name, coll_type, elem_type_owner, elem_type_package, '
            'elem_type_name, length, character_set_name, char_used, index_by '
            "FROM all_plsql_coll_types WHERE package_name = 'PM1607' "
            'ORDER BY type_name'
        ).rows == [
            ('UDT_BOOLEANLIST', 'PL/SQL INDEX TABLE', None, None, 'BOOLEAN', None,
             None, 'B', 'BINARY_INTEGER'),
            ('UDT_RECORDARRAY', 'PL/SQL INDEX TABLE', 'PYO', 'PM1607', 'UDT_RECORD',
             None, None, 'B', 'BINARY_INTEGER'),
            ('UDT_UNICODELIST', 'PL/SQL INDEX TABLE', None, None, 'NVARCHAR2', 100,
             'NCHAR_CS', 'C', 'BINARY_INTEGER'),
        ]  # fmt: skip
        assert backend.execute(
            'SELECT attr_name, attr_type_owner, attr_type_package, attr_type_name, '
            'length, scale, character_set_name, attr_no '
            "FROM all_plsql_type_attrs WHERE package_name = 'PM1607' "
            "AND type_name IN ('UDT_RECORD', 'UDT_OUTER') ORDER BY type_name, attr_no"
        ).rows[:4] == [
            ('INNER1', 'PYO', 'PM1607', 'UDT_INNER', None, None, None, 1),
            ('INNER2', 'PYO', 'PM1607', 'UDT_INNER', None, None, None, 2),
            ('NUMBERVALUE', None, None, 'NUMBER', None, None, None, 1),
            ('STRINGVALUE', None, None, 'VARCHAR2', 30, None, 'CHAR_CS', 2),
        ]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP PACKAGE pm1607')
        except Exception:
            backend.rollback()


def test_a_package_types_values_bind_and_come_back() -> None:
    # Through the Mirror and a client (#1607): a record bound IN and filled as an
    # OUT -- a BOOLEAN and a PLS_INTEGER field among its fields -- an index-by
    # table bound and returned under its own sparse keys, and a classic array
    # (cursor.arrayvar) through an IN OUT index-by table parameter.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute(
            'CREATE OR REPLACE PACKAGE pb1607 AS\n'
            '  TYPE r IS RECORD (n NUMBER, s VARCHAR2(20), b BOOLEAN, i PLS_INTEGER);\n'
            '  TYPE t IS TABLE OF VARCHAR2(20) INDEX BY BINARY_INTEGER;\n'
            '  FUNCTION rep(a r) RETURN VARCHAR2;\n'
            '  PROCEDURE make(n NUMBER, a OUT r);\n'
            '  FUNCTION echo(a t) RETURN t;\n'
            '  PROCEDURE pass(a IN OUT t);\nEND;'
        )
        cur.execute(
            'CREATE OR REPLACE PACKAGE BODY pb1607 AS\n'
            '  FUNCTION rep(a r) RETURN VARCHAR2 IS BEGIN\n'
            "    RETURN a.n || ':' || a.s || ':' || CASE WHEN a.b THEN 'T' ELSE 'F' "
            "END || ':' || a.i;\n  END;\n"
            '  PROCEDURE make(n NUMBER, a OUT r) IS BEGIN\n'
            "    a.n := n; a.s := 'made'; a.b := TRUE; a.i := -3;\n  END;\n"
            '  FUNCTION echo(a t) RETURN t IS BEGIN RETURN a; END;\n'
            '  PROCEDURE pass(a IN OUT t) IS BEGIN NULL; END;\nEND;'
        )
        record_type = conn.gettype('PB1607.R')
        record = record_type.newobject()
        record.N = 25
        record.S = 'x'
        record.B = True
        record.I = -45
        assert cur.callfunc('pb1607.rep', str, [record]) == '25:x:T:-45'
        made = record_type.newobject()
        cur.callproc('pb1607.make', [7, made])
        assert (made.N, made.S, made.B, made.I) == (7, 'made', True, -3)
        table_type = conn.gettype('PB1607.T')
        table = table_type.newobject(['a', 'b', 'c'], keys=[-1048576, 2, 8388608])
        echoed = cur.callfunc('pb1607.echo', table_type, [table])
        assert echoed.aslist() == ['a', 'b', 'c']
        assert (echoed.first(), echoed.next(2), echoed.last()) == (
            -1048576,
            8388608,
            8388608,
        )
        array = cur.arrayvar(str, ['x', 'y'], 5)
        cur.callproc('pb1607.pass', [array])
        assert array.getvalue() == ['x', 'y']
    finally:
        try:
            conn.cursor().execute('DROP PACKAGE pb1607')
        except Exception:
            pass
        conn.close()
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')


def test_a_body_indexes_its_index_by_tables() -> None:
    # A routine's index-by tables, its parameters' and locals', in PostgreSQL's
    # terms (#1607): an element set and read, the collection methods called,
    # DELETE assigned; another's field `x.v` and a range bound `1..v.COUNT`
    # read as what they are.
    from seerdb.server.backends.postgres import (
        _PackageMember,
        _rewrite_index_tables,
        _routine_index_tables,
    )

    member = _PackageMember(
        'PROCEDURE', 'p', 'a IN OUT NOCOPY t, n NUMBER', None,
        ' l t; k PLS_INTEGER; BEGIN NULL; END',
    )  # fmt: skip
    tables = _routine_index_tables('pk', member, {'t': 'pk.t'})
    assert tables == {'a': 'pk.t', 'l': 'pk.t'}
    assert _rewrite_index_tables(
        "BEGIN a(-1) := 'x'; FOR i IN 1..a.COUNT LOOP l(i) := a(i) || 'y'; END LOOP; "
        'k := a.FIRST; WHILE k IS NOT NULL LOOP k := a.NEXT(k); END LOOP; '
        'IF a.EXISTS(3) THEN a.DELETE(3); END IF; l.DELETE; r := x.a; END',
        tables,
    ) == (
        "BEGIN a := pk.t$set(a, -1, 'x'); FOR i IN 1..pk.t$count(a) LOOP "
        "l := pk.t$set(l, i, pk.t$get(a, i) || 'y'); END LOOP; "
        'k := pk.t$first(a); WHILE k IS NOT NULL LOOP k := pk.t$next(a, k); END LOOP; '
        'IF pk.t$exists(a, 3) THEN a := pk.t$delete(a, 3); END IF; '
        'l := pk.t$delete(l); r := x.a; END'
    )
    # A string literal holding the name is no use of it.
    assert _rewrite_index_tables("x := 'a(1)';", tables) == "x := 'a(1)';"
    # Empty parentheses add no argument: `a.LAST()` is `a.LAST`, as Oracle
    # takes it -- python-oracledb 26's PKG_TESTRECORDS writes it so (#1780).
    assert _rewrite_index_tables(
        'k := a.last(); n := a.COUNT( ); a.DELETE();', tables
    ) == ('k := pk.t$last(a); n := pk.t$count(a); a := pk.t$delete(a);')
    # An element's field assigned is the element with that field replaced,
    # made with its other fields NULL when it is not there yet (#1795).
    assert _rewrite_index_tables(
        'BEGIN a(k + 1).NumberValue := n * 2; END', tables
    ) == (
        'BEGIN a := pk.t$set(a, k + 1, jsonb_populate_record('
        'CASE WHEN pk.t$exists(a, k + 1) THEN pk.t$get(a, k + 1) END, '
        "jsonb_build_object('numbervalue', n * 2))); END"
    )
    # An element's field read is a field of the call's result, which
    # PostgreSQL takes only in parentheses (#1799); a range bound is no field.
    assert _rewrite_index_tables(
        'x := a(k).NumberValue + a(1) . s; FOR i IN a(1)..a(2) LOOP NULL; END LOOP;',
        tables,
    ) == (
        'x := (pk.t$get(a, k)).NumberValue + (pk.t$get(a, 1)) . s; '
        'FOR i IN pk.t$get(a, 1)..pk.t$get(a, 2) LOOP NULL; END LOOP;'
    )


def test_an_index_by_tables_methods_run_as_oracles() -> None:
    # A package body walking index-by tables as python-oracledb's test schema
    # does (#1607): sparse keys in key order, a table keyed by a string walked
    # FIRST / NEXT in byte order, EXISTS, DELETE, COUNT, and ORA-01403 for a key
    # that is not there. The answers are 23ai's.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server import BackendError
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE OR REPLACE PACKAGE pi1607 AS\n'
            '  TYPE t IS TABLE OF NUMBER INDEX BY BINARY_INTEGER;\n'
            '  TYPE p IS TABLE OF VARCHAR2(10) INDEX BY VARCHAR2(10);\n'
            '  FUNCTION walk RETURN VARCHAR2;\n'
            '  FUNCTION props RETURN VARCHAR2;\n'
            '  FUNCTION missing RETURN NUMBER;\nEND;'
        )
        backend.execute(
            'CREATE OR REPLACE PACKAGE BODY pi1607 AS\n'
            '  FUNCTION walk RETURN VARCHAR2 IS\n'
            '    a t;\n    k PLS_INTEGER;\n    s VARCHAR2(200);\n  BEGIN\n'
            '    a(8388608) := 4; a(-1048576) := 1; a(284) := 3; a(-576) := 2;\n'
            '    a(284) := a(284) * 10;\n'
            '    k := a.FIRST;\n'
            "    WHILE k IS NOT NULL LOOP s := s || k || '=' || a(k) || ' '; "
            'k := a.NEXT(k); END LOOP;\n'
            "    a.DELETE(-576);\n    s := s || a.COUNT || ' ' || a.LAST || ' ' || "
            "CASE WHEN a.EXISTS(-576) THEN 'y' ELSE 'n' END;\n"
            '    RETURN s;\n  END;\n'
            '  FUNCTION props RETURN VARCHAR2 IS\n'
            '    v p;\n    k VARCHAR2(10);\n    s VARCHAR2(200);\n  BEGIN\n'
            "    v('b') := '2'; v('B') := '1'; v('a') := '3';\n"
            '    k := v.FIRST;\n    WHILE k IS NOT NULL LOOP s := s || k || v(k); '
            'k := v.NEXT(k); END LOOP;\n    RETURN s;\n  END;\n'
            '  FUNCTION missing RETURN NUMBER IS a t; BEGIN a(1) := 1; RETURN a(2); END;\n'
            'END;'
        )
        assert backend.execute(
            "SELECT spec, body FROM sys.ora_packages WHERE name = 'pi1607'"
        ).rows == [('VALID', 'VALID')]
        (row,) = backend.execute('SELECT pi1607.walk() FROM dual').rows
        assert row[0] == '-1048576=1 -576=2 284=30 8388608=4 3 8388608 n'
        (row,) = backend.execute('SELECT pi1607.props() FROM dual').rows
        assert row[0] == 'B1a3b2'
        # Called from PL/SQL, as a client's callfunc does; from SQL, Oracle
        # turns NO_DATA_FOUND into NULL instead.
        with pytest.raises(BackendError) as exc:
            backend.execute(
                'BEGIN :1 := pi1607.missing(); END;',
                [BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22)],
            )
        assert exc.value.ora_code == 1403
    finally:
        backend.rollback()
        try:
            backend.execute('DROP PACKAGE pi1607')
        except Exception:
            backend.rollback()


def test_an_index_by_tables_element_fields_read_as_oracles() -> None:
    # A field of an index-by table's element, set and read in a package body
    # (#1795, #1799). A field never set is NULL. The answer is 23ai's.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE OR REPLACE PACKAGE pf1799 AS\n'
            '  TYPE rec IS RECORD (n NUMBER, s VARCHAR2(10));\n'
            '  TYPE arr IS TABLE OF rec INDEX BY BINARY_INTEGER;\n'
            '  FUNCTION f RETURN VARCHAR2;\nEND;'
        )
        backend.execute(
            'CREATE OR REPLACE PACKAGE BODY pf1799 AS\n'
            '  FUNCTION f RETURN VARCHAR2 IS\n    a arr;\n  BEGIN\n'
            "    a(1).n := 21; a(1).s := 'x'; a(2).n := 4;\n"
            "    RETURN a(1).n * 2 || a(1).s || a(2).n || '/' || NVL(a(2).s, '-');\n"
            '  END;\nEND;'
        )
        assert backend.execute(
            "SELECT spec, body FROM sys.ora_packages WHERE name = 'pf1799'"
        ).rows == [('VALID', 'VALID')]
        (row,) = backend.execute('SELECT pf1799.f() FROM dual').rows
        assert row[0] == '42x4/-'
    finally:
        backend.rollback()
        try:
            backend.execute('DROP PACKAGE pf1799')
        except Exception:
            backend.rollback()


def test_an_is_json_condition_is_no_json_column() -> None:
    # A CHECK (x IS JSON) on a VARCHAR2 / CLOB / BLOB column is 12.1's, not the
    # JSON type a pre-21c server refuses (#1614); the condition is
    # sys.ora_is_json, which takes a CLOB's or BLOB's domain, without Oracle's
    # FORMAT JSON or STRICT / LAX. A JSON column is still refused.
    from seerdb.server import BackendError
    from seerdb.server.backends.postgres import _reject_unsupported_ddl_types

    _reject_unsupported_ddl_types(
        'CREATE TABLE t (v VARCHAR2(10), CONSTRAINT c CHECK (v IS JSON FORMAT JSON))',
        (12, 1),
    )
    with pytest.raises(BackendError):
        _reject_unsupported_ddl_types('CREATE TABLE t (j JSON)', (12, 1))
    assert (
        _translate_idioms(
            "SELECT 1 FROM t WHERE t.v IS JSON STRICT AND ('x') IS NOT JSON LAX"
        )
        == "SELECT 1 FROM t WHERE sys.ora_is_json(t.v) AND NOT sys.ora_is_json(('x'))"
    )


def test_a_table_with_is_json_constraints_keeps_its_json() -> None:
    # python-oracledb's TestJsonCols shape (#1614): JSON in a VARCHAR2, a CLOB
    # and a BLOB, each checked IS JSON; text that is none is ORA-02290, a NULL
    # passes, and IS JSON reads in a query. As 23ai answers.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TABLE jc1614 (id NUMBER, v VARCHAR2(100), c CLOB, b BLOB, '
            'CONSTRAINT jc1614_v CHECK (v IS JSON FORMAT JSON), '
            'CONSTRAINT jc1614_c CHECK (c IS JSON), '
            'CONSTRAINT jc1614_b CHECK (b IS JSON FORMAT JSON))'
        )
        backend.execute(
            "INSERT INTO jc1614 VALUES (1, '[1, 2]', '{\"a\": 1}', :1)", [b'[3]']
        )
        backend.execute('INSERT INTO jc1614 VALUES (2, NULL, NULL, NULL)')
        for column in ('v', 'c'):
            with pytest.raises(BackendError) as exc:
                backend.execute(f"INSERT INTO jc1614 (id, {column}) VALUES (3, 'nope')")
            assert exc.value.ora_code == 2290
        assert backend.execute(
            'SELECT id FROM jc1614 WHERE v IS JSON ORDER BY id'
        ).rows == [(1,)]
        assert backend.execute('SELECT id FROM jc1614 WHERE c IS NOT JSON').rows == []
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE jc1614')
        except Exception:
            backend.rollback()


def test_a_cursor_bound_in_resumes_where_the_client_stopped() -> None:
    # A client's cursor bound IN as a REF CURSOR (#1609): its query opened as
    # a portal past the rows the client already has, so a routine's FETCH
    # reads the next one -- python-oracledb's test_1609 gets row 7 after its
    # cursor prefetched 5 and 6, as from Oracle -- and the portal goes to a
    # SYS_REFCURSOR parameter, not as text.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE OR REPLACE FUNCTION rc1609(c SYS_REFCURSOR) RETURN VARCHAR2 IS\n'
            '  s VARCHAR2(20);\nBEGIN\n  FETCH c INTO s;\n  RETURN s;\nEND;'
        )
        query = "SELECT 'row ' || level FROM dual CONNECT BY level <= 5"
        resumed = backend.open_ref_cursor(query, 2)
        (row,) = backend.execute('SELECT rc1609(:1) FROM dual', [resumed]).rows
        assert row[0] == 'row 3'
        fresh = backend.open_ref_cursor(query)
        (row,) = backend.execute('SELECT rc1609(:1) FROM dual', [fresh]).rows
        assert row[0] == 'row 1'
    finally:
        backend.rollback()
        try:
            backend.execute('DROP FUNCTION rc1609')
        except Exception:
            backend.rollback()


def test_a_cursor_bound_in_is_not_reported_back() -> None:
    # A procedure handed a client's cursor (#1634) reports nothing for it, as
    # for a cursor it closed (#1048) -- not the portal's name, which the Mirror
    # sent as text and python-oracledb read as a cursor (DPY-5002).
    from seerdb.common.tns_consts import TNS_TYPE_REFCURSOR
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE OR REPLACE PROCEDURE rc1634(c SYS_REFCURSOR) IS\n'
            '  n NUMBER;\nBEGIN\n  FETCH c INTO n;\n  CLOSE c;\nEND;'
        )
        portal = backend.open_ref_cursor('SELECT 1 FROM dual')
        result = backend.execute(
            'BEGIN rc1634(:1); END;',
            [BindVar(value=portal, tns_type=TNS_TYPE_REFCURSOR, max_size=0)],
        )
        assert result.out_binds == [None]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP PROCEDURE rc1634')
        except Exception:
            backend.rollback()


def test_a_failing_call_keeps_the_callers_open_work() -> None:
    # A procedure or function call that fails undoes only itself (#1632): the
    # caller's uncommitted row survives it, as 23ai's does, where a rollback of
    # the whole transaction lost it -- a call to no such overload included.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
    from seerdb.server import BackendError
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE fc1632t (n NUMBER)')
        backend.execute(
            'CREATE OR REPLACE PROCEDURE fc1632p(v NUMBER) IS\nBEGIN\n'
            '  INSERT INTO fc1632t VALUES (v);\n'
            "  raise_application_error(-20001, 'boom');\nEND;"
        )
        backend.execute(
            'CREATE OR REPLACE FUNCTION fc1632f(v NUMBER) RETURN NUMBER IS\nBEGIN\n'
            '  INSERT INTO fc1632t VALUES (v);\n'
            "  raise_application_error(-20002, 'boom');\n  RETURN 1;\nEND;"
        )
        backend.execute('INSERT INTO fc1632t VALUES (3)')
        with pytest.raises(BackendError) as exc:
            backend.execute(
                'BEGIN fc1632p(:1); END;',
                [BindVar(value=4, tns_type=TNS_TYPE_NUMBER, max_size=22)],
            )
        assert exc.value.ora_code == 20001
        with pytest.raises(BackendError) as exc:
            backend.execute(
                'BEGIN :1 := fc1632f(:2); END;',
                [
                    BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22),
                    BindVar(value=5, tns_type=TNS_TYPE_NUMBER, max_size=22),
                ],
            )
        assert exc.value.ora_code == 20002
        # A call PostgreSQL resolves to no routine, with a string argument in
        # python-oracledb's callfunc shape, is named from the catalog -- after
        # the failed call is undone.
        with pytest.raises(BackendError) as exc:
            backend.execute(
                'BEGIN :retval := fc1632f(:1, :2, :3); END;',
                [
                    BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22),
                    BindVar(value='hi', tns_type=TNS_TYPE_VARCHAR, max_size=22),
                    BindVar(value=7, tns_type=TNS_TYPE_NUMBER, max_size=22),
                    BindVar(value=9, tns_type=TNS_TYPE_NUMBER, max_size=22),
                ],
            )
        assert exc.value.ora_code == 6550
        rows = backend.execute('SELECT n FROM fc1632t ORDER BY n').rows
        assert [int(row[0]) for row in rows] == [3]
    finally:
        backend.rollback()
        for statement in (
            'DROP FUNCTION fc1632f',
            'DROP PROCEDURE fc1632p',
            'DROP TABLE fc1632t',
        ):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_a_calls_savepoint_rides_with_the_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The savepoint a PL/SQL call takes (#1632) goes in the call's own round
    # trip, and its release in the next statement's, not each in one of its
    # own (#1875).
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.backend import BindVar, Result

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    sent: list[tuple[str, bool]] = []
    execute = psycopg.Cursor.execute
    off = psycopg.pq.PipelineStatus.OFF

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        pipelined = cursor.connection.pgconn.pipeline_status != off
        sent.append((str(query), pipelined))
        return execute(cursor, query, *args, **kwargs)

    def call(n: int) -> Result:
        return backend.execute(
            'BEGIN :1 := :2 + 1; END;',
            [
                BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22),
                BindVar(value=n, tns_type=TNS_TYPE_NUMBER, max_size=22),
            ],
        )

    try:
        # A session's first query looks the catalog up without parameters, a
        # statement no prelude rides with; warm, a query sends none.
        call(0)
        backend.execute('SELECT :1 FROM dual', [0])
        monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
        for n in range(3):
            assert int(call(n).out_binds[0]) == n + 1
        backend.execute('SELECT :1 FROM dual', [1])
        for name in ('SAVEPOINT _mirror_call', 'RELEASE SAVEPOINT _mirror_call'):
            assert [p for q, p in sent if q == name] == [True] * 3, name
    finally:
        monkeypatch.undo()
        backend.rollback()
        backend.close()


def test_a_calls_release_waits_no_longer_than_its_transaction() -> None:
    # The release a call leaves for the next statement (#1875) goes with the
    # transaction: a commit or a rollback drops it, and the next call or
    # statement runs in the new transaction as usual. A client's savepoint
    # taken before the call still undoes the call.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))

    def insert(n: int) -> None:
        backend.execute(
            'BEGIN INSERT INTO pc1875t VALUES (:1); END;',
            [BindVar(value=n, tns_type=TNS_TYPE_NUMBER, max_size=22)],
        )

    def rows() -> list[int]:
        found = backend.execute('SELECT n FROM pc1875t ORDER BY n').rows
        return [int(row[0]) for row in found]

    try:
        backend.execute('CREATE TABLE pc1875t (n NUMBER)')
        insert(1)
        backend.commit()
        insert(2)
        backend.rollback()
        insert(3)
        backend.execute('SAVEPOINT pc1875')
        insert(4)
        backend.execute('ROLLBACK TO SAVEPOINT pc1875')
        backend.execute('COMMIT')
        insert(5)
        assert rows() == [1, 3, 5]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE pc1875t')
        except Exception:
            backend.rollback()
        backend.close()


def test_a_block_returns_cursors_as_implicit_results() -> None:
    # DBMS_SQL.RETURN_RESULT (#1617): each cursor a block hands back comes back
    # as an implicit result, its rows and columns, in the order it was
    # returned, the portal closed once fetched.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        result = backend.execute(
            'DECLARE\n  c1 SYS_REFCURSOR;\n  c2 SYS_REFCURSOR;\nBEGIN\n'
            '  OPEN c1 FOR SELECT level AS n FROM dual CONNECT BY level <= 3;\n'
            '  DBMS_SQL.RETURN_RESULT(c1);\n'
            "  OPEN c2 FOR SELECT 'x' AS s FROM dual;\n"
            '  DBMS_SQL.RETURN_RESULT(c2);\nEND;'
        )
        assert [
            ([c.name for c in columns], [tuple(r) for r in rows])
            for columns, rows in result.implicit_results
        ] == [([b'N'], [(1,), (2,), (3,)]), ([b'S'], [('x',)])]
        (open_portals,) = backend.execute(
            "SELECT count(*) FROM pg_cursors WHERE name LIKE '<unnamed portal%'"
        ).rows[0]
        assert open_portals == 0
        assert backend.execute('BEGIN NULL; END;').implicit_results == []
    finally:
        backend.rollback()
        backend.close()


def test_a_ref_cursor_describes_not_null_columns_as_not_nullable() -> None:
    # A REF CURSOR a routine opens over a table (#1618) describes a column
    # straight from a NOT NULL one as not nullable, as a query's result does,
    # and a computed one as nullable -- python-oracledb's test_1301 reads it.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_REFCURSOR
    from seerdb.server.backend import BindVar, CursorResult

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE rn1618t (a NUMBER(9) NOT NULL, b NUMBER(9))')
        backend.execute('INSERT INTO rn1618t VALUES (1, 2)')
        backend.execute(
            'CREATE OR REPLACE PROCEDURE rn1618(n NUMBER, c OUT SYS_REFCURSOR) IS\n'
            'BEGIN\n  OPEN c FOR SELECT a, b, a + n AS s FROM rn1618t;\nEND;'
        )
        result = backend.execute(
            'BEGIN rn1618(:1, :2); END;',
            [
                BindVar(value=1, tns_type=TNS_TYPE_NUMBER, max_size=22),
                BindVar(value=None, tns_type=TNS_TYPE_REFCURSOR, max_size=1),
            ],
        )
        cursor = result.out_binds[1]
        assert isinstance(cursor, CursorResult)
        assert [c.null_ok for c in cursor.columns] == [0, 1, 1]
    finally:
        backend.rollback()
        for statement in ('DROP PROCEDURE rn1618', 'DROP TABLE rn1618t'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_date_minus_date_is_a_number_of_days() -> None:
    # Oracle's DATE arithmetic (#1611): DATE - DATE a number of days, DATE + n
    # still a DATE, for a table's column, TO_DATE, SYSDATE and a routine's
    # parameters alike; TIMESTAMP - TIMESTAMP stays an interval. 23ai's answers.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE dm1611t (d0 DATE, d1 DATE)')
        backend.execute(
            "INSERT INTO dm1611t VALUES (TO_DATE('2020-01-01', 'YYYY-MM-DD'), "
            "TO_DATE('2020-01-02 12:00', 'YYYY-MM-DD HH24:MI'))"
        )
        backend.execute(
            'CREATE OR REPLACE FUNCTION dm1611f(n NUMBER, a DATE, b DATE) '
            'RETURN NUMBER IS\n  v NUMBER := n;\nBEGIN\n  v := v + a - b;\n'
            '  RETURN v;\nEND;'
        )
        for expr, expected in (
            ("DATE '2020-01-02' - DATE '2020-01-01'", 1),
            (
                "TO_DATE('2020-01-02 12:00', 'YYYY-MM-DD HH24:MI') "
                "- TO_DATE('2020-01-01', 'YYYY-MM-DD')",
                Decimal('1.5'),
            ),
            ('d1 - d0', Decimal('1.5')),
            ('(d0 + 1) - d0', 1),
            ('(1 + d0) - d0', 1),
            ('(d1 - 1.5) - d0', 0),
            ("TO_CHAR(d0 + 1.5, 'YYYY-MM-DD HH24:MI')", '2020-01-02 12:00'),
            ('SYSDATE - SYSDATE', 0),
            ('dm1611f(10, d1, d0)', Decimal('11.5')),
            (
                "TIMESTAMP '2020-01-02 12:00:00' - TIMESTAMP '2020-01-01 00:00:00'",
                datetime.timedelta(days=1, hours=12),
            ),
        ):
            (row,) = backend.execute(f'SELECT {expr} FROM dm1611t').rows
            assert row[0] == expected, expr
    finally:
        backend.rollback()
        for statement in ('DROP FUNCTION dm1611f', 'DROP TABLE dm1611t'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_a_timestamp_plus_a_number_is_a_date() -> None:
    # TIMESTAMP + n failed, `operator is not unique` (#2164). On 23ai it is a
    # DATE: the TIMESTAMP becomes a DATE first, its fraction dropped, and the
    # sum is rounded to the second.
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_DATE

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2164 (ts TIMESTAMP, ts3 TIMESTAMP(3))')
        try:
            backend.execute(
                "INSERT INTO t2164 VALUES (TIMESTAMP '2020-01-31 10:00:00.9', "
                "TIMESTAMP '2020-01-31 10:00:00.5')"
            )
            for expression, binds, value in (
                ('ts + 1', [], datetime.datetime(2020, 2, 1, 10)),
                ('1 + ts', [], datetime.datetime(2020, 2, 1, 10)),
                ('ts - 1', [], datetime.datetime(2020, 1, 30, 10)),
                ('ts3 + 1.5', [], datetime.datetime(2020, 2, 1, 22)),
                ('ts + 0.5 / 86400', [], datetime.datetime(2020, 1, 31, 10, 0, 1)),
                ('ts + :1', [2], datetime.datetime(2020, 2, 2, 10)),
            ):
                result = backend.execute(f'SELECT {expression} FROM t2164', binds)
                assert result.columns[0].data_type == TNS_TYPE_DATE, expression
                assert result.rows == [(value,)], expression
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2164')
    finally:
        backend.close()


def test_trunc_and_round_of_a_datetime_are_dates() -> None:
    # TRUNC / ROUND of a DATE, a TIMESTAMP or a TIMESTAMP WITH TIME ZONE
    # return a DATE (#2076), so the difference of two is a number of days and
    # the column describes as a DATE. orafce's returned a timestamp, and the
    # difference was an interval. 23ai's answers.
    from seerdb.common.tns_consts import TNS_TYPE_DATE

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        d = "TO_DATE('2024-05-06 13:14:15', 'YYYY-MM-DD HH24:MI:SS')"
        for expr, expected in (
            ('TRUNC(SYSDATE) - TRUNC(SYSDATE)', 0),
            (f"TRUNC({d}, 'MM') - TRUNC({d}, 'YYYY')", 121),
            (f'{d} - TRUNC({d})', Decimal('0.551562500000000000')),
            (f'ROUND({d}) - TRUNC({d})', 1),
            (f"ROUND(CAST({d} AS TIMESTAMP), 'DD') - TRUNC({d})", 1),
            ('TRUNC(SYSTIMESTAMP) - TRUNC(SYSDATE)', 0),
        ):
            (row,) = backend.execute(f'SELECT {expr} FROM dual').rows
            assert row[0] == expected, expr
        result = backend.execute(
            f"SELECT TRUNC({d}) a, ROUND({d}, 'HH') b, TRUNC(LOCALTIMESTAMP) c, "
            "TRUNC(SYSTIMESTAMP, 'MM') e, TRUNC(1.57, 1) f FROM dual"
        )
        assert [c.data_type for c in result.columns[:4]] == [TNS_TYPE_DATE] * 4
        assert result.rows[0][:2] == (
            datetime.datetime(2024, 5, 6),
            datetime.datetime(2024, 5, 6, 13),
        )
        assert result.rows[0][4] == Decimal('1.5')
    finally:
        backend.close()


def test_add_months_last_day_and_next_day_of_a_date_are_dates() -> None:
    # ADD_MONTHS, LAST_DAY and NEXT_DAY of a DATE return a DATE, its time of
    # day kept, so a difference with one is a number of days (#2095). orafce's
    # returned a timestamp, and the difference was an interval. 23ai's answers.
    from seerdb.common.tns_consts import TNS_TYPE_DATE

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        d = "TO_DATE('2024-01-31 13:14:15', 'YYYY-MM-DD HH24:MI:SS')"
        for expr, expected in (
            (f'ADD_MONTHS({d}, 1) - {d}', 29),
            (f'LAST_DAY({d}) - {d}', 0),
            (f"NEXT_DAY({d}, 'MONDAY') - {d}", 5),
        ):
            (row,) = backend.execute(f'SELECT {expr} FROM dual').rows
            assert row[0] == expected, expr
        result = backend.execute(
            f'SELECT ADD_MONTHS({d}, 1) a, ADD_MONTHS({d}, 1.9) b, '
            f'ADD_MONTHS({d}, -1) c, LAST_DAY({d} + 1) e, '
            f"NEXT_DAY({d}, 'MONDAY') f, "
            "ADD_MONTHS(TIMESTAMP '2024-02-29 10:00:00.7', 12) g FROM dual"
        )
        assert [c.data_type for c in result.columns] == [TNS_TYPE_DATE] * 6
        assert result.rows[0] == (
            datetime.datetime(2024, 2, 29, 13, 14, 15),
            datetime.datetime(2024, 2, 29, 13, 14, 15),
            datetime.datetime(2023, 12, 31, 13, 14, 15),
            datetime.datetime(2024, 2, 29, 13, 14, 15),
            datetime.datetime(2024, 2, 5, 13, 14, 15),
            datetime.datetime(2025, 2, 28, 10, 0, 0),
        )
    finally:
        backend.close()


def test_sql_monitor_reports_the_sessions_database_operation() -> None:
    # V$SQL_MONITOR (#1619): with a database operation named (connection.dbop,
    # in the tracing piggyback) the session's statement is EXECUTING under it,
    # as python-oracledb's test_1103 reads it; with none there is no row.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    query = (
        "SELECT dbop_name FROM v$sql_monitor WHERE sid = sys_context('userenv', 'sid') "
        "AND status = 'EXECUTING'"
    )
    try:
        assert backend.execute(query).rows == []
        backend.set_end_to_end({'dbop': 'oracledb_dbop'})
        assert backend.execute(query).rows == [('oracledb_dbop',)]
        backend.set_end_to_end({'dbop': None})
        assert backend.execute(query).rows == []
    finally:
        backend.rollback()
        backend.close()


def test_a_proxy_login_is_a_session_of_the_user_it_acts_for() -> None:
    # A proxy login, `pyo[target]` (#1620): the session is the target's, in its
    # schema, and PROXY_USER names the user who logged in -- as Oracle reports
    # it to python-oracledb's test_2427. A plain login has no PROXY_USER. The
    # target granted CONNECT THROUGH the login first, as Oracle needs (#1860).
    query = (
        "SELECT sys_context('userenv', 'session_user'), "
        "sys_context('userenv', 'proxy_user'), "
        "sys_context('userenv', 'current_schema') FROM dual"
    )
    plain = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    proxied = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        plain.authenticate('pyo')
        plain.open_session({})
        (row,) = plain.execute(query).rows
        assert tuple(row[:2]) == ('PYO', None)
        proxied.authenticate('pyo')
        proxied.execute('CREATE SCHEMA IF NOT EXISTS px1620')
        proxied.execute('ALTER USER px1620 GRANT CONNECT THROUGH pyo')
        proxied.open_session({'proxy_client_name': 'px1620'})
        assert proxied.execute(query).rows == [('PX1620', 'PYO', 'PX1620')]
    finally:
        proxied.rollback()
        try:
            proxied.execute("DELETE FROM sys.ora_proxy_grants WHERE client = 'PX1620'")
            proxied.execute('DROP SCHEMA px1620')
            proxied.commit()
        except Exception:
            proxied.rollback()
        plain.close()
        proxied.close()


def test_a_proxy_login_needs_a_grant_of_connect_through() -> None:
    # A proxy login is admitted only where the target granted CONNECT THROUGH
    # the user logging in (#1860), as 23ai admits it: otherwise ORA-01017. The
    # grants are PROXY_USERS's rows; ALTER USER names a user that exists, on
    # either side (ORA-01918), REVOKE one that was granted (ORA-38470), and
    # DROP USER takes a user's grants with it. Measured on 23ai.
    from seerdb.server import BackendError

    admin = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    proxied = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    rows = "SELECT * FROM proxy_users WHERE client = 'PX1860'"
    try:
        admin.authenticate('pyo')
        admin.open_session({})
        admin.execute('CREATE USER px1860 IDENTIFIED BY px1860pw')
        proxied.authenticate('pyo')
        with pytest.raises(BackendError) as refused:
            proxied.open_session({'proxy_client_name': 'px1860'})
        assert refused.value.ora_code == 1017
        for statement, code in (
            ('ALTER USER no_such_1860 GRANT CONNECT THROUGH pyo', 1918),
            ('ALTER USER px1860 GRANT CONNECT THROUGH no_such_1860', 1918),
            ('ALTER USER px1860 REVOKE CONNECT THROUGH pyo', 38470),
        ):
            with pytest.raises(BackendError) as raised:
                admin.execute(statement)
            assert raised.value.ora_code == code, statement
        admin.execute('ALTER USER px1860 GRANT CONNECT THROUGH pyo')
        assert admin.execute(rows).rows == [
            ('PYO', 'PX1860', 'NO', 'PROXY MAY ACTIVATE ALL CLIENT ROLES')
        ]
        proxied.open_session({'proxy_client_name': 'px1860'})
        admin.execute('ALTER USER px1860 REVOKE CONNECT THROUGH pyo')
        assert admin.execute(rows).rows == []
        admin.execute('ALTER USER px1860 GRANT CONNECT THROUGH pyo')
        admin.execute('DROP USER px1860')
        assert admin.execute(rows).rows == []
    finally:
        for backend in (proxied, admin):
            backend.rollback()
        try:
            admin.execute('DROP USER px1860 CASCADE')
        except Exception:
            admin.rollback()
        admin.close()
        proxied.close()


def test_a_null_object_bind_resolves_an_overloaded_routine() -> None:
    # A NULL object bound to a routine overloaded on object types (#1622): the
    # NULL goes as the type its bind names, so the overload for that type is
    # the one called -- python-oracledb's test_2300 gets 'null' back.
    from seerdb.common.tns_consts import TNS_TYPE_ADT, TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar
    from seerdb.server.backends.postgres import _object_type_oid

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TYPE no1622a AS OBJECT (n NUMBER)')
        backend.execute('CREATE TYPE no1622b AS OBJECT (s VARCHAR2(10))')
        backend.execute(
            'CREATE OR REPLACE PACKAGE no1622 AS\n'
            '  FUNCTION f(x no1622a) RETURN VARCHAR2;\n'
            '  FUNCTION f(x no1622b) RETURN VARCHAR2;\nEND;'
        )
        backend.execute(
            'CREATE OR REPLACE PACKAGE BODY no1622 AS\n'
            "  FUNCTION f(x no1622a) RETURN VARCHAR2 IS BEGIN RETURN 'a'; END;\n"
            "  FUNCTION f(x no1622b) RETURN VARCHAR2 IS BEGIN RETURN 'b'; END;\nEND;"
        )
        for name, expected in (('no1622a', 'a'), ('no1622b', 'b')):
            (pg_oid,) = backend.execute(
                f"SELECT '{name}'::regtype::oid::bigint FROM dual"
            ).rows[0]
            result = backend.execute(
                'BEGIN :retval := no1622.f(:1); END;',
                [
                    BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=10),
                    BindVar(
                        value=None,
                        tns_type=TNS_TYPE_ADT,
                        max_size=0,
                        toid=_object_type_oid(int(pg_oid)),
                    ),
                ],
            )
            assert result.out_binds[0] == expected
    finally:
        backend.rollback()
        for statement in (
            'DROP PACKAGE no1622',
            'DROP TYPE no1622b',
            'DROP TYPE no1622a',
        ):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_a_function_returns_a_table_of_varrays() -> None:
    # A nested table of VARRAYs a function returns (#1623) comes back as that
    # collection of collections, as python-oracledb's test_2345 reads it --
    # not empty, as its array text left it.
    from seerdb.common.tns_consts import TNS_TYPE_ADT
    from seerdb.server.backend import BindVar
    from seerdb.server.backends.postgres import _object_type_oid

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TYPE va1623 AS VARRAY(10) OF NUMBER')
        backend.execute('CREATE TYPE tv1623 AS TABLE OF va1623')
        backend.execute(
            'CREATE OR REPLACE FUNCTION f1623 RETURN tv1623 IS\nBEGIN\n'
            '  RETURN tv1623(va1623(10, 20), va1623(30, 40));\nEND;'
        )
        (pg_oid,) = backend.execute(
            "SELECT 'tv1623'::regtype::oid::bigint FROM dual"
        ).rows[0]
        result = backend.execute(
            'BEGIN :retval := f1623(); END;',
            [
                BindVar(
                    value=None,
                    tns_type=TNS_TYPE_ADT,
                    max_size=0,
                    toid=_object_type_oid(int(pg_oid)),
                )
            ],
        )
        returned = result.out_binds[0]
        assert [inner.aslist() for inner in returned.aslist()] == [[10, 20], [30, 40]]
    finally:
        backend.rollback()
        for statement in (
            'DROP FUNCTION f1623',
            'DROP TYPE tv1623',
            'DROP TYPE va1623',
        ):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_an_is_json_column_is_described_as_json() -> None:
    # A column with an IS JSON check constraint (#1626) is described as JSON,
    # as 18c, 21c and 23ai describe it, so a client hands back the parsed value
    # (python-oracledb's test_1941); an IS NOT JSON one, a plain one and a
    # computed one are not.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TABLE jd1626t (j CLOB, n CLOB, p CLOB, '
            'CONSTRAINT jd1626_j CHECK (j IS JSON), '
            'CONSTRAINT jd1626_n CHECK (n IS NOT JSON))'
        )
        backend.execute("INSERT INTO jd1626t VALUES ('[4, 5, 6]', 'x', 'y')")
        result = backend.execute("SELECT j, n, p, j || '' AS c FROM jd1626t")
        assert [column.is_json for column in result.columns] == [
            True,
            False,
            False,
            False,
        ]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE jd1626t')
        except Exception:
            backend.rollback()


def test_a_blob_bind_describes_as_a_blob() -> None:
    # A BLOB bind selected back (#1625) describes as a BLOB, as Oracle's does
    # -- python-oracledb's test_3655 asks a handler for LONG RAW of it, which
    # it refuses from a RAW -- and inserts as the same bytes.
    from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_RAW
    from seerdb.server.backend import BlobValue

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        result = backend.execute(
            'SELECT :1, :2 FROM dual', [BlobValue(b'blob data'), b'raw data']
        )
        assert [c.data_type for c in result.columns] == [TNS_TYPE_BLOB, TNS_TYPE_RAW]
        backend.execute('CREATE TABLE bb1625t (b BLOB)')
        backend.execute('INSERT INTO bb1625t VALUES (:1)', [BlobValue(b'stored')])
        (row,) = backend.execute(
            'SELECT dbms_lob.getlength(b) FROM bb1625t WHERE b = :1',
            [BlobValue(b'stored')],
        ).rows
        assert row[0] == 6
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE bb1625t')
        except Exception:
            backend.rollback()


def test_a_clob_bind_describes_as_a_clob() -> None:
    # A CLOB bind (#2035) -- a sqlplus CLOB variable, a client's temp LOB --
    # describes as a CLOB, as Oracle's does, and is still the same text to a
    # function. As bare text it described as a VARCHAR2, which crashed sqlplus
    # printing an empty one; a NULL CLOB, the same.
    from seerdb.common.tns_consts import TNS_TYPE_CLOB, TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar, ClobValue

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        result = backend.execute(
            'SELECT :1, :2, :3, :4 FROM dual',
            [
                ClobValue('clob data'),
                ClobValue(''),
                BindVar(value=None, tns_type=TNS_TYPE_CLOB, max_size=0),
                'text',
            ],
        )
        assert [c.data_type for c in result.columns] == [
            TNS_TYPE_CLOB,
            TNS_TYPE_CLOB,
            TNS_TYPE_CLOB,
            TNS_TYPE_VARCHAR,
        ]
        assert result.rows[0][2] is None
        (row,) = backend.execute(
            'SELECT dbms_lob.getlength(:1) FROM dual', [ClobValue('clob data')]
        ).rows
        assert row == (9,)
    finally:
        backend.rollback()


def test_rr_years_print_and_parse_as_in_oracle() -> None:
    # Oracle's RR and RRRR years (#1638): printed as YY / YYYY, read into the
    # RR window -- 00-49 this century, 50-99 the last, while the current year
    # ends in 00-49 (true until 2050) -- and four digits as they are. 23ai's.
    assert _translate_idioms("SELECT TO_CHAR(d, 'DD-MON-RR') FROM t") == (
        "SELECT TO_CHAR(d, 'DD-MON-YY') FROM t"
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        for expr, expected in (
            ("TO_CHAR(DATE '2000-12-15', 'DD-MON-RR')", '15-DEC-00'),
            ("TO_CHAR(DATE '2000-12-15', 'DD-MON-RRRR')", '15-DEC-2000'),
            ("TO_CHAR(TO_DATE('15-DEC-60', 'DD-MON-RR'), 'YYYY')", '1960'),
            ("TO_CHAR(TO_DATE('15-DEC-49', 'DD-MON-RR'), 'YYYY')", '2049'),
            ("TO_CHAR(TO_DATE('15-DEC-00', 'DD-MON-RR'), 'YYYY-MM-DD')", '2000-12-15'),
            ("TO_CHAR(TO_DATE('15-DEC-1960', 'DD-MON-RR'), 'YYYY')", '1960'),
            ("TO_CHAR(TO_DATE('15-DEC-60', 'DD-MON-RRRR'), 'YYYY')", '1960'),
            ("TO_CHAR(TO_DATE('15-DEC-60', 'DD-MON-YY'), 'YYYY')", '2060'),
            (
                "TO_CHAR(TO_TIMESTAMP('15-DEC-75 10:00', 'DD-MON-RR HH24:MI'), "
                "'YYYY HH24')",
                '1975 10',
            ),
        ):
            (row,) = backend.execute(f'SELECT {expr} FROM dual').rows
            assert row[0] == expected, expr
    finally:
        backend.rollback()
        backend.close()


def test_no_data_found_in_a_function_sql_calls_is_null() -> None:
    # NO_DATA_FOUND out of a function a SQL statement calls (#1612) is the
    # function's NULL -- through a function that only calls it, too -- where a
    # PL/SQL expression's call raises ORA-01403. 23ai's answers. A function
    # that cannot raise one gets no handler, which costs a subtransaction.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server import BackendError
    from seerdb.server.backend import BindVar

    plain = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION nd1612x(n NUMBER) RETURN NUMBER IS '
        'BEGIN RETURN n + 1; END;',
        frozenset(),
    )
    assert 'no_data_found' not in plain
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE OR REPLACE PACKAGE nd1612 AS\n  FUNCTION f RETURN NUMBER;\n'
            '  FUNCTION g RETURN NUMBER;\nEND;'
        )
        backend.execute(
            'CREATE OR REPLACE PACKAGE BODY nd1612 AS\n'
            '  TYPE t IS TABLE OF NUMBER INDEX BY BINARY_INTEGER;\n'
            '  FUNCTION f RETURN NUMBER IS a t;\n'
            '  BEGIN a(1) := 1; RETURN a(2); END;\n'
            '  FUNCTION g RETURN NUMBER IS\n  BEGIN RETURN f() + 1; END;\nEND;'
        )
        for call in ('nd1612.f()', 'nd1612.g()'):
            assert backend.execute(f'SELECT {call} FROM dual').rows == [(None,)]
            assert backend.execute(f'SELECT nvl({call}, -1) FROM dual').rows == [(-1,)]
            number = BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22)
            result = backend.execute(
                f'DECLARE x NUMBER; BEGIN SELECT {call} INTO x FROM dual; '
                ':o := nvl(x, -1); END;',
                [number],
            )
            assert result.out_binds == [-1]
            for block in (
                f'DECLARE x NUMBER; BEGIN x := {call}; :o := x; END;',
                f'BEGIN :o := {call}; END;',
            ):
                with pytest.raises(BackendError) as exc:
                    backend.execute(block, [number])
                assert exc.value.ora_code == 1403
    finally:
        backend.rollback()
        try:
            backend.execute('DROP PACKAGE nd1612')
        except Exception:
            backend.rollback()


def test_a_plsql_select_into_needs_exactly_one_row() -> None:
    # A PL/SQL SELECT ... INTO (#1650) with no row is ORA-01403 and with two
    # ORA-01422, in a block and in a routine, as 23ai answers; one row goes
    # through. A function a query calls makes the ORA-01403 its NULL (#1612).
    # Only a SELECT that starts a PL/SQL statement is STRICT: not a subquery's,
    # a FETCH's, a RETURNING's, quoted text, or a statement with no body.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server import BackendError
    from seerdb.server.backend import BindVar
    from seerdb.server.backends.postgres import _strict_select_into

    assert _strict_select_into(
        'DO $$ BEGIN SELECT (SELECT max(n) FROM t) INTO x FROM dual; '
        'FETCH c INTO y; UPDATE t SET n = 1 RETURNING n INTO z; '
        "w := 'select 1 into v'; END $$"
    ) == (
        'DO $$ BEGIN SELECT (SELECT max(n) FROM t) INTO STRICT x FROM dual; '
        'FETCH c INTO y; UPDATE t SET n = 1 RETURNING n INTO z; '
        "w := 'select 1 into v'; END $$"
    )
    assert _strict_select_into('SELECT a INTO b FROM t') == 'SELECT a INTO b FROM t'
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    out = BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22)
    two_rows = '(SELECT 1 AS n FROM dual UNION ALL SELECT 2 FROM dual)'
    try:
        for source, code in (('dual WHERE 1 = 0', 1403), (two_rows, 1422)):
            with pytest.raises(BackendError) as exc:
                backend.execute(
                    f'DECLARE x NUMBER; BEGIN SELECT 1 INTO x FROM {source}; '
                    ':o := x; END;',
                    [out],
                )
            assert exc.value.ora_code == code
        result = backend.execute(
            'DECLARE x NUMBER; BEGIN SELECT 7 INTO x FROM dual; :o := x; END;', [out]
        )
        assert result.out_binds == [7]
        backend.execute(
            'CREATE OR REPLACE FUNCTION si1650 RETURN NUMBER IS x NUMBER;\n'
            'BEGIN SELECT 1 INTO x FROM dual WHERE 1 = 0; RETURN x; END;'
        )
        with pytest.raises(BackendError) as exc:
            backend.execute('BEGIN :o := si1650(); END;', [out])
        assert exc.value.ora_code == 1403
        assert backend.execute('SELECT si1650() FROM dual').rows == [(None,)]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP FUNCTION si1650')
        except Exception:
            backend.rollback()


def test_a_package_function_is_called_without_parentheses() -> None:
    # A package's function with no arguments, named without parentheses
    # (#1651), is called, in a query and in PL/SQL -- not read as column f of
    # a table pkg. A table aliased as the package keeps its column, as Oracle
    # looks for one first. 23ai's answers.
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE OR REPLACE PACKAGE bp1651 AS FUNCTION f RETURN NUMBER; '
            'FUNCTION g(n NUMBER) RETURN NUMBER; END;'
        )
        backend.execute(
            'CREATE OR REPLACE PACKAGE BODY bp1651 AS '
            'FUNCTION f RETURN NUMBER IS BEGIN RETURN 7; END; '
            'FUNCTION g(n NUMBER) RETURN NUMBER IS BEGIN RETURN n * 2; END; END;'
        )
        backend.execute('CREATE TABLE bt1651 (f NUMBER)')
        backend.execute('INSERT INTO bt1651 VALUES (5)')
        for query, expected in (
            ('SELECT bp1651.f FROM dual', 7),
            ('SELECT bp1651.f + 1 FROM dual', 8),
            ('SELECT f FROM bt1651 WHERE f = bp1651.f - 2', 5),
            ('SELECT bp1651.f FROM bt1651 bp1651', 5),
            ('SELECT bp1651.g(2) FROM dual', 4),
            ("SELECT 'bp1651.f' FROM dual", 'bp1651.f'),
        ):
            (row,) = backend.execute(query).rows
            assert row[0] == expected, query
        number = BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22)
        for block in (
            'BEGIN :o := bp1651.f; END;',
            'DECLARE x NUMBER; BEGIN x := bp1651.f; :o := x; END;',
        ):
            assert backend.execute(block, [number]).out_binds == [7], block
    finally:
        backend.rollback()
        for statement in ('DROP TABLE bt1651', 'DROP PACKAGE bp1651'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_a_type_is_visible_to_its_owner_and_its_grantees() -> None:
    # A user sees another user's type only once granted EXECUTE on it (#1621):
    # in ALL_TYPES, the OCI describe and gettype()'s GET_TYPE_SHAPE, which
    # answers 1001 (not found) for one it may not use -- python-oracledb's
    # test_2341 then raises DPY-2035. REVOKE takes it away again.
    from seerdb.common.tns_consts import (
        TNS_TYPE_NUMBER,
        TNS_TYPE_RAW,
        TNS_TYPE_REFCURSOR,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server.backend import BindVar

    admin = psycopg.connect(_CONNINFO, autocommit=True)
    for schema in ('own1621', 'oth1621'):
        admin.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        admin.execute(f'CREATE SCHEMA {schema}')
    owner = PostgresBackend(_CONNINFO, credentials={'OWN1621': 'x'})
    other = PostgresBackend(_CONNINFO, credentials={'OTH1621': 'x'})

    def shape(backend: PostgresBackend) -> int:
        binds = [
            BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=4),
            BindVar(value='OWN1621.T1621', tns_type=TNS_TYPE_VARCHAR, max_size=128),
            BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=16),
            BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=4),
            BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=32767),
            BindVar(value=None, tns_type=TNS_TYPE_REFCURSOR, max_size=1),
            BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=128),
        ]
        return backend.execute(_TYPE_SHAPE_SQL, binds).out_binds[0]

    def sees(backend: PostgresBackend) -> tuple:
        listed = backend.execute(
            "SELECT count(*) FROM all_types WHERE owner = 'OWN1621' "
            "AND type_name = 'T1621'"
        ).rows[0][0]
        backend.rollback()
        return (
            listed,
            backend.describe_type('OWN1621.T1621') is not None,
            shape(backend),
        )

    try:
        owner.authenticate('OWN1621')
        other.authenticate('OTH1621')
        owner.execute('CREATE TYPE t1621 AS OBJECT (n NUMBER)')
        assert sees(owner) == (1, True, 0)
        assert sees(other) == (0, False, 1001)
        owner.execute('GRANT EXECUTE ON t1621 TO oth1621')
        assert sees(other) == (1, True, 0)
        owner.execute('REVOKE EXECUTE ON own1621.t1621 FROM oth1621')
        assert sees(other) == (0, False, 1001)
        owner.execute('GRANT EXECUTE ON own1621.t1621 TO PUBLIC')
        assert sees(other) == (1, True, 0)
    finally:
        owner.rollback()
        other.rollback()
        owner.close()
        other.close()
        admin.execute("DELETE FROM sys.ora_grants WHERE owner = 'OWN1621'")
        for schema in ('own1621', 'oth1621'):
            admin.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        admin.close()


@pytest.mark.parametrize(('presents', 'all_count'), [('12.1', 12), ('23ai', 13)])
def test_a_grant_is_recorded_as_oracle_keys_it(presents: str, all_count: int) -> None:
    # A grant's record (#1858): its grantor, whether it may be granted on,
    # the kind of object, and ALL as the privileges the presented release
    # lists for it -- 23ai adds ASSERTION REFERENCES. A grantee holding one
    # WITH GRANT OPTION grants it on; revoking it from that grantee takes
    # what it granted, as Oracle's cascade does.
    from seerdb.server.backend import BackendError

    admin = psycopg.connect(_CONNINFO, autocommit=True)
    for schema in ('own1858', 'oth1858'):
        admin.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        admin.execute(f'CREATE SCHEMA {schema}')
    owner = PostgresBackend(_CONNINFO, credentials={'OWN1858': 'x'}, presents=presents)
    other = PostgresBackend(_CONNINFO, credentials={'OTH1858': 'x'}, presents=presents)

    def recorded() -> list[tuple]:
        return admin.execute(
            'SELECT grantee, grantor, grantable, object_type, count(*) '
            "FROM sys.ora_grants WHERE owner = 'OWN1858' "
            'GROUP BY 1, 2, 3, 4 ORDER BY 1'
        ).fetchall()

    try:
        owner.authenticate('OWN1858')
        other.authenticate('OTH1858')
        owner.execute('CREATE TABLE t1858 (n NUMBER)')
        owner.execute('GRANT ALL ON t1858 TO oth1858 WITH GRANT OPTION')
        assert recorded() == [('OTH1858', 'OWN1858', 'YES', 'TABLE', all_count)]
        other.execute('GRANT SELECT ON own1858.t1858 TO PUBLIC')
        assert recorded() == [
            ('OTH1858', 'OWN1858', 'YES', 'TABLE', all_count),
            ('PUBLIC', 'OTH1858', 'NO', 'TABLE', 1),
        ]
        with pytest.raises(BackendError) as raised:
            owner.execute('REVOKE SELECT ON t1858 FROM PUBLIC')
        assert raised.value.ora_code == 1927
        owner.execute('REVOKE ALL ON t1858 FROM oth1858')
        assert recorded() == []
    finally:
        owner.close()
        other.close()
        admin.execute("DELETE FROM sys.ora_grants WHERE owner = 'OWN1858'")
        for schema in ('own1858', 'oth1858'):
            admin.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        admin.close()


def test_the_tab_privs_views_list_each_users_grants() -> None:
    # The six *_TAB_PRIVS views (#1858), as 23ai lists them: owner A grants
    # B SELECT WITH GRANT OPTION, B grants C, A grants PUBLIC INSERT; each of
    # A, B and C sees the rows the measurement on 23ai showed it.
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    users = ('tpa1858', 'tpb1858', 'tpc1858')
    for schema in users:
        admin.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        admin.execute(f'CREATE SCHEMA {schema}')
    (a, b, c) = (
        PostgresBackend(_CONNINFO, credentials={u.upper(): 'x'}) for u in users
    )
    (A, B, C) = (u.upper() for u in users)
    to_b = (A, B, 'SELECT', 'YES')
    to_c = (B, C, 'SELECT', 'NO')
    to_public = (A, 'PUBLIC', 'INSERT', 'NO')
    views = {
        'all_tab_privs': 'grantor, grantee',
        'all_tab_privs_made': 'grantor, grantee',
        'all_tab_privs_recd': 'grantor, grantee',
        'user_tab_privs': 'grantor, grantee',
        'user_tab_privs_made': 'grantor, grantee',
        'user_tab_privs_recd': "grantor, ''",
    }
    seen = {
        A: [
            [to_public, to_b, to_c],
            [to_public, to_b, to_c],
            [to_public],
            [to_public, to_b, to_c],
            [to_public, to_b, to_c],
            [],
        ],
        B: [
            [to_public, to_b, to_c],
            [to_c],
            [to_public, to_b],
            [to_b, to_c],
            [],
            [(A, '', 'SELECT', 'YES')],
        ],
        C: [
            [to_public, to_c],
            [],
            [to_public, to_c],
            [to_c],
            [],
            [(B, '', 'SELECT', 'NO')],
        ],
    }
    try:
        for backend, user in ((a, A), (b, B), (c, C)):
            backend.authenticate(user)
        a.execute('CREATE TABLE tp1858 (n NUMBER)')
        a.execute(f'GRANT SELECT ON tp1858 TO {B} WITH GRANT OPTION')
        b.execute(f'GRANT SELECT ON {A}.tp1858 TO {C}')
        a.execute('GRANT INSERT ON tp1858 TO PUBLIC')
        for backend, user in ((a, A), (b, B), (c, C)):
            for (view, columns), expected in zip(views.items(), seen[user]):
                listed = backend.execute(
                    f'SELECT {columns}, privilege, grantable FROM {view} '
                    "WHERE table_name = 'TP1858' ORDER BY 1, 2"
                ).rows
                backend.rollback()
                assert [tuple(r) for r in listed] == expected, (user, view)
        kind = a.execute(
            'SELECT DISTINCT type, hierarchy, common, inherited FROM user_tab_privs '
            "WHERE table_name = 'TP1858'"
        ).rows
        assert [tuple(r) for r in kind] == [('TABLE', 'NO', 'NO', 'NO')]
    finally:
        for backend in (a, b, c):
            backend.rollback()
            backend.close()
        admin.execute("DELETE FROM sys.ora_grants WHERE owner = 'TPA1858'")
        for schema in users:
            admin.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        admin.close()


def test_a_routine_runs_with_its_owners_rights_unless_authid_current_user() -> None:
    # Definer and invoker rights (#1945), as 23ai has them: another user's
    # call of a routine without AUTHID, or AUTHID DEFINER, reads the owner's
    # table, and CURRENT_SCHEMA is the owner's; AUTHID CURRENT_USER reads the
    # caller's. USER is the caller either way. ALL_PROCEDURES lists which.
    from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar

    admin = psycopg.connect(_CONNINFO, autocommit=True)
    for schema in ('own1945', 'oth1945'):
        admin.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        admin.execute(f'CREATE SCHEMA {schema}')
    owner = PostgresBackend(_CONNINFO, credentials={'OWN1945': 'x'})
    other = PostgresBackend(_CONNINFO, credentials={'OTH1945': 'x'})
    body = (
        '(r OUT VARCHAR2) {authid} AS n NUMBER; BEGIN '
        'SELECT count(*) INTO n FROM t1945; '
        "r := USER || ',' || sys_context('userenv', 'current_schema') || ',' || n; "
        'END;'
    )

    def call(name: str) -> str:
        out = BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=200)
        result = other.execute(f'BEGIN own1945.{name}(:r); END;', [out])
        return result.out_binds[0]

    try:
        owner.authenticate('OWN1945')
        other.authenticate('OTH1945')
        owner.execute('CREATE TABLE t1945 (n NUMBER)')
        owner.execute('INSERT INTO t1945 VALUES (1)')
        owner.commit()
        other.execute('CREATE TABLE t1945 (n NUMBER)')
        other.execute('INSERT INTO t1945 VALUES (7)')
        other.execute('INSERT INTO t1945 VALUES (8)')
        other.commit()
        for name, authid in (
            ('p_none', ''),
            ('p_definer', 'AUTHID DEFINER'),
            ('p_invoker', 'AUTHID CURRENT_USER'),
        ):
            owner.execute(f'CREATE PROCEDURE {name} ' + body.format(authid=authid))
        assert call('p_none') == 'OTH1945,OWN1945,1'
        assert call('p_definer') == 'OTH1945,OWN1945,1'
        assert call('p_invoker') == 'OTH1945,OTH1945,2'
        # A COMMIT in a definer's routine, which PostgreSQL refuses in a
        # SECURITY DEFINER one, is the Mirror's deferred COMMIT as before.
        owner.execute(
            'CREATE PROCEDURE p_commit AS BEGIN INSERT INTO t1945 VALUES (5); '
            'COMMIT; END;'
        )
        other.execute('BEGIN own1945.p_commit; END;')
        other.rollback()
        counted = owner.execute('SELECT count(*) FROM t1945').rows
        owner.rollback()
        assert [tuple(r) for r in counted] == [(2,)]
        owner.execute('CREATE PACKAGE k1945 AUTHID CURRENT_USER AS PROCEDURE p; END;')
        owner.execute('CREATE PACKAGE j1945 AS PROCEDURE p; END;')
        listed = owner.execute(
            'SELECT object_name, authid FROM user_procedures WHERE procedure_name '
            "IS NULL AND (object_name LIKE '%1945' OR object_name LIKE 'P!_%' "
            "ESCAPE '!') ORDER BY 1"
        ).rows
        assert [tuple(r) for r in listed] == [
            ('J1945', 'DEFINER'),
            ('K1945', 'CURRENT_USER'),
            ('P_COMMIT', 'DEFINER'),
            ('P_DEFINER', 'DEFINER'),
            ('P_INVOKER', 'CURRENT_USER'),
            ('P_NONE', 'DEFINER'),
        ]
    finally:
        owner.rollback()
        other.rollback()
        owner.close()
        other.close()
        admin.execute("DELETE FROM sys.ora_packages WHERE name IN ('k1945', 'j1945')")
        for schema in ('own1945', 'oth1945', 'k1945', 'j1945'):
            admin.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        admin.close()


def test_the_col_privs_views_list_each_users_column_grants() -> None:
    # The six *_COL_PRIVS views (#1946), by the rules the *_TAB_PRIVS views
    # list grants by: owner A grants B UPDATE (c1) WITH GRANT OPTION, B grants
    # C, A grants PUBLIC INSERT (c2). Column grants are not table grants.
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    users = ('cpa1946', 'cpb1946', 'cpc1946')
    for schema in users:
        admin.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        admin.execute(f'CREATE SCHEMA {schema}')
    (a, b, c) = (
        PostgresBackend(_CONNINFO, credentials={u.upper(): 'x'}) for u in users
    )
    (A, B, C) = (u.upper() for u in users)
    to_b = (A, B, 'C1', 'UPDATE', 'YES')
    to_c = (B, C, 'C1', 'UPDATE', 'NO')
    to_public = (A, 'PUBLIC', 'C2', 'INSERT', 'NO')
    views = (
        'all_col_privs',
        'all_col_privs_made',
        'all_col_privs_recd',
        'user_col_privs',
        'user_col_privs_made',
        'user_col_privs_recd',
    )
    seen = {
        A: [
            [to_public, to_b, to_c],
            [to_public, to_b, to_c],
            [to_public],
            [to_public, to_b, to_c],
            [to_public, to_b, to_c],
            [],
        ],
        B: [
            [to_public, to_b, to_c],
            [to_c],
            [to_public, to_b],
            [to_b, to_c],
            [],
            [(A, '', 'C1', 'UPDATE', 'YES')],
        ],
        C: [
            [to_public, to_c],
            [],
            [to_public, to_c],
            [to_c],
            [],
            [(B, '', 'C1', 'UPDATE', 'NO')],
        ],
    }
    try:
        for backend, user in ((a, A), (b, B), (c, C)):
            backend.authenticate(user)
        a.execute('CREATE TABLE cp1946 (c1 NUMBER, c2 NUMBER)')
        a.execute(f'GRANT UPDATE (c1) ON cp1946 TO {B} WITH GRANT OPTION')
        b.execute(f'GRANT UPDATE (c1) ON {A}.cp1946 TO {C}')
        a.execute('GRANT INSERT (c2) ON cp1946 TO PUBLIC')
        for backend, user in ((a, A), (b, B), (c, C)):
            for view, expected in zip(views, seen[user]):
                grantee = "''" if view == 'user_col_privs_recd' else 'grantee'
                listed = backend.execute(
                    f'SELECT grantor, {grantee}, column_name, privilege, grantable '
                    f"FROM {view} WHERE table_name = 'CP1946' ORDER BY 1, 2"
                ).rows
                backend.rollback()
                assert sorted(tuple(r) for r in listed) == sorted(expected), (
                    user,
                    view,
                )
        tables = a.execute(
            "SELECT count(*) FROM user_tab_privs WHERE table_name = 'CP1946'"
        ).rows
        a.rollback()
        assert [tuple(r) for r in tables] == [(0,)]
    finally:
        for backend in (a, b, c):
            backend.rollback()
            backend.close()
        admin.execute("DELETE FROM sys.ora_col_grants WHERE owner = 'CPA1946'")
        for schema in users:
            admin.execute(f'DROP SCHEMA IF EXISTS {schema} CASCADE')
        admin.close()


def test_a_rowid_column_refuses_a_number_and_a_bad_rowid() -> None:
    # A ROWID column (#1624): a number bound or written into it by INSERT ...
    # VALUES or UPDATE ... SET is ORA-00932, text that reads as no rowid
    # ORA-01410, a real rowid goes in -- 23ai's answers, which python-oracledb's
    # test_2902 checks. A number a query computes is refused too, as ORA-01410.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE rw1624t (n NUMBER, r ROWID, s VARCHAR2(30))')
        backend.execute("INSERT INTO rw1624t (n, s) VALUES (1, 'x')")
        (rowid,) = backend.execute('SELECT ROWID FROM rw1624t').rows[0]
        for statement, binds, code in (
            ('INSERT INTO rw1624t (n, r) VALUES (2, :1)', [12345], 932),
            ('INSERT INTO rw1624t (n, r) VALUES (2, 12345)', [], 932),
            ('UPDATE rw1624t SET r = :1 WHERE n = 1', [12345], 932),
            ('INSERT INTO rw1624t (n, r) VALUES (2, :1)', ['523lkhlf'], 1410),
            ('INSERT INTO rw1624t (n, r) SELECT 4, 12345 FROM dual', [], 1410),
        ):
            with pytest.raises(BackendError) as exc:
                backend.execute(statement, binds)
            assert exc.value.ora_code == code, statement
        backend.execute('INSERT INTO rw1624t (n, r) VALUES (2, :1)', [rowid])
        backend.execute('INSERT INTO rw1624t (n, s) VALUES (5, :1)', [12345])
        rows = backend.execute('SELECT r FROM rw1624t WHERE n = 2').rows
        assert rows == [(rowid,)]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE rw1624t')
        except Exception:
            backend.rollback()


def test_only_an_insert_or_update_looks_for_rowid_columns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The ROWID-number check (#1624) applies to INSERT ... VALUES and UPDATE ...
    # SET alone, so a query or a PL/SQL call asks PostgreSQL nothing for it
    # (#1868): it cost every statement a round trip.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    sent: list[str] = []
    execute = psycopg.Cursor.execute

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        sent.append(str(query))
        return execute(cursor, query, *args, **kwargs)

    def looked() -> int:
        return sum("typname = 'ora_rowid'" in query for query in sent)

    try:
        backend.execute('CREATE TABLE rw1868t (n NUMBER, r ROWID)')
        monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
        backend.execute('SELECT :1 FROM dual', [1])
        backend.execute('SELECT n FROM rw1868t')
        backend.execute('BEGIN NULL; END;')
        assert looked() == 0
        backend.execute('INSERT INTO rw1868t (n) VALUES (:1)', [1])
        assert looked() == 1
    finally:
        monkeypatch.undo()
        backend.rollback()
        try:
            backend.execute('DROP TABLE rw1868t')
        except Exception:
            backend.rollback()


def test_the_rowid_check_reads_a_quoted_table_name() -> None:
    # A quoted table name reaches the ROWID check (#1624) as itself, not as
    # its mask: an INSERT into "_rw1868" asked PostgreSQL about a name holding
    # NUL bytes, which it refuses (#1868).
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE "_rw1868" (n NUMBER, r ROWID)')
        backend.execute('INSERT INTO "_rw1868" (n) VALUES (:1)', [1])
        for statement in (
            'INSERT INTO "_rw1868" (n, r) VALUES (2, :1)',
            'UPDATE "_rw1868" SET r = :1 WHERE n = 1',
        ):
            with pytest.raises(BackendError) as exc:
                backend.execute(statement, [12345])
            assert exc.value.ora_code == 932, statement
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE "_rw1868"')
        except Exception:
            backend.rollback()


def test_the_rowid_check_reads_a_quoted_column_name() -> None:
    # A quoted ROWID column (#1876) is one the ROWID check (#1624) knows, by
    # its name rather than its mask: a number put in it is ORA-00932, as an
    # unquoted column's is.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE rw1876t (n NUMBER, "Rr" ROWID)')
        backend.execute('INSERT INTO rw1876t (n) VALUES (:1)', [1])
        for statement in (
            'INSERT INTO rw1876t (n, "Rr") VALUES (2, :1)',
            'UPDATE rw1876t SET "Rr" = :1 WHERE n = 1',
        ):
            with pytest.raises(BackendError) as exc:
                backend.execute(statement, [12345])
            assert exc.value.ora_code == 932, statement
        (rowid,) = backend.execute('SELECT ROWID FROM rw1876t').rows[0]
        backend.execute('UPDATE rw1876t SET "Rr" = :1 WHERE n = 1', [rowid])
        assert backend.execute('SELECT "Rr" FROM rw1876t').rows == [(rowid,)]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE rw1876t')
        except Exception:
            backend.rollback()


def test_v_version_lists_the_presented_release() -> None:
    # V$VERSION (#1603) in 12.1's shape: 11g's five component rows of the
    # release the Mirror presents, and CON_ID 0 -- the banner sqlplus reads
    # with `WHERE rownum = 1`.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        result = backend.execute('SELECT * FROM v$version')
        assert [c.name for c in result.columns] == [b'BANNER', b'CON_ID']
        assert [tuple(r) for r in result.rows] == [
            (
                'Oracle Database 12c Enterprise Edition Release 12.1.0.2.0 '
                '- 64bit Production',
                0,
            ),
            ('PL/SQL Release 12.1.0.2.0 - Production', 0),
            ('CORE\t12.1.0.2.0\tProduction', 0),
            ('TNS for Linux: Version 12.1.0.2.0 - Production', 0),
            ('NLSRTL Version 12.1.0.2.0 - Production', 0),
        ]
        assert backend.execute(
            'SELECT banner FROM v$version WHERE rownum = 1'
        ).rows == [
            (
                'Oracle Database 12c Enterprise Edition Release 12.1.0.2.0 - 64bit Production',
            )
        ]
    finally:
        backend.rollback()
        backend.close()


def test_a_session_keeps_its_edition() -> None:
    # Editions by name (#1662): ORA$BASE until one is set, CREATE EDITION's
    # name accepted by ALTER SESSION and at login, one that does not exist
    # ORA-38802 at either, a second CREATE ORA-00955 -- 23ai's answers.
    from seerdb.server import BackendError

    query = (
        "SELECT sys_context('userenv', 'current_edition_name'), "
        "sys_context('userenv', 'session_edition_name') FROM dual"
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    login = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('DROP EDITION ed1662')
    except BackendError:
        backend.rollback()  # not there yet
    try:
        assert backend.execute(query).rows == [('ORA$BASE', 'ORA$BASE')]
        backend.execute('CREATE EDITION ed1662')
        with pytest.raises(BackendError) as exc:
            backend.execute('CREATE EDITION ed1662')
        assert exc.value.ora_code == 955
        with pytest.raises(BackendError) as exc:
            backend.execute('ALTER SESSION SET EDITION = nosuch1662')
        assert exc.value.ora_code == 38802
        backend.execute('ALTER SESSION SET EDITION = ed1662')
        assert backend.execute(query).rows == [('ED1662', 'ED1662')]
        backend.rollback()  # an ALTER SESSION outlives a rollback
        assert backend.execute(query).rows == [('ED1662', 'ED1662')]
        login.authenticate('pyo')
        with pytest.raises(BackendError) as exc:
            login.open_session({'edition': 'nosuch1662'})
        assert exc.value.ora_code == 38802
        login.open_session({'edition': 'ed1662'})
        assert login.execute(query).rows == [('ED1662', 'ED1662')]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP EDITION ed1662')
        except BackendError:
            backend.rollback()
        backend.close()
        login.close()


def test_a_plsql_trigger_fires_as_oracles_does() -> None:
    # CREATE TRIGGER with a PL/SQL block was a syntax error (#2174). 23ai's,
    # on trg_t (a, b, c): a BEFORE row trigger sets :new; INSERTING, UPDATING
    # and DELETING tell its events apart with :new and :old; a statement
    # trigger fires once a statement; UPDATE OF and WHEN choose the rows;
    # REFERENCING renames :new. USER_OBJECTS lists each trigger VALID and
    # USER_SOURCE its text; ORA-04081 for a second CREATE, ORA-04080 for a
    # DROP of none.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE trg_t (a NUMBER, b NUMBER, c VARCHAR2(10))')
        backend.execute('CREATE TABLE trg_log (what VARCHAR2(20), n NUMBER)')
        try:
            for trigger in (
                'CREATE OR REPLACE TRIGGER trg1 BEFORE INSERT ON trg_t FOR EACH ROW '
                'BEGIN :new.b := :new.a * 2; END;',
                'CREATE OR REPLACE TRIGGER trg2 AFTER INSERT OR UPDATE OR DELETE '
                'ON trg_t FOR EACH ROW BEGIN IF inserting THEN '
                "INSERT INTO trg_log VALUES ('I', :new.a); ELSIF updating THEN "
                "INSERT INTO trg_log VALUES ('U', :old.a); ELSE "
                "INSERT INTO trg_log VALUES ('D', :old.a); END IF; END;",
                'CREATE OR REPLACE TRIGGER trg3 AFTER INSERT ON trg_t '
                "BEGIN INSERT INTO trg_log VALUES ('S', NULL); END;",
                'CREATE OR REPLACE TRIGGER trg4 BEFORE UPDATE OF c ON trg_t '
                'FOR EACH ROW WHEN (new.a > 5) BEGIN :new.c := upper(:new.c); END;',
            ):
                backend.execute(trigger)
            backend.execute("INSERT INTO trg_t (a, c) VALUES (3, 'x')")
            backend.execute("INSERT INTO trg_t (a, c) VALUES (7, 'y')")
            assert backend.execute('SELECT a, b, c FROM trg_t ORDER BY a').rows == [
                (3, 6, 'x'),
                (7, 14, 'y'),
            ]
            backend.execute("UPDATE trg_t SET c = 'z'")
            assert backend.execute('SELECT a, c FROM trg_t ORDER BY a').rows == [
                (3, 'z'),
                (7, 'Z'),
            ]
            backend.execute('UPDATE trg_t SET b = 0 WHERE a = 7')
            backend.execute('DELETE FROM trg_t WHERE a = 3')
            assert backend.execute('SELECT what, n FROM trg_log').rows == [
                ('I', 3),
                ('S', None),
                ('I', 7),
                ('S', None),
                ('U', 3),
                ('U', 7),
                ('U', 7),
                ('D', 3),
            ]
            assert backend.execute(
                'SELECT object_name, status FROM user_objects '
                "WHERE object_type = 'TRIGGER' ORDER BY 1"
            ).rows == [
                ('TRG1', 'VALID'),
                ('TRG2', 'VALID'),
                ('TRG3', 'VALID'),
                ('TRG4', 'VALID'),
            ]
            assert backend.execute(
                "SELECT text FROM user_source WHERE name = 'TRG1'"
            ).rows == [
                (
                    'TRIGGER trg1 BEFORE INSERT ON trg_t FOR EACH ROW '
                    'BEGIN :new.b := :new.a * 2; END;',
                )
            ]
            backend.execute('DROP TRIGGER trg1')
            backend.execute(
                'CREATE TRIGGER trg5 BEFORE INSERT ON trg_t REFERENCING NEW AS nn '
                'FOR EACH ROW DECLARE k NUMBER := 99; BEGIN :nn.b := k; END;'
            )
            backend.execute('INSERT INTO trg_t (a) VALUES (2)')
            assert backend.execute('SELECT b FROM trg_t WHERE a = 2').rows == [(99,)]
            for statement, code in (
                (
                    'CREATE TRIGGER trg5 BEFORE INSERT ON trg_t FOR EACH ROW '
                    'BEGIN NULL; END;',
                    4081,
                ),
                ('DROP TRIGGER trg1', 4080),
            ):
                with pytest.raises(BackendError) as raised:
                    backend.execute(statement)
                assert raised.value.ora_code == code, statement
        finally:
            backend.rollback()
            backend.execute('DROP TABLE trg_t')
            backend.execute('DROP TABLE trg_log')
        assert backend.execute(
            "SELECT count(*) FROM user_objects WHERE object_type = 'TRIGGER'"
        ).rows == [(0,)]
        assert backend._conn.execute(
            "SELECT count(*) FROM pg_proc WHERE proname LIKE 'ora$trg%'"
        ).fetchone() == (0,)
    finally:
        backend.close()


def test_user_triggers_lists_a_trigger_as_oracles_does() -> None:
    # USER_TRIGGERS did not list a PL/SQL trigger, and ALTER TRIGGER failed
    # (#2174). 23ai's columns: the kind and events, REFERENCING names in upper
    # case, WHEN and the body as written, DESCRIPTION from the trigger's name
    # to its WHEN or block; ALTER TRIGGER DISABLE / ENABLE and ALTER TABLE ...
    # DISABLE / ENABLE ALL TRIGGERS switch them, COMPILE does nothing, and
    # ORA-04080 for no such trigger.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))

    def listed(columns: str) -> list:
        return backend.execute(
            f'SELECT {columns} FROM user_triggers ORDER BY trigger_name'
        ).rows

    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE trg_u (a NUMBER, b NUMBER, c VARCHAR2(10))')
        try:
            backend.execute(
                'create or replace trigger trg1 before insert on trg_u for each row '
                'begin :new.b := :new.a * 2; end;'
            )
            backend.execute(
                'create or replace trigger trg4 before update of c, b on trg_u '
                'referencing new as nn old as oo for each row when (nn.a > 5) '
                'begin :nn.c := upper(:nn.c); end;'
            )
            backend.execute(
                'create or replace trigger trg3 after insert or delete on trg_u '
                'begin null; end;'
            )
            assert listed(
                'trigger_name, trigger_type, triggering_event, table_owner, '
                'base_object_type, table_name, column_name, referencing_names, '
                'when_clause, status, description, action_type, trigger_body'
            ) == [
                (
                    'TRG1',
                    'BEFORE EACH ROW',
                    'INSERT',
                    'PYO',
                    'TABLE',
                    'TRG_U',
                    None,
                    'REFERENCING NEW AS NEW OLD AS OLD',
                    None,
                    'ENABLED',
                    'trg1 before insert on trg_u for each row ',
                    'PL/SQL     ',
                    'begin :new.b := :new.a * 2; end;',
                ),
                (
                    'TRG3',
                    'AFTER STATEMENT',
                    'INSERT OR DELETE',
                    'PYO',
                    'TABLE',
                    'TRG_U',
                    None,
                    'REFERENCING NEW AS NEW OLD AS OLD',
                    None,
                    'ENABLED',
                    'trg3 after insert or delete on trg_u ',
                    'PL/SQL     ',
                    'begin null; end;',
                ),
                (
                    'TRG4',
                    'BEFORE EACH ROW',
                    'UPDATE',
                    'PYO',
                    'TABLE',
                    'TRG_U',
                    None,
                    'REFERENCING NEW AS NN OLD AS OO',
                    'nn.a > 5',
                    'ENABLED',
                    'trg4 before update of c, b on trg_u referencing new as nn '
                    'old as oo for each row ',
                    'PL/SQL     ',
                    'begin :nn.c := upper(:nn.c); end;',
                ),
            ]
            backend.execute("INSERT INTO trg_u (a, c) VALUES (7, 'x')")
            backend.execute("UPDATE trg_u SET c = 'y'")
            assert backend.execute('SELECT b, c FROM trg_u').rows == [(14, 'Y')]
            backend.execute('ALTER TRIGGER trg1 DISABLE')
            backend.execute('INSERT INTO trg_u (a) VALUES (1)')
            assert backend.execute('SELECT b FROM trg_u WHERE a = 1').rows == [(None,)]
            backend.execute('ALTER TRIGGER trg1 ENABLE')
            backend.execute('ALTER TRIGGER trg1 COMPILE')
            backend.execute('ALTER TABLE trg_u DISABLE ALL TRIGGERS')
            assert set(listed('status')) == {('DISABLED',)}
            backend.execute('ALTER TABLE trg_u ENABLE ALL TRIGGERS')
            assert set(listed('status')) == {('ENABLED',)}
            with pytest.raises(BackendError) as raised:
                backend.execute('ALTER TRIGGER nosuch2174 ENABLE')
            assert raised.value.ora_code == 4080
        finally:
            backend.rollback()
            backend.execute('DROP TABLE trg_u')
        assert listed('trigger_name') == []
    finally:
        backend.close()


def test_a_standalone_routine_is_listed_with_the_objects() -> None:
    # A user's standalone procedure and function (#1606): in ALL_OBJECTS as
    # PROCEDURE / FUNCTION, VALID or INVALID as they compiled, and the valid
    # ones in ALL_PROCEDURES under their own names -- 23ai's rows. A package's
    # member is the package's, and the backend's own helpers are none.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    names = "('OB1606F', 'OB1606P', 'OB1606X', 'OB1606K', 'M')"
    try:
        backend.execute(
            'CREATE OR REPLACE FUNCTION ob1606f RETURN NUMBER IS BEGIN RETURN 1; END;'
        )
        backend.execute(
            'CREATE OR REPLACE PROCEDURE ob1606p(n NUMBER) IS BEGIN NULL; END;'
        )
        backend.execute(
            'CREATE OR REPLACE PROCEDURE ob1606x IS BEGIN no_such_thing; END;'
        )
        backend.execute('CREATE OR REPLACE PACKAGE ob1606k AS PROCEDURE m; END;')
        backend.execute(
            'CREATE OR REPLACE PACKAGE BODY ob1606k AS PROCEDURE m IS BEGIN NULL; END; END;'
        )
        objects = backend.execute(
            'SELECT object_name, object_type, status FROM all_objects '
            f'WHERE object_name IN {names} ORDER BY 1, 2'
        ).rows
        assert [tuple(r) for r in objects] == [
            ('OB1606F', 'FUNCTION', 'VALID'),
            ('OB1606K', 'PACKAGE', 'VALID'),
            ('OB1606K', 'PACKAGE BODY', 'VALID'),
            ('OB1606P', 'PROCEDURE', 'VALID'),
            ('OB1606X', 'PROCEDURE', 'INVALID'),
        ]
        procedures = backend.execute(
            'SELECT object_name, procedure_name, object_type, subprogram_id, overload '
            f'FROM all_procedures WHERE object_name IN {names} ORDER BY 1, 4'
        ).rows
        assert [tuple(r) for r in procedures] == [
            ('OB1606F', None, 'FUNCTION', 1, None),
            ('OB1606K', None, 'PACKAGE', 0, None),
            ('OB1606K', 'M', 'PACKAGE', 1, None),
            ('OB1606P', None, 'PROCEDURE', 1, None),
        ]
        helpers = backend.execute(
            "SELECT count(*) FROM all_objects WHERE object_type IN ('FUNCTION', "
            "'PROCEDURE') AND object_name NOT LIKE 'OB1606%'"
        ).rows[0][0]
        assert helpers == 0
    finally:
        backend.rollback()
        for statement in (
            'DROP FUNCTION ob1606f',
            'DROP PROCEDURE ob1606p',
            'DROP PROCEDURE ob1606x',
            'DROP PACKAGE ob1606k',
        ):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()
        backend.close()


def test_rowcount_attributes_read_as_in_oracle() -> None:
    # %ROWCOUNT (#1608): SQL%ROWCOUNT is the last SQL statement's row count --
    # NULL before any, an UPDATE's rows, 1 for a SELECT INTO, 0 for a DELETE of
    # none -- and a cursor's the rows fetched since it was opened. 23ai's.
    from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE rc1608t (n NUMBER)')
        backend.execute(
            'INSERT INTO rc1608t SELECT level FROM dual CONNECT BY level <= 5'
        )
        backend.execute(
            'CREATE OR REPLACE FUNCTION rc1608 RETURN VARCHAR2 IS\n'
            '  k SYS_REFCURSOR; v NUMBER; s VARCHAR2(200);\nBEGIN\n'
            "  s := 'start:' || nvl(to_char(SQL%ROWCOUNT), 'null');\n"
            '  UPDATE rc1608t SET n = n WHERE n <= 3;\n'
            "  s := s || ' upd:' || SQL%ROWCOUNT;\n"
            "  IF SQL%ROWCOUNT = 3 THEN s := s || ' if3'; END IF;\n"
            '  SELECT count(*) INTO v FROM rc1608t;\n'
            "  s := s || ' sel:' || SQL%ROWCOUNT;\n"
            '  DELETE FROM rc1608t WHERE n > 99;\n'
            "  s := s || ' del:' || SQL%ROWCOUNT;\n"
            '  OPEN k FOR SELECT n FROM rc1608t ORDER BY n;\n'
            "  s := s || ' open:' || k%ROWCOUNT;\n"
            "  FETCH k INTO v; FETCH k INTO v; s := s || ' f2:' || k%ROWCOUNT;\n"
            '  LOOP FETCH k INTO v; EXIT WHEN k%NOTFOUND; END LOOP;\n'
            "  s := s || ' end:' || k%ROWCOUNT;\n"
            '  CLOSE k; RETURN s;\nEND;'
        )
        result = backend.execute(
            'BEGIN :1 := rc1608(); END;',
            [BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=200)],
        )
        assert result.out_binds[0] == (
            'start:null upd:3 if3 sel:1 del:0 open:0 f2:2 end:5'
        )
    finally:
        backend.rollback()
        for statement in ('DROP FUNCTION rc1608', 'DROP TABLE rc1608t'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()
        backend.close()


def test_directory_objects_are_kept_and_listed() -> None:
    # DIRECTORY objects (#1668): CREATE keeps a name for a path on the
    # PostgreSQL host, ALL_DIRECTORIES lists it as SYS's, OR REPLACE moves it, a
    # second CREATE is ORA-00955 and dropping a missing one ORA-04043.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    query = (
        'SELECT owner, directory_name, directory_path, origin_con_id '
        "FROM all_directories WHERE directory_name = 'DIR1668'"
    )
    try:
        try:
            backend.execute('DROP DIRECTORY dir1668')
        except BackendError:
            backend.rollback()  # not there yet
        backend.execute("CREATE DIRECTORY dir1668 AS '/tmp/one'")
        assert [tuple(r) for r in backend.execute(query).rows] == [
            ('SYS', 'DIR1668', '/tmp/one', 0)
        ]
        with pytest.raises(BackendError) as exc:
            backend.execute("CREATE DIRECTORY dir1668 AS '/tmp/two'")
        assert exc.value.ora_code == 955
        backend.execute("CREATE OR REPLACE DIRECTORY dir1668 AS '/tmp/it''s'")
        assert backend.execute(query).rows[0][2] == "/tmp/it's"
        backend.execute('DROP DIRECTORY dir1668')
        assert backend.execute(query).rows == []
        with pytest.raises(BackendError) as exc:
            backend.execute('DROP DIRECTORY dir1668')
        assert exc.value.ora_code == 4043
    finally:
        backend.rollback()
        try:
            backend.execute('DROP DIRECTORY dir1668')
        except BackendError:
            backend.rollback()
        backend.close()


def test_a_bfile_names_a_file_on_the_postgresql_host() -> None:
    # BFILE values (#1669): BFILENAME and a BFILE column carry the directory's
    # and the file's names, described as a BFILE, and bfile_exists answers from
    # the PostgreSQL host -- ORA-22285 for a DIRECTORY object that does not
    # exist, as 23ai's FILEEXISTS does, else whether the file is there.
    from seerdb.common.tns_consts import TNS_TYPE_BFILE
    from seerdb.server import BackendError, BFile

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        result = backend.execute(
            "SELECT BFILENAME('TEST_1936_MISSING_DIR', 'f.txt') FROM dual"
        )
        assert result.columns[0].data_type == TNS_TYPE_BFILE
        assert result.rows == [(BFile('TEST_1936_MISSING_DIR', 'f.txt'),)]
        with pytest.raises(BackendError) as exc:
            backend.bfile_exists('TEST_1936_MISSING_DIR', 'f.txt')
        assert exc.value.ora_code == 22285
        try:
            backend.execute('DROP DIRECTORY etc1669')
        except BackendError:
            backend.rollback()  # not there yet
        backend.execute("CREATE DIRECTORY etc1669 AS '/etc'")
        assert backend.bfile_exists('ETC1669', 'hostname')
        assert not backend.bfile_exists('ETC1669', 'no_such_file_1669')
        backend.execute('CREATE TABLE bt1669 (n NUMBER, b BFILE)')
        backend.execute(
            "INSERT INTO bt1669 VALUES (1, BFILENAME('ETC1669', 'hostname'))"
        )
        (row,) = backend.execute('SELECT b FROM bt1669').rows
        assert row[0] == BFile('ETC1669', 'hostname')
    finally:
        backend.rollback()
        for statement in ('DROP TABLE bt1669', 'DROP DIRECTORY etc1669'):
            try:
                backend.execute(statement)
            except BackendError:
                backend.rollback()
        backend.close()


def test_a_bfiles_bytes_are_read_on_the_postgresql_host() -> None:
    # A BFILE's length and bytes (#1672), read through PostgreSQL: the whole
    # file, a slice from a 1-based offset, an amount past the end cut short,
    # and ORA-22285 for a file that is not there, as 23ai answers.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        try:
            backend.execute('DROP DIRECTORY etc1672')
        except BackendError:
            backend.rollback()  # not there yet
        backend.execute("CREATE DIRECTORY etc1672 AS '/etc'")
        whole = backend.bfile_read('ETC1672', 'hostname', 1, 0)
        assert whole
        assert backend.bfile_length('ETC1672', 'hostname') == len(whole)
        assert backend.bfile_read('ETC1672', 'hostname', 3, 5) == whole[2:7]
        assert backend.bfile_read('ETC1672', 'hostname', 2, 0xFFFFFFFF) == whole[1:]
        for read in (
            lambda: backend.bfile_length('ETC1672', 'no_such_file_1672'),
            lambda: backend.bfile_read('ETC1672', 'no_such_file_1672', 1, 0),
            lambda: backend.bfile_length('NO_SUCH_DIR_1672', 'hostname'),
        ):
            with pytest.raises(BackendError) as exc:
                read()
            assert exc.value.ora_code == 22285
    finally:
        backend.rollback()
        try:
            backend.execute('DROP DIRECTORY etc1672')
        except BackendError:
            backend.rollback()
        backend.close()


def test_a_cursors_attributes_read_as_in_oracle() -> None:
    # c%FOUND / c%NOTFOUND after a FETCH, c%ISOPEN before and after CLOSE, and
    # SQL%FOUND / SQL%NOTFOUND after an UPDATE (#1608); a string holding one is
    # data. The answer is 23ai's.
    from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar

    assert _translate_idioms("v := 'a%found'; w := SQL%ISOPEN;") == (
        "v := 'a%found'; w := FALSE;"
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE ca1608t (n NUMBER)')
        backend.execute('INSERT INTO ca1608t VALUES (1)')
        backend.execute(
            'CREATE OR REPLACE FUNCTION ca1608 RETURN VARCHAR2 IS\n'
            '  c SYS_REFCURSOR;\n  v NUMBER;\n  s VARCHAR2(200);\nBEGIN\n'
            '  OPEN c FOR SELECT level FROM dual CONNECT BY level <= 3;\n'
            "  IF c%ISOPEN THEN s := 'open '; END IF;\n"
            '  LOOP\n    FETCH c INTO v;\n    EXIT WHEN c%NOTFOUND;\n'
            "    s := s || v || ' ';\n  END LOOP;\n"
            "  IF NOT c%FOUND THEN s := s || 'done '; END IF;\n"
            '  CLOSE c;\n'
            "  IF NOT c%ISOPEN THEN s := s || 'closed '; END IF;\n"
            '  UPDATE ca1608t SET n = n + 1 WHERE n = 1;\n'
            "  IF SQL%FOUND THEN s := s || 'updated '; END IF;\n"
            '  UPDATE ca1608t SET n = n + 1 WHERE n = 99;\n'
            "  IF SQL%NOTFOUND THEN s := s || 'none'; END IF;\n"
            '  RETURN s;\nEND;'
        )
        result = backend.execute(
            'BEGIN :1 := ca1608(); END;',
            [BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=200)],
        )
        assert result.out_binds[0] == 'open 1 2 3 done closed updated none'
    finally:
        backend.rollback()
        for statement in ('DROP FUNCTION ca1608', 'DROP TABLE ca1608t'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_an_explicit_cursor_declaration_translates() -> None:
    # CURSOR c [(params)] IS ... (#1665), in a routine and in a block: PL/pgSQL
    # spells it c CURSOR [(params)] FOR ..., a parameter without its IN. A
    # cursor type is no declaration. The answers are 23ai's.
    from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar

    assert _translate_routine_types(
        'CURSOR k (m IN NUMBER) RETURN t%ROWTYPE IS SELECT n FROM t;'
    ) == ('k CURSOR (m numeric) FOR SELECT n FROM t;')
    assert _translate_routine_types('c SYS_REFCURSOR;') == 'c refcursor;'
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE xc1665t (n NUMBER)')
        for n in (1, 2, 3):
            backend.execute(f'INSERT INTO xc1665t VALUES ({n})')
        backend.execute(
            'CREATE OR REPLACE FUNCTION xc1665(lo NUMBER) RETURN VARCHAR2 IS\n'
            '  CURSOR k IS SELECT n FROM xc1665t ORDER BY n;\n'
            '  CURSOR p (m IN NUMBER) IS\n'
            '    SELECT n FROM xc1665t WHERE n > m ORDER BY n;\n'
            '  v NUMBER;\n  s VARCHAR2(200);\nBEGIN\n'
            "  OPEN k; FETCH k INTO v; s := v || ' ';\n"
            "  FETCH k INTO v; s := s || v || ' ' || k%ROWCOUNT || ' '; CLOSE k;\n"
            "  FOR r IN p(lo) LOOP s := s || r.n || ' '; END LOOP;\n"
            '  RETURN s;\nEND;'
        )
        (row,) = backend.execute('SELECT xc1665(1) FROM dual').rows
        assert row[0] == '1 2 2 2 3 '
        result = backend.execute(
            'DECLARE CURSOR k IS SELECT n FROM xc1665t ORDER BY n DESC; '
            'v NUMBER; BEGIN OPEN k; FETCH k INTO v; CLOSE k; :1 := v; END;',
            [BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=20)],
        )
        assert result.out_binds[0] == '3'
    finally:
        backend.rollback()
        for statement in ('DROP FUNCTION xc1665', 'DROP TABLE xc1665t'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_a_commit_in_a_routine_commits_once_the_call_succeeds() -> None:
    # A COMMIT in a procedure, a package member or a block (#1630) commits the
    # caller's open work with the routine's, as Oracle's does, once the call
    # has succeeded; a call that fails before it commits nothing. The rows
    # another session sees are 23ai's.
    from seerdb.server import BackendError

    assert _translate_idioms('COMMIT') == 'COMMIT'
    assert _translate_idioms(
        'CREATE GLOBAL TEMPORARY TABLE t (n NUMBER) ON COMMIT DELETE ROWS'
    ) == ('CREATE GLOBAL TEMPORARY TABLE t (n NUMBER) ON COMMIT DELETE ROWS')
    assert _translate_idioms("BEGIN x := 'commit;'; COMMIT WORK; END;") == (
        "BEGIN x := 'commit;'; PERFORM sys.ora_commit_request(); END;"
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    other = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))

    def committed() -> list[int]:
        rows = other.execute('SELECT n FROM cm1630t ORDER BY n').rows
        other.rollback()
        return [int(row[0]) for row in rows]

    try:
        backend.execute('CREATE TABLE cm1630t (n NUMBER)')
        backend.execute(
            'CREATE OR REPLACE PROCEDURE cm1630(v NUMBER, fail NUMBER) IS\nBEGIN\n'
            '  INSERT INTO cm1630t VALUES (v);\n'
            "  IF fail = 1 THEN raise_application_error(-20001, 'boom'); END IF;\n"
            '  COMMIT;\nEND;'
        )
        backend.execute(
            'CREATE OR REPLACE PACKAGE cm1630p AS PROCEDURE p(v NUMBER); END;'
        )
        backend.execute(
            'CREATE OR REPLACE PACKAGE BODY cm1630p AS PROCEDURE p(v NUMBER) IS\n'
            'BEGIN\n  INSERT INTO cm1630t VALUES (v);\n  COMMIT;\nEND;\nEND;'
        )
        backend.execute('INSERT INTO cm1630t VALUES (1)')
        backend.execute('BEGIN cm1630(2, 0); END;')
        assert committed() == [1, 2]
        with pytest.raises(BackendError) as exc:
            backend.execute('BEGIN cm1630(4, 1); END;')
        assert exc.value.ora_code == 20001
        assert committed() == [1, 2]
        backend.execute('BEGIN INSERT INTO cm1630t VALUES (5); COMMIT; END;')
        assert committed() == [1, 2, 5]
        backend.execute('BEGIN cm1630p.p(6); END;')
        assert committed() == [1, 2, 5, 6]
    finally:
        backend.rollback()
        for statement in (
            'DROP PACKAGE cm1630p',
            'DROP PROCEDURE cm1630',
            'DROP TABLE cm1630t',
        ):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()
        other.close()
        backend.close()


def test_get_type_shape_of_a_rowtype_with_a_date_column() -> None:
    # A table's DATE column is the ora_date domain (#1316). As a %ROWTYPE
    # attribute it had no Oracle type at all; its TDS leaf is the DATE code
    # alone and its built-in type OID ends in 0x08. The whole TDS is the one a
    # live 23ai returns for the same table (#1474).
    from seerdb.common.tns_consts import (
        TNS_TYPE_NUMBER,
        TNS_TYPE_RAW,
        TNS_TYPE_REFCURSOR,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE pyo_rowtype_date (n NUMBER, d DATE, t TIMESTAMP)')
        binds = [
            BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=4),
            BindVar(
                value='PYO_ROWTYPE_DATE%ROWTYPE',
                tns_type=TNS_TYPE_VARCHAR,
                max_size=128,
            ),
            BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=16),
            BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=4),
            BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=32767),
            BindVar(value=None, tns_type=TNS_TYPE_REFCURSOR, max_size=1),
            BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=128),
        ]
        (ret_val, _f, _o, _v, tds, attrs, _p) = backend.execute(
            _TYPE_SHAPE_SQL, binds
        ).out_binds
        assert ret_val == 0
        assert tds.hex() == (
            '0000001b260200010003002900000000000c0600810215062a0007000a000b'
        )
        assert [(r[1], r[3], r[6][-1]) for r in attrs.rows[:2]] == [
            ('N', 'NUMBER', 0x0F),
            ('D', 'DATE', 0x08),
        ]
    finally:
        backend.execute('DROP TABLE IF EXISTS pyo_rowtype_date')
        backend.commit()
        backend.close()


def test_get_type_shape_qualifies_a_rowtype_full_name() -> None:
    # full_name is IN OUT: the server hands a %ROWTYPE's name back qualified by
    # the table's owner, as 23ai does ('T%ROWTYPE' -> 'PYO.T%ROWTYPE').
    # python-oracledb reads the record's schema from it and then the columns
    # from all_tab_cols by that owner; echoed back unqualified, the owner was
    # empty and the columns query found nothing (#1479).
    from seerdb.common.tns_consts import (
        TNS_TYPE_NUMBER,
        TNS_TYPE_RAW,
        TNS_TYPE_REFCURSOR,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE pyo_rowtype_fn (n NUMBER, s VARCHAR2(10))')
        binds = [
            BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=4),
            BindVar(
                value='PYO_ROWTYPE_FN%ROWTYPE', tns_type=TNS_TYPE_VARCHAR, max_size=128
            ),
            BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=16),
            BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=4),
            BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=32767),
            BindVar(value=None, tns_type=TNS_TYPE_REFCURSOR, max_size=1),
            BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=128),
        ]
        (ret_val, full_name, *_rest) = backend.execute(_TYPE_SHAPE_SQL, binds).out_binds
        owner = backend.execute(
            "SELECT owner FROM all_tables WHERE table_name = 'PYO_ROWTYPE_FN'"
        ).rows[0][0]
        assert ret_val == 0
        assert full_name == f'{owner}.PYO_ROWTYPE_FN%ROWTYPE'
    finally:
        backend.execute('DROP TABLE IF EXISTS pyo_rowtype_fn')
        backend.commit()
        backend.close()


def test_the_column_visibility_attribute_comes_out_of_the_ddl() -> None:
    # INVISIBLE / VISIBLE follow a column's type in CREATE TABLE and in ALTER
    # TABLE ADD / MODIFY; the statement loses it and says which columns it named,
    # in PostgreSQL's spelling (#1195).
    from seerdb.server.backends.postgres import _column_visibility as visibility

    assert visibility('CREATE TABLE t (a NUMBER, h NUMBER INVISIBLE DEFAULT 5)') == (
        'CREATE TABLE t (a NUMBER, h NUMBER  DEFAULT 5)',
        ('t', ['h'], [], False),
    )
    assert visibility(
        'CREATE TABLE t ("Hid" NUMBER INVISIBLE, c NUMBER(5, 2) VISIBLE)'
    )[1] == ('t', ['Hid'], ['c'], False)
    # A MODIFY that only changes visibility leaves nothing to run.
    assert visibility('ALTER TABLE t MODIFY (a INVISIBLE, b VISIBLE)')[1] == (
        't',
        ['a'],
        ['b'],
        True,
    )
    assert (
        _present(visibility('ALTER TABLE t MODIFY (a NUMBER(10) INVISIBLE)')[1])[3]
        is False
    )
    # A table or column merely named so is not the attribute.
    assert visibility('CREATE TABLE invisible (visible NUMBER)')[1] is None


def test_translate_idioms_rewrites_rowid_pseudocolumn() -> None:
    # The ROWID pseudo-column becomes the row's ctid in Oracle's extended form —
    # one rewrite serving a SELECT, a WHERE ROWID = :bind (text compare), and the
    # form cursor.lastrowid reports.
    rowid = 'sys.ora_rowid(tableoid, ctid)'
    assert _translate_idioms('SELECT ROWID FROM t') == f'SELECT {rowid} FROM t'
    assert _translate_idioms('SELECT id FROM t WHERE ROWID = :r') == (
        f'SELECT id FROM t WHERE {rowid} = :r'
    )
    # The word boundary keeps it off ROWIDTOCHAR (no boundary mid-token) — that call
    # resolves to the installed identity helper — and off UROWID (a word char
    # precedes ROWID), so a UROWID column type name is left intact.
    assert _translate_idioms('SELECT ROWIDTOCHAR(ROWID) FROM t') == (
        f'SELECT ROWIDTOCHAR({rowid}) FROM t'
    )
    assert _translate_idioms('CREATE TABLE t (r UROWID)') == (
        'CREATE TABLE t (r UROWID)'
    )
    # Case-insensitive, like the other pseudo-column rewrites.
    assert (
        _translate_idioms('select rowid from t')
        == 'select sys.ora_rowid(tableoid, ctid) from t'
    )


def test_translate_idioms_binary_float_double_literals() -> None:
    # The BINARY_DOUBLE / BINARY_FLOAT literal suffix is dropped; the special
    # values become IEEE-754 float literals.
    assert _translate_idioms('VALUES (1234.5678d)') == 'VALUES (1234.5678)'
    assert _translate_idioms('VALUES (-2.25f)') == 'VALUES (-2.25)'
    assert _translate_idioms('VALUES (binary_double_infinity)') == (
        "VALUES ('Infinity'::float8)"
    )
    assert _translate_idioms('VALUES (binary_double_nan)') == "VALUES ('NaN'::float8)"
    # A decimal point is required, so a plain integer or identifier is untouched.
    assert _translate_idioms('SELECT id2 FROM t') == 'SELECT id2 FROM t'
    assert _translate_idioms('VALUES (100)') == 'VALUES (100)'


# --- Oracle-only type rejection (#504) — a pure check, no live PG needed --------


def test_reject_oracle_only_ddl_types_raises_ora_902() -> None:
    from seerdb.server import BackendError

    # JSON (21c+), VECTOR / BOOLEAN (23ai+) are invalid at the 11.2 version the
    # Mirror advertises, so a CREATE TABLE using one is refused with ORA-00902 —
    # which is exactly what the suite's version guards skip on.
    for coltype in ('doc JSON', 'v VECTOR(3, FLOAT32)', 'flag BOOLEAN'):
        with pytest.raises(BackendError) as exc:
            _reject_unsupported_ddl_types(
                f'CREATE TABLE t (id NUMBER, {coltype})', (12, 1)
            )
        assert exc.value.ora_code == 902

    # An ordinary CREATE TABLE — and any non-CREATE-TABLE statement — is fine.
    _reject_unsupported_ddl_types('CREATE TABLE t (id NUMBER, v VARCHAR2(10))', (12, 1))
    # At 23ai all three are taken, and JSON already at 21c (#1704).
    for coltype in ('doc JSON', 'v VECTOR(3, FLOAT32)', 'flag BOOLEAN'):
        _reject_unsupported_ddl_types(
            f'CREATE TABLE t (id NUMBER, {coltype})', (23, 26)
        )
    _reject_unsupported_ddl_types('CREATE TABLE t (id NUMBER, doc JSON)', (21, 0))
    _reject_unsupported_ddl_types('SELECT json_col FROM t WHERE flag = 1', (12, 1))


def test_reject_create_domain_raises_ora_901() -> None:
    from seerdb.server import BackendError

    # SQL domains are 23ai; the 11.2 Mirror's server doesn't know CREATE DOMAIN, so
    # it is refused with ORA-00901 — one of the codes the suite's SQL-domain guard
    # skips on (#512). A domain-referencing CREATE TABLE is not itself a domain
    # definition and passes this check.
    with pytest.raises(BackendError) as exc:
        _reject_unsupported_ddl_types('CREATE DOMAIN PYO_DOM_T AS NUMBER(3,0)', (12, 1))
    assert exc.value.ora_code == 901
    _reject_unsupported_ddl_types(
        'CREATE TABLE t (id NUMBER, d NUMBER DOMAIN PYO_DOM_T)', (12, 1)
    )


# --- PL/SQL routine translation (#503) — a pure function, no live PG needed -----


def test_constructor_items_name_each_whole_call() -> None:
    # A select item that is one call, aliased or not, by the name it calls; an
    # expression around a call, or a wildcard list, names nothing (#1473).
    from seerdb.server.backends.postgres import _constructor_items

    assert _constructor_items(
        'SELECT t_arr(5, 10), s.t_arr(1) AS c, n + f(1), x FROM dual'
    ) == {0: 't_arr', 1: 's.t_arr'}
    assert _constructor_items('SELECT * FROM t') == {}


# A standalone routine's default rights: its owner's (#1945).
_DEFINER = 'SECURITY DEFINER SET search_path FROM CURRENT '


def test_translate_routine_ddl_procedure() -> None:
    out = _translate_routine_ddl(
        'CREATE OR REPLACE PROCEDURE p '
        '(p_in IN NUMBER, p_out OUT NUMBER, p_io IN OUT VARCHAR2) '
        'AS BEGIN p_out := p_in * 2; END;'
    )
    # DROP-first so a changed signature can replace a prior definition (#521).
    assert out.startswith('DROP PROCEDURE IF EXISTS p; CREATE OR REPLACE PROCEDURE p(')
    assert 'p_in IN numeric' in out
    assert 'p_out OUT numeric' in out
    assert 'p_io INOUT varchar' in out  # IN OUT -> INOUT
    assert (
        'LANGUAGE plpgsql ' + _DEFINER + 'AS $$ BEGIN p_out := p_in * 2; END $$' in out
    )


def test_translate_routine_ddl_body_with_a_parenthesised_alias() -> None:
    # The parameter list ends at ITS closing parenthesis. A greedy match ran on
    # to the body's last `) AS` -- `count(*) AS cnt` -- and split the routine
    # there; a parameter's own parentheses (`NUMBER(5,2)`) stay inside it (#1467).
    out = _translate_routine_ddl(
        'CREATE OR REPLACE PROCEDURE p(n OUT NUMBER, m IN NUMBER(5,2)) AS '
        'BEGIN SELECT count(*) AS cnt INTO n FROM dual; END;',
        mark=False,
    )
    assert out == (
        'DROP PROCEDURE IF EXISTS p; CREATE OR REPLACE PROCEDURE '
        'p(n OUT numeric, m IN numeric(5,2)) LANGUAGE plpgsql AS $$ '
        'BEGIN SELECT count(*) AS cnt INTO n FROM dual; END $$'
    )


def test_translate_routine_ddl_function() -> None:
    out = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION f(p IN NUMBER) RETURN NUMBER '
        'AS BEGIN RETURN p + 100; END;'
    )
    assert out.startswith(
        'DROP FUNCTION IF EXISTS f; '
        'CREATE OR REPLACE FUNCTION f(p IN numeric) RETURNS numeric'
    )
    assert 'LANGUAGE plpgsql ' + _DEFINER + 'AS $$ BEGIN RETURN p + 100; END $$' in out


def test_translate_routine_ddl_parameterless_function() -> None:
    # Oracle lets a no-parameter routine omit the list entirely; PostgreSQL always
    # needs the parentheses, so an absent list becomes an empty one (#530). A body
    # containing its own parentheses still parses (params don't swallow the body).
    out = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION f RETURN BINARY_DOUBLE AS BEGIN RETURN 2.25; END;'
    )
    assert 'CREATE OR REPLACE FUNCTION f() RETURNS double precision' in out
    assert 'LANGUAGE plpgsql ' + _DEFINER + 'AS $$ BEGIN RETURN 2.25; END $$' in out
    withbody = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION g(x IN NUMBER) RETURN NUMBER '
        'AS BEGIN RETURN x * (x + 1); END;'
    )
    assert 'FUNCTION g(x IN numeric) RETURNS numeric' in withbody
    assert 'BEGIN RETURN x * (x + 1); END' in withbody


def test_translate_routine_ddl_maps_sys_refcursor_out() -> None:
    # A REF CURSOR OUT parameter (SYS_REFCURSOR) maps to PostgreSQL's refcursor; the
    # OPEN … FOR body is already valid PL/pgSQL (#518).
    out = _translate_routine_ddl(
        'CREATE OR REPLACE PROCEDURE seerdb_test_proc (p_rc OUT SYS_REFCURSOR) '
        'AS BEGIN OPEN p_rc FOR SELECT 1 AS a FROM dual; END;'
    )
    assert 'p_rc OUT refcursor' in out
    assert 'SYS_REFCURSOR' not in out
    assert 'OPEN p_rc FOR SELECT 1 AS a FROM dual' in out


def test_translate_routine_ddl_drops_before_create() -> None:
    # PostgreSQL cannot change an existing routine's OUT/return row type via CREATE
    # OR REPLACE; the suite reuses one name with different signatures, so a DROP …
    # IF EXISTS by name precedes every CREATE (#521).
    proc = _translate_routine_ddl(
        'CREATE OR REPLACE PROCEDURE seerdb_test_proc (p OUT TIMESTAMP) '
        'AS BEGIN p := SYSTIMESTAMP; END;'
    )
    assert proc.startswith(
        'DROP PROCEDURE IF EXISTS seerdb_test_proc; CREATE OR REPLACE'
    )
    func = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION seerdb_test_func(p IN NUMBER) RETURN NUMBER '
        'AS BEGIN RETURN p; END;'
    )
    assert func.startswith(
        'DROP FUNCTION IF EXISTS seerdb_test_func; CREATE OR REPLACE'
    )


def test_translate_routine_ddl_leaves_other_sql_unchanged() -> None:
    for sql in ('SELECT 1', 'CREATE TABLE t (id NUMBER)', 'BEGIN p(:1); END;'):
        assert _translate_routine_ddl(sql) == sql


def test_translate_routine_ddl_declares_a_bodys_locals() -> None:
    # A routine's locals go under DECLARE, their types mapped, PL/SQL's integer
    # types too; END loses the routine's name, which PL/pgSQL reads as a label;
    # NOCOPY goes (#1604). A CASE expression's END before an IF statement closes
    # the CASE, not an END IF.
    out = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION f(a NUMBER, b IN OUT NOCOPY VARCHAR2) '
        'RETURN NUMBER IS\n  t NUMBER;\n  i PLS_INTEGER;\n  s VARCHAR2(10);\n'
        'BEGIN\n  t := CASE WHEN a > 0 THEN 1 ELSE 2 END;\n'
        '  IF t > 1 THEN t := 3; END IF;\n  RETURN t;\nEND f;',
        mark=False,
    )
    assert out == (
        'DROP FUNCTION IF EXISTS f; CREATE OR REPLACE FUNCTION '
        'f(a numeric, b INOUT varchar) RETURNS numeric LANGUAGE plpgsql AS $$ '
        'DECLARE t numeric;\n  i integer;\n  s varchar(10); BEGIN\n'
        '  t := CASE WHEN a > 0 THEN 1 ELSE 2 END;\n'
        '  IF t > 1 THEN t := 3; END IF;\n  RETURN t;\nEND $$'
    )
    # No locals: the body as it was, its END's name gone.
    assert _translate_routine_ddl(
        'CREATE PROCEDURE p IS BEGIN NULL; END p;', mark=False
    ) == (
        'DROP PROCEDURE IF EXISTS p; CREATE OR REPLACE PROCEDURE p() '
        'LANGUAGE plpgsql AS $$ BEGIN NULL; END $$'
    )


def test_editionable_is_accepted_in_a_create() -> None:
    # CREATE OR REPLACE EDITIONABLE PROCEDURE, as DDL tools write it, was a
    # syntax error, and so were a function, view and type (#2175). Oracle
    # takes EDITIONABLE and NONEDITIONABLE before the object; the Mirror has
    # no editions to give it, so blanks it out, every position kept.
    from seerdb.server.backends.postgres import _without_editionable

    assert _without_editionable('create or replace editionable view v') == (
        'create or replace             view v'
    )
    assert _without_editionable("select 'editionable view' from dual") == (
        "select 'editionable view' from dual"
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE OR REPLACE EDITIONABLE PROCEDURE e2175 AS BEGIN NULL; END;'
        )
        backend.execute(
            'CREATE NONEDITIONABLE FUNCTION f2175 RETURN NUMBER IS BEGIN RETURN 7; END;'
        )
        backend.execute(
            'CREATE OR REPLACE EDITIONABLE VIEW v2175 AS SELECT 1 a FROM dual'
        )
        try:
            assert backend.execute('SELECT f2175(), a FROM v2175').rows == [(7, 1)]
            backend.execute('BEGIN e2175; END;')
        finally:
            backend.execute('DROP VIEW v2175')
            backend.execute('DROP FUNCTION f2175')
            backend.execute('DROP PROCEDURE e2175')
    finally:
        backend.close()


def test_a_routine_with_locals_compiles_and_runs() -> None:
    # It compiled with a warning and never existed (#1604). The value is 23ai's.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        result = backend.execute(
            'CREATE OR REPLACE FUNCTION f1604 (a NUMBER) RETURN NUMBER IS\n'
            '  t NUMBER;\n  i PLS_INTEGER := 2;\nBEGIN\n'
            '  t := a * i;\n  RETURN t + 1;\nEND f1604;'
        )
        assert not result.compilation_warning
        (row,) = backend.execute('SELECT f1604(20) FROM dual').rows
        assert row[0] == 41
    finally:
        try:
            backend.execute('DROP FUNCTION f1604')
        except Exception:
            backend.rollback()


def test_a_packages_members_are_read_from_its_spec_and_body() -> None:
    # The routines a spec declares or a body defines, overloads too; its types
    # and variables passed over, and a ; or an END inside a string or a comment
    # read as nothing (#1605); a type's declaration too (#1607). An
    # initialization section is not read.
    from seerdb.server.backends.postgres import _package_members

    spec = (
        'CREATE PACKAGE pk AS\n  TYPE t IS TABLE OF NUMBER INDEX BY PLS_INTEGER;\n'
        '  FUNCTION f(a NUMBER) RETURN NUMBER;\n  FUNCTION f(a VARCHAR2) RETURN VARCHAR2;'
        '\n  PROCEDURE p;\nEND pk;'
    )
    members = _present(_package_members(spec, spec.index(' AS') + 3))
    assert [(m.kind, m.name, m.params, m.returns, m.body) for m in members] == [
        ('TYPE', 't', None, None, 'TABLE OF NUMBER INDEX BY PLS_INTEGER'),
        ('FUNCTION', 'f', 'a NUMBER', 'NUMBER', None),
        ('FUNCTION', 'f', 'a VARCHAR2', 'VARCHAR2', None),
        ('PROCEDURE', 'p', None, None, None),
    ]
    body = (
        'CREATE PACKAGE BODY pk IS\n  g NUMBER := 1; -- not END; a comment\n'
        '  FUNCTION f(a NUMBER) RETURN NUMBER IS\n    t NUMBER;\n  BEGIN\n'
        '    t := CASE WHEN a > 0 THEN 1 END;\n    RETURN t;\n  END f;\n'
        '  PROCEDURE p IS BEGIN NULL; END;\nEND;'
    )
    members = _present(_package_members(body, body.index(' IS') + 3))
    assert [(m.name, m.body) for m in members if m.kind != 'TYPE'] == [
        (
            'f',
            '\n    t NUMBER;\n  BEGIN\n    t := CASE WHEN a > 0 THEN 1 END;\n'
            '    RETURN t;\n  END',
        ),
        ('p', ' BEGIN NULL; END'),
    ]
    assert members[0].body is not None
    initialized = (
        'CREATE PACKAGE BODY pk AS PROCEDURE p IS BEGIN NULL; END; BEGIN NULL; END;'
    )
    assert _package_members(initialized, initialized.index(' AS') + 3) is None


def test_a_package_type_is_a_postgresql_type_of_its_schema() -> None:
    # A record a composite; an index-by table a composite of its keys and its
    # values, keyed by text when indexed by a string, with its methods (the
    # index-by tables' own test runs them); a VARRAY or nested table a
    # domain over an array with its constructors; a REF CURSOR and a SUBTYPE
    # domains (#1607).
    from seerdb.server.backends.postgres import _package_type, _PackageMember

    def declare(kind: str, name: str, definition: str) -> str | None:
        return _package_type('pk', _PackageMember(kind, name, None, None, definition))

    assert declare(
        'TYPE',
        'r',
        'RECORD (n NUMBER NOT NULL := 0, s VARCHAR2(30), b BOOLEAN, '
        'i PLS_INTEGER, d DATE)',
    ) == (
        'CREATE TYPE pk.r AS (n numeric, s varchar(30), b BOOLEAN, i integer, '
        'd ora_date)'
    )
    indexed = declare('TYPE', 't', 'TABLE OF VARCHAR2(100) INDEX BY BINARY_INTEGER')
    assert indexed is not None and indexed.startswith(
        'CREATE TYPE pk.t AS (keys integer[], vals varchar(100)[]); '
        'CREATE FUNCTION pk.t$get(pk.t, integer) RETURNS varchar(100) '
    )
    indexed = declare('TYPE', 'p', 'TABLE OF VARCHAR2(64) INDEX BY VARCHAR2(64)')
    assert indexed is not None and indexed.startswith(
        'CREATE TYPE pk.p AS (keys text[], vals varchar(64)[]); '
        'CREATE FUNCTION pk.p$get(pk.p, text) RETURNS varchar(64) '
    )
    indexed = declare('TYPE', 'a', 'TABLE OF r INDEX BY PLS_INTEGER')
    assert indexed is not None and indexed.startswith(
        'CREATE TYPE pk.a AS (keys integer[], vals r[]); '
        'CREATE FUNCTION pk.a$get(pk.a, integer) RETURNS r '
    )
    varray = declare('TYPE', 'v', 'VARRAY(3) OF NUMBER')
    assert varray is not None and varray.startswith(
        'CREATE DOMAIN pk.v AS numeric[] CHECK '
        '(VALUE IS NULL OR array_length(VALUE, 1) <= 3); '
        'CREATE OR REPLACE FUNCTION pk.v(VARIADIC numeric[])'
    )
    nested = declare('TYPE', 'n', 'TABLE OF NUMBER')
    assert nested is not None and nested.startswith('CREATE DOMAIN pk.n AS numeric[]; ')
    assert declare('TYPE', 'c', 'REF CURSOR') == 'CREATE DOMAIN pk.c AS refcursor'
    assert declare('SUBTYPE', 'w', 'TestTempTable%ROWTYPE') == (
        'CREATE DOMAIN pk.w AS TestTempTable'
    )
    assert declare('TYPE', 'x', 'OBJECT (a NUMBER)') is None


def test_a_package_declares_types_its_routines_use() -> None:
    # A spec whose routines use its types compiles, and a body builds and reads
    # a record; each type is recorded as it was declared -- an NVARCHAR2
    # element stays one (#1607).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE OR REPLACE PACKAGE pt1607 AS\n'
            '  TYPE r IS RECORD (n NUMBER, s VARCHAR2(30), b BOOLEAN);\n'
            '  TYPE t IS TABLE OF NVARCHAR2(10) INDEX BY BINARY_INTEGER;\n'
            '  FUNCTION f(a NUMBER) RETURN NUMBER;\n'
            '  FUNCTION g(a t) RETURN NUMBER;\nEND;'
        )
        backend.execute(
            'CREATE OR REPLACE PACKAGE BODY pt1607 AS\n'
            '  FUNCTION f(a NUMBER) RETURN NUMBER IS\n    v r;\n  BEGIN\n'
            "    v.n := a * 2;\n    v.s := 'x';\n    v.b := TRUE;\n"
            '    RETURN v.n;\n  END;\n'
            '  FUNCTION g(a t) RETURN NUMBER IS BEGIN RETURN 0; END;\nEND;'
        )
        assert backend.execute(
            "SELECT spec, body FROM sys.ora_packages WHERE name = 'pt1607'"
        ).rows == [('VALID', 'VALID')]
        (row,) = backend.execute('SELECT pt1607.f(21) FROM dual').rows
        assert row[0] == 42
        assert backend.execute(
            'SELECT name, declaration FROM sys.ora_plsql_types '
            "WHERE package = 'pt1607' ORDER BY ord"
        ).rows == [
            ('R', 'TYPE RECORD (n NUMBER, s VARCHAR2(30), b BOOLEAN)'),
            ('T', 'TYPE TABLE OF NVARCHAR2(10) INDEX BY BINARY_INTEGER'),
        ]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP PACKAGE pt1607')
        except Exception:
            backend.rollback()


def test_package_ddl_is_a_schema_of_its_routines() -> None:
    # A spec is a schema of stand-ins, a body its routines in their place, each
    # resolving names as its creator's session did, the package first (#1605).
    from seerdb.server.backends.postgres import _translate_package_ddl

    spec = _translate_package_ddl(
        'CREATE OR REPLACE PACKAGE pyo.pk AS FUNCTION f(a NUMBER) RETURN NUMBER; END;'
    )
    assert 'DROP SCHEMA IF EXISTS pk CASCADE; CREATE SCHEMA pk; ' in spec
    assert (
        'CREATE OR REPLACE FUNCTION pk.f(a numeric) RETURNS numeric LANGUAGE '
        "plpgsql AS $$ BEGIN PERFORM sys.ora_package_unusable('pk'); END $$"
    ) in spec
    # The stand-ins are kept with the package's search path, as they name its
    # types (#1607).
    assert (
        "VALUES ('pk', 'PYO', $stubs$SELECT set_config('search_path', 'pk, ' || "
        "current_setting('search_path'), true); CREATE OR REPLACE FUNCTION pk.f("
    ) in spec
    body = _translate_package_ddl(
        'CREATE OR REPLACE PACKAGE BODY pyo.pk AS\n'
        '  FUNCTION f(a NUMBER) RETURN NUMBER IS BEGIN RETURN a; END f;\nEND pk;'
    )
    assert (
        "SELECT set_config('search_path', 'pk, ' || "
        "current_setting('search_path'), true); "
        "DELETE FROM sys.ora_plsql_types WHERE package = 'pk' AND NOT public; "
        'CREATE OR REPLACE FUNCTION pk.f(a numeric) RETURNS numeric LANGUAGE '
        'plpgsql SET search_path FROM CURRENT AS $$ BEGIN RETURN a; END $$; '
        + _package_rights('pk')
        + "; UPDATE sys.ora_packages SET body = 'VALID' WHERE name = 'pk'"
    ) in body
    assert 'DROP FUNCTION IF EXISTS' not in body  # members may share a name
    assert _translate_package_ddl('DROP PACKAGE pk').endswith(
        "DROP SCHEMA pk CASCADE; DELETE FROM sys.ora_packages WHERE name = 'pk'; "
        "DELETE FROM sys.ora_plsql_types WHERE package = 'pk'"
    )
    assert _translate_package_ddl('SELECT 1 FROM dual') == 'SELECT 1 FROM dual'


def test_the_dictionary_lists_a_package_and_its_members() -> None:
    # USER_OBJECTS has a package's spec and body; USER_PROCEDURES the package
    # and the routines its spec declares, overloads numbered, a private one not
    # listed; a package's schema is no user. The rows are 23ai's (#1605).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE OR REPLACE PACKAGE pd1605 AS\n'
            '  FUNCTION f(a NUMBER) RETURN NUMBER;\n'
            '  PROCEDURE p(a NUMBER, b OUT NUMBER);\n'
            '  FUNCTION f(a VARCHAR2) RETURN VARCHAR2;\nEND;'
        )
        listed = (
            'SELECT object_name, object_type, status FROM user_objects '
            "WHERE object_name = 'PD1605' ORDER BY object_type"
        )
        assert backend.execute(listed).rows == [('PD1605', 'PACKAGE', 'VALID')]
        backend.execute(
            'CREATE OR REPLACE PACKAGE BODY pd1605 AS\n'
            '  FUNCTION helper(a NUMBER) RETURN NUMBER IS BEGIN RETURN a; END;\n'
            '  FUNCTION f(a NUMBER) RETURN NUMBER IS BEGIN RETURN helper(a); END;\n'
            '  PROCEDURE p(a NUMBER, b OUT NUMBER) IS BEGIN b := a; END;\n'
            '  FUNCTION f(a VARCHAR2) RETURN VARCHAR2 IS BEGIN RETURN a; END;\nEND;'
        )
        assert backend.execute(listed).rows == [
            ('PD1605', 'PACKAGE', 'VALID'),
            ('PD1605', 'PACKAGE BODY', 'VALID'),
        ]
        assert backend.execute(
            'SELECT object_name, procedure_name, overload, object_type '
            "FROM user_procedures WHERE object_name = 'PD1605' "
            'ORDER BY procedure_name, overload'
        ).rows == [
            ('PD1605', 'F', '1', 'PACKAGE'),
            ('PD1605', 'F', '2', 'PACKAGE'),
            ('PD1605', 'P', None, 'PACKAGE'),
            ('PD1605', None, None, 'PACKAGE'),
        ]
        assert not backend.execute(
            "SELECT 1 FROM all_users WHERE username = 'PD1605'"
        ).rows
    finally:
        backend.rollback()
        try:
            backend.execute('DROP PACKAGE pd1605')
        except Exception:
            backend.rollback()


def test_a_package_is_created_called_and_dropped_as_oracle_does() -> None:
    # Through the Mirror and a client: overloads and an OUT procedure called by
    # package.member, and every refusal measured on 23ai (#1605) -- a spec with
    # no body ORA-04067, a body that does not compile a warning and then
    # ORA-04063, a dropped package PLS-00201, dropping it again ORA-04043.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute(
            'CREATE OR REPLACE PACKAGE pyo.pk1605 AS\n'
            '  FUNCTION f(a NUMBER) RETURN NUMBER;\n'
            '  FUNCTION f(a VARCHAR2) RETURN VARCHAR2;\n'
            '  PROCEDURE p(a NUMBER, b OUT NUMBER);\nEND;'
        )
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            cur.callfunc('pk1605.f', int, [1])
        assert 'ORA-04067: not executed, package body "PYO.PK1605" does not exist' in (
            str(excinfo.value)
        )
        cur.execute(
            'CREATE OR REPLACE PACKAGE BODY pyo.pk1605 AS\n'
            '  FUNCTION helper(a NUMBER) RETURN NUMBER IS BEGIN RETURN a * 2; END;\n'
            '  FUNCTION f(a NUMBER) RETURN NUMBER IS\n    t NUMBER;\n  BEGIN\n'
            '    t := helper(a);\n    RETURN t + 1;\n  END f;\n'
            '  PROCEDURE p(a NUMBER, b OUT NUMBER) IS BEGIN b := a + 100; END;\n'
            "  FUNCTION f(a VARCHAR2) RETURN VARCHAR2 IS BEGIN RETURN a || '!'; END;\n"
            'END pk1605;'
        )
        assert cur.callfunc('pk1605.f', int, [1]) == 3
        assert cur.callfunc('pk1605.f', str, ['x']) == 'x!'
        out = cur.var(int)
        cur.callproc('pk1605.p', [5, out])
        assert out.getvalue() == 105
        cur.execute(
            'CREATE OR REPLACE PACKAGE BODY pyo.pk1605 AS\n'
            '  FUNCTION f(a NUMBER) RETURN NUMBER IS BEGIN RETURN a; END;\n'
            '  PROCEDURE p(a NUMBER, b OUT no_such_type) IS BEGIN NULL; END;\n'
            '  FUNCTION f(a VARCHAR2) RETURN VARCHAR2 IS BEGIN RETURN a; END;\nEND;'
        )
        assert cur.warning is not None
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            cur.callfunc('pk1605.f', int, [1])
        assert 'ORA-04063: package body "PYO.PK1605" has errors' in str(excinfo.value)
        cur.execute('DROP PACKAGE pk1605')
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            cur.callfunc('pk1605.f', int, [1])
        assert "PLS-00201: identifier 'PK1605.F' must be declared" in str(excinfo.value)
        with pytest.raises(seerdb.DatabaseError) as excinfo:
            cur.execute('DROP PACKAGE pk1605')
        assert 'ORA-04043' in str(excinfo.value)
    finally:
        try:
            conn.cursor().execute('DROP PACKAGE pk1605')
        except Exception:
            pass
        conn.close()
        server.join(timeout=5)
        listen.close()
    assert result.get('error') is None, result.get('error')


# --- changepassword (#515) — credential-map only, no live PG needed -------------


class _NoConnPostgresBackend(PostgresBackend):
    # Skip the psycopg connect / orafce setup — change_password only touches the
    # credential map, so no live PostgreSQL is needed to test it.
    def __init__(self, credentials: dict) -> None:
        from seerdb.server.accounts import _AccountStore

        self._credentials = credentials
        self._accounts = _AccountStore(credentials, None)


def test_change_password_updates_the_shared_credential_map() -> None:

    creds = {'PYO': 'pyo123'}
    backend = _NoConnPostgresBackend(creds)
    backend.change_password('PYO', 'pyo123', 'pyo123_new')
    # The shared map now carries the new secret (a fresh session authenticates
    # with it); the backend's own PostgreSQL conninfo is untouched.
    assert creds['PYO'] == 'pyo123_new'
    # Case-insensitive on the username, like Oracle.
    backend.change_password('pyo', 'pyo123_new', 'again')
    assert creds['PYO'] == 'again'


class _RecordingConn:
    closed = False  # a live connection, as the backend's calls check (#1367)

    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, statement: str) -> None:
        self.calls.append(statement)

    def commit(self) -> None:
        self.calls.append('<commit>')

    def rollback(self) -> None:
        self.calls.append('<rollback>')

    def end_own_transaction(self) -> None:
        pass  # no transaction begun in a pipeline to end (#1915)


class _RecordingPostgresBackend(PostgresBackend):
    # Just a connection that records what reaches it.
    def __init__(self) -> None:
        self.recording = _RecordingConn()
        self._conn = cast(Any, self.recording)
        self._sql_dialect = 'oracle'
        self._reporting = False


def test_transaction_control_runs_outside_the_statement_savepoint() -> None:
    # COMMIT / ROLLBACK end the transaction and SAVEPOINT must outlive the
    # statement, so none of them may sit inside `_mirror_stmt` (#1181).
    backend = _RecordingPostgresBackend()
    for statement in ('COMMIT', 'commit work', 'ROLLBACK', '-- done\nROLLBACK WORK'):
        backend.execute(statement)
    backend.execute('SAVEPOINT sp1')
    assert backend.recording.calls == [
        '<commit>',
        '<commit>',
        '<rollback>',
        '<rollback>',
        'SAVEPOINT sp1',
    ]


def test_rollback_to_a_savepoint_is_guarded_but_not_released() -> None:
    # Under `_mirror_stmt`, so an unknown name fails without aborting the
    # transaction; no RELEASE after, as rolling back to the older savepoint
    # destroyed it (#1181).
    backend = _RecordingPostgresBackend()
    backend.execute('ROLLBACK WORK TO SAVEPOINT sp1')
    backend.execute('rollback to "Sp2"')
    assert backend.recording.calls == [
        'SAVEPOINT _mirror_stmt',
        'ROLLBACK TO SAVEPOINT sp1',
        'SAVEPOINT _mirror_stmt',
        'ROLLBACK TO SAVEPOINT "Sp2"',
    ]
    unknown = _backend_error(_FakePgError('3B001', 'savepoint "sp9" does not exist'))
    assert unknown.ora_code == 1086


def test_change_password_rejects_a_wrong_old_password() -> None:
    from seerdb.server import BackendError

    backend = _NoConnPostgresBackend({'PYO': 'pyo123'})
    with pytest.raises(BackendError) as exc:
        backend.change_password('PYO', 'not-the-old-one', 'whatever')
    assert exc.value.ora_code == 1017


def test_change_password_refuses_a_password_oracle_would() -> None:
    # Past 1024 bytes 23ai answers a change with ORA-28218, up to 1039 bytes
    # (#1713), and with ORA-01017 from 1040, as 11g does too; the stored
    # password stays as it was. 1024 bytes itself is taken (#1266).
    from seerdb.server import BackendError

    creds = {'PYO': 'pyo123'}
    backend = _NoConnPostgresBackend(creds)
    for password, code in (
        ('1' * 1500, 1017),
        ('1' * 1040, 1017),
        ('1' * 1039, 28218),
        ('\u00e9' * 513, 28218),  # 1026 bytes
    ):
        with pytest.raises(BackendError) as exc:
            backend.change_password('PYO', 'pyo123', password)
        assert exc.value.ora_code == code
        assert creds['PYO'] == 'pyo123'
    backend.change_password('PYO', 'pyo123', 'x' * 1024)
    assert creds['PYO'] == 'x' * 1024


# --- Bind translation (#516) — a pure function, no live PG needed --------------


def test_a_computed_date_describes_as_a_date() -> None:
    # SYSDATE, TO_DATE and a DATE literal are timestamp(0) values that report
    # the ora_date domain's base type, and described as a TIMESTAMP; sqlplus
    # then printed them with NLS_TIMESTAMP_FORMAT (#2058). A table's DATE
    # column was a DATE already, and its TIMESTAMP(0) column stays a TIMESTAMP.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        computed = backend.execute(
            "SELECT DATE '2024-05-06' a, TO_DATE('2024-05-06', 'YYYY-MM-DD') b, "
            "SYSDATE c, DATE '2024-05-06' + 1 d, LOCALTIMESTAMP e FROM dual"
        )
        assert [c.data_type for c in computed.columns] == [12, 12, 12, 12, 180]
        assert computed.rows[0][0] == datetime.datetime(2024, 5, 6)
        try:
            backend.execute('CREATE TABLE t_2058 (d DATE, t0 TIMESTAMP(0))')
            backend.execute('INSERT INTO t_2058 VALUES (SYSDATE, LOCALTIMESTAMP)')
            stored = backend.execute('SELECT d, t0 FROM t_2058')
            assert [c.data_type for c in stored.columns] == [12, 180]
        finally:
            backend.execute('DROP TABLE t_2058 PURGE')
    finally:
        backend.close()


def test_a_timestamp_literal_and_its_calls_describe_nine_digits() -> None:
    # Oracle describes a TIMESTAMP literal, TO_TIMESTAMP, TO_TIMESTAMP_TZ and
    # FROM_TZ with nine fractional digits, and SYSTIMESTAMP, LOCALTIMESTAMP and
    # a bare CAST with six; PostgreSQL keeps six at most, and every one
    # described with six, so sqlplus printed `.500000` for `.500000000`
    # (#2062). Measured against 23ai.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        result = backend.execute(
            "SELECT TIMESTAMP '2024-01-02 03:04:05.5' a, "
            "TIMESTAMP '2024-01-02 03:04:05.5 -05:30' AS b, "
            "TO_TIMESTAMP('2024', 'YYYY') c, "
            "FROM_TZ(TIMESTAMP '2024-01-02 03:04:05', '+01:00') d, "
            'SYSTIMESTAMP e, LOCALTIMESTAMP f, CAST(SYSDATE AS TIMESTAMP(3)) g '
            'FROM dual'
        )
        assert [c.scale for c in result.columns] == [9, 9, 9, 9, 6, 6, 3]
    finally:
        backend.close()


def test_nine_digit_items_are_whole_items_only() -> None:
    # A literal or call inside an expression is not the item; `*` expands.
    from seerdb.server.backends.postgres import _nine_digit_items

    assert _nine_digit_items(
        "select to_timestamp_tz(x, 'f') z, to_timestamp(x) + 1, y from t"
    ) == {0}
    assert _nine_digit_items("select timestamp '2024-01-02' from dual") == {0}
    assert _nine_digit_items("select *, timestamp '2024-01-02' from t") == set()
    assert _nine_digit_items('update t set x = 1') == set()


@pytest.mark.parametrize(
    ('sql', 'offset'),
    [
        ('  drop   table   nosuch_2074', 17),
        ('/* c */ select * from nosuch_2074', 22),
        ('-- x\nselect nosuch from dual', 12),
        ('\n\n  select 1 from nosuch_2074', 18),
        ('select * from nosuch_2074', 14),
    ],
)
def test_an_error_offset_counts_the_leading_text(sql: str, offset: int) -> None:
    # Oracle counts from the start of the statement as sent; the backend runs
    # it past its leading whitespace and comments, and counted from there
    # (#2074). The offsets are 18c's.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        with pytest.raises(BackendError) as raised:
            backend.execute(sql)
        assert raised.value.error_offset == offset
        if not sql.lstrip().lower().startswith('drop'):
            # A parse alone reports the same place.
            with pytest.raises(BackendError) as parsed:
                backend.parse(sql)
            assert parsed.value.error_offset == offset
    finally:
        backend.close()


def test_a_rowid_reads_dual_and_a_qualified_relation() -> None:
    # DUAL is a view, with no tableoid or ctid: its ROWID failed with
    # ORA-00904 where Oracle has a fixed one (#2059). A qualified ROWID left
    # its qualifier in front of the function, `t.sys.ora_rowid(...)`, which
    # PostgreSQL refused as a cross-database reference (#2082).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        dual = 'AAAACPAABAAAAABAAB'
        assert backend.execute('SELECT ROWID FROM dual').rows == [(dual,)]
        assert backend.execute('SELECT d.rowid, dummy FROM sys.dual d').rows == [
            (dual, 'X')
        ]
        assert backend.execute(
            "SELECT 'rowid' FROM dual WHERE ROWID IS NOT NULL"
        ).rows == [('rowid',)]
        try:
            backend.execute('CREATE TABLE t_2082 (a NUMBER)')
            backend.execute('INSERT INTO t_2082 VALUES (1)')
            [(plain,)] = backend.execute('SELECT ROWID FROM t_2082').rows
            for qualified in (
                'SELECT t.rowid FROM t_2082 t',
                'SELECT t_2082.rowid FROM t_2082',
                'SELECT pyo.t_2082.rowid FROM pyo.t_2082',
            ):
                assert backend.execute(qualified).rows == [(plain,)]
            # A ROWID from a table beside DUAL is the table's.
            assert backend.execute(
                'SELECT a FROM t_2082 WHERE ROWID = (SELECT ROWID FROM t_2082)'
            ).rows == [(1,)]
        finally:
            backend.execute('DROP TABLE t_2082 PURGE')
    finally:
        backend.close()


def test_a_refcursor_describes_its_columns_as_the_query_does() -> None:
    # A REF CURSOR's columns were described from the bare PostgreSQL types:
    # a CLOB, BLOB, DATE or NVARCHAR2 table column and a TO_CLOB item as a
    # VARCHAR2, RAW, TIMESTAMP or VARCHAR2, where the same query described
    # them right (#2071).
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_2071')
        cur.execute('create table t_2071 (c clob, b blob, d date, n nvarchar2(5))')
        cur.execute("insert into t_2071 values ('x', hextoraw('01'), sysdate, 'ab')")
        query = "select c, b, d, n, to_clob('y') tc, sysdate s from t_2071"
        cur.execute(query)
        plain = [d[1] for d in cur.description]
        rc = cur.var(seerdb.DB_TYPE_CURSOR)
        cur.execute(f'begin open :rc for {query}; end;', {'rc': rc})
        opened = rc.getvalue()
        through_cursor = [d[1] for d in opened.description]
        rows = opened.fetchall()
        first = rows[0][0].read()
        cur.execute('drop table t_2071')
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert plain == [
        seerdb.DB_TYPE_CLOB,
        seerdb.DB_TYPE_BLOB,
        seerdb.DB_TYPE_DATE,
        seerdb.DB_TYPE_NVARCHAR,
        seerdb.DB_TYPE_CLOB,
        seerdb.DB_TYPE_DATE,
    ]
    assert through_cursor == plain
    assert first == 'x'


def test_a_sql_statement_binds_each_occurrence() -> None:
    # Oracle binds a SQL statement's placeholders by position (#1714): with a
    # value for each occurrence, `:1` twice is two binds. One value a name, or
    # a PL/SQL block, binds by name as before.
    sql = 'insert into t values (:1, f(:1, :2, :3))'
    (renamed, rows) = _occurrence_binds(sql, [[4, 1626, 1627, 1628]])
    assert renamed.count(':1') == 1
    assert _translate_binds(renamed, rows[0])[1] == {
        'b1': 4,
        'seerdb_occ_14': 1626,
        'b2': 1627,
        'b3': 1628,
    }
    assert _occurrence_binds(sql, [[4, 1626, 1627]]) == (sql, [[4, 1626, 1627]])
    block = 'begin :a := :a + 1; end;'
    assert _occurrence_binds(block, [[1, 2]]) == (block, [[1, 2]])
    # The same value at each occurrence stays one bind, typed by its other use
    # (#15); in an executemany it splits where any row differs.
    predicate = 'select id from t where id = :x or :x is null'
    assert _occurrence_binds(predicate, [[1, 1]]) == (predicate, [[1]])
    assert _occurrence_binds(predicate, [[1, 1], [2, 3]])[0] != predicate


def test_a_repeat_before_another_name_keeps_the_values_in_place() -> None:
    # A repeat with its first's value stays one bind, and its value left the
    # rows with it: kept, it took the next name's place, and `:n` read 'x'
    # (#2066).
    sql = 'select :s || :s || :n || :s d from dual where :n = 7'
    (merged, rows) = _occurrence_binds(sql, [['x', 'x', 7, 'x', 7]])
    assert merged == sql
    assert rows == [['x', 7]]
    assert _translate_binds(merged, rows[0])[1] == {'s': 'x', 'n': 7}


def test_a_repeat_before_another_name_runs_through_the_mirror() -> None:
    # The client sends one value per occurrence, for the positional and the
    # named form alike; both failed with ORA-01722, `:n` reading 'x' (#2066).
    sql = 'select :s || :s || :n || :s d from dual where :n = 7'
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute(sql, ['x', 'x', 7, 'x', 7])
        positional = cur.fetchall()
        cur.execute(sql, {'s': 'x', 'n': 7})
        named = cur.fetchall()
        cur.execute(sql, ['x', 'y', 7, 'x', 7])
        differing = cur.fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        server.join(timeout=5)
        listen.close()

    assert result.get('error') is None, result.get('error')
    assert positional == named == [('xx7x',)]
    assert differing == [('xy7x',)]


def test_to_nchar_is_to_char_in_the_national_set() -> None:
    # TO_NCHAR did not exist (#2057). It converts as TO_CHAR does, and its
    # value is an NVARCHAR2 of the result's length: n characters, 2n bytes.
    # Measured on 18c.
    from seerdb.common.tns_consts import AL16UTF16_CHARSET

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        result = backend.execute(
            "SELECT TO_NCHAR('abc') a, TO_NCHAR(RPAD('n', 300, 'm')) b, "
            "TO_NCHAR(123.5, '0000.00') c, "
            "to_nchar(DATE '2024-05-06', 'YYYY-MM-DD') AS d FROM dual"
        )
        assert result.rows == [('abc', 'n' + 'm' * 299, ' 0123.50', '2024-05-06')]
        assert [
            (c.csfrm, c.charset, c.data_length, c.max_size) for c in result.columns
        ] == [
            (2, AL16UTF16_CHARSET, 6, 3),
            (2, AL16UTF16_CHARSET, 600, 300),
            (2, AL16UTF16_CHARSET, 16, 8),
            (2, AL16UTF16_CHARSET, 20, 10),
        ]
        # In a literal it is text, not the call.
        assert backend.execute("SELECT 'to_nchar(1)' FROM dual").rows == [
            ('to_nchar(1)',)
        ]
    finally:
        backend.close()


def test_concat_width_sums_the_operands_oracle_counts() -> None:
    # Oracle sizes a concatenation as its operands' sum (#2063): a bind by its
    # describe size, a literal by its bytes, CONCAT as `||`. A column or a
    # call counts nothing and leaves the item incomplete. Measured on 23ai.
    from seerdb.server.backends.postgres import _bind_describe_size, _concat_width

    assert [_bind_describe_size(n) for n in (4, 32, 33, 128, 1012, 2001, 4001)] == [
        32,
        32,
        128,
        128,
        2000,
        4000,
        8192,
    ]
    assert _bind_describe_size(40000) == 32767
    sizes = {'w': 2000, '1': 32}
    assert _concat_width(":w || '!' x", sizes) == (2001, True)
    assert _concat_width(':w', sizes) == (2000, True)
    assert _concat_width("'abc' || :w AS x", sizes) == (2003, True)
    assert _concat_width(':w || :w "X"', sizes) == (4000, True)
    assert _concat_width("concat(:w, '!')", sizes) == (2001, True)
    assert _concat_width("(:1 || 'é') || :1", sizes) == (66, True)
    assert _concat_width("'it''s'", sizes) == (4, True)
    assert _concat_width('dummy || :w x', sizes) == (2000, False)
    assert _concat_width("upper(:w) || 'x'", sizes) == (1, False)
    assert _concat_width(':w + 1', sizes) == (0, False)
    assert _concat_width(
        ':w || :w || :w || :w || :w || :w || :w || :w || :w || :w '
        '|| :w || :w || :w || :w || :w || :w || :w',
        sizes,
    ) == (32767, True)


def test_concat_takes_a_bind_and_reads_a_null_as_empty() -> None:
    # CONCAT(:v, 'xy') failed with ORA-00900: PostgreSQL's concat is variadic
    # "any", which an untyped parameter cannot resolve to (#2093). Oracle's
    # CONCAT is ||: a NULL operand reads as '', and only two NULLs are NULL,
    # where PostgreSQL's gave ''. A sqlplus VARCHAR2(253) bind describes as
    # 2001 wide, as `:v || 'xy'` does (#2063).
    from seerdb.server import VarcharValue

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        result = backend.execute(
            "SELECT CONCAT(:v, 'xy') a, CONCAT('x', :v) b, CONCAT(NULL, 'x') c, "
            "CONCAT(NULL, NULL) d, CONCAT(5, 'x') e FROM dual",
            [VarcharValue.of('abc', 1012)],
        )
        assert result.rows == [('abcxy', 'xabc', 'x', None, '5x')]
        assert [c.data_length for c in result.columns[:2]] == [2002, 2001]
        assert backend.execute("SELECT CONCAT(:v, 'xy') FROM dual", ['q']).rows == [
            ('qxy',)
        ]
    finally:
        backend.close()


def test_sys_context_takes_a_length() -> None:
    # SYS_CONTEXT(namespace, attribute, length) did not exist (#2116). On 23ai
    # the value is cut to the length, from 1 to 4000; another length is the
    # whole value, and a NULL one NULL.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        result = backend.execute(
            "SELECT sys_context('USERENV','SESSION_USER', 2) a, "
            "sys_context('USERENV','SESSION_USER', 0) b, "
            "sys_context('USERENV','SESSION_USER', 5000) c, "
            "sys_context('USERENV','SESSION_USER', NULL) d FROM dual"
        )
        assert result.rows == [('PY', 'PYO', 'PYO', None)]
    finally:
        backend.close()


def test_a_column_in_a_concatenation_counts_as_oracle_counts_it() -> None:
    # A column, or SYSDATE, concatenated described as its values' width
    # (#2147). Oracle counts what the column's type converts to: 40 for a
    # NUMBER or a TIMESTAMP, a VARCHAR2's length in bytes, 18 for a DATE, 73
    # for a TIMESTAMP WITH TIME ZONE. Measured on 23ai, `<operand> || 'x'`.
    from seerdb.server.backends.postgres import _from_tables

    assert _from_tables('select a from t x, s.u join v on 1 = 1 where 1 = 1') == [
        (None, 't', 'x'),
        ('s', 'u', None),
        (None, 'v', None),
    ]
    assert _from_tables('select a from (select 1 a from dual)') == []
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2147 (id NUMBER, p NUMBER(5), n VARCHAR2(7), d DATE, '
            'ts TIMESTAMP, tz TIMESTAMP WITH TIME ZONE, '
            'iym INTERVAL YEAR(4) TO MONTH, ids INTERVAL DAY TO SECOND, '
            'nb VARCHAR2(7 CHAR), bd BINARY_DOUBLE)'
        )
        try:
            for operand, width in (
                ('id', 41),
                ('p', 41),
                ('n', 8),
                ('d', 19),
                ('ts', 41),
                ('tz', 74),
                ('iym', 10),
                ('ids', 21),
                ('nb', 29),
                ('bd', 41),
                ('sysdate', 19),
                ('systimestamp', 74),
                ('n || n', 15),
                ('t2147.n', 8),
                ('x.n', 8),
            ):
                source = 't2147 x' if operand.startswith('x.') else 't2147'
                (column,) = backend.execute(
                    f"SELECT {operand} || 'x' a FROM {source}"
                ).columns
                assert column.data_length == width, operand
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2147')
    finally:
        backend.close()


def test_a_raw_in_a_concatenation_is_its_hex_text() -> None:
    # A RAW concatenated stayed bytes, `r || 'x'` the RAW b'\n\x1bx' (#2158):
    # PostgreSQL's || joins bytea, its untyped literal taking the RAW's type.
    # Measured on 23ai, r RAW(4) = 0A1B: the hex text, a VARCHAR2 counting
    # two characters a byte, as RAWTOHEX(r) is.
    from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
    from seerdb.server.backends.postgres import _concatenated_columns

    assert [
        parts
        for _f, _l, parts in _concatenated_columns(
            "SELECT a || 'x', concat(t.b, c), f(d) || e, 'g||h' FROM t"
        )
    ] == [['a'], ['t', 'b'], ['c'], ['e']]
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2158 (r RAW(4), v VARCHAR2(10))')
        try:
            backend.execute("INSERT INTO t2158 VALUES (hextoraw('0A1B'), 'ab')")
            for expression, width, value in (
                ("r || 'x'", 9, '0A1Bx'),
                ("'x' || r", 9, 'x0A1B'),
                ('r || r', 16, '0A1B0A1B'),
                ("concat(r, 'x')", 9, '0A1Bx'),
                ("concat(concat(r, 'a'), r)", 17, '0A1Ba0A1B'),
                ('x.r || v', 18, '0A1Bab'),
                ('rawtohex(r)', 8, '0A1B'),
                ("v || 'x'", 11, 'abx'),
            ):
                source = 't2158 x' if 'x.' in expression else 't2158'
                result = backend.execute(f'SELECT {expression} FROM {source}')
                (column,) = result.columns
                assert (column.data_type, column.data_length) == (
                    TNS_TYPE_VARCHAR,
                    width,
                ), expression
                assert result.rows == [(value,)], expression
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2158')
    finally:
        backend.close()


def test_sys_context_describes_as_oracle_sizes_it() -> None:
    # SYS_CONTEXT(ns, attr) is a VARCHAR2(256), and 4000 given a length,
    # whatever the length (#2109). It described as its value's width, so
    # sqlplus cut the column's heading to `SYS`. A concatenation adds it up
    # as any operand. Measured on 23ai and 11g.
    from seerdb.server.backends.postgres import _concat_width

    assert _concat_width("sys_context('USERENV','SESSION_USER')", {}) == (256, True)
    assert _concat_width("SYS_CONTEXT('USERENV', 'SESSION_USER', 10) x", {}) == (
        4000,
        True,
    )
    assert _concat_width("sys_context('USERENV','SESSION_USER') || 'x'", {}) == (
        257,
        True,
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        result = backend.execute(
            "SELECT sys_context('USERENV','SESSION_USER'), "
            "sys_context('USERENV','SESSION_USER') || 'x' c FROM dual"
        )
        assert result.rows == [('PYO', 'PYOx')]
        assert [c.data_length for c in result.columns] == [256, 257]
        assert result.columns[0].name == b"SYS_CONTEXT('USERENV','SESSION_USER')"
    finally:
        backend.close()


def test_a_number_in_a_concatenation_counts_as_oracle_counts_it() -> None:
    # A NUMBER bind concatenated described as its value's width, `5x` as 2,
    # where Oracle counts a NUMBER's 40 characters: 41 (#2140). A number
    # literal counts the digits Oracle prints for it. Measured on 23ai.
    import decimal

    from seerdb.server.backends.postgres import _concat_width

    assert _concat_width("123.45 || 'x'", {}) == (7, True)
    assert _concat_width("1.50 || 'x'", {}) == (4, True)
    assert _concat_width("5 || 'x'", {}) == (2, True)
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        for value in (5, 5.5, decimal.Decimal('12345.678')):
            result = backend.execute("SELECT :v || 'x' a FROM dual", [value])
            assert result.columns[0].data_length == 41, value
        result = backend.execute("SELECT 5 || 'x' a, 123.45 || 'x' b FROM dual")
        assert [c.data_length for c in result.columns] == [2, 7]
    finally:
        backend.close()


def test_a_concatenation_of_a_bind_describes_by_its_declared_size() -> None:
    # A concatenation over a bind described by its longest value, so sqlplus
    # printed `:w || '!'` under a 4-character heading where Oracle gives 2001
    # (#2063). A table's column still describes as declared.
    from seerdb.server import VarcharValue

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        result = backend.execute(
            "SELECT :w || '!' a, :w b, 'abc' || :w c, :w || :w d, dummy || :w e, "
            "'xy' f FROM dual",
            [VarcharValue.of('abc', 1012)],
        )
        assert result.rows == [('abc!', 'abc', 'abcabc', 'abcabc', 'Xabc', 'xy')]
        assert [c.data_length for c in result.columns] == [
            2001,
            2000,
            2003,
            4000,
            2000,
            2,
        ]
        # A bare value, as a backend caller other than the Mirror hands one,
        # still describes by the values.
        result = backend.execute("SELECT :w || '!' a FROM dual", ['abc'])
        assert [c.data_length for c in result.columns] == [4]
    finally:
        backend.close()


def test_a_nested_blocks_declarations_take_oracles_types() -> None:
    # A block nested in a block or a routine declared its variables in
    # Oracle's types as written: `type "number" does not exist` (#2182). Only
    # the outermost declarations were mapped. 23ai runs each of these; a
    # DECLARE in a comment or a string is no block.
    from seerdb.server.backends.postgres import _nested_declarations

    assert _nested_declarations(' x := 1; /* declare n number; begin */ END') == (
        ' x := 1; /* declare n number; begin */ END'
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('BEGIN DECLARE x NUMBER; BEGIN x := 1; END; END;')
        backend.execute(
            'BEGIN DECLARE x NUMBER; BEGIN DECLARE n PLS_INTEGER := 4; '
            'BEGIN x := n; END; END; END;'
        )
        backend.execute(
            'BEGIN FOR i IN 1..2 LOOP DECLARE t NUMBER := i * 10; '
            'BEGIN NULL; END; END LOOP; END;'
        )
        result = backend.execute(
            'CREATE OR REPLACE PROCEDURE n2182 (r OUT NUMBER) AS BEGIN '
            "DECLARE x NUMBER := 6; d DATE := DATE '2024-01-02'; "
            'BEGIN r := x * 7 + (d - d); END; END;'
        )
        try:
            assert not result.compilation_warning
            assert backend.execute(
                "SELECT status FROM user_objects WHERE object_name = 'N2182'"
            ).rows == [('VALID',)]
        finally:
            backend.execute('DROP PROCEDURE n2182')
    finally:
        backend.close()


def test_an_undeclared_name_is_pls_00201_with_its_statement_ignored() -> None:
    # A routine whose statement starts with a name no declaration gives -- a
    # bare call, an assignment to an undeclared variable -- lists PostgreSQL's
    # syntax error or `not a known variable` (#2121). 23ai lists PLS-00201 at
    # the name, then the statement it ignored, at the same place.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        for source, line, position, name in (
            ('begin nosuch; end;', 1, 26, 'NOSUCH'),
            ('begin nosuch(1); end;', 1, 26, 'NOSUCH'),
            ('begin x := 1; end;', 1, 26, 'X'),
            ('begin\n  null;\n  nosuch;\nend;', 3, 3, 'NOSUCH'),
        ):
            result = backend.execute(f'create or replace procedure p2121 as {source}')
            assert result.compilation_warning
            assert backend.execute(
                'SELECT sequence, line, position, text, message_number '
                "FROM user_errors WHERE name = 'P2121' ORDER BY sequence"
            ).rows == [
                (
                    1,
                    line,
                    position,
                    f"PLS-00201: identifier '{name}' must be declared",
                    201,
                ),
                (2, line, position, 'PL/SQL: Statement ignored', 0),
            ], source
    finally:
        try:
            backend.execute('drop procedure p2121')
        finally:
            backend.close()


def test_a_check_finds_what_a_routine_names_that_does_not_resolve() -> None:
    # plpgsql_check's errors as ALL_ERRORS lists 23ai's (#2129): each at its
    # name, after the routine's BEGIN, then the statement Oracle ignored, at
    # its start; an error whose name the source does not show is left.
    sql = (
        'create or replace procedure p as x number; '
        'begin x := length(1, 2); select nosuchcol into x from nosuchtab; end;'
    )
    assert _checked_error_rows(
        sql,
        [
            ('assignment', '42883', 'function length(integer, integer) does not exist'),
            ('SQL statement', '42703', 'column "nosuchcol" does not exist'),
            ('SQL statement', '42P01', 'relation "nosuchtab" does not exist'),
            ('assignment', '42703', 'column "elsewhere" does not exist'),
        ],
        frozenset({'length'}),
    ) == [
        (
            1,
            37,
            "PLS-00306: wrong number or types of arguments in call to 'LENGTH'",
            306,
        ),
        (1, 32, 'PL/SQL: Statement ignored', 0),
        (1, 58, 'PL/SQL: ORA-00904: "NOSUCHCOL": invalid identifier', 904),
        (1, 51, 'PL/SQL: SQL Statement ignored', 0),
        (1, 80, 'PL/SQL: ORA-00942: table or view does not exist', 942),
        (1, 51, 'PL/SQL: SQL Statement ignored', 0),
    ]


def test_a_routine_naming_what_does_not_resolve_is_created_invalid() -> None:
    # A routine whose body named an undeclared variable, an unknown column or
    # table, or a call no function takes compiled VALID: PL/pgSQL resolves
    # names only when it runs a statement (#2129). With plpgsql_check, 23ai's
    # ALL_ERRORS rows, positions from the routine's keyword on.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        if not backend._has_plpgsql_check():
            pytest.skip('the PostgreSQL bed has no plpgsql_check')
        for body, rows in (
            (
                'x := nosuch;',
                [
                    (1, 42, "PLS-00201: identifier 'NOSUCH' must be declared"),
                    (1, 37, 'PL/SQL: Statement ignored'),
                ],
            ),
            (
                'select nosuchcol into x from dual;',
                [
                    (1, 44, 'PL/SQL: ORA-00904: "NOSUCHCOL": invalid identifier'),
                    (1, 37, 'PL/SQL: SQL Statement ignored'),
                ],
            ),
            (
                'select count(*) into x from nosuchtab;',
                [
                    (1, 65, 'PL/SQL: ORA-00942: table or view does not exist'),
                    (1, 37, 'PL/SQL: SQL Statement ignored'),
                ],
            ),
            (
                'x := length(1, 2, 3);',
                [
                    (
                        1,
                        42,
                        "PLS-00306: wrong number or types of arguments in call to 'LENGTH'",
                    ),
                    (1, 37, 'PL/SQL: Statement ignored'),
                ],
            ),
            (
                'if y > 1 then null; end if;',
                [
                    (1, 40, "PLS-00201: identifier 'Y' must be declared"),
                    (1, 37, 'PL/SQL: Statement ignored'),
                ],
            ),
        ):
            result = backend.execute(
                f'create or replace procedure p2129a as x number; begin {body} end;'
            )
            assert result.compilation_warning, body
            assert backend.execute(
                "SELECT status FROM user_objects WHERE object_name = 'P2129A'"
            ).rows == [('INVALID',)], body
            assert (
                backend.execute(
                    "SELECT line, position, text FROM user_errors WHERE name = 'P2129A' "
                    'ORDER BY sequence'
                ).rows
                == rows
            ), body
        result = backend.execute(
            'create or replace procedure p2129a as x number; '
            "begin x := length('ab'); end;"
        )
        assert not result.compilation_warning
        assert backend.execute(
            "SELECT status FROM user_objects WHERE object_name = 'P2129A'"
        ).rows == [('VALID',)]
    finally:
        try:
            with contextlib.suppress(BackendError):  # none where it was skipped
                backend.execute('drop procedure p2129a')
        finally:
            backend.close()


def test_a_name_the_unit_declares_is_no_compile_error() -> None:
    # What plpgsql_check finds of a name the unit declares -- a collection
    # parameter's a(i), a.COUNT -- is the Mirror's translation, which Oracle
    # compiles: left, so nothing that works is made INVALID (#2212).
    sql = (
        'create or replace procedure p(a_array udt_objectarray) as n number; '
        'begin n := a_array.count; n := a_array(1); n := nosuch; end;'
    )
    assert [
        row[2]
        for row in _checked_error_rows(
            sql,
            [
                ('assignment', '42703', 'column "a_array" does not exist'),
                ('assignment', '42883', 'function a_array(integer) does not exist'),
                ('assignment', '42703', 'column "nosuch" does not exist'),
            ],
            frozenset(),
        )
    ] == [
        "PLS-00201: identifier 'NOSUCH' must be declared",
        'PL/SQL: Statement ignored',
    ]


def test_a_package_body_or_trigger_naming_what_does_not_resolve_is_invalid() -> None:
    # A package body or a trigger whose code named what does not resolve was
    # created VALID (#2212). 23ai's: the body INVALID, the spec VALID, its
    # errors placed from PACKAGE on, a call ORA-04063; the trigger INVALID but
    # ENABLED, its errors placed from its block on, a DML of its table
    # ORA-04098, and VALID again once it compiles.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))

    def errors(name: str) -> list:
        return backend.execute(
            'SELECT type, line, position, text FROM user_errors '
            f"WHERE name = '{name}' ORDER BY sequence"
        ).rows

    def status(name: str) -> list:
        return backend.execute(
            'SELECT object_type, status FROM user_objects '
            f"WHERE object_name = '{name}' ORDER BY 1"
        ).rows

    try:
        backend.authenticate('PYO')
        backend.open_session({})
        if not backend._has_plpgsql_check():
            pytest.skip('the PostgreSQL bed has no plpgsql_check')
        backend.execute('CREATE TABLE t2212 (a NUMBER, b NUMBER)')
        try:
            backend.execute(
                'create or replace package k2212 as '
                'function f(n number) return number; procedure p; end;'
            )
            result = backend.execute(
                'create or replace package body k2212 as\n'
                '  function f(n number) return number is\n'
                '  begin\n'
                '    return n * nosuch;\n'
                '  end;\n'
                '  procedure p is\n'
                '    x number;\n'
                '  begin\n'
                '    select nosuchcol into x from dual;\n'
                '  end;\n'
                'end;'
            )
            assert result.compilation_warning
            assert status('K2212') == [
                ('PACKAGE', 'VALID'),
                ('PACKAGE BODY', 'INVALID'),
            ]
            assert errors('K2212') == [
                (
                    'PACKAGE BODY',
                    4,
                    16,
                    "PLS-00201: identifier 'NOSUCH' must be declared",
                ),
                ('PACKAGE BODY', 4, 5, 'PL/SQL: Statement ignored'),
                (
                    'PACKAGE BODY',
                    9,
                    12,
                    'PL/SQL: ORA-00904: "NOSUCHCOL": invalid identifier',
                ),
                ('PACKAGE BODY', 9, 5, 'PL/SQL: SQL Statement ignored'),
            ]
            with pytest.raises(BackendError) as raised:
                backend.execute('SELECT k2212.f(1) FROM dual')
            assert raised.value.ora_code == 4063
            result = backend.execute(
                'create or replace trigger trg2212 before insert on t2212 for each row '
                'begin :new.b := nosuch; end;'
            )
            assert result.compilation_warning
            assert status('TRG2212') == [('TRIGGER', 'INVALID')]
            assert errors('TRG2212') == [
                ('TRIGGER', 1, 17, "PLS-00201: identifier 'NOSUCH' must be declared"),
                ('TRIGGER', 1, 7, 'PL/SQL: Statement ignored'),
            ]
            assert backend.execute(
                "SELECT status FROM user_triggers WHERE trigger_name = 'TRG2212'"
            ).rows == [('ENABLED',)]
            with pytest.raises(BackendError) as raised:
                backend.execute('INSERT INTO t2212 (a) VALUES (1)')
            assert (raised.value.ora_code, str(raised.value)) == (
                4098,
                "trigger 'PYO.TRG2212' is invalid and failed re-validation",
            )
            backend.execute(
                'create or replace trigger trg2212 before insert on t2212 for each row '
                'begin :new.b := 1; end;'
            )
            assert status('TRG2212') == [('TRIGGER', 'VALID')]
            backend.execute('INSERT INTO t2212 (a) VALUES (1)')
            assert backend.execute('SELECT b FROM t2212').rows == [(1,)]
        finally:
            backend.rollback()
            for leftover in ('PACKAGE k2212', 'TABLE t2212'):
                with contextlib.suppress(BackendError):
                    backend.execute(f'DROP {leftover}')
    finally:
        backend.close()


def test_a_not_null_violation_is_worded_and_placed_as_oracle_does() -> None:
    # A NOT NULL column given NULL carried PostgreSQL's text, no position, and
    # ORA-01400 for an UPDATE too (#2134). Oracle's, in every release, is
    # ORA-01400 for an INSERT, at the value that fills the column (0 when the
    # column list leaves it out), and ORA-01407 for an UPDATE, at the column
    # in SET. Measured on 23ai.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2134 (id NUMBER PRIMARY KEY, n VARCHAR2(3) NOT NULL, '
            'k NUMBER)'
        )
        try:
            backend.execute("INSERT INTO t2134 VALUES (1, 'a', 1)")
            inserted = 'cannot insert NULL into ("PYO"."T2134"."N")'
            updated = 'cannot update ("PYO"."T2134"."N") to NULL'
            for statement, code, text, offset in (
                ('insert into t2134 values (2, null, 1)', 1400, inserted, 29),
                (
                    'insert into t2134 (k, n, id) values (1, null, 5)',
                    1400,
                    inserted,
                    40,
                ),
                ('insert into t2134 (id, k) values (6, 1)', 1400, inserted, 0),
                ('insert into t2134 select 7, null, 1 from dual', 1400, inserted, 28),
                ('update t2134 set n = null where id = 1', 1407, updated, 17),
                ('update t2134 set k = 2, n = null', 1407, updated, 24),
            ):
                with pytest.raises(BackendError) as raised:
                    backend.execute(statement)
                assert (
                    raised.value.ora_code,
                    str(raised.value),
                    raised.value.error_offset,
                ) == (code, text, offset), statement
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2134')
    finally:
        backend.close()


def test_a_constant_too_long_fails_only_on_a_row_it_changes() -> None:
    # An UPDATE or INSERT ... SELECT that touched no row failed on a constant
    # or bind too long for its column: PostgreSQL coerces it as it plans,
    # where Oracle checks each row it changes (#2138). Measured on 23ai: every
    # statement here succeeds with 0 rows on the empty table, and fails once a
    # row is there to change.
    from decimal import Decimal

    from seerdb.server.backend import BackendError
    from seerdb.server.backends.postgres import _late_constants

    assert _late_constants("UPDATE t SET n = 'abcdef', k = k + 1 WHERE id = 1") == (
        "UPDATE t SET n = sys.ora_late('abcdef'), k = k + 1 WHERE id = 1"
    )
    assert _late_constants('INSERT INTO t (id, n) SELECT 1, :1 FROM dual') == (
        'INSERT INTO t (id, n) SELECT sys.ora_late(1), sys.ora_late(:1) FROM dual'
    )
    assert _late_constants("UPDATE t SET n = upper('x')") is None
    assert _late_constants("SELECT 'abcdef' FROM dual") is None
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2138 (id NUMBER, n VARCHAR2(3), k NUMBER(3))')
        try:
            cases: tuple[tuple[str, list[object], int], ...] = (
                ("update t2138 set n = 'abcdef'", [], 12899),
                ('update t2138 set k = 12345', [], 1438),
                ("update t2138 set n = 'abcdef' where id = 1", [], 12899),
                ('update t2138 set n = :1 where id = 1', ['abcdef'], 12899),
                ('update t2138 set k = :1', [Decimal('12345.5')], 1438),
            )
            for statement, binds, _code in cases:
                assert backend.execute(statement, binds).rowcount == 0, statement
            assert (
                backend.execute(
                    "insert into t2138 (id, n) select 1, 'abcdef' from dual where 1 = 0"
                ).rowcount
                == 0
            )
            backend.execute("INSERT INTO t2138 VALUES (1, 'a', 1)")
            for statement, binds, code in cases:
                with pytest.raises(BackendError) as raised:
                    backend.execute(statement, binds)
                assert raised.value.ora_code == code, statement
            assert backend.execute("update t2138 set n = 'xy'").rowcount == 1
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2138')
    finally:
        backend.close()


def test_translate_binds_repeated_named_bind_is_one_value() -> None:
    # `:x` twice is one Oracle value → one psycopg parameter reused, not two.
    sql, params = _translate_binds('SELECT id FROM t WHERE id = :x OR :x IS NULL', [1])
    assert sql == 'SELECT id FROM t WHERE id = %(x)s OR %(x)s IS NULL'
    assert params == {'x': 1}


def test_translate_binds_skips_colon_inside_string_literal() -> None:
    sql, params = _translate_binds(
        "INSERT INTO t VALUES ('hello :not_a_bind ' || :v)", ['world']
    )
    assert sql == "INSERT INTO t VALUES ('hello :not_a_bind ' || %(v)s)"
    assert params == {'v': 'world'}


def test_translate_binds_positional_and_casts() -> None:
    # Positional :1/:2 map by order; a :: cast is left alone.
    sql, params = _translate_binds('INSERT INTO t VALUES (:1, :2)', [7, 'a'])
    assert sql == 'INSERT INTO t VALUES (%(b1)s, %(b2)s)'
    assert params == {'b1': 7, 'b2': 'a'}
    sql, params = _translate_binds('SELECT :a::text FROM t', ['x'])
    assert sql == 'SELECT %(a)s::text FROM t'
    assert params == {'a': 'x'}


def test_translate_binds_casts_a_typed_null() -> None:
    # A NULL bind arrives as a BindVar carrying the type the client declared,
    # and becomes a cast placeholder, so PostgreSQL can type it (#699). A type
    # with no PostgreSQL counterpart stays a bare placeholder.
    from seerdb.common.tns_consts import (
        TNS_TYPE_NUMBER,
        TNS_TYPE_REFCURSOR,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server.backend import BindVar

    sql, params = _translate_binds(
        'SELECT id FROM t WHERE CASE WHEN :foo IS NOT NULL THEN :foo ELSE d END = d',
        [BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22)],
    )
    assert sql == (
        'SELECT id FROM t WHERE CASE WHEN %(foo)s::numeric IS NOT NULL '
        'THEN %(foo)s::numeric ELSE d END = d'
    )
    assert params == {'foo': None}
    sql, params = _translate_binds(
        'SELECT :1 FROM t',
        [BindVar(value=None, tns_type=TNS_TYPE_REFCURSOR, max_size=1)],
    )
    assert sql == 'SELECT %(b1)s FROM t'
    assert params == {'b1': None}
    # A string type stays uncast too: an undeclared NULL travels as VARCHAR, and
    # `id = :x` on a NUMBER column has to keep letting PostgreSQL infer numeric.
    sql, params = _translate_binds(
        'SELECT id FROM t WHERE id = :x OR :x IS NULL',
        [BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=1)],
    )
    assert sql == 'SELECT id FROM t WHERE id = %(x)s OR %(x)s IS NULL'
    assert params == {'x': None}


def test_translate_binds_mixed_named_first_appearance_order() -> None:
    sql, params = _translate_binds(
        'SELECT * FROM t WHERE a = :x AND b = :y AND c = :x', [1, 2]
    )
    assert sql == 'SELECT * FROM t WHERE a = %(x)s AND b = %(y)s AND c = %(x)s'
    assert params == {'x': 1, 'y': 2}


# --- Anonymous PL/SQL blocks with binds (#517) — pure helpers, no live PG ------


def test_parse_out_assignments_recognises_assignment_blocks() -> None:
    # A pure OUT-assignment block → the (ref, expr) pairs; anything else → None.
    assert _parse_out_assignments(':y := 7 * 6') == [('y', '7 * 6')]
    assert _parse_out_assignments(":1 := 'x'; :2 := NULL; :3 := 'z'") == [
        ('1', "'x'"),
        ('2', 'NULL'),
        ('3', "'z'"),
    ]
    # A DML block is not an assignment block.
    assert _parse_out_assignments('INSERT INTO t VALUES (:x)') is None
    assert _parse_out_assignments('proc(:a, :b)') is None


def test_bind_names_first_appearance_order_skips_literals() -> None:
    from seerdb.server.backends.postgres import _bind_names

    assert _bind_names(':a := :b; :c := :a') == ['a', 'b', 'c']
    # A colon inside a string literal is not a bind ref.
    assert _bind_names("INSERT INTO t VALUES ('x :nope' || :v)") == ['v']


def test_masking_reads_the_text_as_the_tokenizer_does() -> None:
    # _mask_quoted on the shared tokenizer (#1693): the mask always gives the
    # text back exactly -- an unterminated literal used to gain a closing
    # quote it never had -- a q-literal is masked whole, prefix outside, and a
    # quoted bind name is masked as an identifier.
    from seerdb.server.backends.postgres import _mask_quoted, _unmask_quoted

    for sql in (
        "VALUES (1, 'open",
        'SELECT "open',
        "SELECT q'[it's :z]', NQ'!a'b!' FROM t -- don't",
        "x := 'a' /* 'b */ || :\"q x\" || N'n'",
    ):
        assert _unmask_quoted(*_mask_quoted(sql)) == sql
    assert _mask_quoted("SELECT q'[it's]' -- don't") == (
        "SELECT q'\x000\x00' -- don't",
        ["[it's]"],
    )
    assert _mask_quoted(':"q x" || N\'n\'') == (
        ':"\x000\x00" || N\'\x001\x00\'',
        ['q x', 'n'],
    )


def test_a_kept_reading_of_the_text_is_never_changed_by_its_caller() -> None:
    # The quoted-text mask and the bind names are kept per text, as a batch
    # reads them once per row (#1870): each caller gets a list of its own.
    from seerdb.server.backends.postgres import _bind_names, _mask_quoted

    sql = "INSERT INTO t VALUES (:a, 'x', :b)"
    _mask_quoted(sql)[1].append('changed')
    _bind_names(sql).append('changed')
    assert _mask_quoted(sql)[1] == ['x']
    assert _bind_names(sql) == ['a', 'b']


def test_block_words_are_the_tokenizers_words() -> None:
    # _words and _blank_plsql on the shared tokenizer (#1693): `$` and `#` are
    # part of a name, so `x$begin` hides no BEGIN; nothing inside a literal, a
    # quoted name or a comment is a word; a bind's name still is one.
    from seerdb.server.backends.postgres import _blank_plsql, _words

    text = 'x$begin := \'begin\'; /* begin */ "BEGIN" := obj#; :end := 1; BEGIN'
    assert [w for w, _s, _e in _words(text)] == ['X$BEGIN', 'OBJ#', 'END', 'BEGIN']
    assert [w for w, _s, _e in _words(text, text.index(';'))] == [
        'OBJ#',
        'END',
        'BEGIN',
    ]
    assert _blank_plsql("a := q'[x;y]' -- ;\n; b := 'open;") == (
        "a := q'     '     \n; b := '     "
    )


def test_a_routine_with_a_quoted_name_is_created_and_called() -> None:
    # CREATE PROCEDURE "MixedP" was a syntax error (#2176): the routine
    # translation read a name as letters and dots only. 23ai creates it as
    # MixedP, callable as "MixedP" from a block, from SQL and from another
    # routine, and lists it so.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE OR REPLACE PROCEDURE "Mixed2176" AS BEGIN NULL; END;')
        backend.execute(
            'CREATE OR REPLACE FUNCTION pyo."Fn2176" RETURN NUMBER IS BEGIN RETURN 5; END;'
        )
        backend.execute(
            'CREATE OR REPLACE PROCEDURE plain2176 AS BEGIN "Mixed2176"; END;'
        )
        try:
            backend.execute('BEGIN "Mixed2176"; END;')
            backend.execute('BEGIN plain2176; END;')
            assert backend.execute('SELECT "Fn2176"() FROM dual').rows == [(5,)]
            assert backend.execute(
                'SELECT object_name, status FROM user_objects '
                "WHERE object_name IN ('Mixed2176', 'Fn2176', 'PLAIN2176') "
                'ORDER BY object_name'
            ).rows == [
                ('Fn2176', 'VALID'),
                ('Mixed2176', 'VALID'),
                ('PLAIN2176', 'VALID'),
            ]
        finally:
            backend.execute('DROP PROCEDURE plain2176')
            backend.execute('DROP FUNCTION pyo."Fn2176"')
            backend.execute('DROP PROCEDURE "Mixed2176"')
    finally:
        backend.close()


def test_a_routine_calls_a_routine_as_a_statement() -> None:
    # A stored routine whose body called a routine as a statement -- `callee;`,
    # `callee1(1);`, DBMS_OUTPUT.PUT_LINE -- compiled INVALID, PLS-00201 at the
    # call (#2180): PL/pgSQL wants CALL or PERFORM, which #1533 wrote for
    # blocks only. 23ai: all VALID, a procedure calling itself too, and a
    # package's members calling each other, the private ones among them.
    # An element assigned to is no call, whatever routine shares its name.
    from seerdb.server.backends.postgres import _perform_bare_calls

    assert _perform_bare_calls('a(1) := 2; a(1).n := 3; a(1); a;', {'a': 'p'}.get) == (
        'a(1) := 2; a(1).n := 3; CALL a(1); CALL a();'
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE OR REPLACE PROCEDURE callee2180 AS BEGIN NULL; END;')
        backend.execute(
            'CREATE OR REPLACE PROCEDURE callee2180a (a NUMBER) AS BEGIN NULL; END;'
        )
        try:
            for body in (
                'callee2180;',
                'callee2180();',
                'callee2180a(1);',
                "dbms_output.put_line('x');",
                'IF 1 = 0 THEN caller2180; END IF;',
            ):
                result = backend.execute(
                    f'CREATE OR REPLACE PROCEDURE caller2180 AS BEGIN {body} END;'
                )
                assert not result.compilation_warning, body
                backend.execute('BEGIN caller2180; END;')
            backend.execute(
                'CREATE OR REPLACE PACKAGE pk2180 AS PROCEDURE a; PROCEDURE b; END;'
            )
            result = backend.execute(
                'CREATE OR REPLACE PACKAGE BODY pk2180 AS '
                'PROCEDURE h IS BEGIN NULL; END; '
                "PROCEDURE a IS BEGIN h; callee2180; dbms_output.put_line('x'); END; "
                'PROCEDURE b IS BEGIN a; pk2180.a; END; END pk2180;'
            )
            assert not result.compilation_warning
            backend.execute('BEGIN pk2180.b; END;')
        finally:
            for unit in (
                'PACKAGE pk2180',
                'PROCEDURE caller2180',
                'PROCEDURE callee2180a',
                'PROCEDURE callee2180',
            ):
                backend.execute(f'DROP {unit}')
    finally:
        backend.close()


def test_statement_scanners_read_the_tokenizers_spans() -> None:
    # The statement-level scanners on the shared tokenizer (#1693): a bind
    # named like a keyword is no top-level keyword, a cast's type name is a
    # word, and `#` names are quoted past literals and comments alike.
    from seerdb.server.backends.postgres import (
        _perform_bare_calls,
        _quote_hash_identifiers,
        _top_level_words,
    )

    (words, rownums) = _top_level_words(
        "select :from, x::int, 'from' from t where (rownum < :order) -- order"
    )
    assert [w for _p, w in words] == ['SELECT', 'X', 'INT', 'FROM', 'T', 'WHERE']
    assert len(rownums) == 1
    assert _quote_hash_identifiers("select obj# /* x# */, 'y#' from t") == (
        'select "obj#" /* x# */, \'y#\' from t'
    )
    kinds = {'p': 'p', 'f': 'f', 'pkg.q': 'p'}.get
    assert _perform_bare_calls("p; f(1); pkg.q; x := 'p;'; -- p;\n", kinds) == (
        "CALL p(); PERFORM f(1); CALL pkg.q(); x := 'p;'; -- p;\n"
    )


def test_structure_is_read_past_literals_and_comments() -> None:
    # _matching_paren and _top_level_items on the shared tokenizer (#1695): a
    # parenthesis or comma inside a literal (escaped quotes included), a quoted
    # identifier or a comment is not structure, raw text or masked alike.
    from seerdb.server.backends.postgres import (
        _mask_quoted,
        _matching_paren,
        _top_level_items,
    )

    sql = "f('a (b', \"c)d\" /* ) */, 'it''s, x', g(1, 2)) -- )\n"
    assert _matching_paren(sql, 1) == sql.rindex(')', 0, sql.index('--'))
    items = _top_level_items(sql, 2, _matching_paren(sql, 1))
    assert [sql[a:b].strip() for a, b in items] == [
        "'a (b'",
        '"c)d" /* ) */',
        "'it''s, x'",
        'g(1, 2)',
    ]
    masked = _mask_quoted("select 'a', 'b' -- don't\n, c from t")[0]
    assert len(_top_level_items(masked, 7, masked.index(' from'))) == 3
    assert _matching_paren('f(1', 1) == 3


def test_calls_are_islands_in_the_token_stream() -> None:
    # The call layer (#1695): a call is found as a whole, unqualified word and
    # its `(`, outside literals and comments; its arguments split at top-level
    # commas only; the translators built on it leave literals and comments
    # alone.
    from seerdb.server.backends.postgres import (
        _calls,
        _rewrite_calls,
        _translate_decode,
        _translate_deref,
        _translate_rr_year,
    )

    sql = "f(a, 'f(x)') /* f(y) */ || pkg.f(1) || myf(2) || f (g(3), 4)"
    found = list(_calls(sql, frozenset({'F'}), '.'))
    assert [(c.start, [sql[a:b] for a, b in c.args]) for c in found] == [
        (0, ['a', " 'f(x)'"]),
        (sql.rindex('f ('), ['g(3)', ' 4']),
    ]
    assert _rewrite_calls(sql, frozenset({'F'}), lambda n, a: 'X', '.') == (
        'X /* f(y) */ || pkg.f(1) || myf(2) || X'
    )
    assert _translate_decode("select decode(x, 1, 'a(', /* , */ 'b') from t") == (
        "select CASE WHEN (x) IS NOT DISTINCT FROM (1) THEN 'a(' "
        "ELSE /* , */ 'b' END from t"
    )
    assert _translate_deref("select deref(r).n, 'deref(x)' from t") == (
        "select (sys.deref(r)).n, 'deref(x)' from t"
    )
    assert _translate_rr_year("select 1 -- to_char(d, 'RR')\n from t") == (
        "select 1 -- to_char(d, 'RR')\n from t"
    )
    # A call that never closes stops the search, to fail as it was sent.
    assert _translate_decode('select decode(a, b, c') == 'select decode(a, b, c'


def test_users_are_kept_by_create_alter_and_drop_user() -> None:
    # CREATE USER ... IDENTIFIED BY, ALTER USER ... IDENTIFIED BY [REPLACE] and
    # DROP USER [CASCADE] keep the Mirror's accounts as well as the schemas,
    # with Oracle's errors (#879). In the launcher's map, shared by sessions.
    from seerdb.server import BackendError

    creds = dict(_CREDS)
    backend = PostgresBackend(_CONNINFO, credentials=creds)
    other = PostgresBackend(_CONNINFO, credentials=creds)
    try:
        for statement in ('DROP USER u879 CASCADE', 'DROP USER "u879q" CASCADE'):
            try:
                backend.execute(statement)
            except BackendError:
                backend.rollback()  # not there yet
        backend.execute('CREATE USER u879 IDENTIFIED BY Secret879')
        assert other.authenticate('u879') == 'Secret879'  # case kept
        backend.execute('CREATE USER "u879q" IDENTIFIED BY "p w"')
        assert other.authenticate('u879q') == 'p w'
        with pytest.raises(BackendError) as exc:
            backend.execute('CREATE USER U879 IDENTIFIED BY x')
        assert exc.value.ora_code == 1920
        # A launcher's account with no schema yet is refused the same, and
        # given the schema an Oracle user always has.
        creds['ACCT879'] = 'a'
        with pytest.raises(BackendError) as exc:
            backend.execute('CREATE USER acct879 IDENTIFIED BY a')
        assert exc.value.ora_code == 1920
        backend.execute('CREATE TABLE acct879.t879 (n NUMBER)')
        backend.execute('DROP USER acct879 CASCADE')
        backend.execute('ALTER USER u879 IDENTIFIED BY again REPLACE Secret879')
        assert other.authenticate('U879') == 'again'
        with pytest.raises(BackendError) as exc:
            backend.execute('ALTER USER u879 IDENTIFIED BY x REPLACE wrong')
        assert exc.value.ora_code == 1017
        backend.execute('ALTER USER u879 ACCOUNT UNLOCK')  # accepted, nothing kept
        backend.execute('CREATE TABLE u879.t879 (n NUMBER)')
        with pytest.raises(BackendError) as exc:
            backend.execute('DROP USER u879')
        assert exc.value.ora_code == 1922
        backend.execute('DROP USER u879 CASCADE')
        assert other.authenticate('u879') is None
        with pytest.raises(BackendError) as exc:
            backend.execute('DROP USER u879')
        assert exc.value.ora_code == 1918
        with pytest.raises(BackendError) as exc:
            backend.execute('ALTER USER nobody879 IDENTIFIED BY x')
        assert exc.value.ora_code == 1918
    finally:
        backend.rollback()
        for statement in ('DROP USER u879 CASCADE', 'DROP USER "u879q" CASCADE'):
            try:
                backend.execute(statement)
            except BackendError:
                backend.rollback()
        backend.close()
        other.close()


def test_accounts_in_an_auth_database_are_out_of_sql_reach() -> None:
    # With an auth database the accounts live in seerdb_auth.accounts, owned by
    # the auth role: they survive the process's map, the launcher's accounts
    # seed it without overwriting a changed password, and a role without a
    # grant -- what a Mirror session should run as -- cannot read them (#879).

    admin = psycopg.connect(_CONNINFO, autocommit=True)
    dbname = admin.info.dbname
    auth = f'{_CONNINFO} user=mirror_auth879 password=auth879'
    try:
        admin.execute('DROP SCHEMA IF EXISTS seerdb_auth CASCADE')
        for role, password in (
            ('mirror_auth879', 'auth879'),
            ('mirror_plain879', 'plain879'),
        ):
            admin.execute(f'DROP ROLE IF EXISTS {role}')
            admin.execute(f"CREATE ROLE {role} LOGIN PASSWORD '{password}'")
        admin.execute(f'GRANT CREATE ON DATABASE "{dbname}" TO mirror_auth879')
        _ACCOUNTS_READY.discard(auth)
        backend = PostgresBackend(
            _CONNINFO, credentials={'PYO': 'pyo123', 'SEED879': 's'}, auth_conninfo=auth
        )
        try:
            assert backend.authenticate('seed879') == 's'
            backend.change_password('SEED879', 's', 'changed')
            backend.execute('CREATE USER db879 IDENTIFIED BY d')
        finally:
            backend.close()
        _ACCOUNTS_READY.discard(auth)  # as a new process would
        fresh = PostgresBackend(
            _CONNINFO, credentials={'PYO': 'pyo123', 'SEED879': 's'}, auth_conninfo=auth
        )
        try:
            assert fresh.authenticate('SEED879') == 'changed'
            assert fresh.authenticate('DB879') == 'd'
            fresh.execute('DROP USER db879')
            assert fresh.authenticate('DB879') is None
        finally:
            fresh.close()
        plain = psycopg.connect(f'{_CONNINFO} user=mirror_plain879 password=plain879')
        try:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                plain.execute('SELECT password FROM seerdb_auth.accounts')
        finally:
            plain.close()
    finally:
        admin.execute('DROP SCHEMA IF EXISTS seerdb_auth CASCADE')
        admin.execute(f'REVOKE CREATE ON DATABASE "{dbname}" FROM mirror_auth879')
        for role in ('mirror_auth879', 'mirror_plain879'):
            admin.execute(f'DROP ROLE IF EXISTS {role}')
        admin.close()


def test_plsql_pads_run_to_32767_and_sqls_stop_at_4000() -> None:
    # RPAD / LPAD stopped at 4000 characters in PL/SQL too, orafce's SQL limit
    # (#2061). Measured on 18c: 5000 in a PL/SQL assignment, ORA-06502 past
    # 32767, and 4000 in SQL.
    from seerdb.server.backend import BackendError, BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))

    def out(block: str, tns_type: int = 1):
        result = backend.execute(
            block, [BindVar(value=None, tns_type=tns_type, max_size=32767)]
        )
        return result.out_binds[0]

    try:
        backend.authenticate('PYO')
        backend.open_session({})
        assert len(out("BEGIN :v := RPAD('x', 5000, 'y'); END;")) == 5000
        assert len(out("BEGIN :v := lpad('x', 5000) || 'z'; END;")) == 5001
        assert (
            out(
                'DECLARE s VARCHAR2(32767); BEGIN '
                "s := RPAD('x', 6000, 'y'); :v := LENGTH(s); END;",
                2,
            )
            == 6000
        )
        with pytest.raises(BackendError) as raised:
            out("BEGIN :v := RPAD('x', 40000, 'y'); END;")
        assert raised.value.ora_code == 6502
        assert backend.execute(
            "SELECT LENGTH(RPAD('x', 5000, 'y')), 'rpad(' FROM dual"
        ).rows == [(4000, 'rpad(')]
    finally:
        backend.close()


def test_the_presented_release_is_per_backend() -> None:
    # A backend presents 12.1 or 23ai (#1704): its wire field version and
    # identity, V$VERSION and DBMS_UTILITY.DB_VERSION follow it -- two sessions
    # on one database each see their own -- and so do the types its DDL takes:
    # BOOLEAN is refused at 12.1, as 12.1 refuses it, and taken at 23ai.
    from seerdb.common.tns_consts import FIELD_VERSION_12_1, FIELD_VERSION_23_4
    from seerdb.server import BackendError

    with pytest.raises(ValueError):
        PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='19c')
    old = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    new = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        assert (old.field_version, new.field_version) == (
            FIELD_VERSION_12_1,
            FIELD_VERSION_23_4,
        )
        banner = 'SELECT banner FROM v$version WHERE ROWNUM = 1'
        assert old.execute(banner).rows[0][0].startswith('Oracle Database 12c')
        assert new.execute(banner).rows[0][0] == new.server_identity.banner.decode()
        assert 'PL/SQL Release 23.26.2.0.0 - Production' in [
            r[0] for r in new.execute('SELECT banner FROM v$version').rows
        ]
        with pytest.raises(BackendError) as exc:
            old.execute('CREATE TABLE b1704 (b BOOLEAN)')
        assert exc.value.ora_code == 902
        new.execute('CREATE TABLE b1704 (n NUMBER, b BOOLEAN)')
        new.execute('INSERT INTO b1704 VALUES (1, TRUE)')
        assert new.execute('SELECT n FROM b1704 WHERE b').rows == [(1,)]
    finally:
        for backend in (old, new):
            backend.rollback()
        try:
            new.execute('DROP TABLE b1704')
        except BackendError:
            new.rollback()
        old.close()
        new.close()


def test_a_boolean_is_23ais_boolean_and_stores_as_a_number() -> None:
    # Presenting 23ai, a boolean result describes as BOOLEAN and a bool bind
    # into a NUMBER column stores 1 or 0, as 23ai converts it (#1705);
    # presenting 12.1 it describes as the NUMBER 12.1 has.
    from seerdb.common.tns_consts import TNS_TYPE_BOOLEAN, TNS_TYPE_NUMBER
    from seerdb.server import BackendError

    old = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    new = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        result = new.execute('SELECT NOT :1 FROM dual', [True])
        assert result.columns[0].data_type == TNS_TYPE_BOOLEAN
        assert result.rows == [(False,)]
        assert old.execute('SELECT 1 = 1 FROM dual').columns[0].data_type == (
            TNS_TYPE_NUMBER
        )
        new.execute('CREATE TABLE n1705 (n NUMBER(9), s VARCHAR2(10))')
        new.execute('INSERT INTO n1705 VALUES (:1, :2)', [False, 'zero'])
        new.execute('INSERT INTO n1705 VALUES (:1, :2)', [True, 'one'])
        assert new.execute('SELECT n, s FROM n1705 ORDER BY n').rows == [
            (0, 'zero'),
            (1, 'one'),
        ]
    finally:
        for backend in (old, new):
            backend.rollback()
        try:
            new.execute('DROP TABLE n1705')
        except BackendError:
            new.rollback()
        old.close()
        new.close()


def test_json_columns_keep_osons_types_in_extended_form() -> None:
    # A JSON column is jsonb, described as 21c's native JSON when the backend
    # presents 23ai, and a document's DATE / TIMESTAMP / interval / NUMBER /
    # RAW values are kept in Oracle's extended JSON form and come back as the
    # types they went in as (#1706).
    import datetime
    import decimal

    from seerdb.common.datatypes import JSON, IntervalYM
    from seerdb.common.tns_consts import TNS_TYPE_JSON
    from seerdb.server import BackendError
    from seerdb.server.backends.postgres import _from_extended, _to_extended

    doc = {
        'when': datetime.datetime(2022, 12, 5, 15, 6, 5, 123000),
        'tz': datetime.datetime(2022, 12, 7, 22, 59, 15, tzinfo=datetime.timezone.utc),
        'day': datetime.date(2022, 12, 5),
        'price': decimal.Decimal('319438950232418390.273596'),
        'gap': datetime.timedelta(days=8, hours=12, seconds=1.5),
        'back': -datetime.timedelta(days=2),
        'ym': IntervalYM(8, 4),
        'raw': b'\x01\xff',
        'plain': [1, 2.5, 'x', None, True, {'k': []}],
    }
    extended = _to_extended(doc)
    assert isinstance(extended, dict)
    assert extended['price'] == {'$numberDecimal': '319438950232418390.273596'}
    assert extended['raw'] == {'$rawhex': '01FF'}
    assert extended['ym'] == {'$intervalYearMonth': 'P8Y4M'}
    back = _from_extended(extended)
    assert isinstance(back, dict)
    assert back['day'] == datetime.datetime(2022, 12, 5)  # a DATE, as OSON's
    # A WITH TIME ZONE value comes back naive in UTC, as a client decodes
    # OSON's (#1707).
    assert back['tz'] == datetime.datetime(2022, 12, 7, 22, 59, 15)
    assert {k: v for k, v in back.items() if k not in ('day', 'tz')} == {
        k: v for k, v in doc.items() if k not in ('day', 'tz')
    }
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        backend.execute('CREATE TABLE j1706 (n NUMBER, j JSON)')
        backend.execute('INSERT INTO j1706 VALUES (1, :1)', [JSON(doc)])
        result = backend.execute('SELECT j FROM j1706')
        assert result.columns[0].data_type == TNS_TYPE_JSON
        assert result.rows[0][0]['price'] == doc['price']
        assert result.rows[0][0]['gap'] == doc['gap']
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE j1706')
        except BackendError:
            backend.rollback()
        backend.close()


def test_storage_clauses_go_and_an_empty_lob_is_json_enough() -> None:
    # A JSON / LOB column's STORE AS clause is Oracle's storage, which
    # PostgreSQL decides itself, so it goes; and an IS JSON check lets an
    # empty LOB in, as Oracle's does (#1706).
    from seerdb.server import BackendError

    for statement in (
        'create table t (n number(9), j json) json (j) store as (compress high)',
        'create table t (n number, c clob) lob (c) store as securefile s (cache)',
        'create table t (n number, c clob, d blob) lob (c, d) store as basicfile',
    ):
        assert 'store' not in _translate_ddl(statement).lower()
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TABLE e1706 (n NUMBER, c CLOB CHECK (c IS JSON), '
            'b BLOB CHECK (b IS JSON))'
        )
        backend.execute('INSERT INTO e1706 VALUES (1, empty_clob(), empty_blob())')
        with pytest.raises(BackendError) as exc:
            backend.execute("INSERT INTO e1706 VALUES (2, 'not json', empty_blob())")
        assert exc.value.ora_code == 2290
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE e1706')
        except BackendError:
            backend.rollback()
        backend.close()


def test_an_oson_column_holds_the_document_and_hands_out_its_image() -> None:
    # A BLOB with an IS JSON FORMAT OSON check is the ora_oson domain over
    # jsonb (#1706): it takes JSON text, an OSON image as bytes or as a BLOB,
    # or a JSON bind, and describes as a BLOB flagged OSON whose value is the
    # document's OSON image.
    from seerdb.common.datatypes import JSON
    from seerdb.common.oson import decode_oson, encode_oson
    from seerdb.common.tns_consts import TNS_TYPE_BLOB
    from seerdb.server import BackendError
    from seerdb.server.backend import BlobValue

    assert 'ora_oson' in _translate_ddl(
        'create table t (n number, o blob, constraint c check (o is json format oson))'
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        backend.execute(
            'CREATE TABLE o1706 (n NUMBER, o BLOB, '
            'CONSTRAINT o1706_ck CHECK (o IS JSON FORMAT OSON))'
        )
        backend.execute("""INSERT INTO o1706 VALUES (1, '{"id": 1}')""")
        backend.execute(
            'INSERT INTO o1706 (n, o) VALUES (2, :2)', [encode_oson({'id': 2})]
        )
        backend.execute(
            'INSERT INTO o1706 VALUES (3, :1)', [BlobValue(encode_oson({'id': 3}))]
        )
        backend.execute('INSERT INTO o1706 VALUES (4, :1)', [JSON({'id': 4})])
        backend.execute('UPDATE o1706 SET o = :1 WHERE n = 4', [encode_oson({'id': 5})])
        result = backend.execute('SELECT n, o FROM o1706 ORDER BY n')
        column = result.columns[1]
        assert (column.data_type, column.is_oson) == (TNS_TYPE_BLOB, True)
        assert [decode_oson(r[1]) for r in result.rows] == [
            {'id': 1},
            {'id': 2},
            {'id': 3},
            {'id': 5},
        ]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE o1706')
        except BackendError:
            backend.rollback()
        backend.close()


def test_oracles_sql_json_over_jsonb() -> None:
    # JSON(x [EXTENDED]), JSON_SCALAR, JSON_QUERY, JSON_EXISTS, JSON_SERIALIZE
    # and dot notation into a JSON column, over jsonb (#1707). The answers are
    # the ones python-oracledb's suite expects of 23ai.
    import datetime

    from seerdb.common.datatypes import JSON, IntervalYM
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        (doc,) = backend.execute(
            """SELECT JSON('{"d": {"$oracleDate": "2022-12-05"}, """
            """"f": {"$numberFloat": 38.75}, "l": {"$numberLong": 9}, """
            """"z": {"$oracleTimestampTZ": "2022-12-07T22:59:15.1234Z"}}' """
            'EXTENDED) FROM dual'
        ).rows[0]
        assert doc == {
            'd': datetime.datetime(2022, 12, 5),
            'f': 38.75,
            'l': 9,
            'z': datetime.datetime(2022, 12, 7, 22, 59, 15, 123400),
        }
        (ym,) = backend.execute(
            "SELECT JSON(JSON_SCALAR(TO_YMINTERVAL('8-04'))) FROM dual"
        ).rows[0]
        assert ym == IntervalYM(8, 4)
        backend.execute('CREATE TABLE f1707 (n NUMBER, j JSON)')
        for n, value in enumerate(
            [{'a': 12.5}, {'employees': ['John', 'Matthew']}, {'Permanent': True}]
        ):
            backend.execute('INSERT INTO f1707 VALUES (:1, :2)', [n, JSON(value)])
        assert backend.execute(
            'SELECT JSON_SERIALIZE(j) FROM f1707 ORDER BY n'
        ).rows == [
            ('{"a":12.5}',),
            ('{"employees":["John","Matthew"]}',),
            ('{"Permanent":true}',),
        ]
        assert backend.execute(
            "SELECT COUNT(*) FROM f1707 WHERE JSON_EXISTS(j, '$.Permanent')"
        ).rows == [(1,)]
        assert backend.execute(
            "SELECT JSON_QUERY(j, '$.employees') FROM f1707 WHERE n = 1"
        ).rows == [(['John', 'Matthew'],)]
        assert backend.execute(
            'SELECT t.j.employees FROM f1707 t WHERE t.j.employees IS NOT NULL'
        ).rows == [(['John', 'Matthew'],)]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE f1707')
        except BackendError:
            backend.rollback()
        backend.close()


def test_vector_columns_on_pgvector() -> None:
    # VECTOR columns (#1708): FLOAT32 on pgvector's vector, FLOAT64 / INT8 as
    # float8[] / int2[], a flexible format in the ora_vector composite; each
    # value back as the array.array of its format, the describe's dimensions
    # and format the declaration's; a wrong count ORA-51803, an INT8 out of
    # range ORA-51806, as 23ai raises them.
    import array

    from seerdb.common.tns_consts import TNS_TYPE_VECTOR, VECTOR_FLAG_FLEXIBLE_DIM
    from seerdb.server import BackendError

    assert _translate_ddl(
        'create table t (a vector, b vector(2), c vector(*, int8), '
        'd vector(16, float32), e vector(16, float64))'
    ) == (
        'create table t (a ora_vector, b ora_vector, c int2[], d vector(16), '
        'e float8[] CHECK (sys.ora_vector_dims(e, 16)))'
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    try:
        backend.execute(
            'CREATE TABLE v1708 (n NUMBER, flex VECTOR, i8 VECTOR(*, INT8), '
            'f32 VECTOR(3, FLOAT32), f64 VECTOR(3, FLOAT64))'
        )
        d = array.array('d', [1.0000001, -2.5, 3.25])
        f = array.array('f', [1.5, 2.5, 3.5])
        b = array.array('b', [-3, 0, 127])
        backend.execute('INSERT INTO v1708 VALUES (1, :1, :2, :3, :4)', [d, b, f, d])
        backend.execute('INSERT INTO v1708 (n, flex) VALUES (2, :1)', [b])
        result = backend.execute('SELECT flex, i8, f32, f64 FROM v1708 ORDER BY n')
        assert [
            (c.data_type, c.vector_dimensions, c.vector_format, c.vector_flags)
            for c in result.columns
        ] == [
            (TNS_TYPE_VECTOR, 0, 0, VECTOR_FLAG_FLEXIBLE_DIM),
            (TNS_TYPE_VECTOR, 0, 4, VECTOR_FLAG_FLEXIBLE_DIM),
            (TNS_TYPE_VECTOR, 3, 2, 0),
            (TNS_TYPE_VECTOR, 3, 3, 0),
        ]
        (first, second) = result.rows
        assert [(v.typecode, list(v)) for v in first] == [
            ('d', list(d)),
            ('b', list(b)),
            ('f', list(f)),
            ('d', list(d)),
        ]
        assert second[0] == b  # a flexible column keeps each value's format
        (echo,) = backend.execute('SELECT :1 FROM dual', [b]).rows[0]
        assert echo == b and echo.typecode == 'b'
        for column, value, code in (
            ('f32', array.array('f', [1.0] * 4), 51803),
            ('f64', array.array('d', [1.0] * 2), 51803),
            ('i8', array.array('f', [-130.0, 1.0]), 51806),
        ):
            with pytest.raises(BackendError) as exc:
                backend.execute(
                    f'INSERT INTO v1708 (n, {column}) VALUES (3, :1)', [value]
                )
            assert exc.value.ora_code == code
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE v1708')
        except BackendError:
            backend.rollback()
        backend.close()


def test_sparse_vector_columns() -> None:
    # Sparse VECTOR columns (#1709), every one the ora_sparse_vector composite,
    # as pgvector's sparsevec drops a zero a client stored: each value back as
    # a SparseVector of the column's format, else its own; the describe flags
    # it sparse. A dense value into one keeps its non-zero elements, a sparse
    # one into a dense column fills its zeros in. The answers are 23ai's,
    # measured: an INT8 rounds half to even, an explicit zero is kept, indices
    # out of order are ORA-51822, past the count ORA-51836, inf ORA-51805.
    import array

    from seerdb.common.tns_consts import (
        TNS_TYPE_VECTOR,
        VECTOR_FLAG_FLEXIBLE_DIM,
        VECTOR_FLAG_SPARSE,
    )
    from seerdb.common.vector import SparseVector
    from seerdb.server import BackendError

    assert _translate_ddl(
        'create table t (a vector(4, float64, sparse), b vector(*, *, sparse))'
    ) == (
        'create table t (a ora_sparse_vector CHECK (sys.ora_sparse_check(a, 4, 3)), '
        'b ora_sparse_vector CHECK (sys.ora_sparse_check(b, NULL, NULL)))'
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    try:
        backend.execute(
            'CREATE TABLE s1709 (n NUMBER, fx VECTOR(*, *, SPARSE), '
            'i8 VECTOR(*, INT8, SPARSE), f64 VECTOR(4, FLOAT64, SPARSE), '
            'dense VECTOR(4, FLOAT64))'
        )
        value = SparseVector(4, [0, 1, 3], array.array('d', [2.5, 0.0, -2.5]))
        backend.execute('INSERT INTO s1709 VALUES (1, :1, :2, :3, :4)', [value] * 4)
        result = backend.execute('SELECT fx, i8, f64, dense FROM s1709')
        assert [
            (c.data_type, c.vector_dimensions, c.vector_format, c.vector_flags)
            for c in result.columns
        ] == [
            (TNS_TYPE_VECTOR, 0, 0, VECTOR_FLAG_FLEXIBLE_DIM | VECTOR_FLAG_SPARSE),
            (TNS_TYPE_VECTOR, 0, 4, VECTOR_FLAG_FLEXIBLE_DIM | VECTOR_FLAG_SPARSE),
            (TNS_TYPE_VECTOR, 4, 3, VECTOR_FLAG_SPARSE),
            (TNS_TYPE_VECTOR, 4, 3, 0),
        ]
        (fx, i8, f64, dense) = result.rows[0]
        assert fx == value and fx.values.typecode == 'd'
        assert i8 == SparseVector(4, [0, 1, 3], array.array('b', [2, 0, -2]))
        assert f64 == value
        assert dense == array.array('d', [2.5, 0.0, 0.0, -2.5])
        (echo,) = backend.execute('SELECT :1 FROM dual', [value]).rows[0]
        assert echo == value
        (resized,) = backend.execute(
            'SELECT TO_VECTOR(:1, 4, FLOAT32) FROM dual', [value]
        ).rows[0]
        assert resized == SparseVector(4, [0, 1, 3], array.array('f', [2.5, 0.0, -2.5]))
        # A dense value, a string and a literal into a sparse column.
        backend.execute('DELETE FROM s1709')
        backend.execute(
            'INSERT INTO s1709 (n, fx) VALUES (1, :1)', [array.array('b', [0, 3, 0])]
        )
        backend.execute(
            'INSERT INTO s1709 (n, fx) VALUES (2, :1)', ['[4, [1, 3], [1, 2]]']
        )
        backend.execute("INSERT INTO s1709 (n, fx) VALUES (3, '[4, [1, 3], [1.5, 2]]')")
        rows = [r[0] for r in backend.execute('SELECT fx FROM s1709 ORDER BY n').rows]
        assert rows == [
            SparseVector(3, [1], array.array('b', [3])),
            SparseVector(4, [1, 3], array.array('f', [1, 2])),
            SparseVector(4, [1, 3], array.array('f', [1.5, 2])),
        ]
        for column, bad, code in (
            ('fx', SparseVector(4, [3, 1], array.array('d', [1, 2])), 51822),
            ('fx', SparseVector(4, [7], array.array('d', [1])), 51836),
            ('f64', SparseVector(5, [1], array.array('d', [1])), 51803),
            ('i8', SparseVector(4, [1], array.array('f', [-130])), 51806),
            ('fx', SparseVector(4, [1], array.array('d', [float('inf')])), 51805),
        ):
            with pytest.raises(BackendError) as exc:
                backend.execute(
                    f'INSERT INTO s1709 (n, {column}) VALUES (9, :1)', [bad]
                )
            assert exc.value.ora_code == code
        # The dictionary lists a sparse column with no scale, as Oracle does.
        (scale,) = backend.execute(
            "SELECT data_scale FROM user_tab_columns WHERE table_name = 'S1709' "
            "AND column_name = 'FX'"
        ).rows[0]
        assert scale is None
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE s1709')
        except BackendError:
            backend.rollback()
        backend.close()


def test_binary_vector_columns() -> None:
    # BINARY VECTOR columns (#1710) as varbit, each element a byte: back as
    # array('B'), dimensions counted in bits, VECTOR_DISTANCE by the bits for
    # every metric. The answers are 23ai's, measured: a count not a multiple
    # of 8 ORA-51813, a wrong count ORA-51803, a byte out of range ORA-51806,
    # a BINARY vector with one of another format ORA-51814 / ORA-51812.
    import array

    from seerdb.common.tns_consts import TNS_TYPE_VECTOR, VECTOR_FLAG_FLEXIBLE_DIM
    from seerdb.server import BackendError

    assert _translate_ddl(
        'create table t (a vector(16, binary), b vector(*, binary))'
    ) == ('create table t (a varbit CHECK (sys.ora_binary_dims(a, 16)), b varbit)')
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    try:
        with pytest.raises(BackendError) as exc:
            backend.execute('CREATE TABLE b1710 (v VECTOR(12, BINARY))')
        assert exc.value.ora_code == 51813
        backend.execute(
            'CREATE TABLE b1710 (n NUMBER, v VECTOR(16, BINARY), fx VECTOR(*, BINARY), '
            'f32 VECTOR(*, FLOAT32), flex VECTOR)'
        )
        value = array.array('B', [3, 255])
        backend.execute(
            'INSERT INTO b1710 VALUES (1, :1, :2, NULL, :3)',
            [value, array.array('B', [1, 2, 3]), value],
        )
        backend.execute("INSERT INTO b1710 (n, v) VALUES (2, '[7, 8]')")
        backend.execute('INSERT INTO b1710 (n, v) VALUES (3, :1)', ['[9, 10]'])
        result = backend.execute('SELECT v, fx, flex FROM b1710 ORDER BY n')
        assert [
            (c.data_type, c.vector_dimensions, c.vector_format, c.vector_flags)
            for c in result.columns
        ] == [
            (TNS_TYPE_VECTOR, 16, 5, 0),
            (TNS_TYPE_VECTOR, 0, 5, VECTOR_FLAG_FLEXIBLE_DIM),
            (TNS_TYPE_VECTOR, 0, 0, VECTOR_FLAG_FLEXIBLE_DIM),
        ]
        assert result.rows[0] == (value, array.array('B', [1, 2, 3]), value)
        assert result.rows[0][0].typecode == 'B'
        assert [r[0] for r in result.rows[1:]] == [
            array.array('B', [7, 8]),
            array.array('B', [9, 10]),
        ]
        other = array.array('B', [1, 255])
        distances = backend.execute(
            'SELECT VECTOR_DISTANCE(v, :1), VECTOR_DISTANCE(v, :1, HAMMING), '
            'VECTOR_DISTANCE(v, :1, JACCARD), VECTOR_DISTANCE(v, :1, DOT), '
            'VECTOR_DISTANCE(v, :1, EUCLIDEAN) FROM b1710 WHERE n = 1',
            [other],
        ).rows[0]
        assert distances == pytest.approx((1 - 9 / 90**0.5, 1.0, 0.1, -9.0, 1.0))
        (to_vector,) = backend.execute(
            "SELECT TO_VECTOR('[3, 2, 3]', 24, BINARY) FROM dual"
        ).rows[0]
        assert to_vector == array.array('B', [3, 2, 3])
        for sql, binds, code in (
            ('INSERT INTO b1710 (v) VALUES (:1)', [array.array('B', [1])], 51803),
            ("SELECT TO_VECTOR('[256]', 8, BINARY) FROM dual", [], 51806),
            ('INSERT INTO b1710 (f32) VALUES (:1)', [value], 51814),
            ("SELECT VECTOR_DISTANCE(v, TO_VECTOR('[1, 2]')) FROM b1710", [], 51812),
        ):
            with pytest.raises(BackendError) as exc:
                backend.execute(sql, binds)
            assert exc.value.ora_code == code
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE b1710')
        except BackendError:
            backend.rollback()
        backend.close()


def test_from_vector_and_vector_kinds() -> None:
    # FROM_VECTOR / VECTOR_SERIALIZE, VECTOR(...) and TO_VECTOR's DENSE /
    # SPARSE (#1726). Every answer is 23ai's, measured: an element's exact
    # value to 9 (FLOAT32) or 17 (FLOAT64) significant digits as d.dddE+nnn,
    # zero as 0; a sparse vector [dims,[indices],[values]]; a UNION of sparse
    # vectors of differing dimension counts not described sparse.
    import array

    from seerdb.common.tns_consts import (
        TNS_TYPE_CLOB,
        VECTOR_FLAG_FLEXIBLE_DIM,
        VECTOR_FLAG_SPARSE,
    )
    from seerdb.common.vector import SparseVector
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    try:
        (f32, f64, i8, b, sparse) = backend.execute(
            "SELECT FROM_VECTOR(TO_VECTOR('[34.6, 0, 1, 1e-40, 123456789]')), "
            "VECTOR_SERIALIZE(TO_VECTOR('[34.6, 5e-324, 0.30000000000000004]', *, FLOAT64)), "
            "FROM_VECTOR(TO_VECTOR('[3, -4, 0]', *, INT8)), "
            "FROM_VECTOR(TO_VECTOR('[3, 255]', *, BINARY)), "
            "FROM_VECTOR(TO_VECTOR('[8, [0, 7], [34.6, 77.8]]', 8, FLOAT64, SPARSE)) "
            'FROM dual'
        ).rows[0]
        assert f32 == '[3.45999985E+001,0,1.0E+000,9.9999461E-041,1.23456792E+008]'
        assert f64 == (
            '[3.4600000000000001E+001,4.9406564584124654E-324,3.0000000000000004E-001]'
        )
        assert (i8, b) == ('[3,-4,0]', '[3,255]')
        assert sparse == '[8,[0,7],[3.4600000000000001E+001,7.7799999999999997E+001]]'
        result = backend.execute(
            "SELECT FROM_VECTOR(TO_VECTOR('[4, [0, 2], [1.5, 2]]', 4, FLOAT64, SPARSE) "
            'RETURNING CLOB FORMAT DENSE), '
            "FROM_VECTOR(VECTOR('[0, 1.5, 0]', 3, FLOAT64) RETURNING VARCHAR2 FORMAT SPARSE) "
            'FROM dual'
        )
        assert result.columns[0].data_type == TNS_TYPE_CLOB
        assert result.rows[0] == ('[1.5E+000,0,2.0E+000,0]', '[3,[1],[1.5E+000]]')
        (dense, made_sparse) = backend.execute(
            "SELECT VECTOR(TO_VECTOR('[4, [0, 2], [1.5, 2]]', 4, FLOAT32, SPARSE), "
            "4, FLOAT64, DENSE), TO_VECTOR('[8, [0, 7], [34.6, 77.8]]', 8, FLOAT64, SPARSE) "
            'FROM dual'
        ).rows[0]
        assert dense == array.array('d', [1.5, 0, 2, 0])
        assert made_sparse == SparseVector(8, [0, 7], array.array('d', [34.6, 77.8]))
        for sql, flags in (
            (
                "SELECT TO_VECTOR('[3, [0], [1]]', 3, FLOAT64, SPARSE) FROM dual UNION ALL "
                "SELECT TO_VECTOR('[4, [0], [1]]', 4, FLOAT64, SPARSE) FROM dual",
                VECTOR_FLAG_FLEXIBLE_DIM,
            ),
            (
                "SELECT TO_VECTOR('[3, [0], [1]]', 3, FLOAT64, SPARSE) FROM dual UNION ALL "
                "SELECT TO_VECTOR('[3, [1], [1]]', 3, FLOAT32, SPARSE) FROM dual",
                VECTOR_FLAG_SPARSE,
            ),
        ):
            assert backend.execute(sql).columns[0].vector_flags == flags
        for sql, code in (
            ("SELECT TO_VECTOR('[8, [0], [1]]', 4, FLOAT32, SPARSE) FROM dual", 51820),
            ("SELECT VECTOR('[0, 1.5]', 2, FLOAT32, SPARSE) FROM dual", 51833),
            ("SELECT TO_VECTOR('[8, [0], [3]]', 8, BINARY, SPARSE) FROM dual", 51804),
        ):
            with pytest.raises(BackendError) as exc:
                backend.execute(sql)
            assert exc.value.ora_code == code
    finally:
        backend.rollback()
        backend.close()


def test_sql_domains_and_annotations() -> None:
    # 23ai SQL domains and column annotations (#1711): a column's DOMAIN is its
    # PostgreSQL type, the domain's constraints holding; its annotations go to
    # sys.ora_annotations; the describe names both, as the client reads them.
    from seerdb.server import BackendError

    assert _column_annotations(
        'create table t (a number, b number(3, 0) domain s.d '
        "annotations (x 'one', \"Y\" 'it''s', z))"
    ) == (
        'create table t (a number, b s.d )',
        ('t', {'b': [('X', 'one'), ('Y', "it's"), ('Z', '')]}),
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        backend.execute('CREATE DOMAIN d1711 AS NUMBER(3, 0) NOT NULL')
        backend.execute(
            'CREATE TABLE t1711 (id NUMBER(9), age NUMBER(3, 0) DOMAIN d1711 '
            "ANNOTATIONS (Anno_1 'first annotation', Anno_3))"
        )
        backend.execute('INSERT INTO t1711 VALUES (1, 25)')
        result = backend.execute('SELECT * FROM t1711')
        assert [
            (c.domain_schema, c.domain_name, c.annotations) for c in result.columns
        ] == [
            (b'', b'', ()),
            (
                b'PUBLIC',
                b'D1711',
                ((b'ANNO_1', b'first annotation'), (b'ANNO_3', b'')),
            ),
        ]
        with pytest.raises(BackendError) as exc:
            backend.execute('INSERT INTO t1711 VALUES (2, NULL)')
        assert exc.value.ora_code == 1400
    finally:
        backend.rollback()
        for statement in ('DROP TABLE t1711', 'DROP DOMAIN d1711'):
            try:
                backend.execute(statement)
            except BackendError:
                backend.rollback()
        backend.close()


def test_dbms_lob_copy_and_writeappend() -> None:
    # DBMS_LOB.COPY and WRITEAPPEND (#1712), procedures handing the LOB they
    # change back to the caller's variable. The answers are 23ai's, measured:
    # COPY overwrites from dest_offset, a gap before it spaces for a CLOB and
    # zero bytes for a BLOB; a BLOB's buffer written as a string is hex.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        conn = backend._conn
        conn.execute('CREATE TEMP TABLE r1712 (n integer, c text, b bytea)')
        conn.execute(
            'DO $$ DECLARE c text; b bytea; BEGIN '
            "c := 'XY'; CALL dbms_lob.copy(c, 'abcdef', 5, 6, 2); "
            'INSERT INTO r1712 (n, c) VALUES (1, c); '
            "c := 'XYZWVU'; CALL dbms_lob.copy(c, 'abcdef', 2, 2, 3); "
            'INSERT INTO r1712 (n, c) VALUES (2, c); '
            "c := 'XY'; CALL dbms_lob.copy(c, 'abc', 10); "
            "CALL dbms_lob.writeappend(c, 2, 'BBBB'); "
            'INSERT INTO r1712 (n, c) VALUES (3, c); '
            "b := '\\x11'; CALL dbms_lob.copy(b, '\\xaabbcc'::bytea, 2, 4, 2); "
            "CALL dbms_lob.writeappend(b, 1, '5151'); "
            'INSERT INTO r1712 (n, b) VALUES (4, b); END $$'
        )
        rows = conn.execute('SELECT c, b FROM r1712 ORDER BY n').fetchall()
        assert rows == [
            ('XY   bcdef', None),
            ('XcdWVU', None),
            ('abcBB', None),
            (None, b'\x11\x00\x00\xbb\xccQ'),
        ]
    finally:
        backend.rollback()
        backend.close()


def test_json_constructor_values_keep_their_type() -> None:
    # JSON_OBJECT / JSON_ARRAY values in their extended form (#1724), so a
    # timestamp, a RAW and a vector come back as themselves, as 23ai's do; a
    # literal, a bind, NULL and a FORMAT JSON value go as they are.
    import array
    import datetime

    from seerdb.common.vector import SparseVector

    assert _translate_json_constructor_values(
        "select json_object('a' : :1, 'b' : c FORMAT JSON, KEY 'k' VALUE d, "
        "'n' : NULL ABSENT ON NULL), json_array(e, 'x', 3 returning json) from t"
    ) == (
        "select json_object('a' : :1, 'b' : c FORMAT JSON, KEY 'k' VALUE "
        "sys.ora_json_scalar(d), 'n' : NULL ABSENT ON NULL), "
        "json_array(sys.ora_json_scalar(e), 'x', 3 returning json) from t"
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        (row,) = backend.execute(
            "SELECT JSON_OBJECT('t' : TIMESTAMP '2024-01-02 03:04:05', "
            "'r' : HEXTORAW('AB') RETURNING JSON) FROM dual"
        ).rows
        assert row[0] == {'t': datetime.datetime(2024, 1, 2, 3, 4, 5), 'r': b'\xab'}
        if backend._has_pgvector:
            (row,) = backend.execute(
                "SELECT JSON_ARRAY(TO_VECTOR('[1, 2]'), "
                "TO_VECTOR('[4, [1], [2.5]]', 4, FLOAT64, SPARSE) RETURNING JSON) FROM dual"
            ).rows
            assert row[0] == [
                array.array('f', [1, 2]),
                SparseVector(4, [1], array.array('d', [2.5])),
            ]
    finally:
        backend.rollback()
        backend.close()


def test_a_block_of_several_statements_reads_and_writes_its_binds() -> None:
    # A PL/SQL block of several statements runs whole, its binds its locals
    # (#1723): each statement sees what the one before wrote, a SELECT ... INTO
    # :b among them. One-statement blocks keep their own paths.
    import decimal

    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
    from seerdb.server import BindVar

    assert _several_statements("select 1 into :1 from dual; :2 := ';'")
    assert not _several_statements('select 1 into :1 from dual;')
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        for sql, binds, expected in (
            (
                'begin select 1 + 1 into :1 from dual; :2 := 5; end;',
                [
                    BindVar(None, TNS_TYPE_NUMBER, 22),
                    BindVar(None, TNS_TYPE_NUMBER, 22),
                ],
                [2, 5],
            ),
            (
                'begin :1 := 3; :2 := :1 + 1; end;',
                [
                    BindVar(None, TNS_TYPE_NUMBER, 22),
                    BindVar(None, TNS_TYPE_NUMBER, 22),
                ],
                [3, 4],
            ),
            (
                "begin select 'x' || :1 into :2 from dual; :3 := :2 || 'y'; end;",
                [
                    BindVar('a', TNS_TYPE_VARCHAR, 10),
                    BindVar(None, TNS_TYPE_VARCHAR, 10),
                    BindVar(None, TNS_TYPE_VARCHAR, 10),
                ],
                ['a', 'xa', 'xay'],
            ),
        ):
            out = backend.execute(sql, binds).out_binds
            assert [
                int(v) if isinstance(v, decimal.Decimal) else v for v in out
            ] == expected
    finally:
        backend.rollback()
        backend.close()


def test_to_vector_and_vector_distance() -> None:
    # TO_VECTOR(text [, n [, format]]) and VECTOR_DISTANCE(a, b [, metric]) on
    # pgvector (#1708): a computed TO_VECTOR describes as its call says, a
    # distance is a BINARY_DOUBLE, and a string written into a VECTOR column is
    # the vector it spells. The answers are 23ai's.
    import array

    from seerdb.common.tns_consts import (
        TNS_TYPE_BDOUBLE,
        TNS_TYPE_VECTOR,
        VECTOR_FLAG_FLEXIBLE_DIM,
    )
    from seerdb.server import BackendError

    assert _translate_vector_functions(
        "select to_vector('[1]', *, int8), vector_distance(a, '[1]', dot) from t"
    ) == (
        "select sys.ora_to_vector('[1]', NULL, 'INT8'), "
        "sys.ora_vector_distance(CAST(a AS ora_vector), sys.ora_to_vector('[1]'), 'DOT') "
        'from t'
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    try:
        result = backend.execute(
            "SELECT TO_VECTOR('[34.6, 77.8]', 2, FLOAT64), "
            "TO_VECTOR('[34, -77]', 2, INT8), TO_VECTOR('[1, 2]') FROM dual"
        )
        assert [
            (c.data_type, c.vector_dimensions, c.vector_format) for c in result.columns
        ][:2] == [(TNS_TYPE_VECTOR, 2, 3), (TNS_TYPE_VECTOR, 2, 4)]
        assert [(v.typecode, list(v)) for v in result.rows[0]] == [
            ('d', [34.6, 77.8]),
            ('b', [34, -77]),
            ('f', [1.0, 2.0]),
        ]
        # Across a UNION, a dimension count or a format holds where every
        # branch names the same one; a NULL branch says nothing.
        union = backend.execute(
            "SELECT TO_VECTOR('[1, 2]', 2, FLOAT32) FROM dual UNION ALL "
            'SELECT NULL FROM dual UNION ALL '
            "SELECT TO_VECTOR('[1, 2, 3]', 3, FLOAT32) FROM dual"
        )
        assert (
            union.columns[0].vector_dimensions,
            union.columns[0].vector_format,
            union.columns[0].vector_flags,
        ) == (0, 2, VECTOR_FLAG_FLEXIBLE_DIM)
        union = backend.execute(
            "SELECT TO_VECTOR('[1, 2]', 2, FLOAT32) FROM dual UNION ALL "
            "SELECT TO_VECTOR('[1, 2]', 2, FLOAT64) FROM dual"
        )
        assert (union.columns[0].vector_dimensions, union.columns[0].vector_format) == (
            2,
            0,
        )
        assert [r[0].typecode for r in union.rows] == ['f', 'd']
        distance = backend.execute(
            'SELECT VECTOR_DISTANCE(:1, :2, EUCLIDEAN) FROM dual',
            [array.array('f', [0, 0]), array.array('d', [3, 4])],
        )
        assert distance.columns[0].data_type == TNS_TYPE_BDOUBLE
        assert distance.rows == [(5.0,)]
        with pytest.raises(BackendError) as exc:
            backend.execute("SELECT TO_VECTOR('[1, 2]', 3, FLOAT32) FROM dual")
        assert exc.value.ora_code == 51803
        backend.execute('CREATE TABLE t1708 (n NUMBER, v VECTOR, i VECTOR(*, INT8))')
        backend.execute(
            'INSERT INTO t1708 VALUES (1, :1, :2)', ['[6427, -25.75]', '[3, -4]']
        )
        (row,) = backend.execute('SELECT v, i FROM t1708').rows
        assert (row[0].typecode, list(row[0])) == ('f', [6427.0, -25.75])
        assert (row[1].typecode, list(row[1])) == ('b', [3, -4])
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE t1708')
        except BackendError:
            backend.rollback()
        backend.close()


def test_vector_distance_past_pgvector() -> None:
    # VECTOR_DISTANCE of FLOAT64 / INT8 vectors, and of longer ones than
    # pgvector's 16000 dimensions, sums the elements in float8 (#1738). The
    # FLOAT64 answers are 23ai's exactly, measured; a zero vector's COSINE is
    # NaN and vectors of different counts ORA-51808, as 23ai's.
    import array
    import math

    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    try:
        x = array.array('d', array.array('f', [0.1, 0.7, 1e-3, 3.3]))
        y = array.array('d', array.array('f', [0.3, 0.2, 2.5, -1.1]))
        row = backend.execute(
            'SELECT VECTOR_DISTANCE(:1, :2, EUCLIDEAN), VECTOR_DISTANCE(:1, :2), '
            'VECTOR_DISTANCE(:1, :2, DOT), VECTOR_DISTANCE(:1, :2, MANHATTAN) FROM dual',
            [x, y],
        ).rows[0]
        assert row == (
            5.0887130769208655,
            1.3718599678520904,
            3.4575000247661944,
            7.598999971640296,
        )
        for typecode, high, low in (('f', 3.5, 2.5), ('d', 3.5, 2.5), ('b', 3, 2)):
            (distance,) = backend.execute(
                'SELECT VECTOR_DISTANCE(:1, :2, EUCLIDEAN) FROM dual',
                [
                    array.array(typecode, [high] * 65535),
                    array.array(typecode, [low] * 65535),
                ],
            ).rows[0]
            assert distance == pytest.approx(math.sqrt(65535))
        (cosine,) = backend.execute(
            'SELECT VECTOR_DISTANCE(:1, :2, COSINE) FROM dual',
            [array.array('d', [0, 0]), array.array('d', [1, 2])],
        ).rows[0]
        assert math.isnan(cosine)
        with pytest.raises(BackendError) as exc:
            backend.execute(
                'SELECT VECTOR_DISTANCE(:1, :2) FROM dual',
                [array.array('d', [1, 2]), array.array('d', [1, 2, 3])],
            )
        assert exc.value.ora_code == 51808
    finally:
        backend.rollback()
        backend.close()


def test_a_vector_bind_in_a_plsql_block() -> None:
    # A VECTOR bind of a PL/SQL block is the block's local as its composite,
    # dense or sparse, and comes back as the vector it ended with (#1737):
    # python-oracledb's test_6445-6447 block, in each format.
    import array

    from seerdb.common.tns_consts import TNS_TYPE_BDOUBLE, TNS_TYPE_VECTOR
    from seerdb.common.vector import SparseVector
    from seerdb.server import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    block = (
        'BEGIN select vector_distance(:in_vec, :in_out_vec, euclidean) into :distance; '
        ':output_vec := :in_out_vec; :in_out_vec := :in_vec; END;'
    )
    try:
        for typecode, first, second, distance in (
            ('f', [1, 1.5, 2, 2.5], [4, 4.5, 5, 5.5], 6.0),
            ('d', [1, 1.5, 2, 2.5], [4, 4.5, 5, 5.5], 6.0),
            ('b', [1, 2, 3, 4], [5, 6, 7, 8], 8.0),
        ):
            (a, b) = (array.array(typecode, first), array.array(typecode, second))
            out = backend.execute(
                block,
                [
                    BindVar(a, TNS_TYPE_VECTOR, 0),
                    BindVar(b, TNS_TYPE_VECTOR, 0),
                    BindVar(None, TNS_TYPE_BDOUBLE, 8),
                    BindVar(None, TNS_TYPE_VECTOR, 0),
                ],
            ).out_binds
            assert out == [a, a, distance, b]
            assert [v.typecode for v in (out[1], out[3])] == [typecode, typecode]
        sparse = SparseVector(4, [1, 3], array.array('d', [1.5, 2]))
        # A sparse bind's local is sparse, by its value; an OUT VECTOR bind
        # with no value says nothing of which it is, and is dense.
        (converted,) = backend.execute(
            'BEGIN :v := TO_VECTOR(:v, 4, FLOAT32); END;',
            [BindVar(sparse, TNS_TYPE_VECTOR, 0)],
        ).out_binds
        assert converted == SparseVector(4, [1, 3], array.array('f', [1.5, 2]))
    finally:
        backend.rollback()
        backend.close()


def test_a_string_literal_into_every_vector_column() -> None:
    # A string literal into a VECTOR column is the vector it spells, whatever
    # the column's storage (#1742): a FLOAT64 / INT8 one's float8[] / int2[]
    # included, a FLOAT64 one's read exactly, in an INSERT and an UPDATE.
    import array

    from seerdb.common.vector import SparseVector
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    try:
        backend.execute(
            'CREATE TABLE l1742 (n NUMBER, f32 VECTOR(3, FLOAT32), '
            'f64 VECTOR(3, FLOAT64), i8 VECTOR(4, INT8), fx VECTOR, '
            'sp VECTOR(4, FLOAT64, SPARSE), bn VECTOR(16, BINARY))'
        )
        backend.execute(
            "INSERT INTO l1742 VALUES (1, '[1, 2, 3]', '[0.1, 2.5, 3.5]', "
            "'[1, -2, 3, -4]', '[7, 8]', '[4, [1], [2.5]]', '[7, 8]')"
        )
        backend.execute("UPDATE l1742 SET i8 = '[5, 6, 7, 8]' WHERE n = 1")
        (row,) = backend.execute('SELECT f32, f64, i8, fx, sp, bn FROM l1742').rows
        assert row == (
            array.array('f', [1, 2, 3]),
            array.array('d', [0.1, 2.5, 3.5]),
            array.array('b', [5, 6, 7, 8]),
            array.array('f', [7, 8]),
            SparseVector(4, [1], array.array('d', [2.5])),
            array.array('B', [7, 8]),
        )
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE l1742')
        except BackendError:
            backend.rollback()
        backend.close()


def test_a_number_into_and_against_a_boolean_column() -> None:
    # A number into a 23ai BOOLEAN column, bound or literal, and a BOOLEAN
    # compared with one (#1743). The answers are 23ai's, measured: zero is
    # FALSE and any other number TRUE, 0.5 and -1 among them; a NULL declared
    # NUMBER is NULL.
    import decimal

    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server import BackendError, BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        backend.execute('CREATE TABLE b1743 (n NUMBER, flag BOOLEAN)')
        for i, value in enumerate(
            [0, 1, -1, 0.5, decimal.Decimal('0.0'), BindVar(None, TNS_TYPE_NUMBER, 22)]
        ):
            backend.execute('INSERT INTO b1743 VALUES (:1, :2)', [i, value])
        backend.execute('INSERT INTO b1743 (n, flag) VALUES (10, 2)')
        backend.execute('INSERT INTO b1743 (n, flag) VALUES (11, 0)')
        backend.execute('UPDATE b1743 SET flag = 0 WHERE n = 1')
        rows = backend.execute('SELECT n, flag FROM b1743 ORDER BY n').rows
        assert [flag for _n, flag in rows] == [
            False,
            False,
            True,
            True,
            False,
            None,
            True,
            False,
        ]
        (count,) = backend.execute('SELECT count(*) FROM b1743 WHERE flag = 1').rows[0]
        assert count == 3
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE b1743')
        except BackendError:
            backend.rollback()
        backend.close()


def test_drop_domain_as_23ai_runs_it() -> None:
    # DROP DOMAIN (#1744), measured on 23ai: refused while a column uses the
    # domain (ORA-11502), a missing one ORA-11504 unless IF EXISTS; FORCE
    # returns the column to the base type, precision kept, without the
    # domain's NOT NULL, and FORCE PRESERVE keeps it.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')

    def code(sql: str) -> int | None:
        try:
            backend.execute(sql)
        except BackendError as exc:
            backend.rollback()
            return exc.ora_code
        return None

    try:
        for mode, null_code in (('FORCE', None), ('FORCE PRESERVE', 1400)):
            code('DROP TABLE d1744')
            code('DROP DOMAIN d1744dom FORCE')
            backend.execute('CREATE DOMAIN d1744dom AS NUMBER(3) NOT NULL')
            backend.execute(
                'CREATE TABLE d1744 (id NUMBER, v NUMBER(3) DOMAIN d1744dom)'
            )
            assert code('DROP DOMAIN d1744dom') == 11502
            assert code(f'DROP DOMAIN d1744dom {mode}') is None
            assert code('INSERT INTO d1744 VALUES (1, NULL)') == null_code
            assert code('INSERT INTO d1744 VALUES (2, 1000)') == 1438
        assert code('DROP DOMAIN d1744nope') == 11504
        assert code('DROP DOMAIN IF EXISTS d1744nope') is None
    finally:
        backend.rollback()
        code('DROP TABLE d1744')
        code('DROP DOMAIN d1744dom FORCE')
        backend.close()


def test_column_layouts_follow_a_drop_and_recreate() -> None:
    # The per-session column layouts the bind rewrites read -- VECTOR and OSON
    # columns -- are forgotten at a DDL (#1749): a table dropped and created
    # again under its name, its VECTOR column moved, takes a text bind into
    # that column where it now is.
    import array

    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    try:
        backend.execute('CREATE TABLE c1749 (n NUMBER, v VECTOR(2, FLOAT64))')
        backend.execute('INSERT INTO c1749 VALUES (1, :1)', ['[1.5, 2.5]'])
        backend.execute('DROP TABLE c1749')
        backend.execute('CREATE TABLE c1749 (v VECTOR(2, FLOAT64), n NUMBER)')
        backend.execute('INSERT INTO c1749 VALUES (:1, 2)', ['[3.5, 4.5]'])
        (row,) = backend.execute('SELECT v, n FROM c1749').rows
        assert row[0] == array.array('d', [3.5, 4.5])
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE c1749')
        except BackendError:
            backend.rollback()
        backend.close()


def test_sessionless_transactions_move_between_sessions() -> None:
    # A sessionless transaction (#1746): begun and suspended on one session,
    # invisible to others while suspended, resumed and committed on another.
    # 23ai's refusals, measured: an id that exists ORA-26217, an unknown or
    # finished one ORA-26218, one active elsewhere ORA-25351 after the timeout.
    from seerdb.server import BackendError

    def code(call) -> int | None:
        try:
            call()
        except BackendError as exc:
            return exc.ora_code
        return None

    (one, two, outsider) = (
        PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
        for _ in range(3)
    )
    try:
        outsider.execute('CREATE TABLE s1746 (n NUMBER)')
        one.sessionless_begin(b'sl-1746', 60)
        one.execute('INSERT INTO s1746 VALUES (10)')
        assert code(lambda: two.sessionless_begin(b'sl-1746', 60)) == 26217
        assert code(lambda: two.sessionless_resume(b'sl-1746', 0)) == 25351
        one.sessionless_suspend()
        assert outsider.execute('SELECT count(*) FROM s1746').rows == [(0,)]
        assert code(lambda: two.sessionless_resume(b'sl-unknown', 1)) == 26218
        two.sessionless_resume(b'sl-1746', 5)
        two.execute('INSERT INTO s1746 VALUES (20)')
        two.commit()
        assert outsider.execute('SELECT n FROM s1746 ORDER BY n').rows == [(10,), (20,)]
        assert code(lambda: one.sessionless_resume(b'sl-1746', 1)) == 26218
        # The suspending session went on with a fresh connection of its own.
        assert one.execute('SELECT count(*) FROM s1746').rows == [(2,)]
    finally:
        for backend in (one, two):
            backend.rollback()
            backend.close()
        outsider.rollback()
        try:
            outsider.execute('DROP TABLE s1746')
        except BackendError:
            outsider.rollback()
        outsider.close()


def test_a_number_as_a_condition_at_23ai() -> None:
    # 23ai takes a number where a condition goes, zero FALSE and any other
    # TRUE (#1760), measured: SQLAlchemy writes true() as `ON 1` there. A
    # comparison's operand and BETWEEN's AND are left alone.
    from seerdb.server.backends.postgres import _number_conditions

    assert _number_conditions('SELECT 1 FROM a JOIN b ON 1 WHERE 0 OR NOT 0') == (
        'SELECT 1 FROM a JOIN b ON TRUE WHERE FALSE OR NOT FALSE'
    )
    for unchanged in (
        'SELECT 1 FROM t WHERE x = 1 AND y > 0',
        'SELECT 1 FROM t WHERE x BETWEEN 1 AND 2 ORDER BY 1',
        'SELECT CASE x WHEN 1 THEN 2 END FROM t',
        "SELECT 'ON 1' FROM t",
    ):
        assert _number_conditions(unchanged) == unchanged
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    try:
        assert backend.execute('SELECT 1 FROM dual WHERE 0.5').rows == [(1,)]
        assert backend.execute('SELECT 1 FROM dual WHERE 0').rows == []
        (count,) = backend.execute(
            'SELECT count(*) FROM dual a LEFT OUTER JOIN dual b ON 0'
        ).rows[0]
        assert count == 1
    finally:
        backend.rollback()
        backend.close()


def test_a_bind_in_a_comment_or_a_q_literal_is_text() -> None:
    # #1692: a `:c` in a comment was counted as a bind, so every value after it
    # shifted -- `:b` silently got the wrong one; an apostrophe in a comment
    # opened a string that hid the binds after it; and PostgreSQL has no
    # q'...' literals at all.
    from seerdb.server.backends.postgres import (
        _bind_names,
        _plain_quoting,
        _replace_binds,
    )

    sql = 'select 1 /* :c */ from t where x = :b'
    assert _bind_names(sql) == ['b']
    assert _translate_binds(sql, ['B'])[1] == {'b': 'B'}
    sql = "select :a -- don't :c\n from t where x = :b"
    assert _translate_binds(sql, [1, 2]) == (
        "select %(a)s -- don't :c\n from t where x = %(b)s",
        {'a': 1, 'b': 2},
    )
    assert _replace_binds("select :a /* it's */, ':b' from t", {'a': '1'}) == (
        "select 1 /* it's */, ':b' from t"
    )
    assert _plain_quoting("select q'[it's :z]', NQ'!a'b!', 'q''x' from t") == (
        "select 'it''s :z', N'a''b', 'q''x' from t"
    )
    assert _plain_quoting("select q'[open from t") == "select q'[open from t"
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        result = backend.execute(
            "SELECT q'[it's :z]', :b /* :c */ FROM dual -- don't", [5]
        )
        assert [tuple(r) for r in result.rows] == [("it's :z", 5)]
    finally:
        backend.rollback()
        backend.close()


def test_dictionary_views_reflect_a_created_table() -> None:
    # The Oracle data-dictionary emulation (#759): SYS_CONTEXT + the catalog views
    # let a reflecting client find a table's metadata. Create a table and read it
    # back through the Oracle-shaped views, UPPER-cased and Oracle-typed.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('drop table if exists dict_reflect')
        backend.execute(
            'CREATE TABLE dict_reflect (id NUMBER PRIMARY KEY, name VARCHAR2(20))'
        )
        backend.commit()
        assert (
            backend.execute("SELECT sys_context('userenv', 'current_schema')").rows[0][
                0
            ]
            == 'PUBLIC'
        )
        cols = backend.execute(
            'SELECT column_name, data_type FROM all_tab_columns '
            "WHERE table_name = 'DICT_REFLECT' ORDER BY column_id"
        ).rows
        typ = {c[0]: c[1] for c in cols}
        assert typ.get('ID') == 'NUMBER'
        assert typ.get('NAME') == 'VARCHAR2'
        assert backend.execute(
            "SELECT table_name FROM all_tables WHERE table_name = 'DICT_REFLECT'"
        ).rows
        assert backend.execute(
            'SELECT constraint_type FROM all_constraints '
            "WHERE table_name = 'DICT_REFLECT' AND constraint_type = 'P'"
        ).rows
        backend.execute('drop table dict_reflect')
        backend.commit()
    finally:
        backend.close()


def test_a_private_synonym_reaches_its_table_as_oracles_does() -> None:
    # CREATE / DROP SYNONYM were syntax errors and USER_SYNONYMS missing
    # (#2179). 23ai's: the synonym reads and writes its table; USER_SYNONYMS
    # and ALL_SYNONYMS list it, USER_OBJECTS as a SYNONYM, USER_VIEWS and
    # USER_TAB_COLUMNS not at all; ORA-00955, ORA-01471 and ORA-01434.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2179 (id NUMBER, v VARCHAR2(5))')
        try:
            backend.execute("INSERT INTO t2179 VALUES (1, 'a')")
            backend.execute('CREATE SYNONYM s2179 FOR t2179')
            backend.execute('CREATE OR REPLACE SYNONYM s2179 FOR pyo.t2179')
            assert backend.execute('SELECT id, v FROM s2179').rows == [(1, 'a')]
            backend.execute("INSERT INTO s2179 VALUES (2, 'b')")
            assert backend.execute('SELECT count(*) FROM t2179').rows == [(2,)]

            def one(sql: str) -> list:
                return backend.execute(sql).rows

            assert one("SELECT * FROM user_synonyms WHERE synonym_name = 'S2179'") == [
                ('S2179', 'PYO', 'T2179', None, 3)
            ]
            assert one(
                'SELECT owner, synonym_name, table_owner, table_name FROM all_synonyms '
                "WHERE synonym_name = 'S2179'"
            ) == [('PYO', 'S2179', 'PYO', 'T2179')]
            assert one(
                "SELECT object_type, status FROM user_objects WHERE object_name = 'S2179'"
            ) == [('SYNONYM', 'VALID')]
            assert one("SELECT 1 FROM user_views WHERE view_name = 'S2179'") == []
            assert (
                one("SELECT 1 FROM user_tab_columns WHERE table_name = 'S2179'") == []
            )
            for statement, code in (
                ('CREATE SYNONYM s2179 FOR t2179', 955),
                ('CREATE SYNONYM t2179 FOR t2179', 1471),
                ('CREATE SYNONYM t2179 FOR s2179', 955),
            ):
                with pytest.raises(BackendError) as raised:
                    backend.execute(statement)
                assert raised.value.ora_code == code, statement
            backend.execute('DROP SYNONYM s2179')
            assert one("SELECT 1 FROM user_synonyms WHERE synonym_name = 'S2179'") == []
            with pytest.raises(BackendError) as raised:
                backend.execute('DROP SYNONYM s2179')
            assert raised.value.ora_code == 1434
        finally:
            backend.rollback()
            with contextlib.suppress(BackendError):
                backend.execute('DROP SYNONYM s2179')  # left by a failed assert
            backend.execute('DROP TABLE t2179')
    finally:
        backend.close()


def test_a_synonym_follows_its_target_as_oracles_does() -> None:
    # A synonym's view kept the columns its target had when it was made, and
    # one whose target went was a missing table (#2179). 23ai's: a column the
    # target gains shows through; with the target gone the synonym is
    # INVALID and ORA-00980, and VALID once a table of its name is back; one
    # made for a target not yet there works once it is; OR REPLACE retargets.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))

    def status() -> list:
        return backend.execute(
            "SELECT status FROM user_objects WHERE object_name = 'S2179B'"
        ).rows

    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2179b (id NUMBER)')
        try:
            backend.execute('INSERT INTO t2179b VALUES (1)')
            backend.execute('CREATE SYNONYM s2179b FOR t2179b')
            backend.execute('ALTER TABLE t2179b ADD (w NUMBER)')
            assert backend.execute('SELECT * FROM s2179b').rows == [(1, None)]
            backend.execute('DROP TABLE t2179b')
            assert status() == [('INVALID',)]
            with pytest.raises(BackendError) as raised:
                backend.execute('SELECT * FROM s2179b')
            assert raised.value.ora_code == 980
            backend.execute('CREATE TABLE t2179b (k VARCHAR2(5))')
            assert backend.execute('SELECT * FROM s2179b').rows == []
            assert status() == [('VALID',)]
            backend.execute('CREATE SYNONYM s2179c FOR u2179c')
            with pytest.raises(BackendError) as raised:
                backend.execute('SELECT * FROM s2179c')
            assert raised.value.ora_code == 980
            backend.execute('CREATE TABLE u2179c (z NUMBER)')
            backend.execute('INSERT INTO u2179c VALUES (7)')
            assert backend.execute('SELECT z FROM s2179c').rows == [(7,)]
            backend.execute('CREATE OR REPLACE SYNONYM s2179b FOR u2179c')
            assert backend.execute('SELECT * FROM s2179b').rows == [(7,)]
        finally:
            backend.rollback()
            for leftover in (
                'SYNONYM s2179b',
                'SYNONYM s2179c',
                'TABLE t2179b',
                'TABLE u2179c',
            ):
                with contextlib.suppress(BackendError):
                    backend.execute(f'DROP {leftover}')
    finally:
        backend.close()


def test_a_public_synonym_reaches_its_table_as_oracles_does() -> None:
    # CREATE PUBLIC SYNONYM was ORA-03001 (#2179). 23ai's: ALL_SYNONYMS and
    # ALL_OBJECTS list it under PUBLIC and USER_SYNONYMS does not; a target
    # with no schema is the creator's; a private synonym of its name wins;
    # ORA-00955 again without OR REPLACE, ORA-01432 for a DROP of none, and
    # ORA-00980 while its target is gone.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE p2179 (id NUMBER)')
        backend.execute('CREATE TABLE q2179 (k NUMBER)')
        try:
            backend.execute('INSERT INTO p2179 VALUES (1)')
            backend.execute('INSERT INTO q2179 VALUES (2)')
            backend.execute('CREATE PUBLIC SYNONYM ps2179 FOR p2179')
            assert backend.execute(
                'SELECT owner, table_owner, table_name FROM all_synonyms '
                "WHERE synonym_name = 'PS2179'"
            ).rows == [('PUBLIC', 'PYO', 'P2179')]
            assert backend.execute(
                "SELECT owner, object_type FROM all_objects WHERE object_name = 'PS2179'"
            ).rows == [('PUBLIC', 'SYNONYM')]
            assert (
                backend.execute(
                    "SELECT 1 FROM user_synonyms WHERE synonym_name = 'PS2179'"
                ).rows
                == []
            )
            assert backend.execute('SELECT * FROM ps2179').rows == [(1,)]
            backend.execute('CREATE SYNONYM ps2179 FOR q2179')
            assert backend.execute('SELECT * FROM ps2179').rows == [(2,)]
            backend.execute('DROP SYNONYM ps2179')
            with pytest.raises(BackendError) as raised:
                backend.execute('CREATE PUBLIC SYNONYM ps2179 FOR p2179')
            assert raised.value.ora_code == 955
            backend.execute('CREATE OR REPLACE PUBLIC SYNONYM ps2179 FOR q2179')
            assert backend.execute('SELECT * FROM ps2179').rows == [(2,)]
            backend.execute('DROP TABLE q2179')
            with pytest.raises(BackendError) as raised:
                backend.execute('SELECT * FROM ps2179')
            assert raised.value.ora_code == 980
            backend.execute('DROP PUBLIC SYNONYM ps2179')
            with pytest.raises(BackendError) as raised:
                backend.execute('DROP PUBLIC SYNONYM ps2179')
            assert raised.value.ora_code == 1432
        finally:
            backend.rollback()
            for leftover in ('PUBLIC SYNONYM ps2179', 'TABLE p2179', 'TABLE q2179'):
                with contextlib.suppress(BackendError):
                    backend.execute(f'DROP {leftover}')
    finally:
        backend.close()


def test_a_synonym_target_is_written_as_its_name_whatever_it_holds() -> None:
    # A target named in a rewritten statement is the name its record gives:
    # an ordinary one as it is, any other quoted, a double quote in it doubled
    # (#2179).
    assert _oracle_reference('PYO', 'NEXT_ID') == 'PYO.NEXT_ID'
    assert _oracle_reference('PYO', 'next id') == 'PYO."next id"'
    assert _oracle_reference(None, 'say "hi"') == '"say ""hi"""'
    assert _oracle_reference('o"wner', 'N') == '"o""wner".N'


def test_a_synonym_reaches_a_sequence_routine_or_package_as_oracles_does() -> None:
    # A synonym for a sequence, function, procedure or package was ORA-03001
    # (#2179). 23ai's: sq.NEXTVAL and CURRVAL, in a DEFAULT too, f(n), a call
    # of p, k.member, and a procedure using them all compiles VALID. Its name
    # is rewritten to its target where only such a name stands: not as a FROM
    # alias, not where a DDL names an object, not after a dot.
    synonyms = {
        'SQ4': ('SEQUENCE', 'PYO.SQ_T4'),
        'F4': ('FUNCTION', 'PYO.F_T4'),
        'K4': ('PACKAGE', 'K_T4'),
    }
    assert _through_synonyms(
        'select sq4.nextval, f4(1), k4.g, x.f4 from dual', synonyms
    ) == ('select PYO.SQ_T4.nextval, PYO.F_T4(1), K_T4.g, x.f4 from dual')
    for unchanged in (
        'select k4.id from t k4',
        'create or replace function f4(n number) return number as begin return n; end;',
        'drop synonym f4',
        'select f4 from t',
    ):
        assert _through_synonyms(unchanged, synonyms) == unchanged, unchanged
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    made = []

    def make(statement: str, drop: str) -> None:
        backend.execute(statement)
        made.append(drop)

    try:
        backend.authenticate('PYO')
        backend.open_session({})
        try:
            make('CREATE SEQUENCE sq_t2179 START WITH 10', 'SEQUENCE sq_t2179')
            make('CREATE SYNONYM sq2179 FOR sq_t2179', 'SYNONYM sq2179')
            assert backend.execute('SELECT sq2179.NEXTVAL FROM dual').rows == [(10,)]
            assert backend.execute('SELECT sq2179.CURRVAL FROM dual').rows == [(10,)]
            make(
                'CREATE TABLE t2179s (id NUMBER DEFAULT sq2179.NEXTVAL, v NUMBER)',
                'TABLE t2179s',
            )
            backend.execute('INSERT INTO t2179s (v) VALUES (1)')
            assert backend.execute('SELECT id FROM t2179s').rows == [(11,)]
            make(
                'CREATE OR REPLACE FUNCTION f_t2179(n NUMBER) RETURN NUMBER AS '
                'BEGIN RETURN n * 2; END;',
                'FUNCTION f_t2179',
            )
            make('CREATE SYNONYM f2179 FOR f_t2179', 'SYNONYM f2179')
            assert backend.execute('SELECT f2179(21) FROM dual').rows == [(42,)]
            make(
                'CREATE OR REPLACE PACKAGE k_t2179 AS FUNCTION g RETURN NUMBER; END;',
                'PACKAGE k_t2179',
            )
            backend.execute(
                'CREATE OR REPLACE PACKAGE BODY k_t2179 AS FUNCTION g RETURN NUMBER '
                'IS BEGIN RETURN 7; END; END;'
            )
            make('CREATE SYNONYM k2179 FOR k_t2179', 'SYNONYM k2179')
            assert backend.execute('SELECT k2179.g FROM dual').rows == [(7,)]
            make(
                'CREATE OR REPLACE PROCEDURE p_t2179(r OUT NUMBER) AS BEGIN '
                'r := f2179(1) + k2179.g + sq2179.NEXTVAL; END;',
                'PROCEDURE p_t2179',
            )
            make('CREATE SYNONYM p2179 FOR p_t2179', 'SYNONYM p2179')
            backend.execute('DECLARE r NUMBER; BEGIN p2179(r); END;')
            assert backend.execute(
                'SELECT object_name, status FROM user_objects WHERE object_name IN '
                "('SQ2179', 'F2179', 'K2179', 'P2179', 'P_T2179') ORDER BY 1"
            ).rows == [
                ('F2179', 'VALID'),
                ('K2179', 'VALID'),
                ('P2179', 'VALID'),
                ('P_T2179', 'VALID'),
                ('SQ2179', 'VALID'),
            ]
        finally:
            backend.rollback()
            for leftover in reversed(made):
                with contextlib.suppress(BackendError):
                    backend.execute(f'DROP {leftover}')
    finally:
        backend.close()


def test_all_constraints_gives_a_checks_condition_as_written() -> None:
    # A CHECK's SEARCH_CONDITION was NULL (#2171). 23ai's: the text between
    # its parentheses as written, spaces and case kept, inline or out of line,
    # in CREATE TABLE or ALTER TABLE ... ADD, named or not.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2171c (c NUMBER CHECK (c > 0), '
            'd NUMBER CONSTRAINT d_ok CHECK ( D>0  and d<10 ), e VARCHAR2(5), '
            "CONSTRAINT e_ok CHECK (e in ('a','b')))"
        )
        try:
            backend.execute('ALTER TABLE t2171c ADD CHECK (c<100)')
            backend.execute('ALTER TABLE t2171c ADD CONSTRAINT c_lo CHECK(c   >= 1)')
            assert sorted(
                backend.execute(
                    'SELECT search_condition FROM user_constraints '
                    "WHERE table_name = 'T2171C'"
                ).rows
            ) == [
                (' D>0  and d<10 ',),
                ('c   >= 1',),
                ('c > 0',),
                ('c<100',),
                ("e in ('a','b')",),
            ]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2171c')
    finally:
        backend.close()


def test_all_constraints_says_whose_name_a_constraint_has() -> None:
    # ALL_CONSTRAINTS had no GENERATED column (#2141). 23ai's: GENERATED NAME
    # for each unnamed constraint, a NOT NULL among them, USER NAME otherwise.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2141g (id NUMBER PRIMARY KEY, n NUMBER NOT NULL, '
            'k NUMBER, CONSTRAINT named_u UNIQUE (k))'
        )
        try:
            assert backend.execute(
                'SELECT constraint_type, generated FROM user_constraints '
                "WHERE table_name = 'T2141G' ORDER BY constraint_type"
            ).rows == [
                ('C', 'GENERATED NAME'),
                ('P', 'GENERATED NAME'),
                ('U', 'USER NAME'),
            ]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2141g')
    finally:
        backend.close()


def test_all_constraints_lists_a_not_null_as_oracle_does() -> None:
    # A primary key's own NOT NULL was listed as a constraint, and a NOT
    # NULL's SEARCH_CONDITION was NULL (#2171): PostgreSQL 16 has no NOT NULL
    # constraint, and information_schema makes one up for every such column.
    # 23ai lists a declared NOT NULL only, its condition `"N" IS NOT NULL`.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute(
            'CREATE TABLE t2171 (id NUMBER PRIMARY KEY, n NUMBER NOT NULL, '
            '"MixedC" NUMBER NOT NULL, o NUMBER)'
        )
        try:
            assert backend.execute(
                'SELECT constraint_type, search_condition FROM user_constraints '
                "WHERE table_name = 'T2171' ORDER BY constraint_type, search_condition"
            ).rows == [
                ('C', '"MixedC" IS NOT NULL'),
                ('C', '"N" IS NOT NULL'),
                ('P', None),
            ]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2171')
    finally:
        backend.close()


def test_user_indexes_lists_the_sessions_indexes() -> None:
    # USER_INDEXES did not exist (#2188): the dictionary had ALL_INDEXES only,
    # and orafce has none. 23ai's: the session's indexes, without OWNER.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2188 (id NUMBER, u VARCHAR2(5))')
        try:
            backend.execute('CREATE UNIQUE INDEX i2188u ON t2188 (u)')
            backend.execute('CREATE INDEX i2188 ON t2188 (id)')
            assert backend.execute(
                'SELECT index_name, table_owner, uniqueness, index_type '
                "FROM user_indexes WHERE table_name = 'T2188' ORDER BY index_name"
            ).rows == [
                ('I2188', 'PYO', 'NONUNIQUE', 'NORMAL'),
                ('I2188U', 'PYO', 'UNIQUE', 'NORMAL'),
            ]
        finally:
            backend.rollback()
            backend.execute('DROP TABLE t2188')
    finally:
        backend.close()


def test_the_user_dictionary_views_have_oracles_columns() -> None:
    # USER_CONSTRAINTS, USER_CONS_COLUMNS, USER_IND_COLUMNS and USER_VIEWS were
    # orafce's oracle.user_*, without Oracle's columns and with TABLE_NAME a
    # regclass (#2169). 23ai's answers to the queries below.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.authenticate('PYO')
        backend.open_session({})
        backend.execute('CREATE TABLE t2169 (id NUMBER PRIMARY KEY, u VARCHAR2(5))')
        try:
            backend.execute('CREATE INDEX i2169 ON t2169 (u)')
            backend.execute('CREATE VIEW v2169 AS SELECT id FROM t2169')
            assert backend.execute(
                'SELECT constraint_type, table_name, owner, status '
                "FROM user_constraints WHERE table_name = 'T2169' "
                "AND constraint_type = 'P'"
            ).rows == [('P', 'T2169', 'PYO', 'ENABLED')]
            assert backend.execute(
                'SELECT column_name, position, table_name, owner '
                "FROM user_cons_columns WHERE table_name = 'T2169'"
            ).rows == [('ID', 1, 'T2169', 'PYO')]
            assert backend.execute(
                'SELECT index_name, column_name, column_position '
                "FROM user_ind_columns WHERE table_name = 'T2169' "
                "AND index_name = 'I2169'"
            ).rows == [('I2169', 'U', 1)]
            ((name, length, text),) = backend.execute(
                'SELECT view_name, text_length, text FROM user_views '
                "WHERE view_name = 'V2169'"
            ).rows
            assert (name, length) == ('V2169', len(text))
        finally:
            backend.rollback()
            backend.execute('DROP VIEW v2169')
            backend.execute('DROP TABLE t2169')
    finally:
        backend.close()


def _hold_a_dictionary_read() -> Any:
    # A client mid-transaction that has read a dictionary view: its lock on the
    # view is what a CREATE OR REPLACE VIEW has to wait for (#1152).
    holder = psycopg.connect(_CONNINFO)
    holder.execute('SET search_path TO public, sys, oracle, pg_catalog')
    holder.execute('SELECT count(*) FROM sys.user_tables').fetchone()
    return holder


def _connect_time(deadline: float = 15.0) -> float:
    # How long a new backend takes to connect -- infinity past `deadline`, so a
    # regression fails the test rather than hanging it (the holder's rollback
    # in the caller's `finally` then frees the stuck connect).
    took: list[float] = []

    def connect() -> None:
        started = time.monotonic()
        PostgresBackend(_CONNINFO, credentials=dict(_CREDS)).close()
        took.append(time.monotonic() - started)

    worker = threading.Thread(target=connect, daemon=True)
    worker.start()
    worker.join(deadline)
    return took[0] if took else float('inf')


def test_a_held_dictionary_read_does_not_block_a_new_connection() -> None:
    # The dictionary is installed once, stamped, and left alone: every connect
    # used to CREATE OR REPLACE its views, and so waited for any open
    # transaction that had read one -- a login hang until that client ended
    # its transaction (#1152).
    PostgresBackend(_CONNINFO, credentials=dict(_CREDS)).close()  # installed
    holder = _hold_a_dictionary_read()
    try:
        assert _connect_time() < 1.5
    finally:
        holder.rollback()
        holder.close()


def test_a_held_read_delays_a_reinstall_but_does_not_hang_it() -> None:
    # When the views do have to be (re)installed -- a first start, or a seerdb
    # whose dictionary changed -- a held view makes the install give up after a
    # short wait; the session carries on with the views already there, and a
    # later connection installs them.
    with psycopg.connect(_CONNINFO, autocommit=True) as admin:
        admin.execute('COMMENT ON SCHEMA sys IS NULL')
    holder = _hold_a_dictionary_read()
    try:
        assert _connect_time() < 10
    finally:
        holder.rollback()
        holder.close()
    PostgresBackend(_CONNINFO, credentials=dict(_CREDS)).close()
    with psycopg.connect(_CONNINFO) as check:
        (stamp,) = check.execute(
            "SELECT obj_description(to_regnamespace('sys'), 'pg_namespace')"
        ).fetchone()
    assert stamp == _DICTIONARY_STAMP


def test_a_timestamptz_column_is_local_time_zone() -> None:
    # A timestamptz column is TIMESTAMP WITH LOCAL TIME ZONE (#1208), and the
    # dictionary says so; WITH TIME ZONE is the ora_tstz composite (#1272). Each
    # names its fractional-seconds precision, as Oracle's dictionary does (#1480).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('drop table if exists t_ltzcol')
        backend.execute(
            'CREATE TABLE t_ltzcol (a TIMESTAMP, b TIMESTAMP WITH TIME ZONE, '
            'c TIMESTAMP WITH LOCAL TIME ZONE)'
        )
        assert backend.execute(
            "SELECT data_type FROM all_tab_columns WHERE table_name = 'T_LTZCOL' "
            'ORDER BY column_id'
        ).rows == [
            ('TIMESTAMP(6)',),
            ('TIMESTAMP(6) WITH TIME ZONE',),
            ('TIMESTAMP(6) WITH LOCAL TIME ZONE',),
        ]
        backend.execute('drop table t_ltzcol')
        backend.commit()
    finally:
        backend.close()


def test_rownum_becomes_limit_only_where_it_means_limit() -> None:
    # A top-level `AND ROWNUM <= n` filter is LIMIT n (#1271); where Oracle
    # numbers rows before a sort, grouping, DISTINCT, aggregate, set operator,
    # OR or FOR UPDATE, the two differ, and ROWNUM is refused by name.
    from seerdb.server.backends.postgres import UnsupportedFeature, _rewrite_rownum

    rewritten = {
        'select c from t where c is not null and rownum <= 1': (
            'select c from t WHERE c is not null LIMIT 1'
        ),
        'SELECT id FROM t WHERE rownum < 3 AND a = 1': 'SELECT id FROM t WHERE a = 1 LIMIT 2',
        'SELECT id FROM t WHERE rownum = 1': 'SELECT id FROM t LIMIT 1',
        'SELECT id FROM t WHERE rownum = 2': 'SELECT id FROM t LIMIT 0',
        'SELECT id FROM t WHERE rownum <= :1': 'SELECT id FROM t LIMIT :1',
        'SELECT * FROM (SELECT id FROM t ORDER BY id) WHERE rownum <= 3': (
            'SELECT * FROM (SELECT id FROM t ORDER BY id) LIMIT 3'
        ),
        "SELECT 'rownum' FROM dual": "SELECT 'rownum' FROM dual",
    }
    for sql, expected in rewritten.items():
        assert _rewrite_rownum(sql) == expected, sql
    for sql in (
        'SELECT id FROM t WHERE rownum <= 1 ORDER BY id',
        'SELECT count(*) FROM t WHERE rownum <= 5',
        'SELECT DISTINCT a FROM t WHERE rownum <= 5',
        'SELECT id FROM t WHERE a = 1 OR rownum <= 1',
        'SELECT id FROM t WHERE rownum <= 1 FOR UPDATE',
        'SELECT id, rownum FROM t',
        'SELECT id FROM t WHERE rownum > 1',
    ):
        with pytest.raises(UnsupportedFeature):
            _rewrite_rownum(sql)


def test_a_collection_column_fetches_as_a_collection() -> None:
    # PostgreSQL describes a domain column by its base type; traced back to its
    # table, an array-domain column is the collection type, and its value a
    # collection DbObject of that type -- objects for an object element (#1206).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    drops = (
        'DROP TABLE t_collfetch',
        'DROP TYPE t_collfetch_nt',
        'DROP TYPE t_collfetch_va',
        'DROP TYPE t_collfetch_o',
    )
    try:
        for stmt in drops:
            try:
                backend.execute(stmt)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        backend.execute(
            'CREATE TYPE t_collfetch_o AS OBJECT (id NUMBER, name VARCHAR2(9))'
        )
        backend.execute('CREATE TYPE t_collfetch_va AS VARRAY(3) OF NUMBER')
        backend.execute('CREATE TYPE t_collfetch_nt AS TABLE OF t_collfetch_o')
        backend.execute(
            'CREATE TABLE t_collfetch (id NUMBER, v t_collfetch_va, w t_collfetch_nt)'
        )
        backend.execute(
            "INSERT INTO t_collfetch VALUES (1, '{1,2}', "
            "ARRAY[ROW(1,'a')::t_collfetch_o, ROW(2,'b')::t_collfetch_o])"
        )
        backend.execute("INSERT INTO t_collfetch VALUES (2, '{}', NULL)")
        result = backend.execute('SELECT v, w FROM t_collfetch ORDER BY id')
        assert [c.type_name for c in result.columns] == [
            b'T_COLLFETCH_VA',
            b'T_COLLFETCH_NT',
        ]
        (v1, w1), (v2, w2) = result.rows
        assert v1.aslist() == [1, 2]
        assert [(e.ID, e.NAME) for e in w1.aslist()] == [(1, 'a'), (2, 'b')]
        assert (v2.aslist(), w2) == ([], None)
        for stmt in drops:
            backend.execute(stmt)
        backend.commit()
    finally:
        backend.close()


def test_a_collection_bind_is_bound_as_its_array() -> None:
    # A collection image whose OID names an array domain is decoded against the
    # element type and bound as the array; object elements as composites (#1206).
    from seerdb.common.dbobject import ObjectImage
    from seerdb.common.tns import encode_object_image

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    drops = (
        'DROP TABLE t_collbind',
        'DROP TYPE t_collbind_nt',
        'DROP TYPE t_collbind_va',
        'DROP TYPE t_collbind_o',
    )
    try:
        for stmt in drops:
            try:
                backend.execute(stmt)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        backend.execute(
            'CREATE TYPE t_collbind_o AS OBJECT (id NUMBER, name VARCHAR2(9))'
        )
        backend.execute('CREATE TYPE t_collbind_va AS VARRAY(3) OF NUMBER')
        backend.execute('CREATE TYPE t_collbind_nt AS TABLE OF t_collbind_o')
        backend.execute(
            'CREATE TABLE t_collbind (id NUMBER, v t_collbind_va, w t_collbind_nt)'
        )
        oids = dict(
            backend.execute(
                'SELECT type_name, type_oid FROM all_types '
                "WHERE type_name LIKE 'T_COLLBIND%'"
            ).rows
        )
        va = _present(
            backend._collection_type(_present(_pg_oid_of(bytes(oids['T_COLLBIND_VA']))))
        )
        nt = _present(
            backend._collection_type(_present(_pg_oid_of(bytes(oids['T_COLLBIND_NT']))))
        )
        elem = nt.element['object_type']
        images = [
            ObjectImage(
                bytes(oids[t.name]), t.schema, t.name, None, encode_object_image(v)
            )
            for t, v in (
                (va, va.newobject([5, Decimal('10.5')])),
                (nt, nt.newobject([elem.newobject({'ID': 1, 'NAME': 'a'})])),
            )
        ]
        backend.execute('INSERT INTO t_collbind VALUES (1, :1, :2)', images)
        (v, w) = backend.execute('SELECT v, w FROM t_collbind').rows[0]
        assert v.aslist() == [5, Decimal('10.5')]
        assert [(e.ID, e.NAME) for e in w.aslist()] == [(1, 'a')]
        for stmt in drops:
            backend.execute(stmt)
        backend.commit()
    finally:
        backend.close()


def test_lob_attributes_are_clob_and_blob() -> None:
    # An object's CLOB / BLOB attribute is the ora_clob / ora_blob domain; it is
    # listed and described as CLOB / BLOB, not taken for a nested object type,
    # fetches as its content, and binds back from the locators the Mirror served
    # -- NULL for one it never served (#1256).
    from seerdb.common.dbobject import ObjectImage
    from seerdb.common.lob import LOB
    from seerdb.common.tns import encode_object_image
    from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_CLOB

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        for stmt in ('DROP TABLE t_lobattr', 'DROP TYPE t_lobattr_o'):
            try:
                backend.execute(stmt)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        backend.execute('CREATE TYPE t_lobattr_o AS OBJECT (id NUMBER, c CLOB, b BLOB)')
        backend.execute('CREATE TABLE t_lobattr (k NUMBER, o t_lobattr_o)')
        assert backend.execute(
            'SELECT attr_name, attr_type_name, attr_type_owner FROM all_type_attrs '
            "WHERE type_name = 'T_LOBATTR_O' ORDER BY attr_no"
        ).rows == [('ID', 'NUMBER', None), ('C', 'CLOB', None), ('B', 'BLOB', None)]
        backend.execute(
            "INSERT INTO t_lobattr VALUES (1, t_lobattr_o(1, 'text', HEXTORAW('01FF')))"
        )
        (got,) = backend.execute('SELECT o FROM t_lobattr WHERE k = 1').rows[0]
        assert (got.C, got.B) == ('text', b'\x01\xff')

        (oid,) = backend.execute(
            "SELECT type_oid FROM all_types WHERE type_name = 'T_LOBATTR_O'"
        ).rows[0]
        typ, _info = _present(backend._object_type(_present(_pg_oid_of(bytes(oid)))))
        assert [a['data_type'] for a in typ.attrs][1:] == [TNS_TYPE_CLOB, TNS_TYPE_BLOB]
        obj = typ.newobject(
            {
                'ID': 2,
                'C': LOB(TNS_TYPE_CLOB, b'served-clob', connection=None),
                'B': LOB(TNS_TYPE_BLOB, b'never-served', connection=None),
            }
        )
        image = ObjectImage(
            bytes(oid), typ.schema, typ.name, None, encode_object_image(obj)
        )
        image.lob_contents = {b'served-clob': ('bound text', True)}
        backend.execute('INSERT INTO t_lobattr VALUES (2, :1)', [image])
        (got,) = backend.execute('SELECT o FROM t_lobattr WHERE k = 2').rows[0]
        assert (got.C, got.B) == ('bound text', None)
        for stmt in ('DROP TABLE t_lobattr', 'DROP TYPE t_lobattr_o'):
            backend.execute(stmt)
        backend.commit()
    finally:
        backend.close()


def test_object_and_collection_attributes_nest() -> None:
    # An object whose attributes are an object and a VARRAY of objects: the
    # describe embeds both types, a fetch builds the nested DbObjects, and a
    # bound image goes back into the nested composite and array (#1265).
    from seerdb.common.dbobject import ObjectImage
    from seerdb.common.tns import encode_object_image

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    drops = (
        'DROP TABLE t_nest',
        'DROP TYPE t_nest_outer',
        'DROP TYPE t_nest_arr',
        'DROP TYPE t_nest_sub',
    )
    try:
        for stmt in drops:
            try:
                backend.execute(stmt)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        backend.execute('CREATE TYPE t_nest_sub AS OBJECT (n NUMBER, s VARCHAR2(9))')
        backend.execute('CREATE TYPE t_nest_arr AS VARRAY(3) OF t_nest_sub')
        backend.execute(
            'CREATE TYPE t_nest_outer AS OBJECT (id NUMBER, sub t_nest_sub, subs t_nest_arr)'
        )
        backend.execute('CREATE TABLE t_nest (k NUMBER, o t_nest_outer)')
        backend.execute(
            "INSERT INTO t_nest VALUES (1, t_nest_outer(1, t_nest_sub(7, 'seven'), "
            "t_nest_arr(t_nest_sub(1, 'a'))))"
        )
        (o,) = backend.execute('SELECT o FROM t_nest').rows[0]
        typ = o._dbtype
        assert [a['object_type'].name for a in typ.attrs[1:]] == [
            'T_NEST_SUB',
            'T_NEST_ARR',
        ]
        assert (o.SUB.N, o.SUB.S) == (7, 'seven')
        assert [(e.N, e.S) for e in o.SUBS.aslist()] == [(1, 'a')]
        o.ID = 2
        o.SUB.S = 'changed'
        image = ObjectImage(typ.oid, typ.schema, typ.name, None, encode_object_image(o))
        backend.execute('INSERT INTO t_nest VALUES (2, :1)', [image])
        (got,) = backend.execute('SELECT o FROM t_nest WHERE k = 2').rows[0]
        assert (got.SUB.S, [e.S for e in got.SUBS.aslist()]) == ('changed', ['a'])
        for stmt in drops:
            backend.execute(stmt)
        backend.commit()
    finally:
        backend.close()


def test_zoned_timestamp_attributes_take_oracle_names() -> None:
    # Oracle spells a zoned attribute's type TIMESTAMP WITH [LOCAL] TZ in
    # ALL_TYPE_ATTRS; a timestamptz is the LOCAL one here, and its value goes
    # out and comes back as a naive database-zone instant (#1270).
    import datetime

    from seerdb.common.dbobject import ObjectImage
    from seerdb.common.tns import encode_object_image

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        for stmt in ('DROP TABLE t_zoneattr', 'DROP TYPE t_zoneattr_o'):
            try:
                backend.execute(stmt)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        backend.execute(
            'CREATE TYPE t_zoneattr_o AS OBJECT (a TIMESTAMP, '
            'b TIMESTAMP WITH TIME ZONE, c TIMESTAMP WITH LOCAL TIME ZONE)'
        )
        backend.execute('CREATE TABLE t_zoneattr (k NUMBER, o t_zoneattr_o)')
        assert backend.execute(
            'SELECT attr_type_name FROM all_type_attrs '
            "WHERE type_name = 'T_ZONEATTR_O' ORDER BY attr_no"
        ).rows == [('TIMESTAMP',), ('TIMESTAMP WITH TZ',), ('TIMESTAMP WITH LOCAL TZ',)]
        (oid,) = backend.execute(
            "SELECT type_oid FROM all_types WHERE type_name = 'T_ZONEATTR_O'"
        ).rows[0]
        typ, _info = _present(backend._object_type(_present(_pg_oid_of(bytes(oid)))))
        given = datetime.datetime(2026, 9, 27, 13, 14, 15)
        obj = typ.newobject({'A': given, 'C': given})
        image = ObjectImage(
            bytes(oid), typ.schema, typ.name, None, encode_object_image(obj)
        )
        backend.execute('INSERT INTO t_zoneattr VALUES (1, :1)', [image])
        (got,) = backend.execute('SELECT o FROM t_zoneattr').rows[0]
        assert (got.A, got.C) == (given, given)
        for stmt in ('DROP TABLE t_zoneattr', 'DROP TYPE t_zoneattr_o'):
            backend.execute(stmt)
        backend.commit()
    finally:
        backend.close()


def test_a_collection_of_collections_fetches_and_binds() -> None:
    # A nested table whose elements are nested tables (#1276): the element type
    # is embedded, a value loads as nested collections -- a NULL and an empty
    # inner one included -- and a bound image goes back as an array literal.
    from seerdb.common.dbobject import ObjectImage
    from seerdb.common.tns import encode_object_image

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    drops = ('DROP TABLE t_coc', 'DROP TYPE t_coc_tt', 'DROP TYPE t_coc_t1')
    try:
        for stmt in drops:
            try:
                backend.execute(stmt)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        backend.execute('CREATE TYPE t_coc_t1 AS TABLE OF NUMBER')
        backend.execute('CREATE TYPE t_coc_tt AS TABLE OF t_coc_t1')
        backend.execute('CREATE TABLE t_coc (id NUMBER, c t_coc_tt)')
        backend.execute(
            'INSERT INTO t_coc VALUES (1, t_coc_tt(t_coc_t1(1, 2), NULL, t_coc_t1()))'
        )
        (c,) = backend.execute('SELECT c FROM t_coc').rows[0]
        assert c._dbtype.element['object_type'].name == 'T_COC_T1'
        assert [None if e is None else e.aslist() for e in c.aslist()] == [
            [1, 2],
            None,
            [],
        ]
        typ = c._dbtype
        image = ObjectImage(typ.oid, typ.schema, typ.name, None, encode_object_image(c))
        backend.execute('INSERT INTO t_coc VALUES (2, :1)', [image])
        (c2,) = backend.execute('SELECT c FROM t_coc WHERE id = 2').rows[0]
        assert [None if e is None else e.aslist() for e in c2.aslist()] == [
            [1, 2],
            None,
            [],
        ]
        for stmt in drops:
            backend.execute(stmt)
        backend.commit()
    finally:
        backend.close()


def test_an_array_literal_quotes_every_element() -> None:
    # NULL bare; strings, timestamps and inner literals quoted, `"` and `\\`
    # escaped, so PostgreSQL parses each by the element type (#1276).
    import datetime
    from decimal import Decimal

    from seerdb.server.backends.postgres import _array_literal

    assert (
        _array_literal([None, Decimal('1.5'), 'a"b\\c']) == '{NULL,"1.5","a\\"b\\\\c"}'
    )
    assert (
        _array_literal([datetime.datetime(2026, 1, 2, 3, 4, 5)])
        == '{"2026-01-02 03:04:05"}'
    )
    assert (
        _array_literal([_array_literal([1, 2]), None]) == '{"{\\"1\\",\\"2\\"}",NULL}'
    )


def test_dictionary_views_preserve_quoted_identifier_case() -> None:
    # Oracle stores an unquoted identifier upper-case and a quoted one verbatim;
    # PostgreSQL folds unquoted names lower-case. sys.ora_name() reconstructs the
    # Oracle-stored form so a reflecting client sees a plain name UPPER-cased and a
    # quoted mixed-case name unchanged — the round trip the SQLAlchemy Oracle
    # dialect's normalize/denormalize relies on for *_quoted_name reflection.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('drop table if exists quoted_ident')
        backend.execute('CREATE TABLE quoted_ident (plain NUMBER, "mixedCase" NUMBER)')
        backend.commit()
        names = {
            r[0]
            for r in backend.execute(
                'SELECT column_name FROM all_tab_columns '
                "WHERE table_name = 'QUOTED_IDENT'"
            ).rows
        }
        # A quoted mixed-case name survives byte-for-byte; a plain name is UPPER'd.
        assert names == {'PLAIN', 'mixedCase'}
        backend.execute('drop table quoted_ident')
        backend.commit()
    finally:
        backend.close()


def test_dictionary_views_report_desc_index_as_expression() -> None:
    # Oracle represents a descending index column as a function-based index: the
    # column shows up in all_ind_expressions as the quoted expression "COL" and its
    # all_ind_columns row is marked DESC, so the dialect reflects it with an
    # expression and column_sorting rather than a plain column. PostgreSQL stores it
    # as a plain descending key, so the views reconstruct Oracle's shape (#759).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('drop table if exists desc_idx')
        backend.execute('CREATE TABLE desc_idx (id NUMBER, q NUMBER, b VARCHAR2(20))')
        backend.execute('CREATE INDEX desc_ix ON desc_idx (q DESC)')
        backend.execute('CREATE INDEX asc_ix ON desc_idx (b)')
        backend.commit()
        # The descending column is DESC in all_ind_columns and an expression "Q".
        assert backend.execute(
            'SELECT descend FROM all_ind_columns '
            "WHERE index_name = 'DESC_IX' AND column_name = 'Q'"
        ).rows == [('DESC',)]
        assert backend.execute(
            'SELECT column_expression FROM all_ind_expressions '
            "WHERE index_name = 'DESC_IX'"
        ).rows == [('"Q"',)]
        # A plain ascending index carries no expression row and stays ASC.
        assert backend.execute(
            "SELECT descend FROM all_ind_columns WHERE index_name = 'ASC_IX'"
        ).rows == [('ASC',)]
        assert (
            backend.execute(
                'SELECT column_expression FROM all_ind_expressions '
                "WHERE index_name = 'ASC_IX'"
            ).rows
            == []
        )
        backend.execute('drop table desc_idx')
        backend.commit()
    finally:
        backend.close()


def test_dictionary_views_keep_reserved_word_columns_lowercase() -> None:
    # A reserved word (asc, desc, ...) can only be a column name when quoted, and a
    # quoted identifier keeps its case in both Oracle and PostgreSQL. sys.ora_name()
    # must therefore leave a reserved word lower-case rather than fold it upper the
    # way it does a plain identifier, so reflection round-trips it (#759).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('drop table if exists reserved_cols')
        backend.execute(
            'CREATE TABLE reserved_cols (a NUMBER, "asc" NUMBER, "desc" NUMBER)'
        )
        backend.commit()
        cols = {
            r[0]
            for r in backend.execute(
                'SELECT column_name FROM all_tab_columns '
                "WHERE table_name = 'RESERVED_COLS'"
            ).rows
        }
        # A plain name folds upper; the reserved words stay exactly as stored.
        assert cols == {'A', 'asc', 'desc'}
        backend.execute('drop table reserved_cols')
        backend.commit()
    finally:
        backend.close()


def test_dictionary_views_list_schemas_as_users() -> None:
    # get_schema_names()/has_schema() read all_users; every schema is an Oracle user
    # under its upper-cased name, except the emulation layer (oracle, sys) and
    # PostgreSQL's own schemas, which stay hidden (#759).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE SCHEMA IF NOT EXISTS unit_user_schema')
        backend.commit()
        users = {r[0] for r in backend.execute('SELECT username FROM all_users').rows}
        assert 'UNIT_USER_SCHEMA' in users
        assert 'PUBLIC' in users
        assert 'SYS' not in users and 'ORACLE' not in users
        assert not any(u.startswith('PG_') for u in users)
        backend.execute('DROP SCHEMA unit_user_schema')
        backend.commit()
    finally:
        backend.close()


def test_dictionary_views_reflect_an_identity_column() -> None:
    # A PostgreSQL identity column surfaces in all_tab_identity_cols with its Oracle
    # generation type, so the dialect (once it believes the server is 12c) reflects it
    # as an identity rather than raising ORA-00942 on the missing view (#33). The
    # dialect renders an autoincrement column as INTEGER, the integer type a
    # PostgreSQL identity column requires.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('drop table if exists id_reflect')
        backend.execute(
            'CREATE TABLE id_reflect (id INTEGER GENERATED BY DEFAULT AS IDENTITY, '
            'data VARCHAR2(20))'
        )
        backend.commit()
        rows = backend.execute(
            'SELECT column_name, generation_type FROM all_tab_identity_cols '
            "WHERE table_name = 'ID_REFLECT'"
        ).rows
        assert rows == [('ID', 'BY DEFAULT')]
        # A non-identity column is not reported here.
        assert not backend.execute(
            'SELECT column_name FROM all_tab_identity_cols '
            "WHERE table_name = 'ID_REFLECT' AND column_name = 'DATA'"
        ).rows
        backend.execute('drop table id_reflect')
        backend.commit()
    finally:
        backend.close()


def test_utl_raw_functions() -> None:
    # UTL_RAW is orafce's utl_raw schema (4.17), so a schema-qualified Oracle call
    # round-trips RAW/bytea (#765).
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:

        def scalar(sql: str):
            return backend.execute(sql).rows[0][0]

        # CAST_TO_RAW / CAST_TO_VARCHAR2 round-trip a string through its bytes.
        assert scalar("SELECT rawtohex(utl_raw.cast_to_raw('ABC'))") == '414243'
        assert scalar("SELECT utl_raw.cast_to_varchar2(hextoraw('414243'))") == 'ABC'
        # LENGTH, SUBSTR (1-based; negative counts from the end), CONCAT.
        assert scalar("SELECT utl_raw.length(hextoraw('DEADBEEF'))") == 4
        assert scalar(
            "SELECT rawtohex(utl_raw.substr(hextoraw('DEADBEEF'), 2, 2))"
        ) == ('ADBE')
        assert (
            scalar("SELECT rawtohex(utl_raw.substr(hextoraw('DEADBEEF'), -1))") == 'EF'
        )
        assert (
            scalar(
                "SELECT rawtohex(utl_raw.concat(hextoraw('DEAD'), hextoraw('BEEF')))"
            )
            == 'DEADBEEF'
        )
        # Bitwise ops; the tail of the longer operand is appended, like Oracle.
        assert (
            scalar(
                "SELECT rawtohex(utl_raw.bit_and(hextoraw('F0F0'), hextoraw('FF00')))"
            )
            == 'F000'
        )
        assert (
            scalar(
                "SELECT rawtohex(utl_raw.bit_or(hextoraw('F000'), hextoraw('0F0F')))"
            )
            == 'FF0F'
        )
        assert (
            scalar("SELECT rawtohex(utl_raw.bit_xor(hextoraw('FF'), hextoraw('0F')))")
            == 'F0'
        )
        assert (
            scalar("SELECT rawtohex(utl_raw.bit_and(hextoraw('FFFF'), hextoraw('F0')))")
            == 'F0FF'
        )
        # As Oracle 11g, 18c and 23ai answer (#800): SUBSTR reads a position of
        # 0 or NULL as 1 and refuses a range past the end; a NULL operand of a
        # bitwise op makes NULL.
        assert scalar("SELECT rawtohex(utl_raw.substr(hextoraw('4142'), 0))") == '4142'
        assert (
            scalar("SELECT rawtohex(utl_raw.substr(hextoraw('4142'), NULL, 1))") == '41'
        )
        with pytest.raises(BackendError):
            backend.execute("SELECT utl_raw.substr(hextoraw('4142'), 2, 2)")
        assert scalar('SELECT utl_raw.bit_and(NULL, NULL)') is None
    finally:
        backend.close()


def test_dbms_utility_functions() -> None:
    # The DBMS_UTILITY entry points orafce does not ship (#764): FORMAT_ERROR_STACK
    # / FORMAT_ERROR_BACKTRACE return the empty string a no-active-error context
    # yields in Oracle; DB_VERSION returns the demo's advertised release via the
    # callproc OUT-bind path. (GET_TIME / FORMAT_CALL_STACK already come from orafce.)
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        assert backend.execute('SELECT dbms_utility.format_error_stack()').rows == [
            ('',)
        ]
        assert backend.execute('SELECT dbms_utility.format_error_backtrace()').rows == [
            ('',)
        ]
        from seerdb.common.tns_consts import TNS_TYPE_VARCHAR
        from seerdb.server.backend import BindVar

        result = backend.execute(
            'BEGIN DBMS_UTILITY.DB_VERSION(:1, :2); END;',
            [
                BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=64),
                BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=64),
            ],
        )
        assert result.out_binds == ['12.1.0.2.0', '12.1.0.0.0']
    finally:
        backend.close()


def test_describe_type_answers_an_oci_type_describe() -> None:
    # sqlplus describes DBMSOUTPUT_LINESARRAY by name under `set serveroutput
    # on`; the backend answers with the type's identity and the TDS pair, which
    # for this type are the live 11g ones byte for byte (#1411). A user's types
    # describe the same way; a name that is no type is None.
    import os

    sys.path.insert(0, os.path.dirname(__file__))
    import kod_11g as fx

    from seerdb.common.tns import decode_kod_image, decode_kod_reply

    (record,) = decode_kod_reply(fx.BY_NAME_REPLY).records
    captured = decode_kod_image(record.image)
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        lines = backend.describe_type('DBMSOUTPUT_LINESARRAY')
        assert lines is not None
        assert (lines.schema, lines.name, lines.kind) == (
            'SYS',
            'DBMSOUTPUT_LINESARRAY',
            'varray',
        )
        assert (lines.tds, lines.null_tds) == (captured[5], captured[6])
        backend.execute('CREATE TYPE kod1411_va AS VARRAY(10) OF NUMBER')
        backend.execute('CREATE TYPE kod1411_nt AS TABLE OF VARCHAR2(30)')
        backend.execute('CREATE TYPE kod1411_obj AS OBJECT (n NUMBER, s VARCHAR2(20))')
        backend.commit()
        kinds = {
            name: backend.describe_type(name)
            for name in ('KOD1411_VA', 'KOD1411_NT', 'KOD1411_OBJ')
        }
        assert {n: d.kind for n, d in kinds.items() if d} == {
            'KOD1411_VA': 'varray',
            'KOD1411_NT': 'nested_table',
            'KOD1411_OBJ': 'object',
        }
        assert backend.describe_type('NO_SUCH_TYPE_1411') is None
    finally:
        for name in ('kod1411_va', 'kod1411_nt', 'kod1411_obj'):
            try:
                backend.execute(f'DROP TYPE {name}')
                backend.commit()
            except Exception:
                backend.rollback()
        backend.close()


def test_a_call_with_named_binds_passes_them() -> None:
    # A call block's binds may be named as well as numbered; a client sends the
    # values one per distinct placeholder in order of first appearance either
    # way. A named one used to find no argument at all: the routine ran with
    # none and the binds came back as they went in (#1529).
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar

    def outs() -> list:
        return [
            BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=32767),
            BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22),
        ]

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'BEGIN DBMS_OUTPUT.ENABLE(:1); END;',
            [BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22)],
        )
        for sql, want in (
            ('BEGIN DBMS_OUTPUT.GET_LINE(:1, :2); END;', ['hello', 0]),
            ('BEGIN DBMS_OUTPUT.GET_LINE(:l, :s); END;', ['hello', 0]),
            # By name, in the order the placeholders first appear.
            (
                'BEGIN DBMS_OUTPUT.GET_LINE(status => :s, line => :l); END;',
                [0, 'hello'],
            ),
        ):
            backend.execute(
                'BEGIN DBMS_OUTPUT.PUT_LINE(:1); END;',
                [BindVar(value='hello', tns_type=TNS_TYPE_VARCHAR, max_size=4000)],
            )
            assert backend.execute(sql, outs()).out_binds == want, sql
    finally:
        backend.close()


def test_a_call_with_literal_arguments_passes_them() -> None:
    # sqlplus's `BEGIN DBMS_OUTPUT.ENABLE(NULL); END;`, a script's
    # `put_line('...')`: a call's literal arguments go in as written. They used
    # to be dropped, the routine called without them -- and for DBMS_OUTPUT the
    # failure was swallowed, so the line silently never arrived (#1531).
    from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('BEGIN DBMS_OUTPUT.ENABLE(NULL); END;', [])
        backend.execute("BEGIN DBMS_OUTPUT.PUT_LINE('it''s literal'); END;", [])
        backend.execute(
            'BEGIN DBMS_OUTPUT.PUT_LINE(:1); END;',
            [BindVar(value='bound', tns_type=TNS_TYPE_VARCHAR, max_size=4000)],
        )
        lines = [
            backend.execute(
                'BEGIN DBMS_OUTPUT.GET_LINE(:1, :2); END;',
                [
                    BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=32767),
                    BindVar(value=None, tns_type=TNS_TYPE_NUMBER, max_size=22),
                ],
            ).out_binds
            for _ in range(3)
        ]
        assert lines == [["it's literal", 0], ['bound', 0], [None, 1]]
    finally:
        backend.close()


def test_put_line_prints_a_number_as_plsql_converts_it() -> None:
    # DBMS_OUTPUT.PUT_LINE(1) was PLS-00306: orafce's takes text (#2181).
    # 23ai converts the NUMBER as PL/SQL does, not as SQL's TO_CHAR: no
    # leading zero, no trailing zeros, and no 40-character limit.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('BEGIN DBMS_OUTPUT.ENABLE(NULL); END;', [])
        backend.execute(
            'BEGIN DBMS_OUTPUT.PUT_LINE(1); DBMS_OUTPUT.PUT_LINE(1.50); '
            'DBMS_OUTPUT.PUT_LINE(-0.5); DBMS_OUTPUT.PUT_LINE(1e40); '
            'DBMS_OUTPUT.PUT_LINE(1/3); DBMS_OUTPUT.PUT(7); DBMS_OUTPUT.PUT(8.0); '
            'DBMS_OUTPUT.NEW_LINE; END;',
            [],
        )
        ((lines,),) = backend.execute(
            "SELECT array_to_string(lines, '|') FROM dbms_output.get_lines(10)"
        ).rows
        assert lines.split('|') == [
            '1',
            '1.5',
            '-.5',
            '1' + '0' * 40,
            '.' + '3' * 40,
            '78',
        ]
    finally:
        backend.close()


def test_get_lines_hands_back_a_collection_object() -> None:
    # sqlplus reads DBMS_OUTPUT.GET_LINES with the lines bound as
    # DBMSOUTPUT_LINESARRAY (#1411). orafce returns them as text[]; the bind's
    # type id makes them an object of that type, which the Mirror encodes.
    from seerdb.common.dbobject import DbObject
    from seerdb.common.tns_consts import TNS_TYPE_ADT, TNS_TYPE_NUMBER
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        lines_type = backend.describe_type('DBMSOUTPUT_LINESARRAY')
        assert lines_type is not None
        backend.execute('BEGIN DBMS_OUTPUT.ENABLE(NULL); END;', [])
        backend.execute("BEGIN DBMS_OUTPUT.PUT_LINE('first'); END;", [])
        backend.execute("BEGIN DBMS_OUTPUT.PUT_LINE('second'); END;", [])
        result = backend.execute(
            'BEGIN DBMS_OUTPUT.GET_LINES(:LINES, :NUMLINES); END;',
            [
                BindVar(
                    value=None,
                    tns_type=TNS_TYPE_ADT,
                    max_size=2000,
                    toid=lines_type.oid,
                ),
                BindVar(value=15, tns_type=TNS_TYPE_NUMBER, max_size=22),
            ],
        )
        (lines, count) = result.out_binds
        assert isinstance(lines, DbObject)
        assert lines.aslist()[:count] == ['first', 'second']
        assert count == 2
    finally:
        backend.close()


def test_an_xmltype_column_holds_and_describes_a_document() -> None:
    # CREATE TABLE ... XMLTYPE failed with ORA-00902 (#1536). The column is
    # PostgreSQL's xml, described as Oracle describes an XMLType one -- an ADT of
    # SYS.XMLTYPE -- and its value comes back as the document's text, which the
    # Mirror serves as an XMLType image. A string inserts into it, and so does
    # SYS.XMLTYPE(...).
    from seerdb.common.tns_consts import TNS_TYPE_ADT

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TABLE xml1536 (IntCol NUMBER(9) NOT NULL, XMLCol XMLTYPE NOT NULL)'
        )
        backend.execute(
            'INSERT INTO xml1536 (IntCol, XMLCol) VALUES (:1, :2)', [1, '<a>one</a>']
        )
        backend.execute(
            'INSERT INTO xml1536 (IntCol, XMLCol) VALUES (:1, sys.xmltype(:2))',
            [2, '<a>two</a>'],
        )
        result = backend.execute('SELECT XMLCol FROM xml1536 ORDER BY IntCol')
        (column,) = result.columns
        assert column.data_type == TNS_TYPE_ADT
        assert (column.type_schema, column.type_name) == (b'SYS', b'XMLTYPE')
        assert column.type_oid == bytes.fromhex('00000000000000000000000000020100')
        assert result.rows == [('<a>one</a>',), ('<a>two</a>',)]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE xml1536')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_the_type_shape_of_xmltype_is_oracles() -> None:
    # A client resolves an XMLType column's type through
    # DBMS_PICKLER.GET_TYPE_SHAPE before reading it; SYS.XMLTYPE has no
    # PostgreSQL type to look up, and was refused as an invalid type name. It
    # answers as a live 23ai does (#1536).
    from seerdb.common.tns_consts import TNS_TYPE_RAW, TNS_TYPE_VARCHAR
    from seerdb.server.backend import BindVar
    from seerdb.server.backends.postgres import _XMLTYPE_OID, _XMLTYPE_TDS

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        block = (
            'begin :ret_val := dbms_pickler.get_type_shape(:full_name, :oid, '
            ':version, :tds, t1, t2, t3, :attrs_rc, t4); end;'
        )
        binds = [
            BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=22),
            BindVar(value='"SYS"."XMLTYPE"', tns_type=TNS_TYPE_VARCHAR, max_size=200),
            BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=16),
            BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=22),
            BindVar(value=None, tns_type=TNS_TYPE_RAW, max_size=2000),
            BindVar(value=None, tns_type=TNS_TYPE_VARCHAR, max_size=22),
        ]
        (ret, _name, oid, version, tds, _attrs) = backend.execute(
            block, binds
        ).out_binds
        assert (ret, oid, version, tds) == (0, _XMLTYPE_OID, 1, _XMLTYPE_TDS)
    finally:
        backend.close()


def test_an_xmltype_attribute_or_element_has_23ais_tds() -> None:
    # An XMLType attribute or element is a reference to SYS.XMLTYPE's opaque
    # descriptor: `1b <block> 3a` and the block 23ai carries, where an object's
    # reference ends fa and a collection's fb (#1537). Both measured on 23ai.
    from seerdb.server.backends.postgres import (
        _TDS_XMLTYPE,
        _tds,
        _tds_chars,
        _tds_number,
        _TdsCollection,
        _TdsObject,
    )

    obj = _TdsObject((_tds_number(), _TDS_XMLTYPE, _tds_chars(7, 60, False)))
    assert _tds(obj) == bytes.fromhex(
        '0000003626010001000300290000000000270600811b000000223a07003c0100002afd'
        '0000000d010000000700000000000000090007000a0010'
    )
    table = _TdsCollection(varray=False, bound=0, element=_TDS_XMLTYPE)
    assert _tds(table) == bytes.fromhex(
        '00000033260100010001ff290000000000281c0000001d00000000022a1b000000233afd'
        '0000000d010000000700000000000000090007'
    )


def test_an_object_with_an_xmltype_attribute_fetches() -> None:
    # An object with an XMLType attribute -- python-oracledb's
    # udt_ObjectWithXmlType -- was refused as having no Oracle attribute type
    # (#1537). It fetches with the document in the attribute, which describes
    # as SYS.XMLTYPE.
    from seerdb.server.backends.postgres import _XMLTYPE_OID

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TYPE xa1537 AS OBJECT '
            '(NumberValue NUMBER, XMLValue sys.xmltype, StringValue VARCHAR2(60))'
        )
        backend.commit()
        result = backend.execute(
            "SELECT xa1537(1, sys.xmltype('<item>one</item>'), 'abc') FROM dual"
        )
        (obj,) = result.rows[0]
        assert obj.XMLVALUE == '<item>one</item>'
        assert (obj.NUMBERVALUE, obj.STRINGVALUE) == (1, 'abc')
        pg_oid = _fetched_row(backend._conn.execute("SELECT 'xa1537'::regtype::oid"))[0]
        rows = backend._attribute_rows(pg_oid)
        assert (rows[1][3], rows[1][4], rows[1][6]) == ('XMLTYPE', 'SYS', _XMLTYPE_OID)
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TYPE xa1537')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_a_table_of_xmltype_names_sys_xmltype_its_element() -> None:
    # The dictionary names an XMLType element SYS.XMLTYPE, as Oracle does;
    # it said "None"."XML", which a client then failed to describe (#1537).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TYPE xt1537 AS TABLE OF sys.xmltype')
        backend.commit()
        result = backend.execute(
            'SELECT elem_type_owner, elem_type_name FROM all_coll_types '
            "WHERE type_name = 'XT1537'"
        )
        assert result.rows == [('SYS', 'XMLTYPE')]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TYPE xt1537')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_a_collection_of_a_national_type_stays_national() -> None:
    # A collection of NVARCHAR2 / NCHAR was reported as one of VARCHAR2 / CHAR:
    # its domain has no relation for sys.ora_columns to record the element by
    # (#1437). The dictionary, the TDS and the element's character set now say
    # what 23ai does; the TDS is 23ai's byte for byte.
    from seerdb.common.tns import AL16UTF16_CHARSET
    from seerdb.server.backends.postgres import _tds

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    types = {
        'na1437': 'TABLE OF NVARCHAR2(10)',
        'nb1437': 'VARRAY(5) OF NCHAR(3)',
        'nc1437': 'TABLE OF VARCHAR2(10)',
    }
    try:
        for name, definition in types.items():
            backend.execute(f'CREATE TYPE {name} AS {definition}')
        backend.commit()
        result = backend.execute(
            'SELECT type_name, elem_type_name, length, character_set_name '
            "FROM user_coll_types WHERE type_name LIKE 'N_1437' ORDER BY 1"
        )
        assert result.rows == [
            ('NA1437', 'NVARCHAR2', 10, 'NCHAR_CS'),
            ('NB1437', 'NCHAR', 3, 'NCHAR_CS'),
            ('NC1437', 'VARCHAR2', 10, 'CHAR_CS'),
        ]
        expected = {
            'na1437': '00000021260100010001ff290000000000161c0000001d00000000022a'
            '0700148200000007',
            'nb1437': '00000021260100010001ff290000000000161c0000001d00000005032a'
            '0100068200000007',
            'nc1437': '00000021260100010001ff290000000000161c0000001d00000000022a'
            '07000a0100000007',
        }
        for name, tds in expected.items():
            pg_oid = _fetched_row(
                backend._conn.execute(f"SELECT '{name}'::regtype::oid")
            )[0]
            assert _tds(backend._type_shape(pg_oid)).hex() == tds, name
            element = _present(backend._collection_type(pg_oid)).element
            national = name != 'nc1437'
            assert (element['charset'] == AL16UTF16_CHARSET) is national, name
        # A type that is gone takes its record with it.
        backend.execute('DROP TYPE na1437')
        backend.commit()
        left = _fetched_row(
            backend._conn.execute(
                'SELECT count(*) FROM sys.ora_collection_elements x '
                'WHERE NOT EXISTS (SELECT 1 FROM pg_type t WHERE t.oid = x.typid)'
            )
        )[0]
        assert left == 0
    finally:
        backend.rollback()
        for name in types:
            try:
                backend.execute(f'DROP TYPE {name}')
                backend.commit()
            except Exception:
                backend.rollback()
        backend.close()


def test_a_collection_bound_into_a_select_list_fetches_as_the_collection() -> None:
    # `SELECT :o FROM dual` with a collection bound described a plain array --
    # PostgreSQL types a bare placeholder from its value -- and fetched the
    # array's text (#1541). The bind is cast to its domain, which names the
    # collection type, as a constructor call's name does (#1473).
    from seerdb.common.dbobject import ObjectImage
    from seerdb.common.tns import encode_object_image

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TYPE cb1541 AS VARRAY(5) OF VARCHAR2(10)')
        backend.commit()
        pg_oid = _fetched_row(backend._conn.execute("SELECT 'cb1541'::regtype::oid"))[0]
        typ = _present(backend._collection_type(pg_oid))
        image = encode_object_image(typ.newobject(['a', 'é']))
        bind = ObjectImage(typ.oid, typ.schema, typ.name, 0, image)
        result = backend.execute('SELECT :o v FROM dual', [bind])
        assert result.columns[0].type_name == b'CB1541'
        (value,) = result.rows[0]
        assert value.aslist() == ['a', 'é']
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TYPE cb1541')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_an_objects_raw_attribute_is_raw() -> None:
    # A RAW(n) attribute, a bytea here, was described and carried as a BLOB
    # (#1544). Its record says RAW(n): the dictionary, the attribute cursor and
    # the TDS -- 23ai's byte for byte, leaf `13 0010` -- now say so too.
    from seerdb.server.backends.postgres import _tds

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TYPE ra1544 AS OBJECT (n NUMBER, r RAW(16), s VARCHAR2(5))'
        )
        backend.commit()
        result = backend.execute(
            'SELECT attr_name, attr_type_name, length FROM user_type_attrs '
            "WHERE type_name = 'RA1544' ORDER BY attr_no"
        )
        assert result.rows == [
            ('N', 'NUMBER', None),
            ('R', 'RAW', 16),
            ('S', 'VARCHAR2', 5),
        ]
        pg_oid = _fetched_row(backend._conn.execute("SELECT 'ra1544'::regtype::oid"))[0]
        assert _tds(backend._type_shape(pg_oid)).hex() == (
            '0000002126010001000300290000000000120600811300100700050100002a0007000a000d'
        )
        row = backend._attribute_rows(pg_oid)[1]
        assert (row[3], row[6]) == ('RAW', bytes(15) + b'\x17')
        result = backend.execute("SELECT ra1544(2, hextoraw('ABCD'), 'y') FROM dual")
        assert result.rows[0][0].R == b'\xab\xcd'
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TYPE ra1544')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_a_float_column_keeps_the_digits_its_bits_hold() -> None:
    # FLOAT(b) keeps ceil(b * log10(2)) significant digits, rounded half away
    # from zero: 1, 4, 16, 19 (REAL) and 38 (FLOAT) here (#1422). INSERT and
    # UPDATE alike, and an ALTER moves the limit. The values are 23ai's; long
    # literals, as PostgreSQL divides to fewer digits than Oracle.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TABLE f1422 (id NUMBER, a FLOAT(1), b FLOAT(10), c FLOAT(53), '
            'd REAL, e FLOAT)'
        )
        for i, value in enumerate(
            (
                '0.' + '3' * 42,
                '-0.' + '6' * 42,
                '123456789.123456789',
                '0.000123456789',
                '9.99951',
                '25',
            )
        ):
            backend.execute(
                f'INSERT INTO f1422 VALUES ({i}, {value}, {value}, {value}, '
                f'{value}, {value})'
            )
        backend.execute('UPDATE f1422 SET b = 98765.4321 WHERE id = 5')
        rows = backend.execute('SELECT a, b, c, d, e FROM f1422 ORDER BY id').rows
        expected = [
            ('0.3', '0.3333', '0.' + '3' * 16, '0.' + '3' * 19, '0.' + '3' * 38),
            (
                '-0.7',
                '-0.6667',
                '-0.' + '6' * 15 + '7',
                '-0.' + '6' * 18 + '7',
                '-0.' + '6' * 37 + '7',
            ),
            (
                '1E8',
                '1.235E8',
                '123456789.1234568',
                '123456789.123456789',
                '123456789.123456789',
            ),
            (
                '0.0001',
                '0.0001235',
                '0.000123456789',
                '0.000123456789',
                '0.000123456789',
            ),
            ('10', '10', '9.99951', '9.99951', '9.99951'),
            ('30', '98770', '25', '25', '25'),
        ]
        assert [tuple(row) for row in rows] == [
            tuple(Decimal(value) for value in row) for row in expected
        ]
        backend.execute('ALTER TABLE f1422 MODIFY (b FLOAT(20))')
        backend.execute('UPDATE f1422 SET b = 98765.4321 WHERE id = 5')
        (row,) = backend.execute('SELECT b FROM f1422 WHERE id = 5').rows
        assert row[0] == Decimal('98765.43')
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE f1422')
        except Exception:
            backend.rollback()


def test_an_objects_float_attribute_is_a_number_of_binary_precision() -> None:
    # An object's FLOAT / REAL / DOUBLE PRECISION attribute was PostgreSQL's
    # binary float (#1423). Oracle makes it a NUMBER of binary precision, as a
    # table's FLOAT column (#1384), listed by the name it was declared with: a
    # numeric here, its declaration recorded. The TDS is 23ai's byte for byte.
    from seerdb.server.backends.postgres import _tds

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TYPE fa1423 AS OBJECT '
            '(r REAL, d DOUBLE PRECISION, f FLOAT, f10 FLOAT(10), n NUMBER)'
        )
        backend.commit()
        result = backend.execute(
            'SELECT attr_name, attr_type_name, length, precision, scale '
            "FROM user_type_attrs WHERE type_name = 'FA1423' ORDER BY attr_no"
        )
        assert result.rows == [
            ('R', 'REAL', None, None, None),
            ('D', 'DOUBLE PRECISION', None, None, None),
            ('F', 'FLOAT', None, None, None),
            ('F10', 'FLOAT', None, 10, None),
            ('N', 'NUMBER', None, None, None),
        ]
        pg_oid = _fetched_row(backend._conn.execute("SELECT 'fa1423'::regtype::oid"))[0]
        assert _tds(backend._type_shape(pg_oid)).hex() == (
            '000000242601000100050029000000000011050005000500050a0600812a'
            '00070009000b000d000f'
        )
        assert [(row[3], row[6][-1]) for row in backend._attribute_rows(pg_oid)] == [
            ('REAL', 0x0C),
            ('DOUBLE PRECISION', 0x0D),
            ('FLOAT', 0x0E),
            ('FLOAT', 0x0E),
            ('NUMBER', 0x0F),
        ]
        result = backend.execute('SELECT fa1423(1.5, 2, 3, 4.25, 5) FROM dual')
        assert result.rows[0][0].F10 == Decimal('4.25')
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TYPE fa1423')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_an_objects_date_attribute_is_a_date() -> None:
    # An object's DATE attribute stayed timestamp(0) and described as a
    # TIMESTAMP (#1548). It is the ora_date domain, as a table's DATE column
    # is (#1316): DATE in the dictionary and the attribute cursor, and its TDS
    # leaf `02` -- 23ai's TDS byte for byte -- and it fetches as a datetime.
    from seerdb.server.backends.postgres import _tds

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TYPE da1548 AS OBJECT (n NUMBER, d DATE, t TIMESTAMP)')
        backend.commit()
        result = backend.execute(
            'SELECT attr_name, attr_type_name, attr_type_owner FROM user_type_attrs '
            "WHERE type_name = 'DA1548' ORDER BY attr_no"
        )
        assert result.rows == [
            ('N', 'NUMBER', None),
            ('D', 'DATE', None),
            ('T', 'TIMESTAMP', None),
        ]
        pg_oid = _fetched_row(backend._conn.execute("SELECT 'da1548'::regtype::oid"))[0]
        assert _tds(backend._type_shape(pg_oid)).hex() == (
            '0000001b260200010003002900000000000c0600810215062a0007000a000b'
        )
        assert backend._attribute_rows(pg_oid)[1][3] == 'DATE'
        result = backend.execute(
            "SELECT da1548(1, DATE '2024-01-02', TIMESTAMP '2024-01-02 03:04:05') "
            'FROM dual'
        )
        assert result.rows[0][0].D == datetime.datetime(2024, 1, 2)
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TYPE da1548')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_a_timestamp_attributes_scale_is_its_precision() -> None:
    # all_type_attrs listed every TIMESTAMP attribute's scale as NULL; Oracle
    # lists its fractional-seconds precision there (#1550). A WITH TIME ZONE
    # one is the ora_tstz composite, its precision recorded as a table
    # column's is (#1308). Measured on 23ai.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TYPE ts1550 AS OBJECT (d DATE, t TIMESTAMP, t3 TIMESTAMP(3), '
            't0 TIMESTAMP(0), tz TIMESTAMP(2) WITH TIME ZONE, '
            'ltz TIMESTAMP(4) WITH LOCAL TIME ZONE, tzd TIMESTAMP WITH TIME ZONE)'
        )
        backend.commit()
        result = backend.execute(
            'SELECT attr_name, attr_type_name, scale FROM user_type_attrs '
            "WHERE type_name = 'TS1550' ORDER BY attr_no"
        )
        assert result.rows == [
            ('D', 'DATE', None),
            ('T', 'TIMESTAMP', 6),
            ('T3', 'TIMESTAMP', 3),
            ('T0', 'TIMESTAMP', 0),
            ('TZ', 'TIMESTAMP WITH TZ', 2),
            ('LTZ', 'TIMESTAMP WITH LOCAL TZ', 4),
            ('TZD', 'TIMESTAMP WITH TZ', 6),
        ]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TYPE ts1550')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_a_tstz_attributes_type_shape_takes_its_precision() -> None:
    # A TIMESTAMP(n) WITH TIME ZONE attribute is the ora_tstz composite, whose
    # leaf said precision 6 whatever n was (#1552). It takes the recorded one
    # (#1550): 23ai's TDS byte for byte, `17 02` then `17 06`.
    from seerdb.server.backends.postgres import _tds

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TYPE tz1552 AS OBJECT (n NUMBER, '
            'tz TIMESTAMP(2) WITH TIME ZONE, tzd TIMESTAMP WITH TIME ZONE)'
        )
        backend.commit()
        pg_oid = _fetched_row(backend._conn.execute("SELECT 'tz1552'::regtype::oid"))[0]
        assert _tds(backend._type_shape(pg_oid)).hex() == (
            '0000001c260200010003002900000000000d060081170217062a0007000a000c'
        )
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TYPE tz1552')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_a_pg_hint_marks_a_native_statement() -> None:
    # An Oracle hint naming PG, at the start or after the first keyword, marks
    # a statement as PostgreSQL's own (#1556); any other hint, or PG inside a
    # longer word, does not.
    from seerdb.server.backends.postgres import _PG_HINT

    for sql in (
        'SELECT /*+ PG */ 1',
        '/*+ PG */ SELECT 1',
        '  -- why\n/* plain */ insert /*+ pg */ into t values (1)',
        'SELECT /*+ PG INDEX(t i) */ 1',
    ):
        assert _PG_HINT.match(sql), sql
    for sql in (
        'SELECT 1',
        'SELECT /*+ INDEX(t pg_idx) */ 1',
        'SELECT /* PG */ 1',
        "SELECT '/*+ PG */' FROM dual",
        'SELECT a, /*+ PG */ b FROM t',
    ):
        assert not _PG_HINT.match(sql), sql
    # A comment's body cannot run past its `*/`, so a run of comments matches in
    # linear time; a lazy body backtracked exponentially on this one.
    assert not _PG_HINT.match('/*' + '*//*' * 100_000)


def test_native_sql_is_off_unless_the_operator_allows_it() -> None:
    # Native PostgreSQL SQL (#1556) is the operator's choice, off by default
    # (#1859). Off, a /*+ PG */ hint is one Oracle does not know, so the
    # statement is Oracle's, translated -- SYSDATE is Oracle's, where native
    # SQL would find no such column -- and ALTER SESSION SET seerdb_dialect is
    # a parameter Oracle does not have, ORA-02248 as 23ai answers.
    import datetime

    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        (value,) = backend.execute('SELECT /*+ PG */ sysdate FROM dual').rows[0]
        assert isinstance(value, datetime.datetime)
        with pytest.raises(BackendError) as raised:
            backend.execute("ALTER SESSION SET seerdb_dialect = 'postgres'")
        assert raised.value.ora_code == 2248
    finally:
        backend.rollback()
        backend.close()


def test_native_postgresql_over_the_oracle_connection() -> None:
    # A statement hinted PG, or any in a session switched to the postgres
    # dialect, runs untranslated (#1556): ROWNUM and SYSDATE are then plain
    # column aliases the Oracle translation would rewrite or refuse. Binds stay
    # Oracle's, DDL still commits, executemany takes the hint, and a result
    # type with no Oracle form is refused by name.
    from seerdb.server.backends.postgres import UnsupportedFeature

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), native_sql=True)
    try:
        result = backend.execute(
            'SELECT /*+ PG */ x AS rownum FROM generate_series(1, 3) x WHERE x >= :1',
            [2],
        )
        assert [list(r) for r in result.rows] == [[2], [3]]
        backend.execute('/*+ PG */ CREATE TABLE nat1556 (id int PRIMARY KEY, v text)')
        backend.rollback()  # DDL committed, as Oracle's does
        assert (
            backend.execute_many(
                'INSERT /*+ PG */ INTO nat1556 VALUES (:1, :2) '
                'ON CONFLICT (id) DO NOTHING',
                [(1, 'a'), (2, 'b'), (1, 'again')],
            )
            == 2
        )
        assert (
            backend.execute("ALTER SESSION SET seerdb_dialect = 'postgres'").rows == []
        )
        result = backend.execute(
            "SELECT id AS sysdate FROM nat1556 WHERE v ~ '^[a-z]$' ORDER BY id"
        )
        assert [list(r) for r in result.rows] == [[1], [2]]
        # Transaction control keeps its own path, outside the statement
        # savepoint (#1181), in this dialect too.
        backend.execute('COMMIT')
        backend.execute("ALTER SESSION SET seerdb_dialect = 'oracle'")
        (row,) = backend.execute('SELECT SYSDATE FROM dual').rows
        assert isinstance(row[0], datetime.datetime)
        with pytest.raises(UnsupportedFeature, match='not supported'):
            backend.execute('SELECT /*+ PG */ gen_random_uuid()')
    finally:
        backend.rollback()
        try:
            backend.execute('/*+ PG */ DROP TABLE IF EXISTS nat1556')
        except Exception:
            backend.rollback()
        backend.close()


def test_the_translation_report_names_the_rules_a_statement_needed() -> None:
    # Each translation step notes its name when it changes the text, while a
    # report is being taken (#1557); a portable statement needs none, and with
    # no report nothing is collected.
    from seerdb.server.backends.postgres import _TRANSLATION_RULES

    rules: list[str] = []
    token = _TRANSLATION_RULES.set(rules)
    try:
        _translate_idioms('SELECT NVL(a, 1), SYSDATE FROM t MINUS SELECT 1, 2 FROM u')
        assert rules == ['nvl', 'sysdate', 'minus']
        rules.clear()
        _translate_idioms('SELECT coalesce(a, 1) FROM t WHERE b = :1')
        assert rules == []
    finally:
        _TRANSLATION_RULES.reset(token)
    _translate_idioms('SELECT NVL(a, 1) FROM t')  # no report: nothing to note


def test_a_kept_translation_still_names_its_rules() -> None:
    # A statement's rewrite is kept per text (#1884); the rules it needed are
    # kept with it, so a report names them whenever the statement runs again,
    # also one first translated while no report was being taken.
    from seerdb.server.backends.postgres import _TRANSLATION_RULES

    first = 'SELECT NVL(a, 2), SYSDATE FROM t1884'
    assert _translate_idioms(first) == _translate_idioms(first)
    for _ in range(2):
        rules: list[str] = []
        token = _TRANSLATION_RULES.set(rules)
        try:
            _translate_idioms(first)
        finally:
            _TRANSLATION_RULES.reset(token)
        assert rules == ['nvl', 'sysdate']


def test_the_translation_report_folds_a_statements_literals() -> None:
    # Runs with different values count as one statement; a quoted identifier
    # and a bind stay as written (#1557).
    from seerdb.server.backends.postgres import _normalise_statement

    assert (
        _normalise_statement(
            "select 'it''s',  12, -3.5e2,\n\"col 1\", t1.c2 from t where a = :1"
        )
        == 'select ?, ?, -?, "col 1", t1.c2 from t where a = :1'
    )


def test_the_translation_report_records_runs_apart_from_the_transaction() -> None:
    # With the report on, every run is recorded: the rules it needed, a
    # failure and its error, a native statement (#1556). The log is written on
    # its own connection, so the client's rollback leaves it, and ALTER SESSION
    # turns the report off and on (#1557).
    from seerdb.server import BackendError

    backend = PostgresBackend(
        _CONNINFO, credentials=dict(_CREDS), translation_report=True, native_sql=True
    )
    probe = psycopg.connect(_CONNINFO, autocommit=True)
    marker = 'rep1557t'
    try:
        probe.execute(
            'DELETE FROM sys.ora_translation_log WHERE statement LIKE %s',
            (f'%{marker}%',),
        )
        for value in (1, 2):
            backend.execute(f'SELECT NVL(NULL, {value}) AS {marker} FROM dual')
        backend.execute(f'SELECT /*+ PG */ 1 AS {marker}')
        with pytest.raises(BackendError):
            backend.execute(f'SELECT no_such_column AS {marker} FROM dual')
        backend.execute('ALTER SESSION SET seerdb_translation_report = false')
        backend.execute(f"SELECT NVL(NULL, 'off') AS {marker}x FROM dual")
        backend.execute('ALTER SESSION SET seerdb_translation_report = true')
        backend.rollback()
        backend.close()
        logged = probe.execute(
            'SELECT statement, rules, runs, failures, native, last_error '
            'FROM sys.ora_translation_log WHERE statement LIKE %s ORDER BY statement',
            (f'%{marker}%',),
        ).fetchall()
        assert [(r[0], r[1], r[2], r[3], r[4]) for r in logged] == [
            (f'SELECT /*+ PG */ ? AS {marker}', [], 1, 0, True),
            (f'SELECT NVL(NULL, ?) AS {marker} FROM dual', ['nvl'], 2, 0, False),
            (f'SELECT no_such_column AS {marker} FROM dual', [], 1, 1, False),
        ]
        assert 'NO_SUCH_COLUMN' in logged[2][5].upper()
    finally:
        probe.execute(
            'DELETE FROM sys.ora_translation_log WHERE statement LIKE %s',
            (f'%{marker}%',),
        )
        probe.close()


def test_a_collection_of_raw_is_a_collection_of_raw() -> None:
    # A collection of RAW(n) was reported as one of BLOB: its domain is over
    # bytea[], which keeps no length (#1545). The element's type and n are
    # recorded with the DDL, as a national element's are (#1437): the
    # dictionary, the TDS -- 23ai's byte for byte, leaf `13 0014` -- and the
    # element's description say RAW.
    from seerdb.server.backends.postgres import _tds

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TYPE rc1545 AS TABLE OF RAW(20)')
        backend.execute('CREATE TYPE rv1545 AS VARRAY(3) OF RAW(4)')
        backend.commit()
        result = backend.execute(
            'SELECT type_name, elem_type_name, length, character_set_name '
            "FROM user_coll_types WHERE type_name LIKE 'R_1545' ORDER BY 1"
        )
        assert result.rows == [
            ('RC1545', 'RAW', 20, None),
            ('RV1545', 'RAW', 4, None),
        ]
        pg_oid = _fetched_row(backend._conn.execute("SELECT 'rc1545'::regtype::oid"))[0]
        assert _tds(backend._type_shape(pg_oid)).hex() == (
            '0000001e260100010001ff290000000000131c0000001d00000000022a1300140007'
        )
        element = _present(backend._collection_type(pg_oid)).element
        assert (element['type_name'], element['charset']) == ('RAW', None)
    finally:
        backend.rollback()
        for name in ('rc1545', 'rv1545'):
            try:
                backend.execute(f'DROP TYPE {name}')
                backend.commit()
            except Exception:
                backend.rollback()
        backend.close()


def test_oracle_alter_table_column_forms_translate() -> None:
    # Oracle's ADD (list), MODIFY and DROP (list) in PostgreSQL's spelling, the
    # types as CREATE TABLE translates them (#1414).
    from seerdb.server.backends.postgres import _translate_ddl

    assert _translate_ddl('ALTER TABLE t ADD (d DATE, e CLOB, f RAW(5))') == (
        'ALTER TABLE t ADD COLUMN d ora_date, ADD COLUMN e ora_clob, ADD COLUMN f bytea '
        "CONSTRAINT \"ora_raw_len_f\" CHECK (sys.ora_raw_fits(f, 5, 'T', 'F'))"
    )
    assert _translate_ddl("ALTER TABLE t ADD (g VARCHAR2(5) DEFAULT 'q' NOT NULL)") == (
        'ALTER TABLE t ADD COLUMN g varchar(5) COLLATE "C" DEFAULT \'q\' NOT NULL'
    )
    assert _translate_ddl('ALTER TABLE t ADD CONSTRAINT t_pk PRIMARY KEY (id)') == (
        'ALTER TABLE t ADD CONSTRAINT t_pk PRIMARY KEY (id)'
    )
    assert _translate_ddl(
        "ALTER TABLE t MODIFY (a VARCHAR2(20) DEFAULT 'x' NOT NULL, b NULL)"
    ) == (
        'ALTER TABLE t ALTER COLUMN a TYPE varchar(20) COLLATE "C", '
        'DROP CONSTRAINT IF EXISTS "ora_raw_len_a", '
        "ALTER COLUMN a SET DEFAULT 'x', ALTER COLUMN a SET NOT NULL, "
        'ALTER COLUMN b DROP NOT NULL'
    )
    assert _translate_ddl('ALTER TABLE t MODIFY (a DEFAULT NULL)') == (
        'ALTER TABLE t ALTER COLUMN a SET DEFAULT NULL'
    )
    assert _translate_ddl('ALTER TABLE t MODIFY n NUMBER(7, 2)') == (
        'ALTER TABLE t ALTER COLUMN n TYPE numeric(7, 2), '
        'DROP CONSTRAINT IF EXISTS "ora_raw_len_n"'
    )
    assert _translate_ddl('ALTER TABLE t DROP (e, "F")') == (
        'ALTER TABLE t DROP COLUMN e, DROP COLUMN "F"'
    )
    # Not modelled: runs as written, to fail honestly.
    named = 'ALTER TABLE t MODIFY (a CONSTRAINT a_nn NOT NULL)'
    assert _translate_ddl(named) == named


def test_oracle_alter_table_column_forms_run() -> None:
    # The forms run, and the dictionary reads what they declared (#1414).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE alt1414 (id NUMBER, a VARCHAR2(10))')
        for statement in (
            'ALTER TABLE alt1414 ADD (b NUMBER(5), d DATE, f RAW(5))',
            'ALTER TABLE alt1414 MODIFY (a VARCHAR2(20) NOT NULL, b NUMBER(7, 2))',
            'ALTER TABLE alt1414 DROP (d)',
        ):
            backend.execute(statement)
        result = backend.execute(
            'SELECT column_name, data_type, data_length, data_precision, '
            'data_scale, nullable FROM user_tab_columns '
            "WHERE table_name = 'ALT1414' ORDER BY column_id"
        )
        assert [tuple(r) for r in result.rows] == [
            ('ID', 'NUMBER', 22, None, None, 'Y'),
            ('A', 'VARCHAR2', 20, None, None, 'N'),
            ('B', 'NUMBER', 22, 7, 2, 'Y'),
            ('F', 'RAW', 5, None, None, 'Y'),
        ]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE alt1414')
        except Exception:
            backend.rollback()
        backend.close()


def test_tab_columns_list_char_used_and_the_declared_length() -> None:
    # USER_TAB_COLUMNS has CHAR_USED and CHAR_COL_DECL_LENGTH, and a column
    # declared in CHAR semantics is 4n bytes long, as 23ai lists it (#1451):
    # the rewrite drops the CHAR qualifier, so it is recorded with the DDL.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TABLE cu1451 (a VARCHAR2(20), b VARCHAR2(10 BYTE), '
            'cc VARCHAR2(10 CHAR), d CHAR(4), dc CHAR(3 CHAR), e NVARCHAR2(5), '
            'f NCHAR(3), g CLOB, h LONG, i NUMBER, l BLOB, n NCLOB)'
        )
        result = backend.execute(
            'SELECT column_name, data_length, char_length, char_col_decl_length, '
            "char_used FROM user_tab_columns WHERE table_name = 'CU1451' "
            'ORDER BY column_id'
        )
        assert [tuple(r) for r in result.rows] == [
            ('A', 20, 20, 20, 'B'),
            ('B', 10, 10, 10, 'B'),
            ('CC', 40, 10, 40, 'C'),
            ('D', 4, 4, 4, 'B'),
            ('DC', 12, 3, 12, 'C'),
            ('E', 10, 5, 5, 'C'),
            ('F', 6, 3, 3, 'C'),
            ('G', 4000, 0, 4000, None),
            ('H', 0, 0, 0, None),
            ('I', 22, 0, None, None),
            # A CLOB / BLOB is 4000 long, as 23ai lists it (#1566).
            ('L', 4000, 0, None, None),
            ('N', 4000, 0, 2000, None),
        ]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE cu1451')
        except Exception:
            backend.rollback()
        backend.close()


def test_a_character_value_headed_for_raw_is_hex() -> None:
    # Oracle converts a character value headed for a RAW column or attribute
    # as HEXTORAW does; bytea read its text's own bytes (#1496). An INSERT's
    # VALUES, with a column list or without, an UPDATE's SET, an object
    # constructor's arguments, literal or bound, and executemany; a bytes value
    # is itself. The rows are 23ai's.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE hx1496 (id NUMBER, r RAW(16), s VARCHAR2(20))')
        backend.execute('CREATE TYPE hxo1496 AS OBJECT (n NUMBER, r RAW(8))')
        backend.execute("INSERT INTO hx1496 VALUES (1, '52617720', '41')")
        backend.execute("INSERT INTO hx1496 (s, r, id) VALUES ('b', :1, 2)", ['4142'])
        backend.execute("INSERT INTO hx1496 VALUES (3, :r, 'c')", [b'Raw '])
        backend.execute_many("INSERT INTO hx1496 VALUES (:1, :2, 'd')", [(4, 'FF')])
        backend.execute("UPDATE hx1496 SET r = '00FF', s = 'u' WHERE id = 1")
        result = backend.execute('SELECT id, r, s FROM hx1496 ORDER BY id')
        assert [tuple(row) for row in result.rows] == [
            (1, b'\x00\xff', 'u'),
            (2, b'AB', 'b'),
            (3, b'Raw ', 'c'),
            (4, b'\xff', 'd'),
        ]
        (row,) = backend.execute("SELECT hxo1496(1, '52617720') FROM dual").rows
        assert row[0].R == b'Raw '
    finally:
        backend.rollback()
        for statement in ('DROP TABLE hx1496', 'DROP TYPE hxo1496'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_a_raw_columns_length_is_a_check() -> None:
    # bytea has no length, so a RAW(n) column carries a named CHECK that
    # raises Oracle's ORA-12899 (#1415); MODIFY replaces it.
    assert _translate_ddl('CREATE TABLE t (id NUMBER, r RAW(2) NOT NULL)') == (
        'CREATE TABLE t (id numeric, r bytea NOT NULL CONSTRAINT "ora_raw_len_r" '
        "CHECK (sys.ora_raw_fits(r, 2, 'T', 'R')))"
    )


def test_a_raw_value_longer_than_its_column_is_ora_12899() -> None:
    # Too long by INSERT, by bind and by UPDATE, each ORA-12899 in 23ai's
    # wording; MODIFY to a wider RAW moves the limit (#1415).
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE rl1415 (id NUMBER, r RAW(2))')
        backend.execute("INSERT INTO rl1415 VALUES (1, HEXTORAW('0102'))")
        for statement, binds in (
            ("INSERT INTO rl1415 VALUES (2, HEXTORAW('010203'))", ()),
            ('INSERT INTO rl1415 VALUES (3, :1)', [b'abc']),
            ("UPDATE rl1415 SET r = HEXTORAW('AABBCC') WHERE id = 1", ()),
        ):
            with pytest.raises(BackendError) as exc:
                backend.execute(statement, binds)
            assert exc.value.ora_code == 12899
            assert '"RL1415"."R" (actual: 3, maximum: 2)' in str(exc.value)
            backend.rollback()
            backend.execute("INSERT INTO rl1415 VALUES (1, HEXTORAW('0102'))")
        backend.execute('ALTER TABLE rl1415 MODIFY (r RAW(4))')
        backend.execute("INSERT INTO rl1415 VALUES (4, HEXTORAW('010203'))")
        with pytest.raises(BackendError) as exc:
            backend.execute("INSERT INTO rl1415 VALUES (5, HEXTORAW('0102030405'))")
        assert '(actual: 5, maximum: 4)' in str(exc.value)
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE rl1415')
        except Exception:
            backend.rollback()


def test_type_attrs_list_char_used() -> None:
    # all_type_attrs has CHAR_USED: C for a CHAR-semantics or national
    # attribute, B for every other one, a number included (#1573). The rows
    # are 23ai's; a client sizes a VARCHAR2(n CHAR) attribute by it (#1490).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TYPE tc1573 AS OBJECT (n NUMBER, v VARCHAR2(20), '
            'vc VARCHAR2(10 CHAR), cc CHAR(2 CHAR), nv NVARCHAR2(5), r RAW(4))'
        )
        backend.commit()
        result = backend.execute(
            'SELECT attr_name, char_used FROM user_type_attrs '
            "WHERE type_name = 'TC1573' ORDER BY attr_no"
        )
        assert [tuple(r) for r in result.rows] == [
            ('N', 'B'),
            ('V', 'B'),
            ('VC', 'C'),
            ('CC', 'C'),
            ('NV', 'C'),
            ('R', 'B'),
        ]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TYPE tc1573')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_an_application_context_reads_back_from_sys_context() -> None:
    # The application context a client declares at login reaches the backend
    # through set_app_context, and SYS_CONTEXT(namespace, attribute) reads it
    # back, either name in any case, as 23ai does; an attribute not declared is
    # NULL, and a rollback keeps it (#1581).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.set_app_context(
            [('CLIENTCONTEXT', 'ATTR1', 'VALUE1'), ('clientcontext', 'Attr2', 'v 2')]
        )
        backend.rollback()

        def context(namespace: str, attribute: str):
            return backend.execute(
                'SELECT sys_context(:1, :2) FROM dual', [namespace, attribute]
            ).rows[0][0]

        assert context('CLIENTCONTEXT', 'ATTR1') == 'VALUE1'
        assert context('ClientContext', 'attr2') == 'v 2'
        assert context('CLIENTCONTEXT', 'NOPE') is None
        assert context('USERENV', 'SESSION_USER') == 'PYO'
    finally:
        backend.close()


def test_dbms_application_info_sets_what_sys_context_reads() -> None:
    # sqlplus names itself as it logs in, BEGIN DBMS_APPLICATION_INFO.SET_MODULE
    # (:1, NULL); END;, and SYS_CONTEXT('USERENV', 'MODULE' / 'ACTION' /
    # 'CLIENT_INFO') reads the values back. PostgreSQL answers it itself now that
    # no shim stands in front of it (#1840); a NULL clears a value.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:

        def userenv(attribute: str):
            return backend.execute(
                "SELECT sys_context('USERENV', :1) FROM dual", [attribute]
            ).rows[0][0]

        backend.execute(
            'BEGIN DBMS_APPLICATION_INFO.SET_MODULE(:1, NULL); END;', ['SQL*Plus']
        )
        assert (userenv('MODULE'), userenv('ACTION')) == ('SQL*Plus', None)
        backend.execute("BEGIN dbms_application_info.set_action('load'); END;")
        backend.execute("BEGIN dbms_application_info.set_client_info('batch 7'); END;")
        assert (userenv('ACTION'), userenv('CLIENT_INFO')) == ('load', 'batch 7')
        backend.execute('BEGIN dbms_application_info.set_module(NULL, NULL); END;')
        assert (userenv('MODULE'), userenv('ACTION')) == (None, None)
    finally:
        backend.close()


def test_user_is_described_as_oracle_describes_it() -> None:
    # USER is a VARCHAR2(128) from 12.2 on, and sqlplus sizes its column by
    # that; PostgreSQL's text would have been described by its value (#1840).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        result = backend.execute('SELECT USER FROM DUAL')
        assert result.rows == [('PYO',)]
        assert result.columns[0].max_size == 128
    finally:
        backend.close()


def test_a_dictionary_from_a_newer_seerdb_is_replaced() -> None:
    # A dictionary view with a column this seerdb does not define -- left by a
    # newer seerdb, or a branch's -- made CREATE OR REPLACE VIEW fail, so the
    # install failed on every connection and the stamp was never written
    # (#1571). The views are dropped and created again.
    from seerdb.server.backends.postgres import _DICTIONARY_STAMP

    raw = psycopg.connect(_CONNINFO, autocommit=True)
    try:
        PostgresBackend(_CONNINFO, credentials=dict(_CREDS)).close()  # installed
        raw.execute(
            'CREATE OR REPLACE VIEW sys.user_types AS SELECT t.*, 1 AS newer_column '
            'FROM sys.all_types t WHERE t.owner = upper(current_schema())'
        )
        raw.execute('COMMENT ON SCHEMA sys IS NULL')
        PostgresBackend(_CONNINFO, credentials=dict(_CREDS)).close()
        stamp = raw.execute(
            "SELECT obj_description('sys'::regnamespace, 'pg_namespace')"
        ).fetchone()[0]
        assert stamp == _DICTIONARY_STAMP
        columns = [
            r[0]
            for r in raw.execute(
                "SELECT attname FROM pg_attribute WHERE attrelid = 'sys.user_types'::regclass "
                'AND attnum > 0'
            ).fetchall()
        ]
        assert 'newer_column' not in columns
    finally:
        raw.close()


def test_a_type_shape_block_is_answered_by_argument_position() -> None:
    # A GET_TYPE_SHAPE block answers each bind for the argument it is in the
    # call, or the call's return value -- not by python-oracledb's bind names,
    # which a hand-written block need not use (#1542). The TDS is 23ai's.
    from types import SimpleNamespace

    from seerdb.server.backends.postgres import _tds, _type_shape_roles

    block = (
        'declare i varchar2(3); o varchar2(128); m varchar2(128); s sys_refcursor; '
        'begin :r := dbms_pickler.get_type_shape(:nm, :oid, :ver, :tds, i, o, m, '
        ':rc, s); end;'
    )
    assert _type_shape_roles(block) == (
        {
            'r': 'ret_val',
            'nm': 'full_name',
            'oid': 'oid',
            'ver': 'version',
            'tds': 'tds',
            'rc': 'attrs_rc',
        },
        None,
    )
    assert (
        _type_shape_roles(
            "begin :x := dbms_pickler.get_type_shape('T', :o, :v, :t, a, b, c, d, e); end;"
        )[1]
        == 'T'
    )
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TYPE ts1542 AS OBJECT (n NUMBER(5), v VARCHAR2(10))')
        backend.commit()
        binds = [
            SimpleNamespace(value=v) for v in (None, 'TS1542', None, None, None, None)
        ]
        (ret, _name, oid, version, tds, cursor) = backend.execute(
            block, binds
        ).out_binds
        assert (ret, version) == (0, 1) and len(oid) == 16
        pg_oid = _fetched_row(backend._conn.execute("SELECT 'ts1542'::regtype::oid"))[0]
        assert tds == _tds(backend._type_shape(pg_oid))
        assert [(row[1], row[3]) for row in cursor.rows] == [
            ('N', 'NUMBER'),
            ('V', 'VARCHAR2'),
        ]
        missing = [
            SimpleNamespace(value=v) for v in (None, 'NOSUCH', None, None, None, None)
        ]
        (ret, _name, oid, version, tds, _cursor) = backend.execute(
            block, missing
        ).out_binds
        assert (ret, oid, version, tds) == (1001, None, 0, None)
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TYPE ts1542')
            backend.commit()
        except Exception:
            backend.rollback()
        backend.close()


def test_a_character_value_compared_with_raw_is_hex() -> None:
    # A single-table statement's WHERE compares a RAW column with a character
    # value as hex, as Oracle does (#1496): either way round, an IN list, a
    # bind, an UPDATE's and a DELETE's. A character column's comparison, and
    # one in a subquery, are left alone. The rows are 23ai's.
    from seerdb.server.backends.postgres import _mask_quoted

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE rc1496 (id NUMBER, r RAW(8), s VARCHAR2(10))')
        backend.execute("INSERT INTO rc1496 VALUES (1, hextoraw('52617720'), '41')")
        backend.execute("INSERT INTO rc1496 VALUES (2, hextoraw('41'), 'x')")

        def ids(sql: str, binds=()) -> list:
            return sorted(row[0] for row in backend.execute(sql, list(binds)).rows)

        assert ids("SELECT id FROM rc1496 WHERE r = '52617720'") == [1]
        assert ids('SELECT id FROM rc1496 t WHERE t.r = :1', ['41']) == [2]
        assert ids("SELECT id FROM rc1496 WHERE '41' = r") == [2]
        assert ids("SELECT id FROM rc1496 WHERE r IN ('41', '52617720')") == [1, 2]
        assert ids("SELECT id FROM rc1496 WHERE s = '41'") == [1]
        assert ids(
            "SELECT id FROM rc1496 WHERE id IN (SELECT id FROM rc1496 WHERE s = 'x')"
        ) == [2]
        (masked, contents) = _mask_quoted("SELECT id FROM rc1496 WHERE s = '41'")
        assert backend._raw_comparison_spans(masked, contents) == []
        assert backend.execute("UPDATE rc1496 SET id = 3 WHERE r = '41'").rowcount == 1
        assert (
            backend.execute('DELETE FROM rc1496 WHERE r = :1', ['52617720']).rowcount
            == 1
        )
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE rc1496')
        except Exception:
            backend.rollback()
        backend.close()


def test_dbms_lock_and_dbms_session_sleep() -> None:
    # The way a client makes a call take time -- python-oracledb's cancel and
    # call-timeout tests call one or the other, by server version. orafce ships
    # neither, so the call failed at once with ORA-00900 and the cancel never
    # had anything to interrupt (#1511). Seconds may be fractional.
    import time

    from seerdb.common.tns_consts import TNS_TYPE_NUMBER
    from seerdb.server.backend import BindVar

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        for name in ('DBMS_LOCK.SLEEP', 'DBMS_SESSION.SLEEP'):
            start = time.monotonic()
            backend.execute(
                f'BEGIN {name}(:1); END;',
                [BindVar(value=0.2, tns_type=TNS_TYPE_NUMBER, max_size=22)],
            )
            assert time.monotonic() - start >= 0.2, name
    finally:
        backend.close()


def test_sys_dual_is_dual() -> None:
    # sqlplus writes the schema out: PRINT is `SELECT :v v FROM SYS.DUAL`, and
    # its login query reads SYS.DUAL too. Only the bare `dual` resolved, to
    # orafce's oracle.dual, so both failed with ORA-00942 (#1516).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        assert backend.execute('SELECT 1 FROM SYS.DUAL').rows == [(1,)]
        assert backend.execute('SELECT dummy FROM sys.dual').rows == [('X',)]
        assert backend.execute('SELECT :v v FROM SYS.DUAL', [42]).rows == [(42,)]
        # sqlplus's login query: XS_SYS_CONTEXT is NULL without a RAS session,
        # and DECODE falls through to USER.
        login = backend.execute(
            "SELECT DECODE(USER, 'XS$NULL', XS_SYS_CONTEXT('XS$SESSION','USERNAME'), "
            'USER) FROM SYS.DUAL'
        )
        assert login.rows == [(backend.execute('SELECT USER FROM dual').rows[0][0],)]
    finally:
        backend.close()


def test_nvl_with_literal_arguments_runs() -> None:
    # NVL with bare literals is ordinary Oracle, and it did not run here at all:
    # orafce's four overloads left `nvl(unknown, unknown)` ambiguous and the
    # resolver refused to choose (#819). Assert against the real backend rather
    # than only the rewrite, because the rewrite is not the claim -- the claim is
    # that the statement an application writes now returns the right value.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        assert backend.execute("SELECT nvl(NULL, 'ok') FROM dual").rows == [('ok',)]
        assert backend.execute("SELECT nvl('a', 'b') FROM dual").rows == [('a',)]
        assert backend.execute('SELECT nvl(NULL, 1) FROM dual').rows == [(1,)]
        # The typed calls that already worked through orafce still do.
        assert backend.execute('SELECT nvl(1, 2) FROM dual').rows == [(1,)]
        # NVL2 is a different function and keeps its orafce implementation.
        assert backend.execute("SELECT nvl2(NULL, 'y', 'n') FROM dual").rows == [('n',)]
        assert backend.execute("SELECT nvl2('x', 'y', 'n') FROM dual").rows == [('y',)]
        # A column reference, not just a literal, and inside a WHERE clause.
        backend.execute('CREATE TABLE nvl819 (a VARCHAR(8), b VARCHAR(8))')
        backend.execute("INSERT INTO nvl819 VALUES ('x', NULL)")
        backend.commit()
        assert backend.execute('SELECT nvl(b, a) FROM nvl819').rows == [('x',)]
        assert backend.execute(
            "SELECT a FROM nvl819 WHERE nvl(b, 'none') = 'none'"
        ).rows == [('x',)]
        backend.execute('DROP TABLE nvl819')
        backend.commit()
    finally:
        backend.close()


def test_translate_connect_by_rewrites_a_hierarchical_query() -> None:
    # Oracle's CONNECT BY hierarchical query maps to a PostgreSQL WITH RECURSIVE
    # CTE: START WITH is the anchor filter, CONNECT BY PRIOR the recursive join,
    # and LEVEL / SYS_CONNECT_BY_PATH / CONNECT_BY_ROOT become computed columns
    # (#760).
    out = _translate_connect_by(
        "SELECT id, LEVEL, SYS_CONNECT_BY_PATH(name, '/'), CONNECT_BY_ROOT name "
        'FROM emp START WITH mgr IS NULL CONNECT BY PRIOR id = mgr'
    )
    assert out.startswith('WITH RECURSIVE __hcte AS (')
    assert 'WHERE mgr IS NULL' in out  # START WITH → anchor filter
    assert '__p.id = emp.mgr' in out  # PRIOR id = mgr → parent.id = child.mgr
    assert '__level' in out and '__path' in out and '__root' in out


def test_translate_connect_by_passes_through_unsupported_shapes() -> None:
    # Correct-or-passthrough: anything but the recognised single-table shape is
    # returned untouched (and then errors on PostgreSQL exactly as before) rather
    # than mistranslated (#760).
    passthrough = [
        'SELECT id FROM emp WHERE mgr IS NULL',  # no CONNECT BY at all
        'SELECT * FROM emp CONNECT BY PRIOR id = mgr',  # SELECT *
        'SELECT a.id FROM emp a, emp b CONNECT BY PRIOR a.id = a.mgr',  # multi-table
        'SELECT id FROM emp CONNECT BY PRIOR id = mgr AND id > 0',  # compound
        'SELECT id FROM emp CONNECT BY PRIOR id = mgr ORDER SIBLINGS BY id',  # siblings
    ]
    for sql in passthrough:
        assert _translate_connect_by(sql) == sql


def test_connect_by_hierarchical_query_runs() -> None:
    # End to end through the backend: a real employee/manager tree returns its rows
    # with LEVEL, the root-to-node path, and the root value (#760).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('drop table if exists hier_emp')
        backend.execute(
            'CREATE TABLE hier_emp (id NUMBER, mgr NUMBER, name VARCHAR2(20))'
        )
        for id_, mgr, name in [
            (1, None, 'KING'),
            (2, 1, 'JONES'),
            (3, 1, 'BLAKE'),
            (4, 2, 'SCOTT'),
        ]:
            backend.execute(
                'INSERT INTO hier_emp (id, mgr, name) VALUES (:1, :2, :3)',
                [id_, mgr, name],
            )
        backend.commit()
        rows = backend.execute(
            "SELECT id, LEVEL, SYS_CONNECT_BY_PATH(name, '/'), CONNECT_BY_ROOT name "
            'FROM hier_emp START WITH mgr IS NULL '
            'CONNECT BY PRIOR id = mgr ORDER BY LEVEL'
        ).rows
        assert (1, 1, '/KING', 'KING') in rows
        assert (4, 3, '/KING/JONES/SCOTT', 'KING') in rows
        assert len(rows) == 4
        backend.execute('drop table hier_emp')
        backend.commit()
    finally:
        backend.close()


def test_utl_raw_takes_a_character_argument_as_hex() -> None:
    # A UTL_RAW function given a character value where it takes a RAW reads it
    # as hex, as Oracle converts one (#1496): '414243' is ABC's bytes. RAWTOHEX
    # does not -- Oracle gives the hex of the text's own bytes. The values are
    # 23ai's.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:

        def scalar(sql: str):
            return backend.execute(sql).rows[0][0]

        assert scalar("SELECT utl_raw.cast_to_varchar2('414243') FROM dual") == 'ABC'
        assert (
            backend.execute(
                'SELECT utl_raw.cast_to_varchar2(:1) FROM dual', ['4142']
            ).rows[0][0]
            == 'AB'
        )
        assert scalar("SELECT utl_raw.length('41424344') FROM dual") == 4
        assert scalar("SELECT utl_raw.substr('41424344', 2, 2) FROM dual") == b'BC'
        assert scalar("SELECT utl_raw.concat('41', '42') FROM dual") == b'AB'
        assert scalar("SELECT utl_raw.bit_and('FF0F', '0FFF') FROM dual") == b'\x0f\x0f'
        assert scalar("SELECT utl_raw.bit_or('F0', '0F') FROM dual") == b'\xff'
        assert scalar("SELECT utl_raw.bit_xor('FF', '0F') FROM dual") == b'\xf0'
        assert scalar("SELECT rawtohex('4142') FROM dual") == '34313432'
    finally:
        backend.close()


def test_utl_raw_length_does_not_recurse_with_schema_on_path() -> None:
    # utl_raw.length()'s body must call pg_catalog.length, not a bare length():
    # with utl_raw on the search path (and pg_catalog explicitly after it) a bare
    # length() would bind to utl_raw.length itself and recurse until the stack
    # overflows. Exercise exactly that path (the bug fixed upstream in orafce #317).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('SET search_path TO utl_raw, oracle, public, pg_catalog')
        assert backend.execute("SELECT utl_raw.length(hextoraw('DEADBEEF'))").rows == [
            (4,)
        ]
        # substr and the bit operators call length internally too.
        assert backend.execute(
            "SELECT rawtohex(utl_raw.substr(hextoraw('DEADBEEF'), 2, 2))"
        ).rows == [('ADBE',)]
        assert backend.execute(
            "SELECT rawtohex(utl_raw.bit_and(hextoraw('FFFF'), hextoraw('F0')))"
        ).rows == [('F0FF',)]
    finally:
        backend.close()


def test_an_assignment_into_an_ltz_out_bind_is_read_in_the_session_zone() -> None:
    # `:ltz := :ltz + 5.25` makes a DATE on the session's clock; going back into
    # the LTZ it is read in the session zone again, so the value moves by exactly
    # the days, as on Oracle. The declared type is on the bind, not its value
    # (#1240, #1245). The session zone must differ from the database's (UTC) for
    # this to show: Helsinki is +03:00 in May.
    import datetime

    from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMPLTZ
    from seerdb.server import BindVar, LtzValue

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend._conn.execute("SET TimeZone = 'Europe/Helsinki'")
        value = LtzValue.of(datetime.datetime(2022, 5, 10, 12, 0, 0))
        bind = BindVar(value=value, tns_type=TNS_TYPE_TIMESTAMPLTZ, max_size=11)
        result = backend.execute('begin :value := :value + 5.25; end;', [bind])
        assert result.out_binds == [datetime.datetime(2022, 5, 15, 18, 0, 0)]
    finally:
        backend.close()


def test_an_object_type_oid_is_its_pg_oid_padded_and_back() -> None:
    # all_types reports a composite's PostgreSQL oid zero-padded to Oracle's 16
    # bytes, so the OID a bind carries turns straight back into the type. A real
    # Oracle OID a client carried over is not one of ours (#1127).
    oid = _object_type_oid(0x16F248)
    assert oid == bytes(13) + b'\x16\xf2\x48'
    assert _pg_oid_of(oid) == 0x16F248
    assert _pg_oid_of(bytes.fromhex('5c284ab405f7def0e0639600a8c0b006')) is None
    assert _pg_oid_of(b'short') is None


def test_an_object_column_describes_as_a_real_server_does() -> None:
    # Measured on 23ai: ADT, data length 2000, max size 0, no charset / form, and
    # the type's identity -- a zero length would claim the column sends nothing.
    from seerdb.common.dbobject import DbObjectType

    typ = DbObjectType('PUBLIC', 'T_OBJ', _object_type_oid(42), 1, [])
    col = _object_column_meta('o', typ)
    assert (col.name, col.data_type, col.data_length, col.max_size) == (
        b'O',
        109,
        2000,
        0,
    )
    assert (col.charset, col.csfrm) == (0, 0)
    assert (col.type_schema, col.type_name, col.type_oid) == (
        b'PUBLIC',
        b'T_OBJ',
        _object_type_oid(42),
    )


def test_an_object_type_is_in_the_dictionary_and_round_trips() -> None:
    # CREATE TYPE ... AS OBJECT is a composite; all_types / all_type_attrs are
    # what a client's gettype reads, a bound image is decoded into the
    # composite, and a selected composite comes back as a DbObject (#1127).
    from seerdb.common.dbobject import ObjectImage
    from seerdb.common.tns import encode_object_image

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        for stmt in ('DROP TABLE t_objround', 'DROP TYPE t_objround_t'):
            try:
                backend.execute(stmt)
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        backend.execute(
            'CREATE TYPE t_objround_t AS OBJECT (id NUMBER, name VARCHAR2(40))'
        )
        backend.execute('CREATE TABLE t_objround (n NUMBER, o t_objround_t)')
        (row,) = backend.execute(
            'SELECT owner, type_oid, typecode FROM all_types '
            "WHERE type_name = 'T_OBJROUND_T'"
        ).rows
        owner, oid, typecode = row
        assert typecode == 'OBJECT'
        attrs = backend.execute(
            'SELECT attr_name, attr_type_name, attr_type_owner, length '
            "FROM all_type_attrs WHERE type_name = 'T_OBJROUND_T' ORDER BY attr_no"
        ).rows
        assert attrs == [('ID', 'NUMBER', None, None), ('NAME', 'VARCHAR2', None, 40)]

        typ, _info = _present(backend._object_type(_present(_pg_oid_of(bytes(oid)))))
        obj = typ.newobject({'ID': 7, 'NAME': 'Alice'})
        image = ObjectImage(bytes(oid), owner, typ.name, None, encode_object_image(obj))
        backend.execute('INSERT INTO t_objround VALUES (1, :o)', [image])
        (got,) = backend.execute('SELECT o FROM t_objround').rows[0]
        assert got.NAME == 'Alice'
        assert int(got.ID) == 7
        backend.execute('DROP TABLE t_objround')
        backend.execute('DROP TYPE t_objround_t')
        backend.commit()
    finally:
        backend.close()


def test_a_collection_type_is_in_the_dictionary() -> None:
    # A VARRAY / nested table is a COLLECTION in all_types, with no attributes;
    # all_coll_types gives its element's size as Oracle does (#1206).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    names = ('t_colldict_s', 't_colldict_n')
    try:
        for name in names:
            try:
                backend.execute(f'DROP TYPE {name}')
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass
        backend.execute('CREATE TYPE t_colldict_s AS VARRAY(5) OF VARCHAR2(20)')
        backend.execute('CREATE TYPE t_colldict_n AS TABLE OF NUMBER(9,2)')
        assert backend.execute(
            'SELECT type_name, typecode, attributes FROM all_types '
            "WHERE type_name LIKE 'T_COLLDICT%' ORDER BY 1"
        ).rows == [('T_COLLDICT_N', 'COLLECTION', 0), ('T_COLLDICT_S', 'COLLECTION', 0)]
        assert backend.execute(
            'SELECT type_name, coll_type, upper_bound, elem_type_name, length, '
            "precision, scale FROM all_coll_types WHERE type_name LIKE 'T_COLLDICT%' "
            'ORDER BY 1'
        ).rows == [
            ('T_COLLDICT_N', 'TABLE', None, 'NUMBER', None, 9, 2),
            ('T_COLLDICT_S', 'VARYING ARRAY', 5, 'VARCHAR2', 20, None, None),
        ]
        for name in names:
            backend.execute(f'DROP TYPE {name}')
        backend.commit()
    finally:
        backend.close()


def test_idiom_rewrites_leave_quoted_text_alone() -> None:
    # A literal or a quoted identifier holding an Oracle word is data: a type
    # name compared in the dictionary, an escaped quote, a word in a comment's
    # apostrophe. The SQL around them is still rewritten (#1481).
    out = _translate_idioms(
        "SELECT 'VARCHAR2', 'it''s NVARCHAR2', \"MINUS\" FROM t -- don't\n"
        "WHERE c = CAST(x AS VARCHAR2(5)) MINUS SELECT 'sysdate', sysdate FROM dual"
    )
    assert out == (
        "SELECT 'VARCHAR2', 'it''s NVARCHAR2', \"MINUS\" FROM t -- don't\n"
        "WHERE c = CAST(x AS varchar(5)) EXCEPT SELECT 'sysdate', localtimestamp(0)::ora_date "
        'FROM dual'
    )
    # A rule that reads into a literal still sees it: a negative INTERVAL.
    assert _translate_idioms("SELECT INTERVAL '-1 2:00:00' DAY TO SECOND") == (
        "SELECT - INTERVAL '1 2:00:00' DAY TO SECOND"
    )


def test_an_unsized_number_is_recorded_without_a_precision() -> None:
    # INTEGER, SMALLINT, a bare DECIMAL and NUMBER(*, s) are numeric(38, s) here,
    # as NUMBER(38, s) is; only the declaration says they have no precision, so
    # it is recorded (#1483). A sized NUMBER needs no record.
    from seerdb.server.backends.postgres import _declared_type

    assert _declared_type('INTEGER NOT NULL') == ('NUMBER', 22, None, 0)
    assert _declared_type('smallint') == ('NUMBER', 22, None, 0)
    assert _declared_type('DECIMAL') == ('NUMBER', 22, None, 0)
    assert _declared_type('NUMBER(*, 2)') == ('NUMBER', 22, None, 2)
    assert _declared_type('NUMERIC(7,1)') is None
    assert _declared_type('NUMBER(5)') is None
    assert _declared_type('INTERVAL DAY TO SECOND') == (
        'INTERVAL DAY(2) TO SECOND(6)',
        11,
        2,
        6,
    )


def test_the_dictionary_lists_a_rowid_urowid_or_bfile_column_as_itself() -> None:
    # A ROWID, UROWID or BFILE column (#1904) is listed by its Oracle type, at
    # Oracle's length, with no owner and no character length -- 23ai's
    # answers -- not by the domain, varchar or composite that stores it.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute(
            'CREATE TABLE rw1904t (r ROWID, "Rq" ROWID, u UROWID, f BFILE, '
            's UROWID(100))'
        )
        rows = backend.execute(
            'SELECT column_name, data_type, data_type_owner, data_length, '
            'char_length, char_used, char_col_decl_length FROM all_tab_columns '
            "WHERE table_name = 'RW1904T' ORDER BY column_id"
        ).rows
        assert rows == [
            ('R', 'ROWID', None, 10, 0, None, None),
            ('Rq', 'ROWID', None, 10, 0, None, None),
            ('U', 'UROWID', None, 4000, 0, None, None),
            ('F', 'BFILE', None, 530, 0, None, None),
            # A sized one is its size long (#1906).
            ('S', 'UROWID', None, 100, 0, None, None),
        ]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE rw1904t')
        except Exception:
            backend.rollback()


def test_the_dictionary_lists_a_ref_column_by_the_type_it_points_at() -> None:
    # A REF column (#1905) is listed by the object type it points at, owned
    # by that type's owner (the table's here), 50 long and DATA_TYPE_MOD REF
    # -- 23ai's answers -- not by the `<type>$ref` composite that stores it.
    # Any other column has no DATA_TYPE_MOD.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TYPE rf1905_o AS OBJECT (n NUMBER)')
        backend.execute('CREATE TABLE rf1905t (n NUMBER, x REF rf1905_o)')
        rows = backend.execute(
            'SELECT column_name, data_type, data_type_mod, data_type_owner, '
            "data_length, owner FROM all_tab_columns WHERE table_name = 'RF1905T' "
            'ORDER BY column_id'
        ).rows
        owner = rows[0][5]
        assert rows == [
            ('N', 'NUMBER', None, None, 22, owner),
            ('X', 'RF1905_O', 'REF', owner, 50, owner),
        ]
    finally:
        backend.rollback()
        for statement in ('DROP TABLE rf1905t', 'DROP TYPE rf1905_o'):
            try:
                backend.execute(statement)
            except Exception:
                backend.rollback()


def test_the_dictionary_lists_a_vector_column_as_23ai_does() -> None:
    # A VECTOR column (#1907) is 8200 long whatever its dimensions and format,
    # with no precision or scale, and its dimension count -- 0 where that is
    # flexible -- as its CHAR_LENGTH: 23ai's answers. Its record keeps the
    # count and the format in the length and precision slots (#1708).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    try:
        backend.execute(
            'CREATE TABLE vc1907t (a VECTOR, b VECTOR(3, FLOAT32), '
            'c VECTOR(16, BINARY), d VECTOR(*, FLOAT64), e VECTOR(3, INT8, SPARSE))'
        )
        rows = backend.execute(
            'SELECT column_name, data_type, data_length, data_precision, '
            "data_scale, char_length FROM all_tab_columns WHERE table_name = 'VC1907T' "
            'ORDER BY column_id'
        ).rows
        assert rows == [
            ('A', 'VECTOR', 8200, None, None, 0),
            ('B', 'VECTOR', 8200, None, None, 3),
            ('C', 'VECTOR', 8200, None, None, 16),
            ('D', 'VECTOR', 8200, None, None, 0),
            ('E', 'VECTOR', 8200, None, None, 3),
        ]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE vc1907t')
        except Exception:
            backend.rollback()


def test_a_literal_select_item_is_cast_to_its_char_length() -> None:
    # A select item that is one string literal is CHAR(n) in Oracle (#1494): in
    # a query, a subquery and a cursor a block opens. So is a concatenation of
    # literals alone, n their lengths together, '' (NULL) none (#1587). An
    # empty literal, an expression with anything else in it, a comparison and
    # a set operation's branches are left as they are.
    out = _translate_idioms(
        "SELECT 'X' s, 'it''s' AS b, '' e, 'a' || 'b' c, 'ab' || '' d, "
        "'a' || n f, (SELECT 'z' FROM dual) q FROM t WHERE c = 'lit'"
    )
    assert out == (
        "SELECT CAST('X' AS char(1)) s, CAST('it''s' AS char(4)) AS b, '' e, "
        "CAST(('a' || 'b') AS char(2)) c, CAST(('ab' || '') AS char(2)) d, "
        "'a' || n f, (SELECT CAST('z' AS char(1)) FROM dual) q FROM t "
        "WHERE c = 'lit'"
    )
    assert _translate_idioms("BEGIN OPEN :c FOR SELECT 'X' v FROM dual; END;") == (
        "BEGIN OPEN :c FOR SELECT CAST('X' AS char(1)) v FROM dual; END;"
    )
    union = "SELECT 'a' x FROM dual UNION ALL SELECT 'bbb' FROM dual"
    assert _translate_idioms(union) == union
    # With no FROM at all, as the compat layer leaves `SELECT 'X' FROM dual`;
    # and twice in one DO block, as a CREATE OR REPLACE VIEW becomes, where the
    # first list must not run on into the second.
    assert _translate_idioms("SELECT 'X' a") == "SELECT CAST('X' AS char(1)) a"
    block = (
        "DO $$ BEGIN EXECUTE $v$CREATE VIEW v AS SELECT 'ab' s, 'c' t$v$; "
        "EXECUTE $v$CREATE VIEW v AS SELECT 'ab' s, 'c' t$v$; END $$"
    )
    assert _translate_idioms(block) == block.replace(
        "'ab' s, 'c' t", "CAST('ab' AS char(2)) s, CAST('c' AS char(1)) t"
    )


def test_a_compile_time_error_in_a_block_is_ora_06550() -> None:
    # PostgreSQL's class-42 errors inside a PL/SQL block are compile errors in
    # Oracle: ORA-06550, "line L, column C:" and the PLS- error, at the position
    # of what is wrong in the client's block. A string passed positionally where
    # a routine of that arity takes a number converts at run time: ORA-06502
    # (#1497).
    from seerdb.server.backends.postgres import _plsql_compile_error

    class Failure(Exception):
        def __init__(self, sqlstate: str, message: str) -> None:
            super().__init__(message)
            self.sqlstate = sqlstate

    unknown = _present(
        _plsql_compile_error(
            Failure('42601', '"t_missing" is not a known variable'),
            'begin t_Missing := 5; end;',
        )
    )
    assert (unknown.ora_code, unknown.error_offset) == (6550, 6)
    assert str(unknown).startswith('line 1, column 7:')
    assert "PLS-00201: identifier 'T_MISSING' must be declared" in str(unknown)
    call = 'begin :r := f(:1, :2, :3); end;'
    too_many = _present(
        _plsql_compile_error(
            Failure('42883', 'function f(unknown, integer, integer) does not exist'),
            call,
            lambda name: {2},
        )
    )
    assert too_many.ora_code == 6550 and 'PLS-00306' in str(too_many)
    converted = _present(
        _plsql_compile_error(
            Failure('42883', 'function f(integer, text) does not exist'),
            call,
            lambda name: {2},
        )
    )
    assert converted.ora_code == 6502
    named = _present(
        _plsql_compile_error(
            Failure('42883', 'function f(text, a => boolean) does not exist'),
            call,
            lambda name: {2},
        )
    )
    assert named.ora_code == 6550
    assert _plsql_compile_error(Failure('22012', 'division by zero'), call) is None


def test_a_create_that_does_not_compile_leaves_an_invalid_object() -> None:
    # Oracle creates a routine or type that does not compile, invalid, and warns;
    # the backend stands one in and reports the warning. Calling it fails, a
    # clean CREATE replaces it, and a DDL error of any other kind still fails
    # (#1499).
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        bad = backend.execute(
            'CREATE OR REPLACE PROCEDURE pyo_invalid_p AS BEGIN NULL END;'
        )
        assert bad.compilation_warning
        with pytest.raises(BackendError) as raised:
            backend.execute('BEGIN pyo_invalid_p; END;')
        assert raised.value.ora_code == 6550
        good = backend.execute(
            'CREATE OR REPLACE PROCEDURE pyo_invalid_p AS BEGIN NULL; END;'
        )
        assert not good.compilation_warning
        backend.execute('BEGIN pyo_invalid_p; END;')
        backend.execute('DROP PROCEDURE pyo_invalid_p')
        assert backend.execute(
            'CREATE OR REPLACE TYPE pyo_invalid_t AS OBJECT (x no_such_type)'
        ).compilation_warning
        backend.execute('DROP TYPE pyo_invalid_t')
        with pytest.raises(BackendError):
            backend.execute('CREATE TABLE pyo_invalid_tab bogus')
    finally:
        backend.close()


def test_all_objects_lists_types_valid_or_invalid() -> None:
    # An object type, a VARRAY and a nested table are each a TYPE in
    # ALL_OBJECTS, and one that did not compile is INVALID until a clean
    # CREATE OR REPLACE; a package's types are not listed, only the package
    # (#1940, measured on 23ai).
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    names = ('ao_obj_t', 'ao_va_t', 'ao_nt_t', 'ao_bad_t')
    try:
        backend.execute('CREATE TYPE ao_obj_t AS OBJECT (a NUMBER)')
        backend.execute('CREATE TYPE ao_va_t AS VARRAY(3) OF NUMBER')
        backend.execute('CREATE TYPE ao_nt_t AS TABLE OF VARCHAR2(10)')
        assert backend.execute(
            'CREATE TYPE ao_bad_t AS OBJECT (a no_such_type)'
        ).compilation_warning
        backend.execute(
            'CREATE PACKAGE ao_pk AS TYPE rec IS RECORD (a NUMBER); '
            'TYPE tab IS TABLE OF NUMBER; END;'
        )
        query = (
            'SELECT object_name, subobject_name, object_type, status, temporary, '
            "generated, secondary FROM user_objects WHERE object_name LIKE 'AO\\_%' "
            "ESCAPE '\\' OR object_name IN ('REC', 'TAB') ORDER BY 1, 3"
        )
        assert [tuple(row) for row in backend.execute(query).rows] == [
            ('AO_BAD_T', None, 'TYPE', 'INVALID', 'N', 'N', 'N'),
            ('AO_NT_T', None, 'TYPE', 'VALID', 'N', 'N', 'N'),
            ('AO_OBJ_T', None, 'TYPE', 'VALID', 'N', 'N', 'N'),
            ('AO_PK', None, 'PACKAGE', 'VALID', 'N', 'N', 'N'),
            ('AO_VA_T', None, 'TYPE', 'VALID', 'N', 'N', 'N'),
        ]
        assert not backend.execute(
            'CREATE OR REPLACE TYPE ao_bad_t AS OBJECT (a NUMBER)'
        ).compilation_warning
        status = backend.execute(
            "SELECT status FROM user_objects WHERE object_name = 'AO_BAD_T'"
        )
        assert [tuple(row) for row in status.rows] == [('VALID',)]
    finally:
        for name in names:
            try:
                backend.execute(f'DROP TYPE {name}')
            except Exception:
                pass
        try:
            backend.execute('DROP PACKAGE ao_pk')
        except Exception:
            pass
        backend.close()


def test_an_invalid_type_stands_in_whoever_the_connection_role_is() -> None:
    # The stand-in for an object type that does not compile (#1499) is one any
    # role may make, not a shell type, which only a superuser may (#1937). It
    # is listed as Oracle lists an invalid type, an OBJECT of no attributes,
    # and a clean CREATE OR REPLACE replaces it.
    role = f'inv_probe_{os.getpid()}'
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    try:
        admin.execute(f"CREATE ROLE {role} LOGIN PASSWORD 'inv123'")
        admin.execute(f'CREATE SCHEMA {role} AUTHORIZATION {role}')
        # What a Mirror user's role gets from its group (#1857).
        from seerdb.server.backends.postgres import _USER_WRITTEN_RECORDS

        admin.execute(f'GRANT USAGE ON SCHEMA sys TO {role}')
        admin.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA sys TO {role}')
        records = ', '.join(f'sys.{table}' for table in _USER_WRITTEN_RECORDS)
        admin.execute(f'GRANT INSERT, UPDATE, DELETE ON {records} TO {role}')
        backend = PostgresBackend(
            make_conninfo(_CONNINFO, user=role, password='inv123'),
            credentials=dict(_CREDS),
        )
        try:
            backend.execute(f'ALTER SESSION SET CURRENT_SCHEMA = {role}')
            assert backend.execute(
                'CREATE OR REPLACE TYPE inv_t AS OBJECT (x no_such_type)'
            ).compilation_warning
            listed = backend.execute(
                "SELECT typecode, attributes FROM all_types WHERE type_name = 'INV_T'"
            )
            assert [tuple(row) for row in listed.rows] == [('OBJECT', 0)]
            assert not backend.execute(
                'CREATE OR REPLACE TYPE inv_t AS OBJECT (x NUMBER)'
            ).compilation_warning
            listed = backend.execute(
                "SELECT attributes FROM all_types WHERE type_name = 'INV_T'"
            )
            assert [tuple(row) for row in listed.rows] == [(1,)]
            backend.execute('DROP TYPE inv_t')
        finally:
            backend.close()
    finally:
        admin.execute(f'DROP SCHEMA IF EXISTS {role} CASCADE')
        admin.execute(f'DROP OWNED BY {role}')
        admin.execute(f'DROP ROLE {role}')
        admin.close()


def test_raise_application_error_becomes_a_coded_raise() -> None:
    # RAISE_APPLICATION_ERROR raises P0001 with its ORA code as the message's
    # prefix, which the error mapping reads back (#1323); the message may itself
    # hold parentheses, and the optional third argument is dropped.
    out = _translate_idioms(
        "BEGIN raise_application_error(-20101, 'Test (it)!', TRUE); END;"
    )
    assert out == (
        "BEGIN RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = "
        "'ORA-' || lpad(abs((-20101))::text, 5, '0') || ': ' || ('Test (it)!'); END;"
    )


def test_a_cursor_expression_is_a_drained_cursor_at_every_level() -> None:
    # CURSOR(subquery) runs in place, naming the outer row's columns; each value
    # is a CursorResult with the subquery's own column names and types, empty when
    # no row matches, and a CURSOR(...) within one is a CursorResult of its own
    # (#1461).
    from seerdb.common.tns_consts import TNS_TYPE_REFCURSOR
    from seerdb.server.backend import CursorResult

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        result = backend.execute(
            "SELECT n, CURSOR(SELECT n + 1, 'x' label, CURSOR(SELECT n * 10 FROM "
            'dual) inner_c FROM dual WHERE n > 1) c FROM (SELECT 1 n FROM dual '
            'UNION ALL SELECT 2 FROM dual) t ORDER BY n'
        )
        assert [c.name for c in result.columns] == [b'N', b'C']
        assert result.columns[1].data_type == TNS_TYPE_REFCURSOR
        (first, second) = result.rows
        assert first[0] == 1 and first[1].rows == []
        assert [c.name for c in first[1].columns] == [b'N+1', b'LABEL', b'INNER_C']
        assert first[1].columns[2].data_type == TNS_TYPE_REFCURSOR
        ((plus_one, label, inner),) = second[1].rows
        assert (plus_one, label) == (3, 'x')
        assert isinstance(inner, CursorResult)
        assert inner.rows == [(20,)]
    finally:
        backend.close()


def test_a_failing_statement_leaves_the_prepared_statements_whole() -> None:
    # A statement that fails in its pipeline takes the commands after it with
    # it (#1885): psycopg, preparing one of those on its fifth run, would count
    # it prepared, and the next run named a statement the server never made --
    # the session's transaction then stayed aborted. The Mirror's own
    # statements are never prepared, so each failure stays its own.
    from seerdb.server import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        backend.execute('CREATE TABLE pp1885t (n NUMBER, r ROWID)')
        for _ in range(8):
            with pytest.raises(BackendError) as exc:
                backend.execute('INSERT INTO pp1885t (n, r) VALUES (2, :1)', ['bogus'])
            assert exc.value.ora_code == 1410
        backend.execute('INSERT INTO pp1885t (n) VALUES (1)')
        assert backend.execute('SELECT n FROM pp1885t').rows == [(1,)]
    finally:
        backend.rollback()
        try:
            backend.execute('DROP TABLE pp1885t')
        except Exception:
            backend.rollback()


def test_a_prepared_query_follows_another_sessions_ddl() -> None:
    # A query prepared on the server, whose table another session then gives a
    # new column, fails once in PostgreSQL ("cached plan must not change result
    # type") and is planned afresh on the next run (#1885); the Mirror runs it
    # again, so the client sees the new shape and no error, as Oracle's does.
    reader = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    other = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        reader.execute('CREATE TABLE pq1885t (n NUMBER)')
        reader.execute('INSERT INTO pq1885t VALUES (1)')
        reader.commit()
        for _ in range(7):
            assert len(reader.execute('SELECT * FROM pq1885t').columns) == 1
        other.execute('ALTER TABLE pq1885t ADD (m NUMBER)')
        result = reader.execute('SELECT * FROM pq1885t')
        assert (len(result.columns), result.rows) == (2, [(1, None)])
    finally:
        reader.rollback()
        try:
            reader.execute('DROP TABLE pq1885t')
        except Exception:
            reader.rollback()
        reader.close()
        other.close()


def test_another_sessions_ddl_reaches_what_a_session_knows_of_the_schema() -> None:
    # A session keeps what it learnt of a table -- here whether a column may
    # be NULL, which a query's describe reports -- until a DDL. Its own DDL
    # always cleared that; another session's now does too, through the DDL
    # log its event trigger keeps (#1887), read in the round trip a statement
    # makes anyway.
    reader = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    other = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        reader.execute('CREATE TABLE dg1887t (n NUMBER)')
        assert reader.execute('SELECT n FROM dg1887t').columns[0].null_ok == 1
        other.execute('ALTER TABLE dg1887t MODIFY (n NOT NULL)')
        assert reader.execute('SELECT n FROM dg1887t').columns[0].null_ok == 0
    finally:
        reader.rollback()
        try:
            reader.execute('DROP TABLE dg1887t')
        except Exception:
            reader.rollback()
        reader.close()
        other.close()


def test_a_describe_reads_a_tables_columns_in_one_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # What a describe needs of a table's columns -- NOT NULL, a quoted name,
    # an IS JSON check, the declared type, a time zone precision -- comes from
    # the schema model, read in one query per result (#1872, #1887), with one
    # more for the result's types; a repeat reads nothing.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    sent: list[str] = []
    execute = psycopg.Cursor.execute
    off = psycopg.pq.PipelineStatus.OFF

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        text = str(query)
        if cursor.connection.pgconn.pipeline_status == off and (
            'pg_current_xact_id_if_assigned' not in text
        ):
            sent.append(text)
        return execute(cursor, query, *args, **kwargs)

    query = 'SELECT id, "low", doc, r, ts FROM dm1872t'
    try:
        backend.execute(
            'CREATE TABLE dm1872t (id NUMBER NOT NULL, "low" NUMBER, '
            'doc VARCHAR2(200) CHECK (doc IS JSON), r RAW(16), '
            'ts TIMESTAMP(3) WITH TIME ZONE)'
        )
        # A computed item traces to no table: this reads the schema-wide
        # facts (whether any RAW column or SQL domain exists) and no relation.
        backend.execute('SELECT count(*) FROM dm1872t')
        monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
        columns = backend.execute(query).columns
        assert len(sent) <= 2, sent
        assert [c.null_ok for c in columns] == [0, 1, 1, 1, 1]
        assert columns[1].name == b'low'
        assert columns[2].is_json
        assert columns[3].data_length == 16
        assert columns[4].scale == 3
        sent.clear()
        backend.execute(query)
        assert sent == []
    finally:
        monkeypatch.undo()
        backend.rollback()
        try:
            backend.execute('DROP TABLE dm1872t')
        except Exception:
            backend.rollback()
        backend.close()


def _sent_statements(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    # Each statement the backend pipelines from here on, but its savepoints,
    # its guard and its checks.
    sent: list[str] = []
    execute = psycopg.Cursor.execute
    off = psycopg.pq.PipelineStatus.OFF
    plumbing = (
        'SAVEPOINT',
        'RELEASE',
        'ROLLBACK',
        'SELECT pg_current_xact_id_if_assigned',
        'SELECT sys.ora_ddl_unchanged',
        # The DDL generation a query with no transaction reads on its own
        # (#1916).
        'SELECT (SELECT count(*)',
        'SELECT NULL',
        # The BEGIN a statement opens its transaction with (#1915).
        'BEGIN',
    )

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        text = str(query)
        if cursor.connection.pgconn.pipeline_status != off and not text.startswith(
            plumbing
        ):
            sent.append(text)
        return execute(cursor, query, *args, **kwargs)

    monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
    return sent


def test_an_nvl_of_a_not_null_column_is_the_column(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # NVL(column, x) on a NOT NULL column always answers the column, and the
    # bare column is what an index serves (#1889). Each query answers as the
    # emulation as written does, for every row.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    queries = {
        "SELECT id FROM nv1889t WHERE NVL(name, 'x') = 'b' ORDER BY id": (
            "SELECT id FROM nv1889t WHERE name = 'b' ORDER BY id"
        ),
        'SELECT id FROM nv1889t t WHERE NVL(t.id, 0) > :1 ORDER BY id': (
            'SELECT id FROM nv1889t t WHERE t.id > %(b1)s ORDER BY id'
        ),
        'UPDATE nv1889t SET opt = \'u\' WHERE NVL("low", :1) = :2': (
            'UPDATE nv1889t SET opt = \'u\' WHERE "low" = %(b2)s'
        ),
    }
    try:
        backend.execute(
            'CREATE TABLE nv1889t (id NUMBER NOT NULL, name VARCHAR2(9) NOT NULL, '
            '"low" VARCHAR2(9) NOT NULL, opt VARCHAR2(9))'
        )
        backend.execute(
            "INSERT INTO nv1889t SELECT level, chr(96 + level), 'l' || level, "
            "CASE WHEN mod(level, 2) = 0 THEN 'o' END FROM dual CONNECT BY level <= 4"
        )
        backend.commit()
        sent = _sent_statements(monkeypatch)
        for query, rewritten in queries.items():
            sent.clear()
            binds = ['z', 'l2'] if ':2' in query else [1] if ':1' in query else []
            got = backend.execute(query, binds)
            assert sent[0].split(' RETURNING ')[0] == rewritten
            monkeypatch.undo()
            backend.rollback()  # its row locks, which the check below would wait on
            # The emulation as written, NVL as COALESCE.
            written = query.replace('NVL(', 'COALESCE(').replace(':1', '%(b1)s')
            written = written.replace(':2', '%(b2)s')
            params = {'b1': binds[0], 'b2': binds[1]} if len(binds) == 2 else {}
            if len(binds) == 1:
                params = {'b1': binds[0]}
            with admin.transaction(force_rollback=True):
                expected = admin.execute(written, params)
                if expected.description is None:
                    assert got.rowcount == expected.rowcount
                else:
                    assert [list(r) for r in got.rows] == [
                        list(r) for r in expected.fetchall()
                    ]
            sent = _sent_statements(monkeypatch)
        # A column that may be NULL keeps its NVL; so does one of a table
        # that an outer join or a subquery may make NULL, and a CHAR, which
        # compares blank-padded.
        for kept in (
            "SELECT id FROM nv1889t WHERE NVL(opt, 'x') = 'x'",
            'SELECT a.id FROM nv1889t a LEFT JOIN nv1889t b ON b.opt = a.name '
            'WHERE NVL(b.id, 0) = 0',
            'SELECT id FROM nv1889t WHERE id IN (SELECT id FROM nv1889t) '
            'AND NVL(id, 0) = 1',
        ):
            sent.clear()
            backend.execute(kept)
            assert 'COALESCE(' in sent[0]
    finally:
        monkeypatch.undo()
        backend.rollback()
        try:
            backend.execute('DROP TABLE nv1889t')
        except Exception:
            backend.rollback()
        backend.close()
        admin.close()


def test_another_sessions_ddl_undoes_an_nvl_rewrite_in_time() -> None:
    # The NOT NULL an NVL was cut on (#1889) may be gone by the time the
    # statement runs, and a NULL row with it: a guard in the same pipeline
    # sees the other session's DDL, and the statement runs as written.
    reader = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    other = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    query = "SELECT id FROM ng1889t WHERE NVL(name, 'none') = 'none'"
    try:
        reader.execute('CREATE TABLE ng1889t (id NUMBER, name VARCHAR2(9) NOT NULL)')
        reader.execute("INSERT INTO ng1889t VALUES (1, 'a')")
        reader.commit()
        assert reader.execute(query).rows == []
        other.execute('ALTER TABLE ng1889t MODIFY (name NULL)')
        other.execute('INSERT INTO ng1889t VALUES (2, NULL)')
        other.commit()
        assert [list(r) for r in reader.execute(query).rows or []] == [[2]]
    finally:
        reader.rollback()
        try:
            reader.execute('DROP TABLE ng1889t')
        except Exception:
            reader.rollback()
        reader.close()
        other.close()


def test_the_mirrors_own_setup_is_not_logged_as_ddl() -> None:
    # Every connect runs the Mirror's setup DDL again; logged, it would make
    # every session forget its schema knowledge at every connect (#1887).
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    try:
        if admin.execute("SELECT to_regclass('sys.ora_ddl_log')").fetchone() == (None,):
            PostgresBackend(_CONNINFO, credentials=dict(_CREDS)).close()
        (before,) = _fetched_row(admin.execute('SELECT count(*) FROM sys.ora_ddl_log'))
        PostgresBackend(_CONNINFO, credentials=dict(_CREDS)).close()
        (after,) = _fetched_row(admin.execute('SELECT count(*) FROM sys.ora_ddl_log'))
        assert after == before
    finally:
        admin.close()


def test_a_with_time_zone_column_is_indexed_on_its_instant() -> None:
    # The Mirror compares a WITH TIME ZONE column by its instant, (col).utc,
    # which an index on the composite can't serve; Oracle indexes such a column
    # on SYS_EXTRACT_UTC(col), and the dictionary says so (#1897).
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    try:
        backend.execute(
            'CREATE TABLE tz1897t (id NUMBER, tz TIMESTAMP(3) WITH TIME ZONE, '
            '"Tz2" TIMESTAMP WITH TIME ZONE)'
        )
        backend.execute('CREATE INDEX tz1897_a ON tz1897t (tz)')
        backend.execute('CREATE UNIQUE INDEX tz1897_b ON tz1897t (id, "Tz2" DESC)')
        defs = admin.execute(
            'SELECT pg_get_indexdef(indexrelid) FROM pg_index '
            "WHERE indrelid = 'tz1897t'::regclass ORDER BY indexrelid"
        ).fetchall()
        assert [d.split(' USING btree ')[1] for (d,) in defs] == [
            '(((tz).utc))',
            '(id, (("Tz2").utc) DESC)',
        ]
        with admin.transaction(force_rollback=True):
            admin.execute('SET LOCAL enable_seqscan = off')
            plan = admin.execute(
                "EXPLAIN SELECT id FROM tz1897t WHERE tz > timestamptz '2000-01-01'"
            ).fetchall()
        assert any('tz1897_a' in line for (line,) in plan), plan
        dictionary = {
            'SELECT index_name, index_type, uniqueness FROM all_indexes '
            "WHERE table_name = 'TZ1897T' ORDER BY 1": [
                ('TZ1897_A', 'FUNCTION-BASED NORMAL', 'NONUNIQUE'),
                ('TZ1897_B', 'FUNCTION-BASED NORMAL', 'UNIQUE'),
            ],
            'SELECT index_name, column_name, column_position, descend '
            "FROM all_ind_columns WHERE table_name = 'TZ1897T' ORDER BY 1, 3": [
                ('TZ1897_A', 'SYS_NC00004$', 1, 'ASC'),
                ('TZ1897_B', 'ID', 1, 'ASC'),
                ('TZ1897_B', 'SYS_NC00005$', 2, 'DESC'),
            ],
            'SELECT index_name, column_expression, column_position '
            "FROM all_ind_expressions WHERE table_name = 'TZ1897T' ORDER BY 1, 3": [
                ('TZ1897_A', 'SYS_EXTRACT_UTC("TZ")', 1),
                ('TZ1897_B', 'SYS_EXTRACT_UTC("Tz2")', 2),
            ],
        }
        for query, rows in dictionary.items():
            assert [tuple(r) for r in backend.execute(query).rows] == rows
        # A UNIQUE index refuses two values at one instant, as Oracle does.
        backend.execute(
            "INSERT INTO tz1897t VALUES (1, NULL, TIMESTAMP '2000-01-01 12:00:00 +00:00')"
        )
        with pytest.raises(BackendError) as raised:
            backend.execute(
                'INSERT INTO tz1897t VALUES '
                "(1, NULL, TIMESTAMP '2000-01-01 14:00:00 +02:00')"
            )
        assert raised.value.ora_code == 1
        # Any other index, and an index on another type, stays as written.
        backend.execute('CREATE INDEX tz1897_c ON tz1897t (id)')
        (c,) = admin.execute(
            "SELECT pg_get_indexdef('tz1897_c'::regclass)"
        ).fetchone() or ('',)
        assert c.endswith('USING btree (id)')
    finally:
        backend.rollback()
        backend.execute('DROP TABLE IF EXISTS tz1897t')
        backend.close()
        admin.close()


def test_a_character_column_compares_byte_by_byte() -> None:
    # A character column takes the C collation (#1896): it sorts as Oracle's
    # default NLS_SORT BINARY does, whatever the database's collation, and an
    # index on it serves a LIKE prefix, which no other collation's index can.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    try:
        backend.execute(
            'CREATE TABLE co1896t (id NUMBER, v VARCHAR2(9 CHAR), c CHAR(3), '
            'n NCHAR(3), nv NVARCHAR2(9), "Q" VARCHAR(9), l CLOB)'
        )
        backend.execute('ALTER TABLE co1896t ADD (a VARCHAR2(9), b NUMBER)')
        backend.execute('ALTER TABLE co1896t MODIFY (nv NVARCHAR2(12))')
        collations = admin.execute(
            'SELECT a.attname, c.collname FROM pg_attribute a '
            'LEFT JOIN pg_collation c ON c.oid = a.attcollation '
            "WHERE a.attrelid = 'co1896t'::regclass AND a.attnum > 0 ORDER BY a.attnum"
        ).fetchall()
        assert collations == [
            ('id', None),
            ('v', 'C'),
            ('c', 'C'),
            ('n', 'C'),
            ('nv', 'C'),
            ('Q', 'C'),
            ('l', 'default'),
            ('a', 'C'),
            ('b', None),
        ]
        backend.execute(
            "INSERT INTO co1896t (id, v) SELECT level, CASE level WHEN 1 THEN 'a' "
            "WHEN 2 THEN 'B' ELSE 'k' || level END FROM dual CONNECT BY level <= 300"
        )
        got = backend.execute("SELECT v FROM co1896t WHERE v IN ('a', 'B') ORDER BY v")
        assert [r[0] for r in got.rows] == ['B', 'a']
        backend.execute('CREATE INDEX co1896_v ON co1896t (v)')
        with admin.transaction(force_rollback=True):
            admin.execute('SET LOCAL enable_seqscan = off')
            plan = admin.execute(
                "EXPLAIN SELECT id FROM co1896t WHERE v LIKE 'k5%'"
            ).fetchall()
        assert any("Index Cond: (((v)::text >= 'k5'" in line for (line,) in plan), plan
    finally:
        backend.rollback()
        backend.execute('DROP TABLE IF EXISTS co1896t')
        backend.close()
        admin.close()


def test_a_repeated_write_reads_no_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    # An INSERT ... VALUES or an UPDATE ... SET checks the table's ROWID
    # columns (#1624) from the schema model (#1884): a repeat sends PostgreSQL
    # nothing but the statement, and a number into a ROWID column is still
    # ORA-00932.
    from seerdb.server.backend import BackendError

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    sent: list[str] = []
    execute = psycopg.Cursor.execute
    off = psycopg.pq.PipelineStatus.OFF

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        text = str(query)
        if cursor.connection.pgconn.pipeline_status == off and (
            'pg_current_xact_id_if_assigned' not in text
        ):
            sent.append(text)
        return execute(cursor, query, *args, **kwargs)

    writes = [
        ('INSERT INTO rw1884t (n, s) VALUES (:1, :2)', [1, 'x']),
        ('UPDATE rw1884t SET s = :1 WHERE n = :2', ['y', 1]),
    ]
    try:
        backend.execute('CREATE TABLE rw1884t (n NUMBER, r ROWID, s VARCHAR2(30))')
        for sql, binds in writes:
            backend.execute(sql, binds)
        monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
        for sql, binds in writes:
            backend.execute(sql, binds)
        assert sent == []
        with pytest.raises(BackendError) as raised:
            backend.execute('UPDATE rw1884t SET r = :1 WHERE n = 1', [12345])
        assert raised.value.ora_code == 932
    finally:
        monkeypatch.undo()
        backend.rollback()
        backend.execute('DROP TABLE IF EXISTS rw1884t')
        backend.close()


def test_the_column_readers_share_the_schema_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The features that read a table's columns -- BOOLEAN (#1743), RAW
    # (#1496), VECTOR (#1708), OSON and JSON (#1706, #1707) and INVISIBLE
    # (#1195) -- read them from the schema model (#1887): a table's columns
    # are read once, where each feature read them on its own.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS), presents='23ai')
    if not backend._has_pgvector:
        backend.close()
        pytest.skip('the PostgreSQL bed has no pgvector')
    sent: list[str] = []
    execute = psycopg.Cursor.execute

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        sent.append(str(query))
        return execute(cursor, query, *args, **kwargs)

    try:
        backend.execute(
            'CREATE TABLE m1887t (n NUMBER, f BOOLEAN, r RAW(4), '
            'v VECTOR(3, FLOAT32), d JSON, h NUMBER INVISIBLE)'
        )
        monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
        backend.execute(
            'INSERT INTO m1887t (n, f, r, v, d) VALUES (:1, :2, :3, :4, :5)',
            [1, 1, 'ABCD', '[1, 2, 3]', '{"a": 1}'],
        )
        backend.execute(
            "INSERT INTO m1887t VALUES (2, 0, 'ab', '[1,2,3]', '{\"a\": 2}')"
        )
        rows = backend.execute('SELECT * FROM m1887t ORDER BY n').rows
        assert [row[:3] for row in rows] == [
            (1, True, b'\xab\xcd'),
            (2, False, b'\xab'),
        ]
        assert len(rows[0]) == 5  # h is INVISIBLE
        dotted = backend.execute('SELECT t.d.a FROM m1887t t ORDER BY n').rows
        assert [row[0] for row in dotted] == [1, 2]
        monkeypatch.undo()
        assert sum('a.attrelid = ANY(' in query for query in sent) == 1
        assert not [
            query
            for query in sent
            if 'pg_attribute' in query and 'to_regclass(%s)' in query
        ]
    finally:
        monkeypatch.undo()
        backend.rollback()
        backend.execute('DROP TABLE IF EXISTS m1887t')
        backend.close()


def test_a_ddl_prunes_its_records_and_rereads_the_schema_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # After a DDL (#1918): the records of the columns and types it took away
    # are pruned in one round trip, not one per catalog, and the statement
    # after it reads the schema-wide facts -- collection names, RAW columns,
    # SQL domains, the object types' RAW attributes -- in one query, not one
    # each.
    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    sent: list[str] = []
    execute = psycopg.Cursor.execute

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        sent.append(str(query))
        return execute(cursor, query, *args, **kwargs)

    try:
        backend.execute('CREATE TABLE pr1918t (r RAW(4), n NVARCHAR2(5))')
        (relid,) = _fetched_row(
            backend._conn.execute("SELECT to_regclass('pr1918t')::oid")
        )
        backend._conn.commit()
        monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
        backend.execute('DROP TABLE pr1918t')
        prunes = [q for q in sent if 'WHERE NOT EXISTS' in q and 'DELETE' in q]
        assert len(prunes) == 1
        # Columns, annotations, collection elements, CHECK conditions (#2171),
        # triggers' text (#2174) and column grants (#1946).
        assert prunes[0].count('DELETE FROM sys.ora_') == 6
        sent.clear()
        backend.execute('SELECT 1 FROM dual')
        # The object types' RAW attributes come with them (#1331).
        backend._raw_constructors()
        monkeypatch.undo()
        facts = [q for q in sent if "data_type = 'RAW'" in q or 'typcategory' in q]
        assert len(facts) == 1, facts
        assert [q for q in sent if 'array_agg(x.pos - 1)' in q] == facts
        (left,) = _fetched_row(
            backend._conn.execute(
                'SELECT count(*) FROM sys.ora_columns WHERE relid = %s', (relid,)
            )
        )
        assert left == 0
    finally:
        monkeypatch.undo()
        backend.rollback()
        backend.execute('DROP TABLE IF EXISTS pr1918t')
        backend.close()


def test_a_connect_to_an_installed_database_installs_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A database stamped with this seerdb's installation is left alone: a
    # connect sends its session settings, the DDL log's generation and no DDL
    # (#1871). A missing stamp installs again and stamps it.
    from seerdb.server.backends.postgres import _installation_stamp

    sent: list[str] = []
    execute = psycopg.Cursor.execute

    def recorded(cursor: Any, query: Any, *args: Any, **kwargs: Any) -> Any:
        sent.append(str(query))
        return execute(cursor, query, *args, **kwargs)

    admin = psycopg.connect(_CONNINFO, autocommit=True)
    try:
        admin.execute('COMMENT ON SCHEMA system IS NULL')
        monkeypatch.setattr(psycopg.Cursor, 'execute', recorded)
        PostgresBackend(_CONNINFO, credentials=dict(_CREDS)).close()
        assert any('CREATE OR REPLACE FUNCTION' in s for s in sent)
        (extensions, stamp) = admin.execute(
            "SELECT (SELECT string_agg(extname, ' ' ORDER BY extname) FROM pg_extension "
            "WHERE extname IN ('orafce', 'vector')), "
            "obj_description('system'::regnamespace, 'pg_namespace')"
        ).fetchone() or (None, None)
        assert stamp == _installation_stamp(extensions)
        sent.clear()
        backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
        assert len(sent) <= 3, sent
        assert not any(s.lstrip().startswith(('CREATE', 'DO', 'COMMENT')) for s in sent)
        monkeypatch.undo()
        # And the session works as one that installed: a WITH TIME ZONE value,
        # a LOB and a DATE come back typed.
        row = backend.execute(
            "SELECT TIMESTAMP '2000-01-01 12:00:00 +02:00', to_clob('x'), "
            "DATE '2000-01-02' FROM dual"
        ).rows[0]
        assert row[0].utcoffset() == datetime.timedelta(hours=2)
        assert row[1] == 'x'
        assert row[2] == datetime.datetime(2000, 1, 2)
        backend.close()
    finally:
        monkeypatch.undo()
        admin.close()
