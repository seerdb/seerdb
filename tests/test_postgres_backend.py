# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A live client runs real SQL against a PostgreSQL-backed Mirror.

Skips cleanly when psycopg is not installed or no PostgreSQL is reachable
(``MIRROR_PG`` overrides the connection string), so CI without a database just
skips — the same pattern as the live-Oracle integration tests.
"""

from __future__ import annotations

import datetime
import os
import socket
import sys
import threading
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import seerdb
from seerdb.server import PacketStream, serve_session

psycopg = pytest.importorskip('psycopg')
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'examples'))
from postgres_backend import (  # noqa: E402
    _DICTIONARY_STAMP,
    _HELPER_FUNCTIONS_DDL,
    _IS_DDL,
    _NO_OP,
    _REF_SELECT,
    OraInterval,
    PostgresBackend,
    _backend_error,
    _bc_date_loader,
    _distinct_bind_refs,
    _iot_primary_key,
    _object_column_meta,
    _object_type_oid,
    _parse_out_assignments,
    _pg_oid_of,
    _reject_unsupported_ddl_types,
    _strip_leading_comments,
    _to_interval_ym,
    _translate_admin,
    _translate_binds,
    _translate_connect_by,
    _translate_ddl,
    _translate_idioms,
    _translate_plsql_block,
    _translate_routine_ddl,
    _translate_signed_year,
    _urowid_expression,
)


class _FakePgError(Exception):
    def __init__(self, sqlstate: str, message: str) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


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


def test_translate_ddl_maps_create_table_column_types() -> None:
    sent = _translate_ddl(
        'CREATE TABLE t (id NUMBER(10,2), v VARCHAR2(20), d DATE, '
        'r RAW(16), c CLOB, b BLOB, ts TIMESTAMP WITH TIME ZONE, '
        'f BINARY_FLOAT, g BINARY_DOUBLE)'
    )
    assert 'numeric(10,2)' in sent
    assert 'varchar(20)' in sent
    assert 'timestamp(0)' in sent  # DATE keeps its time-of-day
    assert 'r bytea' in sent  # RAW(16) → bytea (size dropped)
    assert 'c ora_clob' in sent  # CLOB → domain over text, so empty ≠ NULL (#534)
    assert 'b ora_blob' in sent  # BLOB → domain over bytea (#534)
    assert 'ts ora_tstz' in sent  # WITH TIME ZONE preserves the offset (#519)
    assert 'f real' in sent and 'g double precision' in sent
    assert 'NUMBER' not in sent and 'VARCHAR2' not in sent


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
    assert 'CREATE FUNCTION sys.deref(r person_t$ref) RETURNS person_t' in out
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


def test_deref_becomes_a_parenthesised_sys_deref() -> None:
    assert _translate_idioms('SELECT id, DEREF(r).name FROM t') == (
        'SELECT id, (sys.deref(r)).name FROM t'
    )
    assert _translate_idioms('SELECT DEREF(:1).name FROM dual') == (
        'SELECT (sys.deref(:1)).name FROM dual'
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
        "SELECT 'decode(a, b, c)' FROM dual",
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


def test_a_replaced_type_is_dropped_and_created() -> None:
    # PostgreSQL has no CREATE OR REPLACE TYPE; the old type goes, without
    # CASCADE, and the new one is translated as a plain CREATE TYPE (#1197). The
    # REF companions of an object type depend on it, so they go first when they
    # exist, and a replaced object type gets new ones (#1127).
    companions_first = (
        "DO $$ BEGIN IF to_regtype('s.o$ref') IS NOT NULL THEN "
        'DROP FUNCTION sys.deref(s.o$ref); DROP TYPE s.o$ref; END IF; END $$'
        '; DROP TYPE IF EXISTS s.o; CREATE TYPE s.o AS (a numeric)'
    )
    replaced_object = _translate_ddl('CREATE OR REPLACE TYPE s.o AS OBJECT (a NUMBER)')
    assert replaced_object.startswith(companions_first)
    assert '; CREATE TYPE s.o$ref AS (tab oid, id uuid)' in replaced_object
    assert _translate_ddl(
        'create or replace type s.v as varray(4) of number;'
    ).endswith(
        '; DROP TYPE IF EXISTS s.v; CREATE DOMAIN s.v AS numeric[] '
        'CHECK (VALUE IS NULL OR array_length(VALUE, 1) <= 4)'
    )
    assert _translate_ddl('create or replace type s.t\n    as table of s.o;').endswith(
        '; DROP TYPE IF EXISTS s.t; CREATE DOMAIN s.t AS s.o[]'
    )
    # FORCE is not translated.
    forced = 'CREATE OR REPLACE TYPE s.o FORCE AS OBJECT (a NUMBER)'
    assert not _translate_ddl(forced).startswith(('DROP TYPE', 'DO $$'))
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
    assert _translate_ddl('create type s.t as table of number;') == (
        'CREATE DOMAIN s.t AS numeric[]'
    )
    assert _translate_ddl('CREATE TYPE s.v AS TABLE OF VARCHAR2(20)') == (
        'CREATE DOMAIN s.v AS varchar(20)[]'
    )
    assert _translate_ddl('create type s.tt\n    as table of s.t;') == (
        'CREATE DOMAIN s.tt AS s.t[]'
    )


def test_a_varray_type_becomes_a_bounded_array_domain() -> None:
    # The bound rides in a CHECK; a script's trailing `;`, which Oracle accepts
    # on type DDL, stays out of the element type.
    bounded = (
        'CREATE DOMAIN s.a AS numeric[] '
        'CHECK (VALUE IS NULL OR array_length(VALUE, 1) <= 10)'
    )
    assert _translate_ddl('create type s.a as varray(10) of number') == bounded
    assert _translate_ddl('create type s.a as varray(10) of number;') == bounded
    assert _translate_ddl('create type s.o as\n    varray(10) of s.sub;') == (
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
        == 'SET search_path TO test_schema, public, sys, oracle'
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
    assert _translate_admin("ALTER SESSION SET NLS_DATE_FORMAT='YYYY'") == _NO_OP


def test_sessiontimezone_reads_the_zone_the_session_was_given() -> None:
    # The Oracle spelling ALTER SESSION stored, or before any was set the
    # session's own offset in Oracle's `+hh:mm` form.
    assert _translate_idioms('SELECT sessiontimezone FROM dual') == (
        "SELECT coalesce(nullif(current_setting('seerdb.time_zone', true), ''), "
        "to_char(now(), 'TZH:TZM')) FROM dual"
    )
    # An ordinary statement is passed through untouched.
    assert _translate_admin('SELECT 1 FROM dual') == 'SELECT 1 FROM dual'


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


def test_translate_idioms_negates_whole_day_to_second_interval() -> None:
    # Oracle's leading `-` negates the whole DAY TO SECOND interval; PostgreSQL
    # applies it only to the days, so lift it to a unary minus on the literal (#520).
    neg = _translate_idioms(
        "INSERT INTO t VALUES (INTERVAL '-0 00:00:01.5' DAY TO SECOND)"
    )
    assert "(- INTERVAL '0 00:00:01.5' DAY TO SECOND)" in neg
    # Precision qualifiers ride along; a positive literal is left untouched.
    prec = _translate_idioms("p := INTERVAL '-1 02:03:04.5' DAY(4) TO SECOND(6)")
    assert "- INTERVAL '1 02:03:04.5' DAY(4) TO SECOND(6)" in prec
    pos = _translate_idioms("INTERVAL '5 04:03:02.123456' DAY TO SECOND")
    assert pos == "INTERVAL '5 04:03:02.123456' DAY TO SECOND"


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
    # A plain (non-batcherrors) array DML now runs through the backend's own
    # executemany. A row that fails mid-batch must abort the whole batch (Oracle's
    # non-batcherrors semantics) — the savepoint rolls back every row of it — and
    # leave the session usable for the next statement, never desyncing.
    listen, server, result = _start_mirror()
    conn = _connect(listen.getsockname()[1])
    try:
        cur = conn.cursor()
        cur.execute('drop table if exists t_manyfail')
        cur.execute('create table t_manyfail (id integer primary key)')
        with pytest.raises(seerdb.DatabaseError):
            # The third row duplicates the first key — the batch aborts.
            cur.executemany('insert into t_manyfail values (:1)', [(1,), (2,), (1,)])
        # The session survived; the aborted batch applied nothing (the two good
        # rows were rolled back with it).
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
    assert remaining == 0


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
    from postgres_backend import PostgresBackend

    from seerdb.server import BackendError

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


def test_helper_functions_ddl_defines_the_scalar_helpers() -> None:
    # The Oracle scalar functions orafce doesn't cover are installed as real
    # PostgreSQL functions (#513) instead of rewritten per call site, so those
    # call sites resolve directly. Each is defined idempotently (CREATE OR
    # REPLACE) and returns the LOB domains where appropriate.
    for name in (
        'hextoraw',
        'rawtohex',
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
    ):
        assert f'FUNCTION {name}(' in _HELPER_FUNCTIONS_DDL
    assert _HELPER_FUNCTIONS_DDL.count('CREATE OR REPLACE FUNCTION') == 37
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


def test_translate_idioms_functions_and_literals() -> None:
    assert _translate_idioms('SELECT SYSDATE') == 'SELECT localtimestamp(0)'
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
        'CREATE TABLE t (n numeric, r varchar(18), u varchar(4000))'
    )
    assert 'varchar' not in _translate_ddl('CREATE TABLE t AS SELECT ROWID FROM s')


def test_a_rowid_renders_as_the_client_renders_it() -> None:
    # The backend's sys.ora_rowid and the client's rowid_to_string must agree,
    # or a lastrowid the Mirror reports would never match a SELECT ROWID. The
    # block is one past the ctid's: a client takes block 0 for "no rowid".
    from seerdb.common.types import rowid_to_string

    backend = PostgresBackend(_CONNINFO, credentials=dict(_CREDS))
    try:
        (got,) = backend._conn.execute(
            "SELECT sys.ora_rowid(16384, '(12,3)'::tid)"
        ).fetchone()
        assert got == rowid_to_string(16384, 1, 13, 3)
    finally:
        backend.close()


def test_unqualified_names_resolve_in_the_login_users_schema() -> None:
    # Oracle starts a session in the login user's schema, so a table created as
    # user.t is found as plain t (#1188); a user without a schema of its own
    # still resolves through public, as before.
    admin = psycopg.connect(_CONNINFO, autocommit=True)
    admin.execute('DROP SCHEMA IF EXISTS pyo_login CASCADE')
    admin.execute('CREATE SCHEMA pyo_login')
    admin.execute('CREATE TABLE pyo_login.pyo_login_t (n integer)')
    admin.execute('INSERT INTO pyo_login.pyo_login_t VALUES (7)')
    creds = {'PYO_LOGIN': 'x', 'PYO_NO_SCHEMA': 'y'}
    backend = PostgresBackend(_CONNINFO, credentials=creds)
    other = PostgresBackend(_CONNINFO, credentials=creds)
    try:
        assert backend.authenticate('PYO_LOGIN') == 'x'
        assert backend.execute('SELECT n FROM pyo_login_t').rows == [(7,)]
        (schema,) = backend._conn.execute('SELECT current_schema()').fetchone()
        assert schema == 'pyo_login'
        assert other.authenticate('PYO_NO_SCHEMA') == 'y'
        (schema,) = other._conn.execute('SELECT current_schema()').fetchone()
        assert schema == 'public'
    finally:
        backend.close()
        other.close()
        admin.execute('DROP SCHEMA pyo_login CASCADE')
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


def test_a_column_name_folds_as_oracle_folds_it() -> None:
    # A legal unquoted lower-case name came from an unquoted one; anything else
    # was quoted and is kept (#1204). A reserved word could only be quoted.
    from postgres_backend import _oracle_column_name

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
        (timeout,) = ddl._conn.execute('SHOW lock_timeout').fetchone()
        assert timeout == '0'
        holder.rollback()
        ddl.execute('TRUNCATE TABLE pyo_ddl_nowait')
    finally:
        holder.rollback()
        holder.execute('DROP TABLE pyo_ddl_nowait')
        holder.close()
        ddl.close()


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
        (pid, sid, serial) = backend._conn.execute(
            "SELECT pg_backend_pid(), sys.sys_context('userenv', 'sid'), "
            'sys.ora_serial(pg_backend_pid())'
        ).fetchone()
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
    # do (#1212).
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
        with pytest.raises(psycopg.OperationalError):
            victim._conn.execute('SELECT 1')
        assert killer.execute('SELECT 1 FROM dual').rows == [(1,)]
    finally:
        killer.close()
        victim.close()


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
    from postgres_backend import _tds_chars, _tds_number, _tds_timestamp
    from postgres_backend import _TdsCollection as C
    from postgres_backend import _TdsLeaf as L
    from postgres_backend import _TdsObject as _O

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
    from postgres_backend import _tds

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
    from postgres_backend import _tds

    from seerdb.common.tns_consts import (
        TNS_TYPE_NUMBER,
        TNS_TYPE_RAW,
        TNS_TYPE_REFCURSOR,
        TNS_TYPE_VARCHAR,
    )
    from seerdb.server.backend import BindVar

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
        from postgres_backend import _tds_chars, _tds_number, _TdsCollection, _TdsObject

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
            _reject_unsupported_ddl_types(f'CREATE TABLE t (id NUMBER, {coltype})')
        assert exc.value.ora_code == 902

    # An ordinary CREATE TABLE — and any non-CREATE-TABLE statement — is fine.
    _reject_unsupported_ddl_types('CREATE TABLE t (id NUMBER, v VARCHAR2(10))')
    _reject_unsupported_ddl_types('SELECT json_col FROM t WHERE flag = 1')


def test_reject_create_domain_raises_ora_901() -> None:
    from seerdb.server import BackendError

    # SQL domains are 23ai; the 11.2 Mirror's server doesn't know CREATE DOMAIN, so
    # it is refused with ORA-00901 — one of the codes the suite's SQL-domain guard
    # skips on (#512). A domain-referencing CREATE TABLE is not itself a domain
    # definition and passes this check.
    with pytest.raises(BackendError) as exc:
        _reject_unsupported_ddl_types('CREATE DOMAIN PYO_DOM_T AS NUMBER(3,0)')
    assert exc.value.ora_code == 901
    _reject_unsupported_ddl_types(
        'CREATE TABLE t (id NUMBER, d NUMBER DOMAIN PYO_DOM_T)'
    )


# --- PL/SQL routine translation (#503) — a pure function, no live PG needed -----


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
    assert 'LANGUAGE plpgsql AS $$ BEGIN p_out := p_in * 2; END $$' in out


def test_translate_routine_ddl_function() -> None:
    out = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION f(p IN NUMBER) RETURN NUMBER '
        'AS BEGIN RETURN p + 100; END;'
    )
    assert out.startswith(
        'DROP FUNCTION IF EXISTS f; '
        'CREATE OR REPLACE FUNCTION f(p IN numeric) RETURNS numeric'
    )
    assert 'LANGUAGE plpgsql AS $$ BEGIN RETURN p + 100; END $$' in out


def test_translate_routine_ddl_parameterless_function() -> None:
    # Oracle lets a no-parameter routine omit the list entirely; PostgreSQL always
    # needs the parentheses, so an absent list becomes an empty one (#530). A body
    # containing its own parentheses still parses (params don't swallow the body).
    out = _translate_routine_ddl(
        'CREATE OR REPLACE FUNCTION f RETURN BINARY_DOUBLE AS BEGIN RETURN 2.25; END;'
    )
    assert 'CREATE OR REPLACE FUNCTION f() RETURNS double precision' in out
    assert 'LANGUAGE plpgsql AS $$ BEGIN RETURN 2.25; END $$' in out
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


# --- changepassword (#515) — credential-map only, no live PG needed -------------


class _NoConnPostgresBackend(PostgresBackend):
    # Skip the psycopg connect / orafce setup — change_password only touches the
    # credential map, so no live PostgreSQL is needed to test it.
    def __init__(self, credentials: dict) -> None:
        self._credentials = credentials


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
    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, statement: str) -> None:
        self.calls.append(statement)

    def commit(self) -> None:
        self.calls.append('<commit>')

    def rollback(self) -> None:
        self.calls.append('<rollback>')


class _RecordingPostgresBackend(PostgresBackend):
    # Just a connection that records what reaches it.
    def __init__(self) -> None:
        self._conn = _RecordingConn()


def test_transaction_control_runs_outside_the_statement_savepoint() -> None:
    # COMMIT / ROLLBACK end the transaction and SAVEPOINT must outlive the
    # statement, so none of them may sit inside `_mirror_stmt` (#1181).
    backend = _RecordingPostgresBackend()
    for statement in ('COMMIT', 'commit work', 'ROLLBACK', '-- done\nROLLBACK WORK'):
        backend.execute(statement)
    backend.execute('SAVEPOINT sp1')
    assert backend._conn.calls == [
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
    assert backend._conn.calls == [
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


def test_change_password_rejects_one_oracle_would_not_store() -> None:
    # Oracle up to 12.1 -- the release this backend presents -- keeps passwords
    # of at most 30 bytes, and the protocol route refuses a longer one with
    # ORA-01017. Accepting it left the account with a password no client could
    # log in with (#1127).
    from seerdb.server import BackendError

    creds = {'PYO': 'pyo123'}
    backend = _NoConnPostgresBackend(creds)
    with pytest.raises(BackendError) as exc:
        backend.change_password('PYO', 'pyo123', '1' * 31)
    assert exc.value.ora_code == 1017
    assert creds['PYO'] == 'pyo123'
    backend.change_password('PYO', 'pyo123', '1' * 30)
    assert creds['PYO'] == '1' * 30


# --- Bind translation (#516) — a pure function, no live PG needed --------------


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


def test_distinct_bind_refs_first_appearance_order_skips_literals() -> None:
    assert _distinct_bind_refs(':a := :b; :c := :a') == ['a', 'b', 'c']
    # A colon inside a string literal is not a bind ref.
    assert _distinct_bind_refs("INSERT INTO t VALUES ('x :nope' || :v)") == ['v']


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


def _hold_a_dictionary_read() -> Any:
    # A client mid-transaction that has read a dictionary view: its lock on the
    # view is what a CREATE OR REPLACE VIEW has to wait for (#1152).
    holder = psycopg.connect(_CONNINFO)
    holder.execute('SET search_path TO public, sys, oracle')
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

        typ, _info = backend._object_type(_pg_oid_of(bytes(oid)))
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
    # UTL_RAW is installed as PostgreSQL functions in a utl_raw schema (orafce ships
    # none), so a schema-qualified Oracle call round-trips RAW/bytea (#765).
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
