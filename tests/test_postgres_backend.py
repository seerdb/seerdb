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
from decimal import Decimal
from pathlib import Path

import pytest

import seerdb
from seerdb.server import PacketStream, serve_session

psycopg = pytest.importorskip('psycopg')
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'examples'))
from postgres_backend import (  # noqa: E402
    _HELPER_FUNCTIONS_DDL,
    _IS_DDL,
    _REF_SELECT,
    OraInterval,
    PostgresBackend,
    _backend_error,
    _distinct_bind_refs,
    _iot_primary_key,
    _parse_out_assignments,
    _reject_unsupported_ddl_types,
    _to_interval_ym,
    _translate_admin,
    _translate_binds,
    _translate_connect_by,
    _translate_ddl,
    _translate_idioms,
    _translate_plsql_block,
    _translate_routine_ddl,
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


def test_translate_ddl_maps_ref_column_to_bytea() -> None:
    # A `REF <object type>` column has no PostgreSQL equal; since the REF bind that
    # uses it is 12c+ and skips on the 11g Mirror, the column becomes a bytea
    # placeholder so the CREATE succeeds (#139). A REF() call is left alone.
    sent = _translate_ddl('CREATE TABLE t (id NUMBER, r REF PYORACLE_REF_PERSON)')
    assert 'r bytea' in sent
    assert 'REF' not in sent
    # CREATE TABLE ... OF type (a typed table) passes through unchanged.
    assert _translate_ddl('CREATE TABLE people OF PYORACLE_REF_PERSON') == (
        'CREATE TABLE people OF PYORACLE_REF_PERSON'
    )
    # A column merely NAMED `ref` (with an ordinary type) is not a REF type, so
    # it is left alone — the match is anchored to a column name before REF, which
    # a leading `ref INTEGER` has none of (BizarroCharacterTest, #10275).
    named = _translate_ddl('CREATE TABLE other (id INTEGER, ref INTEGER)')
    assert 'ref integer' in named.lower() and 'bytea' not in named


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


def test_translate_idioms_rewrites_connect_by_level_row_generator() -> None:
    # FROM dual CONNECT BY LEVEL <= N maps to generate_series aliased `level`, so a
    # bare LEVEL in the select list resolves to its column (#531).
    simple = _translate_idioms('SELECT LEVEL FROM dual CONNECT BY LEVEL <= 5')
    assert simple == 'SELECT LEVEL FROM generate_series(1, 5) AS level'
    multi = _translate_idioms(
        'SELECT 42 AS k, LEVEL AS n FROM dual CONNECT BY LEVEL <= 200'
    )
    assert multi == 'SELECT 42 AS k, LEVEL AS n FROM generate_series(1, 200) AS level'


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
    assert _translate_admin('GRANT CREATE SESSION TO test_schema') == 'SELECT 1'
    assert (
        _translate_admin('CREATE INDEX test_schema.ix1 ON test_schema.t (c)')
        == 'CREATE INDEX ix1 ON test_schema.t (c)'
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
    # timestamptz → TIMESTAMPTZ (offset-aware).
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
    # TIMESTAMPTZ is offset-aware and equals the same instant as 07:00Z.
    assert tz_value.tzinfo is not None
    assert tz_value == datetime.datetime(
        2024, 6, 1, 7, 0, 0, tzinfo=datetime.timezone.utc
    )


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
    ):
        assert f'FUNCTION {name}(' in _HELPER_FUNCTIONS_DDL
    assert _HELPER_FUNCTIONS_DDL.count('CREATE OR REPLACE FUNCTION') == 6
    # rowidtochar is the identity on the text ctid the ROWID pseudo-column rewrites
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


def test_translate_idioms_rewrites_rowid_pseudocolumn() -> None:
    # The ROWID pseudo-column becomes ctid::text — one rewrite serving both a
    # SELECT (returns the '(0,1)' text) and a WHERE ROWID = :bind (text compare).
    assert _translate_idioms('SELECT ROWID FROM t') == 'SELECT ctid::text FROM t'
    assert _translate_idioms('SELECT id FROM t WHERE ROWID = :r') == (
        'SELECT id FROM t WHERE ctid::text = :r'
    )
    # The word boundary keeps it off ROWIDTOCHAR (no boundary mid-token) — that call
    # resolves to the installed identity helper — and off UROWID (a word char
    # precedes ROWID), so a UROWID column type name is left intact.
    assert _translate_idioms('SELECT ROWIDTOCHAR(ROWID) FROM t') == (
        'SELECT ROWIDTOCHAR(ctid::text) FROM t'
    )
    assert _translate_idioms('CREATE TABLE t (r UROWID)') == (
        'CREATE TABLE t (r UROWID)'
    )
    # Case-insensitive, like the other pseudo-column rewrites.
    assert _translate_idioms('select rowid from t') == 'select ctid::text from t'


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


def test_change_password_rejects_a_wrong_old_password() -> None:
    from seerdb.server import BackendError

    backend = _NoConnPostgresBackend({'PYO': 'pyo123'})
    with pytest.raises(BackendError) as exc:
        backend.change_password('PYO', 'not-the-old-one', 'whatever')
    assert exc.value.ora_code == 1017


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
