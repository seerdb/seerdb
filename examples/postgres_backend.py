# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A PostgreSQL backend for the Mirror (psycopg 3).

Point a Mirror at a PostgreSQL database and thin-dialect Oracle clients run real
SQL against it. Result columns map from PostgreSQL type OIDs to Oracle types; a
column whose type the Mirror cannot yet represent is refused with a clean
``ORA-03001`` (unimplemented feature) rather than mis-encoded — the same
capabilities-and-errors contract SQLite uses, just with a different set of
supported types.

Requires the ``psycopg`` package. This is a demo/adapter outside ``seerdb``
core; the driver dependency lives here, not in the library.

**Requires the** `orafce <https://github.com/orafce/orafce>`_ **PostgreSQL
extension** for Oracle-compatible SQL functions (``nvl``, ``decode``,
``to_char`` / ``to_date``, ``add_months``, ``instr``, …). The backend puts its
``oracle`` schema on the search_path and creates the extension if it can, so
those idioms need no hand-rolled translation. Install it on the server (e.g.
Alpine ``apk add postgresql-orafce`` for a matching PG major, or build from
source with PGXS) — see ``examples/mirror-pg.Dockerfile``.

A handful of scalar Oracle functions — ``hextoraw`` / ``rawtohex``,
``empty_clob`` / ``empty_blob``, ``from_tz``, ``rowidtochar`` — the backend installs
itself as real PostgreSQL functions at connect (see ``_HELPER_FUNCTIONS_DDL``), so
those call sites resolve directly with no rewrite, the same way the ``ora_tstz``
composite and the ``ora_clob`` / ``ora_blob`` domains back their types. Only bare
pseudo-columns / -constants (``ROWID``, ``SYSDATE``, ``BINARY_DOUBLE_INFINITY``) and
literal / clause shapes (a negative ``INTERVAL``, the ``1.5f`` suffix, ``CONNECT BY
LEVEL``) — none of which is a call that could resolve to a function — remain regex
rewrites.

**Oracle-only ceiling.** A handful of Oracle features a real server offers cannot
be represented faithfully behind an 11.2 Mirror on PostgreSQL. Where the 11.2 suite
has a version guard, the backend rejects the feature so the test *skips* exactly as
it would on a server that lacks it — a SQL domain (23ai) is refused with ORA-00901,
just as the JSON / VECTOR / BOOLEAN column types (21c/23ai) are refused with
ORA-00902. The rest have no such guard and simply do not pass; they are the honest
edge of this adapter:

- **UROWID / index-organized rowids** — the physical ``ROWID`` pseudo-column is
  emulated with PostgreSQL's ``ctid`` (rendered as text, ``ROWIDTOCHAR``-comparable,
  usable as a bind), but ``ctid`` is *mutable* — it changes on ``UPDATE`` / ``VACUUM
  FULL`` — so it is a faithful locator only within an unmodified snapshot, not a
  durable cross-transaction handle (a real migration substitutes a surrogate identity
  key). The UROWID (``*``-prefixed logical rowid) of an ``ORGANIZATION INDEX`` table
  is emulated from the table's primary key (see ``_urowid_expression``): a stable,
  ``*``-prefixed handle that round-trips as a ``WHERE ROWID = :bind``, but not
  Oracle's actual key encoding. ``DBMS_ROWID`` is unimplemented: ``ctid`` exposes
  only a block and a slot, not the data-object# and
  relative-file# that the package's accessors (``ROWID_OBJECT``,
  ``ROWID_RELATIVE_FNO``, …) decompose a physical rowid into.
- **Real ``REF`` / ``DEREF``** — an Oracle object type maps to a PostgreSQL
  composite type and a typed table (``CREATE TABLE t OF type``), and ``SELECT
  REF(p)`` is emulated with the row's ctid as the locator plus the object type
  recovered from ``pg_class.reloftype`` — enough for the client to decode a REF with
  the right ``type_name`` (which is all the 11g REF tests check before they skip the
  bind). But a PostgreSQL composite has no REF *pointer*: the actual REF **bind** and
  ``DEREF`` round-trip is a 12c+ feature the suite already skips on the 11g Mirror,
  and could not be served if it did not — the ctid locator is opaque and never
  dereferenced.
- **Integer division semantics** — Oracle's ``/`` is always NUMBER (float)
  division, so ``15 / 10`` is ``1.5``; PostgreSQL's integer ``/`` truncates to
  ``1``. Matching Oracle would mean coercing every division to numeric, a broad
  change to expression semantics the backend does not make, so an integer-operand
  division reflects PostgreSQL's result (SQLAlchemy ``TrueDivTest``).
- **A deliberately quoted lower-case identifier** — Oracle stores an unquoted
  name upper-case and a quoted one verbatim, so a lower-case name is
  unambiguously a quoted one; PostgreSQL folds *both* an unquoted name and a
  quoted lower-case one to the same stored lower-case, so the two cannot be told
  apart after the fact. ``sys.ora_name`` upper-cases a stored lower-case name to
  Oracle's canonical form — required for the overwhelmingly common unquoted case —
  which means a table or column created as a quoted lower-case ``"t1"`` does not
  round-trip back as ``t1`` (SQLAlchemy ``NormalizedNameTest``). A quoted
  mixed-case or reserved-word name, which PostgreSQL *does* store distinctly, is
  preserved.
"""

from __future__ import annotations

import datetime
import re
import struct
from collections.abc import Sequence

import psycopg
from psycopg import sql
from psycopg.adapt import Loader
from psycopg.types.composite import CompositeInfo, register_composite

from seerdb.common.datatypes import IntervalYM
from seerdb.common.dbobject import DbRef
from seerdb.common.sqltext import is_plsql, strip_returning_into
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_BLOB,
    TNS_TYPE_BOOLEAN,
    TNS_TYPE_CLOB,
    TNS_TYPE_DATE,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_REF,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
)
from seerdb.server import (
    BackendError,
    BindVar,
    Capability,
    ColumnMeta,
    Credentials,
    CursorResult,
    Result,
    UnsupportedFeature,
    credential_lookup,
)
from seerdb.server.identity import IDENTITY_12_1

# The PostgreSQL composite type that backs Oracle's TIMESTAMP WITH TIME ZONE
# (#519). A native timestamptz stores UTC and hands the value back in the session
# zone, discarding the offset the client entered — but Oracle preserves that
# offset. So a WITH TIME ZONE column becomes this two-field composite: `utc` is
# the instant (a real timestamptz, so the instant is stored correctly) and `off`
# is the entered offset in seconds, which the read path uses to re-tag the value.
_TSTZ_TYPE = 'ora_tstz'
_TSTZ_TYPE_DDL = (
    'DO $$ BEGIN CREATE TYPE ora_tstz AS (utc timestamptz, off integer); '
    'EXCEPTION WHEN duplicate_object THEN NULL; END $$'
)

# CLOB / BLOB back onto PostgreSQL domains over text / bytea (#534). A plain text
# column can't tell an empty CLOB from a NULL one — a zero-length value encodes as
# NULL on the Oracle wire (empty-string-is-NULL), so an empty LOB came back as None
# instead of '' / b''. A domain is transparent for INSERT (it accepts its base
# type) and for every text / bytea operation, yet a result column still traces back
# through pg_attribute to the domain — so the read path can recognise a LOB column
# and encode it as a real LOB, whose empty value is distinct from NULL. The domain
# is otherwise invisible: values arrive as ordinary str / bytes.
_CLOB_TYPE = 'ora_clob'
_BLOB_TYPE = 'ora_blob'
_LOB_TYPE_DDL = (
    'DO $$ BEGIN CREATE DOMAIN ora_clob AS text; '
    'EXCEPTION WHEN duplicate_object THEN NULL; END $$;'
    'DO $$ BEGIN CREATE DOMAIN ora_blob AS bytea; '
    'EXCEPTION WHEN duplicate_object THEN NULL; END $$;'
)

# INTERVAL YEAR TO MONTH onto a PostgreSQL domain over `interval` (#504). Oracle
# has two interval families — YEAR TO MONTH (a calendar count of months) and DAY
# TO SECOND (an exact duration) — but PostgreSQL has a single `interval` type, so
# both share oid 1186 and neither is distinguishable by wire oid alone. A domain
# lets a YEAR TO MONTH column trace back through pg_attribute to `ora_intervalym`
# (exactly as the LOB domains do), so the read path can encode it as the Oracle
# INTERVAL YEAR TO MONTH type rather than DAY TO SECOND. The months themselves
# survive via a custom interval loader (see OraInterval below); psycopg's default
# loader flattens a year-month interval to a `timedelta`, dropping the months.
_INTERVALYM_TYPE = 'ora_intervalym'
_INTERVALYM_TYPE_DDL = (
    'DO $$ BEGIN CREATE DOMAIN ora_intervalym AS interval; '
    'EXCEPTION WHEN duplicate_object THEN NULL; END $$'
)

# Oracle scalar functions the backend installs as real PostgreSQL functions,
# rather than rewriting each call site with a regex (#513). A parens-called Oracle
# function — HEXTORAW('..'), EMPTY_CLOB(), FROM_TZ(ts, 'zone') — resolves
# case-insensitively to a same-named function on the search_path, so once these
# exist the call text needs no translation at all. This is the same "install a
# server-side object" pattern the ora_tstz composite and the ora_clob / ora_blob
# domains already use. orafce 4.17 also ships hextoraw / rawtohex / empty_clob /
# empty_blob / from_tz, but as plain text / bytea / timestamptz — the backend keeps
# its own so empty_clob / empty_blob return the ora_clob / ora_blob domains and
# from_tz returns the ora_tstz composite, which the LOB read-back and the
# offset-preserving WITH TIME ZONE round-trip both rely on.
# Only the parens-called functions move here; a bare pseudo-constant (SYSDATE,
# BINARY_DOUBLE_INFINITY) or a literal / clause shape (a negative INTERVAL, the
# `1.5f` suffix, CONNECT BY LEVEL) has no call to resolve and stays a rewrite in
# _translate_idioms. EMPTY_CLOB / EMPTY_BLOB return the LOB domains, so they need
# those to exist first (created just before this in __init__).
_HELPER_FUNCTIONS_DDL = (
    # HEXTORAW('DEADBEEF') → the RAW/bytea value of a hex string.
    'CREATE OR REPLACE FUNCTION hextoraw(text) RETURNS bytea '
    "LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT decode($1, 'hex') $$;"
    # RAWTOHEX(x) → the hex text of a bytea. Oracle returns upper-case hex.
    'CREATE OR REPLACE FUNCTION rawtohex(bytea) RETURNS text '
    "LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT upper(encode($1, 'hex')) $$;"
    # EMPTY_CLOB() / EMPTY_BLOB() → an empty LOB (the domain type, so a value
    # stored through one is recognised as a LOB on read-back).
    f'CREATE OR REPLACE FUNCTION empty_clob() RETURNS {_CLOB_TYPE} '
    f"LANGUAGE sql IMMUTABLE AS $$ SELECT ''::{_CLOB_TYPE} $$;"
    f'CREATE OR REPLACE FUNCTION empty_blob() RETURNS {_BLOB_TYPE} '
    f"LANGUAGE sql IMMUTABLE AS $$ SELECT ''::bytea::{_BLOB_TYPE} $$;"
    # FROM_TZ(ts, 'zone') → a TIMESTAMP WITH TIME ZONE: the naive timestamp read as
    # local wall-clock in `zone`, returned as the ora_tstz composite (utc, offset)
    # so it inserts into a WITH TIME ZONE column and round-trips its offset. `zone`
    # may be a named IANA region (US/Eastern), whose offset PostgreSQL resolves at
    # that instant from the live zone database — so the stored offset is DST-correct
    # (EST -05:00 in January, EDT -04:00 in July). The offset is local minus the
    # instant shown as naive UTC. STABLE, not IMMUTABLE: a named region's offset
    # depends on the tz database. The region *name* itself is not preserved — the
    # value carries the resolved offset, exactly like an explicit ±HH:MM literal.
    # A numeric ±HH:MM offset is applied as an interval so it follows Oracle's ISO
    # sign convention (east of UTC is positive); handing it straight to AT TIME ZONE
    # as text would use PostgreSQL's inverted POSIX sign. The zone-applied instant is
    # computed once in the subselect and reused for both composite fields.
    f'CREATE OR REPLACE FUNCTION from_tz(timestamp, text) RETURNS {_TSTZ_TYPE} '
    'LANGUAGE sql STABLE STRICT AS $$ SELECT ROW('
    'z.i, '
    "EXTRACT(EPOCH FROM ($1 - (z.i AT TIME ZONE 'UTC')))::int"
    f')::{_TSTZ_TYPE} FROM (SELECT CASE '
    "WHEN $2 ~ '^[+-]?[0-9]{1,2}:[0-9]{2}$' THEN $1 AT TIME ZONE ($2)::interval "
    'ELSE $1 AT TIME ZONE $2 END) AS z(i) $$;'
    # ROWIDTOCHAR(rowid) → the VARCHAR2 form of a ROWID. The ROWID pseudo-column is
    # rewritten to `ctid::text` (already text), so this is the identity on that text.
    'CREATE OR REPLACE FUNCTION rowidtochar(text) RETURNS text '
    'LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT $1 $$;'
)


# UTL_RAW — Oracle's RAW/bytea manipulation package (#765). orafce does not ship
# it, so the backend installs it as PostgreSQL functions in a `utl_raw` schema, and
# a schema-qualified Oracle call (UTL_RAW.CAST_TO_RAW(...)) resolves to it
# case-insensitively. Bytes are the DB charset (UTF-8) for the varchar2/raw casts;
# BIT_AND/OR/XOR follow Oracle's rule that the unprocessed tail of the longer
# operand is appended after the shorter one runs out. The bodies qualify
# pg_catalog.length so utl_raw.length does not recurse into itself when a
# caller puts utl_raw on the search_path.
_UTL_RAW_DDL = """
CREATE SCHEMA IF NOT EXISTS utl_raw;
CREATE OR REPLACE FUNCTION utl_raw.cast_to_raw(text) RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT convert_to($1, 'UTF8') $$;
CREATE OR REPLACE FUNCTION utl_raw.cast_to_varchar2(bytea) RETURNS text
  LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT convert_from($1, 'UTF8') $$;
CREATE OR REPLACE FUNCTION utl_raw.length(bytea) RETURNS integer
  LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT pg_catalog.length($1) $$;
CREATE OR REPLACE FUNCTION utl_raw.substr(bytea, integer, integer DEFAULT NULL)
  RETURNS bytea LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN $2 = 0 THEN NULL
      WHEN $2 < 0 THEN substring($1 from pg_catalog.length($1) + $2 + 1 for coalesce($3, pg_catalog.length($1)))
      ELSE substring($1 from $2 for coalesce($3, pg_catalog.length($1))) END $$;
CREATE OR REPLACE FUNCTION utl_raw.concat(VARIADIC bytea[]) RETURNS bytea
  LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(string_agg(x, ''::bytea), ''::bytea) FROM unnest($1) AS x $$;
CREATE OR REPLACE FUNCTION utl_raw._bitop(a bytea, b bytea, op char) RETURNS bytea
  LANGUAGE plpgsql IMMUTABLE AS $$
  DECLARE n int := least(pg_catalog.length(a), pg_catalog.length(b)); r bytea := ''::bytea; i int; v int;
  BEGIN
    FOR i IN 0 .. n - 1 LOOP
      v := CASE op WHEN '&' THEN get_byte(a, i) & get_byte(b, i)
                   WHEN '|' THEN get_byte(a, i) | get_byte(b, i)
                   ELSE get_byte(a, i) # get_byte(b, i) END;
      r := r || decode(lpad(to_hex(v), 2, '0'), 'hex');
    END LOOP;
    IF pg_catalog.length(a) > n THEN r := r || substring(a from n + 1);
    ELSIF pg_catalog.length(b) > n THEN r := r || substring(b from n + 1); END IF;
    RETURN r;
  END $$;
CREATE OR REPLACE FUNCTION utl_raw.bit_and(bytea, bytea) RETURNS bytea
  LANGUAGE sql IMMUTABLE AS $$ SELECT utl_raw._bitop($1, $2, '&') $$;
CREATE OR REPLACE FUNCTION utl_raw.bit_or(bytea, bytea) RETURNS bytea
  LANGUAGE sql IMMUTABLE AS $$ SELECT utl_raw._bitop($1, $2, '|') $$;
CREATE OR REPLACE FUNCTION utl_raw.bit_xor(bytea, bytea) RETURNS bytea
  LANGUAGE sql IMMUTABLE AS $$ SELECT utl_raw._bitop($1, $2, '#') $$;
"""


# DBMS_UTILITY — the commonly-called entry points orafce does not already ship
# (it has GET_TIME and FORMAT_CALL_STACK) (#764). Installed into the same
# dbms_utility schema. FORMAT_ERROR_STACK / FORMAT_ERROR_BACKTRACE return the
# empty string a plain SQL context (no active exception) yields in Oracle too.
# DB_VERSION is a procedure with OUT arguments, reached through the callproc
# path; its release string tracks the demo's advertised server_identity (12.1).
# COMMA_TO_TABLE / TABLE_TO_COMMA are left unimplemented: they exchange an Oracle
# collection (DBMS_UTILITY.UNCL_ARRAY / LNAME_ARRAY), a PL/SQL table type the
# Mirror does not model.
_DBMS_UTILITY_DDL = """
CREATE SCHEMA IF NOT EXISTS dbms_utility;
CREATE OR REPLACE FUNCTION dbms_utility.format_error_stack() RETURNS text
  LANGUAGE sql IMMUTABLE AS $$ SELECT ''::text $$;
CREATE OR REPLACE FUNCTION dbms_utility.format_error_backtrace() RETURNS text
  LANGUAGE sql IMMUTABLE AS $$ SELECT ''::text $$;
CREATE OR REPLACE PROCEDURE dbms_utility.db_version(
    INOUT version text, INOUT compatibility text)
  LANGUAGE plpgsql AS $$ BEGIN
    version := '12.1.0.2.0'; compatibility := '12.1.0.0.0';
  END $$;
"""


# Oracle data-dictionary emulation (#759): the SYS_CONTEXT userenv function and a
# minimal set of Oracle-shaped catalog views over pg_catalog / information_schema,
# so a reflecting client (SQLAlchemy's Oracle dialect, ORMs) finds the metadata it
# queries. Oracle folds unquoted identifiers to upper case and treats the user as
# the schema; the views surface UPPER-cased names and take the current schema as
# the "owner", so a table created through the Mirror shows up under the connected
# user's schema. Installed idempotently at connect alongside the helper functions.
_ORACLE_DICTIONARY_DDL = (
    # SYS_CONTEXT('userenv', <param>) — the session context the dialect reads to
    # learn its current schema/user before it reflects anything.
    'CREATE OR REPLACE FUNCTION sys.sys_context(text, text) RETURNS text '
    'LANGUAGE sql STABLE AS $$ SELECT CASE lower($2) '
    "WHEN 'current_schema' THEN upper(current_schema()) "
    "WHEN 'current_user' THEN upper(current_user::text) "
    "WHEN 'session_user' THEN upper(session_user::text) "
    "WHEN 'current_schemaid' THEN current_setting('search_path') "
    "WHEN 'db_name' THEN upper(current_database()) "
    "WHEN 'db_unique_name' THEN upper(current_database()) "
    "WHEN 'instance_name' THEN upper(current_database()) "
    "WHEN 'server_host' THEN NULL "
    "WHEN 'host' THEN NULL "
    "WHEN 'ip_address' THEN NULL "
    "WHEN 'lang' THEN 'US' "
    "WHEN 'language' THEN 'AMERICAN_AMERICA.AL32UTF8' "
    'ELSE NULL END $$;'
    # ora_owner(schema): the Oracle owner for a PostgreSQL schema — the current
    # schema for a session-local (pg_temp) object, so GLOBAL TEMPORARY tables and
    # their indexes/constraints report under the user's schema like Oracle (#759).
    'CREATE OR REPLACE FUNCTION sys.ora_owner(text) RETURNS text LANGUAGE sql '
    "STABLE AS $$ SELECT CASE WHEN $1 LIKE 'pg_temp%' THEN upper(current_schema()) "
    'ELSE upper($1) END $$;'
    # ora_name(name): fold a PostgreSQL identifier to Oracle's stored form.
    # Oracle stores an unquoted identifier upper-case and a quoted one verbatim;
    # PostgreSQL stores an unquoted identifier lower-case and a quoted one
    # verbatim. A name that is a legal unquoted identifier (all lower-case, no
    # dots or other specials) came from an unquoted name, so upper-case it to
    # Oracle's canonical form; anything else (mixed case, dots) was quoted, so
    # keep it exactly. A reserved word (asc, key, ...) must be quoted in Oracle
    # too, so it is also left as-is. This matches the dialect's normalize/
    # denormalize round trip, so quoted mixed-case, dotted and reserved-word
    # identifiers reflect back unchanged.
    'CREATE OR REPLACE FUNCTION sys.ora_name(text) RETURNS text LANGUAGE sql '
    "IMMUTABLE AS $$ SELECT CASE WHEN $1 ~ '^[a-z][a-z0-9_$#]*$' "
    "AND upper($1) <> ALL (ARRAY['ALL','ALTER','AND','ANY','AS','ASC','BETWEEN','BY','CHAR','CHECK','CLUSTER','COMMENT','COMPRESS','CONNECT','CREATE','CURRENT','DATE','DECIMAL','DEFAULT','DELETE','DESC','DISTINCT','DROP','ELSE','EXCLUSIVE','EXISTS','FLOAT','FOR','FROM','GRANT','GROUP','HAVING','IDENTIFIED','IN','INDEX','INSERT','INTEGER','INTERSECT','INTO','IS','LEVEL','LIKE','LOCK','LONG','MINUS','MODE','NOCOMPRESS','NOT','NOWAIT','NULL','NUMBER','OF','ON','OPTION','OR','ORDER','PCTFREE','PRIOR','PUBLIC','RAW','RENAME','RESOURCE','REVOKE','SELECT','SET','SHARE','SIZE','SMALLINT','START','SYNONYM','TABLE','THEN','TO','TRIGGER','UID','UNION','UNIQUE','UPDATE','USER','VALUES','VARCHAR','VARCHAR2','VIEW','WHERE','WITH']) THEN upper($1) "
    'ELSE $1 END $$;'
    # Oracle-shaped catalog views over information_schema / pg_catalog. Oracle
    # treats the user as the schema and folds names upper-case, so `owner` and the
    # object names are UPPER(pg schema/relation), and a client that filters
    # `owner = SYS_CONTEXT('userenv','current_schema')` (which returns UPPER'd
    # current schema) sees objects in its own schema. Enough columns for the
    # SQLAlchemy Oracle dialect's reflection (get_table_names / get_columns /
    # get_pk_constraint / get_indexes).
    'CREATE OR REPLACE VIEW sys.all_tables AS SELECT upper(table_schema) AS owner, '
    'ora_name(table_name) AS table_name, NULL::text AS tablespace_name, '
    'NULL::text AS iot_name, NULL::text AS duration, '
    'NULL::text AS compression, NULL::text AS compress_for '
    "FROM information_schema.tables WHERE table_type='BASE TABLE' "
    "AND table_schema NOT IN ('pg_catalog','information_schema','oracle','sys') "
    # Oracle GLOBAL TEMPORARY tables are PostgreSQL temporary tables (session-local,
    # in a pg_temp schema); report them under the current schema like Oracle does.
    'UNION ALL SELECT upper(current_schema()), ora_name(table_name), NULL, NULL, '
    "'SYS$SESSION', NULL, NULL FROM information_schema.tables "
    "WHERE table_type='LOCAL TEMPORARY';"
    'CREATE OR REPLACE VIEW sys.user_tables AS SELECT table_name, tablespace_name, '
    'iot_name, duration FROM all_tables WHERE owner=upper(current_schema());'
    'CREATE OR REPLACE VIEW sys.all_views AS SELECT upper(table_schema) AS owner, '
    'ora_name(table_name) AS view_name, view_definition AS text '
    'FROM information_schema.views '
    "WHERE table_schema NOT IN ('pg_catalog','information_schema','oracle','sys');"
    'CREATE OR REPLACE VIEW sys.all_sequences AS SELECT upper(sequence_schema) AS '
    'sequence_owner, ora_name(sequence_name) AS sequence_name, '
    'minimum_value::numeric AS min_value, maximum_value::numeric AS max_value, '
    'increment::numeric AS increment_by, '
    "CASE cycle_option WHEN 'YES' THEN 'Y' ELSE 'N' END AS cycle_flag, "
    "'N' AS order_flag, 20::numeric AS cache_size, start_value::numeric AS last_number "
    'FROM information_schema.sequences '
    "WHERE sequence_schema NOT IN ('pg_catalog','information_schema','oracle','sys');"
    'CREATE OR REPLACE VIEW sys.user_sequences AS SELECT sequence_name, min_value, '
    'max_value, increment_by, cycle_flag, order_flag, cache_size, last_number '
    'FROM all_sequences WHERE sequence_owner=upper(current_schema());'
    'CREATE OR REPLACE VIEW sys.all_mviews AS SELECT upper(schemaname) AS owner, '
    'ora_name(matviewname) AS mview_name, definition AS query FROM pg_matviews;'
    'CREATE OR REPLACE VIEW sys.all_mview_comments AS SELECT upper(schemaname) AS owner, '
    "ora_name(matviewname) AS mview_name, obj_description((quote_ident(schemaname)||'.'||"
    'quote_ident(matviewname))::regclass) AS comments FROM pg_matviews;'
    'CREATE OR REPLACE VIEW sys.all_tab_cols AS SELECT '
    "CASE WHEN c.table_schema LIKE 'pg_temp%' THEN upper(current_schema()) "
    'ELSE upper(c.table_schema) END AS owner, '
    'ora_name(c.table_name) AS table_name, ora_name(c.column_name) AS column_name, '
    'c.ordinal_position AS column_id, '
    "CASE c.data_type WHEN 'numeric' THEN 'NUMBER' WHEN 'integer' THEN 'NUMBER' "
    "WHEN 'bigint' THEN 'NUMBER' WHEN 'smallint' THEN 'NUMBER' "
    "WHEN 'double precision' THEN 'BINARY_DOUBLE' WHEN 'real' THEN 'BINARY_FLOAT' "
    "WHEN 'character varying' THEN 'VARCHAR2' WHEN 'character' THEN 'CHAR' "
    "WHEN 'text' THEN 'CLOB' WHEN 'date' THEN 'DATE' "
    "WHEN 'timestamp without time zone' THEN 'TIMESTAMP' "
    "WHEN 'timestamp with time zone' THEN 'TIMESTAMP WITH TIME ZONE' "
    "WHEN 'bytea' THEN 'BLOB' WHEN 'boolean' THEN 'NUMBER' "
    'ELSE upper(c.data_type) END AS data_type, '
    'coalesce(c.character_maximum_length, c.numeric_precision, 22) AS data_length, '
    'c.numeric_precision AS data_precision, c.numeric_scale AS data_scale, '
    'c.character_maximum_length AS char_length, '
    "CASE c.is_nullable WHEN 'YES' THEN 'Y' ELSE 'N' END AS nullable, "
    "c.column_default AS data_default, 'NO' AS hidden_column, "
    "'NO' AS virtual_column, 'NO' AS identity_column, NULL::text AS default_on_null "
    'FROM information_schema.columns c '
    "WHERE c.table_schema NOT IN ('pg_catalog','information_schema','oracle','sys');"
    'CREATE OR REPLACE VIEW sys.all_tab_columns AS SELECT * FROM all_tab_cols;'
    'CREATE OR REPLACE VIEW sys.user_tab_columns AS SELECT * FROM all_tab_cols '
    'WHERE owner=upper(current_schema());'
    'CREATE OR REPLACE VIEW sys.all_col_comments AS SELECT ora_owner(n.nspname) AS owner, '
    'ora_name(c.relname) AS table_name, ora_name(a.attname) AS column_name, '
    'col_description(c.oid, a.attnum) AS comments '
    'FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace '
    'JOIN pg_attribute a ON a.attrelid=c.oid '
    "WHERE a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','v','m') "
    "AND n.nspname NOT IN ('pg_catalog','information_schema','oracle','sys');"
    'CREATE OR REPLACE VIEW sys.all_tab_comments AS SELECT ora_owner(n.nspname) AS owner, '
    'ora_name(c.relname) AS table_name, '
    "CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' "
    "ELSE 'TABLE' END AS table_type, obj_description(c.oid) AS comments "
    'FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace '
    "WHERE c.relkind IN ('r','v','m') "
    "AND n.nspname NOT IN ('pg_catalog','information_schema','oracle','sys');"
    # all_users: every schema is an Oracle user. get_schema_names()/has_schema()
    # read username from here; the emulation schemas (oracle, sys) and PostgreSQL's
    # own (pg_*, information_schema) are hidden, so a reflecting client sees the
    # real schemas (public, test_schema, ...) under Oracle's upper-cased names.
    'CREATE OR REPLACE VIEW sys.all_users AS SELECT upper(nspname) AS username, '
    'oid::bigint AS user_id, NULL::timestamp AS created FROM pg_namespace '
    "WHERE nspname NOT LIKE 'pg\\_%' "
    "AND nspname NOT IN ('information_schema','oracle','sys');"
    # all_tab_identity_cols: an identity column is a PostgreSQL identity column
    # (pg_attribute.attidentity 'a'=ALWAYS, 'd'=BY DEFAULT). The dialect JOINs this
    # on every get_columns once it believes the server is 12c, so it must exist or
    # reflection raises ORA-00942. Options are reported as Oracle's defaults for now.
    """CREATE OR REPLACE VIEW sys.all_tab_identity_cols AS SELECT ora_owner(n.nspname) AS owner, ora_name(c.relname) AS table_name, ora_name(a.attname) AS column_name, CASE a.attidentity WHEN 'a' THEN 'ALWAYS' ELSE 'BY DEFAULT' END AS generation_type, ora_name(c.relname || '_' || a.attname || '_seq') AS sequence_name, 'START WITH: 1, INCREMENT BY: 1, MAX_VALUE: 9999999999999999999999999999, MIN_VALUE: 1, CYCLE_FLAG: N, CACHE_SIZE: 20, ORDER_FLAG: N' AS identity_options FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE a.attidentity IN ('a','d') AND NOT a.attisdropped AND a.attnum>0 AND n.nspname NOT IN ('pg_catalog','information_schema','oracle','sys');"""
    'CREATE OR REPLACE VIEW sys.all_objects AS SELECT '
    "CASE WHEN n.nspname LIKE 'pg_temp%' THEN upper(current_schema()) "
    'ELSE upper(n.nspname) END AS owner, '
    'ora_name(c.relname) AS object_name, NULL::text AS subobject_name, '
    'c.oid::bigint AS object_id, '
    "CASE c.relkind WHEN 'r' THEN 'TABLE' WHEN 'v' THEN 'VIEW' "
    "WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'i' THEN 'INDEX' "
    "WHEN 'S' THEN 'SEQUENCE' ELSE upper(c.relkind::text) END AS object_type, "
    "'VALID' AS status, "
    "CASE WHEN c.relpersistence='t' THEN 'Y' ELSE 'N' END AS temporary, "
    "'N' AS generated, 'N' AS secondary "
    'FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace '
    "WHERE c.relkind IN ('r','v','m','i','S') "
    "AND n.nspname NOT IN ('pg_catalog','information_schema','oracle','sys');"
    'CREATE OR REPLACE VIEW sys.all_constraints AS SELECT ora_owner(tc.constraint_schema) '
    'AS owner, ora_name(tc.constraint_name) AS constraint_name, '
    "CASE tc.constraint_type WHEN 'PRIMARY KEY' THEN 'P' WHEN 'FOREIGN KEY' THEN 'R' "
    "WHEN 'UNIQUE' THEN 'U' WHEN 'CHECK' THEN 'C' ELSE '?' END AS constraint_type, "
    'ora_owner(tc.table_schema) AS table_schema, ora_name(tc.table_name) AS table_name, '
    'NULL::text AS search_condition, '
    'upper(rc.unique_constraint_schema) AS r_owner, '
    'ora_name(rc.unique_constraint_name) AS r_constraint_name, '
    "'NO ACTION' AS delete_rule, 'ENABLED' AS status, 'VALIDATED' AS validated "
    'FROM information_schema.table_constraints tc '
    'LEFT JOIN information_schema.referential_constraints rc '
    'ON rc.constraint_schema=tc.constraint_schema '
    'AND rc.constraint_name=tc.constraint_name '
    "WHERE tc.constraint_schema NOT IN ('pg_catalog','information_schema','oracle','sys');"
    'CREATE OR REPLACE VIEW sys.all_cons_columns AS SELECT ora_owner(kcu.constraint_schema) '
    'AS owner, ora_name(kcu.constraint_name) AS constraint_name, '
    'ora_name(kcu.table_name) AS table_name, ora_name(kcu.column_name) AS column_name, '
    'kcu.ordinal_position AS position '
    'FROM information_schema.key_column_usage kcu '
    "WHERE kcu.constraint_schema NOT IN ('pg_catalog','information_schema','oracle','sys');"
    'CREATE OR REPLACE VIEW sys.all_indexes AS SELECT ora_owner(n.nspname) AS owner, '
    'ora_name(ic.relname) AS index_name, ora_owner(tn.nspname) AS table_owner, '
    'ora_name(tc.relname) AS table_name, '
    "CASE WHEN ix.indisunique THEN 'UNIQUE' ELSE 'NONUNIQUE' END AS uniqueness, "
    "'NORMAL' AS index_type, 'VALID' AS status, "
    'NULL::text AS compression, NULL::int AS prefix_length, '
    'NULL::text AS tablespace_name, NULL::text AS ityp_owner, '
    'NULL::text AS ityp_name, NULL::text AS parameters '
    'FROM pg_index ix JOIN pg_class ic ON ic.oid=ix.indexrelid '
    'JOIN pg_namespace n ON n.oid=ic.relnamespace '
    'JOIN pg_class tc ON tc.oid=ix.indrelid '
    'JOIN pg_namespace tn ON tn.oid=tc.relnamespace '
    "WHERE n.nspname NOT IN ('pg_catalog','information_schema','oracle','sys');"
    'CREATE OR REPLACE VIEW sys.all_ind_columns AS SELECT ora_owner(n.nspname) AS index_owner, '
    'ora_name(ic.relname) AS index_name, ora_owner(tn.nspname) AS table_owner, '
    'ora_name(tc.relname) AS table_name, ora_name(a.attname) AS column_name, '
    "k.n AS column_position, CASE WHEN (k.opt & 1) = 1 THEN 'DESC' ELSE 'ASC' END AS descend "
    'FROM pg_index ix JOIN pg_class ic ON ic.oid=ix.indexrelid '
    'JOIN pg_namespace n ON n.oid=ic.relnamespace '
    'JOIN pg_class tc ON tc.oid=ix.indrelid '
    'JOIN pg_namespace tn ON tn.oid=tc.relnamespace '
    'CROSS JOIN LATERAL unnest(ix.indkey::int2[], ix.indoption::int2[]) WITH ORDINALITY AS k(attnum, opt, n) '
    'JOIN pg_attribute a ON a.attrelid=tc.oid AND a.attnum=k.attnum '
    "WHERE n.nspname NOT IN ('pg_catalog','information_schema','oracle','sys');"
    # A DESC column in an index is a function-based index in Oracle: the column
    # appears here as the quoted expression "COL" at its position, so reflection
    # (which LEFT JOINs on column_position) renders it as an expression with DESC
    # sorting. PostgreSQL stores it as a plain descending key column, so emit a row
    # only for descending columns (indoption bit 0x01), matching Oracle's shape.
    'CREATE OR REPLACE VIEW sys.all_ind_expressions AS SELECT '
    'ora_owner(n.nspname) AS index_owner, ora_name(ic.relname) AS index_name, '
    'ora_owner(tn.nspname) AS table_owner, ora_name(tc.relname) AS table_name, '
    "'\"' || ora_name(a.attname) || '\"' AS column_expression, k.n AS column_position "
    'FROM pg_index ix JOIN pg_class ic ON ic.oid=ix.indexrelid '
    'JOIN pg_namespace n ON n.oid=ic.relnamespace '
    'JOIN pg_class tc ON tc.oid=ix.indrelid '
    'JOIN pg_namespace tn ON tn.oid=tc.relnamespace '
    'CROSS JOIN LATERAL unnest(ix.indkey::int2[], ix.indoption::int2[]) '
    'WITH ORDINALITY AS k(attnum, opt, n) '
    'JOIN pg_attribute a ON a.attrelid=tc.oid AND a.attnum=k.attnum '
    'WHERE (k.opt & 1) = 1 '
    "AND n.nspname NOT IN ('pg_catalog','information_schema','oracle','sys');"
)

# The PostgreSQL `interval` OID (pg_type.oid) — the base type ora_intervalym is a
# domain over, so both YEAR TO MONTH and DAY TO SECOND columns report it on the
# wire.
_INTERVAL_OID = 1186


class OraInterval(datetime.timedelta):
    """A ``timedelta`` that also carries the interval's whole-month count.

    psycopg's default loader turns a PostgreSQL ``interval`` into a plain
    ``timedelta``, which has no notion of months — so a YEAR TO MONTH interval
    (``3-7``) arrives as an approximate day count and its calendar months are
    lost. The loaders below return this subclass instead, capturing ``months``
    from the raw value while still being a real ``timedelta``: a DAY TO SECOND
    interval keeps its exact duration with ``months == 0`` (so the existing
    INTERVALDS encode path, which tests ``isinstance(value, timedelta)``, is
    untouched), and a YEAR TO MONTH interval carries its months for the read path
    to turn into an :class:`IntervalYM`.
    """

    months: int

    def __new__(cls, *, months: int, td: datetime.timedelta) -> 'OraInterval':
        self = super().__new__(
            cls, days=td.days, seconds=td.seconds, microseconds=td.microseconds
        )
        self.months = months
        return self


# `<n> years <m> mons` in a PostgreSQL interval's text form (either field may be
# signed and either may be absent). Their sum is the whole-month count.
_PG_INTERVAL_YEARS = re.compile(r'(-?\d+)\s+years?')
_PG_INTERVAL_MONS = re.compile(r'(-?\d+)\s+mons?')


class _IntervalMonthsTextLoader(Loader):
    # Parse the month fields out of the text form, delegating the duration to
    # psycopg's built-in text interval loader.
    format = psycopg.pq.Format.TEXT

    def __init__(self, oid: int, context=None) -> None:
        super().__init__(oid, context)
        from psycopg.types.datetime import IntervalLoader

        self._base = IntervalLoader(oid, context)

    def load(self, data) -> OraInterval:
        text = bytes(data).decode()
        years = int(m.group(1)) if (m := _PG_INTERVAL_YEARS.search(text)) else 0
        mons = int(m.group(1)) if (m := _PG_INTERVAL_MONS.search(text)) else 0
        return OraInterval(months=years * 12 + mons, td=self._base.load(data))


class _IntervalMonthsBinaryLoader(Loader):
    # The binary form is int64 microseconds, int32 days, int32 months; take the
    # months field and delegate the duration to the built-in binary loader.
    format = psycopg.pq.Format.BINARY

    def __init__(self, oid: int, context=None) -> None:
        super().__init__(oid, context)
        from psycopg.types.datetime import IntervalBinaryLoader

        self._base = IntervalBinaryLoader(oid, context)

    def load(self, data) -> OraInterval:
        _micros, _days, months = struct.unpack('!qii', data)
        return OraInterval(months=months, td=self._base.load(data))


def _to_interval_ym(value: 'OraInterval | None') -> 'IntervalYM | None':
    # An OraInterval → an IntervalYM built from its whole-month count; IntervalYM
    # normalises the split (0, 43) → 3y 7m and shares the sign, so a negative
    # (0, -14) → -1y -2m. A None (SQL NULL) passes through.
    if value is None:
        return None
    return IntervalYM(0, getattr(value, 'months', 0))


# One Oracle bind reference: `:` + an identifier or number (`:x`, `:my_var`,
# `:1`), or a quoted name (`:"desc"`), which is how a client reaches a name the
# plain form cannot express (#686). A `::` cast is left alone (handled by the
# scan below, which only starts a bind where the previous char isn't `:`).
_BIND_REF = re.compile(r':(?:"([^"\n]+)"|(\w+))')


def _bind_name(match: 're.Match') -> str:
    # The name either spelling refers to. The quotes are not part of it.
    return match.group(1) if match.group(1) is not None else match.group(2)


def _bind_key(name: str) -> str:
    # A psycopg dict key for a bind name — a numbered bind (:1), and a quoted
    # name that is not a plain identifier, aren't valid placeholder keys, so
    # prefix them (b1). Ordinary named binds keep their name.
    return name if name.isidentifier() else f'b{name}'


# The PostgreSQL type a NULL bind is cast to, from the type the client declared
# for it (#699). A NULL carries no type of its own: PostgreSQL either refuses a
# parameter it cannot infer ("could not determine data type of parameter") or
# infers text where the statement needs a number. Oracle reads the type off the
# bind descriptor; the Mirror hands it over as a BindVar, and the cast says it.
# The string types are deliberately absent: a NULL nobody declared travels as
# VARCHAR too, so a text cast would turn `id = :x` on a NUMBER column into
# `numeric = text` and break it, while an uncast placeholder lets PostgreSQL
# infer the column's type from context, which is what an Oracle NULL does.
_NULL_CASTS = {
    TNS_TYPE_NUMBER: 'numeric',
    TNS_TYPE_BFLOAT: 'real',
    TNS_TYPE_BDOUBLE: 'double precision',
    TNS_TYPE_DATE: 'timestamp',
    TNS_TYPE_TIMESTAMP: 'timestamp',
    TNS_TYPE_TIMESTAMPTZ: _TSTZ_TYPE,
    TNS_TYPE_TIMESTAMPLTZ: 'timestamptz',
    TNS_TYPE_INTERVALYM: 'interval',
    TNS_TYPE_INTERVALDS: 'interval',
    TNS_TYPE_RAW: 'bytea',
    TNS_TYPE_LONGRAW: 'bytea',
    TNS_TYPE_BLOB: 'bytea',
    TNS_TYPE_BOOLEAN: 'boolean',
}


def _copy_quoted_region(sql: str, start: int, out: list[str]) -> int:
    """Copy the quoted region at ``start`` (a ``'`` string literal or a ``\"``
    identifier) into ``out`` verbatim and return the index just past it. A doubled
    quote is an escaped quote that stays inside; a literal ``%`` is doubled so
    psycopg does not read it as a placeholder."""
    quote = sql[start]
    out.append(quote)
    i, n = start + 1, len(sql)
    while i < n:
        char = sql[i]
        if char == quote:
            if i + 1 < n and sql[i + 1] == quote:
                out.append(quote)
                out.append(quote)
                i += 2
                continue
            out.append(quote)
            return i + 1
        out.append('%%' if char == '%' else char)
        i += 1
    return i  # unterminated region: copied to end of string


def _translate_binds(sql: str, binds: Sequence) -> tuple[str, dict]:
    """Rewrite Oracle bind references to psycopg named placeholders and build the
    parameter dict (#516). Oracle binds by name, so a bind repeated in the text
    (``:x … :x``) is one value, and a ``:`` inside a string literal is not a bind
    — both of which a blind ``:name`` → ``%s`` substitution gets wrong. Distinct
    binds map to ``binds`` in first-appearance order (positional ``:1 :2`` and a
    single dict/list of values both land correctly). A literal ``%`` in the text
    (a LIKE pattern, a column name) is doubled: psycopg treats the bound query as
    a format string, so a bare ``%`` would be read as a broken placeholder."""
    values = list(binds)
    names: list[str] = []  # distinct bind names, in first-appearance order
    out: list[str] = []
    tstz_keys: set[str] = set()  # bind keys whose value is an aware datetime
    intervalym_keys: set[str] = set()  # bind keys whose value is an IntervalYM
    i, n = 0, len(sql)
    while i < n:
        char = sql[i]
        if char == "'" or char == '"':
            # Copy a whole quoted region verbatim -- a string literal ('...') or a
            # quoted identifier ("...") -- so a ':' inside it (a column named
            # "col:ons") is never mistaken for a bind. A doubled quote ('' or "")
            # is an escaped quote that stays inside the region, and a literal % is
            # doubled for psycopg's format-string parsing.
            i = _copy_quoted_region(sql, i, out)
            continue
        match = _BIND_REF.match(sql, i)
        if match is not None and (i == 0 or sql[i - 1] != ':'):
            name = _bind_name(match)
            if name not in names:
                names.append(name)
            key = _bind_key(name)
            value = (
                values[names.index(name)] if names.index(name) < len(values) else None
            )
            if isinstance(value, BindVar):
                # A typed NULL (#699): the value is None; the cast carries the
                # declared type, where there is a PostgreSQL type to cast to.
                cast = _NULL_CASTS.get(value.tns_type)
                out.append(f'%({key})s::{cast}' if cast else f'%({key})s')
            elif isinstance(value, datetime.datetime) and value.tzinfo is not None:
                # An aware datetime binds a TIMESTAMP WITH TIME ZONE — build the
                # offset-preserving composite so the entered offset survives the
                # round trip rather than being normalised to UTC (#519).
                out.append(f'ROW(%({key})s, %({key}__off)s)::{_TSTZ_TYPE}')
                tstz_keys.add(key)
            elif isinstance(value, IntervalYM):
                # An IntervalYM binds an INTERVAL YEAR TO MONTH — send its whole-month
                # count and rebuild a PostgreSQL interval, so the months survive
                # (psycopg has no dumper for IntervalYM) (#504).
                out.append(f'make_interval(months => %({key})s)')
                intervalym_keys.add(key)
            else:
                out.append(f'%({key})s')
            i = match.end()
            continue
        out.append(char.replace('%', '%%'))
        i += 1
    params: dict = {}
    for idx, name in enumerate(names):
        if idx >= len(values):
            continue
        key = _bind_key(name)
        value = values[idx]
        params[key] = value.value if isinstance(value, BindVar) else value
        if key in tstz_keys:
            params[f'{key}__off'] = int(values[idx].utcoffset().total_seconds())
        elif key in intervalym_keys:
            params[key] = values[idx].years * 12 + values[idx].months
    return ''.join(out), params


# Oracle → PostgreSQL column-type rewrites for CREATE TABLE (#500). Applied in
# order, so a multi-word / longer keyword comes before a shorter one it contains
# (LONG RAW before RAW / LONG, TIMESTAMP WITH TIME ZONE before TIMESTAMP,
# NVARCHAR2 before VARCHAR2, NCLOB before CLOB). A size suffix the target type
# keeps (VARCHAR2(10) → varchar(10), NUMBER(p,s) → numeric(p,s)) rides along
# because only the keyword is replaced; one PostgreSQL rejects (RAW(16)) is
# matched with its parens and dropped. Word boundaries keep column names and
# other tokens untouched; only CREATE TABLE is rewritten, so a type keyword used
# as an identifier elsewhere is left alone.
_DDL_TYPE_REWRITES = [
    # Oracle character-length semantics: VARCHAR2(20 CHAR) / CHAR(1 BYTE) — the
    # `CHAR` / `BYTE` length qualifier PostgreSQL has no syntax for; drop it so the
    # length maps to a plain varchar(n) / char(n) (#759, the reflection fixtures
    # declare columns this way).
    (re.compile(r'\(\s*(\d+)\s+(?:CHAR|BYTE)\s*\)', re.IGNORECASE), r'(\1)'),
    # SYS_REFCURSOR (a REF CURSOR OUT param) → PostgreSQL's refcursor (#518).
    (re.compile(r'\bSYS_REFCURSOR\b', re.IGNORECASE), 'refcursor'),
    # A `REF <object type>` column (#139). PostgreSQL has no REF, but the REF-bind
    # column is only exercised by the 12c+ path the suite skips on the 11g Mirror —
    # the CREATE just has to succeed — so the column becomes a bytea placeholder.
    # The column name before REF is kept: it anchors the match to a REF *type*, so
    # a column merely *named* `ref` (ref INTEGER) is left alone. `REF(` (a REF()
    # call) has no space and is not matched.
    (re.compile(r'\b(\w+)\s+REF\s+\w+', re.IGNORECASE), r'\1 bytea'),
    (re.compile(r'\bLONG\s+RAW\b', re.IGNORECASE), 'bytea'),
    (re.compile(r'\bRAW\s*\(\s*\d+\s*\)', re.IGNORECASE), 'bytea'),
    (re.compile(r'\bRAW\b', re.IGNORECASE), 'bytea'),
    # WITH LOCAL TIME ZONE normalises to the session zone (like PostgreSQL's own
    # timestamptz), so map it there. WITH TIME ZONE instead *preserves* the entered
    # offset — which timestamptz cannot — so it maps to the `ora_tstz` composite
    # (utc, offset) that carries the offset across the round trip (#519). LOCAL is
    # matched first (it is the more specific keyword).
    (
        re.compile(r'\bTIMESTAMP\s+WITH\s+LOCAL\s+TIME\s+ZONE\b', re.IGNORECASE),
        'timestamptz',
    ),
    (
        re.compile(r'\bTIMESTAMP\s+WITH\s+TIME\s+ZONE\b', re.IGNORECASE),
        _TSTZ_TYPE,
    ),
    (re.compile(r'\bTIMESTAMP\b', re.IGNORECASE), 'timestamp'),
    (re.compile(r'\bDATE\b', re.IGNORECASE), 'timestamp(0)'),
    (
        re.compile(
            r'\bINTERVAL\s+DAY(?:\s*\(\d+\))?\s+TO\s+SECOND(?:\s*\(\d+\))?\b',
            re.IGNORECASE,
        ),
        'interval',
    ),
    # INTERVAL YEAR TO MONTH → the ora_intervalym domain over interval, so the read
    # path can tell it from a DAY TO SECOND interval and preserve the months (#504).
    (
        re.compile(r'\bINTERVAL\s+YEAR(?:\s*\(\d+\))?\s+TO\s+MONTH\b', re.IGNORECASE),
        _INTERVALYM_TYPE,
    ),
    (re.compile(r'\bNVARCHAR2\b', re.IGNORECASE), 'varchar'),
    (re.compile(r'\bVARCHAR2\b', re.IGNORECASE), 'varchar'),
    (re.compile(r'\bNCHAR\b', re.IGNORECASE), 'char'),
    (re.compile(r'\bNUMBER\b', re.IGNORECASE), 'numeric'),
    # CLOB / NCLOB / BLOB → domains over text / bytea, so the read path can tell a
    # LOB column from a plain VARCHAR2 / RAW and preserve empty-vs-NULL (#534).
    (re.compile(r'\bNCLOB\b', re.IGNORECASE), _CLOB_TYPE),
    (re.compile(r'\bCLOB\b', re.IGNORECASE), _CLOB_TYPE),
    (re.compile(r'\bBLOB\b', re.IGNORECASE), _BLOB_TYPE),
    (re.compile(r'\bLONG\b', re.IGNORECASE), 'text'),
    (re.compile(r'\bBINARY_FLOAT\b', re.IGNORECASE), 'real'),
    (re.compile(r'\bBINARY_DOUBLE\b', re.IGNORECASE), 'double precision'),
]
# Oracle table clauses PostgreSQL has no equal for — dropped (the resulting plain
# table is close enough for the suite): an index-organized table is just a table
# (a PRIMARY KEY already gives the index), and GLOBAL TEMPORARY maps to a plain
# TEMPORARY table (ON COMMIT ... ROWS is already valid PostgreSQL).
_DDL_ORG_INDEX = re.compile(r'\s+ORGANIZATION\s+INDEX\b', re.IGNORECASE)
_DDL_GLOBAL_TEMPORARY = re.compile(r'\bGLOBAL\s+TEMPORARY\b', re.IGNORECASE)
# Index-organized tables: Oracle gives their rows a logical UROWID — a
# '*'-prefixed base64 of the primary key — where a heap table has a physical
# ROWID. PostgreSQL has neither, so the backend remembers which tables a session
# created ORGANIZATION INDEX and their primary-key columns, and renders ROWID on
# those as '*' || base64(primary key): a stable, '*'-prefixed handle that
# round-trips through a `WHERE ROWID = :bind` because the same expression stands
# on both sides. It is not Oracle's key encoding, just its shape. The primary key
# is read from an inline `col type PRIMARY KEY` or a `PRIMARY KEY (cols)`
# constraint; a column whose type carries parentheses (NUMBER(10,2)) is not
# matched inline, and a table with no recognised key keeps the heap ctid form.
_CREATE_TABLE_NAME = re.compile(
    r'\s*CREATE\s+(?:GLOBAL\s+TEMPORARY\s+)?TABLE\s+([\w.]+)', re.IGNORECASE
)
_PK_CONSTRAINT = re.compile(r'\bPRIMARY\s+KEY\s*\(([^)]+)\)', re.IGNORECASE)
_PK_INLINE = re.compile(r'[(,]\s*(\w+)\s+[^,()]*?\bPRIMARY\s+KEY\b', re.IGNORECASE)
_DROP_TABLE_NAME = re.compile(r'\s*DROP\s+TABLE\s+([\w.]+)', re.IGNORECASE)
_STATEMENT_TABLE = re.compile(r'\b(?:FROM|UPDATE|INTO)\s+([\w.]+)', re.IGNORECASE)
_ROWID_WORD = re.compile(r'\bROWID\b', re.IGNORECASE)


def _bare_table(name: str) -> str:
    return name.split('.')[-1].upper()


def _iot_primary_key(sql: str) -> tuple[str, list[str]] | None:
    """The (table, primary-key columns) of a ``CREATE TABLE … ORGANIZATION INDEX``,
    or None for any other statement or an IOT whose key isn't recognised."""
    if not _IS_CREATE_TABLE.match(sql) or not _DDL_ORG_INDEX.search(sql):
        return None
    name = _CREATE_TABLE_NAME.match(sql)
    if name is None:
        return None
    constraint = _PK_CONSTRAINT.search(sql)
    if constraint is not None:
        cols = [c.strip() for c in constraint.group(1).split(',') if c.strip()]
    else:
        inline = _PK_INLINE.search(sql)
        cols = [inline.group(1)] if inline is not None else []
    return (_bare_table(name.group(1)), cols) if cols else None


def _urowid_expression(pk_columns: list[str]) -> str:
    """The SQL rendering an IOT row's logical rowid from its primary key."""
    key = ', '.join(pk_columns)
    return f"('*' || encode(convert_to(ROW({key})::text, 'UTF8'), 'base64'))"


_IS_CREATE_TABLE = re.compile(
    r'\s*CREATE\s+(?:GLOBAL\s+TEMPORARY\s+)?TABLE\b', re.IGNORECASE
)
# Oracle auto-commits DDL (an implicit COMMIT before and after), so a DDL statement
# is never rolled back and any pending DML committed with it. PostgreSQL keeps DDL
# transactional, so the Mirror commits after a successful DDL to match — a later
# rollback then discards only the DML, not the table (#532).
_IS_DDL = re.compile(
    r'\s*(CREATE|ALTER|DROP|TRUNCATE|RENAME|COMMENT|GRANT|REVOKE)\b', re.IGNORECASE
)


# An Oracle object type — `CREATE [OR REPLACE] TYPE name AS OBJECT (attrs)` — maps
# to a PostgreSQL composite type (`CREATE TYPE name AS (attrs)`), which a typed
# table (`CREATE TABLE t OF name`) can then be built on. It is not a true Oracle
# object type (no methods, no REF), but it carries the attribute structure and the
# type identity a `SELECT REF(p)` describe reports — enough for the REF tests to
# reach their 11g self-skip (#139).
_CREATE_TYPE_OBJECT = re.compile(
    r'(\s*CREATE\s+(?:OR\s+REPLACE\s+)?TYPE\b.*?\bAS)\s+OBJECT\b',
    re.IGNORECASE | re.DOTALL,
)


# Oracle session / user admin statements the provisioning issues, mapped to their
# PostgreSQL equivalent or a no-op (#759). Oracle treats a user as a schema, so a
# CREATE USER becomes a CREATE SCHEMA; ALTER SESSION SET CURRENT_SCHEMA points
# unqualified name resolution at a schema, which is PostgreSQL's search_path; the
# tablespace / grant / password admin has no PostgreSQL analogue and becomes a
# harmless no-op so the statement succeeds.
_ALTER_SESSION_SCHEMA = re.compile(
    r'\s*ALTER\s+SESSION\s+SET\s+CURRENT_SCHEMA\s*=\s*"?(\w+)"?\s*$', re.IGNORECASE
)
_CREATE_USER = re.compile(r'\s*CREATE\s+USER\s+"?(\w+)"?\b', re.IGNORECASE)
_CREATE_INDEX_QUALIFIED = re.compile(
    r'(\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+)"?\w+"?\.("?\w+"?\s+ON\s+.*)$',
    re.IGNORECASE | re.DOTALL,
)
_ADMIN_NOOP = re.compile(
    r'\s*(ALTER\s+USER|GRANT|REVOKE|ALTER\s+SESSION|CREATE\s+ROLE|DROP\s+USER)\b',
    re.IGNORECASE,
)


def _translate_admin(sql: str) -> str:
    m = _ALTER_SESSION_SCHEMA.match(sql)
    if m:
        return f'SET search_path TO {m.group(1).lower()}, public, sys, oracle'
    m = _CREATE_USER.match(sql)
    if m:
        return f'CREATE SCHEMA IF NOT EXISTS {m.group(1).lower()}'
    m = _CREATE_INDEX_QUALIFIED.match(sql)
    if m:
        # Oracle allows a schema-qualified index name (CREATE INDEX s.i ON s.t);
        # PostgreSQL puts the index in the table's schema and rejects the prefix.
        return m.group(1) + m.group(2)
    if _ADMIN_NOOP.match(sql):
        return 'SELECT 1'  # no PostgreSQL equivalent — succeed and do nothing
    return sql


# Oracle's negative / unbounded / caching keywords in CREATE/ALTER SEQUENCE are
# single words (NOMINVALUE, NOMAXVALUE, NOCYCLE, NOCACHE); PostgreSQL spells the
# first three as two words and has no NOCACHE (its minimum cache is 1). ORDER /
# NOORDER is an Oracle RAC ordering hint PostgreSQL has no equal for, so it is
# dropped. MINVALUE/MAXVALUE/CYCLE/CACHE/START WITH/INCREMENT BY are shared.
_IS_SEQUENCE_DDL = re.compile(r'\s*(?:CREATE|ALTER)\s+SEQUENCE\b', re.IGNORECASE)
_SEQUENCE_KEYWORD_REWRITES = [
    (re.compile(r'\bNOMINVALUE\b', re.IGNORECASE), 'NO MINVALUE'),
    (re.compile(r'\bNOMAXVALUE\b', re.IGNORECASE), 'NO MAXVALUE'),
    (re.compile(r'\bNOCYCLE\b', re.IGNORECASE), 'NO CYCLE'),
    (re.compile(r'\bNOCACHE\b', re.IGNORECASE), 'CACHE 1'),
    (re.compile(r'\bNOORDER\b', re.IGNORECASE), ''),
    (re.compile(r'\bORDER\b', re.IGNORECASE), ''),
]


def _translate_ddl(sql: str) -> str:
    """Rewrite an Oracle ``CREATE TABLE`` / object ``CREATE TYPE`` to PostgreSQL:
    map the column/attribute types and drop the clauses PostgreSQL has no equal
    for (#500). Other SQL is returned unchanged."""
    if _IS_SEQUENCE_DDL.match(sql):
        for pattern, replacement in _SEQUENCE_KEYWORD_REWRITES:
            sql = pattern.sub(replacement, sql)
        return re.sub(r'\s{2,}', ' ', sql).rstrip()
    if _CREATE_TYPE_OBJECT.match(sql):
        # `... AS OBJECT (attrs)` → `... AS (attrs)`, then map the attribute types
        # (NUMBER → numeric, VARCHAR2(n) → varchar(n), …) the same way as a table.
        out = _CREATE_TYPE_OBJECT.sub(r'\1', sql, count=1)
        for pattern, replacement in _DDL_TYPE_REWRITES:
            out = pattern.sub(replacement, out)
        return out
    if not _IS_CREATE_TABLE.match(sql):
        return sql
    out = _DDL_GLOBAL_TEMPORARY.sub('TEMPORARY', sql)
    out = _DDL_ORG_INDEX.sub('', out)
    for pattern, replacement in _DDL_TYPE_REWRITES:
        out = pattern.sub(replacement, out)
    return out


# `SELECT REF(<alias>) FROM <table> <alias> [rest]` — the object-REF fetch (#139).
# PostgreSQL has no REF, so the row's identity (its ctid) stands in for the opaque
# locator and the referenced object type is recovered from the typed table's
# catalog entry (pg_class.reloftype). Only this single-REF-column shape is handled
# (all the suite issues); anything else falls through to the ordinary path.
_REF_SELECT = re.compile(
    r'\s*SELECT\s+REF\s*\(\s*(\w+)\s*\)\s+FROM\s+([\w.]+)\s+(\w+)\b(.*)$',
    re.IGNORECASE | re.DOTALL,
)


# Oracle SQL functions / literal idioms → PostgreSQL (#502). Each is a function
# call or a literal keyword the suite uses; the rewrites are anchored on the
# call's `(` or a word boundary, so ordinary identifiers are left alone. Applied
# to every statement (a DEFAULT SYSDATE in DDL is rewritten too).
_IDIOM_REWRITES = [
    # (HEXTORAW, RAWTOHEX, EMPTY_CLOB / EMPTY_BLOB and FROM_TZ are installed as
    # real PostgreSQL functions — see _HELPER_FUNCTIONS_DDL / __init__ — so their
    # call sites resolve directly and need no rewrite here. DECODE, TO_CHAR,
    # TO_DATE, ADD_MONTHS, INSTR, … come from the orafce extension the same way.
    # Only bare pseudo-constants and literal / clause shapes remain below.)
    # NVL is the exception: orafce offers four overloads — nvl(anyelement,
    # anyelement), nvl(bigint, integer), nvl(integer, integer) and nvl(numeric,
    # integer) — and a PostgreSQL literal starts out as `unknown`, so a call with
    # bare literals (NVL(NULL, 'ok'), the most ordinary Oracle there is) matches
    # several candidates and the resolver refuses to pick. COALESCE is native,
    # accepts untyped literals, and for the two arguments NVL takes means exactly
    # the same thing — so sidestep overload resolution rather than adding a fifth
    # candidate to it (#819).
    (re.compile(r'\bNVL\s*\(', re.IGNORECASE), 'COALESCE('),
    # BINARY_DOUBLE/FLOAT special values → IEEE-754 float literals.
    (
        re.compile(r'\bbinary_(?:double|float)_infinity\b', re.IGNORECASE),
        "'Infinity'::float8",
    ),
    (
        re.compile(r'\bbinary_(?:double|float)_nan\b', re.IGNORECASE),
        "'NaN'::float8",
    ),
    # A negative INTERVAL DAY TO SECOND literal. Oracle's leading `-` negates the
    # whole interval — INTERVAL '-1 02:03:04' DAY TO SECOND is -(1d 2h3m4s) — but
    # PostgreSQL applies the sign only to the field it prefixes (the days), leaving
    # the time part positive. Lift the inner `-` out to a unary minus on the whole
    # literal, which negates every field the way Oracle does (#520).
    (
        re.compile(
            r"\bINTERVAL\s+'-([^']*)'\s+"
            r'(DAY(?:\s*\(\d+\))?\s+TO\s+SECOND(?:\s*\(\d+\))?)\b',
            re.IGNORECASE,
        ),
        r"- INTERVAL '\1' \2",
    ),
    # SYSDATE / SYSTIMESTAMP → the session clock (SYSDATE is to-the-second).
    (re.compile(r'\bsystimestamp\b', re.IGNORECASE), 'now()'),
    (re.compile(r'\bsysdate\b', re.IGNORECASE), 'localtimestamp(0)'),
    # The ROWID pseudo-column → PostgreSQL's `ctid` as text ('(0,1)'). This one
    # rewrite serves both a SELECT (returns the str) and a `WHERE ROWID = :bind`
    # (compares the bound text). The word boundary keeps it off ROWIDTOCHAR (no
    # boundary mid-token) and UROWID (a word char precedes ROWID). ctid is a
    # physical, *mutable* address — it changes on UPDATE / VACUUM FULL — so it is a
    # faithful row locator only within an unmodified snapshot, which is all the
    # read-then-bind suite needs; it is not a durable cross-transaction handle like
    # Oracle's ROWID (a real migration uses a surrogate identity key instead). An
    # index-organized table's ROWID is rewritten earlier, per session, from its
    # primary key (PostgresBackend._rewrite_iot_rowid), so this only sees heap
    # tables.
    (re.compile(r'\bROWID\b', re.IGNORECASE), 'ctid::text'),
    # A BINARY_DOUBLE / BINARY_FLOAT numeric literal suffix (1234.5678d, 1.5f) —
    # PostgreSQL has no such suffix, so drop it. A decimal point is required so
    # this never touches an identifier or a plain integer.
    (re.compile(r'\b(\d+\.\d+)[dfDF]\b'), r'\1'),
    # FROM dual CONNECT BY LEVEL <= N — Oracle's row-generator idiom (LEVEL counts
    # 1..N). PostgreSQL has no CONNECT BY, but this common counter form maps to
    # generate_series aliased `level`, so a bare `LEVEL` in the select list resolves
    # to its column. Only this literal-bound counter shape is handled; a general
    # CONNECT BY hierarchical query stays Oracle-only (#531).
    (
        re.compile(r'\bFROM\s+dual\s+CONNECT\s+BY\s+LEVEL\s*<=\s*(\d+)', re.IGNORECASE),
        r'FROM generate_series(1, \1) AS level',
    ),
    # Oracle's MINUS set operator is PostgreSQL's EXCEPT (#759, reflection uses it).
    (re.compile(r'\bMINUS\b', re.IGNORECASE), 'EXCEPT'),
    # Sequence pseudo-columns: Oracle's `seq.nextval` / `seq.currval` are
    # PostgreSQL's `nextval('seq')` / `currval('seq')` function calls. The captured
    # name (optionally schema-qualified) becomes the regclass argument; it is
    # created and referenced lower-case, so an unquoted regclass literal resolves.
    (
        re.compile(r'\b([A-Za-z_][\w$#.]*)\.nextval\b', re.IGNORECASE),
        r"nextval('\1')",
    ),
    (
        re.compile(r'\b([A-Za-z_][\w$#.]*)\.currval\b', re.IGNORECASE),
        r"currval('\1')",
    ),
    # The SQL-standard OFFSET/FETCH the 12c dialect emits: PostgreSQL accepts only a
    # restricted expression before ROWS, so `OFFSET 1 + 2 ROWS` is a syntax error
    # while `OFFSET (1 + 2) ROWS` is fine. Wrap the operand in parentheses (a bare
    # literal or bind is already valid, and the extra parens are harmless there).
    (
        re.compile(r'\bOFFSET\s+(.+?)\s+ROWS\b', re.IGNORECASE),
        r'OFFSET (\1) ROWS',
    ),
    (
        re.compile(r'\bFETCH\s+(FIRST|NEXT)\s+(.+?)\s+ROWS\b', re.IGNORECASE),
        r'FETCH \1 (\2) ROWS',
    ),
    # A CAST to an Oracle string type in DML (CAST(x AS VARCHAR2(50 CHAR))): the
    # column-type rewrites only fire on CREATE TABLE, so translate the string type
    # and drop the CHAR/BYTE length qualifier here too. VARCHAR2 / NVARCHAR2 are
    # never valid identifiers, and the qualifier shape is specific, so this is safe
    # on any statement (a DDL CAST is already varchar by the time it reaches here).
    (re.compile(r'\bNVARCHAR2\b', re.IGNORECASE), 'varchar'),
    (re.compile(r'\bVARCHAR2\b', re.IGNORECASE), 'varchar'),
    (re.compile(r'\(\s*(\d+)\s+(?:CHAR|BYTE)\s*\)', re.IGNORECASE), r'(\1)'),
]


# An Oracle TIMESTAMP literal carrying an explicit offset — TIMESTAMP '<ts> ±HH:MM'
# — is a TIMESTAMP WITH TIME ZONE value. PostgreSQL's `TIMESTAMP '…'` keyword
# parses as *without* time zone and silently drops the offset (wrong instant), so
# such a literal is rewritten to build the offset-preserving `ora_tstz` composite:
# the instant via `TIMESTAMPTZ '…'` (which does honour the offset) and the offset
# itself in seconds. A TIMESTAMP literal with no offset is an ordinary timestamp
# and is left untouched (#519).
_TSTZ_LITERAL = re.compile(r"\bTIMESTAMP\s*'([^']*)'", re.IGNORECASE)
_OFFSET_TAIL = re.compile(r'([+-])(\d{2}):(\d{2})\s*$')


def _tstz_literal_sub(match: 're.Match') -> str:
    content = match.group(1)
    tail = _OFFSET_TAIL.search(content)
    if tail is None:
        return match.group(0)  # a plain TIMESTAMP literal — not WITH TIME ZONE
    sign = -1 if tail.group(1) == '-' else 1
    seconds = sign * (int(tail.group(2)) * 3600 + int(tail.group(3)) * 60)
    return f"ROW(TIMESTAMPTZ '{content}', {seconds})::{_TSTZ_TYPE}"


# CONNECT BY -> WITH RECURSIVE (#760). Oracle's hierarchical query has no
# PostgreSQL keyword; the common single-table shape maps to a recursive CTE.
# Correct-or-passthrough: this only fires on a query containing CONNECT BY, and
# either produces a faithful WITH RECURSIVE for a shape it fully recognises or
# returns the query untouched (which then errors on PostgreSQL exactly as before)
# -- it never yields a wrong-but-successful result. The projection and FROM body
# are reused verbatim; only the clause structure, the single table, and the
# single-equality CONNECT BY are parsed. Unsupported and passed through: multiple
# tables / joins, a compound or non-equality CONNECT BY, SELECT *, ORDER SIBLINGS
# BY, and more than one distinct SYS_CONNECT_BY_PATH / CONNECT_BY_ROOT.
_HAS_CONNECT_BY = re.compile(r'\bCONNECT\s+BY\b', re.IGNORECASE)
_HIER_QUERY = re.compile(
    r'(?is)^\s*SELECT\s+(?P<proj>.+?)\s+FROM\s+(?P<from>.+?)'
    r'(?:\s+WHERE\s+(?P<where>.+?))?'
    r'(?:'
    r'\s+START\s+WITH\s+(?P<sw_a>.+?)\s+CONNECT\s+BY\s+(?P<cb_a>.+?)'
    r'|\s+CONNECT\s+BY\s+(?P<cb_b>.+?)\s+START\s+WITH\s+(?P<sw_b>.+?)'
    r'|\s+CONNECT\s+BY\s+(?P<cb_c>.+?)'
    r')'
    r'(?:\s+ORDER\s+(?P<siblings>SIBLINGS\s+)?BY\s+(?P<order>.+?))?'
    r'\s*;?\s*$'
)
_HIER_SINGLE_TABLE = re.compile(
    r'^\s*(?P<table>[A-Za-z_][\w$#]*)(?:\s+(?P<alias>[A-Za-z_][\w$#]*))?\s*$'
)
_HIER_CB_COND = re.compile(
    r'^\s*(?:NOCYCLE\s+)?(?P<l>.+?)\s*=\s*(?P<r>.+?)\s*$', re.IGNORECASE
)
_HIER_PRIOR = re.compile(r'^\s*PRIOR\s+(?P<col>.+?)\s*$', re.IGNORECASE)
_HIER_SIMPLE_COL = re.compile(r'^[A-Za-z_][\w$#]*(?:\.[A-Za-z_][\w$#]*)?$')
_HIER_STAR = re.compile(r'(^|,)\s*(\w+\s*\.\s*)?\*\s*(,|$)')
_HIER_LEVEL = re.compile(r'\bLEVEL\b', re.IGNORECASE)
_HIER_PATH = re.compile(
    r"\bSYS_CONNECT_BY_PATH\s*\(\s*(?P<col>[\w.]+)\s*,\s*'(?P<sep>[^']*)'\s*\)",
    re.IGNORECASE,
)
_HIER_ROOT = re.compile(r'\bCONNECT_BY_ROOT\s+(?P<col>[\w.]+)', re.IGNORECASE)
_HIER_COMPOUND = re.compile(r'\b(AND|OR)\b', re.IGNORECASE)


def _hier_colname(ref: str) -> str:
    return ref.split('.')[-1].strip()


def _translate_connect_by(sql: str) -> str:
    """Rewrite an Oracle CONNECT BY hierarchical query to a PostgreSQL WITH
    RECURSIVE CTE, or return it unchanged when it is not a shape we translate."""
    if _HAS_CONNECT_BY.search(sql) is None:
        return sql
    match = _HIER_QUERY.match(sql)
    if match is None or match.group('siblings'):
        return sql
    proj = match.group('proj').strip()
    from_clause = match.group('from').strip()
    where = match.group('where')
    start_with = match.group('sw_a') or match.group('sw_b')
    connect_by = (
        match.group('cb_a') or match.group('cb_b') or match.group('cb_c')
    ).strip()
    order = match.group('order')

    table_match = _HIER_SINGLE_TABLE.match(from_clause)
    if table_match is None:  # a join, subquery or comma-list is not a single table
        return sql
    table = table_match.group('table')
    alias = table_match.group('alias') or table

    if _HIER_COMPOUND.search(connect_by):  # a compound CONNECT BY is not modelled
        return sql
    cond = _HIER_CB_COND.match(connect_by)
    if cond is None:
        return sql
    left, right = cond.group('l').strip(), cond.group('r').strip()
    left_prior, right_prior = _HIER_PRIOR.match(left), _HIER_PRIOR.match(right)
    # PRIOR must be on exactly one side.
    if left_prior is not None and right_prior is None:
        prior_side, child_side = left_prior.group('col'), right
    elif right_prior is not None and left_prior is None:
        prior_side, child_side = right_prior.group('col'), left
    else:
        return sql
    if not (_HIER_SIMPLE_COL.match(prior_side) and _HIER_SIMPLE_COL.match(child_side)):
        return sql  # both operands must be plain column references
    parent_col, child_col = _hier_colname(prior_side), _hier_colname(child_side)

    if _HIER_STAR.search(proj):  # SELECT * would leak the CTE's computed columns
        return sql

    scan = ' '.join(part for part in (proj, where, order) if part)
    paths = {(col.lower(), sep) for col, sep in _HIER_PATH.findall(scan)}
    roots = {col.lower() for col in _HIER_ROOT.findall(scan)}
    if len(paths) > 1 or len(roots) > 1:  # v1 handles one distinct path / root
        return sql

    def rewrite(text: str) -> str:
        text = _HIER_LEVEL.sub('__level', text)
        text = _HIER_PATH.sub('__path', text)
        return _HIER_ROOT.sub('__root', text)

    anchor_cols = ['1 AS __level']
    rec_cols = ['__p.__level + 1']
    if paths:
        path_match = _HIER_PATH.search(scan)
        assert path_match is not None
        pcol, sep = _hier_colname(path_match.group('col')), path_match.group('sep')
        anchor_cols.append(f"'{sep}' || {alias}.{pcol} AS __path")
        rec_cols.append(f"__p.__path || '{sep}' || {alias}.{pcol}")
    if roots:
        root_match = _HIER_ROOT.search(scan)
        assert root_match is not None
        anchor_cols.append(
            f'{alias}.{_hier_colname(root_match.group("col"))} AS __root'
        )
        rec_cols.append('__p.__root')

    anchor_where = f' WHERE {start_with.strip()}' if start_with else ''
    join = f'__p.{parent_col} = {alias}.{child_col}'
    outer_where = f' WHERE {rewrite(where).strip()}' if where else ''
    outer_order = f' ORDER BY {rewrite(order).strip()}' if order else ''
    return (
        'WITH RECURSIVE __hcte AS ('
        f'SELECT {alias}.*, '
        + ', '.join(anchor_cols)
        + f' FROM {table} {alias}{anchor_where}'
        ' UNION ALL '
        f'SELECT {alias}.*, '
        + ', '.join(rec_cols)
        + f' FROM {table} {alias} JOIN __hcte __p ON {join}'
        f') SELECT {rewrite(proj)} FROM __hcte {alias}{outer_where}{outer_order}'
    )


def _translate_idioms(sql: str) -> str:
    """Rewrite the Oracle SQL functions / literal idioms the suite uses to their
    PostgreSQL equivalents (#502). Applied to every statement."""
    sql = _translate_connect_by(sql)
    for pattern, replacement in _IDIOM_REWRITES:
        sql = pattern.sub(replacement, sql)
    return _TSTZ_LITERAL.sub(_tstz_literal_sub, sql)


# Column types that are Oracle-only *for the version the Mirror advertises*
# (11.2) — native JSON is 21c+, VECTOR and BOOLEAN are 23ai+. The Mirror pins
# field version 11.2, so a real Oracle at that version rejects such a column with
# ORA-00902 (invalid datatype). PostgreSQL would instead accept JSON / BOOLEAN
# and reject VECTOR as an unknown type, so the suite's version guards (which skip
# on ORA-00902) never fired. Reject them here so those tests skip exactly as they
# do against a real pre-21c/23ai Oracle, rather than failing on a value the
# backend can't faithfully represent (#504). This is the honest ceiling: a
# PostgreSQL backend behind an 11.2 Mirror does not offer these types.
_ORA_INVALID_DATATYPE = 902
_ORACLE_ONLY_DDL_TYPES = re.compile(r'\b(JSON|VECTOR|BOOLEAN)\b', re.IGNORECASE)


# A SQL domain (CREATE DOMAIN) is 23ai — the 11.2 Mirror's server doesn't know the
# command, so a real one raises ORA-00901 ("invalid CREATE command"). PostgreSQL
# *does* have CREATE DOMAIN, so without this it would run (and then fail on the
# Oracle type name), never letting the suite's version guard skip. Reject it with
# ORA-00901 so the SQL-domain test skips exactly as on a pre-23ai server (#512).
_ORA_INVALID_CREATE = 901
_IS_CREATE_DOMAIN = re.compile(r'\s*CREATE\s+DOMAIN\b', re.IGNORECASE)


def _reject_unsupported_ddl_types(sql: str) -> None:
    if _IS_CREATE_DOMAIN.match(sql):
        raise BackendError(
            'invalid CREATE command: SQL domains need a 23ai server',
            ora_code=_ORA_INVALID_CREATE,
        )
    if not _IS_CREATE_TABLE.match(sql):
        return
    match = _ORACLE_ONLY_DDL_TYPES.search(sql)
    if match is not None:
        raise BackendError(
            f'invalid datatype: {match.group(1).upper()} is not available on '
            f'this server version',
            ora_code=_ORA_INVALID_DATATYPE,
        )


# --- PL/SQL: CREATE PROCEDURE / FUNCTION and callproc / callfunc (#503) ---------

# Oracle `CREATE [OR REPLACE] PROCEDURE|FUNCTION name (params) [RETURN t] AS|IS
# <body>`. The signature is close to PostgreSQL's; the body (BEGIN … END) is
# valid PL/pgSQL for the simple assignment / RETURN cases the suite uses.
_ROUTINE_DDL = re.compile(
    r'(?is)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(PROCEDURE|FUNCTION)\s+([\w.]+)\s*'
    r'(?:\((.*)\)\s*)?(?:RETURN\s+([\w ]+?)\s+)?(?:AS|IS)\s+(.*?)\s*;?\s*$'
)
# Oracle parameter direction `IN OUT` → PostgreSQL `INOUT` (do this before the
# type rewrites, which share the DDL type list).
_PARAM_IN_OUT = re.compile(r'\bIN\s+OUT\b', re.IGNORECASE)


def _translate_routine_types(text: str) -> str:
    for pattern, replacement in _DDL_TYPE_REWRITES:
        text = pattern.sub(replacement, text)
    return text


def _translate_routine_ddl(sql: str) -> str:
    """Rewrite an Oracle ``CREATE PROCEDURE`` / ``CREATE FUNCTION`` to a PL/pgSQL
    routine (#503): translate the parameter types + ``IN OUT`` → ``INOUT``, map
    ``RETURN t`` → ``RETURNS t``, and wrap the ``BEGIN … END`` body as a
    ``LANGUAGE plpgsql`` dollar-quoted body. Non-routine SQL is unchanged."""
    match = _ROUTINE_DDL.match(sql)
    if match is None:
        return sql
    kind, name, params, return_type, body = match.groups()
    # Oracle allows a routine with no parameters to omit the list entirely
    # (FUNCTION f RETURN NUMBER AS …); PostgreSQL always needs the parentheses, so
    # an absent list (params is None) becomes an empty one (#530).
    params = _translate_routine_types(_PARAM_IN_OUT.sub('INOUT', params or ''))
    header = f'CREATE OR REPLACE {kind.upper()} {name}({params})'
    if kind.upper() == 'FUNCTION' and return_type:
        header += f' RETURNS {_translate_routine_types(return_type.strip())}'
    # Oracle's CREATE OR REPLACE freely redefines a routine, but PostgreSQL's
    # refuses to change an existing routine's OUT-parameter row type or return type
    # ("cannot change return type of existing function"). The suite reuses one
    # routine name across tests with different signatures, so drop any prior
    # definition first — by name (the suite never overloads, so it is unambiguous),
    # IF EXISTS so the first CREATE is fine (#521).
    drop = f'DROP {kind.upper()} IF EXISTS {name};'
    return f'{drop} {header} LANGUAGE plpgsql AS $$ {body} $$'


# An anonymous PL/SQL block a bind-less client sends — DECLARE … BEGIN … END, or a
# bare BEGIN … END. PostgreSQL can't run one directly, so wrap it as an anonymous
# code block: DO $$ … $$. The declared local types are mapped (VARCHAR2 → varchar,
# NUMBER → numeric, …) and the body is already valid PL/pgSQL for the assignment /
# DML cases the suite uses. A DO block takes no parameters, so this is the bind-less
# path — a block carrying binds goes through the callproc / OUT-bind flow (#517).
# The END must be present, so a bare `BEGIN` (transaction control) is left alone.
_ANON_BLOCK = re.compile(r'(?is)^\s*(DECLARE\b.*?\s)?BEGIN\b(.*)\bEND\s*;?\s*$')


def _translate_plsql_block(sql: str) -> str:
    """Wrap an anonymous DECLARE/BEGIN … END block as a PostgreSQL ``DO $$ … $$``
    block, mapping the declared local types (#533). Non-block SQL is unchanged."""
    match = _ANON_BLOCK.match(sql)
    if match is None:
        return sql
    declare_part, body = match.groups()
    declare = _translate_routine_types(declare_part) if declare_part else ''
    return f'DO $$ {declare}BEGIN {body.strip()} END $$'


# The anonymous block a thin callproc / callfunc sends: BEGIN name(:a, :b); END;
# or BEGIN :r := name(:a, :b); END;
_CALL_BLOCK = re.compile(r'(?is)^\s*BEGIN\s+(.*?)\s*;?\s*END\s*;?\s*$')
_FUNC_CALL = re.compile(r'(?is)^\s*:(\d+)\s*:=\s*([\w.]+)\s*\((.*)\)\s*$')
_PROC_CALL = re.compile(r'(?is)^\s*([\w.]+)\s*\((.*)\)\s*$')
# A scalar OUT-bind assignment inside a block: `:ref := <expr>` (#517).
_OUT_ASSIGN = re.compile(r'(?is)^\s*:(\w+)\s*:=\s*(.+?)\s*$')


def _distinct_bind_refs(text: str) -> list[str]:
    # The distinct bind references in first-appearance order (their positions in
    # the Mirror's bind list), ignoring `:` inside string literals — the same
    # scan _translate_binds uses, so a ref's position stays consistent.
    seen: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "'":
            i += 1
            while i < n and text[i] != "'":
                i += 1
            i += 1
            continue
        match = _BIND_REF.match(text, i)
        if match is not None and (i == 0 or text[i - 1] != ':'):
            name = _bind_name(match)
            if name not in seen:
                seen.append(name)
            i = match.end()
            continue
        i += 1
    return seen


def _parse_out_assignments(body: str) -> list[tuple[str, str]] | None:
    # An OUT-bind-assignment block is one or more `:ref := <expr>` statements
    # (BEGIN :y := 7*6; :2 := NULL; END). Returns (ref, expr) per assignment, or
    # None if any statement isn't such an assignment (so it isn't this shape).
    assignments = []
    for statement in filter(None, (s.strip() for s in body.split(';'))):
        match = _OUT_ASSIGN.match(statement)
        if match is None:
            return None
        assignments.append((match.group(1), match.group(2)))
    return assignments or None


# PostgreSQL type OIDs (pg_type.oid) → Oracle wire type.
_NUMBER_OIDS = frozenset(
    {
        16,
        20,
        21,
        23,
        26,
        1700,
    }  # bool int8 int2 int4 oid numeric
)
# IEEE-754 floats map to Oracle's native binary types, not base-100 NUMBER —
# preserving the exact bits and the "this is a float, not a decimal" nature.
_BINARY_FLOAT_OIDS = {
    700: (TNS_TYPE_BFLOAT, 4),  # float4 (real)
    701: (TNS_TYPE_BDOUBLE, 8),  # float8 (double precision)
}
_TEXT_OIDS = frozenset({18, 19, 25, 1042, 1043})  # char name text bpchar varchar
_RAW_OIDS = frozenset({17})  # bytea
# The base type oids the Oracle-typed domains report on the wire — ora_clob /
# ora_blob over text / bytea (#534), ora_intervalym over interval (#504). Only a
# column of one of these can be such a domain, so the catalog lookup that
# distinguishes them is skipped for anything else.
_DOMAIN_BASE_OIDS = frozenset({25, 17, _INTERVAL_OID})
# Each PostgreSQL temporal OID maps to the Oracle type of matching precision:
# a bare date → DATE (7 bytes), timestamp → TIMESTAMP (11), timestamptz → 13.
_TEMPORAL_OIDS = {
    1082: (TNS_TYPE_DATE, 7),  # date
    1114: (TNS_TYPE_TIMESTAMP, 11),  # timestamp (without time zone)
    1184: (TNS_TYPE_TIMESTAMPTZ, 13),  # timestamptz
}
# PostgreSQL `interval` (oid 1186) → Oracle INTERVAL DAY TO SECOND by default;
# psycopg returns it as a timedelta (an OraInterval, months == 0), which the Mirror
# encodes for an INTERVALDS column. A YEAR TO MONTH interval is distinguished by its
# ora_intervalym domain (traced through the catalog) and handled separately (#504).
_INTERVAL_OIDS = frozenset({_INTERVAL_OID})

_ORA_INVALID_SQL = 900

# Map a PostgreSQL error (by SQLSTATE) to the Oracle error number a client
# expects, so error-conditional flows behave (#500). The load-bearing one is
# `undefined_table` → ORA-00942: the suite's setUp/tearDown drops tables
# best-effort and only swallows ORA-00942 — reporting ORA-00900 instead re-raised
# and failed every test in setUp. Anything unmapped falls back to ORA-00900.
_SQLSTATE_TO_ORA = {
    '42P01': 942,  # undefined_table         -> table or view does not exist
    '42704': 942,  # undefined_object (type) -> (DROP TYPE cleanup)
    '42P07': 955,  # duplicate_table         -> name is already used
    '42703': 904,  # undefined_column        -> invalid identifier
    '42883': 904,  # undefined_function
    '23505': 1,  # unique_violation        -> unique constraint violated
    '23502': 1400,  # not_null_violation      -> cannot insert NULL
    '23503': 2291,  # foreign_key_violation   -> integrity constraint: parent
    #                key not found (the insert/update direction; the delete
    #                direction is ORA-02292, not distinguished by SQLSTATE alone)
    '23514': 2290,  # check_violation         -> check constraint violated
    '22P02': 1722,  # invalid_text_representation -> invalid number (TO_NUMBER)
}


# The canonical Oracle message text for a mapped ORA code, used in place of
# PostgreSQL's own wording so a client that matches on the Oracle phrasing behaves
# — ORA-00942 reads "table or view does not exist", not "relation … does not
# exist" (#529). A code with no entry keeps PostgreSQL's message (still prefixed
# with its ORA-NNNNN by the Mirror), which is right where the English text varies
# by Oracle version anyway (e.g. ORA-01722).
_ORA_MESSAGE = {
    942: 'table or view does not exist',
}


def _ora_code_for(exc) -> int:
    sqlstate = getattr(exc, 'sqlstate', None)
    if not isinstance(sqlstate, str):
        return _ORA_INVALID_SQL
    return _SQLSTATE_TO_ORA.get(sqlstate, _ORA_INVALID_SQL)


def _backend_error(
    exc, *, original: str | None = None, translated: str | None = None
) -> BackendError:
    # A PostgreSQL failure as a clean ORA error: the mapped code, and the Oracle
    # canonical text for it when there is one, else PostgreSQL's own message (#529).
    code = _ora_code_for(exc)
    return BackendError(
        _ORA_MESSAGE.get(code, str(exc).strip()),
        ora_code=code,
        error_offset=_error_offset(exc, original, translated),
    )


def _error_offset(exc, original: str | None, translated: str | None) -> int | None:
    # PostgreSQL reports where a parse error sits as a 1-based character position
    # into the statement it received — the dialect-rewritten one. Oracle's offset
    # (DatabaseError.offset, the sqlplus caret) is 0-based into the statement the
    # client sent. The two agree only where the rewrite left everything before the
    # error untouched, so relay the position when the two texts share that prefix
    # and report nothing (None) otherwise, rather than a misplaced caret.
    position = getattr(getattr(exc, 'diag', None), 'statement_position', None)
    if position is None or original is None or translated is None:
        return None
    try:
        offset = int(position) - 1
    except (TypeError, ValueError):
        return None
    if offset < 0 or offset > len(translated):
        return None
    return offset if translated[:offset] == original[:offset] else None


# PostgreSQL's built-in `refcursor` type OID (stable across versions) — a CALL's
# OUT refcursor comes back as the portal name at this OID, which the backend then
# drains into a CursorResult for the REF CURSOR OUT bind (#518).
_REFCURSOR_OID = 1790


def _reconstruct_tstz(value):
    # A psycopg `ora_tstz(utc, off)` composite → an aware datetime re-tagged with
    # the entered offset, so TIMESTAMP WITH TIME ZONE round-trips its offset the way
    # Oracle does rather than coming back normalised to UTC (#519).
    if value is None:
        return None
    return value.utc.astimezone(
        datetime.timezone(datetime.timedelta(seconds=value.off))
    )


def _decode_row(cursor, row, tstz_oid: int | None) -> list | None:
    # Re-tag any ora_tstz composite cells in a fetched row to aware datetimes, so a
    # WITH TIME ZONE value returned from a routine keeps its offset (#519).
    if row is None:
        return None
    return [
        _reconstruct_tstz(value)
        if (tstz_oid is not None and desc.type_code == tstz_oid)
        else value
        for value, desc in zip(row, cursor.description or ())
    ]


def _lob_column_meta(name: str, tns_type: int) -> ColumnMeta:
    # A CLOB / BLOB result column (an ora_clob / ora_blob domain traced back through
    # the catalog). LOBs are unsized on the wire — data_length is nominal, max_size
    # 0 — and the Mirror streams the cell content as a locator (#534).
    return ColumnMeta(
        name=name.upper().encode('utf-8'),
        data_type=tns_type,
        data_length=4000,
        max_size=0,
    )


def _intervalym_column_meta(name: str) -> ColumnMeta:
    # An INTERVAL YEAR TO MONTH result column (an ora_intervalym domain traced back
    # through the catalog). The wire form is 5 bytes — 4-byte years + 1-byte months
    # (see the Mirror's encode_interval_ym) — and its cells are IntervalYM (#504).
    return ColumnMeta(
        name=name.upper().encode('utf-8'),
        data_type=TNS_TYPE_INTERVALYM,
        data_length=5,
        max_size=5,
    )


def _column_meta(desc, values: list, tstz_oid: int | None = None) -> ColumnMeta:
    # `desc` is a psycopg Column (name / type_code / precision / scale / ...).
    name, oid = desc.name, desc.type_code
    ident = name.upper().encode('utf-8')
    if tstz_oid is not None and oid == tstz_oid:
        # The ora_tstz composite backing TIMESTAMP WITH TIME ZONE — the cells are
        # reconstructed to aware datetimes by the caller (#519).
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_TIMESTAMPTZ, data_length=13, max_size=13
        )
    if oid in _NUMBER_OIDS:
        # A numeric(p, s) column reports its precision/scale; int / float / bare
        # numeric report None, which becomes Oracle's unconstrained NUMBER (0/0).
        return ColumnMeta(
            name=ident,
            data_type=TNS_TYPE_NUMBER,
            data_length=22,
            max_size=22,
            precision=desc.precision or 0,
            scale=desc.scale or 0,
        )
    if oid in _BINARY_FLOAT_OIDS:
        data_type, width = _BINARY_FLOAT_OIDS[oid]
        return ColumnMeta(
            name=ident, data_type=data_type, data_length=width, max_size=width
        )
    if oid in _TEMPORAL_OIDS:
        data_type, width = _TEMPORAL_OIDS[oid]
        return ColumnMeta(
            name=ident, data_type=data_type, data_length=width, max_size=width
        )
    if oid in _INTERVAL_OIDS:
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_INTERVALDS, data_length=11, max_size=11
        )
    if oid in _RAW_OIDS:
        width = max(
            (len(v) for v in values if isinstance(v, (bytes, bytearray, memoryview))),
            default=1,
        )
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_RAW, data_length=width, max_size=width
        )
    if oid in _TEXT_OIDS:
        width = max((len(str(v)) for v in values if v is not None), default=1)
        return ColumnMeta(
            name=ident, data_type=TNS_TYPE_VARCHAR, data_length=width, max_size=width
        )
    raise UnsupportedFeature(
        f'column {name!r}: PostgreSQL type oid {oid} is not supported yet'
    )


class PostgresBackend:
    """A :class:`~seerdb.server.Backend` over a psycopg connection.

    One instance per Mirror session. ``conninfo`` is a libpq connection string,
    e.g. ``host=127.0.0.1 port=5432 user=pyo password=... dbname=mirror``.

    The connection is transactional (``autocommit`` off), so the Mirror's
    commit / rollback are real: work persists only on commit and is discarded on
    rollback. Each statement runs inside an implicit ``SAVEPOINT`` so a failed
    statement rolls back only itself — the transaction (and any earlier
    uncommitted work) survives, matching Oracle's statement-level error model
    rather than PostgreSQL's abort-the-whole-transaction default.
    """

    capabilities = frozenset({Capability.TRANSACTIONS})
    # This demo speaks the 11.2 WIRE protocol (field version): it cannot back the
    # 12c+/23ai wire formats a higher field version would invite, so it pins the
    # floor the whole conformance suite is baselined at. But it REPORTS release
    # 12.1 (server_identity, read only from the login banner, never the wire), so
    # the SQLAlchemy dialect uses native OFFSET/FETCH pagination and identity
    # columns -- both of which PostgreSQL runs directly -- instead of Oracle's
    # nested-ROWNUM pagination, which has no faithful PostgreSQL rewrite (#33).
    field_version = FIELD_VERSION_11_2
    server_identity = IDENTITY_12_1

    def __init__(
        self, conninfo: str = '', *, credentials: Credentials | None = None
    ) -> None:
        self._conn = psycopg.connect(conninfo)
        # Disable psycopg's automatic server-side prepared statements. Every
        # statement runs inside a SAVEPOINT, and a ROLLBACK TO SAVEPOINT deallocates
        # any prepared statement created after that savepoint — which desyncs
        # psycopg's prepared-statement cache from the server ("prepared statement
        # _pgN_M does not exist"). A proxy backend running varied SQL gains little
        # from the cache anyway; the pipeline below is the real round-trip win.
        self._conn.prepare_threshold = None
        # Shared, not copied, when a dict is given: the example hands one map to
        # every backend it creates, and ALTER USER ... IDENTIFIED BY rewrites an
        # entry in place so the new password reaches the next login. A read-only
        # mapping is copied into a dict the rewrite can touch.
        self._credentials: dict[str, str] = (
            credentials if isinstance(credentials, dict) else dict(credentials or {})
        )
        # Index-organized tables this session created, with their primary-key
        # columns, for the logical-rowid rendering.
        self._iot_pk: dict[str, list[str]] = {}
        # Pipeline mode ships a statement's SAVEPOINT / statement / RELEASE in one
        # network round-trip instead of three (a 3x per-statement latency cut
        # against a remote database). It needs libpq >= 14; older builds fall back
        # to the sequential path.
        try:
            self._use_pipeline = psycopg.pq.version() >= 140000
        except Exception:
            self._use_pipeline = False
        # Lean on the `orafce` extension for Oracle-compatible SQL functions —
        # nvl, decode, to_char / to_date, add_months, instr, and much more —
        # rather than hand-rolling each rewrite. It installs those into the
        # `oracle` schema, so put it on the search_path; then only the idioms
        # orafce does NOT cover are translated in _translate_idioms. orafce is a
        # requirement of this backend (see the module docstring). Best-effort so a
        # PostgreSQL without it still starts — the uncovered idioms just fail as
        # before.
        try:
            self._conn.execute('CREATE EXTENSION IF NOT EXISTS orafce')
        except psycopg.Error:
            self._conn.rollback()
        # The Oracle data dictionary (#759) lives in a dedicated `sys` schema —
        # like Oracle's SYS — so its views are never reflected as user objects.
        try:
            self._conn.execute('CREATE SCHEMA IF NOT EXISTS sys')
        except psycopg.Error:
            self._conn.rollback()
        # `sys` ahead of `oracle`: orafce ships its own `user_tables` and
        # `user_tab_columns` in the `oracle` schema, and they select from
        # information_schema with no owner filter at all -- every base table in
        # the database, PostgreSQL's own catalogs included, reported as though
        # the connected user owned them. Those are the only two names the two
        # schemas share, so this ordering changes nothing else: user objects
        # still resolve first through the schema ahead of both, and the rest of
        # orafce is still reached through `oracle` (#818).
        self._conn.execute('SET search_path TO public, sys, oracle')
        # Create + register the composite that backs TIMESTAMP WITH TIME ZONE, so
        # its columns come back as a typed tuple the read path can re-tag with the
        # entered offset (#519). Best-effort: a backend that can't create the type
        # just leaves WITH TIME ZONE unsupported, like the orafce idioms above.
        self._tstz_oid: int | None = None
        try:
            self._conn.execute(_TSTZ_TYPE_DDL)
            info = CompositeInfo.fetch(self._conn, _TSTZ_TYPE)
            if info is not None:
                register_composite(info, self._conn)
                self._tstz_oid = info.oid
        except psycopg.Error:
            self._conn.rollback()
        # Create the typed domains and map each domain's oid to the Oracle wire type
        # it stands for, so a result column tracing back to one is encoded as that
        # Oracle type — ora_clob / ora_blob as a LOB (#534), ora_intervalym as
        # INTERVAL YEAR TO MONTH (#504). Best-effort, like the composite above; a
        # (relid, attnum) → type cache avoids re-querying the catalog for a column
        # already seen. The ora_intervalym oid is kept on its own for the OUT-bind
        # path, which has no result column to trace and matches on the arg type.
        self._intervalym_oid: int | None = None
        self._domain_type_by_oid: dict[int, int] = {}
        self._domain_col_cache: dict[tuple[int, int], int | None] = {}
        try:
            self._conn.execute(_LOB_TYPE_DDL)
            self._conn.execute(_INTERVALYM_TYPE_DDL)
            for name, tns_type in (
                (_CLOB_TYPE, TNS_TYPE_CLOB),
                (_BLOB_TYPE, TNS_TYPE_BLOB),
                (_INTERVALYM_TYPE, TNS_TYPE_INTERVALYM),
            ):
                row = self._conn.execute(
                    'SELECT oid FROM pg_type WHERE typname = %s', (name,)
                ).fetchone()
                if row is not None:
                    self._domain_type_by_oid[row[0]] = tns_type
                    if name == _INTERVALYM_TYPE:
                        self._intervalym_oid = row[0]
            # Preserve an interval's months through psycopg (its default loader
            # flattens them to a timedelta), so a YEAR TO MONTH value survives (#504).
            self._conn.adapters.register_loader('interval', _IntervalMonthsTextLoader)
            self._conn.adapters.register_loader('interval', _IntervalMonthsBinaryLoader)
        except psycopg.Error:
            self._conn.rollback()
        # Install the Oracle scalar helper functions (hextoraw, rawtohex,
        # empty_clob / empty_blob, from_tz), so those call sites need no rewrite
        # (#513). Best-effort like the type / domain setup above; empty_clob /
        # empty_blob return the LOB domains just created, so this runs after them.
        try:
            self._conn.execute(_HELPER_FUNCTIONS_DDL)
        except psycopg.Error:
            self._conn.rollback()
        # UTL_RAW as PostgreSQL functions (orafce ships no utl_raw) (#765).
        try:
            self._conn.execute(_UTL_RAW_DDL)
        except psycopg.Error:
            self._conn.rollback()
        # DBMS_UTILITY entry points orafce does not ship (#764).
        try:
            self._conn.execute(_DBMS_UTILITY_DDL)
        except psycopg.Error:
            self._conn.rollback()
        # Oracle data-dictionary emulation (#759): SYS_CONTEXT + catalog views.
        try:
            self._conn.execute(_ORACLE_DICTIONARY_DDL)
        except psycopg.Error:
            self._conn.rollback()
        self._conn.commit()

    def authenticate(self, username: str) -> str | None:
        # The login store the Mirror authenticates clients against — separate
        # from the libpq `conninfo` the backend itself connects to PostgreSQL
        # with. A production backend might instead consult a PG table here.
        return credential_lookup(self._credentials, username)

    def execute(self, sql: str, binds: Sequence = ()) -> Result:
        # A PL/SQL block from callproc / callfunc arrives with BindVar binds (the
        # Mirror's OUT-bind flow); run it via CALL / SELECT and return the OUT
        # values (#503). An ordinary statement's BindVar is a typed NULL, which
        # _translate_binds casts (#699).
        if binds and is_plsql(sql):
            return self._execute_plsql(sql, binds)
        # A `SELECT REF(alias)` object-REF fetch: PostgreSQL has no REF, so stand in
        # the row's ctid as the locator and report the referenced object type from
        # the typed table's catalog entry, so the client decodes a REF whose
        # type_name matches (#139). The 12c+ REF *bind* the test does next is skipped
        # by its own version guard on the 11g Mirror.
        ref_select = _REF_SELECT.match(sql)
        if ref_select and ref_select.group(1).lower() == ref_select.group(3).lower():
            return self._execute_ref_select(ref_select)
        # Reject the column types that are Oracle-only for the version the Mirror
        # advertises (JSON/VECTOR/BOOLEAN), so the suite's version guards skip
        # rather than the backend mis-representing them (#504).
        _reject_unsupported_ddl_types(sql)
        # Register / forget an index-organized table, and render ROWID on one from
        # its primary key before the generic rewrite turns ROWID into ctid.
        iot = _iot_primary_key(sql)
        if iot is not None:
            self._iot_pk[iot[0]] = iot[1]
        dropped = _DROP_TABLE_NAME.match(sql)
        if dropped is not None:
            self._iot_pk.pop(_bare_table(dropped.group(1)), None)
        sql = self._rewrite_iot_rowid(sql)
        # Oracle auto-commits DDL — decide from the original statement, before the
        # dialect rewrite reshapes it (#532).
        is_ddl = _IS_DDL.match(sql) is not None
        original = sql
        # Translate Oracle SQL to PostgreSQL's dialect (#500/#502/#503) — DDL
        # column types, CREATE PROCEDURE/FUNCTION → PL/pgSQL, then the function /
        # literal idioms. This is where dialect knowledge belongs, not in the
        # generic compat shim.
        sql = _translate_idioms(
            _translate_plsql_block(
                _translate_routine_ddl(_translate_ddl(_translate_admin(sql)))
            )
        )
        params: dict | None = None
        if binds:
            sql, params = _translate_binds(sql, binds)
        # Each statement runs inside a SAVEPOINT so a failure rolls back just it
        # (clearing PostgreSQL's aborted-transaction state) and leaves the rest of
        # the transaction intact — Oracle's statement-level error model. The
        # pipelined path ships the SAVEPOINT, the statement and the RELEASE in one
        # network round-trip instead of three; the sequential path is the fallback
        # when libpq is too old for pipeline mode. DDL stays sequential: pipeline
        # mode forces the extended query protocol, which rejects the multi-command
        # `DROP …; CREATE …` a routine DDL rewrites to (#526) — the simple protocol
        # the sequential path uses accepts it. DDL is infrequent and auto-commits,
        # so the hot SELECT/DML path (single-command) is where the round-trips count.
        if self._use_pipeline and not is_ddl:
            result = self._execute_pipelined(sql, params, original)
        else:
            result = self._execute_sequential(sql, params, original)
        # DDL auto-commits (Oracle semantics): persist it — and any pending DML —
        # so a later rollback discards only DML, not the table (#532).
        if is_ddl:
            self._conn.commit()
        return result

    def execute_returning(self, sql: str, rows: Sequence[Sequence]) -> Result:
        # DML ... RETURNING col INTO :b (#689). PostgreSQL has the feature but
        # spells it without the INTO part, handing the columns back as rows
        # rather than assigning them to binds, so the clause is trimmed to the
        # form it knows and the rows are read.
        #
        # Each iteration goes through `execute` so the whole dialect rewrite,
        # bind translation and per-statement savepoint apply exactly as they do
        # to any other statement. The binds the clause fills carry no value and
        # are dropped: their placeholders are gone from the trimmed text.
        statement = strip_returning_into(sql)
        returned: list[list[tuple]] = []
        affected = 0
        for row in rows:
            values = [v for v in row if not isinstance(v, BindVar)]
            result = self.execute(statement, values)
            iteration = [tuple(r) for r in result.rows]
            returned.append(iteration)
            # A RETURNING statement gives back one row per row it changed, so
            # the count is the rows read rather than a separate report.
            affected += len(iteration)
        return Result(rowcount=affected, returned_rows=returned)

    def _rewrite_iot_rowid(self, sql: str) -> str:
        # ROWID on a registered index-organized table → its logical-rowid
        # expression. The statement's table is its first FROM / UPDATE / INTO
        # target; anything else is left for the generic ctid rewrite.
        if not self._iot_pk or _ROWID_WORD.search(sql) is None:
            return sql
        table = _STATEMENT_TABLE.search(sql)
        if table is None:
            return sql
        pk = self._iot_pk.get(_bare_table(table.group(1)))
        if pk is None:
            return sql
        return _ROWID_WORD.sub(_urowid_expression(pk), sql)

    def _build_result(self, cursor) -> Result:
        # Turn an executed statement's cursor into a Result: a row count for a
        # no-row statement, else the fetched rows plus a ColumnMeta per column.
        if cursor.description is None:
            return Result(rowcount=max(cursor.rowcount, 0))
        rows = [list(r) for r in cursor.fetchall()]
        # Re-tag any ora_tstz composite cells to aware datetimes carrying the
        # entered offset before they reach the wire encoder (#519).
        for i, desc in enumerate(cursor.description):
            if self._tstz_oid is not None and desc.type_code == self._tstz_oid:
                for row in rows:
                    row[i] = _reconstruct_tstz(row[i])
        columns = []
        for i, desc in enumerate(cursor.description):
            # A column tracing back to a typed domain is that Oracle type — an
            # ora_clob / ora_blob LOB (so an empty value stays '' / b'' rather than
            # collapsing to NULL, #534), or an ora_intervalym INTERVAL YEAR TO MONTH
            # (so its months survive, #504). Only a text / bytea / interval column
            # can be one, so cheaper types skip the catalog lookup.
            domain = (
                self._domain_type(cursor.pgresult, i)
                if desc.type_code in _DOMAIN_BASE_OIDS
                else None
            )
            if domain in (TNS_TYPE_CLOB, TNS_TYPE_BLOB):
                columns.append(_lob_column_meta(desc.name, domain))
            elif domain == TNS_TYPE_INTERVALYM:
                for row in rows:
                    row[i] = _to_interval_ym(row[i])
                columns.append(_intervalym_column_meta(desc.name))
            else:
                columns.append(_column_meta(desc, [r[i] for r in rows], self._tstz_oid))
        return Result(columns=columns, rows=[tuple(r) for r in rows])

    def _execute_sequential(
        self, sql: str, params: dict | None, original: str | None = None
    ) -> Result:
        # SAVEPOINT + statement + RELEASE as three round-trips; the fallback path.
        cursor = self._conn.cursor()
        cursor.execute('SAVEPOINT _mirror_stmt')
        try:
            cursor.execute(sql, params)
            result = self._build_result(cursor)
        except psycopg.Error as exc:
            self._conn.execute('ROLLBACK TO SAVEPOINT _mirror_stmt')
            self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
            # A PostgreSQL failure surfaces as a clean ORA error — never a desync.
            # Map the SQLSTATE to the matching Oracle code so error-conditional
            # client flows (e.g. a best-effort DROP that swallows ORA-00942) work.
            raise _backend_error(exc, original=original, translated=sql) from exc
        except Exception:
            # An our-side rejection (e.g. UnsupportedFeature on an unmapped column
            # type) after the statement ran — undo it and re-raise for the session
            # to map to an ORA error.
            self._conn.execute('ROLLBACK TO SAVEPOINT _mirror_stmt')
            self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
            raise
        self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
        return result

    def _execute_pipelined(
        self, sql: str, params: dict | None, original: str | None = None
    ) -> Result:
        # SAVEPOINT + statement + RELEASE shipped in ONE round-trip via a psycopg
        # pipeline. Each command uses its own cursor so the statement's cursor keeps
        # its own result (rowcount / description / rows / pgresult) after the sync —
        # a shared cursor would only retain the last command's (RELEASE) result.
        savepoint = self._conn.cursor()
        statement = self._conn.cursor()
        release = self._conn.cursor()
        try:
            with self._conn.pipeline():
                savepoint.execute('SAVEPOINT _mirror_stmt')
                statement.execute(sql, params)
                release.execute('RELEASE SAVEPOINT _mirror_stmt')
        except psycopg.Error as exc:
            # The statement failed inside the pipeline; the RELEASE that followed it
            # was discarded, so the savepoint still stands — roll the statement back
            # to it (preserving the rest of the transaction) and surface a clean ORA
            # error, never a desync.
            self._conn.execute('ROLLBACK TO SAVEPOINT _mirror_stmt')
            self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
            raise _backend_error(exc, original=original, translated=sql) from exc
        # The pipeline succeeded, so the savepoint is already released and the
        # statement had its effect. Building the result can only raise on an
        # unencodable SELECT column — no side effect to undo — so let it propagate
        # for the session to map to an ORA error; the connection stays usable.
        return self._build_result(statement)

    def execute_many(self, sql: str, rows: Sequence[Sequence]) -> int:
        # Array DML (executemany) in one round-trip: translate the statement once
        # and send every bind row through psycopg's executemany (which pipelines),
        # instead of a round-trip per row — the difference is ~7 s vs a few ms for
        # 500 rows against a remote database. Returns the total affected-row count.
        # The Mirror calls this only for the non-batcherrors path, where a per-row
        # failure aborts the whole batch — exactly Oracle's non-batcherrors DML.
        rows = list(rows)
        if not rows:
            return 0
        translated = _translate_idioms(
            _translate_plsql_block(_translate_routine_ddl(_translate_ddl(sql)))
        )
        bound_sql, _ = _translate_binds(translated, rows[0])
        params = [_translate_binds(translated, row)[1] for row in rows]
        cursor = self._conn.cursor()
        cursor.execute('SAVEPOINT _mirror_stmt')
        try:
            cursor.executemany(bound_sql, params)
            affected = cursor.rowcount
        except psycopg.Error as exc:
            self._conn.execute('ROLLBACK TO SAVEPOINT _mirror_stmt')
            self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
            raise _backend_error(exc) from exc
        self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
        return max(affected, 0)

    def _object_type_name(self, table: str) -> str | None:
        # The Oracle object-type name of a typed table (CREATE TABLE t OF type), or
        # None if `table` is not one. pg_class.reloftype names the row type; Oracle
        # folds identifiers to upper case, so the name is compared uppercased.
        relname = table.split('.')[-1].strip('"').lower()
        row = self._conn.execute(
            'SELECT reloftype::regtype::text FROM pg_class '
            'WHERE relname = %s AND reloftype <> 0',
            (relname,),
        ).fetchone()
        if row is None or row[0] is None:
            return None
        return row[0].split('.')[-1].strip('"').upper()

    def _execute_ref_select(self, match: 're.Match[str]') -> Result:
        # Serve `SELECT REF(alias) FROM table alias [rest]` (#139). The referenced
        # object type comes from the typed table's catalog entry; the REF locator is
        # stood in by the row's ctid (opaque, and never dereferenced — the DEREF /
        # bind the test does next is 12c+ and skips on the 11g Mirror). The result is
        # one REF column of DbRef values carrying the type identity the describe
        # reports, so the client reads ref.type_name correctly.
        ref_alias, table, table_alias, rest = match.groups()
        type_name = self._object_type_name(table)
        if type_name is None:
            raise UnsupportedFeature(
                f'REF({ref_alias}): {table} is not an object table'
            )
        query = f'SELECT {table_alias}.ctid::text FROM {table} {table_alias}{rest}'
        cursor = self._conn.cursor()
        cursor.execute('SAVEPOINT _mirror_stmt')
        try:
            cursor.execute(query)
            ctids = [r[0] for r in cursor.fetchall()]
        except psycopg.Error as exc:
            self._conn.execute('ROLLBACK TO SAVEPOINT _mirror_stmt')
            self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
            raise _backend_error(exc) from exc
        self._conn.execute('RELEASE SAVEPOINT _mirror_stmt')
        schema = 'PUBLIC'
        oid = b'\x00' * 16  # Oracle carries a 16-byte type OID; unused pre-12c bind
        column = ColumnMeta(
            name=f'REF({ref_alias})'.upper().encode('utf-8'),
            data_type=TNS_TYPE_REF,
            data_length=4000,
            max_size=0,
            type_name=type_name.encode('ascii'),
            type_schema=schema.encode('ascii'),
            type_oid=oid,
        )
        rows = [
            (
                DbRef(
                    ctid.encode('utf-8'),
                    type_name=type_name,
                    type_schema=schema,
                    type_oid=oid,
                ),
            )
            for ctid in ctids
        ]
        return Result(columns=[column], rows=rows)

    def _domain_type(self, pgresult, index: int) -> int | None:
        # The Oracle wire type if result column `index` comes from one of the typed
        # domains — TNS_TYPE_CLOB / TNS_TYPE_BLOB (ora_clob / ora_blob, #534) or
        # TNS_TYPE_INTERVALYM (ora_intervalym, #504) — else None. A domain value
        # reports its base type on the wire (text / bytea / interval), so trace the
        # column back to its source table + attribute (libpq ftable / ftablecol) and
        # read the real declared type from pg_attribute — cached per (relid, attnum).
        # A computed column (ftable 0) isn't a domain column.
        if not self._domain_type_by_oid:
            return None
        relid = pgresult.ftable(index)
        if not relid:
            return None
        attnum = pgresult.ftablecol(index)
        key = (relid, attnum)
        if key not in self._domain_col_cache:
            row = self._conn.execute(
                'SELECT atttypid FROM pg_attribute WHERE attrelid = %s AND attnum = %s',
                (relid, attnum),
            ).fetchone()
            atttypid = row[0] if row else None
            self._domain_col_cache[key] = (
                self._domain_type_by_oid.get(atttypid) if atttypid is not None else None
            )
        return self._domain_col_cache[key]

    def _execute_plsql(self, sql: str, binds: Sequence) -> Result:
        # A callproc / callfunc block. `binds` is one BindVar per positional bind
        # (:1 → index 0), value None for a pure OUT. Run the underlying routine and
        # return every bind's value in order (input for IN, the routine's result
        # for OUT / IN OUT / the function return) — the Mirror marks them all OUT
        # and the client keeps only the positions it bound as a Var (#483/#503).
        values = [b.value for b in binds]
        inner = _CALL_BLOCK.match(sql)
        statement = inner.group(1) if inner else ''
        try:
            func = _FUNC_CALL.match(statement)
            if func is not None:
                return self._call_function(func, values)
            proc = _PROC_CALL.match(statement)
            if proc is not None:
                return self._call_procedure(proc, values)
            assignments = _parse_out_assignments(statement)
            if assignments is not None:
                return self._eval_out_assignments(statement, assignments, binds, values)
            if inner is not None:
                # A block wrapping DML (BEGIN INSERT/UPDATE/DELETE …(:x); END) —
                # unwrap and run the inner statement with the binds.
                return self._run_block_statement(statement, values)
            # Not a shape we model — run it as-is (best effort) so a
            # side-effecting block still executes.
            self._conn.cursor().execute(_translate_idioms(sql))
            return Result(out_binds=values)
        except psycopg.Error as exc:
            self._conn.rollback()
            raise _backend_error(exc) from exc

    def _call_function(self, match: 're.Match', values: list) -> Result:
        # BEGIN :r := name(:a, :b); END;  →  SELECT name(a, b); the result is the
        # function's return value, written back into the :r bind position.
        ret_ref, name, args = match.groups()
        arg_refs = [int(r) for r in re.findall(r':(\d+)', args)]
        arg_values = [values[r - 1] for r in arg_refs]
        placeholders = ', '.join(['%s'] * len(arg_values))
        cursor = self._conn.cursor()
        cursor.execute(f'SELECT {name}({placeholders})', tuple(arg_values) or None)
        row = _decode_row(cursor, cursor.fetchone(), self._tstz_oid)
        out = list(values)
        out[int(ret_ref) - 1] = row[0] if row else None
        return Result(out_binds=out)

    def _call_procedure(self, match: 're.Match', values: list) -> Result:
        # BEGIN name(:a, :b); END;  →  CALL name(a, b); the OUT / IN OUT arguments
        # come back as a result row, in parameter order, which we place onto their
        # bind positions.
        name, args = match.groups()
        arg_refs = [int(r) for r in re.findall(r':(\d+)', args)]
        modes, argtypes = self._proc_signature(name)
        # A pure-OUT argument carries no input — pass an untyped NULL, not the
        # client's placeholder Var value: a REF CURSOR Var marshals to bytea, which
        # makes CALL's overload resolution miss the refcursor parameter (#518). IN
        # and IN OUT arguments pass their value.
        arg_values = [
            None if modes and modes[position] == 'o' else values[ref - 1]
            for position, ref in enumerate(arg_refs)
        ]
        placeholders = ', '.join(['%s'] * len(arg_values))
        cursor = self._conn.cursor()
        cursor.execute(f'CALL {name}({placeholders})', tuple(arg_values) or None)
        returned = self._decode_out_row(cursor, cursor.fetchone())
        out = list(values)
        result_i = 0
        for position, ref in enumerate(arg_refs):
            is_out = modes[position] in ('o', 'b') if modes else False
            if is_out and result_i < len(returned):
                value = returned[result_i]
                # An OUT INTERVAL YEAR TO MONTH arrives as an OraInterval (base
                # interval on the wire) — turn it into an IntervalYM by matching the
                # argument's declared ora_intervalym type, since a CALL result has no
                # table column to trace (#504).
                if (
                    self._intervalym_oid is not None
                    and position < len(argtypes)
                    and argtypes[position] == self._intervalym_oid
                ):
                    value = _to_interval_ym(value)
                out[ref - 1] = value
                result_i += 1
        return Result(out_binds=out)

    def _decode_out_row(self, cursor, row) -> list:
        # Decode a routine's OUT-value row: an ora_tstz composite → an aware
        # datetime at its offset (#519); a refcursor portal → its rows drained into
        # a CursorResult for the REF CURSOR OUT bind (#518); anything else verbatim.
        if row is None:
            return []
        decoded: list = []
        for value, desc in zip(row, cursor.description or ()):
            if value is None:
                decoded.append(None)
            elif desc.type_code == _REFCURSOR_OID:
                decoded.append(self._drain_refcursor(value))
            elif self._tstz_oid is not None and desc.type_code == self._tstz_oid:
                decoded.append(_reconstruct_tstz(value))
            else:
                decoded.append(value)
        return decoded

    def _drain_refcursor(self, portal: str) -> CursorResult:
        # A REF CURSOR OUT bind: the routine OPENed a portal, whose name the CALL
        # returned. Fetch all its rows (still inside this transaction) and hand them
        # back as a CursorResult the Mirror parks and serves as a nested cursor —
        # re-tagging any ora_tstz cells the same way the top-level read path does.
        fetch = self._conn.cursor()
        fetch.execute(sql.SQL('FETCH ALL FROM {}').format(sql.Identifier(portal)))
        rows = [list(r) for r in fetch.fetchall()]
        for i, desc in enumerate(fetch.description or ()):
            if self._tstz_oid is not None and desc.type_code == self._tstz_oid:
                for row in rows:
                    row[i] = _reconstruct_tstz(row[i])
        columns = [
            _column_meta(desc, [r[i] for r in rows], self._tstz_oid)
            for i, desc in enumerate(fetch.description or ())
        ]
        return CursorResult(columns=columns, rows=[tuple(r) for r in rows])

    def _eval_out_assignments(
        self, body: str, assignments: list, binds: Sequence, values: list
    ) -> Result:
        # BEGIN :a := <expr>; :b := <expr>; END — evaluate the right-hand sides
        # with one SELECT and place each result onto its bind position (#517).
        refs = _distinct_bind_refs(body)
        exprs = ', '.join(expr for _ref, expr in assignments)
        sql, params = _translate_binds(_translate_idioms(f'SELECT {exprs}'), values)
        cursor = self._conn.cursor()
        cursor.execute(sql, params)
        row = _decode_row(cursor, cursor.fetchone(), self._tstz_oid) or []
        out = list(values)
        for (ref, _expr), result in zip(assignments, row):
            if ref in refs:
                out[refs.index(ref)] = result
        return Result(out_binds=out)

    def _run_block_statement(self, statement: str, values: list) -> Result:
        # A single DML statement unwrapped from a BEGIN … END block — run it with
        # the binds (#517). The block carried IN binds, so there are no OUT values
        # to return; the input values keep the bind positions aligned.
        sql, params = _translate_binds(
            _translate_idioms(_translate_ddl(statement)), values
        )
        self._conn.cursor().execute(sql, params)
        return Result(out_binds=values)

    def _proc_signature(self, name: str) -> tuple[list | None, list]:
        # A routine's parameter modes ('i' IN, 'o' OUT, 'b' IN OUT) and the aligned
        # argument type oids, from one pg_proc row. Modes place a CALL's result row
        # (which carries only the OUT / IN OUT values) back onto the right bind
        # positions; the types let the OUT-bind path spot an ora_intervalym argument
        # (which has no result column to trace). Modes are None for an all-IN routine
        # (PostgreSQL leaves proargmodes — and proallargtypes — NULL then).
        row = self._conn.execute(
            'SELECT proargmodes, proallargtypes FROM pg_proc WHERE proname = %s '
            'ORDER BY oid DESC LIMIT 1',
            (name.split('.')[-1].lower(),),
        ).fetchone()
        if not row or not row[0]:
            return None, []
        return list(row[0]), list(row[1] or ())

    def change_password(
        self, username: str, old_password: str, new_password: str
    ) -> None:
        # The Mirror's client auth (the credential map) is separate from the
        # backend's PostgreSQL connection (a fixed conninfo), so a password change
        # updates only the map — a fresh Mirror session then authenticates with
        # the new password and the old one is rejected — without touching a
        # PostgreSQL role (which would break the backend's own conninfo). Oracle
        # validates the old password (ALTER USER … REPLACE); do the same against
        # the stored secret (#515). The map is shared across sessions.
        current = credential_lookup(self._credentials, username)
        if current is not None and old_password != current:
            raise BackendError('invalid username/password; logon denied', ora_code=1017)
        for name in list(self._credentials):
            if name.upper() == username.upper():
                self._credentials[name] = new_password
                return
        self._credentials[username.upper()] = new_password

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()
