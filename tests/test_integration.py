# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Integration tests that talk to a real Oracle database. Disabled unless the
# connection parameters are exported in the environment:
#
#   SEERDB_TEST_USER       (required — gate; if unset, all tests skip)
#   SEERDB_TEST_PASSWORD   (required)
#   SEERDB_TEST_HOST       (default '127.0.0.1')
#   SEERDB_TEST_PORT       (default 1521)
#   SEERDB_TEST_SERVICE    (default 'XE')
#
# The DB user only needs CREATE SESSION and CREATE TABLE privileges plus a
# writable tablespace. Each test creates and drops its own scratch table.
#
# Optional — only the pre-SHA-2 verifier login test (#311) uses these; it forges
# and drops a throwaway 11g-only account, so it needs a DBA login (and skips if
# absent):
#
#   SEERDB_TEST_ADMIN_USER      a DBA (e.g. 'system')
#   SEERDB_TEST_ADMIN_PASSWORD

import array
import asyncio
import datetime
import functools
import inspect
import math
import os
import re
import socket
import ssl
import tempfile
import time
import unittest
from decimal import Decimal
from typing import Any, NamedTuple

import seerdb
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_12_2,
    FIELD_VERSION_20_1,
    FIELD_VERSION_23_1,
    FIELD_VERSION_23_1_EXT_1,
    FIELD_VERSION_23_1_EXT_3,
)

# Features the Oracle 9i (fv2) server genuinely lacks, keyed by a substring of
# the test method name. A 9i (field_version < 10.2) connection skips these with
# a clear reason — the same bar 10g uses for 12c+/23ai features (#171). These
# are *server* limitations or capabilities seerdb deliberately does not offer
# on fv2, not fixable fv2 bind gaps (those are #172 dates, #173 intervals,
# #174 national charset).
_FV2_UNSUPPORTED = (
    ('binary_double', 'BINARY_DOUBLE is a 10g+ type; Oracle 9i lacks it'),
    ('binary_float', 'BINARY_FLOAT is a 10g+ type; Oracle 9i lacks it'),
    ('kib', '9i takes no bind over 4000 bytes into a LOB column (#2260)'),
    (
        'clob_bind_above_varchar2_cap',
        '9i takes no bind over 4000 bytes into a LOB column (#2260)',
    ),
    (
        'clob_bind_spans_multiple_packets',
        '9i takes no bind over 4000 bytes into a LOB column (#2260)',
    ),
    (
        'blob_bind_round_trip_all_byte_values',
        '9i takes no bind over 4000 bytes into a LOB column (#2260)',
    ),
    (
        'error_then_large_lob',
        '9i takes no bind over 4000 bytes into a LOB column (#2260)',
    ),
    # Behavioural features the fv2 path does not implement (#168): they now
    # raise a clean NotSupportedError or exercise a capability 9i lacks, rather
    # than silently misbehaving, so the tests skip on 9i.
    ('ref_bind', 'REF / object types are not supported on Oracle 9i'),
    # 9i fetches objects over TTI_ALL7 (#2258). These read national text the
    # test writes as a SQL literal, which the 9i bed's WE8ISO8859P1 database
    # cannot hold (#174).
    (
        'national_attribute_fetches',
        "the 9i bed's database cannot hold the national text (#174)",
    ),
    (
        'national_attribute_collection',
        "the 9i bed's database cannot hold the national text (#174)",
    ),
    (
        'lob_attribute_fetches_as_a_lob',
        "the 9i bed's database cannot hold the national text (#174)",
    ),
    (
        'lob_attributes_read_in_any_order',
        "the 9i bed's database cannot hold the national text (#174)",
    ),
    ('changepassword', 'changepassword is not supported on Oracle 9i'),
    # The 9i test DB is WE8ISO8859P1 (Latin-1). #174 made representable VARCHAR2
    # text round-trip (see test_db_charset_varchar_roundtrip) and full Unicode
    # work through DB_TYPE_NVARCHAR / DB_TYPE_NCHAR (test_national_char_var_bind,
    # which runs on every tier). What remains genuinely unsupported on 9i is a
    # *plain str* bind of non-Latin-1 / supplementary text: it routes through the
    # DB charset, which cannot hold those characters. Those tests stay skipped.
    ('varchar_utf8', "plain str non-Latin-1 can't store in 9i WE8ISO8859P1 (#174)"),
    (
        'varchar_supplementary',
        "plain str supplementary char can't store in 9i WE8ISO8859P1 (#174)",
    ),
    (
        'nvarchar',
        'plain str -> NVARCHAR2 via 9i DB charset; use DB_TYPE_NVARCHAR (#174)',
    ),
    ('nchar', 'plain str -> NCHAR via 9i DB charset; use DB_TYPE_NCHAR (#174)'),
    ('nclob', "the 9i bed's database cannot hold the national text (#174)"),
    (
        'each_lob_type_round_trips',
        "the 9i bed's database cannot hold the national text (#174)",
    ),
    (
        'fetched_lob_attribute_binds_back',
        "9i takes no CHAR for a CLOB attribute in an object's constructor (ORA-00932)",
    ),
    ('large_clob_into_xmltype', 'XMLSERIALIZE is a 10g function'),
    # The fixture SELECT ... CONNECT BY LEVEL <= 200 returns only 10 rows on 9i
    # (a 9i CONNECT-BY-against-dual quirk, like the 8i "returns one row"), so it
    # never crosses a fetch boundary here. The fv2 fetch loop itself is fine — a
    # real 200-row table returns all 200 — so this is a fixture limitation, not a
    # 9i bug. Already skipped on 8i for the same reason.
    ('bit_vector_reuse', 'CONNECT BY LEVEL returns few rows on Oracle 9i'),
    # RETURNING itself now works on pre-10g through the PL/SQL block rewrite
    # (#801, #802), but an *array* RETURNING still cannot: 9i's array DML
    # (#2245) is a plain TTI_ALL7 batch, and the rewrite is one block a row.
    ('array_returning', 'an array DML RETURNING is not supported before 10g'),
    ('executemany_returning', 'an array DML RETURNING is not supported before 10g'),
    # The rewrite runs the statement as a PL/SQL block, and the server rejects
    # a quoted placeholder inside one (ORA-01006) even though plain pre-10g DML
    # accepts it. Measured on 9i; the driver refuses it with a clear message.
    (
        'quoted_bind_in_returning_into',
        'a quoted bind cannot ride the pre-10g block rewrite',
    ),
    # The pre-10 error reply carries the code and text but no position.
)


def _fv2_skip_reason(test_method_name: str) -> str | None:
    # The skip reason for a test whose feature Oracle 9i (fv2) lacks, or None.
    for Pattern, Reason in _FV2_UNSUPPORTED:
        if Pattern in test_method_name:
            return Reason
    return None


# Oracle 8i (8.1.7) lacks more than 9i does — it is fv2 like 9i, so these are an
# *additional* 8i-only layer on top of _FV2_UNSUPPORTED (matched by a substring
# of the test method name). Two kinds:
#   * genuine 8i limitations — a datatype or SQL feature 8.1.7 predates;
#   * known 8i bugs tracked by a ticket — skipped with the issue number until
#     fixed, so the 8i suite stays green *and* honest (milestone #25).
_8I_UNSUPPORTED = (
    # Genuine 8i limitations (8.1.7 predates the feature).
    (
        'methods_on_a_missing_directory',
        '8i has no LOB object calls, fileexists() included',
    ),
    ('timestamp', 'TIMESTAMP is a 9i+ type; Oracle 8i has only DATE'),
    ('interval', 'INTERVAL is a 9i+ type; Oracle 8i lacks it'),
    ('multilevel', 'a collection of collections is a 9i+ type; Oracle 8i lacks it'),
    ('national_char', 'Oracle 8i predates AL16UTF16 NCHAR (WE8ISO8859P1 only)'),
    ('national_attribute', 'an Oracle 8i object type takes no NVARCHAR2 attribute'),
    (
        'attributes_metadata',
        'the type covers TIMESTAMP and AL16UTF16 NVARCHAR2, which Oracle 8i lacks',
    ),
    ('bit_vector_reuse', 'CONNECT BY LEVEL returns one row on Oracle 8i'),
    # Async-only / connectivity tests (AsyncConnectionIntegration, Redirect).
    # In the subquery those tests use, 8.1.7 refuses it (ORA-01436).
    ('async_iteration', 'Oracle 8i has no CONNECT BY LEVEL row generator'),
    ('fetchall_and_fetchmany', 'Oracle 8i has no CONNECT BY LEVEL row generator'),
    # The test's column is a TIMESTAMP; 8i honours the declared types it has.
    ('declared_type_governs', 'TIMESTAMP is a 9i+ type; Oracle 8i has only DATE'),
    # 9i runs array DML over TTI_ALL7 (#2245); 8i's OALL8 dialect has none yet.
    ('executemany', 'executemany (array DML) is not supported on Oracle 8i'),
    ('mixed_batch', 'executemany (array DML) is not supported on Oracle 8i'),
    ('pipeline', 'the pipeline test uses array DML, unsupported on Oracle 8i'),
    # 9i reads a REF CURSOR by its id over TTI_ALL7 (#2246); 8i's dialect does not.
    ('refcursor', 'REF CURSOR is not supported on Oracle 8i'),
    ('batcherror', 'executemany (array DML) is not supported on Oracle 8i'),
    ('error_offset', 'the 8i error reply carries no offset (#719)'),
    (
        'collection_of_objects',
        'object types are not supported on Oracle 8i (9i: #2258)',
    ),
    ('lob_attribute', 'object types are not supported on Oracle 8i (9i: #2258)'),
    ('large_object_image', 'object types are not supported on Oracle 8i (9i: #2258)'),
    ('nested_attribute', 'object types are not supported on Oracle 8i (9i: #2258)'),
    (
        'collection_of_collections',
        'object types are not supported on Oracle 8i (9i: #2258)',
    ),
    (
        'local_time_zone_attribute',
        'object types are not supported on Oracle 8i (9i: #2258)',
    ),
    ('collection_value', 'object types are not supported on Oracle 8i (9i: #2258)'),
    ('cache_evicts', 'the 8i dialect keeps no cursor cache (9i: #2261)'),
    ('reuses_cursor', 'the 8i dialect keeps no cursor cache (9i: #2261)'),
    ('forgets_the_cached_cursor', 'the 8i dialect keeps no cursor cache (9i: #2261)'),
    ('never_cached', 'the 8i dialect keeps no cursor cache (9i: #2261)'),
)


# What the experimental 9i OALL8 opt-in (SEERDB_TEST_OALL8, #798) lacks by design,
# as 8i does: a cursor cache. Its open gaps are left to fail.
# What a pooled 11g session in the native form (#2466) lacks by design: a cursor
# cache, the server session behind it changing between calls (#2535).
_NATIVE11_UNSUPPORTED = tuple(
    (Pattern, 'a pooled 11g session keeps no cursor cache (#2535)')
    for Pattern in (
        'cache_evicts',
        'reuses_cursor',
        'forgets_the_cached',
        'never_cached',
    )
)


def _8i_skip_reason(test_method_name: str) -> str | None:
    # The skip reason for a test Oracle 8i lacks or has a tracked bug in, or None.
    for Pattern, Reason in _8I_UNSUPPORTED:
        if Pattern in test_method_name:
            return Reason
    return None


# Non-_IntegrationBase classes (async, SSL, redirect) build their own
# connection, so they can't use the setUp auto-skip. Probe once whether the
# configured target is an 8i server and cache it, so those classes can gate
# without connecting per test. Lazy — never connects at import/collection time.
_TARGET_IS_8I: bool | None = None


def _conn_is_8i(conn) -> bool:
    # 8i is now identified by its dialect object, not a flag (#369).
    from seerdb.client.dialect import O8iDialect

    return isinstance(getattr(conn, '_dialect', None), O8iDialect)


def _target_is_8i() -> bool:
    global _TARGET_IS_8I
    if _TARGET_IS_8I is None:
        if not _USER:
            _TARGET_IS_8I = False
        else:
            try:
                Conn = _connect()
                _TARGET_IS_8I = _conn_is_8i(Conn)
                Conn.close()
            except Exception:
                _TARGET_IS_8I = False
    return _TARGET_IS_8I


# What the server a test runs against can do (#1339): one table of the facts
# the suite used to restate in each test body, each with the server or field
# version that has it and the error or reason that rules it out. A test or a
# whole class declares what it needs with @_requires(...); the check runs when
# the test does, against its own connection, or a probe one for a class that
# makes its own. What a test meets at run time -- a privilege the bed's user
# lacks, an ORA code the server answers -- stays a skip in the test body.
class _Target(NamedTuple):
    field_version: int
    is_8i: bool
    # The server's major release, from its banner: 23 for 23ai.
    server_major: int
    # The Mirror leg this is (SEERDB_TEST_MIRROR): 'postgres', 'passthrough',
    # '1' for a runner that does not name its backend, or '' for none.
    mirror: str
    # Whether the session makes a temporary LOB: 12c+, and a pooled 11g one in
    # the native form (#2466).
    temp_lobs: bool = False
    # Whether a DML's RETURNING runs as a PL/SQL block, as below 10g and on a
    # pooled 11g session, whose INTO targets take one row.
    wrapped_returning: bool = False
    # Whether the server refuses a password change on the session: a pooled 11g
    # one answers ORA-56609 (#2466).
    no_password_change: bool = False
    # Whether the session binds an open cursor IN: 12.1+, and a pooled 11g one
    # in the native form (#2466).
    refcursor_in: bool = False
    # Whether the session binds an object or a collection, IN and OUT: 12.1+,
    # and 11g's native form, pooled or dedicated with oall8 (#2463).
    object_binds: bool = False
    # Whether the session writes to a persistent LOB: 10g closes the
    # connection on the converted form's write (#964), not on the native
    # form's (oall8, #2518).
    lob_modify: bool = True
    # Whether the session sends the end-to-end tracing attributes: 12.1+, and
    # the native form on 10g and 11g.
    end_to_end: bool = False
    # Whether the session binds a PL/SQL associative array: 12.1+, and the
    # native form on 10g and 11g.
    assoc_arrays: bool = False
    # Whether the session runs two-phase commit: 12.1+, and the native form on
    # 10g and 11g.
    tpc: bool = False
    # Whether the session binds a REF: 12.1+, and the native form on 10g and 11g.
    ref_binds: bool = False


def _dialect_binds_objects(conn) -> bool:
    # A pre-12c dialect that binds objects itself: the native form on 9i too.
    from seerdb.client.dialect import CAP_OBJECT_BIND

    Dialect = getattr(conn, '_dialect', None)
    return Dialect is not None and CAP_OBJECT_BIND in Dialect.capabilities()


def _target_of(conn) -> _Target:
    from seerdb.client._conn_logic import temp_lobs_available

    return _Target(
        conn.field_version,
        _conn_is_8i(conn),
        conn.server_version >> 24,
        os.environ.get('SEERDB_TEST_MIRROR', ''),
        temp_lobs_available(conn),
        getattr(conn, '_dialect', None) is not None,
        bool(getattr(conn, '_native11', False))
        and getattr(conn, 'server_type', None) == 'pooled',
        conn.field_version >= FIELD_VERSION_12_1
        or bool(getattr(conn, '_native11', False)),
        conn.field_version >= FIELD_VERSION_12_1
        or bool(getattr(conn, '_native11', False))
        or _dialect_binds_objects(conn),
        conn.server_version >> 24 != 10 or bool(getattr(conn, '_native11', False)),
        conn.field_version >= FIELD_VERSION_12_1
        or bool(getattr(conn, '_native11', False)),
        conn.field_version >= FIELD_VERSION_12_1
        or bool(getattr(conn, '_native11', False)),
        conn.field_version >= FIELD_VERSION_12_1
        or bool(getattr(conn, '_native11', False)),
        conn.field_version >= FIELD_VERSION_12_1
        or bool(getattr(conn, '_native11', False)),
    )


_PROBED_TARGET: _Target | None = None


def _probed_target() -> _Target:
    # The configured server, probed once and cached, for a test with no
    # connection of the suite's own: one built as the suite builds them.
    global _PROBED_TARGET
    if _PROBED_TARGET is None:
        conn = _connect()
        try:
            _PROBED_TARGET = _target_of(conn)
        finally:
            conn.close()
    return _PROBED_TARGET


class _Need(NamedTuple):
    # A capability: why a server without it skips, and what it takes. Every
    # condition named must hold.
    reason: str
    # The field version a session needs at least, or stays below (a pre-X
    # behaviour the test is about).
    min_fv: int = 0
    below_fv: int = 0
    # The server's major release it needs at least.
    min_server: int = 0
    # Whether 8i lacks it, or only 8i has it.
    not_8i: bool = False
    only_8i: bool = False
    # The Mirror legs that lack it: '*' for any Mirror, else backend names. A
    # runner that names no backend ('1') lacks what any backend lacks.
    not_mirror: tuple[str, ...] = ()
    # Whether it needs a session that makes a temporary LOB.
    temp_lobs: bool = False
    # Whether it needs RETURNING over several rows, which a wrapped one lacks.
    rows_returning: bool = False
    # Whether it changes a password, which some sessions' servers refuse.
    password_change: bool = False
    # Whether it binds an open cursor IN.
    refcursor_in: bool = False
    # Whether it binds an object or a collection.
    object_binds: bool = False
    # Whether it writes to a persistent LOB.
    lob_modify: bool = False
    # Whether it sends the end-to-end tracing attributes.
    end_to_end: bool = False
    # Whether it binds a PL/SQL associative array.
    assoc_arrays: bool = False
    # Whether it runs two-phase commit.
    tpc: bool = False
    # Whether it binds a REF.
    ref_binds: bool = False

    def missing(self, target: _Target) -> bool:
        fv = target.field_version
        if self.temp_lobs and not target.temp_lobs:
            return True
        if self.rows_returning and target.wrapped_returning:
            return True
        if self.password_change and target.no_password_change:
            return True
        if self.refcursor_in and not target.refcursor_in:
            return True
        if self.object_binds and not target.object_binds:
            return True
        if self.lob_modify and not target.lob_modify:
            return True
        if self.end_to_end and not target.end_to_end:
            return True
        if self.assoc_arrays and not target.assoc_arrays:
            return True
        if self.tpc and not target.tpc:
            return True
        if self.ref_binds and not target.ref_binds:
            return True
        if self.min_fv and fv < self.min_fv:
            return True
        if self.below_fv and fv >= self.below_fv:
            return True
        if self.min_server and target.server_major < self.min_server:
            return True
        if (self.not_8i and target.is_8i) or (self.only_8i and not target.is_8i):
            return True
        leg = target.mirror
        return (
            bool(leg)
            and bool(self.not_mirror)
            and ('*' in self.not_mirror or leg in self.not_mirror or leg == '1')
        )


def _postgres_cannot(feature: str) -> _Need:
    # What the Mirror's postgres backend cannot do, while the passthrough,
    # which asks a real server, does (#1019).
    return _Need(
        f"the Mirror's postgres backend cannot {feature}", not_mirror=('postgres',)
    )


def _mirror_lacks(feature: str) -> _Need:
    # What no Mirror leg serves yet, whatever its backend; each caller names
    # the follow-up ticket.
    return _Need(f'the Mirror does not implement {feature} yet', not_mirror=('*',))


def _skip_unless(test: unittest.TestCase, *needs: _Need) -> None:
    # The check @_requires makes, for a helper that sets a test up and skips
    # on its way (#1339).
    conn = getattr(test, 'conn', None)
    target = _target_of(conn) if conn is not None else _probed_target()
    for need in needs:
        if need.missing(target):
            test.skipTest(need.reason)


def _requires(*needs: _Need):
    """Skip a test, or every test of a class, on a server without ``needs``.

    On a test, checked as it runs, against ``self.conn`` where the test has
    one -- set up by _IntegrationBase -- and the probed target otherwise. On a
    class of _IntegrationBase, checked in its setUp right after connecting,
    before the class's own setUp makes anything a server without it lacks.
    """

    def decorate(item):
        if isinstance(item, type):
            item._NEEDS = (*getattr(item, '_NEEDS', ()), *needs)
            return item

        if inspect.iscoroutinefunction(item):

            @functools.wraps(item)
            async def run_async(test_self, *args, **kwargs):
                _skip_unless(test_self, *needs)
                return await item(test_self, *args, **kwargs)

            return run_async

        @functools.wraps(item)
        def run(test_self, *args, **kwargs):
            _skip_unless(test_self, *needs)
            return item(test_self, *args, **kwargs)

        return run

    return decorate


# The capabilities, by the field version that brings them.
_FV = FIELD_VERSION_10_2
_TRUNC_TIMESTAMP = _Need(
    "9i's TRUNC and ROUND take no TIMESTAMP (ORA-00932)", min_fv=_FV
)
_Q_QUOTING = _Need("alternative quoting (q'[...]') is 10g and later", min_fv=_FV)
_LTZ_SESSION_ARITHMETIC = _Need(
    '9i PL/SQL does LTZ + n on the database clock (#1241)', min_fv=_FV
)
_PING_ROUND_TRIP = _Need('9i pings with a query, which already raises', min_fv=_FV)
_BINARY_DOUBLE_AND_INTERVAL = _Need(
    'BINARY_DOUBLE / INTERVAL are 10g+ types; Oracle 9i lacks them', min_fv=_FV
)
_BINARY_FLOAT = _Need('BINARY_FLOAT / BINARY_DOUBLE are 10g+', min_fv=_FV)
_BINARY_FLOAT_SERVER = _Need(
    'BINARY_FLOAT / BINARY_DOUBLE are Oracle 10g+', min_server=10
)
_GAP_DATE_LITERAL = _Need(
    'a DATE literal in the 1582 gap is 1582-10-15 from 18c; 11g and older keep '
    'the day the calendar lacks',
    min_server=18,
)
_MOD_FLOAT_BY_ZERO = _Need(
    'MOD of a BINARY_FLOAT / BINARY_DOUBLE by 0 is the dividend from 18c; '
    '10g and 11g give 0',
    min_server=18,
)
_BITAND_FETCHABLE = _Need(
    "8i's SQL BITAND returns a type no client can fetch: its sqlplus gets "
    'ORA-00932, and seerdb refuses it (#2584)',
    not_8i=True,
)
_STREAMED_LOB_BIND = _Need(
    '9i takes no bind over 4000 bytes into a LOB column (#2260)', min_fv=_FV
)
_NATIONAL_OUT_BIND = _Need(
    'a national OUT bind is refused on fv2 (ORA-03120)', min_fv=_FV
)
_CHANGE_PASSWORD = _Need(
    'changepassword is not supported on Oracle 9i, and a pooled 11g session '
    'refuses it (ORA-56609)',
    min_fv=_FV,
    password_change=True,
)
_PARSE = _Need('cursor.parse() needs 10g+', min_fv=_FV)
_ARRAY_DML = _Need('executemany (array DML) is not supported on Oracle 8i', not_8i=True)
_FV2_EXECUTE_PATH = _Need('fv2 (9i) uses a separate execute path', min_fv=_FV)
_PROXY_AUTH = _Need('proxy authentication needs a 10g+ server', min_fv=_FV)
_SERVER_SCROLL = _Need(
    'server-side scroll needs 10g+ (9i uses buffered scroll)', min_fv=_FV
)
_LOBOPS = _Need('the 8i LOB object has no LOBOPS calls (9i: #2259)', not_8i=True)
_OER_WARN_BYTE = _Need('the 8i OER warn byte is not located (9i: #2262)', not_8i=True)
_BLOCK_IOV = _Need(
    'the 8i block reply carries no IOV directions (9i: #2264)', not_8i=True
)
_PRE10_PARSE_REFUSAL = _Need(
    '10g+ sends a real parse; this is the pre-10g refusal', below_fv=_FV
)
_PRE10_RETURNING = _Need(
    'RETURNING ... INTO takes the native path from 10g', below_fv=_FV
)
_FV = FIELD_VERSION_11_2
_EDITIONS = _Need('editions need 11g or later', min_fv=_FV)
# 10g closes the connection on the converted form's persistent-LOB write (#964),
# not on the native form's (oall8, #2518), and 8i's dialect serves no LOB
# object calls; 9i writes through its own LOBOPS form (#2259).
_LOB_MODIFY = _Need(
    'modifying a LOB: 10g closes the connection without oall8, 8i has no LOB calls',
    lob_modify=True,
    not_8i=True,
)
_FV = FIELD_VERSION_12_1
_INVISIBLE_COLUMNS = _Need('INVISIBLE columns are 12.1+', min_fv=_FV)
_REF_BIND = _Need(
    'REF bind needs a 12.1+ server, or the native form on 10g and 11g', ref_binds=True
)
_ROWS_RETURNING = _Need(
    'a RETURNING over several rows runs as a PL/SQL block below 10g and on a pooled '
    '11g session, whose INTO targets take one row',
    rows_returning=True,
)
_LOB_VAR_BIND = _Need(
    'a LOB Var bind needs the 12.1+ OAC and temp-LOB path (#902), or the native form',
    temp_lobs=True,
)
_REFCURSOR_IN_BIND = _Need(
    'a REF CURSOR IN bind needs the 12c+ bind OAC, or a pooled 11g session',
    refcursor_in=True,
)
_VECTOR_BIND = _Need('a VECTOR bind needs a 12.1+ session (#1762)', min_fv=_FV)
_PACKAGE_TYPE_BIND = _Need(
    'a package-level type is 12.1+: before it the server has no ALL_PLSQL_TYPES'
    ' and no OID for one, OCI included (#2463)',
    min_fv=_FV,
)
_ASSOC_ARRAY_BIND = _Need(
    'an associative-array bind needs 12.1+ (#122), or the native form on 10g and 11g',
    assoc_arrays=True,
)
_OBJECT_BIND = _Need(
    "an object bind needs the 12.1+ OAC, or 11g's native form (#2463)",
    object_binds=True,
)
_ARRAY_DML_ROWCOUNTS = _Need('arraydmlrowcounts needs a 12.1+ server', min_fv=_FV)
_TIME_ZONE_SYNC = _Need(
    'client time-zone sync is 12c+ (AUTH_ALTER_SESSION)', min_fv=_FV
)
_TEMP_LOB = _Need(
    'a temporary LOB needs a 12c+ server (CREATE_TEMP), or the native form',
    temp_lobs=True,
)
_END_TO_END = _Need(
    'end-to-end tracing requires 12c+, or the native form on 10g and 11g',
    end_to_end=True,
)
_IMPLICIT_RESULTS = _Need('DBMS_SQL.RETURN_RESULT is 12c+', min_server=12)
_PRE12_VECTOR_REFUSAL = _Need('a 12.1+ session binds a VECTOR', below_fv=_FV)
_CURSOR_CACHE = _Need(
    'cursor cache is disabled on 12c+ (re-parse each execute)', below_fv=_FV
)
_PRE12_ROWCOUNTS_REFUSAL = _Need('server supports arraydmlrowcounts', below_fv=_FV)
_JSON = _Need(
    'native JSON needs a session at field version 20.1+', min_fv=FIELD_VERSION_20_1
)
_BOOLEAN = _Need(
    'native BOOLEAN needs a session at field version 23.1+', min_fv=FIELD_VERSION_23_1
)
_SESSION_CONTEXT = _Need(
    'session-context pairs need the fv > 23.1 FAST_AUTH',
    min_fv=FIELD_VERSION_23_1_EXT_1,
)
# The describe carries a column's annotations from 23.1 EXT 3, its domain
# from 23.1 (measured against 23ai).
_DOMAINS = _Need(
    'column annotations need a session at field version 23.1 EXT 3+',
    min_fv=FIELD_VERSION_23_1_EXT_3,
)
del _FV
# By the server.
_SODA = _Need('SODA needs an Oracle 18c+ server (DBMS_SODA)', min_server=18)
_LTZ = _Need('8i has no TIMESTAMP WITH LOCAL TIME ZONE', not_8i=True)
_TSTZ = _Need('8i has no TIMESTAMP WITH TIME ZONE', not_8i=True)
_INTERVAL = _Need('INTERVAL is a 9i+ type; Oracle 8i lacks it', not_8i=True)
_CHAR_LENGTH = _Need('Oracle 8i has no USER_TAB_COLUMNS.CHAR_LENGTH', not_8i=True)
_8I_DESCRIBE_SPANS_PACKETS = _Need('a describe outgrows a packet on 8i', only_8i=True)
_ONLY_8I = _Need('not an Oracle 8i server', only_8i=True)
_GRID_10G = _Need('the grid starts at 10g', min_fv=FIELD_VERSION_10_2)
_MEDIAN_FUNCTION = _Need('MEDIAN is a 10g function', min_fv=FIELD_VERSION_10_2)
_MEDIAN_ANALYTIC = _postgres_cannot(
    'window MEDIAN: PostgreSQL has no exact one (#1992)'
)
# By the Mirror leg.
_REAL_SERVER_REPORT = _Need(
    'a Mirror reports whatever its backend knows', not_mirror=('*',)
)
_REAL_SERVER_READS = _Need(
    'the grid checks what a real Oracle server reads', not_mirror=('*',)
)


# Resolve the TLS proxy fixture without depending on the `tests` package
# layout (works under both `python -m unittest tests.test_integration` and
# discovery from the repo root).
import sys as _sys

_sys.path.insert(0, os.path.dirname(__file__))
import temporal_bind_grid as _grid  # noqa: E402
from _redirect_listener import RedirectListener  # noqa: E402
from _tls_proxy import CERT_PATH, TLSProxy  # noqa: E402

_USER = os.environ.get('SEERDB_TEST_USER')
_PASSWORD = os.environ.get('SEERDB_TEST_PASSWORD', '')
_HOST = os.environ.get('SEERDB_TEST_HOST', '127.0.0.1')
_PORT = int(os.environ.get('SEERDB_TEST_PORT', '1521'))
_SERVICE = os.environ.get('SEERDB_TEST_SERVICE', 'XE')
# Advertise a 12c+ TTC field version (e.g. 16 = 21.1) to run the suite against
# a 12c+ server; unset/0 keeps the 11g default. Lets the same suite cover both
# testbeds (issue #27).
_FIELD_VERSION = int(os.environ.get('SEERDB_TEST_FIELD_VERSION', '0'))
_FV_KW: dict[str, Any] = {'field_version': _FIELD_VERSION} if _FIELD_VERSION else {}
# Run the suite over the experimental native OALL8 form: the 9i dialect on a 9.2
# bed (#798), 10g's and 11g's native form on a dedicated session (#2463, #2518);
# every other server ignores the option.
if os.environ.get('SEERDB_TEST_OALL8', '') not in ('', '0'):
    _FV_KW['oall8'] = True
# Run the suite over pooled sessions, as DRCP serves them (#2466): on 11g that
# is the native form. The server's pool must be started.
if os.environ.get('SEERDB_TEST_SERVER_TYPE'):
    _FV_KW['server_type'] = os.environ['SEERDB_TEST_SERVER_TYPE']

_SKIP_REASON = (
    'integration tests require a real DB connection; '
    'set SEERDB_TEST_USER (and SEERDB_TEST_PASSWORD) to enable'
)

# A DBA login, used only by the pre-SHA-2-verifier login test (#311) to forge an
# 11g-only account. Kept separate from the app user so the rest of the suite
# still runs with a least-privilege account.
_ADMIN_USER = os.environ.get('SEERDB_TEST_ADMIN_USER')
_ADMIN_PASSWORD = os.environ.get('SEERDB_TEST_ADMIN_PASSWORD', '')
_ADMIN_SKIP_REASON = (
    'set SEERDB_TEST_ADMIN_USER / SEERDB_TEST_ADMIN_PASSWORD (a DBA) to enable '
    'the pre-SHA-2 verifier login test (#311)'
)


# Pause before each connection. Oracle XE's listener throttles rapid logins
# ("logon storm" protection) and cancels early statements on the throttled
# session with ORA-01013. The whole suite opens ~150 connections; on a busy or
# freshly-booted XE (e.g. CI) the default 0.05 s isn't always enough, so the
# delay is tunable via SEERDB_TEST_CONNECT_DELAY (CI sets it higher).
_CONNECT_DELAY = float(os.environ.get('SEERDB_TEST_CONNECT_DELAY', '0.05'))


def _connect_with(**extra):
    """A connection with extra connect arguments, for the attribute tests."""
    return seerdb.connect(
        host=_HOST,
        port=_PORT,
        user=_USER,
        password=_PASSWORD,
        service_name=_SERVICE,
        autocommit=True,
        **_FV_KW,
        **extra,
    )


def _tz_offset(zone: str) -> datetime.timedelta | None:
    """A ``+HH:MM`` time zone as its offset; None for a named region."""
    m = re.fullmatch(r'\s*([+-])(\d{1,2}):(\d{2})\s*', zone or '')
    if m is None:
        return None
    offset = datetime.timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
    return -offset if m.group(1) == '-' else offset


def _session_zone_apart_from(
    database: datetime.timedelta,
) -> tuple[datetime.timedelta, str]:
    """A session zone five hours from the database's, and its ALTER SESSION
    spelling. With the two zones equal, an LTZ bind and a TIMESTAMP bind read
    alike, and a test could not tell the database zone from the session's
    (#1967)."""
    shift = datetime.timedelta(
        hours=5 if database <= datetime.timedelta(hours=9) else -5
    )
    zone = database + shift
    minutes = int(zone.total_seconds()) // 60
    sign = '-' if minutes < 0 else '+'
    return zone, f'{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}'


def _alias_entry(alias: str) -> str:
    """A tnsnames.ora entry naming the bed the suite runs against (#1976)."""
    return (
        f'{alias} = (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={_HOST})(PORT={_PORT}))'
        f'(CONNECT_DATA=(SERVICE_NAME={_SERVICE})))\n'
    )


# Three groups, the last all NULL: the shape a live 11g's reply was misread on
# (#1995); two groups did not trip it.
_NULL_GROUP_ROWS = (
    (1, '12345678901234567890.123'),
    (1, '12345678901234567890.125'),
    (2, '12345678901234567890.127'),
    (2, '12345678901234567890.131'),
    (3, 'NULL'),
)
_NULL_GROUP_AVERAGES = [
    (1, Decimal('12345678901234567890.124'), 2),
    (2, Decimal('12345678901234567890.129'), 2),
    (3, None, 0),
]


def _failover_descriptors() -> list[tuple[str, str]]:
    """Two descriptors that reach the bed only by failing over (#1983): a dead
    address ahead of it, and a service its listener refuses (ORA-12514) ahead of
    the real one."""
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        dead = probe.getsockname()[1]
    bed = f'(ADDRESS=(PROTOCOL=TCP)(HOST={_HOST})(PORT={_PORT}))'
    return [
        (
            'dead address first',
            f'(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT={dead}))'
            f'{bed}(CONNECT_DATA=(SERVICE_NAME={_SERVICE})))',
        ),
        (
            'refused service first',
            f'(DESCRIPTION_LIST=(DESCRIPTION={bed}(CONNECT_DATA=(SERVICE_NAME=PYO_NO_SUCH)))'
            f'(DESCRIPTION={bed}(CONNECT_DATA=(SERVICE_NAME={_SERVICE}))))',
        ),
    ]


_LTZ_VALUE = datetime.datetime(2026, 9, 25, 13, 45, 6, 123456)
_LTZ_TABLE_DDL = (
    'CREATE TABLE {} (k NUMBER, a TIMESTAMP WITH LOCAL TIME ZONE, '
    'b TIMESTAMP(3) WITH LOCAL TIME ZONE)'
)


def _tz(hours: int) -> datetime.timezone:
    return datetime.timezone(datetime.timedelta(hours=hours))


# Two rows at the same instant written at different offsets, and a later one:
# Oracle compares WITH TIME ZONE values by their instant (#1239).
_TSTZ_ROWS = [
    [1, datetime.datetime(2022, 5, 10, 12, 0, tzinfo=_tz(0))],
    [2, datetime.datetime(2022, 5, 10, 14, 0, tzinfo=_tz(2))],
    [3, datetime.datetime(2022, 5, 10, 13, 0, tzinfo=_tz(0))],
]
_TSTZ_SAME_INSTANT = datetime.datetime(2022, 5, 10, 17, 0, tzinfo=_tz(5))
_TSTZ_BEFORE = datetime.datetime(2022, 5, 10, 12, 30, tzinfo=_tz(0))


def _connect(fetch_lobs: bool = True):
    import time

    time.sleep(_CONNECT_DELAY)
    return seerdb.connect(
        host=_HOST,
        port=_PORT,
        user=_USER,
        password=_PASSWORD,
        service_name=_SERVICE,
        autocommit=True,
        fetch_lobs=fetch_lobs,
        **_FV_KW,
    )


# Number of times to replay a whole test that tripped a transient server
# refusal, and the pause between attempts. See `_ThrottleRetry.run`.
_THROTTLE_RETRIES = int(os.environ.get('SEERDB_TEST_THROTTLE_RETRIES', '2'))
_THROTTLE_RETRY_DELAY = float(os.environ.get('SEERDB_TEST_THROTTLE_DELAY', '0.5'))
# The refusals worth a replay: XE's logon-storm cancel (ORA-01013), and a login
# its listener refuses while it still counts sessions that have just closed
# (ORA-12516, #1229).
_TRANSIENT_CODES = frozenset({1013, 12516})


class _CaptureResult(unittest.TestResult):
    """Runs one test attempt and remembers its single outcome (with the
    original exc_info) instead of reporting it. Lets `_IntegrationBase.run`
    decide whether the attempt hit a transient server refusal worth retrying
    (_TRANSIENT_CODES), then forward the final outcome to the real result — without
    double-running the test or losing the traceback."""

    def __init__(self):
        super().__init__()
        self.outcome = ('success', None)
        # Each failing `subTest` block, as (subtest, exc_info). unittest reports
        # those through addSubTest alone and then calls none of the methods
        # below for the test itself, so without this a failing subtest was
        # forwarded as a pass (#1807).
        self.subtests = []

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.subtests.append((subtest, err))

    def addSuccess(self, test):
        self.outcome = ('success', None)

    def addError(self, test, err):
        self.outcome = ('error', err)  # err = exc_info tuple

    def addFailure(self, test, err):
        self.outcome = ('failure', err)

    def addSkip(self, test, reason):
        self.outcome = ('skip', reason)

    def is_throttle(self) -> bool:
        kind, payload = self.outcome
        errs = [err for _, err in self.subtests]
        if kind in ('error', 'failure') and payload:
            errs.append(payload)
        return any(
            isinstance(err[1], seerdb.DatabaseError)
            and getattr(err[1], 'code', None) in _TRANSIENT_CODES
            for err in errs
        )


class _ThrottleRetry:
    """Replay a whole test that hit a transient server refusal (_TRANSIENT_CODES),
    after a pause, up to _THROTTLE_RETRIES times; report only the last attempt.

    Mixed into every integration class, sync and async alike: the async ones
    open connections as fast as any, and were the ones left without it when
    11g's listener began refusing logins (#1229).
    """

    def run(self, result=None):
        import time

        for attempt in range(_THROTTLE_RETRIES + 1):
            # An IsolatedAsyncioTestCase keeps its finished asyncio runner and
            # refuses to run again while one is set, so drop it before a replay.
            if getattr(self, '_asyncioRunner', None) is not None:
                self._asyncioRunner = None
            capture = _CaptureResult()
            super().run(capture)  # type: ignore[misc]
            if attempt == _THROTTLE_RETRIES or not capture.is_throttle():
                break
            time.sleep(_THROTTLE_RETRY_DELAY)
        # Forward the final attempt's outcome to the real result so reporting
        # (counts, tracebacks, verbose output) is unaffected by the retry.
        if result is not None:
            kind, payload = capture.outcome
            result.startTest(self)
            try:
                for subtest, err in capture.subtests:
                    if hasattr(result, 'addSubTest'):
                        result.addSubTest(self, subtest, err)
                    elif issubclass(err[0], self.failureException):  # type: ignore[attr-defined]
                        result.addFailure(self, err)
                    else:
                        result.addError(self, err)
                if kind == 'error':
                    result.addError(self, payload)
                elif kind == 'failure':
                    result.addFailure(self, payload)
                elif kind == 'skip':
                    result.addSkip(self, payload)
                elif not capture.subtests:
                    result.addSuccess(self)
            finally:
                result.stopTest(self)
        return result


class ThrottleRetryOutcomeTests(unittest.TestCase):
    """The outcome `_ThrottleRetry` forwards is the test's own. Needs no server."""

    class _Probe(_ThrottleRetry, unittest.TestCase):
        def test_subtest_fails(self):
            with self.subTest(n=1):
                self.assertEqual(1, 2)

        def test_subtest_errors(self):
            with self.subTest(n=1):
                raise RuntimeError('boom')

        def test_subtests_pass(self):
            with self.subTest(n=1):
                pass

    class _NoSubTestResult(unittest.TestResult):
        # A result without subtest support, as some runners' are.
        def __getattribute__(self, name):
            if name == 'addSubTest':
                raise AttributeError(name)
            return super().__getattribute__(name)

    def _run(self, name, result):
        self._Probe(name).run(result)
        return result

    def test_a_failing_subtest_fails_the_test(self):
        result = self._run('test_subtest_fails', unittest.TestResult())
        self.assertEqual((len(result.failures), len(result.errors)), (1, 0))

    def test_an_erroring_subtest_errors_the_test(self):
        result = self._run('test_subtest_errors', unittest.TestResult())
        self.assertEqual((len(result.failures), len(result.errors)), (0, 1))

    def test_passing_subtests_pass(self):
        result = self._run('test_subtests_pass', unittest.TestResult())
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(result.testsRun, 1)

    def test_a_result_without_subtests_still_sees_the_failure(self):
        result = self._run('test_subtest_fails', self._NoSubTestResult())
        self.assertEqual((len(result.failures), len(result.errors)), (1, 0))


class _IntegrationBase(_ThrottleRetry, unittest.TestCase):
    """Per-test connection; fresh cursor + scratch table per test.

    Oracle XE's listener throttles rapid logins ("logon storm"
    protection) and cancels statements on a throttled session with
    ORA-01013 ("user requested cancel of current operation"). This is
    documented server behaviour, not a driver bug — production code uses
    connection pools (`seerdb.Pool`, issue #6) and doesn't hit it. The
    suite defends in three layers: `_connect` paces logins
    (SEERDB_TEST_CONNECT_DELAY), `setUp` retries the connect / initial
    drop, and `run` (below) replays a whole test that still tripped
    ORA-01013 mid-body — each replay gets a fresh connection via setUp, so
    it is safe and keeps CI from flaking on the throttle.
    """

    TABLE = 'SEERDB_TEST'

    def __init_subclass__(cls, **kwargs):
        # Give each integration class its OWN table name (#170). All classes
        # used to share "SEERDB_TEST", so a single stuck lock — e.g. a 9i
        # connection killed mid-DML leaving a zombie session (#168/#169) — would
        # block every later class's setUp/tearDown DROP and cascade into dozens
        # of phantom ORA-00054, especially on the slow 9i VM. A unique name per
        # class contains the blast radius to that one class. A subclass that
        # sets its own TABLE keeps it.
        super().__init_subclass__(**kwargs)
        if 'TABLE' not in cls.__dict__:
            Name = cls.__name__.replace('Integration', '') or cls.__name__
            cls.TABLE = ('PYO_' + Name.upper())[:30]

    def setUp(self):
        Last: Exception = RuntimeError('setUp: connection retries exhausted')
        for _ in range(5):
            try:
                self.conn = _connect(getattr(self, '_fetch_lobs', True))
                self.cur = self.conn.cursor()
                self._skip_if_fv2_unsupported()
                self._skip_if_class_needs_unmet()
                self._drop_silently(self.cur)
                return
            except seerdb.DatabaseError as e:
                if e.code not in _TRANSIENT_CODES:
                    raise
                Last = e
                # Bleed a few ms and try a fresh connection.
                try:
                    self.conn.close()
                except Exception:
                    # Best-effort: we are retrying with a fresh connection;
                    # a failed close on the stale one does not matter.
                    pass
                import time

                time.sleep(0.05)
        raise Last

    def _skip_if_class_needs_unmet(self):
        # A class's @_requires (#1339): checked before the class's own setUp
        # makes anything; the connection is closed first, as a skip from setUp
        # runs no tearDown.
        target = _target_of(self.conn)
        for need in getattr(type(self), '_NEEDS', ()):
            if need.missing(target):
                self.conn.close()
                self.skipTest(need.reason)

    def _skip_if_fv2_unsupported(self):
        # On a 9i (fv2) connection, skip the tests whose feature the 9i server
        # genuinely lacks — same bar 10g uses for 12c+/23ai features (#171).
        # Close the connection first: a SkipTest from setUp means tearDown does
        # not run, so we must not leak the connection (a leak on the slow 9i VM
        # piles up sessions).
        if getattr(self.conn, '_native11', False):
            Reason = (
                next(
                    (
                        R
                        for (P, R) in _NATIVE11_UNSUPPORTED
                        if P in self._testMethodName
                    ),
                    None,
                )
                if getattr(self.conn, 'server_type', None) == 'pooled'
                else None
            )
            if Reason is not None:
                self.conn.close()
                self.skipTest(Reason)
            return
        if self.conn.field_version >= FIELD_VERSION_10_2:
            return
        Reason = _fv2_skip_reason(self._testMethodName)
        if Reason is None and _conn_is_8i(self.conn):
            # 8i is fv2 too but lacks more than 9i; layer its extra skips on top.
            Reason = _8i_skip_reason(self._testMethodName)
        if Reason is not None:
            self.conn.close()
            self.skipTest(Reason)

    def tearDown(self):
        # The test may have closed self.cur — always reach for a fresh one.
        try:
            with self.conn.cursor() as cleanup:
                try:
                    self._drop_silently(cleanup)
                except seerdb.OperationalError as e:
                    # The setUp/tearDown cleanup is best-effort; ORA-01013
                    # here just means "Oracle cancelled the cleanup
                    # statement", and the next test's setUp will retry.
                    if e.code != 1013:
                        raise
        finally:
            self.conn.close()

    def _drop_silently(self, cur):
        try:
            cur.execute(f'DROP TABLE {self.TABLE}')
        except seerdb.DatabaseError as e:
            # ORA-00942: table or view does not exist — expected on first run.
            if e.code != 942:
                raise


def _release_of(banner: str, version: str | None) -> str | None:
    # The release a v$version banner names, as connection.version should give
    # it. From 18c the banner names the base release and the version the release
    # update, so there the version stands if its major is the banner's (#2278).
    match = re.search(r'Release (\d+(?:\.\d+)+)', banner)
    assert match, banner
    release = match.group(1)
    if int(release.split('.')[0]) >= 18 and version:
        return version if version.split('.')[0] == release.split('.')[0] else release
    return release


def _banner_release(cur, version: str | None) -> str | None:
    cur.execute("SELECT banner FROM v$version WHERE banner LIKE 'Oracle%'")
    (banner,) = cur.fetchone()
    return _release_of(banner, version)


@unittest.skipUnless(_USER, _SKIP_REASON)
class AvgIntegration(_IntegrationBase):
    """AVG over a NUMBER keeps Oracle's precision (#1997).

    Through Mirror-over-PG it went through PostgreSQL's numeric division: 16
    significant digits, and no more decimals than its input."""

    def setUp(self):
        super().setUp()
        self.cur.execute(f'CREATE TABLE {self.TABLE} (k NUMBER, g NUMBER, n NUMBER)')
        for k, g, n in (
            (1, 1, '12345678901234567890.127'),
            (2, 1, '12345678901234567890.130'),
            (3, 2, '1'),
            (4, 2, '2'),
            (5, 2, '2'),
            (6, 3, 'NULL'),
        ):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES ({k}, {g}, {n})')

    def test_avg_keeps_every_digit(self):
        t = self.TABLE
        self.cur.execute(f'SELECT g, AVG(n) FROM {t} GROUP BY g ORDER BY g')
        self.assertEqual(
            self.cur.fetchall(),
            [
                (1, Decimal('12345678901234567890.1285')),
                (2, Decimal('1.66666666666666666666666666666666666667')),
                (3, None),
            ],
        )
        self.cur.execute(f'SELECT AVG(DISTINCT n) FROM {t} WHERE g = 2')
        self.assertEqual(self.cur.fetchone(), (Decimal('1.5'),))
        self.cur.execute(f'SELECT AVG(n) FROM {t} WHERE k > 99')
        self.assertEqual(self.cur.fetchone(), (None,))

    def test_avg_as_an_analytic_function(self):
        self.cur.execute(
            f'SELECT k, AVG(n) OVER (PARTITION BY g) FROM {self.TABLE} '
            'WHERE g = 2 ORDER BY k'
        )
        self.assertEqual(
            [a for _, a in self.cur.fetchall()],
            [Decimal('1.66666666666666666666666666666666666667')] * 3,
        )


@unittest.skipUnless(_USER, _SKIP_REASON)
class MedianIntegration(_IntegrationBase):
    """MEDIAN over a NUMBER is exact and over a DATE stays a DATE (#1994).

    Through Mirror-over-PG it resolved to orafce's double precision median and
    came back a rounded float, and a DATE had no median at all."""

    _N = (
        '12345678901234567890.123',
        '12345678901234567890.125',
        '12345678901234567890.127',
        '12345678901234567890.130',
    )
    _D = ('2024-01-01', '2024-01-03', '2024-01-10', '2024-01-11')

    def setUp(self):
        super().setUp()
        _skip_unless(self, _MEDIAN_FUNCTION)
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (k NUMBER, g NUMBER, n NUMBER, d DATE)'
        )
        for k, (n, d) in enumerate(zip(self._N, self._D), start=1):
            self.cur.execute(
                f"INSERT INTO {self.TABLE} VALUES ({k}, {(k + 1) // 2}, {n}, DATE '{d}')"
            )
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (5, 3, NULL, NULL)')

    def _one(self, sql):
        self.cur.execute(sql)
        return self.cur.fetchone()[0]

    def test_median_is_exact_and_keeps_its_type(self):
        t = self.TABLE
        # An odd count is its middle row, an even one the two middle rows'
        # midpoint; NULLs are ignored, and no rows at all is NULL.
        self.assertEqual(
            self._one(f'SELECT MEDIAN(n) FROM {t} WHERE k <= 3'),
            Decimal('12345678901234567890.125'),
        )
        self.assertEqual(
            self._one(f'SELECT MEDIAN(n) FROM {t}'), Decimal('12345678901234567890.126')
        )
        # The midpoint of a wide spread keeps every digit.
        self.assertEqual(
            self._one(
                'SELECT MEDIAN(x) FROM (SELECT 0 x FROM dual UNION ALL '
                'SELECT 12345678901234567891 FROM dual)'
            ),
            Decimal('6172839450617283945.5'),
        )
        self.assertIsNone(self._one(f'SELECT MEDIAN(n) FROM {t} WHERE k = 5'))
        self.assertIsNone(self._one(f'SELECT MEDIAN(n) FROM {t} WHERE k > 9'))
        self.assertEqual(
            self._one(f'SELECT MEDIAN(d) FROM {t} WHERE k <= 3'),
            datetime.datetime(2024, 1, 3),
        )
        self.assertEqual(
            self._one(f'SELECT MEDIAN(d) FROM {t}'), datetime.datetime(2024, 1, 6, 12)
        )
        self.cur.execute(f'SELECT g, MEDIAN(n) FROM {t} GROUP BY g ORDER BY g')
        self.assertEqual(
            self.cur.fetchall(),
            [
                (1, Decimal('12345678901234567890.124')),
                (2, Decimal('12345678901234567890.1285')),
                (3, None),
            ],
        )

    @_requires(_MEDIAN_ANALYTIC)
    def test_median_as_an_analytic_function(self):
        self.cur.execute(
            f'SELECT k, MEDIAN(n) OVER (PARTITION BY g) FROM {self.TABLE} '
            'WHERE k <= 4 ORDER BY k'
        )
        self.assertEqual(
            [m for _, m in self.cur.fetchall()],
            [Decimal('12345678901234567890.124')] * 2
            + [Decimal('12345678901234567890.1285')] * 2,
        )

    def test_an_order_by_in_its_window_is_refused(self):
        # Its window takes only PARTITION BY: ORA-30487 on Oracle, and so on
        # the Mirror.
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.execute(f'SELECT MEDIAN(n) OVER (ORDER BY k) FROM {self.TABLE}')
        self.assertEqual(ctx.exception.code, 30487)


@unittest.skipUnless(_USER, _SKIP_REASON)
class TypesIntegration(_IntegrationBase):
    """Verify that wire bytes are coerced into the right Python types."""

    def _round_trip(self, ddl_col: str, insert_value: str):
        """CREATE + INSERT + SELECT one column, return the fetched cell."""
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v {ddl_col})')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES ({insert_value})')
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 1)
        return rows[0][0]

    # ----- NUMBER -----

    def test_number_positive_int(self):
        v = self._round_trip('NUMBER', '42')
        self.assertEqual(v, 42)
        self.assertIsInstance(v, int)

    def test_number_zero(self):
        v = self._round_trip('NUMBER', '0')
        self.assertEqual(v, 0)
        self.assertIsInstance(v, int)

    def test_number_negative_int(self):
        v = self._round_trip('NUMBER', '-17')
        self.assertEqual(v, -17)
        self.assertIsInstance(v, int)

    def test_number_big_int(self):
        v = self._round_trip('NUMBER', '1234567890123456')
        self.assertEqual(v, 1234567890123456)
        self.assertIsInstance(v, int)

    def test_number_decimal_positive(self):
        v = self._round_trip('NUMBER(12,4)', '3.1415')
        self.assertEqual(v, Decimal('3.1415'))
        self.assertIsInstance(v, Decimal)

    def test_number_decimal_negative(self):
        v = self._round_trip('NUMBER', '-0.5')
        self.assertEqual(v, Decimal('-0.5'))
        self.assertIsInstance(v, Decimal)

    def test_number_small_fractional(self):
        v = self._round_trip('NUMBER(12,4)', '0.0001')
        self.assertEqual(v, Decimal('0.0001'))

    # ----- VARCHAR / CHAR -----

    def test_varchar_ascii(self):
        v = self._round_trip('VARCHAR2(40)', "'hello world'")
        self.assertEqual(v, 'hello world')
        self.assertIsInstance(v, str)

    def test_varchar_utf8(self):
        v = self._round_trip('VARCHAR2(40)', "'utf-8 ✓ 中文'")
        self.assertEqual(v, 'utf-8 ✓ 中文')

    def test_varchar_supplementary_plane(self):
        # Characters above the BMP (emoji, U+1F600 etc.) are 4-byte UTF-8 /
        # surrogate pairs in UTF-16. They round-trip only when the client
        # advertises AL32UTF8 (real UTF-8); Oracle's legacy "UTF8" (CESU-8)
        # 6-byte-encodes them and decode then yields replacement chars (#29).
        v = self._round_trip('VARCHAR2(40)', "'hi 😀🎉 端 end'")
        self.assertEqual(v, 'hi 😀🎉 端 end')

    def test_char_preserves_padding(self):
        v = self._round_trip('CHAR(10)', "'x'")
        self.assertEqual(v, 'x' + ' ' * 9)
        self.assertEqual(len(v), 10)

    # ----- NCHAR / NVARCHAR (national character set) -----

    def test_nvarchar_non_ascii(self):
        v = self._round_trip('NVARCHAR2(40)', "N'national ünî 中'")
        self.assertEqual(v, 'national ünî 中')
        self.assertIsInstance(v, str)

    def test_nvarchar_supplementary_plane(self):
        v = self._round_trip('NVARCHAR2(40)', "N'n 😀🎉 end'")
        self.assertEqual(v, 'n 😀🎉 end')

    def test_nchar_preserves_padding(self):
        v = self._round_trip('NCHAR(6)', "N'hï'")
        self.assertEqual(v, 'hï' + ' ' * 4)
        self.assertEqual(len(v), 6)

    # ----- DATE / TIMESTAMP -----

    def test_date(self):
        v = self._round_trip('DATE', "DATE '2026-05-23'")
        self.assertEqual(v, datetime.datetime(2026, 5, 23, 0, 0, 0))
        self.assertIsInstance(v, datetime.datetime)

    def test_date_min(self):
        v = self._round_trip('DATE', "DATE '0001-01-01'")
        self.assertEqual(v, datetime.datetime(1, 1, 1))

    def test_to_date_of_a_number(self):
        # Oracle converts a numeric first argument of TO_DATE to text, so a
        # number works as the date's digits, and the result takes DATE
        # arithmetic. The python-oracledb suite builds its date test data this
        # way; a Mirror-over-PG had no to_date(numeric, text) (#1299).
        v = self._round_trip('DATE', "to_date(20021209, 'YYYYMMDD') + 1")
        self.assertEqual(v, datetime.datetime(2002, 12, 10))

    def test_to_date_keeps_the_time_of_day(self):
        # Oracle's TO_DATE yields a DATE, which carries a time of day. On a
        # Mirror-over-PG, PostgreSQL's own date-only to_date shadowed orafce's
        # and dropped it (#1305).
        v = self._round_trip(
            'DATE', "to_date('20220601 15:38:12', 'YYYYMMDD HH24:MI:SS')"
        )
        self.assertEqual(v, datetime.datetime(2022, 6, 1, 15, 38, 12))

    def test_timestamp_microseconds(self):
        v = self._round_trip('TIMESTAMP', "TIMESTAMP '2026-05-23 10:11:12.345678'")
        self.assertEqual(v, datetime.datetime(2026, 5, 23, 10, 11, 12, 345678))

    def test_timestamp_max(self):
        v = self._round_trip('TIMESTAMP', "TIMESTAMP '9999-12-31 23:59:59.999999'")
        self.assertEqual(v, datetime.datetime(9999, 12, 31, 23, 59, 59, 999999))

    def test_timestamp_with_negative_tz(self):
        v = self._round_trip(
            'TIMESTAMP WITH TIME ZONE',
            "TIMESTAMP '2026-05-23 10:11:12.345678 -05:30'",
        )
        # Oracle normalises to UTC and tags the offset; both pieces must match.
        self.assertIsNotNone(v.tzinfo)
        self.assertEqual(v.utcoffset(), datetime.timedelta(hours=-5, minutes=-30))
        expected = datetime.datetime(
            2026,
            5,
            23,
            10,
            11,
            12,
            345678,
            tzinfo=datetime.timezone(datetime.timedelta(hours=-5, minutes=-30)),
        )
        self.assertEqual(v, expected)

    def test_timestamp_with_positive_tz(self):
        v = self._round_trip(
            'TIMESTAMP WITH TIME ZONE',
            "TIMESTAMP '2026-05-23 10:11:12 +14:00'",
        )
        self.assertEqual(v.utcoffset(), datetime.timedelta(hours=14))

    def test_timestamp_with_named_region_winter(self):
        # Named region (issue #20): offset resolved via zoneinfo, so January is
        # standard time (EST, -05:00).
        v = self._round_trip(
            'TIMESTAMP WITH TIME ZONE',
            "FROM_TZ(TIMESTAMP '2024-01-15 12:00:00', 'US/Eastern')",
        )
        self.assertEqual(v.utcoffset(), datetime.timedelta(hours=-5))
        self.assertEqual(
            v.replace(tzinfo=None), datetime.datetime(2024, 1, 15, 12, 0, 0)
        )

    def test_timestamp_with_named_region_dst(self):
        # Same region in July is daylight time (EDT, -04:00) — proof the offset
        # comes from the live IANA database, not a fixed per-region value.
        v = self._round_trip(
            'TIMESTAMP WITH TIME ZONE',
            "FROM_TZ(TIMESTAMP '2024-07-15 12:00:00', 'US/Eastern')",
        )
        self.assertEqual(v.utcoffset(), datetime.timedelta(hours=-4))

    # ----- BINARY_FLOAT / BINARY_DOUBLE -----

    def test_binary_float(self):
        v = self._round_trip('BINARY_FLOAT', '1.5f')
        self.assertEqual(v, 1.5)
        self.assertIsInstance(v, float)

    def test_binary_float_negative(self):
        self.assertEqual(self._round_trip('BINARY_FLOAT', '-2.25f'), -2.25)

    def test_binary_double(self):
        v = self._round_trip('BINARY_DOUBLE', '1234.5678d')
        self.assertEqual(v, 1234.5678)
        self.assertIsInstance(v, float)

    def test_binary_double_infinity(self):
        self.assertEqual(
            self._round_trip('BINARY_DOUBLE', 'binary_double_infinity'), math.inf
        )

    def test_binary_double_nan(self):
        self.assertTrue(
            math.isnan(self._round_trip('BINARY_DOUBLE', 'binary_double_nan'))
        )

    # ----- INTERVAL -----

    def test_interval_ds(self):
        v = self._round_trip(
            'INTERVAL DAY(4) TO SECOND(6)', "INTERVAL '5 04:03:02.123456' DAY TO SECOND"
        )
        self.assertEqual(
            v,
            datetime.timedelta(
                days=5, hours=4, minutes=3, seconds=2, microseconds=123456
            ),
        )
        self.assertIsInstance(v, datetime.timedelta)

    def test_interval_ds_negative(self):
        v = self._round_trip(
            'INTERVAL DAY(4) TO SECOND(6)', "INTERVAL '-0 00:00:01.5' DAY TO SECOND"
        )
        self.assertEqual(v, datetime.timedelta(seconds=-1.5))

    def test_interval_ym(self):
        v = self._round_trip(
            'INTERVAL YEAR(4) TO MONTH', "INTERVAL '3-7' YEAR TO MONTH"
        )
        self.assertEqual(v, seerdb.IntervalYM(3, 7))
        self.assertIsInstance(v, seerdb.IntervalYM)

    def test_interval_ym_negative(self):
        v = self._round_trip(
            'INTERVAL YEAR(4) TO MONTH', "INTERVAL '-1-2' YEAR TO MONTH"
        )
        self.assertEqual(v, seerdb.IntervalYM(-1, -2))

    def test_an_interval_ym_out_bind_assigned_in_a_block(self):
        # A block assigning an INTERVAL YEAR TO MONTH to its OUT bind returns an
        # IntervalYM. The Mirror over PostgreSQL returned a plain interval it had
        # no wire form for (#1400).
        for text, expected in (
            ('-25-7', seerdb.IntervalYM(-25, -7)),
            ('3-2', seerdb.IntervalYM(3, 2)),
        ):
            v = self.cur.var(seerdb.DB_TYPE_INTERVAL_YM)
            self.cur.execute(f"BEGIN :v := TO_YMINTERVAL('{text}'); END;", [v])
            self.assertEqual(v.getvalue(), expected)

    @_requires(_INTERVAL)
    def test_an_interval_ym_bound_into_a_select_list(self):
        # An IntervalYM bound into a select list comes back as one. The Mirror
        # over PostgreSQL described it as DAY TO SECOND and read its months as
        # days (#1401).
        for value in (seerdb.IntervalYM(-12, -5), seerdb.IntervalYM(3, 2)):
            self.cur.execute('SELECT :1 FROM dual', [value])
            self.assertEqual(self.cur.fetchone(), (value,))

    # ----- ROWID -----

    def test_rowid_matches_rowidtochar(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        for i in range(3):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES ({i})')
        self.cur.execute(
            f'SELECT ROWID, ROWIDTOCHAR(ROWID) FROM {self.TABLE} ORDER BY id'
        )
        for driver_rowid, ref in self.cur.fetchall():
            self.assertIsInstance(driver_rowid, str)
            self.assertEqual(driver_rowid, ref)

    def test_rowid_usable_as_bind(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (42)')
        self.cur.execute(f'SELECT ROWID FROM {self.TABLE}')
        rid = self.cur.fetchone()[0]
        self.cur.execute(f'SELECT id FROM {self.TABLE} WHERE ROWID = :r', [rid])
        self.assertEqual(self.cur.fetchone(), (42,))

    def test_urowid_index_organized_table(self):
        # An index-organized table's ROWID is a UROWID (type 208): a
        # "*"-prefixed base64 string, and usable as a bind.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} '
            f'(id NUMBER PRIMARY KEY, v VARCHAR2(20)) ORGANIZATION INDEX'
        )
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 'a')")
        self.cur.execute(f'SELECT ROWID, id FROM {self.TABLE}')
        rid, idv = self.cur.fetchone()
        self.assertIsInstance(rid, str)
        self.assertTrue(rid.startswith('*'))
        self.assertEqual(idv, 1)
        self.cur.execute(f'SELECT id FROM {self.TABLE} WHERE ROWID = :r', [rid])
        self.assertEqual(self.cur.fetchone(), (1,))

    def test_a_long_bfile_locator_reaches_the_server_whole(self):
        # A BFILE's locator holds its file name, and a long one passes 252
        # bytes. Opening it is the server's to refuse -- the directory is not
        # there -- and the session goes on. On 9i the locator went out in
        # chunks, which 9.2.0.4 refused with ORA-03120 (#2331).
        self.cur.execute(
            'SELECT BFILENAME(:d, :f) FROM dual',
            ['NO_SUCH_DIR_2331', 'f' * 240],
        )
        (lob,) = self.cur.fetchone()
        with self.assertRaises(seerdb.DatabaseError) as raised:
            lob.read()
        self.assertNotEqual(getattr(raised.exception, 'code', None), 3120)
        self.cur.execute('SELECT 42 FROM dual')
        self.assertEqual(self.cur.fetchone(), (42,))

    def test_a_null_urowid_between_two_that_are_set(self):
        # Through a CASE, an index-organized table's ROWID can be NULL. On 8i
        # its cell left a byte unread, and the fetch failed with ORA-01002
        # (#2328).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} '
            f'(id NUMBER PRIMARY KEY, v VARCHAR2(20)) ORGANIZATION INDEX'
        )
        for i in (1, 2, 3):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [i, 'v'])
        self.cur.execute(
            f'SELECT id, CASE WHEN id <> 2 THEN ROWID END FROM {self.TABLE} ORDER BY id'
        )
        rows = self.cur.fetchall()
        self.assertEqual([r[0] for r in rows], [1, 2, 3])
        self.assertIsNone(rows[1][1])
        self.assertTrue(rows[0][1].startswith('*') and rows[2][1].startswith('*'))

    def test_a_long_urowid_comes_back_whole(self):
        # An index-organized table's ROWID holds its key: a 900-character key
        # makes a rowid of more than a thousand. On 9i it came back cut to 128
        # characters, and the longest no longer bound back to its row (#2335).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} '
            f'(k VARCHAR2(1000) PRIMARY KEY, v NUMBER) ORGANIZATION INDEX'
        )
        for i, n in enumerate((100, 400, 900)):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', ['k' * n, i])
        self.cur.execute(f'SELECT ROWID, v FROM {self.TABLE} ORDER BY v')
        rows = self.cur.fetchall()
        # An index-organized table's rowid is logical: '*'-prefixed, its key in
        # it, so a 900-character key makes a rowid past a thousand. The Mirror
        # over PostgreSQL gave a VARCHAR2-keyed IOT a physical-style rowid, where
        # a NUMBER-keyed one got the '*' form (#2339).
        self.assertTrue(rows[2][0].startswith('*'))
        self.assertGreater(len(rows[2][0]), 1000)
        for rid, v in rows:
            self.cur.execute(f'SELECT v FROM {self.TABLE} WHERE ROWID = :1', [rid])
            self.assertEqual(self.cur.fetchone(), (v,))

    @_requires(_INTERVAL)
    def test_interval_columns_describe_their_precisions(self):
        # An INTERVAL column describes its leading-field precision and its
        # fractional-seconds precision, declared or Oracle's default, with rows
        # or without, and USER_TAB_COLUMNS spells them in the type. The Mirror
        # over PostgreSQL dropped both (#1381).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (a INTERVAL DAY TO SECOND, '
            'b INTERVAL DAY(3) TO SECOND(2), c INTERVAL YEAR TO MONTH, '
            'd INTERVAL YEAR(4) TO MONTH)'
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (INTERVAL '1 2:3:4.5' DAY TO SECOND, "
            "NULL, INTERVAL '1-2' YEAR TO MONTH, NULL)"
        )
        for where in ('', ' WHERE 1 = 0'):
            self.cur.execute(f'SELECT a, b, c, d FROM {self.TABLE}{where}')
            self.cur.fetchall()
            self.assertEqual(
                [tuple(d)[4:6] for d in self.cur.description],
                [(2, 6), (3, 2), (2, 0), (4, 0)],
                where,
            )
        self.cur.execute(
            'SELECT data_type, data_length, data_precision, data_scale '
            'FROM user_tab_columns WHERE table_name = :1 ORDER BY column_id',
            [self.TABLE],
        )
        self.assertEqual(
            self.cur.fetchall(),
            [
                ('INTERVAL DAY(2) TO SECOND(6)', 11, 2, 6),
                ('INTERVAL DAY(3) TO SECOND(2)', 11, 3, 2),
                ('INTERVAL YEAR(2) TO MONTH', 5, 2, 0),
                ('INTERVAL YEAR(4) TO MONTH', 5, 4, 0),
            ],
        )

    # ----- LONG / LONG RAW -----

    def test_long(self):
        v = self._round_trip('LONG', "'a long value'")
        self.assertEqual(v, 'a long value')
        self.assertIsInstance(v, str)

    def test_long_multichunk(self):
        # > 1 wire chunk, exercising the chunk loop.
        v = self._round_trip('LONG', "RPAD('X', 700, 'X')")
        self.assertEqual(v, 'X' * 700)

    def test_long_over_sdu(self):
        # A LONG larger than one SDU-sized packet: the fetch response spans
        # several packets, which the reader must reassemble into one value. On
        # Oracle 8i this also verifies the fetch request's long-size field is set
        # wide enough to pull the whole value (#377). Built in a PL/SQL VARCHAR2
        # since a SQL string literal / RPAD caps at 4000.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, l LONG)')
        self.cur.execute(
            f'DECLARE v VARCHAR2(32767); BEGIN '
            f"v := RPAD('X', 4000, 'X'); v := v || RPAD('Y', 1000, 'Y'); "
            f'INSERT INTO {self.TABLE} VALUES (1, v); END;'
        )
        self.conn.commit()
        self.cur.execute(f'SELECT l FROM {self.TABLE} WHERE id = 1')
        v = self.cur.fetchone()[0]
        self.assertEqual(v, 'X' * 4000 + 'Y' * 1000)

    def test_a_declared_long_bind_takes_a_large_value(self):
        # Declared DB_TYPE_LONG / DB_TYPE_LONG_RAW, a value past 4000 bytes goes
        # in -- on 9i too, where an undeclared one is refused because a LOB
        # column would cost the session (#2260).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, l LONG)')
        text = self.cur.var(seerdb.DB_TYPE_LONG, 50000)
        text.setvalue(0, 'q' * 50000)
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, :1)', [text])
        self.cur.execute(f'SELECT l FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone()[0], 'q' * 50000)
        self.cur.execute(f'DROP TABLE {self.TABLE}')
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, r LONG RAW)')
        raw = self.cur.var(seerdb.DB_TYPE_LONG_RAW, 50000)
        raw.setvalue(0, bytes(range(256)) * 195)
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, :1)', [raw])
        self.cur.execute(f'SELECT r FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone()[0], bytes(range(256)) * 195)

    def test_sql_text_that_is_not_ascii(self):
        # Non-ASCII characters in the statement itself: 9i hung on any (#2275),
        # and 8i took a Latin-1 one's text as a byte longer than it is (#2276).
        # A Latin-1 one round-trips on every tier the suite runs, the 8i and 9i
        # beds' databases included.
        self.cur.execute("SELECT 'caf\u00e9' FROM dual")
        self.assertEqual(self.cur.fetchone(), ('caf\u00e9',))
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v VARCHAR2(20))')
        self.cur.execute(f"BEGIN INSERT INTO {self.TABLE} VALUES ('na\u00efve'); END;")
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), ('na\u00efve',))

    def test_sql_text_the_database_cannot_hold(self):
        # A character a WE8ISO8859P1 database cannot hold becomes its
        # replacement character, the inverted question mark: the 9i server puts
        # it, and the 8i client sends it, where 8i raised in the client (#2276).
        # A database that holds the character gives it back.
        self.cur.execute(
            'SELECT value FROM nls_database_parameters '
            "WHERE parameter = 'NLS_CHARACTERSET'"
        )
        (charset,) = self.cur.fetchone()
        self.cur.execute("SELECT '\u017e\u00e1ba' FROM dual")
        expected = '\u00bf\u00e1ba' if charset == 'WE8ISO8859P1' else '\u017e\u00e1ba'
        self.assertEqual(self.cur.fetchone(), (expected,))

    def test_long_null(self):
        self.assertIsNone(self._round_trip('LONG', 'NULL'))

    def test_long_raw(self):
        v = self._round_trip('LONG RAW', "HEXTORAW('DEADBEEFCAFE')")
        self.assertEqual(v, bytes.fromhex('DEADBEEFCAFE'))
        self.assertIsInstance(v, bytes)

    def test_long_raw_null(self):
        self.assertIsNone(self._round_trip('LONG RAW', 'NULL'))

    def test_long_not_last_column(self):
        # A LONG followed by another column: the reader must leave the stream
        # aligned for the trailing NUMBER.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (txt LONG, id NUMBER)')
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('hi', 5)")
        self.cur.execute(f'SELECT txt, id FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), ('hi', 5))

    def test_long_in_an_uncompressed_table(self):
        # A table compression clause is storage only: the table behaves the
        # same (#1182). The reference thin client's suite creates its LONG and
        # LONG RAW tables NOCOMPRESS. Table compression is 9i Release 2 and
        # later; 8i rejects the clause, ORA-00922 (#1214).
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute(
                f'CREATE TABLE {self.TABLE} (id NUMBER, l LONG) NOCOMPRESS'
            )
        except DatabaseError as exc:
            if exc.code == 922:
                self.skipTest('no table compression before 9i Release 2')
            raise
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 'kept')")
        self.cur.execute(f'SELECT id, l FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (1, 'kept'))

    def test_long_columns_describe_as_long(self):
        # A LONG / LONG RAW column describes as itself, unsized, with rows or
        # without, and USER_TAB_COLUMNS lists it with length 0. The Mirror over
        # PostgreSQL stores them as text / bytea and described a VARCHAR2 / RAW
        # sized from the data (#1382). A table holds one LONG-class column.
        from seerdb.common.datatypes import DB_TYPE_LONG, DB_TYPE_LONG_RAW

        for declared, db_type, value in (
            ('LONG', DB_TYPE_LONG, "'abc'"),
            ('LONG RAW', DB_TYPE_LONG_RAW, "HEXTORAW('0102')"),
        ):
            self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, l {declared})')
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, {value})')
            for where in ('', ' WHERE 1 = 0'):
                self.cur.execute(f'SELECT l FROM {self.TABLE}{where}')
                self.cur.fetchall()
                self.assertEqual(
                    tuple(self.cur.description[0])[1:4],
                    (db_type, None, None),
                    declared + where,
                )
            self.cur.execute(
                'SELECT data_type, data_length FROM user_tab_columns '
                "WHERE table_name = :1 AND column_name = 'L'",
                [self.TABLE],
            )
            self.assertEqual(self.cur.fetchall(), [(declared, 0)])
            self.cur.execute(f'DROP TABLE {self.TABLE}')

    def test_drop_table_purge(self):
        # DROP TABLE ... PURGE drops the table past the recycle bin (#1207). 9i
        # has no recycle bin and rejects the clause, ORA-00933.
        from seerdb.common.exceptions import DatabaseError

        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER)')
        try:
            self.cur.execute(f'DROP TABLE {self.TABLE} PURGE')
        except DatabaseError as exc:
            if exc.code == 933:
                self.skipTest('no recycle bin, so no PURGE, before 10g')
            raise
        with self.assertRaises(DatabaseError) as ctx:
            self.cur.execute(f'SELECT n FROM {self.TABLE}')
        self.assertEqual(ctx.exception.code, 942)

    # ----- NULL -----

    def test_null_number(self):
        v = self._round_trip('NUMBER', 'NULL')
        self.assertIsNone(v)

    def test_null_varchar(self):
        v = self._round_trip('VARCHAR2(40)', 'NULL')
        self.assertIsNone(v)

    def test_null_date(self):
        v = self._round_trip('DATE', 'NULL')
        self.assertIsNone(v)

    def test_a_varray_type_can_type_a_column(self):
        # A VARRAY type, written as a script writes it -- type DDL takes a
        # trailing `;` -- then a table with a column of it (#1193).
        from seerdb.common.exceptions import DatabaseError

        vtype = 'PYO_VARRAY_T'
        try:
            self.cur.execute(f'DROP TYPE {vtype}')
        except DatabaseError:
            # No leftover type from a prior run; nothing to clean up.
            pass
        self.cur.execute(f'CREATE TYPE {vtype} AS VARRAY(3) OF NUMBER;')
        try:
            self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v {vtype})')
            self.cur.execute(f'INSERT INTO {self.TABLE} (id) VALUES (1)')
            self.cur.execute(f'SELECT id FROM {self.TABLE}')
            self.assertEqual(self.cur.fetchone(), (1,))
            self.cur.execute(f'DROP TABLE {self.TABLE}')
        finally:
            self.cur.execute(f'DROP TYPE {vtype}')

    def test_a_nested_table_type_can_type_a_collection(self):
        # A nested table type, one of it, and a VARRAY of it (#1194). The types
        # are created as a script writes them, with type DDL's trailing `;`.
        from seerdb.common.exceptions import DatabaseError

        names = ('PYO_NT_VARRAY_T', 'PYO_NT_NESTED_T', 'PYO_NT_T')
        for name in names:
            try:
                self.cur.execute(f'DROP TYPE {name}')
            except DatabaseError:
                # No leftover type from a prior run; nothing to clean up.
                pass
        try:
            self.cur.execute('CREATE TYPE PYO_NT_T AS TABLE OF NUMBER;')
            self.cur.execute('CREATE TYPE PYO_NT_NESTED_T AS TABLE OF PYO_NT_T;')
            self.cur.execute('CREATE TYPE PYO_NT_VARRAY_T AS VARRAY(3) OF PYO_NT_T;')
        finally:
            for name in names:
                try:
                    self.cur.execute(f'DROP TYPE {name}')
                except DatabaseError:
                    # A CREATE above failed, so there is no type to drop.
                    pass

    def test_a_collection_type_has_its_constructors(self):
        # A collection type comes with Oracle's constructors: `t(e1, e2, …)` and
        # the empty `t()`, which is a collection and not NULL; a VARRAY's bound
        # holds for what they build (#1206).
        from seerdb.common.exceptions import DatabaseError

        vtype = 'PYO_CTOR_T'
        try:
            self.cur.execute(f'DROP TYPE {vtype}')
        except DatabaseError:
            # No leftover type from a prior run; nothing to clean up.
            pass
        self.cur.execute(f'CREATE TYPE {vtype} AS VARRAY(3) OF NUMBER')
        try:
            self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v {vtype})')
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, {vtype}(5, 10, 15))')
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (2, {vtype}())')
            self.cur.execute(f'INSERT INTO {self.TABLE} (id) VALUES (3)')
            with self.assertRaises(DatabaseError):
                self.cur.execute(
                    f'INSERT INTO {self.TABLE} VALUES (4, {vtype}(1, 2, 3, 4))'
                )
            self.cur.execute(
                f'SELECT id FROM {self.TABLE} WHERE v IS NOT NULL ORDER BY id'
            )
            self.assertEqual(self.cur.fetchall(), [(1,), (2,)])
            self.cur.execute(f'DROP TABLE {self.TABLE}')
        finally:
            self.cur.execute(f'DROP TYPE {vtype}')

    def test_a_multilevel_nested_table_names_its_inner_storage(self):
        # A nested table of nested tables names the inner one's storage inside
        # the outer one's parenthesized properties, as the reference suite's
        # schema does; the Mirror left that clause behind (#1275).
        from seerdb.common.exceptions import DatabaseError

        inner, outer = 'PYO_NTP_INNER_T', 'PYO_NTP_OUTER_T'
        for name in (outer, inner):
            try:
                self.cur.execute(f'DROP TYPE {name}')
            except DatabaseError:
                pass  # no leftover type from a prior run
        self.cur.execute(f'CREATE TYPE {inner} AS TABLE OF NUMBER')
        self.cur.execute(f'CREATE TYPE {outer} AS TABLE OF {inner}')
        try:
            self.cur.execute(
                f'CREATE TABLE {self.TABLE} (id NUMBER, c {outer}) '
                f'NESTED TABLE c STORE AS {self.TABLE}_NT ('
                f'NESTED TABLE COLUMN_VALUE STORE AS {self.TABLE}_NTI)'
            )
            self.cur.execute(f'INSERT INTO {self.TABLE} (id) VALUES (1)')
            self.cur.execute(f'SELECT id FROM {self.TABLE}')
            self.assertEqual(self.cur.fetchone(), (1,))
            self.cur.execute(f'DROP TABLE {self.TABLE}')
        finally:
            for name in (outer, inner):
                self.cur.execute(f'DROP TYPE {name}')

    def test_a_nested_table_column_names_its_storage(self):
        # A nested-table column needs `NESTED TABLE c STORE AS s` on Oracle; the
        # Mirror stores it in the row and takes the clause as said (#1253).
        from seerdb.common.exceptions import DatabaseError

        ntype = 'PYO_NT_STORE_T'
        try:
            self.cur.execute(f'DROP TYPE {ntype}')
        except DatabaseError:
            # No leftover type from a prior run; nothing to clean up.
            pass
        self.cur.execute(f'CREATE TYPE {ntype} AS TABLE OF NUMBER;')
        try:
            self.cur.execute(
                f'CREATE TABLE {self.TABLE} (id NUMBER, v {ntype}) '
                f'NESTED TABLE v STORE AS {self.TABLE}_V'
            )
            self.cur.execute(f'INSERT INTO {self.TABLE} (id) VALUES (1)')
            self.cur.execute(f'SELECT id FROM {self.TABLE}')
            self.assertEqual(self.cur.fetchone(), (1,))
            self.cur.execute(f'DROP TABLE {self.TABLE}')
        finally:
            self.cur.execute(f'DROP TYPE {ntype}')

    def test_an_object_type_has_its_constructor(self):
        # An object type comes with Oracle's constructor, one argument per
        # attribute; a call with the wrong number of them is refused (#1206).
        from seerdb.common.exceptions import DatabaseError

        otype = 'PYO_OBJ_CTOR_T'
        try:
            self.cur.execute(f'DROP TYPE {otype}')
        except DatabaseError:
            # No leftover type from a prior run; nothing to clean up.
            pass
        self.cur.execute(f'CREATE TYPE {otype} AS OBJECT (n NUMBER, s VARCHAR2(10));')
        try:
            self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, o {otype})')
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, {otype}(5, 'x'))")
            self.cur.execute(f'INSERT INTO {self.TABLE} (id) VALUES (2)')
            with self.assertRaises(DatabaseError):
                self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (3, {otype}(5))')
            self.cur.execute(f'SELECT id FROM {self.TABLE} WHERE o IS NOT NULL')
            self.assertEqual(self.cur.fetchall(), [(1,)])
            self.cur.execute(f'DROP TABLE {self.TABLE}')
        finally:
            self.cur.execute(f'DROP TYPE {otype}')

    def test_a_local_time_zone_timestamp_column_is_named_so(self):
        # USER_TAB_COLUMNS tells a WITH LOCAL TIME ZONE column from a WITH TIME
        # ZONE one; the Mirror-over-PG called both WITH TIME ZONE (#1272). Oracle
        # also names the precision -- TIMESTAMP(6) WITH ... -- which is left out.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (a TIMESTAMP WITH TIME ZONE, '
            'b TIMESTAMP WITH LOCAL TIME ZONE)'
        )
        self.cur.execute(
            'SELECT column_name, data_type FROM user_tab_columns '
            'WHERE table_name = :1 ORDER BY column_name',
            [self.TABLE],
        )
        (a, b) = [row[1] for row in self.cur.fetchall()]
        self.assertTrue(a.endswith('WITH TIME ZONE') and 'LOCAL' not in a, a)
        self.assertTrue(b.endswith('WITH LOCAL TIME ZONE'), b)

    def test_a_date_column_is_named_so(self):
        # USER_TAB_COLUMNS names a DATE column DATE, 7 bytes long; the
        # Mirror-over-PG called it a 22-byte TIMESTAMP (#1318).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (d DATE)')
        self.cur.execute(
            'SELECT data_type, data_length, data_precision, data_scale '
            'FROM user_tab_columns WHERE table_name = :1',
            [self.TABLE],
        )
        self.assertEqual(self.cur.fetchall(), [('DATE', 7, None, None)])

    def test_a_varchar2_column_describes_with_its_declared_length(self):
        # A VARCHAR2(n) column describes as n, whatever its values are -- or when
        # there are none. The Mirror over PostgreSQL sized it from the longest
        # value returned (#1385).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (s VARCHAR2(20))')
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('short')")
        for where in ('', ' WHERE 1 = 0'):
            self.cur.execute(f'SELECT s FROM {self.TABLE}{where}')
            self.cur.fetchall()
            self.assertEqual(self.cur.description[0][2:4], (20, 20), where)

    def test_delete_without_from(self):
        # Oracle takes DELETE without FROM. The Mirror over PostgreSQL sent it
        # as written, a syntax error there (#1407).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER)')
        for n in (1, 2, 3):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [n])
        self.cur.execute(f'DELETE {self.TABLE} WHERE n = 2')
        self.assertEqual(self.cur.rowcount, 1)
        self.cur.execute(f'DELETE {self.TABLE}')
        self.assertEqual(self.cur.rowcount, 2)

    def test_a_raw_column_keeps_its_declared_length(self):
        # A RAW(n) column describes as n, and USER_TAB_COLUMNS names it RAW of
        # length n, through a rename, whatever its values are. The Mirror over
        # PostgreSQL stores it as bytea, which keeps no length: it described the
        # widest value and listed a BLOB (#1386).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, r RAW(30), q RAW(5))')
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, HEXTORAW('0A0B'), HEXTORAW('01'))"
        )
        q = 'q'
        if not _conn_is_8i(self.conn):  # RENAME COLUMN arrived in 9i
            self.cur.execute(f'ALTER TABLE {self.TABLE} RENAME COLUMN q TO q2')
            q = 'q2'
        for where in ('', ' WHERE 1 = 0'):
            self.cur.execute(f'SELECT r, {q} FROM {self.TABLE}{where}')
            self.cur.fetchall()
            self.assertEqual(
                [d[2:4] for d in self.cur.description], [(30, 30), (5, 5)], where
            )
        self.cur.execute(
            'SELECT column_name, data_type, data_length FROM user_tab_columns '
            'WHERE table_name = :1 ORDER BY column_id',
            [self.TABLE],
        )
        self.assertEqual(
            self.cur.fetchall()[1:], [('R', 'RAW', 30), (q.upper(), 'RAW', 5)]
        )

    def test_float_is_a_number_of_binary_precision(self):
        # FLOAT(b), REAL and DOUBLE PRECISION are NUMBERs of binary precision b
        # -- 126 for a bare FLOAT and DOUBLE PRECISION, 63 for REAL -- that
        # describe with scale -127 and keep a 19-digit value exactly. The Mirror
        # over PostgreSQL stored them as binary floating point and described
        # BINARY_DOUBLE / BINARY_FLOAT (#1384).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (a FLOAT, b FLOAT(10), c REAL, '
            'd DOUBLE PRECISION)'
        )
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (1234567890.123456789, 1, 2, 3)'
        )
        for where in ('', ' WHERE 1 = 0'):
            self.cur.execute(f'SELECT a, b, c, d FROM {self.TABLE}{where}')
            self.cur.fetchall()
            self.assertEqual(
                [(d[1], d[4], d[5]) for d in self.cur.description],
                [(seerdb.DB_TYPE_NUMBER, bits, -127) for bits in (126, 10, 63, 126)],
                where,
            )
        self.cur.execute(
            f'SELECT COUNT(*) FROM {self.TABLE} WHERE a = 1234567890.123456789'
        )
        self.assertEqual(self.cur.fetchone(), (1,))
        self.cur.execute(
            'SELECT data_type, data_length, data_precision, data_scale '
            'FROM user_tab_columns WHERE table_name = :1 ORDER BY column_id',
            [self.TABLE],
        )
        self.assertEqual(
            self.cur.fetchall(),
            [('FLOAT', 22, bits, None) for bits in (126, 10, 63, 126)],
        )

    def test_an_nvarchar2_column_describes_as_national(self):
        # An NVARCHAR2(n) column describes as NVARCHAR, n characters and 2n bytes
        # of AL16UTF16, with rows or without, keeps its text, and
        # USER_TAB_COLUMNS lists it as NVARCHAR2 of length 2n. The Mirror over
        # PostgreSQL stored it as a varchar and described a VARCHAR2 (#1383).
        text = 'ko\u010dka \u4e2d'
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v NVARCHAR2(20), p VARCHAR2(20))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [text, 'plain'])
        for where in ('', ' WHERE 1 = 0'):
            self.cur.execute(f'SELECT v, p FROM {self.TABLE}{where}')
            self.cur.fetchall()
            self.assertEqual(
                [tuple(d)[1:4] for d in self.cur.description],
                [(seerdb.DB_TYPE_NVARCHAR, 20, 40), (seerdb.DB_TYPE_VARCHAR, 20, 20)],
                where,
            )
        self.cur.execute(f'SELECT v FROM {self.TABLE} WHERE v = :1', [text])
        self.assertEqual(self.cur.fetchall(), [(text,)])
        self.cur.execute(
            'SELECT data_type, data_length, char_length FROM user_tab_columns '
            'WHERE table_name = :1 ORDER BY column_id',
            [self.TABLE],
        )
        self.assertEqual(
            self.cur.fetchall(), [('NVARCHAR2', 40, 20), ('VARCHAR2', 20, 20)]
        )

    def test_char_and_nchar_columns_describe_as_char(self):
        # A CHAR(n) column describes as CHAR, an NCHAR(n) as NCHAR of n
        # characters and 2n bytes, with rows or without, blank-padded; the
        # dictionary lists them so. The Mirror over PostgreSQL described both as
        # VARCHAR (#1416).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (c CHAR(4), n NCHAR(5), v VARCHAR2(4))'
        )
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('ab', N'xy', 'ab')")
        for where in ('', ' WHERE 1 = 0'):
            self.cur.execute(f'SELECT c, n, v FROM {self.TABLE}{where}')
            self.cur.fetchall()
            self.assertEqual(
                [tuple(d)[1:4] for d in self.cur.description],
                [
                    (seerdb.DB_TYPE_CHAR, 4, 4),
                    (seerdb.DB_TYPE_NCHAR, 5, 10),
                    (seerdb.DB_TYPE_VARCHAR, 4, 4),
                ],
                where,
            )
        self.cur.execute(f'SELECT c, n, v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [('ab  ', 'xy   ', 'ab')])
        self.cur.execute(
            'SELECT data_type, data_length, char_length FROM user_tab_columns '
            'WHERE table_name = :1 ORDER BY column_id',
            [self.TABLE],
        )
        self.assertEqual(
            self.cur.fetchall(),
            [('CHAR', 4, 4), ('NCHAR', 10, 5), ('VARCHAR2', 4, 4)],
        )

    def test_a_cast_to_a_national_type_describes_as_national(self):
        # CAST(... AS NVARCHAR2(n) / NCHAR(n)) describes the national type, n
        # characters and 2n bytes. python-oracledb's suite measures its national
        # ratio with exactly this cast. The Mirror over PostgreSQL described a
        # plain VARCHAR of n bytes (#1440). National literals, which 8i insists
        # on (ORA-12704 otherwise).
        self.cur.execute(
            "SELECT CAST('X' AS VARCHAR2(1)), CAST(N'Y' AS NVARCHAR2(1)), "
            "CAST(N'ab' AS NCHAR(4)) c FROM dual"
        )
        self.assertEqual(self.cur.fetchall(), [('X', 'Y', 'ab  ')])
        description = [tuple(d)[1:4] for d in self.cur.description]
        self.assertEqual(
            [d[0] for d in description],
            [seerdb.DB_TYPE_VARCHAR, seerdb.DB_TYPE_NVARCHAR, seerdb.DB_TYPE_NCHAR],
        )
        if self.conn.field_version < FIELD_VERSION_10_2:
            return  # before 10g the describe carries no character length
        self.assertEqual([d[1:] for d in description], [(1, 1), (1, 2), (4, 8)])

    def test_an_unconstrained_number_column_describes_as_oracle_does(self):
        # A NUMBER column with no precision describes as precision 0 and scale
        # -127; a computed number carries neither, and a fetched value keeps its
        # kind. The Mirror over PostgreSQL gave the column neither (#1421).
        # 8i itself describes the column with neither, as a computed one.
        bare = (None, None) if _conn_is_8i(self.conn) else (0, -127)
        self.cur.execute(f'CREATE TABLE {self.TABLE} (a NUMBER, b NUMBER(10, 2))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (7, 3.25)')
        for where in ('', ' WHERE 1 = 0'):
            self.cur.execute(f'SELECT a, b, a + 1 FROM {self.TABLE}{where}')
            self.cur.fetchall()
            self.assertEqual(
                [tuple(d)[4:6] for d in self.cur.description],
                [bare, (10, 2), (None, None)],
                where,
            )
        self.cur.execute(f'SELECT a, b FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(7, 3.25)])

    def test_a_clean_logoff_commits_the_open_transaction(self):
        # A session that logs off with a transaction open, sending no rollback
        # first, has it committed, as Oracle does: sqlplus's EXIT sends only the
        # logoff and relies on it. close() rolls back while autocommit is off, so
        # turning it on just before closing logs off with the INSERT still open.
        # The Mirror dropped the transaction (#1429).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (k NUMBER)')
        other = _connect()
        try:
            other.autocommit = False
            other.cursor().execute(f'INSERT INTO {self.TABLE} VALUES (1)')
            other.autocommit = True  # close() now skips its rollback
        finally:
            other.close()
        self.cur.execute(f'SELECT k FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(1,)])

    def test_a_number_of_any_precision_is_accepted(self):
        # NUMBER(*, s) is NUMBER(38, s), rounding to s digits, and NUMBER(*) a
        # plain NUMBER. The Mirror over PostgreSQL refused both (#1443).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (d NUMBER(*, 0), f NUMBER(*, 2), e NUMBER(*))'
        )
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (12.4, 3.456, 1.5)')
        self.cur.execute(f'SELECT d, f, e FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(12, Decimal('3.46'), Decimal('1.5'))])
        self.assertEqual(
            [tuple(d)[4:6] for d in self.cur.description][:2], [(38, 0), (38, 2)]
        )

    def test_gettype_of_a_tables_rowtype(self):
        # `gettype('T%ROWTYPE')` describes a table's record type: its columns, in
        # order, as the attributes, any case and qualified or not. It used to be
        # 'not found' on every server (#1476). Its OID, which a bind of the record
        # needs, only DBMS_PICKLER gives, from 12.1.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (n NUMBER, s VARCHAR2(20), d DATE)'
        )
        typ = self.conn.gettype(f'{self.TABLE.lower()}%rowtype')
        self.assertEqual(typ.name, f'{self.TABLE}%ROWTYPE')
        self.assertEqual(typ.attr_names, ['N', 'S', 'D'])
        # Each column's metadata, as python-oracledb lists it (#1490).
        self.assertEqual(
            [(a.type, a.precision, a.scale, a.max_size) for a in typ.attributes],
            [
                (seerdb.DB_TYPE_NUMBER, 0, -127, None),
                (seerdb.DB_TYPE_VARCHAR, None, None, 20),
                (seerdb.DB_TYPE_DATE, None, None, None),
            ],
        )
        self.assertEqual(
            self.conn.gettype(f'{typ.schema}.{self.TABLE}%ROWTYPE').attr_names,
            ['N', 'S', 'D'],
        )
        if (self.conn.server_version >> 24) >= 12:
            self.assertEqual(len(typ.oid), 16)
        record = typ.newobject({'s': 'x'})
        self.assertEqual((record.N, record.S, record.D), (None, 'x', None))
        with self.assertRaises(seerdb.DatabaseError):
            self.conn.gettype('NO_SUCH_TABLE_AT_ALL%ROWTYPE')

    def test_tab_columns_describe_the_number_family_as_oracle(self):
        # A NUMBER's DATA_LENGTH is 22 whatever its precision; INTEGER, SMALLINT,
        # a bare DECIMAL and NUMBER(*, s) have no precision, only a scale. The
        # Mirror over PostgreSQL gave the precision as the length and 38 as the
        # precision of each unsized one (#1483).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (n NUMBER, n52 NUMBER(5,2), '
            'nm NUMBER(*,2), i INTEGER, si SMALLINT, dc DECIMAL, nu NUMERIC(7,1))'
        )
        self.cur.execute(
            'SELECT column_name, data_type, data_length, data_precision, data_scale '
            'FROM user_tab_columns WHERE table_name = :1 ORDER BY column_id',
            [self.TABLE],
        )
        self.assertEqual(
            self.cur.fetchall(),
            [
                ('N', 'NUMBER', 22, None, None),
                ('N52', 'NUMBER', 22, 5, 2),
                ('NM', 'NUMBER', 22, None, 2),
                ('I', 'NUMBER', 22, None, 0),
                ('SI', 'NUMBER', 22, None, 0),
                ('DC', 'NUMBER', 22, None, 0),
                ('NU', 'NUMBER', 22, 7, 1),
            ],
        )

    def test_a_literal_select_item_describes_as_char(self):
        # A string literal in a select list is CHAR of its length, as Oracle
        # describes it; a CAST to VARCHAR2 stays VARCHAR. The Mirror over
        # PostgreSQL described every literal as VARCHAR (#1494).
        self.cur.execute("SELECT 'X' a, 'abc' b, CAST('x' AS VARCHAR2(5)) c FROM dual")
        self.assertEqual(
            [(d[1], d[2]) for d in self.cur.description],
            [
                (seerdb.DB_TYPE_CHAR, 1),
                (seerdb.DB_TYPE_CHAR, 3),
                (seerdb.DB_TYPE_VARCHAR, 5),
            ],
        )
        self.assertEqual(self.cur.fetchall(), [('X', 'abc', 'x')])

    def test_autocommit_is_off_unless_asked_for(self):
        # A connection opened without `autocommit` starts with it off, as PEP 249
        # and python-oracledb have it: a row it inserted and never committed is
        # rolled back when it closes. seerdb defaulted to on until 3.0.0, and
        # such a row was kept (#1447).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (k NUMBER)')
        writer = seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            **_FV_KW,
        )
        self.assertIs(writer.autocommit, False)
        writer.cursor().execute(f'INSERT INTO {self.TABLE} VALUES (1)')
        writer.close()
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (0,))

    @_requires(_CHAR_LENGTH)
    def test_char_length_is_zero_for_a_type_without_one(self):
        # USER_TAB_COLUMNS.CHAR_LENGTH is a character column's declared length
        # and 0 for any other type, never NULL. The Mirror over PostgreSQL gave
        # NULL (#1418). 8i has no CHAR_LENGTH; 9i gives a RAW its length, so the
        # test keeps to types every version agrees on.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (n NUMBER, v VARCHAR2(20), d DATE)'
        )
        self.cur.execute(
            'SELECT column_name, char_length FROM user_tab_columns '
            'WHERE table_name = :1 ORDER BY column_id',
            [self.TABLE],
        )
        self.assertEqual(self.cur.fetchall(), [('N', 0), ('V', 20), ('D', 0)])

    @_requires(_BINARY_FLOAT_SERVER)
    def test_tab_columns_describe_binary_and_timestamp_types_as_oracle(self):
        # A TIMESTAMP's type name carries its fractional-seconds precision, which
        # is also its DATA_SCALE, and its length is that of its wire form; a
        # BINARY_FLOAT / BINARY_DOUBLE has no precision and 4 / 8 bytes. The
        # Mirror over PostgreSQL reported PostgreSQL's float precision and lost
        # the timestamps' (#1480). BINARY_FLOAT is 10g+.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (bf BINARY_FLOAT, bd BINARY_DOUBLE, '
            'ts TIMESTAMP, ts3 TIMESTAMP(3), ts0 TIMESTAMP(0), '
            'tz TIMESTAMP WITH TIME ZONE, tz2 TIMESTAMP(2) WITH TIME ZONE, '
            'ltz TIMESTAMP WITH LOCAL TIME ZONE, ltz0 TIMESTAMP(0) WITH LOCAL TIME ZONE)'
        )
        self.cur.execute(
            'SELECT column_name, data_type, data_length, data_precision, data_scale '
            'FROM user_tab_columns WHERE table_name = :1 ORDER BY column_id',
            [self.TABLE],
        )
        self.assertEqual(
            self.cur.fetchall(),
            [
                ('BF', 'BINARY_FLOAT', 4, None, None),
                ('BD', 'BINARY_DOUBLE', 8, None, None),
                ('TS', 'TIMESTAMP(6)', 11, None, 6),
                ('TS3', 'TIMESTAMP(3)', 11, None, 3),
                ('TS0', 'TIMESTAMP(0)', 7, None, 0),
                ('TZ', 'TIMESTAMP(6) WITH TIME ZONE', 13, None, 6),
                ('TZ2', 'TIMESTAMP(2) WITH TIME ZONE', 13, None, 2),
                ('LTZ', 'TIMESTAMP(6) WITH LOCAL TIME ZONE', 11, None, 6),
                ('LTZ0', 'TIMESTAMP(0) WITH LOCAL TIME ZONE', 7, None, 0),
            ],
        )

    def test_a_block_opens_a_refcursor_into_a_bind(self):
        # An anonymous block opens a REF CURSOR into a bind -- `OPEN :c FOR`, its
        # query taking IN binds of its own -- or assigns a local cursor to one.
        # The Mirror over PostgreSQL ran neither: a block is a DO block there,
        # which returns nothing (#1456).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (k NUMBER, s VARCHAR2(10))')
        for k in range(1, 7):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [k, f's{k}'])
        out = self.cur.var(seerdb.DB_TYPE_CURSOR)
        self.cur.execute(
            f'BEGIN OPEN :c FOR SELECT k, s FROM {self.TABLE} '
            'WHERE k BETWEEN :a AND :b ORDER BY k; END;',
            [out, 2, 4],
        )
        self.assertEqual(
            [tuple(r) for r in out.getvalue().fetchall()],
            [(2, 's2'), (3, 's3'), (4, 's4')],
        )
        out = self.cur.var(seerdb.DB_TYPE_CURSOR)
        self.cur.execute(
            'DECLARE t SYS_REFCURSOR; BEGIN '
            f'OPEN t FOR SELECT s FROM {self.TABLE} WHERE k = :k; :c := t; END;',
            [5, out],
        )
        self.assertEqual([tuple(r) for r in out.getvalue().fetchall()], [('s5',)])

    def test_a_cursor_expression_fetches_as_a_nested_refcursor(self):
        # A CURSOR(subquery) select-list item is a cursor per row, its query
        # naming the outer row's columns -- empty for one row here. The Mirror
        # over PostgreSQL rejected the expression as a syntax error (#1461).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (k NUMBER, s VARCHAR2(10))')
        for k in range(1, 4):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [k, f's{k}'])
        self.cur.execute(
            f'SELECT t.k, CURSOR(SELECT u.s, u.k * 10 FROM {self.TABLE} u '
            f'WHERE u.k < t.k ORDER BY u.k) c FROM {self.TABLE} t ORDER BY t.k'
        )
        self.assertIs(self.cur.description[1][1], seerdb.DB_TYPE_CURSOR)
        fetched = [(k, [tuple(r) for r in c.fetchall()]) for k, c in self.cur]
        self.assertEqual(
            fetched,
            [(1, []), (2, [('s1', 10)]), (3, [('s1', 10), ('s2', 20)])],
        )

    def test_a_literal_naming_a_type_or_keyword_stays_as_written(self):
        # A string literal is data, whatever word it holds: the dictionary's own
        # type names among them, which a query compares against. The Mirror over
        # PostgreSQL rewrote 'VARCHAR2' to 'varchar' inside the literal, and a
        # `data_type = 'VARCHAR2'` matched nothing (#1481).
        self.cur.execute(
            "SELECT 'VARCHAR2', 'NVARCHAR2(10)', 'sysdate', 'MINUS' FROM dual"
        )
        self.assertEqual(
            self.cur.fetchall(), [('VARCHAR2', 'NVARCHAR2(10)', 'sysdate', 'MINUS')]
        )
        self.cur.execute(f'CREATE TABLE {self.TABLE} (s VARCHAR2(10))')
        self.cur.execute(
            'SELECT column_name FROM user_tab_columns '
            "WHERE table_name = :1 AND data_type = 'VARCHAR2'",
            [self.TABLE],
        )
        self.assertEqual(self.cur.fetchall(), [('S',)])

    def test_a_declare_block_takes_and_returns_its_binds(self):
        # An anonymous block with declarations reads its IN binds, assigns its OUT
        # binds through locals, and returns DML's RETURNING ... INTO one -- in a
        # loop of executes too. The Mirror over PostgreSQL ran such a block with
        # its binds ignored and its declarations untranslated (#1459).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (k NUMBER, s VARCHAR2(20))')
        out = self.cur.var(int)
        self.cur.execute(
            'DECLARE t NUMBER; BEGIN t := :a * 2; :b := t + 1; END;', [20, out]
        )
        self.assertEqual(out.getvalue(), 41)
        returned = self.cur.var(seerdb.NUMBER)
        for _ in range(3):
            self.cur.execute(
                'DECLARE i NUMBER; BEGIN '
                f'SELECT NVL(COUNT(*), 0) + 1 INTO i FROM {self.TABLE}; '
                f"INSERT INTO {self.TABLE} VALUES (i, 'r' || i) RETURNING k INTO :o; END;",
                [returned],
            )
        self.assertEqual(returned.getvalue(), 3)
        length = self.cur.var(int)
        self.cur.execute(
            'DECLARE t VARCHAR2(20000); BEGIN t := :big; :n := LENGTH(t); END;',
            ['X' * 3000, length],
        )
        self.assertEqual(length.getvalue(), 3000)

    def test_integer_and_smallint_are_number_38(self):
        # INTEGER, INT and SMALLINT are NUMBER(38): 20 digits fit, and the
        # columns describe as NUMBER(38,0). A SMALLINT parameter takes an
        # integer. A Mirror-over-PG made them PostgreSQL's integers (#1326).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (a INTEGER, b SMALLINT, c INT)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (1, 2, 12345678901234567890)'
        )
        self.cur.execute(f'SELECT a, b, c FROM {self.TABLE}')
        self.assertEqual(
            [(column[4], column[5]) for column in self.cur.description],
            [(38, 0)] * 3,
        )
        self.assertEqual(self.cur.fetchall(), [(1, 2, 12345678901234567890)])
        self.cur.execute(
            'CREATE OR REPLACE FUNCTION f1326(a SMALLINT) RETURN NUMBER AS '
            'BEGIN RETURN a * 2; END;'
        )
        try:
            self.cur.execute('SELECT f1326(21) FROM dual')
            self.assertEqual(self.cur.fetchone(), (42,))
        finally:
            self.cur.execute('DROP FUNCTION f1326')

    def test_concatenating_a_null(self):
        # || reads a NULL as an empty string: only NULL || NULL is NULL, a NULL
        # number adds nothing, and a string built up from an unset variable
        # starts from nothing. A Mirror-over-PG gave NULL for any NULL (#1325).
        self.cur.execute(
            "SELECT NULL || 'ab', 'ab' || NULL, NULL || NULL, "
            "'n=' || TO_NUMBER(NULL) FROM dual"
        )
        self.assertEqual(self.cur.fetchone(), ('ab', 'ab', None, 'n='))
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v VARCHAR2(20))')
        self.cur.execute(
            'DECLARE s VARCHAR2(20); BEGIN FOR i IN 1..3 LOOP '
            f's := s || to_char(i); END LOOP; INSERT INTO {self.TABLE} VALUES (s); '
            'END;'
        )
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), ('123',))

    def test_named_arguments_bind_to_their_parameters(self):
        # Named notation binds an argument to the parameter it names, in whatever
        # order the call lists them, and each OUT value comes back to its own
        # bind. The Mirror over PostgreSQL read the names away and bound by
        # position, so a reordered call silently got wrong values (#1377).
        self.cur.execute(
            'CREATE OR REPLACE PROCEDURE pyo_p1377 '
            '(a IN NUMBER, b IN OUT NUMBER, c OUT NUMBER) AS '
            'BEGIN b := b + a; c := a * 10; END;'
        )
        try:
            b, c = self.cur.var(seerdb.NUMBER), self.cur.var(seerdb.NUMBER)
            b.setvalue(0, 5)
            self.cur.execute(
                'BEGIN pyo_p1377(c => :1, b => :2, a => :3); END;', [c, b, 2]
            )
            self.assertEqual((b.getvalue(), c.getvalue()), (7, 20))
            b.setvalue(0, 5)
            # A positional argument first, then named ones.
            self.cur.execute('BEGIN pyo_p1377(:1, c => :2, b => :3); END;', [3, c, b])
            self.assertEqual((b.getvalue(), c.getvalue()), (8, 30))
        finally:
            self.cur.execute('DROP PROCEDURE pyo_p1377')

    def test_positional_binds_follow_the_placeholders_order(self):
        # A list of bind values fills a block's placeholders in the order they
        # appear, whatever their numbers: `p(:3, c => :1, b => :2)` takes its
        # first value for :3. The Mirror over PostgreSQL read `:N` as the Nth
        # value (#1380).
        self.cur.execute(
            'CREATE OR REPLACE PROCEDURE pyo_p1380 '
            '(a IN NUMBER, b IN OUT NUMBER, c OUT NUMBER) AS '
            'BEGIN b := b + a; c := a * 10; END;'
        )
        self.cur.execute(
            'CREATE OR REPLACE FUNCTION pyo_f1380 (x IN NUMBER) RETURN NUMBER AS '
            'BEGIN RETURN x + 1; END;'
        )
        try:
            b, c = self.cur.var(seerdb.NUMBER), self.cur.var(seerdb.NUMBER)
            b.setvalue(0, 5)
            self.cur.execute('BEGIN pyo_p1380(:3, c => :1, b => :2); END;', [2, c, b])
            self.assertEqual((b.getvalue(), c.getvalue()), (7, 20))
            ret = self.cur.var(seerdb.NUMBER)
            self.cur.execute('BEGIN :2 := pyo_f1380(:1); END;', [ret, 41])
            self.assertEqual(ret.getvalue(), 42)
        finally:
            self.cur.execute('DROP PROCEDURE pyo_p1380')
            self.cur.execute('DROP FUNCTION pyo_f1380')

    def test_a_block_selects_into_binds(self):
        # A block's SELECT ... INTO takes its one row into the binds; no row is
        # ORA-01403 and more than one ORA-01422. The Mirror over PostgreSQL
        # answered ORA-00900 for every one (#1396).
        from seerdb.common.exceptions import DatabaseError

        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, s VARCHAR2(20))')
        for row in ((3, 'three'), (4, 'four')):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', row)
        n, s = self.cur.var(seerdb.NUMBER), self.cur.var(str, 20)
        self.cur.execute(
            f'BEGIN SELECT n, s INTO :n, :s FROM {self.TABLE} WHERE n = :k; END;',
            {'n': n, 's': s, 'k': 3},
        )
        self.assertEqual((n.getvalue(), s.getvalue()), (3, 'three'))
        rid = self.cur.var(str, 40)  # the rowid as text; a ROWID Var: #1397
        self.cur.execute(
            f'BEGIN SELECT rowid INTO :r FROM {self.TABLE} WHERE n = 4; END;', [rid]
        )
        self.cur.execute(
            f'SELECT s FROM {self.TABLE} WHERE rowid = :1', [rid.getvalue()]
        )
        self.assertEqual(self.cur.fetchone(), ('four',))
        for where, code in (('n = 99', 1403), ('n > 0', 1422)):
            with self.assertRaises(DatabaseError) as caught:
                self.cur.execute(
                    f'BEGIN SELECT s INTO :s FROM {self.TABLE} WHERE {where}; END;', [s]
                )
            self.assertEqual(caught.exception.code, code)

    def test_a_rowid_variable_binds_out_and_in(self):
        # A ROWID / UROWID variable binds as the rowid's text: a block fills it,
        # and it binds straight back in to find the row. The client had no bind
        # encoding for it (#1397); before 10g, 9i answered with a garbled error
        # and 8i dropped the session (#1399).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (4)')
        for typ in (seerdb.ROWID, seerdb.DB_TYPE_UROWID):
            rid = self.cur.var(typ)
            self.cur.execute(
                f'BEGIN SELECT rowid INTO :r FROM {self.TABLE} WHERE n = 4; END;', [rid]
            )
            self.assertIsInstance(rid.getvalue(), str)
            self.cur.execute(f'SELECT n FROM {self.TABLE} WHERE rowid = :r', [rid])
            self.assertEqual(self.cur.fetchall(), [(4,)], typ)

    def test_a_variable_an_out_bind_filled_binds_back_in(self):
        # A Var a block filled holds that value: bound into a statement it is
        # the value, and bound into the block again it is filled afresh. On 8i
        # it went back in as NULL, so the statement matched nothing (#1505).
        var = self.cur.var(str)
        for value in ('abc', 'xyz'):
            self.cur.execute(f"BEGIN :v := '{value}'; END;", [var])
            self.assertEqual(var.getvalue(), value)
        self.cur.execute("SELECT COUNT(*) FROM dual WHERE :v = 'xyz'", [var])
        self.assertEqual(self.cur.fetchall(), [(1,)])

    def test_callproc_of_a_procedure_without_out_parameters(self):
        # A procedure with no arguments, and one with only IN ones, run through
        # callproc like any other. The Mirror over PostgreSQL sent the first to
        # PostgreSQL as written, and fetched a result row neither returns (#1404).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER)')
        self.cur.execute(
            f'CREATE OR REPLACE PROCEDURE pyo_p1404 AS BEGIN '
            f'INSERT INTO {self.TABLE} VALUES (1); END;'
        )
        self.cur.execute(
            f'CREATE OR REPLACE PROCEDURE pyo_q1404 (a IN NUMBER) AS BEGIN '
            f'INSERT INTO {self.TABLE} VALUES (a); END;'
        )
        try:
            self.assertEqual(self.cur.callproc('pyo_p1404'), [])
            # A lone NULL is a statement, not a procedure's name.
            self.cur.execute('BEGIN NULL; END;')
            self.assertEqual(self.cur.callproc('pyo_q1404', [7]), [7])
            self.cur.execute(f'SELECT n FROM {self.TABLE} ORDER BY n')
            self.assertEqual(self.cur.fetchall(), [(1,), (7,)])
        finally:
            self.cur.execute('DROP PROCEDURE pyo_p1404')
            self.cur.execute('DROP PROCEDURE pyo_q1404')

    def test_dbms_output_round_trip(self):
        # DBMS_OUTPUT through callproc: ENABLE, PUT_LINE, then GET_LINE hands
        # the line back, status 0, and an empty buffer is status 1. The Mirror
        # over PostgreSQL could not CALL orafce's DBMS_OUTPUT, whose routines are
        # functions, and answered the ENABLE itself without running it (#1410).
        self.cur.callproc('dbms_output.enable')
        self.cur.callproc('dbms_output.put_line', ['a line of output'])
        line, status = self.cur.var(str, 255), self.cur.var(int)
        self.cur.callproc('dbms_output.get_line', [line, status])
        self.assertEqual((line.getvalue(), status.getvalue()), ('a line of output', 0))
        self.cur.callproc('dbms_output.get_line', [line, status])
        self.assertEqual(status.getvalue(), 1)

    def test_a_named_argument_given_twice_is_a_compile_error(self):
        # Oracle compiles a call naming one argument twice into PLS-00703 under
        # ORA-06550, and the session carries on. The Mirror over PostgreSQL
        # crashed on it into an ORA-00600, which clients read as a dead
        # connection (#1368).
        from seerdb.common.exceptions import DatabaseError

        self.cur.execute(
            'CREATE OR REPLACE PROCEDURE pyo_p1368 (a IN NUMBER, b OUT NUMBER) AS '
            'BEGIN b := a + 1; END;'
        )
        try:
            out = self.cur.var(seerdb.NUMBER)
            with self.assertRaises(DatabaseError) as caught:
                self.cur.execute('BEGIN pyo_p1368(a => :1, a => :2); END;', [1, out])
            self.assertEqual(caught.exception.code, 6550)
            self.assertIn('PLS-00703', str(caught.exception))
            self.cur.execute('BEGIN pyo_p1368(a => :1, b => :2); END;', [1, out])
            self.assertEqual(out.getvalue(), 2)
        finally:
            self.cur.execute('DROP PROCEDURE pyo_p1368')

    def test_dividing_integers_is_exact(self):
        # Oracle's / never truncates: integers divide exactly whether they are
        # literals, binds or an aggregate's count (#1361).
        self.cur.execute(
            'SELECT 3 / 2, 15 / 10, 4 / 2, :1 / :2, '
            '(SELECT COUNT(*) FROM (SELECT 1 FROM dual UNION ALL SELECT 2 FROM dual '
            'UNION ALL SELECT 3 FROM dual)) / 2 FROM dual',
            [7, 2],
        )
        self.assertEqual(self.cur.fetchone(), (1.5, 1.5, 2, 3.5, 1.5))

    def test_power_of_integers_is_exact(self):
        # Oracle's POWER of NUMBERs is exact, to all 20 digits of 143 ** 9, from
        # literals or binds (#1362).
        self.cur.execute(
            'SELECT POWER(143, 9), POWER(38, 12), POWER(2, -1), POWER(:1, :2) FROM dual',
            [10, 20],
        )
        self.assertEqual(self.cur.fetchone(), (143**9, 38**12, 0.5, 10**20))

    def test_a_query_casts_to_oracle_types(self):
        # CAST to an Oracle type inside a query, not only in DDL; a type no one
        # knows is ORA-00902, not a missing table (#1329); 8i reads such a cast as
        # one to a collection it cannot find (ORA-22907). BINARY_DOUBLE and
        # BINARY_FLOAT arrived in 10g.
        from seerdb.common.exceptions import DatabaseError

        self.cur.execute(
            "SELECT CAST(:1 AS NUMBER(15)), 'n=' || CAST(NULL AS NUMBER) FROM dual",
            [42],
        )
        self.assertEqual(self.cur.fetchone(), (42, 'n='))
        if self.conn.field_version >= FIELD_VERSION_10_2:
            self.cur.execute(
                'SELECT CAST(1.5 AS BINARY_DOUBLE), CAST(2.5 AS BINARY_FLOAT) FROM dual'
            )
            self.assertEqual(self.cur.fetchone(), (1.5, 2.5))
        with self.assertRaises(DatabaseError) as caught:
            self.cur.execute('SELECT CAST(1 AS no_such_type) FROM dual')
        self.assertEqual(
            caught.exception.code, 22907 if _conn_is_8i(self.conn) else 902
        )

    def test_errors_carry_their_oracle_codes(self):
        # Each of these fails with its own ORA code, which clients check by
        # number; a Mirror-over-PG reported them all as ORA-00900 (#1323).
        from seerdb.common.exceptions import DatabaseError

        def code_of(sql):
            with self.assertRaises(DatabaseError) as raised:
                self.cur.execute(sql)
            return raised.exception.code, str(raised.exception)

        self.assertEqual(code_of('SELECT 1 / 0 FROM dual')[0], 1476)
        self.assertEqual(code_of('BEGIN RAISE no_data_found; END;')[0], 1403)
        code, message = code_of(
            "BEGIN raise_application_error(-20101, 'Test (it)!'); END;"
        )
        self.assertEqual(code, 20101)
        self.assertIn('Test (it)!', message)
        self.cur.execute(f'CREATE TABLE {self.TABLE} (a NUMBER, b NUMBER)')
        self.assertEqual(code_of(f'INSERT INTO {self.TABLE} (a) VALUES (1, 2)')[0], 913)
        self.assertEqual(code_of(f'INSERT INTO {self.TABLE} (a, b) VALUES (1)')[0], 947)

    def test_rownum_filters_the_first_rows(self):
        # ROWNUM as a top-level filter, the top-N idiom over an ordered inline
        # view, and `ROWNUM = 2`, which Oracle never satisfies (#1271).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(5))')
        for i in range(1, 6):
            self.cur.execute(
                f'INSERT INTO {self.TABLE} VALUES (:1, :2)',
                [i, None if i == 2 else 'x'],
            )
        self.cur.execute(
            f'SELECT id FROM {self.TABLE} WHERE v IS NOT NULL AND ROWNUM <= 2'
        )
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 2)
        self.assertNotIn((2,), rows)
        self.cur.execute(
            f'SELECT id FROM (SELECT id FROM {self.TABLE} ORDER BY id DESC) '
            'WHERE ROWNUM < 3'
        )
        self.assertEqual(self.cur.fetchall(), [(5,), (4,)])
        self.cur.execute(f'SELECT id FROM {self.TABLE} WHERE ROWNUM = 2')
        self.assertEqual(self.cur.fetchall(), [])
        self.cur.execute(f'SELECT id FROM {self.TABLE} WHERE ROWNUM <= :1', [3])
        self.assertEqual(len(self.cur.fetchall()), 3)

    def test_a_bool_declared_number_is_stored_as_a_number(self):
        # A bool bound with a declared NUMBER type is the NUMBER 0 or 1 on every
        # server; from 23.1 it used to go out as a native BOOLEAN value, which
        # the server read as some non-zero NUMBER (#1201).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, n NUMBER)')
        for i, value in ((1, True), (2, False)):
            self.cur.setinputsizes(None, seerdb.DB_TYPE_NUMBER)
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [i, value])
        self.cur.execute(f'SELECT id, n FROM {self.TABLE} ORDER BY id')
        self.assertEqual(self.cur.fetchall(), [(1, 1), (2, 0)])

    def test_a_type_may_be_replaced_until_something_depends_on_it(self):
        # CREATE OR REPLACE TYPE replaces a type nothing depends on, and is
        # refused with ORA-02303 once another type does (#1197). The dependent is
        # a type, not a table: a dropped table stays in Oracle's recycle bin,
        # still depending on the type.
        from seerdb.common.exceptions import DatabaseError

        (obj, arr) = ('PYO_REPLACE_T', 'PYO_REPLACE_ARR_T')
        for name in (arr, obj):
            try:
                self.cur.execute(f'DROP TYPE {name}')
            except DatabaseError:
                # No leftover type from a prior run; nothing to clean up.
                pass
        self.cur.execute(f'CREATE TYPE {obj} AS OBJECT (a NUMBER)')
        try:
            self.cur.execute(
                f'CREATE OR REPLACE TYPE {obj} AS OBJECT (a NUMBER, b NUMBER)'
            )
            self.cur.execute(f'CREATE OR REPLACE TYPE {arr} AS VARRAY(3) OF {obj};')
            with self.assertRaises(DatabaseError) as ctx:
                self.cur.execute(f'CREATE OR REPLACE TYPE {obj} AS OBJECT (c NUMBER)')
            self.assertEqual(ctx.exception.code, 2303)
        finally:
            for name in (arr, obj):
                try:
                    self.cur.execute(f'DROP TYPE {name}')
                except DatabaseError:
                    # A CREATE above failed, so there is no type to drop.
                    pass

    def test_quoted_column_names_keep_their_case(self):
        # Oracle folds an unquoted name to upper case and keeps a quoted one as
        # written, whatever its case (#1204).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, all_lowercase NUMBER, '
            '"MixedCase" NUMBER, "all_lowercase_quoted" NUMBER, '
            '"ALL_UPPERCASE_QUOTED" NUMBER)'
        )
        self.cur.execute(f'SELECT * FROM {self.TABLE}')
        self.assertEqual(
            [d[0] for d in self.cur.description],
            [
                'ID',
                'ALL_LOWERCASE',
                'MixedCase',
                'all_lowercase_quoted',
                'ALL_UPPERCASE_QUOTED',
            ],
        )

    def test_untyped_null_column(self):
        # An untyped NULL is described with a zero data length and sends no
        # value; the column after it must still decode (#682, and #1185 on 9i).
        # Oracle folds a DECODE that matches nothing into the same thing.
        self.cur.execute("SELECT NULL AS a, 5 AS b, DECODE(3, 1, 'one') AS c FROM dual")
        self.assertEqual(self.cur.fetchone(), (None, 5, None))

    def test_null_number_expression_column(self):
        # A NUMBER expression that is NULL is described with a zero data length
        # as well, but its cell still carries a length. On 9i it was read as
        # an empty one: the end of the fetch went unseen and the next one was
        # ORA-01002 (#2578).
        self.cur.execute(
            'SELECT TO_NUMBER(NULL) AS a, 5 AS b, DECODE(1, 2, 3) AS c, '
            'LENGTH(NULL) AS d, NULL * 1 AS e FROM dual'
        )
        self.assertEqual(self.cur.fetchall(), [(None, 5, None, None, None)])
        self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_NUMBER)


@unittest.skipUnless(_USER, _SKIP_REASON)
class CursorIntegration(_IntegrationBase):
    """Verify the PEP 249 Cursor surface."""

    def _setup_rows(self):
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} '
            f'(id NUMBER, name VARCHAR2(40), score NUMBER(6,2))'
        )
        for row in [
            (1, 'alpha', Decimal('3.14')),
            (2, 'beta', Decimal('9.99')),
            (3, 'gamma', Decimal('100.50')),
            (4, 'delta', Decimal('-1.25')),
            (5, None, None),
        ]:
            name = 'NULL' if row[1] is None else f"'{row[1]}'"
            score = 'NULL' if row[2] is None else str(row[2])
            self.cur.execute(
                f'INSERT INTO {self.TABLE} VALUES ({row[0]}, {name}, {score})'
            )

    # ----- description -----

    def test_description_is_7_tuples(self):
        self._setup_rows()
        self.cur.execute(f'SELECT id, name, score FROM {self.TABLE}')
        self.assertIsNotNone(self.cur.description)
        for col in self.cur.description:
            self.assertEqual(len(col), 7)

    def test_description_names_are_str(self):
        self._setup_rows()
        self.cur.execute(f'SELECT id, name FROM {self.TABLE}')
        names = [c[0] for c in self.cur.description]
        self.assertEqual(names, ['ID', 'NAME'])
        for n in names:
            self.assertIsInstance(n, str)

    def test_description_precision_scale(self):
        self._setup_rows()
        self.cur.execute(f'SELECT score FROM {self.TABLE}')
        # score is NUMBER(6,2): precision=6, scale=2.
        (_, _, _, _, precision, scale, _) = self.cur.description[0]
        self.assertEqual(precision, 6)
        self.assertEqual(scale, 2)

    def test_description_none_after_ddl(self):
        # DDL doesn't produce a result set.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.assertIsNone(self.cur.description)

    # ----- rowcount -----

    def test_rowcount_select_matches(self):
        self._setup_rows()
        self.cur.execute(f'SELECT * FROM {self.TABLE}')
        self.assertEqual(self.cur.rowcount, 5)

    def test_rowcount_empty_select(self):
        self._setup_rows()
        self.cur.execute(f'SELECT * FROM {self.TABLE} WHERE id > 1000')
        self.assertEqual(self.cur.rowcount, 0)

    # ----- fetch* -----

    def test_fetchone_returns_rows_then_none(self):
        self._setup_rows()
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        self.assertEqual(self.cur.fetchone(), (1,))
        self.assertEqual(self.cur.fetchone(), (2,))
        # Drain.
        for _ in range(3):
            self.cur.fetchone()
        self.assertIsNone(self.cur.fetchone())

    def test_fetchmany_with_size(self):
        self._setup_rows()
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        batch = self.cur.fetchmany(3)
        self.assertEqual(batch, [(1,), (2,), (3,)])

    def test_fetchmany_default_arraysize(self):
        self._setup_rows()
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        self.cur.arraysize = 2
        self.assertEqual(self.cur.fetchmany(), [(1,), (2,)])

    def test_fetchmany_more_than_available(self):
        self._setup_rows()
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        rows = self.cur.fetchmany(100)
        self.assertEqual(len(rows), 5)

    def test_fetchall(self):
        self._setup_rows()
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        self.assertEqual(self.cur.fetchall(), [(1,), (2,), (3,), (4,), (5,)])

    def test_fetchall_after_partial_fetch(self):
        self._setup_rows()
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        self.cur.fetchone()
        self.assertEqual(self.cur.fetchall(), [(2,), (3,), (4,), (5,)])

    @_requires(_TIME_ZONE_SYNC)
    def test_session_timezone_synced_to_client(self):
        # #307: on 12c+ the driver sends AUTH_ALTER_SESSION at login to pin the
        # session time zone to the client's UTC offset (as oracledb / OCI /
        # sqlplus do), so SESSIONTIMEZONE / CURRENT_TIMESTAMP reflect the client,
        # not the server default. Gated to 12c+ (10g/11g's stricter auth parse
        # rejects the extra pair; no oracledb reference to match there).
        off = datetime.datetime.now().astimezone().utcoffset() or datetime.timedelta(0)
        total = int(off.total_seconds())
        sign = '+' if total >= 0 else '-'
        hh, mm = divmod(abs(total) // 60, 60)
        expected = f'{sign}{hh:02d}:{mm:02d}'
        self.cur.execute('SELECT sessiontimezone FROM dual')
        self.assertEqual(self.cur.fetchone()[0].strip(), expected)

    def test_a_query_may_start_with_a_comment(self):
        # Whether a statement is a query is read off its first word, and a
        # comment ahead of that word does not change it. Read off the raw text,
        # `/* why */ SELECT ...` was taken for DML and its rows were never
        # fetched: "no result set".
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER(9, 2), s VARCHAR2(10))')
        self.cur.execute(f"/* one row */ INSERT INTO {self.TABLE} VALUES (1.5, 'a')")
        self.cur.execute(f'/* leading */ -- and another\nSELECT n, s FROM {self.TABLE}')
        (n, text) = self.cur.fetchone()
        self.assertEqual((float(n), text), (1.5, 'a'))

    def test_a_ddl_statement_may_start_with_a_comment(self):
        # A script's statements often lead with a comment. It must not change
        # what the statement is: a backend that recognised a CREATE TABLE by its
        # first word sent `-- ...\nCREATE TABLE ... NUMBER(9, 2)` on
        # untranslated and failed on the type.
        self.cur.execute(
            f'-- the table the rest of this test reads\n'
            f'CREATE TABLE {self.TABLE} (n NUMBER(9, 2), s VARCHAR2(10))'
        )
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1.5, 'a')")
        self.cur.execute(f'SELECT n, s FROM {self.TABLE}')
        (n, text) = self.cur.fetchone()
        self.assertEqual((float(n), text), (1.5, 'a'))

    @_requires(_BINARY_FLOAT)
    def test_the_conversion_functions(self):
        # TO_BINARY_FLOAT / _DOUBLE, TO_DSINTERVAL / TO_YMINTERVAL, TO_BLOB and
        # TO_NCLOB -- a backend without them answered "function ... does not
        # exist" to the reference thin client's own suite.
        self.cur.execute(
            "SELECT TO_BINARY_DOUBLE(1.5), TO_BINARY_FLOAT('2.5'), "
            "TO_DSINTERVAL('1 02:03:04') FROM dual"
        )
        (dbl, flt, ds) = self.cur.fetchone()
        self.assertEqual((dbl, flt), (1.5, 2.5))
        self.assertEqual(ds, datetime.timedelta(days=1, hours=2, minutes=3, seconds=4))
        self.cur.execute("SELECT TO_BLOB(HEXTORAW('ABCD')), TO_NCLOB('n') FROM dual")
        (blob, nclob) = self.cur.fetchone()
        # A real server hands back LOBs, this backend the values themselves.
        self.assertEqual(blob.read() if hasattr(blob, 'read') else blob, b'\xab\xcd')
        self.assertEqual(nclob.read() if hasattr(nclob, 'read') else nclob, 'n')

    @_requires(
        _postgres_cannot('tell a computed YEAR TO MONTH interval from DAY TO SECOND')
    )
    def test_a_computed_year_to_month_interval(self):
        # PostgreSQL reports a computed domain-typed value as its base type, so
        # that backend can tell a YEAR TO MONTH interval from a DAY TO SECOND one
        # only when it comes from a column of that type.
        self.cur.execute("SELECT TO_YMINTERVAL('01-02') FROM dual")
        (ym,) = self.cur.fetchone()
        self.assertEqual((ym.years, ym.months), (1, 2))

    def test_a_view_may_be_replaced_with_different_column_types(self):
        # Oracle's CREATE OR REPLACE VIEW replaces the view whatever its new
        # columns are; PostgreSQL's refuses to change a column's type, and the
        # reference thin client's suite redefines one view per type it tests.
        from seerdb.common.exceptions import DatabaseError

        view = 'PYO_REPLACED_VIEW'
        try:
            self.cur.execute(
                f'CREATE OR REPLACE VIEW {view} AS SELECT 1 AS c FROM dual'
            )
        except DatabaseError as exc:
            if exc.code == 1031:  # ORA-01031: the suite needs no CREATE VIEW
                self.skipTest('the test user lacks the CREATE VIEW privilege')
            raise
        try:
            self.cur.execute(
                f"CREATE OR REPLACE VIEW {view} AS SELECT 'x' AS c FROM dual"
            )
            self.cur.execute(f'SELECT c FROM {view}')
            self.assertEqual(self.cur.fetchone(), ('x',))
        finally:
            self.cur.execute(f'DROP VIEW {view}')

    def test_a_view_column_keeps_its_base_columns_type(self):
        # A view's column describes and lists as the table column it comes from:
        # a RAW(n) keeps its n through a view, and through a view over that
        # view. The Mirror over PostgreSQL recorded the type for the table alone
        # (#1425).
        from seerdb.common.exceptions import DatabaseError

        inner, outer = 'PYO_TYPED_VIEW', 'PYO_TYPED_VIEW2'
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, r RAW(30))')
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, HEXTORAW('0102'))")
        try:
            self.cur.execute(
                f'CREATE OR REPLACE VIEW {inner} (a, b) AS SELECT id, r FROM {self.TABLE}'
            )
        except DatabaseError as exc:
            if exc.code == 1031:  # ORA-01031: the suite needs no CREATE VIEW
                self.skipTest('the test user lacks the CREATE VIEW privilege')
            raise
        try:
            self.cur.execute(f'CREATE OR REPLACE VIEW {outer} AS SELECT b FROM {inner}')
            for view in (inner, outer):
                self.cur.execute(f'SELECT b FROM {view}')
                self.cur.fetchall()
                self.assertEqual(self.cur.description[0][2:4], (30, 30), view)
                self.cur.execute(
                    'SELECT data_type, data_length FROM user_tab_columns '
                    "WHERE table_name = :1 AND column_name = 'B'",
                    [view],
                )
                self.assertEqual(self.cur.fetchall(), [('RAW', 30)], view)
        finally:
            self.cur.execute(f'DROP VIEW {outer}')
            self.cur.execute(f'DROP VIEW {inner}')

    def test_returning_into_inside_a_plsql_block(self):
        # A block wrapping a DML with RETURNING ... INTO: the returned value
        # goes to the OUT bind, and a statement that matched no row leaves it
        # NULL (#1209).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, n NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, 10)')
        block = (
            f'BEGIN UPDATE {self.TABLE} SET n = :1 WHERE id = :2 '
            'RETURNING n INTO :3; END;'
        )
        out = self.cur.var(int)
        self.cur.execute(block, [20, 1, out])
        self.assertEqual(out.getvalue(), 20)
        out = self.cur.var(int)
        self.cur.execute(block, [30, 2, out])
        self.assertIsNone(out.getvalue())

    def test_an_anonymous_block_with_local_functions(self):
        # A block may declare its own functions, one calling another, ended by
        # END or END <name>. A Mirror-over-PG refused the block (#1322).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(20))')
        self.cur.execute(
            'declare\n'
            '    t_Label varchar2(20);\n'
            '    function twice(a number) return number is\n'
            '    begin\n'
            '        return a * 2;\n'
            '    end;\n'
            '    function label(a number) return varchar2 is\n'
            "        s varchar2(20) := 'n';\n"
            '    begin\n'
            '        for i in 1..a loop\n'
            "            s := s || '+';\n"
            '        end loop;\n'
            '        return s || to_char(twice(a));\n'
            '    end label;\n'
            'begin\n'
            '    for i in 1..3 loop\n'
            '        t_Label := label(i);\n'
            f'        insert into {self.TABLE} values (i, t_Label);\n'
            '    end loop;\n'
            'end;'
        )
        self.cur.execute(f'SELECT id, v FROM {self.TABLE} ORDER BY id')
        self.assertEqual(self.cur.fetchall(), [(1, 'n+2'), (2, 'n++4'), (3, 'n+++6')])

    def test_userenv_service_name_is_the_service_connected_to(self):
        # USERENV SERVICE_NAME names the service the session connected to. The
        # Mirror over PostgreSQL answered NULL, and its login named none (#1409).
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute("SELECT sys_context('userenv', 'service_name') FROM dual")
        except DatabaseError as exc:
            if exc.code == 2003:
                self.skipTest('no USERENV SERVICE_NAME on this version')
            raise
        (service,) = self.cur.fetchone()
        self.assertIsNotNone(service)
        if os.environ.get('SEERDB_TEST_MIRROR') == 'passthrough':
            return  # the upstream session's service, not the one asked of the Mirror
        # A service can be registered with a domain (orcl.example.com); the
        # name connected with is its first part.
        self.assertEqual(service.split('.')[0].upper(), _SERVICE.split('.')[0].upper())

    def test_v_parameter_names_the_instance_parameters(self):
        # V$PARAMETER answers open_cursors and db_domain. On the Mirror over
        # PostgreSQL they are what its login reports -- AUTH_MAX_OPEN_CURSORS
        # (300) and no domain -- which a client compares them with (#1353).
        # Reading the V$ views takes a privilege the test user may lack.
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute(
                'SELECT name, value FROM v$parameter WHERE name IN '
                "('open_cursors', 'db_domain') ORDER BY name"
            )
        except DatabaseError as exc:
            if exc.code == 942 and os.environ.get('SEERDB_TEST_MIRROR') != 'postgres':
                self.skipTest('the test user cannot read V$PARAMETER')
            raise
        rows = dict(self.cur.fetchall())
        self.assertEqual(set(rows), {'db_domain', 'open_cursors'})
        self.assertGreater(int(rows['open_cursors']), 0)
        if os.environ.get('SEERDB_TEST_MIRROR') == 'postgres':
            self.assertEqual(rows, {'open_cursors': '300', 'db_domain': None})

    def test_v_database_names_the_database(self):
        # V$DATABASE names the database. On the Mirror over PostgreSQL that is the
        # backend database, upper-cased, as the login reports it as db_name
        # (#1354). Reading the V$ views takes a privilege the test user may lack;
        # 8i has no DB_UNIQUE_NAME, so the test reads the columns every version has.
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute('SELECT name, dbid FROM v$database')
        except DatabaseError as exc:
            if exc.code == 942 and os.environ.get('SEERDB_TEST_MIRROR') != 'postgres':
                self.skipTest('the test user cannot read V$DATABASE')
            raise
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 1)
        name, dbid = rows[0]
        self.assertTrue(name)
        self.assertGreater(dbid, 0)
        dbname = re.search(r'dbname=(\S+)', os.environ.get('MIRROR_PG', ''))
        if os.environ.get('SEERDB_TEST_MIRROR') == 'postgres' and dbname:
            self.assertEqual(name, dbname.group(1).upper())

    def test_v_sesstat_counts_the_round_trips(self):
        # Another session reads this one's round trips from V$SESSTAT, one per
        # call, as Oracle counts them (#1324). Reading the V$ views takes a
        # privilege the test user may lack, and before 10g USERENV has no SID.
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute("SELECT sys_context('userenv', 'sid') FROM dual")
        except DatabaseError as exc:
            if exc.code == 2003:
                self.skipTest('no USERENV SID before 10g')
            raise
        (sid,) = self.cur.fetchone()
        reader = _connect()
        try:
            cur = reader.cursor()

            def round_trips():
                cur.execute(
                    'SELECT ss.value FROM v$sesstat ss, v$statname sn '
                    'WHERE ss.sid = :1 AND ss.statistic# = sn.statistic# '
                    "AND sn.name = 'SQL*Net roundtrips to/from client'",
                    [sid],
                )
                return cur.fetchone()[0]

            try:
                before = round_trips()
            except DatabaseError as exc:
                # The Mirror over PostgreSQL serves V$SESSTAT to every user.
                if (
                    exc.code == 942
                    and os.environ.get('SEERDB_TEST_MIRROR') != 'postgres'
                ):
                    self.skipTest('the test user cannot read V$SESSTAT')
                raise
            self.conn.ping()
            self.assertEqual(round_trips() - before, 1)
            self.conn.commit()
            self.assertEqual(round_trips() - before, 2)
        finally:
            reader.close()

    def test_the_session_id_is_the_sid_sql_reports(self):
        # A client reads its session id and serial from the login reply alone,
        # and SQL names the same session (#1212, #1218). Before 10g USERENV has
        # no SID (ORA-02003), and the login carries neither.
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute("SELECT sys_context('userenv', 'sid') FROM dual")
        except DatabaseError as exc:
            if exc.code == 2003:
                self.skipTest('no USERENV SID before 10g')
            raise
        (sid,) = self.cur.fetchone()
        # Both are ints, as python-oracledb gives them (#1218).
        self.assertIsInstance(self.conn.session_id, int)
        self.assertIsInstance(self.conn.serial_num, int)
        self.assertEqual(self.conn.session_id, int(sid))
        # The id and serial are the ones the server names the session by, read
        # through the package that needs no privilege (#1355).
        self.cur.execute(
            'SELECT dbms_debug_jdwp.current_session_id, '
            'dbms_debug_jdwp.current_session_serial FROM dual'
        )
        self.assertEqual(
            self.cur.fetchone(), (self.conn.session_id, self.conn.serial_num)
        )

    def test_an_error_after_the_first_rows_is_raised(self):
        # The third row divides by zero. 8i ended the fetch on the failed
        # fetch's empty reply and returned the first row as the result,
        # raising nothing (#2314).
        from seerdb.common.exceptions import DatabaseError

        with self.assertRaisesRegex(DatabaseError, 'ORA-01476'):
            self.cur.execute(
                'SELECT 1 / (n - 3) FROM (SELECT 1 n FROM dual UNION ALL '
                'SELECT 2 FROM dual UNION ALL SELECT 3 FROM dual UNION ALL '
                'SELECT 4 FROM dual)'
            )
            self.cur.fetchall()

    def test_an_error_a_fetch_meets_has_its_message(self):
        # 9i raised an error its fetch met from the code alone: `ORA-01476`
        # with no text (#2315).
        from seerdb.common.exceptions import DatabaseError

        with self.assertRaisesRegex(DatabaseError, r'^ORA-01476: \w'):
            self.cur.execute('SELECT 1 / 0 FROM dual')
            self.cur.fetchall()

    def test_a_query_of_300_columns(self):
        # 9i read its describe's column count as one byte: past 255 columns it
        # described one, and the fetch failed with ORA-03115 (#2306).
        self.cur.execute(
            'SELECT '
            + ', '.join(f"{i} n{i}, 'v{i}' s{i}" for i in range(150))
            + ' FROM dual'
        )
        self.assertEqual(len(self.cur.description), 300)
        self.assertEqual(
            self.cur.fetchone(), tuple(v for i in range(150) for v in (i, f'v{i}'))
        )

    def test_a_statement_takes_more_than_255_binds(self):
        # 9i wrote the bind count before the SQL as one byte, and the client
        # raised on a 256th bind before sending anything (#2305). Ones, so the
        # sum stays in a smallint, which the Mirror over PostgreSQL adds
        # small integer binds as (#2307).
        self.cur.execute(
            'SELECT ' + ' + '.join(f':{i + 1}' for i in range(300)) + ' FROM dual',
            [1] * 300,
        )
        self.assertEqual(self.cur.fetchall(), [(300,)])

    def test_a_block_of_300_binds_follows_their_directions(self):
        # A Var the block only reads is an IN bind. 9i and 8i read the bind
        # prompt's count as its low byte, so past 255 binds the client guessed
        # the directions, took that Var for an OUT one, and shifted the values
        # back: 9i gave v 303 and r garbage, 8i a malformed NUMBER (#2311).
        v = self.cur.var(int)
        v.setvalue(0, 5)
        r = self.cur.var(int)
        ones = ' + '.join(f':{i}' for i in range(3, 301))
        self.cur.execute(
            f'BEGIN IF :1 IS NULL THEN NULL; END IF; :2 := :1 + {ones}; END;',
            [v, r] + [1] * 298,
        )
        self.assertEqual((v.getvalue(), r.getvalue()), (5, 303))

    def test_a_session_outlasts_open_cursors(self):
        # More statements than the beds' open_cursors (300), of each kind that
        # takes a cursor on 8i: a query, a block with and without an OUT bind, a
        # refused query, a COMMIT. 8i kept every one open and the session failed
        # with ORA-01000 (#2286), and 9i did too when they alternated (#2288).
        # Before that, cursor ids past 255 cut the next query to its first row
        # (#2285), whose byte order the offline test pins now that closed
        # cursors keep the ids low.
        from seerdb.common.exceptions import DatabaseError

        out = self.cur.var(int)
        for n in range(80):
            self.cur.execute('SELECT 1 FROM dual')
            self.cur.fetchall()
            self.cur.execute('BEGIN NULL; END;')
            self.cur.execute('BEGIN :1 := :2; END;', [out, n])
            self.assertEqual(out.getvalue(), n)
            with self.assertRaises(DatabaseError):
                self.cur.execute('SELECT * FROM no_such_table_2286')
            self.conn.commit()
        for _ in range(2):
            # 50 rows, more than one fetch: a ROWNUM filter alone, which the
            # Mirror over PostgreSQL translates, and no CONNECT BY LEVEL, which
            # gives one row on 8i.
            self.cur.execute('SELECT object_id FROM all_objects WHERE rownum <= 50')
            self.assertEqual(len(set(self.cur.fetchall())), 50)

    def test_a_long_out_value_reads_from_every_packet(self):
        # A 4000-character OUT value's reply is three packets on 8i, none
        # marked last. Read from its first alone, the block failed whenever the
        # rest had not arrived yet -- about one call in two -- and the rest
        # answered the next call (#2334). Ten calls, each followed by another.
        out = self.cur.var(str, 4000)
        value = 'o' + 'p' * 3999
        for _ in range(10):
            self.cur.execute('BEGIN :1 := :2; END;', [out, value])
            self.assertEqual(out.getvalue(), value)
            self.cur.execute('SELECT 42 FROM dual')
            self.assertEqual(self.cur.fetchone(), (42,))

    def test_a_refcursor_per_call_outlasts_open_cursors(self):
        # A block that returns a REF CURSOR, more times than open_cursors: 9i
        # closed each one after reading it but never freed it (#2288), and from
        # 10g the client never closed one at all (#2291), so every call left a
        # cursor open and the session failed with ORA-01000.
        for n in range(320):
            rc = self.cur.var(seerdb.DB_TYPE_CURSOR)
            self.cur.execute('BEGIN OPEN :1 FOR SELECT :2 FROM dual; END;', [rc, n])
            self.assertEqual(rc.getvalue().fetchall(), [(n,)])

    @_requires(_IMPLICIT_RESULTS)
    def test_implicit_results_outlast_open_cursors(self):
        # More implicit result sets than open_cursors (300): each one read was
        # left open on the server, and the session failed with ORA-01000
        # (#2291).
        for n in range(320):
            self.cur.execute(
                'DECLARE c SYS_REFCURSOR; BEGIN OPEN c FOR SELECT :1 FROM dual; '
                'DBMS_SQL.RETURN_RESULT(c); END;',
                [n],
            )
            self.assertTrue(self.cur.nextset())
            self.assertEqual(self.cur.fetchall(), [(n,)])

    @_requires(_IMPLICIT_RESULTS)
    def test_a_block_returns_out_binds_and_implicit_results(self):
        # A block with binds and an implicit result set: through the passthrough
        # Mirror the set was lost, and a Mirror sent either the OUT values or
        # the set, never both. A server sends the values, then the set (#2295).
        out = self.cur.var(int)
        self.cur.execute(
            'DECLARE c SYS_REFCURSOR; BEGIN :1 := :2 + 1; '
            'OPEN c FOR SELECT :2 FROM dual; DBMS_SQL.RETURN_RESULT(c); END;',
            [out, 7],
        )
        self.assertEqual(out.getvalue(), 8)
        self.assertTrue(self.cur.nextset())
        self.assertEqual(self.cur.fetchall(), [(7,)])
        self.assertIsNone(self.cur.nextset())

    def test_the_version_is_the_release_the_banner_names(self):
        # Every tier reports its release, 8i and 9i too: 8i's login reply
        # carries it, and 9i is asked once after login, as ojdbc14 asks (#2278).
        # From 18c the banner names the base release (23.0.0.0.0) and the
        # version the release update, so only the major is compared there.
        self.assertEqual(
            self.conn.version, _banner_release(self.cur, self.conn.version)
        )

    def test_transaction_priority(self):
        # 23ai's priority transactions (#1776): the value the server reports at
        # login, a change sent with the next call, a reset to the default, and an
        # ALTER SESSION in SQL, each as the server reports it back. Before 23ai
        # the attribute and the connect option are refused.
        from seerdb.common.exceptions import NotSupportedError

        kwargs = dict(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            **_FV_KW,
        )
        if not self.conn._supports_txn_priority():
            with self.assertRaises(NotSupportedError):
                self.conn.transaction_priority
            with self.assertRaises(NotSupportedError):
                seerdb.connect(**kwargs, transaction_priority='low')
            return
        P = seerdb.TransactionPriority
        default = self.conn.transaction_priority
        self.assertIsInstance(default, P)
        self.conn.transaction_priority = 'low'
        self.conn.ping()
        self.assertIs(self.conn.transaction_priority, P.LOW)
        self.conn.transaction_priority = None
        self.conn.ping()
        self.assertIs(self.conn.transaction_priority, default)
        self.cur.execute('ALTER SESSION SET TXN_PRIORITY = MEDIUM')
        self.assertIs(self.conn.transaction_priority, P.MEDIUM)
        with seerdb.connect(**kwargs, transaction_priority=P.LOW) as conn:
            self.assertIs(conn.transaction_priority, P.LOW)

    def test_app_context_rides_the_next_call(self):
        # set_app_context() / clear_app_context() reach the server with the next
        # call, a ping included, and a namespace the session may not set fails
        # that call (#1775). 8i and 9i ignore the piggyback, so it is refused.
        from seerdb.common.exceptions import DatabaseError, NotSupportedError
        from seerdb.common.tns_consts import FIELD_VERSION_10_2

        if self.conn.field_version < FIELD_VERSION_10_2:
            with self.assertRaises(NotSupportedError):
                self.conn.set_app_context('CLIENTCONTEXT', ATTR1='VALUE1')
            return
        query = (
            "SELECT sys_context('CLIENTCONTEXT', 'ATTR1'), "
            "sys_context('CLIENTCONTEXT', 'ATTR2') FROM dual"
        )
        self.conn.set_app_context('CLIENTCONTEXT', ATTR1='VALUE1')
        self.conn.set_app_context('CLIENTCONTEXT', ATTR2='VALUE2')
        self.cur.execute(query)
        self.assertEqual(self.cur.fetchone(), ('VALUE1', 'VALUE2'))
        self.conn.clear_app_context('CLIENTCONTEXT')
        self.cur.execute(query)
        self.assertEqual(self.cur.fetchone(), (None, None))
        self.conn.set_app_context('CLIENTCONTEXT', ATTR1='PING')
        self.conn.ping()
        self.cur.execute(query)
        self.assertEqual(self.cur.fetchone(), ('PING', None))
        self.conn.set_app_context('NOT_A_VALID_NAMESPACE', attr='value')
        with self.assertRaises(DatabaseError) as raised:
            self.conn.ping()
        self.assertEqual(raised.exception.code, 28267)
        self.cur.execute('SELECT 1 FROM dual')
        self.assertEqual(self.cur.fetchone(), (1,))

    def test_a_refused_commit_raises(self):
        # A deferred constraint is checked at commit; a violation rolls the
        # transaction back and says so only in the commit's reply, which commit()
        # used to drop, reporting success for data that was gone (#1786).
        from seerdb.common.exceptions import DatabaseError

        table = 'SEERDB_DEFER'
        try:
            self.cur.execute(f'DROP TABLE {table}')
        except DatabaseError as exc:
            if exc.code != 942:
                raise
        self.cur.execute(
            f'CREATE TABLE {table} (id NUMBER CONSTRAINT {table}_PK PRIMARY KEY '
            'DEFERRABLE INITIALLY DEFERRED)'
        )
        try:
            self.conn.autocommit = False
            self.cur.execute(f'INSERT INTO {table} VALUES (1)')
            self.cur.execute(f'INSERT INTO {table} VALUES (1)')
            with self.assertRaises(DatabaseError) as raised:
                self.conn.commit()
            self.assertEqual(raised.exception.code, 2091)
            self.cur.execute(f'SELECT COUNT(*) FROM {table}')
            self.assertEqual(self.cur.fetchone(), (0,))
            # The session carries on: a good commit and a rollback still work.
            self.cur.execute(f'INSERT INTO {table} VALUES (2)')
            self.conn.commit()
            self.conn.rollback()
        finally:
            self.cur.execute(f'DROP TABLE {table}')

    def test_transaction_in_progress_follows_the_server(self):
        # The TXN_IN_PROGRESS bit of each reply's call status (#2456): a DML
        # sets it, and a commit's or a rollback's bare status reply clears it.
        # Before 10g seerdb doesn't read it, and says so.
        from seerdb.common.exceptions import DatabaseError

        with seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            **_FV_KW,
        ) as conn:
            if conn.field_version < FIELD_VERSION_10_2:
                with self.assertRaises(seerdb.NotSupportedError):
                    conn.transaction_in_progress
                return
            cur = conn.cursor()
            table = 'PYO_TXN_IN_PROGRESS'
            try:
                cur.execute(f'DROP TABLE {table}')
            except DatabaseError:
                pass  # not left over from an earlier run
            cur.execute(f'CREATE TABLE {table} (n NUMBER)')
            try:
                self.assertFalse(conn.transaction_in_progress)
                cur.execute(f'INSERT INTO {table} VALUES (1)')
                self.assertTrue(conn.transaction_in_progress)
                conn.commit()
                self.assertFalse(conn.transaction_in_progress)
                cur.execute(f'UPDATE {table} SET n = 2')
                self.assertTrue(conn.transaction_in_progress)
                conn.rollback()
                self.assertFalse(conn.transaction_in_progress)
                cur.execute(f'SELECT n FROM {table}')
                self.assertEqual(cur.fetchall(), [(1,)])
                self.assertFalse(conn.transaction_in_progress)
            finally:
                cur.execute(f'DROP TABLE {table}')

    def test_the_login_reply_names_the_instance_and_identifier_limit(self):
        # From the login reply alone (#2456): the instance's name, as SQL
        # reports it, and the longest identifier, which 12.2 and later send
        # (128) to a session at field version 12.2 or later, and nothing before.
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute("SELECT sys_context('userenv', 'instance_name') FROM dual")
        except DatabaseError as exc:
            if exc.code != 2003:
                raise
            self.assertIsNone(self.conn.instance_name)
        else:
            self.assertEqual(self.conn.instance_name, self.cur.fetchone()[0])
        # The server tells a session at field version 12.2 or later; a 23ai
        # tells a 12.1 session nothing.
        if self.conn.field_version >= FIELD_VERSION_12_2:
            self.assertEqual(self.conn.max_identifier_length, 128)
        else:
            self.assertIsNone(self.conn.max_identifier_length)

    def test_an_unknown_service_name_is_refused(self):
        # A listener refuses a SERVICE_NAME it doesn't serve with ORA-12514:
        # measured on 10g, 11g, 18c, 21c and 23ai. The Mirror served any
        # (#2471).
        from seerdb.common.exceptions import DatabaseError

        with self.assertRaises(DatabaseError) as raised:
            seerdb.connect(
                host=_HOST,
                port=_PORT,
                user=_USER,
                password=_PASSWORD,
                service_name='SEERDB_NO_SUCH_SERVICE',
                **_FV_KW,
            )
        self.assertEqual(raised.exception.code, 12514)

    def test_an_unknown_instance_name_is_refused(self):
        # A listener refuses (INSTANCE_NAME=...) naming an instance it doesn't
        # know, with ORA-12521: measured on 9i, 10g, 11g and 23ai (#2456). The
        # Mirror served any (#2471).
        from seerdb.common.exceptions import DatabaseError

        with self.assertRaises(DatabaseError) as raised:
            _connect_with(instance_name='SEERDB_NO_SUCH_INSTANCE')
        self.assertEqual(raised.exception.code, 12521)

    def test_instance_name_reaches_that_instance(self):
        # (INSTANCE_NAME=...) in CONNECT_DATA (#2456): the listener hands the
        # session to the instance named.
        from seerdb.common.exceptions import DatabaseError

        with _connect_with() as conn:
            cur = conn.cursor()
            try:
                cur.execute("SELECT sys_context('userenv', 'instance_name') FROM dual")
            except DatabaseError as exc:
                if exc.code != 2003:
                    raise
                self.skipTest('USERENV names no instance before 10g')
            (instance,) = cur.fetchone()
        with _connect_with(instance_name=instance) as conn:
            cur = conn.cursor()
            cur.execute("SELECT sys_context('userenv', 'instance_name') FROM dual")
            self.assertEqual(cur.fetchone(), (instance,))

    def test_expire_time_turns_keepalive_on(self):
        # expire_time (#2456): TCP keepalive on the socket, after that many
        # minutes of quiet, and (EXPIRE_TIME=n) in the descriptor, which the
        # server takes.
        import socket

        with _connect_with(expire_time=2) as conn:
            sock = conn.sock
            self.assertEqual(sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE), 1)
            idle = getattr(socket, 'TCP_KEEPIDLE', None)
            if idle is not None:
                self.assertEqual(sock.getsockopt(socket.IPPROTO_TCP, idle), 120)
            conn.cursor().execute('SELECT 1 FROM dual')
        with _connect_with() as conn:
            self.assertEqual(
                conn.sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE), 0
            )

    def test_is_healthy_needs_no_round_trip(self):
        # True on an open connection, False once closed (#2456).
        with _connect_with() as conn:
            self.assertTrue(conn.is_healthy())
            conn.close()
            self.assertFalse(conn.is_healthy())

    def test_db_unique_name_is_the_one_sql_reports(self):
        # Read from the login reply alone, as python-oracledb 26 reads it, and
        # equal to what SQL reports (#1774). Before 10g USERENV has no
        # DB_UNIQUE_NAME (ORA-02003), and the login carries none.
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute(
                "SELECT sys_context('userenv', 'db_unique_name') FROM dual"
            )
        except DatabaseError as exc:
            if exc.code != 2003:
                raise
            self.assertIsNone(self.conn.db_unique_name)
            return
        self.assertEqual(self.conn.db_unique_name, self.cur.fetchone()[0])

    def test_v_session_shows_the_identity_the_client_declared(self):
        # v$session and v$session_connect_info show this session as its login
        # declared it (#1212); the terminal is left out, since a login in the
        # pre-12c shape declares none. Reading them needs SELECT on v$session
        # (tools/test_bed_setup.sql grants it); without it the test skips.
        from seerdb.common.exceptions import DatabaseError

        with _connect_with(
            program='pyo-program',
            machine='pyo-machine',
            terminal='pyo-terminal',
            osuser='pyo-osuser',
            driver_name='pyo-driver',
        ) as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    'SELECT program, machine, osuser FROM v$session '
                    "WHERE sid = sys_context('userenv', 'sid')"
                )
            except DatabaseError as exc:
                if exc.code in (942, 2003):
                    self.skipTest(f'v$session not readable: ORA-{exc.code:05d}')
                raise
            self.assertEqual(
                cur.fetchall(),
                [('pyo-program', 'pyo-machine', 'pyo-osuser')],
            )
            if int(conn.version.split('.')[0]) < 11:
                return  # v$session_connect_info has no CLIENT_DRIVER before 11g
            if _FV_KW.get('server_type') == 'pooled':
                # A DRCP session's v$session_connect_info is its pooled server
                # process's, which keeps the details of the client that first
                # attached to it, whoever runs on it now (#2466).
                return
            cur.execute(
                'SELECT DISTINCT client_driver FROM v$session_connect_info '
                "WHERE sid = sys_context('userenv', 'sid')"
            )
            # The driver name travels only in the 23ai-shaped login (fv > 23.1).
            driver = (
                'pyo-driver' if conn.field_version >= FIELD_VERSION_23_1_EXT_1 else None
            )
            self.assertEqual(cur.fetchall(), [(driver,)])

    def test_a_descriptor_over_230_bytes_connects(self):
        # A server reads at most 230 bytes of connect data from the CONNECT; a
        # longer descriptor hung the connect on every bed until it went out in
        # a DATA packet of its own (#1768). The program name takes this one past.
        with _connect_with(app_name='p' * 200) as conn:
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM dual')
            self.assertEqual(cur.fetchone(), (1,))

    def test_an_easy_connect_dsn_names_the_address(self):
        # connect(dsn='host:port/service') without a wallet used to drop the dsn
        # and dial localhost:1521 (#1972). The DSN wins over a host passed beside
        # it, as in python-oracledb.
        with seerdb.connect(
            user=_USER,
            password=_PASSWORD,
            dsn=f'{_HOST}:{_PORT}/{_SERVICE}',
            host='nowhere.invalid',
            **_FV_KW,
        ) as conn:
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM dual')
            self.assertEqual(cur.fetchone(), (1,))

    def test_a_connect_descriptor_dsn_names_the_address(self):
        # A descriptor with one address, as python-oracledb reads it (#1976).
        descriptor = (
            f'(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={_HOST})(PORT={_PORT}))'
            f'(CONNECT_DATA=(SERVICE_NAME={_SERVICE})(CID=(PROGRAM=pyo))))'
        )
        with seerdb.connect(
            user=_USER, password=_PASSWORD, dsn=descriptor, **_FV_KW
        ) as conn:
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM dual')
            self.assertEqual(cur.fetchone(), (1,))

    def test_a_tnsnames_alias_dsn_names_the_address(self):
        # A tnsnames alias from config_dir, no wallet, as python-oracledb reads
        # it (#1976).
        with tempfile.TemporaryDirectory() as config_dir:
            with open(os.path.join(config_dir, 'tnsnames.ora'), 'w') as f:
                f.write(_alias_entry('pyo_bed'))
            with seerdb.connect(
                user=_USER,
                password=_PASSWORD,
                dsn='pyo_bed',
                config_dir=config_dir,
                **_FV_KW,
            ) as conn:
                cur = conn.cursor()
                cur.execute('SELECT 1 FROM dual')
                self.assertEqual(cur.fetchone(), (1,))

    def test_a_server_type_connects(self):
        # server_type (#1977): dedicated anywhere; pooled asks for DRCP, which a
        # server only serves once its pool is started (ORA-12520 otherwise).
        # Before 11g there is no DRCP and the listener ignores SERVER=pooled.
        for kind in ('dedicated', 'pooled'):
            with self.subTest(server_type=kind):
                try:
                    conn = seerdb.connect(
                        user=_USER,
                        password=_PASSWORD,
                        host=_HOST,
                        port=_PORT,
                        service_name=_SERVICE,
                        **{**_FV_KW, 'server_type': kind},
                    )
                except seerdb.DatabaseError as e:
                    if kind == 'pooled' and getattr(e, 'code', None) == 12520:
                        self.skipTest('the DRCP pool is not started on this server')
                    raise
                with conn:
                    cur = conn.cursor()
                    cur.execute('SELECT 1 FROM dual')
                    self.assertEqual(cur.fetchone(), (1,))

    def test_a_pool_boundary_connects(self):
        # pool_boundary (#2542) asks a 23ai DRCP pool for implicit pooling; an
        # older server and a dedicated one ignore it. Under it the server
        # answers with a two-byte call status, which hung a LOB read (#2540).
        for boundary in ('statement', 'transaction'):
            with self.subTest(pool_boundary=boundary):
                try:
                    conn = seerdb.connect(
                        user=_USER,
                        password=_PASSWORD,
                        host=_HOST,
                        port=_PORT,
                        service_name=_SERVICE,
                        **{
                            **_FV_KW,
                            'server_type': 'pooled',
                            'pool_boundary': boundary,
                        },
                    )
                except seerdb.DatabaseError as e:
                    if getattr(e, 'code', None) == 12520:
                        self.skipTest('the DRCP pool is not started on this server')
                    raise
                with conn:
                    cur = conn.cursor()
                    for _ in range(2):
                        cur.execute('SELECT 1 FROM dual')
                        self.assertEqual(cur.fetchone(), (1,))
                    if _target_is_8i():
                        continue  # 8i has no TO_CLOB, and no DRCP to test
                    cur.execute("SELECT TO_CLOB(RPAD('x', 3000, 'x')) FROM dual")
                    lob = cur.fetchone()[0]
                    text = lob if isinstance(lob, str) else lob.read()
                    self.assertEqual(text, 'x' * 3000)

    def test_an_aggregate_over_a_null_group(self):
        # An aggregate that skipped NULLs makes the server set a warning in the
        # closing status, a field that before 12.1 is a ub2; read as one byte
        # it desynced the reply on 11g (#1995).
        t = self.TABLE
        self.cur.execute(f'CREATE TABLE {t} (g NUMBER, n NUMBER)')
        for g, n in _NULL_GROUP_ROWS:
            self.cur.execute(f'INSERT INTO {t} VALUES ({g}, {n})')
        self.cur.execute(f'SELECT g, AVG(n), COUNT(n) FROM {t} GROUP BY g ORDER BY g')
        self.assertEqual(
            self.cur.fetchall(),
            _NULL_GROUP_AVERAGES,
        )
        self.cur.execute('SELECT 1 FROM dual')  # and the session reads on
        self.assertEqual(self.cur.fetchone(), (1,))

    def test_easy_connect_parameters_apply(self):
        # ? parameters with a seerdb argument (#1977): sdu, the transport
        # timeout, a connection class and purity.
        with seerdb.connect(
            user=_USER,
            password=_PASSWORD,
            dsn=f'{_HOST}:{_PORT}/{_SERVICE}?sdu=16384&transport_connect_timeout=10',
            **_FV_KW,
        ) as conn:
            # The SDU is what the server agreed to, at most the one asked for.
            self.assertEqual(conn.timeout, 10000)
            self.assertLessEqual(conn.sdu, 16384)
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM dual')
            self.assertEqual(cur.fetchone(), (1,))

    def test_a_descriptor_fails_over_to_the_bed(self):
        for name, descriptor in _failover_descriptors():
            with (
                self.subTest(name),
                seerdb.connect(
                    user=_USER, password=_PASSWORD, dsn=descriptor, **_FV_KW
                ) as conn,
            ):
                cur = conn.cursor()
                cur.execute('SELECT 1 FROM dual')
                self.assertEqual(cur.fetchone(), (1,))

    def test_a_connection_class_alone_requests_no_pooled_server(self):
        # A class and a purity only label the session, as in python-oracledb:
        # no SERVER=POOLED, so a server without a DRCP pool started connects
        # instead of refusing with ORA-12520 (#1990).
        with seerdb.connect(
            user=_USER,
            password=_PASSWORD,
            host=_HOST,
            port=_PORT,
            service_name=_SERVICE,
            cclass='PYO_LABEL',
            purity=seerdb.PURITY_SELF,
            **_FV_KW,
        ) as conn:
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM dual')
            self.assertEqual(cur.fetchone(), (1,))

    def test_a_drcp_pool_connects_with_its_own_class(self):
        # A pool asking for a pooled server gives its sessions a generated class
        # and purity SELF, as python-oracledb's pools do (#2006). A server whose
        # DRCP pool is not started refuses it (ORA-12520).
        try:
            pool = seerdb.create_pool(
                user=_USER,
                password=_PASSWORD,
                host=_HOST,
                port=_PORT,
                service_name=_SERVICE,
                min=1,
                max=2,
                **{**_FV_KW, 'server_type': 'pooled'},
            )
        except seerdb.DatabaseError as e:
            if getattr(e, 'code', None) == 12520:
                self.skipTest('the DRCP pool is not started on this server')
            raise
        try:
            with pool.acquire() as conn:
                self.assertTrue(conn.cclass.startswith('SEERDB:'))
                cur = conn.cursor()
                cur.execute('SELECT 1 FROM dual')
                self.assertEqual(cur.fetchone(), (1,))
        finally:
            pool.close()

    def test_a_one_way_message_is_not_answered(self):
        # A Mirror answered a one-way message (type 26) as a call, and the
        # client read that answer as its next call's reply (#2559). The one a
        # client sends is python-oracledb's pool's session release, which it
        # sends whatever server it got. A real dedicated server never answers
        # the call after one (18c, 21c, 23ai), so this runs on a Mirror only:
        # it keeps the session, as a pool that hands back the same server.
        if not os.environ.get('SEERDB_TEST_MIRROR'):
            self.skipTest('a dedicated server hangs after a session release')
        from seerdb.common.tns import encode_session_release
        from seerdb.common.tns_consts import TNS_DATA

        with _connect_with() as conn:
            conn.send(
                TNS_DATA, encode_session_release(conn._next_seq(), conn.field_version)
            )
            cur = conn.cursor()
            cur.execute('SELECT 42 FROM dual')
            self.assertEqual(cur.fetchone(), (42,))

    def test_a_drcp_pool_hands_its_server_back_and_is_served_again(self):
        # A pool releases its pooled server whenever it takes a connection
        # back, as python-oracledb's does (#2544), and the next acquire is
        # served by whichever server DRCP picks. The cursors closed before a
        # release went with its REQUEST_END: closed after it, against the old
        # session, they were ORA-56600. The pool's close then only hangs up.
        try:
            pool = seerdb.create_pool(
                user=_USER,
                password=_PASSWORD,
                host=_HOST,
                port=_PORT,
                service_name=_SERVICE,
                min=1,
                max=1,
                **{**_FV_KW, 'server_type': 'pooled'},
            )
        except seerdb.DatabaseError as e:
            if getattr(e, 'code', None) == 12520:
                self.skipTest('the DRCP pool is not started on this server')
            raise
        try:
            for n in range(3):
                conn = pool.acquire()
                for _ in range(2):
                    cur = conn.cursor()
                    cur.execute('SELECT :1 FROM dual', [n])
                    self.assertEqual(cur.fetchone(), (n,))
                    cur.close()
                pool.release(conn)
        finally:
            pool.close()

    def test_a_long_program_name_connects(self):
        # 8i's login gives a program name one length byte, which stops at 252:
        # 253 to 255 failed the login and a longer one could not be sent at all
        # (#1773). Every other server takes these whole.
        for length in (253, 254, 255, 600):
            with self.subTest(length=length):
                with _connect_with(app_name='p' * length) as conn:
                    cur = conn.cursor()
                    cur.execute('SELECT 1 FROM dual')
                    self.assertEqual(cur.fetchone(), (1,))

    def test_kill_session_ends_the_named_session(self):
        # ALTER SYSTEM KILL SESSION 'sid,serial' ends that session: its next call
        # fails with ORA-00028 and the connection is gone (#1212, #1367) -- even a
        # SELECT USER, which the Mirror over PostgreSQL answered without its
        # backend and so from a dead session. A malformed ID is ORA-00026, an
        # unknown one ORA-00030. The suite's user may neither read v$session nor
        # ALTER SYSTEM on any Oracle bed, so there it skips.
        from seerdb.common.exceptions import DatabaseError

        victim = _connect_with()
        try:
            vcur = victim.cursor()
            try:
                vcur.execute(
                    "SELECT * FROM v$session WHERE sid = sys_context('userenv', 'sid')"
                )
            except DatabaseError as exc:
                if exc.code in (942, 2003):
                    self.skipTest(f'v$session not readable: ORA-{exc.code:05d}')
                raise
            names = [d[0] for d in vcur.description]
            row = vcur.fetchone()
            (sid, serial) = (row[names.index('SID')], row[names.index('SERIAL#')])
            try:
                self.cur.execute(f"ALTER SYSTEM KILL SESSION '{sid},{serial}'")
            except DatabaseError as exc:
                if exc.code == 1031:
                    self.skipTest('no ALTER SYSTEM privilege')
                raise
            with self.assertRaises(seerdb.Error) as killed:
                vcur.execute('SELECT USER FROM dual')
                vcur.fetchall()
            self.assertEqual(getattr(killed.exception, 'code', None), 28)
        finally:
            try:
                victim.close()
            except seerdb.Error:
                pass
        for session, code in (('x', 26), (f'{sid},{serial}', 30)):
            with self.assertRaises(DatabaseError) as caught:
                self.cur.execute(f"ALTER SYSTEM KILL SESSION '{session}'")
            self.assertEqual(caught.exception.code, code)

    @_requires(_LTZ)
    def test_timestamp_with_local_time_zone(self):
        # TIMESTAMP WITH LOCAL TIME ZONE (#1208), as measured on 9i to 23ai: a value
        # bound as LTZ is the instant in the database zone and round-trips as it
        # is; a TIMESTAMP bound into one is read in the session zone and comes
        # back in the database's; a precision truncates; a CAST does the same
        # conversions; SYSTIMESTAMP / CURRENT_TIMESTAMP are WITH TIME ZONE.
        self.cur.execute('SELECT sessiontimezone, dbtimezone FROM dual')
        (session, database) = (_tz_offset(z) for z in self.cur.fetchone())
        if session is None or database is None:
            self.skipTest('a named time zone')
        (session, zone) = _session_zone_apart_from(database)
        self.cur.execute(f"ALTER SESSION SET TIME_ZONE = '{zone}'")
        value = _LTZ_VALUE
        local = value - session + database
        self.cur.execute(_LTZ_TABLE_DDL.format(self.TABLE))
        for k, kind in (
            (1, seerdb.DB_TYPE_TIMESTAMP_LTZ),
            (2, seerdb.DB_TYPE_TIMESTAMP),
        ):
            self.cur.setinputsizes(kind, kind)
            self.cur.execute(
                f'INSERT INTO {self.TABLE} VALUES ({k}, :1, :2)', [value, value]
            )
        self.cur.execute(f'SELECT k, a, b FROM {self.TABLE} ORDER BY k')
        self.assertEqual(
            [d[1] for d in self.cur.description[1:]], [seerdb.DB_TYPE_TIMESTAMP_LTZ] * 2
        )
        self.assertEqual(
            self.cur.fetchall(),
            [
                (1, value, value.replace(microsecond=123000)),
                (2, local, local.replace(microsecond=123000)),
            ],
        )
        for kind, expected in (
            (seerdb.DB_TYPE_TIMESTAMP_LTZ, value),
            (seerdb.DB_TYPE_TIMESTAMP, local),
        ):
            self.cur.setinputsizes(kind)
            self.cur.execute(
                'SELECT CAST(:1 AS TIMESTAMP WITH LOCAL TIME ZONE) FROM dual', [value]
            )
            self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_TIMESTAMP_LTZ)
            self.assertEqual(self.cur.fetchone(), (expected,))
        self.cur.execute(
            'SELECT systimestamp, current_timestamp, localtimestamp FROM dual'
        )
        self.assertEqual(
            [d[1] for d in self.cur.description],
            [
                seerdb.DB_TYPE_TIMESTAMP_TZ,
                seerdb.DB_TYPE_TIMESTAMP_TZ,
                seerdb.DB_TYPE_TIMESTAMP,
            ],
        )

    @_requires(_8I_DESCRIBE_SPANS_PACKETS)
    def test_a_describe_wider_than_a_packet(self):
        # V$SESSION's 45 columns describe to more than an 8i packet holds, and
        # the server pauses between the packets, so the client sees the
        # describe split (#1226). It is read whole; a describe that a failing
        # execute cuts short gives the server's error, and the session goes on.
        # 8i only: that is where the describe outgrows a packet, and where the
        # suite's user (SYSTEM) may read V$SESSION.
        from seerdb.common.exceptions import DatabaseError

        self.cur.execute("SELECT * FROM v$session WHERE audsid = userenv('sessionid')")
        self.assertGreater(len(self.cur.description), 40)
        self.assertEqual(len(self.cur.fetchall()), 1)
        # 8i's USERENV has no SID: it starts to describe, then fails.
        with self.assertRaises(DatabaseError) as caught:
            self.cur.execute(
                "SELECT * FROM v$session WHERE sid = sys_context('userenv', 'sid')"
            )
        self.assertEqual(caught.exception.code, 2003)
        self.cur.execute('SELECT 1 FROM dual')
        self.assertEqual(self.cur.fetchall(), [(1,)])

    @_requires(_TSTZ)
    def test_timestamp_with_time_zone_compares_by_instant(self):
        # Equal, ordered and counted by the instant, whatever the offset each
        # value was written at; a NULL bind matches nothing (#1239).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (k NUMBER, t TIMESTAMP WITH TIME ZONE)'
        )
        for row in _TSTZ_ROWS:  # one at a time: 9i has no array DML
            self.cur.setinputsizes(None, seerdb.DB_TYPE_TIMESTAMP_TZ)
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', row)
        for value, expected in ((_TSTZ_SAME_INSTANT, [(1,), (2,)]), (None, [])):
            self.cur.setinputsizes(seerdb.DB_TYPE_TIMESTAMP_TZ)
            self.cur.execute(
                f'SELECT k FROM {self.TABLE} WHERE t = :1 ORDER BY k', [value]
            )
            self.assertEqual(self.cur.fetchall(), expected)
        self.cur.setinputsizes(seerdb.DB_TYPE_TIMESTAMP_TZ)
        self.cur.execute(
            f'SELECT k FROM {self.TABLE} WHERE t < :1 ORDER BY k', [_TSTZ_BEFORE]
        )
        self.assertEqual(self.cur.fetchall(), [(1,), (2,)])
        self.cur.execute(f'SELECT k FROM {self.TABLE} ORDER BY t DESC, k')
        self.assertEqual(self.cur.fetchall(), [(3,), (1,), (2,)])
        self.cur.execute(f'SELECT COUNT(DISTINCT t) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(2,)])

    @_requires(_LTZ, _LTZ_SESSION_ARITHMETIC)
    def test_days_added_to_a_timestamp_with_local_time_zone(self):
        # LTZ + n is a DATE on the session's clock, its fractional seconds
        # dropped; assigned back to an LTZ it is read in the session zone again,
        # so a PL/SQL in/out round trip moves the value by exactly n days (#1240).
        self.cur.execute('SELECT sessiontimezone, dbtimezone FROM dual')
        (session, database) = (_tz_offset(z) for z in self.cur.fetchone())
        if session is None or database is None:
            self.skipTest('a named time zone')
        value = datetime.datetime(2022, 5, 10, 12, 0, 0, 700000)
        on_session_clock = value.replace(microsecond=0) - database + session
        self.cur.setinputsizes(seerdb.DB_TYPE_TIMESTAMP_LTZ)
        self.cur.execute('SELECT :1 + 5.25, :1 - 0.5 FROM dual', [value])
        self.assertEqual(
            self.cur.fetchone(),
            (
                on_session_clock + datetime.timedelta(days=5.25),
                on_session_clock - datetime.timedelta(days=0.5),
            ),
        )
        var = self.cur.var(seerdb.DB_TYPE_TIMESTAMP_LTZ)
        var.setvalue(0, value.replace(microsecond=0))
        self.cur.execute('begin :value := :value + 5.25; end;', {'value': var})
        self.assertEqual(var.getvalue(), datetime.datetime(2022, 5, 15, 18, 0, 0))

    @_requires(_LTZ, _TRUNC_TIMESTAMP)
    def test_a_midnight_ltz_bind_matches_a_truncated_ltz_column(self):
        # A TIMESTAMP WITH LOCAL TIME ZONE bind with no fractional seconds goes
        # out in the 7-byte DATE form, as python-oracledb sends it: the server
        # compared the 11-byte form with a zero fraction to trunc() of an LTZ
        # column and matched nothing (#1337). The session runs in the database's
        # zone, as python-oracledb's own suite pins it.
        self.cur.execute('SELECT sessiontimezone, dbtimezone FROM dual')
        (session, database) = self.cur.fetchone()
        self.cur.execute(f"ALTER SESSION SET TIME_ZONE = '{database}'")
        try:
            self.cur.execute(
                f'CREATE TABLE {self.TABLE} (id NUMBER, t TIMESTAMP WITH LOCAL TIME ZONE)'
            )
            self.cur.execute(
                f"INSERT INTO {self.TABLE} VALUES (1, TIMESTAMP '2022-06-12 10:30:20')"
            )
            self.cur.setinputsizes(seerdb.DB_TYPE_TIMESTAMP_LTZ)
            self.cur.execute(
                f'SELECT id FROM {self.TABLE} WHERE trunc(t) = :1',
                [datetime.datetime(2022, 6, 12)],
            )
            self.assertEqual(self.cur.fetchall(), [(1,)])
        finally:
            self.cur.execute(f"ALTER SESSION SET TIME_ZONE = '{session}'")

    def test_a_var_read_only_as_input_beside_an_out_var(self):
        # A Var the block only reads is an IN bind: no value comes back for it,
        # and the OUT Var beside it gets its own. On 9i the reply's values were
        # read one per Var, so the IN one shifted them and failed (#1242).
        out, inp = self.cur.var(int), self.cur.var(int)
        inp.setvalue(0, 7)
        self.cur.execute('begin :1 := :2 * 10; end;', [out, inp])
        self.assertEqual((out.getvalue(), inp.getvalue()), (70, 7))
        out, inp = self.cur.var(int), self.cur.var(int)
        inp.setvalue(0, 8)
        self.cur.execute('begin :h := :v * 10; end;', {'v': inp, 'h': out})
        self.assertEqual((out.getvalue(), inp.getvalue()), (80, 8))

    def test_an_identifier_may_contain_a_hash(self):
        # Oracle takes `#` in an unquoted name after its first character, as its
        # own dictionary does (serial#, statistic#); it reads back upper-cased
        # like any unquoted name (#1249).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (obj# NUMBER, name VARCHAR2(10))')
        self.cur.execute(f"INSERT INTO {self.TABLE} (obj#, name) VALUES (7, 'a#b')")
        self.cur.execute(
            f'SELECT t.obj#, name FROM {self.TABLE} t WHERE obj# = :1', [7]
        )
        self.assertEqual([d[0] for d in self.cur.description], ['OBJ#', 'NAME'])
        self.assertEqual(self.cur.fetchall(), [(7, 'a#b')])

    def test_a_column_of_a_user_defined_type_names_its_owner(self):
        # A collection column is reported by its type's name, and the type's
        # schema is DATA_TYPE_OWNER; a built-in has none (#1251).
        Type = 'PYO_DTO_ARR'
        try:
            self.cur.execute(f'DROP TYPE {Type}')
        except seerdb.DatabaseError:
            pass
        self.cur.execute(f'CREATE TYPE {Type} AS VARRAY(5) OF NUMBER')
        # The type's owner is the schema it was made in: the current one.
        self.cur.execute("SELECT sys_context('userenv', 'current_schema') FROM dual")
        (owner,) = self.cur.fetchone()
        try:
            self.cur.execute(
                f'CREATE TABLE {self.TABLE} (i NUMBER(9), v VARCHAR2(10), a {Type})'
            )
            self.cur.execute(
                'SELECT column_name, data_type, data_type_owner FROM user_tab_columns '
                'WHERE table_name = :1 ORDER BY column_name',
                [self.TABLE],
            )
            self.assertEqual(
                self.cur.fetchall(),
                [
                    ('A', Type, owner),
                    ('I', 'NUMBER', None),
                    ('V', 'VARCHAR2', None),
                ],
            )
        finally:
            self._drop_silently(self.cur)
            self.cur.execute(f'DROP TYPE {Type}')

    @_requires(_INVISIBLE_COLUMNS)
    def test_an_invisible_column(self):
        # An INVISIBLE column (12.1+) is left out of `*` and of an INSERT with no
        # column list, works when named, and has no COLUMN_ID; USER_TAB_COLS
        # marks it HIDDEN (#1195). Measured on 23ai.
        T = self.TABLE
        self.cur.execute(f'CREATE TABLE {T} (a NUMBER, h NUMBER INVISIBLE, b NUMBER)')
        self.cur.execute(f'INSERT INTO {T} VALUES (1, 2)')
        self.cur.execute(f'INSERT INTO {T} (a, h, b) VALUES (3, 4, 5)')
        self.cur.execute(f'SELECT * FROM {T} ORDER BY a')
        self.assertEqual([d[0] for d in self.cur.description], ['A', 'B'])
        self.assertEqual(self.cur.fetchall(), [(1, 2), (3, 5)])
        self.cur.execute(f'SELECT t.*, h FROM {T} t ORDER BY a')
        self.assertEqual([d[0] for d in self.cur.description], ['A', 'B', 'H'])
        self.assertEqual(self.cur.fetchall(), [(1, 2, None), (3, 5, 4)])
        self.cur.execute(
            'SELECT column_name, column_id, hidden_column FROM user_tab_cols '
            'WHERE table_name = :1 ORDER BY column_name',
            [T],
        )
        self.assertEqual(
            self.cur.fetchall(), [('A', 1, 'NO'), ('B', 2, 'NO'), ('H', None, 'YES')]
        )
        self.cur.execute(
            'SELECT column_name, column_id FROM user_tab_columns '
            'WHERE table_name = :1 ORDER BY column_name',
            [T],
        )
        self.assertEqual(self.cur.fetchall(), [('A', 1), ('B', 2), ('H', None)])
        # Made visible, it is in `*` again (Oracle moves it last; see #1195).
        self.cur.execute(f'ALTER TABLE {T} MODIFY h VISIBLE')
        self.cur.execute(f'SELECT * FROM {T} ORDER BY a')
        self.assertEqual(sorted(d[0] for d in self.cur.description), ['A', 'B', 'H'])

    def test_decode(self):
        # DECODE with untyped literals, a NULL matching a NULL, several searches
        # and no default; and, as a schema script populates a table, a DECODE of
        # mixed types into a NUMBER column (#822).
        self.cur.execute(
            "SELECT DECODE('a', 'a', 'A', 'z'), DECODE(NULL, NULL, 'null', 'no'), "
            "DECODE(2, 1, 'one', 2, 'two'), DECODE(3, 1, 'one') FROM dual"
        )
        self.assertEqual(self.cur.fetchone(), ('A', 'null', 'two', None))
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, n NUMBER)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} '
            'SELECT 3, DECODE(MOD(3, 2), 0, NULL, POWER(2, 3)) FROM dual'
        )
        self.cur.execute(f'SELECT n FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (8,))

    def test_ddl_on_a_table_another_session_holds_fails(self):
        # Oracle's DDL does not wait for a lock another session holds: ORA-00054
        # at once, where PostgreSQL would wait for ever (#1191).
        from seerdb.common.exceptions import DatabaseError

        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER)')
        self.conn.autocommit = False
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')
        other = _connect_with()
        try:
            with self.assertRaises(DatabaseError) as ctx:
                other.cursor().execute(f'TRUNCATE TABLE {self.TABLE}')
            self.assertEqual(ctx.exception.code, 54)
        finally:
            other.close()
            self.conn.rollback()

    def test_a_query_does_not_block_another_sessions_ddl(self):
        # A query takes no table lock, so another session may truncate the
        # table it read while the reader's session is still open (#1190).
        self.conn.autocommit = False
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER)')
        self.cur.execute(f'SELECT n FROM {self.TABLE}')
        self.cur.fetchall()
        other = _connect_with()
        try:
            other.cursor().execute(f'TRUNCATE TABLE {self.TABLE}')
        finally:
            other.close()

    def test_transaction_control_statements_run_as_sql(self):
        # COMMIT, ROLLBACK, SAVEPOINT and ROLLBACK TO sent as SQL text, as a
        # script sends them, rather than through the connection's calls (#1181).
        from seerdb.common.exceptions import DatabaseError

        self.conn.autocommit = False
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')
        self.cur.execute('COMMIT')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (2)')
        self.cur.execute('ROLLBACK')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (3)')
        self.cur.execute('SAVEPOINT pyo_sp')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (4)')
        self.cur.execute('ROLLBACK TO SAVEPOINT pyo_sp')
        # A savepoint never taken fails alone; the transaction goes on.
        with self.assertRaises(DatabaseError) as ctx:
            self.cur.execute('ROLLBACK TO pyo_no_such_sp')
        self.assertEqual(ctx.exception.code, 1086)
        self.cur.execute('COMMIT WORK')
        self.cur.execute(f'SELECT n FROM {self.TABLE} ORDER BY n')
        self.assertEqual(self.cur.fetchall(), [(1,), (3,)])

    def test_the_nls_parameters_are_readable(self):
        # A client may read the database character set before anything else:
        # the reference thin client's own test harness does, and a server that
        # lacked the view failed every one of its tests in setup (ORA-00942).
        self.cur.execute(
            'SELECT value FROM nls_database_parameters '
            "WHERE parameter = 'NLS_CHARACTERSET'"
        )
        (charset,) = self.cur.fetchone()
        self.assertTrue(charset)
        self.cur.execute(
            "SELECT value FROM nls_session_parameters WHERE parameter = 'NLS_DATE_FORMAT'"
        )
        self.assertTrue(self.cur.fetchone()[0])

    def test_a_session_setting_answers_with_no_result_set(self):
        # ALTER SESSION is not a query: a server answers it with a status and no
        # rows. A backend that stood a `SELECT 1` in for one answered with a row,
        # which seerdb let pass and the reference thin client failed on.
        self.cur.execute("ALTER SESSION SET NLS_NUMERIC_CHARACTERS = '.,'")
        self.assertIsNone(self.cur.description)

    def test_alter_session_current_schema_round_trips(self):
        # 11g answers this with a return-parameters block that carries the
        # session-state change as key/value pairs; reading past them only by
        # skipping zero bytes left "no decoder for response token 1" (#1141).
        self.cur.execute("SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM dual")
        (own,) = self.cur.fetchone()
        self.cur.execute('ALTER SESSION SET CURRENT_SCHEMA = SYSTEM')
        try:
            self.cur.execute(
                "SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM dual"
            )
            self.assertEqual(self.cur.fetchone(), ('SYSTEM',))
        finally:
            self.cur.execute(f'ALTER SESSION SET CURRENT_SCHEMA = {own}')

    def test_bit_vector_reuse_across_fetch_boundary(self):
        # #326: a column the server elides as "same as previous row" (bit-vector
        # duplicate detection) must survive a fetch-continuation boundary. The
        # result set (200 rows) far exceeds the ~15-row prefetch, and the two
        # constant columns are reused every row — the first row of each
        # continuation batch used to decode them as None.
        self.cur.execute(
            "SELECT 42 AS k, LEVEL AS n, 'fixed' AS s FROM dual CONNECT BY LEVEL <= 200"
        )
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 200)
        self.assertTrue(all(r[0] == 42 and r[2] == 'fixed' for r in rows))
        self.assertEqual([r[1] for r in rows], list(range(1, 201)))

    # ----- iteration -----

    def test_iter_yields_all_rows(self):
        self._setup_rows()
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        seen = [row for row in self.cur]
        self.assertEqual(seen, [(1,), (2,), (3,), (4,), (5,)])

    # ----- NULL passthrough -----

    def test_null_values_in_row(self):
        self._setup_rows()
        self.cur.execute(f'SELECT name, score FROM {self.TABLE} WHERE id = 5')
        self.assertEqual(self.cur.fetchone(), (None, None))

    # ----- context managers -----

    def test_cursor_context_manager_closes(self):
        with self.conn.cursor() as cur:
            cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        # After the block the cursor must be closed.
        with self.assertRaises(seerdb.InterfaceError):
            cur.execute('SELECT 1 FROM dual')

    # ----- error mapping -----

    def test_select_from_nonexistent_raises_942(self):
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.execute(f'SELECT * FROM nope_{os.getpid()}_xyz')
        self.assertEqual(ctx.exception.code, 942)

    # ----- executemany (array DML) -----

    def test_executemany_insert(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(20))')
        rows = [(i, f'n{i}') for i in range(1, 21)]
        self.cur.executemany(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', rows)
        self.assertEqual(self.cur.rowcount, 20)
        self.cur.execute(f'SELECT id, name FROM {self.TABLE} ORDER BY id')
        self.assertEqual(self.cur.fetchall(), rows)

    def test_executemany_single_round_trip(self):
        # The whole batch must go in one server round trip, not one per row:
        # no more sends than one row's execute takes -- one on 10g+, and on 9i
        # the call and close a single DML makes (#2245), and the OOPEN that
        # gives a cacheable single row a cursor of its own, which the batch,
        # not cached, does without (#2288).
        # Count only TNS_DATA sends: under XE's logon-storm throttle the server
        # can inject a break/marker mid-response, and the driver's marker ack is
        # an extra (non-data) send that would otherwise make this flake.
        from seerdb.common.tns_consts import TNS_DATA

        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.conn.autocommit = False
        import seerdb.client.connection as _c

        orig = _c.OracleConnect.send
        sends = [0]
        _c.OracleConnect.send = lambda s, T, D: (
            sends.__setitem__(0, sends[0] + (1 if T == TNS_DATA else 0)),
            orig(s, T, D),
        )[1]
        try:
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [100])
            single = sends[0]
            sends[0] = 0
            self.cur.executemany(
                f'INSERT INTO {self.TABLE} VALUES (:1)', [(i,) for i in range(50)]
            )
        finally:
            _c.OracleConnect.send = orig
        self.assertLessEqual(sends[0], single)
        self.assertLessEqual(single, 3)
        self.assertEqual(self.cur.rowcount, 50)

    def test_executemany_delete(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1)', [(i,) for i in range(10)]
        )
        self.cur.executemany(
            f'DELETE FROM {self.TABLE} WHERE id = :1', [(2,), (4,), (6,)]
        )
        self.assertEqual(self.cur.rowcount, 3)
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (7,))

    def test_binary_integer_out_bind_is_an_int(self):
        # BINARY_INTEGER / PLS_INTEGER travels as an Oracle NUMBER, so the bytes
        # for `:v := 2.9` are the same either way -- the DECLARED type is what
        # makes the value an integer, and the truncation is the client's (#1044).
        for expr, want in (('2.9', 2), ('-2.9', -2), ('5', 5), ('0', 0)):
            with self.subTest(expr=expr):
                got = self.cur.var(seerdb.DB_TYPE_BINARY_INTEGER)
                self.cur.execute(f'BEGIN :value := {expr}; END;', [got])
                value = got.getvalue()
                self.assertIsInstance(value, int)
                self.assertEqual(value, want)

    def test_a_number_out_bind_is_still_not_truncated(self):
        # The companion: the same statement through a NUMBER var keeps its
        # fraction, so the coercion belongs to the declared type and not to the
        # wire form the two share.
        got = self.cur.var(seerdb.DB_TYPE_NUMBER)
        self.cur.execute('BEGIN :value := 2.9; END;', [got])
        self.assertEqual(float(got.getvalue()), 2.9)

    def test_select_into_with_no_rows_raises(self):
        # ORA-01403 is the end-of-fetch sentinel a query's last FETCH ends on,
        # AND the error a PL/SQL `SELECT ... INTO` raises when it matches
        # nothing. Masking it for both turned every such block into a silent
        # success handing back NULL (#1039).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        got = self.cur.var(int)
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.execute(
                f'BEGIN SELECT id INTO :1 FROM {self.TABLE} WHERE 1 = 0; END;',
                [got],
            )
        self.assertEqual(ctx.exception.code, 1403)
        # The session is still usable: this is an ordinary error, not a desync.
        self.cur.execute('SELECT 1 FROM dual')
        self.assertEqual(self.cur.fetchone(), (1,))

    def test_a_bound_dml_waits_for_the_commit(self):
        # A bound INSERT, and a bound block, are part of the transaction like
        # any other statement: another session does not see them, and rollback
        # undoes them and what came before. Over the 9i OALL8 opt-in both
        # carried commit-on-success and committed the whole transaction (#798).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        conn = seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=False,
            **_FV_KW,
        )
        try:
            cur = conn.cursor()
            cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')
            cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [2])
            cur.execute(f'BEGIN INSERT INTO {self.TABLE} VALUES (:1); END;', [3])
            self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
            self.assertEqual(self.cur.fetchone(), (0,))
            conn.rollback()
            cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
            self.assertEqual(cur.fetchone(), (0,))
        finally:
            conn.close()

    def test_a_query_that_matches_nothing_still_raises_nothing(self):
        # The other half, and the reason the mask exists: a SELECT that matches
        # no row ends on the same ORA-01403 and must stay silent. A fix that
        # only looked at the code would break every empty result set.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.execute(f'SELECT id FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [])
        self.cur.execute(f'SELECT id FROM {self.TABLE} WHERE 1 = 0')
        self.assertIsNone(self.cur.fetchone())

    def test_select_into_that_finds_a_row_is_unaffected(self):
        # The block still works when it does find its row -- the guard must not
        # turn a success into an error either.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (7)')
        got = self.cur.var(int)
        self.cur.execute(f'BEGIN SELECT id INTO :1 FROM {self.TABLE}; END;', [got])
        self.assertEqual(int(got.getvalue()), 7)

    def test_failing_returning_raises_cleanly_and_keeps_the_session(self):
        # A statement with a RETURNING clause that fails does not answer with the
        # error straight away: the server sends a bare flush-out-binds token and
        # waits for the client to echo it back first. Reading that as a result
        # abandoned the response, and the *next* statement on the connection then
        # got ORA-03137 because the server was still waiting (#697).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER NOT NULL, v NUMBER)')
        got = self.cur.var(int)
        with self.assertRaises(seerdb.IntegrityError) as ctx:
            self.cur.execute(
                f'INSERT INTO {self.TABLE} (v) VALUES (:1) RETURNING id INTO :2',
                [1.5, got],
            )
        self.assertEqual(ctx.exception.code, 1400)
        # The session is still usable, which is the half that made this dangerous.
        self.cur.execute('SELECT 1 FROM dual')
        self.assertEqual(self.cur.fetchall(), [(1,)])

    def test_a_too_small_returning_variable_is_reported(self):
        # A RETURNING value that does not fit its variable comes back cut down,
        # and the server says so in the sb4 after the value -- 0 when it fitted,
        # the untruncated length when it did not. Discarding that field turned a
        # wrong answer into a plausible one: the variable held half a string and
        # nothing was raised (#1021).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(40))')
        small = self.cur.var(str, 2)
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.execute(
                f'INSERT INTO {self.TABLE} (id, v) VALUES (1, :1) RETURNING v INTO :2',
                ['a value far longer than two characters', small],
            )
        if self.conn.field_version < FIELD_VERSION_10_2:
            # Pre-10g runs RETURNING as a PL/SQL block (#801), where the INTO
            # target is an ordinary OUT bind — so the *server* catches it, and
            # says so in its own words. Reported either way, which is the point.
            self.assertEqual(ctx.exception.code, 6502)
        else:
            self.assertIn('DPY-4002', str(ctx.exception))
        # The session is still usable: the report comes after the whole response
        # has been read, not part way through it.
        self.cur.execute('SELECT 1 FROM dual')
        self.assertEqual(self.cur.fetchall(), [(1,)])

    def test_a_returning_variable_that_fits_is_untouched(self):
        # The companion: the same statement into a big-enough variable must not
        # be reported. A rule of "non-zero means truncated" is only safe if what
        # fits really does report 0, on every tier.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(40))')
        big = self.cur.var(str, 100)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (id, v) VALUES (1, :1) RETURNING v INTO :2',
            ['a value far longer than two characters', big],
        )
        self.assertEqual(big.getvalue(), ['a value far longer than two characters'])

    def test_a_null_returning_value_is_not_a_truncation(self):
        # A NULL returned value carries -1 in the same actual-length field, on
        # every type. Read as "the untruncated length" it turns every NULL
        # RETURNING into a truncation report (#1021) -- which is how the live
        # matrix caught the first cut of this check, on a NULL LOB.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(40))')
        got = self.cur.var(str, 100)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (id) VALUES (1) RETURNING v INTO :1', [got]
        )
        self.assertEqual(got.getvalue(), [None])

    def test_a_returned_value_takes_its_variables_type(self):
        # RETURNING converts the value into the receiving variable's type: text
        # into a RAW is read as hex, into a NUMBER as a number. One it cannot
        # convert fails the statement, which is undone. The Mirror over
        # PostgreSQL sent the text's own bytes, or encoded the text as if it were
        # a NUMBER, and kept the row (#1370).
        from seerdb.common.exceptions import DatabaseError

        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(40))')
        insert = f'INSERT INTO {self.TABLE} (id, v) VALUES (1, :1) RETURNING v INTO :2'
        raw, number = self.cur.var(seerdb.DB_TYPE_RAW, 40), self.cur.var(seerdb.NUMBER)
        self.cur.execute(insert, ['0A0B', raw])
        self.cur.execute(insert, ['42', number])
        self.assertEqual((raw.getvalue(), number.getvalue()), ([b'\n\x0b'], [42]))
        for value, typ, code in (
            ('not hex', seerdb.DB_TYPE_RAW, 1465),
            ('not a number', seerdb.NUMBER, 1722),
        ):
            with self.assertRaises(DatabaseError) as caught:
                self.cur.execute(insert, [value, self.cur.var(typ, 40)])
            self.assertEqual(caught.exception.code, code)
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (2,))
        # A RETURNING that matches no row returns nothing, and is no error.
        none = self.cur.var(seerdb.DB_TYPE_RAW, 40)
        self.cur.execute(
            f'UPDATE {self.TABLE} SET v = v WHERE id = 99 RETURNING v INTO :1', [none]
        )
        self.assertEqual(self.cur.rowcount, 0)

    def test_a_number_returned_into_a_varchar_variable_is_its_text(self):
        # A NUMBER column returned into a VARCHAR variable comes back as text,
        # TO_CHAR's default form: 0.5 is '.5'. The Mirror sent the NUMBER's own
        # bytes in the VARCHAR, which the client could not decode (#1501).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, n NUMBER)')
        insert = f'INSERT INTO {self.TABLE} (id, n) VALUES (1, :1) RETURNING n INTO :2'
        for value, text in ((1, '1'), (0.5, '.5'), (-1.25, '-1.25')):
            got = self.cur.var(seerdb.DB_TYPE_VARCHAR, 40)
            self.cur.execute(insert, [value, got])
            self.assertEqual(got.getvalue(), [text])

    def test_a_returning_variable_can_be_used_again(self):
        # The variable that received one RETURNING receives the next. On 8i the
        # client sent the list it held as the next execute's input and could not
        # encode it (#1390).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(40))')
        got = self.cur.var(str, 40)
        insert = f'INSERT INTO {self.TABLE} (id, v) VALUES (:1, :2) RETURNING v INTO :3'
        self.cur.execute(insert, [1, 'first', got])
        self.assertEqual(got.getvalue(), ['first'])
        self.cur.execute(insert, [2, 'second', got])
        self.assertEqual(got.getvalue(), ['second'])

    def test_failing_array_returning_raises_cleanly(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER NOT NULL, v NUMBER)')
        got = self.cur.var(int)
        with self.assertRaises(seerdb.IntegrityError):
            self.cur.executemany(
                f'INSERT INTO {self.TABLE} (v) VALUES (:1) RETURNING id INTO :2',
                [[1.5, got], [2.5, got]],
            )
        self.cur.execute('SELECT 1 FROM dual')
        self.assertEqual(self.cur.fetchall(), [(1,)])

    # ----- executemany + RETURNING ... INTO (#687) -----

    def test_executemany_returning_collects_every_iteration(self):
        # Each iteration returns its own rows, so the receiving Var holds one
        # entry per iteration and getvalue(pos) selects it. Before #687 the
        # request itself was malformed: a value was sent for the server-filled
        # bind in every row, the server rejected the call with ORA-03137 and
        # dropped the connection.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(20))')
        got = self.cur.var(int)
        rows = [[1, 'a', got], [2, 'bb', got], [3, 'ccc', got]]
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} (id, v) VALUES (:1, :2) RETURNING id INTO :3',
            rows,
        )
        self.assertEqual(self.cur.rowcount, 3)
        self.assertEqual([got.getvalue(i) for i in range(3)], [[1], [2], [3]])
        # The rows really landed, and the connection is still usable.
        self.cur.execute(f'SELECT id, v FROM {self.TABLE} ORDER BY id')
        self.assertEqual(self.cur.fetchall(), [(1, 'a'), (2, 'bb'), (3, 'ccc')])

    def test_executemany_returning_iteration_row_counts_differ(self):
        # An UPDATE iteration can affect any number of rows, and the counts are
        # per iteration rather than shared.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(20))')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} (id, v) VALUES (:1, :2)',
            [(1, 'a'), (2, 'b'), (3, 'c')],
        )
        got = self.cur.var(int)
        self.cur.executemany(
            f'UPDATE {self.TABLE} SET v = v || :1 WHERE id <= :2 RETURNING id INTO :3',
            [['x', 2, got], ['y', 3, got]],
        )
        self.assertEqual(self.cur.rowcount, 5)
        # Which rows each iteration returned, not the order it returned them in:
        # a RETURNING clause has no ORDER BY and no database promises one.
        self.assertEqual(sorted(got.getvalue(0)), [1, 2])
        self.assertEqual(sorted(got.getvalue(1)), [1, 2, 3])

    def test_executemany_returning_keeps_the_slot_of_a_no_op_iteration(self):
        # An iteration that matches nothing still occupies its position, with an
        # empty list, so the positions stay aligned with the submitted rows.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} (id) VALUES (:1)', [(1,), (2,), (3,)]
        )
        got = self.cur.var(int)
        self.cur.executemany(
            f'UPDATE {self.TABLE} SET id = id WHERE id = :1 RETURNING id INTO :2',
            [[1, got], [99, got], [3, got]],
        )
        self.assertEqual([got.getvalue(i) for i in range(3)], [[1], [], [3]])

    def test_executemany_returning_named_binds(self):
        # The form the report was filed with: named placeholders and a dict per
        # row, all rows sharing one receiving Var (#687).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(10))')
        got = self.cur.var(int)
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} (id, v) VALUES (:id, :v) RETURNING id INTO :out',
            [{'id': 1, 'v': 'a', 'out': got}, {'id': 2, 'v': 'b', 'out': got}],
        )
        self.assertEqual([got.getvalue(i) for i in range(2)], [[1], [2]])

    def test_executemany_returning_several_binds(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(20))')
        ids = self.cur.var(int)
        names = self.cur.var(str)
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} (id, v) VALUES (:1, :2) '
            'RETURNING id, v INTO :3, :4',
            [[1, 'a', ids, names], [2, 'bb', ids, names]],
        )
        self.assertEqual([ids.getvalue(i) for i in range(2)], [[1], [2]])
        self.assertEqual([names.getvalue(i) for i in range(2)], [['a'], ['bb']])

    def test_executemany_returning_single_row_batch_stays_flat(self):
        # One iteration is one iteration however it was submitted, so the value
        # reads back the same way a plain execute's does.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        got = self.cur.var(int)
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} (id) VALUES (:1) RETURNING id INTO :2',
            [[7, got]],
        )
        self.assertEqual(got.getvalue(), [7])

    def test_executemany_empty(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.executemany(f'INSERT INTO {self.TABLE} VALUES (:1)', [])
        self.assertEqual(self.cur.rowcount, 0)
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (0,))

    def test_executemany_batcherrors(self):
        # With batcherrors=True a per-row constraint violation no longer aborts
        # the batch: good rows are applied and the failures are collected via
        # getbatcherrors() (#18).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY, v VARCHAR2(10))'
        )
        rows = [(1, 'a'), (2, 'b'), (1, 'dup'), (3, 'c'), (2, 'dup2')]
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2)', rows, batcherrors=True
        )
        errs = self.cur.getbatcherrors()
        self.assertEqual([(e.offset, e.code) for e in errs], [(2, 1), (4, 1)])
        self.assertIn('ORA-00001', str(errs[0]))
        # The non-violating rows were committed.
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        self.assertEqual([r[0] for r in self.cur.fetchall()], [1, 2, 3])

    def test_executemany_without_batcherrors_raises(self):
        # Default behaviour is unchanged: a constraint violation aborts and
        # raises rather than being collected.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY)')
        with self.assertRaises(seerdb.IntegrityError):
            self.cur.executemany(f'INSERT INTO {self.TABLE} VALUES (:1)', [(1,), (1,)])

    def test_getbatcherrors_empty_when_no_errors(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1)', [(1,), (2,)], batcherrors=True
        )
        self.assertEqual(self.cur.getbatcherrors(), [])

    @_requires(_ARRAY_DML)
    def test_the_statement_runs_again_after_a_batch_error(self):
        # Below 12.1 the statement's server cursor is cached, and a batch error
        # keeps it. It was queued for close all the same, so the next execute
        # of the statement answered ORA-01001 (#2563).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY)')
        sql = f'INSERT INTO {self.TABLE} VALUES (:1)'
        self.cur.executemany(sql, [(1,), (2,)], batcherrors=True)
        self.cur.executemany(sql, [(3,), (1,)], batcherrors=True)
        self.assertEqual(
            [(e.offset, e.code) for e in self.cur.getbatcherrors()], [(1, 1)]
        )
        self.cur.executemany(sql, [(4,), (5,)], batcherrors=True)
        self.assertEqual(self.cur.getbatcherrors(), [])
        self.cur.execute(sql, [6])
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        self.assertEqual([r[0] for r in self.cur.fetchall()], [1, 2, 3, 4, 5, 6])

    # ----- executemany arraydmlrowcounts (12c+) -----

    @_requires(_ARRAY_DML_ROWCOUNTS)
    def test_executemany_arraydmlrowcounts_update(self):
        # Per-iteration affected-row counts: UPDATE g=1 hits 3 rows, g=2 hits 1,
        # g=3 hits 2, g=9 hits none -> [3, 1, 2, 0]. Matches oracledb (#18).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (g NUMBER, v NUMBER)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2)',
            [(1, 1), (1, 2), (2, 3), (1, 4), (3, 5), (3, 6)],
        )
        self.cur.executemany(
            f'UPDATE {self.TABLE} SET v = v + 10 WHERE g = :1',
            [(1,), (2,), (3,), (9,)],
            arraydmlrowcounts=True,
        )
        self.assertEqual(self.cur.getarraydmlrowcounts(), [3, 1, 2, 0])

    @_requires(_ARRAY_DML_ROWCOUNTS)
    def test_arraydmlrowcounts_survive_a_batch_that_aborts(self):
        # A batch that fails part-way really applied the earlier rows, and a
        # client that asked for the per-iteration counts is owed them in the
        # ERROR reply too. Without them it reports the mode as never enabled --
        # a worse answer than the failure it is also being told about (#1031).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY, v VARCHAR2(10))'
        )
        with self.assertRaises(seerdb.IntegrityError):
            self.cur.executemany(
                f'INSERT INTO {self.TABLE} VALUES (:1, :2)',
                [(1, 'a'), (2, 'b'), (2, 'dup'), (4, 'd')],
                arraydmlrowcounts=True,
            )
        self.assertEqual(self.cur.getarraydmlrowcounts(), [1, 1])

    @_requires(_ARRAY_DML_ROWCOUNTS)
    def test_batcherrors_and_arraydmlrowcounts_together(self):
        # They are not alternatives: one execute may ask for both, and then the
        # batcherrors reply owes the counts as well (#1031). A row that failed
        # affected nothing and still holds its slot, or every count after it
        # shifts.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY, v VARCHAR2(10))'
        )
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2)',
            [(1, 'a'), (2, 'b'), (2, 'dup'), (4, 'd')],
            batcherrors=True,
            arraydmlrowcounts=True,
        )
        self.assertEqual(
            [(e.offset, e.code) for e in self.cur.getbatcherrors()], [(2, 1)]
        )
        self.assertEqual(self.cur.getarraydmlrowcounts(), [1, 1, 0, 1])

    @_requires(_ARRAY_DML_ROWCOUNTS)
    def test_batch_errors_report_index_failures_last(self):
        # Not row order: a real server evaluates the row (conversion, NOT NULL,
        # CHECK) as it goes and maintains the unique index afterwards, so the
        # unique violations come after every other failure, each group still
        # ascending. Measured on a live 23ai with the orders deliberately
        # reversed against each other (#1031).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} '
            '(id NUMBER PRIMARY KEY, v NUMBER(3), c NUMBER CHECK (c < 100))'
        )
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (99, 1, 1)')
        # The duplicate comes FIRST in row order and must be reported LAST.
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3)',
            [(1, 1, 1), (99, 1, 1), (3, 1, 999), (4, 1000, 1), (5, 1, 1)],
            batcherrors=True,
        )
        self.assertEqual(
            [(e.offset, e.code) for e in self.cur.getbatcherrors()],
            [(2, 2290), (3, 1438), (1, 1)],
        )

    @_requires(_ARRAY_DML_ROWCOUNTS)
    def test_executemany_arraydmlrowcounts_insert(self):
        # Each INSERT iteration affects exactly one row.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1)',
            [(i,) for i in range(5)],
            arraydmlrowcounts=True,
        )
        self.assertEqual(self.cur.getarraydmlrowcounts(), [1, 1, 1, 1, 1])

    @_requires(_ARRAY_DML_ROWCOUNTS)
    def test_arraydmlrowcounts_empty_without_request(self):
        # Without arraydmlrowcounts the list stays empty, and a prior request's
        # counts don't leak into a later plain executemany.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1)',
            [(1,), (2,)],
            arraydmlrowcounts=True,
        )
        self.assertEqual(self.cur.getarraydmlrowcounts(), [1, 1])
        self.cur.executemany(f'INSERT INTO {self.TABLE} VALUES (:1)', [(3,), (4,)])
        self.assertEqual(self.cur.getarraydmlrowcounts(), [])

    @_requires(_PRE12_ROWCOUNTS_REFUSAL)
    def test_arraydmlrowcounts_unsupported_on_11g(self):
        # On an 11g server the feature is rejected up front (oracledb-compatible).

        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        with self.assertRaises(seerdb.NotSupportedError):
            self.cur.executemany(
                f'INSERT INTO {self.TABLE} VALUES (:1)',
                [(1,), (2,)],
                arraydmlrowcounts=True,
            )

    # ----- closed-state guards -----

    def test_fetch_without_execute_raises(self):
        with self.assertRaises(seerdb.InterfaceError):
            self.cur.fetchone()

    def test_use_after_close_raises(self):
        self.cur.close()
        with self.assertRaises(seerdb.InterfaceError):
            self.cur.execute('SELECT 1 FROM dual')


@unittest.skipUnless(_USER, _SKIP_REASON)
class BindIntegration(_IntegrationBase):
    """Verify Cursor.execute parameter binding."""

    def test_arithmetic_on_two_small_integer_binds(self):
        # Two binds that each fit a smallint: Oracle does the arithmetic in
        # NUMBER and never overflows. The Mirror over PostgreSQL bound each as a
        # smallint, so `:1 + :2` of 30000 and `:1 * :2` of 300 overflowed past
        # 32767 (ORA-01426, #2307), where every Oracle (8i up) gives the full
        # value.
        self.cur.execute('SELECT :1 + :2 FROM dual', [30000, 30000])
        self.assertEqual(self.cur.fetchone()[0], 60000)
        self.cur.execute('SELECT :1 * :2 FROM dual', [300, 300])
        self.assertEqual(self.cur.fetchone()[0], 90000)

    def test_repeated_ddl_actually_runs_every_time(self):
        # The DML cursor cache reuses a server handle to save a parse, which is
        # right for DML and wrong for DDL: a CREATE or DROP does its work when
        # the server parses it, so a cached re-execute has nothing left to do
        # and reports success without acting. Issuing the same CREATE twice
        # silently created nothing the second time, on every server old enough
        # to use the cache (#703).
        #
        # A fresh cursor per statement, because that is what an ORM does and it
        # is what made the reuse visible.
        def run(sql):
            with self.conn.cursor() as cur:
                cur.execute(sql)

        def exists():
            # Ask the table itself rather than a data-dictionary view, so this
            # means the same thing against a real server and against the Mirror.
            try:
                run(f'SELECT 1 FROM {self.TABLE} WHERE 1 = 0')
                return True
            except seerdb.DatabaseError:
                return False

        for _ in range(3):
            run(f'CREATE TABLE {self.TABLE} (id NUMBER)')
            self.assertTrue(exists(), 'the CREATE did not take effect')
            run(f'DROP TABLE {self.TABLE}')
            self.assertFalse(exists(), 'the DROP did not take effect')

    def test_repeated_dml_still_reuses_its_cursor(self):
        # The other half: real DML must keep the cache, which is the parse it
        # exists to save. Behaviourally all that can be checked is that
        # re-executing the same statement keeps working and keeps applying.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        for n in range(3):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [n])
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (3,))

    # ----- setinputsizes types a bind the value cannot (#696) -----
    #
    # The exact type byte the declaration puts on the wire is pinned in
    # tests/test_setinputsizes.py; what is checked here is what the server makes
    # of it. The Mirror carries the declared type through to its backend (#699),
    # so the tests hold against it as well.

    def test_a_declared_type_lets_a_null_bind_take_part(self):
        # What the declaration is *for*: a NULL carries no type, the server takes
        # it as CHAR, and a CASE arm pairing it with a NUMBER column is refused
        # (ORA-00932). Declared NUMBER, the NULL takes part. Matches python-oracledb.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, d NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, 5)')
        query = (
            f'SELECT id FROM {self.TABLE} '
            'WHERE CASE WHEN :foo IS NOT NULL THEN :foo ELSE d END = d'
        )
        with self.assertRaises(seerdb.DatabaseError):
            self.cur.execute(query, {'foo': None})
        self.cur.setinputsizes(foo=seerdb.DB_TYPE_NUMBER)
        self.cur.execute(query, {'foo': None})
        self.assertEqual(self.cur.fetchall(), [(1,)])

    def test_a_declared_type_governs_how_the_value_is_sent(self):
        # A declaration tells the server what the bind is; the value then has to
        # be sent as that, or the payload does not match the descriptor and the
        # server rejects the pair (#701). Declared DATE, a microsecond value is
        # truncated; declared TIMESTAMP, it survives. Matches python-oracledb.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, d TIMESTAMP)')
        moment = datetime.datetime(2012, 10, 15, 12, 57, 18, 396)
        self.cur.setinputsizes(d=seerdb.DB_TYPE_DATE)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (id, d) VALUES (1, :d)', {'d': moment}
        )
        self.cur.execute(f'SELECT d FROM {self.TABLE} WHERE id = 1')
        self.assertEqual(self.cur.fetchall(), [(moment.replace(microsecond=0),)])
        self.cur.setinputsizes(d=seerdb.DB_TYPE_TIMESTAMP)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (id, d) VALUES (2, :d)', {'d': moment}
        )
        self.cur.execute(f'SELECT d FROM {self.TABLE} WHERE id = 2')
        self.assertEqual(self.cur.fetchall(), [(moment,)])

    def test_setinputsizes_does_not_disturb_an_ordinary_bind(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, n NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, 5)')
        self.cur.setinputsizes(n=seerdb.DB_TYPE_NUMBER)
        self.cur.execute(f'SELECT id FROM {self.TABLE} WHERE n = :n', {'n': 5})
        self.assertEqual(self.cur.fetchall(), [(1,)])

    def test_setinputsizes_positionally_and_by_python_type(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, s VARCHAR2(20))')
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 'x')")
        self.cur.setinputsizes(str)
        self.cur.execute(f'SELECT id FROM {self.TABLE} WHERE s = :1', ['x'])
        self.assertEqual(self.cur.fetchall(), [(1,)])

    def test_setinputsizes_is_spent_by_one_execute(self):
        # PEP 249: the declaration applies to the next execute and is forgotten.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.setinputsizes(seerdb.DB_TYPE_NUMBER)
        self.assertNotEqual(self.cur._inputsizes, ((), {}))
        self.cur.execute(f'SELECT id FROM {self.TABLE} WHERE id = :1', [1])
        self.assertEqual(self.cur._inputsizes, ((), {}))

    # ----- a declared bind grows to a longer value (#2564) -----
    # Its size is the bind's announced maximum length, which the server holds a
    # value to (ORA-01461). python-oracledb grows the variable to fit.

    def _stored(self, column: str, value: object) -> object:
        self.cur.execute(f'SELECT {column} FROM {self.TABLE}')
        got = self.cur.fetchone()[0]
        return got.read() if hasattr(got, 'read') else got

    def test_a_sized_string_variable_takes_a_longer_value(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, s VARCHAR2(200))')
        text = 'y' * 50
        var = self.cur.var(str, 10)
        var.setvalue(0, text)
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, :1)', [var])
        self.assertEqual(self._stored('s', text), text)

    def test_a_declared_string_size_takes_a_longer_value(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, s VARCHAR2(200))')
        text = 'y' * 50
        self.cur.setinputsizes(None, 10)
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [1, text])
        self.assertEqual(self._stored('s', text), text)

    @_requires(
        _Need(
            'a 9i server drops the connection on a CLOB bind past 4000 bytes',
            min_fv=FIELD_VERSION_10_2,
        )
    )
    def test_a_declared_varchar_takes_a_clob_past_32k(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, c CLOB)')
        text = 'z' * 40000
        self.cur.setinputsizes(None, seerdb.DB_TYPE_VARCHAR)
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [1, text])
        self.assertEqual(self._stored('c', text), text)

    def test_a_declared_long_takes_a_value_past_32k(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, l LONG)')
        text = 'x' * 40000
        self.cur.setinputsizes(None, seerdb.DB_TYPE_LONG)
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [1, text])
        self.assertEqual(self._stored('l', text), text)
        self.cur.execute(f'DELETE FROM {self.TABLE}')
        var = self.cur.var(seerdb.DB_TYPE_LONG)
        var.setvalue(0, text)
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [2, var])
        self.assertEqual(self._stored('l', text), text)

    @_requires(_ARRAY_DML)
    def test_an_array_dml_declared_bind_fits_its_longest_row(self):
        # Each row's declared bind is a variable of its own, and the one OAC an
        # array DML sends is sized from the largest.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, s VARCHAR2(200))')
        rows = [(1, 'a'), (2, 'b' * 150), (3, 'c' * 20)]
        self.cur.setinputsizes(None, 10)
        self.cur.executemany(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', rows)
        self.cur.execute(f'SELECT id, s FROM {self.TABLE} ORDER BY id')
        self.assertEqual(self.cur.fetchall(), rows)

    # ----- a wide bind's value comes after the row's others (#705) -----

    def test_a_wide_bind_before_a_plain_one_lands_in_its_own_column(self):
        # A Var(str) declares 32767 bytes; a pre-12c server takes only 4000 in
        # place and reads a wider bind's value after the row's others. Written
        # in place, the two columns silently swapped.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, a VARCHAR2(50), b VARCHAR2(50))'
        )
        wide = self.cur.var(str)
        wide.setvalue(0, 'first')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3)', [1, wide, 'second']
        )
        self.cur.execute(f'SELECT a, b FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [('first', 'second')])

    def test_executemany_with_a_declared_bind_keeps_the_columns_apart(self):
        # The shape an ORM produces: named binds, one of them declared.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, a VARCHAR2(50), b VARCHAR2(50))'
        )
        self.cur.setinputsizes(a=seerdb.DB_TYPE_VARCHAR)
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} (id, a, b) VALUES (:id, :a, :b)',
            [{'id': n, 'a': f'a{n}', 'b': f'b{n}'} for n in (1, 2, 3)],
        )
        self.cur.execute(f'SELECT id, a, b FROM {self.TABLE} ORDER BY id')
        self.assertEqual(
            self.cur.fetchall(), [(1, 'a1', 'b1'), (2, 'a2', 'b2'), (3, 'a3', 'b3')]
        )

    # ----- a 253-byte value must not ride behind a single length byte (#707) -----

    def test_a_253_byte_bind_value_round_trips(self):
        # 253 is the TTC escape byte, so a value of exactly that length sent
        # with a plain length byte is an escape where a 12c+ server expects a
        # length, and it rejected the call with ORA-03125. 252 and 254 were fine.
        for length in (252, 253, 254):
            self.cur.execute('SELECT LENGTH(:1) FROM dual', ['y' * length])
            self.assertEqual(self.cur.fetchone(), (length,))

    def test_a_253_byte_statement_runs(self):
        # The statement text takes the same length prefix on 12c+.
        for length in (252, 253, 254):
            text = 'SELECT 1 FROM dual --'
            text += 'x' * (length - len(text))
            self.cur.execute(text)
            self.assertEqual(self.cur.fetchone(), (1,))

    # ----- var() reads back as the type it was asked for (#688) -----

    def test_var_float_reads_back_as_float(self):
        # A NUMBER column can be read as an int, a float or a Decimal, and the
        # wire says nothing about which the caller wanted. Asking for a float and
        # receiving a Decimal made the type argument worthless.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (f NUMBER)')
        got = self.cur.var(float)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (f) VALUES (:1) RETURNING f INTO :2',
            [8.5514716, got],
        )
        self.assertEqual(got.getvalue(), [8.5514716])
        self.assertIsInstance(got.getvalue()[0], float)

    def test_var_float_reads_back_a_whole_number_as_float(self):
        # A NUMBER with no fractional part decodes to an int; it is still a float
        # that was asked for.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (f NUMBER)')
        got = self.cur.var(float)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (f) VALUES (:1) RETURNING f INTO :2',
            [42, got],
        )
        self.assertIsInstance(got.getvalue()[0], float)
        self.assertEqual(got.getvalue(), [42.0])

    def test_var_decimal_reads_back_as_decimal(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (f NUMBER)')
        got = self.cur.var(Decimal)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (f) VALUES (:1) RETURNING f INTO :2',
            [42, got],
        )
        self.assertIsInstance(got.getvalue()[0], Decimal)

    def test_var_float_out_of_a_plsql_block(self):
        # The same on the OUT-bind path, which carries a bare value rather than
        # the list a RETURNING clause produces.
        got = self.cur.var(float)
        self.cur.execute('BEGIN :o := 8.5514716; END;', {'o': got})
        self.assertIsInstance(got.getvalue(), float)
        self.assertEqual(got.getvalue(), 8.5514716)

    def test_an_out_assignment_reads_the_in_bind_on_its_right(self):
        # The OUT tests above all assign a literal. With a bind on the right-hand
        # side too, Mirror-over-PostgreSQL passed the function the OUT target's
        # value -- None -- instead of :p, because the SELECT it evaluates the
        # right-hand side with no longer contains :r and so its placeholders sat
        # one position off from the block's bind list (#1137). No error; just a
        # wrong answer. LENGTH is native to both servers, so this holds every leg
        # to the answer Oracle gives, at every version.
        got = self.cur.var(seerdb.NUMBER)
        self.cur.execute('BEGIN :r := LENGTH(:p); END;', {'r': got, 'p': 'hello'})
        self.assertEqual(got.getvalue(), 5)

    def test_several_out_assignments_share_an_in_bind(self):
        # The same through the multi-assignment path, with the IN bind between the
        # two OUT targets in the block's own bind order: [a, x, b].
        a = self.cur.var(seerdb.NUMBER)
        b = self.cur.var(seerdb.NUMBER)
        self.cur.execute(
            'BEGIN :a := :x + 1; :b := :x * 2; END;', {'a': a, 'x': 5, 'b': b}
        )
        self.assertEqual((a.getvalue(), b.getvalue()), (6, 10))

    def test_var_float_in_every_iteration_of_an_array_returning(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, f NUMBER)')
        got = self.cur.var(float)
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} (id, f) VALUES (:1, :2) RETURNING f INTO :3',
            [[1, 1.5, got], [2, 2.5, got]],
        )
        self.assertEqual([got.getvalue(i) for i in range(2)], [[1.5], [2.5]])

    def test_var_asked_with_a_database_type_decides_for_itself(self):
        # Asking with a database type rather than a Python one states no
        # preference, so the value arrives however that type decodes.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (f NUMBER)')
        got = self.cur.var(seerdb.DB_TYPE_NUMBER)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (f) VALUES (:1) RETURNING f INTO :2',
            [8.55, got],
        )
        self.assertIsInstance(got.getvalue()[0], Decimal)

    # ----- quoted placeholders (#686) -----

    def test_quoted_bind_names_the_plain_form_cannot_express(self):
        # The reason this spelling exists. Unquoted, each of these names is
        # refused, and each for a different reason: a reserved word with
        # ORA-01745, a leading underscore with ORA-00911, and a leading digit is
        # not a placeholder at all so nothing is bound for it. Quoting is how
        # any of them gets through.
        for name, value in (('desc', 7), ('2x', 8), ('_lead', 9)):
            with self.subTest(name=name):
                self.cur.execute(f'SELECT :"{name}" FROM dual', {f'"{name}"': value})
                self.assertEqual(self.cur.fetchall(), [(value,)])

    def test_quoted_bind_is_case_sensitive(self):
        # Two placeholders differing only in case are two different binds, which
        # is not true of the unquoted form.
        self.cur.execute('SELECT :"p", :"P" FROM dual', {'"p"': 1, '"P"': 2})
        self.assertEqual(self.cur.fetchall(), [(1, 2)])

    def test_quoted_and_plain_binds_together(self):
        self.cur.execute('SELECT :"a" + :b FROM dual', {'"a"': 1, 'b': 2})
        self.assertEqual(self.cur.fetchall(), [(3,)])

    def test_quoted_bind_repeated(self):
        # Plain SQL sends one value per textual occurrence.
        self.cur.execute('SELECT :"a", :"a" FROM dual', {'"a"': 5})
        self.assertEqual(self.cur.fetchall(), [(5, 5)])

    @_requires(_Q_QUOTING)
    def test_a_colon_word_in_a_q_literal_or_a_comment_is_no_bind(self):
        # q'[...]' is a string literal however it is quoted, and a `:z` inside
        # one -- or inside a comment -- is text, not a placeholder. Read as one,
        # named binds were refused: "missing bind value for :Z" (#1679).
        self.cur.execute("SELECT q'[it's :z]', :b /* :c */ FROM dual", {'b': 5})
        self.assertEqual(self.cur.fetchall(), [("it's :z", 5)])

    def test_quoted_bind_positional_parameters(self):
        self.cur.execute('SELECT :"p" FROM dual', [9])
        self.assertEqual(self.cur.fetchall(), [(9,)])

    def test_quoted_bind_in_returning_into(self):
        # The clause is counted by placeholder, so the quoted spelling has to be
        # visible to that count as well.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(20))')
        got = self.cur.var(int)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (id, v) VALUES (:"desc", :v) '
            'RETURNING id INTO :"out"',
            {'"desc"': 5, 'v': 'x', '"out"': got},
        )
        self.assertEqual(got.getvalue(), [5])

    def test_quoted_identifier_is_not_mistaken_for_a_bind(self):
        # A quoted table or column name looks like a quoted bind name a colon
        # short, and the closing quote of a real one must not open an identifier
        # that swallows the rest of the statement.
        self.cur.execute(f'CREATE TABLE {self.TABLE} ("Col A" NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} ("Col A") VALUES (:v)', {'v': 3})
        self.cur.execute(
            f'SELECT "Col A" FROM {self.TABLE} WHERE "Col A" = :v', {'v': 3}
        )
        self.assertEqual(self.cur.fetchall(), [(3,)])

    def test_unquoted_bind_name_stays_case_insensitive(self):
        self.cur.execute('SELECT :q FROM dual', {'Q': 4})
        self.assertEqual(self.cur.fetchall(), [(4,)])
        self.cur.execute('SELECT :Q FROM dual', {'q': 4})
        self.assertEqual(self.cur.fetchall(), [(4,)])

    # ----- positional binds -----

    def test_positional_int_string(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [7, 'alpha'])
        self.cur.execute(f'SELECT id, name FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(7, 'alpha')])

    def test_positional_tuple_accepted(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', (8, 'beta'))
        self.cur.execute(f'SELECT id, name FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(8, 'beta')])

    def test_varchar_supplementary_bind(self):
        # Binding a supplementary-plane string must encode real UTF-8 (the OAC
        # advertises AL32UTF8); otherwise the emoji corrupts on the way in (#29).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v VARCHAR2(40))')
        val = 'go 😀 端 🎉 stop'
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [val])
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(val,)])

    def test_nvarchar_bind(self):
        # Bind into an NVARCHAR2 (national charset) column, including a
        # supplementary-plane character.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v NVARCHAR2(40))')
        val = 'nat ünî 中 😀'
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [val])
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(val,)])

    def test_national_char_var_bind(self):
        # Bind full Unicode into NVARCHAR2 via the national bind type (#174).
        # Works on every tier: 9i rides it natively as AL16UTF16, where a plain
        # str bind would route through the (non-Unicode) DB charset and lose
        # characters; 10g+ get the same csfrm-2 OAC.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v NVARCHAR2(40))')
        val = 'café—Ω—日本'
        var = self.cur.var(seerdb.DB_TYPE_NVARCHAR)
        var.setvalue(0, val)
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [var])
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(val,)])

    @_requires(_NATIONAL_OUT_BIND)
    def test_national_scalar_out_bind(self):
        # A national OUT bind arrives as AL16UTF16, and the Var's charset form is
        # what says so. Without it the value came back as its raw UTF-16BE bytes
        # read one per character (#991).
        #
        # 10g+ only: on fv2 (9i / 8i) the server refuses the bind descriptor
        # outright with ORA-03120 "two-task conversion routine: integer
        # overflow", before any value comes back. That is a tier limitation, not
        # this decode -- the request bytes are identical either way.
        Var = self.cur.var(seerdb.DB_TYPE_NVARCHAR)
        self.cur.execute("BEGIN :v := N'nat \u00fcn\u00ee \u4e2d'; END;", [Var])
        self.assertEqual(Var.getvalue(), 'nat ünî 中')

    @_requires(_ASSOC_ARRAY_BIND)
    def test_array_binds_in_and_out(self):
        # Numbers in, strings in and out with one the block adds, and a NULL
        # element each way.
        Proc = 'PYORACLE_AARR'
        self.cur.execute(
            f"""CREATE OR REPLACE PACKAGE {Proc} AS
                    TYPE n IS TABLE OF NUMBER INDEX BY BINARY_INTEGER;
                    TYPE s IS TABLE OF VARCHAR2(20) INDEX BY BINARY_INTEGER;
                    PROCEDURE go(a IN n, x IN OUT s, t OUT NUMBER);
                    PROCEDURE fill(x OUT s);
                END;"""
        )
        self.cur.execute(
            f"""CREATE OR REPLACE PACKAGE BODY {Proc} AS
                    PROCEDURE go(a IN n, x IN OUT s, t OUT NUMBER) IS
                    BEGIN
                        t := 0;
                        FOR i IN 1 .. a.COUNT LOOP t := t + NVL(a(i), 100); END LOOP;
                        FOR i IN 1 .. x.COUNT LOOP
                            IF x(i) IS NOT NULL THEN x(i) := x(i) || 'Z'; END IF;
                        END LOOP;
                        x(x.COUNT + 1) := 'new';
                        x(x.COUNT + 1) := NULL;
                    END;
                    PROCEDURE fill(x OUT s) IS
                    BEGIN
                        x(1) := 'one';
                        x(2) := 'two';
                    END;
                END;"""
        )
        try:
            Nums = self.cur.arrayvar(seerdb.DB_TYPE_NUMBER, [10, 20, None])
            Strs = self.cur.arrayvar(seerdb.DB_TYPE_VARCHAR, 6, 20)
            Strs.setvalue(0, ['ab', None, 'cde'])
            Total = self.cur.var(seerdb.DB_TYPE_NUMBER)
            self.cur.execute(f'BEGIN {Proc}.go(:1, :2, :3); END;', [Nums, Strs, Total])
            self.assertEqual(Total.getvalue(), 130)
            self.assertEqual(Strs.getvalue(), ['abZ', None, 'cdeZ', 'new', None])
            Out = self.cur.arrayvar(seerdb.DB_TYPE_VARCHAR, 4, 20)
            self.cur.execute(f'BEGIN {Proc}.fill(:1); END;', [Out])
            self.assertEqual(Out.getvalue(), ['one', 'two'])
        finally:
            self.cur.execute(f'DROP PACKAGE {Proc}')

    @_requires(_ASSOC_ARRAY_BIND)
    def test_national_array_bind_round_trip(self):
        # PL/SQL-bound: an associative array lives in a PL/SQL PACKAGE (#1127).
        # An associative array of NVARCHAR2 in both directions (#991). The
        # element is encoded as a bare value, so it never saw the bind's charset
        # form: going out it went as UTF-8 and the server read those bytes as
        # UTF-16BE, silently halving every string.
        Proc = 'PYORACLE_NARR'
        self.cur.execute(
            f"""CREATE OR REPLACE PACKAGE {Proc} AS
                    TYPE t IS TABLE OF NVARCHAR2(60) INDEX BY BINARY_INTEGER;
                    FUNCTION total_len(a t) RETURN NUMBER;
                    PROCEDURE echo(a IN OUT t);
                END;"""
        )
        self.cur.execute(
            f"""CREATE OR REPLACE PACKAGE BODY {Proc} AS
                    FUNCTION total_len(a t) RETURN NUMBER IS
                        n NUMBER := 0;
                    BEGIN
                        FOR i IN 1 .. a.COUNT LOOP n := n + LENGTH(a(i)); END LOOP;
                        RETURN n;
                    END;
                    PROCEDURE echo(a IN OUT t) IS
                    BEGIN
                        FOR i IN 1 .. a.COUNT LOOP a(i) := a(i) || N'\u00e9'; END LOOP;
                    END;
                END;"""
        )
        try:
            Values = ['nat \u00fcn\u00ee \u4e2d', 'caf\u00e9 \u65e5\u672c']
            # IN: the server must count CHARACTERS, not halved UTF-8 bytes.
            Arr = self.cur.arrayvar(seerdb.DB_TYPE_NVARCHAR, Values)
            Total = self.cur.var(seerdb.DB_TYPE_NUMBER)
            self.cur.execute(f'BEGIN :n := {Proc}.total_len(:a); END;', [Total, Arr])
            self.assertEqual(Total.getvalue(), sum(len(V) for V in Values))
            # IN OUT: and what comes back decodes from AL16UTF16.
            Arr2 = self.cur.arrayvar(seerdb.DB_TYPE_NVARCHAR, Values)
            self.cur.execute(f'BEGIN {Proc}.echo(:a); END;', [Arr2])
            self.assertEqual(Arr2.getvalue(), [V + 'é' for V in Values])
        finally:
            from seerdb.common.exceptions import DatabaseError

            try:
                self.cur.execute(f'DROP PACKAGE {Proc}')
            except DatabaseError:
                pass

    def test_a_bc_date_is_out_of_range_not_malformed(self):
        # Oracle's DATE runs from 4712 BC; Python's datetime starts at year 1. The
        # value is correct -- it was reported as "malformed" (#1060). It is now
        # both a DataError and a ValueError, as python-oracledb raises.
        from seerdb.common.exceptions import DataError, DateOutOfRangeError

        # The precondition is a server that really HOLDS a BC date. Not every
        # backend does: Mirror-over-PostgreSQL drops the sign and returns 4712
        # AD, so there is nothing out of range to report. Ask the server itself,
        # as text, and skip with its answer when it disagrees.
        self.cur.execute(
            "SELECT TO_CHAR(TO_DATE('-4712-01-01', 'SYYYY-MM-DD'), 'SYYYY-MM-DD') "
            'FROM dual'
        )
        (AsText,) = self.cur.fetchone()
        if AsText.strip() != '-4712-01-01':
            self.skipTest(f'this server does not hold a BC date: it says {AsText!r}')
        # Both calls sit inside the block: the row is prefetched, so the decode
        # -- and the raise -- happens in execute(), before fetchone() is reached.
        with self.assertRaises(DateOutOfRangeError) as caught:
            self.cur.execute("SELECT TO_DATE('-4712-01-01', 'SYYYY-MM-DD') FROM dual")
            self.cur.fetchone()
        self.assertIsInstance(caught.exception, DataError)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertNotIn('malformed', str(caught.exception))

    def test_a_julian_leap_day_is_out_of_range_not_malformed(self):
        # Oracle's DATE is Julian before 1582-10-15, so 1500-02-29 is a valid
        # date that Python's Gregorian datetime cannot hold. It was reported as
        # "malformed" (#2601), and a passthrough Mirror could not relay it. A
        # server that cannot hold the date -- Mirror-over-PostgreSQL (#2600) --
        # is skipped, asked as text first.
        from seerdb.common.exceptions import DataError, DateOutOfRangeError

        try:
            self.cur.execute(
                "SELECT TO_CHAR(TO_DATE('1500-02-29', 'YYYY-MM-DD'), 'YYYY-MM-DD') "
                'FROM dual'
            )
            (AsText,) = self.cur.fetchone()
        except seerdb.DatabaseError as exc:
            self.skipTest(f'this server does not hold 1500-02-29: {exc}')
        if AsText != '1500-02-29':
            self.skipTest(f'this server does not hold 1500-02-29: it says {AsText!r}')
        with self.assertRaises(DateOutOfRangeError) as caught:
            self.cur.execute("SELECT TO_DATE('1500-02-29', 'YYYY-MM-DD') FROM dual")
            self.cur.fetchone()
        self.assertIsInstance(caught.exception, DataError)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertNotIn('malformed', str(caught.exception))

    def test_db_charset_varchar_roundtrip(self):
        # VARCHAR2 non-ASCII that the database charset can represent round-trips
        # (#174). On 9i (WE8ISO8859P1) the server converts the AL32UTF8 session
        # bytes to its Latin-1 DB charset and back; decoding by the column's DB
        # charset instead of the session charset used to mojibake it.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v VARCHAR2(40))')
        val = 'café déjà vu'  # Latin-1-representable
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [val])
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(val,)])

    def test_null_bind(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [9, None])
        self.cur.execute(f'SELECT name FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(None,)])

    # ----- types -----

    def test_decimal_round_trip(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v NUMBER(12, 4))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [Decimal('3.1415')])
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (Decimal('3.1415'),))

    def test_integer_decimal_round_trips_as_int(self):
        # A Decimal with no fractional part comes back as int, not Decimal.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [Decimal('42')])
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (42,))

    def test_date_round_trip(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (d DATE)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (:1)',
            [datetime.datetime(2026, 5, 23, 10, 11, 12)],
        )
        self.cur.execute(f'SELECT d FROM {self.TABLE}')
        self.assertEqual(
            self.cur.fetchone(), (datetime.datetime(2026, 5, 23, 10, 11, 12),)
        )

    def test_timestamp_round_trip(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (t TIMESTAMP)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (:1)',
            [datetime.datetime(2026, 5, 23, 10, 11, 12, 345678)],
        )
        self.cur.execute(f'SELECT t FROM {self.TABLE}')
        self.assertEqual(
            self.cur.fetchone(),
            (datetime.datetime(2026, 5, 23, 10, 11, 12, 345678),),
        )

    def test_timestamptz_round_trip(self):
        Tz = datetime.timezone(datetime.timedelta(hours=-5, minutes=-30))
        Value = datetime.datetime(2026, 5, 23, 10, 11, 12, 345678, tzinfo=Tz)
        self.cur.execute(f'CREATE TABLE {self.TABLE} (t TIMESTAMP WITH TIME ZONE)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [Value])
        self.cur.execute(f'SELECT t FROM {self.TABLE}')
        Got = self.cur.fetchone()[0]
        # The instant must match; the tagged offset must round-trip.
        self.assertEqual(Got, Value)
        self.assertEqual(Got.utcoffset(), Value.utcoffset())

    def test_to_timestamp_is_a_timestamp(self):
        # TO_TIMESTAMP gives a TIMESTAMP, fractional seconds and all. A
        # Mirror-over-PG gave a timestamptz, which described as WITH LOCAL TIME
        # ZONE and matched no function taking a TIMESTAMP (#1321).
        self.cur.execute(
            "SELECT to_timestamp('20080912 16:40:00.125', 'YYYYMMDD HH24:MI:SS.FF') "
            'FROM dual'
        )
        self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_TIMESTAMP)
        self.assertEqual(
            self.cur.fetchone(), (datetime.datetime(2008, 9, 12, 16, 40, 0, 125000),)
        )

    def test_to_timestamp_tz_with_an_offset(self):
        # TO_TIMESTAMP_TZ reads the zone off the text: an offset for TZH:TZM,
        # which the value keeps. The python-oracledb suite builds its time-zone
        # test data this way; a Mirror-over-PG had no TO_TIMESTAMP_TZ (#1300).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (t TIMESTAMP WITH TIME ZONE)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (to_timestamp_tz('
            "'20220602 13:45:06.25 +01:30', 'YYYYMMDD HH24:MI:SS.FF TZH:TZM'))"
        )
        self.cur.execute(f'SELECT t FROM {self.TABLE}')
        Got = self.cur.fetchone()[0]
        Tz = datetime.timezone(datetime.timedelta(hours=1, minutes=30))
        self.assertEqual(Got, datetime.datetime(2022, 6, 2, 13, 45, 6, 250000, Tz))
        self.assertEqual(Got.utcoffset(), datetime.timedelta(hours=1, minutes=30))

    def test_to_timestamp_tz_with_a_region(self):
        # A region for TZR, which gets the offset in force on that date: US/Eastern
        # is five hours behind UTC in January (#1300).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (t TIMESTAMP WITH TIME ZONE)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (to_timestamp_tz('
            "'20220112 10:00 US/Eastern', 'YYYYMMDD HH24:MI TZR'))"
        )
        self.cur.execute(f'SELECT t FROM {self.TABLE}')
        Got = self.cur.fetchone()[0]
        self.assertEqual(Got.utcoffset(), datetime.timedelta(hours=-5))
        self.assertEqual(
            Got.astimezone(datetime.timezone.utc),
            datetime.datetime(2022, 1, 12, 15, 0, tzinfo=datetime.timezone.utc),
        )

    def test_a_timestamp_stored_into_a_timestamptz_column(self):
        # Oracle converts a TIMESTAMP, or a TIMESTAMP WITH LOCAL TIME ZONE, into
        # a WITH TIME ZONE column in the session's zone. A Mirror-over-PG had no
        # way to store either there at all (#1310).
        self.cur.execute('SELECT sessiontimezone FROM dual')
        (zone,) = self.cur.fetchone()
        self.cur.execute("ALTER SESSION SET TIME_ZONE = '+03:00'")
        try:
            self.cur.execute(
                f'CREATE TABLE {self.TABLE} (id NUMBER, t TIMESTAMP WITH TIME ZONE)'
            )
            self.cur.execute(
                f"INSERT INTO {self.TABLE} VALUES (1, timestamp '2022-06-03 10:00:00')"
            )
            self.cur.execute(
                f'INSERT INTO {self.TABLE} VALUES (2, CAST(timestamp '
                "'2022-06-03 10:00:00' AS TIMESTAMP WITH LOCAL TIME ZONE))"
            )
            self.cur.execute(f'SELECT t FROM {self.TABLE} ORDER BY id')
            got = [row[0] for row in self.cur.fetchall()]
        finally:
            self.cur.execute(f"ALTER SESSION SET TIME_ZONE = '{zone}'")
        Tz = datetime.timezone(datetime.timedelta(hours=3))
        expected = datetime.datetime(2022, 6, 3, 10, 0, tzinfo=Tz)
        self.assertEqual(got, [expected, expected])
        for value in got:
            self.assertEqual(value.utcoffset(), datetime.timedelta(hours=3))

    def test_decode_of_a_converted_null_and_a_timestamptz(self):
        # DECODE chooses between a NULL converted to a timestamp and a WITH TIME
        # ZONE value; either lands in a WITH TIME ZONE column. The
        # python-oracledb suite populates its time-zone tables this way; a
        # Mirror-over-PG refused the translated CASE (#1306). Oracle types a
        # DECODE by its first result, so the WITH TIME ZONE value becomes a
        # plain TIMESTAMP first: it keeps its wall-clock time and loses its
        # offset, and the column then takes it in the session's zone.
        self.cur.execute('SELECT sessiontimezone FROM dual')
        (zone,) = self.cur.fetchone()
        self.cur.execute("ALTER SESSION SET TIME_ZONE = '+03:00'")
        try:
            self.cur.execute(
                f'CREATE TABLE {self.TABLE} (id NUMBER, t TIMESTAMP WITH TIME ZONE)'
            )
            for n in (1, 2):
                self.cur.execute(
                    f'INSERT INTO {self.TABLE} VALUES ({n}, decode(mod({n}, 2), 0, '
                    "to_timestamp(null, 'YYYYMMDD'), "
                    "from_tz(timestamp '2022-06-03 10:00:00', '+05:30')))"
                )
            self.cur.execute(f'SELECT t FROM {self.TABLE} ORDER BY id')
            got = [row[0] for row in self.cur.fetchall()]
        finally:
            self.cur.execute(f"ALTER SESSION SET TIME_ZONE = '{zone}'")
        Tz = datetime.timezone(datetime.timedelta(hours=3))
        self.assertEqual(got, [datetime.datetime(2022, 6, 3, 10, 0, tzinfo=Tz), None])
        self.assertEqual(got[0].utcoffset(), datetime.timedelta(hours=3))

    @_requires(_TRUNC_TIMESTAMP)
    def test_trunc_and_round_of_a_timestamptz(self):
        # TRUNC and ROUND of a WITH TIME ZONE value work on its own wall-clock
        # time and give a DATE. 2022-06-08 00:00:10 +05:30 is 2022-06-07 in UTC,
        # which a Mirror-over-PG used to truncate in a UTC session (#1313).
        self.cur.execute('SELECT sessiontimezone FROM dual')
        (zone,) = self.cur.fetchone()
        self.cur.execute("ALTER SESSION SET TIME_ZONE = '+00:00'")
        try:
            self.cur.execute(f'CREATE TABLE {self.TABLE} (t TIMESTAMP WITH TIME ZONE)')
            self.cur.execute(
                f'INSERT INTO {self.TABLE} VALUES '
                "(from_tz(timestamp '2022-06-08 00:00:10', '+05:30'))"
            )
            self.cur.execute(
                f"SELECT trunc(t), trunc(t, 'MM'), round(t) FROM {self.TABLE}"
            )
            got = self.cur.fetchone()
        finally:
            self.cur.execute(f"ALTER SESSION SET TIME_ZONE = '{zone}'")
        self.assertEqual(
            got,
            (
                datetime.datetime(2022, 6, 8),
                datetime.datetime(2022, 6, 1),
                datetime.datetime(2022, 6, 8),
            ),
        )

    def test_a_not_null_column_is_described_as_not_nullable(self):
        # A column declared NOT NULL is described with null_ok false; a nullable
        # one and a computed one with it true. A Mirror-over-PG described every
        # column as nullable (#1307).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (a NUMBER(9) NOT NULL, b VARCHAR2(10))'
        )
        self.cur.execute(f'SELECT a, b, a + 1 AS c FROM {self.TABLE}')
        null_ok = [column[6] for column in self.cur.description]
        self.assertEqual(null_ok, [False, True, True])

    def test_a_timestamp_column_describes_its_precision(self):
        # A TIMESTAMP column, with or without a time zone, is described with
        # precision 0 and its fractional-seconds precision as the scale: the
        # declared one, else 6. A Mirror-over-PG described neither (#1308).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (a TIMESTAMP(3), b TIMESTAMP, '
            'c TIMESTAMP(5) WITH LOCAL TIME ZONE, d TIMESTAMP(2) WITH TIME ZONE, '
            'f TIMESTAMP WITH TIME ZONE)'
        )
        self.cur.execute(f'SELECT a, b, c, d, f FROM {self.TABLE}')
        self.assertEqual(
            [(column[4], column[5]) for column in self.cur.description],
            [(0, 3), (0, 6), (0, 5), (0, 2), (0, 6)],
        )

    def test_a_date_column_is_described_as_a_date(self):
        # A DATE column is described as a DATE, with neither precision nor
        # scale, and keeps its time of day. A Mirror-over-PG described it as a
        # TIMESTAMP (#1316).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (d DATE)')
        value = datetime.datetime(2022, 6, 3, 13, 14, 15)
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [value])
        self.cur.execute(f'SELECT d FROM {self.TABLE}')
        column = self.cur.description[0]
        self.assertIs(column[1], seerdb.DB_TYPE_DATE)
        self.assertEqual((column[4], column[5]), (None, None))
        self.assertEqual(self.cur.fetchone(), (value,))

    def test_timestamptz_plus_and_minus_an_interval(self):
        # A WITH TIME ZONE value moved by an INTERVAL keeps its own offset, in
        # either operand order. The python-oracledb suite builds its time-zone
        # test data this way; a Mirror-over-PG returned a plain value that lost
        # the offset and did not fit the column (#1301).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, t TIMESTAMP WITH TIME ZONE)'
        )
        start = "from_tz(timestamp '2022-06-03 00:00:00', '+05:30')"
        step = "interval '2 00:00:03.125' day to second"
        for n, expr in (
            (1, f'{start} + {step}'),
            (2, f'{step} + {start}'),
            (3, f'{start} - {step}'),
        ):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES ({n}, {expr})')
        self.cur.execute(f'SELECT t FROM {self.TABLE} ORDER BY id')
        got = [row[0] for row in self.cur.fetchall()]
        Tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
        later = datetime.datetime(2022, 6, 5, 0, 0, 3, 125000, Tz)
        earlier = datetime.datetime(2022, 5, 31, 23, 59, 56, 875000, Tz)
        self.assertEqual(got, [later, later, earlier])
        for value in got:
            self.assertEqual(value.utcoffset(), datetime.timedelta(hours=5, minutes=30))

    def test_binary_float_bind(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v BINARY_FLOAT)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (:1)', [seerdb.BinaryFloat(-2.25)]
        )
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (-2.25,))

    def test_binary_double_bind(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v BINARY_DOUBLE)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (:1)', [seerdb.BinaryDouble(1234.5678)]
        )
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (1234.5678,))

    def test_binary_double_nonfinite_bind(self):
        # inf / nan can't be NUMBER; a plain float auto-routes to BINARY_DOUBLE.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v BINARY_DOUBLE)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [float('inf')])
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [float('nan')])
        self.cur.execute(f'SELECT v FROM {self.TABLE} ORDER BY 1')
        rows = self.cur.fetchall()
        self.assertEqual(rows[0], (math.inf,))
        self.assertTrue(math.isnan(rows[1][0]))

    def test_a_float_number_bind_keeps_every_digit(self):
        # A float binds as NUMBER with its shortest round-trip digits, as
        # python-oracledb sends it, so the server holds the float the client
        # does: 1/3 kept 15 of its 16 digits and 2**53 + 2 read back as
        # 9007199254740990 (#2576).
        for value in (
            1 / 3,
            -2 / 3,
            0.1 + 0.2,
            float(2**53 + 2),
            1e15 + 0.25,
            9.9e125,
            1.2345678901234566e125,
            1.5e-130,
        ):
            with self.subTest(value=value):
                self.cur.execute('SELECT :1, TO_CHAR(:1) FROM dual', [value])
                (got, text) = self.cur.fetchone()
                self.assertEqual(float(got), value)
                self.assertEqual(float(text), value)

    def test_a_number_bind_out_of_range_is_refused(self):
        # Past 1e126 the encoder raised a bare ValueError, and below 1e-130 it
        # bound a different, negative value: 1e-131 arrived as -9e-129
        # (#2575). Like python-oracledb, the driver refuses it before sending
        # anything, and the connection goes on.
        for value in (1e126, -1e126, 1e-131, 5e-324, Decimal('-1E-131'), 10**126):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    seerdb.DataError, 'cannot be represented as an Oracle number'
                ):
                    self.cur.execute('SELECT :1 FROM dual', [value])
        self.cur.execute('SELECT 1 FROM dual')
        self.assertEqual(self.cur.fetchone(), (1,))

    def test_date_differences_and_months_between_keep_oracles_digits(self):
        # A NUMBER keeps twenty base-100 digits; over PostgreSQL a DATE
        # difference kept 16 decimals and MONTHS_BETWEEN, orafce's, 15
        # (#2597). MONTHS_BETWEEN rounds its fraction of a month before adding
        # the whole months, so one near zero keeps fewer: 23ai's answers.
        def d(text):
            return f"TO_DATE('{text}', 'YYYY-MM-DD HH24:MI:SS')"

        for expr, value in (
            (
                f'{d("2020-01-15 10:20:30")} - {d("2020-01-01 00:00:00")}',
                '14.43090277777777777777777777777777777778',
            ),
            (
                f'{d("2020-01-01 00:00:00")} - {d("2020-01-01 08:00:00")}',
                '-0.3333333333333333333333333333333333333333',
            ),
            (
                f'{d("2020-01-01 00:00:01")} - {d("2020-01-01 00:00:00")}',
                '0.00001157407407407407407407407407407407407407',
            ),
            (
                f'{d("2019-01-01 00:00:00")} - {d("2020-12-31 23:59:59")}',
                '-730.999988425925925925925925925925925926',
            ),
            (
                f'MONTHS_BETWEEN({d("2020-01-15 10:20:30")}, {d("2019-11-03 04:00:00")})',
                '2.39562051971326164874551971326164874552',
            ),
            (
                f'MONTHS_BETWEEN({d("2020-02-28 00:00:00")}, {d("2020-01-31 00:00:00")})',
                '0.9032258064516129032258064516129032258065',
            ),
            (
                f'MONTHS_BETWEEN({d("1999-12-31 23:59:59")}, {d("2000-01-01 00:00:00")})',
                '-3.733572281959378733572281959378734E-7',
            ),
            (
                f'MONTHS_BETWEEN({d("2020-03-31 00:00:00")}, {d("2020-02-29 00:00:00")})',
                '1',
            ),
            (
                f'MONTHS_BETWEEN({d("2020-03-15 12:00:00")}, {d("2020-02-15 00:00:00")})',
                '1',
            ),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                self.assertEqual(self.cur.fetchone(), (Decimal(value),))
                self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_NUMBER)

    def test_a_date_mixed_with_another_date_stays_a_date(self):
        # NVL, NVL2, GREATEST, LEAST or DECODE of two DATEs is a DATE, so its
        # difference with a date is a number of days. Over PostgreSQL a TO_DATE
        # was orafce's own DATE beside the Mirror's, and a mix of the two -- or
        # any GREATEST or LEAST -- a timestamp, the difference an INTERVAL
        # (#2596).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (d DATE, e DATE)')
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (TO_DATE('2020-01-15 12:00', "
            "'YYYY-MM-DD HH24:MI'), TO_DATE('2020-01-10', 'YYYY-MM-DD'))"
        )
        to_date = "TO_DATE('2020-01-01', 'YYYY-MM-DD')"
        bind = datetime.datetime(2020, 1, 5)
        for expr, binds, days in (
            (f'NVL(d, {to_date}) - e', [], Decimal('5.5')),
            (f'NVL2(d, {to_date}, e) - e', [], -9),
            ('GREATEST(d, e) - e', [], Decimal('5.5')),
            (f'LEAST(d, {to_date}) - e', [], -9),
            ('GREATEST(d, SYSDATE) - SYSDATE', [], 0),
            (f'DECODE(1, 1, {to_date}, d) - e', [], -9),
            (f'NVL(:1, {to_date}) - e', [bind], -5),
            ('GREATEST(:1, e) - :1', [bind], 5),
            # A DATE literal and a CAST to DATE were orafce's DATE (#2603).
            ("NVL(d, DATE '2020-01-01') - e", [], Decimal('5.5')),
            ("GREATEST(d, DATE '2020-01-01') - e", [], Decimal('5.5')),
            ("NVL2(d, DATE '2020-01-01', e) - e", [], -9),
            ('DECODE(1, 1, CAST(d AS DATE), e) - e', [], Decimal('5.5')),
            (f'NVL(CAST(d AS DATE), {to_date}) - e', [], Decimal('5.5')),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM {self.TABLE}', binds)
                self.assertEqual(self.cur.fetchone(), (days,))
                self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_NUMBER)

    def test_dates_before_1582_are_julian(self):
        # Oracle's DATE follows the Julian calendar before 1582-10-15: no days
        # between 10-04 and 10-15, a leap year every fourth year, and a day
        # literal in the gap read as 10-15. Over PostgreSQL, Gregorian
        # throughout, each was off by up to ten days (#2600).
        for expr, value in (
            ("DATE '1582-10-15' - DATE '1582-10-04'", 1),
            ("DATE '1500-03-01' - DATE '1500-02-28'", 2),
            ("DATE '1600-01-01' - DATE '1500-01-01'", 36515),
            ("DATE '2020-01-15' - DATE '1020-07-04'", 365066),
            ("TO_CHAR(DATE '1582-10-04' + 1, 'YYYY-MM-DD')", '1582-10-15'),
            (
                "TO_CHAR(DATE '1582-10-15' - 0.25, 'YYYY-MM-DD HH24:MI')",
                '1582-10-04 18:00',
            ),
            ("TO_CHAR(DATE '1000-01-01' + 365000, 'YYYY-MM-DD')", '1999-05-09'),
            (
                "TO_CHAR(TO_DATE('1582-10-05 13:00', 'YYYY-MM-DD HH24:MI'), "
                "'YYYY-MM-DD HH24:MI')",
                '1582-10-15 13:00',
            ),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                self.assertEqual(self.cur.fetchone(), (value,))

    @_requires(_GAP_DATE_LITERAL)
    def test_a_date_literal_in_the_1582_gap_is_1582_10_15(self):
        # From 18c, a DATE or TIMESTAMP literal of a day the calendar lacks is
        # 1582-10-15 at the same time, as TO_DATE's is everywhere (#2600).
        for expr, value in (
            ("TO_CHAR(DATE '1582-10-10', 'YYYY-MM-DD')", '1582-10-15'),
            (
                "TO_CHAR(TIMESTAMP '1582-10-10 01:02:03', 'YYYY-MM-DD HH24:MI:SS')",
                '1582-10-15 01:02:03',
            ),
            ("TO_CHAR(DATE '1582-10-14' + 1, 'YYYY-MM-DD')", '1582-10-16'),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                self.assertEqual(self.cur.fetchone(), (value,))

    def test_day_counting_formats_before_1582_are_julian(self):
        # TO_CHAR's day-counting elements, TO_DATE's J, TRUNC and ROUND to an
        # ISO week and NEXT_DAY count Julian days before 1582-10-15. Over
        # PostgreSQL the weekday was ten days off and the day of the year a
        # Julian February 29 short (#2600).
        d = "TO_DATE('1582-10-04 13:45:06', 'YYYY-MM-DD HH24:MI:SS')"
        for expr, value in (
            (f"TO_CHAR({d}, 'DY J DDD WW IW IYYY')", 'THU 2299160 277 40 40 1582'),
            (
                "TO_CHAR(TO_DATE('1500-12-31', 'YYYY-MM-DD'), 'Dy DDD WW IW')",
                'Thu 366 53 53',
            ),
            (f"TO_CHAR(TRUNC({d}, 'IW'), 'YYYY-MM-DD')", '1582-10-01'),
            (f"TO_CHAR(TRUNC({d}, 'WW'), 'YYYY-MM-DD')", '1582-10-01'),
            (f"TO_CHAR(ROUND({d}, 'IW'), 'YYYY-MM-DD')", '1582-10-18'),
            (
                f"TO_CHAR(NEXT_DAY({d}, 'FRIDAY'), 'YYYY-MM-DD HH24:MI:SS')",
                '1582-10-15 13:45:06',
            ),
            ("TO_CHAR(TO_DATE('2299160', 'J'), 'YYYY-MM-DD')", '1582-10-04'),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                self.assertEqual(self.cur.fetchone(), (value,))

    def test_fm_is_a_toggle(self):
        # Oracle's FM turns fill mode off for every element after it, and a
        # second FM back on; quoted text and punctuation are left as they are.
        # Over PostgreSQL FM applied to the next element alone (#2607).
        d = "TO_DATE('2020-03-07 01:05:09', 'YYYY-MM-DD HH24:MI:SS')"
        for fmt, value in (
            ('fmHH:MI:SS', '1:5:9'),
            ('HH:fmMI:SS', '01:5:9'),
            ('fmDD fmMM', '7 03'),
            ('fmDay, DD Month YYYY', 'Saturday, 7 March 2020'),
            ('FMDD"x"MM', '7x3'),
            ('DD-fm-MM', '07--3'),
            ('fmyyyy-mm-dd', '2020-3-7'),
        ):
            with self.subTest(fmt=fmt):
                self.cur.execute(f"SELECT TO_CHAR({d}, '{fmt}') FROM dual")
                self.assertEqual(self.cur.fetchone(), (value,))
        # A number format's FM is its own, and the session's date format
        # toggles as a TO_CHAR's does.
        self.cur.execute("SELECT TO_CHAR(5, 'FM009') FROM dual")
        self.assertEqual(self.cur.fetchone(), ('005',))
        conn = _connect_with()
        try:
            cur = conn.cursor()
            cur.execute("ALTER SESSION SET NLS_DATE_FORMAT = 'fmDD.MM.YYYY HH24:MI'")
            cur.execute(f'SELECT TO_CHAR({d}) FROM dual')
            self.assertEqual(cur.fetchone(), ('7.3.2020 1:5',))
        finally:
            conn.close()

    @_requires(_INTERVAL)
    def test_timestamp_arithmetic_before_1582_is_julian(self):
        # TIMESTAMP - TIMESTAMP and TIMESTAMP +/- INTERVAL count Oracle's Julian
        # days before 1582-10-15, as DATE arithmetic does. Over PostgreSQL each
        # was off by up to ten days (#2600).
        f = "'YYYY-MM-DD HH24:MI:SS'"
        for expr, value in (
            (
                "EXTRACT(DAY FROM (TIMESTAMP '1582-10-15 00:00:00' "
                "- TIMESTAMP '1582-10-04 00:00:00'))",
                1,
            ),
            (
                "EXTRACT(DAY FROM (TIMESTAMP '1500-03-01 00:00:00' "
                "- TIMESTAMP '1500-02-28 00:00:00'))",
                2,
            ),
            (
                "EXTRACT(DAY FROM (TIMESTAMP '2020-01-15 00:00:00' "
                "- TIMESTAMP '1020-07-04 00:00:00'))",
                365066,
            ),
            (
                f"TO_CHAR(TIMESTAMP '1582-10-04 12:00:00' + INTERVAL '12' HOUR, {f})",
                '1582-10-15 00:00:00',
            ),
            (
                "TO_CHAR(TIMESTAMP '1582-10-15 01:00:00' "
                f"- INTERVAL '1 02:00:00' DAY TO SECOND, {f})",
                '1582-10-03 23:00:00',
            ),
            (
                f"TO_CHAR(INTERVAL '1' DAY + TIMESTAMP '1582-10-04 08:00:00', {f})",
                '1582-10-15 08:00:00',
            ),
            (
                "TO_CHAR(TIMESTAMP '1000-01-01 00:00:00' + INTERVAL '365000' DAY(6), "
                "'YYYY-MM-DD')",
                '1999-05-09',
            ),
            (
                "TO_CHAR(DATE '1582-10-15' - INTERVAL '1' DAY, 'YYYY-MM-DD')",
                '1582-10-04',
            ),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                self.assertEqual(self.cur.fetchone(), (value,))

    @_requires(_INTERVAL)
    def test_an_intervals_months_on_a_missing_day_are_refused(self):
        # A DATE or TIMESTAMP plus an interval's months on a day the month
        # lacks is ORA-01839, as is a WITH TIME ZONE value's, whose months move
        # it in UTC, and a WITH LOCAL TIME ZONE value's, in the session's zone.
        # Over PostgreSQL the month ended short (#2611). ADD_MONTHS ends it
        # short on Oracle too.
        for expr in (
            "DATE '2020-01-31' + INTERVAL '1' MONTH",
            "TIMESTAMP '2020-02-29 10:00:00' + INTERVAL '1' YEAR",
            "TIMESTAMP '2020-05-31 00:00:00' - INTERVAL '1' MONTH",
            "INTERVAL '1-1' YEAR TO MONTH + DATE '2020-01-30'",
            "TIMESTAMP '2020-02-01 02:00:00 +05:00' + INTERVAL '1' MONTH",
            "TIMESTAMP '1500-01-30 00:00:00' + INTERVAL '1' MONTH",
            # The 31st in any session zone within 12 hours of UTC.
            "CAST(TIMESTAMP '2020-01-31 12:00:00 +00:00' AS TIMESTAMP WITH LOCAL TIME ZONE) "
            "+ INTERVAL '1' MONTH",
        ):
            with self.subTest(expr=expr):
                with self.assertRaises(seerdb.DatabaseError) as ctx:
                    self.cur.execute(f'SELECT {expr} FROM dual')
                    self.cur.fetchall()
                self.assertEqual(ctx.exception.code, 1839)
        f = "'YYYY-MM-DD HH24:MI'"
        for expr, value in (
            (
                f"TO_CHAR(DATE '2020-01-31' + INTERVAL '2' MONTH, {f})",
                '2020-03-31 00:00',
            ),
            (
                f"TO_CHAR(DATE '2020-02-29' - INTERVAL '4' YEAR, {f})",
                '2016-02-29 00:00',
            ),
            (
                f"TO_CHAR(DATE '2020-01-31' + INTERVAL '30' DAY, {f})",
                '2020-03-01 00:00',
            ),
            (f"TO_CHAR(ADD_MONTHS(DATE '2020-01-31', 1), {f})", '2020-02-29 00:00'),
            (
                "TO_CHAR(SYS_EXTRACT_UTC(TIMESTAMP '2020-01-30 00:00:00 +03:00' "
                f"+ INTERVAL '1' MONTH), {f})",
                '2020-02-29 21:00',
            ),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                self.assertEqual(self.cur.fetchone(), (value,))

    def test_a_date_bind_is_a_date(self):
        # seerdb binds a datetime without a fraction as a DATE, as Oracle's
        # clients do, and Oracle types the bind and every expression over it
        # so: the difference of two is a NUMBER of days. Over PostgreSQL it was
        # a timestamp, and the difference an INTERVAL DAY TO SECOND (#2593).
        a = datetime.datetime(2020, 1, 15, 10, 20, 30)
        b = datetime.datetime(2020, 1, 10, 4, 20, 30)
        self.cur.execute('SELECT :1 - :2, :1, NVL(:1, SYSDATE) - :2 FROM dual', [a, b])
        self.assertEqual(self.cur.fetchone(), (Decimal('5.25'), a, Decimal('5.25')))
        self.assertEqual(
            [d[1] for d in self.cur.description],
            [seerdb.DB_TYPE_NUMBER, seerdb.DB_TYPE_DATE, seerdb.DB_TYPE_NUMBER],
        )
        self.cur.execute('SELECT DUMP(:1) FROM dual', [a])
        self.assertEqual(self.cur.fetchone(), ('Typ=12 Len=7: 120,120,1,15,11,21,31',))

    @_requires(_BINARY_FLOAT_SERVER)
    def test_declared_binary_float_and_double_binds_keep_their_type(self):
        # Oracle types a bind by the type the client declared, not by its
        # value: 1.5 declared BINARY_FLOAT describes as one, BINARY_DOUBLE as
        # the other, and undeclared as a NUMBER. Through the Mirror both
        # declared binds came back NUMBER over the passthrough and
        # BINARY_DOUBLE over PostgreSQL (#2562).
        for declared, described, value in (
            (seerdb.DB_TYPE_BINARY_FLOAT, seerdb.DB_TYPE_BINARY_FLOAT, 1.5),
            (seerdb.DB_TYPE_BINARY_DOUBLE, seerdb.DB_TYPE_BINARY_DOUBLE, 1.5),
            (None, seerdb.DB_TYPE_NUMBER, Decimal('1.5')),
        ):
            with self.subTest(declared=declared):
                if declared is not None:
                    self.cur.setinputsizes(declared)
                self.cur.execute('SELECT :1 FROM dual', [1.5])
                (got,) = self.cur.fetchone()
                self.assertIs(self.cur.description[0][1], described)
                self.assertEqual(got, value)
                self.assertIs(type(got), type(value))

    @_requires(_BINARY_FLOAT_SERVER)
    def test_binary_float_with_a_number_stays_binary_float(self):
        # Oracle converts the NUMBER operand to BINARY_FLOAT and computes in
        # single precision: 1.5f - 0.1 is the float nearest 1.4, described as
        # a BINARY_FLOAT. With a BINARY_DOUBLE, it is a BINARY_DOUBLE. The
        # Mirror over PostgreSQL widened every real with a NUMBER or an
        # integer to a double, so the first gave 1.4 as a BINARY_DOUBLE
        # (#2569).
        f = 'TO_BINARY_FLOAT(1.5)'
        single = seerdb.DB_TYPE_BINARY_FLOAT
        for expr, described, value in (
            (f'{f} - 0.1', single, 1.399999976158142),
            (f'0.1 + {f}', single, 1.600000023841858),
            (f'{f} * 3', single, 4.5),
            (f'3 / {f}', single, 2.0),
            ('TO_BINARY_FLOAT(0.1) + 0.2', single, 0.30000001192092896),
            (f'{f} * TO_BINARY_DOUBLE(2)', seerdb.DB_TYPE_BINARY_DOUBLE, 3.0),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                self.assertEqual(self.cur.fetchone(), (value,))
                self.assertIs(self.cur.description[0][1], described)

    def test_trigonometric_functions_of_a_number_are_numbers(self):
        # Over PostgreSQL, which has them for double precision only, these
        # came back as BINARY_DOUBLE, and SQRT, EXP and LN of an integer
        # literal too (#2585). Oracle's are NUMBER, whatever the NUMBER.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, i NUMBER(5))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (0.5, 2)')
        for expr, value in (
            ('SIN(n)', math.sin(0.5)),
            ('COS(i)', math.cos(2)),
            ('TAN(0.5)', math.tan(0.5)),
            ('ASIN(n)', math.asin(0.5)),
            ('ACOS(1)', 0.0),
            ('ATAN(i)', math.atan(2)),
            ('SINH(1)', math.sinh(1)),
            ('COSH(n)', math.cosh(0.5)),
            ('TANH(2)', math.tanh(2)),
            ('ATAN2(n, i)', math.atan2(0.5, 2)),
            ('ATAN2(1, 2)', math.atan2(1, 2)),
            ('SQRT(4)', 2.0),
            ('EXP(1)', math.e),
            ('LN(1)', 0.0),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM {self.TABLE}')
                (got,) = self.cur.fetchone()
                self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_NUMBER)
                self.assertAlmostEqual(float(got), value, places=12)

    def test_dump_shows_oracle_type_numbers_and_bytes(self):
        # DUMP reports a value's Oracle type number and its stored bytes; over
        # PostgreSQL it was orafce's, PostgreSQL's type oid and in-memory bytes
        # (#2568). The formats and the byte range, and a NULL's text NULL.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (n NUMBER, m NUMBER, v VARCHAR2(10), '
            'c CHAR(3), d DATE, r RAW(4))'
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1.5, -12.34, 'abc', 'xy', "
            "TO_DATE('2020-01-15', 'YYYY-MM-DD'), HEXTORAW('DEADBEEF'))"
        )
        for expr, binds, dumped in (
            ('DUMP(n)', [], 'Typ=2 Len=3: 193,2,51'),
            ('DUMP(m)', [], 'Typ=2 Len=4: 62,89,67,102'),
            ('DUMP(0)', [], 'Typ=2 Len=1: 128'),
            ('DUMP(-1)', [], 'Typ=2 Len=3: 62,100,102'),
            ('DUMP(1e125)', [], 'Typ=2 Len=2: 255,11'),
            ('DUMP(v)', [], 'Typ=1 Len=3: 97,98,99'),
            ('DUMP(c)', [], 'Typ=96 Len=3: 120,121,32'),
            ('DUMP(d)', [], 'Typ=12 Len=7: 120,120,1,15,1,1,1'),
            ('DUMP(r)', [], 'Typ=23 Len=4: 222,173,190,239'),
            ('DUMP(n, 16)', [], 'Typ=2 Len=3: c1,2,33'),
            ('DUMP(n, 8)', [], 'Typ=2 Len=3: 301,2,63'),
            ('DUMP(n, 17)', [], 'Typ=2 Len=3: c1,^B,3'),
            ('DUMP(n, 1016)', [], 'Typ=2 Len=3: c1,2,33'),
            ('DUMP(n, 10, 2)', [], 'Typ=2 Len=3: 2,51'),
            ('DUMP(n, 10, 2, 1)', [], 'Typ=2 Len=3: 2'),
            ('DUMP(v, 16, -1)', [], 'Typ=1 Len=3: 63'),
            ('DUMP(n, 10, 5)', [], None),
            ('DUMP(NULL)', [], 'NULL'),
            ('DUMP(:1)', [Decimal('1.5')], 'Typ=2 Len=3: 193,2,51'),
            ('DUMP(:1)', ['hi'], 'Typ=1 Len=2: 104,105'),
            ('DUMP(:1)', [None], 'NULL'),
        ):
            with self.subTest(expr=expr, binds=binds):
                self.cur.execute(f'SELECT {expr} FROM {self.TABLE}', binds)
                self.assertEqual(self.cur.fetchone(), (dumped,))
        # Past 1000 a character type names its character set, the database's.
        self.cur.execute(f'SELECT DUMP(v, 1016) FROM {self.TABLE}')
        self.assertRegex(
            self.cur.fetchone()[0], r'^Typ=1 Len=3 CharacterSet=\w+: 61,62,63$'
        )

    @_requires(_BINARY_FLOAT_SERVER)
    def test_dump_of_floats_timestamps_and_intervals(self):
        # As above, for the 10g types and the 9i datetimes (#2568).
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (f BINARY_FLOAT, g BINARY_DOUBLE, '
            't TIMESTAMP(6), t0 TIMESTAMP, z TIMESTAMP WITH TIME ZONE, '
            'l TIMESTAMP WITH LOCAL TIME ZONE, '
            'ym INTERVAL YEAR TO MONTH, ds INTERVAL DAY TO SECOND)'
        )
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (-1.5, 1.5, '
            "TIMESTAMP '2020-01-15 10:20:30.123456', TIMESTAMP '2020-01-15 10:20:30', "
            "TO_TIMESTAMP_TZ('2020-01-15 10:20:30.5 -05:30', "
            "'YYYY-MM-DD HH24:MI:SS.FF TZH:TZM'), TIMESTAMP '2020-01-15 10:20:30', "
            "INTERVAL '-1-2' YEAR TO MONTH, INTERVAL '3 04:05:06.5' DAY TO SECOND)"
        )
        for expr, dumped in (
            ('DUMP(f)', 'Typ=100 Len=4: 64,63,255,255'),
            ('DUMP(g)', 'Typ=101 Len=8: 191,248,0,0,0,0,0,0'),
            ('DUMP(t)', 'Typ=180 Len=11: 120,120,1,15,11,21,31,7,91,202,0'),
            ('DUMP(t0)', 'Typ=180 Len=7: 120,120,1,15,11,21,31'),
            ('DUMP(z)', 'Typ=181 Len=13: 120,120,1,15,16,51,31,29,205,101,0,15,30'),
            ('DUMP(ym)', 'Typ=182 Len=5: 127,255,255,255,58'),
            ('DUMP(ds)', 'Typ=183 Len=11: 128,0,0,3,64,65,66,157,205,101,0'),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM {self.TABLE}')
                self.assertEqual(self.cur.fetchone(), (dumped,))
        # LOCAL TIME ZONE is stored in the database time zone, its type 231.
        self.cur.execute(f'SELECT DUMP(l) FROM {self.TABLE}')
        self.assertTrue(self.cur.fetchone()[0].startswith('Typ=231 Len=7: '))

    @_requires(_BINARY_FLOAT_SERVER)
    def test_square_root_of_a_binary_float_is_a_binary_float(self):
        # Oracle's SQRT keeps a BINARY_FLOAT single (#2585); its other
        # functions of one are BINARY_DOUBLE.
        self.cur.execute(
            'SELECT SQRT(TO_BINARY_FLOAT(2)), EXP(TO_BINARY_FLOAT(0)) FROM dual'
        )
        (root, one) = self.cur.fetchone()
        self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_BINARY_FLOAT)
        self.assertIs(self.cur.description[1][1], seerdb.DB_TYPE_BINARY_DOUBLE)
        self.assertEqual(root, 1.4142135381698608)  # sqrt(2) in single precision
        self.assertEqual(one, 1.0)

    @_requires(_BINARY_FLOAT_SERVER)
    def test_binary_float_and_double_arithmetic_is_ieee(self):
        # Oracle divides a BINARY_FLOAT / BINARY_DOUBLE by zero to an infinity
        # or NaN, a BINARY_FLOAT overflow is an infinity, and a result too
        # small for either type is 0. Over PostgreSQL each raised (#2571);
        # a BINARY_DOUBLE overflow raises on both. 10g to 23ai alike.
        (f, d) = ('TO_BINARY_FLOAT', 'TO_BINARY_DOUBLE')
        (single, double) = (seerdb.DB_TYPE_BINARY_FLOAT, seerdb.DB_TYPE_BINARY_DOUBLE)
        inf = math.inf
        for expr, value, described in (
            (f'{f}(1.5) / 0', inf, single),
            (f'-{f}(1.5) / 0', -inf, single),
            (f'{f}(1.5) / {f}(0)', inf, single),
            (f'{f}(1.5) / -{f}(0)', inf, single),
            (f'1 / {f}(0)', inf, single),
            (f'{d}(1.5) / 0', inf, double),
            (f'{d}(-1.5) / {d}(0)', -inf, double),
            (f'{f}(1.5) / {d}(0)', inf, double),
            (f'{f}(1e38) * 10', inf, single),
            (f'{f}(3e38) + {f}(3e38)', inf, single),
            (f'-{f}(3e38) - {f}(3e38)', -inf, single),
            (f'{f}(1e38) / {f}(1e-10)', inf, single),
            (f'{f}(1e-38) * {f}(1e-10)', 0.0, single),
            (f'{f}(1e-45) / 2', 0.0, single),
            (f'{d}(1e-308) * {d}(1e-100)', 0.0, double),
            (f'{d}(1e-308) / {d}(1e100)', 0.0, double),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                self.assertEqual(self.cur.fetchone(), (value,))
                self.assertIs(self.cur.description[0][1], described)
        for expr, described in (
            (f'{f}(0) / 0', single),
            (f'0 / {f}(0)', single),
            (f'{d}(0) / {d}(0)', double),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                self.assertTrue(math.isnan(self.cur.fetchone()[0]))
                self.assertIs(self.cur.description[0][1], described)
        with self.assertRaisesRegex(seerdb.DatabaseError, 'ORA-01426'):
            self.cur.execute(f'SELECT {d}(1e308) * {d}(10) FROM dual')
            self.cur.fetchall()

    @_requires(_BINARY_FLOAT_SERVER)
    def test_mod_and_remainder_of_binary_float_and_double(self):
        # IEEE fmod and remainder in the operands' type: a NUMBER operand is
        # converted, so MOD(5.1f, 0.3) is the BINARY_FLOAT 0.2999997.
        # REMAINDER(x, 0) is NaN, a NaN or infinite dividend NaN, an infinite
        # divisor gives x, and a zero result is +0. The Mirror over PostgreSQL
        # had neither function for either type (#2572).
        single = seerdb.DB_TYPE_BINARY_FLOAT
        double = seerdb.DB_TYPE_BINARY_DOUBLE
        f, d = 'TO_BINARY_FLOAT', 'TO_BINARY_DOUBLE'
        for expr, described, value in (
            (f'MOD({f}(1.5), 1)', single, 0.5),
            (f'MOD({f}(-7.5), 2)', single, -1.5),
            (f'MOD({f}(7.5), -2)', single, 1.5),
            (f'MOD({f}(5.1), 0.3)', single, 0.2999997138977051),
            (f'MOD(7, {f}(2.5))', single, 2.0),
            (f'MOD({d}(1.5), 1)', double, 0.5),
            (f'MOD({f}(7.5), {d}(2))', double, 1.5),
            (f'MOD({d}(123456789.123), 0.001)', double, 0.000999993376923471),
            (f'MOD({d}(-6), 3)', double, 0.0),
            (f'MOD({f}(7.5), BINARY_FLOAT_INFINITY)', single, 7.5),
            (f'REMAINDER({f}(7.5), 2)', single, -0.5),
            (f'REMAINDER({f}(5), 2)', single, 1.0),
            (f'REMAINDER({f}(7), 2)', single, -1.0),
            (f'REMAINDER({d}(5.5), 2)', double, -0.5),
            (f'REMAINDER(7, {f}(2.5))', single, -0.5),
            (f'REMAINDER({d}(-6), 3)', double, 0.0),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                (got,) = self.cur.fetchone()
                self.assertEqual(got, value)
                self.assertEqual(math.copysign(1, got), math.copysign(1, value))
                self.assertIs(self.cur.description[0][1], described)
        for expr, described in (
            (f'REMAINDER({f}(7.5), 0)', single),
            ('MOD(BINARY_FLOAT_NAN, 2)', single),
            ('MOD(BINARY_FLOAT_INFINITY, 2)', single),
            ('REMAINDER(BINARY_DOUBLE_NAN, 2)', double),
            ('REMAINDER(-BINARY_DOUBLE_INFINITY, 2)', double),
        ):
            with self.subTest(expr=expr):
                self.cur.execute(f'SELECT {expr} FROM dual')
                self.assertTrue(math.isnan(self.cur.fetchone()[0]))
                self.assertIs(self.cur.description[0][1], described)

    @_requires(_MOD_FLOAT_BY_ZERO)
    def test_mod_of_binary_float_by_zero_is_the_dividend(self):
        # 18c on, as NUMBER's MOD does; 10g and 11g give 0 (#2572).
        for kind, described in (
            ('TO_BINARY_FLOAT', seerdb.DB_TYPE_BINARY_FLOAT),
            ('TO_BINARY_DOUBLE', seerdb.DB_TYPE_BINARY_DOUBLE),
        ):
            with self.subTest(kind=kind):
                self.cur.execute(f'SELECT MOD({kind}(7.5), 0) FROM dual')
                self.assertEqual(self.cur.fetchone(), (7.5,))
                self.assertIs(self.cur.description[0][1], described)

    def test_mod_of_untyped_operands_is_a_number(self):
        # Oracle converts a string or NULL operand to NUMBER. Over PostgreSQL,
        # two untyped operands matched no overload ("not unique"), and beside
        # MOD of a double (#2572) they would have taken that one.
        for sql, binds, value in (
            ('SELECT MOD(NULL, NULL) FROM dual', [], None),
            ("SELECT MOD('7', '2') FROM dual", [], 1),
            ('SELECT MOD(:1, :2) FROM dual', ['7', '2'], 1),
            ('SELECT MOD(:1, :2) FROM dual', [None, None], None),
        ):
            with self.subTest(sql=sql, binds=binds):
                self.cur.execute(sql, binds)
                self.assertEqual(self.cur.fetchone(), (value,))
                self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_NUMBER)

    def test_greatest_and_least_are_null_with_a_null_argument(self):
        # Over PostgreSQL, whose GREATEST and LEAST skip a NULL, LEAST(a, b)
        # with a NULL was b (#2580). Columns, binds and literals take one form
        # there, calls and expressions another.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (a NUMBER, b NUMBER, s VARCHAR2(5))'
        )
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (NULL, 1, NULL)')
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (3, 1, 'q')")
        for expr, binds, values in (
            ('LEAST(a, b)', [], [None, 1]),
            ('GREATEST(a, b)', [], [None, 3]),
            ('GREATEST(b, a, 5)', [], [None, 5]),
            ("LEAST(s, 'x')", [], [None, 'q']),
            ('LEAST(:1, b)', [None], [None, None]),
            ('LEAST(:1, b)', [0], [0, 0]),
            ('LEAST(NULL, b)', [], [None, None]),
            ('GREATEST(a + 1, b)', [], [None, 4]),
            ('LEAST(LENGTH(s), 9)', [], [None, 1]),
            ('GREATEST(LEAST(a, 2), b)', [], [None, 2]),
        ):
            with self.subTest(expr=expr, binds=binds):
                self.cur.execute(
                    f'SELECT {expr} FROM {self.TABLE} ORDER BY a NULLS FIRST', binds
                )
                self.assertEqual([r[0] for r in self.cur.fetchall()], values)

    @_requires(_ONLY_8I)
    def test_a_column_8i_cannot_return_is_refused_before_the_fetch(self):
        # 8i describes SQL's BITAND as type 29, which no client fetches: its
        # sqlplus gets ORA-00932. Fetching it anyway was an ORA-00600 [kpodfl1]
        # in the server process (#2584). The refusal leaves the session usable.
        with self.assertRaisesRegex(seerdb.NotSupportedError, 'data type 29'):
            self.cur.execute('SELECT BITAND(7, 2) AS b FROM dual')
        self.cur.execute('SELECT 1 + 1 FROM dual')
        self.assertEqual(self.cur.fetchone(), (2,))

    def test_numeric_functions_of_untyped_arguments_are_numbers(self):
        # Oracle converts a NULL, string or string-bind argument of a numeric
        # function or operator to a NUMBER. Over PostgreSQL, ROUND(NULL),
        # POWER(NULL, 2) and NULL * NULL were "not unique", and ABS(NULL) or
        # SIN(:1) a BINARY_DOUBLE (#2581).
        null_args = [
            f'{f}(NULL)'
            for f in (
                'ROUND',
                'TRUNC',
                'ABS',
                'SIGN',
                'CEIL',
                'FLOOR',
                'SQRT',
                'EXP',
                'LN',
                'SIN',
                'COS',
                'TAN',
                'ASIN',
                'ACOS',
                'ATAN',
                'SINH',
                'COSH',
                'TANH',
            )
        ]
        null_args += [
            'ROUND(NULL, NULL)',
            'POWER(NULL, 2)',
            'POWER(2, NULL)',
            'POWER(NULL, NULL)',
            'ATAN2(NULL, NULL)',
            'NULL + NULL',
            'NULL - NULL',
            'NULL * NULL',
            'NULL / NULL',
            '-NULL',
        ]
        cases = [(expr, [], None) for expr in null_args] + [
            ("ROUND('8.756', '1')", [], Decimal('8.8')),
            ('TRUNC(:1, :2)', ['8.75', '1'], Decimal('8.7')),
            ("ROUND(8.756, '1.7')", [], Decimal('8.8')),
            ('ABS(:1)', ['-3'], 3),
            ("CEIL('0.5')", [], 1),
            ('FLOOR(:1)', [None], None),
            ("POWER('2', '3')", [], 8),
            ('POWER(:1, :2)', ['8', '2'], 64),
            ("'8' + '2'", [], 10),
            (':1 - :2', ['8', '2'], 6),
            (':1 * :2', [None, None], None),
            ("'7' / '2'", [], Decimal('3.5')),
            ('-:1', ['8.5'], Decimal('-8.5')),
        ]
        self._assert_numbers(cases)
        # Unary plus leaves a string a string.
        self.cur.execute('SELECT +:1 FROM dual', ['8'])
        self.assertEqual(self.cur.fetchone(), ('8',))
        self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_VARCHAR)

    @_requires(_BITAND_FETCHABLE)
    def test_bitand_of_untyped_arguments_is_a_number(self):
        # As above (#2581).
        self._assert_numbers(
            [('BITAND(NULL, NULL)', [], None), ("BITAND('7', '2')", [], 2)]
        )

    def _assert_numbers(self, cases):
        for expr, binds, value in cases:
            with self.subTest(expr=expr, binds=binds):
                self.cur.execute(f'SELECT {expr} FROM dual', binds)
                self.assertEqual(self.cur.fetchone(), (value,))
                self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_NUMBER)

    def test_interval_ds_bind(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v INTERVAL DAY(4) TO SECOND(6))')
        Value = datetime.timedelta(
            days=5, hours=4, minutes=3, seconds=2, microseconds=123456
        )
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', [Value])
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (Value,))

    def test_interval_ym_bind(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v INTERVAL YEAR(4) TO MONTH)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (:1)', [seerdb.IntervalYM(3, 7)]
        )
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (seerdb.IntervalYM(3, 7),))

    # ----- bind ordering (str before number) -----

    def test_str_before_number_bind(self):
        # A VARCHAR bind preceding a NUMBER bind used to be sized at 32767,
        # which the server treated as a LONG and reordered — silently swapping
        # the two binds. Both columns must round-trip correctly.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (a VARCHAR2(20), b NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', ['hi', 7])
        self.cur.execute(f'SELECT a, b FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), ('hi', 7))

    def test_update_set_str_where_number(self):
        # The classic failing shape: SET <string> WHERE <number>.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(20))')
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 'orig')")
        self.cur.execute(
            f'UPDATE {self.TABLE} SET name = :1 WHERE id = :2', ['updated', 1]
        )
        self.assertEqual(self.cur.rowcount, 1)
        self.cur.execute(f'SELECT name FROM {self.TABLE} WHERE id = 1')
        self.assertEqual(self.cur.fetchone(), ('updated',))

    def test_three_binds_str_in_middle(self):
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (a NUMBER, b VARCHAR2(20), c NUMBER)'
        )
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3)', [11, 'XX', 33]
        )
        self.cur.execute(f'SELECT a, b, c FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (11, 'XX', 33))

    # ----- PL/SQL blocks with binds -----

    def test_plsql_block_in_bind(self):
        # An anonymous PL/SQL block carrying a bind variable must execute
        # server-side (previously ORA-00600 [12259]). Prove the bound value
        # reached the block by having it insert the value.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v NUMBER)')
        self.cur.execute(f'BEGIN INSERT INTO {self.TABLE} VALUES (:x); END;', [42])
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (42,))

    def test_plsql_block_mixed_binds(self):
        # Issue #13: a VARCHAR + NUMBER bind in an UPDATE inside a PL/SQL block
        # used to raise ORA-00600 [12259]. Must run and update the row.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(100))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, NULL)')
        self.cur.execute(
            f'BEGIN UPDATE {self.TABLE} SET v = :a WHERE id = :b; END;',
            {'a': 'hi', 'b': 1},
        )
        self.cur.execute(f'SELECT v FROM {self.TABLE} WHERE id = 1')
        self.assertEqual(self.cur.fetchone(), ('hi',))

    def test_plsql_block_two_in_binds(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v NUMBER)')
        self.cur.execute(
            f'BEGIN INSERT INTO {self.TABLE} VALUES (:a + :b); END;', [3, 4]
        )
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (7,))

    # ----- named binds -----

    def test_named_dict_binds(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (:id, :name)',
            {'id': 10, 'name': 'named'},
        )
        self.cur.execute(f'SELECT id, name FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(10, 'named')])

    def test_named_binds_are_case_insensitive(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        # Mixed case on both sides; bind names normalised lower-case.
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (:ID, :Name)',
            {'id': 11, 'NAME': 'case'},
        )
        self.cur.execute(f'SELECT id, name FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(11, 'case')])

    def test_named_binds_repeated_placeholder(self):
        # `:x` referenced twice in the SQL — the same value gets bound to
        # each textual occurrence. Each occurrence is a distinct bind
        # position on the wire (Oracle expects N OAC + N RXD entries for
        # N placeholder occurrences in plain SQL), but the caller only
        # has to provide one mapping.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (a NUMBER, b NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:x, :x)', {'x': 42})
        self.cur.execute(f'SELECT a, b FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(42, 42)])

    def test_named_binds_repeated_in_predicate(self):
        # Reproducer from issue #15: `:x` referenced twice in a WHERE
        # clause used to trip ORA-01008 ("not all variables bound")
        # because the resolver deduplicated by name and only sent one
        # bind value where Oracle wanted two.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (2)')
        # Match-on-value
        self.cur.execute(
            f'SELECT id FROM {self.TABLE} WHERE id = :x OR :x IS NULL',
            {'x': 1},
        )
        self.assertEqual(self.cur.fetchall(), [(1,)])
        # Match-on-NULL: `:x IS NULL` triggers the second branch and
        # returns every row regardless of value.
        self.cur.execute(
            f'SELECT id FROM {self.TABLE} WHERE id = :x OR :x IS NULL',
            {'x': None},
        )
        self.assertEqual(sorted(self.cur.fetchall()), [(1,), (2,)])

    def test_named_binds_missing_key_raises(self):
        # ProgrammingError is the right slot in the PEP 249 hierarchy for
        # "the caller supplied bad inputs".
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        with self.assertRaises(seerdb.ProgrammingError):
            self.cur.execute(
                f'INSERT INTO {self.TABLE} VALUES (:id, :name)',
                {'id': 12},  # missing :name
            )

    # ----- type validation -----

    def test_bad_parameters_type_raises(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        with self.assertRaises(seerdb.NotSupportedError):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1)', 'not-a-sequence')

    # ----- SELECT with binds -----

    def test_select_with_bind_filter(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        for Row in [(1, 'a'), (2, 'b'), (3, 'c')]:
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', list(Row))
        self.cur.execute(f'SELECT name FROM {self.TABLE} WHERE id = :1', [2])
        self.assertEqual(self.cur.fetchall(), [('b',)])

    def test_select_with_named_bind(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [5, 'five'])
        self.cur.execute(
            f'SELECT name FROM {self.TABLE} WHERE id = :target',
            {'target': 5},
        )
        self.assertEqual(self.cur.fetchall(), [('five',)])

    # ----- safety: literal colons in strings shouldn't confuse bind parsing -----

    def test_colon_inside_string_literal_is_not_a_bind(self):
        # The SQL contains a `:not_a_bind` inside a quoted string. The bind
        # extractor must ignore it; only the real :v should require a value.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v VARCHAR2(40))')
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES ('hello :not_a_bind ' || :v)",
            {'v': 'world'},
        )
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        self.assertEqual(
            self.cur.fetchall(),
            [('hello :not_a_bind world',)],
        )


@unittest.skipUnless(_USER, _SKIP_REASON)
class LastRowidIntegration(_IntegrationBase):
    """``cursor.lastrowid``: the rowid of the last row a DML statement touched.

    Nothing in the suite checked it live, so the Mirror reporting None for every
    statement went unnoticed (#1077).
    """

    def _row_at(self, rowid):
        # Which row a rowid names, asked of the server. Compared this way, not as
        # strings: in a bigfile tablespace the status token carries the bigfile
        # marker (1024) as the relative file number where a fetched ROWID carries
        # 0, so the two print differently (AQ vs AA) while naming the same row.
        # python-oracledb reports the same pair; the server accepts either.
        self.cur.execute(f'SELECT n FROM {self.TABLE} WHERE ROWID = :1', [rowid])
        return [r[0] for r in self.cur.fetchall()]

    @_requires(_ARRAY_DML)
    def test_lastrowid_follows_the_touched_row(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, s VARCHAR2(10))')
        self.assertIsNone(self.cur.lastrowid)  # DDL
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 'a')")
        self.assertEqual(self._row_at(self.cur.lastrowid), [1])
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [(2, 'b'), (3, 'c')]
        )
        self.assertEqual(self._row_at(self.cur.lastrowid), [3])
        self.cur.execute(f"UPDATE {self.TABLE} SET s = 'z' WHERE n = 2")
        self.assertEqual(self._row_at(self.cur.lastrowid), [2])

    def test_each_single_row_dml_reports_its_rowid(self):
        # INSERT, UPDATE and DELETE each report the row they touched, and a DDL
        # or a DML that touched nothing reports None -- on every server. 8i and
        # 9i carry the rowid in their short status as 10g+ does, and leave the
        # previous one in place when nothing was touched (#1079).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, s VARCHAR2(10))')
        self.assertIsNone(self.cur.lastrowid)
        rowids = {}
        for n in (1, 2, 3):
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ({n}, 'a')")
            rowids[n] = self.cur.lastrowid
            self.assertEqual(self._row_at(rowids[n]), [n])
        self.cur.execute(f"UPDATE {self.TABLE} SET s = 'z' WHERE n = 1")
        self.assertEqual(self._row_at(self.cur.lastrowid), [1])
        self.cur.execute(f"UPDATE {self.TABLE} SET s = 'z' WHERE n = 99")
        self.assertIsNone(self.cur.lastrowid)
        self.cur.execute(f'DELETE FROM {self.TABLE} WHERE n = 2')
        # The deleted row is gone, so compare with the INSERT's rowid -- by data
        # object, block and slot, not as strings: in a bigfile tablespace the
        # INSERT's status carries the relative file as 1024 and the DELETE's as
        # 0 (23ai), so the same row prints ...AQ... and ...AA....
        without_file = lambda rowid: rowid[:6] + rowid[9:]  # noqa: E731
        self.assertEqual(without_file(self.cur.lastrowid), without_file(rowids[2]))
        self.cur.execute(f'CREATE INDEX {self.TABLE}_i ON {self.TABLE} (n)')
        self.assertIsNone(self.cur.lastrowid)


@unittest.skipUnless(_USER, _SKIP_REASON)
class ZeroRowDmlIntegration(_IntegrationBase):
    """A DML that touches no rows has no rowid (#1078)."""

    def test_a_dml_touching_no_row_reports_no_rowid(self):
        # After a SELECT on the same cursor, 23ai's reply to a DELETE that
        # matched nothing carried the rowid of the row the SELECT fetched, and
        # the client reported it. python-oracledb reports None (test_4321).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, s VARCHAR2(10))')
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 'a')")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (2, 'b')")
        self.cur.execute(f"UPDATE {self.TABLE} SET s = 'z' WHERE n = 2")
        touched = self.cur.lastrowid
        self.cur.execute(f'SELECT n FROM {self.TABLE} WHERE ROWID = :1', [touched])
        self.cur.fetchall()
        self.cur.execute(f'DELETE FROM {self.TABLE} WHERE 1 = 0')
        self.assertEqual(self.cur.rowcount, 0)
        self.assertIsNone(self.cur.lastrowid)


@_requires(_DOMAINS)
@unittest.skipUnless(_USER, _SKIP_REASON)
class ColumnDomainIntegration(_IntegrationBase):
    """A 23ai column's SQL domain and annotations on ``cursor.description`` (#1083)."""

    DOMAIN = 'PYO_SIMPLE_DOMAIN'

    def setUp(self):
        super().setUp()
        self._drop_domain()

    def tearDown(self):
        self._drop_domain()
        super().tearDown()

    def _drop_domain(self):
        # The table first, PURGEd: a dropped table in the recycle bin still uses
        # the domain, and the domain would then outlive the test. FORCE covers a
        # leftover from an interrupted run.
        with self.conn.cursor() as cur:
            for sql in (
                f'DROP TABLE {self.TABLE} PURGE',
                f'DROP DOMAIN {self.DOMAIN} FORCE',
            ):
                try:
                    cur.execute(sql)
                except seerdb.DatabaseError:
                    pass

    def test_domain_and_annotations_are_described(self):
        # The table python-oracledb's suite uses for the same check (test_4361).
        self.cur.execute(f'CREATE DOMAIN {self.DOMAIN} AS NUMBER(3, 0) NOT NULL')
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER(9) NOT NULL, '
            f'age NUMBER(3, 0) DOMAIN {self.DOMAIN} '
            "ANNOTATIONS (Anno_1 'first annotation', Anno_2 'second annotation', Anno_3))"
        )
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, 25)')
        self.cur.execute(f'SELECT * FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(1, 25)])
        (plain, annotated) = self.cur.description
        self.assertIsNone(plain.domain_schema)
        self.assertIsNone(plain.domain_name)
        self.assertIsNone(plain.annotations)
        self.assertEqual(annotated.domain_schema, _USER.upper())
        self.assertEqual(annotated.domain_name, self.DOMAIN)
        self.assertEqual(
            annotated.annotations,
            {'ANNO_1': 'first annotation', 'ANNO_2': 'second annotation', 'ANNO_3': ''},
        )


@unittest.skipUnless(_USER, _SKIP_REASON)
class PhysicalUrowidIntegration(_IntegrationBase):
    """A physical rowid stored in a UROWID column (#1086)."""

    @_requires(_postgres_cannot('keep a row at one address across an UPDATE'))
    def test_it_reads_back_as_the_same_rowid(self):
        # A UROWID value is tagged 0x01 when it holds a physical rowid; it used to
        # render in the '*' logical form, unlike the same row's ROWID column and
        # unlike python-oracledb.
        # PostgreSQL writes an UPDATEd row as a new version at a new address, so
        # the rowid `SET r = ROWID` stores names the version it replaced; an
        # Oracle ROWID does not move on UPDATE.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, r ROWID, u UROWID)')
        self.cur.execute(f'INSERT INTO {self.TABLE} (n) VALUES (1)')
        self.cur.execute(f'UPDATE {self.TABLE} SET r = ROWID, u = ROWID')
        self.cur.execute(f'SELECT r, u FROM {self.TABLE}')
        (r, u) = self.cur.fetchone()
        self.assertFalse(u.startswith('*'), u)
        self.assertEqual(u, r)
        self.cur.execute(f'SELECT n FROM {self.TABLE} WHERE ROWID = :1', [u])
        self.assertEqual(self.cur.fetchall(), [(1,)])


def _kill_session(sid) -> None:
    # Kill a session through the suite's admin account, as a DBA would. The
    # admin, not the session's own user, reads v$session: an ordinary account
    # cannot (ORA-00942).
    with seerdb.connect(
        host=_HOST,
        port=_PORT,
        user=_ADMIN_USER,
        password=_ADMIN_PASSWORD,
        service_name=_SERVICE,
        **_FV_KW,
    ) as admin:
        cur = admin.cursor()
        cur.execute('SELECT serial# FROM v$session WHERE sid = :1', [sid])
        (serial,) = cur.fetchone()
        cur.execute(f"ALTER SYSTEM KILL SESSION '{sid},{serial}'")


@unittest.skipUnless(_USER, _SKIP_REASON)
@unittest.skipUnless(
    _ADMIN_USER, 'set SEERDB_TEST_ADMIN_USER (a DBA) to kill a session'
)
class PingKilledSessionIntegration(_ThrottleRetry, unittest.TestCase):
    """A ping on a session the server killed raises, as the server says (#1095)."""

    @_requires(_PING_ROUND_TRIP)
    def test_a_killed_session_turns_unhealthy_once_the_server_says_so(self):
        # A kill reaches the client on its next call, as ORA-00028; until then
        # is_healthy can't know, and after it says False (#2456).
        conn = seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            **_FV_KW,
        )
        try:
            cur = conn.cursor()
            cur.execute("SELECT SYS_CONTEXT('userenv', 'sid') FROM dual")
            _kill_session(int(cur.fetchone()[0]))
            with self.assertRaises(seerdb.DatabaseError):
                cur.execute('SELECT 1 FROM dual')
            self.assertFalse(conn.is_healthy())
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - the session is gone
                pass

    @_requires(_PING_ROUND_TRIP)
    def test_ping_raises_on_a_killed_session(self):
        conn = seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            **_FV_KW,
        )
        try:
            cur = conn.cursor()
            cur.execute("SELECT SYS_CONTEXT('userenv', 'sid') FROM dual")
            _kill_session(int(cur.fetchone()[0]))
            with self.assertRaises(seerdb.DatabaseError):
                conn.ping()
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - the session is gone
                pass


# Two-phase commit (#131, #2457): a 12.1+ server, and no Mirror, which doesn't
# serve XA (docs/MIRROR.md, "Not served").
_TPC = _Need(
    'two-phase commit needs a 12.1+ server or the native form on 10g and 11g, '
    'and the Mirror does not serve XA',
    tpc=True,
    not_mirror=('*',),
)
_TPC_FORMAT = 0x5EED


def _tpc_xid(tag: str) -> seerdb.Xid:
    # An XID of this run alone, so two runs on one bed never share a branch.
    return seerdb.Xid(_TPC_FORMAT, f'seerdb-{tag}-{os.getpid()}'.encode(), b'1')


@unittest.skipUnless(_USER, _SKIP_REASON)
class TpcIntegration(_ThrottleRetry, unittest.TestCase):
    """Two-phase commit, end to end (#131, #2457). Each test settles every
    branch it prepares, so nothing is left in doubt on the bed.

    A session that prepared a branch stays open until the branch is settled:
    a second or two after it closes, the database's recovery process takes the
    branch over, and from then on it can only be forced (ORA-24756 to a commit
    or rollback by XID), measured on 23ai. Keeping it open is also how XA runs:
    one session prepares, the coordinator settles."""

    TABLE = 'PYO_TPC_BRANCHES'

    def _connect(self):
        return seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            **_FV_KW,
        )

    def setUp(self):
        from seerdb.common.exceptions import DatabaseError

        self.xids: list = []
        self.preparers: list = []
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(f'DROP TABLE {self.TABLE}')
            except DatabaseError:
                pass  # not left over from an earlier run
            cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER)')

    def tearDown(self):
        # A branch a failed test left prepared is rolled back by its XID while
        # the session that prepared it is still open, then the sessions close.
        from seerdb.common.exceptions import Error

        with self._connect() as conn:
            for xid in self.xids:
                try:
                    conn.tpc_rollback(xid)
                except Error:
                    pass  # settled already, as a passing test leaves it
            for preparer in self.preparers:
                preparer.close()
            conn.cursor().execute(f'DROP TABLE {self.TABLE}')

    def _rows(self) -> list:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(f'SELECT n FROM {self.TABLE} ORDER BY n')
            return [n for (n,) in cur.fetchall()]

    def _prepare(self, conn, tag: str, n: int) -> seerdb.Xid:
        xid = _tpc_xid(tag)
        self.xids.append(xid)
        conn.tpc_begin(xid)
        conn.cursor().execute(f'INSERT INTO {self.TABLE} VALUES ({n})')
        conn.tpc_end(xid)
        self.assertTrue(conn.tpc_prepare(xid))
        return xid

    @_requires(_TPC)
    def test_a_branch_prepares_and_commits(self):
        with self._connect() as conn:
            xid = self._prepare(conn, 'whole', 1)
            conn.tpc_commit(xid)
        self.assertEqual(self._rows(), [1])

    @_requires(_TPC)
    def test_a_branch_prepares_and_rolls_back(self):
        with self._connect() as conn:
            xid = self._prepare(conn, 'undo', 1)
            conn.tpc_rollback(xid)
        self.assertEqual(self._rows(), [])

    @_requires(_TPC)
    def test_a_read_only_branch_needs_no_commit(self):
        with self._connect() as conn:
            xid = _tpc_xid('readonly')
            conn.tpc_begin(xid)
            conn.cursor().execute(f'SELECT COUNT(*) FROM {self.TABLE}')
            conn.tpc_end(xid)
            self.assertFalse(conn.tpc_prepare(xid))

    @_requires(_TPC)
    def test_a_one_phase_commit_needs_no_prepare(self):
        with self._connect() as conn:
            xid = _tpc_xid('onephase')
            self.xids.append(xid)
            conn.tpc_begin(xid)
            conn.cursor().execute(f'INSERT INTO {self.TABLE} VALUES (7)')
            conn.tpc_end(xid)
            conn.tpc_commit(xid, one_phase=True)
        self.assertEqual(self._rows(), [7])

    @_requires(_TPC)
    def test_branches_left_in_doubt_are_recovered_and_settled_elsewhere(self):
        # tpc_recover lists the prepared branches other sessions hold, and
        # this one commits or rolls each back by its XID (#2457).
        from seerdb.common.exceptions import DatabaseError

        for tag, n in (('keep', 1), ('drop', 2)):
            conn = self._connect()
            self.preparers.append(conn)
            self._prepare(conn, tag, n)
        (keep, drop) = self.xids
        with self._connect() as conn:
            try:
                recovered = conn.tpc_recover()
            except DatabaseError as exc:
                if exc.code != 942:
                    raise
                self.skipTest(
                    'the test user cannot read DBA_PENDING_TRANSACTIONS '
                    '(tools/test_bed_setup.sql grants it)'
                )
            self.assertIn(keep, recovered)
            self.assertIn(drop, recovered)
            conn.tpc_commit(keep)
            conn.tpc_rollback(drop)
            left = conn.tpc_recover()
        self.assertNotIn(keep, left)
        self.assertNotIn(drop, left)
        self.assertEqual(self._rows(), [1])

    @_requires(_TPC)
    def test_tpc_forget_is_refused_as_python_oracledb_thin_refuses_it(self):
        with self._connect() as conn:
            with self.assertRaises(seerdb.NotSupportedError):
                conn.tpc_forget(_tpc_xid('forget'))


@unittest.skipUnless(_USER, _SKIP_REASON)
class ProxyLoginIntegration(_ThrottleRetry, unittest.TestCase):
    """A proxy login, ``user[proxy]`` (#126), keeps its proxy end to end (#1093).

    Needs a user the test user may connect through (``ALTER USER <proxy> GRANT
    CONNECT THROUGH <user>``), named by SEERDB_TEST_PROXY_USER. The suite's own
    account has no such grant, so without it the test says so and skips.
    """

    @_requires(_PROXY_AUTH)
    def test_the_session_runs_as_the_proxied_user(self):
        proxy = os.environ.get('SEERDB_TEST_PROXY_USER')
        if not proxy:
            self.skipTest(
                'set SEERDB_TEST_PROXY_USER to a user the test user may proxy for'
            )
        with seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=f'{_USER}[{proxy}]',
            password=_PASSWORD,
            service_name=_SERVICE,
            **_FV_KW,
        ) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT SYS_CONTEXT('userenv', 'session_user'), "
                "SYS_CONTEXT('userenv', 'proxy_user') FROM dual"
            )
            self.assertEqual(cur.fetchone(), (proxy.upper(), _USER.upper()))


@unittest.skipUnless(_USER, _SKIP_REASON)
class MixedPrecisionBatchIntegration(_IntegrationBase):
    """An executemany whose datetimes differ in sub-second precision (#1098)."""

    def test_a_mixed_batch_inserts_and_round_trips(self):
        # Every row of an array bind must match the one descriptor the OAC
        # declares. Sending a 7-byte value under an 11-byte one (or the reverse)
        # was rejected: ORA-01483.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, t TIMESTAMP)')
        values = [
            datetime.datetime(2056, 2, 29),
            datetime.datetime(2020, 2, 29, 23, 59, 59, 123456),
            datetime.datetime(1900, 1, 1),
            datetime.datetime(2024, 1, 1, 0, 0, 0, 789012),
        ]
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2)', list(enumerate(values))
        )
        self.conn.commit()
        self.cur.execute(f'SELECT t FROM {self.TABLE} ORDER BY n')
        self.assertEqual([r[0] for r in self.cur.fetchall()], values)


@_requires(
    _Need(
        'binding a fetched LOB needs the 10g+ bind (8i and 9i: not measured)',
        min_fv=FIELD_VERSION_10_2,
    ),
)
@unittest.skipUnless(_USER, _SKIP_REASON)
class FetchedLobBindIntegration(_IntegrationBase):
    """A CLOB or BLOB a query returned, bound back IN by its locator."""

    def test_a_fetched_clob_and_blob_bind_back(self):
        # Bound by its locator, as python-oracledb binds one: the temp-LOB bind's
        # OAC and the LOB framing, a persistent locator's 114 bytes as much as a
        # temporary one's 40. It raised `Unknown OAC token` before anything was
        # sent; below 12.1 it takes the older OAC layout.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, c CLOB, b BLOB)')
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, 'hello', HEXTORAW('0102'))"
        )
        self.conn.commit()
        self.cur.execute(f'SELECT c, b FROM {self.TABLE}')
        (Clob, Blob) = self.cur.fetchone()
        self.cur.execute(
            'SELECT DBMS_LOB.GETLENGTH(:1), DBMS_LOB.GETLENGTH(:2) FROM dual',
            [Clob, Blob],
        )
        self.assertEqual(self.cur.fetchone(), (5, 2))
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3)',
            [(2, Clob, Blob), (3, Clob, Blob)],
        )
        self.cur.execute(
            f'SELECT n, DBMS_LOB.GETLENGTH(c), DBMS_LOB.GETLENGTH(b) '
            f'FROM {self.TABLE} ORDER BY n'
        )
        self.assertEqual(self.cur.fetchall(), [(1, 5, 2), (2, 5, 2), (3, 5, 2)])


@unittest.skipUnless(_USER, _SKIP_REASON)
class BFileMissingDirectoryIntegration(_IntegrationBase):
    """A BFILE naming a directory that does not exist (#1101).

    Needs no configured directory, unlike BFILEIntegration: the point is that
    selecting the locator works and only reading it fails.
    """

    def test_bfile_missing_directory_fetches_and_only_the_read_fails(self):
        # fetch_lobs=False used to materialise the BFILE at fetch time, which
        # opens the file -- so the SELECT itself raised ORA-22285 where
        # python-oracledb hands back the locator.
        Conn = _connect(fetch_lobs=False)
        try:
            Cur = Conn.cursor()
            Cur.execute(
                'SELECT BFILENAME(:1, :2) FROM dual',
                ['PYO_MISSING_DIR', 'pyo_missing_file.txt'],
            )
            (Lob,) = Cur.fetchone()
            self.assertEqual(Lob.directory_name, 'PYO_MISSING_DIR')
            self.assertEqual(Lob.filename, 'pyo_missing_file.txt')
            with self.assertRaises(seerdb.DatabaseError) as caught:
                Lob.read()
            self.assertEqual(caught.exception.code, 22285)
        finally:
            Conn.close()

    def _fetched_bfile(self):
        self.cur.execute(
            'SELECT BFILENAME(:1, :2) FROM dual',
            ['PYO_MISSING_DIR', 'pyo_missing_file.txt'],
        )
        (Lob,) = self.cur.fetchone()
        return Lob

    @_requires(_Need('a BFILE bind needs the 10g+ bind', min_fv=FIELD_VERSION_10_2))
    def test_a_fetched_bfile_binds_back(self):
        # Bound by its locator with the BFILE OAC -- type 114, the type's buffer
        # of 4000, no LOB cont-flag -- as python-oracledb binds one. It raised
        # `Unknown OAC token` before anything was sent. The server takes the
        # locator without opening the file, so the missing directory is fine.
        # The Mirror refused it with ORA-22275 (#2510).
        Lob = self._fetched_bfile()
        self.cur.execute(
            "SELECT CASE WHEN :1 IS NULL THEN 'null' ELSE 'set' END FROM dual", [Lob]
        )
        self.assertEqual(self.cur.fetchone(), ('set',))
        self.cur.execute('SELECT :1 FROM dual', [Lob])
        (Back,) = self.cur.fetchone()
        self.assertEqual(
            Back.getfilename(), ('PYO_MISSING_DIR', 'pyo_missing_file.txt')
        )

    @_requires(
        _postgres_cannot("run DBMS_LOB's file routines"),
        _Need('a BFILE bind needs the 10g+ bind', min_fv=FIELD_VERSION_10_2),
    )
    def test_a_fetched_bfile_binds_into_a_block(self):
        Lob = self._fetched_bfile()
        Out = self.cur.var(str)
        self.cur.execute(
            'DECLARE d VARCHAR2(30); f VARCHAR2(200); '
            "BEGIN DBMS_LOB.FILEGETNAME(:1, d, f); :2 := d || '/' || f; END;",
            [Lob, Out],
        )
        self.assertEqual(Out.getvalue(), 'PYO_MISSING_DIR/pyo_missing_file.txt')

    def test_bfile_methods_on_a_missing_directory(self):
        # getfilename() answers from the locator, so it works for a file that is
        # not there and a DIRECTORY that was never created. fileexists() asks
        # the server, and a missing alias is ORA-22285 rather than False --
        # "there is no such alias" and "the file is missing" are different
        # answers (#1109).
        Conn = _connect(fetch_lobs=False)
        try:
            Cur = Conn.cursor()
            Cur.execute(
                'SELECT BFILENAME(:1, :2) FROM dual',
                ['PYO_MISSING_DIR', 'pyo_missing_file.txt'],
            )
            (Lob,) = Cur.fetchone()
            self.assertEqual(
                Lob.getfilename(), ('PYO_MISSING_DIR', 'pyo_missing_file.txt')
            )
            with self.assertRaises(seerdb.DatabaseError) as caught:
                Lob.fileexists()
            self.assertEqual(caught.exception.code, 22285)
            # setfilename retargets the locator locally; nothing is sent, so a
            # name that does not exist is accepted here too.
            Lob.setfilename('PYO_OTHER_DIR', 'other.txt')
            self.assertEqual(Lob.getfilename(), ('PYO_OTHER_DIR', 'other.txt'))
            self.assertEqual(Lob.directory_name, 'PYO_OTHER_DIR')
            self.assertEqual(Lob.filename, 'other.txt')
        finally:
            Conn.close()

    @_requires(_postgres_cannot('create a temp LOB'), _TEMP_LOB)
    def test_bfile_methods_refuse_a_non_bfile_lob(self):
        # The three are meaningless on a CLOB / BLOB and are refused there, as
        # the reference client refuses them (DPY-3026) rather than answering
        # something (#1109). Needs a temp LOB to have a non-BFILE to refuse, and
        # CREATE_TEMP is 12c+ -- 11g refuses it (#91), so there is nothing to
        # build the CLOB / BLOB out of there.
        Conn = _connect()
        try:
            for Kind in (seerdb.DB_TYPE_CLOB, seerdb.DB_TYPE_BLOB):
                Lob = Conn.createlob(Kind)
                with self.assertRaises(seerdb.NotSupportedError):
                    Lob.getfilename()
                with self.assertRaises(seerdb.NotSupportedError):
                    Lob.setfilename('not_relevant', 'not_relevant')
                with self.assertRaises(seerdb.NotSupportedError):
                    Lob.fileexists()
        finally:
            Conn.close()


@_requires(_BLOCK_IOV)
@unittest.skipUnless(_USER, _SKIP_REASON)
class BindDirectionIntegration(_IntegrationBase):
    """``cursor.bind_directions``: what the server said each bind was (#1064)."""

    # A backend with a real server behind it forwards the server's directions;
    # the Mirror-over-PG reports what the block's text shows, as 23ai would
    # (#1783, #2453).

    def test_a_block_reports_its_bind_directions(self):
        # The wire carries no direction on the way in, so the reply is the only
        # place this can be learned. The Mirror's passthrough forwards these so
        # its own client is told the truth rather than "every bind is OUT".
        Out = self.cur.var(str)
        self.cur.execute(
            "begin :result := 'got ' || :given; end;",
            {'result': Out, 'given': 'a value'},
        )
        self.assertEqual(Out.getvalue(), 'got a value')
        self.assertEqual(self.cur.bind_directions, [16, 32])  # OUT, IN

    def test_an_out_bind_left_unassigned_comes_back_null(self):
        # A bind the block only writes is OUT, and the server never reads what
        # the client sent for it (#2453).
        Value = self.cur.var(int)
        for _ in range(2):
            Value.setvalue(0, 41)
            self.cur.execute('begin if 1 = 0 then :r := 1; end if; end;', {'r': Value})
            self.assertEqual(self.cur.bind_directions, [16])  # OUT
            self.assertIsNone(Value.getvalue())

    def test_a_block_whose_binds_are_all_in_reports_them_too(self):
        self.cur.execute('CREATE TABLE ' + self.TABLE + ' (n NUMBER)')
        self.cur.execute(
            f'begin insert into {self.TABLE} values (:only); end;', {'only': 7}
        )
        self.assertEqual(self.cur.bind_directions, [32])  # IN

    def test_a_query_reports_none(self):
        self.cur.execute('SELECT 1 FROM dual')
        self.cur.fetchall()
        self.assertIsNone(self.cur.bind_directions)


@_requires(_TEMP_LOB)
@unittest.skipUnless(_USER, _SKIP_REASON)
class TempLobBindIntegration(_IntegrationBase):
    """Large CLOB / BLOB into a PL/SQL locator param (#91).

    A str / bytes bind over the 32767-byte PL/SQL limit can't go through the
    streamed path (ORA-01460). The driver transparently routes it through a
    server temp LOB (CREATE_TEMP -> WRITE -> bind locator). 12c+ only — 11g
    rejects CREATE_TEMP, so the feature is gated and large PL/SQL binds keep
    their prior (ORA-01460) behaviour there.
    """

    def setUp(self):
        super().setUp()
        self.cur.execute(
            'CREATE OR REPLACE FUNCTION pyo_clob_len(p CLOB) RETURN NUMBER IS '
            'BEGIN RETURN DBMS_LOB.GETLENGTH(p); END;'
        )
        self.cur.execute(
            'CREATE OR REPLACE FUNCTION pyo_blob_len(p BLOB) RETURN NUMBER IS '
            'BEGIN RETURN DBMS_LOB.GETLENGTH(p); END;'
        )

    def tearDown(self):
        # Left behind, they are routines in the schema a later suite lists
        # (#1674).
        from seerdb.common.exceptions import DatabaseError

        for Name in ('PYO_CLOB_LEN', 'PYO_BLOB_LEN'):
            try:
                self.cur.execute(f'DROP FUNCTION {Name}')
            except DatabaseError:
                pass
        super().tearDown()

    def test_large_clob_bind(self):
        for n in (40000, 100000, 500000):
            r = self.cur.var(seerdb.NUMBER)
            self.cur.execute(
                'BEGIN :r := pyo_clob_len(:p); END;', {'r': r, 'p': 'X' * n}
            )
            self.assertEqual(r.getvalue(), n)

    def test_large_blob_bind(self):
        for n in (40000, 100000, 300000):
            r = self.cur.var(seerdb.NUMBER)
            self.cur.execute(
                'BEGIN :r := pyo_blob_len(:p); END;', {'r': r, 'p': b'\xab' * n}
            )
            self.assertEqual(r.getvalue(), n)

    def test_small_bind_unaffected(self):
        # Values within the PL/SQL limit keep the regular streamed path.
        for n in (10, 100, 30000):
            r = self.cur.var(seerdb.NUMBER)
            self.cur.execute(
                'BEGIN :r := pyo_clob_len(:p); END;', {'r': r, 'p': 'Y' * n}
            )
            self.assertEqual(r.getvalue(), n)

    def test_repeated_mixed_sizes_stay_synced(self):
        # The temp-LOB ops are interleaved with the execute; a stale OER scan
        # used to desync the next write. Exercise the alternating path.
        for n in (100, 100000, 30000, 200000, 50):
            r = self.cur.var(seerdb.NUMBER)
            self.cur.execute(
                'BEGIN :r := pyo_clob_len(:p); END;', {'r': r, 'p': 'Z' * n}
            )
            self.assertEqual(r.getvalue(), n)


@_requires(_TEMP_LOB)
@unittest.skipUnless(_USER, _SKIP_REASON)
class CreateLobIntegration(_IntegrationBase):
    """``connection.createlob()``: a temp LOB the caller makes and binds (#1066).

    12c+ only, like every temp LOB: 11g refuses CREATE_TEMP (#91).
    """

    def test_each_lob_type_round_trips_through_a_bind(self):
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, c CLOB, n NCLOB, b BLOB)'
        )
        Text = 'createlob \u3042\u4e2d ' * 3000  # past the inline limit
        Data = bytes(range(256)) * 200
        Clob = self.conn.createlob(seerdb.DB_TYPE_CLOB, Text)
        Nclob = self.conn.createlob(seerdb.DB_TYPE_NCLOB)
        Nclob.write(Text)
        Blob = self.conn.createlob(seerdb.DB_TYPE_BLOB, Data)
        self.assertEqual(
            (Clob.size(), Nclob.size(), Blob.size()), (len(Text),) * 2 + (len(Data),)
        )
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (1, :1, :2, :3)', [Clob, Nclob, Blob]
        )
        # The server holds each as the type asked for, not all as a CLOB.
        self.cur.execute(
            f'SELECT c, n, b, DBMS_LOB.GETLENGTH(n) FROM {self.TABLE} WHERE id = 1'
        )
        (c, n, b, n_len) = self.cur.fetchone()
        self.assertEqual((c.read(), n.read(), b.read()), (Text, Text, Data))
        self.assertEqual(n_len, len(Text))

    @_requires(_postgres_cannot('build an XMLType'))
    def test_a_large_clob_into_xmltype(self):
        # What the method is for: sys.xmltype() needs a genuine LOB argument,
        # and refuses the same 32 KB as a plain string with ORA-01461.
        Xml = '<data>' + 'x' * 32768 + '</data>'
        self.cur.execute(
            'SELECT XMLSERIALIZE(CONTENT sys.xmltype(:1) AS CLOB) FROM dual',
            [self.conn.createlob(seerdb.DB_TYPE_CLOB, Xml)],
        )
        Out = self.cur.fetchone()[0]
        self.assertEqual(Out.read() if hasattr(Out, 'read') else Out, Xml)

    def test_an_empty_temp_lob_is_not_null(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, c CLOB NOT NULL)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (1, :1)',
            [self.conn.createlob(seerdb.DB_TYPE_CLOB)],
        )
        self.cur.execute(f'SELECT DBMS_LOB.GETLENGTH(c) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone()[0], 0)

    def test_empty_temp_lob_binds_non_null(self):
        # An empty temp LOB (CREATE_TEMP, no WRITE) is a zero-length, non-NULL
        # LOB, not a NULL bind. The bind OAC announces a fixed LOB buffer size,
        # not the value's byte budget; announcing 0 for the empty value made the
        # server store NULL -- ORA-01400 on a NOT NULL column (#903). A thick
        # client / the Mirror passthrough reaches this through the temp-LOB
        # primitives, so exercise them directly.
        from seerdb.common.datatypes import TempLob

        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, c CLOB NOT NULL, b BLOB NOT NULL)'
        )
        c_loc = self.conn.create_temp_lob(is_blob=False)
        b_loc = self.conn.create_temp_lob(is_blob=True)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (1, :c, :b)',
            [TempLob(c_loc, False), TempLob(b_loc, True)],
        )
        self.conn.commit()
        self.cur.execute(
            f'SELECT DBMS_LOB.GETLENGTH(c), DBMS_LOB.GETLENGTH(b), '
            f'c, b FROM {self.TABLE} WHERE id = 1'
        )
        c_len, b_len, c_val, b_val = self.cur.fetchone()
        self.assertEqual((c_len, b_len), (0, 0))
        c_val = c_val.read() if hasattr(c_val, 'read') else c_val
        b_val = b_val.read() if hasattr(b_val, 'read') else b_val
        self.assertEqual((c_val, b_val), ('', b''))

    def test_clob_blob_var_bind(self):
        # A CLOB / BLOB bound through a Var -- setinputsizes(DB_TYPE_CLOB) or
        # cursor.var(DB_TYPE_BLOB) -- has no inline wire form; its value is
        # promoted to a temp LOB and the locator bound (#902). Previously raised
        # "no bind encoding for data type 112 / 113".
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, c CLOB, b BLOB)')
        # setinputsizes path
        self.cur.setinputsizes(None, seerdb.DB_TYPE_CLOB, seerdb.DB_TYPE_BLOB)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3)',
            [1, 'a clob value', b'\x01\x02\x03'],
        )
        # cursor.var path
        cvar = self.cur.var(seerdb.DB_TYPE_CLOB)
        cvar.setvalue(0, 'x' * 50000)  # over the inline limit, too
        bvar = self.cur.var(seerdb.DB_TYPE_BLOB)
        bvar.setvalue(0, b'\xaa' * 40000)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (2, :c, :b)', {'c': cvar, 'b': bvar}
        )
        self.conn.commit()
        self.cur.execute(
            f'SELECT id, DBMS_LOB.GETLENGTH(c), DBMS_LOB.GETLENGTH(b) '
            f'FROM {self.TABLE} ORDER BY id'
        )
        self.assertEqual(self.cur.fetchall(), [(1, 12, 3), (2, 50000, 40000)])

    def test_declared_lob_values_in_every_row_of_an_executemany(self):
        # Every row's value goes as a temporary LOB, as python-oracledb makes
        # one for each (#902). Only a single execute's were: an executemany's
        # rows went as text under the LOB bind, which 12c+ answered with
        # ORA-64219 (invalid LOB locator) and a pooled 11g session refused.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, c CLOB, b BLOB)')
        self.cur.setinputsizes(None, seerdb.DB_TYPE_CLOB, seerdb.DB_TYPE_BLOB)
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3)',
            [
                (1, 'a', b'\x01'),
                (2, 'x' * 50000, b'\xaa' * 40000),
                (3, 'ccc', b'\x02\x03'),
            ],
        )
        self.cur.execute(
            f'SELECT id, DBMS_LOB.GETLENGTH(c), DBMS_LOB.GETLENGTH(b) '
            f'FROM {self.TABLE} ORDER BY id'
        )
        self.assertEqual(self.cur.fetchall(), [(1, 1, 1), (2, 50000, 40000), (3, 3, 2)])

    def test_a_declared_null_lob_in_an_executemany(self):
        # A NULL row keeps the LOB bind with a NULL value, among rows that go
        # as temporary LOBs (#902); a pooled 11g session sends it as OCI 11.2
        # does, the zero length alone (#2466).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, c CLOB, b BLOB)')
        self.cur.setinputsizes(None, seerdb.DB_TYPE_CLOB, seerdb.DB_TYPE_BLOB)
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3)',
            [(1, None, b'\x01'), (2, 'bb', None), (3, None, None)],
        )
        self.cur.execute(
            f'SELECT id, DBMS_LOB.GETLENGTH(c), DBMS_LOB.GETLENGTH(b) '
            f'FROM {self.TABLE} ORDER BY id'
        )
        self.assertEqual(
            self.cur.fetchall(), [(1, None, 1), (2, 2, None), (3, None, None)]
        )


@unittest.skipUnless(_USER, _SKIP_REASON)
class ErrorAndRowcountIntegration(_IntegrationBase):
    """Verify that DatabaseError carries the server's message text and that
    Cursor.rowcount reflects the affected-row count from the OER block."""

    def test_error_message_includes_ora_text(self):
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.execute(f'SELECT * FROM nope_{os.getpid()}_xyz')
        # Exception code: the ORA number; str(): the full server message.
        self.assertEqual(ctx.exception.code, 942)
        self.assertIn('ORA-00942', str(ctx.exception))
        # Assert the message fragments separately: 23ai+ embeds the object name
        # (table or view "PYO"."NOPE…" does not exist), so the literal
        # "table or view does not exist" no longer appears as one substring.
        self.assertIn('table or view', str(ctx.exception))
        self.assertIn('does not exist', str(ctx.exception))

    def test_a_session_below_the_server_release_keeps_the_message(self):
        # A 20.1+ server ends every error with a SQL type and a checksum, even
        # to a session that negotiated lower. Read by the negotiated version,
        # the SQL type became the message length and the text was lost (#1145).
        conn = seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            field_version=FIELD_VERSION_12_2,
        )
        try:
            if conn._server_field_version() < FIELD_VERSION_20_1:
                self.skipTest('the server predates 20.1, so it sends no such fields')
            with self.assertRaises(seerdb.DatabaseError) as ctx:
                conn.cursor().execute("SELECT TO_NUMBER('x') FROM dual")
            self.assertEqual(ctx.exception.code, 1722)
            self.assertIn('ORA-01722', str(ctx.exception))
        finally:
            conn.close()

    def test_error_offset_points_at_the_bad_token(self):
        # oracledb parity: DatabaseError.offset is the 0-based character offset of
        # the error in the statement text (the position sqlplus draws its caret
        # under). "nonexistent_col" starts at offset 7; the value is stable across
        # 11g/21c/23ai.
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.execute('SELECT nonexistent_col FROM dual')
        self.assertEqual(ctx.exception.code, 904)
        self.assertEqual(ctx.exception.offset, 7)

    def test_error_message_for_invalid_number(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('not-a-number')")
        # The ORA-01722 code is the stable contract; the English text varies by
        # version (11g/21c: "invalid number"; 23ai: "unable to convert string
        # value … to a number"), so assert on the code + prefix, not the phrase.
        self.assertEqual(ctx.exception.code, 1722)
        self.assertIn('ORA-01722', str(ctx.exception))

    def test_a_string_too_long_for_its_column_is_ora_12899(self):
        # "value too large for column". A real server raises it natively, so this
        # holds every leg to the same answer -- over PostgreSQL it arrives as
        # SQLSTATE 22001 and has to be mapped, or a client branching on the code
        # is told ORA-00900, a syntax error (#1127).
        # Before 10g the same error is ORA-01401, "inserted value too large for
        # column" (measured on 8i and 9i).
        expected = 1401 if self.conn.field_version < FIELD_VERSION_10_2 else 12899
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v VARCHAR2(3))')
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('abcd')")
        self.assertEqual(ctx.exception.code, expected)
        self.assertIn(f'ORA-{expected:05d}', str(ctx.exception))

    def test_a_number_too_wide_for_its_column_is_ora_01438(self):
        # "value larger than specified precision allowed for this column". Over
        # PostgreSQL it shares SQLSTATE 22003 with arithmetic overflow, which is
        # Oracle's ORA-01426 instead, so the mapping has to tell them apart
        # (#1127). This is the column case.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (v NUMBER(3))')
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1000)')
        self.assertEqual(ctx.exception.code, 1438)
        self.assertIn('ORA-01438', str(ctx.exception))

    def test_error_message_for_unique_constraint(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn('ORA-00001', str(ctx.exception))
        self.assertIn('unique constraint', str(ctx.exception))

    # ----- PEP 249 exception subclass dispatch -----

    def test_unique_constraint_raises_integrity_error(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')
        with self.assertRaises(seerdb.IntegrityError):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')

    def test_invalid_number_raises_data_error(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        with self.assertRaises(seerdb.DataError):
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('not-a-number')")

    def test_missing_table_raises_programming_error(self):
        with self.assertRaises(seerdb.ProgrammingError):
            self.cur.execute(f'SELECT * FROM nope_{os.getpid()}_xyz')

    def test_subclass_still_catchable_as_database_error(self):
        # All the subclasses inherit from DatabaseError, so existing
        # callers that catch the base class keep working.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        with self.assertRaises(seerdb.DatabaseError):
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('not-a-number')")

    def test_rowcount_insert_single(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')
        self.assertEqual(self.cur.rowcount, 1)

    def test_rowcount_update_affecting_multiple(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        for n in (1, 2, 3, 4):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES ({n})')
        self.cur.execute(f'UPDATE {self.TABLE} SET id = id + 10 WHERE id <= 3')
        self.assertEqual(self.cur.rowcount, 3)

    def test_rowcount_update_no_match(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')
        self.cur.execute(f'UPDATE {self.TABLE} SET id = 99 WHERE id > 1000')
        self.assertEqual(self.cur.rowcount, 0)

    def test_rowcount_delete(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        for n in (1, 2, 3):
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES ({n})')
        self.cur.execute(f'DELETE FROM {self.TABLE} WHERE id < 3')
        self.assertEqual(self.cur.rowcount, 2)

    def test_rowcount_ddl_is_zero(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.assertEqual(self.cur.rowcount, 0)


@unittest.skipUnless(_USER, _SKIP_REASON)
class CursorCacheIntegration(_IntegrationBase):
    """Verify the cursor cache hands out a non-zero handle on the first
    DML execute and reuses it (with a smaller wire request) on repeats."""

    def _cached_handle(self, sql):
        # The cursor cache is keyed on (SQL text, bind-OAC signature), not the
        # bare SQL, so look up by the SQL component of the tuple keys.
        handles = [v for k, v in self.conn._cursor_cache.items() if k[0] == sql]
        return handles[0] if handles else None

    @_requires(_CURSOR_CACHE)
    def test_repeated_dml_reuses_cursor(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(10))')
        Sql = f'INSERT INTO {self.TABLE} VALUES (:id, :v)'
        # First execute: parses + caches.
        self.cur.execute(Sql, {'id': 1, 'v': 'a'})
        FirstCursor = self._cached_handle(Sql)
        self.assertIsNotNone(FirstCursor)
        self.assertGreater(FirstCursor, 0)
        # Second execute of identical SQL (same bind shape): same cached handle.
        self.cur.execute(Sql, {'id': 2, 'v': 'b'})
        self.assertEqual(self._cached_handle(Sql), FirstCursor)
        # Different SQL → different cache entry.
        Sql2 = f'UPDATE {self.TABLE} SET v = :v WHERE id = 1'
        self.cur.execute(Sql2, {'v': 'z'})
        self.assertIsNotNone(self._cached_handle(Sql2))
        self.assertNotEqual(self._cached_handle(Sql), self._cached_handle(Sql2))
        # And the rows are what we expect.
        self.cur.execute(f'SELECT id, v FROM {self.TABLE} ORDER BY id')
        self.assertEqual(self.cur.fetchall(), [(1, 'z'), (2, 'b')])

    @_requires(_CURSOR_CACHE)
    def test_a_failed_execute_forgets_the_cached_cursor(self):
        # The server drops a cursor whose execute failed. Keeping its id made
        # every later execute of the same statement answer ORA-01001 (#709).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY)')
        Sql = f'INSERT INTO {self.TABLE} VALUES (:id)'
        self.cur.execute(Sql, {'id': 1})
        self.assertIsNotNone(self._cached_handle(Sql))
        with self.assertRaises(seerdb.DatabaseError):
            self.cur.execute(Sql, {'id': 1})  # ORA-00001, as it should
        self.assertIsNone(self._cached_handle(Sql))
        self.cur.execute(Sql, {'id': 2})  # parses afresh: no ORA-01001
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (2,))

    @_requires(_CURSOR_CACHE)
    def test_ddl_forgets_the_cached_cursors(self):
        # A cached cursor re-executed after its table was dropped and
        # re-created made the server reuse the previous execution's value for
        # a NULL LONG-class bind: ORA-12899 here, silent corruption into a
        # wider column (#720). DDL flushes the cache.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, d CLOB)')
        Sql = f'INSERT INTO {self.TABLE} (id, d) VALUES (:id, :d)'
        Wide = self.cur.var(str)
        Wide.setvalue(0, 'x' * 3826)
        self.cur.execute(Sql, {'id': 1, 'd': Wide})
        self.cur.execute(f'DROP TABLE {self.TABLE}')
        self.assertEqual(self.conn._cursor_cache, {})
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, d VARCHAR2(255))')
        self.cur.execute(Sql, {'id': 2, 'd': self.cur.var(str)})  # NULL
        self.cur.execute(f'SELECT id, d FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(2, None)])

    @_requires(_PRE10_RETURNING)
    def test_pre_10g_serves_the_into_clause_through_a_block(self):
        # Below 10g the 10g+ request form is refused by the server (9i answers
        # ORA-00439), but the identical statement runs inside a PL/SQL block
        # where the INTO targets are ordinary OUT binds, so the driver rewrites
        # it there (#801). 8i keeps refusing (#802).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        Sql = f'INSERT INTO {self.TABLE} (id) VALUES (:1) RETURNING id INTO :2'
        Got = self.cur.var(int)
        self.cur.execute(Sql, [1, Got])
        # A RETURNING bind hands back one entry per affected row, exactly as it
        # does on 10g+ -- the rewrite must not change the shape callers see.
        self.assertEqual(Got.getvalue(), [1])
        # The row count must come from SQL%ROWCOUNT, not from the block itself --
        # a block reports its own execution, always 1.
        self.assertEqual(self.cur.rowcount, 1)
        # A statement that matches nothing reports zero rows and no value,
        # rather than failing to decode the reply.
        Miss = self.cur.var(int)
        self.cur.execute(
            f'UPDATE {self.TABLE} SET id = 9 WHERE id = :1 RETURNING id INTO :2',
            [12345, Miss],
        )
        self.assertEqual(Miss.getvalue(), [])  # 10g+ reports [] for no rows
        self.assertEqual(self.cur.rowcount, 0)
        # Either way the session stays usable.
        self.cur.execute(f'INSERT INTO {self.TABLE} (id) VALUES (:1)', [2])
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        self.assertIn((2,), self.cur.fetchall())

    @_requires(_CURSOR_CACHE)
    def test_a_wide_bind_is_never_cached(self):
        # DDL from another session would leave the same stale buffer behind,
        # so a statement with a LONG-class bind parses afresh every time (#720).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, d VARCHAR2(50))')
        Sql = f'INSERT INTO {self.TABLE} (id, d) VALUES (:id, :d)'
        Wide = self.cur.var(str)
        Wide.setvalue(0, 'w')
        self.cur.execute(Sql, {'id': 1, 'd': Wide})
        self.assertIsNone(self._cached_handle(Sql))
        self.cur.execute(Sql, {'id': 2, 'd': 'plain'})
        self.assertIsNotNone(self._cached_handle(Sql))

    def test_cache_does_not_apply_to_select(self):
        # SELECT cache is intentionally skipped — caching a SELECT would
        # also need to remember the row format from the first DCB. Make
        # sure repeat SELECT works (i.e., we re-parse cleanly each time)
        # and that the cache stays SELECT-free.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (2)')
        Sql = f'SELECT id FROM {self.TABLE} WHERE id = :x'
        self.cur.execute(Sql, {'x': 1})
        self.assertEqual(self.cur.fetchall(), [(1,)])
        self.cur.execute(Sql, {'x': 2})
        self.assertEqual(self.cur.fetchall(), [(2,)])
        self.assertNotIn(Sql, self.conn._cursor_cache)

    @_requires(_CURSOR_CACHE)
    def test_cache_evicts_oldest_when_full(self):
        # Drive past `_cursor_cache_max` distinct DML statements and
        # confirm the cache stays bounded and keeps the most recent.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        Max = self.conn._cursor_cache_max
        for i in range(Max + 5):
            # Each statement text is distinct, so each occupies its own
            # cache slot rather than sharing a handle.
            self.cur.execute(f'INSERT INTO {self.TABLE} /*{i}*/ VALUES ({i})')
        self.assertEqual(len(self.conn._cursor_cache), Max)
        # The most recent insert's SQL must still be cached; the
        # earliest ones must have been evicted.
        Latest = f'INSERT INTO {self.TABLE} /*{Max + 4}*/ VALUES ({Max + 4})'
        Earliest = f'INSERT INTO {self.TABLE} /*0*/ VALUES (0)'
        CachedSql = {k[0] for k in self.conn._cursor_cache}
        self.assertIn(Latest, CachedSql)
        self.assertNotIn(Earliest, CachedSql)


def _clob_as_text(cursor, metadata):
    # An output type handler fetching the CLOB / BLOB columns as their content
    # (#2458), as python-oracledb's documentation writes one.
    if metadata.type_code is seerdb.DB_TYPE_CLOB:
        return cursor.var(seerdb.DB_TYPE_LONG, arraysize=cursor.arraysize)
    if metadata.type_code is seerdb.DB_TYPE_BLOB:
        return cursor.var(seerdb.DB_TYPE_LONG_RAW, arraysize=cursor.arraysize)
    return None


def _number_as_text(cursor, metadata):
    if metadata.type_code is seerdb.DB_TYPE_NUMBER:
        return cursor.var(str, arraysize=cursor.arraysize)
    return None


@unittest.skipUnless(_USER, _SKIP_REASON)
class TypeHandlerIntegration(_IntegrationBase):
    """Output type handlers and fetch_decimals on a live server (#2458)."""

    _WHEN = datetime.datetime(2026, 11, 4)

    def _fill(self):
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, n NUMBER, c CLOB, b BLOB, d DATE)'
        )
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES '
            "(1, 1.5, 'lob text', HEXTORAW('0102'), "
            "TO_DATE('2026-11-04', 'YYYY-MM-DD'))"
        )
        self.cur.execute(f'INSERT INTO {self.TABLE} (id) VALUES (2)')

    def test_a_number_fetched_as_text(self):
        self.cur.outputtypehandler = _number_as_text
        self.cur.execute('SELECT 1.5, 4371, -0.0000001 FROM dual')
        self.assertEqual(self.cur.fetchone(), ('1.5', '4371', '-0.0000001'))
        # The description still says what the column is.
        self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_NUMBER)

    def test_lobs_as_content_then_as_lobs_on_the_same_statement(self):
        # The statement is cached after the first run, so the second and third
        # reuse it with a different handler -- the sequence python-oracledb
        # misreads. A DATE beside the LOBs is where a misread shows.
        from seerdb.common.lob import LOB

        self._fill()
        Sql = f'SELECT c, b, d FROM {self.TABLE} WHERE id = 1'
        # 8i reads every LOB's content as it fetches, LOB objects or not.
        KeepsLobs = not _conn_is_8i(self.conn)
        for Handler in (None, _clob_as_text, None):
            with self.subTest(handler=Handler):
                Cur = self.conn.cursor()
                Cur.outputtypehandler = Handler
                Cur.execute(Sql)
                (C, B, D) = Cur.fetchone()
                if Handler is None and KeepsLobs:
                    self.assertIsInstance(C, LOB)
                    self.assertIsInstance(B, LOB)
                    (C, B) = (C.read(), B.read())
                self.assertEqual((C, B, D), ('lob text', b'\x01\x02', self._WHEN))

    def test_the_connection_handler_serves_cursors_without_one(self):
        self.conn.outputtypehandler = _number_as_text
        Cur = self.conn.cursor()
        self.assertEqual(Cur.execute('SELECT 7 FROM dual').fetchone(), ('7',))
        # A cursor's own handler wins, even one that leaves the column alone.
        Cur = self.conn.cursor()
        Cur.outputtypehandler = lambda cursor, metadata: None
        self.assertEqual(Cur.execute('SELECT 7 FROM dual').fetchone(), (7,))

    def test_outconverter_and_convert_nulls(self):
        self._fill()
        Sql = f'SELECT n FROM {self.TABLE} ORDER BY id'

        def Converting(nulls):
            def Handler(cursor, metadata):
                return cursor.var(
                    str,
                    arraysize=cursor.arraysize,
                    outconverter=lambda v: f'<{v}>',
                    convert_nulls=nulls,
                )

            return Handler

        self.cur.outputtypehandler = Converting(False)
        self.assertEqual(self.cur.execute(Sql).fetchall(), [('<1.5>',), (None,)])
        self.cur.outputtypehandler = Converting(True)
        self.assertEqual(self.cur.execute(Sql).fetchall(), [('<1.5>',), ('<None>',)])

    def test_fetch_decimals(self):
        Sql = "SELECT 4371, 1.5, CAST(NULL AS NUMBER), 'x' FROM dual"
        self.cur.execute(Sql, fetch_decimals=True)
        self.assertEqual(
            self.cur.fetchone(), (Decimal(4371), Decimal('1.5'), None, 'x')
        )
        self.assertEqual(self.cur.execute(Sql).fetchone()[0], 4371)
        Saved = seerdb.defaults.fetch_decimals
        seerdb.defaults.fetch_decimals = True
        try:
            self.assertIsInstance(self.cur.execute(Sql).fetchone()[0], Decimal)
        finally:
            seerdb.defaults.fetch_decimals = Saved

    def test_a_refused_conversion_fails_the_execute(self):
        self.cur.outputtypehandler = lambda cursor, metadata: cursor.var(bytes)
        with self.assertRaises(seerdb.DatabaseError):
            self.cur.execute('SELECT 1 FROM dual')
        self.assertIsNone(self.cur.description)
        # The connection is fine afterwards.
        self.cur.outputtypehandler = None
        self.assertEqual(self.cur.execute('SELECT 1 FROM dual').fetchone(), (1,))

    # --- the input side ---

    def test_an_input_handler_binds_a_python_object(self):
        self.cur.inputtypehandler = _point_as_text
        self.assertEqual(
            self.cur.execute('SELECT :1 FROM dual', [_Point(1, 2)]).fetchone(), ('1,2',)
        )
        # The connection's serves a cursor without one.
        self.conn.inputtypehandler = _point_as_text
        Cur = self.conn.cursor()
        self.assertEqual(
            Cur.execute('SELECT :1 FROM dual', [_Point(3, 4)]).fetchone(), ('3,4',)
        )

    def test_an_input_handler_over_an_executemany(self):
        Calls = []

        def Handler(cursor, value, num_elements):
            Calls.append(num_elements)
            return _point_as_text(cursor, value, num_elements)

        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, p VARCHAR2(20))')
        self.cur.inputtypehandler = Handler
        Rows = [(1, _Point(1, 2)), (2, _Point(3, 4)), (3, _Point(5, 6))]
        self.cur.executemany(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', Rows)
        # A PL/SQL block's rows run one at a time (#2479); the handler still
        # sees the batch once per position.
        self.cur.executemany(
            f'BEGIN INSERT INTO {self.TABLE} VALUES (:1 + 10, :2); END;', Rows
        )
        self.assertEqual(Calls, [3, 3, 3, 3])
        self.cur.execute(f'SELECT n, p FROM {self.TABLE} ORDER BY n')
        self.assertEqual(
            self.cur.fetchall(),
            [(1, '1,2'), (2, '3,4'), (3, '5,6'), (11, '1,2'), (12, '3,4'), (13, '5,6')],
        )

    def test_a_value_the_handler_s_var_cannot_take_is_refused(self):
        self.cur.inputtypehandler = lambda cursor, value, num_elements: cursor.var(str)
        with self.assertRaises(seerdb.NotSupportedError):
            self.cur.execute('SELECT :1 FROM dual', [12])
        self.cur.inputtypehandler = None
        self.assertEqual(
            self.cur.execute('SELECT :1 FROM dual', [12]).fetchone(), (12,)
        )


class _Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y


def _point_as_text(cursor, value, num_elements):
    # An input type handler binding a Python object the driver can't (#2458).
    if isinstance(value, _Point):
        return cursor.var(
            str, arraysize=num_elements, inconverter=lambda p: f'{p.x},{p.y}'
        )
    return None


@unittest.skipUnless(_USER, _SKIP_REASON)
class VarValueIntegration(_IntegrationBase):
    """A Var's value must fit its type (#2477): one that doesn't used to reach
    the server as the wrong type's bytes and come back as garbage."""

    def test_a_value_that_does_not_fit_is_refused_before_the_server(self):
        for Typ, Value in ((str, 12), (int, '12'), (seerdb.DB_TYPE_DATE, '12')):
            with self.subTest(var=Typ, value=Value):
                V = self.cur.var(Typ)
                with self.assertRaises(seerdb.NotSupportedError):
                    V.setvalue(0, Value)
        # As a declared bind type too.
        self.cur.setinputsizes(int)
        with self.assertRaises(seerdb.NotSupportedError):
            self.cur.execute('SELECT :1 FROM dual', ['12'])
        self.assertEqual(self.cur.execute('SELECT 1 FROM dual').fetchone(), (1,))

    def test_a_binary_double_takes_a_decimal(self):
        from seerdb.common.tns_consts import FIELD_VERSION_10_2

        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('BINARY_DOUBLE is 10g+')
        for Value, Expected in ((Decimal('1.25'), 1.25), (True, 1.0), (12, 12.0)):
            with self.subTest(value=Value):
                V = self.cur.var(seerdb.DB_TYPE_BINARY_DOUBLE)
                V.setvalue(0, Value)
                self.assertEqual(
                    self.cur.execute('SELECT :1 FROM dual', [V]).fetchone(), (Expected,)
                )


@unittest.skipUnless(_USER, _SKIP_REASON)
class PlsqlExecutemanyIntegration(_IntegrationBase):
    """executemany() of a PL/SQL block with binds (#2479): sent as one array
    execute it was refused, ORA-03146 and a killed session on 23ai, a dropped
    connection on 11g."""

    def _fill(self, Rows):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, s VARCHAR2(20))')
        self.cur.executemany(
            f'BEGIN INSERT INTO {self.TABLE} VALUES (:1, :2); END;', Rows
        )

    def test_every_row_runs(self):
        Rows = [(1, 'one'), (2, 'two'), (3, None)]
        self._fill(Rows)
        self.cur.execute(f'SELECT n, s FROM {self.TABLE} ORDER BY n')
        self.assertEqual(self.cur.fetchall(), Rows)
        # The connection is fine afterwards.
        self.assertEqual(self.cur.execute('SELECT 1 FROM dual').fetchone(), (1,))

    def test_named_binds(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, s VARCHAR2(20))')
        self.cur.executemany(
            f'BEGIN INSERT INTO {self.TABLE} VALUES (:n, :s); END;',
            [{'n': 1, 's': 'a'}, {'n': 2, 's': 'b'}],
        )
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (2,))

    def test_a_failing_row_is_named_and_the_rows_before_it_ran(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER)')
        Sql = (
            f'BEGIN IF :1 = 2 THEN '
            "RAISE_APPLICATION_ERROR(-20001, 'row two'); END IF; "
            f'INSERT INTO {self.TABLE} VALUES (:1); END;'
        )
        with self.assertRaises(seerdb.DatabaseError) as Raised:
            self.cur.executemany(Sql, [(1,), (2,), (3,)])
        self.assertEqual(Raised.exception.code, 20001)
        self.assertEqual(Raised.exception.offset, 1)
        self.cur.execute(f'SELECT n FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [(1,)])

    def test_setinputsizes_types_every_row(self):
        # Every row's NULL is a NUMBER, so the comparison with a NUMBER column
        # is accepted for each of them, not only for the first.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER)')
        self.cur.setinputsizes(int)
        self.cur.executemany(
            f'BEGIN INSERT INTO {self.TABLE} VALUES (NVL(:1, 0) + 1); END;',
            [(None,), (None,), (None,)],
        )
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE} WHERE n = 1')
        self.assertEqual(self.cur.fetchone(), (3,))


@unittest.skipUnless(_USER, _SKIP_REASON)
class ParseIntegration(_IntegrationBase):
    """`cursor.parse()` (#1018): parse the statement, never run it.

    The server validates syntax, object names and bind-variable names, and
    nothing else happens. A query also comes back described. 10g and up — the
    pre-10g request dialects have no parse-without-execute shape, and refuse.
    """

    def _pre10(self):
        return self.conn.field_version < FIELD_VERSION_10_2

    @_requires(_PRE10_PARSE_REFUSAL)
    def test_parse_is_refused_on_pre10(self):
        with self.assertRaises(seerdb.NotSupportedError):
            self.cur.parse('SELECT 1 FROM DUAL')
        # The connection is untouched by the refusal — nothing went on the wire.
        self.cur.execute('SELECT 1 FROM DUAL')
        self.assertEqual(self.cur.fetchone(), (1,))

    @_requires(_PARSE)
    def test_parse_describes_a_query_without_fetching_it(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, %s)' % "'a'")
        self.cur.parse(f'SELECT id, name FROM {self.TABLE}')
        self.assertEqual([d[0] for d in self.cur.description], ['ID', 'NAME'])
        # Described, not run: no rows were fetched. Draining the parse's cursor
        # is what ORA-01002 (fetch out of sequence) came from.
        self.assertEqual(self.cur.fetchall(), [])

    @_requires(_PARSE)
    def test_parse_does_not_run_the_statement(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.parse(f'INSERT INTO {self.TABLE} (id) VALUES (:v)')
        self.assertIsNone(self.cur.description)  # not a query
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (0,))

    @_requires(_PARSE)
    def test_parse_reports_an_unknown_column(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.parse(f'SELECT nonexistent_col FROM {self.TABLE}')
        self.assertEqual(ctx.exception.code, 904)  # ORA-00904

    @_requires(_PARSE)
    def test_parse_reports_an_invalid_bind_name(self):
        # The motivating case (#826): a RETURNING clause whose INTO target names
        # a reserved word is rejected at parse time and at no other time.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.parse(
                f'INSERT INTO {self.TABLE} (id) VALUES (:v) RETURNING id INTO :ROWID'
            )
        self.assertEqual(ctx.exception.code, 1745)  # ORA-01745

    def test_a_query_with_a_reserved_bind_name_is_ora_01745(self):
        # A query's bind named by a reserved word is refused as a DML's is, at
        # parse and at execute. The Mirror over PostgreSQL turned `:ROWID` in a
        # select list into its ROWID rewrite, a syntax error (#1371).
        with self.assertRaises(seerdb.DatabaseError) as executed:
            self.cur.execute('SELECT :ROWID FROM dual', [1])
        self.assertEqual(executed.exception.code, 1745)
        if self._pre10():
            return  # cursor.parse() needs 10g+
        with self.assertRaises(seerdb.DatabaseError) as parsed:
            self.cur.parse('SELECT :ROWID FROM dual')
        self.assertEqual(parsed.exception.code, 1745)

    @_requires(_PARSE)
    def test_parse_takes_numbered_placeholders(self):
        # A parse carries no values, so its statement is checked with a NULL for
        # each placeholder -- numbered ones too. The Mirror counted only named
        # ones and sent `values (:1)` to the database unbound (#1394).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.parse(f'INSERT INTO {self.TABLE} (id) VALUES (:1)')
        self.cur.parse(f'SELECT id FROM {self.TABLE} WHERE id = :1')
        self.assertEqual([d[0] for d in self.cur.description], ['ID'])

    @_requires(_PARSE)
    def test_parse_reports_a_statement_that_is_not_sql(self):
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.parse('this is not sql')
        self.assertEqual(ctx.exception.code, 900)  # ORA-00900

    @_requires(_PARSE)
    def test_parse_accepts_a_plsql_block(self):
        self.cur.parse('BEGIN NULL; END;')
        self.assertIsNone(self.cur.description)

    @_requires(_PARSE)
    def test_the_cursor_is_usable_after_a_failed_parse(self):
        # A parse that raised must leave the session in step — the whole point
        # of validating without running.
        with self.assertRaises(seerdb.DatabaseError):
            self.cur.parse('this is not sql')
        self.cur.execute('SELECT 1 FROM DUAL')
        self.assertEqual(self.cur.fetchone(), (1,))


@unittest.skipUnless(_USER, _SKIP_REASON)
class FetchFlowIntegration(_IntegrationBase):
    """Verify the follow-up TTI_FETCH flow.

    When a SELECT result set exceeds the per-call fetch size, the server
    returns the first N rows inline plus OER.call_status == 1 ("more on
    this cursor"). The driver must then issue TTI_FETCH against the open
    cursor until the server signals ORA-01403 (end of fetch).
    """

    def _populate(self, num_rows: int):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        for n in range(1, num_rows + 1):
            self.cur.execute(
                f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [n, f'row{n}']
            )

    def test_select_within_fetch_size(self):
        # 3 rows, default fetch (15) — single round-trip, no follow-up needed.
        self._populate(3)
        self.cur.execute(f'SELECT id, name FROM {self.TABLE} ORDER BY id')
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 3)
        self.assertEqual([r[0] for r in rows], [1, 2, 3])

    def test_select_spans_multiple_fetches(self):
        # 50 rows with fetch=7 → 8 round-trips (1 EXEC + 7 FETCH).
        self._populate(50)
        self.conn.fetch = 7
        self.cur.execute(f'SELECT id, name FROM {self.TABLE} ORDER BY id')
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 50)
        self.assertEqual([r[0] for r in rows], list(range(1, 51)))
        self.assertEqual(rows[-1], (50, 'row50'))

    def test_select_exactly_one_fetch_boundary(self):
        # Row count exactly equal to fetch size — boundary case where the
        # server may or may not signal "more available" on the initial EXEC.
        self._populate(7)
        self.conn.fetch = 7
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        rows = self.cur.fetchall()
        self.assertEqual([r[0] for r in rows], list(range(1, 8)))

    def test_select_empty_table(self):
        # Zero-row SELECT — the FETCH loop must not fire.
        self._populate(0)
        self.cur.execute(f'SELECT id FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchall(), [])

    def test_scroll_over_buffered_result(self):
        # Cursor.scroll (issue #19) over a result set that spans several
        # server fetches — the whole set is buffered, so scroll repositions
        # locally in any direction.
        self._populate(20)
        self.conn.fetch = 6
        self.cur.execute(f'SELECT id, name FROM {self.TABLE} ORDER BY id')
        self.cur.scroll(mode='last')
        self.assertEqual(self.cur.fetchone(), (20, 'row20'))
        self.cur.scroll(10, mode='absolute')
        self.assertEqual(self.cur.fetchone(), (10, 'row10'))
        self.cur.scroll(-5, mode='relative')  # from row 10 -> row 5
        self.assertEqual(self.cur.fetchone(), (5, 'row5'))
        self.cur.scroll(mode='first')
        self.assertEqual(self.cur.fetchone(), (1, 'row1'))
        with self.assertRaises(IndexError):
            self.cur.scroll(999, mode='absolute')

    def test_scrollable_cursor(self):
        # Scrollable cursor (#161, oracledb parity): cursor(scrollable=True) +
        # the .scrollable property + scroll in every mode.
        self._populate(10)
        sc = self.conn.cursor(scrollable=True)
        self.assertIs(sc.scrollable, True)
        self.assertIs(self.conn.cursor().scrollable, False)
        sc.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        sc.scroll(5, mode='absolute')
        self.assertEqual(sc.fetchone(), (5,))
        sc.scroll(-2, mode='relative')
        self.assertEqual(sc.fetchone(), (3,))
        sc.scroll(mode='last')
        self.assertEqual(sc.fetchone(), (10,))
        sc.scroll(mode='first')
        self.assertEqual(sc.fetchone(), (1,))

    @_requires(_SERVER_SCROLL)
    def test_scrollable_lazy_fetch_on_demand(self):
        # Server-side scrollable cursor (#181), 10g+: rows are pulled lazily from
        # a kept-open cursor in arraysize batches (here prefetchrows=2,
        # arraysize=3 over 10 rows forces several positioned re-executes), and
        # scroll() repositions server-side. 9i has no OALL8 scroll and falls back
        # to the buffered path (covered by test_scrollable_cursor).
        self._populate(10)
        sc = self.conn.cursor(scrollable=True)
        sc.prefetchrows = 2
        sc.arraysize = 3
        sc.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        self.assertTrue(sc._scroll_active)  # lazy path engaged
        # fetch-on-demand across batch boundaries
        self.assertEqual([r[0] for r in sc.fetchmany(5)], [1, 2, 3, 4, 5])
        sc.scroll(8, mode='absolute')
        self.assertEqual([r[0] for r in sc.fetchall()], [8, 9, 10])
        sc.scroll(mode='first')
        self.assertEqual([r[0] for r in sc.fetchall()], list(range(1, 11)))

    @_requires(_SERVER_SCROLL)
    def test_scrollable_scroll_off_end_and_back(self):
        # Scrolling past the end (#181) leaves the cursor empty (next fetchone is
        # None), and a later scroll repositions back into the result set.
        self._populate(5)
        sc = self.conn.cursor(scrollable=True)
        sc.prefetchrows = 2
        sc.arraysize = 2
        sc.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        sc.scroll(99, mode='absolute')
        self.assertIsNone(sc.fetchone())
        sc.scroll(mode='first')
        self.assertEqual(sc.fetchone(), (1,))

    @_requires(_SERVER_SCROLL)
    def test_scrollable_last_after_eof_duplicate_value(self):
        # LAST after the buffer already reached EOF with arraysize >= row count
        # (#181): the server repositions onto the last row, whose value equals the
        # one just returned, so it omits the value and flags "reuse previous" in
        # the row-header bit vector. Exercises decode_token_rxh's bit-vector pass
        # + the previous-row seed (this used to desync / crash on token 0x0a).
        self._populate(6)
        sc = self.conn.cursor(scrollable=True)
        sc.prefetchrows = 2
        sc.arraysize = 50  # >= row count
        sc.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        sc.scroll(mode='first')
        self.assertEqual([r[0] for r in sc.fetchall()], list(range(1, 7)))
        sc.scroll(mode='last')
        self.assertEqual(sc.fetchone(), (6,))  # correct value, no crash

    def test_fetch_df_all_and_batches(self):
        # Arrow / DataFrame bulk fetch (#162): fetch_df_all returns a
        # pyarrow.Table column-major; fetch_df_batches streams it in chunks.
        import pyarrow as pa

        self._populate(7)
        self.cur.execute(f'SELECT id, name FROM {self.TABLE} ORDER BY id')
        table = self.cur.fetch_df_all()
        self.assertIsInstance(table, pa.Table)
        self.assertEqual(table.num_rows, 7)
        self.assertEqual([c.upper() for c in table.column_names], ['ID', 'NAME'])
        self.assertEqual(table.column('ID').to_pylist(), list(range(1, 8)))
        self.assertEqual(
            table.column('NAME').to_pylist(), [f'row{i}' for i in range(1, 8)]
        )
        # batches of 3 -> 3 + 3 + 1
        self.cur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        sizes = [b.num_rows for b in self.cur.fetch_df_batches(size=3)]
        self.assertEqual(sizes, [3, 3, 1])
        # empty result keeps a usable schema
        self.cur.execute(f'SELECT id, name FROM {self.TABLE} WHERE id > 999')
        empty = self.cur.fetch_df_all()
        self.assertEqual(empty.num_rows, 0)
        self.assertEqual(len(empty.column_names), 2)

    def test_end_to_end_tracing(self):
        # End-to-end application tracing (#183): set module / action /
        # client_identifier; the change flushes with the next execute and shows
        # up in SYS_CONTEXT('USERENV', ...). 12c+ and the native form on 10g and
        # 11g (thin's piggyback closes a pre-12c connection); elsewhere it must
        # raise NotSupportedError instead.
        if not _target_of(self.conn).end_to_end:
            with self.assertRaises(seerdb.NotSupportedError):
                self.conn.module = 'M'
            return
        self.conn.module = 'PYOMOD'
        self.conn.action = 'PYOACT'
        self.conn.client_identifier = 'PYOCLID'
        self.assertEqual(self.conn.module, 'PYOMOD')
        self.cur.execute(
            "SELECT SYS_CONTEXT('USERENV','MODULE'), "
            "SYS_CONTEXT('USERENV','ACTION'), "
            "SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') FROM dual"
        )
        self.assertEqual(self.cur.fetchone(), ('PYOMOD', 'PYOACT', 'PYOCLID'))
        # changing only one updates just that attribute
        self.conn.action = 'ACT2'
        self.cur.execute(
            "SELECT SYS_CONTEXT('USERENV','ACTION'), "
            "SYS_CONTEXT('USERENV','MODULE') FROM dual"
        )
        self.assertEqual(self.cur.fetchone(), ('ACT2', 'PYOMOD'))
        # clientinfo (#184) shows in USERENV.CLIENT_INFO.
        self.conn.clientinfo = 'PYOINFO'
        self.cur.execute("SELECT SYS_CONTEXT('USERENV','CLIENT_INFO') FROM dual")
        self.assertEqual(self.cur.fetchone(), ('PYOINFO',))
        self.assertEqual(self.conn.clientinfo, 'PYOINFO')
        # dbop (#184) is monitored via V$SQL_MONITOR (not USERENV); just confirm
        # the piggyback is accepted and the connection stays usable. OCI 11.2's
        # form has no field for it.
        if self.conn.field_version < FIELD_VERSION_12_1:
            with self.assertRaises(seerdb.NotSupportedError):
                self.conn.dbop = 'PYODBOP'
            return
        self.conn.dbop = 'PYODBOP'
        self.cur.execute('SELECT 1 FROM dual')
        self.assertEqual(self.cur.fetchone(), (1,))
        self.assertEqual(self.conn.dbop, 'PYODBOP')

    @_requires(_END_TO_END)
    def test_module_alone(self):
        # Setting module without action must not malform the piggyback — Oracle
        # requires both together, so a module-only flush carries action too
        # (#184).
        self.conn.module = 'SOLOMOD'
        self.cur.execute("SELECT SYS_CONTEXT('USERENV','MODULE') FROM dual")
        self.assertEqual(self.cur.fetchone(), ('SOLOMOD',))

    @_requires(_END_TO_END)
    def test_clearing_a_tracing_attribute(self):
        self.conn.client_identifier = 'TOCLEAR'
        self.cur.execute("SELECT SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') FROM dual")
        self.assertEqual(self.cur.fetchone(), ('TOCLEAR',))
        self.conn.client_identifier = None
        self.cur.execute("SELECT SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') FROM dual")
        self.assertEqual(self.cur.fetchone(), (None,))

    @_requires(_END_TO_END)
    def test_a_non_ascii_tracing_attribute(self):
        self.conn.clientinfo = 'caf\u00e9'
        self.cur.execute("SELECT SYS_CONTEXT('USERENV','CLIENT_INFO') FROM dual")
        self.assertEqual(self.cur.fetchone(), ('caf\u00e9',))

    @_requires(_FV2_EXECUTE_PATH)
    def test_repeated_execute_no_cursor_leak(self):
        # #191: repeated execute() of one statement must not leak server
        # cursors. Pre-fix this tripped ORA-01000 after ~300 executes on 12c+
        # (cache off); the drained cursor is now freed by an OCCA piggyback in
        # front of the next call. 400 > the typical OPEN_CURSORS, so this would
        # fail on 12c+ without the fix.
        t = 'PYO_LEAK191'
        try:
            self.cur.execute(f'DROP TABLE {t}')
        except seerdb.DatabaseError:
            # table may not exist; drop is best-effort cleanup
            pass
        self.cur.execute(f'CREATE TABLE {t} (id NUMBER)')
        try:
            for i in range(400):
                self.cur.execute(f'INSERT INTO {t} VALUES (:1)', [i])
            self.conn.commit()
            self.cur.execute(f'SELECT COUNT(*) FROM {t}')
            self.assertEqual(self.cur.fetchone()[0], 400)
        finally:
            self.cur.execute(f'DROP TABLE {t}')


@unittest.skipUnless(_USER, _SKIP_REASON)
class LOBIntegration(_IntegrationBase):
    """Verify LOB column read + content extraction.

    These tests are about the CONTENT surviving the wire, so they connect with
    ``fetch_lobs=False`` and keep asserting on str / bytes. The LOB OBJECT that
    the default now returns is exercised by :class:`LOBObjectIntegration`
    below (#964).

    NULL LOBs surface as Python None. EMPTY_CLOB() / EMPTY_BLOB() come
    back as `""` / `b""`. Non-empty small LOBs whose content fits inside
    the inline section of the locator block round-trip as `str` (CLOB) or
    `bytes` (BLOB). Out-of-line content (large LOBs that overflow the
    inline budget) needs a TTI_LOBOPS round-trip the driver doesn't yet
    issue — see the README's "still in progress" list.
    """

    def setUp(self):
        # Values, not LOB objects: see the class docstring (#964).
        self._fetch_lobs = False
        super().setUp()

    def test_lob_columns_are_readable_inside_an_open_transaction(self):
        # call_status reads 2 while a transaction is open; keyed on the value 1,
        # the drain never fetched the row the server had deferred (pre-12c) and
        # the LOB reader never saw the end of call (12c+) (#712).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, t CLOB, b BLOB)')
        Conn = seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=False,
            **_FV_KW,
        )
        try:
            Cur = Conn.cursor()
            Cur.execute(
                f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3)',
                [1, 'some text', b'\x00\x01'],
            )
            Cur.execute(f'SELECT t, b FROM {self.TABLE}')
            Row = Cur.fetchone()
            self.assertIsNotNone(Row, 'the uncommitted LOB row was not returned')
            Values = tuple(V.read() if hasattr(V, 'read') else V for V in Row)
            self.assertEqual(Values, ('some text', b'\x00\x01'))
            Conn.rollback()
        finally:
            Conn.close()
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (0,))

    def _setup(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, c CLOB, b BLOB)')

    def test_null_lobs_are_none(self):
        self._setup()
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, NULL, NULL)')
        self.cur.execute(f'SELECT id, c, b FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (1, None, None))

    def test_empty_lobs_are_empty_str_or_bytes(self):
        self._setup()
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (1, EMPTY_CLOB(), EMPTY_BLOB())'
        )
        self.cur.execute(f'SELECT c, b FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), ('', b''))

    def test_clob_content_round_trip(self):
        self._setup()
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 'hello clob', NULL)")
        self.cur.execute(f'SELECT c FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), ('hello clob',))

    def test_non_ascii_clob_content_reads_as_itself(self):
        # 'é' read back as 'Ã©' from a 9i WE8ISO8859P1 database (#2383).
        self._setup()
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, :1, NULL)', ['café'])
        self.cur.execute(f'SELECT c FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), ('café',))

    def test_blob_content_round_trip(self):
        self._setup()
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, NULL, HEXTORAW('DEADBEEF'))"
        )
        self.cur.execute(f'SELECT b FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (b'\xde\xad\xbe\xef',))

    def test_blob_with_non_ascii_high_bytes(self):
        # Includes a byte (0xCA) that's outside ASCII so we'd notice if the
        # decoder accidentally tried to decode the BLOB as text.
        self._setup()
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, NULL, HEXTORAW('CAFEBABE0123'))"
        )
        self.cur.execute(f'SELECT b FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (b'\xca\xfe\xba\xbe\x01\x23',))

    def test_clob_with_longer_content(self):
        self._setup()
        Text = 'longer text content here'
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, '{Text}', NULL)")
        self.cur.execute(f'SELECT c FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (Text,))

    def test_multiple_rows_with_lobs(self):
        # Walks the row decoder across several rows so any byte-count
        # mistake in the LOB reader would derail the next row.
        self._setup()
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, NULL, NULL)')
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (2, EMPTY_CLOB(), EMPTY_BLOB())'
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (3, 'three', HEXTORAW('A1'))"
        )
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES '
            f"(4, 'four bytes more', HEXTORAW('1234567890ABCDEF'))"
        )
        self.cur.execute(f'SELECT id, c, b FROM {self.TABLE} ORDER BY id')
        rows = self.cur.fetchall()
        self.assertEqual(
            rows,
            [
                (1, None, None),
                (2, '', b''),
                (3, 'three', b'\xa1'),
                (4, 'four bytes more', b'\x12\x34\x56\x78\x90\xab\xcd\xef'),
            ],
        )

    def test_lob_alongside_other_columns(self):
        # Mix a LOB with surrounding non-LOB columns so we exercise the
        # decoder's transition into and out of the LOB code path.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (prefix VARCHAR2(10), c CLOB, suffix NUMBER)'
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES ('alpha', 'middle clob', 42)"
        )
        self.cur.execute(f'SELECT prefix, c, suffix FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), ('alpha', 'middle clob', 42))

    def test_clob_larger_than_inline_budget(self):
        # A CLOB whose content makes the locator+inline section big enough
        # that Oracle would normally not pack it inline. We can't tell from
        # the client side whether the server chose inline or out-of-line
        # storage; what matters is that the TTI_LOBOPS round-trip in
        # LOB.read() returns the full content either way.
        self._setup()
        Text = 'abcdefghij' * 200  # 2000 chars, fits in a SQL literal
        self.cur.execute(f"INSERT INTO {self.TABLE}(id, c) VALUES (1, '{Text}')")
        self.cur.execute(f'SELECT c FROM {self.TABLE}')
        (Got,) = self.cur.fetchone()
        self.assertEqual(len(Got), len(Text))
        self.assertEqual(Got, Text)

    def test_clob_bind_above_varchar2_cap(self):
        # SQL VARCHAR2 binds top out at 4000 bytes. Anything bigger used
        # to trip ORA-01461 ("can bind a LONG value only for insert into a
        # LONG column"). The bind OAC now declares max_size = 32767 so
        # multi-KiB CLOB binds reach the column.
        self._setup()
        Text = 'abcdefghij' * 700  # 7000 chars
        self.cur.execute(f'INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)', {'c': Text})
        self.cur.execute(f'SELECT c FROM {self.TABLE}')
        (Got,) = self.cur.fetchone()
        self.assertEqual(Got, Text)

    def test_clob_bind_spans_multiple_packets(self):
        # A bind whose request exceeds the SDU (default 8 KiB) must be split
        # across multiple TNS_DATA packets (non-final fragments carry data
        # flags 0x0020). 20 KiB → ~3 fragments; kept under the 32767 regular-
        # bind ceiling so it round-trips on both 11g and 12c+ (issue #8).
        self._setup()
        Text = '0123456789abcdef' * 1250  # 20000 chars, > 2x SDU
        self.cur.execute(f'INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)', {'c': Text})
        self.cur.execute(f'SELECT c FROM {self.TABLE}')
        (Got,) = self.cur.fetchone()
        self.assertEqual(Got, Text)

    def test_blob_bind_round_trip_all_byte_values(self):
        # Two things at once: bytes binds used to be decoded as UTF-8 and
        # re-encoded as UTF-16BE — which corrupted anything outside ASCII
        # and outright crashed on 0x80+ bytes — and they used to share the
        # 4000-byte VARCHAR2 cap. Now they're bound as RAW with the same
        # 32767-byte ceiling. This payload exercises every possible byte
        # value and is past the old cap.
        self._setup()
        Payload = bytes(range(256)) * 25  # 6400 bytes
        self.cur.execute(
            f'INSERT INTO {self.TABLE}(id, b) VALUES (1, :b)', {'b': Payload}
        )
        self.cur.execute(f'SELECT b FROM {self.TABLE}')
        (Got,) = self.cur.fetchone()
        self.assertEqual(Got, Payload)

    # --- Very large LOB binds (#14) -------------------------------------
    #
    # A bind larger than the 32767-byte regular ceiling is streamed to the
    # server as a chunked LONG value and lands in the CLOB / BLOB column. The
    # request itself spans many TNS packets, so this also leans on the request
    # fragmentation fix (#8). These exercise the issue's acceptance sizes
    # (50 KiB and 500 KiB) for both LOB types, byte-for-byte, on 11g and 12c+.

    def test_clob_bind_50kib(self):
        self._setup()
        Text = '0123456789abcdef' * (50 * 1024 // 16)  # 51200 chars
        self.cur.execute(f'INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)', {'c': Text})
        self.cur.execute(f'SELECT c FROM {self.TABLE}')
        (Got,) = self.cur.fetchone()
        self.assertEqual(len(Got), len(Text))
        self.assertEqual(Got, Text)

    def test_clob_bind_500kib(self):
        self._setup()
        Text = '0123456789abcdef' * (500 * 1024 // 16)  # 512000 chars
        self.cur.execute(f'INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)', {'c': Text})
        self.cur.execute(f'SELECT c FROM {self.TABLE}')
        (Got,) = self.cur.fetchone()
        self.assertEqual(len(Got), len(Text))
        self.assertEqual(Got, Text)

    def test_blob_bind_50kib(self):
        self._setup()
        Payload = bytes(range(256)) * 200  # 51200 bytes, every byte value
        self.cur.execute(
            f'INSERT INTO {self.TABLE}(id, b) VALUES (1, :b)', {'b': Payload}
        )
        self.cur.execute(f'SELECT b FROM {self.TABLE}')
        (Got,) = self.cur.fetchone()
        self.assertEqual(len(Got), len(Payload))
        self.assertEqual(Got, Payload)

    def test_blob_bind_500kib(self):
        self._setup()
        Payload = bytes(range(256)) * 2000  # 512000 bytes, every byte value
        self.cur.execute(
            f'INSERT INTO {self.TABLE}(id, b) VALUES (1, :b)', {'b': Payload}
        )
        self.cur.execute(f'SELECT b FROM {self.TABLE}')
        (Got,) = self.cur.fetchone()
        self.assertEqual(len(Got), len(Payload))
        self.assertEqual(Got, Payload)

    def test_clob_inline_chunked_locator(self):
        # A CLOB whose content is woven inline into the locator block can push
        # that block past 254 bytes, where it switches to the 0xFE chunked DALC
        # form. The row decoder must read the block as a DALC, not as a 1-byte
        # size echo + raw bytes (#37). 400 chars lands in that band.
        self._setup()
        Text = 'abcd' * 100
        self.cur.execute(f'INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)', {'c': Text})
        self.cur.execute(f'SELECT c FROM {self.TABLE} WHERE id=1')
        self.assertEqual(self.cur.fetchone()[0], Text)

    def test_nclob_round_trip(self):
        # NCLOB (national-charset LOB). Its inline content is UTF-16BE, so the
        # locator block crosses the 254-byte chunked-DALC threshold at half the
        # character count of a CLOB — the case #37 reported as broken on 11g.
        # Cover small, the chunked band, and supplementary-plane content.
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, nc NCLOB)')
        Cases = {
            1: 'national ünî 中',
            2: 'B' * 200,
            3: 'nclob ünî 中 😀🎉 ' * 80,
        }
        for Id, Text in Cases.items():
            self.cur.execute(
                f'INSERT INTO {self.TABLE}(id, nc) VALUES (:i, :t)',
                {'i': Id, 't': Text},
            )
        for Id, Text in Cases.items():
            self.cur.execute(f'SELECT nc FROM {self.TABLE} WHERE id=:i', {'i': Id})
            self.assertEqual(self.cur.fetchone()[0], Text)

    @_requires(_Need('8i has no UNISTR', not_8i=True))
    def test_a_server_built_national_lob_reads_back(self):
        # Built on the server from UNISTR, so no client text goes through any
        # charset on the way in: what comes back is how the client reads the
        # national form. A native 9i session read its UTF-16 as UTF-8 (#174).
        # As a LOB object (fetch_lobs, the default), whose read takes its charset
        # from the column, and as its content.
        for FetchLobs in (True, False):
            Conn = _connect(fetch_lobs=FetchLobs)
            try:
                Cur = Conn.cursor()
                Cur.execute("SELECT TO_NCLOB(UNISTR('\\0041\\00e9\\4e2d')) FROM dual")
                Value = Cur.fetchone()[0]
                Text = Value.read() if hasattr(Value, 'read') else Value
                self.assertEqual(Text, 'A\u00e9\u4e2d', f'fetch_lobs={FetchLobs}')
            finally:
                Conn.close()

    def test_an_nclob_column_describes_as_nclob(self):
        # An NCLOB column describes as NCLOB, not CLOB, with rows or without,
        # its content still reads back, and USER_TAB_COLUMNS lists it as NCLOB.
        # The Mirror over PostgreSQL stores NCLOB and CLOB alike and described
        # both as CLOB (#1369).
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NCLOB, c CLOB)')
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('ünî 中', 'plain')")
        for where in ('', ' WHERE 1 = 0'):
            self.cur.execute(f'SELECT n, c FROM {self.TABLE}{where}')
            self.cur.fetchall()
            self.assertEqual(
                [d[1] for d in self.cur.description],
                [seerdb.DB_TYPE_NCLOB, seerdb.DB_TYPE_CLOB],
                where,
            )
        self.cur.execute(f'SELECT n FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone()[0], 'ünî 中')
        self.cur.execute(
            'SELECT column_name, data_type FROM user_tab_columns '
            'WHERE table_name = :1 ORDER BY column_id',
            [self.TABLE],
        )
        self.assertEqual(self.cur.fetchall(), [('N', 'NCLOB'), ('C', 'CLOB')])

    def test_error_then_large_lob_stays_synced(self):
        # #45: an errored call leaves the server's break/reset markers on the
        # wire; mishandling them (replying to every marker) storms the line and
        # discards the next response's data, so a large CLOB read right after a
        # few errors came back empty. Interleave errored SELECTs with a 50 KB
        # CLOB read and assert the content is intact and the connection usable.
        from seerdb.common.exceptions import DatabaseError

        self._setup()
        Big = 'A' * 50000
        self.cur.execute(f'INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)', {'c': Big})
        self.conn.commit()
        for _ in range(8):
            with self.assertRaises(DatabaseError):
                self.cur.execute('SELECT * FROM pyoracle_no_such_table_45')
                self.cur.fetchall()
            self.cur.execute(f'SELECT c FROM {self.TABLE} WHERE id=1')
            (Got,) = self.cur.fetchone()
            self.assertEqual(len(Got), len(Big))
            self.assertEqual(Got, Big)


# LOB content lengths around the single-byte length's markers (253-255 are not
# lengths): BLOBs in bytes, CLOBs in characters, which travel as UTF-16, so 127
# characters are the 254 bytes that hung a pre-12.1 session (#1970).
_LOB_EDGE_BLOB_LENGTHS = (1, 250, 251, 252, 253, 254, 255, 256, 257)
_LOB_EDGE_CLOB_LENGTHS = (1, 125, 126, 127, 128, 129)


@unittest.skipUnless(_USER, _SKIP_REASON)
class LOBReadLengthIntegration(_IntegrationBase):
    """A LOB read of every length around the length-byte markers comes back
    whole, at the default field version and at 11.2 (#1970). Before 10g a LOB
    column arrives as its value rather than a LOB object, so both are read."""

    TABLE = 'PYO_LOB_EDGE'

    def _read_all(self, field_version=None):
        kwargs = dict(_FV_KW)
        if field_version is not None:
            kwargs['field_version'] = field_version
        conn = seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            **kwargs,
        )
        try:
            cur = conn.cursor()
            cur.execute(f'SELECT id, b, c FROM {self.TABLE} ORDER BY id')
            return [
                (i, *(v.read() if hasattr(v, 'read') else v for v in (b, c)))
                for i, b, c in cur.fetchall()
            ]
        finally:
            conn.close()

    def test_lob_reads_around_the_length_markers_come_back_whole(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, b BLOB, c CLOB)')
        rows = [
            (n, b'x' * n, 'y' * min(n, _LOB_EDGE_CLOB_LENGTHS[-1]))
            for n in _LOB_EDGE_BLOB_LENGTHS
        ] + [(1000 + n, b'w', 'z' * n) for n in _LOB_EDGE_CLOB_LENGTHS]
        for row in rows:
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3)', list(row))
        for fv in (None, FIELD_VERSION_11_2):
            with self.subTest(field_version=fv or 'default'):
                self.assertEqual(self._read_all(fv), rows)


@_requires(_LOBOPS)
@unittest.skipUnless(_USER, _SKIP_REASON)
class LOBObjectIntegration(_IntegrationBase):
    """The LOB OBJECT a fetch returns by default (#964).

    `fetch_lobs` defaults True, matching python-oracledb, so a CLOB / BLOB
    column comes back as a LOB rather than str / bytes. Everything here was
    reverse-engineered against a live 23ai and then checked on every tier:
    GET_LENGTH / GET_CHUNK_SIZE / TRIM answer a ub4 after the updated locator,
    OPEN takes a mode in its amount field, and each reply carries the locator
    AS THE SERVER NOW SEES IT -- keeping the original made a write look like it
    had silently done nothing.
    """

    TABLE = 'PYORACLE_LOBOBJ'

    def _fetch_lob(self):
        # A LOB is only mutable while its ROW is locked, so the insert is left
        # uncommitted and the select takes FOR UPDATE -- otherwise Oracle
        # answers ORA-22920 rather than writing.
        self.cur.execute(f'SELECT c FROM {self.TABLE} FOR UPDATE')
        (lob,) = self.cur.fetchone()
        return lob

    def setUp(self):
        super().setUp()
        self.conn.autocommit = False
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, c CLOB)')
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 'hello world')")

    def tearDown(self):
        # The row is deliberately left LOCKED for the duration of each test (a
        # LOB is only mutable that way), so the transaction has to be released
        # here -- otherwise the lock outlives the test and the base tearDown's
        # DROP hits ORA-00054 "resource busy", which is how this first showed up
        # on 10g while 11g happened to get away with it.
        try:
            self.conn.rollback()
        except Exception:  # noqa: BLE001, S110
            pass
        super().tearDown()

    def test_a_lob_call_in_a_select_list_is_a_lob(self):
        # TO_CLOB / EMPTY_CLOB / EMPTY_BLOB in a select list describe as a CLOB or
        # a BLOB and fetch as a LOB, as a LOB column does (#1351).
        self.cur.execute(
            "SELECT TO_CLOB('some value') c, EMPTY_CLOB(), EMPTY_BLOB() FROM dual"
        )
        self.assertEqual(
            [d[1] for d in self.cur.description],
            [seerdb.DB_TYPE_CLOB, seerdb.DB_TYPE_CLOB, seerdb.DB_TYPE_BLOB],
        )
        clob, empty_clob, empty_blob = self.cur.fetchone()
        self.assertEqual(clob.read(), 'some value')
        self.assertEqual(empty_clob.read(), '')
        self.assertEqual(empty_blob.read(), b'')

    def test_a_fetched_clob_is_a_lob_object(self):
        lob = self._fetch_lob()
        self.assertTrue(hasattr(lob, 'read'), f'expected a LOB, got {type(lob)}')
        self.assertEqual(lob.read(), 'hello world')

    @_requires(_mirror_lacks('GET_LENGTH / GET_CHUNK_SIZE on a column locator'))
    def test_size_and_chunk_size_come_from_the_server(self):
        # Against a Mirror both of these answer 0: it recovers a column
        # locator from a GET_LENGTH only in the ub2-PREFIXED form, while a real
        # server wants the BARE one for that op (and answers the prefixed form
        # with an error), so the Mirror never finds the locator the client
        # actually sent. GET_CHUNK_SIZE it acks without a value at all. Both are
        # Mirror-side follow-ups to #964.
        lob = self._fetch_lob()
        self.assertEqual(lob.size(), 11)
        self.assertGreater(lob.getchunksize(), 0)

    def test_read_takes_a_one_based_offset_and_an_amount(self):
        lob = self._fetch_lob()
        self.assertEqual(lob.read(7, 5), 'world')
        self.assertEqual(lob.read(1, 5), 'hello')
        self.assertEqual(lob.read(7), 'world')

    def test_a_bad_read_range_is_refused_before_the_wire(self):
        lob = self._fetch_lob()
        with self.assertRaises(Exception):
            lob.read(0)
        with self.assertRaises(Exception):
            lob.read(1, 0)

    @_requires(_LOB_MODIFY, _mirror_lacks('serving LOB writes on a column locator'))
    def test_write_applies_and_the_size_follows(self):
        lob = self._fetch_lob()
        lob.write('WORLD', 7)
        self.assertEqual(lob.read(), 'hello WORLD')
        self.assertEqual(lob.size(), 11)

    @_requires(_LOB_MODIFY, _mirror_lacks('serving LOB writes on a column locator'))
    def test_non_ascii_text_reads_and_writes_as_itself(self):
        # The text is the session's, whatever the database charset: on a 9i
        # WE8ISO8859P1 database 'é' read back as 'Ã©', and writing it failed with
        # ORA-22993 (#2383).
        self.cur.execute(f'UPDATE {self.TABLE} SET c = :1', ['café x'])
        lob = self._fetch_lob()
        self.assertEqual(lob.read(), 'café x')
        lob.write('éa', 6)
        self.assertEqual(lob.read(), 'café éa')
        self.assertEqual(lob.size(), 7)
        self.cur.execute(
            f'SELECT COUNT(*) FROM {self.TABLE} WHERE c LIKE :1', ['café éa']
        )
        self.assertEqual(self.cur.fetchone(), (1,))

    @_requires(_LOB_MODIFY, _mirror_lacks('serving LOB writes on a column locator'))
    def test_write_past_the_end_extends_the_lob(self):
        lob = self._fetch_lob()
        lob.write('!', 12)
        self.assertEqual(lob.read(), 'hello world!')
        self.assertEqual(lob.size(), 12)

    @_requires(_LOB_MODIFY, _mirror_lacks('serving LOB writes on a column locator'))
    def test_trim_shortens_it(self):
        lob = self._fetch_lob()
        lob.trim(5)
        self.assertEqual(lob.read(), 'hello')
        self.assertEqual(lob.size(), 5)

    def test_open_close_round_trip(self):
        lob = self._fetch_lob()
        self.assertFalse(lob.isopen())
        lob.open()
        self.assertTrue(lob.isopen())
        lob.close()
        self.assertFalse(lob.isopen())

    @_requires(_LOB_MODIFY, _mirror_lacks('serving LOB writes on a column locator'))
    def test_writing_the_wrong_python_type_is_a_type_error(self):
        lob = self._fetch_lob()
        self.assertRaises(TypeError, lob.write, 1000, 1)
        self.assertRaises(TypeError, lob.write, b'bytes-into-a-clob', 1)

    def test_fetch_lobs_false_restores_the_plain_value(self):
        self.conn.commit()
        with _connect(fetch_lobs=False) as Conn:
            Cur = Conn.cursor()
            Cur.execute(f'SELECT c FROM {self.TABLE}')
            (value,) = Cur.fetchone()
        self.assertEqual(value, 'hello world')
        self.assertIsInstance(value, str)


@_requires(_LOB_VAR_BIND)
@unittest.skipUnless(_USER, _SKIP_REASON)
class LOBOutBindIntegration(_IntegrationBase):
    """A LOB-class Var bound OUT / IN OUT to a PL/SQL block (#978).

    The value the server sends back is the LOB framing a fetched LOB column
    uses -- a block length, the locator's size and chunk size, then the locator
    -- not the DALC every other scalar OUT bind carries. Reading it as a DALC
    left most of the block in the stream, where its next byte decoded as a
    bogus response token, so EVERY LOB OUT bind failed.

    12.1+ only: below that the CLOB / BLOB bind itself has no encoding (#902),
    which is a separate gap -- the block never gets as far as a reply.
    """

    def test_out_clob_var(self):
        # Pure OUT: the block creates the LOB, the bind brings back its locator.
        Var = self.cur.var(seerdb.DB_TYPE_CLOB)
        self.cur.execute("BEGIN :d := TO_CLOB(LPAD('x', 200, 'x')); END;", [Var])
        self.assertEqual(Var.getvalue().read(), 'x' * 200)

    def test_out_clob_var_left_null(self):
        # A block that assigns NULL sends a one-byte block, not a locator.
        Var = self.cur.var(seerdb.DB_TYPE_CLOB)
        self.cur.execute('BEGIN :d := NULL; END;', [Var])
        self.assertIsNone(Var.getvalue())

    def test_inout_clob_var_small(self):
        # PL/SQL-bound: DBMS_LOB.WRITEAPPEND is a PL/SQL procedure with an IN OUT LOB (#1127).
        # Under the 32767-byte promotion threshold, so the bind stays a Var.
        Var = self.cur.var(seerdb.DB_TYPE_CLOB)
        Var.setvalue(0, 'small')
        self.cur.execute("BEGIN DBMS_LOB.WRITEAPPEND(:d, 3, 'END'); END;", [Var])
        self.assertEqual(Var.getvalue().read(), 'smallEND')

    def test_inout_clob_var_over_the_promotion_threshold(self):
        # PL/SQL-bound: the IN OUT LOB is filled by a multi-statement DECLARE block (#1127).
        # Over it, so the Var is promoted to a temp-LOB marker on the way out
        # (#902). The marker has to carry the Var, or the returned value has
        # neither a type to decode against nor anywhere to land.
        Var = self.cur.var(seerdb.DB_TYPE_CLOB)
        Var.setvalue(0, 'A' * 50000)
        self.cur.execute(
            """
            DECLARE t_Clob CLOB;
            BEGIN
                t_Clob := :d;
                DBMS_LOB.COPY(:d, t_Clob, 50000);
                DBMS_LOB.WRITEAPPEND(:d, 5, 'BBBBB');
            END;""",
            [Var],
        )
        Value = Var.getvalue().read()
        self.assertEqual(len(Value), 50005)
        self.assertEqual(Value, 'A' * 50000 + 'B' * 5)

    def test_inout_blob_var_over_the_promotion_threshold(self):
        # PL/SQL-bound: the IN OUT LOB is filled by a multi-statement DECLARE block (#1127).
        Var = self.cur.var(seerdb.DB_TYPE_BLOB)
        Var.setvalue(0, b'L' * 52345)
        self.cur.execute(
            """
            DECLARE t_Blob BLOB;
            BEGIN
                t_Blob := :d;
                DBMS_LOB.COPY(:d, t_Blob, 52345);
                DBMS_LOB.WRITEAPPEND(:d, 6, '515151515151');
            END;""",
            [Var],
        )
        self.assertEqual(Var.getvalue().read(), b'L' * 52345 + b'Q' * 6)

    @_requires(_LOB_VAR_BIND)
    def test_fetch_lobs_false_materialises_an_out_bind(self):
        # `fetch_lobs=False` applies to an OUT bind's LOB the same way it does
        # to a fetched cell.
        with _connect(fetch_lobs=False) as Conn:
            Cur = Conn.cursor()
            Var = Cur.var(seerdb.DB_TYPE_CLOB)
            Cur.execute("BEGIN :d := TO_CLOB('materialised'); END;", [Var])
            self.assertEqual(Var.getvalue(), 'materialised')


@unittest.skipUnless(_USER, _SKIP_REASON)
class BooleanIntegration(_IntegrationBase):
    # Native SQL BOOLEAN columns, 23ai+ (#54, TNS type 252). Skipped on servers
    # without the type (21c/11g reject the column with ORA-00902).
    def _setup_bool(self):
        from seerdb.common.exceptions import DatabaseError

        # As for JSON: a 23ai server carries BOOLEAN natively only to a
        # session that negotiated 23.1+ (#1149).
        _skip_unless(self, _BOOLEAN)
        try:
            self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, flag BOOLEAN)')
        except DatabaseError as exc:
            if exc.code == 902:  # ORA-00902: invalid datatype (pre-23ai)
                self.skipTest('native BOOLEAN type needs a 23ai+ server')
            raise

    def test_boolean_decode(self):
        self._setup_bool()
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, TRUE)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (2, FALSE)')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (3, NULL)')
        self.conn.commit()
        self.cur.execute(f'SELECT id, flag FROM {self.TABLE} ORDER BY id')
        rows = self.cur.fetchall()
        self.assertEqual(rows, [(1, True), (2, False), (3, None)])
        self.assertIsInstance(rows[0][1], bool)

    def test_boolean_bind(self):
        # Bind a Python bool into a BOOLEAN column and read it back (#54).
        self._setup_bool()
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, :b)', [True])
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (2, :b)', [False])
        self.conn.commit()
        self.cur.execute(f'SELECT id, flag FROM {self.TABLE} ORDER BY id')
        self.assertEqual(self.cur.fetchall(), [(1, True), (2, False)])

    def test_boolean_bind_declared_number(self):
        # A bool whose bind was declared NUMBER, as SQLAlchemy's Oracle dialect
        # declares every Boolean, stores False as FALSE (#1201).
        self._setup_bool()
        for i, value in ((1, True), (2, False)):
            self.cur.setinputsizes(None, seerdb.DB_TYPE_NUMBER)
            self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [i, value])
        self.cur.execute(f'SELECT id, flag FROM {self.TABLE} ORDER BY id')
        self.assertEqual(self.cur.fetchall(), [(1, True), (2, False)])


@_requires(_ARRAY_DML)
@unittest.skipUnless(_USER, _SKIP_REASON)
class DataFrameExecuteManyIntegration(_IntegrationBase):
    """executemany from a DataFrame (#2461): any object with the Arrow PyCapsule
    stream interface binds column i to placeholder i+1, typed by its Arrow type,
    one array execute per record batch, as python-oracledb 3.3+ does it."""

    def _table(self, columns: str) -> None:
        self._drop_silently(self.cur)
        self.cur.execute(f'CREATE TABLE {self.TABLE} ({columns})')

    def _frame(self):
        import datetime
        import decimal

        import pyarrow as pa

        return pa.table(
            {
                'i': pa.array([1, None, 3], pa.int64()),
                'd': pa.array(
                    [decimal.Decimal('1.25'), None, decimal.Decimal('-3.50')],
                    pa.decimal128(10, 2),
                ),
                's': pa.array(['a', None, ''], pa.string()),
                'b': pa.array([b'\x01', None, b'\x03\x04'], pa.binary()),
                't': pa.array(
                    [datetime.datetime(2026, 11, 12, 1, 2, 3, 456789), None, None],
                    pa.timestamp('us'),
                ),
                'dt': pa.array([datetime.date(2026, 11, 12), None, None], pa.date32()),
            }
        )

    _COLUMNS = (
        'i NUMBER, d NUMBER(10, 2), s VARCHAR2(20), b RAW(10), t TIMESTAMP, dt DATE'
    )

    def test_a_table_loads_by_position_with_nulls(self):
        # The null row is NULL in every column, and an empty string NULL too,
        # as Oracle stores one; a date32 is a DATE.
        import datetime
        import decimal

        self._table(self._COLUMNS)
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3, :4, :5, :6)', self._frame()
        )
        self.assertEqual(self.cur.rowcount, 3)
        self.cur.execute(
            f'SELECT i, d, s, b, t, dt FROM {self.TABLE} ORDER BY i NULLS LAST'
        )
        self.assertEqual(
            [tuple(r) for r in self.cur.fetchall()],
            [
                (
                    1,
                    decimal.Decimal('1.25'),
                    'a',
                    b'\x01',
                    datetime.datetime(2026, 11, 12, 1, 2, 3, 456789),
                    datetime.datetime(2026, 11, 12),
                ),
                (3, decimal.Decimal('-3.5'), None, b'\x03\x04', None, None),
                (None, None, None, None, None, None),
            ],
        )

    def test_floats_bind_as_binary_float_and_double(self):
        # float32 binds BINARY_FLOAT and float64 BINARY_DOUBLE, typed by the
        # Arrow schema: into a NUMBER column the server converts, and DUMP of
        # the bind itself names its type.
        import pyarrow as pa

        frame = pa.table(
            {'f': pa.array([1.5], pa.float32()), 'g': pa.array([2.25], pa.float64())}
        )
        self._table('f VARCHAR2(40), g VARCHAR2(40)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (DUMP(:1), DUMP(:2))', frame
        )
        self.cur.execute(f'SELECT f, g FROM {self.TABLE}')
        (f, g) = self.cur.fetchone()
        self.assertTrue(f.startswith('Typ=100 '), f)
        self.assertTrue(g.startswith('Typ=101 '), g)

    def _three_batches(self, values):
        import pyarrow as pa

        frame = pa.Table.from_batches(
            pa.table({'i': pa.array(values, pa.int64())}).to_batches(max_chunksize=2)
        )
        self.assertEqual(frame.column(0).num_chunks, 3)
        return frame

    def test_batches_add_up(self):
        # Each record batch is one array execute, and rowcount covers them
        # all; python-oracledb reports the last batch's rowcount alone.
        self._table('i NUMBER')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1)',
            self._three_batches([1, 2, 3, 4, 5]),
        )
        self.assertEqual(self.cur.rowcount, 5)
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (5,))

    def test_a_batch_errors_offset_counts_from_the_first_row(self):
        self._table('i NUMBER PRIMARY KEY')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1)',
            self._three_batches([1, 2, 3, 1, 5]),
            batcherrors=True,
        )
        self.assertEqual(self.cur.rowcount, 4)
        self.assertEqual(
            [(e.offset, e.code) for e in self.cur.getbatcherrors()], [(3, 1)]
        )

    def test_large_strings_and_binaries_bind_as_long_and_long_raw(self):
        import pyarrow as pa

        text = 'x' * 40000
        self._table('i NUMBER, l LONG')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2)',
            pa.table({'i': pa.array([1]), 'l': pa.array([text], pa.large_string())}),
        )
        self.cur.execute(f'SELECT l FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (text,))
        data = bytes(range(256)) * 160
        self._table('i NUMBER, r LONG RAW')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2)',
            pa.table({'i': pa.array([1]), 'r': pa.array([data], pa.large_binary())}),
        )
        self.cur.execute(f'SELECT r FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (data,))

    def test_an_interval_binds_as_interval_day_to_second(self):
        # Arrow's month-day-nano interval, its months ignored as
        # python-oracledb ignores them; the nanoseconds to the microsecond.
        import datetime

        import pyarrow as pa

        self._table('iv INTERVAL DAY(3) TO SECOND(6)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1)',
            pa.table(
                {
                    'iv': pa.array(
                        [pa.MonthDayNano([0, 2, 3_723_000_001_000]), None],
                        pa.month_day_nano_interval(),
                    )
                }
            ),
        )
        self.cur.execute(f'SELECT iv FROM {self.TABLE} ORDER BY iv NULLS LAST')
        self.assertEqual(
            [r[0] for r in self.cur.fetchall()],
            [datetime.timedelta(days=2, seconds=3723, microseconds=1), None],
        )

    @_requires(_BOOLEAN)
    def test_a_bool_column_binds_as_boolean(self):
        import pyarrow as pa

        self._table('i NUMBER, ok BOOLEAN')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2)',
            pa.table({'i': [1, 2, 3], 'ok': pa.array([True, False, None])}),
        )
        self.cur.execute(f'SELECT ok FROM {self.TABLE} ORDER BY i')
        self.assertEqual([r[0] for r in self.cur.fetchall()], [True, False, None])

    @_requires(_VECTOR_BIND)
    def test_lists_and_structs_bind_as_vectors(self):
        # A list column is a dense VECTOR of its element type, a struct of
        # num_dimensions / indices / values a sparse one (23ai).
        import array

        import pyarrow as pa

        try:
            self._table('i NUMBER, v VECTOR(3, FLOAT64), sv VECTOR(5, FLOAT32, SPARSE)')
        except seerdb.DatabaseError as exc:
            self.skipTest(f'no VECTOR here: {exc}')
        sparse = pa.struct(
            [
                ('num_dimensions', pa.int64()),
                ('indices', pa.list_(pa.uint32())),
                ('values', pa.list_(pa.float32())),
            ]
        )
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3)',
            pa.table(
                {
                    'i': [1],
                    'v': pa.array([[1.5, 2.5, 3.5]], pa.list_(pa.float64())),
                    'sv': pa.array(
                        [
                            {
                                'num_dimensions': 5,
                                'indices': [1, 3],
                                'values': [2.0, 4.0],
                            }
                        ],
                        sparse,
                    ),
                }
            ),
        )
        self.cur.execute(f'SELECT v, sv FROM {self.TABLE}')
        (v, sv) = self.cur.fetchone()
        self.assertEqual(v, array.array('d', [1.5, 2.5, 3.5]))
        self.assertEqual(
            (sv.num_dimensions, list(sv.indices), list(sv.values)),
            (5, [1, 3], [2.0, 4.0]),
        )

    def test_a_null_column_and_a_named_bind(self):
        # A column of Arrow's null type binds as VARCHAR2 NULLs; columns go by
        # position whatever the placeholders are named.
        import pyarrow as pa

        self._table('i NUMBER, s VARCHAR2(10)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:id, :name)',
            pa.table({'i': pa.array([7, 8]), 's': pa.array([None, None], pa.null())}),
        )
        self.cur.execute(f'SELECT i, s FROM {self.TABLE} ORDER BY i')
        self.assertEqual(
            [tuple(r) for r in self.cur.fetchall()], [(7, None), (8, None)]
        )

    def test_an_unsupported_type_is_refused_before_anything_is_sent(self):
        import datetime

        import pyarrow as pa

        self._table('i NUMBER')
        frame = pa.table(
            {
                'i': pa.array([1], pa.int64()),
                't': pa.array([datetime.time(1, 2)], pa.time64('us')),
            }
        )
        with self.assertRaises(seerdb.NotSupportedError):
            self.cur.executemany(f'INSERT INTO {self.TABLE} VALUES (:1, :2)', frame)
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (0,))

    def test_an_empty_frame_runs_nothing(self):
        import pyarrow as pa

        self._table('i NUMBER')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1)',
            pa.table({'i': pa.array([], pa.int64())}),
        )
        self.assertEqual(self.cur.rowcount, 0)

    def test_the_async_cursor_loads_a_frame(self):
        import asyncio

        self._table(self._COLUMNS)
        frame = self._frame()

        async def load():
            async with await seerdb.connect_async(
                host=_HOST,
                port=_PORT,
                user=_USER,
                password=_PASSWORD,
                service_name=_SERVICE,
                **_FV_KW,
            ) as conn:
                cur = conn.cursor()
                await cur.executemany(
                    f'INSERT INTO {self.TABLE} VALUES (:1, :2, :3, :4, :5, :6)', frame
                )
                count = cur.rowcount
                await conn.commit()
                return count

        self.assertEqual(asyncio.run(load()), 3)
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (3,))

    def tearDown(self):
        self._drop_silently(self.cur)
        super().tearDown()


@unittest.skipUnless(_USER, _SKIP_REASON)
class VectorIntegration(_IntegrationBase):
    # Native VECTOR columns, 23ai+ (#55, TNS type 127). The server delivers the
    # vector as a LOB locator; seerdb reads the binary image over TTI_LOBOPS
    # and decodes it to a list. Skipped on servers without the type.
    def _setup_vec(self, coltype):
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute(f'CREATE TABLE {self.TABLE} (v {coltype})')
        except DatabaseError as exc:
            # Pre-23ai: 21c rejects VECTOR with ORA-00902 (invalid datatype);
            # 11g's parser doesn't know the `VECTOR(n, type)` syntax at all and
            # raises ORA-00907 (missing right parenthesis). Skip on either.
            if exc.code in (902, 907):
                self.skipTest('native VECTOR type needs a 23ai+ server')
            raise

    def _roundtrip(self, coltype, literal):
        self._setup_vec(coltype)
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('{literal}')")
        self.conn.commit()
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        return self.cur.fetchone()[0]

    def _skip_below_12_1(self):
        # A session below 12.1 cannot bind a VECTOR, and the client refuses it
        # (#1762); test_a_vector_bind_below_12_1_is_refused checks that.
        _skip_unless(self, _VECTOR_BIND)

    def _bind_roundtrip(self, coltype, value):
        # Bind a Python sequence (#55) and read it back.
        self._skip_below_12_1()
        self._setup_vec(coltype)
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (:v)', [value])
        self.conn.commit()
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        return self.cur.fetchone()[0]

    def test_a_flexible_column_reports_no_dimension_count(self):
        # `VECTOR(*, *)` allows any dimensions and any format. The describe says
        # so with a FLAG; the dimension count beside it is 0 and means nothing,
        # so reporting it would claim the column holds zero-element vectors
        # (#1012). python-oracledb reports None for both.
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute(
                f'CREATE TABLE {self.TABLE} ('
                f'  flex_all VECTOR(*, *),'
                f'  flex_dim VECTOR(*, float32),'
                f'  fixed    VECTOR(16, float32))'
            )
        except DatabaseError as exc:
            # Same two codes _setup_vec skips on: 21c rejects the type
            # (ORA-00902) and 11g's parser cannot read the syntax at all
            # (ORA-00907). This test needs three columns rather than the one
            # _setup_vec makes, so it repeats the guard instead.
            if exc.code in (902, 907):
                self.skipTest('native VECTOR type needs a 23ai+ server')
            raise
        self.cur.execute(f'SELECT flex_all, flex_dim, fixed FROM {self.TABLE}')
        FlexAll, FlexDim, Fixed = self.cur.description
        # The per-column vector descriptor is a 23.4+ addition and not every
        # 23ai release populates it; a server that omits it reports None for
        # every column, flexible or not, and seerdb surfaces what it is sent.
        # The FIXED column is the probe: where the descriptor is populated it
        # has a format, so its absence means there is nothing to assert about
        # any of them. Same guard as
        # test_description_reports_vector_format_and_dimensions.
        if not Fixed.vector_format:
            self.skipTest('server does not populate the vector describe format')
        self.assertEqual(Fixed.vector_dimensions, 16)
        self.assertEqual(Fixed.vector_format, 2)  # float32
        # A flexible dimension is None -- NOT the 0 that rides beside the flag.
        self.assertIsNone(FlexDim.vector_dimensions)
        self.assertEqual(FlexDim.vector_format, 2)
        # And a column flexible in both reports neither.
        self.assertIsNone(FlexAll.vector_dimensions)
        self.assertIsNone(FlexAll.vector_format)

    @_requires(_PRE12_VECTOR_REFUSAL)
    def test_a_vector_bind_below_12_1_is_refused(self):
        # A 23ai answers a VECTOR bind from an 11.2 session with a fatal
        # ORA-03106 (#1762). The client refuses it before sending, in every
        # form a VECTOR binds in, so this runs on any server below 12.1 -- and
        # the session stays usable.
        import array

        Declared = self.cur.var(seerdb.DB_TYPE_VECTOR)
        for Bind in (
            [[1.0, 2.0]],
            [array.array('f', [1.0, 2.0])],
            {'v': [1.0, 2.0]},
            [Declared],
        ):
            with self.assertRaises(seerdb.NotSupportedError):
                self.cur.execute('SELECT :v FROM DUAL', Bind)
        self.cur.execute('SELECT 1 FROM DUAL')
        self.assertEqual(self.cur.fetchall(), [(1,)])

    def test_a_vector_through_a_plsql_in_out_bind(self):
        # A VECTOR OUT / IN OUT bind carries its IMAGE, not a locator (#1010).
        # Served as a locator the client ran off the end of it -- and the size
        # was irrelevant, which is what made this look like the 64 KiB ceiling
        # of #1008 when it is a different bug entirely.
        import array

        self._skip_below_12_1()
        self._setup_vec('VECTOR(4, float32)')  # the table is incidental here
        In = array.array('f', [1.0, 1.5, 2.0, 2.5])
        InOut = self.cur.var(seerdb.DB_TYPE_VECTOR)
        InOut.setvalue(0, array.array('f', [4.0, 4.5, 5.0, 5.5]))
        Out = self.cur.var(seerdb.DB_TYPE_VECTOR)
        # Binds are positional by first appearance, so the list reads :o, :b, :a
        # -- not the order the names appear in the assignment.
        self.cur.execute('BEGIN :o := :b; :b := :a; END;', [Out, InOut, In])
        self.assertEqual(list(Out.getvalue()), [4.0, 4.5, 5.0, 5.5])
        self.assertEqual(list(InOut.getvalue()), [1.0, 1.5, 2.0, 2.5])

    def test_a_vector_larger_than_64_kib(self):
        # The image length is a three-byte field; written as a ub2 it raised
        # OverflowError for anything past 64 KiB, so a float64 vector of more
        # than ~8,000 dimensions never reached the wire (#1008). 30,000
        # dimensions is 240 KB -- comfortably over the old ceiling and well
        # under the 65,533 maximum, so this tests the fix and not the limit.
        import array

        Dims = 30000
        Value = array.array('d', [2.5] * Dims)
        Got = self._bind_roundtrip(f'VECTOR({Dims}, float64)', Value)
        self.assertEqual(len(Got), Dims)
        self.assertEqual(Got[0], 2.5)
        self.assertEqual(Got[-1], 2.5)

    def test_the_largest_vector_the_server_accepts(self):
        # 65,533 float64 dimensions is the documented maximum: a ~512 KB image,
        # which is what python-oracledb's own suite binds.
        import array

        Dims = 65533
        Value = array.array('d', [1.25] * Dims)
        Got = self._bind_roundtrip(f'VECTOR({Dims}, float64)', Value)
        self.assertEqual(len(Got), Dims)
        self.assertEqual(Got[0], 1.25)

    def test_float32(self):
        got = self._roundtrip('VECTOR(3, FLOAT32)', '[1.5, 2.5, 3.5]')
        self.assertEqual(got, array.array('f', [1.5, 2.5, 3.5]))

    def test_float32_signed(self):
        got = self._roundtrip('VECTOR(4, FLOAT32)', '[-1, 0, 2.25, -8]')
        self.assertEqual(got, array.array('f', [-1.0, 0.0, 2.25, -8.0]))

    def test_float64(self):
        got = self._roundtrip('VECTOR(3, FLOAT64)', '[1.5, 2.5, 3.5]')
        self.assertEqual(got, array.array('d', [1.5, 2.5, 3.5]))

    def test_int8(self):
        got = self._roundtrip('VECTOR(4, INT8)', '[1, -2, 3, -4]')
        self.assertEqual(got, array.array('b', [1, -2, 3, -4]))
        self.assertTrue(all(isinstance(v, int) for v in got))

    def test_binary(self):
        # BINARY (bit) vectors (#60): the literal gives one packed byte per 8
        # dimensions; seerdb surfaces those packed bytes verbatim.
        got = self._roundtrip('VECTOR(16, BINARY)', '[170, 1]')
        self.assertEqual(got, array.array('B', [170, 1]))
        self.assertTrue(all(isinstance(v, int) for v in got))

    # Binds (#62): seerdb sends the native binary VECTOR image; covers plain
    # lists and typed array.array values.
    def test_bind_float32_list(self):
        self.assertEqual(
            self._bind_roundtrip('VECTOR(4, FLOAT32)', [-1, 0, 2.25, -8]),
            array.array('f', [-1.0, 0.0, 2.25, -8.0]),
        )

    def test_bind_float32_array(self):
        import array

        self.assertEqual(
            self._bind_roundtrip(
                'VECTOR(3, FLOAT32)', array.array('f', [1.5, 2.5, 3.5])
            ),
            array.array('f', [1.5, 2.5, 3.5]),
        )

    def test_bind_float64_array(self):
        import array

        self.assertEqual(
            self._bind_roundtrip(
                'VECTOR(3, FLOAT64)', array.array('d', [0.1, 2.5, 3.5])
            ),
            array.array('d', [0.1, 2.5, 3.5]),
        )

    def test_bind_int8(self):
        import array

        self.assertEqual(
            self._bind_roundtrip('VECTOR(4, INT8)', array.array('b', [1, -2, 3, -4])),
            array.array('b', [1, -2, 3, -4]),
        )

    def test_bind_binary(self):
        import array

        self.assertEqual(
            self._bind_roundtrip('VECTOR(16, BINARY)', array.array('B', [170, 1])),
            array.array('B', [170, 1]),
        )

    def test_sparse_roundtrip(self):
        # SPARSE vectors (#68): bind a SparseVector and read it back.
        from seerdb.common.vector import SparseVector

        sv = SparseVector(8, array.array('I', [2, 5]), array.array('f', [1.5, 2.5]))
        self.assertEqual(self._bind_roundtrip('VECTOR(8, FLOAT32, SPARSE)', sv), sv)

    def test_description_reports_vector_format_and_dimensions(self):
        # The describe carries a VECTOR column's element format + dimension count
        # (#55), exposed on the FetchInfo description entry. The per-column vector
        # descriptor is a 23.4+ addition, and even then not every 23ai release
        # populates it: a server that omits it reports None (pre-23.4, no
        # descriptor) or 0 (descriptor sent but the per-column format left
        # unset) — seerdb faithfully surfaces whatever the server sends. Assert
        # the exact codes only where the server provides them.
        self._setup_vec('VECTOR(4, INT8)')
        self.cur.execute(f'SELECT v FROM {self.TABLE}')
        info = self.cur.description[0]
        # Every VECTOR column's description entry carries the attributes …
        self.assertTrue(hasattr(info, 'vector_format'))
        self.assertTrue(hasattr(info, 'vector_dimensions'))
        # … and stays the ordinary 7-tuple for every PEP-249 consumer.
        self.assertEqual(len(info), 7)
        if not info.vector_format:
            self.skipTest('server does not populate the vector describe format')
        self.assertEqual(info.vector_format, 4)  # 4 = INT8
        self.assertEqual(info.vector_dimensions, 4)


@unittest.skipUnless(_USER, _SKIP_REASON)
class JSONIntegration(_IntegrationBase):
    # Native JSON (OSON) columns, 21c+ (#30). The server delivers the JSON
    # value as a LOB locator; seerdb reads the OSON image over TTI_LOBOPS and
    # decodes it to a Python value. Skipped on servers without the JSON type.
    def _setup_json(self):
        from seerdb.common.exceptions import DatabaseError

        # The server may have the type and still not hand it to this session
        # natively: 23ai sends a JSON column to a session that negotiated
        # below 20.1 as a plain BLOB, as it would to a real client of that
        # release (#1149).
        _skip_unless(self, _JSON)
        try:
            self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, doc JSON)')
        except DatabaseError as exc:
            if exc.code == 902:  # ORA-00902: invalid datatype (pre-21c)
                self.skipTest('native JSON type needs a 21c+ server')
            raise

    def _roundtrip(self, doc_text):
        # Single-row round trip: insert one JSON doc, read it back decoded.
        # (Multi-row JSON fetches ride the same LOB path as multi-row LOB reads
        # and share the #45 desync limitation, so keep it to one row here.)
        self.cur.execute(f'DELETE FROM {self.TABLE}')
        self.conn.commit()
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, JSON('{doc_text}'))")
        self.conn.commit()
        self.cur.execute(f'SELECT doc FROM {self.TABLE}')
        return self.cur.fetchone()[0]

    def test_object_array_scalars(self):
        self._setup_json()
        got = self._roundtrip('{"hello":"world","n":42,"arr":[1,2,3]}')
        self.assertEqual(got, {'hello': 'world', 'n': 42, 'arr': [1, 2, 3]})

    def test_nested_with_bool_and_null(self):
        self._setup_json()
        got = self._roundtrip('{"a":{"b":[true,false,null],"s":"x"}}')
        self.assertEqual(got, {'a': {'b': [True, False, None], 's': 'x'}})

    def test_top_level_array(self):
        self._setup_json()
        self.assertEqual(
            self._roundtrip('[1,2,3,"four",true]'), [1, 2, 3, 'four', True]
        )

    def test_scalar_string(self):
        self._setup_json()
        self.assertEqual(self._roundtrip('"just a string"'), 'just a string')

    def test_scalar_null(self):
        self._setup_json()
        self.assertIsNone(self._roundtrip('null'))

    def test_wide_object_over_255_keys(self):
        # > 255 distinct keys (#69): the OSON header uses a ub2 num_fnames and
        # the object node ub2 count + ub2 field-ids. A too-small offline fixture
        # can't reach this, so exercise it end-to-end.
        self._setup_json()
        doc = {f'key{i:03d}': i for i in range(300)}
        self.cur.execute(f'DELETE FROM {self.TABLE}')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, :doc)', [doc])
        self.conn.commit()
        self.cur.execute(f'SELECT doc FROM {self.TABLE}')
        got = self.cur.fetchone()[0]
        self.assertEqual(len(got), 300)
        self.assertEqual(got['key000'], 0)
        self.assertEqual(got['key299'], 299)

    # Binds (#50): a bare dict binds as JSON; seerdb.JSON(value) forces JSON on
    # lists / scalars. seerdb serialises to JSON text and the server casts it.
    def _bind_roundtrip(self, value):
        self.cur.execute(f'DELETE FROM {self.TABLE}')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, :doc)', [value])
        self.conn.commit()
        self.cur.execute(f'SELECT doc FROM {self.TABLE}')
        return self.cur.fetchone()[0]

    def test_bind_dict(self):
        self._setup_json()
        self.assertEqual(
            self._bind_roundtrip({'hello': 'world', 'n': 42, 'arr': [1, 2, 3]}),
            {'hello': 'world', 'n': 42, 'arr': [1, 2, 3]},
        )

    def test_bind_nested_dict(self):
        self._setup_json()
        self.assertEqual(
            self._bind_roundtrip({'a': {'b': [True, False, None], 's': 'x'}}),
            {'a': {'b': [True, False, None], 's': 'x'}},
        )

    def test_bind_json_wrapper_list(self):
        self._setup_json()
        self.assertEqual(
            self._bind_roundtrip(seerdb.JSON([1, 2, 3, 'four', True])),
            [1, 2, 3, 'four', True],
        )

    def test_bind_json_wrapper_scalar(self):
        self._setup_json()
        self.assertEqual(
            self._bind_roundtrip(seerdb.JSON('just a string')), 'just a string'
        )

    def test_bind_decimal_stays_exact(self):
        from decimal import Decimal

        self._setup_json()
        got = self._bind_roundtrip({'price': Decimal('19.99')})
        self.assertEqual(got, {'price': Decimal('19.99')})

    def test_large_documents_decode(self):
        # #88: reading a native JSON column whose OSON image uses the large-doc
        # encodings — string values >255 B (ub2 0x37), >64 KiB (ub4 0x38), a
        # tree >64 KiB (ub4 tree_size), and a container with >64 KiB of values /
        # >65535 entries (ub4 offsets / ub4 count). These bind via the text-cast
        # fallback (the compact encoder refuses them) and must round-trip on read.
        self._setup_json()
        cases = [
            {'s': 'x' * 500},  # ub2 string
            {'big': 'y' * 70000},  # ub4 string + ub4 tree
            list(range(30000)),  # ub4 offsets (big tree)
            list(range(70000)),  # ub4 count (>65535 elems)
            {'a': {'b': {'c': 'z' * 1000}}, 'l': ['s' * 400, 't' * 60000]},
        ]
        for n, v in enumerate(cases):
            wrapped = v if isinstance(v, dict) else seerdb.JSON(v)
            got = self._bind_roundtrip(wrapped)
            self.assertEqual(got, v, f'case {n}')


@_requires(_postgres_cannot('run DBMS_SODA, which SODA is built on'), _SODA)
@unittest.skipUnless(_USER, _SKIP_REASON)
class SodaIntegration(_IntegrationBase):
    # SODA collection management (#163 / #199), backed by DBMS_SODA. Needs an
    # Oracle 18c+ server; skipped below that, and over the Mirror's PostgreSQL
    # backend, which has no DBMS_SODA (#1745).
    def setUp(self):
        super().setUp()
        if self.conn.field_version < FIELD_VERSION_12_1:
            # Refused up front below 12.1 (#1763): its document operations bind
            # PL/SQL arrays. The refusal itself is checked here, once per test.
            with self.assertRaises(seerdb.NotSupportedError):
                self.conn.getSodaDatabase()
            self.conn.close()
            self.skipTest('SODA needs a 12.1+ session')
        self.soda = self.conn.getSodaDatabase()
        self._drop_all_collections()

    def _drop_all_collections(self):
        for n in self.soda.getCollectionNames():
            c = self.soda.openCollection(n)
            if c:
                c.drop()

    def tearDown(self):
        try:
            self._drop_all_collections()
        except Exception:
            # best-effort collection cleanup; tearDown still closes the conn
            pass
        super().tearDown()

    def test_create_open_list_drop(self):
        col = self.soda.createCollection('it_a')
        self.assertEqual(col.name, 'it_a')
        self.assertIn('contentColumn', col.metadata)
        self.assertEqual(self.soda.openCollection('it_a').name, 'it_a')
        self.assertIsNone(self.soda.openCollection('no_such_coll'))
        self.soda.createCollection('it_b')
        self.assertEqual(self.soda.getCollectionNames(), ['it_a', 'it_b'])
        self.assertEqual(self.soda.getCollectionNames(limit=1), ['it_a'])
        self.assertEqual(self.soda.getCollectionNames('it_b'), ['it_b'])
        self.assertTrue(col.drop())  # dropped
        self.assertFalse(col.drop())  # already gone

    def test_truncate(self):
        col = self.soda.createCollection('it_trunc')
        # insert one document via DBMS_SODA directly (the document API is a later
        # #163 sub-ticket); truncate must then empty the collection.
        self.cur.execute(
            'DECLARE c SODA_COLLECTION_T; d SODA_DOCUMENT_T; n NUMBER; BEGIN '
            "c := DBMS_SODA.open_collection('it_trunc'); "
            'd := SODA_DOCUMENT_T(b_content => utl_raw.cast_to_raw(\'{"a":1}\')); '
            'n := c.insert_one(d); END;'
        )
        try:
            col.truncate()
        except seerdb.DatabaseError as exc:
            # SODA_COLLECTION_T grew TRUNCATE after 18c: 18c's DBMS_SODA answers
            # PLS-00302 "component 'TRUNCATE' must be declared". Skipping on the
            # server's own answer, not a guessed version, stays right for any
            # release in between.
            if 'PLS-00302' in str(exc) and 'TRUNCATE' in str(exc):
                self.skipTest("this server's DBMS_SODA has no TRUNCATE")
            raise
        v = self.cur.var(seerdb.NUMBER)
        self.cur.execute(
            'DECLARE c SODA_COLLECTION_T; BEGIN '
            "c := DBMS_SODA.open_collection('it_trunc'); "
            ':1 := c.find().count(); END;',
            [v],
        )
        self.assertEqual(v.getvalue(), 0)

    def test_document_insert_and_read(self):
        col = self.soda.createCollection('it_docs')
        # insertOneAndGet returns server-assigned key / version / media type
        saved = col.insertOneAndGet(
            self.soda.createDocument({'name': 'alice', 'age': 30})
        )
        self.assertTrue(saved.key)
        self.assertTrue(saved.version)
        self.assertEqual(saved.mediaType, 'application/json')
        self.assertIsNone(saved.getContentAsBytes())  # no content returned

        # read it back by key -> content parsed as JSON
        got = col.find().key(saved.key).getOne()
        self.assertEqual(got.key, saved.key)
        content = got.getContent()
        self.assertEqual(content['name'], 'alice')
        self.assertEqual(content['age'], 30)
        self.assertIsInstance(got.getContentAsString(), str)

        # insertOne accepts a bare value; a valid-but-absent key reads as None
        col.insertOne({'name': 'bob'})
        self.assertIsNone(col.find().key('AABBCCDDEEFF00112233445566').getOne())

    def test_large_document_round_trip(self):
        col = self.soda.createCollection('it_big')
        # content past the 32767-byte inline window reads back whole, chunked
        # out of the BLOB (#211); insert uses the temp-LOB bind.
        payload = 'x' * 120000
        k1 = col.insertOneAndGet({'tag': 'A', 'blob': payload}).key
        col.insertOneAndGet({'tag': 'B', 'blob': 'y' * 90000})
        self.assertEqual(col.find().key(k1).getOne().getContent()['blob'], payload)
        # a batch with two large documents keeps each one's content distinct
        docs = {
            d.getContent()['tag']: d.getContent()['blob']
            for d in col.find().getDocuments()
        }
        self.assertEqual(docs['A'], payload)
        self.assertEqual(docs['B'], 'y' * 90000)
        # boundary: exactly at and one past the inline window
        for n in (32767, 32768):
            k = col.insertOneAndGet({'p': 'z' * n}).key
            self.assertEqual(col.find().key(k).getOne().getContent()['p'], 'z' * n)

    def test_qbe_find(self):
        col = self.soda.createCollection('it_qbe')
        for age in (20, 25, 30, 35, 40):
            col.insertOne({'age': age})
        self.assertEqual(col.find().count(), 5)
        F = {'age': {'$gte': 30}}
        self.assertEqual(col.find().filter(F).count(), 3)
        ages = sorted(
            d.getContent()['age'] for d in col.find().filter(F).getDocuments()
        )
        self.assertEqual(ages, [30, 35, 40])
        # getOne with a filter; a repeated call must re-evaluate the filter
        # (regression: SODA's get_one() caches a bind filter, so getOne runs the
        # cursor path).
        self.assertEqual(
            col.find().filter({'age': 25}).getOne().getContent()['age'], 25
        )
        self.assertIsNone(col.find().filter({'age': 999}).getOne())
        self.assertEqual(len(col.find().limit(2).getDocuments()), 2)

    def test_getdocuments_overflow_guard(self):
        col = self.soda.createCollection('it_over')
        for i in range(5):
            col.insertOne({'i': i})
        import seerdb.client.soda as _soda

        saved = _soda._DEFAULT_FETCH_CAP
        _soda._DEFAULT_FETCH_CAP = 2  # force overflow without a .limit()
        try:
            with self.assertRaises(seerdb.NotSupportedError):
                col.find().getDocuments()
        finally:
            _soda._DEFAULT_FETCH_CAP = saved

    def test_update_delete_bulk(self):
        col = self.soda.createCollection('it_udb')
        # insertMany (one round trip)
        col.insertMany([{'n': 1}, {'n': 2}, {'n': 3}])
        self.assertEqual(col.find().count(), 3)
        saved = col.insertOneAndGet({'v': 1})

        # replaceOne by key (match + no match)
        self.assertTrue(col.find().key(saved.key).replaceOne({'v': 2}))
        self.assertEqual(col.find().key(saved.key).getOne().getContent()['v'], 2)
        self.assertFalse(
            col.find().key('AABBCCDDEEFF00112233445566').replaceOne({'v': 9})
        )

        # replaceOneAndGet -> new version; None when nothing matches
        got = col.find().key(saved.key).replaceOneAndGet({'v': 3})
        self.assertEqual(got.key, saved.key)
        self.assertTrue(got.version)
        self.assertIsNone(
            col.find().key('AABBCCDDEEFF00112233445566').replaceOneAndGet({})
        )

        # remove by filter -> count removed
        self.assertEqual(col.find().filter({'v': {'$exists': True}}).remove(), 1)
        self.assertEqual(col.find().count(), 3)
        # remove by key
        k = col.find().limit(1).getDocuments()[0].key
        self.assertEqual(col.find().key(k).remove(), 1)
        self.assertEqual(col.find().count(), 2)

    def test_save_upsert(self):
        col = self.soda.createCollection('it_save')
        # save without a key inserts
        col.save({'v': 1})
        self.assertEqual(col.find().count(), 1)
        # saveAndGet returns the stored document
        g = col.saveAndGet(self.soda.createDocument({'v': 2}))
        self.assertTrue(g.key)
        self.assertEqual(col.find().count(), 2)
        # saving a document with an existing key replaces it (count unchanged)
        g2 = col.saveAndGet(self.soda.createDocument({'v': 99}, key=g.key))
        self.assertEqual(g2.key, g.key)
        self.assertEqual(col.find().key(g.key).getOne().getContent()['v'], 99)
        self.assertEqual(col.find().count(), 2)

    def test_streaming_getcursor(self):
        col = self.soda.createCollection('it_cur')
        for i in range(25):
            col.insertOne({'i': i})
        # streams every document exactly once across batches (no dup / skip)
        got = [d.getContent()['i'] for d in col.find().getCursor(batchSize=10)]
        self.assertEqual(sorted(got), list(range(25)))
        self.assertEqual(len(got), len(set(got)))
        # honours filter and limit
        self.assertEqual(
            sorted(
                d.getContent()['i']
                for d in col.find().filter({'i': {'$gte': 20}}).getCursor(batchSize=2)
            ),
            [20, 21, 22, 23, 24],
        )
        self.assertEqual(len(list(col.find().limit(7).getCursor(batchSize=3))), 7)
        self.assertEqual(list(col.find().filter({'i': 999}).getCursor()), [])

    def test_indexing_and_data_guide(self):
        col = self.soda.createCollection('it_idx')
        for age in (20, 30, 40):
            col.insertOne({'name': 'u', 'age': age})
        # no data-guide index yet -> None (not an error)
        self.assertIsNone(col.getDataGuide())
        # functional index, dropped by name (present then absent)
        col.createIndex(
            {'name': 'IT_IDX_AGE', 'fields': [{'path': 'age', 'datatype': 'number'}]}
        )
        self.assertTrue(col.dropIndex('IT_IDX_AGE'))
        self.assertFalse(col.dropIndex('IT_IDX_AGE'))
        # data-guide search index -> getDataGuide returns the structure. The
        # JSON search indextype needs Oracle Text, which 21c XE lacks (ORA-29833),
        # so only assert the data guide where it can be built.
        try:
            col.createIndex(
                {'name': 'IT_SIDX', 'dataguide': 'on', 'search_on': 'text_value'}
            )
        except seerdb.DatabaseError as exc:
            if getattr(exc, 'code', None) == 29833:
                self.skipTest('JSON search index needs Oracle Text (absent on 21c XE)')
            raise
        dg = col.getDataGuide().getContent()
        self.assertEqual(dg['type'], 'object')
        self.assertIn('age', dg['properties'])


@unittest.skipUnless(_USER, _SKIP_REASON)
class SqlDomainIntegration(_IntegrationBase):
    # 23ai SQL-domain columns (#53). At field version 17 a column with a SQL
    # domain carries its schema+name in the per-column describe; before the fix
    # that non-empty layout desynced the row decode. Needs a 23ai server AND the
    # CREATE DOMAIN privilege; skips otherwise (incl. pre-23ai, which lacks the
    # syntax). Run with SEERDB_TEST_FIELD_VERSION=17 to exercise the fv17 path.
    DOMAIN = 'PYO_DOM_T'

    def _setup_domain(self):
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute(f'DROP DOMAIN {self.DOMAIN} FORCE')
        except DatabaseError:
            # No leftover domain from a prior run (or pre-23ai, which has no
            # DROP DOMAIN) — nothing to clean up, proceed to create it.
            pass
        try:
            self.cur.execute(f'CREATE DOMAIN {self.DOMAIN} AS NUMBER(3,0)')
        except DatabaseError as exc:
            # pre-23ai doesn't know the DOMAIN syntax: 11g/21c raise ORA-00901
            # ("invalid CREATE command"), others 900/902/907; 1031 = the user
            # lacks CREATE DOMAIN. Skip on any of these.
            if exc.code in (900, 901, 902, 907, 1031):
                self.skipTest('SQL domains need a 23ai server + CREATE DOMAIN')
            raise

    def test_domain_column_select(self):
        self._setup_domain()
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, d NUMBER DOMAIN {self.DOMAIN})'
        )
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, 42)')
        self.conn.commit()
        # A multi-column SELECT mixing the domain column would desync the row
        # decode before the fix; it should now return cleanly.
        self.cur.execute(f'SELECT id, d FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (1, 42))

    def tearDown(self):
        try:
            self.cur.execute(f'DROP DOMAIN {self.DOMAIN} FORCE')
        except Exception:
            # Best-effort teardown: the domain may never have been created
            # (skipped / pre-23ai test), so any drop error is irrelevant.
            pass
        super().tearDown()


@unittest.skipUnless(_USER, _SKIP_REASON)
class RefusedLoginIntegration(_ThrottleRetry, unittest.IsolatedAsyncioTestCase):
    """A login the server refuses raises its ORA-01017, sync and async, for a
    wrong password and an unknown user alike. On 8i and 9i the refusal was
    read in the 10g+ order and its code missed: a wrong password raised
    ORA-01012 on 9i and an AssertionError on 8i, an unknown user a bare
    "authentication failed" (#2340). One wrong password a run: a successful
    login resets the account's count of failed ones."""

    def _kwargs(self, user, password):
        return dict(
            host=_HOST,
            port=_PORT,
            user=user,
            password=password,
            service_name=_SERVICE,
            **_FV_KW,
        )

    CASES = (
        ('wrong password', _USER, 'not the password 2340'),
        ('unknown user', 'no_such_user_2340', 'x'),
    )

    def test_a_refused_login_raises_ora_01017(self):
        for label, user, password in self.CASES:
            with self.subTest(label):
                with self.assertRaises(seerdb.DatabaseError) as caught:
                    seerdb.connect(**self._kwargs(user, password)).close()
                self.assertEqual(caught.exception.code, 1017, str(caught.exception))
        with seerdb.connect(**self._kwargs(_USER, _PASSWORD)):
            pass  # the account still logs in

    async def test_a_refused_async_login_raises_ora_01017(self):
        for label, user, password in self.CASES:
            with self.subTest(label):
                with self.assertRaises(seerdb.DatabaseError) as caught:
                    conn = await seerdb.connect_async(**self._kwargs(user, password))
                    await conn.close()
                self.assertEqual(caught.exception.code, 1017, str(caught.exception))


@unittest.skipUnless(_USER, _SKIP_REASON)
class EmptyAppNameIntegration(_ThrottleRetry, unittest.TestCase):
    """A login whose app_name is empty: its program pair goes out with an
    empty value. On 8i that value was one zero byte where the server reads a
    zero length, the pair came out three bytes short, and the login failed with
    an IndexError (#2344)."""

    def test_an_empty_app_name_logs_in(self):
        with seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            app_name='',
            **_FV_KW,
        ) as conn:
            cur = conn.cursor()
            cur.execute('SELECT 42 FROM dual')
            self.assertEqual(cur.fetchone(), (42,))


@unittest.skipUnless(_USER, _SKIP_REASON)
class SessionIdentityIntegration(_ThrottleRetry, unittest.TestCase):
    """A session tells the server the client's host, as its machine. 9i's
    login once sent the strings of the JDBC capture it was built from, so a 9i
    server saw every session come from a host called o9i (#2342)."""

    def test_the_server_sees_the_clients_host(self):
        import socket

        # Oracle, and the Mirror over PostgreSQL since #2346, return the client's
        # machine -- the AUTH_MACHINE the login sent, which seerdb fills with the
        # client's hostname.
        conn = _connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT SYS_CONTEXT('USERENV', 'HOST') FROM dual")
            (host,) = cur.fetchone()
            self.assertEqual(host, socket.gethostname())
        finally:
            conn.close()


@unittest.skipUnless(_USER, _SKIP_REASON)
class ChangePasswordIntegration(_ThrottleRetry, unittest.TestCase):
    """Connection.changepassword over the wire (#21). Each test changes the
    test user's password and always restores it (on the original, still-
    authenticated connection) so the rest of the suite is unaffected."""

    def _kwargs(self, password):
        return dict(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=password,
            service_name=_SERVICE,
            autocommit=True,
            **_FV_KW,
        )

    def setUp(self):
        # changepassword is gated on Oracle 9i (its O3LOGON password change
        # differs); skip the live tests there (#168).
        _skip_unless(self, _CHANGE_PASSWORD)

    def test_a_rejected_change_reports_the_servers_code(self):
        # python-oracledb's test_1108: an over-long new password, with the right
        # and then a wrong old one. The server rejects both with ORA-01017 on the
        # protocol route; through the Mirror the change used to go out as ALTER
        # USER ... REPLACE, which the server rejects as ORA-28218 instead (#1089).
        # Both calls fail, so the password never changes.
        # Before 12.1 the long values went out with ub4 chunk lengths, which the
        # server read as ORA-03120 (#1090, #1261).
        with seerdb.connect(**self._kwargs(_PASSWORD)) as conn:
            for old in (_PASSWORD, 'incorrect old password'):
                with self.assertRaises(seerdb.DatabaseError) as caught:
                    conn.changepassword(old, '1' * 1500)
                self.assertIn(caught.exception.code, (1017, 988, 28008))
        with seerdb.connect(**self._kwargs(_PASSWORD)):
            pass  # unchanged

    def test_changepassword_roundtrip(self):
        new = _PASSWORD + '_chg9'
        with seerdb.connect(**self._kwargs(_PASSWORD)) as conn:
            conn.changepassword(_PASSWORD, new)
            try:
                # The session that changed the password stays usable.
                cur = conn.cursor()
                cur.execute('SELECT 1 FROM dual')
                self.assertEqual(cur.fetchone(), (1,))
                # The new password authenticates a fresh connection.
                with seerdb.connect(**self._kwargs(new)) as v:
                    vc = v.cursor()
                    vc.execute('SELECT 1 FROM dual')
                    self.assertEqual(vc.fetchone(), (1,))
                # The old password no longer works.
                with self.assertRaises(seerdb.DatabaseError):
                    seerdb.connect(**self._kwargs(_PASSWORD)).close()
            finally:
                # Restore the original password on the still-authenticated
                # connection before the `with` closes it.
                conn.changepassword(new, _PASSWORD)
        # The original password is restored for the rest of the suite.
        with seerdb.connect(**self._kwargs(_PASSWORD)):
            pass

    def test_changepassword_wrong_old_raises(self):
        # A wrong current password is rejected (ORA-28008) and changes nothing.
        with seerdb.connect(**self._kwargs(_PASSWORD)) as conn:
            with self.assertRaises(seerdb.DatabaseError):
                conn.changepassword('wrong_old_pw_xyz', 'irrelevant9')
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM dual')
            self.assertEqual(cur.fetchone(), (1,))
        with seerdb.connect(**self._kwargs(_PASSWORD)):
            pass


@unittest.skipUnless(_USER, _SKIP_REASON)
class RedirectIntegration(_ThrottleRetry, unittest.TestCase):
    """Follow a TNS_REDIRECT to reconnect to the address the server hands back
    (#23). A RedirectListener stands in for a shared-server / RAC listener: it
    answers the first CONNECT with a redirect to the real backend, and the
    driver must reconnect there and complete the handshake."""

    def test_sync_follows_redirect(self):
        # Connect to the listener's own host (it binds 127.0.0.1, which only
        # equals _HOST on the localhost tiers); it redirects to the real backend.
        with (
            RedirectListener(_HOST, _PORT) as listener,
            seerdb.connect(
                host=listener.listen_host,
                port=listener.listen_port,
                user=_USER,
                password=_PASSWORD,
                service_name=_SERVICE,
                autocommit=True,
                **_FV_KW,
            ) as conn,
        ):
            # The connection moved off the listener to the backend. (8i's own
            # listener then does a second dedicated-server redirect to a dynamic
            # port, so assert it left the listener rather than a fixed port.)
            self.assertNotEqual(conn.port, listener.listen_port)
            cur = conn.cursor()
            cur.execute("SELECT 'redirected' FROM dual")
            self.assertEqual(cur.fetchone(), ('redirected',))


@unittest.skipUnless(_USER, _SKIP_REASON)
class PoolIntegration(_ThrottleRetry, unittest.TestCase):
    """Verify the connection pool: pre-warm, acquire/release, capacity,
    and timeout behaviour."""

    def _kwargs(self, **extra):
        return dict(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            # What the test asks for over the suite's settings (#2466).
            **{**_FV_KW, **extra},
        )

    def test_pre_warms_to_min_and_runs_query(self):
        Pool = seerdb.create_pool(min=2, max=3, **self._kwargs())
        try:
            self.assertEqual(Pool.opened, 2)
            self.assertEqual(Pool.busy, 0)
            with Pool.acquire() as Conn:
                self.assertEqual(Pool.busy, 1)
                Cur = Conn.cursor()
                Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(Cur.fetchone(), (1,))
            self.assertEqual(Pool.busy, 0)
        finally:
            Pool.close()

    def test_acquire_gives_the_connection_itself(self):
        # Used as python-oracledb's pool is, without a `with` block: acquire()
        # returned a guard with no cursor() (#2555). release() and close() both
        # hand it back.
        Pool = seerdb.create_pool(min=1, max=1, **self._kwargs())
        try:
            Conn = Pool.acquire()
            Cur = Conn.cursor()
            Cur.execute('SELECT 1 FROM dual')
            self.assertEqual(Cur.fetchone(), (1,))
            Pool.release(Conn)
            self.assertEqual(Pool.busy, 0)
            Conn = Pool.acquire()
            self.assertEqual(Pool.busy, 1)
            Conn.close()
            self.assertEqual((Pool.busy, Pool.opened), (0, 1))
        finally:
            Pool.close()

    def test_grows_to_max_and_releases_for_reuse(self):
        Pool = seerdb.create_pool(min=1, max=3, **self._kwargs())
        try:
            G1 = Pool.acquire()
            G1.__enter__()
            G2 = Pool.acquire()
            G2.__enter__()
            G3 = Pool.acquire()
            G3.__enter__()
            # All three checked out; pool can't grow further.
            self.assertEqual(Pool.busy, 3)
            self.assertEqual(Pool.opened, 3)
            G1.__exit__(None, None, None)
            self.assertEqual(Pool.busy, 2)
            # New acquire reuses, doesn't grow.
            with Pool.acquire() as _:
                self.assertEqual(Pool.busy, 3)
                self.assertEqual(Pool.opened, 3)
            G2.__exit__(None, None, None)
            G3.__exit__(None, None, None)
        finally:
            Pool.close()

    def test_acquire_times_out_when_full(self):
        Pool = seerdb.create_pool(min=1, max=1, timeout=0.5, **self._kwargs())
        try:
            G = Pool.acquire()
            G.__enter__()
            try:
                with self.assertRaises(seerdb.InterfaceError):
                    Pool.acquire()
            finally:
                G.__exit__(None, None, None)
        finally:
            Pool.close()

    def test_getmode_nowait_raises_when_full(self):
        Pool = seerdb.create_pool(
            min=1, max=1, getmode=seerdb.POOL_GETMODE_NOWAIT, **self._kwargs()
        )
        try:
            with Pool.acquire():
                with self.assertRaises(seerdb.InterfaceError):
                    Pool.acquire()
        finally:
            Pool.close()

    def test_getmode_forceget_opens_past_max(self):
        Pool = seerdb.create_pool(
            min=1, max=1, getmode=seerdb.POOL_GETMODE_FORCEGET, **self._kwargs()
        )
        try:
            with Pool.acquire():
                with Pool.acquire() as Extra:
                    self.assertEqual(Pool.opened, 2)
                    Cur = Extra.cursor()
                    Cur.execute('SELECT 1 FROM dual')
                    self.assertEqual(Cur.fetchone(), (1,))
                self.assertEqual(Pool.opened, 1)
        finally:
            Pool.close()

    def test_max_lifetime_session_replaces_a_connection(self):
        Pool = seerdb.create_pool(
            min=1, max=1, max_lifetime_session=1, **self._kwargs()
        )
        try:
            with Pool.acquire() as First:
                pass
            time.sleep(1.1)
            with Pool.acquire() as Second:
                self.assertIsNot(Second, First)
                Cur = Second.cursor()
                Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(Cur.fetchone(), (1,))
        finally:
            Pool.close()

    def test_session_callback_sets_each_connection_up_once(self):
        # The callback sets the session up the first time a connection is handed
        # out; reused, the connection keeps it and the callback does not run.
        calls = []

        def setup(conn, tag):
            calls.append(tag)
            with conn.cursor() as cur:
                cur.execute("ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD'")

        pool = seerdb.create_pool(
            min=1, max=1, session_callback=setup, **self._kwargs()
        )
        try:
            for _ in range(2):
                with pool.acquire() as conn, conn.cursor() as cur:
                    cur.execute(
                        'SELECT value FROM nls_session_parameters '
                        "WHERE parameter = 'NLS_DATE_FORMAT'"
                    )
                    self.assertEqual(cur.fetchone(), ('YYYY-MM-DD',))
            self.assertEqual(calls, [None])
        finally:
            pool.close()

    def test_a_named_pool_hands_out_by_its_alias(self):
        pool = seerdb.create_pool(min=1, max=1, pool_alias='live', **self._kwargs())
        try:
            self.assertIs(seerdb.get_pool('live'), pool)
            with seerdb.connect(pool_alias='live') as conn:
                cur = conn.cursor()
                cur.execute('SELECT 1 FROM dual')
                self.assertEqual(cur.fetchone(), (1,))
                self.assertEqual(pool.busy, 1)
            self.assertEqual(pool.busy, 0)
        finally:
            pool.close()
        self.assertIsNone(seerdb.get_pool('live'))

    def test_reconfigure_resizes_a_live_pool(self):
        Pool = seerdb.create_pool(min=1, max=3, **self._kwargs())
        try:
            Pool.reconfigure(min=2)
            self.assertEqual(Pool.opened, 2)
            with Pool.acquire() as Conn:
                Cur = Conn.cursor()
                Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(Cur.fetchone(), (1,))
            Pool.reconfigure(min=1, max=1)
            self.assertEqual(Pool.opened, 1)
        finally:
            Pool.close()

    def test_acquire_after_close_raises(self):
        Pool = seerdb.create_pool(min=1, max=2, **self._kwargs())
        Pool.close()
        with self.assertRaises(seerdb.InterfaceError):
            Pool.acquire()

    def test_health_check_replaces_dead_connection(self):
        # idle_timeout=0 forces a health-check on every acquire. Kill
        # the underlying socket between release and acquire and verify
        # the pool transparently swaps in a fresh connection.
        Pool = seerdb.create_pool(min=1, max=2, idle_timeout=0, **self._kwargs())
        try:
            G = Pool.acquire()
            Conn = G.__enter__()
            G.__exit__(None, None, None)
            # Sabotage the underlying socket.
            try:
                Conn.sock.close()
            except Exception:
                # Best-effort: deliberately sabotaging the socket for the
                # test; any close error here is irrelevant.
                pass
            # Next acquire must succeed (with a fresh connection,
            # ping caught the dead one).
            with Pool.acquire() as Conn2:
                Cur = Conn2.cursor()
                Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(Cur.fetchone(), (1,))
        finally:
            Pool.close()


@unittest.skipUnless(_USER, _SKIP_REASON)
class ConnectAttributeIntegration(_IntegrationBase):
    """Connect-time attributes that only reach the server in the login AUTH.

    `driver_name` names the application in v$session_connect_info, and `edition`
    selects the session's edition. Both are LOGIN-time: they ride in the AUTH,
    not in a later ALTER SESSION, which is why a relay has to hold its own
    upstream connect until that message has been read (#826).
    """

    @_requires(_SESSION_CONTEXT)
    def test_driver_name_defaults_to_our_own_banner(self):
        self.cur.execute(
            'select distinct client_driver from v$session_connect_info '
            "where sid = sys_context('userenv', 'sid')"
        )
        (driver,) = self.cur.fetchone()
        self.assertIn('seerdb', driver)

    @_requires(_SESSION_CONTEXT)
    def test_driver_name_can_be_declared(self):
        with _connect_with(driver_name='newdriver') as conn:
            cur = conn.cursor()
            cur.execute(
                'select distinct client_driver from v$session_connect_info '
                "where sid = sys_context('userenv', 'sid')"
            )
            self.assertEqual(cur.fetchone()[0], 'newdriver')

    @_requires(_EDITIONS, _REAL_SERVER_REPORT)
    def test_edition_is_ora_base_unless_asked_for(self):
        # Editions arrived in 11gR2; older tiers have no such context value.
        # Through a Mirror the answer is the BACKEND's: one over PostgreSQL has
        # no notion of editions and returns NULL, which is correct for it. The
        # six-tier matrix covers the real-server behaviour.
        self.cur.execute(
            "select sys_context('USERENV','CURRENT_EDITION_NAME') from dual"
        )
        self.assertEqual(self.cur.fetchone()[0], 'ORA$BASE')


@_requires(_ARRAY_DML)
@unittest.skipUnless(_USER, _SKIP_REASON)
class PartialBatchRowcountIntegration(_IntegrationBase):
    """`cursor.rowcount` after an executemany that failed part-way (#998/#1003).

    The earlier rows really were applied, and the server reports how many in the
    same OER field a success reports its own count. The cursor set that AFTER the
    error check, so on the raising path the attribute kept whatever it had -- the
    -1 a fresh cursor starts with, or a count left over from an earlier
    statement, which is the worse of the two because it looks plausible.
    """

    TABLE = 'PYORACLE_PARTIAL'

    def setUp(self):
        super().setUp()
        self.conn.autocommit = False
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (n NUMBER CONSTRAINT {self.TABLE}_pk PRIMARY KEY)'
        )

    def tearDown(self):
        try:
            self.conn.rollback()
        except Exception:
            pass
        super().tearDown()

    def test_rowcount_reports_the_rows_applied_before_the_failure(self):
        from seerdb.common.exceptions import DatabaseError

        Rows = [(n,) for n in (1, 2, 3, 2, 5)]  # the 4th duplicates the 2nd
        with self.assertRaises(DatabaseError):
            self.cur.executemany(f'INSERT INTO {self.TABLE} (n) VALUES (:1)', Rows)
        # Read it before anything else runs: the next execute replaces it.
        Reported = self.cur.rowcount
        self.cur.execute(f'SELECT n FROM {self.TABLE} ORDER BY n')
        # Oracle undoes only the row that failed: the three before it stay, and
        # the count says so. Comparing the count with whatever landed was not
        # enough -- the Mirror over PostgreSQL undid all three and reported 0,
        # which agreed (#1365).
        self.assertEqual(self.cur.fetchall(), [(1,), (2,), (3,)])
        self.assertEqual(Reported, 3)

    def test_a_statement_that_fails_outright_reports_none_applied(self):
        # The count is what the call MANAGED, so a statement that never applied
        # a row reports 0 -- not a leftover from the executemany before it.
        from seerdb.common.exceptions import DatabaseError

        self.cur.executemany(
            f'INSERT INTO {self.TABLE} (n) VALUES (:1)', [(10,), (11,), (12,)]
        )
        self.assertEqual(self.cur.rowcount, 3)
        with self.assertRaises(DatabaseError):
            self.cur.execute(f'INSERT INTO {self.TABLE} (n) VALUES (10)')
        self.assertEqual(self.cur.rowcount, 0)


@_requires(_OER_WARN_BYTE)
@unittest.skipUnless(_USER, _SKIP_REASON)
class CursorWarningIntegration(_IntegrationBase):
    """`cursor.warning` for a PL/SQL object created with compilation errors.

    Such a CREATE **succeeds** -- the object exists, invalid -- and the only
    thing that says otherwise is bit 0x20 of the OER's warn byte, which the
    decoder used to skip along with its five neighbours. Measured by diffing a
    live 23ai's reply to the same CREATE compiled clean and broken: identical
    but for the sequence fields and that byte, 0x21 against 0x00 (#993).
    """

    def _bad_procedure(self, name: str) -> None:
        # Creating an object that does NOT compile is the precondition of this
        # whole class, and it is an Oracle behaviour: the statement succeeds and
        # the object exists, invalid. Mirror-over-PostgreSQL refused it outright
        # (ORA-00900) until it stood an invalid object in (#1499).
        self.cur.execute(
            f"""CREATE OR REPLACE PROCEDURE {name} AS
                BEGIN
                    NULL
                END;"""  # the missing semicolon is the point
        )

    def tearDown(self):
        from seerdb.common.exceptions import DatabaseError

        for Name in ('PYORACLE_WARN_P', 'PYORACLE_WARN_F'):
            try:
                self.cur.execute(f'DROP PROCEDURE {Name}')
            except DatabaseError:
                pass
        super().tearDown()

    def test_no_warning_before_anything_runs(self):
        # A caller may read it before any execute; it must exist and be None.
        self.assertIsNone(self.conn.cursor().warning)

    def test_a_procedure_with_compilation_errors_warns(self):
        self._bad_procedure('PYORACLE_WARN_P')
        Warn = self.cur.warning
        self.assertIsNotNone(Warn, 'a CREATE that compiled with errors set no warning')
        self.assertEqual(Warn.full_code, 'DPY-7000')
        self.assertTrue(Warn.iswarning)

    def test_the_warning_is_cleared_by_the_next_clean_execute(self):
        # It reports the LAST execute, not "something once went wrong".
        self._bad_procedure('PYORACLE_WARN_P')
        self.assertIsNotNone(self.cur.warning)
        self.cur.execute(
            """CREATE OR REPLACE PROCEDURE PYORACLE_WARN_P AS
               BEGIN
                   NULL;
               END;"""
        )
        self.assertIsNone(self.cur.warning)
        self.cur.execute('DROP PROCEDURE PYORACLE_WARN_P')
        self.assertIsNone(self.cur.warning)

    def test_a_function_and_a_type_with_compilation_errors_warn(self):
        # A function and an object type that do not compile are created too,
        # with the same warning, and can be dropped (#1499).
        for create, drop in (
            (
                'CREATE OR REPLACE FUNCTION PYORACLE_WARN_F RETURN NUMBER AS '
                'BEGIN RETURN NULL END;',
                'DROP FUNCTION PYORACLE_WARN_F',
            ),
            (
                'CREATE OR REPLACE TYPE PYORACLE_WARN_T AS OBJECT (x no_such_type)',
                'DROP TYPE PYORACLE_WARN_T',
            ),
        ):
            self.cur.execute(create)
            self.assertEqual(self.cur.warning.full_code, 'DPY-7000', create)
            self.cur.execute(drop)
            self.assertIsNone(self.cur.warning)

    def test_an_ordinary_statement_sets_no_warning(self):
        self.cur.execute('SELECT 1 FROM dual')
        self.assertIsNone(self.cur.warning)


@_requires(_LOB_VAR_BIND)
@unittest.skipUnless(_USER, _SKIP_REASON)
class LOBReturningIntegration(_IntegrationBase):
    """`DML ... RETURNING <lob column> INTO :b` (#985).

    The returned value is the LOB block a fetched column carries -- a block
    length, the locator's size and chunk size, then the locator -- not a DALC.
    Read as a DALC the block length was taken for the whole value and the rest
    left in the stream, where its next byte decoded as a response token, so the
    number came from the data. Same misunderstanding as the OUT bind in #978,
    reached through the other reader. Against a REAL server, no Mirror.
    """

    TABLE = 'PYORACLE_LOBRET'

    def setUp(self):
        super().setUp()
        self.conn.autocommit = False
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, c CLOB, b BLOB)')

    def tearDown(self):
        try:
            self.conn.rollback()
        except Exception:
            pass
        super().tearDown()

    def test_returning_a_clob(self):
        Var = self.cur.var(seerdb.DB_TYPE_CLOB)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (n, c) VALUES (1, :a) RETURNING c INTO :b',
            ['the returned clob', Var],
        )
        self.assertEqual([V.read() for V in Var.getvalue()], ['the returned clob'])

    def test_returning_a_blob(self):
        Var = self.cur.var(seerdb.DB_TYPE_BLOB)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (n, b) VALUES (1, :a) RETURNING b INTO :b',
            [b'the returned blob', Var],
        )
        self.assertEqual([V.read() for V in Var.getvalue()], [b'the returned blob'])

    @_requires(_ROWS_RETURNING)
    def test_returning_several_lobs_from_one_update(self):
        # An UPDATE touching several rows returns one value per row, so the
        # reader has to walk the whole list in the LOB framing, not just the
        # first -- a per-row desync only shows from the second value on.
        for N, Text in enumerate(('first', 'second', 'third'), start=1):
            self.cur.execute(
                f'INSERT INTO {self.TABLE} (n, c) VALUES (:1, :2)', [N, Text]
            )
        Var = self.cur.var(seerdb.DB_TYPE_CLOB)
        self.cur.execute(
            f'UPDATE {self.TABLE} SET n = n + 10 RETURNING c INTO :v', [Var]
        )
        self.assertEqual(
            sorted(V.read() for V in Var.getvalue()), ['first', 'second', 'third']
        )

    def test_returning_a_null_lob(self):
        Var = self.cur.var(seerdb.DB_TYPE_CLOB)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (n, c) VALUES (1, NULL) RETURNING c INTO :v',
            [Var],
        )
        self.assertEqual(Var.getvalue(), [None])

    @_requires(_LOB_VAR_BIND)
    def test_fetch_lobs_false_materialises_a_returned_lob(self):
        self.conn.rollback()
        with _connect(fetch_lobs=False) as Conn:
            Cur = Conn.cursor()
            Var = Cur.var(seerdb.DB_TYPE_CLOB)
            Cur.execute(
                f'INSERT INTO {self.TABLE} (n, c) VALUES (2, :a) RETURNING c INTO :b',
                ['materialised', Var],
            )
            self.assertEqual(Var.getvalue(), ['materialised'])
            Conn.rollback()


@unittest.skipUnless(_USER, _SKIP_REASON)
class GettypeCurrentSchemaIntegration(_IntegrationBase):
    """An unqualified `gettype()` name resolves in the CURRENT schema.

    That is where Oracle's own SQL resolves one, and the reference client too;
    ALTER SESSION SET CURRENT_SCHEMA moves it away from the login user. Looking
    under USER instead found a type the session could not use in SQL at all.
    """

    TYPE = 'PYORACLE_CURSCHEMA_T'

    def setUp(self):
        super().setUp()
        self._drop_type()
        self.cur.execute(f'CREATE TYPE {self.TYPE} AS OBJECT (id NUMBER)')
        self.owner = self.conn.gettype(self.TYPE).schema

    def tearDown(self):
        self._drop_type()
        super().tearDown()

    def _drop_type(self):
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute(f'DROP TYPE {self.TYPE}')
        except DatabaseError:
            pass  # best-effort teardown of a leftover

    def test_an_unqualified_name_follows_the_current_schema(self):
        from seerdb.common.exceptions import DatabaseError

        # A schema that is not the type's owner: the suite logs in as SYSTEM
        # where the bed has no application user (8i), and SYSTEM is then the
        # owner's own (#1215).
        other = 'SYS' if self.owner == 'SYSTEM' else 'SYSTEM'
        self.cur.execute(f'ALTER SESSION SET CURRENT_SCHEMA = {other}')
        try:
            # SQL cannot see the type from here, so neither may gettype...
            with self.assertRaises(DatabaseError):
                self.conn.gettype(self.TYPE)
            # ...while the qualified name still names it.
            typ = self.conn.gettype(f'{self.owner}.{self.TYPE}')
            self.assertEqual(typ.schema, self.owner)
        finally:
            self.cur.execute(f'ALTER SESSION SET CURRENT_SCHEMA = {self.owner}')


@_requires(_PACKAGE_TYPE_BIND)
@unittest.skipUnless(_USER, _SKIP_REASON)
class PlsqlTypeIntegration(_IntegrationBase):
    """`gettype()` of a PL/SQL **package-level** type (#1030).

    These live in `all_plsql_types` / `all_plsql_type_attrs` /
    `all_plsql_coll_types`, invisible to the `all_types` pair a schema-level
    type is read from -- so `gettype` could not see one at all, whatever the
    name it was given.
    """

    PKG = 'PYORACLE_PLSQLTYPE_PKG'
    SCHEMA_TYPE = 'PYORACLE_PLSQLTYPE_T'

    def setUp(self):
        super().setUp()
        # A package-level type lives in a PL/SQL PACKAGE, so this class cannot
        # run against a backend with no PL/SQL at all. It skipped on the
        # PostgreSQL leg only by accident until that Mirror reached 12.1: the
        # version gate above was doing the work. The capability is what actually
        # decides it (#1127).
        self._drop_objects()
        # A schema-level type of the SAME shape, so the two-part name
        # `PKG.TYPE` cannot be confused with `SCHEMA.TYPE` by accident.
        self.cur.execute(f'CREATE TYPE {self.SCHEMA_TYPE} AS VARRAY(5) OF NUMBER')
        self.cur.execute(f"""CREATE PACKAGE {self.PKG} AS
              TYPE udt_numlist IS TABLE OF NUMBER INDEX BY BINARY_INTEGER;
              TYPE udt_rec IS RECORD (id NUMBER, name VARCHAR2(40));
              PROCEDURE fill(n IN NUMBER, l IN OUT udt_numlist);
              FUNCTION total_from_zero(l IN udt_numlist) RETURN NUMBER;
              PROCEDURE fill_sparse(l OUT udt_numlist);
            END;""")
        self.cur.execute(f"""CREATE PACKAGE BODY {self.PKG} AS
              PROCEDURE fill(n IN NUMBER, l IN OUT udt_numlist) IS
              BEGIN
                FOR i IN 1..n LOOP l(i) := i * 100; END LOOP;
              END;
              FUNCTION total_from_zero(l IN udt_numlist) RETURN NUMBER IS
                t NUMBER := 0;
              BEGIN
                FOR i IN 0..l.COUNT - 1 LOOP t := t + l(i); END LOOP;
                RETURN t;
              END;
              PROCEDURE fill_sparse(l OUT udt_numlist) IS
              BEGIN
                l(-1048576) := 10;
                l(-576)     := 20;
                l(284)      := 30;
                l(8388608)  := 40;
              END;
            END;""")

    def _drop_objects(self):
        for stmt in (f'DROP PACKAGE {self.PKG}', f'DROP TYPE {self.SCHEMA_TYPE}'):
            try:
                self.cur.execute(stmt)
            except seerdb.DatabaseError:
                pass  # best-effort teardown of leftovers

    def tearDown(self):
        try:
            self._drop_objects()
        except seerdb.DatabaseError:
            pass
        super().tearDown()

    def test_a_package_collection_resolves_by_two_part_name(self):
        typ = self.conn.gettype(f'{self.PKG}.UDT_NUMLIST')
        self.assertTrue(typ.is_collection)
        self.assertEqual(typ.package_name, self.PKG)
        self.assertTrue(typ.oid)  # the identity a bind announces

    def test_a_package_type_resolves_by_three_part_name(self):
        owner = self.conn.gettype(f'{self.PKG}.UDT_NUMLIST').schema
        typ = self.conn.gettype(f'{owner}.{self.PKG}.UDT_NUMLIST')
        self.assertEqual(typ.full_name, f'{owner}.{self.PKG}.UDT_NUMLIST')

    def test_a_package_record_carries_its_attributes_in_order(self):
        typ = self.conn.gettype(f'{self.PKG}.UDT_REC')
        self.assertFalse(typ.is_collection)
        self.assertEqual(typ.attr_names, ['ID', 'NAME'])

    def test_a_schema_level_type_still_resolves_the_same_way(self):
        # The two-part name is ambiguous -- SCHEMA.TYPE or PACKAGE.TYPE -- so
        # the schema reading is tried first and every name that resolved before
        # still resolves to the same type.
        typ = self.conn.gettype(self.SCHEMA_TYPE)
        self.assertTrue(typ.is_collection)
        self.assertIsNone(typ.package_name)
        qualified = self.conn.gettype(f'{typ.schema}.{self.SCHEMA_TYPE}')
        self.assertEqual(qualified.full_name, typ.full_name)

    def test_a_name_that_resolves_to_nothing_still_raises(self):
        with self.assertRaises(seerdb.DatabaseError):
            self.conn.gettype('PYORACLE_NO_SUCH_PKG.PYORACLE_NO_SUCH_TYPE')
        with self.assertRaises(seerdb.DatabaseError):
            self.conn.gettype('PYORACLE_NO_SUCH_TYPE')

    def test_a_package_type_resolved_by_name_can_be_bound(self):
        # The point of resolving it: an index-by table bound through the type
        # `gettype` returned, with no Mirror and no hand-built DbObjectType.
        typ = self.conn.gettype(f'{self.PKG}.UDT_NUMLIST')
        obj = typ.newobject()
        self.cur.callproc(f'{self.PKG}.fill', (3, obj))
        self.assertEqual([int(v) for v in obj.aslist()], [100, 200, 300])

    def test_a_locally_built_array_is_keyed_from_zero(self):
        # PL/SQL written for an index-by table indexes from ZERO -- `for i in
        # 0..l.COUNT - 1` is the ordinary idiom. seerdb keyed a locally built
        # array 1..N, so `l(0)` was a missing key and PL/SQL raised
        # NO_DATA_FOUND, surfacing as ORA-01403 (#1055).
        typ = self.conn.gettype(f'{self.PKG}.UDT_NUMLIST')
        obj = typ.newobject()
        for Value in (10, 20, 30):
            obj.append(Value)
        Total = self.cur.callfunc(f'{self.PKG}.total_from_zero', int, [obj])
        self.assertEqual(int(Total), 60)

    def test_sparse_keys_survive_and_are_walkable(self):
        # The keys PL/SQL used, not positions: sparse and negative, read back
        # through first/last/next/prev/exists/getelement/asdict (#1035).
        typ = self.conn.gettype(f'{self.PKG}.UDT_NUMLIST')
        obj = typ.newobject()
        self.cur.callproc(f'{self.PKG}.fill_sparse', [obj])
        self.assertEqual(obj.first(), -1048576)
        self.assertEqual(obj.last(), 8388608)
        self.assertEqual(obj.next(-576), 284)
        self.assertEqual(obj.prev(284), -576)
        self.assertEqual(obj.size(), 4)
        self.assertTrue(obj.exists(-576))
        self.assertFalse(obj.exists(-577))
        self.assertEqual(int(obj.getelement(284)), 30)
        self.assertIsNone(obj.next(8388608))
        self.assertEqual(
            {K: int(V) for (K, V) in obj.asdict().items()},
            {-1048576: 10, -576: 20, 284: 30, 8388608: 40},
        )

    def test_a_deleted_key_leaves_a_hole_on_the_wire(self):
        # delete() must reach the server as a hole, not as a renumbering: the
        # survivors keep their own keys, so total_from_zero (which indexes
        # 0..count-1) can no longer find them.
        typ = self.conn.gettype(f'{self.PKG}.UDT_NUMLIST')
        obj = typ.newobject()
        self.cur.callproc(f'{self.PKG}.fill_sparse', [obj])
        obj.delete(-576)
        self.assertEqual([int(V) for V in obj.aslist()], [10, 30, 40])
        self.assertEqual(obj.next(-1048576), 284)
        Echo = typ.newobject()
        self.cur.callproc(f'{self.PKG}.fill_sparse', [Echo])
        self.assertEqual(Echo.size(), 4)

    def test_a_seeded_array_is_keyed_from_zero(self):
        # Same, seeded through newobject() rather than append().
        typ = self.conn.gettype(f'{self.PKG}.UDT_NUMLIST')
        Total = self.cur.callfunc(
            f'{self.PKG}.total_from_zero', int, [typ.newobject([1, 2, 3, 4])]
        )
        self.assertEqual(int(Total), 10)


@_requires(_REFCURSOR_IN_BIND)
@unittest.skipUnless(_USER, _SKIP_REASON)
class RefCursorInBindIntegration(_IntegrationBase):
    """Binding an OPEN cursor as a REF CURSOR IN parameter (#1047).

    The block declares a plain `sys_refcursor` IN, fetches from the cursor the
    server already has, and closes it. What travels is the cursor **id**, so the
    cursor has to still be open with its rows unread -- which is what a
    scrollable cursor (#181) is.
    """

    PKG = 'PYORACLE_RCIN_PKG'
    TABLE = 'PYORACLE_RCIN'

    def setUp(self):
        super().setUp()
        # The cursor is drained by a PL/SQL procedure in a PACKAGE, and the whole
        # class is built on one, so a backend with no PL/SQL cannot run it. It
        # skipped on the PostgreSQL leg only because that Mirror was below 12.1;
        # the capability is what actually decides it (#1127).
        try:
            self.cur.execute(f'DROP PACKAGE {self.PKG}')
        except seerdb.DatabaseError:
            pass
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(40))')
        self.cur.execute(
            f'CREATE PACKAGE {self.PKG} AS '
            'PROCEDURE drain(c IN OUT SYS_REFCURSOR); END;'
        )
        self.cur.execute(f"""CREATE PACKAGE BODY {self.PKG} AS
              PROCEDURE drain(c IN OUT SYS_REFCURSOR) IS
                t_id NUMBER; t_v VARCHAR2(40);
              BEGIN
                FETCH c INTO t_id, t_v;
                IF c%FOUND THEN
                  INSERT INTO {self.TABLE} (id, v) VALUES (t_id, t_v);
                END IF;
                CLOSE c;
              END;
            END;""")

    def tearDown(self):
        try:
            self.cur.execute(f'DROP PACKAGE {self.PKG}')
        except seerdb.DatabaseError:
            pass
        super().tearDown()

    def _open_ref_cursor(self):
        rc = self.conn.cursor(scrollable=True)
        rc.prefetchrows = 1
        rc.execute("SELECT level, 'String ' || level FROM dual CONNECT BY level <= 5")
        return rc

    def test_the_block_fetches_from_the_bound_cursor(self):
        # The proof that the id reached the server and named a usable cursor:
        # the block read a row off it and wrote the row down. Row 1 was consumed
        # by the scrollable open's prefetch, so row 2 is what it sees.
        self.cur.execute(f'BEGIN {self.PKG}.drain(:1); END;', [self._open_ref_cursor()])
        self.cur.execute(f'SELECT id, v FROM {self.TABLE}')
        self.assertEqual(
            [(int(i), v) for i, v in self.cur.fetchall()], [(2, 'String 2')]
        )

    def test_a_drained_cursor_is_refused_with_a_reason(self):
        # An ordinary cursor is drained to EOF and queued for close, so its id
        # names nothing the block can fetch from. The server's answer three
        # layers down is ORA-01007; say so up front instead.
        plain = self.conn.cursor()
        plain.execute('SELECT 1 FROM dual')
        with self.assertRaises(seerdb.NotSupportedError) as ctx:
            self.cur.execute(f'BEGIN {self.PKG}.drain(:1); END;', [plain])
        self.assertIn('still open on the server', str(ctx.exception))

    def test_an_out_ref_cursor_still_works(self):
        # The OUT form shares the OAC this changed, and sends cursor id 0 -- the
        # same bytes as before. It is the regression guard for that.
        self.cur.execute(
            f'CREATE PACKAGE {self.PKG}_O AS PROCEDURE give(c OUT SYS_REFCURSOR); END;'
        )
        self.cur.execute(
            f'CREATE PACKAGE BODY {self.PKG}_O AS '
            'PROCEDURE give(c OUT SYS_REFCURSOR) IS BEGIN '
            'OPEN c FOR SELECT 42 FROM dual; END; END;'
        )
        try:
            out = self.cur.var(seerdb.DB_TYPE_CURSOR)
            self.cur.execute(f'BEGIN {self.PKG}_O.give(:1); END;', [out])
            self.assertEqual([tuple(r) for r in out.getvalue().fetchall()], [(42,)])
        finally:
            try:
                self.cur.execute(f'DROP PACKAGE {self.PKG}_O')
            except seerdb.DatabaseError:
                pass


@_requires(_OBJECT_BIND)
@unittest.skipUnless(_USER, _SKIP_REASON)
class ObjectBlockBindIntegration(_IntegrationBase):
    """An object or collection bound into a block of several statements (#2548).

    A block of one call takes the call path; one of several runs as a whole,
    and has to take the object in and give it back as the object it is.
    """

    REC = 'PYORACLE_BLKREC_T'
    TYPE = 'PYORACLE_BLKARR_T'
    PROC = 'PYORACLE_BLK_RENAME'

    def setUp(self):
        super().setUp()
        self._drop_objects()
        self.cur.execute(
            f'CREATE TYPE {self.REC} AS OBJECT (id NUMBER, name VARCHAR2(40))'
        )
        self.cur.execute(f'CREATE TYPE {self.TYPE} AS VARRAY(10) OF NUMBER')
        self.cur.execute(f"""CREATE PROCEDURE {self.PROC}(r IN OUT {self.REC}) IS
              BEGIN
                r.id := r.id + 1;
                r.name := 'renamed ' || r.name;
              END;""")

    def _drop_objects(self):
        for stmt in (
            f'DROP PROCEDURE {self.PROC}',
            f'DROP TYPE {self.TYPE}',
            f'DROP TYPE {self.REC}',
        ):
            try:
                self.cur.execute(stmt)
            except seerdb.DatabaseError:
                pass  # best-effort teardown of leftovers

    def tearDown(self):
        self._drop_objects()
        super().tearDown()

    def test_a_record_goes_in_and_comes_back_changed(self):
        obj = self.conn.gettype(self.REC).newobject()
        obj.ID = 7
        obj.NAME = 'Alice'
        tail = self.cur.var(int)
        self.cur.execute(f'BEGIN {self.PROC}(:1); :2 := 4242; END;', [obj, tail])
        self.assertEqual((int(obj.ID), obj.NAME), (8, 'renamed Alice'))
        self.assertEqual(int(tail.getvalue()), 4242)

    def test_a_collection_goes_in_and_comes_back(self):
        typ = self.conn.gettype(self.TYPE)
        given = typ.newobject([1, 2, 3])
        made = typ.newobject()
        seen = self.cur.var(str)
        self.cur.execute(
            f"BEGIN :made := {self.TYPE}(7, 8); :seen := 'null'; "
            "IF :given IS NOT NULL THEN :seen := 'set'; END IF; END;",
            {'given': given, 'made': made, 'seen': seen},
        )
        self.assertEqual([int(v) for v in made.aslist()], [7, 8])
        self.assertEqual([int(v) for v in given.aslist()], [1, 2, 3])
        self.assertEqual(seen.getvalue(), 'set')

    def test_a_null_object_goes_in_null(self):
        var = self.cur.var(self.conn.gettype(self.REC))
        seen = self.cur.var(str)
        self.cur.execute(
            "BEGIN :seen := 'set'; IF :obj IS NULL THEN :seen := 'null'; END IF; END;",
            {'obj': var, 'seen': seen},
        )
        self.assertEqual(seen.getvalue(), 'null')
        self.assertIsNone(var.getvalue())


@_requires(_OBJECT_BIND)
@unittest.skipUnless(_USER, _SKIP_REASON)
class ObjectOutBindIntegration(_IntegrationBase):
    """An object bound DIRECTLY as an OUT / IN OUT parameter (#1029).

    `cursor.callproc(name, (3, obj))` hands the object over itself, with no Var
    around it -- which is how python-oracledb is normally called. Recognising
    only the Var form sent the bare object down the plain-DALC branch, where the
    object frame's 36-byte toid was read as a length and the reply desynced onto
    that toid's own `00 22 02 08` prefix ("no decoder for response token 34").
    Against a REAL server, no Mirror.
    """

    TYPE = 'PYORACLE_OUTBIND_T'
    REC = 'PYORACLE_OUTREC_T'
    PKG = 'PYORACLE_OUTBIND_PKG'

    def setUp(self):
        super().setUp()
        # The object OUT binds are filled by procedures in a PL/SQL PACKAGE this
        # setUp builds and every test calls into, so a backend with no PL/SQL
        # cannot run the class. It was hidden twice over on the PostgreSQL leg:
        # first by the 12.1 version gate above, then by the VARRAY it declares,
        # which PostgreSQL could not parse until that was translated (#1127).
        self._drop_objects()
        self.cur.execute(f'CREATE TYPE {self.TYPE} AS VARRAY(10) OF NUMBER')
        self.cur.execute(
            f'CREATE TYPE {self.REC} AS OBJECT (id NUMBER, name VARCHAR2(40))'
        )
        self.cur.execute(f"""CREATE PACKAGE {self.PKG} AS
              PROCEDURE fill(n IN NUMBER, l IN OUT {self.TYPE});
              PROCEDURE double_all(l IN OUT {self.TYPE});
              PROCEDURE rename(r IN OUT {self.REC});
              PROCEDURE blank(l IN OUT {self.TYPE});
            END;""")
        self.cur.execute(f"""CREATE PACKAGE BODY {self.PKG} AS
              PROCEDURE fill(n IN NUMBER, l IN OUT {self.TYPE}) IS
              BEGIN
                l := {self.TYPE}();
                FOR i IN 1..n LOOP l.extend; l(i) := i * 100; END LOOP;
              END;
              PROCEDURE double_all(l IN OUT {self.TYPE}) IS
              BEGIN
                FOR i IN 1..l.count LOOP l(i) := l(i) * 2; END LOOP;
              END;
              PROCEDURE rename(r IN OUT {self.REC}) IS
              BEGIN
                r.id := r.id + 1;
                r.name := 'renamed ' || r.name;
              END;
              PROCEDURE blank(l IN OUT {self.TYPE}) IS
              BEGIN
                l := NULL;
              END;
            END;""")

    def _drop_objects(self):
        for stmt in (
            f'DROP PACKAGE {self.PKG}',
            f'DROP TYPE {self.REC}',
            f'DROP TYPE {self.TYPE}',
        ):
            try:
                self.cur.execute(stmt)
            except seerdb.DatabaseError:
                pass  # best-effort teardown of leftovers

    def tearDown(self):
        try:
            self._drop_objects()
        except seerdb.DatabaseError:
            pass
        super().tearDown()

    def test_a_bare_collection_takes_the_out_value(self):
        # The plain reproduction: nothing but the object goes in, and the
        # caller reads the result off that same object.
        typ = self.conn.gettype(self.TYPE)
        obj = typ.newobject()
        self.cur.callproc(f'{self.PKG}.fill', (3, obj))
        self.assertEqual([int(v) for v in obj.aslist()], [100, 200, 300])

    def test_a_bare_collection_round_trips_in_out(self):
        # IN OUT: the values sent must reach the server and the values it wrote
        # must come back -- [] or the unchanged input both mean it did not.
        typ = self.conn.gettype(self.TYPE)
        obj = typ.newobject()
        obj.extend([1, 2, 3])
        self.cur.callproc(f'{self.PKG}.double_all', (obj,))
        self.assertEqual([int(v) for v in obj.aslist()], [2, 4, 6])

    def test_a_bare_record_takes_its_attributes_back(self):
        # The non-collection shape: attributes are written back by name, in
        # place, on the caller's own object.
        typ = self.conn.gettype(self.REC)
        obj = typ.newobject()
        obj.ID = 7
        obj.NAME = 'Alice'
        self.cur.callproc(f'{self.PKG}.rename', (obj,))
        self.assertEqual(int(obj.ID), 8)
        self.assertEqual(obj.NAME, 'renamed Alice')

    def test_a_null_out_value_empties_the_object(self):
        # A NULL object OUT must not leave the INPUT half of an IN OUT bind
        # sitting in the caller's object, which reads as a successful no-op.
        typ = self.conn.gettype(self.TYPE)
        obj = typ.newobject()
        obj.extend([1, 2, 3])
        self.cur.callproc(f'{self.PKG}.blank', (obj,))
        self.assertEqual(obj.aslist(), [])

    def test_the_bind_after_an_object_is_still_intact(self):
        # The object frame has to consume exactly its own bytes: a scalar OUT
        # behind it is what catches a mis-measurement, since the desync this
        # fixes showed up as a bogus token rather than a wrong value.
        typ = self.conn.gettype(self.TYPE)
        obj = typ.newobject()
        tail = self.cur.var(int)
        self.cur.execute(f'BEGIN {self.PKG}.fill(2, :1); :2 := 4242; END;', [obj, tail])
        self.assertEqual([int(v) for v in obj.aslist()], [100, 200])
        self.assertEqual(int(tail.getvalue()), 4242)


@_requires(_OBJECT_BIND)
@unittest.skipUnless(_USER, _SKIP_REASON)
class ObjectReturningIntegration(_IntegrationBase):
    """`DML ... RETURNING <object column> INTO :b` (#826).

    The returned value carries the OBJECT frame a column uses -- toid, object
    OID, snapshot, version, image gate, flags, image -- not a DALC. Read as a
    DALC the constructed 36-byte toid was taken for a length, the reply desynced
    two bytes in, and the decoder reported that toid's own `00 22 02 08` prefix
    as "no decoder for response token 34". Against a REAL server, no Mirror.
    """

    TYPE = 'PYORACLE_OBJRET_T'
    TABLE = 'PYORACLE_OBJRET'

    def setUp(self):
        super().setUp()
        from seerdb.common.exceptions import DatabaseError

        for stmt in (f'DROP TABLE {self.TABLE}', f'DROP TYPE {self.TYPE}'):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass  # best-effort teardown of leftovers
        self.cur.execute(
            f'CREATE TYPE {self.TYPE} AS OBJECT (id NUMBER, name VARCHAR2(40))'
        )
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, o {self.TYPE})')

    def tearDown(self):
        from seerdb.common.exceptions import DatabaseError

        for stmt in (f'DROP TABLE {self.TABLE}', f'DROP TYPE {self.TYPE}'):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass
        super().tearDown()

    def test_returns_the_inserted_object(self):
        typ = self.conn.gettype(self.TYPE)
        obj = typ.newobject()
        obj.ID = 7
        obj.NAME = 'Alice'
        out = self.cur.var(typ)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (n, o) VALUES (1, :obj) '
            'RETURNING o INTO :outObj',
            [obj, out],
        )
        (returned,) = out.getvalue()
        self.assertEqual(returned.NAME, 'Alice')
        self.assertEqual(int(returned.ID), 7)

    def test_a_returned_object_survives_alongside_a_scalar(self):
        # The object frame has to consume exactly its own bytes, or the bind
        # after it reads the remainder: a scalar behind it is the check.
        typ = self.conn.gettype(self.TYPE)
        obj = typ.newobject()
        obj.ID = 9
        obj.NAME = 'Bob'
        out_obj = self.cur.var(typ)
        out_num = self.cur.var(int)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (n, o) VALUES (42, :obj) '
            'RETURNING o, n INTO :outObj, :outNum',
            [obj, out_obj, out_num],
        )
        (returned,) = out_obj.getvalue()
        self.assertEqual(returned.NAME, 'Bob')
        self.assertEqual(int(out_num.getvalue()[0]), 42)


@unittest.skipUnless(_USER, _SKIP_REASON)
class LargeObjectImageIntegration(_IntegrationBase):
    """An object image past 252 bytes rides chunked, with one length byte per
    chunk before 12.1 and a ub4 one from 12.1 (#1261). Read the 12.1 way on
    10g / 11g, a 300-character attribute came back one character long, and an
    object with three LOB locators desynced the row."""

    TEXT_TYPE = 'PYO_BIGIMG_V_T'
    LOB_TYPE = 'PYO_BIGIMG_L_T'
    TABLE = 'PYO_BIGIMG_TAB'

    def setUp(self):
        super().setUp()
        self._drop()
        self.cur.execute(f'CREATE TYPE {self.TEXT_TYPE} AS OBJECT (v VARCHAR2(400))')
        self.cur.execute(
            f'CREATE TYPE {self.LOB_TYPE} AS OBJECT (a CLOB, b CLOB, c BLOB)'
        )
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (t {self.TEXT_TYPE}, l {self.LOB_TYPE})'
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES ({self.TEXT_TYPE}(RPAD('x', 300, 'x')), "
            f"{self.LOB_TYPE}(TO_CLOB('first'), TO_CLOB('second'), "
            f"TO_BLOB(HEXTORAW('0A0B'))))"
        )

    def tearDown(self):
        self._drop()
        super().tearDown()

    def _drop(self):
        from seerdb.common.exceptions import DatabaseError

        for stmt in (
            f'DROP TABLE {self.TABLE}',
            f'DROP TYPE {self.LOB_TYPE}',
            f'DROP TYPE {self.TEXT_TYPE}',
        ):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass  # best-effort teardown of leftovers

    def test_a_large_object_image_fetches_whole(self):
        self.cur.execute(f'SELECT t FROM {self.TABLE}')
        (value,) = self.cur.fetchone()
        self.assertEqual(value.V, 'x' * 300)

    def test_a_large_object_image_with_three_lobs_fetches(self):
        self.cur.execute(f'SELECT l, 42 FROM {self.TABLE}')
        (value, after) = self.cur.fetchone()
        self.assertEqual(
            (value.A.read(), value.B.read(), value.C.read(), after),
            ('first', 'second', b'\n\x0b', 42),
        )


@unittest.skipUnless(_USER, _SKIP_REASON)
class NationalAttributeIntegration(_IntegrationBase):
    """An NVARCHAR2 object attribute or collection element is AL16UTF16 in the
    object image, as in a column: it fetches whole, and a bound value is stored
    as the national text it is (#1433). Read and written as UTF-8, a fetch came
    back garbled and a bind stored the UTF-8 bytes as if they were AL16UTF16 --
    which seerdb then read back as the right text, and every other client did
    not."""

    TYPE = 'PYO_NATTR_T'
    LIST = 'PYO_NATTR_L'
    TABLE = 'PYO_NATTR_TAB'
    TEXT = 'ko\u010dka \u4e2d'
    BOUND = '\u017e\u00e1ba \u732b'

    def setUp(self):
        super().setUp()
        self._drop()
        self.cur.execute(
            f'CREATE TYPE {self.TYPE} AS OBJECT (id NUMBER, v NVARCHAR2(10), w VARCHAR2(10), f NCHAR(3))'
        )
        self.cur.execute(f'CREATE TYPE {self.LIST} AS TABLE OF NVARCHAR2(10)')
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (k NUMBER, o {self.TYPE}, l {self.LIST}) '
            f'NESTED TABLE l STORE AS {self.TABLE}_S'
        )

    def tearDown(self):
        self._drop()
        super().tearDown()

    def _drop(self):
        from seerdb.common.exceptions import DatabaseError

        for stmt in (
            f'DROP TABLE {self.TABLE}',
            f'DROP TYPE {self.LIST}',
            f'DROP TYPE {self.TYPE}',
        ):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass  # best-effort teardown of leftovers

    def _stored_length(self, k):
        # The server's own reading of what was stored: the UTF-8 bytes of BOUND
        # taken as AL16UTF16 are 5 characters, not 7. The Mirror over PostgreSQL
        # cannot select an attribute in SQL yet (#1434).
        # A leg that names no backend ('1', the CI job) gets the conservative
        # answer, as _postgres_cannot gives it.
        if os.environ.get('SEERDB_TEST_MIRROR') in ('postgres', '1'):
            return len(self.BOUND)
        self.cur.execute(f'SELECT LENGTH(x.o.v) FROM {self.TABLE} x WHERE k = :1', [k])
        return self.cur.fetchone()[0]

    def test_a_national_attribute_fetches_and_binds(self):
        self.cur.execute(
            f"INSERT INTO {self.TABLE} (k, o) VALUES (1, {self.TYPE}(1, N'{self.TEXT}', 'pes', NULL))"
        )
        self.cur.execute(f'SELECT o FROM {self.TABLE} WHERE k = 1')
        o = self.cur.fetchone()[0]
        self.assertEqual((o.V, o.W), (self.TEXT, 'pes'))
        if self.conn.field_version < FIELD_VERSION_12_1:
            return  # an object bind needs the 12.1+ OAC
        obj = self.conn.gettype(self.TYPE).newobject(
            {'ID': 2, 'V': self.BOUND, 'W': 'x'}
        )
        self.cur.execute(f'INSERT INTO {self.TABLE} (k, o) VALUES (2, :1)', [obj])
        self.assertEqual(self._stored_length(2), len(self.BOUND))
        self.cur.execute(f'SELECT o FROM {self.TABLE} WHERE k = 2')
        self.assertEqual(self.cur.fetchone()[0].V, self.BOUND)

    def test_a_national_attribute_is_listed_as_national(self):
        # USER_TYPE_ATTRS names an NVARCHAR2 / NCHAR attribute so, with the
        # national character set; 10g itself names them VARCHAR2 / CHAR. The
        # Mirror over PostgreSQL stores them as a varchar / char (#1383, #1416).
        old = int(self.conn.version.split('.')[0]) < 11
        self.cur.execute(
            'SELECT attr_name, attr_type_name, length, character_set_name '
            'FROM user_type_attrs WHERE type_name = :1 AND attr_name IN (:2, :3, :4) '
            'ORDER BY attr_no',
            [self.TYPE, 'V', 'W', 'F'],
        )
        self.assertEqual(
            self.cur.fetchall(),
            [
                ('V', 'VARCHAR2' if old else 'NVARCHAR2', 10, 'NCHAR_CS'),
                ('W', 'VARCHAR2', 10, 'CHAR_CS'),
                ('F', 'CHAR' if old else 'NCHAR', 3, 'NCHAR_CS'),
            ],
        )

    def test_a_national_attribute_collection_fetches_and_binds(self):
        self.cur.execute(
            f"INSERT INTO {self.TABLE} (k, l) VALUES (1, {self.LIST}('{self.TEXT}', 'pes'))"
        )
        self.cur.execute(f'SELECT l FROM {self.TABLE} WHERE k = 1')
        self.assertEqual(self.cur.fetchone()[0].aslist(), [self.TEXT, 'pes'])
        if self.conn.field_version < FIELD_VERSION_12_1:
            return  # an object bind needs the 12.1+ OAC
        coll = self.conn.gettype(self.LIST).newobject([self.BOUND])
        self.cur.execute(f'INSERT INTO {self.TABLE} (k, l) VALUES (2, :1)', [coll])
        self.cur.execute(f'SELECT l FROM {self.TABLE} WHERE k = 2')
        self.assertEqual(self.cur.fetchone()[0].aslist(), [self.BOUND])


@unittest.skipUnless(_USER, _SKIP_REASON)
class ObjectLobAttributeIntegration(_IntegrationBase):
    """CLOB / NCLOB / BLOB attributes of an object type (#1260): fetched, each is
    a LOB on the connection; bound, it takes a LOB -- fetched or temporary -- or a
    str / bytes, which goes out as a temporary LOB, as the reference client does."""

    TYPE = 'PYO_LOBATTR_T'
    NTYPE = 'PYO_LOBATTR_N_T'
    LIST = 'PYO_LOBATTR_LIST_T'
    TABLE = 'PYO_LOBATTR_TAB'
    TEXT = 'national \u00e9\u4e2d'

    def setUp(self):
        super().setUp()
        self._drop()
        self.cur.execute(
            f'CREATE TYPE {self.TYPE} AS OBJECT (id NUMBER, c CLOB, b BLOB)'
        )
        self.cur.execute(f'CREATE TYPE {self.NTYPE} AS OBJECT (id NUMBER, n NCLOB)')
        self.cur.execute(f'CREATE TYPE {self.LIST} AS TABLE OF CLOB')
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (k NUMBER, o {self.TYPE}, p {self.NTYPE})'
        )

    def tearDown(self):
        self._drop()
        super().tearDown()

    def _drop(self):
        from seerdb.common.exceptions import DatabaseError

        for stmt in (
            f'DROP TABLE {self.TABLE}',
            f'DROP TABLE {self.TABLE}_L',
            f'DROP TYPE {self.LIST}',
            f'DROP TYPE {self.NTYPE}',
            f'DROP TYPE {self.TYPE}',
        ):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass  # best-effort teardown of leftovers

    def _fetched(self, k, column='o'):
        self.cur.execute(f'SELECT {column} FROM {self.TABLE} WHERE k = :1', [k])
        return self.cur.fetchone()[0]

    def test_a_lob_attribute_fetches_as_a_lob(self):
        from seerdb.common.lob import LOB

        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, {self.TYPE}(1, TO_CLOB('some clob'), "
            f"TO_BLOB(HEXTORAW('0102FF'))), {self.NTYPE}(1, TO_NCLOB('{self.TEXT}')))"
        )
        o = self._fetched(1)
        self.assertIsInstance(o.C, LOB)
        self.assertIsInstance(o.B, LOB)
        self.assertEqual((o.C.read(), o.B.read()), ('some clob', b'\x01\x02\xff'))
        n = self._fetched(1, 'p')
        self.assertIsInstance(n.N, LOB)
        self.assertEqual(n.N.read(), self.TEXT)

    def test_an_nclob_attribute_is_listed_as_nclob(self):
        # An NCLOB attribute is an NCLOB, not a CLOB. A client types the
        # attribute by this name, and refuses an NCLOB for a CLOB attribute. The
        # Mirror over PostgreSQL stores both alike and reported CLOB (#1431).
        # 10g itself still lists it as CLOB; 11g on name it NCLOB.
        national = 'CLOB' if int(self.conn.version.split('.')[0]) < 11 else 'NCLOB'
        self.cur.execute(
            'SELECT type_name, attr_name, attr_type_name FROM user_type_attrs '
            'WHERE type_name IN (:1, :2) AND attr_name IN (:3, :4) '
            'ORDER BY type_name',
            [self.TYPE, self.NTYPE, 'C', 'N'],
        )
        self.assertEqual(
            self.cur.fetchall(),
            [(self.NTYPE, 'N', national), (self.TYPE, 'C', 'CLOB')],
        )

    def test_lob_attributes_read_in_any_order(self):
        # Read only after a later query, and in another order: over the Mirror
        # every attribute LOB shared one locator, served in fetch order, so
        # these read another object's content (#1262).
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (7, {self.TYPE}(7, TO_CLOB('seven'), "
            f"TO_BLOB(HEXTORAW('07'))), {self.NTYPE}(7, TO_NCLOB('{self.TEXT}')))"
        )
        o = self._fetched(7)
        n = self._fetched(7, 'p')
        self.assertEqual(
            (n.N.read(), o.B.read(), o.C.read(), o.C.read()),
            (self.TEXT, b'\x07', 'seven', 'seven'),
        )

    def test_a_null_lob_attribute_is_none(self):
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (2, {self.TYPE}(2, NULL, NULL), '
            f'{self.NTYPE}(2, NULL))'
        )
        self.assertEqual((self._fetched(2).C, self._fetched(2).B), (None, None))
        self.assertIsNone(self._fetched(2, 'p').N)

    def test_a_collection_of_lob_attributes_fetches_lobs(self):
        # From a column: the Mirror-over-PG cannot type a computed collection.
        # _drop removes the table.
        table = f'{self.TABLE}_L'
        self.cur.execute(
            f'CREATE TABLE {table} (l {self.LIST}) NESTED TABLE l STORE AS {table}_S'
        )
        self.cur.execute(
            f"INSERT INTO {table} VALUES ({self.LIST}(TO_CLOB('a'), TO_CLOB('bc')))"
        )
        self.cur.execute(f'SELECT l FROM {table}')
        (value,) = self.cur.fetchone()
        self.assertEqual([e.read() for e in value.aslist()], ['a', 'bc'])

    @_requires(_OBJECT_BIND)
    def test_a_lob_attribute_binds_from_str_and_bytes(self):
        typ = self.conn.gettype(self.TYPE)
        obj = typ.newobject({'ID': 3, 'C': 'bound text', 'B': b'\x07'})
        nobj = self.conn.gettype(self.NTYPE).newobject({'ID': 3, 'N': self.TEXT})
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (3, :1, :2)', [obj, nobj])
        o = self._fetched(3)
        self.assertEqual((o.C.read(), o.B.read()), ('bound text', b'\x07'))
        self.assertEqual(self._fetched(3, 'p').N.read(), self.TEXT)
        # The caller's object keeps what it was set to.
        self.assertEqual(obj.C, 'bound text')

    @_requires(_OBJECT_BIND)
    def test_a_lob_attribute_binds_a_temporary_lob(self):
        typ = self.conn.gettype(self.TYPE)
        obj = typ.newobject({'ID': 4})
        obj.C = self.conn.createlob(seerdb.DB_TYPE_CLOB, 'temp lob')
        self.cur.execute(f'INSERT INTO {self.TABLE} (k, o) VALUES (4, :1)', [obj])
        self.assertEqual(self._fetched(4).C.read(), 'temp lob')

    @_requires(_OBJECT_BIND)
    def test_a_fetched_lob_attribute_binds_back(self):
        self.cur.execute(
            f"INSERT INTO {self.TABLE} (k, o) VALUES (5, {self.TYPE}(5, 'fetched', NULL))"
        )
        o = self._fetched(5)
        o.ID = 6
        self.cur.execute(f'INSERT INTO {self.TABLE} (k, o) VALUES (6, :1)', [o])
        self.assertEqual(self._fetched(6).C.read(), 'fetched')


@_requires(_postgres_cannot('fetch a computed collection'))
@unittest.skipUnless(_USER, _SKIP_REASON)
class ObjectCollectionFetchIntegration(_IntegrationBase):
    """A collection of an object type fetches its elements as objects (#1254)."""

    ELEM = 'PYO_OCOLL_ELEM_T'
    ELEMS = 'PYO_OCOLL_ELEMS_T'

    def setUp(self):
        super().setUp()
        self._drop()
        self.cur.execute(
            f'CREATE TYPE {self.ELEM} AS OBJECT (id NUMBER, name VARCHAR2(40))'
        )
        self.cur.execute(f'CREATE TYPE {self.ELEMS} AS TABLE OF {self.ELEM}')

    def tearDown(self):
        self._drop()
        super().tearDown()

    def _drop(self):
        from seerdb.common.exceptions import DatabaseError

        for stmt in (f'DROP TYPE {self.ELEMS}', f'DROP TYPE {self.ELEM}'):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass  # best-effort teardown of leftovers

    def test_a_collection_of_objects_fetches_objects(self):
        self.cur.execute(
            f"SELECT {self.ELEMS}({self.ELEM}(1, 'a'), {self.ELEM}(2, 'b')) FROM dual"
        )
        (value,) = self.cur.fetchone()
        self.assertEqual(
            [(int(e.ID), e.NAME) for e in value.aslist()], [(1, 'a'), (2, 'b')]
        )


@unittest.skipUnless(_USER, _SKIP_REASON)
class NestedAttributeIntegration(_IntegrationBase):
    """An object whose attributes are an object and a VARRAY of objects (#1268):
    fetched, bound and returned whole."""

    SUB = 'PYO_NEST_SUB_T'
    ARR = 'PYO_NEST_ARR_T'
    OUTER = 'PYO_NEST_OUTER_T'
    TABLE = 'PYO_NEST_TAB'

    def setUp(self):
        super().setUp()
        self._drop()
        self.cur.execute(f'CREATE TYPE {self.SUB} AS OBJECT (n NUMBER, s VARCHAR2(20))')
        self.cur.execute(f'CREATE TYPE {self.ARR} AS VARRAY(5) OF {self.SUB}')
        self.cur.execute(
            f'CREATE TYPE {self.OUTER} AS OBJECT '
            f'(id NUMBER, sub {self.SUB}, subs {self.ARR})'
        )
        self.cur.execute(f'CREATE TABLE {self.TABLE} (k NUMBER, o {self.OUTER})')

    def tearDown(self):
        self._drop()
        super().tearDown()

    def _drop(self):
        from seerdb.common.exceptions import DatabaseError

        for stmt in (
            f'DROP TABLE {self.TABLE}',
            f'DROP TYPE {self.OUTER}',
            f'DROP TYPE {self.ARR}',
            f'DROP TYPE {self.SUB}',
        ):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass  # best-effort teardown of leftovers

    def _shape(self, o):
        return (
            int(o.ID),
            (int(o.SUB.N), o.SUB.S) if o.SUB is not None else None,
            [(int(e.N), e.S) for e in o.SUBS.aslist()] if o.SUBS is not None else None,
        )

    def test_a_nested_attribute_fetches(self):
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, {self.OUTER}(1, {self.SUB}(7, 'seven'), "
            f"{self.ARR}({self.SUB}(1, 'a'), {self.SUB}(2, 'b'))))"
        )
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (2, {self.OUTER}(2, NULL, NULL))'
        )
        self.cur.execute(f'SELECT o FROM {self.TABLE} ORDER BY k')
        rows = [self._shape(o) for (o,) in self.cur.fetchall()]
        self.assertEqual(
            rows, [(1, (7, 'seven'), [(1, 'a'), (2, 'b')]), (2, None, None)]
        )

    @_requires(_OBJECT_BIND)
    def test_a_nested_attribute_binds_and_returns(self):
        sub = self.conn.gettype(self.SUB)
        outer = self.conn.gettype(self.OUTER)
        arr = self.conn.gettype(self.ARR)
        obj = outer.newobject(
            {
                'ID': 3,
                'SUB': sub.newobject({'N': 9, 'S': 'nine'}),
                'SUBS': arr.newobject([sub.newobject({'N': 4, 'S': 'd'})]),
            }
        )
        out = self.cur.var(outer)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (3, :1) RETURNING o INTO :2', [obj, out]
        )
        (returned,) = out.getvalue()
        self.assertEqual(self._shape(returned), (3, (9, 'nine'), [(4, 'd')]))
        self.cur.execute(f'SELECT o FROM {self.TABLE} WHERE k = 3')
        self.assertEqual(
            self._shape(self.cur.fetchone()[0]), (3, (9, 'nine'), [(4, 'd')])
        )


@_requires(_OBJECT_BIND)
@unittest.skipUnless(_USER, _SKIP_REASON)
class ObjectTimeZoneAttributeIntegration(_IntegrationBase):
    # An object whose attribute is TIMESTAMP WITH TIME ZONE binds and returns
    # with the offset it was entered at. The Mirror-over-PG stores that type as
    # a composite of its own, which its object support once took for a nested
    # object type and refused (#1134).
    TYPE = 'PYO_TSTZ_ATTR_T'

    def setUp(self):
        super().setUp()
        from seerdb.common.exceptions import DatabaseError

        for stmt in (f'DROP TABLE {self.TABLE}', f'DROP TYPE {self.TYPE}'):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass  # best-effort teardown of leftovers
        self.cur.execute(
            f'CREATE TYPE {self.TYPE} AS OBJECT (id NUMBER, ts TIMESTAMP WITH TIME ZONE)'
        )
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, o {self.TYPE})')

    def tearDown(self):
        from seerdb.common.exceptions import DatabaseError

        for stmt in (f'DROP TABLE {self.TABLE}', f'DROP TYPE {self.TYPE}'):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass
        super().tearDown()

    def test_the_attribute_keeps_its_offset(self):
        import datetime

        entered = datetime.datetime(
            2026, 9, 25, 1, 2, 3, tzinfo=datetime.timezone(datetime.timedelta(hours=2))
        )
        typ = self.conn.gettype(self.TYPE)
        obj = typ.newobject()
        obj.ID = 1
        obj.TS = entered
        out = self.cur.var(typ)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} (n, o) VALUES (1, :obj) '
            'RETURNING o INTO :outObj',
            [obj, out],
        )
        (returned,) = out.getvalue()
        self.assertEqual(returned.TS, entered)
        self.assertEqual(returned.TS.utcoffset(), datetime.timedelta(hours=2))
        self.cur.execute(f'SELECT o FROM {self.TABLE}')
        (fetched,) = self.cur.fetchone()
        self.assertEqual(fetched.TS, entered)
        self.assertEqual(fetched.TS.utcoffset(), datetime.timedelta(hours=2))


@unittest.skipUnless(_USER, _SKIP_REASON)
@_requires(_REAL_SERVER_READS, _GRID_10G)
class TemporalBindGridIntegration(_IntegrationBase):
    """Every cell of the temporal bind grid, as the server reads it (#1338).

    tests/test_temporal_bind_grid.py checks the bytes each cell sends; this
    checks what they mean to a real server. Each value is bound in its cell's
    context and the server prints what it received with TO_CHAR, to the
    microsecond and the offset, for comparison with what the value should
    mean (``expected_text`` in temporal_bind_grid). A Mirror leg is skipped:
    the question is what Oracle reads."""

    TABLE = _grid.OBJECT_TYPE_PREFIX + 'T'

    def setUp(self):
        super().setUp()
        # A LOCAL TIME ZONE bind is an instant in the database's zone (#1222);
        # printed in that zone too, it reads back as the wall clock sent.
        self.cur.execute('ALTER SESSION SET TIME_ZONE = DBTIMEZONE')
        self._drop_types()
        columns = ', '.join(f'{Short} {Sql}' for Sql, Short in _grid.SQL_TYPE.values())
        self.cur.execute(f'CREATE TABLE {self.TABLE} (K NUMBER, {columns})')
        # Where the session binds an object: 12.1+, or 11g's native form (#2463).
        if _target_of(self.conn).object_binds:
            for declared, (sql_type, _short) in _grid.SQL_TYPE.items():
                self.cur.execute(
                    f'CREATE TYPE {_grid.object_type_name(declared)} AS OBJECT (A {sql_type})'
                )

    def tearDown(self):
        self._drop_types()
        super().tearDown()

    def _drop_types(self):
        with self.conn.cursor() as cur:
            for declared in _grid.SQL_TYPE:
                try:
                    cur.execute(f'DROP TYPE {_grid.object_type_name(declared)} FORCE')
                except seerdb.DatabaseError:
                    pass  # not created yet

    def _each(self, context, read):
        # Every cell of `context` that seerdb sends right, through `read`, which
        # binds the cell's values and returns the server's TO_CHAR of each. The
        # mismatches are collected and compared at the end, so one run reports
        # every cell that is wrong.
        wrong = {}
        for cell in _grid.cells():
            if cell.context != context or _grid.gap(cell, 'server') is not None:
                continue
            values = cell.values
            fmt = _grid.TO_CHAR_FORMAT[_grid.kind(cell, values[0])]
            if cell.seerdb_only and cell.declared == 'DB_TYPE_TIMESTAMP_TZ':
                # A date before year 1 has no time zone rules to apply.
                expected: object = 'DataError'
            else:
                expected = [_grid.expected_text(cell, V) for V in values]
            try:
                got: object = read(cell, fmt)
            except seerdb.DataError:
                got = 'DataError'
            if got != expected:
                wrong[cell.key] = (got, expected)
        self.assertEqual(wrong, {})

    def _declared(self, cell):
        return getattr(seerdb, cell.declared) if cell.declared else None

    def test_execute(self):
        def read(cell, fmt):
            declared = self._declared(cell)
            if declared is not None:
                self.cur.setinputsizes(declared)
            self.cur.execute(f"SELECT TO_CHAR(:b, '{fmt}') FROM dual", cell.values)
            return [self.cur.fetchone()[0]]

        self._each('execute', read)

    def _read_executemany(self, cell, fmt):
        column = _grid.SQL_TYPE[_grid.kind(cell, cell.values[0])][1]
        self.cur.execute(f'DELETE FROM {self.TABLE}')
        declared = self._declared(cell)
        if declared is not None:
            self.cur.setinputsizes(None, declared)
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} (K, {column}) VALUES (:k, :b)',
            [[K, V] for K, V in enumerate(cell.values)],
        )
        self.cur.execute(
            f"SELECT TO_CHAR({column}, '{fmt}') FROM {self.TABLE} ORDER BY K"
        )
        return [R[0] for R in self.cur.fetchall()]

    def test_executemany(self):
        self._each('executemany', self._read_executemany)

    def test_executemany_mixed_widths(self):
        self._each('executemany_mixed', self._read_executemany)

    @_requires(_OBJECT_BIND)
    def test_object_attribute(self):

        def read(cell, fmt):
            name = _grid.object_type_name(cell.declared)
            obj = self.conn.gettype(name).newobject()
            obj.A = cell.values[0]
            out = self.cur.var(str)
            self.cur.execute(
                f"DECLARE o {name} := :b; BEGIN :r := TO_CHAR(o.A, '{fmt}'); END;",
                [obj, out],
            )
            return [out.getvalue()]

        self._each('object', read)

    def test_in_out(self):
        def read(cell, fmt):
            var = self.cur.var(self._declared(cell))
            var.setvalue(0, cell.values[0])
            out = self.cur.var(str)
            # Written as well as read, so the bind is IN OUT; NULL, as a value
            # before year 1 cannot come back as a datetime.
            self.cur.execute(
                f"BEGIN :r := TO_CHAR(:b, '{fmt}'); :b := NULL; END;", [out, var]
            )
            return [out.getvalue()]

        self._each('inout', read)


@unittest.skipUnless(_USER, _SKIP_REASON)
class CollectionTypeIntegration(_IntegrationBase):
    """VARRAY and nested-table types: described, fetched and bound (#1206)."""

    ELEM = 'PYO_COLL_ELEM_T'
    NUMS = 'PYO_COLL_NUMS_T'
    ELEMS = 'PYO_COLL_ELEMS_T'
    TABLE = 'PYO_COLL_TAB'

    def setUp(self):
        super().setUp()
        self._drop()
        self.cur.execute(
            f'CREATE TYPE {self.ELEM} AS OBJECT (id NUMBER, name VARCHAR2(40))'
        )
        self.cur.execute(f'CREATE TYPE {self.NUMS} AS VARRAY(3) OF NUMBER')
        self.cur.execute(f'CREATE TYPE {self.ELEMS} AS TABLE OF {self.ELEM}')

    def tearDown(self):
        self._drop()
        super().tearDown()

    def _drop(self):
        from seerdb.common.exceptions import DatabaseError

        for stmt in (
            f'DROP TABLE {self.TABLE}',
            f'DROP TYPE {self.ELEMS}',
            f'DROP TYPE {self.NUMS}',
            f'DROP TYPE {self.ELEM}',
        ):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass  # best-effort teardown of leftovers

    def test_gettype_describes_a_collection(self):
        from seerdb.common.dbobject import COLLECTION_NESTED_TABLE, COLLECTION_VARRAY

        nums = self.conn.gettype(self.NUMS)
        self.assertTrue(nums.is_collection)
        self.assertEqual(
            (nums.collection_type, nums.max_elements, nums.element['type_name']),
            (COLLECTION_VARRAY, 3, 'NUMBER'),
        )
        elems = self.conn.gettype(self.ELEMS)
        self.assertEqual(elems.collection_type, COLLECTION_NESTED_TABLE)
        self.assertEqual(elems.element['object_type'].name, self.ELEM)
        # As python-oracledb describes them (#1490): a collection's element type,
        # a DB_TYPE_* or the element's own type, and an object's attributes.
        self.assertTrue(nums.iscollection)
        self.assertIs(nums.element_type, seerdb.DB_TYPE_NUMBER)
        self.assertEqual(elems.element_type.name, self.ELEM)
        elem = self.conn.gettype(self.ELEM)
        self.assertFalse(elem.iscollection)
        self.assertIsNone(elem.element_type)
        self.assertEqual(
            [
                (a.name, a.type, a.precision, a.scale, a.max_size)
                for a in elem.attributes
            ],
            [
                ('ID', seerdb.DB_TYPE_NUMBER, 0, -127, None),
                ('NAME', seerdb.DB_TYPE_VARCHAR, None, None, 40),
            ],
        )
        self.assertEqual(elem(None).ID, None)

    def test_gettype_lists_each_attributes_metadata(self):
        # Each attribute's type, precision, scale and maximum size, as
        # python-oracledb lists them -- measured against it on 18c, 21c and 23ai
        # (#1490). A CHAR-semantics VARCHAR2 is 4n bytes where ALL_TYPE_ATTRS
        # says so (CHAR_USED, 11g on); elsewhere it reads as BYTE.
        meta = 'PYO_COLL_META_T'
        try:
            self.cur.execute(f'DROP TYPE {meta}')
        except seerdb.DatabaseError:
            pass  # no leftover from a prior run
        self.cur.execute(
            f'CREATE TYPE {meta} AS OBJECT (n NUMBER, n92 NUMBER(9,2), f FLOAT, '
            'i INTEGER, r REAL, v VARCHAR2(20), vc VARCHAR2(10 CHAR), c CHAR(3), '
            'nv NVARCHAR2(5), rw RAW(16), d DATE, ts3 TIMESTAMP(3), cl CLOB, '
            f'o {self.ELEM}, a {self.NUMS})'
        )
        try:
            # Whether ALL_TYPE_ATTRS says how a character attribute was declared:
            # 11g on, and not yet the Mirror over PostgreSQL (#1573).
            try:
                self.cur.execute('SELECT char_used FROM all_type_attrs WHERE 1 = 0')
                char_semantics = True
            except seerdb.DatabaseError:
                char_semantics = False
            typ = self.conn.gettype(meta)
            self.assertEqual(
                [
                    (a.name, a.type, a.precision, a.scale, a.max_size)
                    for a in typ.attributes[:13]
                ],
                [
                    ('N', seerdb.DB_TYPE_NUMBER, 0, -127, None),
                    ('N92', seerdb.DB_TYPE_NUMBER, 9, 2, None),
                    ('F', seerdb.DB_TYPE_NUMBER, 126, -127, None),
                    ('I', seerdb.DB_TYPE_NUMBER, 38, 0, None),
                    ('R', seerdb.DB_TYPE_NUMBER, 63, -127, None),
                    ('V', seerdb.DB_TYPE_VARCHAR, None, None, 20),
                    (
                        'VC',
                        seerdb.DB_TYPE_VARCHAR,
                        None,
                        None,
                        40 if char_semantics else 10,
                    ),
                    ('C', seerdb.DB_TYPE_CHAR, None, None, 3),
                    ('NV', seerdb.DB_TYPE_NVARCHAR, None, None, 10),
                    ('RW', seerdb.DB_TYPE_RAW, None, None, 16),
                    ('D', seerdb.DB_TYPE_DATE, None, None, None),
                    ('TS3', seerdb.DB_TYPE_TIMESTAMP, 0, 3, None),
                    ('CL', seerdb.DB_TYPE_CLOB, None, None, None),
                ],
            )
            self.assertEqual(
                [(a.name, a.type.name) for a in typ.attributes[13:]],
                [('O', self.ELEM), ('A', self.NUMS)],
            )
        finally:
            self.cur.execute(f'DROP TYPE {meta}')

    def test_a_collection_value_fetches(self):
        # A VARRAY of NUMBER and a nested table of objects, filled, empty and
        # NULL: an empty collection is a value, not NULL.
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, v {self.NUMS}, w {self.ELEMS}) '
            f'NESTED TABLE w STORE AS {self.TABLE}_W'
        )
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (1, {self.NUMS}(5, 10, 15), '
            f"{self.ELEMS}({self.ELEM}(1, 'a'), {self.ELEM}(2, 'b')))"
        )
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (2, {self.NUMS}(), NULL)')
        self.cur.execute(f'SELECT v, w FROM {self.TABLE} ORDER BY id')
        (v1, w1), (v2, w2) = self.cur.fetchall()
        self.assertEqual([int(x) for x in v1.aslist()], [5, 10, 15])
        self.assertEqual(
            [(int(e.ID), e.NAME) for e in w1.aslist()], [(1, 'a'), (2, 'b')]
        )
        self.assertEqual((v2.aslist(), w2), ([], None))

    def test_a_collection_value_from_a_constructor_in_the_select_list(self):
        # A constructor computed in the select list, not read from a column. The
        # Mirror over PostgreSQL described it by its domain's base type, a bare
        # numeric array, and refused it as an unsupported type (#1473).
        self.cur.execute(f'SELECT {self.NUMS}(5, 10, 15), {self.NUMS}(7) c FROM dual')
        ((three, one),) = self.cur.fetchall()
        self.assertEqual([int(x) for x in three.aslist()], [5, 10, 15])
        self.assertEqual([int(x) for x in one.aslist()], [7])

    def test_a_collection_value_describes_as_db_type_object(self):
        # An object or collection column's type_code is DB_TYPE_OBJECT, as
        # python-oracledb reports it -- not the bare wire code 109 (#1478).
        self.cur.execute(f'SELECT {self.NUMS}(1, 2) FROM dual')
        self.assertIs(self.cur.description[0][1], seerdb.DB_TYPE_OBJECT)

    @_requires(_postgres_cannot('serve BFILE or XMLType'))
    def test_a_collection_value_of_bfile_or_xmltype_describes_as_its_dbtype(self):
        # A BFILE's type_code is DB_TYPE_BFILE and an XMLType's -- an object of
        # type SYS.XMLTYPE on the wire -- DB_TYPE_XMLTYPE, not 114 and 109 (#1478).
        self.cur.execute("SELECT bfilename('X', 'y'), sys.xmltype('<a/>') FROM dual")
        self.assertEqual(
            [d[1] for d in self.cur.description],
            [seerdb.DB_TYPE_BFILE, seerdb.DB_TYPE_XMLTYPE],
        )

    def test_a_collection_value_from_a_one_element_constructor(self):
        # A constructor with one string literal builds a one-element collection,
        # a national literal too. The Mirror over PostgreSQL read `t('a')` as a
        # cast of the literal to the type: malformed array literal (#1435).
        words = f'{self.TABLE}_W_T'
        self.cur.execute(f'CREATE TYPE {words} AS TABLE OF VARCHAR2(10)')
        try:
            self.cur.execute(
                f'CREATE TABLE {self.TABLE} (id NUMBER, v {words}) '
                f'NESTED TABLE v STORE AS {self.TABLE}_V'
            )
            for k, value in ((1, "('a')"), (2, "(N'z')"), (3, "('it''s')")):
                self.cur.execute(
                    f'INSERT INTO {self.TABLE} VALUES ({k}, {words}{value})'
                )
            self.cur.execute(f'SELECT v FROM {self.TABLE} ORDER BY id')
            self.assertEqual(
                [v.aslist() for (v,) in self.cur.fetchall()], [['a'], ['z'], ["it's"]]
            )
        finally:
            self._drop()
            self.cur.execute(f'DROP TYPE {words}')

    @_requires(_OBJECT_BIND)
    def test_a_collection_value_binds(self):
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, v {self.NUMS}, w {self.ELEMS}) '
            f'NESTED TABLE w STORE AS {self.TABLE}_W'
        )
        nums = self.conn.gettype(self.NUMS)
        elems = self.conn.gettype(self.ELEMS)
        elem = self.conn.gettype(self.ELEM)
        filled = elems.newobject(
            [
                elem.newobject({'ID': 1, 'NAME': 'a'}),
                elem.newobject({'ID': 2, 'NAME': 'b'}),
            ]
        )
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (1, :1, :2)',
            [nums.newobject([5, 10, 15]), filled],
        )
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (2, :1, NULL)', [nums.newobject()]
        )
        self.cur.execute(f'SELECT v, w FROM {self.TABLE} ORDER BY id')
        (v1, w1), (v2, w2) = self.cur.fetchall()
        self.assertEqual([int(x) for x in v1.aslist()], [5, 10, 15])
        self.assertEqual(
            [(int(e.ID), e.NAME) for e in w1.aslist()], [(1, 'a'), (2, 'b')]
        )
        self.assertEqual((v2.aslist(), w2), ([], None))


@_requires(_OBJECT_BIND)
@unittest.skipUnless(_USER, _SKIP_REASON)
class ObjectLocalTimeZoneAttributeIntegration(_IntegrationBase):
    # An object's TIMESTAMP WITH LOCAL TIME ZONE attribute binds and returns as
    # the time it was given. The Mirror-over-PG described one as WITH TIME ZONE
    # and wrapped the value in its WITH TIME ZONE composite, which PostgreSQL
    # refused (#1270).
    TYPE = 'PYO_LTZ_ATTR_T'
    TABLE = 'PYO_LTZ_ATTR_TAB'

    def setUp(self):
        super().setUp()
        self._drop()
        self.cur.execute(
            f'CREATE TYPE {self.TYPE} AS OBJECT '
            '(id NUMBER, ts TIMESTAMP WITH LOCAL TIME ZONE)'
        )
        self.cur.execute(f'CREATE TABLE {self.TABLE} (n NUMBER, o {self.TYPE})')

    def tearDown(self):
        self._drop()
        super().tearDown()

    def _drop(self):
        from seerdb.common.exceptions import DatabaseError

        for stmt in (f'DROP TABLE {self.TABLE}', f'DROP TYPE {self.TYPE}'):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass  # best-effort teardown of leftovers

    def test_a_local_time_zone_attribute_round_trips(self):
        import datetime

        given = datetime.datetime(2026, 9, 27, 13, 14, 15)
        typ = self.conn.gettype(self.TYPE)
        self.assertEqual(typ.attrs[1]['type_name'], 'TIMESTAMP WITH LOCAL TZ')
        out = self.cur.var(typ)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (1, :1) RETURNING o INTO :2',
            [typ.newobject({'ID': 1, 'TS': given}), out],
        )
        (returned,) = out.getvalue()
        self.assertEqual(returned.TS.replace(tzinfo=None), given)
        self.cur.execute(f'SELECT o FROM {self.TABLE}')
        (fetched,) = self.cur.fetchone()
        self.assertEqual(fetched.TS.replace(tzinfo=None), given)


@unittest.skipUnless(_USER, _SKIP_REASON)
class CollectionOfCollectionsIntegration(_IntegrationBase):
    """A nested table and a VARRAY whose elements are nested tables, the shapes
    the reference suite's NestedCollectionTests uses (#1276): fetched and bound,
    a NULL and an empty inner collection included."""

    INNER = 'PYO_COC_INNER_T'
    TABLE_OF = 'PYO_COC_TT'
    VARRAY_OF = 'PYO_COC_VT'
    TABLE = 'PYO_COC_TAB'

    def setUp(self):
        super().setUp()
        self._drop()
        self.cur.execute(f'CREATE TYPE {self.INNER} AS TABLE OF NUMBER')
        self.cur.execute(f'CREATE TYPE {self.TABLE_OF} AS TABLE OF {self.INNER}')
        self.cur.execute(f'CREATE TYPE {self.VARRAY_OF} AS VARRAY(5) OF {self.INNER}')
        self.cur.execute(
            f'CREATE TABLE {self.TABLE} (id NUMBER, tc {self.TABLE_OF}, '
            f'vc {self.VARRAY_OF}) NESTED TABLE tc STORE AS {self.TABLE}_NT '
            f'(NESTED TABLE COLUMN_VALUE STORE AS {self.TABLE}_NTI)'
        )

    def tearDown(self):
        self._drop()
        super().tearDown()

    def _drop(self):
        from seerdb.common.exceptions import DatabaseError

        for stmt in (
            f'DROP TABLE {self.TABLE}',
            f'DROP TYPE {self.VARRAY_OF}',
            f'DROP TYPE {self.TABLE_OF}',
            f'DROP TYPE {self.INNER}',
        ):
            try:
                self.cur.execute(stmt)
            except DatabaseError:
                pass  # best-effort teardown of leftovers

    @staticmethod
    def _lists(value):
        if value is None:
            return None
        return [
            None if e is None else [int(x) for x in e.aslist()] for e in value.aslist()
        ]

    def test_a_collection_of_collections_fetches(self):
        i, tt, vt = self.INNER, self.TABLE_OF, self.VARRAY_OF
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (1, '
            f'{tt}({i}(1, 2), {i}(3), NULL, {i}()), {vt}({i}(4)))'
        )
        self.cur.execute(f'SELECT tc, vc FROM {self.TABLE}')
        (tc, vc) = self.cur.fetchone()
        self.assertEqual(
            (self._lists(tc), self._lists(vc)), ([[1, 2], [3], None, []], [[4]])
        )

    @_requires(_OBJECT_BIND)
    def test_a_collection_of_collections_binds(self):
        inner = self.conn.gettype(self.INNER)
        tt = self.conn.gettype(self.TABLE_OF)
        vt = self.conn.gettype(self.VARRAY_OF)
        self.cur.execute(
            f'INSERT INTO {self.TABLE} VALUES (2, :1, :2)',
            [
                tt.newobject([inner.newobject([5, 6]), None, inner.newobject()]),
                vt.newobject([inner.newobject([7])]),
            ],
        )
        self.cur.execute(f'SELECT tc, vc FROM {self.TABLE} WHERE id = 2')
        (tc, vc) = self.cur.fetchone()
        self.assertEqual(
            (self._lists(tc), self._lists(vc)), ([[5, 6], None, []], [[7]])
        )


@unittest.skipUnless(_USER, _SKIP_REASON)
class RefBindIntegration(_IntegrationBase):
    # REF bind (#139): fetch a REF for a row object, bind it back into an INSERT
    # and into DEREF(?), and confirm it round-trips to the original object. REF
    # decode works on all tiers (#119), but the bind needs the 12c+ OAC — pre-12c
    # raises NotSupportedError, so the test skips there.
    TYPE = 'PYORACLE_REF_PERSON'
    PEOPLE = 'PYORACLE_REF_PEOPLE'
    REFS = 'PYORACLE_REF_REFS'

    def _setup_schema(self):
        from seerdb.common.exceptions import DatabaseError

        for s in (
            f'DROP TABLE {self.REFS}',
            f'DROP TABLE {self.PEOPLE}',
            f'DROP TYPE {self.TYPE}',
        ):
            try:
                self.cur.execute(s)
            except DatabaseError:
                # best-effort teardown of leftover objects
                pass
        self.cur.execute(
            f'CREATE TYPE {self.TYPE} AS OBJECT (id NUMBER, name VARCHAR2(40))'
        )
        self.cur.execute(f'CREATE TABLE {self.PEOPLE} OF {self.TYPE}')
        self.cur.execute(f"INSERT INTO {self.PEOPLE} VALUES (1, 'Alice')")
        self.cur.execute(f'CREATE TABLE {self.REFS} (id NUMBER, r REF {self.TYPE})')

    def tearDown(self):
        try:
            cleanup = self.conn.cursor()
            for s in (
                f'DROP TABLE {self.REFS}',
                f'DROP TABLE {self.PEOPLE}',
                f'DROP TYPE {self.TYPE}',
            ):
                try:
                    cleanup.execute(s)
                except Exception:
                    # best-effort teardown of leftover objects
                    pass
            cleanup.close()
        finally:
            super().tearDown()

    @_requires(_REF_BIND)
    def test_ref_bind_roundtrip(self):
        self._setup_schema()
        self.cur.execute(f'SELECT REF(p) FROM {self.PEOPLE} p WHERE p.id = 1')
        ref = self.cur.fetchone()[0]
        self.assertEqual(ref.type_name, self.TYPE)
        # Bind into an INSERT, then DEREF the stored REF back to the object.
        self.cur.execute(f'INSERT INTO {self.REFS} (id, r) VALUES (:1, :2)', [100, ref])
        self.cur.execute(f'SELECT id, DEREF(r).name FROM {self.REFS} WHERE id = 100')
        self.assertEqual(self.cur.fetchone(), (100, 'Alice'))
        # Bind into DEREF directly.
        self.cur.execute('SELECT DEREF(:1).name FROM dual', [ref])
        self.assertEqual(self.cur.fetchone(), ('Alice',))


@unittest.skipUnless(_USER, _SKIP_REASON)
class PipelineIntegration(_IntegrationBase):
    # Request pipelining (#132). Runs on every tier (serial execution); the
    # API, ordering and results match a single-round-trip pipelined run.
    def test_pipeline_runs_all_ops(self):
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(20))')
        p = seerdb.create_pipeline()
        p.add_execute(f"INSERT INTO {self.TABLE} VALUES (1, 'a')")
        p.add_executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1, :2)', [(2, 'b'), (3, 'c')]
        )
        p.add_commit()
        p.add_fetchall(f'SELECT id, name FROM {self.TABLE} ORDER BY id')
        p.add_fetchone(f'SELECT COUNT(*) FROM {self.TABLE}')
        results = self.conn.run_pipeline(p)
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r.error is None for r in results))
        self.assertEqual(results[3].rows, [(1, 'a'), (2, 'b'), (3, 'c')])
        self.assertEqual(results[4].rows, [(3,)])

    def test_pipeline_continue_on_error(self):
        p = seerdb.create_pipeline()
        p.add_execute('SELECT * FROM a_table_that_does_not_exist')
        p.add_fetchone('SELECT 42 FROM dual')
        results = self.conn.run_pipeline(p, continue_on_error=True)
        self.assertIsNotNone(results[0].error)
        self.assertEqual(results[1].rows, [(42,)])

    def test_pipeline_abort_raises(self):
        p = seerdb.create_pipeline()
        p.add_execute('SELECT * FROM a_table_that_does_not_exist')
        p.add_fetchone('SELECT 42 FROM dual')
        with self.assertRaises(seerdb.DatabaseError):
            self.conn.run_pipeline(p)


@unittest.skipUnless(_USER, _SKIP_REASON)
class SessionlessTransactionIntegration(_ThrottleRetry, unittest.TestCase):
    # Sessionless transactions (#133, 23ai). A transaction is started on one
    # session, suspended, then resumed and committed on a *different* session.
    # Needs two connections with autocommit off, so it manages its own
    # connections rather than the single-connection _IntegrationBase. Skips
    # below 23ai (begin raises NotSupportedError at field version < 23.1).
    TABLE = 'PYORACLE_SL_TEST'

    def _conn(self):
        c = seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            **_FV_KW,
        )
        c.autocommit = False
        return c

    def setUp(self):
        from seerdb.common.exceptions import NotSupportedError

        self.conns = []
        setup = self._conn()
        self.conns.append(setup)
        # Probe support before creating anything, so a pre-23ai skip leaves no
        # table behind (#1224). A fresh id, rolled back while active: a probe
        # suspended under a fixed one outlived the test, and the next setUp's
        # begin of it is ORA-26217 once the client reports it (#1755).
        try:
            setup.begin_sessionless_transaction(timeout=10)
            setup.rollback()
        except NotSupportedError:
            # tearDown does not run after a skip in setUp: close the probe's
            # connection here, or it stays open until it is collected.
            setup.close()
            self.skipTest('sessionless transactions need a 23ai+ server')
        cur = setup.cursor()
        try:
            cur.execute(f'DROP TABLE {self.TABLE}')
        except seerdb.DatabaseError as e:
            if e.code != 942:
                raise
        cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        setup.commit()

    def tearDown(self):
        for c in self.conns:
            try:
                c.close()
            except Exception:
                # best-effort close; the test already passed/failed
                pass
        # The table the test made, on a fresh connection: the test's own may
        # hold a transaction open on it (#1224).
        with self._conn() as c:
            try:
                c.cursor().execute(f'DROP TABLE {self.TABLE}')
            except seerdb.DatabaseError as e:
                if e.code != 942:
                    raise

    def test_suspend_resume_commit_across_sessions(self):
        c1 = self._conn()
        self.conns.append(c1)
        tid = c1.begin_sessionless_transaction('sl-it-1', timeout=120)
        self.assertEqual(tid, b'sl-it-1')
        c1.cursor().execute(f'INSERT INTO {self.TABLE} VALUES (10)')
        c1.suspend_sessionless_transaction()

        # An outsider must not see the uncommitted, suspended row.
        obs = self._conn()
        self.conns.append(obs)
        ocur = obs.cursor()
        ocur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(ocur.fetchone()[0], 0)

        c2 = self._conn()
        self.conns.append(c2)
        c2.resume_sessionless_transaction('sl-it-1', timeout=120)
        c2.cursor().execute(f'INSERT INTO {self.TABLE} VALUES (20)')
        c2.commit()

        ocur.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        self.assertEqual(ocur.fetchall(), [(10,), (20,)])

    def test_rollback_discards_sessionless_work(self):
        c = self._conn()
        self.conns.append(c)
        c.begin_sessionless_transaction('sl-it-2', timeout=60)
        c.cursor().execute(f'INSERT INTO {self.TABLE} VALUES (99)')
        c.rollback()
        cur = c.cursor()
        cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(cur.fetchone()[0], 0)

    def test_server_refusals_are_raised(self):
        # The server's refusals reach the caller (#1755), with its own codes:
        # beginning an id that exists (ORA-26217), resuming one that does not
        # (ORA-26218) or is in use in another session (ORA-25351).
        held = self._conn()
        self.conns.append(held)
        held.begin_sessionless_transaction('sl-it-err', timeout=60)
        held.suspend_sessionless_transaction()
        other = self._conn()
        self.conns.append(other)
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            other.begin_sessionless_transaction('sl-it-err', timeout=60)
        self.assertEqual(ctx.exception.code, 26217)
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            other.resume_sessionless_transaction('sl-it-unknown', timeout=1)
        self.assertEqual(ctx.exception.code, 26218)
        active = self._conn()
        self.conns.append(active)
        active.resume_sessionless_transaction('sl-it-err', timeout=5)
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            other.resume_sessionless_transaction('sl-it-err', timeout=1)
        self.assertEqual(ctx.exception.code, 25351)
        active.rollback()

    def test_default_id_is_uuid_and_double_begin_rejected(self):
        c = self._conn()
        self.conns.append(c)
        tid = c.begin_sessionless_transaction(timeout=30)
        self.assertEqual(len(tid), 16)  # uuid4 bytes
        with self.assertRaises(seerdb.DatabaseError):
            c.begin_sessionless_transaction('other')  # already active
        c.suspend_sessionless_transaction()


_BFILE_TEST_FILE = 'pyoracle_bfile_test.txt'
_BFILE_TEST_CONTENT = b'hello bfile from disk'


@unittest.skipUnless(_USER, _SKIP_REASON)
class AsyncConnectionIntegration(_ThrottleRetry, unittest.IsolatedAsyncioTestCase):
    """Verify the async surface: connect_async, AsyncCursor, fetch
    flow, async iteration, context managers."""

    def _kwargs(self, **extra):
        return dict(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            # What the test asks for over the suite's settings (#2466).
            **{**_FV_KW, **extra},
        )

    async def asyncSetUp(self):
        # Skip the async tests whose feature Oracle 9i (fv2) lacks, mirroring
        # _IntegrationBase._skip_if_fv2_unsupported for this standalone async
        # class (#168). A quick connect just to learn the negotiated field
        # version, then close — the tests open their own connections.
        if _target_is_8i():
            # 8i is fv2 too but lacks more than 9i (CONNECT BY LEVEL, tracked
            # bugs #387/#388); layer its extra skips on top.
            Reason8i = _8i_skip_reason(self._testMethodName)
            if Reason8i is not None:
                self.skipTest(Reason8i)
        Reason = _fv2_skip_reason(self._testMethodName)
        if Reason is None:
            return
        Conn = await seerdb.connect_async(**self._kwargs())
        Fv = Conn.field_version
        await Conn.close()
        if Fv < FIELD_VERSION_10_2:
            self.skipTest(Reason)

    async def test_executemany_of_a_plsql_block(self):
        # Async twin of PlsqlExecutemanyIntegration (#2479).
        Table = 'PYO_ASYNC_BLOCK_MANY'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TABLE {Table}')
            except seerdb.DatabaseError:
                pass  # not there on a first run
            await Cur.execute(f'CREATE TABLE {Table} (n NUMBER)')
            try:
                await Cur.executemany(
                    f'BEGIN INSERT INTO {Table} VALUES (:1); END;', [(1,), (2,), (3,)]
                )
                await Cur.execute(f'SELECT n FROM {Table} ORDER BY n')
                self.assertEqual(await Cur.fetchall(), [(1,), (2,), (3,)])
            finally:
                await Cur.execute(f'DROP TABLE {Table}')
        finally:
            await Conn.close()

    async def test_output_type_handlers_and_fetch_decimals(self):
        # Async twin of TypeHandlerIntegration (#2458): the LOB is read with an
        # awaited read, on a statement the plain run before it cached.
        from seerdb.common.lob import LOB

        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Sql = "SELECT TO_CLOB('lob text'), 1.5 FROM dual"
            if Conn.field_version < FIELD_VERSION_10_2:
                Sql = "SELECT 'lob text', 1.5 FROM dual"
            for Handler in (None, _clob_as_text, None):
                Cur = Conn.cursor()
                Cur.outputtypehandler = Handler
                await Cur.execute(Sql)
                (Text, Number) = await Cur.fetchone()
                if isinstance(Text, LOB):
                    self.assertIsNone(Handler)
                    Text = await Text.aread()
                self.assertEqual((Text, Number), ('lob text', Decimal('1.5')))
            Conn.outputtypehandler = _number_as_text
            Cur = Conn.cursor()
            await Cur.execute('SELECT 7 FROM dual')
            self.assertEqual(await Cur.fetchone(), ('7',))
            Conn.outputtypehandler = None
            await Cur.execute('SELECT 7 FROM dual', fetch_decimals=True)
            self.assertEqual(await Cur.fetchone(), (Decimal(7),))
            # The input side.
            Conn.inputtypehandler = _point_as_text
            Cur = Conn.cursor()
            await Cur.execute('SELECT :1 FROM dual', [_Point(1, 2)])
            self.assertEqual(await Cur.fetchone(), ('1,2',))
            Cur.inputtypehandler = lambda cursor, value, num_elements: 5
            with self.assertRaises(seerdb.ProgrammingError):
                await Cur.execute('SELECT :1 FROM dual', [1])
        finally:
            await Conn.close()

    async def test_lob_reads_around_the_length_markers_come_back_whole(self):
        # Async twin of LOBReadLengthIntegration (#1970).
        Table = 'PYO_ASYNC_LOB_EDGE'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TABLE {Table}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(f'CREATE TABLE {Table} (id NUMBER, b BLOB, c CLOB)')
            Rows = [
                (n, b'x' * n, 'y' * min(n, 129)) for n in _LOB_EDGE_BLOB_LENGTHS
            ] + [(1000 + n, b'w', 'z' * n) for n in _LOB_EDGE_CLOB_LENGTHS]
            for Row in Rows:
                await Cur.execute(f'INSERT INTO {Table} VALUES (:1, :2, :3)', list(Row))
            for Fv in (None, FIELD_VERSION_11_2):
                Extra = {} if Fv is None else {'field_version': Fv}
                Kwargs = {**self._kwargs(), **Extra}
                Reader = await seerdb.connect_async(**Kwargs)
                try:
                    RCur = Reader.cursor()
                    await RCur.execute(f'SELECT id, b, c FROM {Table} ORDER BY id')
                    Got = []
                    for I, B, C in await RCur.fetchall():
                        # Before 10g a LOB column arrives as its value.
                        Values = []
                        for V in (B, C):
                            Values.append(await V.read() if hasattr(V, 'read') else V)
                        Got.append((I, *Values))
                finally:
                    await Reader.close()
                self.assertEqual(Got, Rows, f'field_version={Fv or "default"}')
            await Cur.execute(f'DROP TABLE {Table}')
        finally:
            await Conn.close()

    async def test_lastrowid_follows_the_touched_row(self):
        # Async twin of LastRowidIntegration (#1077).
        Table = 'PYO_ASYNC_LASTROWID'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TABLE {Table}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(f'CREATE TABLE {Table} (n NUMBER)')
            try:
                await Cur.execute(f'INSERT INTO {Table} VALUES (7)')
                Rowid = Cur.lastrowid
                self.assertIsNotNone(Rowid)
                # Which row it names, asked of the server (see LastRowidIntegration).
                await Cur.execute(f'SELECT n FROM {Table} WHERE ROWID = :1', [Rowid])
                self.assertEqual(await Cur.fetchone(), (7,))
            finally:
                await Cur.execute(f'DROP TABLE {Table}')
        finally:
            await Conn.close()

    async def test_a_clean_logoff_commits_the_open_transaction(self):
        # Async twin of test_a_clean_logoff_commits_the_open_transaction (#1429).
        Table = 'PYO_ASYNC_LOGOFF_COMMIT'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TABLE {Table}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(f'CREATE TABLE {Table} (k NUMBER)')
            try:
                Other = await seerdb.connect_async(**self._kwargs())
                try:
                    Other.autocommit = False
                    await Other.cursor().execute(f'INSERT INTO {Table} VALUES (1)')
                    Other.autocommit = True  # close() now skips its rollback
                finally:
                    await Other.close()
                await Cur.execute(f'SELECT k FROM {Table}')
                self.assertEqual(await Cur.fetchall(), [(1,)])
            finally:
                await Cur.execute(f'DROP TABLE {Table}')
        finally:
            await Conn.close()

    async def test_a_dml_touching_no_row_reports_no_rowid(self):
        # Async twin of ZeroRowDmlIntegration (#1078).
        Table = 'PYO_ASYNC_ZERO_ROW'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TABLE {Table}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(f'CREATE TABLE {Table} (n NUMBER)')
            try:
                await Cur.execute(f'INSERT INTO {Table} VALUES (2)')
                await Cur.execute(f'SELECT n FROM {Table}')
                await Cur.fetchall()
                await Cur.execute(f'DELETE FROM {Table} WHERE 1 = 0')
                self.assertEqual(Cur.rowcount, 0)
                self.assertIsNone(Cur.lastrowid)
            finally:
                await Cur.execute(f'DROP TABLE {Table}')
        finally:
            await Conn.close()

    async def test_the_version_is_the_release_the_banner_names(self):
        # Async twin of the sync test: its login reads the release too (#2278).
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute(
                "SELECT banner FROM v$version WHERE banner LIKE 'Oracle%'"
            )
            (banner,) = await Cur.fetchone()
            self.assertEqual(Conn.version, _release_of(banner, Conn.version))
        finally:
            await Conn.close()

    @_requires(_PING_ROUND_TRIP)
    async def test_ping_raises_on_a_killed_session(self):
        # Async twin of PingKilledSessionIntegration (#1095).
        if not _ADMIN_USER:
            self.skipTest('set SEERDB_TEST_ADMIN_USER (a DBA) to kill a session')
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute("SELECT SYS_CONTEXT('userenv', 'sid') FROM dual")
            _kill_session(int((await Cur.fetchone())[0]))
            with self.assertRaises(seerdb.DatabaseError):
                await Conn.ping()
        finally:
            try:
                await Conn.close()
            except Exception:  # noqa: BLE001 - the session is gone
                pass

    @_requires(_TEMP_LOB)
    async def test_createlob_binds_as_a_lob(self):
        # Async twin of CreateLobIntegration (#1066).
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            Text = 'async createlob \u3042 ' * 3000
            Nclob = await Conn.createlob(seerdb.DB_TYPE_NCLOB, Text)
            self.assertEqual(await Nclob.asize(), len(Text))
            await Cur.execute('SELECT DBMS_LOB.GETLENGTH(:1) FROM dual', [Nclob])
            self.assertEqual(await Cur.fetchone(), (len(Text),))
        finally:
            await Conn.close()

    async def test_select_into_with_no_rows_raises(self):
        # Async twin of the ORA-01403 tests (#1039).
        Table = 'PYO_ASYNC_NODATA'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TABLE {Table}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(f'CREATE TABLE {Table} (id NUMBER)')
            try:
                Got = Cur.var(int)
                with self.assertRaises(seerdb.DatabaseError) as ctx:
                    await Cur.execute(
                        f'BEGIN SELECT id INTO :1 FROM {Table} WHERE 1 = 0; END;',
                        [Got],
                    )
                self.assertEqual(ctx.exception.code, 1403)
                # A query matching nothing still raises nothing.
                await Cur.execute(f'SELECT id FROM {Table}')
                self.assertEqual(await Cur.fetchall(), [])
            finally:
                await Cur.execute(f'DROP TABLE {Table}')
        finally:
            await Conn.close()

    async def test_a_session_below_the_server_release_keeps_the_message(self):
        # Async twin of ErrorAndRowcountIntegration's (#1145).
        Conn = await seerdb.connect_async(
            **{**self._kwargs(), 'field_version': FIELD_VERSION_12_2}
        )
        try:
            if Conn._server_field_version() < FIELD_VERSION_20_1:
                self.skipTest('the server predates 20.1, so it sends no such fields')
            with self.assertRaises(seerdb.DatabaseError) as ctx:
                await Conn.cursor().execute("SELECT TO_NUMBER('x') FROM dual")
            self.assertEqual(ctx.exception.code, 1722)
            self.assertIn('ORA-01722', str(ctx.exception))
        finally:
            await Conn.close()

    async def test_a_query_may_start_with_a_comment(self):
        # Async twin of CursorIntegration's.
        Table = 'PYO_ASYNC_LEADING_COMMENT'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await self._drop_async(Cur, Table)
            await Cur.execute(f'CREATE TABLE {Table} (n NUMBER(9, 2))')
            await Cur.execute(f'/* one row */ INSERT INTO {Table} VALUES (2.5)')
            await Cur.execute(f'/* leading */ SELECT n FROM {Table}')
            self.assertEqual(float((await Cur.fetchone())[0]), 2.5)
            await self._drop_async(Cur, Table)
        finally:
            await Conn.close()

    async def test_a_ddl_statement_may_start_with_a_comment(self):
        # Async twin of CursorIntegration's.
        Table = 'PYO_ASYNC_COMMENTED_DDL'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await self._drop_async(Cur, Table)
            await Cur.execute(
                f'-- made by a script\nCREATE TABLE {Table} (n NUMBER(9, 2))'
            )
            await Cur.execute(f'INSERT INTO {Table} VALUES (2.5)')
            await Cur.execute(f'SELECT n FROM {Table}')
            self.assertEqual(float((await Cur.fetchone())[0]), 2.5)
            await self._drop_async(Cur, Table)
        finally:
            await Conn.close()

    async def test_a_view_may_be_replaced_with_different_column_types(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        View = 'PYO_ASYNC_REPLACED_VIEW'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(
                    f'CREATE OR REPLACE VIEW {View} AS SELECT 1 AS c FROM dual'
                )
            except DatabaseError as exc:
                if exc.code == 1031:  # ORA-01031: the suite needs no CREATE VIEW
                    self.skipTest('the test user lacks the CREATE VIEW privilege')
                raise
            try:
                await Cur.execute(
                    f"CREATE OR REPLACE VIEW {View} AS SELECT 'x' AS c FROM dual"
                )
                await Cur.execute(f'SELECT c FROM {View}')
                self.assertEqual(await Cur.fetchone(), ('x',))
            finally:
                await Cur.execute(f'DROP VIEW {View}')
        finally:
            await Conn.close()

    async def test_returning_into_inside_a_plsql_block(self):
        # Async twin of CursorIntegration's.
        Table = 'PYO_ASYNC_BLOCK_RETURNING'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await self._drop_async(Cur, Table)
            await Cur.execute(f'CREATE TABLE {Table} (id NUMBER, n NUMBER)')
            await Cur.execute(f'INSERT INTO {Table} VALUES (1, 10)')
            block = (
                f'BEGIN UPDATE {Table} SET n = :1 WHERE id = :2 '
                'RETURNING n INTO :3; END;'
            )
            out = Cur.var(int)
            await Cur.execute(block, [20, 1, out])
            self.assertEqual(out.getvalue(), 20)
            out = Cur.var(int)
            await Cur.execute(block, [30, 2, out])
            self.assertIsNone(out.getvalue())
            await self._drop_async(Cur, Table)
        finally:
            await Conn.close()

    async def test_the_session_id_is_the_sid_sql_reports(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                try:
                    await Cur.execute("SELECT sys_context('userenv', 'sid') FROM dual")
                except DatabaseError as exc:
                    if exc.code == 2003:
                        self.skipTest('no USERENV SID before 10g')
                    raise
                (sid,) = await Cur.fetchone()
                self.assertIsInstance(Conn.session_id, int)
                self.assertIsInstance(Conn.serial_num, int)
                self.assertEqual(Conn.session_id, int(sid))
                await Cur.execute(
                    'SELECT dbms_debug_jdwp.current_session_id, '
                    'dbms_debug_jdwp.current_session_serial FROM dual'
                )
                self.assertEqual(
                    await Cur.fetchone(), (Conn.session_id, Conn.serial_num)
                )

    async def test_transaction_priority(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import NotSupportedError

        P = seerdb.TransactionPriority
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if not Conn._supports_txn_priority():
                with self.assertRaises(NotSupportedError):
                    Conn.transaction_priority
                with self.assertRaises(NotSupportedError):
                    await seerdb.connect_async(
                        **self._kwargs(), transaction_priority='low'
                    )
                return
            default = Conn.transaction_priority
            self.assertIsInstance(default, P)
            Conn.transaction_priority = 'low'
            await Conn.ping()
            self.assertIs(Conn.transaction_priority, P.LOW)
            Conn.transaction_priority = None
            await Conn.ping()
            self.assertIs(Conn.transaction_priority, default)
            async with Conn.cursor() as Cur:
                await Cur.execute('ALTER SESSION SET TXN_PRIORITY = MEDIUM')
            self.assertIs(Conn.transaction_priority, P.MEDIUM)
        async with await seerdb.connect_async(
            **self._kwargs(), transaction_priority=P.LOW
        ) as Conn:
            self.assertIs(Conn.transaction_priority, P.LOW)

    async def test_app_context_rides_the_next_call(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError, NotSupportedError
        from seerdb.common.tns_consts import FIELD_VERSION_10_2

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_10_2:
                with self.assertRaises(NotSupportedError):
                    Conn.set_app_context('CLIENTCONTEXT', ATTR1='VALUE1')
                return
            query = (
                "SELECT sys_context('CLIENTCONTEXT', 'ATTR1'), "
                "sys_context('CLIENTCONTEXT', 'ATTR2') FROM dual"
            )
            async with Conn.cursor() as Cur:
                Conn.set_app_context('CLIENTCONTEXT', ATTR1='VALUE1')
                Conn.set_app_context('CLIENTCONTEXT', ATTR2='VALUE2')
                await Cur.execute(query)
                self.assertEqual(await Cur.fetchone(), ('VALUE1', 'VALUE2'))
                Conn.clear_app_context('CLIENTCONTEXT')
                await Cur.execute(query)
                self.assertEqual(await Cur.fetchone(), (None, None))
                Conn.set_app_context('CLIENTCONTEXT', ATTR1='PING')
                await Conn.ping()
                await Cur.execute(query)
                self.assertEqual(await Cur.fetchone(), ('PING', None))
                Conn.set_app_context('NOT_A_VALID_NAMESPACE', attr='value')
                with self.assertRaises(DatabaseError) as raised:
                    await Conn.ping()
                self.assertEqual(raised.exception.code, 28267)
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))

    async def test_a_refused_commit_raises(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        table = 'SEERDB_DEFER_A'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, table)
                await Cur.execute(
                    f'CREATE TABLE {table} (id NUMBER CONSTRAINT {table}_PK '
                    'PRIMARY KEY DEFERRABLE INITIALLY DEFERRED)'
                )
                try:
                    Conn.autocommit = False
                    await Cur.execute(f'INSERT INTO {table} VALUES (1)')
                    await Cur.execute(f'INSERT INTO {table} VALUES (1)')
                    with self.assertRaises(DatabaseError) as raised:
                        await Conn.commit()
                    self.assertEqual(raised.exception.code, 2091)
                    await Cur.execute(f'SELECT COUNT(*) FROM {table}')
                    self.assertEqual(await Cur.fetchone(), (0,))
                    await Cur.execute(f'INSERT INTO {table} VALUES (2)')
                    await Conn.commit()
                    await Conn.rollback()
                finally:
                    await Cur.execute(f'DROP TABLE {table}')

    async def test_db_unique_name_is_the_one_sql_reports(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                try:
                    await Cur.execute(
                        "SELECT sys_context('userenv', 'db_unique_name') FROM dual"
                    )
                except DatabaseError as exc:
                    if exc.code != 2003:
                        raise
                    self.assertIsNone(Conn.db_unique_name)
                    return
                self.assertEqual(Conn.db_unique_name, (await Cur.fetchone())[0])

    async def test_v_session_shows_the_identity_the_client_declared(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        async with await seerdb.connect_async(
            **self._kwargs(
                program='pyo-program',
                machine='pyo-machine',
                terminal='pyo-terminal',
                osuser='pyo-osuser',
                driver_name='pyo-driver',
            )
        ) as Conn:
            async with Conn.cursor() as Cur:
                try:
                    await Cur.execute(
                        'SELECT program, machine, osuser FROM v$session '
                        "WHERE sid = sys_context('userenv', 'sid')"
                    )
                except DatabaseError as exc:
                    if exc.code in (942, 2003):
                        self.skipTest(f'v$session not readable: ORA-{exc.code:05d}')
                    raise
                self.assertEqual(
                    await Cur.fetchall(),
                    [('pyo-program', 'pyo-machine', 'pyo-osuser')],
                )
                if int(Conn.version.split('.')[0]) < 11:
                    return  # no CLIENT_DRIVER column before 11g
                if _FV_KW.get('server_type') == 'pooled':
                    return  # the pooled server's, its first client's (sync twin)
                await Cur.execute(
                    'SELECT DISTINCT client_driver FROM v$session_connect_info '
                    "WHERE sid = sys_context('userenv', 'sid')"
                )
                driver = (
                    'pyo-driver'
                    if Conn.field_version >= FIELD_VERSION_23_1_EXT_1
                    else None
                )
                self.assertEqual(await Cur.fetchall(), [(driver,)])

    @_requires(_TPC)
    async def test_branches_left_in_doubt_are_recovered_and_settled_elsewhere(self):
        # Async twin of TpcIntegration's (#2457): begin, end, prepare,
        # recover, commit and roll back, each awaited. The preparing sessions
        # stay open until their branches are settled, as there.
        from seerdb.common.exceptions import DatabaseError, Error

        table = 'PYO_ATPC_BRANCHES'
        Kwargs = self._kwargs()
        Kwargs['autocommit'] = False
        (keep, drop) = (_tpc_xid('akeep'), _tpc_xid('adrop'))
        Preparers = []
        async with await seerdb.connect_async(**Kwargs) as Conn:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TABLE {table}')
            except DatabaseError:
                pass  # not left over from an earlier run
            await Cur.execute(f'CREATE TABLE {table} (n NUMBER)')
        Settler = await seerdb.connect_async(**Kwargs)
        try:
            for xid, n in ((keep, 1), (drop, 2)):
                Conn = await seerdb.connect_async(**Kwargs)
                Preparers.append(Conn)
                await Conn.tpc_begin(xid)
                await Conn.cursor().execute(f'INSERT INTO {table} VALUES ({n})')
                await Conn.tpc_end(xid)
                self.assertTrue(await Conn.tpc_prepare(xid))
            try:
                recovered = await Settler.tpc_recover()
            except DatabaseError as exc:
                if exc.code != 942:
                    raise
                self.skipTest('the test user cannot read DBA_PENDING_TRANSACTIONS')
            self.assertIn(keep, recovered)
            self.assertIn(drop, recovered)
            await Settler.tpc_commit(keep)
            await Settler.tpc_rollback(drop)
            Cur = Settler.cursor()
            await Cur.execute(f'SELECT n FROM {table}')
            self.assertEqual(await Cur.fetchall(), [(1,)])
        finally:
            for xid in (keep, drop):
                try:
                    await Settler.tpc_rollback(xid)
                except Error:
                    pass  # settled already, as a passing test leaves it
            for Conn in Preparers:
                await Conn.close()
            await Settler.cursor().execute(f'DROP TABLE {table}')
            await Settler.close()

    async def test_transaction_in_progress_follows_the_server(self):
        # Async twin of CursorIntegration's (#2456).
        from seerdb.common.exceptions import DatabaseError

        Kwargs = self._kwargs()
        Kwargs['autocommit'] = False
        async with await seerdb.connect_async(**Kwargs) as Conn:
            if Conn.field_version < FIELD_VERSION_10_2:
                with self.assertRaises(seerdb.NotSupportedError):
                    Conn.transaction_in_progress
                return
            table = 'PYO_ATXN_IN_PROGRESS'
            async with Conn.cursor() as Cur:
                try:
                    await Cur.execute(f'DROP TABLE {table}')
                except DatabaseError:
                    pass  # not left over from an earlier run
                await Cur.execute(f'CREATE TABLE {table} (n NUMBER)')
                try:
                    await Cur.execute(f'INSERT INTO {table} VALUES (1)')
                    self.assertTrue(Conn.transaction_in_progress)
                    await Conn.commit()
                    self.assertFalse(Conn.transaction_in_progress)
                    await Cur.execute(f'DELETE FROM {table}')
                    self.assertTrue(Conn.transaction_in_progress)
                    await Conn.rollback()
                    self.assertFalse(Conn.transaction_in_progress)
                finally:
                    await Cur.execute(f'DROP TABLE {table}')

    async def test_is_healthy_needs_no_round_trip(self):
        # Async twin of CursorIntegration's (#2456).
        Conn = await seerdb.connect_async(**self._kwargs())
        self.assertTrue(Conn.is_healthy())
        self.assertEqual(
            Conn.max_identifier_length,
            128 if Conn.field_version >= FIELD_VERSION_12_2 else None,
        )
        await Conn.close()
        self.assertFalse(Conn.is_healthy())

    async def test_a_descriptor_over_230_bytes_connects(self):
        # Async twin of CursorIntegration's.
        async with await seerdb.connect_async(
            **self._kwargs(app_name='p' * 200)
        ) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))

    async def test_an_easy_connect_dsn_names_the_address(self):
        # Async twin of CursorIntegration's (#1972).
        Kwargs = self._kwargs(dsn=f'{_HOST}:{_PORT}/{_SERVICE}')
        for Key in ('host', 'port', 'service_name'):
            Kwargs.pop(Key)
        async with await seerdb.connect_async(**Kwargs) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))

    async def test_a_connect_descriptor_dsn_names_the_address(self):
        # Async twin of CursorIntegration's (#1976).
        Kwargs = self._kwargs(
            dsn=f'(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={_HOST})(PORT={_PORT}))'
            f'(CONNECT_DATA=(SERVICE_NAME={_SERVICE})))'
        )
        for Key in ('host', 'port', 'service_name'):
            Kwargs.pop(Key)
        async with await seerdb.connect_async(**Kwargs) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))

    async def test_a_tnsnames_alias_dsn_names_the_address(self):
        # Async twin of CursorIntegration's (#1976).
        with tempfile.TemporaryDirectory() as ConfigDir:
            with open(os.path.join(ConfigDir, 'tnsnames.ora'), 'w') as F:
                F.write(_alias_entry('pyo_bed'))
            Kwargs = self._kwargs(dsn='pyo_bed', config_dir=ConfigDir)
            for Key in ('host', 'port', 'service_name'):
                Kwargs.pop(Key)
            async with await seerdb.connect_async(**Kwargs) as Conn:
                async with Conn.cursor() as Cur:
                    await Cur.execute('SELECT 1 FROM dual')
                    self.assertEqual(await Cur.fetchone(), (1,))

    async def test_a_server_type_connects(self):
        # Async twin of CursorIntegration's (#1977).
        for Kind in ('dedicated', 'pooled'):
            with self.subTest(server_type=Kind):
                try:
                    Conn = await seerdb.connect_async(**self._kwargs(server_type=Kind))
                except seerdb.DatabaseError as E:
                    if Kind == 'pooled' and getattr(E, 'code', None) == 12520:
                        self.skipTest('the DRCP pool is not started on this server')
                    raise
                async with Conn:
                    async with Conn.cursor() as Cur:
                        await Cur.execute('SELECT 1 FROM dual')
                        self.assertEqual(await Cur.fetchone(), (1,))

    async def test_an_aggregate_over_a_null_group(self):
        # Async twin of CursorIntegration's (#1995).
        Table = 'PYO_ASYNC_NULL_AGG'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TABLE {Table}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(f'CREATE TABLE {Table} (g NUMBER, n NUMBER)')
            for G, N in _NULL_GROUP_ROWS:
                await Cur.execute(f'INSERT INTO {Table} VALUES ({G}, {N})')
            await Cur.execute(
                f'SELECT g, AVG(n), COUNT(n) FROM {Table} GROUP BY g ORDER BY g'
            )
            self.assertEqual(
                await Cur.fetchall(),
                _NULL_GROUP_AVERAGES,
            )
            await Cur.execute(f'DROP TABLE {Table}')
        finally:
            await Conn.close()

    async def test_easy_connect_parameters_apply(self):
        # Async twin of CursorIntegration's (#1977).
        Kwargs = self._kwargs(
            dsn=f'{_HOST}:{_PORT}/{_SERVICE}?sdu=16384&transport_connect_timeout=10'
        )
        for Key in ('host', 'port', 'service_name'):
            Kwargs.pop(Key)
        async with await seerdb.connect_async(**Kwargs) as Conn:
            self.assertEqual(Conn.timeout, 10000)
            self.assertLessEqual(Conn.sdu, 16384)
            async with Conn.cursor() as Cur:
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))

    async def test_a_descriptor_fails_over_to_the_bed(self):
        # Async twin of CursorIntegration's (#1983).
        for Name, Descriptor in _failover_descriptors():
            Kwargs = self._kwargs(dsn=Descriptor)
            for Key in ('host', 'port', 'service_name'):
                Kwargs.pop(Key)
            with self.subTest(Name):
                async with await seerdb.connect_async(**Kwargs) as Conn:
                    async with Conn.cursor() as Cur:
                        await Cur.execute('SELECT 1 FROM dual')
                        self.assertEqual(await Cur.fetchone(), (1,))

    async def test_a_connection_class_alone_requests_no_pooled_server(self):
        # Async twin of CursorIntegration's (#1990).
        async with await seerdb.connect_async(
            **self._kwargs(cclass='PYO_LABEL', purity=seerdb.PURITY_SELF)
        ) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))

    async def test_a_drcp_pool_connects_with_its_own_class(self):
        # Async twin of CursorIntegration's (#2006).
        try:
            Pool = await seerdb.create_pool_async(
                **self._kwargs(server_type='pooled'), min=1, max=2
            )
        except seerdb.DatabaseError as E:
            if getattr(E, 'code', None) == 12520:
                self.skipTest('the DRCP pool is not started on this server')
            raise
        try:
            async with Pool.acquire() as Conn:
                self.assertTrue(Conn.cclass.startswith('SEERDB:'))
                async with Conn.cursor() as Cur:
                    await Cur.execute('SELECT 1 FROM dual')
                    self.assertEqual(await Cur.fetchone(), (1,))
        finally:
            await Pool.close()

    async def test_a_drcp_pool_hands_its_server_back_and_is_served_again(self):
        # Async twin of CursorIntegration's (#2544).
        try:
            Pool = await seerdb.create_pool_async(
                **self._kwargs(server_type='pooled'), min=1, max=1
            )
        except seerdb.DatabaseError as E:
            if getattr(E, 'code', None) == 12520:
                self.skipTest('the DRCP pool is not started on this server')
            raise
        try:
            for N in range(3):
                Conn = await Pool.acquire()
                for _ in range(2):
                    Cur = Conn.cursor()
                    await Cur.execute('SELECT :1 FROM dual', [N])
                    self.assertEqual(await Cur.fetchone(), (N,))
                    await Cur.close()
                await Pool.release(Conn)
        finally:
            await Pool.close()

    async def test_a_long_program_name_connects(self):
        # Async twin of CursorIntegration's.
        for length in (253, 254, 255, 600):
            with self.subTest(length=length):
                async with await seerdb.connect_async(
                    **self._kwargs(app_name='p' * length)
                ) as Conn:
                    async with Conn.cursor() as Cur:
                        await Cur.execute('SELECT 1 FROM dual')
                        self.assertEqual(await Cur.fetchone(), (1,))

    async def test_kill_session_ends_the_named_session(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                victim = await seerdb.connect_async(**self._kwargs())
                try:
                    vcur = victim.cursor()
                    try:
                        await vcur.execute(
                            'SELECT * FROM v$session '
                            "WHERE sid = sys_context('userenv', 'sid')"
                        )
                    except DatabaseError as exc:
                        if exc.code in (942, 2003):
                            self.skipTest(f'v$session not readable: ORA-{exc.code:05d}')
                        raise
                    names = [d[0] for d in vcur.description]
                    row = await vcur.fetchone()
                    (sid, serial) = (
                        row[names.index('SID')],
                        row[names.index('SERIAL#')],
                    )
                    try:
                        await Cur.execute(f"ALTER SYSTEM KILL SESSION '{sid},{serial}'")
                    except DatabaseError as exc:
                        if exc.code == 1031:
                            self.skipTest('no ALTER SYSTEM privilege')
                        raise
                    with self.assertRaises(seerdb.Error) as killed:
                        await vcur.execute('SELECT USER FROM dual')
                        await vcur.fetchall()
                    self.assertEqual(getattr(killed.exception, 'code', None), 28)
                finally:
                    try:
                        await victim.close()
                    except seerdb.Error:
                        pass
                for session, code in (('x', 26), (f'{sid},{serial}', 30)):
                    with self.assertRaises(DatabaseError) as caught:
                        await Cur.execute(f"ALTER SYSTEM KILL SESSION '{session}'")
                    self.assertEqual(caught.exception.code, code)

    @_requires(_LTZ)
    async def test_timestamp_with_local_time_zone(self):
        # Async twin of CursorIntegration's.
        Table = 'PYO_ASYNC_LTZ'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute('SELECT sessiontimezone, dbtimezone FROM dual')
            (session, database) = (_tz_offset(z) for z in await Cur.fetchone())
            if session is None or database is None:
                self.skipTest('a named time zone')
            (session, zone) = _session_zone_apart_from(database)
            await Cur.execute(f"ALTER SESSION SET TIME_ZONE = '{zone}'")
            value = _LTZ_VALUE
            local = value - session + database
            await self._drop_async(Cur, Table)
            await Cur.execute(_LTZ_TABLE_DDL.format(Table))
            for k, kind in (
                (1, seerdb.DB_TYPE_TIMESTAMP_LTZ),
                (2, seerdb.DB_TYPE_TIMESTAMP),
            ):
                Cur.setinputsizes(kind, kind)
                await Cur.execute(
                    f'INSERT INTO {Table} VALUES ({k}, :1, :2)', [value, value]
                )
            await Cur.execute(f'SELECT k, a, b FROM {Table} ORDER BY k')
            self.assertEqual(
                [d[1] for d in Cur.description[1:]], [seerdb.DB_TYPE_TIMESTAMP_LTZ] * 2
            )
            self.assertEqual(
                await Cur.fetchall(),
                [
                    (1, value, value.replace(microsecond=123000)),
                    (2, local, local.replace(microsecond=123000)),
                ],
            )
            for kind, expected in (
                (seerdb.DB_TYPE_TIMESTAMP_LTZ, value),
                (seerdb.DB_TYPE_TIMESTAMP, local),
            ):
                Cur.setinputsizes(kind)
                await Cur.execute(
                    'SELECT CAST(:1 AS TIMESTAMP WITH LOCAL TIME ZONE) FROM dual',
                    [value],
                )
                self.assertIs(Cur.description[0][1], seerdb.DB_TYPE_TIMESTAMP_LTZ)
                self.assertEqual(await Cur.fetchone(), (expected,))
            await Cur.execute(
                'SELECT systimestamp, current_timestamp, localtimestamp FROM dual'
            )
            self.assertEqual(
                [d[1] for d in Cur.description],
                [
                    seerdb.DB_TYPE_TIMESTAMP_TZ,
                    seerdb.DB_TYPE_TIMESTAMP_TZ,
                    seerdb.DB_TYPE_TIMESTAMP,
                ],
            )
            await self._drop_async(Cur, Table)
        finally:
            await Conn.close()

    @_requires(_LTZ, _TRUNC_TIMESTAMP)
    async def test_a_midnight_ltz_bind_matches_a_truncated_ltz_column(self):
        # Async twin of CursorIntegration's (#1337).
        Table = 'PYO_ASYNC_LTZ_TRUNC'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute('SELECT dbtimezone FROM dual')
            (database,) = await Cur.fetchone()
            await Cur.execute(f"ALTER SESSION SET TIME_ZONE = '{database}'")
            await self._drop_async(Cur, Table)
            await Cur.execute(
                f'CREATE TABLE {Table} (id NUMBER, t TIMESTAMP WITH LOCAL TIME ZONE)'
            )
            await Cur.execute(
                f"INSERT INTO {Table} VALUES (1, TIMESTAMP '2022-06-12 10:30:20')"
            )
            Cur.setinputsizes(seerdb.DB_TYPE_TIMESTAMP_LTZ)
            await Cur.execute(
                f'SELECT id FROM {Table} WHERE trunc(t) = :1',
                [datetime.datetime(2022, 6, 12)],
            )
            self.assertEqual(await Cur.fetchall(), [(1,)])
            await self._drop_async(Cur, Table)
        finally:
            await Conn.close()

    @_requires(_8I_DESCRIBE_SPANS_PACKETS)
    async def test_a_describe_wider_than_a_packet(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "SELECT * FROM v$session WHERE audsid = userenv('sessionid')"
                )
                self.assertGreater(len(Cur.description), 40)
                self.assertEqual(len(await Cur.fetchall()), 1)
                with self.assertRaises(DatabaseError) as caught:
                    await Cur.execute(
                        "SELECT * FROM v$session WHERE sid = sys_context('userenv', 'sid')"
                    )
                self.assertEqual(caught.exception.code, 2003)
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchall(), [(1,)])

    @_requires(_TSTZ)
    async def test_timestamp_with_time_zone_compares_by_instant(self):
        # Async twin of CursorIntegration's.
        Table = 'PYO_ASYNC_TSTZ_CMP'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await self._drop_async(Cur, Table)
            await Cur.execute(
                f'CREATE TABLE {Table} (k NUMBER, t TIMESTAMP WITH TIME ZONE)'
            )
            for row in _TSTZ_ROWS:  # one at a time: 9i has no array DML
                Cur.setinputsizes(None, seerdb.DB_TYPE_TIMESTAMP_TZ)
                await Cur.execute(f'INSERT INTO {Table} VALUES (:1, :2)', row)
            for value, expected in ((_TSTZ_SAME_INSTANT, [(1,), (2,)]), (None, [])):
                Cur.setinputsizes(seerdb.DB_TYPE_TIMESTAMP_TZ)
                await Cur.execute(
                    f'SELECT k FROM {Table} WHERE t = :1 ORDER BY k', [value]
                )
                self.assertEqual(await Cur.fetchall(), expected)
            Cur.setinputsizes(seerdb.DB_TYPE_TIMESTAMP_TZ)
            await Cur.execute(
                f'SELECT k FROM {Table} WHERE t < :1 ORDER BY k', [_TSTZ_BEFORE]
            )
            self.assertEqual(await Cur.fetchall(), [(1,), (2,)])
            await Cur.execute(f'SELECT k FROM {Table} ORDER BY t DESC, k')
            self.assertEqual(await Cur.fetchall(), [(3,), (1,), (2,)])
            await Cur.execute(f'SELECT COUNT(DISTINCT t) FROM {Table}')
            self.assertEqual(await Cur.fetchall(), [(2,)])
            await self._drop_async(Cur, Table)
        finally:
            await Conn.close()

    @_requires(_LTZ, _LTZ_SESSION_ARITHMETIC)
    async def test_days_added_to_a_timestamp_with_local_time_zone(self):
        # Async twin of CursorIntegration's.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('SELECT sessiontimezone, dbtimezone FROM dual')
                (session, database) = (_tz_offset(z) for z in await Cur.fetchone())
                if session is None or database is None:
                    self.skipTest('a named time zone')
                value = datetime.datetime(2022, 5, 10, 12, 0, 0, 700000)
                on_session_clock = value.replace(microsecond=0) - database + session
                Cur.setinputsizes(seerdb.DB_TYPE_TIMESTAMP_LTZ)
                await Cur.execute('SELECT :1 + 5.25, :1 - 0.5 FROM dual', [value])
                self.assertEqual(
                    await Cur.fetchone(),
                    (
                        on_session_clock + datetime.timedelta(days=5.25),
                        on_session_clock - datetime.timedelta(days=0.5),
                    ),
                )
                var = Cur.var(seerdb.DB_TYPE_TIMESTAMP_LTZ)
                var.setvalue(0, value.replace(microsecond=0))
                await Cur.execute('begin :value := :value + 5.25; end;', {'value': var})
                self.assertEqual(
                    var.getvalue(), datetime.datetime(2022, 5, 15, 18, 0, 0)
                )

    async def test_a_var_read_only_as_input_beside_an_out_var(self):
        # Async twin of CursorIntegration's.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                out, inp = Cur.var(int), Cur.var(int)
                inp.setvalue(0, 7)
                await Cur.execute('begin :1 := :2 * 10; end;', [out, inp])
                self.assertEqual((out.getvalue(), inp.getvalue()), (70, 7))
                out, inp = Cur.var(int), Cur.var(int)
                inp.setvalue(0, 8)
                await Cur.execute('begin :h := :v * 10; end;', {'v': inp, 'h': out})
                self.assertEqual((out.getvalue(), inp.getvalue()), (80, 8))

    async def test_an_identifier_may_contain_a_hash(self):
        # Async twin of CursorIntegration's.
        Table = 'PYO_ASYNC_HASH'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, Table)
                await Cur.execute(
                    f'CREATE TABLE {Table} (obj# NUMBER, name VARCHAR2(10))'
                )
                await Cur.execute(f"INSERT INTO {Table} (obj#, name) VALUES (7, 'a#b')")
                await Cur.execute(
                    f'SELECT t.obj#, name FROM {Table} t WHERE obj# = :1', [7]
                )
                self.assertEqual([d[0] for d in Cur.description], ['OBJ#', 'NAME'])
                self.assertEqual(await Cur.fetchall(), [(7, 'a#b')])
                await self._drop_async(Cur, Table)

    async def test_a_column_of_a_user_defined_type_names_its_owner(self):
        # Async twin of CursorIntegration's.
        Table, Type = 'PYO_ASYNC_DTO', 'PYO_ASYNC_DTO_ARR'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, Table)
                try:
                    await Cur.execute(f'DROP TYPE {Type}')
                except seerdb.DatabaseError:
                    pass
                await Cur.execute(f'CREATE TYPE {Type} AS VARRAY(5) OF NUMBER')
                await Cur.execute(
                    "SELECT sys_context('userenv', 'current_schema') FROM dual"
                )
                (owner,) = await Cur.fetchone()
                try:
                    await Cur.execute(f'CREATE TABLE {Table} (i NUMBER(9), a {Type})')
                    await Cur.execute(
                        'SELECT column_name, data_type, data_type_owner '
                        'FROM user_tab_columns WHERE table_name = :1 ORDER BY column_name',
                        [Table],
                    )
                    self.assertEqual(
                        await Cur.fetchall(),
                        [('A', Type, owner), ('I', 'NUMBER', None)],
                    )
                finally:
                    await self._drop_async(Cur, Table)
                    await Cur.execute(f'DROP TYPE {Type}')

    async def test_a_collection_type_has_its_constructors(self):
        # Async twin of CursorIntegration's, for a nested table, whose
        # constructors a query can call directly.
        from seerdb.common.exceptions import DatabaseError

        vtype = 'PYO_ASYNC_CTOR_T'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                try:
                    await Cur.execute(f'DROP TYPE {vtype}')
                except DatabaseError:
                    pass
                await Cur.execute(f'CREATE TYPE {vtype} AS TABLE OF NUMBER')
                try:
                    await Cur.execute(
                        f'SELECT CASE WHEN {vtype}(5, 10) IS NOT NULL THEN 1 END, '
                        f'CASE WHEN {vtype}() IS NOT NULL THEN 1 END FROM dual'
                    )
                    self.assertEqual(await Cur.fetchone(), (1, 1))
                finally:
                    await Cur.execute(f'DROP TYPE {vtype}')

    async def test_an_object_type_has_its_constructor(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        Table, otype = 'PYO_ASYNC_OBJ_CTOR', 'PYO_ASYNC_OBJ_CTOR_T'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, Table)
                try:
                    await Cur.execute(f'DROP TYPE {otype}')
                except DatabaseError:
                    pass
                await Cur.execute(
                    f'CREATE TYPE {otype} AS OBJECT (n NUMBER, s VARCHAR2(10))'
                )
                try:
                    await Cur.execute(f'CREATE TABLE {Table} (id NUMBER, o {otype})')
                    await Cur.execute(
                        f"INSERT INTO {Table} VALUES (1, {otype}(5, 'x'))"
                    )
                    await Cur.execute(f'INSERT INTO {Table} (id) VALUES (2)')
                    await Cur.execute(f'SELECT id FROM {Table} WHERE o IS NOT NULL')
                    self.assertEqual(await Cur.fetchall(), [(1,)])
                finally:
                    await self._drop_async(Cur, Table)
                    await Cur.execute(f'DROP TYPE {otype}')

    @_requires(_INVISIBLE_COLUMNS)
    async def test_an_invisible_column(self):
        # Async twin of CursorIntegration's.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            T = 'PYO_ASYNC_INVISIBLE'
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, T)
                await Cur.execute(
                    f'CREATE TABLE {T} (a NUMBER, h NUMBER INVISIBLE, b NUMBER)'
                )
                await Cur.execute(f'INSERT INTO {T} VALUES (1, 2)')
                await Cur.execute(f'INSERT INTO {T} (a, h, b) VALUES (3, 4, 5)')
                await Cur.execute(f'SELECT * FROM {T} ORDER BY a')
                self.assertEqual([d[0] for d in Cur.description], ['A', 'B'])
                self.assertEqual(await Cur.fetchall(), [(1, 2), (3, 5)])
                await Cur.execute(f'SELECT t.*, h FROM {T} t ORDER BY a')
                self.assertEqual(await Cur.fetchall(), [(1, 2, None), (3, 5, 4)])
                await Cur.execute(
                    'SELECT column_name, column_id, hidden_column FROM user_tab_cols '
                    'WHERE table_name = :1 ORDER BY column_name',
                    [T],
                )
                self.assertEqual(
                    await Cur.fetchall(),
                    [('A', 1, 'NO'), ('B', 2, 'NO'), ('H', None, 'YES')],
                )
                await self._drop_async(Cur, T)

    async def test_decode(self):
        # Async twin of CursorIntegration's.
        Table = 'PYO_ASYNC_DECODE'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute(
                "SELECT DECODE('a', 'a', 'A', 'z'), DECODE(NULL, NULL, 'null', 'no'), "
                "DECODE(2, 1, 'one', 2, 'two'), DECODE(3, 1, 'one') FROM dual"
            )
            self.assertEqual(await Cur.fetchone(), ('A', 'null', 'two', None))
            await self._drop_async(Cur, Table)
            await Cur.execute(f'CREATE TABLE {Table} (id NUMBER, n NUMBER)')
            await Cur.execute(
                f'INSERT INTO {Table} '
                'SELECT 3, DECODE(MOD(3, 2), 0, NULL, POWER(2, 3)) FROM dual'
            )
            await Cur.execute(f'SELECT n FROM {Table}')
            self.assertEqual(await Cur.fetchone(), (8,))
            await self._drop_async(Cur, Table)
        finally:
            await Conn.close()

    async def test_ddl_on_a_table_another_session_holds_fails(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        Table = 'PYO_ASYNC_DDL_NOWAIT'
        Kw = self._kwargs()
        Kw['autocommit'] = False
        Conn = await seerdb.connect_async(**Kw)
        try:
            Cur = Conn.cursor()
            await self._drop_async(Cur, Table)
            await Cur.execute(f'CREATE TABLE {Table} (n NUMBER)')
            await Cur.execute(f'INSERT INTO {Table} VALUES (1)')
            Other = await seerdb.connect_async(**self._kwargs())
            try:
                with self.assertRaises(DatabaseError) as ctx:
                    await Other.cursor().execute(f'TRUNCATE TABLE {Table}')
                self.assertEqual(ctx.exception.code, 54)
            finally:
                await Other.close()
            await Conn.rollback()
            await self._drop_async(Cur, Table)
        finally:
            await Conn.close()

    async def test_a_query_does_not_block_another_sessions_ddl(self):
        # Async twin of CursorIntegration's.
        Table = 'PYO_ASYNC_READ_LOCK'
        Kw = self._kwargs()
        Kw['autocommit'] = False
        Conn = await seerdb.connect_async(**Kw)
        try:
            Cur = Conn.cursor()
            await self._drop_async(Cur, Table)
            await Cur.execute(f'CREATE TABLE {Table} (n NUMBER)')
            await Cur.execute(f'SELECT n FROM {Table}')
            await Cur.fetchall()
            Other = await seerdb.connect_async(**self._kwargs())
            try:
                await Other.cursor().execute(f'TRUNCATE TABLE {Table}')
            finally:
                await Other.close()
            await self._drop_async(Cur, Table)
        finally:
            await Conn.close()

    async def test_transaction_control_statements_run_as_sql(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        Table = 'PYO_ASYNC_TXN_SQL'
        Kw = self._kwargs()
        Kw['autocommit'] = False
        Conn = await seerdb.connect_async(**Kw)
        try:
            Cur = Conn.cursor()
            await self._drop_async(Cur, Table)
            await Cur.execute(f'CREATE TABLE {Table} (n NUMBER)')
            await Cur.execute(f'INSERT INTO {Table} VALUES (1)')
            await Cur.execute('COMMIT')
            await Cur.execute(f'INSERT INTO {Table} VALUES (2)')
            await Cur.execute('ROLLBACK')
            await Cur.execute(f'INSERT INTO {Table} VALUES (3)')
            await Cur.execute('SAVEPOINT pyo_sp')
            await Cur.execute(f'INSERT INTO {Table} VALUES (4)')
            await Cur.execute('ROLLBACK TO SAVEPOINT pyo_sp')
            with self.assertRaises(DatabaseError) as ctx:
                await Cur.execute('ROLLBACK TO pyo_no_such_sp')
            self.assertEqual(ctx.exception.code, 1086)
            await Cur.execute('COMMIT WORK')
            await Cur.execute(f'SELECT n FROM {Table} ORDER BY n')
            self.assertEqual(await Cur.fetchall(), [(1,), (3,)])
            await self._drop_async(Cur, Table)
        finally:
            await Conn.close()

    async def test_the_nls_parameters_are_readable(self):
        # Async twin of CursorIntegration's.
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute(
                'SELECT value FROM nls_database_parameters '
                "WHERE parameter = 'NLS_CHARACTERSET'"
            )
            self.assertTrue((await Cur.fetchone())[0])
        finally:
            await Conn.close()

    async def test_a_session_setting_answers_with_no_result_set(self):
        # Async twin of CursorIntegration's.
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute("ALTER SESSION SET NLS_NUMERIC_CHARACTERS = '.,'")
            self.assertIsNone(Cur.description)
        finally:
            await Conn.close()

    async def test_alter_session_current_schema_round_trips(self):
        # Async twin of CursorIntegration's (#1141).
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            Query = "SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM dual"
            await Cur.execute(Query)
            (Own,) = await Cur.fetchone()
            await Cur.execute('ALTER SESSION SET CURRENT_SCHEMA = SYSTEM')
            await Cur.execute(Query)
            self.assertEqual(await Cur.fetchone(), ('SYSTEM',))
            await Cur.execute(f'ALTER SESSION SET CURRENT_SCHEMA = {Own}')
        finally:
            await Conn.close()

    async def test_a_large_object_image_fetches_whole(self):
        # Async twin of LargeObjectImageIntegration's (#1261).
        Typ, Table = 'PYO_ABIGIMG_T', 'PYO_ABIGIMG_TAB'
        Drops = (f'DROP TABLE {Table}', f'DROP TYPE {Typ}')
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for Stmt in Drops:
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass  # no leftover from a prior run
                try:
                    await Cur.execute(
                        f'CREATE TYPE {Typ} AS OBJECT (v VARCHAR2(400), c CLOB)'
                    )
                    await Cur.execute(f'CREATE TABLE {Table} (o {Typ})')
                    await Cur.execute(
                        f"INSERT INTO {Table} VALUES ({Typ}(RPAD('y', 300, 'y'), TO_CLOB('z')))"
                    )
                    await Cur.execute(f'SELECT o FROM {Table}')
                    (Value,) = await Cur.fetchone()
                    self.assertEqual(Value.V, 'y' * 300)
                    self.assertEqual(await Value.C.aread(), 'z')
                finally:
                    for Stmt in Drops:
                        try:
                            await Cur.execute(Stmt)
                        except seerdb.DatabaseError:
                            pass  # a CREATE above failed, so nothing to drop

    async def test_a_nested_attribute_fetches_and_binds(self):
        # Async twin of NestedAttributeIntegration's: the async describe left
        # an attribute's own type out, so it came back as raw bytes (#1268).
        Sub, Arr, Outer, Table = (
            'PYO_ANEST_SUB_T',
            'PYO_ANEST_ARR_T',
            'PYO_ANEST_OUTER_T',
            'PYO_ANEST_TAB',
        )
        Drops = (
            f'DROP TABLE {Table}',
            f'DROP TYPE {Outer}',
            f'DROP TYPE {Arr}',
            f'DROP TYPE {Sub}',
        )
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for Stmt in Drops:
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass  # no leftover from a prior run
                try:
                    await Cur.execute(
                        f'CREATE TYPE {Sub} AS OBJECT (n NUMBER, s VARCHAR2(20))'
                    )
                    await Cur.execute(f'CREATE TYPE {Arr} AS VARRAY(5) OF {Sub}')
                    await Cur.execute(
                        f'CREATE TYPE {Outer} AS OBJECT (id NUMBER, sub {Sub}, subs {Arr})'
                    )
                    await Cur.execute(f'CREATE TABLE {Table} (k NUMBER, o {Outer})')
                    await Cur.execute(
                        f"INSERT INTO {Table} VALUES (1, {Outer}(1, {Sub}(7, 'seven'), "
                        f"{Arr}({Sub}(1, 'a'))))"
                    )
                    await Cur.execute(f'SELECT o FROM {Table}')
                    (O,) = await Cur.fetchone()
                    self.assertEqual(
                        (O.SUB.S, [E.S for E in O.SUBS.aslist()]), ('seven', ['a'])
                    )
                    if Conn.field_version >= FIELD_VERSION_12_1:
                        SubT = await Conn.gettype(Sub)
                        ArrT = await Conn.gettype(Arr)
                        OuterT = await Conn.gettype(Outer)
                        Obj = OuterT.newobject(
                            {
                                'ID': 2,
                                'SUB': SubT.newobject({'N': 9, 'S': 'nine'}),
                                'SUBS': ArrT.newobject(
                                    [SubT.newobject({'N': 4, 'S': 'd'})]
                                ),
                            }
                        )
                        await Cur.execute(f'INSERT INTO {Table} VALUES (2, :1)', [Obj])
                        await Cur.execute(f'SELECT o FROM {Table} WHERE k = 2')
                        (O,) = await Cur.fetchone()
                        self.assertEqual(
                            (O.SUB.S, [E.S for E in O.SUBS.aslist()]), ('nine', ['d'])
                        )
                finally:
                    for Stmt in Drops:
                        try:
                            await Cur.execute(Stmt)
                        except seerdb.DatabaseError:
                            pass  # a CREATE above failed, so nothing to drop

    @_requires(_OBJECT_BIND)
    async def test_a_local_time_zone_attribute_round_trips(self):
        # Async twin of ObjectLocalTimeZoneAttributeIntegration's (#1270).
        import datetime

        Typ, Table = 'PYO_ALTZ_ATTR_T', 'PYO_ALTZ_ATTR_TAB'
        Drops = (f'DROP TABLE {Table}', f'DROP TYPE {Typ}')
        Given = datetime.datetime(2026, 9, 27, 13, 14, 15)
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for Stmt in Drops:
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass  # no leftover from a prior run
                try:
                    await Cur.execute(
                        f'CREATE TYPE {Typ} AS OBJECT '
                        '(id NUMBER, ts TIMESTAMP WITH LOCAL TIME ZONE)'
                    )
                    await Cur.execute(f'CREATE TABLE {Table} (n NUMBER, o {Typ})')
                    ObjType = await Conn.gettype(Typ)
                    await Cur.execute(
                        f'INSERT INTO {Table} VALUES (1, :1)',
                        [ObjType.newobject({'ID': 1, 'TS': Given})],
                    )
                    await Cur.execute(f'SELECT o FROM {Table}')
                    (Fetched,) = await Cur.fetchone()
                    self.assertEqual(Fetched.TS.replace(tzinfo=None), Given)
                finally:
                    for Stmt in Drops:
                        try:
                            await Cur.execute(Stmt)
                        except seerdb.DatabaseError:
                            pass  # a CREATE above failed, so nothing to drop

    async def test_a_national_attribute_fetches_and_binds(self):
        # Async twin of NationalAttributeIntegration (#1433).
        Typ, Table = 'PYO_ANATTR_T', 'PYO_ANATTR_TAB'
        Drops = (f'DROP TABLE {Table}', f'DROP TYPE {Typ}')
        Text, Bound = 'ko\u010dka \u4e2d', '\u017e\u00e1ba \u732b'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for Stmt in Drops:
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass  # no leftover from a prior run
                try:
                    await Cur.execute(
                        f'CREATE TYPE {Typ} AS OBJECT (id NUMBER, v NVARCHAR2(10))'
                    )
                    await Cur.execute(f'CREATE TABLE {Table} (k NUMBER, o {Typ})')
                    await Cur.execute(
                        f"INSERT INTO {Table} VALUES (1, {Typ}(1, N'{Text}'))"
                    )
                    await Cur.execute(f'SELECT o FROM {Table} WHERE k = 1')
                    (Fetched,) = await Cur.fetchone()
                    self.assertEqual(Fetched.V, Text)
                    if Conn.field_version < FIELD_VERSION_12_1:
                        return  # an object bind needs the 12.1+ OAC
                    ObjType = await Conn.gettype(Typ)
                    await Cur.execute(
                        f'INSERT INTO {Table} VALUES (2, :1)',
                        [ObjType.newobject({'ID': 2, 'V': Bound})],
                    )
                    # Not over PostgreSQL (#1434), nor a leg that names no backend.
                    if os.environ.get('SEERDB_TEST_MIRROR') not in ('postgres', '1'):
                        await Cur.execute(
                            f'SELECT LENGTH(x.o.v) FROM {Table} x WHERE k = 2'
                        )
                        self.assertEqual(await Cur.fetchone(), (len(Bound),))
                    await Cur.execute(f'SELECT o FROM {Table} WHERE k = 2')
                    (Fetched,) = await Cur.fetchone()
                    self.assertEqual(Fetched.V, Bound)
                finally:
                    for Stmt in Drops:
                        try:
                            await Cur.execute(Stmt)
                        except seerdb.DatabaseError:
                            pass  # a CREATE above failed, so nothing to drop

    async def test_a_collection_of_collections_fetches_and_binds(self):
        # Async twin of CollectionOfCollectionsIntegration's (#1276).
        Inner, Outer, Table = 'PYO_ACOC_INNER_T', 'PYO_ACOC_TT', 'PYO_ACOC_TAB'
        Drops = (f'DROP TABLE {Table}', f'DROP TYPE {Outer}', f'DROP TYPE {Inner}')
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for Stmt in Drops:
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass  # no leftover from a prior run
                try:
                    await Cur.execute(f'CREATE TYPE {Inner} AS TABLE OF NUMBER')
                    await Cur.execute(f'CREATE TYPE {Outer} AS TABLE OF {Inner}')
                    await Cur.execute(
                        f'CREATE TABLE {Table} (id NUMBER, c {Outer}) '
                        f'NESTED TABLE c STORE AS {Table}_NT '
                        f'(NESTED TABLE COLUMN_VALUE STORE AS {Table}_NTI)'
                    )
                    await Cur.execute(
                        f'INSERT INTO {Table} VALUES (1, {Outer}({Inner}(1, 2), NULL))'
                    )
                    await Cur.execute(f'SELECT c FROM {Table}')
                    (C,) = await Cur.fetchone()
                    self.assertEqual(
                        [
                            None if E is None else [int(X) for X in E.aslist()]
                            for E in C.aslist()
                        ],
                        [[1, 2], None],
                    )
                    if Conn.field_version >= FIELD_VERSION_12_1:
                        InnerT = await Conn.gettype(Inner)
                        OuterT = await Conn.gettype(Outer)
                        await Cur.execute(
                            f'INSERT INTO {Table} VALUES (2, :1)',
                            [OuterT.newobject([InnerT.newobject([3])])],
                        )
                        await Cur.execute(f'SELECT c FROM {Table} WHERE id = 2')
                        (C,) = await Cur.fetchone()
                        self.assertEqual(
                            [[int(X) for X in E.aslist()] for E in C.aslist()], [[3]]
                        )
                finally:
                    for Stmt in Drops:
                        try:
                            await Cur.execute(Stmt)
                        except seerdb.DatabaseError:
                            pass  # a CREATE above failed, so nothing to drop

    async def test_a_lob_attribute_fetches_and_binds(self):
        # Async twin of ObjectLobAttributeIntegration's fetch and str bind (#1260).
        from seerdb.common.lob import LOB

        Typ, Table = 'PYO_ALOBATTR_T', 'PYO_ALOBATTR_TAB'
        Drops = (f'DROP TABLE {Table}', f'DROP TYPE {Typ}')
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for Stmt in Drops:
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass  # no leftover from a prior run
                try:
                    await Cur.execute(
                        f'CREATE TYPE {Typ} AS OBJECT (id NUMBER, c CLOB, b BLOB)'
                    )
                    await Cur.execute(f'CREATE TABLE {Table} (k NUMBER, o {Typ})')
                    await Cur.execute(
                        f"INSERT INTO {Table} VALUES (1, {Typ}(1, TO_CLOB('some clob'), "
                        "TO_BLOB(HEXTORAW('0102FF'))))"
                    )
                    await Cur.execute(f'SELECT o FROM {Table} WHERE k = 1')
                    (O,) = await Cur.fetchone()
                    self.assertIsInstance(O.C, LOB)
                    self.assertEqual(
                        (await O.C.aread(), await O.B.aread()),
                        ('some clob', b'\x01\x02\xff'),
                    )
                    if Conn.field_version >= FIELD_VERSION_12_1:
                        ObjType = await Conn.gettype(Typ)
                        Obj = ObjType.newobject({'ID': 2, 'C': 'bound', 'B': b'\x07'})
                        await Cur.execute(f'INSERT INTO {Table} VALUES (2, :1)', [Obj])
                        await Cur.execute(f'SELECT o FROM {Table} WHERE k = 2')
                        (O,) = await Cur.fetchone()
                        self.assertEqual(
                            (await O.C.aread(), await O.B.aread()), ('bound', b'\x07')
                        )
                finally:
                    for Stmt in Drops:
                        try:
                            await Cur.execute(Stmt)
                        except seerdb.DatabaseError:
                            pass  # a CREATE above failed, so nothing to drop

    @_requires(_postgres_cannot('fetch a computed collection'))
    async def test_a_collection_of_objects_fetches_objects(self):
        # Async twin of ObjectCollectionFetchIntegration: the async describe
        # left the element's object type out, so each element came back as its
        # raw image (#1254).
        Elem, Elems = 'PYO_AOCOLL_ELEM_T', 'PYO_AOCOLL_ELEMS_T'
        Drops = (f'DROP TYPE {Elems}', f'DROP TYPE {Elem}')
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for Stmt in Drops:
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass  # no leftover from a prior run
                try:
                    await Cur.execute(
                        f'CREATE TYPE {Elem} AS OBJECT (id NUMBER, name VARCHAR2(40))'
                    )
                    await Cur.execute(f'CREATE TYPE {Elems} AS TABLE OF {Elem}')
                    await Cur.execute(
                        f"SELECT {Elems}({Elem}(1, 'a'), {Elem}(2, 'b')) FROM dual"
                    )
                    (Value,) = await Cur.fetchone()
                    self.assertEqual(
                        [(int(E.ID), E.NAME) for E in Value.aslist()],
                        [(1, 'a'), (2, 'b')],
                    )
                finally:
                    for Stmt in Drops:
                        try:
                            await Cur.execute(Stmt)
                        except seerdb.DatabaseError:
                            pass  # a CREATE above failed, so nothing to drop

    async def test_gettype_follows_the_current_schema(self):
        # Async twin of GettypeCurrentSchemaIntegration.
        Typ = 'PYO_ASYNC_CURSCHEMA_T'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TYPE {Typ}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(f'CREATE TYPE {Typ} AS OBJECT (id NUMBER)')
            try:
                Owner = (await Conn.gettype(Typ)).schema
                Other = 'SYS' if Owner == 'SYSTEM' else 'SYSTEM'
                await Cur.execute(f'ALTER SESSION SET CURRENT_SCHEMA = {Other}')
                with self.assertRaises(seerdb.DatabaseError):
                    await Conn.gettype(Typ)
                Qualified = await Conn.gettype(f'{Owner}.{Typ}')
                self.assertEqual(Qualified.schema, Owner)
                await Cur.execute(f'ALTER SESSION SET CURRENT_SCHEMA = {Owner}')
            finally:
                await Cur.execute(f'DROP TYPE {Typ}')
        finally:
            await Conn.close()

    @_requires(_PACKAGE_TYPE_BIND)
    async def test_gettype_resolves_a_package_level_type(self):
        # PL/SQL-bound: a package-level type lives in a PL/SQL PACKAGE (#1127).
        # Async twin of PlsqlTypeIntegration (#1030).
        Pkg = 'PYO_ASYNC_PLSQLTYPE_PKG'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP PACKAGE {Pkg}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(
                f'CREATE PACKAGE {Pkg} AS '
                'TYPE udt_numlist IS TABLE OF NUMBER INDEX BY BINARY_INTEGER; '
                'TYPE udt_rec IS RECORD (id NUMBER, name VARCHAR2(40)); '
                'PROCEDURE fill(n IN NUMBER, l IN OUT udt_numlist); END;'
            )
            await Cur.execute(
                f'CREATE PACKAGE BODY {Pkg} AS '
                'PROCEDURE fill(n IN NUMBER, l IN OUT udt_numlist) IS BEGIN '
                'FOR i IN 1..n LOOP l(i) := i * 100; END LOOP; END; END;'
            )
            try:
                Coll = await Conn.gettype(f'{Pkg}.UDT_NUMLIST')
                self.assertTrue(Coll.is_collection)
                self.assertEqual(Coll.package_name, Pkg)
                Rec = await Conn.gettype(f'{Coll.schema}.{Pkg}.UDT_REC')
                self.assertEqual(Rec.attr_names, ['ID', 'NAME'])
                Obj = Coll.newobject()
                await Cur.callproc(f'{Pkg}.fill', (3, Obj))
                self.assertEqual([int(v) for v in Obj.aslist()], [100, 200, 300])
            finally:
                try:
                    await Cur.execute(f'DROP PACKAGE {Pkg}')
                except seerdb.DatabaseError:
                    pass
        finally:
            await Conn.close()

    @_requires(_OBJECT_BIND)
    async def test_a_collection_value_binds(self):
        # Async twin of CollectionTypeIntegration's.
        Elem, Nums, Elems = 'PYO_ACOLB_ELEM_T', 'PYO_ACOLB_NUMS_T', 'PYO_ACOLB_ELEMS_T'
        Table = 'PYO_ACOLB_TAB'
        Drops = (
            f'DROP TABLE {Table}',
            f'DROP TYPE {Elems}',
            f'DROP TYPE {Nums}',
            f'DROP TYPE {Elem}',
        )
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for Stmt in Drops:
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass  # no leftover from a prior run
                try:
                    await Cur.execute(
                        f'CREATE TYPE {Elem} AS OBJECT (id NUMBER, name VARCHAR2(40))'
                    )
                    await Cur.execute(f'CREATE TYPE {Nums} AS VARRAY(3) OF NUMBER')
                    await Cur.execute(f'CREATE TYPE {Elems} AS TABLE OF {Elem}')
                    await Cur.execute(
                        f'CREATE TABLE {Table} (id NUMBER, v {Nums}, w {Elems}) '
                        f'NESTED TABLE w STORE AS {Table}_W'
                    )
                    NumsType = await Conn.gettype(Nums)
                    ElemsType = await Conn.gettype(Elems)
                    ElemType = await Conn.gettype(Elem)
                    Filled = ElemsType.newobject(
                        [
                            ElemType.newobject({'ID': 1, 'NAME': 'a'}),
                            ElemType.newobject({'ID': 2, 'NAME': 'b'}),
                        ]
                    )
                    await Cur.execute(
                        f'INSERT INTO {Table} VALUES (1, :1, :2)',
                        [NumsType.newobject([5, 10, 15]), Filled],
                    )
                    await Cur.execute(
                        f'INSERT INTO {Table} VALUES (2, :1, NULL)',
                        [NumsType.newobject()],
                    )
                    await Cur.execute(f'SELECT v, w FROM {Table} ORDER BY id')
                    (V1, W1), (V2, W2) = await Cur.fetchall()
                    self.assertEqual([int(X) for X in V1.aslist()], [5, 10, 15])
                    self.assertEqual(
                        [(int(E.ID), E.NAME) for E in W1.aslist()],
                        [(1, 'a'), (2, 'b')],
                    )
                    self.assertEqual((V2.aslist(), W2), ([], None))
                finally:
                    for Stmt in Drops:
                        try:
                            await Cur.execute(Stmt)
                        except seerdb.DatabaseError:
                            pass  # a CREATE above failed, so nothing to drop

    async def test_a_collection_value_fetches(self):
        # Async twin of CollectionTypeIntegration's.
        Elem, Nums, Elems = 'PYO_ACOLF_ELEM_T', 'PYO_ACOLF_NUMS_T', 'PYO_ACOLF_ELEMS_T'
        Table = 'PYO_ACOLF_TAB'
        Drops = (
            f'DROP TABLE {Table}',
            f'DROP TYPE {Elems}',
            f'DROP TYPE {Nums}',
            f'DROP TYPE {Elem}',
        )
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for Stmt in Drops:
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass  # no leftover from a prior run
                try:
                    await Cur.execute(
                        f'CREATE TYPE {Elem} AS OBJECT (id NUMBER, name VARCHAR2(40))'
                    )
                    await Cur.execute(f'CREATE TYPE {Nums} AS VARRAY(3) OF NUMBER')
                    await Cur.execute(f'CREATE TYPE {Elems} AS TABLE OF {Elem}')
                    await Cur.execute(
                        f'CREATE TABLE {Table} (id NUMBER, v {Nums}, w {Elems}) '
                        f'NESTED TABLE w STORE AS {Table}_W'
                    )
                    await Cur.execute(
                        f'INSERT INTO {Table} VALUES (1, {Nums}(5, 10, 15), '
                        f"{Elems}({Elem}(1, 'a'), {Elem}(2, 'b')))"
                    )
                    await Cur.execute(f'INSERT INTO {Table} VALUES (2, {Nums}(), NULL)')
                    await Cur.execute(f'SELECT v, w FROM {Table} ORDER BY id')
                    (V1, W1), (V2, W2) = await Cur.fetchall()
                    self.assertEqual([int(X) for X in V1.aslist()], [5, 10, 15])
                    self.assertEqual(
                        [(int(E.ID), E.NAME) for E in W1.aslist()],
                        [(1, 'a'), (2, 'b')],
                    )
                    self.assertEqual((V2.aslist(), W2), ([], None))
                finally:
                    for Stmt in Drops:
                        try:
                            await Cur.execute(Stmt)
                        except seerdb.DatabaseError:
                            pass  # a CREATE above failed, so nothing to drop

    async def test_gettype_describes_a_collection(self):
        # Async twin of CollectionTypeIntegration's.
        from seerdb.common.dbobject import COLLECTION_NESTED_TABLE, COLLECTION_VARRAY

        Elem, Nums, Elems = 'PYO_ACOLL_ELEM_T', 'PYO_ACOLL_NUMS_T', 'PYO_ACOLL_ELEMS_T'
        Drops = (f'DROP TYPE {Elems}', f'DROP TYPE {Nums}', f'DROP TYPE {Elem}')
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for Stmt in Drops:
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass  # no leftover from a prior run
                try:
                    await Cur.execute(
                        f'CREATE TYPE {Elem} AS OBJECT (id NUMBER, name VARCHAR2(40))'
                    )
                    await Cur.execute(f'CREATE TYPE {Nums} AS VARRAY(3) OF NUMBER')
                    await Cur.execute(f'CREATE TYPE {Elems} AS TABLE OF {Elem}')
                    NumsType = await Conn.gettype(Nums)
                    self.assertTrue(NumsType.is_collection)
                    self.assertEqual(
                        (
                            NumsType.collection_type,
                            NumsType.max_elements,
                            NumsType.element['type_name'],
                        ),
                        (COLLECTION_VARRAY, 3, 'NUMBER'),
                    )
                    ElemsType = await Conn.gettype(Elems)
                    self.assertEqual(ElemsType.collection_type, COLLECTION_NESTED_TABLE)
                    self.assertEqual(ElemsType.element['object_type'].name, Elem)
                    # As python-oracledb describes them (#1490).
                    self.assertIs(NumsType.element_type, seerdb.DB_TYPE_NUMBER)
                    self.assertEqual(ElemsType.element_type.name, Elem)
                    ElemType = await Conn.gettype(Elem)
                    self.assertEqual(
                        [
                            (A.name, A.type, A.precision, A.scale, A.max_size)
                            for A in ElemType.attributes
                        ],
                        [
                            ('ID', seerdb.DB_TYPE_NUMBER, 0, -127, None),
                            ('NAME', seerdb.DB_TYPE_VARCHAR, None, None, 40),
                        ],
                    )
                finally:
                    for Stmt in Drops:
                        try:
                            await Cur.execute(Stmt)
                        except seerdb.DatabaseError:
                            pass  # a CREATE above failed, so nothing to drop

    @_requires(_OBJECT_BIND)
    async def test_a_bare_object_out_bind_takes_its_value(self):
        # PL/SQL-bound: the object OUT bind is filled by a PL/SQL PACKAGE (#1127).
        # Async twin of ObjectOutBindIntegration (#1029): an object handed to
        # callproc with no Var around it takes the OUT value in place.
        Typ = 'PYO_ASYNC_OUTBIND_T'
        Pkg = 'PYO_ASYNC_OUTBIND_PKG'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            for Stmt in (f'DROP PACKAGE {Pkg}', f'DROP TYPE {Typ}'):
                try:
                    await Cur.execute(Stmt)
                except seerdb.DatabaseError:
                    pass
            await Cur.execute(f'CREATE TYPE {Typ} AS VARRAY(10) OF NUMBER')
            await Cur.execute(
                f'CREATE PACKAGE {Pkg} AS '
                f'PROCEDURE fill(n IN NUMBER, l IN OUT {Typ}); END;'
            )
            await Cur.execute(
                f'CREATE PACKAGE BODY {Pkg} AS '
                f'PROCEDURE fill(n IN NUMBER, l IN OUT {Typ}) IS BEGIN '
                f'l := {Typ}(); '
                'FOR i IN 1..n LOOP l.extend; l(i) := i * 100; END LOOP; '
                'END; END;'
            )
            try:
                ObjType = await Conn.gettype(Typ)
                Obj = ObjType.newobject()
                await Cur.callproc(f'{Pkg}.fill', (3, Obj))
                self.assertEqual([int(v) for v in Obj.aslist()], [100, 200, 300])
            finally:
                for Stmt in (f'DROP PACKAGE {Pkg}', f'DROP TYPE {Typ}'):
                    try:
                        await Cur.execute(Stmt)
                    except seerdb.DatabaseError:
                        pass
        finally:
            await Conn.close()

    async def test_parse_describes_a_query_without_running_it(self):
        # Async twin of ParseIntegration (#1018). Pre-10g refuses instead.
        Table = 'PYO_ASYNC_PARSE'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            if Conn.field_version < FIELD_VERSION_10_2:
                with self.assertRaises(seerdb.NotSupportedError):
                    await Cur.parse('SELECT 1 FROM DUAL')
                return
            try:
                await Cur.execute(f'DROP TABLE {Table}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(f'CREATE TABLE {Table} (id NUMBER)')
            try:
                await Cur.parse(f'SELECT id FROM {Table}')
                self.assertEqual([d[0] for d in Cur.description], ['ID'])
                self.assertEqual(await Cur.fetchall(), [])
                # A DML parse validates and stops: the row never lands.
                await Cur.parse(f'INSERT INTO {Table} (id) VALUES (:v)')
                self.assertIsNone(Cur.description)
                await Cur.execute(f'SELECT COUNT(*) FROM {Table}')
                self.assertEqual(await Cur.fetchone(), (0,))
                with self.assertRaises(seerdb.DatabaseError) as ctx:
                    await Cur.parse(f'SELECT nonexistent_col FROM {Table}')
                self.assertEqual(ctx.exception.code, 904)
            finally:
                await Cur.execute(f'DROP TABLE {Table}')
        finally:
            await Conn.close()

    async def test_lob_columns_are_readable_inside_an_open_transaction(self):
        # The async twin of LOBIntegration's test (#712).
        Table = 'PYO_ASYNC_LOB_TXN'
        Conn = await seerdb.connect_async(**{**self._kwargs(), 'autocommit': False})
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TABLE {Table}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(f'CREATE TABLE {Table} (id NUMBER, t CLOB, b BLOB)')
            try:
                await Cur.execute(
                    f'INSERT INTO {Table} VALUES (:1, :2, :3)',
                    [1, 'some text', b'\x00\x01'],
                )
                await Cur.execute(f'SELECT t, b FROM {Table}')
                Row = await Cur.fetchone()
                self.assertIsNotNone(Row, 'the uncommitted LOB row was not returned')
                Values = []
                for V in Row:
                    Values.append((await V.read()) if hasattr(V, 'read') else V)
                self.assertEqual(tuple(Values), ('some text', b'\x00\x01'))
                await Conn.rollback()
            finally:
                await Cur.execute(f'DROP TABLE {Table}')
        finally:
            await Conn.close()

    @_requires(_LOB_VAR_BIND)
    async def test_inout_clob_var(self):
        # PL/SQL-bound: the IN OUT LOB is filled by a multi-statement DECLARE block (#1127).
        # The async twin of LOBOutBindIntegration (#978): a LOB OUT bind's value
        # arrives in the LOB framing, and the read that materialises it is
        # awaited. 12.1+ only, like the sync class.
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            Var = Cur.var(seerdb.DB_TYPE_CLOB)
            Var.setvalue(0, 'A' * 50000)
            await Cur.execute(
                """
                DECLARE t_Clob CLOB;
                BEGIN
                    t_Clob := :d;
                    DBMS_LOB.COPY(:d, t_Clob, 50000);
                    DBMS_LOB.WRITEAPPEND(:d, 5, 'BBBBB');
                END;""",
                [Var],
            )
            self.assertEqual(await Var.getvalue().aread(), 'A' * 50000 + 'B' * 5)
        finally:
            await Conn.close()

    @_requires(_LOB_VAR_BIND)
    async def test_returning_a_clob(self):
        # The async twin of LOBReturningIntegration (#985): the read that
        # materialises a returned LOB is awaited. 12.1+ only, like the sync class.
        Table = 'PYO_ASYNC_LOBRET'
        Conn = await seerdb.connect_async(**{**self._kwargs(), 'autocommit': False})
        try:
            Cur = Conn.cursor()
            try:
                await Cur.execute(f'DROP TABLE {Table}')
            except seerdb.DatabaseError:
                pass
            await Cur.execute(f'CREATE TABLE {Table} (n NUMBER, c CLOB)')
            try:
                Var = Cur.var(seerdb.DB_TYPE_CLOB)
                await Cur.execute(
                    f'INSERT INTO {Table} (n, c) VALUES (1, :a) RETURNING c INTO :b',
                    ['async returned clob', Var],
                )
                Values = [await V.aread() for V in Var.getvalue()]
                self.assertEqual(Values, ['async returned clob'])
                await Conn.rollback()
            finally:
                await Cur.execute(f'DROP TABLE {Table}')
        finally:
            await Conn.close()

    async def test_connect_and_simple_query(self):
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute('SELECT 1 FROM dual')
            self.assertEqual(await Cur.fetchone(), (1,))
            await Cur.close()
        finally:
            await Conn.close()

    async def test_follows_redirect(self):
        # Async mirror of RedirectIntegration: follow a TNS_REDIRECT to the
        # backend the listener hands back (#23).
        with RedirectListener(_HOST, _PORT) as listener:
            Kw = self._kwargs()
            Kw['host'] = listener.listen_host
            Kw['port'] = listener.listen_port
            Conn = await seerdb.connect_async(**Kw)
            try:
                # Moved off the listener (8i double-redirects to a dynamic port).
                self.assertNotEqual(Conn.port, listener.listen_port)
                Cur = Conn.cursor()
                await Cur.execute("SELECT 'redirected' FROM dual")
                self.assertEqual(await Cur.fetchone(), ('redirected',))
            finally:
                await Conn.close()

    async def test_context_managers(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute("SELECT 'hi' FROM dual")
                self.assertEqual(await Cur.fetchone(), ('hi',))

    async def test_async_iteration_yields_all_rows(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                # In a subquery: a bare CONNECT BY LEVEL against dual returns
                # 9.2's native OCI client one row -- sqlplus 9.2 too (#798).
                await Cur.execute(
                    'SELECT * FROM (SELECT LEVEL FROM dual CONNECT BY LEVEL <= 5)'
                )
                Rows = [row async for row in Cur]
                self.assertEqual(Rows, [(1,), (2,), (3,), (4,), (5,)])

    async def test_fetchall_and_fetchmany(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'SELECT * FROM (SELECT LEVEL FROM dual CONNECT BY LEVEL <= 4)'
                )
                # fetchmany(2) → first batch
                First = await Cur.fetchmany(2)
                self.assertEqual(First, [(1,), (2,)])
                # fetchall() → remainder
                Rest = await Cur.fetchall()
                self.assertEqual(Rest, [(3,), (4,)])

    async def test_named_bind(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('SELECT :v FROM dual', {'v': 42})
                self.assertEqual(await Cur.fetchone(), (42,))

    async def test_ddl_dml_roundtrip(self):
        # DDL → DML → SELECT round-trip using a scratch table.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                try:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_TEST')
                except seerdb.DatabaseError as e:
                    if e.code != 942:
                        raise
                await Cur.execute(
                    'CREATE TABLE PYORACLE_ASYNC_TEST (id NUMBER, v VARCHAR2(10))'
                )
                for n in range(3):
                    await Cur.execute(
                        'INSERT INTO PYORACLE_ASYNC_TEST VALUES (:id, :v)',
                        {'id': n, 'v': f'r{n}'},
                    )
                await Cur.execute('SELECT id, v FROM PYORACLE_ASYNC_TEST ORDER BY id')
                self.assertEqual(
                    await Cur.fetchall(),
                    [(0, 'r0'), (1, 'r1'), (2, 'r2')],
                )
                await Cur.execute('DROP TABLE PYORACLE_ASYNC_TEST')

    @_requires(_PRE12_VECTOR_REFUSAL)
    async def test_a_vector_bind_below_12_1_is_refused(self):
        # Async parity for the pre-12.1 VECTOR refusal (#1762).
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                with self.assertRaises(seerdb.NotSupportedError):
                    await Cur.execute('SELECT :v FROM DUAL', [[1.0, 2.0]])
                await Cur.execute('SELECT 1 FROM DUAL')
                self.assertEqual(await Cur.fetchall(), [(1,)])

    @_requires(_VECTOR_BIND)
    async def test_vector_bind_roundtrip(self):
        # Async parity for VECTOR binds (#55): bind a sequence, read it back.
        import array

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, 'PYORACLE_ASYNC_VEC')
                try:
                    await Cur.execute(
                        'CREATE TABLE PYORACLE_ASYNC_VEC (v VECTOR(3, FLOAT32))'
                    )
                except seerdb.DatabaseError as e:
                    if e.code in (902, 907):
                        self.skipTest('native VECTOR type needs a 23ai+ server')
                    raise
                await Cur.execute(
                    'INSERT INTO PYORACLE_ASYNC_VEC VALUES (:v)',
                    [array.array('f', [1.5, 2.5, 3.5])],
                )
                await Cur.execute('SELECT v FROM PYORACLE_ASYNC_VEC')
                self.assertEqual(
                    await Cur.fetchone(), (array.array('f', [1.5, 2.5, 3.5]),)
                )
                await self._drop_async(Cur, 'PYORACLE_ASYNC_VEC')

    @_requires(_VECTOR_BIND)
    async def test_sparse_vector_bind_roundtrip(self):
        # Async parity for SPARSE vectors (#68).
        from seerdb.common.vector import SparseVector

        sv = SparseVector(8, array.array('I', [2, 5]), array.array('f', [1.5, 2.5]))
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, 'PYORACLE_ASYNC_SPV')
                try:
                    await Cur.execute(
                        'CREATE TABLE PYORACLE_ASYNC_SPV (v VECTOR(8, FLOAT32, SPARSE))'
                    )
                except seerdb.DatabaseError as e:
                    if e.code in (902, 907):
                        self.skipTest('native VECTOR type needs a 23ai+ server')
                    raise
                await Cur.execute('INSERT INTO PYORACLE_ASYNC_SPV VALUES (:v)', [sv])
                await Cur.execute('SELECT v FROM PYORACLE_ASYNC_SPV')
                self.assertEqual(await Cur.fetchone(), (sv,))
                await self._drop_async(Cur, 'PYORACLE_ASYNC_SPV')

    @_requires(_JSON)
    async def test_json_bind_roundtrip(self):
        # Async parity for JSON binds (#50): bind a dict, read it back.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, 'PYORACLE_ASYNC_JSON')
                try:
                    await Cur.execute('CREATE TABLE PYORACLE_ASYNC_JSON (doc JSON)')
                except seerdb.DatabaseError as e:
                    if e.code == 902:
                        self.skipTest('native JSON type needs a 21c+ server')
                    raise
                await Cur.execute(
                    'INSERT INTO PYORACLE_ASYNC_JSON VALUES (:doc)',
                    [{'k': 'v', 'n': [1, 2, 3]}],
                )
                await Cur.execute('SELECT doc FROM PYORACLE_ASYNC_JSON')
                self.assertEqual(await Cur.fetchone(), ({'k': 'v', 'n': [1, 2, 3]},))
                await self._drop_async(Cur, 'PYORACLE_ASYNC_JSON')

    async def _drop_async(self, cur, table):
        try:
            await cur.execute(f'DROP TABLE {table}')
        except seerdb.DatabaseError as e:
            if e.code != 942:
                raise

    async def test_ping_succeeds(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            # Ping completes cleanly on a freshly-authenticated session;
            # the test just verifies no exception escapes.
            await Conn.ping()

    @_requires(_CHANGE_PASSWORD)
    async def test_changepassword_roundtrip(self):
        # Async mirror of ChangePasswordIntegration (#21): change the test
        # user's password and always restore it on the original session.
        new = _PASSWORD + '_achg9'
        Kw = self._kwargs()
        Conn = await seerdb.connect_async(**dict(Kw, password=_PASSWORD))
        try:
            await Conn.changepassword(_PASSWORD, new)
            try:
                Cur = Conn.cursor()
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))
                V = await seerdb.connect_async(**dict(Kw, password=new))
                await V.close()
                with self.assertRaises(seerdb.DatabaseError):
                    Bad = await seerdb.connect_async(**dict(Kw, password=_PASSWORD))
                    await Bad.close()
            finally:
                await Conn.changepassword(new, _PASSWORD)
        finally:
            await Conn.close()
        Ok = await seerdb.connect_async(**dict(Kw, password=_PASSWORD))
        await Ok.close()

    @_requires(_CHANGE_PASSWORD)
    async def test_changepassword_wrong_old_raises(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            with self.assertRaises(seerdb.DatabaseError):
                await Conn.changepassword('wrong_old_pw_xyz', 'irrelevant9')
            Cur = Conn.cursor()
            await Cur.execute('SELECT 1 FROM dual')
            self.assertEqual(await Cur.fetchone(), (1,))

    async def test_a_varray_type_can_type_a_column(self):
        # Async twin of TypesIntegration's.
        from seerdb.common.exceptions import DatabaseError

        Table, VType = 'PYO_ASYNC_VARRAY', 'PYO_ASYNC_VARRAY_T'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, Table)
                try:
                    await Cur.execute(f'DROP TYPE {VType}')
                except DatabaseError:
                    # No leftover type from a prior run; nothing to clean up.
                    pass
                await Cur.execute(f'CREATE TYPE {VType} AS VARRAY(3) OF NUMBER;')
                try:
                    await Cur.execute(f'CREATE TABLE {Table} (id NUMBER, v {VType})')
                    await Cur.execute(f'INSERT INTO {Table} (id) VALUES (1)')
                    await Cur.execute(f'SELECT id FROM {Table}')
                    self.assertEqual(await Cur.fetchone(), (1,))
                    await Cur.execute(f'DROP TABLE {Table}')
                finally:
                    await Cur.execute(f'DROP TYPE {VType}')

    async def test_a_nested_table_type_can_type_a_collection(self):
        # Async twin of TypesIntegration's.
        from seerdb.common.exceptions import DatabaseError

        names = ('PYO_ANT_VARRAY_T', 'PYO_ANT_NESTED_T', 'PYO_ANT_T')
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for name in names:
                    try:
                        await Cur.execute(f'DROP TYPE {name}')
                    except DatabaseError:
                        # No leftover type from a prior run; nothing to clean up.
                        pass
                try:
                    await Cur.execute('CREATE TYPE PYO_ANT_T AS TABLE OF NUMBER;')
                    await Cur.execute(
                        'CREATE TYPE PYO_ANT_NESTED_T AS TABLE OF PYO_ANT_T;'
                    )
                    await Cur.execute(
                        'CREATE TYPE PYO_ANT_VARRAY_T AS VARRAY(3) OF PYO_ANT_T;'
                    )
                finally:
                    for name in names:
                        try:
                            await Cur.execute(f'DROP TYPE {name}')
                        except DatabaseError:
                            # A CREATE above failed, so there is no type to drop.
                            pass

    async def test_a_nested_table_column_names_its_storage(self):
        # Async twin of TypesIntegration's.
        from seerdb.common.exceptions import DatabaseError

        Table, NType = 'PYO_ASYNC_NT_STORE', 'PYO_ASYNC_NT_STORE_T'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, Table)
                try:
                    await Cur.execute(f'DROP TYPE {NType}')
                except DatabaseError:
                    # No leftover type from a prior run; nothing to clean up.
                    pass
                await Cur.execute(f'CREATE TYPE {NType} AS TABLE OF NUMBER;')
                try:
                    await Cur.execute(
                        f'CREATE TABLE {Table} (id NUMBER, v {NType}) '
                        f'NESTED TABLE v STORE AS {Table}_V RETURN AS VALUE'
                    )
                    await Cur.execute(f'INSERT INTO {Table} (id) VALUES (1)')
                    await Cur.execute(f'SELECT id FROM {Table}')
                    self.assertEqual(await Cur.fetchone(), (1,))
                    await Cur.execute(f'DROP TABLE {Table}')
                finally:
                    await Cur.execute(f'DROP TYPE {NType}')

    async def test_rownum_filters_the_first_rows(self):
        # Async twin of TypesIntegration's (#1271).
        Table = 'PYO_ASYNC_ROWNUM'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, Table)
                await Cur.execute(f'CREATE TABLE {Table} (id NUMBER)')
                for I in range(1, 6):
                    await Cur.execute(f'INSERT INTO {Table} VALUES (:1)', [I])
                await Cur.execute(
                    f'SELECT id FROM (SELECT id FROM {Table} ORDER BY id) '
                    'WHERE ROWNUM <= 2'
                )
                self.assertEqual(await Cur.fetchall(), [(1,), (2,)])
                await self._drop_async(Cur, Table)

    async def test_a_bool_declared_number_is_stored_as_a_number(self):
        # Async twin of TypesIntegration's.
        Table = 'PYO_ASYNC_BOOL_NUMBER'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, Table)
                await Cur.execute(f'CREATE TABLE {Table} (id NUMBER, n NUMBER)')
                for i, value in ((1, True), (2, False)):
                    Cur.setinputsizes(None, seerdb.DB_TYPE_NUMBER)
                    await Cur.execute(
                        f'INSERT INTO {Table} VALUES (:1, :2)', [i, value]
                    )
                await Cur.execute(f'SELECT id, n FROM {Table} ORDER BY id')
                self.assertEqual(await Cur.fetchall(), [(1, 1), (2, 0)])
                await self._drop_async(Cur, Table)

    async def test_a_type_may_be_replaced_until_something_depends_on_it(self):
        # Async twin of TypesIntegration's.
        from seerdb.common.exceptions import DatabaseError

        (Obj, Arr) = ('PYO_AREPLACE_T', 'PYO_AREPLACE_ARR_T')
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                for name in (Arr, Obj):
                    try:
                        await Cur.execute(f'DROP TYPE {name}')
                    except DatabaseError:
                        # No leftover type from a prior run; nothing to clean up.
                        pass
                await Cur.execute(f'CREATE TYPE {Obj} AS OBJECT (a NUMBER)')
                try:
                    await Cur.execute(
                        f'CREATE OR REPLACE TYPE {Obj} AS OBJECT (a NUMBER, b NUMBER)'
                    )
                    await Cur.execute(
                        f'CREATE OR REPLACE TYPE {Arr} AS VARRAY(3) OF {Obj};'
                    )
                    with self.assertRaises(DatabaseError) as ctx:
                        await Cur.execute(
                            f'CREATE OR REPLACE TYPE {Obj} AS OBJECT (c NUMBER)'
                        )
                    self.assertEqual(ctx.exception.code, 2303)
                finally:
                    for name in (Arr, Obj):
                        try:
                            await Cur.execute(f'DROP TYPE {name}')
                        except DatabaseError:
                            # A CREATE above failed, so there is no type to drop.
                            pass

    async def test_quoted_column_names_keep_their_case(self):
        # Async twin of TypesIntegration's.
        Table = 'PYO_ASYNC_QUOTED_NAMES'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, Table)
                await Cur.execute(
                    f'CREATE TABLE {Table} (id NUMBER, all_lowercase NUMBER, '
                    '"MixedCase" NUMBER, "all_lowercase_quoted" NUMBER, '
                    '"ALL_UPPERCASE_QUOTED" NUMBER)'
                )
                await Cur.execute(f'SELECT * FROM {Table}')
                self.assertEqual(
                    [d[0] for d in Cur.description],
                    [
                        'ID',
                        'ALL_LOWERCASE',
                        'MixedCase',
                        'all_lowercase_quoted',
                        'ALL_UPPERCASE_QUOTED',
                    ],
                )
                await self._drop_async(Cur, Table)

    async def test_untyped_null_column(self):
        # Async twin of TypesIntegration's.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "SELECT NULL AS a, 5 AS b, DECODE(3, 1, 'one') AS c FROM dual"
                )
                self.assertEqual(await Cur.fetchone(), (None, 5, None))

    async def test_commit_persists_dml(self):
        # autocommit=False, then explicit commit. A second connection
        # sees the row.
        Kw = self._kwargs()
        Kw['autocommit'] = False
        async with await seerdb.connect_async(**Kw) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, 'PYORACLE_ASYNC_TX')
                # CREATE TABLE auto-commits server-side regardless of the
                # client flag, so we issue it first and then test commit /
                # rollback against the rows.
                await Cur.execute('CREATE TABLE PYORACLE_ASYNC_TX (id NUMBER)')
                await Cur.execute('INSERT INTO PYORACLE_ASYNC_TX VALUES (1)')
                await Conn.commit()
        async with await seerdb.connect_async(**Kw) as Conn2:
            async with Conn2.cursor() as Cur:
                await Cur.execute('SELECT id FROM PYORACLE_ASYNC_TX')
                self.assertEqual(await Cur.fetchall(), [(1,)])
                await Cur.execute('DROP TABLE PYORACLE_ASYNC_TX')

    async def test_rollback_discards_dml(self):
        Kw = self._kwargs()
        Kw['autocommit'] = False
        async with await seerdb.connect_async(**Kw) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, 'PYORACLE_ASYNC_RB')
                await Cur.execute('CREATE TABLE PYORACLE_ASYNC_RB (id NUMBER)')
                await Cur.execute('INSERT INTO PYORACLE_ASYNC_RB VALUES (1)')
                await Cur.execute('INSERT INTO PYORACLE_ASYNC_RB VALUES (2)')
                await Conn.rollback()
                # After rollback, the table exists (DDL auto-committed)
                # but the rows are gone.
                await Cur.execute('SELECT COUNT(*) FROM PYORACLE_ASYNC_RB')
                self.assertEqual(await Cur.fetchone(), (0,))
                await Cur.execute('DROP TABLE PYORACLE_ASYNC_RB')

    async def test_long_in_an_uncompressed_table(self):
        # Async twin of TypesIntegration's.
        from seerdb.common.exceptions import DatabaseError

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, 'PYO_ASYNC_NOCOMPRESS')
                try:
                    await Cur.execute(
                        'CREATE TABLE PYO_ASYNC_NOCOMPRESS (id NUMBER, l LONG) NOCOMPRESS'
                    )
                except DatabaseError as exc:
                    if exc.code == 922:
                        self.skipTest('no table compression before 9i Release 2')
                    raise
                await Cur.execute("INSERT INTO PYO_ASYNC_NOCOMPRESS VALUES (1, 'kept')")
                await Cur.execute('SELECT id, l FROM PYO_ASYNC_NOCOMPRESS')
                self.assertEqual(await Cur.fetchone(), (1, 'kept'))
                await Cur.execute('DROP TABLE PYO_ASYNC_NOCOMPRESS')

    async def test_drop_table_purge(self):
        # Async twin of TypesIntegration's.
        from seerdb.common.exceptions import DatabaseError

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, 'PYO_ASYNC_PURGE')
                await Cur.execute('CREATE TABLE PYO_ASYNC_PURGE (n NUMBER)')
                try:
                    await Cur.execute('DROP TABLE PYO_ASYNC_PURGE PURGE')
                except DatabaseError as exc:
                    if exc.code == 933:
                        self.skipTest('no recycle bin, so no PURGE, before 10g')
                    raise
                with self.assertRaises(DatabaseError) as ctx:
                    await Cur.execute('SELECT n FROM PYO_ASYNC_PURGE')
                self.assertEqual(ctx.exception.code, 942)

    async def test_lob_auto_resolve(self):
        # CLOB / BLOB / NULL / EMPTY all surface as Python str/bytes/None
        # through the auto-resolve in `AsyncCursor.execute`.
        async with await seerdb.connect_async(**self._kwargs(fetch_lobs=False)) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, 'PYORACLE_ASYNC_LOB')
                await Cur.execute(
                    'CREATE TABLE PYORACLE_ASYNC_LOB (id NUMBER, c CLOB, b BLOB)'
                )
                await Cur.execute(
                    'INSERT INTO PYORACLE_ASYNC_LOB VALUES (1, NULL, NULL)'
                )
                await Cur.execute(
                    'INSERT INTO PYORACLE_ASYNC_LOB VALUES '
                    '(2, EMPTY_CLOB(), EMPTY_BLOB())'
                )
                await Cur.execute(
                    'INSERT INTO PYORACLE_ASYNC_LOB VALUES '
                    "(3, 'hello async clob', HEXTORAW('DEADBEEF'))"
                )
                await Cur.execute('SELECT id, c, b FROM PYORACLE_ASYNC_LOB ORDER BY id')
                Rows = await Cur.fetchall()
                self.assertEqual(
                    Rows,
                    [
                        (1, None, None),
                        (2, '', b''),
                        (3, 'hello async clob', b'\xde\xad\xbe\xef'),
                    ],
                )
                await Cur.execute('DROP TABLE PYORACLE_ASYNC_LOB')

    @_requires(_STREAMED_LOB_BIND)
    async def test_error_then_large_lob_stays_synced(self):
        # #45 (async parity): errored calls leave break/reset markers; a few of
        # them followed by a large CLOB read must not desync the stream.
        from seerdb.common.exceptions import DatabaseError

        async with await seerdb.connect_async(**self._kwargs(fetch_lobs=False)) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, 'PYORACLE_ASYNC_LOB45')
                await Cur.execute(
                    'CREATE TABLE PYORACLE_ASYNC_LOB45 (id NUMBER, c CLOB)'
                )
                Big = 'A' * 50000
                await Cur.execute(
                    'INSERT INTO PYORACLE_ASYNC_LOB45 VALUES (1, :c)', {'c': Big}
                )
                await Conn.commit()
                for _ in range(8):
                    with self.assertRaises(DatabaseError):
                        await Cur.execute('SELECT * FROM pyoracle_no_such_table_45')
                        await Cur.fetchall()
                    await Cur.execute('SELECT c FROM PYORACLE_ASYNC_LOB45 WHERE id=1')
                    (Got,) = await Cur.fetchone()
                    self.assertEqual(len(Got), len(Big))
                    self.assertEqual(Got, Big)
                await Cur.execute('DROP TABLE PYORACLE_ASYNC_LOB45')

    async def test_async_plsql_in_bind(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('CREATE TABLE PYORACLE_ASYNC_PLSQL (v NUMBER)')
                try:
                    await Cur.execute(
                        'BEGIN INSERT INTO PYORACLE_ASYNC_PLSQL VALUES (:x); END;', [42]
                    )
                    await Cur.execute('SELECT v FROM PYORACLE_ASYNC_PLSQL')
                    self.assertEqual(await Cur.fetchone(), (42,))
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_PLSQL')

    async def test_async_callproc_out_and_inout(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'CREATE OR REPLACE PROCEDURE PYORACLE_ASYNC_PROC'
                    '(p_in IN NUMBER, p_out OUT NUMBER, p_io IN OUT VARCHAR2) AS '
                    "BEGIN p_out := p_in * 2; p_io := p_io || '!'; END;"
                )
                try:
                    o = Cur.var(seerdb.NUMBER)
                    io = Cur.var(seerdb.STRING)
                    io.setvalue(0, 'hi')
                    ret = await Cur.callproc('PYORACLE_ASYNC_PROC', [5, o, io])
                    self.assertEqual(ret, [5, 10, 'hi!'])
                    self.assertEqual(o.getvalue(), 10)
                    self.assertEqual(io.getvalue(), 'hi!')
                finally:
                    await Cur.execute('DROP PROCEDURE PYORACLE_ASYNC_PROC')

    async def test_async_execute_out_var(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                y = Cur.var(seerdb.NUMBER)
                await Cur.execute('BEGIN :y := 7 * 6; END;', [y])
                self.assertEqual(y.getvalue(), 42)

    @_requires(_BINARY_DOUBLE_AND_INTERVAL)
    async def test_async_out_extended_types(self):
        # OUT binds for the extended scalar types (issue #17), async path.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'CREATE OR REPLACE PROCEDURE PYORACLE_ASYNC_OUTX'
                    '(o_ts OUT TIMESTAMP, o_bd OUT BINARY_DOUBLE, '
                    ' o_ids OUT INTERVAL DAY TO SECOND, '
                    ' o_iym OUT INTERVAL YEAR TO MONTH) AS BEGIN '
                    "o_ts := TIMESTAMP '2026-06-07 13:14:15.5'; "
                    'o_bd := 2.25; '
                    "o_ids := INTERVAL '1 02:03:04.5' DAY TO SECOND; "
                    "o_iym := INTERVAL '3-7' YEAR TO MONTH; END;"
                )
                try:
                    ts = Cur.var(seerdb.DB_TYPE_TIMESTAMP)
                    bd = Cur.var(seerdb.DB_TYPE_BINARY_DOUBLE)
                    ids = Cur.var(seerdb.DB_TYPE_INTERVAL_DS)
                    iym = Cur.var(seerdb.DB_TYPE_INTERVAL_YM)
                    await Cur.callproc('PYORACLE_ASYNC_OUTX', [ts, bd, ids, iym])
                    self.assertEqual(
                        ts.getvalue(), datetime.datetime(2026, 6, 7, 13, 14, 15, 500000)
                    )
                    self.assertEqual(bd.getvalue(), 2.25)
                    self.assertEqual(
                        ids.getvalue(),
                        datetime.timedelta(
                            days=1, hours=2, minutes=3, seconds=4, milliseconds=500
                        ),
                    )
                    self.assertEqual(iym.getvalue(), seerdb.IntervalYM(3, 7))
                finally:
                    await Cur.execute('DROP PROCEDURE PYORACLE_ASYNC_OUTX')

    async def test_async_scroll(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            # Scrollable cursor (#161) on the async path.
            async with Conn.cursor(scrollable=True) as Cur:
                self.assertIs(Cur.scrollable, True)
                await Cur.execute('CREATE TABLE PYORACLE_ASYNC_SCROLL (id NUMBER)')
                try:
                    # Single inserts (not executemany) so scrollable cursors —
                    # which are buffer-backed and work on every tier — can also
                    # be exercised on 9i (#161).
                    for i in range(1, 11):
                        await Cur.execute(
                            'INSERT INTO PYORACLE_ASYNC_SCROLL VALUES (:1)', [i]
                        )
                    Conn.fetch = 4
                    await Cur.execute(
                        'SELECT id FROM PYORACLE_ASYNC_SCROLL ORDER BY id'
                    )
                    await Cur.scroll(mode='last')
                    self.assertEqual(await Cur.fetchone(), (10,))
                    await Cur.scroll(3, mode='absolute')
                    self.assertEqual(await Cur.fetchone(), (3,))
                    await Cur.scroll(mode='first')
                    self.assertEqual(await Cur.fetchone(), (1,))
                    with self.assertRaises(IndexError):
                        await Cur.scroll(-1, mode='relative')
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_SCROLL')

    @_requires(_SERVER_SCROLL)
    async def test_async_scrollable_lazy(self):
        # Server-side lazy scrollable cursor on the async path (#181), 10g+:
        # fetch-on-demand across batches + scroll modes + the LAST-after-EOF
        # duplicate-value (bit-vector reuse) case.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor(scrollable=True) as Cur:
                Cur.prefetchrows = 2
                Cur.arraysize = 3
                await Cur.execute('CREATE TABLE PYORACLE_ASYNC_LAZY (id NUMBER)')
                try:
                    for i in range(1, 9):
                        await Cur.execute(
                            'INSERT INTO PYORACLE_ASYNC_LAZY VALUES (:1)', [i]
                        )
                    await Cur.execute('SELECT id FROM PYORACLE_ASYNC_LAZY ORDER BY id')
                    self.assertTrue(Cur._scroll_active)
                    got = [r[0] for r in await Cur.fetchmany(5)]  # crosses batches
                    self.assertEqual(got, [1, 2, 3, 4, 5])
                    await Cur.scroll(6, mode='absolute')
                    self.assertEqual((await Cur.fetchone())[0], 6)
                    # LAST-after-EOF duplicate value via a big arraysize.
                    Cur.arraysize = 50
                    await Cur.scroll(mode='first')
                    self.assertEqual(
                        [r[0] for r in await Cur.fetchall()], list(range(1, 9))
                    )
                    await Cur.scroll(mode='last')
                    self.assertEqual((await Cur.fetchone())[0], 8)
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_LAZY')

    async def test_async_fetch_df(self):
        # Arrow / DataFrame bulk fetch (#162) on the async path.
        import pyarrow as pa

        table = 'PYORACLE_ASYNC_DF'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(f'CREATE TABLE {table} (id NUMBER)')
                try:
                    for i in range(1, 8):
                        await Cur.execute(f'INSERT INTO {table} VALUES (:1)', [i])
                    await Cur.execute(f'SELECT id FROM {table} ORDER BY id')
                    t = await Cur.fetch_df_all()
                    self.assertIsInstance(t, pa.Table)
                    self.assertEqual(t.column('ID').to_pylist(), list(range(1, 8)))
                    await Cur.execute(f'SELECT id FROM {table} ORDER BY id')
                    sizes = [b.num_rows async for b in Cur.fetch_df_batches(size=3)]
                    self.assertEqual(sizes, [3, 3, 1])
                finally:
                    await Cur.execute(f'DROP TABLE {table}')

    @_requires(_postgres_cannot('run DBMS_SODA'), _SODA)
    async def test_async_soda_collections(self):
        # SODA collection management (#163 / #199) on the async path; 18c+ only,
        # and not over the Mirror's PostgreSQL backend, which has no DBMS_SODA
        # (#1745).
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_12_1:
                # Refused up front below 12.1 (#1763).
                with self.assertRaises(seerdb.NotSupportedError):
                    Conn.getSodaDatabase()
                self.skipTest('SODA needs a 12.1+ session')
            soda = Conn.getSodaDatabase()
            for n in await soda.getCollectionNames():
                c = await soda.openCollection(n)
                if c:
                    await c.drop()
            col = await soda.createCollection('it_async')
            self.assertEqual(col.name, 'it_async')
            self.assertIn('contentColumn', await col.get_metadata())
            self.assertEqual(await soda.getCollectionNames(), ['it_async'])
            self.assertIsNone(await soda.openCollection('no_such_coll'))
            # document insert + read by key on the async path (#200)
            saved = await col.insertOneAndGet(soda.createDocument({'x': 1}))
            self.assertTrue(saved.key)
            got = await col.find().key(saved.key).getOne()
            self.assertEqual(got.getContent()['x'], 1)
            self.assertIsNone(
                await col.find().key('AABBCCDDEEFF00112233445566').getOne()
            )
            # QBE on the async path (#201)
            await col.insertOne({'x': 2})
            self.assertEqual(await col.find().filter({'x': {'$gte': 1}}).count(), 2)
            docs = await col.find().filter({'x': 2}).getDocuments()
            self.assertEqual([d.getContent()['x'] for d in docs], [2])
            self.assertIsNone(await col.find().filter({'x': 999}).getOne())
            # update / delete / bulk on the async path (#202)
            await col.insertMany([{'x': 3}, {'x': 4}])
            self.assertTrue(await col.find().key(saved.key).replaceOne({'x': 5}))
            g = await col.find().key(saved.key).replaceOneAndGet({'x': 6})
            self.assertEqual(g.key, saved.key)
            self.assertEqual(await col.find().key(saved.key).remove(), 1)
            # save upsert on the async path (#212)
            sg = await col.saveAndGet(soda.createDocument({'y': 1}))
            sg2 = await col.saveAndGet(soda.createDocument({'y': 2}, key=sg.key))
            self.assertEqual(sg2.key, sg.key)
            self.assertEqual(
                (await col.find().key(sg.key).getOne()).getContent()['y'], 2
            )
            # streaming getCursor on the async path (#213)
            for i in range(6):
                await col.insertOne({'z': i})
            streamed = [
                d
                async for d in col.find()
                .filter({'z': {'$exists': True}})
                .getCursor(batchSize=2)
            ]
            self.assertEqual(len(streamed), 6)
            # indexing + data guide on the async path (#203)
            self.assertIsNone(await col.getDataGuide())
            await col.createIndex(
                {'name': 'AIDX', 'fields': [{'path': 'x', 'datatype': 'number'}]}
            )
            self.assertTrue(await col.dropIndex('AIDX'))
            self.assertTrue(await col.drop())
            self.assertFalse(await col.drop())

    async def test_async_end_to_end_tracing(self):
        # End-to-end tracing (#183) on the async path.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if not _target_of(Conn).end_to_end:
                with self.assertRaises(seerdb.NotSupportedError):
                    Conn.module = 'M'
                return
            Conn.module = 'AMOD'
            Conn.action = 'AACT'
            Conn.client_identifier = 'ACLID'
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "SELECT SYS_CONTEXT('USERENV','MODULE'), "
                    "SYS_CONTEXT('USERENV','ACTION'), "
                    "SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') FROM dual"
                )
                self.assertEqual(await Cur.fetchone(), ('AMOD', 'AACT', 'ACLID'))

    async def test_async_repeated_execute_no_cursor_leak(self):
        # #191 on the async path.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_10_2:
                return
            Cur = Conn.cursor()
            try:
                await Cur.execute('DROP TABLE PYO_LEAK191A')
            except seerdb.DatabaseError:
                # best-effort drop of a table that may not exist
                pass
            await Cur.execute('CREATE TABLE PYO_LEAK191A (id NUMBER)')
            try:
                for i in range(400):
                    await Cur.execute('INSERT INTO PYO_LEAK191A VALUES (:1)', [i])
                await Conn.commit()
                await Cur.execute('SELECT COUNT(*) FROM PYO_LEAK191A')
                self.assertEqual((await Cur.fetchone())[0], 400)
            finally:
                await Cur.execute('DROP TABLE PYO_LEAK191A')

    async def test_async_executemany(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('CREATE TABLE PYORACLE_ASYNC_EM (id NUMBER)')
                try:
                    await Cur.executemany(
                        'INSERT INTO PYORACLE_ASYNC_EM VALUES (:1)',
                        [(i,) for i in range(8)],
                    )
                    self.assertEqual(Cur.rowcount, 8)
                    await Cur.execute('SELECT COUNT(*) FROM PYORACLE_ASYNC_EM')
                    self.assertEqual(await Cur.fetchone(), (8,))
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_EM')

    async def test_async_setinputsizes_reaches_the_execute(self):
        # Async mirror of the setinputsizes round trip (#696): the declaration is
        # applied in each cursor's own execute path, and spent there.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('CREATE TABLE PYORACLE_ASYNC_SIS (id NUMBER)')
                try:
                    await Cur.execute('INSERT INTO PYORACLE_ASYNC_SIS VALUES (1)')
                    Cur.setinputsizes(seerdb.DB_TYPE_NUMBER)
                    await Cur.execute(
                        'SELECT id FROM PYORACLE_ASYNC_SIS WHERE id = :1', [1]
                    )
                    self.assertEqual(await Cur.fetchall(), [(1,)])
                    self.assertEqual(Cur._inputsizes, ((), {}))
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_SIS')

    async def test_async_failing_returning_keeps_the_session(self):
        # Async mirror of test_failing_returning_raises_cleanly_and_keeps_the
        # _session (#697): the flush-out-binds handshake is in the connection's
        # response loop, which each path has its own copy of.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'CREATE TABLE PYORACLE_ASYNC_FOB (id NUMBER NOT NULL, v NUMBER)'
                )
                try:
                    got = Cur.var(int)
                    with self.assertRaises(seerdb.IntegrityError):
                        await Cur.execute(
                            'INSERT INTO PYORACLE_ASYNC_FOB (v) VALUES (:1) '
                            'RETURNING id INTO :2',
                            [1.5, got],
                        )
                    await Cur.execute('SELECT 1 FROM dual')
                    self.assertEqual(await Cur.fetchall(), [(1,)])
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_FOB')

    async def test_async_executemany_returning(self):
        # Async mirror of test_executemany_returning_collects_every_iteration
        # (#687): the encoder and the per-iteration assignment are shared, so
        # this pins that the async path really reaches them.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('CREATE TABLE PYORACLE_ASYNC_EMR (id NUMBER)')
                try:
                    got = Cur.var(int)
                    await Cur.executemany(
                        'INSERT INTO PYORACLE_ASYNC_EMR (id) VALUES (:1) '
                        'RETURNING id INTO :2',
                        [[1, got], [2, got], [3, got]],
                    )
                    self.assertEqual(Cur.rowcount, 3)
                    self.assertEqual(
                        [got.getvalue(i) for i in range(3)], [[1], [2], [3]]
                    )
                    await Cur.execute('SELECT COUNT(*) FROM PYORACLE_ASYNC_EMR')
                    self.assertEqual(await Cur.fetchone(), (3,))
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_EMR')

    async def test_async_error_offset_points_at_the_bad_token(self):
        # Async mirror of test_error_offset_points_at_the_bad_token: the parse
        # offset reaches DatabaseError.offset over the async path too.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                with self.assertRaises(seerdb.DatabaseError) as ctx:
                    await Cur.execute('SELECT nonexistent_col FROM dual')
                self.assertEqual(ctx.exception.code, 904)
                self.assertEqual(ctx.exception.offset, 7)

    async def test_async_executemany_batcherrors(self):
        # Async mirror of test_executemany_batcherrors (#18): per-row constraint
        # violations are collected, not raised, and the good rows still apply.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'CREATE TABLE PYORACLE_ASYNC_BE '
                    '(id NUMBER PRIMARY KEY, v VARCHAR2(10))'
                )
                try:
                    await Cur.executemany(
                        'INSERT INTO PYORACLE_ASYNC_BE VALUES (:1, :2)',
                        [(1, 'a'), (2, 'b'), (1, 'dup'), (3, 'c'), (2, 'd2')],
                        batcherrors=True,
                    )
                    errs = Cur.getbatcherrors()
                    self.assertEqual(
                        [(e.offset, e.code) for e in errs], [(2, 1), (4, 1)]
                    )
                    await Cur.execute('SELECT id FROM PYORACLE_ASYNC_BE ORDER BY id')
                    self.assertEqual([r[0] for r in await Cur.fetchall()], [1, 2, 3])
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_BE')

    @_requires(_ARRAY_DML)
    async def test_async_statement_runs_again_after_a_batch_error(self):
        # Async mirror of test_the_statement_runs_again_after_a_batch_error
        # (#2563): the cached cursor a batch error keeps is not closed.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'CREATE TABLE PYORACLE_ASYNC_BE (id NUMBER PRIMARY KEY)'
                )
                sql = 'INSERT INTO PYORACLE_ASYNC_BE VALUES (:1)'
                try:
                    await Cur.executemany(sql, [(1,), (2,)], batcherrors=True)
                    await Cur.executemany(sql, [(3,), (1,)], batcherrors=True)
                    await Cur.executemany(sql, [(4,)], batcherrors=True)
                    await Cur.execute('SELECT id FROM PYORACLE_ASYNC_BE ORDER BY id')
                    self.assertEqual([r[0] for r in await Cur.fetchall()], [1, 2, 3, 4])
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_BE')

    @_requires(_ARRAY_DML_ROWCOUNTS)
    async def test_async_executemany_arraydmlrowcounts(self):
        # Async mirror of test_executemany_arraydmlrowcounts_update (#18).

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'CREATE TABLE PYORACLE_ASYNC_ADR (g NUMBER, v NUMBER)'
                )
                try:
                    await Cur.executemany(
                        'INSERT INTO PYORACLE_ASYNC_ADR VALUES (:1, :2)',
                        [(1, 1), (1, 2), (2, 3), (1, 4), (3, 5), (3, 6)],
                    )
                    await Cur.executemany(
                        'UPDATE PYORACLE_ASYNC_ADR SET v = v + 10 WHERE g = :1',
                        [(1,), (2,), (3,), (9,)],
                        arraydmlrowcounts=True,
                    )
                    self.assertEqual(Cur.getarraydmlrowcounts(), [3, 1, 2, 0])
                    # Combined with batcherrors a failed iteration counts 0.
                    await Cur.executemany(
                        'INSERT INTO PYORACLE_ASYNC_ADR VALUES (:1, :2)',
                        [(7, 7), (7, 7)],
                    )
                    await Cur.executemany(
                        'INSERT INTO PYORACLE_ASYNC_ADR VALUES (:1, :2)',
                        [(8, 8), (9, 9)],
                        arraydmlrowcounts=True,
                    )
                    self.assertEqual(Cur.getarraydmlrowcounts(), [1, 1])
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_ADR')

    @_requires(_PRE12_ROWCOUNTS_REFUSAL)
    async def test_async_arraydmlrowcounts_unsupported_on_11g(self):
        # On an 11g server the async feature is rejected up front, same as sync.

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('CREATE TABLE PYORACLE_ASYNC_NS (id NUMBER)')
                try:
                    with self.assertRaises(seerdb.NotSupportedError):
                        await Cur.executemany(
                            'INSERT INTO PYORACLE_ASYNC_NS VALUES (:1)',
                            [(1,), (2,)],
                            arraydmlrowcounts=True,
                        )
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_NS')

    async def test_async_gettype_of_a_tables_rowtype(self):
        # The async gettype resolves `T%ROWTYPE` as the sync one does (#1476).
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'CREATE TABLE PYORACLE_ASYNC_RT (n NUMBER, s VARCHAR2(5))'
                )
                try:
                    typ = await Conn.gettype('PYORACLE_ASYNC_RT%ROWTYPE')
                    self.assertEqual(typ.attr_names, ['N', 'S'])
                finally:
                    await Cur.execute('DROP TABLE PYORACLE_ASYNC_RT')

    async def test_async_callproc_refcursor(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'CREATE OR REPLACE PROCEDURE PYORACLE_ASYNC_RC'
                    '(p_rc OUT SYS_REFCURSOR) AS BEGIN OPEN p_rc FOR '
                    "SELECT 1 AS a, 'x' AS b FROM dual "
                    "UNION ALL SELECT 2, 'y' FROM dual; END;"
                )
                try:
                    rc = Cur.var(seerdb.CURSOR)
                    await Cur.callproc('PYORACLE_ASYNC_RC', [rc])
                    nested = rc.getvalue()
                    self.assertEqual([d[0] for d in nested.description], ['A', 'B'])
                    self.assertEqual(await nested.fetchall(), [(1, 'x'), (2, 'y')])
                finally:
                    await Cur.execute('DROP PROCEDURE PYORACLE_ASYNC_RC')

    async def test_async_refcursor_nested_in_a_nested_cursor_fetches(self):
        # A CURSOR(...) inside a CURSOR(...): the inner cursor is a cursor too,
        # not the decoder's marker dict the async path left there (#1464).
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "SELECT CURSOR(SELECT 1, CURSOR(SELECT 'inner' FROM dual) "
                    'FROM dual) FROM dual'
                )
                ((outer,),) = await Cur.fetchall()
                ((one, inner),) = await outer.fetchall()
                self.assertEqual(one, 1)
                self.assertEqual(await inner.fetchall(), [('inner',)])

    async def test_async_callfunc(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'CREATE OR REPLACE FUNCTION PYORACLE_ASYNC_FUNC'
                    '(p IN NUMBER) RETURN NUMBER AS BEGIN RETURN p * 2; END;'
                )
                try:
                    self.assertEqual(
                        await Cur.callfunc('PYORACLE_ASYNC_FUNC', seerdb.NUMBER, [21]),
                        42,
                    )
                finally:
                    await Cur.execute('DROP FUNCTION PYORACLE_ASYNC_FUNC')

    async def test_async_pipeline(self):
        # Async mirror of PipelineIntegration (#132).
        table = 'PYORACLE_APIPE'
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            cur = Conn.cursor()
            try:
                await cur.execute(f'DROP TABLE {table}')
            except seerdb.DatabaseError:
                # best-effort drop of a table that may not exist
                pass
            await cur.execute(f'CREATE TABLE {table} (id NUMBER)')
            p = seerdb.create_pipeline()
            p.add_execute(f'INSERT INTO {table} VALUES (1)')
            p.add_executemany(f'INSERT INTO {table} VALUES (:1)', [(2,), (3,)])
            p.add_commit()
            p.add_fetchall(f'SELECT id FROM {table} ORDER BY id')
            results = await Conn.run_pipeline(p)
            self.assertEqual(results[3].rows, [(1,), (2,), (3,)])
            self.assertTrue(all(r.error is None for r in results))
            await cur.execute(f'DROP TABLE {table}')

    @_requires(_REF_BIND)
    async def test_async_ref_bind(self):
        # Async mirror of RefBindIntegration (#139): fetch a REF, bind it back.

        TYPE, PEOPLE, REFS = (
            'PYORACLE_AREF_T',
            'PYORACLE_AREF_PEOPLE',
            'PYORACLE_AREF_REFS',
        )
        Conn = await seerdb.connect_async(**self._kwargs())
        drops = (f'DROP TABLE {REFS}', f'DROP TABLE {PEOPLE}', f'DROP TYPE {TYPE}')
        try:
            # Checked before creating anything, so a skip leaves nothing behind
            # (#1224).
            cur = Conn.cursor()
            for s in drops:
                try:
                    await cur.execute(s)
                except seerdb.DatabaseError:
                    # best-effort drop of a table that may not exist
                    pass
            await cur.execute(
                f'CREATE TYPE {TYPE} AS OBJECT (id NUMBER, name VARCHAR2(40))'
            )
            await cur.execute(f'CREATE TABLE {PEOPLE} OF {TYPE}')
            await cur.execute(f"INSERT INTO {PEOPLE} VALUES (1, 'Alice')")
            await cur.execute(f'CREATE TABLE {REFS} (id NUMBER, r REF {TYPE})')
            await cur.execute(f'SELECT REF(p) FROM {PEOPLE} p WHERE p.id = 1')
            ref = (await cur.fetchone())[0]
            await cur.execute(f'INSERT INTO {REFS} (id, r) VALUES (:1, :2)', [100, ref])
            await cur.execute(f'SELECT id, DEREF(r).name FROM {REFS} WHERE id = 100')
            self.assertEqual(await cur.fetchone(), (100, 'Alice'))
        finally:
            cur = Conn.cursor()
            for s in drops:
                try:
                    await cur.execute(s)
                except seerdb.DatabaseError:
                    # best-effort drop of a table that may not exist
                    pass
            await Conn.close()

    async def test_async_sessionless_suspend_resume(self):
        # Async mirror of SessionlessTransactionIntegration (#133): suspend on
        # one async connection, resume + commit on another. Skips below 23ai.
        from seerdb.common.exceptions import NotSupportedError

        Kw = dict(self._kwargs())
        Kw['autocommit'] = False
        table = 'PYORACLE_ASL_TEST'
        setup = await seerdb.connect_async(**Kw)
        c1 = c2 = None
        try:
            # Probe before creating anything, so a pre-23ai skip leaves no
            # table behind (#1224). A fresh id, rolled back while active: one
            # suspended under a fixed id outlived the test (#1755).
            try:
                await setup.begin_sessionless_transaction(timeout=10)
            except NotSupportedError:
                self.skipTest('sessionless transactions need a 23ai+ server')
            await setup.rollback()
            scur = setup.cursor()
            try:
                await scur.execute(f'DROP TABLE {table}')
            except seerdb.DatabaseError as e:
                if e.code != 942:
                    raise
            await scur.execute(f'CREATE TABLE {table} (id NUMBER)')
            await setup.commit()

            c1 = await seerdb.connect_async(**Kw)
            await c1.begin_sessionless_transaction('asl-1', timeout=120)
            await c1.cursor().execute(f'INSERT INTO {table} VALUES (10)')
            await c1.suspend_sessionless_transaction()

            c2 = await seerdb.connect_async(**Kw)
            await c2.resume_sessionless_transaction('asl-1', timeout=120)
            await c2.cursor().execute(f'INSERT INTO {table} VALUES (20)')
            await c2.commit()

            ccur = c2.cursor()
            await ccur.execute(f'SELECT id FROM {table} ORDER BY id')
            self.assertEqual(await ccur.fetchall(), [(10,), (20,)])
        finally:
            for c in (c1, c2):
                if c is not None:
                    await c.close()
            # The table the test made, on the connection that made it, now that
            # no other session holds it (#1224).
            try:
                await self._drop_async(setup.cursor(), table)
            finally:
                await setup.close()


@unittest.skipUnless(
    _USER and os.environ.get('SEERDB_TEST_BFILE_DIR'),
    'BFILE tests need SEERDB_TEST_BFILE_DIR (Oracle DIRECTORY object '
    'name that already exists, with READ granted to the test user, plus '
    'a file named `pyoracle_bfile_test.txt` containing the text '
    "'hello bfile from disk'). The test user also needs EXECUTE on "
    'DBMS_LOB and CREATE PROCEDURE so the helper function can install '
    'itself on first call.',
)
class BFILEIntegration(_ThrottleRetry, unittest.TestCase):
    """Verify BFILE read round-trips."""

    def setUp(self):
        self.conn = seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            **_FV_KW,
        )
        self.cur = self.conn.cursor()
        self.dir = os.environ['SEERDB_TEST_BFILE_DIR']

    def tearDown(self):
        self.conn.close()

    def test_bfile_select_returns_file_contents(self):
        # The user-facing path: a plain SELECT of a BFILE column hands back the
        # LOB, and reading it gives the file's bytes.
        #
        # It used to hand back the bytes directly, resolved at fetch time. #1101
        # stopped that on purpose: reading a BFILE OPENS the file, so the SELECT
        # itself raised ORA-22285 for a missing directory where the reference
        # client simply returns a locator. The content still arrives -- one
        # explicit read later (#1119).
        self.cur.execute(
            'SELECT BFILENAME(:d, :f) FROM DUAL',
            {'d': self.dir, 'f': _BFILE_TEST_FILE},
        )
        (Lob,) = self.cur.fetchone()
        self.assertTrue(Lob.is_file)
        self.assertEqual(Lob.read(), _BFILE_TEST_CONTENT)

    def test_bfile_locator_parsing(self):
        # The LOB-object surface: directory_name / filename / is_file
        # attributes from the locator bytes. Auto-resolve has to be off
        # to see the LOB object before it's read.
        import seerdb.client.cursor as _cm

        Saved = _cm._resolve_lobs
        _cm._resolve_lobs = lambda c, r: r
        try:
            self.cur.execute(
                'SELECT BFILENAME(:d, :f) FROM DUAL',
                {'d': self.dir, 'f': _BFILE_TEST_FILE},
            )
            (Lob,) = self.cur.fetchone()
        finally:
            _cm._resolve_lobs = Saved
        self.assertTrue(Lob.is_file)
        self.assertTrue(Lob.is_binary)
        self.assertFalse(Lob.is_character)
        self.assertEqual(Lob.directory_name, self.dir)
        self.assertEqual(Lob.filename, _BFILE_TEST_FILE)

    def test_bfile_fileexists_against_a_real_directory(self):
        # The server's own answer for a directory that DOES exist: True for the
        # file that is there, False for one that is not -- no error either way,
        # because the alias resolves (#1109). fetch_lobs=False rather than the
        # monkeypatch the sibling test uses: fileexists() needs the connection,
        # and stubbing the resolver out is what attaches it.
        Conn = _connect(fetch_lobs=False)
        try:
            Cur = Conn.cursor()
            Cur.execute(
                'SELECT BFILENAME(:d, :f) FROM DUAL',
                {'d': self.dir, 'f': _BFILE_TEST_FILE},
            )
            (Lob,) = Cur.fetchone()
            self.assertEqual(Lob.getfilename(), (self.dir, _BFILE_TEST_FILE))
            self.assertIs(Lob.fileexists(), True)
            # ...and the same locator pointed at a file that is not there. The
            # 16-byte header the server minted is kept, so it stays valid.
            Lob.setfilename(self.dir, 'pyo_no_such_file.txt')
            self.assertEqual(Lob.getfilename(), (self.dir, 'pyo_no_such_file.txt'))
            self.assertIs(Lob.fileexists(), False)
        finally:
            Conn.close()


@unittest.skipUnless(
    _USER and os.environ.get('SEERDB_TEST_BFILE_DIR'),
    'Async BFILE tests share the same fixture requirements as the '
    'sync BFILEIntegration.',
)
class AsyncBFILEIntegration(_ThrottleRetry, unittest.IsolatedAsyncioTestCase):
    async def test_async_bfile_select_returns_file_contents(self):
        Dir = os.environ['SEERDB_TEST_BFILE_DIR']
        async with await seerdb.connect_async(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            **_FV_KW,
        ) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'SELECT BFILENAME(:d, :f) FROM DUAL',
                    {'d': Dir, 'f': _BFILE_TEST_FILE},
                )
                (Lob,) = await Cur.fetchone()
                self.assertTrue(Lob.is_file)
                self.assertEqual(await Lob.aread(), _BFILE_TEST_CONTENT)

    async def test_async_bfile_fileexists(self):
        # Sync/async parity for the BFILE round-trip (#1109).
        Dir = os.environ['SEERDB_TEST_BFILE_DIR']
        async with await seerdb.connect_async(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            fetch_lobs=False,
            **_FV_KW,
        ) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    'SELECT BFILENAME(:d, :f) FROM DUAL',
                    {'d': Dir, 'f': _BFILE_TEST_FILE},
                )
                (Lob,) = await Cur.fetchone()
                self.assertEqual(Lob.getfilename(), (Dir, _BFILE_TEST_FILE))
                self.assertIs(await Lob.afileexists(), True)
                Lob.setfilename(Dir, 'pyo_no_such_file.txt')
                self.assertIs(await Lob.afileexists(), False)


@unittest.skipUnless(_USER, _SKIP_REASON)
class AsyncPoolIntegration(_ThrottleRetry, unittest.IsolatedAsyncioTestCase):
    """AsyncPool: pre-warm, acquire / release, capacity, timeout,
    health-check on dead connection."""

    def _kwargs(self, **extra):
        return dict(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            # What the test asks for over the suite's settings (#2466).
            **{**_FV_KW, **extra},
        )

    async def test_pre_warms_to_min_and_runs_query(self):
        Pool = await seerdb.create_pool_async(min=2, max=3, **self._kwargs())
        try:
            self.assertEqual(Pool.opened, 2)
            self.assertEqual(Pool.busy, 0)
            async with Pool.acquire() as Conn:
                self.assertEqual(Pool.busy, 1)
                Cur = Conn.cursor()
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))
            self.assertEqual(Pool.busy, 0)
        finally:
            await Pool.close()

    async def test_acquire_gives_the_connection_itself(self):
        # Awaited, as python-oracledb's is (#2555).
        Pool = await seerdb.create_pool_async(min=1, max=1, **self._kwargs())
        try:
            Conn = await Pool.acquire()
            Cur = Conn.cursor()
            await Cur.execute('SELECT 1 FROM dual')
            self.assertEqual(await Cur.fetchone(), (1,))
            await Pool.release(Conn)
            self.assertEqual(Pool.busy, 0)
            Conn = await Pool.acquire()
            await Conn.close()
            self.assertEqual((Pool.busy, Pool.opened), (0, 1))
        finally:
            await Pool.close()

    async def test_grows_to_max_and_releases_for_reuse(self):
        Pool = await seerdb.create_pool_async(min=1, max=3, **self._kwargs())
        try:
            G1 = Pool.acquire()
            await G1.__aenter__()
            G2 = Pool.acquire()
            await G2.__aenter__()
            G3 = Pool.acquire()
            await G3.__aenter__()
            self.assertEqual(Pool.busy, 3)
            self.assertEqual(Pool.opened, 3)
            await G1.__aexit__(None, None, None)
            self.assertEqual(Pool.busy, 2)
            async with Pool.acquire():
                # Pool reused the released entry; should NOT have grown.
                self.assertEqual(Pool.busy, 3)
                self.assertEqual(Pool.opened, 3)
            await G2.__aexit__(None, None, None)
            await G3.__aexit__(None, None, None)
        finally:
            await Pool.close()

    async def test_acquire_times_out_when_full(self):
        Pool = await seerdb.create_pool_async(
            min=1,
            max=1,
            timeout=0.3,
            **self._kwargs(),
        )
        try:
            async with Pool.acquire():
                with self.assertRaises(seerdb.InterfaceError):
                    async with Pool.acquire():
                        pass
        finally:
            await Pool.close()

    async def test_acquire_after_close_raises(self):
        Pool = await seerdb.create_pool_async(min=1, max=2, **self._kwargs())
        await Pool.close()
        with self.assertRaises(seerdb.InterfaceError):
            async with Pool.acquire():
                pass

    async def test_getmode_nowait_raises_when_full(self):
        Pool = await seerdb.create_pool_async(
            min=1, max=1, getmode=seerdb.POOL_GETMODE_NOWAIT, **self._kwargs()
        )
        try:
            async with Pool.acquire():
                with self.assertRaises(seerdb.InterfaceError):
                    async with Pool.acquire():
                        pass
        finally:
            await Pool.close()

    async def test_max_lifetime_session_replaces_a_connection(self):
        Pool = await seerdb.create_pool_async(
            min=1, max=1, max_lifetime_session=1, **self._kwargs()
        )
        try:
            async with Pool.acquire() as First:
                pass
            await asyncio.sleep(1.1)
            async with Pool.acquire() as Second:
                self.assertIsNot(Second, First)
                Cur = Second.cursor()
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))
        finally:
            await Pool.close()

    async def test_session_callback_sets_each_connection_up_once(self):
        # Async twin: a coroutine callback, awaited the first time only.
        calls = []

        async def setup(conn, tag):
            calls.append(tag)
            async with conn.cursor() as cur:
                await cur.execute("ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD'")

        pool = await seerdb.create_pool_async(
            min=1, max=1, session_callback=setup, **self._kwargs()
        )
        try:
            for _ in range(2):
                async with pool.acquire() as conn:
                    cur = conn.cursor()
                    await cur.execute(
                        'SELECT value FROM nls_session_parameters '
                        "WHERE parameter = 'NLS_DATE_FORMAT'"
                    )
                    self.assertEqual(await cur.fetchone(), ('YYYY-MM-DD',))
            self.assertEqual(calls, [None])
        finally:
            await pool.close()

    async def test_a_named_pool_hands_out_by_its_alias(self):
        pool = await seerdb.create_pool_async(
            min=1, max=1, pool_alias='alive', **self._kwargs()
        )
        try:
            async with await seerdb.connect_async(pool_alias='alive') as conn:
                cur = conn.cursor()
                await cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await cur.fetchone(), (1,))
                self.assertEqual(pool.busy, 1)
            self.assertEqual(pool.busy, 0)
        finally:
            await pool.close()
        self.assertIsNone(seerdb.get_pool('alive'))

    async def test_reconfigure_resizes_a_live_pool(self):
        Pool = await seerdb.create_pool_async(min=1, max=3, **self._kwargs())
        try:
            await Pool.reconfigure(min=2)
            self.assertEqual(Pool.opened, 2)
            async with Pool.acquire() as Conn:
                Cur = Conn.cursor()
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))
            await Pool.reconfigure(min=1, max=1)
            self.assertEqual(Pool.opened, 1)
        finally:
            await Pool.close()

    async def test_health_check_replaces_dead_connection(self):
        Pool = await seerdb.create_pool_async(
            min=1,
            max=2,
            idle_timeout=0,
            **self._kwargs(),
        )
        try:
            G = Pool.acquire()
            Conn = await G.__aenter__()
            await G.__aexit__(None, None, None)
            # Sabotage the underlying writer to force the next health-check
            # to see a dead session.
            try:
                Conn._writer.close()
                await Conn._writer.wait_closed()
            except Exception:
                # Best-effort: deliberately sabotaging the writer for the
                # test; any close error here is irrelevant.
                pass
            async with Pool.acquire() as Conn2:
                Cur = Conn2.cursor()
                await Cur.execute('SELECT 1 FROM dual')
                self.assertEqual(await Cur.fetchone(), (1,))
        finally:
            await Pool.close()


@unittest.skipUnless(_USER, _SKIP_REASON)
class SSLIntegration(_ThrottleRetry, unittest.TestCase):
    """Verify the TLS wrap by talking to Oracle through a local TLS proxy.

    The proxy terminates TLS on a random local port and forwards plaintext
    to the configured Oracle listener, so we can exercise the full TLS
    handshake + encrypted TNS exchange without reconfiguring Oracle itself.
    """

    @classmethod
    def setUpClass(cls):
        if _target_is_8i():
            # Not a driver limitation: Oracle 8i is dedicated-server, so its
            # listener redirects every session to a dynamic dedicated-server port
            # and drops the listener socket. seerdb follows that redirect fine on
            # plaintext (see RedirectIntegration), but this fixture only wraps the
            # listener port in TLS — the redirect target is a plaintext port
            # outside the tunnel, so the TLS session can't follow it. A real TCPS
            # 8i deployment terminates TLS end-to-end; the fixture can't. (#388)
            raise unittest.SkipTest(
                'Oracle 8i dedicated-server redirect escapes the TLS-proxy fixture'
            )

    def setUp(self):
        # A fresh proxy per test (#2228). Several tests here fail the TLS
        # handshake on purpose (no-CA, hostname mismatch); a single proxy shared
        # across the class via setUpClass meant a failed handshake's server-side
        # teardown — and the shared TLS context's session state — could race the
        # next test's connection, which showed up as an intermittent client
        # `UNEXPECTED_MESSAGE` in CI. A proxy per test gives each one its own
        # socket and SSLContext, so no state crosses from one test to the next.
        self.proxy = TLSProxy(_HOST, _PORT)
        self.proxy.start()

    def tearDown(self):
        if getattr(self, 'proxy', None) is not None:
            self.proxy.stop()
            self.proxy = None

    def _connect_via_tls(self, **overrides):
        Kwargs = dict(
            host='127.0.0.1',
            port=self.proxy.listen_port,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            ssl={'ca_certs': CERT_PATH, 'server_hostname': 'localhost'},
        )
        Kwargs.update(overrides)
        return seerdb.connect(**Kwargs)

    def test_tls_select_round_trip(self):
        with self._connect_via_tls() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 'tls works', 7 FROM dual")
            self.assertEqual(cur.fetchone(), ('tls works', 7))

    def test_tls_with_explicit_ssl_context(self):
        Ctx = ssl.create_default_context(cafile=CERT_PATH)
        with self._connect_via_tls(ssl=Ctx) as conn:
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM dual')
            self.assertEqual(cur.fetchone(), (1,))

    def test_tls_no_ca_fails_handshake(self):
        # Default context with no extra trust → our self-signed cert is
        # rejected. The exact exception class is platform-dependent (SSLError
        # vs SSLCertVerificationError); both are subclasses of OSError.
        with self.assertRaises((ssl.SSLError, OSError)):
            self._connect_via_tls(ssl=True)

    def test_tls_hostname_mismatch_fails(self):
        # Cert SAN covers localhost / 127.0.0.1; pretend we asked for a
        # different hostname and expect the cert to fail verification.
        with self.assertRaises((ssl.SSLError, OSError)):
            self._connect_via_tls(
                ssl={'ca_certs': CERT_PATH, 'server_hostname': 'elsewhere.test'},
            )

    def test_tls_verify_disabled_accepts_self_signed(self):
        with self._connect_via_tls(
            ssl={'check_hostname': False, 'verify_mode': ssl.CERT_NONE},
        ) as conn:
            cur = conn.cursor()
            cur.execute("SELECT 'no-verify' FROM dual")
            self.assertEqual(cur.fetchone(), ('no-verify',))

    def test_tls_unknown_option_rejected(self):
        with self.assertRaises(ValueError):
            self._connect_via_tls(
                ssl={
                    'ca_certs': CERT_PATH,
                    'server_hostname': 'localhost',
                    'made_up_option': True,
                }
            )

    def test_ssl_none_still_plain(self):
        # Connecting directly to the plaintext Oracle port with ssl=None
        # should work unchanged — this guards against regressions in the
        # default code path.
        with seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            **_FV_KW,
        ) as conn:
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM dual')
            self.assertEqual(cur.fetchone(), (1,))


@unittest.skipUnless(_USER, _SKIP_REASON)
class CallprocIntegration(_IntegrationBase):
    """OUT / IN OUT binds via cursor.var + callproc against a real procedure."""

    PROC = 'SEERDB_TEST_PROC'

    def tearDown(self):
        try:
            with self.conn.cursor() as c:
                try:
                    c.execute(f'DROP PROCEDURE {self.PROC}')
                except seerdb.DatabaseError:
                    pass  # ORA-04043: procedure does not exist
        finally:
            super().tearDown()

    def _make(self, signature_and_body: str):
        self.cur.execute(
            f'CREATE OR REPLACE PROCEDURE {self.PROC} {signature_and_body}'
        )

    def test_callproc_out(self):
        self._make(
            '(p_in IN NUMBER, p_out OUT NUMBER) AS BEGIN p_out := p_in * 2; END;'
        )
        o = self.cur.var(int)
        ret = self.cur.callproc(self.PROC, [21, o])
        self.assertEqual(o.getvalue(), 42)
        self.assertEqual(ret, [21, 42])

    def test_a_block_that_does_not_compile_is_ora_06550(self):
        # A block naming an undeclared identifier, and a function called as a
        # procedure, fail to compile: ORA-06550, with the position of what is
        # wrong. The Mirror over PostgreSQL raised ORA-00900 for the first and ran
        # the second (#1497).
        with self.assertRaises(seerdb.DatabaseError) as raised:
            self.cur.execute('begin t_Missing := 5; end;')
        self.assertEqual(raised.exception.code, 6550)
        self.assertIn('T_MISSING', str(raised.exception).upper())
        fn = f'{self.PROC}_F'
        self.cur.execute(
            f'CREATE OR REPLACE FUNCTION {fn}(p IN NUMBER) RETURN NUMBER AS '
            'BEGIN RETURN p; END;'
        )
        try:
            with self.assertRaises(seerdb.DatabaseError) as raised:
                self.cur.callproc(fn, [1])
            self.assertEqual(raised.exception.code, 6550)
        finally:
            self.cur.execute(f'DROP FUNCTION {fn}')

    def test_a_long_out_bind_returns_its_value(self):
        # A LONG / LONG RAW OUT bind returns its value. Through the Mirror the
        # value went out in a LONG column's chunked form, and the client read
        # the bytes after it as an unknown message (#1458).
        text = self.cur.var(seerdb.DB_TYPE_LONG)
        self.cur.execute("BEGIN :v := 'abc' || RPAD('x', 300, 'y'); END;", [text])
        self.assertEqual(text.getvalue(), 'abc' + 'x' + 'y' * 299)
        raw = self.cur.var(seerdb.DB_TYPE_LONG_RAW)
        self.cur.execute("BEGIN :v := HEXTORAW('0A0B'); END;", [raw])
        self.assertEqual(raw.getvalue(), b'\n\x0b')

    def test_a_bare_pad_call_out_bind(self):
        # `:v := RPAD(s, n, p)` as the whole right-hand side (#2337): a bare
        # function-call assignment, which the Mirror over PostgreSQL routed to a
        # direct SELECT that dropped the literal arguments, building a wrong-arity
        # call PostgreSQL refused and the error mapped to PLS-00306. Oracle runs
        # it from 8i up; RPAD / LPAD here are PL/SQL's.
        v = self.cur.var(str, 4000)
        self.cur.execute("BEGIN :v := RPAD('o', 4000, 'p'); END;", [v])
        self.assertEqual(v.getvalue(), 'o' + 'p' * 3999)
        self.cur.execute("BEGIN :v := LPAD('o', 5, '.'); END;", [v])
        self.assertEqual(v.getvalue(), '....o')

    def test_callproc_body_with_a_parenthesised_alias(self):
        # A body selecting `count(*) AS cnt`: the Mirror over PostgreSQL took that
        # `) AS` for the end of the parameter list and split the routine (#1467).
        self._make(
            '(p_out OUT NUMBER) AS BEGIN '
            'SELECT count(*) AS cnt INTO p_out FROM dual; END;'
        )
        o = self.cur.var(int)
        self.cur.callproc(self.PROC, [o])
        self.assertEqual(o.getvalue(), 1)

    def test_callproc_inout(self):
        self._make("(p_io IN OUT VARCHAR2) AS BEGIN p_io := p_io || '!'; END;")
        io = self.cur.var(str)
        io.setvalue(0, 'hi')
        ret = self.cur.callproc(self.PROC, [io])
        self.assertEqual(io.getvalue(), 'hi!')
        self.assertEqual(ret, ['hi!'])

    def test_callproc_out_and_inout(self):
        self._make(
            '(p_in IN NUMBER, p_out OUT NUMBER, p_io IN OUT VARCHAR2) AS '
            "BEGIN p_out := p_in * 2; p_io := p_io || '!'; END;"
        )
        o = self.cur.var(seerdb.NUMBER)
        io = self.cur.var(seerdb.STRING)
        io.setvalue(0, 'hi')
        ret = self.cur.callproc(self.PROC, [5, o, io])
        self.assertEqual(ret, [5, 10, 'hi!'])

    def test_callproc_string_out(self):
        self._make("(p OUT VARCHAR2) AS BEGIN p := 'seerdb'; END;")
        s = self.cur.var(str)
        self.cur.callproc(self.PROC, [s])
        self.assertEqual(s.getvalue(), 'seerdb')

    def test_null_scalar_out_bind(self):
        # A NULL scalar OUT bind: the IOV return code is a variable-length int
        # (ub4(-1) = 2 bytes for NULL vs one 0x00 byte for non-NULL), so a fixed
        # 1-byte skip desynced the decoder (#205). A mix of NULL and non-NULL
        # OUT binds in one block must all decode.
        a, b, c = (self.cur.var(str) for _ in range(3))
        self.cur.execute("BEGIN :1 := 'x'; :2 := NULL; :3 := 'z'; END;", [a, b, c])
        self.assertEqual((a.getvalue(), b.getvalue(), c.getvalue()), ('x', None, 'z'))
        only = self.cur.var(str)
        self.cur.execute('BEGIN :1 := NULL; END;', [only])
        self.assertIsNone(only.getvalue())

    def test_execute_out_var(self):
        y = self.cur.var(seerdb.NUMBER)
        self.cur.execute('BEGIN :y := 7 * 6; END;', [y])
        self.assertEqual(y.getvalue(), 42)

    def test_callproc_refcursor(self):
        self._make(
            '(p_rc OUT SYS_REFCURSOR) AS BEGIN OPEN p_rc FOR '
            "SELECT 1 AS a, 'x' AS b FROM dual "
            "UNION ALL SELECT 2, 'y' FROM dual; END;"
        )
        rc = self.cur.var(seerdb.CURSOR)
        self.cur.callproc(self.PROC, [rc])
        nested = rc.getvalue()
        self.assertEqual([d[0] for d in nested.description], ['A', 'B'])
        self.assertEqual(nested.fetchall(), [(1, 'x'), (2, 'y')])

    def test_a_refcursor_nested_in_a_nested_cursor_fetches(self):
        # A CURSOR(...) inside a CURSOR(...): a cursor whose rows hold cursors.
        # Fetched with TTI_FETCH, 10g-21c sent each inner cursor without its
        # describe, and the decoder desynced (#1462).
        self.cur.execute(
            "SELECT CURSOR(SELECT 1, CURSOR(SELECT 'inner' FROM dual) FROM dual) "
            'FROM dual'
        )
        ((outer,),) = self.cur.fetchall()
        ((one, inner),) = outer.fetchall()
        self.assertEqual(one, 1)
        self.assertEqual(inner.fetchall(), [('inner',)])

    def test_callproc_refcursor_holding_a_cursor(self):
        # A REF CURSOR whose rows hold a CURSOR(...) column: the inner cursor
        # fetches too. The Mirror parked the REF CURSOR but not the cursors in
        # its rows, and the session died when the client drained it (#1465).
        self._make(
            '(p_rc OUT SYS_REFCURSOR) AS BEGIN OPEN p_rc FOR '
            "SELECT 2 a, CURSOR(SELECT 'deep' FROM dual) c FROM dual; END;"
        )
        rc = self.cur.var(seerdb.CURSOR)
        self.cur.callproc(self.PROC, [rc])
        ((two, deep),) = rc.getvalue().fetchall()
        self.assertEqual(two, 2)
        self.assertEqual(deep.fetchall(), [('deep',)])

    def test_callfunc_number(self):
        fn = f'{self.PROC}_F'
        self.cur.execute(
            f'CREATE OR REPLACE FUNCTION {fn}(p IN NUMBER) RETURN NUMBER AS '
            'BEGIN RETURN p + 100; END;'
        )
        try:
            self.assertEqual(self.cur.callfunc(fn, seerdb.NUMBER, [5]), 105)
            self.assertEqual(self.cur.callfunc(fn, int, [0]), 100)
        finally:
            self.cur.execute(f'DROP FUNCTION {fn}')

    def test_callfunc_string(self):
        fn = f'{self.PROC}_F'
        self.cur.execute(
            f'CREATE OR REPLACE FUNCTION {fn}(p IN NUMBER, q IN VARCHAR2) '
            "RETURN VARCHAR2 AS BEGIN RETURN q || ':' || TO_CHAR(p * 2); END;"
        )
        try:
            self.assertEqual(self.cur.callfunc(fn, str, [21, 'x']), 'x:42')
        finally:
            self.cur.execute(f'DROP FUNCTION {fn}')

    # ----- OUT binds for the extended scalar types (issue #17) -----

    def test_callproc_out_timestamp(self):
        self._make(
            "(p OUT TIMESTAMP) AS BEGIN p := TIMESTAMP '2026-06-07 13:14:15.5'; END;"
        )
        v = self.cur.var(seerdb.DB_TYPE_TIMESTAMP)
        self.cur.callproc(self.PROC, [v])
        self.assertEqual(
            v.getvalue(), datetime.datetime(2026, 6, 7, 13, 14, 15, 500000)
        )

    def test_callproc_out_timestamp_tz(self):
        self._make(
            '(p OUT TIMESTAMP WITH TIME ZONE) AS BEGIN '
            "p := TIMESTAMP '2026-06-07 13:14:15.5 +02:00'; END;"
        )
        v = self.cur.var(seerdb.DB_TYPE_TIMESTAMP_TZ)
        self.cur.callproc(self.PROC, [v])
        got = v.getvalue()
        self.assertEqual(got.utcoffset(), datetime.timedelta(hours=2))
        self.assertEqual(
            got.replace(tzinfo=None), datetime.datetime(2026, 6, 7, 13, 14, 15, 500000)
        )

    def test_callproc_out_binary_float(self):
        self._make('(p OUT BINARY_FLOAT) AS BEGIN p := 1.5; END;')
        v = self.cur.var(seerdb.DB_TYPE_BINARY_FLOAT)
        self.cur.callproc(self.PROC, [v])
        self.assertEqual(v.getvalue(), 1.5)

    def test_callproc_out_binary_double(self):
        self._make('(p OUT BINARY_DOUBLE) AS BEGIN p := 2.25; END;')
        v = self.cur.var(seerdb.DB_TYPE_BINARY_DOUBLE)
        self.cur.callproc(self.PROC, [v])
        self.assertEqual(v.getvalue(), 2.25)

    def test_callproc_out_interval_ds(self):
        self._make(
            '(p OUT INTERVAL DAY TO SECOND) AS BEGIN '
            "p := INTERVAL '1 02:03:04.5' DAY TO SECOND; END;"
        )
        v = self.cur.var(seerdb.DB_TYPE_INTERVAL_DS)
        self.cur.callproc(self.PROC, [v])
        self.assertEqual(
            v.getvalue(),
            datetime.timedelta(days=1, hours=2, minutes=3, seconds=4, milliseconds=500),
        )

    def test_callproc_out_interval_ym(self):
        self._make(
            '(p OUT INTERVAL YEAR TO MONTH) AS BEGIN '
            "p := INTERVAL '3-7' YEAR TO MONTH; END;"
        )
        v = self.cur.var(seerdb.DB_TYPE_INTERVAL_YM)
        self.cur.callproc(self.PROC, [v])
        self.assertEqual(v.getvalue(), seerdb.IntervalYM(3, 7))

    def test_callfunc_binary_double(self):
        fn = f'{self.PROC}_F'
        self.cur.execute(
            f'CREATE OR REPLACE FUNCTION {fn} RETURN BINARY_DOUBLE AS '
            'BEGIN RETURN 9.875; END;'
        )
        try:
            self.assertEqual(self.cur.callfunc(fn, seerdb.DB_TYPE_BINARY_DOUBLE), 9.875)
        finally:
            self.cur.execute(f'DROP FUNCTION {fn}')


@unittest.skipUnless(_USER, _SKIP_REASON)
@unittest.skipUnless(_ADMIN_USER, _ADMIN_SKIP_REASON)
class PreSha2VerifierLoginIntegration(_ThrottleRetry, unittest.TestCase):
    """#311/#312: authenticate an account whose *only* password verifier is the
    11g SHA-1 one against a modern (12c+) server.

    Such a server sends AUTH_VFR_DATA (an 11g salt, with verifier-type flag
    6949) *and* AUTH_PBKDF2_CSK_SALT together, and the client must combine
    SHA-1 key material with the modern PBKDF2 (192-bit) session-key derivation.
    Before #312 this raised ORA-01017.

    A stock account always also carries the SHA-2 (``T:``) verifier, so the
    server would pick SHA-2 and never exercise this path. We forge an 11g-only
    account with a supported ``IDENTIFIED BY VALUES 'S:<sha1||salt>'`` — no
    SYS.USER$ surgery (that is ORA-41900 on 23ai). Needs a DBA to create the
    account and skips on a pre-12c server, which does not send
    AUTH_PBKDF2_CSK_SALT and so is not this path.
    """

    _ACCOUNT = 'PYO_VFR11G'
    _PW = 'pyo123'
    _SALT = bytes(range(1, 11))  # fixed salt → deterministic 11g verifier

    @classmethod
    def _s_verifier(cls) -> str:
        # Oracle 11g verifier: SHA1(password_bytes || salt) || salt, stored as
        # S:<40-hex sha1><20-hex salt>. The server hands the salt back as
        # AUTH_VFR_DATA during O5LOGON; the client recomputes the same SHA1.
        from hashlib import sha1

        digest = sha1(cls._PW.encode() + cls._SALT).digest()
        return 'S:' + (digest + cls._SALT).hex().upper()

    def _admin_ddl(self, *statements: str) -> None:
        cur = self._admin.cursor()
        try:
            for sql in statements:
                cur.execute(sql)
        finally:
            cur.close()

    def _drop_account(self) -> None:
        try:
            self._admin_ddl(f'DROP USER {self._ACCOUNT} CASCADE')
        except seerdb.DatabaseError:
            # First run (or a clean teardown already happened): nothing to drop.
            pass

    def setUp(self):
        # This path only exists on a 12c+ server (it alone sends
        # AUTH_PBKDF2_CSK_SALT). Detect the tier from a normal connection's
        # negotiated field version and skip cleanly on 9i/10g/11g *before*
        # provisioning, so no DBA is needed on those tiers.
        probe = _connect()
        modern = probe.field_version >= FIELD_VERSION_12_1
        probe.close()
        if not modern:
            self.skipTest('#311 path needs a 12c+ server (sends AUTH_PBKDF2_CSK_SALT)')
        self._admin = seerdb.connect(
            host=_HOST,
            port=_PORT,
            user=_ADMIN_USER,
            password=_ADMIN_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            **_FV_KW,
        )
        self._drop_account()
        self._admin_ddl(
            f"CREATE USER {self._ACCOUNT} IDENTIFIED BY VALUES '{self._s_verifier()}'",
            f'GRANT CREATE SESSION TO {self._ACCOUNT}',
        )

    def tearDown(self):
        try:
            self._drop_account()
        finally:
            self._admin.close()

    def _connect_capturing_challenge(self):
        # Log in as the forged account, capturing the SESS challenge the server
        # sent so we can assert it really is the #311 combination.
        import seerdb.client.connection as _cm

        captured = {}
        original = _cm.decode_token_rpa

        from seerdb.common.tns_consts import TTI_SESS

        def spy(data, acc):
            result = original(data, acc)
            # The challenge, by its type: the auth result is a 7-tuple too
            # since it carries the login identity (#2456).
            if isinstance(result, tuple) and result and result[0] == TTI_SESS:
                captured['sess'] = result
            return result

        _cm.decode_token_rpa = spy
        try:
            conn = seerdb.connect(
                host=_HOST,
                port=_PORT,
                user=self._ACCOUNT,
                password=self._PW,
                service_name=_SERVICE,
                autocommit=True,
                **_FV_KW,
            )
        finally:
            _cm.decode_token_rpa = original
        return conn, captured.get('sess')

    def test_pre_sha2_account_authenticates_on_modern_server(self):
        try:
            conn, sess = self._connect_capturing_challenge()
        except seerdb.DatabaseError as e:
            if getattr(e, 'code', None) == 28040:
                # Server configured to refuse the 11g auth protocol outright.
                self.skipTest('server rejects 11g auth protocol (ORA-28040)')
            # ORA-01017 here would be exactly the #311 regression — let it fail.
            raise
        try:
            # The challenge must carry the #311 combination: an 11g SHA-1
            # verifier (flag 6949) with a salt, alongside the modern PBKDF2
            # session-key salt.
            self.assertIsNotNone(sess, 'no SESS challenge was captured')
            (_kind, _sesskey, salt, derived, _vgen, _sder, vfr) = sess
            self.assertEqual(vfr, 6949, 'expected the 11g SHA-1 verifier-type flag')
            self.assertIsNotNone(salt, 'AUTH_VFR_DATA salt must be present')
            self.assertIsNotNone(
                derived, 'AUTH_PBKDF2_CSK_SALT must be present on a modern server'
            )
            # And mutual auth actually completed end-to-end.
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM dual')
            self.assertEqual(cur.fetchone()[0], 1)
            cur.close()
        finally:
            conn.close()


@unittest.skipUnless(_USER, _SKIP_REASON)
class O8iSelectIntegration(_ThrottleRetry, unittest.TestCase):
    # Live read-only SELECT coverage for Oracle 8i (8.1.7), whose support is
    # currently SELECT-only (#244 task #4, PROTOCOL.md §19.9-10). 8i cannot run
    # the CREATE/INSERT the rest of the suite uses to seed a table, so these
    # tests query only always-present read-only sources — DUAL and the ALL_USERS
    # data dictionary view. The class self-skips unless the target the SEERDB_TEST_*
    # env points at is actually an 8i server, so it is inert on every other tier.
    def setUp(self):
        _skip_unless(self, _ONLY_8I)
        self.conn = _connect()
        self.cur = self.conn.cursor()

    def tearDown(self):
        try:
            self.conn.close()
        except Exception:
            # Best-effort close; the test already recorded its outcome.
            pass

    def test_select_literals_from_dual(self):
        # NUMBER + CHAR literals, and the column names from the 8i DCB describe.
        self.cur.execute("select 42 as n, 'hello' as s from dual")
        self.assertEqual(self.cur.fetchall(), [(42, 'hello')])
        self.assertEqual([d[0] for d in self.cur.description], ['N', 'S'])

    def test_null_column_between_present_ones(self):
        # The 8i RXD NULL form (bare `ff ff 00 00`) decodes to None without
        # slipping the neighbouring columns.
        self.cur.execute("select 1 a, cast(null as varchar2(4)) b, 'xy' cc from dual")
        self.assertEqual(self.cur.fetchall(), [(1, None, 'xy')])

    def test_multi_row_fetch_continuation(self):
        # 8i returns one row per batch, so >1 row exercises the OALL8 fetch loop.
        self.cur.execute(
            'select username from all_users where rownum <= 5 order by username'
        )
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(isinstance(r[0], str) and r[0] for r in rows))

    def test_varchar_number_date_types(self):
        # ALL_USERS gives a VARCHAR2, a NUMBER, and a DATE column in one row.
        import datetime

        self.cur.execute(
            'select username, user_id, created from all_users where rownum <= 3'
        )
        rows = self.cur.fetchall()
        self.assertTrue(rows)
        for name, uid, created in rows:
            self.assertIsInstance(name, str)
            self.assertIsInstance(uid, int)
            self.assertIsInstance(created, datetime.datetime)
        self.assertEqual(
            [d[0] for d in self.cur.description], ['USERNAME', 'USER_ID', 'CREATED']
        )

    def test_aggregate_count(self):
        self.cur.execute('select count(*) from all_users')
        (n,) = self.cur.fetchone()
        self.assertIsInstance(n, int)
        self.assertGreater(n, 0)

    def test_sysdate_is_datetime(self):
        import datetime

        self.cur.execute('select sysdate from dual')
        (value,) = self.cur.fetchone()
        self.assertIsInstance(value, datetime.datetime)

    def test_empty_result_set(self):
        self.cur.execute('select username from all_users where 1 = 0')
        self.assertEqual(self.cur.fetchall(), [])

    def test_number_bind(self):
        # Positional NUMBER IN bind (#359): the 9.2-era OALL8 bind section.
        self.cur.execute('select username from all_users where user_id = :1', [5])
        self.assertEqual(self.cur.fetchall(), [('SYSTEM',)])

    def test_varchar_and_multi_bind(self):
        # Named VARCHAR bind (dict) and a two-bind range, plus a NULL bind.
        self.cur.execute(
            'select user_id from all_users where username = :u', {'u': 'SYSTEM'}
        )
        self.assertEqual(self.cur.fetchall(), [(5,)])
        self.cur.execute(
            'select username from all_users where user_id >= :a and user_id <= :b '
            'order by user_id',
            [0, 5],
        )
        self.assertEqual([r[0] for r in self.cur.fetchall()], ['SYS', 'SYSTEM'])
        self.cur.execute("select nvl(:v, 'was-null') from dual", [None])
        self.assertEqual(self.cur.fetchone()[0], 'was-null')


@unittest.skipUnless(_USER, _SKIP_REASON)
class O8iDmlIntegration(_ThrottleRetry, unittest.TestCase):
    # Live DDL / DML / transaction coverage for Oracle 8i (#360): the 9.2-era
    # OALL8 with the statement-type option word and no fetch, the affected-row
    # count from the response OER, and OALL8-based COMMIT / ROLLBACK. Self-skips
    # unless the target is an 8i server; creates and drops its own scratch table.
    TABLE = 'zz_seerdb_o8i_dml'

    def setUp(self):
        _skip_unless(self, _ONLY_8I)
        self.conn = _connect()
        self.conn.autocommit = False
        self.cur = self.conn.cursor()
        self._drop()
        self.cur.execute(f'create table {self.TABLE} (a number, b varchar2(20))')

    def _drop(self):
        try:
            self.conn.cursor().execute(f'drop table {self.TABLE}')
        except Exception:
            # First run / already gone: nothing to drop.
            pass

    def tearDown(self):
        try:
            self._drop()
            self.conn.close()
        except Exception:
            pass

    def _rows(self):
        self.cur.execute(f'select a, b from {self.TABLE} order by a')
        return self.cur.fetchall()

    def test_insert_update_delete_rowcounts(self):
        self.cur.execute(f"insert into {self.TABLE} values (1, 'one')")
        self.assertEqual(self.cur.rowcount, 1)
        self.cur.execute(f'insert into {self.TABLE} values (:1, :2)', [2, 'two'])
        self.assertEqual(self.cur.rowcount, 1)
        self.cur.execute(f"insert into {self.TABLE} values (3, 'three')")
        self.assertEqual(self._rows(), [(1, 'one'), (2, 'two'), (3, 'three')])
        # Update two rows to the SAME value (exercises duplicate-column fetch).
        self.cur.execute(f'update {self.TABLE} set b = :1 where a >= :2', ['x', 2])
        self.assertEqual(self.cur.rowcount, 2)
        self.assertEqual(self._rows(), [(1, 'one'), (2, 'x'), (3, 'x')])
        self.cur.execute(f'delete from {self.TABLE} where a = :1', [1])
        self.assertEqual(self.cur.rowcount, 1)
        self.assertEqual(self._rows(), [(2, 'x'), (3, 'x')])

    def test_commit_and_rollback(self):
        self.cur.execute(f"insert into {self.TABLE} values (1, 'keep')")
        self.conn.commit()
        self.cur.execute(f"insert into {self.TABLE} values (2, 'undo')")
        self.conn.rollback()
        self.assertEqual(self._rows(), [(1, 'keep')])

    def test_dml_error_surfaces(self):
        with self.assertRaises(seerdb.DatabaseError):
            self.cur.execute('insert into zz_seerdb_no_such_table values (1)')

    def test_plsql_block_with_in_binds(self):
        # Anonymous PL/SQL block (#361): IN bind values ride inline, executed in a
        # single round trip. Insert via a block (no-bind, positional, named) and
        # read the rows back to confirm the binds reached the server.
        self.cur.execute(f"begin insert into {self.TABLE} values (1, 'nobind'); end;")
        self.cur.execute(
            f'begin insert into {self.TABLE} values (:1, :2); end;', [2, 'pos']
        )
        self.cur.execute(
            f'begin insert into {self.TABLE} values (:a, :b); end;',
            {'a': 3, 'b': 'named'},
        )
        self.conn.commit()
        self.assertEqual(self._rows(), [(1, 'nobind'), (2, 'pos'), (3, 'named')])

    def test_plsql_block_error_surfaces(self):
        with self.assertRaises(seerdb.DatabaseError):
            self.cur.execute('begin this_identifier_does_not_exist; end;')

    def test_out_binds_callproc_callfunc(self):
        # PL/SQL OUT binds (#362): a block with OUT Vars, then callproc / callfunc.
        self.cur.execute(
            'create or replace procedure zz_seerdb_p '
            '(x in number, y out number, z out varchar2) is '
            "begin y := x * 10; z := 'out'; end;"
        )
        self.cur.execute(
            'create or replace function zz_seerdb_f (a in number) return number is '
            'begin return a + 100; end;'
        )
        try:
            y = self.cur.var(int)
            z = self.cur.var(str)
            self.cur.execute('begin zz_seerdb_p(:1, :2, :3); end;', [5, y, z])
            self.assertEqual((y.getvalue(), z.getvalue()), (50, 'out'))

            yy, zz = self.cur.var(int), self.cur.var(str)
            self.assertEqual(
                self.cur.callproc('zz_seerdb_p', [8, yy, zz]), [8, 80, 'out']
            )
            self.assertEqual(self.cur.callfunc('zz_seerdb_f', int, [7]), 107)
        finally:
            self.cur.execute('drop procedure zz_seerdb_p')
            self.cur.execute('drop function zz_seerdb_f')

    def test_in_out_binds(self):
        # IN OUT binds (#363): the input value rides inline and the updated value
        # comes back, in one round trip. Also covers a mixed IN / IN OUT / OUT proc.
        self.cur.execute(
            'create or replace procedure zz_seerdb_io '
            '(a in number, b in out number, c out varchar2) is '
            "begin b := a + b; c := 'done'; end;"
        )
        try:
            b = self.cur.var(int)
            b.setvalue(0, 100)
            c = self.cur.var(str)
            self.cur.execute('begin zz_seerdb_io(:1, :2, :3); end;', [5, b, c])
            self.assertEqual((b.getvalue(), c.getvalue()), (105, 'done'))
        finally:
            self.cur.execute('drop procedure zz_seerdb_io')

    def test_clob_blob_read(self):
        # LOB read (#364): a CLOB (short + a 4000-char one that spans packets), a
        # BLOB, and NULL LOBs — resolved via the single TTI_LOBOPS READ.
        self.cur.execute(f'drop table {self.TABLE}')
        self.cur.execute(f'create table {self.TABLE} (id number, c clob, b blob)')
        self.cur.execute(
            f'insert into {self.TABLE} values '
            "(1, 'hello-clob', hextoraw('DEADBEEF00CAFE'))"
        )
        self.cur.execute(
            f"insert into {self.TABLE} values (2, rpad('A', 4000, 'AB'), hextoraw('00'))"
        )
        self.cur.execute(f'insert into {self.TABLE} values (3, NULL, NULL)')
        self.conn.commit()
        self.cur.execute(f'select id, c, b from {self.TABLE} order by id')
        rows = self.cur.fetchall()
        self.assertEqual(rows[0], (1, 'hello-clob', b'\xde\xad\xbe\xef\x00\xca\xfe'))
        self.assertEqual((rows[1][0], len(rows[1][1]), rows[1][2]), (2, 4000, b'\x00'))
        self.assertEqual(rows[2], (3, None, None))

    def test_bfile_read(self):
        # 8i BFILE read (#401) over the native FILE_OPEN -> GETLEN -> READ ->
        # FILE_CLOSE TTI_LOBOPS wire (no DBMS_LOB helper). There is no writable
        # UTL_FILE directory on the 8i testbed, so use the instance's own
        # background-dump directory + alert log (always present) as a read-only
        # fixture. A plain SELECT of a BFILE column must return the file bytes
        # (Cursor auto-resolve -> _bfile_read_8i).
        self.conn.autocommit = True
        (DumpDir,) = (
            self.conn.cursor()
            .execute(
                "select value from v$parameter where name = 'background_dump_dest'"
            )
            .fetchone()
        )
        self.cur.execute(f"create or replace directory zz_seerdb_bd as '{DumpDir}'")
        Alert = None
        for Cand in ('ORCLALRT.LOG', 'alert_ORCL.log', 'alert_orcl.log'):
            (Exists,) = self.cur.execute(
                "select dbms_lob.fileexists(bfilename('ZZ_SEERDB_BD', :f)) from dual",
                {'f': Cand},
            ).fetchone()
            if Exists == 1:
                Alert = Cand
                break
        if Alert is None:
            self.skipTest('no alert log found in background_dump_dest')
        (FileLen,) = self.cur.execute(
            "select dbms_lob.getlength(bfilename('ZZ_SEERDB_BD', :f)) from dual",
            {'f': Alert},
        ).fetchone()
        (Lob,) = self.cur.execute(
            "select bfilename('ZZ_SEERDB_BD', :f) from dual", {'f': Alert}
        ).fetchone()
        # The fetch hands back the locator; the file is read when asked (#1103).
        from seerdb.common.lob import LOB

        self.assertIsInstance(Lob, LOB)
        Got = Lob.read()
        self.assertIsInstance(Got, bytes)
        self.assertEqual(len(Got), FileLen)
        self.assertTrue(Got.startswith(b'Dump file'))

    def test_char_data_is_latin1(self):
        # 8i char data (VARCHAR2 / CHAR / NVARCHAR2 / NCHAR) is WE8ISO8859P1, not
        # the UTF-8 / UTF-16 a modern session uses (#366): non-ASCII VARCHAR2 and
        # any NVARCHAR2 / NCHAR previously came back mojibaked.
        self.cur.execute(f'drop table {self.TABLE}')
        self.cur.execute(
            f'create table {self.TABLE} (v varchar2(20), nv nvarchar2(20), nc nchar(6))'
        )
        self.cur.execute(
            f'insert into {self.TABLE} values '
            "('caf'||chr(233)||'-ni'||chr(241)||'o', N'nv-val', N'nchar')"
        )
        self.conn.commit()
        self.cur.execute(f'select v, nv, nc from {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), ('café-niño', 'nv-val', 'nchar '))

    def test_bind_over_255_bytes(self):
        # A VARCHAR2 / RAW bind of 256+ bytes (#375): the OAC max_size must ride
        # little-endian or 8i rejects it as a LONG value (ORA-01461).
        self.cur.execute(f'drop table {self.TABLE}')
        self.cur.execute(f'create table {self.TABLE} (v varchar2(4000), r raw(2000))')
        big = 'Z' * 500
        raw = bytes(range(256)) + bytes(range(44))  # 300 bytes, all byte values
        self.cur.execute(f'insert into {self.TABLE} (v) values (:1)', [big])
        self.cur.execute(f'insert into {self.TABLE} (r) values (:1)', [raw])
        self.conn.commit()
        self.cur.execute(f'select v from {self.TABLE} where v is not null')
        self.assertEqual(self.cur.fetchone()[0], big)
        self.cur.execute(f'select r from {self.TABLE} where r is not null')
        self.assertEqual(self.cur.fetchone()[0], raw)
        # SELECT bind at 4000 bytes too
        self.cur.execute('select length(:s) from dual', ['A' * 4000])
        self.assertEqual(self.cur.fetchone()[0], 4000)


@unittest.skipUnless(_USER, _SKIP_REASON)
class AsyncO8iIntegration(_ThrottleRetry, unittest.IsolatedAsyncioTestCase):
    # Async Oracle 8i coverage (#365): the sync 8i surface ported to
    # aconnection.py / acursor.py. Self-skips unless the target is an 8i server.
    TABLE = 'zz_seerdb_o8i_async'

    def _kwargs(self):
        return dict(
            host=_HOST,
            port=_PORT,
            user=_USER,
            password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            **_FV_KW,
        )

    async def _connect_8i(self):
        _skip_unless(self, _ONLY_8I)
        return await seerdb.connect_async(**self._kwargs())

    async def test_async_8i_select_dml_plsql_lob(self):
        conn = await self._connect_8i()
        try:
            cur = conn.cursor()
            # SELECT (multi-row) + a NUMBER bind
            await cur.execute('select username from all_users where user_id = :1', [5])
            self.assertEqual(await cur.fetchall(), [('SYSTEM',)])
            # DDL + DML + rowcount
            try:
                await cur.execute(f'drop table {self.TABLE}')
            except Exception:
                pass
            await cur.execute(f'create table {self.TABLE} (id number, c clob)')
            await cur.execute(
                f"insert into {self.TABLE} values (:1, 'async-clob')", [7]
            )
            self.assertEqual(cur.rowcount, 1)
            # PL/SQL OUT bind via callfunc
            await cur.execute(
                'create or replace function zz_seerdb_af (a number) return number is '
                'begin return a * 3; end;'
            )
            self.assertEqual(await cur.callfunc('zz_seerdb_af', int, [11]), 33)
            # LOB read
            await cur.execute(f'select id, c from {self.TABLE}')
            self.assertEqual(await cur.fetchall(), [(7, 'async-clob')])
            # BFILE read (#401): native FILE_OPEN -> GETLEN -> READ -> FILE_CLOSE,
            # using the instance's own bdump directory + alert log as the fixture
            # (mirrors the sync O8iDmlIntegration.test_bfile_read).
            await cur.execute(
                "select value from v$parameter where name = 'background_dump_dest'"
            )
            (DumpDir,) = await cur.fetchone()
            await cur.execute(
                f"create or replace directory zz_seerdb_bd as '{DumpDir}'"
            )
            for Cand in ('ORCLALRT.LOG', 'alert_ORCL.log', 'alert_orcl.log'):
                await cur.execute(
                    "select dbms_lob.fileexists(bfilename('ZZ_SEERDB_BD', :f)) from dual",
                    {'f': Cand},
                )
                (Exists,) = await cur.fetchone()
                if Exists == 1:
                    await cur.execute(
                        "select bfilename('ZZ_SEERDB_BD', :f) from dual", {'f': Cand}
                    )
                    # The fetch hands back the locator; aread() reads the file
                    # (#1103).
                    (Lob,) = await cur.fetchone()
                    Got = await Lob.aread()
                    self.assertIsInstance(Got, bytes)
                    self.assertTrue(Got.startswith(b'Dump file'))
                    break
            await conn.commit()
        finally:
            try:
                await conn.cursor().execute(f'drop table {self.TABLE}')
                await conn.cursor().execute('drop function zz_seerdb_af')
            except Exception:
                pass
            await conn.close()


@unittest.skipUnless(_USER, _SKIP_REASON)
class PreTwelveObjectOutBindIntegration(unittest.TestCase):
    # Before 12.1 an object or collection OUT bind is refused up front, as an
    # object value already is (#116): pre-12c answers it with a fatal ORA-03106
    # that lost the connection (#2039). From 12.1 it is an ordinary bind.
    TYPE = 'zz_seerdb_2039_list'

    def test_an_object_out_bind_is_refused_and_the_session_lives(self):

        conn = _connect()
        try:
            if _target_of(conn).object_binds:
                # 12.1+ serves it, and 11g's native form, pooled or with oall8
                # (#2463): only the converted form below 12.1 refuses it.
                self.skipTest('an object OUT bind is served from 12.1, and natively')
            cur = conn.cursor()
            cur.execute(
                f'create or replace type {self.TYPE} as varray(5) of varchar2(10)'
            )
            try:
                out = cur.var(conn.gettype(self.TYPE.upper()))
                with self.assertRaises(seerdb.NotSupportedError):
                    cur.execute(f"begin :1 := {self.TYPE}('a'); end;", [out])
                self.assertEqual(cur.execute('select 1 from dual').fetchone(), (1,))
            finally:
                cur.execute(f'drop type {self.TYPE}')
        finally:
            conn.close()


if __name__ == '__main__':
    unittest.main()
