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
import datetime
import math
import os
import re
import ssl
import unittest
from decimal import Decimal

import seerdb
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_12_2,
    FIELD_VERSION_20_1,
    FIELD_VERSION_23_1,
    FIELD_VERSION_23_4,
)

# Features the Oracle 9i (fv2) server genuinely lacks, keyed by a substring of
# the test method name. A 9i (field_version < 10.2) connection skips these with
# a clear reason — the same bar 10g uses for 12c+/23ai features (#171). These
# are *server* limitations or capabilities seerdb deliberately does not offer
# on fv2, not fixable fv2 bind gaps (those are #172 dates, #173 intervals,
# #174 national charset).
_FV2_UNSUPPORTED = (
    ('missing_directory', 'pre-10g reads a BFILE at fetch time (#1103)'),
    ('mixed_batch', 'executemany (array DML) is a 10g+ path'),
    ('lastrowid', 'the fv2 DML status is not read for a rowid yet (#1079)'),
    ('binary_double', 'BINARY_DOUBLE is a 10g+ type; Oracle 9i lacks it'),
    ('binary_float', 'BINARY_FLOAT is a 10g+ type; Oracle 9i lacks it'),
    ('kib', 'Oracle 9i has no streamed LOB/LONG bind path (#169)'),
    (
        'clob_bind_above_varchar2_cap',
        'Oracle 9i has no streamed LOB/LONG bind path (#169)',
    ),
    (
        'clob_bind_spans_multiple_packets',
        'Oracle 9i has no streamed LOB/LONG bind path (#169)',
    ),
    (
        'blob_bind_round_trip_all_byte_values',
        'Oracle 9i has no streamed LOB/LONG bind path (#169)',
    ),
    ('error_then_large_lob', 'Oracle 9i has no streamed LOB/LONG bind path (#169)'),
    # Behavioural features the fv2 path does not implement (#168): they now
    # raise a clean NotSupportedError or exercise a capability 9i lacks, rather
    # than silently misbehaving, so the tests skip on 9i.
    ('executemany', 'array DML (executemany) is not supported on Oracle 9i'),
    ('batcherror', 'array DML batcherrors are not supported on Oracle 9i'),
    ('refcursor', 'REF CURSOR is not supported on Oracle 9i (fv2)'),
    ('ref_bind', 'REF / object types are not supported on Oracle 9i'),
    ('changepassword', 'changepassword is not supported on Oracle 9i'),
    ('cache_evicts', 'the cursor cache is a fv4+ feature; 9i re-parses'),
    ('reuses_cursor', 'the cursor cache is a fv4+ feature; 9i re-parses'),
    ('forgets_the_cached_cursor', 'the cursor cache is a fv4+ feature; 9i re-parses'),
    ('never_cached', 'the cursor cache is a fv4+ feature; 9i re-parses'),
    ('pipeline', 'the pipeline test uses array DML, unsupported on Oracle 9i'),
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
    ('nclob', '9i national-charset LOB handling deferred (#174)'),
    # The fixture SELECT ... CONNECT BY LEVEL <= 200 returns only 10 rows on 9i
    # (a 9i CONNECT-BY-against-dual quirk, like the 8i "returns one row"), so it
    # never crosses a fetch boundary here. The fv2 fetch loop itself is fine — a
    # real 200-row table returns all 200 — so this is a fixture limitation, not a
    # 9i bug. Already skipped on 8i for the same reason.
    ('bit_vector_reuse', 'CONNECT BY LEVEL returns few rows on Oracle 9i'),
    # RETURNING itself now works on pre-10g through the PL/SQL block rewrite
    # (#801, #802), but an *array* RETURNING still cannot: executemany is array
    # DML, which these tiers do not have at all.
    ('array_returning', 'executemany (array DML) is a 10g+ feature'),
    # The rewrite runs the statement as a PL/SQL block, and the server rejects
    # a quoted placeholder inside one (ORA-01006) even though plain pre-10g DML
    # accepts it. Measured on 9i; the driver refuses it with a clear message.
    (
        'quoted_bind_in_returning_into',
        'a quoted bind cannot ride the pre-10g block rewrite',
    ),
    # The pre-10 error reply carries the code and text but no position.
    ('error_offset', 'the 9i/8i error reply carries no offset (#719)'),
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
    ('timestamp', 'TIMESTAMP is a 9i+ type; Oracle 8i has only DATE'),
    ('interval', 'INTERVAL is a 9i+ type; Oracle 8i lacks it'),
    ('national_char', 'Oracle 8i predates AL16UTF16 NCHAR (WE8ISO8859P1 only)'),
    ('bit_vector_reuse', 'CONNECT BY LEVEL returns one row on Oracle 8i'),
    # Async-only / connectivity tests (AsyncConnectionIntegration, Redirect).
    ('async_iteration', 'CONNECT BY LEVEL returns one row on Oracle 8i'),
    ('fetchall_and_fetchmany', 'CONNECT BY LEVEL returns one row on Oracle 8i'),
    # The test's column is a TIMESTAMP; 8i honours the declared types it has.
    ('declared_type_governs', 'TIMESTAMP is a 9i+ type; Oracle 8i has only DATE'),
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


# Resolve the TLS proxy fixture without depending on the `tests` package
# layout (works under both `python -m unittest tests.test_integration` and
# discovery from the repo root).
import sys as _sys

_sys.path.insert(0, os.path.dirname(__file__))
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
_FV_KW = {'field_version': _FIELD_VERSION} if _FIELD_VERSION else {}

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
        if kind not in ('error', 'failure') or not payload:
            return False
        exc = payload[1]
        return (
            isinstance(exc, seerdb.DatabaseError)
            and getattr(exc, 'code', None) in _TRANSIENT_CODES
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
                if kind == 'error':
                    result.addError(self, payload)
                elif kind == 'failure':
                    result.addFailure(self, payload)
                elif kind == 'skip':
                    result.addSkip(self, payload)
                else:
                    result.addSuccess(self)
            finally:
                result.stopTest(self)
        return result


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

    def _skip_if_fv2_unsupported(self):
        # On a 9i (fv2) connection, skip the tests whose feature the 9i server
        # genuinely lacks — same bar 10g uses for 12c+/23ai features (#171).
        # Close the connection first: a SkipTest from setUp means tearDown does
        # not run, so we must not leak the connection (a leak on the slow 9i VM
        # piles up sessions).
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

    def _skip_if_mirror(self, feature: str):
        # A Mirror leg runs the same suite against seerdb's own server, which
        # trails the client on some features -- a column LOB's mutation (#964).
        # Skip rather than fail, so a Mirror gap does not read as a client
        # regression. Each caller names the follow-up ticket.
        if os.environ.get('SEERDB_TEST_MIRROR'):
            self.skipTest(f'the Mirror does not implement {feature} yet')

    def _skip_if_mirror_backend(self, backend: str, feature: str):
        # Narrower than _skip_if_mirror: what this leg cannot do belongs to the
        # BACKEND, not to the Mirror, so only the named one skips. PostgreSQL
        # cannot parse Oracle SQL and serves no non-query `cursor.parse()`,
        # while the passthrough asks a real server and does (#1019).
        leg = os.environ.get('SEERDB_TEST_MIRROR')
        # A leg that does not name its backend -- '1', which is what a runner
        # predating the named value sets, including the CI job that starts its
        # own Mirror -- gets the conservative answer rather than a guess.
        if leg and leg in (backend, '1'):
            self.skipTest(f"the Mirror's {backend} backend cannot {feature}")

    def _drop_silently(self, cur):
        try:
            cur.execute(f'DROP TABLE {self.TABLE}')
        except seerdb.DatabaseError as e:
            # ORA-00942: table or view does not exist — expected on first run.
            if e.code != 942:
                raise


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

    def test_session_timezone_synced_to_client(self):
        # #307: on 12c+ the driver sends AUTH_ALTER_SESSION at login to pin the
        # session time zone to the client's UTC offset (as oracledb / OCI /
        # sqlplus do), so SESSIONTIMEZONE / CURRENT_TIMESTAMP reflect the client,
        # not the server default. Gated to 12c+ (10g/11g's stricter auth parse
        # rejects the extra pair; no oracledb reference to match there).
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('client time-zone sync is 12c+ (AUTH_ALTER_SESSION)')
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

    def test_the_conversion_functions(self):
        # TO_BINARY_FLOAT / _DOUBLE, TO_DSINTERVAL / TO_YMINTERVAL, TO_BLOB and
        # TO_NCLOB -- a backend without them answered "function ... does not
        # exist" to the reference thin client's own suite.
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('BINARY_FLOAT / BINARY_DOUBLE are 10g+')
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

    def test_a_computed_year_to_month_interval(self):
        # PostgreSQL reports a computed domain-typed value as its base type, so
        # that backend can tell a YEAR TO MONTH interval from a DAY TO SECOND one
        # only when it comes from a column of that type.
        self._skip_if_mirror_backend(
            'postgres', 'tell a computed YEAR TO MONTH interval from DAY TO SECOND'
        )
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
        # The serial is the one the server names the session by. The package
        # needs no privilege; a server without it (the Mirror over PostgreSQL)
        # checks only the type.
        try:
            self.cur.execute('SELECT dbms_debug_jdwp.current_session_serial FROM dual')
        except DatabaseError:
            return
        self.assertEqual(self.cur.fetchone(), (self.conn.serial_num,))

    def test_v_session_shows_the_identity_the_client_declared(self):
        # v$session and v$session_connect_info show this session as its login
        # declared it (#1212); the terminal is left out, since a login in the
        # pre-12c shape declares none. Reading them needs a privilege the suite's user
        # has on no Oracle bed (ORA-00942), so there it skips.
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
            cur.execute(
                'SELECT DISTINCT client_driver FROM v$session_connect_info '
                "WHERE sid = sys_context('userenv', 'sid')"
            )
            # The driver name travels only in the 23ai-shaped login (fv > 23.1).
            driver = 'pyo-driver' if conn.field_version > FIELD_VERSION_23_1 else None
            self.assertEqual(cur.fetchall(), [(driver,)])

    def test_kill_session_ends_the_named_session(self):
        # ALTER SYSTEM KILL SESSION 'sid,serial' ends that session: its next call
        # fails and the connection is gone (#1212). A malformed ID is ORA-00026,
        # an unknown one ORA-00030. The suite's user may neither read v$session
        # nor ALTER SYSTEM on any Oracle bed, so there it skips.
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
            with self.assertRaises(seerdb.Error):
                vcur.execute('SELECT 1 FROM dual')
                vcur.fetchall()
        finally:
            try:
                victim.close()
            except seerdb.Error:
                pass
        for session, code in (('x', 26), (f'{sid},{serial}', 30)):
            with self.assertRaises(DatabaseError) as caught:
                self.cur.execute(f"ALTER SYSTEM KILL SESSION '{session}'")
            self.assertEqual(caught.exception.code, code)

    def test_timestamp_with_local_time_zone(self):
        # TIMESTAMP WITH LOCAL TIME ZONE (#1208), as measured on 9i to 23ai: a value
        # bound as LTZ is the instant in the database zone and round-trips as it
        # is; a TIMESTAMP bound into one is read in the session zone and comes
        # back in the database's; a precision truncates; a CAST does the same
        # conversions; SYSTIMESTAMP / CURRENT_TIMESTAMP are WITH TIME ZONE.
        if _conn_is_8i(self.conn):
            self.skipTest('8i has no TIMESTAMP WITH LOCAL TIME ZONE')
        self.cur.execute('SELECT sessiontimezone, dbtimezone FROM dual')
        (session, database) = (_tz_offset(z) for z in self.cur.fetchone())
        if session is None or database is None:
            self.skipTest('a named time zone')
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

    def test_a_describe_wider_than_a_packet(self):
        # V$SESSION's 45 columns describe to more than an 8i packet holds, and
        # the server pauses between the packets, so the client sees the
        # describe split (#1226). It is read whole; a describe that a failing
        # execute cuts short gives the server's error, and the session goes on.
        # 8i only: that is where the describe outgrows a packet, and where the
        # suite's user (SYSTEM) may read V$SESSION.
        from seerdb.common.exceptions import DatabaseError

        if not _conn_is_8i(self.conn):
            self.skipTest('a describe outgrows a packet on 8i')
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

    def test_timestamp_with_time_zone_compares_by_instant(self):
        # Equal, ordered and counted by the instant, whatever the offset each
        # value was written at; a NULL bind matches nothing (#1239).
        if _conn_is_8i(self.conn):
            self.skipTest('8i has no TIMESTAMP WITH TIME ZONE')
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

    def test_days_added_to_a_timestamp_with_local_time_zone(self):
        # LTZ + n is a DATE on the session's clock, its fractional seconds
        # dropped; assigned back to an LTZ it is read in the session zone again,
        # so a PL/SQL in/out round trip moves the value by exactly n days (#1240).
        if _conn_is_8i(self.conn):
            self.skipTest('8i has no TIMESTAMP WITH LOCAL TIME ZONE')
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
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('9i reads an LTZ var() bind in the session zone (#1241)')
        var = self.cur.var(seerdb.DB_TYPE_TIMESTAMP_LTZ)
        var.setvalue(0, value.replace(microsecond=0))
        self.cur.execute('begin :value := :value + 5.25; end;', {'value': var})
        self.assertEqual(var.getvalue(), datetime.datetime(2022, 5, 15, 18, 0, 0))

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
        # The whole batch must go in one server round trip, not one per row.
        # Count only TNS_DATA sends: under XE's logon-storm throttle the server
        # can inject a break/marker mid-response, and the driver's marker ack is
        # an extra (non-data) send that would otherwise make this flake.
        from seerdb.common.tns_consts import TNS_DATA

        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        import seerdb.client.connection as _c

        orig = _c.OracleConnect.send
        sends = [0]
        _c.OracleConnect.send = lambda s, T, D: (
            sends.__setitem__(0, sends[0] + (1 if T == TNS_DATA else 0)),
            orig(s, T, D),
        )[1]
        try:
            self.cur.executemany(
                f'INSERT INTO {self.TABLE} VALUES (:1)', [(i,) for i in range(50)]
            )
        finally:
            _c.OracleConnect.send = orig
        self.assertEqual(sends[0], 1)
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
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('a typed BINARY_INTEGER bind needs the 12c+ bind OAC')
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
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('a typed bind needs the 12c+ bind OAC')
        got = self.cur.var(seerdb.DB_TYPE_NUMBER)
        self.cur.execute('BEGIN :value := 2.9; END;', [got])
        self.assertEqual(float(got.getvalue()), 2.9)

    def test_select_into_with_no_rows_raises(self):
        # ORA-01403 is the end-of-fetch sentinel a query's last FETCH ends on,
        # AND the error a PL/SQL `SELECT ... INTO` raises when it matches
        # nothing. Masking it for both turned every such block into a silent
        # success handing back NULL (#1039).
        self._skip_if_mirror_backend('postgres', 'run a PL/SQL block')
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
        self._skip_if_mirror_backend('postgres', 'run a PL/SQL block')
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

    # ----- executemany arraydmlrowcounts (12c+) -----

    def _require_12c(self):
        # arraydmlrowcounts is a 12.1+ server feature (it rides the 12c+ OALL8
        # al8pidmlrc block); skip the positive tests on an 11g server.
        from seerdb.common.tns_consts import FIELD_VERSION_12_1

        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('arraydmlrowcounts needs a 12.1+ server')

    def test_executemany_arraydmlrowcounts_update(self):
        # Per-iteration affected-row counts: UPDATE g=1 hits 3 rows, g=2 hits 1,
        # g=3 hits 2, g=9 hits none -> [3, 1, 2, 0]. Matches oracledb (#18).
        self._require_12c()
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

    def test_arraydmlrowcounts_survive_a_batch_that_aborts(self):
        # A batch that fails part-way really applied the earlier rows, and a
        # client that asked for the per-iteration counts is owed them in the
        # ERROR reply too. Without them it reports the mode as never enabled --
        # a worse answer than the failure it is also being told about (#1031).
        self._require_12c()
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

    def test_batcherrors_and_arraydmlrowcounts_together(self):
        # They are not alternatives: one execute may ask for both, and then the
        # batcherrors reply owes the counts as well (#1031). A row that failed
        # affected nothing and still holds its slot, or every count after it
        # shifts.
        self._require_12c()
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

    def test_batch_errors_report_index_failures_last(self):
        # Not row order: a real server evaluates the row (conversion, NOT NULL,
        # CHECK) as it goes and maintains the unique index afterwards, so the
        # unique violations come after every other failure, each group still
        # ascending. Measured on a live 23ai with the orders deliberately
        # reversed against each other (#1031).
        self._require_12c()
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

    def test_executemany_arraydmlrowcounts_insert(self):
        # Each INSERT iteration affects exactly one row.
        self._require_12c()
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1)',
            [(i,) for i in range(5)],
            arraydmlrowcounts=True,
        )
        self.assertEqual(self.cur.getarraydmlrowcounts(), [1, 1, 1, 1, 1])

    def test_arraydmlrowcounts_empty_without_request(self):
        # Without arraydmlrowcounts the list stays empty, and a prior request's
        # counts don't leak into a later plain executemany.
        self._require_12c()
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.executemany(
            f'INSERT INTO {self.TABLE} VALUES (:1)',
            [(1,), (2,)],
            arraydmlrowcounts=True,
        )
        self.assertEqual(self.cur.getarraydmlrowcounts(), [1, 1])
        self.cur.executemany(f'INSERT INTO {self.TABLE} VALUES (:1)', [(3,), (4,)])
        self.assertEqual(self.cur.getarraydmlrowcounts(), [])

    def test_arraydmlrowcounts_unsupported_on_11g(self):
        # On an 11g server the feature is rejected up front (oracledb-compatible).
        from seerdb.common.tns_consts import FIELD_VERSION_12_1

        if self.conn.field_version >= FIELD_VERSION_12_1:
            self.skipTest('server supports arraydmlrowcounts')
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

    def test_national_scalar_out_bind(self):
        # A national OUT bind arrives as AL16UTF16, and the Var's charset form is
        # what says so. Without it the value came back as its raw UTF-16BE bytes
        # read one per character (#991).
        #
        # 10g+ only: on fv2 (9i / 8i) the server refuses the bind descriptor
        # outright with ORA-03120 "two-task conversion routine: integer
        # overflow", before any value comes back. That is a tier limitation, not
        # this decode -- the request bytes are identical either way.
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('a national OUT bind is refused on fv2 (ORA-03120)')
        Var = self.cur.var(seerdb.DB_TYPE_NVARCHAR)
        self.cur.execute("BEGIN :v := N'nat \u00fcn\u00ee \u4e2d'; END;", [Var])
        self.assertEqual(Var.getvalue(), 'nat ünî 中')

    def test_national_array_bind_round_trip(self):
        # An associative array of NVARCHAR2 in both directions (#991). The
        # element is encoded as a bare value, so it never saw the bind's charset
        # form: going out it went as UTF-8 and the server read those bytes as
        # UTF-16BE, silently halving every string.
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('an associative-array bind needs 12.1+ (#122)')
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


@unittest.skipUnless(_USER, _SKIP_REASON)
class ColumnDomainIntegration(_IntegrationBase):
    """A 23ai column's SQL domain and annotations on ``cursor.description`` (#1083)."""

    DOMAIN = 'PYO_SIMPLE_DOMAIN'

    def setUp(self):
        super().setUp()
        if self.conn.field_version < FIELD_VERSION_23_4:
            self.skipTest('column domains and annotations are 23ai')
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

    def test_it_reads_back_as_the_same_rowid(self):
        # A UROWID value is tagged 0x01 when it holds a physical rowid; it used to
        # render in the '*' logical form, unlike the same row's ROWID column and
        # unlike python-oracledb.
        # PostgreSQL writes an UPDATEd row as a new version at a new address, so
        # the rowid `SET r = ROWID` stores names the version it replaced; an
        # Oracle ROWID does not move on UPDATE.
        self._skip_if_mirror_backend(
            'postgres', 'keep a row at one address across an UPDATE'
        )
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
            if conn.field_version < FIELD_VERSION_10_2:
                self.skipTest('9i pings with a query, which already raises')
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


@unittest.skipUnless(_USER, _SKIP_REASON)
class ProxyLoginIntegration(_ThrottleRetry, unittest.TestCase):
    """A proxy login, ``user[proxy]`` (#126), keeps its proxy end to end (#1093).

    Needs a user the test user may connect through (``ALTER USER <proxy> GRANT
    CONNECT THROUGH <user>``), named by SEERDB_TEST_PROXY_USER. The suite's own
    account has no such grant, so without it the test says so and skips.
    """

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
            if conn.field_version < FIELD_VERSION_10_2:
                self.skipTest('proxy authentication needs a 10g+ server')
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
        self._skip_if_mirror_backend('postgres', 'serve a BFILE column')
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

    def test_bfile_methods_on_a_missing_directory(self):
        # getfilename() answers from the locator, so it works for a file that is
        # not there and a DIRECTORY that was never created. fileexists() asks
        # the server, and a missing alias is ORA-22285 rather than False --
        # "there is no such alias" and "the file is missing" are different
        # answers (#1109).
        self._skip_if_mirror_backend('postgres', 'serve a BFILE column')
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

    def test_bfile_methods_refuse_a_non_bfile_lob(self):
        # The three are meaningless on a CLOB / BLOB and are refused there, as
        # the reference client refuses them (DPY-3026) rather than answering
        # something (#1109). Needs a temp LOB to have a non-BFILE to refuse, and
        # CREATE_TEMP is 12c+ -- 11g refuses it (#91), so there is nothing to
        # build the CLOB / BLOB out of there.
        self._skip_if_mirror_backend('postgres', 'create a temp LOB')
        Conn = _connect()
        if Conn.field_version < FIELD_VERSION_12_1:
            Conn.close()
            self.skipTest('createlob() needs a 12c+ server (CREATE_TEMP)')
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


@unittest.skipUnless(_USER, _SKIP_REASON)
class BindDirectionIntegration(_IntegrationBase):
    """``cursor.bind_directions``: what the server said each bind was (#1064)."""

    def setUp(self):
        super().setUp()
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('the fv2 block reply carries no IOV directions')
        # Only a backend with a real server behind it can know the directions;
        # one that cannot reports every bind OUT, which is the documented
        # fallback rather than a gap (#1064).
        self._skip_if_mirror_backend('postgres', "know a block's bind directions")

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
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('temp-LOB bind needs a 12c+ server (CREATE_TEMP)')
        self.cur.execute(
            'CREATE OR REPLACE FUNCTION pyo_clob_len(p CLOB) RETURN NUMBER IS '
            'BEGIN RETURN DBMS_LOB.GETLENGTH(p); END;'
        )
        self.cur.execute(
            'CREATE OR REPLACE FUNCTION pyo_blob_len(p BLOB) RETURN NUMBER IS '
            'BEGIN RETURN DBMS_LOB.GETLENGTH(p); END;'
        )

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


@unittest.skipUnless(_USER, _SKIP_REASON)
class CreateLobIntegration(_IntegrationBase):
    """``connection.createlob()``: a temp LOB the caller makes and binds (#1066).

    12c+ only, like every temp LOB: 11g refuses CREATE_TEMP (#91).
    """

    def setUp(self):
        super().setUp()
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('createlob() needs a 12c+ server (CREATE_TEMP)')

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

    def test_a_large_clob_into_xmltype(self):
        # What the method is for: sys.xmltype() needs a genuine LOB argument,
        # and refuses the same 32 KB as a plain string with ORA-01461.
        self._skip_if_mirror_backend('postgres', 'build an XMLType')
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

    def test_repeated_dml_reuses_cursor(self):
        if self.conn.field_version >= FIELD_VERSION_12_1:
            # The cache is disabled on the *negotiated* 12c+ connection, so gate
            # on that — not on SEERDB_TEST_FIELD_VERSION, which is unset when
            # the suite simply points at a 21c server (#81).
            self.skipTest('cursor cache is disabled on 12c+ (re-parse each execute)')
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

    def test_a_failed_execute_forgets_the_cached_cursor(self):
        # The server drops a cursor whose execute failed. Keeping its id made
        # every later execute of the same statement answer ORA-01001 (#709).
        if self.conn.field_version >= FIELD_VERSION_12_1:
            self.skipTest('cursor cache is disabled on 12c+ (re-parse each execute)')
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

    def test_ddl_forgets_the_cached_cursors(self):
        # A cached cursor re-executed after its table was dropped and
        # re-created made the server reuse the previous execution's value for
        # a NULL LONG-class bind: ORA-12899 here, silent corruption into a
        # wider column (#720). DDL flushes the cache.
        if self.conn.field_version >= FIELD_VERSION_12_1:
            self.skipTest('cursor cache is disabled on 12c+ (re-parse each execute)')
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

    def test_pre_10g_serves_the_into_clause_through_a_block(self):
        # Below 10g the 10g+ request form is refused by the server (9i answers
        # ORA-00439), but the identical statement runs inside a PL/SQL block
        # where the INTO targets are ordinary OUT binds, so the driver rewrites
        # it there (#801). 8i keeps refusing (#802).
        if self.conn.field_version >= FIELD_VERSION_10_2:
            self.skipTest('RETURNING ... INTO takes the native path from 10g')
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

    def test_a_wide_bind_is_never_cached(self):
        # DDL from another session would leave the same stale buffer behind,
        # so a statement with a LONG-class bind parses afresh every time (#720).
        if self.conn.field_version >= FIELD_VERSION_12_1:
            self.skipTest('cursor cache is disabled on 12c+ (re-parse each execute)')
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

    def test_cache_evicts_oldest_when_full(self):
        if self.conn.field_version >= FIELD_VERSION_12_1:  # cache off on 12c+ (#81)
            self.skipTest('cursor cache is disabled on 12c+ (re-parse each execute)')
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


@unittest.skipUnless(_USER, _SKIP_REASON)
class ParseIntegration(_IntegrationBase):
    """`cursor.parse()` (#1018): parse the statement, never run it.

    The server validates syntax, object names and bind-variable names, and
    nothing else happens. A query also comes back described. 10g and up — the
    pre-10g request dialects have no parse-without-execute shape, and refuse.
    """

    def _pre10(self):
        return self.conn.field_version < FIELD_VERSION_10_2

    def test_parse_is_refused_on_pre10(self):
        if not self._pre10():
            self.skipTest('10g+ sends a real parse; this is the pre-10g refusal')
        with self.assertRaises(seerdb.NotSupportedError):
            self.cur.parse('SELECT 1 FROM DUAL')
        # The connection is untouched by the refusal — nothing went on the wire.
        self.cur.execute('SELECT 1 FROM DUAL')
        self.assertEqual(self.cur.fetchone(), (1,))

    def test_parse_describes_a_query_without_fetching_it(self):
        if self._pre10():
            self.skipTest('cursor.parse() needs 10g+')
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))')
        self.cur.execute(f'INSERT INTO {self.TABLE} VALUES (1, %s)' % "'a'")
        self.cur.parse(f'SELECT id, name FROM {self.TABLE}')
        self.assertEqual([d[0] for d in self.cur.description], ['ID', 'NAME'])
        # Described, not run: no rows were fetched. Draining the parse's cursor
        # is what ORA-01002 (fetch out of sequence) came from.
        self.assertEqual(self.cur.fetchall(), [])

    def test_parse_does_not_run_the_statement(self):
        if self._pre10():
            self.skipTest('cursor.parse() needs 10g+')
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        self.cur.parse(f'INSERT INTO {self.TABLE} (id) VALUES (:v)')
        self.assertIsNone(self.cur.description)  # not a query
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        self.assertEqual(self.cur.fetchone(), (0,))

    def test_parse_reports_an_unknown_column(self):
        if self._pre10():
            self.skipTest('cursor.parse() needs 10g+')
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.parse(f'SELECT nonexistent_col FROM {self.TABLE}')
        self.assertEqual(ctx.exception.code, 904)  # ORA-00904

    def test_parse_reports_an_invalid_bind_name(self):
        # The motivating case (#826): a RETURNING clause whose INTO target names
        # a reserved word is rejected at parse time and at no other time.
        if self._pre10():
            self.skipTest('cursor.parse() needs 10g+')
        self.cur.execute(f'CREATE TABLE {self.TABLE} (id NUMBER)')
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.parse(
                f'INSERT INTO {self.TABLE} (id) VALUES (:v) RETURNING id INTO :ROWID'
            )
        self.assertEqual(ctx.exception.code, 1745)  # ORA-01745

    def test_parse_reports_a_statement_that_is_not_sql(self):
        if self._pre10():
            self.skipTest('cursor.parse() needs 10g+')
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            self.cur.parse('this is not sql')
        self.assertEqual(ctx.exception.code, 900)  # ORA-00900

    def test_parse_accepts_a_plsql_block(self):
        if self._pre10():
            self.skipTest('cursor.parse() needs 10g+')
        self.cur.parse('BEGIN NULL; END;')
        self.assertIsNone(self.cur.description)

    def test_the_cursor_is_usable_after_a_failed_parse(self):
        # A parse that raised must leave the session in step — the whole point
        # of validating without running.
        if self._pre10():
            self.skipTest('cursor.parse() needs 10g+')
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

    def test_scrollable_lazy_fetch_on_demand(self):
        # Server-side scrollable cursor (#181), 10g+: rows are pulled lazily from
        # a kept-open cursor in arraysize batches (here prefetchrows=2,
        # arraysize=3 over 10 rows forces several positioned re-executes), and
        # scroll() repositions server-side. 9i has no OALL8 scroll and falls back
        # to the buffered path (covered by test_scrollable_cursor).
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('server-side scroll needs 10g+ (9i uses buffered scroll)')
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

    def test_scrollable_scroll_off_end_and_back(self):
        # Scrolling past the end (#181) leaves the cursor empty (next fetchone is
        # None), and a later scroll repositions back into the result set.
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('server-side scroll needs 10g+')
        self._populate(5)
        sc = self.conn.cursor(scrollable=True)
        sc.prefetchrows = 2
        sc.arraysize = 2
        sc.execute(f'SELECT id FROM {self.TABLE} ORDER BY id')
        sc.scroll(99, mode='absolute')
        self.assertIsNone(sc.fetchone())
        sc.scroll(mode='first')
        self.assertEqual(sc.fetchone(), (1,))

    def test_scrollable_last_after_eof_duplicate_value(self):
        # LAST after the buffer already reached EOF with arraysize >= row count
        # (#181): the server repositions onto the last row, whose value equals the
        # one just returned, so it omits the value and flags "reuse previous" in
        # the row-header bit vector. Exercises decode_token_rxh's bit-vector pass
        # + the previous-row seed (this used to desync / crash on token 0x0a).
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('server-side scroll needs 10g+')
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
        # up in SYS_CONTEXT('USERENV', ...). 12c+ only (the piggyback closes a
        # pre-12c connection), so pre-12c must raise NotSupportedError instead.
        if self.conn.field_version < FIELD_VERSION_12_1:
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
        # the piggyback is accepted and the connection stays usable.
        self.conn.dbop = 'PYODBOP'
        self.cur.execute('SELECT 1 FROM dual')
        self.assertEqual(self.cur.fetchone(), (1,))
        self.assertEqual(self.conn.dbop, 'PYODBOP')

    def test_module_alone(self):
        # Setting module without action must not malform the piggyback — Oracle
        # requires both together, so a module-only flush carries action too
        # (#184). 12c+ only.
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('end-to-end tracing requires 12c+')
        self.conn.module = 'SOLOMOD'
        self.cur.execute("SELECT SYS_CONTEXT('USERENV','MODULE') FROM dual")
        self.assertEqual(self.cur.fetchone(), ('SOLOMOD',))

    def test_repeated_execute_no_cursor_leak(self):
        # #191: repeated execute() of one statement must not leak server
        # cursors. Pre-fix this tripped ORA-01000 after ~300 executes on 12c+
        # (cache off); the drained cursor is now freed by an OCCA piggyback in
        # front of the next call. 400 > the typical OPEN_CURSORS, so this would
        # fail on 12c+ without the fix.
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('fv2 (9i) uses a separate execute path')
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
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('LOB reads inside a transaction are not exercised on fv2')
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
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest('the LOB object needs the 10g+ LOBOPS path')
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

    def test_a_fetched_clob_is_a_lob_object(self):
        lob = self._fetch_lob()
        self.assertTrue(hasattr(lob, 'read'), f'expected a LOB, got {type(lob)}')
        self.assertEqual(lob.read(), 'hello world')

    def test_size_and_chunk_size_come_from_the_server(self):
        # Against a Mirror both of these answer 0: it recovers a column
        # locator from a GET_LENGTH only in the ub2-PREFIXED form, while a real
        # server wants the BARE one for that op (and answers the prefixed form
        # with an error), so the Mirror never finds the locator the client
        # actually sent. GET_CHUNK_SIZE it acks without a value at all. Both are
        # Mirror-side follow-ups to #964.
        self._skip_if_mirror('GET_LENGTH / GET_CHUNK_SIZE on a column locator')
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

    def _skip_if_immutable(self):
        if self.conn.field_version < FIELD_VERSION_11_2:
            self.skipTest('modifying a LOB needs 11g+ (10g closes the connection)')
        self._skip_if_mirror('serving LOB writes on a column locator')

    def test_write_applies_and_the_size_follows(self):
        self._skip_if_immutable()
        lob = self._fetch_lob()
        lob.write('WORLD', 7)
        self.assertEqual(lob.read(), 'hello WORLD')
        self.assertEqual(lob.size(), 11)

    def test_write_past_the_end_extends_the_lob(self):
        self._skip_if_immutable()
        lob = self._fetch_lob()
        lob.write('!', 12)
        self.assertEqual(lob.read(), 'hello world!')
        self.assertEqual(lob.size(), 12)

    def test_trim_shortens_it(self):
        self._skip_if_immutable()
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

    def test_writing_the_wrong_python_type_is_a_type_error(self):
        self._skip_if_immutable()
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

    def setUp(self):
        super().setUp()
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('a LOB Var bind needs the 12.1+ temp-LOB path (#902)')

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
        # Under the 32767-byte promotion threshold, so the bind stays a Var.
        Var = self.cur.var(seerdb.DB_TYPE_CLOB)
        Var.setvalue(0, 'small')
        self.cur.execute("BEGIN DBMS_LOB.WRITEAPPEND(:d, 3, 'END'); END;", [Var])
        self.assertEqual(Var.getvalue().read(), 'smallEND')

    def test_inout_clob_var_over_the_promotion_threshold(self):
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

    def test_fetch_lobs_false_materialises_an_out_bind(self):
        # `fetch_lobs=False` applies to an OUT bind's LOB the same way it does
        # to a fetched cell.
        with _connect(fetch_lobs=False) as Conn:
            Cur = Conn.cursor()
            if Conn.field_version < FIELD_VERSION_12_1:
                self.skipTest('a LOB Var bind needs the 12.1+ temp-LOB path (#902)')
            Var = Cur.var(seerdb.DB_TYPE_CLOB)
            Cur.execute("BEGIN :d := TO_CLOB('materialised'); END;", [Var])
            self.assertEqual(Var.getvalue(), 'materialised')


@unittest.skipUnless(_USER, _SKIP_REASON)
class BooleanIntegration(_IntegrationBase):
    # Native SQL BOOLEAN columns, 23ai+ (#54, TNS type 252). Skipped on servers
    # without the type (21c/11g reject the column with ORA-00902).
    def _setup_bool(self):
        from seerdb.common.exceptions import DatabaseError

        if self.conn.field_version < FIELD_VERSION_23_1:
            # As for JSON: a 23ai server carries BOOLEAN natively only to a
            # session that negotiated 23.1+ (#1149).
            self.skipTest('native BOOLEAN needs a session at field version 23.1+')
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

    def _bind_roundtrip(self, coltype, value):
        # Bind a Python sequence (#55) and read it back.
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

    def test_a_vector_through_a_plsql_in_out_bind(self):
        # A VECTOR OUT / IN OUT bind carries its IMAGE, not a locator (#1010).
        # Served as a locator the client ran off the end of it -- and the size
        # was irrelevant, which is what made this look like the 64 KiB ceiling
        # of #1008 when it is a different bug entirely.
        import array

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

        if self.conn.field_version < FIELD_VERSION_20_1:
            # The server may have the type and still not hand it to this
            # session natively: 23ai sends a JSON column to a session that
            # negotiated below 20.1 as a plain BLOB, as it would to a real
            # client of that release (#1149).
            self.skipTest('native JSON needs a session at field version 20.1+')
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


@unittest.skipUnless(_USER, _SKIP_REASON)
class SodaIntegration(_IntegrationBase):
    # SODA collection management (#163 / #199), backed by DBMS_SODA. Needs an
    # Oracle 18c+ server; skipped below that.
    def setUp(self):
        super().setUp()
        if (self.conn.server_version >> 24) < 18:
            self.conn.close()
            self.skipTest('SODA needs an Oracle 18c+ server (DBMS_SODA)')
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
        with seerdb.connect(**self._kwargs(_PASSWORD)) as conn:
            if conn.field_version < FIELD_VERSION_10_2:
                self.skipTest('changepassword is not supported on Oracle 9i')

    def test_a_rejected_change_reports_the_servers_code(self):
        # python-oracledb's test_1108: an over-long new password, with the right
        # and then a wrong old one. The server rejects both with ORA-01017 on the
        # protocol route; through the Mirror the change used to go out as ALTER
        # USER ... REPLACE, which the server rejects as ORA-28218 instead (#1089).
        # Both calls fail, so the password never changes.
        with seerdb.connect(**self._kwargs(_PASSWORD)) as conn:
            if conn.field_version < FIELD_VERSION_12_1:
                self.skipTest(
                    'a very long new password gets ORA-03120 before 12c (#1090)'
                )
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
            **_FV_KW,
            **extra,
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

    def _skip_unless_session_kvs(self):
        # The session-context pairs (driver banner, edition) ride only on the
        # FAST_AUTH path, fv > 23.1 -- below that the server is never told, so
        # there is nothing to assert rather than something that fails.
        if self.conn.field_version <= FIELD_VERSION_23_1:
            self.skipTest('session-context pairs need the fv > 23.1 FAST_AUTH')

    def test_driver_name_defaults_to_our_own_banner(self):
        self._skip_unless_session_kvs()
        self.cur.execute(
            'select distinct client_driver from v$session_connect_info '
            "where sid = sys_context('userenv', 'sid')"
        )
        (driver,) = self.cur.fetchone()
        self.assertIn('seerdb', driver)

    def test_driver_name_can_be_declared(self):
        self._skip_unless_session_kvs()
        with _connect_with(driver_name='newdriver') as conn:
            cur = conn.cursor()
            cur.execute(
                'select distinct client_driver from v$session_connect_info '
                "where sid = sys_context('userenv', 'sid')"
            )
            self.assertEqual(cur.fetchone()[0], 'newdriver')

    def test_edition_is_ora_base_unless_asked_for(self):
        # Editions arrived in 11gR2; older tiers have no such context value.
        if self.conn.field_version < FIELD_VERSION_11_2:
            self.skipTest('editions need 11g or later')
        # Through a Mirror the answer is the BACKEND's: one over PostgreSQL has
        # no notion of editions and returns NULL, which is correct for it. The
        # six-tier matrix covers the real-server behaviour.
        if os.environ.get('SEERDB_TEST_MIRROR'):
            self.skipTest('a Mirror reports whatever its backend knows')
        self.cur.execute(
            "select sys_context('USERENV','CURRENT_EDITION_NAME') from dual"
        )
        self.assertEqual(self.cur.fetchone()[0], 'ORA$BASE')


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
        if self.conn.field_version < FIELD_VERSION_10_2:
            # fv2 (9i / 8i) has no array DML at all -- the client refuses the
            # call before a batch can partly apply, so there is no partial count
            # to report.
            self.skipTest('executemany (array DML) is not supported on fv2')
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
        self.cur.execute(f'SELECT COUNT(*) FROM {self.TABLE}')
        (Applied,) = self.cur.fetchone()
        if Applied and not Reported:
            # The rows landed but the server said nothing about them. That is a
            # server that does not report a partial count, not a client that
            # lost one -- Mirror-over-PostgreSQL until #998. Skip rather than
            # fail, and say which it is.
            self.skipTest('this server reports no count for a partly-applied batch')
        # Asserting against what actually LANDED, not against a constant: the
        # point is that the number means something.
        self.assertEqual(Reported, Applied)

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


@unittest.skipUnless(_USER, _SKIP_REASON)
class CursorWarningIntegration(_IntegrationBase):
    """`cursor.warning` for a PL/SQL object created with compilation errors.

    Such a CREATE **succeeds** -- the object exists, invalid -- and the only
    thing that says otherwise is bit 0x20 of the OER's warn byte, which the
    decoder used to skip along with its five neighbours. Measured by diffing a
    live 23ai's reply to the same CREATE compiled clean and broken: identical
    but for the sequence fields and that byte, 0x21 against 0x00 (#993).
    """

    def setUp(self):
        super().setUp()
        if self.conn.field_version < FIELD_VERSION_10_2:
            # fv2 (9i / 8i) answers a CREATE on its own dialect path, whose
            # reply does not carry this byte where the 10g+ OER does -- a broken
            # CREATE there comes back as a bare token, with nothing to read. Not
            # gated because the decode is wrong on those tiers; gated because
            # the signal has not been located on them, and claiming coverage
            # would be worse than admitting the gap (#993).
            self.skipTest('the OER warn byte is not located on fv2')

    def _bad_procedure(self, name: str) -> None:
        # Creating an object that does NOT compile is the precondition of this
        # whole class, and it is an Oracle behaviour: the statement succeeds and
        # the object exists, invalid. A backend without those semantics rejects
        # the statement outright -- Mirror-over-PostgreSQL answers ORA-00900 --
        # and there is no warning to report because there was no create. Skip on
        # that rather than fail, and say which it is (#993).
        from seerdb.common.exceptions import DatabaseError

        try:
            self.cur.execute(
                f"""CREATE OR REPLACE PROCEDURE {name} AS
                    BEGIN
                        NULL
                    END;"""  # the missing semicolon is the point
            )
        except DatabaseError as exc:
            self.skipTest(f'this backend refuses an invalid CREATE outright: {exc}')

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

    def test_an_ordinary_statement_sets_no_warning(self):
        self.cur.execute('SELECT 1 FROM dual')
        self.assertIsNone(self.cur.warning)


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
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('a LOB Var bind needs the 12.1+ OAC (#902)')
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

    def test_fetch_lobs_false_materialises_a_returned_lob(self):
        self.conn.rollback()
        with _connect(fetch_lobs=False) as Conn:
            Cur = Conn.cursor()
            if Conn.field_version < FIELD_VERSION_12_1:
                self.skipTest('a LOB Var bind needs the 12.1+ OAC (#902)')
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
        self._skip_if_mirror_backend('postgres', 'describe an object type')
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
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('a package-level type needs the 12.1+ bind support')
        # A package-level type lives in a PL/SQL PACKAGE, so this class cannot
        # run against a backend with no PL/SQL at all. It skipped on the
        # PostgreSQL leg only by accident until that Mirror reached 12.1: the
        # version gate above was doing the work. The capability is what actually
        # decides it (#1127).
        self._skip_if_mirror_backend('postgres', 'create a PL/SQL package')
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
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('a REF CURSOR IN bind needs the 12c+ bind OAC')
        # The cursor is drained by a PL/SQL procedure in a PACKAGE, and the whole
        # class is built on one, so a backend with no PL/SQL cannot run it. It
        # skipped on the PostgreSQL leg only because that Mirror was below 12.1;
        # the capability is what actually decides it (#1127).
        self._skip_if_mirror_backend('postgres', 'create a PL/SQL package')
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
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('an object bind needs the 12.1+ OAC')
        # The object OUT binds are filled by procedures in a PL/SQL PACKAGE this
        # setUp builds and every test calls into, so a backend with no PL/SQL
        # cannot run the class. It was hidden twice over on the PostgreSQL leg:
        # first by the 12.1 version gate above, then by the VARRAY it declares,
        # which PostgreSQL could not parse until that was translated (#1127).
        self._skip_if_mirror_backend('postgres', 'create a PL/SQL package')
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
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest('an object bind needs the 12.1+ OAC')
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

    def test_ref_bind_roundtrip(self):
        self._setup_schema()
        self.cur.execute(f'SELECT REF(p) FROM {self.PEOPLE} p WHERE p.id = 1')
        ref = self.cur.fetchone()[0]
        self.assertEqual(ref.type_name, self.TYPE)
        if getattr(self.conn, 'field_version', 0) < FIELD_VERSION_12_1:
            self.skipTest('REF bind needs a 12.1+ server')
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
        # table behind (#1224).
        try:
            setup.begin_sessionless_transaction('probe', timeout=10)
            setup.suspend_sessionless_transaction()
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
            **_FV_KW,
            **extra,
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

    async def test_ping_raises_on_a_killed_session(self):
        # Async twin of PingKilledSessionIntegration (#1095).
        if not _ADMIN_USER:
            self.skipTest('set SEERDB_TEST_ADMIN_USER (a DBA) to kill a session')
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            if Conn.field_version < FIELD_VERSION_10_2:
                self.skipTest('9i pings with a query, which already raises')
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

    async def test_createlob_binds_as_a_lob(self):
        # Async twin of CreateLobIntegration (#1066).
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            if Conn.field_version < FIELD_VERSION_12_1:
                self.skipTest('createlob() needs a 12c+ server (CREATE_TEMP)')
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
        if os.environ.get('SEERDB_TEST_MIRROR') in ('postgres', '1'):
            self.skipTest("the Mirror's postgres backend cannot run a PL/SQL block")
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
                try:
                    await Cur.execute(
                        'SELECT dbms_debug_jdwp.current_session_serial FROM dual'
                    )
                except DatabaseError:
                    return
                self.assertEqual(await Cur.fetchone(), (Conn.serial_num,))

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
                await Cur.execute(
                    'SELECT DISTINCT client_driver FROM v$session_connect_info '
                    "WHERE sid = sys_context('userenv', 'sid')"
                )
                driver = (
                    'pyo-driver' if Conn.field_version > FIELD_VERSION_23_1 else None
                )
                self.assertEqual(await Cur.fetchall(), [(driver,)])

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
                    with self.assertRaises(seerdb.Error):
                        await vcur.execute('SELECT 1 FROM dual')
                        await vcur.fetchall()
                finally:
                    try:
                        await victim.close()
                    except seerdb.Error:
                        pass
                for session, code in (('x', 26), (f'{sid},{serial}', 30)):
                    with self.assertRaises(DatabaseError) as caught:
                        await Cur.execute(f"ALTER SYSTEM KILL SESSION '{session}'")
                    self.assertEqual(caught.exception.code, code)

    async def test_timestamp_with_local_time_zone(self):
        # Async twin of CursorIntegration's.
        if _target_is_8i():
            self.skipTest('8i has no TIMESTAMP WITH LOCAL TIME ZONE')
        Table = 'PYO_ASYNC_LTZ'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute('SELECT sessiontimezone, dbtimezone FROM dual')
            (session, database) = (_tz_offset(z) for z in await Cur.fetchone())
            if session is None or database is None:
                self.skipTest('a named time zone')
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

    async def test_a_describe_wider_than_a_packet(self):
        # Async twin of CursorIntegration's.
        from seerdb.common.exceptions import DatabaseError

        if not _target_is_8i():
            self.skipTest('a describe outgrows a packet on 8i')
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

    async def test_timestamp_with_time_zone_compares_by_instant(self):
        # Async twin of CursorIntegration's.
        if _target_is_8i():
            self.skipTest('8i has no TIMESTAMP WITH TIME ZONE')
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

    async def test_days_added_to_a_timestamp_with_local_time_zone(self):
        # Async twin of CursorIntegration's.
        if _target_is_8i():
            self.skipTest('8i has no TIMESTAMP WITH LOCAL TIME ZONE')
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
                if Conn.field_version < FIELD_VERSION_10_2:
                    self.skipTest(
                        '9i reads an LTZ var() bind in the session zone (#1241)'
                    )
                var = Cur.var(seerdb.DB_TYPE_TIMESTAMP_LTZ)
                var.setvalue(0, value.replace(microsecond=0))
                await Cur.execute('begin :value := :value + 5.25; end;', {'value': var})
                self.assertEqual(
                    var.getvalue(), datetime.datetime(2022, 5, 15, 18, 0, 0)
                )

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

    async def test_gettype_follows_the_current_schema(self):
        # Async twin of GettypeCurrentSchemaIntegration.
        if os.environ.get('SEERDB_TEST_MIRROR') in ('postgres', '1'):
            self.skipTest(
                "the Mirror's postgres backend cannot describe an object type"
            )
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

    async def test_gettype_resolves_a_package_level_type(self):
        # Async twin of PlsqlTypeIntegration (#1030).
        Pkg = 'PYO_ASYNC_PLSQLTYPE_PKG'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            if Conn.field_version < FIELD_VERSION_12_1:
                self.skipTest('a package-level type needs the 12.1+ bind support')
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

    async def test_a_bare_object_out_bind_takes_its_value(self):
        # Async twin of ObjectOutBindIntegration (#1029): an object handed to
        # callproc with no Var around it takes the OUT value in place.
        Typ = 'PYO_ASYNC_OUTBIND_T'
        Pkg = 'PYO_ASYNC_OUTBIND_PKG'
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            if Conn.field_version < FIELD_VERSION_12_1:
                self.skipTest('an object bind needs the 12.1+ OAC')
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
            if Conn.field_version < FIELD_VERSION_10_2:
                self.skipTest('LOB reads inside a transaction are not exercised on fv2')
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

    async def test_inout_clob_var(self):
        # The async twin of LOBOutBindIntegration (#978): a LOB OUT bind's value
        # arrives in the LOB framing, and the read that materialises it is
        # awaited. 12.1+ only, like the sync class.
        Conn = await seerdb.connect_async(**self._kwargs())
        try:
            if Conn.field_version < FIELD_VERSION_12_1:
                self.skipTest('a LOB Var bind needs the 12.1+ temp-LOB path (#902)')
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

    async def test_returning_a_clob(self):
        # The async twin of LOBReturningIntegration (#985): the read that
        # materialises a returned LOB is awaited. 12.1+ only, like the sync class.
        Table = 'PYO_ASYNC_LOBRET'
        Conn = await seerdb.connect_async(**{**self._kwargs(), 'autocommit': False})
        try:
            if Conn.field_version < FIELD_VERSION_12_1:
                self.skipTest('a LOB Var bind needs the 12.1+ OAC (#902)')
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
                await Cur.execute('SELECT LEVEL FROM dual CONNECT BY LEVEL <= 5')
                Rows = [row async for row in Cur]
                self.assertEqual(Rows, [(1,), (2,), (3,), (4,), (5,)])

    async def test_fetchall_and_fetchmany(self):
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute('SELECT LEVEL FROM dual CONNECT BY LEVEL <= 4')
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

    async def test_json_bind_roundtrip(self):
        # Async parity for JSON binds (#50): bind a dict, read it back.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_20_1:
                self.skipTest('native JSON needs a session at field version 20.1+')
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

    async def test_error_then_large_lob_stays_synced(self):
        # #45 (async parity): errored calls leave break/reset markers; a few of
        # them followed by a large CLOB read must not desync the stream.
        from seerdb.common.exceptions import DatabaseError

        async with await seerdb.connect_async(**self._kwargs(fetch_lobs=False)) as Conn:
            if Conn.field_version < FIELD_VERSION_10_2:
                self.skipTest('Oracle 9i has no streamed LOB/LONG bind path (#169)')
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

    async def test_async_out_extended_types(self):
        # OUT binds for the extended scalar types (issue #17), async path.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_10_2:
                self.skipTest(
                    'BINARY_DOUBLE / INTERVAL are 10g+ types; Oracle 9i lacks them'
                )
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

    async def test_async_scrollable_lazy(self):
        # Server-side lazy scrollable cursor on the async path (#181), 10g+:
        # fetch-on-demand across batches + scroll modes + the LAST-after-EOF
        # duplicate-value (bit-vector reuse) case.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_10_2:
                self.skipTest('server-side scroll needs 10g+')
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

    async def test_async_soda_collections(self):
        # SODA collection management (#163 / #199) on the async path; 18c+ only.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if (Conn.server_version >> 24) < 18:
                self.skipTest('SODA needs an Oracle 18c+ server (DBMS_SODA)')
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
        # End-to-end tracing (#183) on the async path; 12c+ only.
        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_12_1:
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

    async def test_async_executemany_arraydmlrowcounts(self):
        # Async mirror of test_executemany_arraydmlrowcounts_update (#18).
        from seerdb.common.tns_consts import FIELD_VERSION_12_1

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_12_1:
                self.skipTest('arraydmlrowcounts needs a 12.1+ server')
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

    async def test_async_arraydmlrowcounts_unsupported_on_11g(self):
        # On an 11g server the async feature is rejected up front, same as sync.
        from seerdb.common.tns_consts import FIELD_VERSION_12_1

        async with await seerdb.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version >= FIELD_VERSION_12_1:
                self.skipTest('server supports arraydmlrowcounts')
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

    async def test_async_ref_bind(self):
        # Async mirror of RefBindIntegration (#139): fetch a REF, bind it back.
        from seerdb.common.tns_consts import FIELD_VERSION_12_1 as _FV12

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
            if getattr(Conn, 'field_version', 0) < _FV12:
                self.skipTest('REF bind needs a 12.1+ server')
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
            # table behind (#1224).
            try:
                await setup.begin_sessionless_transaction('aprobe', timeout=10)
            except NotSupportedError:
                self.skipTest('sessionless transactions need a 23ai+ server')
            await setup.suspend_sessionless_transaction()
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
            **_FV_KW,
            **extra,
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
        cls.proxy = TLSProxy(_HOST, _PORT)
        cls.proxy.start()

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, 'proxy', None) is not None:
            cls.proxy.stop()
            cls.proxy = None

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

        def spy(data, acc):
            result = original(data, acc)
            if isinstance(result, tuple) and len(result) == 7:  # SESS challenge
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
        self.conn = _connect()
        if not _conn_is_8i(self.conn):
            self.conn.close()
            self.skipTest('not an Oracle 8i server')
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
        self.conn = _connect()
        if not _conn_is_8i(self.conn):
            self.conn.close()
            self.skipTest('not an Oracle 8i server')
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
        (Got,) = self.cur.execute(
            "select bfilename('ZZ_SEERDB_BD', :f) from dual", {'f': Alert}
        ).fetchone()
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
        conn = await seerdb.connect_async(**self._kwargs())
        if not _conn_is_8i(conn):
            await conn.close()
            self.skipTest('not an Oracle 8i server')
        return conn

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
                    (Got,) = await cur.fetchone()
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


if __name__ == '__main__':
    unittest.main()
