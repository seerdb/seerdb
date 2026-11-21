# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the small DB-API conveniences (issue #22):
stmtcachesize, version, rowfactory, lastrowid. These exercise the
client-side logic without a live server."""

import datetime
import types
import unittest

import seerdb
from seerdb.client._conn_logic import _ConnectionLogic
from seerdb.client.connection import OracleConnect
from seerdb.client.cursor import Cursor
from seerdb.common.exceptions import InterfaceError, ProgrammingError
from seerdb.common.tns_consts import VERSION_11_2_0_2


def _stub_cursor(rows, description=None):
    # A Cursor whose _check_open() passes without a live socket, pre-loaded
    # with already-fetched rows.
    cur = Cursor(types.SimpleNamespace(sock=object()))
    cur._rows = rows
    cur._description = description or [('X', None, None, None, None, None, True)]
    cur._row_index = 0
    return cur


class TestStmtCacheSize(unittest.TestCase):
    def test_default(self):
        self.assertEqual(OracleConnect().stmtcachesize, 32)

    def test_set_evicts_down_to_new_size(self):
        conn = OracleConnect()
        for i in range(10):
            conn._cursor_cache[(f'sql{i}', b'')] = i
        conn.stmtcachesize = 3
        self.assertEqual(conn.stmtcachesize, 3)
        self.assertEqual(len(conn._cursor_cache), 3)
        # Oldest entries evicted, newest kept (insertion-order LRU).
        self.assertEqual(list(conn._cursor_cache.values()), [7, 8, 9])

    def test_zero_disables(self):
        conn = OracleConnect()
        conn._cursor_cache[('sql', b'')] = 1
        conn.stmtcachesize = 0
        self.assertEqual(conn.stmtcachesize, 0)
        self.assertEqual(len(conn._cursor_cache), 0)

    def test_negative_clamped_to_zero(self):
        conn = OracleConnect()
        conn.stmtcachesize = -5
        self.assertEqual(conn.stmtcachesize, 0)


class TestArraysizeDefault(unittest.TestCase):
    def test_default_matches_oracledb(self):
        # arraysize defaults to 100, matching oracledb.defaults.arraysize, so a
        # bare fetchmany() returns up to 100 rows like oracledb (not 1). Shared by
        # the sync and async cursors through _CursorLogic.
        from seerdb.client.acursor import AsyncCursor

        self.assertEqual(Cursor(types.SimpleNamespace(sock=object())).arraysize, 100)
        self.assertEqual(
            AsyncCursor(types.SimpleNamespace(sock=object())).arraysize, 100
        )

    def test_fetchmany_no_arg_uses_the_default(self):
        # fetchmany() with no size returns arraysize rows from the buffer.
        cur = _stub_cursor([[i] for i in range(150)])
        self.assertEqual(len(cur.fetchmany()), 100)


class TestRowFactory(unittest.TestCase):
    def test_default_is_tuple(self):
        cur = _stub_cursor([[1, 'a']])
        self.assertEqual(cur.fetchone(), (1, 'a'))

    def test_called_with_positional_columns(self):
        cur = _stub_cursor(
            [[1, 'a'], [2, 'b']],
            description=[
                ('ID', None, None, None, None, None, True),
                ('NAME', None, None, None, None, None, True),
            ],
        )
        cur.rowfactory = lambda i, n: {'id': i, 'name': n}
        self.assertEqual(
            cur.fetchall(), [{'id': 1, 'name': 'a'}, {'id': 2, 'name': 'b'}]
        )

    def test_applies_through_iteration(self):
        cur = _stub_cursor([[1], [2], [3]])
        cur.rowfactory = lambda x: x * 10
        self.assertEqual(list(cur), [10, 20, 30])


class TestScroll(unittest.TestCase):
    def _cur(self):
        return _stub_cursor([[i] for i in range(1, 6)])  # rows 1..5

    def test_first(self):
        cur = self._cur()
        cur.scroll(mode='first')
        self.assertEqual(cur.fetchone(), (1,))

    def test_last(self):
        cur = self._cur()
        cur.scroll(mode='last')
        self.assertEqual(cur.fetchone(), (5,))

    def test_absolute(self):
        cur = self._cur()
        cur.scroll(3, mode='absolute')
        self.assertEqual(cur.fetchone(), (3,))

    def test_relative_back_after_fetch(self):
        cur = self._cur()
        self.assertEqual(cur.fetchone(), (1,))
        self.assertEqual(cur.fetchone(), (2,))
        self.assertEqual(cur.fetchone(), (3,))  # consumed 3, position = 3
        cur.scroll(-2, mode='relative')  # back to row 1
        self.assertEqual(cur.fetchone(), (1,))

    def test_relative_zero_rereads_current(self):
        cur = self._cur()
        cur.fetchone()
        cur.fetchone()  # consumed 2
        cur.scroll(0, mode='relative')  # re-read row 2
        self.assertEqual(cur.fetchone(), (2,))

    def test_forward_then_continue(self):
        cur = self._cur()
        cur.scroll(2, mode='absolute')
        self.assertEqual([cur.fetchone(), cur.fetchone()], [(2,), (3,)])

    def test_out_of_range_raises_indexerror(self):
        cur = self._cur()
        with self.assertRaises(IndexError):
            cur.scroll(99, mode='absolute')
        with self.assertRaises(IndexError):
            cur.scroll(0, mode='absolute')
        with self.assertRaises(IndexError):
            cur.scroll(-1, mode='relative')

    def test_invalid_mode_raises(self):
        cur = self._cur()
        with self.assertRaises(ProgrammingError):
            cur.scroll(1, mode='sideways')

    def test_no_result_set_raises(self):
        cur = Cursor(types.SimpleNamespace(sock=object()))
        with self.assertRaises(InterfaceError):
            cur.scroll(mode='first')


class _StubConn(_ConnectionLogic):
    # Minimal stand-in for OracleConnect: _run only needs .sock (for
    # _check_open) and .execute returning a wire-shaped result tuple.
    sock = object()

    def __init__(self, result):
        self._result = result

    def execute(
        self,
        operation,
        Bind=None,
        Batch=None,
        BatchErrors=False,
        ArrayDmlRowCounts=False,
    ):
        return self._result


class TestLastRowid(unittest.TestCase):
    # Wire result tuple shape: (call_status, ora_code, cursor_id,
    # (rowcount, col_meta), rows, message, lastrowid)

    def test_dml_sets_rowid(self):
        dml = (0, 0, 1, (1, None), [], None, 'AAAB12AAEAAAAGPAAA')
        cur = Cursor(_StubConn(dml))
        cur.execute('INSERT INTO t VALUES (1)')
        self.assertEqual(cur.lastrowid, 'AAAB12AAEAAAAGPAAA')

    def test_select_clears_rowid(self):
        cur = Cursor(_StubConn((0, 0, 1, (1, None), [], None, 'AAAB12AAEAAAAGPAAA')))
        cur.execute('INSERT INTO t VALUES (1)')
        self.assertIsNotNone(cur.lastrowid)
        # A subsequent SELECT (result set) must clear it.
        cur._connection = _StubConn(
            (0, 0, 1, (0, [{'column_name': 'ID'}]), [[1]], None, None)
        )
        cur.execute('SELECT id FROM t')
        self.assertIsNone(cur.lastrowid)

    def test_ddl_no_rowid(self):
        ddl = (0, 0, 1, (0, None), [], None, None)
        cur = Cursor(_StubConn(ddl))
        cur.execute('CREATE TABLE t (id NUMBER)')
        self.assertIsNone(cur.lastrowid)


class TestVersion(unittest.TestCase):
    def test_none_before_auth(self):
        self.assertIsNone(OracleConnect().version)

    def test_decodes_xe_11g(self):
        conn = OracleConnect()
        conn.server_version = VERSION_11_2_0_2  # as XE 11.2.0.2.0 sends
        self.assertEqual(conn.version, '11.2.0.2.0')


if __name__ == '__main__':
    unittest.main()


class TestScrollableCursor(unittest.TestCase):
    # Scrollable cursor API parity (#161): the cursor accepts and exposes the
    # `scrollable` flag. seerdb buffers the result set so scroll() works
    # regardless; the flag is for oracledb compatibility.
    def test_default_not_scrollable(self):
        cur = Cursor(types.SimpleNamespace(sock=object()))
        self.assertIs(cur.scrollable, False)

    def test_opened_scrollable(self):
        cur = Cursor(types.SimpleNamespace(sock=object()), scrollable=True)
        self.assertIs(cur.scrollable, True)

    def test_setter(self):
        cur = Cursor(types.SimpleNamespace(sock=object()))
        cur.scrollable = True
        self.assertIs(cur.scrollable, True)
        cur.scrollable = 0
        self.assertIs(cur.scrollable, False)

    def test_connection_cursor_passes_flag(self):
        conn = OracleConnect()
        self.assertIs(conn.cursor(scrollable=True).scrollable, True)
        self.assertIs(conn.cursor().scrollable, False)


class TestDbApiModuleInterface(unittest.TestCase):
    """The module-level names PEP 249 requires (#683).

    The driver advertises apilevel 2.0, so code written against the DB-API
    generically — without knowing which driver is underneath — must find these.
    """

    def test_every_required_name_is_present_and_exported(self):
        required = [
            # constructors
            'Date',
            'Time',
            'Timestamp',
            'DateFromTicks',
            'TimeFromTicks',
            'TimestampFromTicks',
            'Binary',
            # type objects
            'STRING',
            'BINARY',
            'NUMBER',
            'DATETIME',
            'ROWID',
            # globals
            'apilevel',
            'threadsafety',
            'paramstyle',
            'connect',
        ]
        missing = [n for n in required if not hasattr(seerdb, n)]
        self.assertEqual(missing, [], f'missing from the module: {missing}')
        unexported = [n for n in required if n not in seerdb.__all__]
        self.assertEqual(unexported, [], f'missing from __all__: {unexported}')

    def test_the_globals_say_what_the_driver_actually_is(self):
        self.assertEqual(seerdb.apilevel, '2.0')
        self.assertEqual(seerdb.paramstyle, 'named')
        self.assertIn(seerdb.threadsafety, (0, 1, 2, 3))

    def test_constructors_build_the_stdlib_values_binds_accept(self):
        self.assertEqual(seerdb.Date(2026, 9, 4), datetime.date(2026, 9, 4))
        self.assertEqual(seerdb.Time(13, 45, 30), datetime.time(13, 45, 30))
        self.assertEqual(
            seerdb.Timestamp(2026, 9, 4, 13, 45, 30),
            datetime.datetime(2026, 9, 4, 13, 45, 30),
        )
        # The hour/minute/second tail is optional, as it is for datetime.
        self.assertEqual(
            seerdb.Timestamp(2026, 9, 4), datetime.datetime(2026, 9, 4, 0, 0, 0)
        )

    def test_the_ticks_constructors_agree_with_their_plain_forms(self):
        ticks = datetime.datetime(2026, 9, 4, 13, 45, 30).timestamp()
        self.assertEqual(seerdb.DateFromTicks(ticks), seerdb.Date(2026, 9, 4))
        self.assertEqual(seerdb.TimeFromTicks(ticks), seerdb.Time(13, 45, 30))
        self.assertEqual(
            seerdb.TimestampFromTicks(ticks), seerdb.Timestamp(2026, 9, 4, 13, 45, 30)
        )

    def test_binary_accepts_what_a_caller_is_likely_to_hold(self):
        self.assertEqual(seerdb.Binary(b'\x00\xff'), b'\x00\xff')
        self.assertEqual(seerdb.Binary(bytearray(b'ab')), b'ab')
        self.assertEqual(seerdb.Binary(memoryview(b'ab')), b'ab')
        self.assertEqual(seerdb.Binary('ab'), b'ab')
        self.assertIsInstance(seerdb.Binary('ab'), bytes)

    def test_type_objects_match_what_description_reports(self):
        # Each is the DbType the server reports for that kind of column, so a
        # caller can compare cursor.description[i][1] against it.
        self.assertIs(seerdb.STRING, seerdb.DB_TYPE_VARCHAR)
        self.assertIs(seerdb.NUMBER, seerdb.DB_TYPE_NUMBER)
        self.assertIs(seerdb.BINARY, seerdb.DB_TYPE_RAW)
        self.assertIs(seerdb.ROWID, seerdb.DB_TYPE_ROWID)
        self.assertIs(seerdb.DATETIME, seerdb.DB_TYPE_DATE)


class TestFailedCachedExecuteIsForgotten(unittest.TestCase):
    """A cached cursor whose execute failed must leave the cache (#709).

    The server drops such a cursor; re-executing its id answered ORA-01001 for
    the rest of the connection. The error arrives as an ordinary status, not an
    exception, so the eviction has to look at the status.
    """

    SQL = 'INSERT INTO t VALUES (:1)'

    def _run(self, status):
        from unittest.mock import patch

        from seerdb.common.tns import exec_oac_signature
        from seerdb.common.tns_consts import FIELD_VERSION_11_2

        conn = OracleConnect()
        conn.field_version = FIELD_VERSION_11_2
        key = (self.SQL, exec_oac_signature([1], []))
        conn._cursor_cache[key] = 7  # a hit: the execute reuses cursor 7
        result = (None, status, 7, [], [], f'ORA-{status:05d}')
        with (
            patch.object(OracleConnect, 'send', return_value=True),
            patch.object(OracleConnect, '_handle_response', return_value=result),
        ):
            conn.execute(self.SQL, [1])
        return key in conn._cursor_cache

    def test_an_error_status_evicts_the_entry(self):
        self.assertFalse(self._run(1))  # ORA-00001

    def test_a_success_keeps_it(self):
        self.assertTrue(self._run(0))

    def test_a_batch_error_keeps_it(self):
        # ORA-24381: the batch ran, some rows failed; the cursor is still good.
        self.assertTrue(self._run(24381))


class TestDdlForgetsCachedCursors(unittest.TestCase):
    """DDL and PL/SQL blocks flush the cursor cache; a LONG-class statement is
    never cached (#720)."""

    def _conn(self):
        from seerdb.common.tns_consts import FIELD_VERSION_11_2

        conn = OracleConnect()
        conn.field_version = FIELD_VERSION_11_2
        conn._cursor_cache[('INSERT INTO t VALUES (:1)', b'sig')] = 7
        return conn

    def _run(self, conn, sql, bind=None, status=0, cursor_id=9):
        from unittest.mock import patch

        sent = []
        result = (None, status, cursor_id, [], [], None)
        with (
            patch.object(
                OracleConnect, 'send', lambda self, t, d: sent.append(bytes(d)) or True
            ),
            patch.object(OracleConnect, '_handle_response', return_value=result),
        ):
            conn.execute(sql, bind or [])
        return b''.join(sent)

    def test_ddl_flushes_and_queues_the_cursors_for_close(self):
        conn = self._conn()
        request = self._run(conn, 'DROP TABLE t')
        self.assertEqual(dict(conn._cursor_cache), {})
        # The flushed cursor rides out in the close-cursors piggyback of the
        # DDL's own request (TTI_MSG_TYPE_PIGGYBACK + TTI_OCCA).
        self.assertIn(bytes([0x11, 0x69]), request)

    def test_a_block_flushes_too(self):
        conn = self._conn()
        self._run(conn, 'begin null; end;')
        self.assertEqual(dict(conn._cursor_cache), {})

    def test_dml_keeps_the_cache(self):
        conn = self._conn()
        self._run(conn, 'UPDATE t SET x = 1')
        self.assertIn(('INSERT INTO t VALUES (:1)', b'sig'), conn._cursor_cache)

    def test_a_long_class_statement_is_not_cached(self):
        conn = self._conn()
        wide = seerdb.Var(str)  # 32767: LONG-class below 12c
        self._run(conn, 'INSERT INTO w VALUES (:1, :2)', [1, wide])
        self.assertFalse(
            any(k[0].startswith('INSERT INTO w') for k in conn._cursor_cache)
        )
        self._run(conn, 'INSERT INTO n VALUES (:1, :2)', [1, 'short'])
        self.assertTrue(
            any(k[0].startswith('INSERT INTO n') for k in conn._cursor_cache)
        )


class TestTouchedRowid(unittest.TestCase):
    # A DML that affected no rows touched no row (#1078).
    def test_a_zero_row_statement_has_no_rowid_whatever_the_token_says(self):
        from seerdb.client._cursor_logic import _touched_rowid

        self.assertIsNone(_touched_rowid('AAAtNiAAAAADSDjAAB', 0))

    def test_a_statement_that_touched_a_row_keeps_it(self):
        from seerdb.client._cursor_logic import _touched_rowid

        self.assertEqual(_touched_rowid('AAAtNiAAAAADSDjAAB', 1), 'AAAtNiAAAAADSDjAAB')
        # No count to go by (a block, an unknown shape): the token decides.
        self.assertEqual(
            _touched_rowid('AAAtNiAAAAADSDjAAB', None), 'AAAtNiAAAAADSDjAAB'
        )
        self.assertIsNone(_touched_rowid(None, 3))


class TestFetchInfoDomain(unittest.TestCase):
    # A 23ai column's domain and annotations on cursor.description (#1083).
    def test_a_described_domain_column(self):
        from seerdb.client.cursor import _column_description

        col = {
            'column_name': b'AGE',
            'data_type': 2,
            'precision': 3,
            'null_ok': 1,
            'domain_schema': b'PYO',
            'domain_name': b'PYO_SIMPLE_DOMAIN',
            'annotations': {b'ANNO_1': b'first annotation', b'ANNO_3': b''},
        }
        info = _column_description(col)
        self.assertEqual(
            (info.domain_schema, info.domain_name), ('PYO', 'PYO_SIMPLE_DOMAIN')
        )
        self.assertEqual(info.annotations, {'ANNO_1': 'first annotation', 'ANNO_3': ''})

    def test_a_plain_column_has_none(self):
        from seerdb.client.cursor import _column_description

        info = _column_description({'column_name': b'ID', 'data_type': 2})
        self.assertEqual(
            (info.domain_schema, info.domain_name, info.annotations), (None,) * 3
        )


class TestPingReplyError(unittest.TestCase):
    # A ping's reply can carry the error that ends the session (#1095).
    def test_the_replys_error_is_raised(self):
        from seerdb.client._conn_logic import _ConnectionLogic

        reply = (0, 28, None, None, None, 'ORA-00028: session has been terminated')
        with self.assertRaises(seerdb.DatabaseError) as caught:
            _ConnectionLogic._raise_reply_error(reply)
        self.assertEqual(caught.exception.code, 28)

    def test_a_clean_reply_raises_nothing(self):
        from seerdb.client._conn_logic import _ConnectionLogic

        _ConnectionLogic._raise_reply_error((0, 0, None, None, None, None))
        # The (done, accumulator) shape a clean ping can come back in (#1095).
        _ConnectionLogic._raise_reply_error((True, (None, None, [])))


class TestBFileIsNeverMaterialised(unittest.TestCase):
    # fetch_lobs=False turns a CLOB / BLOB into a value; a BFILE keeps its LOB
    # object, because reading one opens a file on the server (#1101).
    class _Conn:
        fetch_lobs = False

    def _row(self, data_type):
        from seerdb.client.cursor import _resolve_lobs
        from seerdb.common.lob import LOB

        return _resolve_lobs(self._Conn(), [LOB(data_type, b'locator-bytes')])

    def test_a_bfile_stays_a_lob(self):
        from seerdb.common.lob import LOB
        from seerdb.common.tns_consts import TNS_TYPE_BFILE

        self.assertIsInstance(self._row(TNS_TYPE_BFILE)[0], LOB)

    def test_a_clob_is_still_materialised(self):
        from seerdb.common.tns_consts import TNS_TYPE_CLOB

        # No connection to read over, so the attempt fails -- which is itself the
        # proof that a CLOB still takes the materialising path.
        with self.assertRaises(Exception):
            self._row(TNS_TYPE_CLOB)
