# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A pooled 11g session's calls in the native form (#2466), offline.

The requests are checked against sqlplus 11.2's own, captured running
statements through 11g XE's pool; the replies are 11g's, read by the codec
and by the dialect, which is driven here without a socket: its sends are
collected and its receives answered with the captured replies.
"""

import datetime
import os
import sys
import unittest

from seerdb.client.dialect import RECV, Oci11Dialect, Send
from seerdb.common import oci
from seerdb.common.exceptions import DatabaseError, NotSupportedError
from seerdb.common.tns import (
    O8I_STMT_SELECT,
    OCI11_STMT_COMMIT,
    OCI11_STMT_ROLLBACK,
    decode_oci11_describe,
    decode_oci11_piggybacks,
    decode_oci11_status,
    encode_oci11_close_cursors,
    encode_oci11_execute,
    encode_oci11_fetch,
    oci11_stmt_type,
    set_decode_field_versions,
)
from seerdb.common.tns_consts import FIELD_VERSION_11_2

# Where sqlplus 11.2 leaves its own address in a pointer field of the execute
# (al8txn); seerdb sends the indicator there.
_LEAKED_POINTER = slice(131, 139)


def _capture(name):
    # tests/replay.py, which CI's unittest step, importing this module as
    # tests.test_native11_calls, does not have on its path.
    sys.path.insert(0, os.path.dirname(__file__))
    from replay import load_capture

    return load_capture(name)


def _drive(gen, replies):
    """Run a dialect call: collect what it sends, answer each receive with the
    next of ``replies`` (TTC payloads). Returns (sends, result)."""
    sends = []
    replies = list(replies)
    to_send = None
    try:
        while True:
            intent = gen.send(to_send)
            if intent is RECV:
                to_send = (6, replies.pop(0))
            else:
                assert isinstance(intent, Send)
                sends.append(intent.data)
                to_send = None
    except StopIteration as done:
        return (sends, done.value)


class _At11g(unittest.TestCase):
    def setUp(self):
        set_decode_field_versions(FIELD_VERSION_11_2, FIELD_VERSION_11_2)
        self.addCleanup(set_decode_field_versions, 6, 6)


class Native11RequestTest(_At11g):
    """The requests, against sqlplus 11.2's."""

    def test_the_execute_is_sqlplus_11_2s(self):
        Captured = _capture('oci11_execute_query.hexdump')
        Mine = encode_oci11_execute(
            Captured[2], b'select level from dual connect by level <= 12', 1, 1
        )
        self.assertEqual(len(Mine), len(Captured))
        self.assertTrue(oci.pointer_present(Captured[_LEAKED_POINTER]))
        self.assertEqual(Mine[_LEAKED_POINTER], oci.OCI_INDICATOR)
        Pointer = _LEAKED_POINTER
        self.assertEqual(Mine[: Pointer.start], Captured[: Pointer.start])
        self.assertEqual(Mine[Pointer.stop :], Captured[Pointer.stop :])

    def test_the_fetch_is_sqlplus_11_2s(self):
        Captured = _capture('oci11_fetch.hexdump')
        self.assertEqual(encode_oci11_fetch(Captured[2], 1, 5), Captured)

    def test_the_close_is_sqlplus_11_2s(self):
        Captured = _capture('oci11_close_cursors.hexdump')
        self.assertEqual(encode_oci11_close_cursors(Captured[2], [1]), Captured)

    def test_the_statement_types_are_sqlplus_11_2s(self):
        # al8i4[7], as sqlplus 11.2 sent them through the pool.
        for Statement, Type in (
            ('SELECT LEVEL FROM DUAL', O8I_STMT_SELECT),
            ('UPDATE T SET N = 1', 2),
            ('DELETE FROM T', 3),
            ('INSERT INTO T VALUES (1)', 4),
            ('CREATE TABLE T (N NUMBER)', 5),
            ('DROP TABLE T PURGE', 6),
            ('ROLLBACK', OCI11_STMT_ROLLBACK),
            ('COMMIT', OCI11_STMT_COMMIT),
        ):
            with self.subTest(Statement):
                self.assertEqual(oci11_stmt_type(Statement), Type)

    def test_commit_and_rollback_are_plsql_free(self):
        # Every statement but COMMIT and ROLLBACK carries NOT_PLSQL (0x8000), as
        # sqlplus 11.2's do; a query also fetches.
        def options(Type):
            return int.from_bytes(encode_oci11_execute(1, b'x', Type)[3:7], 'little')

        self.assertEqual(options(O8I_STMT_SELECT), 0x8061)
        self.assertEqual(options(4), 0x8021)
        self.assertEqual(options(OCI11_STMT_COMMIT), 0x21)
        self.assertEqual(options(OCI11_STMT_ROLLBACK), 0x21)


class Native11ReplyTest(_At11g):
    """11g's replies, read by the codec."""

    def test_a_query_reply_is_read(self):
        (Columns, Rest) = decode_oci11_describe(_capture('oci11_query_reply.hexdump'))
        self.assertEqual([C['column_name'] for C in Columns], ['N', 'S', 'D', 'Z'])
        from seerdb.common.tns import decode_9i_oall8_exec_response

        (Rows, Terminal, _) = decode_9i_oall8_exec_response(Rest, Columns, None)
        self.assertEqual(Rows, [[1, 'abc', datetime.datetime(2026, 11, 5), None]])
        Status = decode_oci11_status(Terminal)
        self.assertEqual((Status['cursor'], Status['error_code']), (1, 0))

    def test_a_dml_reply_is_read(self):
        Status = decode_oci11_status(_capture('oci11_dml_reply.hexdump'))
        self.assertEqual((Status['cursor'], Status['row_kind']), (3, 1))
        self.assertEqual(Status['error_code'], 0)

    def test_an_error_reply_is_read(self):
        Status = decode_oci11_status(_capture('oci11_error_reply.hexdump'))
        self.assertEqual((Status['cursor'], Status['error_code']), (4, 942))
        self.assertEqual(Status['error_pos'], 14)
        self.assertEqual(Status['message'], 'ORA-00942: table or view does not exist')

    def test_the_first_reply_carries_the_pooled_session(self):
        (Session, Rest) = decode_oci11_piggybacks(_capture('oci11_first_reply.hexdump'))
        self.assertEqual((Session['session_id'], Session['serial']), (67, 4155))
        self.assertEqual(Rest[0], 0x10)  # the describe follows

    def test_an_unknown_token_is_an_error_not_a_wait(self):
        # Where the OER should be, anything else fails at once: read as "not
        # here yet", it left the dialect waiting for bytes that never came.
        from seerdb.common.exceptions import DataError, Truncated

        with self.assertRaises(DataError):
            decode_oci11_status(b'\x07\x00')
        with self.assertRaises(Truncated):
            decode_oci11_status(b'')


class Native11RowImageTest(_At11g):
    """Rows sent as row images: a row header's byte 2 with 0x08 says so."""

    def _rows(self, name, columns=None, last=None):
        from seerdb.common.tns import decode_oci11_rows

        Data = _capture(name)
        if columns is None:
            (columns, Data) = decode_oci11_describe(Data)
        (Rows, Terminal, Last) = decode_oci11_rows(Data, columns, last)
        return (columns, Rows, decode_oci11_status(Terminal), Last)

    def test_a_long_cell_and_a_trailing_null(self):
        (Columns, Rows, Status, _) = self._rows('oci11_row_image_reply.hexdump')
        self.assertEqual([C['column_name'] for C in Columns], ['N', 'S', 'Z'])
        self.assertEqual(Rows, [[1, 'x' * 300, None]])
        self.assertEqual(Status['error_code'], 0)

    def test_the_fetch_after_it(self):
        (Columns, _, _, Last) = self._rows('oci11_row_image_reply.hexdump')
        (_, Rows, Status, _) = self._rows(
            'oci11_row_image_fetch_reply.hexdump', Columns, Last
        )
        self.assertEqual(Rows, [[2, 'short', 'zz'], [3, None, None]])
        self.assertEqual(Status['error_code'], 1403)

    def test_a_cell_past_the_row_is_an_error(self):
        from seerdb.common.exceptions import DataError
        from seerdb.common.tns import _oci11_row_image

        with self.assertRaises(DataError):
            _oci11_row_image(bytes([0x2C, 1, 1, 5, 0xC1]), [{'data_type': 2}])


class Native11StatusTest(_At11g):
    """What a status carries besides its OER."""

    def test_an_alter_session_returns_its_settings(self):
        Reply = _capture('oci11_alter_session_reply.hexdump')
        (Session, Rest) = decode_oci11_piggybacks(Reply)
        self.assertIsNone(Session)  # behind the return parameters, not ahead
        Status = decode_oci11_status(Rest)
        self.assertEqual(Status['error_code'], 0)
        Values = {bytes(P.get('value') or b'') for P in Status['keywords']}
        self.assertEqual(len(Status['keywords']), 18)
        self.assertIn(b'YYYY-MM-DD', Values)

    def test_a_dml_reports_the_row_it_touched(self):
        Status = decode_oci11_status(_capture('oci11_dml_reply.hexdump'))
        self.assertEqual(len(Status['rowid']), 18)  # a heap table's, extended

    def test_an_index_organized_tables_rowid_is_logical(self):
        Status = decode_oci11_status(_capture('oci11_iot_insert_reply.hexdump'))
        self.assertEqual(Status['rowid'], '*BAEAJrMCwQL+')

    def test_a_query_carries_no_rowid(self):
        (Columns, Rest) = decode_oci11_describe(_capture('oci11_query_reply.hexdump'))
        from seerdb.common.tns import decode_oci11_rows

        (_, Terminal, _) = decode_oci11_rows(Rest, Columns, None)
        self.assertIsNone(decode_oci11_status(Terminal)['rowid'])


class Native11DialectTest(_At11g):
    """The dialect's calls, driven with 11g's captured replies."""

    def setUp(self):
        super().setUp()
        self.seq = iter(range(10, 100))
        self.sessions = []
        self.dialect = Oci11Dialect(
            lambda: next(self.seq), lambda *s: self.sessions.append(s)
        )

    def test_a_query_reads_its_row_and_fetches_to_the_end(self):
        (Sends, Result) = _drive(
            self.dialect.execute_query('select 1 from dual', None, 15),
            [
                _capture('oci11_query_reply.hexdump'),
                _capture('oci11_fetch_end_reply.hexdump'),
            ],
        )
        self.assertEqual(Result[4], [[1, 'abc', datetime.datetime(2026, 11, 5), None]])
        self.assertEqual(len(Sends), 2)  # the execute, then a fetch from cursor 1
        self.assertEqual(Sends[1], encode_oci11_fetch(11, 1, 15))
        # The cursor is closed with the next call.
        (Sends, _) = _drive(
            self.dialect.execute_dml('commit'), [_capture('oci11_dml_reply.hexdump')]
        )
        self.assertTrue(Sends[0].startswith(encode_oci11_close_cursors(12, [1])))

    def test_the_first_reply_tells_the_pooled_session(self):
        (_, Result) = _drive(
            self.dialect.execute_query('select 1 from dual', None, 15),
            [_capture('oci11_first_reply.hexdump')],
        )
        self.assertEqual(Result[4], [['POOLED', '67']])
        self.assertIn((67, 4155), self.sessions)

    def test_a_dml_counts_its_rows(self):
        (_, Result) = _drive(
            self.dialect.execute_dml("insert into t values (1, 'one')"),
            [_capture('oci11_dml_reply.hexdump')],
        )
        self.assertEqual((Result[1], Result[3][0]), (0, 1))
        self.assertEqual(len(Result[6]), 18)  # the touched row, lastrowid

    def test_each_reply_tells_its_call_status(self):
        Statuses = []
        Dialect = Oci11Dialect(lambda: next(self.seq), None, Statuses.append)
        _drive(
            Dialect.execute_dml("insert into t values (1, 'one')"),
            [_capture('oci11_dml_reply.hexdump')],
        )
        self.assertTrue(Statuses[-1] & 0x02)  # TXN_IN_PROGRESS, a row inserted

    def test_a_failed_query_raises_with_its_position(self):
        with self.assertRaises(DatabaseError) as Raised:
            _drive(
                self.dialect.execute_query('select * from no_such_table', None, 15),
                [_capture('oci11_error_reply.hexdump')],
            )
        self.assertEqual(Raised.exception.code, 942)
        self.assertEqual(Raised.exception.offset, 14)

    def test_what_is_not_built_is_refused_before_it_is_sent(self):
        for Call in (
            lambda: self.dialect.execute_query('select :1 from dual', [1], 15),
            lambda: self.dialect.execute_dml('insert into t values (:1)', [1]),
            lambda: self.dialect.execute_block('begin null; end;'),
            lambda: self.dialect.bfile_read(b''),
        ):
            with self.assertRaises(NotSupportedError):
                _drive(Call(), [])

    def test_it_serves_queries_dml_and_its_own_transactions(self):
        from seerdb.client.dialect import (
            CAP_ARRAY_DML,
            CAP_BLOCK,
            CAP_DML,
            CAP_OWN_TXN,
            CAP_QUERY,
        )

        Caps = self.dialect.capabilities()
        self.assertEqual(
            Caps & {CAP_QUERY, CAP_DML, CAP_OWN_TXN}, {CAP_QUERY, CAP_DML, CAP_OWN_TXN}
        )
        self.assertFalse(Caps & {CAP_BLOCK, CAP_ARRAY_DML})


if __name__ == '__main__':
    unittest.main()
