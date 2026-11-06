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


class Native11BindRequestTest(_At11g):
    """Executes carrying binds, against sqlplus 11.2's."""

    @staticmethod
    def _sql_of(Captured):
        # The captured execute's own SQL text, as sqlplus sent it.
        from seerdb.common.tns import _OCI, _oci_all8_head

        (_, LengthAt, _) = _oci_all8_head(Captured)
        return bytes(_OCI.read_chr(Captured[LengthAt:])[0])

    def _same_but_the_pointer(self, Mine, Captured):
        self.assertEqual(len(Mine), len(Captured))
        Pointer = _LEAKED_POINTER
        self.assertEqual(Mine[: Pointer.start], Captured[: Pointer.start])
        self.assertEqual(Mine[Pointer.stop :], Captured[Pointer.stop :])

    def test_a_block_without_binds(self):
        Captured = _capture('oci11_execute_block.hexdump')
        Mine = encode_oci11_execute(Captured[2], self._sql_of(Captured), 8, 1)
        self._same_but_the_pointer(Mine, Captured)

    def test_a_block_with_an_out_bind(self):
        from seerdb import DB_TYPE_NUMBER
        from seerdb.common.datatypes import Var

        Captured = _capture('oci11_execute_block_out_bind.hexdump')
        Mine = encode_oci11_execute(
            Captured[2], self._sql_of(Captured), 8, 1, [Var(DB_TYPE_NUMBER, 22)]
        )
        self._same_but_the_pointer(Mine, Captured)

    def test_a_character_var_is_declared_at_three_bytes_a_character(self):
        # As sqlplus 11.2 declares a VARCHAR2(20) variable: 60 bytes, the
        # session's charset (873) and form 1.
        from seerdb import DB_TYPE_VARCHAR
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import _OAC_FROM_OCI, _encode_oci11_bind_oac

        (Oac, _) = _OAC_FROM_OCI(
            _encode_oci11_bind_oac(Var(DB_TYPE_VARCHAR, 20)), {'oci_12c': False}
        )
        self.assertEqual(
            (Oac['flags'], Oac['max_length'], Oac['charset'], Oac['csfrm']),
            (3, 60, 873, 1),
        )


class Native11BlockReplyTest(_At11g):
    """A block's reply: its prompt, its OUT values, its status."""

    def test_the_out_values_and_their_directions(self):
        from seerdb.common.tns import decode_oci11_block

        (Directions, Values, Rest, Session) = decode_oci11_block(
            _capture('oci11_block_out_reply.hexdump'), 3
        )
        self.assertEqual(Directions, [0x30, 0x30, 0x10])
        self.assertEqual(
            Values, [b'\xc1U', b'HELLO', bytes.fromhex('bff8000000000000')]
        )
        self.assertIsNone(Session)
        self.assertEqual(decode_oci11_status(Rest)['error_code'], 0)

    def test_a_returning_that_matched_no_row_is_null(self):
        from seerdb.common.tns import decode_oci11_block

        (Directions, Values, Rest, _) = decode_oci11_block(
            _capture('oci11_block_null_returning_reply.hexdump'), 3
        )
        self.assertEqual(Directions, [0x20, 0x20, 0x10])
        self.assertEqual(Values, [None])
        self.assertEqual(decode_oci11_status(Rest)['error_code'], 0)

    def test_a_first_call_has_its_session_return_after_the_prompt(self):
        from seerdb.common.tns import decode_oci11_block

        (Directions, Values, Rest, Session) = decode_oci11_block(
            _capture('oci11_block_first_reply.hexdump'), 4
        )
        self.assertEqual(Directions, [0x10, 0x30, 0x10, 0x10])
        self.assertEqual(Values[:2], [b'\xc1+', b'HELLO'])
        self.assertIsNone(Values[3])  # a NULL, its indicator 0xFFFF
        self.assertIsNotNone(Session)
        self.assertEqual(decode_oci11_status(Rest)['error_code'], 0)


class Native11BindTypeTest(unittest.TestCase):
    """A bind's descriptor says the type its value goes as."""

    def _type(self, Value):
        from seerdb.common.tns import _OAC_FROM_OCI, _encode_oci11_bind_oac

        (Oac, _) = _OAC_FROM_OCI(_encode_oci11_bind_oac(Value), {'oci_12c': False})
        return (Oac['data_type'], Oac['max_length'])

    def test_binary_floats_and_non_finite_floats(self):
        from seerdb import BinaryDouble, BinaryFloat

        self.assertEqual(self._type(BinaryDouble(1234.5678)), (101, 8))
        self.assertEqual(self._type(BinaryFloat(1.5)), (100, 4))
        self.assertEqual(self._type(float('inf')), (101, 8))
        self.assertEqual(self._type(1.5), (2, 22))  # a finite float, a NUMBER

    def test_a_bc_date(self):
        from seerdb.common.datatypes import BcDate

        self.assertEqual(self._type(BcDate(-44, 3, 15, 12, 30, 45)), (12, 7))


class Native11ArrayDmlTest(_At11g):
    """executemany: its rows in one execute, and what the status says."""

    def test_each_row_rides_its_own_rxd(self):
        from seerdb.common.tns import _ALL8_HEAD, _OCI_WIDE, wire_schema

        Message = encode_oci11_execute(
            5, b'insert into t values (:1)', 4, 1, [1], [[2], [3]]
        )
        (Head, _) = wire_schema.compile_decoder(_ALL8_HEAD, _OCI_WIDE)(Message)
        self.assertEqual(Head['bind_count'], 1)
        # al8i4[1], the execute flag, counts the rows; three rows behind TTI_RXD.
        Sql = b'insert into t values (:1)'
        At = Message.index(Sql) + len(Sql)
        self.assertEqual(int.from_bytes(Message[At + 4 : At + 8], 'little'), 3)
        self.assertTrue(
            Message.endswith(b'\x07\x02\xc1\x02\x07\x02\xc1\x03\x07\x02\xc1\x04')
        )

    def test_batch_errors_are_asked_for(self):
        Options = int.from_bytes(
            encode_oci11_execute(
                5, b'insert into t values (:1)', 4, 1, [1], [[2]], True
            )[3:7],
            'little',
        )
        self.assertTrue(Options & 0x80000)

    def test_a_batch_counts_its_rows(self):
        Status = decode_oci11_status(_capture('oci11_array_dml_reply.hexdump'))
        self.assertEqual((Status['row_kind'], Status['error_code']), (3, 0))

    def test_batch_errors_name_their_rows(self):
        Status = decode_oci11_status(_capture('oci11_batch_errors_reply.hexdump'))
        self.assertEqual((Status['error_code'], Status['row_kind']), (24381, 2))
        [Error] = Status['batch_errors']
        self.assertEqual((Error['offset'], Error['code']), (1, 1))
        self.assertTrue(Error['message'].startswith('ORA-00001'))
        self.assertTrue(Status['message'].startswith('ORA-24381'))

    def test_a_failing_batch_reports_the_row_it_stopped_at(self):
        Seq = iter(range(10, 99))
        Dialect = Oci11Dialect(lambda: next(Seq))
        (_, Result) = _drive(
            Dialect.execute_dml('insert into t values (:1)', [6], [[1], [7]]),
            [_capture('oci11_array_dml_error_reply.hexdump')],
        )
        self.assertEqual(Result[1], 1)  # ORA-00001
        self.assertEqual(Result[3][0], 1)  # one row applied
        self.assertEqual(Result[9], 1)  # at row 1


class Native11LobTest(_At11g):
    """CLOB and BLOB columns: their locators in the rows, their content read."""

    def _query(self):
        # The describe (no rows with the execute), then the fetch's rows.
        from seerdb.common.tns import decode_oci11_rows

        (Columns, _) = decode_oci11_describe(
            _capture('oci11_lob_describe_reply.hexdump')
        )
        (Rows, Terminal, _) = decode_oci11_rows(
            _capture('oci11_lob_fetch_reply.hexdump'), Columns, None
        )
        return (Columns, Rows, Terminal)

    def test_the_rows_carry_locators(self):
        from seerdb.common.lob import LOB

        (Columns, Rows, Terminal) = self._query()
        self.assertEqual([C['column_name'] for C in Columns], ['ID', 'C', 'B'])
        self.assertEqual(Rows[0][0], 1)
        self.assertIsInstance(Rows[0][1], LOB)
        self.assertEqual(len(Rows[0][1].raw), 122)
        self.assertEqual(len(Rows), 1)  # the next fetch brings (2, NULL, NULL)

    def test_the_read_is_sqlplus_11_2s(self):
        from seerdb.common.tns import encode_oci11_lob_read

        (_, Rows, _) = self._query()
        Captured = _capture('oci11_lob_read.hexdump')
        self.assertEqual(
            encode_oci11_lob_read(Captured[2], Rows[0][1].raw, 1, 100000), Captured
        )

    def test_the_read_replies(self):
        from seerdb.common.tns import decode_oci11_lob_read

        (_, Rows, _) = self._query()
        for Name, Locator, Content in (
            (
                'oci11_lob_read_clob_reply.hexdump',
                Rows[0][1].raw,
                'hello clob'.encode('utf-16-be'),
            ),
            (
                'oci11_lob_read_blob_reply.hexdump',
                Rows[0][2].raw,
                bytes.fromhex('deadbeef'),
            ),
        ):
            with self.subTest(Name):
                (Got, Rest) = decode_oci11_lob_read(_capture(Name), len(Locator))
                self.assertEqual(Got, Content)
                self.assertEqual(decode_oci11_status(Rest)['error_code'], 0)

    def test_the_dialect_reads_a_clob_as_utf_16(self):
        from seerdb.common.types import decode_fv2_lob

        (Columns, Rows, _) = self._query()
        Seq = iter(range(10, 99))
        Dialect = Oci11Dialect(lambda: next(Seq))
        (_, Content) = _drive(
            Dialect.lob_read(Rows[0][1].raw),
            [_capture('oci11_lob_read_clob_reply.hexdump')],
        )
        self.assertEqual(
            decode_fv2_lob(112, Content, Dialect._clob_charset(Columns[1])),
            'hello clob',
        )


class Native11LobCallTest(_At11g):
    """A LOB object's other calls, against an OCI 11.2 program's own."""

    @staticmethod
    def _locator(Captured):
        # The locator the captured call was made on, as it was fetched.
        from seerdb.common.tns import _LOBOPS_READ_FROM_OCI_WIDE

        return bytes(_LOBOPS_READ_FROM_OCI_WIDE(Captured)[0]['locator'])

    def test_the_calls_are_oci_11_2s(self):
        from seerdb.common.tns import encode_oci11_lobop
        from seerdb.common.tns_consts import (
            TNS_LOB_OP_CLOSE,
            TNS_LOB_OP_GET_LENGTH,
            TNS_LOB_OP_IS_OPEN,
            TNS_LOB_OP_OPEN,
            TNS_LOB_OP_TRIM,
            TNS_LOB_OP_WRITE,
        )

        for Name, Operation, Offset, Amount, Data in (
            ('oci11_lobop_get_length.hexdump', TNS_LOB_OP_GET_LENGTH, 0, 0, None),
            ('oci11_lobop_is_open.hexdump', TNS_LOB_OP_IS_OPEN, 0, 0, None),
            ('oci11_lobop_open.hexdump', TNS_LOB_OP_OPEN, 0, 2, None),
            (
                'oci11_lobop_write.hexdump',
                TNS_LOB_OP_WRITE,
                1,
                5,
                'HELLO'.encode('utf-16-be'),
            ),
            ('oci11_lobop_close.hexdump', TNS_LOB_OP_CLOSE, 0, 0, None),
            ('oci11_lobop_trim.hexdump', TNS_LOB_OP_TRIM, 0, 3, None),
        ):
            with self.subTest(Name):
                Captured = _capture(Name)
                self.assertEqual(
                    encode_oci11_lobop(
                        Captured[2],
                        self._locator(Captured),
                        Operation,
                        Offset,
                        Amount,
                        Data,
                    ),
                    Captured,
                )

    def test_the_replies(self):
        from seerdb.common.tns import decode_oci11_lobop
        from seerdb.common.tns_consts import (
            TNS_LOB_OP_CLOSE,
            TNS_LOB_OP_GET_LENGTH,
            TNS_LOB_OP_IS_OPEN,
            TNS_LOB_OP_WRITE,
        )

        Sent = self._locator(_capture('oci11_lobop_write.hexdump'))
        for Name, Operation, Value in (
            ('oci11_lobop_get_length_reply.hexdump', TNS_LOB_OP_GET_LENGTH, 10),
            ('oci11_lobop_is_open_reply.hexdump', TNS_LOB_OP_IS_OPEN, 1),
            ('oci11_lobop_write_reply.hexdump', TNS_LOB_OP_WRITE, 5),
            ('oci11_lobop_close_reply.hexdump', TNS_LOB_OP_CLOSE, None),
        ):
            with self.subTest(Name):
                (Got, Locator, Rest) = decode_oci11_lobop(_capture(Name), Operation)
                self.assertEqual(Got, Value)
                self.assertEqual(len(Locator), len(Sent) - 2)
                self.assertEqual(decode_oci11_status(Rest)['error_code'], 0)
        (_, Written, _) = decode_oci11_lobop(
            _capture('oci11_lobop_write_reply.hexdump'), TNS_LOB_OP_WRITE
        )
        self.assertNotEqual(Written, Sent[2:])  # the write changed it

    def test_the_dialect_returns_the_value_and_the_locator(self):
        from seerdb.common.tns_consts import TNS_LOB_OP_GET_LENGTH

        Locator = self._locator(_capture('oci11_lobop_get_length.hexdump'))
        (Sends, Result) = _drive(
            Oci11Dialect(lambda: 7).lob_operation(Locator, TNS_LOB_OP_GET_LENGTH),
            [_capture('oci11_lobop_get_length_reply.hexdump')],
        )
        self.assertEqual(len(Sends), 1)
        self.assertEqual(Result, (10, Locator[2:]))

    def test_a_failed_call_raises(self):
        from seerdb.common.tns_consts import TNS_LOB_OP_WRITE

        with self.assertRaises(DatabaseError) as Raised:
            _drive(
                Oci11Dialect(lambda: 7).lob_operation(
                    b'\x00\x02ab', TNS_LOB_OP_WRITE, 1, 1, b'\x00x'
                ),
                [_capture('oci11_lobop_not_locked_reply.hexdump')],
            )
        self.assertEqual(Raised.exception.code, 22920)

    def test_an_unmeasured_call_is_refused(self):
        from seerdb.common.tns_consts import TNS_LOB_OP_FILE_OPEN

        Dialect = Oci11Dialect(lambda: 1)
        with self.assertRaises(NotSupportedError):
            _drive(Dialect.lob_operation(b'x', TNS_LOB_OP_FILE_OPEN), [])

    def test_a_write_counts_utf_16_code_units(self):
        # A character past the BMP is two of them; counted as one, the pooled
        # server process died (ORA-03137).
        from seerdb.client._conn_logic import fv2_lob_payload
        from seerdb.common.tns_consts import AL16UTF16_CHARSET

        self.assertEqual(
            fv2_lob_payload('\U0001f600!', False, AL16UTF16_CHARSET),
            ('\U0001f600!'.encode('utf-16-be'), 3),
        )


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
        from seerdb import DB_TYPE_CLOB, DB_TYPE_CURSOR
        from seerdb.common.datatypes import Var

        for Call in (
            lambda: self.dialect.execute_block(
                'begin open :1 for select 1 from dual; end;', [Var(DB_TYPE_CURSOR)]
            ),
            lambda: self.dialect.execute_query(
                'select :1 from dual', [Var(DB_TYPE_CLOB)], 15
            ),
            lambda: self.dialect.bfile_read(b''),
        ):
            with self.assertRaises(NotSupportedError):
                _drive(Call(), [])

    def test_a_block_reads_its_out_values(self):
        from seerdb import DB_TYPE_BINARY_DOUBLE, DB_TYPE_NUMBER, DB_TYPE_VARCHAR
        from seerdb.common.datatypes import Var

        Binds = [Var(DB_TYPE_NUMBER, 22), Var(DB_TYPE_VARCHAR, 20)]
        Binds[0].setvalue(0, 42)
        Binds[1].setvalue(0, 'hello')
        Binds.append(Var(DB_TYPE_BINARY_DOUBLE, 8))
        (_, Result) = _drive(
            self.dialect.execute_block(
                'begin :n := :n * 2; :s := upper(:s); :d := 1.5; end;', Binds
            ),
            [_capture('oci11_block_out_reply.hexdump')],
        )
        Record = Result[4][0]
        self.assertEqual(Record['directions'], [0x30, 0x30, 0x10])
        self.assertEqual(Record['out_positions'], [0, 1, 2])
        self.assertEqual(Record['out_values'][1], b'HELLO')

    def test_a_first_block_tells_the_pooled_session(self):
        (_, Result) = _drive(
            self.dialect.execute_block('begin :n := 42; end;', [None] * 4),
            [_capture('oci11_block_first_reply.hexdump')],
        )
        self.assertEqual(len(self.sessions), 1)
        self.assertIsNone(Result[4][0]['out_values'][3])  # the NULL

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
        self.assertIn(CAP_BLOCK, Caps)
        self.assertIn(CAP_ARRAY_DML, Caps)


if __name__ == '__main__':
    unittest.main()
