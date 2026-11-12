# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""When the 8i row reader reads on, and when it lets an error through (#1061).

8i caps each DATA packet at the SDU with no end-of-message flag, so a message
larger than one packet arrives with nothing saying more is coming (#377). The
reader therefore decodes what it has and, if a field runs off the end, asks for
the next packet. That is only right for a field that RAN OFF THE END.

It used to catch the whole DataError family as "read on". A value that is
complete but does not decode -- a BC date, valid Oracle data that no Python
datetime can hold -- raised a DataError too, so the reader asked for a packet
that was never coming and the fetch hung for the full read timeout.

These drive the reader's generator with the decoder stubbed to raise each kind
of exception, so they test the reader's policy rather than a hand-built frame
(which would only encode the assumption under test). The live test in
test_integration exercises the real bytes on 8i.
"""

import unittest
from unittest import mock

from seerdb.client.dialect import RECV, Fv2Oall8Dialect, O8iDialect, Send
from seerdb.common.exceptions import (
    DataError,
    DateOutOfRangeError,
    NotSupportedError,
    Truncated,
)
from seerdb.common.tns import decode_8i_dcb_describe


def _start(side_effect):
    # A recv_rows generator whose decoder raises `side_effect`, primed up to its
    # first yield. Returns the generator and what it yielded.
    dialect = O8iDialect(next_seq=lambda: 1)
    patch = mock.patch(
        'seerdb.client.dialect.decode_8i_exec_response', side_effect=side_effect
    )
    patch.start()
    gen = dialect.recv_rows(b'partial', [], None)
    try:
        return gen, next(gen), patch
    except BaseException:
        patch.stop()
        raise


class TestReadOnOnlyForTruncation(unittest.TestCase):
    def test_a_truncated_field_reads_on(self):
        # Genuinely incomplete: ask for the next packet.
        gen, first, patch = _start(Truncated('ran off the end'))
        try:
            self.assertIs(first, RECV)
        finally:
            patch.stop()

    def test_an_index_error_from_an_older_primitive_reads_on(self):
        gen, first, patch = _start(IndexError('index out of range'))
        try:
            self.assertIs(first, RECV)
        finally:
            patch.stop()

    def test_a_complete_but_undecodable_value_raises_instead_of_waiting(self):
        # The #1061 case. Used to yield RECV here and wait for the read timeout.
        with self.assertRaises(DateOutOfRangeError):
            _start(DateOutOfRangeError('year -4712 is out of range'))

    def test_any_other_data_error_raises_too(self):
        # Not only dates: a corrupt value in a complete message is an error to
        # report, not a sign that more bytes are on the way.
        with self.assertRaises(DataError) as caught:
            _start(DataError('malformed Oracle NUMBER'))
        self.assertNotIsInstance(caught.exception, Truncated)

    def test_a_connection_closed_on_a_truncated_message_returns_no_rows(self):
        # Nothing more is coming, so a genuinely incomplete message has no rows.
        gen, first, patch = _start(Truncated('ran off the end'))
        try:
            self.assertIs(first, RECV)
            with self.assertRaises(StopIteration) as done:
                gen.send(False)  # the connection closed
            self.assertEqual(done.exception.value, ([], b'', None))
        finally:
            patch.stop()

    def test_a_connection_closed_on_a_bad_value_still_raises(self):
        # The first decode reads on (truncated); after the close, the retry finds
        # a complete-but-bad value, which must raise rather than become "no rows".
        errors = [Truncated('short'), DataError('malformed Oracle DATE')]
        gen, first, patch = _start(errors)
        try:
            self.assertIs(first, RECV)
            with self.assertRaises(DataError):
                gen.send(False)
        finally:
            patch.stop()


class TestReadOnUntilTheStatusIsWhole(unittest.TestCase):
    """A reply cut a few bytes short of its status reads on (#2280).

    8i splits a long reply into packets at no fixed point. Fetching a 50 000-byte
    LONG RAW, it once sent all but the last 3 bytes, then those 3 (`00 00 00`)
    in a packet of their own. The status ends in zero fields, so the short reply
    decoded cleanly: the reader stopped, the 3 bytes answered the next fetch, and
    that fetch's ORA-01403 answered the DROP after it. Replies captured on 8.1.7.
    """

    # SELECT CAST('X' AS VARCHAR2(1)), CAST(N'Y' AS NVARCHAR2(1)), ... : the
    # describe, one row, then the RPA and the 60-byte status.
    REPLY = bytes.fromhex(
        '1019c3bff959d084a5050000787e0a180c320f395c020000000000060000000300000033'
        '018000000100000000000000000000000000000000001f00010116160000001643415354'
        '282758274153564152434841523228312929000000000000000001800000010000000000'
        '0000000000000000000000001f00020118180000001843415354284e27592741534e5641'
        '524348415232283129290000000000000000608000000400000000000000000000000000'
        '000000001f0002010101000000014300000000000000000700000007787e0a180c321506'
        '020300000001000000000000000000000007015800000000015900000000046162202000'
        '0000000804002ca01d000000000001000000010000000000000004010000000000000000'
        '000100000003004000000000000000000000000000000000000000000007000001000000'
        '0000000000000000000000000000'
    )
    # An INSERT's status: its OER carries the row's 13-byte rowid.
    INSERTED = bytes.fromhex(
        '08040035a01d000000000003000000010000000000000004010000000000000000000300'
        '0c00020000000000272d02000500001501000001000000000000090000010000000d000d'
        '0100022d270005000001150001000000000000000000000000'
    )
    # The end of a fetch: ORA-01403 and its message, with no RPA before it.
    NO_DATA = bytes.fromhex(
        '04010000007b050000000001000000030040000000000000000000000000000000000000'
        '000000080000010000000000000000000000000000000000194f52412d30313430333a20'
        '6e6f206461746120666f756e640a'
    )

    def _rows(self):
        from seerdb.common.tns import decode_8i_dcb_describe

        return decode_8i_dcb_describe(self.REPLY)

    def test_each_status_is_whole_and_not_a_byte_short(self):
        from seerdb.common.tns import decode_8i_exec_response, o8i_terminal_complete

        (columns, rows) = self._rows()
        (_, terminal, _) = decode_8i_exec_response(rows, columns)
        for status in (terminal, self.INSERTED, self.NO_DATA):
            self.assertTrue(o8i_terminal_complete(status), status.hex())
            for short in range(1, len(status)):
                self.assertFalse(o8i_terminal_complete(status[:-short]), short)

    def test_a_reply_three_bytes_short_waits_for_the_rest(self):
        (columns, rows) = self._rows()
        gen = O8iDialect(next_seq=lambda: 1).recv_rows(rows[:-3], columns, None)
        # Before the fix the short reply returned here, three bytes unread.
        self.assertIs(next(gen), RECV)
        with self.assertRaises(StopIteration) as done:
            gen.send((6, rows[-3:]))
        (got, terminal, _) = done.exception.value
        self.assertEqual(got, [['X', 'Y', 'ab  ']])
        self.assertEqual(len(terminal), 83)

    def test_a_whole_reply_reads_no_further(self):
        (columns, rows) = self._rows()
        with self.assertRaises(StopIteration) as done:
            next(O8iDialect(next_seq=lambda: 1).recv_rows(rows, columns, None))
        self.assertEqual(done.exception.value[0], [['X', 'Y', 'ab  ']])


class TestAQueryEndsOnItsFetchStatus(unittest.TestCase):
    """An 8i query reads each fetch's status (#2314). A fetch that fails brings
    no rows and the error in its status; ending on the empty fetch alone
    returned the rows before it as the whole result. A fetch ended with
    ORA-01403 is the last: one more draws ORA-01002. Statuses captured on
    8.1.7: `SELECT rownum FROM all_objects WHERE rownum <= 5` and a query whose
    third row divides by zero."""

    # The query's reply: one row, then the RPA and a status with no error.
    FIRST = bytes.fromhex(
        '08040098161f0000000000010000000000000000000000040100000000000000'
        '0000010000000300400000000000000000000000000000000000000000000600'
        '00010000000000000000000000000000000000'
    )
    # A fetch's last rows and ORA-01403 with its message.
    ENDED = bytes.fromhex(
        '04050000007b0500000000010000000300600000090000000000000000000000'
        '00000000000000070000010000000000000000000000000000000000194f5241'
        '2d30313430333a206e6f206461746120666f756e640a'
    )
    # A fetch that failed: no rows, ORA-01476 (`c4 05`) and its message.
    FAILED = bytes.fromhex(
        '0402000000c40500000000010008000300400000090000000000000000000000'
        '00000000000000070000010000000000000000000000000000000000244f5241'
        '2d30313437363a2064697669736f7220697320657175616c20746f207a65726f'
        '0a'
    )

    def test_the_status_says_the_error(self):
        from seerdb.common.tns import decode_8i_terminal_error

        self.assertEqual(decode_8i_terminal_error(self.FIRST), (0, None))
        self.assertEqual(
            decode_8i_terminal_error(self.ENDED), (1403, 'ORA-01403: no data found')
        )
        self.assertEqual(
            decode_8i_terminal_error(self.FAILED),
            (1476, 'ORA-01476: divisor is equal to zero'),
        )

    def _query(self, replies):
        # Run execute_query over `replies`, (rows, status) per reply, the
        # describe stubbed; returns how many calls it sent and its result.
        dialect = O8iDialect(next_seq=lambda: 1)
        it = iter(replies)

        def describe(packet):
            return ([{'data_type': 2}], b'')
            yield

        def recv_rows(buf, columns, last_row):
            (rows, status) = next(it)
            return (rows, status, None)
            yield

        sent = 0
        with (
            mock.patch.object(dialect, '_recv_describe', describe),
            mock.patch.object(dialect, 'recv_rows', recv_rows),
        ):
            gen = dialect.execute_query('SELECT ...')
            reply = None
            try:
                while True:
                    intent = gen.send(reply)
                    reply = (6, b'\x10') if intent is RECV else None
                    sent += intent is not RECV
            except StopIteration as done:
                return (sent, done.value)

    def test_a_failed_fetch_raises_its_error(self):
        from seerdb.common.exceptions import DatabaseError

        with self.assertRaises(DatabaseError) as raised:
            self._query([([[1]], self.FIRST), ([], self.FAILED)])
        self.assertEqual(str(raised.exception), 'ORA-01476: divisor is equal to zero')

    def test_a_fetch_ended_with_01403_is_the_last(self):
        (sent, result) = self._query(
            [([[1]], self.FIRST), ([[2], [3], [4], [5]], self.ENDED)]
        )
        self.assertEqual(sent, 2)  # the query and one fetch
        self.assertEqual(result[4], [[1], [2], [3], [4], [5]])


def _load_capture(name):
    # tests/replay.py, which CI's unittest step, importing this module as
    # tests.test_8i_recv_rows, does not have on its path.
    import os
    import sys

    sys.path.insert(0, os.path.dirname(__file__))
    from replay import load_capture

    return load_capture(name)


class TestALongMessageArrivesWhole(unittest.TestCase):
    """8.1.7 writes an error message past 252 bytes in chunks, `fe`, each with
    a ub1 length, `00` (#2322). Read as one ub1 length, a fetch's error was its
    first 254 bytes behind a stray `ÿ`, and its status counted as whole well
    before its end; a block's kept the second chunk's length, a `²`, in its
    text. Both replies captured from seerdb's own session on 8.1.7."""

    FETCH = 'o8i_fetch_error_long_message.hexdump'
    BLOCK = 'o8i_block_error_long_message.hexdump'

    def test_a_failed_fetch_has_its_whole_message(self):
        from seerdb.common.tns import decode_8i_terminal_error

        (code, message) = decode_8i_terminal_error(_load_capture(self.FETCH))
        self.assertEqual(code, 20003)
        self.assertEqual(len(message), 475)
        self.assertTrue(message.startswith('ORA-20003: mxxx'), message[:16])
        self.assertTrue(message.isascii())
        self.assertTrue(message.endswith('ORA-06512: at line 1'), message[-24:])

    def test_its_status_is_whole_only_at_its_end(self):
        from seerdb.common.tns import o8i_terminal_complete

        status = _load_capture(self.FETCH)
        self.assertTrue(o8i_terminal_complete(status))
        for short in range(1, len(status)):
            self.assertFalse(o8i_terminal_complete(status[:-short]), short)

    def test_a_failed_block_has_its_whole_message(self):
        from seerdb.common.tns import decode_8i_dml_response

        (rows, code, message) = decode_8i_dml_response(_load_capture(self.BLOCK))
        self.assertEqual((rows, code), (0, 20001))
        self.assertEqual(len(message), 432)
        self.assertTrue(message.isascii())
        self.assertTrue(message.endswith('ORA-06512: at line 1'), message[-24:])


class TestANullUrowid(unittest.TestCase):
    """An 8i UROWID cell is a ub2 length and the logical rowid, then the
    trailer every cell has; a NULL one is a zero length (#2328). Read as one
    byte, its second byte was taken for the status, the row after it was
    lost, and the next fetch failed with ORA-01002. The fetch is captured from
    seerdb's own session on 8.1.7."""

    COLUMNS = [
        {'data_type': 2, 'charset': 0, 'csfrm': 0, 'column_name': b'K'},
        {'data_type': 208, 'charset': 0, 'csfrm': 0, 'column_name': b'R'},
    ]

    def test_the_rows_around_it_are_read(self):
        from seerdb.common.tns import decode_8i_exec_response, decode_8i_terminal_error

        (rows, status, last) = decode_8i_exec_response(
            _load_capture('o8i_rows_null_urowid.hexdump'), self.COLUMNS, [1, None]
        )
        self.assertEqual(rows, [[2, None], [3, '*BAFAAMcCwQT+']])
        self.assertEqual(decode_8i_terminal_error(status)[0], 1403)
        self.assertEqual(last, [3, '*BAFAAMcCwQT+'])


class TestABlockReplyReadsOn(unittest.TestCase):
    """An 8i block's reply comes in as many packets as its OUT values need,
    none marked last (#2334). Read alone, the first packet of a 4000-character
    OUT value ran off its end, and the rest answered the next call. The reply
    is captured from seerdb's own session on 8.1.7, split where 8.1.7 split
    it."""

    def _run(self, packets):
        # Drive execute_block over `packets`; how many it read, and its result.
        from seerdb.common.datatypes import Var

        dialect = O8iDialect(next_seq=lambda: 1)
        gen = dialect.execute_block(
            "BEGIN :1 := RPAD('o', 4000, 'p'); END;", [Var(str, 4000)]
        )
        intent = next(gen)
        read = 0
        try:
            while True:
                if intent is RECV:
                    read += 1
                    intent = gen.send((6, packets[read - 1]))
                else:
                    intent = gen.send(None)
        except StopIteration as done:
            return (read, done.value)

    def test_a_long_out_value_is_read_from_every_packet(self):
        reply = _load_capture('o8i_block_out_4000.hexdump')
        packets = [reply[:2009], reply[2009:4018], reply[4018:]]
        (read, result) = self._run(packets)
        self.assertEqual(read, 3)
        (record,) = result[4]
        self.assertEqual(record['out_values'], [b'o' + b'p' * 3999])

    def test_a_whole_reply_reads_no_further(self):
        (read, result) = self._run([_load_capture('o8i_block_out_4000.hexdump')])
        self.assertEqual(read, 1)
        self.assertEqual(result[4][0]['out_values'], [b'o' + b'p' * 3999])

    def test_the_reply_is_whole_only_at_its_end(self):
        from seerdb.common.tns import o8i_block_complete

        reply = _load_capture('o8i_block_out_4000.hexdump')
        self.assertTrue(o8i_block_complete(reply))
        for cut in (1, 18, 19, 21, 2009, 4018, len(reply) - 1):
            self.assertFalse(o8i_block_complete(reply[:cut]), cut)


# The describes 8.1.7 answered `SELECT BITAND(7, 2) AS b FROM dual` and
# `SELECT 5 AS b FROM dual` with, captured live (#2584), past the packet header.
_BITAND_DESCRIBE = bytes.fromhex(
    '10198046a3ad1c23fb040000787e0b0c14370d203e0200000000000000000001'
    '000000331d000000000000000000000000000000000000000000000000010101'
    '000000014200000000000000000700000007787e0b0c14372b080400f49d2700'
    '00000000010000000000000000000000040000000000000000000001001e0003'
    '0040000000000000000000000000000000000000000000060000010000000000'
    '000000000000000000000000'
)
_NUMBER_DESCRIBE = bytes.fromhex(
    '101998097fcc68160f050000787e0b0c14372c223e0200000000000200000001'
    '0000003302000000020000000000000000000000000000000000000000010101'
    '000000014200000000000000000700000007787e0b0c14372c06020100000001'
    '00000000000000000000000702c10600000000080400f49d2700000000000100'
    '0000000000000000000004010000000000000000000100130003004000000000'
    '0000000000000000000000000000000000060000010000000000000000000000'
    '000000000000'
)


class TestAColumnNoClientFetches(unittest.TestCase):
    # 8i describes SQL's BITAND as type 29, which its own sqlplus is refused
    # (ORA-00932); fetching it was an ORA-00600 [kpodfl1] in the server
    # process (#2584). The fetch is refused before anything is sent.
    def test_bitand_is_refused_before_the_fetch(self):
        (columns, _rest) = decode_8i_dcb_describe(_BITAND_DESCRIBE)
        self.assertEqual(columns[0]['data_type'], 29)
        dialect = O8iDialect(next_seq=lambda: 1)
        fetch = dialect._fetch_rest(1, columns, None)
        with self.assertRaisesRegex(NotSupportedError, 'column B as data type 29'):
            next(fetch)

    def test_a_number_is_fetched(self):
        (columns, _rest) = decode_8i_dcb_describe(_NUMBER_DESCRIBE)
        dialect = O8iDialect(next_seq=lambda: 1)
        self.assertIsInstance(next(dialect._fetch_rest(1, columns, None)), Send)

    def test_only_8i_refuses(self):
        # The 9i OALL8 dialect describes BITAND as a NUMBER; nothing is refused.
        (columns, _rest) = decode_8i_dcb_describe(_BITAND_DESCRIBE)
        self.assertEqual(Fv2Oall8Dialect(next_seq=lambda: 1)._unfetchable(columns), [])


if __name__ == '__main__':
    unittest.main()
