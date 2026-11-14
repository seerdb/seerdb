# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""An 8i describe that does not fit in one packet (#1226).

8i caps each DATA packet at the SDU with no end-of-message flag, and the 45
columns of V$SESSION describe to more than one packet holds. The client decoded
the first packet alone and ran off its end with an IndexError. A statement that
fails as it executes can also stop the describe partway: 8i sends what fitted in
the first packet, then the error as a TTI_OER of its own, and nothing more.

The packets are captured from a live 8.1.7 server, not built by hand:
`o8i_describe_split_*` from `SELECT * FROM v$session WHERE audsid =
userenv('sessionid')`, and `o8i_describe_cut_*` from the same select list with
`sid = sys_context('userenv', 'sid')`, which 8i refuses with ORA-02003 once it
has started to describe.
"""

import unittest
from pathlib import Path

from seerdb.client.dialect import RECV, O8iDialect
from seerdb.common.exceptions import DatabaseError, OperationalError, Truncated
from seerdb.common.tns import decode_8i_dcb_describe

_FIXTURES = Path(__file__).parent / 'fixtures'


def _packet(name: str) -> bytes:
    return (_FIXTURES / f'o8i_describe_{name}.bin').read_bytes()


class TestAWideDescribe(unittest.TestCase):
    def test_the_first_packet_alone_says_it_is_incomplete(self):
        # Not an IndexError from a slice, and never a short, wrong column list.
        with self.assertRaises(Truncated):
            decode_8i_dcb_describe(_packet('split_1'))

    def test_both_packets_decode_to_every_column(self):
        columns, rest = decode_8i_dcb_describe(_packet('split_1') + _packet('split_2'))
        names = [c['column_name'] for c in columns]
        self.assertEqual(len(names), 45)
        self.assertEqual(names[:4], [b'SADDR', b'SID', b'SERIAL#', b'AUDSID'])
        self.assertTrue(rest)  # the row stream follows

    def test_the_reader_reads_on_until_the_describe_is_whole(self):
        dialect = O8iDialect(next_seq=lambda: 1)
        gen = dialect._recv_describe(_packet('split_1'))
        self.assertIs(next(gen), RECV)
        with self.assertRaises(StopIteration) as done:
            gen.send((6, _packet('split_2')))
        (columns, _rest) = done.exception.value
        self.assertEqual(len(columns), 45)


class TestADescribeCutShortByAnError(unittest.TestCase):
    def test_the_error_is_the_answer(self):
        # Waiting for the rest of the describe hung for the read timeout: the
        # server had said everything it was going to.
        dialect = O8iDialect(next_seq=lambda: 1)
        gen = dialect._recv_describe(_packet('cut_1'))
        self.assertIs(next(gen), RECV)
        with self.assertRaises(DatabaseError) as caught:
            gen.send((6, _packet('cut_oer')))
        self.assertEqual(caught.exception.code, 2003)
        self.assertIn('invalid USERENV parameter', str(caught.exception))

    def test_a_connection_closed_mid_describe_is_reported(self):
        dialect = O8iDialect(next_seq=lambda: 1)
        gen = dialect._recv_describe(_packet('cut_1'))
        next(gen)
        with self.assertRaisesRegex(
            OperationalError, 'closed the connection during 8i describe'
        ):
            gen.send(False)


class TestAColumnOf256BytesOrMore(unittest.TestCase):
    """A column's size is a ub4, little-endian; read as one byte, a
    VARCHAR2(4000) described as 160 (#2324). Captured from seerdb's own
    session on 8.1.7: `SELECT *` of a table of every 8i column type, its
    describe, rows and status (`o8i_describe_wide_columns`)."""

    def _columns(self) -> dict:
        columns, _ = decode_8i_dcb_describe(_packet('wide_columns'))
        return {c['column_name'].decode(): c for c in columns}

    def test_each_size_is_whole(self):
        columns = self._columns()
        for name, size in (('V4000', 4000), ('CL', 4000), ('BL', 4000), ('BF', 530)):
            self.assertEqual(columns[name]['data_length'], size, name)
        self.assertEqual(columns['V']['data_length'], 10)

    def test_the_description_says_it(self):
        from seerdb.client.cursor import _column_description

        description = _column_description(self._columns()['V4000'])
        self.assertEqual(description[2:4], (4000, 4000))

    def test_a_number_keeps_its_precision_and_scale(self):
        columns = self._columns()
        self.assertEqual(
            [
                (columns[n]['precision'], columns[n]['data_scale'])
                for n in ('N62', 'NNEG', 'F')
            ],
            [(6, 2), (5, -2), (126, -127)],
        )
        self.assertEqual(columns['N62']['null_ok'], 0)

    def test_the_rows_follow_it(self):
        _, rest = decode_8i_dcb_describe(_packet('wide_columns'))
        self.assertEqual(rest[:1], b'\x06')  # TTI_RXH

    def test_each_column_reports_what_10g_does(self):
        # cursor.description's sizes as python-oracledb reports them (#2326):
        # the buffer stood in for the declared size, which the describe does
        # not send, so a DATE and a ROWID reported 1 and a LOB 4000.
        from seerdb.client.cursor import _column_description

        columns = self._columns()
        self.assertEqual(
            {
                n: _column_description(columns[n])[2:4]
                for n in ('D', 'RI', 'CL', 'BL', 'BF', 'N62', 'NC', 'R')
            },
            {
                'D': (23, None),
                'RI': (None, None),
                'CL': (None, None),
                'BL': (None, None),
                'BF': (None, None),
                'N62': (10, None),
                'NC': (4, 4),
                'R': (16, 16),
            },
        )


if __name__ == '__main__':
    unittest.main()
