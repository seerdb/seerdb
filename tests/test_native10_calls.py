# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The native form on a 10g server (#2518), offline.

OCI 11.2 speaks its native form to 10g at 10.2's widths: the OALL8 and the LOB
calls narrow, the data-type request without the timezone-file version, and the
replies' describes without uds_flags or the query key. The requests are checked
against OCI 11.2's own, captured on 10.2.0.5; the replies are 10g's, read by the
codec and by the dialect at 10g's field version (10.2).
"""

import os
import sys
import unittest

from seerdb.client.dialect import RECV, Oci11Dialect, Send
from seerdb.common.tns import (
    O8I_STMT_BEGIN,
    O8I_STMT_SELECT,
    TNS_LOB_OP_GET_LENGTH,
    TNS_LOB_OP_WRITE,
    decode_oci11_block,
    decode_oci11_describe,
    decode_oci11_rows,
    decode_oci11_status,
    encode_dty_oci11,
    encode_oci11_close_cursors,
    encode_oci11_create_temp,
    encode_oci11_cursor_fetch,
    encode_oci11_execute,
    encode_oci11_lobop,
    encode_oci11_ping,
    set_decode_field_versions,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    TNS_TYPE_CLOB,
)


def _capture(name):
    # tests/replay.py, which CI's unittest step, importing this module as
    # tests.test_native10_calls, does not have on its path.
    sys.path.insert(0, os.path.dirname(__file__))
    from replay import load_capture

    return load_capture(name)


def _drive(gen, replies):
    """Run a dialect call: answer each receive with the next of ``replies``
    (TTC payloads). Returns (sends, result)."""
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


class _At10g(unittest.TestCase):
    def setUp(self):
        set_decode_field_versions(FIELD_VERSION_10_2, FIELD_VERSION_10_2)
        self.addCleanup(set_decode_field_versions, 6, 6)


class Native10RequestTest(unittest.TestCase):
    """The requests, against OCI 11.2's to 10g."""

    def test_the_data_type_request_has_no_timezone_file_version(self):
        # OCI's but the flag byte (5), which seerdb sends as sqlplus 11.2 does.
        Captured = _capture('oci10_dty.hexdump')
        Mine = encode_dty_oci11(FieldVersion=FIELD_VERSION_10_2)
        self.assertEqual(len(Mine), len(Captured))
        self.assertEqual(Mine[:5] + Mine[6:], Captured[:5] + Captured[6:])
        # To 11g the version is there, four bytes more.
        self.assertEqual(len(encode_dty_oci11()), len(Mine) + 4)

    def test_the_execute_is_oci_11_2s(self):
        Captured = _capture('oci10_execute_query.hexdump')
        Mine = encode_oci11_execute(
            Captured[2],
            b'select 1 from dual',
            O8I_STMT_SELECT,
            1,
            FieldVersion=FIELD_VERSION_10_2,
        )
        self.assertEqual(Mine, Captured)

    def test_the_execute_is_48_bytes_shorter_than_11gs(self):
        # The head's five 8-byte lengths at 4 bytes, and 20 bytes, not 48,
        # between it and the SQL.
        for Type in (O8I_STMT_SELECT, O8I_STMT_BEGIN):
            with self.subTest(Type=Type):
                Eleven = encode_oci11_execute(1, b'x', Type)
                Ten = encode_oci11_execute(
                    1, b'x', Type, FieldVersion=FIELD_VERSION_10_2
                )
                self.assertEqual(len(Eleven) - len(Ten), 48)

    def test_the_cursor_fetch_is_narrow(self):
        Eleven = encode_oci11_cursor_fetch(1, 3, 10, 23)
        Ten = encode_oci11_cursor_fetch(1, 3, 10, 23, FIELD_VERSION_10_2)
        self.assertEqual(len(Eleven) - len(Ten), 48)
        # The head through the cursor is the execute's, narrow.
        self.assertEqual(Ten[:3], Eleven[:3])

    def test_a_lob_length_is_oci_11_2s(self):
        Captured = _capture('oci10_lob_get_length.hexdump')
        Locator = self._locator(Captured)
        Mine = encode_oci11_lobop(
            Captured[2],
            Locator,
            TNS_LOB_OP_GET_LENGTH,
            FieldVersion=FIELD_VERSION_10_2,
        )
        self.assertEqual(Mine, Captured)
        self.assertEqual(
            len(encode_oci11_lobop(Captured[2], Locator, TNS_LOB_OP_GET_LENGTH)),
            len(Captured) + 28,
        )

    def test_a_lob_write_is_oci_11_2s(self):
        from seerdb.common import wire_schema
        from seerdb.common.tns import _OCI, _OCI11_LOBOPS_WRITE

        Captured = _capture('oci10_lob_write.hexdump')
        (Fields, _) = wire_schema.compile_decoder(_OCI11_LOBOPS_WRITE, _OCI)(Captured)
        Mine = encode_oci11_lobop(
            Captured[2],
            bytes(Fields['locator']),
            TNS_LOB_OP_WRITE,
            Fields['source_offset'],
            Fields['amount'],
            bytes(Fields['data']),
            FieldVersion=FIELD_VERSION_10_2,
        )
        self.assertEqual(Mine, Captured)

    def test_a_temporary_clob_is_oci_11_2s(self):
        Captured = _capture('oci10_create_temp_clob.hexdump')
        Mine = encode_oci11_create_temp(
            Captured[2], TNS_TYPE_CLOB, 1, FIELD_VERSION_10_2
        )
        self.assertEqual(Mine, Captured)

    def test_close_and_ping_are_as_to_11g(self):
        Captured = _capture('oci10_close_and_ping.hexdump')
        Mine = encode_oci11_close_cursors(Captured[2], [1]) + encode_oci11_ping(
            Captured[25]
        )
        self.assertEqual(Mine, Captured)

    @staticmethod
    def _locator(Captured):
        from seerdb.common import wire_schema
        from seerdb.common.tns import _LOBOPS_READ, _OCI

        (Fields, _) = wire_schema.compile_decoder(_LOBOPS_READ, _OCI)(Captured)
        return bytes(Fields['locator'])


class Native10ReplyTest(_At10g):
    """10g's replies, read at its field version."""

    def test_a_query_reply_reads(self):
        (Columns, Rest) = decode_oci11_describe(_capture('oci10_query_reply.hexdump'))
        self.assertEqual(
            [(C['column_name'], C['data_type']) for C in Columns], [('1', 2)]
        )
        (Rows, _, _) = decode_oci11_rows(Rest, Columns, None)
        self.assertEqual(Rows, [[1]])

    def test_columns_carry_no_uds_flags(self):
        # With two columns a uds_flags read would run into the next one.
        (Columns, Rest) = decode_oci11_describe(
            _capture('oci10_two_column_reply.hexdump')
        )
        self.assertEqual([C['column_name'] for C in Columns], ['G', 'AVG(N)'])
        (Rows, _, _) = decode_oci11_rows(Rest, Columns, None)
        self.assertEqual([R[0] for R in Rows], [1, 2, 3])
        self.assertIsNone(Rows[2][1])

    def test_the_dialect_reads_a_query_whole(self):
        from decimal import Decimal

        Dialect = Oci11Dialect(lambda: 7, field_version=FIELD_VERSION_10_2)
        (Sends, Result) = _drive(
            Dialect.execute_query('SELECT g, AVG(n) FROM t GROUP BY g ORDER BY g'),
            [_capture('oci10_two_column_reply.hexdump')],
        )
        # One execute at 10.2's widths, the reply's rows whole: ORA-01403 ended
        # the fetch inside it.
        self.assertEqual(
            Sends,
            [
                encode_oci11_execute(
                    7,
                    b'SELECT g, AVG(n) FROM t GROUP BY g ORDER BY g',
                    O8I_STMT_SELECT,
                    15,
                    FieldVersion=FIELD_VERSION_10_2,
                )
            ],
        )
        self.assertEqual(
            Result[4],
            [
                [1, Decimal('12345678901234567890.1285')],
                [2, Decimal('1.66666666666666666666666666666666666667')],
                [3, None],
            ],
        )

    def test_a_ref_cursor_reads(self):
        # An opened cursor's value: its id and its describe, read as a query's.
        (_, Values, Rest, _) = decode_oci11_block(
            _capture('oci10_refcursor_reply.hexdump'), 1, Cursors=frozenset({0})
        )
        ((Cursor, Columns),) = Values
        self.assertEqual(Cursor, 1)
        self.assertEqual([C['column_name'] for C in Columns], ['7'])
        self.assertEqual(decode_oci11_status(Rest)['error_code'], 0)

    def test_an_unopened_ref_cursor_is_none(self):
        (_, Values, Rest, _) = decode_oci11_block(
            _capture('oci10_unopened_refcursor_reply.hexdump'),
            1,
            Cursors=frozenset({0}),
        )
        self.assertEqual(Values, [None])
        self.assertEqual(decode_oci11_status(Rest)['error_code'], 0)

    def test_an_11g_describe_is_unchanged(self):
        # The same codec at 11.2 still reads 11g's describe, uds_flags and all.
        set_decode_field_versions(FIELD_VERSION_11_2, FIELD_VERSION_11_2)
        (Columns, _) = decode_oci11_describe(_capture('oci11_query_reply.hexdump'))
        self.assertEqual(len(Columns), 4)


if __name__ == '__main__':
    unittest.main()
