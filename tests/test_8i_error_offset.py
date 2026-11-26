# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""DatabaseError.offset on 8i (#2804): 8.1.7's status carries where in the
statement an error is, in its position, as OCI 9.2 reads it. Read from 8.1.7's
reply to OCI 9.2, captured on the 9i VM."""

import os
import sys
import unittest

import seerdb
from seerdb.client.dialect import RECV, O8iDialect, Send
from seerdb.common.tns import decode_8i_error_position, decode_8i_terminal_error

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402

_REPLY = 'oci92_error_offset_reply_8i.hexdump'


class TestTheErrorOffset(unittest.TestCase):
    def test_the_status_says_where(self):
        reply = bytes(load_capture(_REPLY))
        self.assertEqual(decode_8i_terminal_error(reply)[0], 942)
        self.assertEqual(decode_8i_error_position(reply), 14)

    def test_a_refused_query_raises_with_it(self):
        gen = O8iDialect(lambda: 1).execute_query('SELECT 1 FROM nosuchtable')
        self.assertIsInstance(next(gen), Send)
        self.assertIs(gen.send(None), RECV)
        with self.assertRaises(seerdb.DatabaseError) as ctx:
            gen.send((None, bytes(load_capture(_REPLY))))
        self.assertEqual((ctx.exception.code, ctx.exception.offset), (942, 14))


if __name__ == '__main__':
    unittest.main()
