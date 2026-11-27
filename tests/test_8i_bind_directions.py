# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""cursor.bind_directions on 8i (#2804): 8.1.7's reply to a PL/SQL block
opens with the bind prompt, one mask per bind, as 9i's does (#2264). Read from
8.1.7's reply to OCI 9.2, captured on the 9i VM."""

import os
import sys
import unittest

import seerdb
from seerdb.client.dialect import RECV, O8iDialect, Send
from seerdb.common.datatypes import Var
from seerdb.common.tns import decode_fv2_bind_directions

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402

_REPLY = 'oci92_block_reply_8i.hexdump'
_OUT, _IN = 0x10, 0x20


class TestTheBlocksDirections(unittest.TestCase):
    def test_the_prompt_says_out_then_in(self):
        reply = bytes(load_capture(_REPLY))
        self.assertEqual(decode_fv2_bind_directions(reply, O8i=True), [_OUT, _IN])

    def test_the_dialect_hands_them_to_the_cursor(self):
        out = Var(seerdb.DB_TYPE_VARCHAR, 64)
        gen = O8iDialect(lambda: 1).execute_block(
            "BEGIN :r := 'got ' || :g; END;", [out, 'a value']
        )
        self.assertIsInstance(next(gen), Send)
        self.assertIs(gen.send(None), RECV)
        with self.assertRaises(StopIteration) as done:
            gen.send((None, bytes(load_capture(_REPLY))))
        (record,) = done.exception.value[4]
        self.assertEqual(record['directions'], [_OUT, _IN])
        # The value's bytes, which the cursor decodes.
        self.assertEqual(record['out_values'], [b'got a value'])


if __name__ == '__main__':
    unittest.main()
