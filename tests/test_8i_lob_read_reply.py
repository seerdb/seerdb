# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""An 8i LOB read is read on to its status (#2850). 8.1.7's READ reply is the
content's chunks, the RPA and the 8i status, split into packets at no fixed
point; a read that returned at the chunks' end left the rest for the next call
to misread. Checked against 8.1.7's reply to OCI 9.2's READ of a temporary
CLOB, captured with tcpdump."""

import os
import sys
import unittest

from seerdb.client.dialect import RECV, O8iDialect, Send
from seerdb.common.tns import decode_8i_lob_read
from seerdb.common.tns_consts import TNS_DATA

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402

_REPLY = 'oracle8i_lob_read_reply.hexdump'


class TestTheReplyIsWholeAtItsStatus(unittest.TestCase):
    def test_only_the_whole_reply_is_complete(self):
        reply = load_capture(_REPLY)
        for cut in range(1, len(reply)):
            with self.subTest(cut=cut):
                self.assertIsNone(decode_8i_lob_read(reply[:cut])[1])
        (content, status) = decode_8i_lob_read(reply)
        self.assertEqual(content, b'temporary text')
        self.assertEqual(status[:1], b'\x04')


class TestTheReadReadsOn(unittest.TestCase):
    def test_a_read_split_after_its_chunks_waits_for_the_status(self):
        # Split at every point, the read asks for the second packet and returns
        # the content only once it has it.
        reply = load_capture(_REPLY)
        for cut in range(1, len(reply)):
            with self.subTest(cut=cut):
                gen = O8iDialect(lambda: 1).lob_read(b'\x00\x54' + bytes(84))
                self.assertIsInstance(next(gen), Send)
                self.assertIs(next(gen), RECV)
                self.assertIs(gen.send((TNS_DATA, reply[:cut])), RECV)
                with self.assertRaises(StopIteration) as done:
                    gen.send((TNS_DATA, reply[cut:]))
                self.assertEqual(done.exception.value, 'temporary text'.encode())


if __name__ == '__main__':
    unittest.main()
