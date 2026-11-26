# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""cursor.warning on 8i (#2804): a CREATE whose object compiles with errors
succeeds, and only its status's warning flags say otherwise -- 0x21 on 8.1.7,
as on 9.2. Read from 8.1.7's replies to OCI 9.2, captured on the 9i VM."""

import os
import sys
import unittest

from seerdb.client.dialect import RECV, O8iDialect, Send
from seerdb.common.tns import decode_8i_warn_flags
from seerdb.common.tns_consts import TNS_OER_WARN_COMPILATION_ERROR

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402


def _capture(name: str) -> bytes:
    return bytes(load_capture(name))


class TestTheWarningFlags(unittest.TestCase):
    def test_a_broken_procedure_says_so(self):
        flags = decode_8i_warn_flags(_capture('oci92_create_broken_reply_8i.hexdump'))
        self.assertEqual(flags, 0x21)
        self.assertTrue(flags & TNS_OER_WARN_COMPILATION_ERROR)

    def test_a_clean_one_does_not(self):
        self.assertEqual(
            decode_8i_warn_flags(_capture('oci92_create_clean_reply_8i.hexdump')), 0
        )

    def test_the_dialect_returns_them(self):
        # The result's last field, where 9i's forms put the warning flags.
        gen = O8iDialect(lambda: 1).execute_dml(
            'CREATE OR REPLACE PROCEDURE p AS BEGIN no_such_thing; END;'
        )
        self.assertIsInstance(next(gen), Send)
        self.assertIs(gen.send(None), RECV)
        with self.assertRaises(StopIteration) as done:
            gen.send((None, _capture('oci92_create_broken_reply_8i.hexdump')))
        self.assertEqual(done.exception.value[-1], 0x21)


if __name__ == '__main__':
    unittest.main()
