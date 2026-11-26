# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The 8i cursor cache (#2804): a reusable DML's cursor stays open and is
re-executed by id, as OCI 9.2 re-executes a prepared statement on 8.1.7.
Checked against OCI 9.2's calls and 8.1.7's replies, captured on the 9i VM."""

import os
import sys
import unittest

from seerdb.client.dialect import RECV, O8iDialect, Send
from seerdb.common.tns import encode_8i_reexecute

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402

_SQL = 'INSERT INTO pyo_reexec_oci (n) VALUES (:1)'


def _capture(name: str) -> bytes:
    return bytes(load_capture(name))


def _execute(dialect, bind, cache, reply):
    # Drive one execute_dml to its end: the request it sends, and its result.
    gen = dialect.execute_dml(_SQL, bind, None, False, cache)
    step = next(gen)
    assert isinstance(step, Send), step
    assert gen.send(None) is RECV
    try:
        gen.send((None, reply))
    except StopIteration as done:
        return (step.data, done.value)
    raise AssertionError('execute_dml did not finish')


class TestTheReexecute(unittest.TestCase):
    def test_it_is_oci_9_2s(self):
        theirs = _capture('oci92_reexecute_8i.hexdump')
        self.assertEqual(encode_8i_reexecute(theirs[2], 1, [2]), theirs)

    def test_the_second_execute_reexecutes_the_cached_cursor(self):
        seq = iter(range(9, 100))
        dialect = O8iDialect(lambda: next(seq))
        cache: dict = {}
        (first, result) = _execute(
            dialect, [1], cache, _capture('oci92_insert_reply_8i.hexdump')
        )
        self.assertEqual(first[1], 0x5E)  # the OALL8 that parses it
        self.assertEqual(list(cache.values()), [1])
        self.assertEqual(result[3][0], 1)
        theirs = _capture('oci92_reexecute_8i.hexdump')
        (again, result) = _execute(
            dialect, [2], cache, _capture('oci92_reexecute_reply_8i.hexdump')
        )
        self.assertEqual(again, encode_8i_reexecute(again[2], 1, [2]))
        self.assertEqual(again[:2] + again[3:], theirs[:2] + theirs[3:])
        self.assertEqual(result[3][0], 1)


if __name__ == '__main__':
    unittest.main()
