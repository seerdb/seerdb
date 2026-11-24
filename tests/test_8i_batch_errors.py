# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""An 8i batch-errors execute of one row reports its failure (#2799).

8i has no array DML, so an executemany runs there only with one row, as the
execute's bind. With batcherrors that row's error is a batch error at offset 0
under ORA-24381, as 9i and 10g+ report it, not a raise.
"""

import unittest

from seerdb.client.dialect import RECV, O8iDialect, Send
from seerdb.common.exceptions import IntegrityError
from seerdb.common.tns_consts import ORA_ARRAY_DML_ERRORS

# 8.1.7's reply to `INSERT INTO seerdb_cap2799 VALUES (1)` with the key there
# already: ORA-00001 (captured live, as the 8i DML path reads it).
DUPLICATE_KEY = bytes.fromhex(
    '040000000001000000000000000000020000000000ffffffff0000000000000000000000'
    '0000000a00000000000000000000000000000000000000003c4f52412d30303030313a20'
    '756e6971756520636f6e73747261696e74202853595354454d2e5359535f433030313332'
    '3536292076696f6c617465640a'
)
SQL = 'INSERT INTO seerdb_cap2799 VALUES (:1)'


def _drive(gen, reply):
    # Run a dialect generator to its result, answering its one read.
    step = next(gen)
    try:
        while True:
            if isinstance(step, Send):
                step = gen.send(None)
            else:
                assert step is RECV
                step = gen.send((6, reply))
    except StopIteration as done:
        return done.value


class TestThe8iBatchOfOneRow(unittest.TestCase):
    def test_its_failure_is_a_batch_error_at_offset_0(self):
        result = _drive(
            O8iDialect(next_seq=lambda: 1).execute_dml(SQL, [1], batcherrors=True),
            DUPLICATE_KEY,
        )
        self.assertEqual(result[1], ORA_ARRAY_DML_ERRORS)
        (error,) = result[7]
        self.assertEqual((error['offset'], error['code']), (0, 1))
        self.assertTrue(error['message'].startswith('ORA-00001'))

    def test_without_batcherrors_it_raises(self):
        with self.assertRaises(IntegrityError) as ctx:
            _drive(O8iDialect(next_seq=lambda: 1).execute_dml(SQL, [1]), DUPLICATE_KEY)
        self.assertEqual(ctx.exception.code, 1)


if __name__ == '__main__':
    unittest.main()
