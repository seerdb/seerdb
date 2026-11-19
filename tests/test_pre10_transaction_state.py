# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""Whether a transaction is open, as 8i's and 9i's native replies say it
(PROTOCOL.md §19.12, SeerODBC #344).

8.1.7's status has no call status: bit 0x40 of its `flags` is set while no
transaction is open. 9.2's native form has 10g's call status, whose 0x02 is
TXN_IN_PROGRESS. The codec records either as a call status, which
`transaction_in_progress` reads.
"""

import unittest

from seerdb.common.tns import (
    decode_8i_dml_response,
    decode_9i_oall8_dml_response,
    recording_session_keywords,
)
from seerdb.common.tns_consts import TNS_EOCS_FLAGS_TXN_IN_PROGRESS

# Captured 2026-11-19 from 8.1.7: an INSERT's reply (flags 0x00) and a
# COMMIT's (flags 0x40), each an RPA and the status.
_8I_INSERT = bytes.fromhex(
    '0804007e862e000000000001000000010000000000000004010000000000000000000100'
    '0c00020000000000da8c0300050000ff000000000000000000000b0000010000000d000d'
    '0100038cda0005000000ff0000000000000000000000000000'
)
_8I_COMMIT = bytes.fromhex(
    '0804007f862e000000000001000000020000000000000004000000000000000000000100'
    '00002c0040000000da8c0300050000ff0000000000000000000010000001000000000000'
    '0000000000000000000000'
)
# The same from 9.2.0.4 in the native form: call status 2, then 5.
_9I_INSERT = bytes.fromhex(
    '080500cd22bb0200000000010000000100000000000000000000000402000000010100'
    '000000000000000001000c000200000000003694060001000000dab800000000000000'
    '000000000c0000010000003601000000000000000000000000000080d0d40300000000'
    '0d00000000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000d000d0100069436000100'
    '00b8da0000'
)
_9I_COMMIT = bytes.fromhex(
    '080500ce22bb0200000000020000000200000000000000000000000405000000010000'
    '0000000000000000020000002c00000000003694060001000000dab800000000000000'
    '0000000000100000010000003601000000000000000000000000000080d0d403000000'
    '0000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000'
)


def _recorded(decode, reply) -> list[int]:
    status: list[int] = []
    with recording_session_keywords({}, status):
        decode(reply)
    return status


class TransactionStateBefore10g(unittest.TestCase):
    def test_8i_status_flags_say_whether_a_transaction_is_open(self):
        self.assertEqual(
            _recorded(decode_8i_dml_response, _8I_INSERT),
            [TNS_EOCS_FLAGS_TXN_IN_PROGRESS, 0],
        )
        self.assertEqual(_recorded(decode_8i_dml_response, _8I_COMMIT), [0, 0])

    def test_9i_native_call_status_says_whether_a_transaction_is_open(self):
        self.assertEqual(_recorded(decode_9i_oall8_dml_response, _9I_INSERT), [2, 0])
        self.assertEqual(_recorded(decode_9i_oall8_dml_response, _9I_COMMIT), [5, 0])


if __name__ == '__main__':
    unittest.main()
