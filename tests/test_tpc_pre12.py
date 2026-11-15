# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""Two-phase commit before 12c, in thin's form (#2691, PROTOCOL.md §28).

The reference is Oracle's JDBC thin 11.2 driver with native XA, captured on
10.2.0.5 and 9.2.0.4: 10.2's switch has no internal or external name, and
9.2's change of state has no flags. A 9i session that logged on with the XA
names reports its cursor options as a compressed integer, `01 08`.
"""

import unittest

from seerdb.client.connection import Xid
from seerdb.common.tns import (
    FIELD_VERSION_9_2,
    FIELD_VERSION_10_2,
    _o7_status,
    encode_tpc_change_state,
    encode_tpc_switch,
)
from seerdb.common.tns_consts import TNS_TPC_TXN_PREPARE, TNS_TPC_TXN_START

_XID = Xid(0x1234, b'gtrid-seerdb', b'bqual-1')

# JDBC thin's start on 10.2.0.5, byte for byte the same on 9.2.0.4: flags 1
# (new), timeout 60, no names.
_JDBC_START = bytes.fromhex(
    '03670101010000021234010c01070101800101013c01010167747269642d736565726462'
    '627175616c2d310000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000'
)
# JDBC thin's prepare on 10.2.0.5 and on 9.2.0.4, with the context the start's
# reply carried. JDBC's timeout is 60 (`01 3c`), seerdb's 0 (`00`).
_JDBC_PREPARE_10 = bytes.fromhex(
    '03680401030101a8021234010c0107010180013c00010000000000000000003412000000'
    '0000000c00000000000000070000000000000067747269642d736565726462627175616c'
    '2d3100000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000770000000000000067747269642d736565726462627175616c2d31000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000000'
)
_JDBC_PREPARE_9 = bytes.fromhex(
    '03680401030101a8021234010c0107010180013c00010000000000000000341200000000'
    '00000c00000000000000070000000000000067747269642d736565726462627175616c2d'
    '310000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '0000770000000000000067747269642d736565726462627175616c2d3100000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000'
)
_CONTEXT = _JDBC_PREPARE_10[23 : 23 + 168]
# A PL/SQL block's reply on 9.2.0.4, on a session that logged on with the XA
# names: the RPA, then the short status, cursor options `01 08`.
_9I_BLOCK_REPLY = bytes.fromhex(
    '0801020402962c33000401010000000101002f000001080000000000000000000000010100000000'
)


def _with_seerdb_timeout(jdbc: bytes) -> bytes:
    # JDBC's change of state with its timeout, 60, as seerdb's 0.
    at = jdbc.index(bytes.fromhex('01 80 01 3c')) + 2
    return jdbc[:at] + b'\x00' + jdbc[at + 2 :]


class TestTheSwitchBefore11g(unittest.TestCase):
    def test_10g_and_9i_start_as_jdbc_thin_does(self):
        for version in (FIELD_VERSION_10_2, FIELD_VERSION_9_2):
            with self.subTest(version=version):
                got = encode_tpc_switch(
                    1, version, TNS_TPC_TXN_START, _XID, 1, 60, None
                )
                self.assertEqual(got, _JDBC_START)


class TestTheChangeOfStateBefore11g(unittest.TestCase):
    def test_10g_prepares_as_jdbc_thin_does(self):
        got = encode_tpc_change_state(
            4, FIELD_VERSION_10_2, TNS_TPC_TXN_PREPARE, 0, _XID, 0, _CONTEXT
        )
        self.assertEqual(got, _with_seerdb_timeout(_JDBC_PREPARE_10))

    def test_9i_prepares_without_flags(self):
        got = encode_tpc_change_state(
            4, FIELD_VERSION_9_2, TNS_TPC_TXN_PREPARE, 0, _XID, 0, _CONTEXT
        )
        self.assertEqual(got, _with_seerdb_timeout(_JDBC_PREPARE_9))


class TestThe9iStatusOnAnXaSession(unittest.TestCase):
    def test_cursor_options_are_a_compressed_integer(self):
        status = _o7_status(_9I_BLOCK_REPLY)
        assert status is not None
        self.assertEqual(status['cursor_options'], 8)
        self.assertEqual(status['upi_param'], 0)
        self.assertEqual(status['warnings'], 0)
        self.assertEqual(status['code'], 0)


if __name__ == '__main__':
    unittest.main()
