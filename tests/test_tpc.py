# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for two-phase commit / XA (#131): the Xid, the switch /
# change-state request encoders, and the response decoders. The full
# begin/prepare/commit/rollback flow is covered live on 21c/23ai.

import unittest

from seerdb.client.connection import Xid, _decode_tpc_context, _decode_tpc_state
from seerdb.common.tns import (
    _ENCODE_FIELD_VERSION,
    encode_tpc_change_state,
    encode_tpc_switch,
)
from seerdb.common.tns_consts import (
    TNS_FUNC_TPC_TXN_CHANGE_STATE,
    TNS_FUNC_TPC_TXN_SWITCH,
    TNS_TPC_TXN_PREPARE,
    TNS_TPC_TXN_START,
    TTI_FUN,
)


class TestXid(unittest.TestCase):
    def test_namedtuple(self):
        x = Xid(100, b'gtrid', b'bqual')
        self.assertEqual((x.format_id, x[1], x[2]), (100, b'gtrid', b'bqual'))


class TestEncode(unittest.TestCase):
    def setUp(self):
        _ENCODE_FIELD_VERSION.set(16)

    def tearDown(self):
        _ENCODE_FIELD_VERSION.set(6)

    def test_switch_header_and_xid_padding(self):
        out = encode_tpc_switch(
            5, 16, TNS_TPC_TXN_START, Xid(100, b'gtrid', b'bqual'), 1, 0, None
        )
        self.assertEqual(out[0], TTI_FUN)
        self.assertEqual(out[1], TNS_FUNC_TPC_TXN_SWITCH)  # 103
        # the xid (gtrid+bqual) zero-padded to 128 bytes is present
        self.assertIn(b'gtridbqual' + bytes(128 - 10), out)

    def test_change_state_header(self):
        out = encode_tpc_change_state(
            6, 16, TNS_TPC_TXN_PREPARE, 0, Xid(100, b'g', b'b'), 0, b'ctx'
        )
        self.assertEqual(out[0], TTI_FUN)
        self.assertEqual(out[1], TNS_FUNC_TPC_TXN_CHANGE_STATE)  # 104
        self.assertIn(b'ctx', out)  # context replayed


class TestDecode(unittest.TestCase):
    # Shape of a live tpc_begin response (21c/11g identical): RPA token (08),
    # application value (ub4 0), context length (ub2 0xa8 = 168), 168 context
    # bytes (carrying the xid "g1b1"), then the STATUS tail.
    _CTX = bytes(32) + b'g1b1' + bytes(168 - 36)
    _BEGIN = bytes([0x08, 0x00, 0x01, 0xA8]) + _CTX + bytes.fromhex('0901030104')

    def test_decode_context(self):
        ctx = _decode_tpc_context(self._BEGIN)
        self.assertEqual(len(ctx), 168)
        self.assertIn(b'g1b1', ctx)

    def test_decode_state(self):
        # RPA (08) + ub4 state. State 1 -> "01 01".
        self.assertEqual(_decode_tpc_state(bytes.fromhex('080101')), 1)
        self.assertEqual(_decode_tpc_state(bytes.fromhex('080104')), 4)


if __name__ == '__main__':
    unittest.main()


class _FakeCursor:
    # What tpc_recover reads, without a server: the SQL it ran, and the rows
    # DBA_PENDING_TRANSACTIONS would give.
    def __init__(self, rows):
        self.rows = rows
        self.sql = None
        self.closed = False

    def execute(self, sql):
        self.sql = sql

    def fetchall(self):
        return self.rows

    def close(self):
        self.closed = True


class _AsyncFakeCursor(_FakeCursor):
    async def execute(self, sql):
        self.sql = sql

    async def fetchall(self):
        return self.rows

    async def close(self):
        self.closed = True


_PENDING = [(4242, b'seerdb-a', b'1'), (4242, b'seerdb-b', b'2')]


class TestRecoverAndForget(unittest.TestCase):
    # tpc_recover and tpc_forget (#2457), sync and async.

    def _conn(self, cls):
        return cls(host='db', port=1521, service_name='S')

    def test_recover_reads_the_pending_branches_as_xids(self):
        from seerdb.client.connection import OracleConnect

        conn = self._conn(OracleConnect)
        cursor = _FakeCursor(_PENDING)
        conn.cursor = lambda: cursor
        self.assertEqual(conn.tpc_recover(), [Xid(*row) for row in _PENDING])
        self.assertEqual(
            cursor.sql,
            'SELECT formatid, globalid, branchid FROM dba_pending_transactions',
        )
        self.assertTrue(cursor.closed)

    def test_async_recover_reads_them_too(self):
        import asyncio

        from seerdb.client.aconnection import AsyncOracleConnect

        conn = self._conn(AsyncOracleConnect)
        cursor = _AsyncFakeCursor(_PENDING)
        conn.cursor = lambda: cursor
        self.assertEqual(
            asyncio.run(conn.tpc_recover()), [Xid(*row) for row in _PENDING]
        )
        self.assertTrue(cursor.closed)

    def test_forget_is_refused_as_python_oracledb_thin_refuses_it(self):
        from seerdb.client.aconnection import AsyncOracleConnect
        from seerdb.client.connection import OracleConnect
        from seerdb.common.exceptions import NotSupportedError

        for cls in (OracleConnect, AsyncOracleConnect):
            with self.subTest(cls=cls.__name__):
                with self.assertRaisesRegex(NotSupportedError, 'thick mode'):
                    self._conn(cls).tpc_forget(Xid(1, b'g', b'b'))
