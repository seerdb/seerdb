# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for two-phase commit / XA (#131): the Xid, the switch /
# change-state request encoders, and the response decoders. The full
# begin/prepare/commit/rollback flow is covered live on 21c/23ai.

import itertools
import unittest

from seerdb.client.connection import Xid, _decode_tpc_context, _decode_tpc_state
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    _TPC_CHANGE_STATE_FROM_THIN,
    _TPC_SWITCH_FROM_THIN,
    encode_tpc_change_state,
    encode_tpc_switch,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_9_2,
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_23_4,
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

    def test_the_codec_leaves_the_status_behind_the_parameters(self):
        from seerdb.common.tns import decode_tpc_context, decode_tpc_state

        self.assertEqual(
            decode_tpc_context(self._BEGIN), (self._CTX, bytes.fromhex('0901030104'))
        )
        self.assertEqual(
            decode_tpc_state(bytes.fromhex('0801040901')), (4, bytes.fromhex('0901'))
        )

    def test_a_reply_without_parameters_is_a_status(self):
        # A failure's reply: no RPA, so no context or state to read.
        from seerdb.common.tns import decode_tpc_context, decode_tpc_state

        status = bytes.fromhex('0901030104')
        self.assertEqual(decode_tpc_context(status), (None, status))
        self.assertEqual(decode_tpc_state(status), (None, status))


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


class TestTheCallsReadBack(unittest.TestCase):
    # Both calls, read back by their schema's decoder (_TPC_SWITCH,
    # _TPC_CHANGE_STATE, #2773) at the field version they were written for.
    VERSIONS = (
        FIELD_VERSION_9_2,
        FIELD_VERSION_10_2,
        FIELD_VERSION_11_2,
        FIELD_VERSION_12_1,
        FIELD_VERSION_23_4,
    )

    def _read(self, decode, data, fv):
        token = _DECODE_FIELD_VERSION.set(fv)
        try:
            return decode(
                data,
                {
                    'has_names': fv >= FIELD_VERSION_11_2,
                    'has_flags': fv >= FIELD_VERSION_10_2,
                },
            )
        finally:
            _DECODE_FIELD_VERSION.reset(token)

    def test_a_switch(self):
        xid = Xid(0x1234, b'gtrid', b'bqual')
        for fv, context in itertools.product(self.VERSIONS, (None, b'ctx' * 12)):
            with self.subTest(fv=fv, context=context):
                data = encode_tpc_switch(
                    5, fv, TNS_TPC_TXN_START, xid, 1, 60, context, 7
                )
                fields, rest = self._read(_TPC_SWITCH_FROM_THIN, data, fv)
                self.assertEqual(rest, b'')
                self.assertEqual(
                    (fields['operation'], fields['flags'], fields['timeout']),
                    (TNS_TPC_TXN_START, 1, 60),
                )
                self.assertEqual(fields['format_id'], 0x1234)
                self.assertEqual(fields['xid'][:10], b'gtridbqual')
                self.assertEqual(fields['context'], context or b'')
                self.assertEqual(fields['app_value'], 7)

    def test_a_switch_names_only_from_11g(self):
        # 10.2 and 9.2 have no field for the names, so none are sent there.
        xid = Xid(1, b'g', b'b')
        for fv in self.VERSIONS:
            with self.subTest(fv=fv):
                data = encode_tpc_switch(
                    5, fv, TNS_TPC_TXN_START, xid, 1, 0, None, 0, b'INAME', b'ENAME'
                )
                fields, rest = self._read(_TPC_SWITCH_FROM_THIN, data, fv)
                self.assertEqual(rest, b'')
                if fv >= FIELD_VERSION_11_2:
                    names = (fields['internal_name'], fields['external_name'])
                    self.assertEqual(names, (b'INAME', b'ENAME'))
                else:
                    self.assertNotIn(b'INAME', data)

    def test_a_change_of_state(self):
        xid = Xid(9, b'g1', b'b1')
        for fv in self.VERSIONS:
            with self.subTest(fv=fv):
                data = encode_tpc_change_state(
                    6, fv, TNS_TPC_TXN_PREPARE, 0, xid, 2, b'ctx'
                )
                fields, rest = self._read(_TPC_CHANGE_STATE_FROM_THIN, data, fv)
                self.assertEqual(rest, b'')
                self.assertEqual(fields['operation'], TNS_TPC_TXN_PREPARE)
                self.assertEqual(fields['context'], b'ctx')
                self.assertEqual(
                    fields.get('flags'), 2 if fv >= FIELD_VERSION_10_2 else None
                )
