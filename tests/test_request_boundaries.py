# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Request boundaries (session-state piggyback, TTC func 176, #464).

A pool-driven optimisation: on acquire a REQUEST_BEGIN marker rides the next
call; on release a REQUEST_END marker rides a rollback. Gated on the server
advertising both the compile EXPLICIT_BOUNDARY and runtime SESSION_STATE_OPS
bits. Byte layout pinned here; the pool round-trips are live-validated on 26ai.
"""

import unittest
from unittest.mock import patch

import seerdb.client.connection as connmod
from seerdb.client.connection import OracleConnect
from seerdb.common.tns import encode_sb4, encode_session_state_piggyback
from seerdb.common.tns_consts import (
    TNS_SESSION_STATE_REQUEST_BEGIN,
    TNS_SESSION_STATE_REQUEST_END,
)

# compile_caps[40] (TTC4) with EXPLICIT_BOUNDARY (0x40); runtime_caps[6] (TTC)
# with SESSION_STATE_OPS (0x10) — as 26ai / 23ai / 21c advertise them.
_CC_WITH = bytes([0] * 40 + [0xFF])  # TTC4 = 0xff (includes 0x40)
_RC_WITH = bytes([0] * 6 + [0x7F])  # TTC = 0x7f (includes 0x10)
_CC_NO = bytes([0] * 40 + [0x3F])  # TTC4 without 0x40
_RC_NO = bytes([0] * 6 + [0x0F])  # TTC without 0x10


class TestEncoder(unittest.TestCase):
    def test_begin_fv24(self):
        pb = encode_session_state_piggyback(0x07, 24, TNS_SESSION_STATE_REQUEST_BEGIN)
        # 0x11, 176, seq, ub8 token(0), ub8(state|0x40)=0x44
        self.assertEqual(
            pb, bytes([0x11, 176, 0x07]) + encode_sb4(0) + encode_sb4(0x44)
        )

    def test_end_fv24(self):
        pb = encode_session_state_piggyback(0x09, 24, TNS_SESSION_STATE_REQUEST_END)
        self.assertEqual(
            pb, bytes([0x11, 176, 0x09]) + encode_sb4(0) + encode_sb4(0x48)
        )

    def test_fv17_omits_token(self):
        pb = encode_session_state_piggyback(0x07, 17, TNS_SESSION_STATE_REQUEST_BEGIN)
        self.assertEqual(pb, bytes([0x11, 176, 0x07]) + encode_sb4(0x44))


def _bare(cc=_CC_WITH, rc=_RC_WITH):
    conn = object.__new__(OracleConnect)
    conn._server_compile_caps = cc
    conn._server_runtime_caps = rc
    conn._session_state_desired = 0
    conn._in_request = False
    conn.seq = 1
    conn.field_version = 24
    return conn


class TestNegotiation(unittest.TestCase):
    def test_supported(self):
        self.assertTrue(_bare()._supports_request_boundaries())

    def test_missing_compile_bit(self):
        self.assertFalse(_bare(cc=_CC_NO)._supports_request_boundaries())

    def test_missing_runtime_bit(self):
        self.assertFalse(_bare(rc=_RC_NO)._supports_request_boundaries())

    def test_short_arrays(self):
        self.assertFalse(_bare(cc=b'', rc=b'')._supports_request_boundaries())


class TestStateMachine(unittest.TestCase):
    def test_begin_arms_marker(self):
        conn = _bare()
        conn._begin_request()
        self.assertEqual(conn._session_state_desired, TNS_SESSION_STATE_REQUEST_BEGIN)
        self.assertTrue(conn._in_request)

    def test_begin_noop_when_unsupported(self):
        conn = _bare(cc=_CC_NO)
        conn._begin_request()
        self.assertEqual(conn._session_state_desired, 0)
        self.assertFalse(conn._in_request)

    def test_flush_emits_begin_then_clears(self):
        conn = _bare()
        conn._begin_request()
        out = conn._flush_session_state_bytes()
        self.assertTrue(out.startswith(bytes([0x11, 176])))
        self.assertIn(encode_sb4(0x44), out)  # BEGIN | EXPLICIT_BOUNDARY
        self.assertEqual(conn._session_state_desired, 0)  # one-shot
        self.assertTrue(conn._in_request)  # request still open until end
        self.assertEqual(conn._flush_session_state_bytes(), b'')  # nothing left

    def test_flush_empty_when_idle(self):
        self.assertEqual(_bare()._flush_session_state_bytes(), b'')

    def test_end_without_op_cancels_silently(self):
        # acquire then release with no operation: BEGIN never flushed -> no send.
        conn = _bare()
        conn._begin_request()  # desired=BEGIN, in_request=True
        sent = []
        conn.send = lambda t, d: sent.append((t, d))
        conn._handle_response = lambda: None
        conn._end_request()
        self.assertEqual(sent, [])
        self.assertFalse(conn._in_request)
        self.assertEqual(conn._session_state_desired, 0)

    def test_end_after_op_sends_rollback_with_end_marker(self):
        conn = _bare()
        conn._begin_request()
        conn._flush_session_state_bytes()  # BEGIN rode a call; desired now 0
        sent = []
        conn.send = lambda t, d: sent.append((t, d))
        conn._handle_response = lambda: None
        conn._make_dict = lambda Type, **kw: {'type': Type, 'seq': conn._next_seq()}
        with patch.object(connmod, 'encode_dictionary', return_value=b'ROLLBACK'):
            conn._end_request()
        self.assertEqual(len(sent), 1)
        _type, payload = sent[0]
        self.assertTrue(payload.startswith(bytes([0x11, 176])))  # END piggyback
        self.assertIn(encode_sb4(0x48), payload)  # END | EXPLICIT_BOUNDARY
        self.assertTrue(payload.endswith(b'ROLLBACK'))
        self.assertFalse(conn._in_request)

    def test_end_noop_when_not_in_request(self):
        conn = _bare()
        sent = []
        conn.send = lambda t, d: sent.append((t, d))
        conn._end_request()
        self.assertEqual(sent, [])


class TestPoolWiring(unittest.TestCase):
    def test_release_calls_end_request(self):
        from seerdb.client.pool import Pool, _PoolEntry, _PoolPolicy

        pool = object.__new__(Pool)
        import threading

        pool._available = threading.Condition()
        pool._closed = False
        pool._free = __import__('collections').deque()
        pool._opening = 0
        pool._policy = _PoolPolicy(1, 4, 1, 30.0, 60.0, True, None, 0, None, 0, 0)

        class FakeConn:
            def __init__(self):
                self.ended = False

            def _end_request(self):
                self.ended = True

        conn = FakeConn()
        pool._in_use = {id(conn): _PoolEntry(conn)}
        pool.release(conn)
        self.assertTrue(conn.ended)
        self.assertEqual(len(pool._free), 1)
        self.assertIsInstance(pool._free[0], _PoolEntry)


if __name__ == '__main__':
    unittest.main()
