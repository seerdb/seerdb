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
    conn._cursors_to_close = []
    conn._cursor_cache = {}
    conn._drcp_released = False
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
                self.released = False

            def _end_request(self):
                self.ended = True

            def _release_pooled_server(self):
                # After the REQUEST_END, the pooled server goes back (#2544).
                self.released = self.ended

        conn = FakeConn()
        pool._in_use = {id(conn): _PoolEntry(conn)}
        pool.release(conn)
        self.assertTrue(conn.ended)
        self.assertTrue(conn.released)
        self.assertEqual(len(pool._free), 1)
        self.assertIsInstance(pool._free[0], _PoolEntry)


class TestDrcpSessionRelease(unittest.TestCase):
    # A pool hands a pooled (DRCP) server back once it takes the connection
    # back, as python-oracledb's does: without it the server stayed busy while
    # the connection sat idle in the client pool (#2544).
    def _pooled(self, server_type='pooled'):
        from seerdb.common.tns_consts import CONN_STATE_AUTHENTICATED

        conn = _bare()
        conn.server_type = server_type
        conn.conn_state = CONN_STATE_AUTHENTICATED
        conn._dialect = None
        conn._native11 = False
        conn._pooled_server = True  # a session return came: DRCP served it
        return conn

    def test_the_release_is_python_oracledbs(self):
        # Captured from python-oracledb 26.1 against 23ai Free: at pool release
        # mode 0, at a standalone pooled connection's close mode 2.
        from seerdb.common.tns import encode_session_release

        self.assertEqual(encode_session_release(9, 24).hex(), '1aa30900000000')
        self.assertEqual(encode_session_release(4, 24, 2).hex(), '1aa3040000000102')
        self.assertEqual(encode_session_release(9, 17).hex(), '1aa309000000')

    def test_a_pooled_server_is_released_and_forgets_its_cursors(self):
        conn = self._pooled()
        conn._cursors_to_close = [5]
        conn._cursor_cache = {('select 1 from dual', b''): 7}
        sent = []
        conn.send = lambda t, d: sent.append(d)
        conn._release_pooled_server()
        self.assertEqual(sent, [bytes.fromhex('1aa30100000000')])
        self.assertTrue(conn._drcp_released)
        self.assertEqual((conn._cursors_to_close, conn._cursor_cache), ([], {}))
        conn._next_seq()  # the next call brings a server back
        self.assertFalse(conn._drcp_released)

    def test_a_dedicated_server_is_left_alone(self):
        conn = self._pooled(server_type=None)
        sent = []
        conn.send = lambda t, d: sent.append(d)
        conn._release_pooled_server()
        self.assertEqual(sent, [])
        self.assertFalse(conn._drcp_released)

    def test_a_pooled_request_a_dedicated_server_served_is_left_alone(self):
        # 10g and a Mirror answer `server_type='pooled'` with a dedicated
        # server, which sends no session return: a release reset 10g's
        # connection, and the Mirror answered it as a call (ORA-03115).
        conn = self._pooled()
        conn._pooled_server = False
        sent = []
        conn.send = lambda t, d: sent.append(d)
        conn._release_pooled_server()
        self.assertEqual(sent, [])

    def test_a_session_return_says_a_pooled_server_answered(self):
        # The head of 23ai Free's DRCP reply to the first call, captured: the
        # session return (`17 04`) is recorded, and the decode goes on after it.
        from seerdb.common import tns
        from seerdb.common.tns import (
            SESSION_KEYWORD_POOLED_SERVER,
            decode_token_server_piggyback,
            recording_session_keywords,
        )

        reply = bytes.fromhex('1704010114000001ea02b76b101706dbf25b')
        sink: dict = {}
        with (
            patch.object(tns, 'decode_packet', lambda Rest, Acc: Rest),
            recording_session_keywords(sink),
        ):
            rest = decode_token_server_piggyback(reply, ())
        self.assertEqual(rest.hex(), '101706dbf25b')
        self.assertIn(SESSION_KEYWORD_POOLED_SERVER, sink)
        conn = _bare()
        conn._session_keywords = sink
        conn._pooled_server = False
        conn._txn_priority = None
        conn._absorb_session_keywords()
        self.assertTrue(conn._pooled_server)

    def test_the_request_end_closes_the_queued_cursors(self):
        # While the session is attached: after the release the server refuses
        # a close of the old session's cursors (ORA-56600).
        conn = _bare()
        conn._begin_request()
        conn._flush_session_state_bytes()
        conn._cursors_to_close = [5]
        sent = []
        conn.send = lambda t, d: sent.append(d)
        conn._handle_response = lambda: None
        conn._make_dict = lambda Type, **kw: {'type': Type, 'seq': conn._next_seq()}
        with patch.object(connmod, 'encode_dictionary', return_value=b'ROLLBACK'):
            conn._end_request()
        (payload,) = sent
        self.assertTrue(payload.startswith(bytes([0x11, 105])))  # close cursors
        self.assertIn(bytes([0x11, 176]), payload)  # then REQUEST_END
        self.assertEqual(conn._cursors_to_close, [])

    def test_a_released_connection_closes_with_the_eof_alone(self):
        conn = self._pooled()
        conn._drcp_released = True
        conn.autocommit = False
        conn.sock = object()
        written, sent = [], []
        conn._write = written.append
        conn.send = lambda t, d: sent.append(d)
        conn.disconnect = lambda: None
        conn._large_packets = True
        conn.close()
        self.assertEqual(sent, [])  # no rollback, no logoff
        # The EOF packet, as python-oracledb's (#2558).
        self.assertEqual([w.hex() for w in written], ['0000000a060000000040'])


if __name__ == '__main__':
    unittest.main()
