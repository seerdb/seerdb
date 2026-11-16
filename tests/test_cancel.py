# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Tests for query cancellation / call_timeout (#123, #144).
#
# The break has two paths (matching python-oracledb): an out-of-band urgent byte
# when the server advertised attention support (CAN_RECV_ATTENTION -> conn.
# _supports_oob), else an in-band INTERRUPT marker packet (TNS_MARKER, body
# 01 00 03). The in-band path works on any server over any network path; the
# OOB-only break from #123 silently did nothing where OOB isn't advertised /
# carried. Which servers answer which break, and where, is PROTOCOL.md 25's
# table, which tests/test_integration.py's CallTimeoutIntegration checks on
# every bed; these cover the client wiring for both paths.

import socket
import unittest

from seerdb.client.connection import OracleConnect
from seerdb.common.tns_consts import TNS_MARKER, TNS_MARKER_TYPE_INTERRUPT


class _FakeSock:
    def __init__(self):
        self.oob = []
        self.normal = []

    def send(self, data, flags=0):
        if flags & socket.MSG_OOB:
            self.oob.append(bytes(data))
        else:
            self.normal.append(bytes(data))
        return len(data)


def _conn():
    return OracleConnect(host='x', port=1, user='u', password='p')


class TestCallTimeout(unittest.TestCase):
    def test_setter_clamps(self):
        c = _conn()
        self.assertEqual(c.call_timeout, 0)
        c.call_timeout = 5000
        self.assertEqual(c.call_timeout, 5000)
        c.call_timeout = -10
        self.assertEqual(c.call_timeout, 0)
        c.call_timeout = None
        self.assertEqual(c.call_timeout, 0)


class TestBreak(unittest.TestCase):
    def test_cancel_sends_inband_marker_by_default(self):
        # no OOB advertised -> in-band INTERRUPT marker packet
        c = _conn()
        c.sock = _FakeSock()
        self.assertFalse(c._supports_oob)
        c.cancel()
        self.assertTrue(c._break_in_progress)
        self.assertEqual(c.sock.oob, [])
        self.assertEqual(len(c.sock.normal), 1)
        pkt = c.sock.normal[0]
        self.assertEqual(pkt[4], TNS_MARKER)  # packet type byte
        self.assertEqual(pkt[-3:], bytes([1, 0, TNS_MARKER_TYPE_INTERRUPT]))

    def test_cancel_sends_oob_when_supported(self):
        # server advertised CAN_RECV_ATTENTION -> the OOB urgent byte
        c = _conn()
        c.sock = _FakeSock()
        c._supports_oob = True
        c.cancel()
        self.assertEqual(c.sock.oob, [b'!'])
        self.assertEqual(c.sock.normal, [])

    def test_break_is_idempotent(self):
        c = _conn()
        c.sock = _FakeSock()
        c._break_in_progress = True
        c._send_break()
        self.assertEqual(c.sock.normal, [])  # in progress -> no-op

    def test_break_without_socket_is_noop(self):
        c = _conn()
        c.sock = None
        c._send_break()  # must not raise
        self.assertFalse(c._break_in_progress)

    def test_on_call_timeout_flags_and_breaks(self):
        c = _conn()
        c.sock = _FakeSock()
        c._on_call_timeout()
        self.assertTrue(c._timed_out)
        self.assertTrue(c._break_in_progress)
        self.assertEqual(len(c.sock.normal), 1)
        self.assertEqual(
            c.sock.normal[0][-3:], bytes([1, 0, TNS_MARKER_TYPE_INTERRUPT])
        )


def _answered_break(conn, timed_out: bool):
    # A transport-less execute whose reply is the server's ORA-01013 status,
    # the call timeout's timer having fired first or not.
    conn._call_timeout = 1000
    conn.send = lambda *a, **k: None

    def reply(state):
        conn._timed_out = timed_out
        return (0, 1013, 0, (0, None), [], 'ORA-01013: cancel', None, [], None, 0, 0)

    return reply


class TestAnsweredCallTimeout(unittest.TestCase):
    # A call timeout's break the server answers ends the call with an ORA-01013
    # status, which is reported as the call timeout it is, as python-oracledb's
    # DPY-4024 does; without the timeout -- a cancel() of the caller's own --
    # ORA-01013 stays (#1575). Sync and async alike.

    def test_sync(self):
        from seerdb.common.exceptions import OperationalError

        c = _conn()
        c._handle_response = _answered_break(c, True)
        with self.assertRaisesRegex(OperationalError, 'call timeout of 1000 ms'):
            c.execute('select 1 from dual')
        c._handle_response = _answered_break(c, False)
        self.assertEqual(c.execute('select 1 from dual')[1], 1013)

    def test_async(self):
        import asyncio

        from seerdb.client.aconnection import AsyncOracleConnect
        from seerdb.common.exceptions import OperationalError

        async def run():
            c = AsyncOracleConnect(host='x', user='u', password='p', service_name='s')

            async def send(*a, **k):
                return None

            async def reply_with(timed_out):
                c._timed_out = timed_out
                return (0, 1013, 0, (0, None), [], 'ORA-01013', None, [], None, 0, 0)

            c._call_timeout = 1000
            c.send = send
            c._handle_response = lambda state: reply_with(True)
            with self.assertRaisesRegex(OperationalError, 'call timeout of 1000 ms'):
                await c.execute('select 1 from dual')
            c._handle_response = lambda state: reply_with(False)
            self.assertEqual((await c.execute('select 1 from dual'))[1], 1013)

        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()


def _dialect_call(conn, wait_for_timeout: bool):
    # A dialect's call (a generator _drive runs): one read, which the fake
    # transport answers with the server's ORA-01013 once the call timeout's
    # timer has fired, or at once with a reply.
    import time

    from seerdb.client.dialect import RECV
    from seerdb.common.exceptions import OperationalError

    def next_packet():
        if not wait_for_timeout:
            return (6, b'reply')
        deadline = time.monotonic() + 5
        while not conn._timed_out and time.monotonic() < deadline:
            time.sleep(0.005)
        raise OperationalError('ORA-01013: user requested cancel of current operation')

    def gen():
        reply = yield RECV
        return reply

    return (gen(), next_packet)


class TestDialectCallTimeout(unittest.TestCase):
    # call_timeout bounds a dialect's call (8i, 9i, the native forms) as it
    # bounds a thin one. It was armed only around the thin execute, so on those
    # sessions it was ignored and a long call ran to its end.

    def test_sync_reports_the_timeout(self):
        from seerdb.common.exceptions import OperationalError

        c = _conn()
        c.sock = _FakeSock()
        c.call_timeout = 50
        (gen, c._next_data_packet) = _dialect_call(c, True)
        with self.assertRaisesRegex(OperationalError, 'call timeout of 50 ms'):
            c._drive(gen)
        self.assertEqual(len(c.sock.normal), 1)  # the break went out
        self.assertFalse(c._call_in_progress or c._timed_out or c._break_in_progress)

    def test_sync_call_inside_the_timeout(self):
        c = _conn()
        c.sock = _FakeSock()
        c.call_timeout = 5000
        (gen, c._next_data_packet) = _dialect_call(c, False)
        self.assertEqual(c._drive(gen), (6, b'reply'))
        self.assertEqual(c.sock.normal, [])
        self.assertFalse(c._call_in_progress)

    def test_async_reports_the_timeout(self):
        import asyncio

        from seerdb.client.aconnection import AsyncOracleConnect
        from seerdb.client.dialect import RECV
        from seerdb.common.exceptions import OperationalError

        async def run():
            c = AsyncOracleConnect(host='x', user='u', password='p', service_name='s')
            c.call_timeout = 50
            breaks = []
            c._send_break = lambda: breaks.append(1)

            async def next_packet():
                for _ in range(1000):
                    if c._timed_out:
                        break
                    await asyncio.sleep(0.005)
                raise OperationalError('ORA-01013: user requested cancel')

            def gen():
                reply = yield RECV
                return reply

            c._next_data_packet = next_packet
            with self.assertRaisesRegex(OperationalError, 'call timeout of 50 ms'):
                await c._drive(gen())
            self.assertEqual(breaks, [1])
            self.assertFalse(c._call_in_progress or c._timed_out)

        asyncio.run(run())
