# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""The Mirror cancels a backend's call when the client breaks it (#2717).

The session runs a call on its own thread and reads nothing from the client
until the backend returns, so a break -- a call timeout's, or ``cancel()`` --
waited in the socket while the backend ran on. The stream's watcher peeks for a
``MARKER`` (or a hang-up) while a call runs, cancels the backend's call, and has
the stream drop that call's reply, so the session answers the break alone, as a
real server does.
"""

import socket
import struct
import threading
import unittest

from seerdb.common.tns_consts import TNS_DATA, TNS_MARKER
from seerdb.server.framing import BreakWatch, PacketStream


def _packet(packet_type: int, body: bytes) -> bytes:
    # A legacy-header TNS packet: size, checksum, type, flags, header checksum.
    return struct.pack('>HhBBh', 8 + len(body), 0, packet_type, 0, 0) + body


_BREAK = _packet(TNS_MARKER, bytes([1, 0, 1]))
_CALL = _packet(TNS_DATA, b'\x00\x00\x03\x5e')


class _Pair:
    def __init__(self):
        (self.server, self.client) = socket.socketpair()
        self.stream = PacketStream(self.server)

    def close(self):
        self.server.close()
        self.client.close()


class BreakPendingTest(unittest.TestCase):
    def setUp(self):
        self.pair = _Pair()

    def tearDown(self):
        self.pair.close()

    def test_nothing_sent_is_no_break(self):
        self.assertIs(self.pair.stream.break_pending(0.01), False)

    def test_a_call_is_no_break_and_stays_unread(self):
        self.pair.client.sendall(_CALL)
        self.assertIsNone(self.pair.stream.break_pending(0.5))
        self.assertEqual(self.pair.stream.read_packet()[0], TNS_DATA)

    def test_a_break_behind_a_call_is_one(self):
        self.pair.client.sendall(_CALL + _BREAK)
        self.assertIs(self.pair.stream.break_pending(0.5), True)
        # Peeked, not read: the session still reads both.
        self.assertEqual(self.pair.stream.read_packet()[0], TNS_DATA)
        self.assertEqual(self.pair.stream.read_packet()[0], TNS_MARKER)

    def test_a_hang_up_is_one(self):
        self.pair.client.close()
        self.assertIs(self.pair.stream.break_pending(0.5), True)


class BreakWatchTest(unittest.TestCase):
    def setUp(self):
        self.pair = _Pair()
        self.cancelled = threading.Event()
        self.watch = BreakWatch(self.pair.stream, self.cancelled.set)

    def tearDown(self):
        self.watch.close()
        self.pair.close()

    def _reply_seen(self) -> bytes:
        self.pair.client.settimeout(0.3)
        try:
            return self.pair.client.recv(4096)
        except TimeoutError:
            return b''

    def test_a_break_cancels_the_call_and_drops_its_reply(self):
        self.watch.arm()
        self.pair.client.sendall(_BREAK)
        self.assertTrue(self.cancelled.wait(2))
        # The cancelled call fails, and what it answers is dropped.
        self.pair.stream.write_packet(TNS_DATA, b'\x04\x01')
        self.watch.disarm()
        self.assertEqual(self._reply_seen(), b'')
        # Then the break is read and answered as it always was.
        self.assertEqual(self.pair.stream.read_packet()[0], TNS_MARKER)
        self.pair.stream.write_packet(TNS_DATA, b'\x04\x01')
        self.assertNotEqual(self._reply_seen(), b'')

    def test_a_break_after_the_reply_began_cancels_nothing(self):
        self.watch.arm()
        self.pair.stream.write_packet(TNS_DATA, b'\x04\x01')
        self.pair.client.sendall(_BREAK)
        self.assertFalse(self.cancelled.wait(0.5))
        self.assertNotEqual(self._reply_seen(), b'')

    def test_a_disarmed_watch_leaves_a_break_to_the_session(self):
        self.watch.arm()
        self.watch.disarm()
        self.pair.client.sendall(_BREAK)
        self.assertFalse(self.cancelled.wait(0.5))
        self.assertEqual(self.pair.stream.read_packet()[0], TNS_MARKER)

    def test_a_message_read_on_during_its_call_is_no_break(self):
        # A message spanning packets is read on while its call is armed (the
        # session's continuation reader). Its payload is all 0x0c, a MARKER's
        # packet type. A look that peeked the socket, then took the read-ahead
        # after a read moved bytes between the two, parsed out of step and
        # found one.
        self.pair.stream.sdu = 40
        pieces = 2000
        burst = b''.join(
            _packet(TNS_DATA, b'\x00\x00' + b'\x0c' * (10 + i % 70))
            for i in range(pieces)
        )
        sender = threading.Thread(target=self.pair.client.sendall, args=(burst,))
        sender.start()
        self.watch.POLL = 0.0001
        self.watch.arm()
        for _ in range(pieces):
            self.assertEqual(self.pair.stream.read_packet()[0], TNS_DATA)
        self.watch.disarm()
        sender.join()
        self.assertFalse(self.cancelled.is_set())

    def test_no_look_while_a_packet_is_read(self):
        self.pair.client.sendall(_BREAK)
        with self.pair.stream._read_lock:
            self.assertIsNone(self.pair.stream.break_pending(0.5))
        self.assertIs(self.pair.stream.break_pending(0.5), True)

    def test_without_a_cancel_hook_it_does_nothing(self):
        watch = BreakWatch(self.pair.stream, None)
        watch.arm()
        self.pair.client.sendall(_BREAK)
        self.pair.stream.write_packet(TNS_DATA, b'\x04\x01')
        self.assertNotEqual(self._reply_seen(), b'')
        watch.close()


if __name__ == '__main__':
    unittest.main()
