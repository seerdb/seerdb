# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A session the server ends with an EOF DATA packet (#2466), offline.

11g's pool answers a call on a pooled session that was killed with a DATA
packet whose data flags are EOF alone and which carries nothing -- no
ORA-00028, as a dedicated server sends. The bytes are the pool's, captured
2026-11-07 through tools/capture_proxy.py on Oracle 11g XE 11.2.0.2.
"""

import unittest

from replay import load_capture

from seerdb.client.connection import OracleConnect
from seerdb.client.dialect import Oci11Dialect
from seerdb.common.exceptions import DatabaseError, OperationalError
from seerdb.common.tns import (
    assemble_packet,
    decode_packet,
    ends_response,
    ends_session,
    recording_session_keywords,
)
from seerdb.common.tns_consts import (
    CONN_STATE_AUTHENTICATED,
    FIELD_VERSION_MAX,
    TNS_DATA,
)

# The pool's answer to a query on the killed session: a 10-byte DATA packet,
# data flags 0x0040 (EOF), no payload.
_EOF = bytes.fromhex('000a0000060000000040')
# An ordinary reply's last packet: data flags 0x2000 (END_OF_RESPONSE).
_REPLY = bytes.fromhex('000c00000600000020000901')


class _Socket:
    def __init__(self, data):
        self._data = [data]

    def recv(self, _size):
        return self._data.pop(0) if self._data else b''


def _bare(data):
    Conn = object.__new__(OracleConnect)
    Conn._pending = b''
    Conn.sdu = 8192
    Conn._large_packets = False
    Conn._replies_marked = False
    Conn._ano = None
    Conn.sock = _Socket(data)
    Conn._session_shutdown = False
    Conn.conn_state = CONN_STATE_AUTHENTICATED
    Conn._call_status = [1]
    return Conn


class SessionShutdownTest(unittest.TestCase):
    def test_the_codec_tells_an_eof_packet(self):
        self.assertTrue(ends_session(_EOF))
        self.assertFalse(ends_session(_REPLY))
        self.assertTrue(ends_response(_REPLY))

    def test_an_eof_packet_leaves_the_connection_unhealthy(self):
        Conn = _bare(_EOF)
        self.assertEqual(Conn.recv(b'', b''), (TNS_DATA, b''))
        self.assertTrue(Conn._session_shutdown)
        self.assertFalse(Conn.is_healthy())

    def test_an_ordinary_reply_does_not(self):
        Conn = _bare(_REPLY)
        Conn.recv(b'', b'')
        self.assertFalse(Conn._session_shutdown)

    def test_a_dialect_call_raises_and_disconnects(self):
        # The dialect is not handed the empty payload to misread (it read a
        # query's as a describe and raised DataError); the call fails as
        # python-oracledb's DPY-4011 does, a DatabaseError.
        Conn = _bare(_EOF)
        Disconnected = []
        Conn.disconnect = lambda: Disconnected.append(True)
        Conn._next_data_packet = lambda: Conn.recv(b'', b'')
        Conn.send = lambda *_: None
        with self.assertRaises(OperationalError) as Raised:
            Conn._drive(Oci11Dialect(lambda: 7).ping())
        self.assertIsInstance(Raised.exception, DatabaseError)
        self.assertIn('TNS-12572', str(Raised.exception))
        self.assertEqual(Disconnected, [True])


if __name__ == '__main__':
    unittest.main()


class SessionEndedByAnErrorTest(unittest.TestCase):
    # A reply whose error means the server ended the session leaves the
    # connection unhealthy (#2657). ORA-00603 wasn't among the codes is_healthy
    # knew, so after one it still said True. Live 23ai bytes: a DDL's implicit
    # commit hit Transaction Guard's post-commit failpoint.
    _CAPTURE = load_capture('ora_00603_session_ended_23ai.hexdump')

    def test_the_reply_records_its_code(self):
        (_flag, packet_type, body, rest) = assemble_packet(self._CAPTURE, 8192, True)
        self.assertEqual((packet_type, rest), (TNS_DATA, b''))
        assert body is not None
        status: list[int] = []
        with recording_session_keywords({}, status):
            decode_packet(body, (None, None, []), FIELD_VERSION_MAX)
        self.assertEqual(status[1], 603)
        Conn = _bare(b'')
        Conn._socket_open = lambda: True
        Conn._call_status = status
        self.assertFalse(Conn.is_healthy())

    def test_an_ordinary_error_leaves_it_healthy(self):
        Conn = _bare(b'')
        Conn._socket_open = lambda: True
        Conn._call_status = [0, 942]
        self.assertTrue(Conn.is_healthy())
