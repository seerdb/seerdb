# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# A server that goes away mid-handshake must fail the connect (#805).
#
# It used to fail silently: handle_login returned a code that connect() only
# acted on when the negotiation cache was in play, so every other caller got a
# live-looking connection wrapped around a dead socket. The failure surfaced on
# the first statement instead, blaming that statement rather than the login that
# had actually failed -- which is how it cost a long diagnosis during #790.

import socket
import struct
import threading
import unittest

import seerdb
from seerdb.common.exceptions import OperationalError
from seerdb.common.tns_consts import TNS_ACCEPT


def _accept_packet() -> bytes:
    # A well-formed TNS_ACCEPT: version, global options, SDU, then enough body
    # for the ANO-capability bytes handle_login reads at offsets 14 and 15.
    body = struct.pack('>Hhh', 314, 0, 8192) + bytes(12)
    header = struct.pack('>HhBBh', 8 + len(body), 0, TNS_ACCEPT, 0, 0)
    return header + body


class _ClosingListener:
    """Accepts one connection, optionally replies, then hangs up."""

    def __init__(self, reply: bytes = b''):
        self.reply = reply
        self.port = 0
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> '_ClosingListener':
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        if self._sock is None:
            return
        try:
            (conn, _addr) = self._sock.accept()
        except OSError:
            # Closed by __exit__ while still waiting for a client: deliberate.
            return
        with conn:
            try:
                conn.recv(4096)  # the client's CONNECT
                if self.reply:
                    conn.sendall(self.reply)
            except OSError:
                # The client hung up first. The close is the whole point of the
                # fixture, so there is nothing to recover here.
                pass

    def __exit__(self, *_exc) -> None:
        if self._sock is not None:
            self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def connect(self):
        return seerdb.connect(
            host='127.0.0.1',
            port=self.port,
            service_name='XE',
            user='pyo',
            password='pyo123',
        )


class TestServerClosesDuringLogin(unittest.TestCase):
    def test_close_before_any_reply_fails_the_connect(self):
        with _ClosingListener() as Listener:
            with self.assertRaises(OperationalError) as Caught:
                Listener.connect()
        self.assertIn('during login', str(Caught.exception))

    def test_close_after_the_accept_fails_the_connect(self):
        # The #790 shape: the server answers the CONNECT, then goes away while
        # the client waits for the reply to its next handshake packet. This is
        # the case that used to hand back a usable-looking connection.
        with _ClosingListener(reply=_accept_packet()) as Listener:
            with self.assertRaises(OperationalError) as Caught:
                Listener.connect()
        self.assertIn('during login', str(Caught.exception))

    def test_the_error_names_the_login_not_a_later_statement(self):
        # The point of the fix: the message has to point at the handshake, so a
        # reader is not sent looking at whatever statement ran next.
        with _ClosingListener(reply=_accept_packet()) as Listener:
            try:
                Listener.connect()
            except OperationalError as Exc:
                Message = str(Exc)
            else:
                self.fail('connect() returned a connection to a closed socket')
        self.assertIn('closed the connection', Message)
        self.assertNotIn('DML', Message)
