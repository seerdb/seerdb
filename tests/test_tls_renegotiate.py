# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""TLS renegotiation on a listener's RESEND (#2645), against a fake listener.

A listener that hands a TCPS connection to a dedicated server answers the
CONNECT with a RESEND whose header flags carry 0x08: the dedicated server runs
its own TLS handshake on the same TCP connection, and the client has to
handshake again before it resends the CONNECT. Measured against Oracle 26ai
Free. The fake listener here does what that server does: it drops its first TLS
session, handshakes anew on the raw socket, and records whether the resent
CONNECT came over the new session."""

import asyncio
import socket
import ssl
import struct
import threading
import unittest

import seerdb
from tests._tls_proxy import CERT_PATH, KEY_PATH

_TNS_CONNECT = 1
_TNS_RESEND = 11
_FLAG_TLS_RENEGOTIATE = 0x08


def _read_packet(sock) -> tuple[int, bytes]:
    # One TNS packet, in the legacy framing a CONNECT and a RESEND use.
    head = b''
    while len(head) < 8:
        chunk = sock.recv(8 - len(head))
        if not chunk:
            raise EOFError('the client closed the connection')
        head += chunk
    (length, _, kind, _, _) = struct.unpack('>HHBBH', head)
    body = b''
    while len(body) < length - 8:
        chunk = sock.recv(length - 8 - len(body))
        if not chunk:
            raise EOFError('the client closed the connection')
        body += chunk
    return (kind, body)


def _read_connect(sock) -> bytes:
    # The CONNECT and, when its descriptor goes in a DATA packet of its own
    # (past 230 bytes), that packet too.
    (kind, body) = _read_packet(sock)
    if kind != _TNS_CONNECT:
        raise AssertionError(f'expected a CONNECT, got packet type {kind}')
    if b'(DESCRIPTION=' not in body:
        (_, data) = _read_packet(sock)
        body += data
    return body


class _RenegotiatingListener:
    """Answers one connection's CONNECT with a RESEND of the given flags, then,
    when they ask for it, handshakes again; records the resent CONNECT."""

    def __init__(self, flags: int):
        self.flags = flags
        self.handshakes = 0
        self.resent: bytes | None = None
        self.error: BaseException | None = None
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(CERT_PATH, KEY_PATH)
        self._sock = socket.socket()
        self._sock.bind(('127.0.0.1', 0))
        self._sock.listen(1)
        self._sock.settimeout(10)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            (raw, _) = self._sock.accept()
            raw.settimeout(10)
            tls = self._context.wrap_socket(raw, server_side=True)
            self.handshakes += 1
            _read_connect(tls)
            tls.sendall(struct.pack('>HHBBH', 8, 0, _TNS_RESEND, self.flags, 0))
            if self.flags & _FLAG_TLS_RENEGOTIATE:
                # The first session is dropped, not shut down, as a hand-off
                # leaves it, and a new one starts on the same connection.
                raw = socket.socket(fileno=tls.detach())
                raw.settimeout(10)
                tls = self._context.wrap_socket(raw, server_side=True)
                self.handshakes += 1
            self.resent = _read_connect(tls)
            tls.close()
        except BaseException as exc:  # noqa: BLE001 - the test reports it
            self.error = exc
        finally:
            self._sock.close()

    def join(self) -> None:
        self._thread.join(timeout=15)


def _kwargs(port: int) -> dict:
    return {
        'user': 'u',
        'password': 'p',
        'host': '127.0.0.1',
        'port': port,
        'service_name': 'svc',
        'ssl': {'ca_certs': CERT_PATH},
    }


class TestTlsRenegotiation(unittest.TestCase):
    def _connect(self, flags: int) -> _RenegotiatingListener:
        listener = _RenegotiatingListener(flags)
        # The listener closes after the resent CONNECT; the login fails there.
        with self.assertRaises((seerdb.Error, OSError)):
            seerdb.connect(**_kwargs(listener.port))
        listener.join()
        return listener

    def test_a_resend_asking_for_it_renegotiates(self):
        listener = self._connect(_FLAG_TLS_RENEGOTIATE)
        self.assertIsNone(listener.error)
        self.assertEqual(listener.handshakes, 2)
        self.assertIn(b'(SERVICE_NAME=svc)', listener.resent or b'')

    def test_a_plain_resend_stays_on_the_session(self):
        listener = self._connect(0)
        self.assertIsNone(listener.error)
        self.assertEqual(listener.handshakes, 1)
        self.assertIn(b'(SERVICE_NAME=svc)', listener.resent or b'')


class TestAsyncTlsRenegotiation(unittest.IsolatedAsyncioTestCase):
    async def _connect(self, flags: int) -> _RenegotiatingListener:
        listener = _RenegotiatingListener(flags)
        with self.assertRaises((seerdb.Error, OSError)):
            await seerdb.connect_async(**_kwargs(listener.port))
        await asyncio.get_running_loop().run_in_executor(None, listener.join)
        return listener

    async def test_a_resend_asking_for_it_renegotiates(self):
        listener = await self._connect(_FLAG_TLS_RENEGOTIATE)
        self.assertIsNone(listener.error)
        self.assertEqual(listener.handshakes, 2)
        self.assertIn(b'(SERVICE_NAME=svc)', listener.resent or b'')

    async def test_a_plain_resend_stays_on_the_session(self):
        listener = await self._connect(0)
        self.assertIsNone(listener.error)
        self.assertEqual(listener.handshakes, 1)
        self.assertIn(b'(SERVICE_NAME=svc)', listener.resent or b'')


if __name__ == '__main__':
    unittest.main()
