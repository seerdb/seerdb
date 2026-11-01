# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A socket-quacking adapter over a ``websockets`` connection (#1988/#1989).

The seerdb WebSocket transport carries TNS packets in WebSocket **binary**
messages as a **byte pipe**: the existing TNS packet framer reassembles packets
from it exactly as it does over a TCP socket, so the TNS and TTC layers are
untouched. :class:`WsSocket` presents the slice of the :class:`socket.socket`
surface that framer and the connection use, so the same code runs over TCP, TLS
and WebSocket alike.

It lives in ``common`` because both ends need it: the client
(:mod:`seerdb.client._ws`) wraps a ``websockets`` client connection, and the
Mirror's WebSocket listener (:mod:`seerdb.server.ws_service`) wraps a
``websockets`` server connection -- both expose the same ``send`` / ``recv`` /
``close`` surface. Needs the optional ``websockets`` dependency (the ``ws``
extra); this module itself imports it only inside :meth:`WsSocket.recv`.
"""

from __future__ import annotations

from typing import Any


class WsSocket:
    """A :class:`socket.socket`-quacking adapter over a ``websockets``
    connection (client or server). ``recv`` is a byte pipe fed by binary
    messages; ``send`` writes one binary message per call (so in practice one
    TNS packet per message). A WebSocket has no out-of-band data, so break never
    uses the OOB urgent byte over this transport."""

    def __init__(self, Conn: Any) -> None:
        self._conn = Conn
        self._buf = b''
        self._timeout: float | None = None  # seconds; None blocks

    def settimeout(self, Timeout: float | None) -> None:
        self._timeout = Timeout

    def gettimeout(self) -> float | None:
        return self._timeout

    def send(self, Data: Any, Flags: int = 0) -> int:
        # Flags is only ever MSG_OOB, which a WebSocket never carries (the sync
        # connection leaves _supports_oob False), so it is ignored here.
        Payload = bytes(Data)
        try:
            self._conn.send(Payload)
        except Exception as Exc:
            # The caller's break path and _write treat a dead transport as an
            # OSError, matching socket semantics.
            raise OSError(f'websocket send failed: {Exc}') from Exc
        return len(Payload)

    def sendall(self, Data: Any, Flags: int = 0) -> None:
        self.send(Data, Flags)

    def recv(self, Bufsize: int) -> bytes:
        from websockets.exceptions import ConnectionClosed

        while not self._buf:
            try:
                Message = self._conn.recv(timeout=self._timeout)
            except TimeoutError:
                # Surfaced to the connection's read-timeout handling verbatim.
                raise
            except ConnectionClosed:
                # A clean or abrupt close reads as a socket EOF (empty recv).
                return b''
            if isinstance(Message, str):
                Message = Message.encode('utf-8')
            self._buf = Message  # empty frame -> loop and read the next one
        (Chunk, self._buf) = (self._buf[:Bufsize], self._buf[Bufsize:])
        return Chunk

    def set_message_limit(self, Limit: int) -> None:
        """The largest message the connection takes from now on. websockets
        assembles a whole message before recv returns any of it, so its own cap
        is what bounds the memory a message takes; PacketStream raises it with
        its own once the session has logged in (GHSA-wgc5-xh4h-3hhr)."""
        self._conn.protocol.max_size = Limit

    def shutdown(self, How: int) -> None:
        # A WebSocket has no half-close; the following close() tears it down.
        pass

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            # Best effort: the call being closed is finished with the transport.
            pass
