# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Mirror's WebSocket listener (#1989), a seerdb extension.

A ``ws://`` / ``wss://`` listener beside the TCP / TCPS ones
(:class:`seerdb.server.service.Server`). It serves the seerdb client's
WebSocket transport (#1988) and, with the passthrough backend, acts as an
**auditing gateway**: a browser client's traffic reaches a real Oracle through
code that understands it, so statement logging, policy and per-user limits
apply (unlike a protocol-blind bridge such as websockify).

The transport is a byte pipe: each WebSocket connection is wrapped as a
socket (:class:`seerdb.common.ws_transport.WsSocket`) and handed to the same
:func:`serve_session` the TCP path uses, above an unchanged TNS framer.

A browser-facing endpoint is outside the Mirror's stated threat model (behind a
firewall or VPN), so the full security review (milestone 52) is still owed.
This listener does not ship a naked endpoint, though: it enforces an **origin
allow-list** at the WebSocket handshake (``websockets``' own ``origins`` check),
runs the backend's **authentication before any backend work** exactly as the TCP
path does, and honours the **connection limit** (``max_sessions``). wss:// is
WebSocket-over-TLS; ws:// is unencrypted, for local testing.

Needs the optional ``websockets`` dependency (the ``ws`` extra).
"""

from __future__ import annotations

import logging
import socket
import ssl
from typing import TYPE_CHECKING, Any, cast

from seerdb.common.exceptions import NotSupportedError
from seerdb.common.tns_consts import FIELD_VERSION_11_2
from seerdb.server.framing import PRE_LOGIN_MESSAGE_LIMIT
from seerdb.server.service import BackendFactory, _serve_session_on

if TYPE_CHECKING:
    import threading

logger = logging.getLogger('seerdb.server')

_INSTALL_HINT = (
    "the Mirror's ws:// / wss:// listener needs the 'websockets' package; "
    'install seerdb with the "ws" extra (pip install seerdb[ws])'
)


def _import_websockets() -> Any:
    try:
        import websockets  # noqa: F401
    except ImportError as Exc:
        raise NotSupportedError(_INSTALL_HINT) from Exc
    return websockets


class WsServer:
    """A Mirror WebSocket listener. Binds on construction (so ``port=0`` yields
    an ephemeral port readable as :attr:`port` before serving); serve on a
    thread or call :meth:`serve_forever`, and :meth:`close` to stop.

    ``allowed_origins`` is the browser ``Origin`` allow-list: None disables the
    check (any origin, logged as a tech-preview warning); a list admits only
    those origins (plus non-browser clients, which send no ``Origin`` and are
    not subject to cross-site WebSocket hijacking). ``ssl_context`` serves
    ``wss://``; without it the listener is plain ``ws://``.

    ``protocol`` picks what rides the WebSocket: ``'tns'`` (the default) carries
    raw TNS as a byte pipe for seerdb clients and the auditing gateway (#1989);
    ``'query'`` is the thin JSON-over-WebSocket query endpoint (#2371), which
    drives the same backend one layer above TNS."""

    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 1522,
        *,
        backend_factory: BackendFactory,
        field_version: int = FIELD_VERSION_11_2,
        tns_version: int | None = None,
        encryption: str = 'accepted',
        ssl_context: ssl.SSLContext | None = None,
        max_sessions: int | None = None,
        allowed_origins: list[str] | None = None,
        protocol: str = 'tns',
    ) -> None:
        _import_websockets()
        import threading

        from websockets.sync.server import serve as _serve

        if protocol not in ('tns', 'query'):
            raise ValueError(f"protocol must be 'tns' or 'query', not {protocol!r}")
        self._backend_factory = backend_factory
        self._encryption = encryption
        self._field_version = field_version
        self._tns_version = tns_version
        self._protocol = protocol
        self._secure = ssl_context is not None
        if ssl_context is not None:
            # No TLS 1.3 session tickets (#2385). The server sends them after the
            # handshake, and websockets' sync client reads them in its receive
            # thread while its main thread writes the opening request on the same
            # SSL object; OpenSSL does not take the two at once, and now and then
            # the request was lost and the server closed the connection at its
            # 10 s open timeout (about 1 in 20 connects locally, 0 in 200 without
            # tickets). A ticket only speeds up resuming a TLS session, which a
            # long-lived WebSocket hardly does.
            ssl_context.num_tickets = 0
        # One session slot per connection (GHSA-5827-wqfh-x2v3); one more is
        # closed as it arrives. None serves any number.
        self._slots: threading.BoundedSemaphore | None = (
            threading.BoundedSemaphore(max_sessions) if max_sessions else None
        )
        # The browser-origin allow-list (CSWSH defence): websockets rejects a
        # disallowed Origin at the handshake, before this handler runs. None in
        # the list admits non-browser clients (no Origin header).
        if allowed_origins is None:
            origins = None
            logger.warning(
                'WSS listener has no origin allow-list; any browser origin may '
                'connect (technology preview; see milestone 52)'
            )
        else:
            origins = [*allowed_origins, None]
        # websockets assembles a whole message before the handler reads any of
        # it, so a connection starts with the cap a login needs, as the TNS
        # framer does, and is raised to a session's once it has logged in: a
        # large array bind outgrows the first (GHSA-wgc5-xh4h-3hhr).
        self._server = _serve(
            self._handle,
            host,
            port,
            ssl=ssl_context,
            # websockets types origins as its Origin NewType over str; the
            # values are plain strings (plus None for no-Origin clients).
            origins=cast('Any', origins),
            max_size=PRE_LOGIN_MESSAGE_LIMIT,
        )
        (self.host, self.port) = self._server.socket.getsockname()[:2]

    def _handle(self, conn: Any) -> None:
        addr = conn.remote_address or ('?', 0)
        if self._slots is not None and not self._slots.acquire(blocking=False):
            logger.warning(
                'refused WSS %s:%s: already serving the most sessions allowed',
                addr[0],
                addr[1],
            )
            conn.close(1013)  # try again later
            return
        try:
            if self._protocol == 'query':
                self._handle_query(conn, addr)
            else:
                self._handle_tns(conn, addr)
        finally:
            if self._slots is not None:
                self._slots.release()

    def _handle_tns(self, conn: Any, addr: tuple) -> None:
        from seerdb.common.ws_transport import WsSocket

        # WsSocket presents the socket surface serve_session / the framer use;
        # it stands in for the socket.socket the TCP path passes.
        _serve_session_on(
            cast(socket.socket, WsSocket(conn)),
            addr,
            backend_factory=self._backend_factory,
            encryption=self._encryption,
            field_version=self._field_version,
            tns_version=self._tns_version,
        )

    def _handle_query(self, conn: Any, addr: tuple) -> None:
        # The JSON-over-WebSocket query endpoint (#2371): drive the same backend
        # one layer above TNS. Backend lifecycle mirrors _serve_session_on.
        from seerdb.server.ws_query import serve_query_session

        backend = None
        try:
            backend = self._backend_factory()
            user = serve_query_session(conn, backend)
            logger.info('%s:%s query session ended (%s)', addr[0], addr[1], user)
        except Exception:
            logger.exception('query session error from %s:%s', addr[0], addr[1])
        finally:
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    logger.debug('backend close failed', exc_info=True)

    def serve_forever(self) -> None:
        """Accept and serve WebSocket connections until :meth:`close`."""
        logger.info(
            'Mirror WebSocket listening on %s:%d%s',
            self.host,
            self.port,
            ' (wss)' if self._secure else ' (ws)',
        )
        self._server.serve_forever()

    def close(self) -> None:
        """Stop accepting and release the listening socket."""
        self._server.shutdown()


def serve_ws(
    host: str = '127.0.0.1',
    port: int = 1522,
    *,
    backend_factory: BackendFactory,
    field_version: int = FIELD_VERSION_11_2,
    tns_version: int | None = None,
    encryption: str = 'accepted',
    ssl_context: ssl.SSLContext | None = None,
    max_sessions: int | None = None,
    allowed_origins: list[str] | None = None,
    protocol: str = 'tns',
) -> None:
    """Run a Mirror WebSocket listener until interrupted."""
    server = WsServer(
        host,
        port,
        backend_factory=backend_factory,
        field_version=field_version,
        tns_version=tns_version,
        encryption=encryption,
        ssl_context=ssl_context,
        max_sessions=max_sessions,
        allowed_origins=allowed_origins,
        protocol=protocol,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
