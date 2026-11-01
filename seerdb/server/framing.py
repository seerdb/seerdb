# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side TNS packet framing.

This is the read/write counterpart of the client's ``Connection.recv()`` /
``Connection.send()``. Writing reuses :func:`seerdb.common.tns.encode_packet` verbatim
— the on-wire packet is identical whichever end emits it.

Reading, however, is *not* a straight reuse of :func:`seerdb.common.tns.assemble_packet`.
That routine reassembles multi-fragment ``DATA`` the way the **real Oracle
server** fragments it — keyed on an SDU-boundary heuristic
(``PacketSize == Length - 37`` / ``- 81``). A *client* fragments the other way:
``encode_packet`` splits at the full SDU and marks every non-final fragment with
the ``0x0020`` "more data" flag. Those two conventions are not inverses, so a
server that reused ``assemble_packet`` to read client requests would mis-split
any request large enough to fragment. We therefore parse the header ourselves
and key ``DATA`` reassembly on the ``0x0020`` flag — making ``read_packet`` a
true inverse of the client's ``send()``.

The 8-byte header has two layouts (see ``assemble_packet``): legacy
``len(ub2) + cksum(ub2) + type + flags + hdr-cksum(ub2)`` and, from protocol
version 315 (large SDU, #155), ``len(ub4) + type + flags + hdr-cksum(ub2)``.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable
from typing import TYPE_CHECKING

from seerdb.common.tns import (
    encode_ano_fragment,
    encode_data_packet,
    encode_packet,
    encode_sb4,
)
from seerdb.common.tns_consts import (
    DEFAULT_SDU,
    TNS_DATA,
    TNS_DATA_FLAGS_END_OF_RESPONSE,
    TNS_DATA_FLAGS_MORE,
    TTI_END_OF_RESPONSE,
    TTI_TOKEN,
)

if TYPE_CHECKING:
    from seerdb.common.ano_session import AnoChannel

# Re-exported for the server modules that frame at the default SDU.
__all__ = ['DEFAULT_SDU', 'PacketStream']

_HEADER_LEGACY = struct.Struct('>HhBBh')  # size, cksum, type, flags, hdr-cksum
_HEADER_LARGE = struct.Struct('>IBBh')  # size, type, flags, hdr-cksum
_DATA_FLAGS = struct.Struct('>H')
# The bounds a client's input is held to (GHSA-5827-wqfh-x2v3). A packet no
# longer than the 16-bit legacy limit is always accepted, whatever the SDU: a
# CONNECT uses it before one is agreed. Before login a message is the
# handshake's, ANO's or O5LOGON's, all small; after it, a call's, which an
# array of binds can make large.
LEGACY_PACKET_LIMIT = 0xFFFF
PRE_LOGIN_MESSAGE_LIMIT = 1 << 20
SESSION_MESSAGE_LIMIT = 1 << 30


class ProtocolLimitError(ConnectionError):
    # Input past what the Mirror accepts: the session is closed, as for a
    # connection the client dropped.
    pass


class PacketStream:
    """Frames a connected stream socket into TNS packets.

    One instance per client connection; not thread-safe. ``read_packet`` blocks
    until a full packet (reassembling ``DATA`` fragments) is available or the
    peer closes; ``write_packet`` splits oversized payloads exactly as the
    client does.
    """

    def __init__(
        self, sock: socket.socket, *, sdu: int = DEFAULT_SDU, large: bool = False
    ) -> None:
        self._sock = sock
        self.sdu = sdu
        self.large = large
        self._acc = bytearray()
        # The most a reassembled message may hold (GHSA-5827-wqfh-x2v3): what
        # a login needs before authentication, raised once the session has
        # logged in (session.serve_session). A client that sends more is
        # refused rather than buffered.
        self.max_message = PRE_LOGIN_MESSAGE_LIMIT
        # Native network encryption (#448). Set by activate_ano() once the ANO
        # negotiation selects a cipher; each TNS_DATA fragment is then decrypted
        # on read and encrypted on write. None means plaintext framing.
        self._ano: AnoChannel | None = None
        # End-of-response framing (#155/#132/#1059). Set once the client has
        # opted in through its compile caps; until then every reply is framed
        # the old way, because a client that did not ask will not skip the
        # marker and desyncs on it.
        self.end_of_response = False
        # The data flags of the packet last read. A pipelined burst is marked
        # ONLY there (BEGIN_PIPELINE / END_OF_REQUEST), so a session cannot
        # tell one from an ordinary call without them.
        self.last_data_flags = 0
        # The correlation token of the pipelined call being answered, or None.
        # A pipelined response opens with TTI_TOKEN and the token the client put
        # in that call's header, which is how the client matches the N responses
        # of a burst back to its N calls (#1059). Consumed by the next DATA write.
        self.response_token: int | None = None
        # Asked at every DATA write for bytes to lead the reply with -- session
        # state that changed during the call, as a server piggyback (#1779). It
        # is asked when the reply goes out, after the backend ran the call, so a
        # change the call itself made is reported on that call's reply.
        self.reply_prefix: Callable[[], bytes] | None = None

    def allow_session_messages(self) -> None:
        """Raise the message limit to a logged-in session's. A transport that
        assembles whole messages before this framer reads any of them -- a
        WebSocket -- keeps a cap of its own, which goes up with it
        (GHSA-wgc5-xh4h-3hhr)."""
        self.max_message = SESSION_MESSAGE_LIMIT
        raise_cap = getattr(self._sock, 'set_message_limit', None)
        if raise_cap is not None:
            raise_cap(SESSION_MESSAGE_LIMIT)

    def activate_ano(self, channel: AnoChannel) -> None:
        """Turn on per-packet encryption + MAC for every subsequent DATA packet
        (server side of §33). The channel must be a server channel
        (``ClientSide=False``) so its keystreams mirror the client's."""
        self._ano = channel

    def rederive_ano(self) -> None:
        """Re-derive the data-integrity keystreams after a break/reset (#1346).

        Both sides re-derive once per break/reset exchange; the client does when
        it answers the server's reset, so the server must before the DATA that
        closes the episode, or that packet fails the client's MAC. A no-op while
        no encryption is active.
        """
        if self._ano is not None:
            self._ano.rederive()

    def _fill(self, n: int) -> bool:
        # Pull from the socket until the accumulator holds at least n bytes.
        # False signals the peer closed before n bytes arrived. A socket timeout
        # (only ever set by read_packet's `within`) propagates to the caller.
        while len(self._acc) < n:
            chunk = self._sock.recv(self.sdu)
            if not chunk:
                return False
            self._acc += chunk
        return True

    def settimeout(self, seconds: float | None) -> None:
        """Bound every later read to ``seconds`` (None: wait for ever), as a
        login's deadline does (GHSA-5827-wqfh-x2v3)."""
        self._sock.settimeout(seconds)

    def _check_size(self, size: int) -> None:
        # A packet's length as its header gives it (GHSA-5827-wqfh-x2v3): no
        # shorter than the header, no longer than the negotiated SDU -- never
        # under the 16-bit legacy limit, which a CONNECT may use before the SDU
        # is agreed. The large header would otherwise let a client claim 4 GB
        # that the reader then waits to buffer.
        if size < 8 or size > max(self.sdu, LEGACY_PACKET_LIMIT):
            raise ProtocolLimitError(f'packet length {size} out of bounds')

    def _header(self) -> tuple[int, int]:
        # Parse (packet_size, type) from the 8-byte header at the front of _acc.
        head = bytes(self._acc[:8])
        if self.large:
            size, packet_type, _flags, _zero = _HEADER_LARGE.unpack(head)
        else:
            size, _cksum, packet_type, _flags, _zero = _HEADER_LEGACY.unpack(head)
        return size, packet_type

    def _read_packet_within(self, seconds: float) -> tuple[int, bytes] | None:
        # read_packet with the socket timed out for the duration, restoring the
        # previous setting afterwards so the session's ordinary reads keep
        # blocking. socket.timeout is an alias of TimeoutError.
        previous = self._sock.gettimeout()
        self._sock.settimeout(seconds)
        try:
            return self.read_packet()
        finally:
            self._sock.settimeout(previous)

    def read_packet(self, *, within: float | None = None) -> tuple[int, bytes] | None:
        """Return ``(type, body)`` for the next packet, or ``None`` at EOF.

        ``DATA`` fragments (non-final ones carry the ``0x0020`` flag) are
        reassembled into a single body. For non-``DATA`` packets the body is
        everything after the 8-byte header.

        ``within`` bounds the wait in seconds and raises :class:`TimeoutError`
        instead of blocking. It exists for ONE caller -- the reader that grows a
        message spanning several packets (#868). There, waiting forever is not
        safe: the continuation is only coming if the message really was cut in
        transport, and a decode fault inside a complete message looks exactly
        the same to the parser. An ordinary read takes no timeout and blocks, as
        a server should while a client thinks.
        """
        if within is not None:
            return self._read_packet_within(within)
        body = bytearray()
        while True:
            if not self._fill(8):
                self._acc = bytearray()
                return None
            size, packet_type = self._header()
            self._check_size(size)
            if not self._fill(size):
                self._acc = bytearray()
                return None
            packet = bytes(self._acc[:size])
            del self._acc[:size]
            if packet_type == TNS_DATA:
                (data_flags,) = _DATA_FLAGS.unpack(packet[8:10])
                # Kept for the caller: a pipelined burst is marked in these
                # flags (BEGIN_PIPELINE / END_OF_REQUEST) and nowhere else, so
                # a session cannot tell one from an ordinary call without them
                # (#1059).
                self.last_data_flags = data_flags
                fragment = packet[10:size]
                # Each DATA fragment is an independent encrypt+MAC unit (#448),
                # so decrypt before concatenating the plaintext.
                if self._ano is not None and self._ano.active:
                    fragment = self._ano.unwrap(fragment)
                body += fragment
                if len(body) > self.max_message:
                    raise ProtocolLimitError(
                        f'message of more than {self.max_message} bytes'
                    )
                if data_flags & TNS_DATA_FLAGS_MORE:
                    continue
                return (TNS_DATA, bytes(body))
            return (packet_type, packet[8:size])

    def write_packet(self, packet_type: int, body: bytes) -> None:
        """Send one logical packet, fragmenting an oversized ``DATA`` response.

        A ``DATA`` response is fragmented the way the **real Oracle server**
        does — which is *not* how ``encode_packet`` (the client side) fragments.
        A client marks non-final fragments with the ``0x0020`` flag, but the
        client's :func:`assemble_packet` **ignores that flag** when reading a
        response: it treats a ``DATA`` packet as a continuation only when its
        size is exactly ``SDU-37`` or ``SDU-81``, and as final otherwise. So a
        full-``SDU`` fragment (what ``encode_packet`` emits) is misread as a
        complete response and the rest is dropped ("truncated DALC field").

        We therefore emit continuation packets of exactly ``SDU-37`` bytes and a
        final packet whose size is neither magic value. Non-``DATA`` packets
        (handshake replies) are small and go out whole.
        """
        if packet_type == TNS_DATA:
            if self.reply_prefix is not None:
                body = self.reply_prefix() + body
            if self.response_token is not None:
                # Captured from 23ai: `21 01 01 <body> 1d` for the first call of a
                # burst, `21 01 02 ...` for the second -- the marker, the token as
                # a ub4, then the ordinary reply. One response carries it, so it
                # is spent on the write that uses it.
                body = bytes([TTI_TOKEN]) + encode_sb4(self.response_token) + body
                self.response_token = None
            if self.end_of_response:
                # Once the capability is negotiated the client expects EVERY
                # response to end with this marker, not only a pipelined one --
                # it reads until the token and would otherwise wait for a
                # response that has already arrived (#1059).
                body = body + bytes([TTI_END_OF_RESPONSE])
            if self._ano is not None and self._ano.active:
                self._write_data_ano(body)
            else:
                self._write_data(body)
            return
        packet, rest = encode_packet(packet_type, body, self.sdu, self.large)
        self._sock.sendall(packet)
        assert rest is None, 'non-DATA packets do not fragment'

    def _write_data(self, body: bytes) -> None:
        # Continuation packets are sized SDU-37 (the client reads that exact size
        # as "more coming"); the final packet is the remainder. If the remainder
        # would itself land on a magic size (SDU-37 / SDU-81), peel off one more
        # continuation — sized SDU-81, the other value the client reads as "more"
        # — so the final packet is safe.
        cont_body = self.sdu - 37 - 10
        alt_body = self.sdu - 81 - 10
        max_final = self.sdu - 10
        magic = {self.sdu - 37, self.sdu - 81}
        data = body
        while len(data) > max_final:
            self._sock.sendall(
                encode_data_packet(data[:cont_body], TNS_DATA_FLAGS_MORE, self.large)
            )
            data = data[cont_body:]
        if len(data) + 10 in magic:
            self._sock.sendall(
                encode_data_packet(data[:alt_body], TNS_DATA_FLAGS_MORE, self.large)
            )
            data = data[alt_body:]
        final_flags = TNS_DATA_FLAGS_END_OF_RESPONSE if self.end_of_response else 0x0000
        self._sock.sendall(encode_data_packet(data, final_flags, self.large))

    def _write_data_ano(self, body: bytes) -> None:
        # Encrypted DATA fragmentation (#448) — shared with the client's
        # _encode_ano_packet via encode_ano_fragment; loop until it says no more.
        assert self._ano is not None
        data: bytes | None = body
        while data is not None:
            packet, data = encode_ano_fragment(data, self.sdu, self._ano, self.large)
            if data is None and self.end_of_response:
                # The last fragment carries END_OF_RESPONSE, as the plaintext
                # path's last packet does and 26ai's encrypted ones do (#1847): a
                # client reads a reply to that flag (#1845). The data flags follow
                # the 8-byte header.
                packet = (
                    packet[:8]
                    + struct.pack('>H', TNS_DATA_FLAGS_END_OF_RESPONSE)
                    + packet[10:]
                )
            self._sock.sendall(packet)

    def send_raw(self, packet: bytes) -> None:
        """Send an already-framed packet verbatim (it includes its TNS header).

        For the handshake replies (ACCEPT / PRO / DTY) that are built as whole
        packets; TTC payloads go through :meth:`write_packet` instead. Once ANO
        is active a pre-framed DATA packet is re-framed through the encrypted
        path (#448) — its body is encrypted + MAC'd like any other DATA — so the
        captured-template handshake replies (PRO/DTY) still go out encrypted.
        """
        if packet[4] == TNS_DATA:
            # Strip the 8-byte header + 2-byte data flags and re-emit the body
            # through the normal write path, so a pre-framed packet picks up
            # whatever framing this stream is on: encrypted once ANO is active
            # (#448), and the 4-byte packet length on a >= 315 session. The
            # callers build these with the legacy header, which is byte-identical
            # to what _write_data emits for a small packet on a legacy stream —
            # so this only changes what goes out when the stream is not legacy.
            body = packet[10:]
            if self.end_of_response:
                # The pre-framed handshake replies need the marker too: a live
                # server puts it on the PRO answer, the first DATA reply (#1059).
                body = body + bytes([TTI_END_OF_RESPONSE])
            if self._ano is not None and self._ano.active:
                self._write_data_ano(body)
            else:
                self._write_data(body)
            return
        self._sock.sendall(packet)


def listen_socket(host: str, port: int, backlog: int) -> socket.socket:
    """A listening socket for ``host``, in the family the host resolves to, so an
    IPv6 address binds (#2001). A wildcard (``''`` or ``'::'``) binds one
    dual-stack socket that serves IPv4 and IPv6 alike where the system can;
    ``'0.0.0.0'`` stays IPv4-only."""
    if host in ('', '::') and socket.has_dualstack_ipv6():
        return socket.create_server(
            ('', port), family=socket.AF_INET6, backlog=backlog, dualstack_ipv6=True
        )
    (family, *_) = socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE
    )[0]
    return socket.create_server((host, port), family=family, backlog=backlog)
