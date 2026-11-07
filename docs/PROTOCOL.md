# Oracle TNS/TTC Protocol Description

This document describes the Oracle Net Services protocol as used by
this library. seerdb communicates with Oracle Database over TCP/IP
(or TLS) using the Transparent Network Substrate (TNS) transport
layer and the Two-Task Common (TTC/TTI) presentation layer.

The structures here were derived clean-room from public artifacts —
python-oracledb's open-source thin-mode implementation (UPL / Apache
2.0), publicly-available reverse-engineering writeups, and packet
captures of authorized Oracle servers. See `CONTRIBUTING.md` for the
sourcing rules. Where the protocol differs between Oracle versions
(notably 11g vs 12c+) the document calls it out per section; seerdb
is currently validated against Oracle XE 11g.

## 1. Transport Layer: TNS Packets

All communication is framed into TNS packets. Every packet begins with an 8- or 10-byte header depending on type.

### 1.1 Packet Header

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Packet Length         |         Packet Flags          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Packet Type  |    Flags      |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Packet Length** (16 bits): Total packet size in bytes, including the header.
- **Packet Flags** (16 bits): Reserved, set to `0x0000`.
- **Packet Type** (8 bits): Identifies the TNS message type (see below).
- **Flags** (8 bits): Reserved, set to `0x00`.
- **Header Checksum** (16 bits): Set to `0x0000`.

> **Large-SDU header (#155).** When the negotiated protocol version is **≥ 315**
> (a 21c/23ai-era server, reached because seerdb advertises version 319 in the
> CONNECT — see §2), the header changes: the **Packet Length becomes 32 bits**
> (bytes 0–3), replacing the legacy 16-bit length + 16-bit packet-flags pair.
> The Packet Type stays at byte 4, so the rest of the layout is unchanged. The
> CONNECT and ACCEPT packets themselves stay in the legacy 16-bit form; only the
> post-ACCEPT DATA stream on a ≥315 session uses the 4-byte length. seerdb
> flips `self._large_packets` from the ACCEPT's negotiated version and
> `encode_packet` / `assemble_packet` take a `Large` flag. Older tiers (9i/10g/
> 11g) negotiate down below 315 and keep the legacy 16-bit header.

> **End-of-response framing (#155 → #132).** A ≥318 server's ACCEPT carries an
> extended `flags2` word (uint32 at accept-body offset 33); its
> `0x02000000` bit means the server supports **end-of-response** delimiting. When
> set, seerdb advertises `CCAP_TTC4 |= 0x20` in the DTY, and the server then
> ends **every** response with a `TTI_END_OF_RESPONSE` (29) marker. For an
> ordinary single call this marker simply trails the existing STATUS/OER
> terminal in the same packet (so it is consumed implicitly); it becomes load-
> bearing for request **pipelining** (#132), where several responses are stacked
> in one stream and the 29 marks where each ends. `_supports_eor` records the
> negotiation; `decode_packet` treats token 29 as a terminator.
>
> **The last packet is flagged too (#1845).** Such a server also sets the
> `0x2000` data flag (`TNS_DATA_FLAGS_END_OF_RESPONSE`) on the **last DATA
> packet** of a response; the packets before it carry `0x0000`, with no MORE
> flag. A large reply is many such packets, and nothing else on the wire says
> the message goes on: captured from 26ai with native encryption, a 51,200-character
> CLOB read is 12 packets of 8,156 bytes, flags `0x0000`, then one of 5,340
> bytes flagged `0x2000`. A reader must therefore read to that flag. Stopping
> wherever the bytes read so far end loses the rest whenever a read happens to
> end on a packet boundary. That is rare against a plaintext server, which writes
> a reply in one go, and the norm against an encrypting one, which writes packet
> by packet. Not every reply is flagged: 23ai starts with the fast-auth bundle
> reply, so the login's earlier replies are not. Nor is a **flush-out-binds
> request** (`07 00 13`, §6.9): the server sends it unflagged in the middle of a
> call and waits for the client's answer, so a reader still waiting for the flag
> deadlocks with it (captured from 23ai: the request with flags `0x0000`, then
> the real reply flagged `0x2000`). seerdb therefore reads to the flag once a
> reply has carried it (`_replies_marked`), hands on at once a packet that ends
> in the FOB token, and reads as before until a flagged reply has arrived.
>
> **Below 23ai nothing marks where a reply ends** (no end-of-response framing),
> so the reader cannot know from the wire alone. There the **decoder** decides
> (#1845): a reply decode that runs past the bytes read so far raises `Truncated`
> (the codec's readers do, and `decode_packet` does when it runs out before a
> terminal token), and the reader then takes the reply's next packet, appends
> it, and decodes again from the rows it began with. A server writes a reply
> whole, so a real continuation is already in flight; one that does not arrive
> within ten seconds is a decode fault and raised, never waited on. The LOB READ
> reply is walked incrementally instead, a content chunk that straddles packets
> carried over, so a large LOB is not decoded again per packet. The AQ replies
> decode the same way as `decode_packet`'s.

For **TNS_DATA** packets (type 6), an additional 2-byte field follows:

- **Data Flags** (16 bits): on the **client -> server** side, `0x0000` for a
  final (or only) packet and `0x0020` when more data packets follow. The
  **server -> client** side does *not* use this bit: every server data packet,
  final or not, carries Data Flags `0x0000` (verified by probe against XE 11g —
  26 consecutive fragments of a 50 KiB CLOB read were all `0x0000`). The server
  instead signals "more fragments follow" by **filling the packet to its
  maximum size** (see §1.3). Do not rely on `0x0020` to delimit an inbound
  message.

This makes TNS_DATA headers 10 bytes and all other packet headers 8 bytes.

### 1.2 TNS Packet Types

| Value | Name          | Direction      | Description                              |
|-------|---------------|----------------|------------------------------------------|
| 1     | TNS_CONNECT   | Client -> Server | Connection request with connect descriptor |
| 2     | TNS_ACCEPT    | Server -> Client | Connection accepted (SDU negotiated)     |
| 3     | TNS_ACK       | Both           | Acknowledgment                           |
| 4     | TNS_REFUSE    | Server -> Client | Connection refused with error message    |
| 5     | TNS_REDIRECT  | Server -> Client | Redirect to another address              |
| 6     | TNS_DATA      | Both           | Application data (TTC messages)          |
| 7     | TNS_NULL      | Both           | Keep-alive / null message                |
| 9     | TNS_ABORT     | Both           | Abort connection                         |
| 11    | TNS_RESEND    | Server -> Client | Request to resend the last packet        |
| 12    | TNS_MARKER    | Both           | Break / attention marker                 |
| 13    | TNS_ATTENTION | Both           | Attention signal                         |
| 14    | TNS_CONTROL   | Both           | Control message                          |

### 1.3 Packet Fragmentation (SDU)

Messages larger than the Session Data Unit (SDU) are split across multiple TNS_DATA packets. The SDU is negotiated during the connection phase (default: 8192 bytes). When a message is fragmented:

**Client -> server** (requests we send):

- All fragments except the last have Data Flags set to `0x0020`.
- The last fragment has Data Flags set to `0x0000`.

> **The reference thin client does NOT flag its fragments** (#968). That rule
> describes what *seerdb* sends, not what arrives. Captured from
> python-oracledb 4.0.1 connecting with `sdu=803`, its DATA_TYPES message goes
> out as four packets and every one of them carries `0x0000`:
>
> ```
> size=803 type=6 data_flags=0000     <- non-final, unflagged
> size=802 type=6 data_flags=0000     <- non-final, unflagged
> size=802 type=6 data_flags=0000     <- non-final, unflagged
> size=453 type=6 data_flags=0000     <- final
> ```
>
> So a server cannot find the end of an inbound message from the flags: it is
> expected to know the message's own structure. Nor can it find it by size — the
> client flushes as soon as the next *field* will not fit, so a non-final
> fragment can stop a byte or two short of the SDU (note the 803 / 802 above).
> Anything that reassembles an inbound message has to reason about the message,
> not the framing.

**Server -> client** (responses we receive):

- The server does **not** flag fragments at all — Data Flags are `0x0000` on
  every packet (see §1.1).
- Continuation is signalled by **packet size**: a non-final fragment is filled
  to the server's maximum packet size (observed as `SDU - 37` = 8155 bytes for
  the default 8192 SDU; a second framing yields `SDU - 81`). A packet smaller
  than that maximum is the final fragment.
- The receiver reassembles by concatenating fragment bodies until it sees a
  short (sub-maximum) packet. `assemble_packet()` / `recv()` in
  `seerdb/connection.py` implement exactly this size test.

In principle the size test cannot distinguish a final fragment that happens to
be *exactly* maximum-sized from a true continuation. In practice this has not
been observed as the cause of any desync (the server appears to avoid emitting
a maximally-sized final fragment), so the test holds for normal traffic.

**Reading a message that spans packets, and why the wait must be bounded**
(#848 / #851 / #868). The receive side has the harder half of this. A TTC
*message* is a byte stream; TNS packets are only its transport, and a large one
— an OALL8 with sizeable inline binds, a LOB `WRITE` — arrives as several `DATA`
packets. The reference thin client sends those continuations with **no `0x0020`
MORE flag**, so `read_packet` hands back only the first and parsing it runs off
the end.

That leaves exactly one signal that a message is complete: **the parser
succeeded**. The Mirror's codec primitives say the opposite by raising
`Truncated`, and the reader grows the buffer with further packets until the
parse stops complaining.

Two things have to hold for that to work, and neither did (#1097):

- **Every truncation says `Truncated`, not a bare `DataError`.** `decode_dalc`'s
  `IndexError` path raised the latter, so a request cut on that path was refused
  as unparsable instead of grown: a 4000-row `executemany` from python-oracledb
  came back `ORA-03115`.
- **A parse that stops early must not look like success.** The bind-row loop ends
  at the first byte that is not a `TTI_RXD`, which the end of a cut buffer also
  is, so an array DML cut between rows parsed "fine" with rows missing. The
  leftover continuation was then read as a new message (`unhandled message type
  7`) and the session desynced. The parser now checks the rows against the
  iteration count the `al8i4` declared. A batch whose rows are ALL empty sends no
  `TTI_RXD` at all and is not this case.

The catch is that `Truncated` means only "the parser ran off the end", and two
quite different things produce it: a message genuinely cut by the transport, and
a **decode fault inside a message that is already complete** — a decoder that
misreads a marker as a length asks for bytes that were never sent and looks
exactly the same. There is no positional or structural test that separates them,
because the faulty read also runs past the buffer's end.

So the wait is **bounded**, and the invariant is worth stating plainly: *the
Mirror never blocks indefinitely on a request it has begun parsing.* A genuine
continuation is already in flight — the client wrote the whole message in one
call — so a couple of seconds is a vast margin, while a message that will never
complete is refused (`ORA-03115`) like any other request the server cannot
serve. Without that bound a single decode fault hangs the session with the
client blocked on its reply: the silent-hang failure mode of §(unimplemented
calls) returning through a different door, and one such wedge stalls an entire
conformance run.

The timeout is a backstop for decoder bugs, not a substitute for correct
decoders — the fault that exposed it (§12.2, the `0xFD` marker) was fixed so the
bound is rarely reached rather than load-bearing.

The **Mirror** (server side) fragments a large `DATA` response this same way —
`seerdb/server/framing.py::PacketStream._write_data` emits continuation packets
of exactly `SDU-37` bytes and a final packet of the remainder. It must *not*
reuse `encode_packet` (the client-side form), which fills fragments to the full
SDU and marks them `0x0020`: the client ignores that flag and would read the
first full-SDU fragment as a complete response, dropping the rest. It also
guards the edge case above — if the remainder would land on a magic size
(`SDU-37` / `SDU-81`), it peels off one more `SDU-81` continuation so the final
packet is unambiguously short.

### 1.4 Break / reset markers (TNS_MARKER)

A `TNS_MARKER` (type 12) is an out-of-band break/attention signal with a 3-byte
body: `01 00 01` = **break** (interrupt the call), `01 00 02` = **reset**
(clear the line). The server uses them to delimit a **cancelled call**: on 21c+
*every errored call* — even a trivial `SELECT` against a missing table — comes
back as `break` + `reset`, then the inline error (`ORA-00942`, `ORA-01013`, …)
DATA. This is normal server behaviour, confirmed by capturing python-oracledb
through a logging proxy (`tools/capture_proxy.py`).

The receive-side handshake that keeps the stream in sync (#45):

- **One reset per break episode, then drain.** Answer the server's break with
  **exactly one** reset marker (`01 00 02`) and then read further markers —
  including the server's terminal reset — *without replying*, until the real
  DATA packet arrives. python-oracledb does **2 server markers : 1 client
  reset** per cancel; matching that ratio is the whole fix. Replying to *every*
  marker (the old seerdb behaviour) ping-pongs resets into a storm, and a
  stray client reset landing while the server streams a large LOB makes the
  client discard that content — the CLOB-comes-back-empty desync.
- **Preserve the post-marker bytes.** A `break|reset|error` (or
  `break|reset|LOB-content`) often arrives coalesced in one TCP read, so `recv()`
  returns the marker but keeps the trailing bytes (`self._pending`) for the next
  call instead of dropping them; otherwise the inline error/result is lost and
  the next operation reads it misframed. (Preserving *without* the one-reset
  rule above was a dead end — the still-storming bytes crash the packet parser;
  both halves are required.)

**The server side for sqlplus (the Mirror, #2036).** The same rule applies with
the roles swapped. Ctrl-C in sqlplus 23.26 against a live 18c went like this:
1. The break goes out of band (TCP urgent data).
2. The client sends a reset in band.
3. The server answers with **one** reset and then the ORA-01013 OER (`user
   requested cancel of current operation`, no error position, so the caret sits
   at column 0).
4. sqlplus pings (`TTI_PING`, function `0x93`), and the server acks with a
   TTI_STA (`09 01 00 00 00 <seq>`).
5. The next statement runs.

Through the Mirror the interrupt arrives in band (`01 00 03`) ahead of the
reset. The OCI loop used to answer every marker with a reset, so the client's
own reset drew another, and the two sides exchanged resets without end. Now an
interrupt or break gets one reset, and the client's reset is awaited, whatever
it sends first dropped. A lone reset gets the one reset. Either way the cancel's
OER follows, and the ping is relayed to the backend and acknowledged.
- seerdb implements both in `OracleConnect._next_data_packet` (and its async
  twin), with a `self._in_break` latch so at most one reset is sent per episode,
  cleared when a real DATA packet returns. `_handle_response`, `_read_lob_response`
  and the login loop all receive through it.
- seerdb never *initiates* a break (no client-side Ctrl-C/interrupt path), so
  only the server-break case above arises.

The **send side is symmetric, and a server must honour it**: a client that
sends a marker blocks until it gets one back. A thick-OCI client (sqlplus)
sends a bare reset (`01 00 02`) to resynchronise the line — after a cancelled
call, or after a reply it could not line up — and then sends nothing further
until the server answers. A server that silently drops the marker leaves the
client waiting until its own timeout with the session wedged, which is not
distinguishable on the wire from a hung server. Answer with a single reset, the
same one-per-episode rule the receive side follows: echoing every marker
ping-pongs the two ends into the same storm described above. Observed against
sqlplus 23.26 through a logging proxy.

### 1.5 Transports (TCP, TCPS, and the `ws://` / `wss://` seerdb extension)

Oracle carries TNS over TCP (`PROTOCOL=TCP`) or TLS (`PROTOCOL=TCPS`). seerdb
adds a **WebSocket transport, a seerdb extension** (not Oracle; #1988):
`ws://host:port/service` and `wss://host:port/service`, as an Easy Connect
string or a descriptor with `PROTOCOL=WS` / `WSS`. No Oracle client or server
speaks it — python-oracledb 26.0.1 refuses `ws://`/`wss://` with DPY-4021 — so
it reaches only a WebSocket bridge or a seerdb Mirror that speaks it (#1989).

The framing is a **byte pipe**: TNS packets ride WebSocket **binary** messages,
and the packet framer (§1.1, §1.3) reassembles them exactly as over TCP. The
TNS and TTC layers are unchanged. seerdb writes one whole packet per send, so
in practice each binary message carries one TNS packet, which gives a
protocol-aware gateway natural message boundaries — but a receiver must not
rely on it and reassembles from the packet length as always. A WebSocket close
frame is read as a socket EOF. A WebSocket has no out-of-band data, so break
never uses the OOB urgent byte over this transport; it always sends the in-band
`TNS_MARKER_TYPE_INTERRUPT` packet (§1.4).

TLS: `wss://` is WebSocket-over-TLS, terminated by the WebSocket layer, not a
second TNS-level TLS; `ws://` is unencrypted and for local testing. The DSN
`/segment` after `host:port` stays the Oracle **service name** (as for
`tcps://`), and the WebSocket resource path is `/`. A browser-facing endpoint
is outside the Mirror's stated threat model and is gated on the security
milestone (#52).

## 2. Connection Phase

### 2.1 TNS_CONNECT (Client -> Server)

The client sends a TNS_CONNECT packet containing a fixed header and a connect descriptor string.

**Fixed header fields** (74 bytes before the connect data, #155):

| Offset | Size | Field                        | Value             |
|--------|------|------------------------------|-------------------|
| 0      | 2    | Protocol version             | `0x013F` (319)    |
| 2      | 2    | Lowest compatible version    | `0x012C` (300)    |
| 4      | 2    | Global service options       | `0x0401`          |
| 6      | 2    | Session Data Unit (SDU)      | `0x2000` (8192)   |
| 8      | 2    | Transport Data Unit (TDU)    | `0x2000` (8192)   |
| 10     | 2    | Protocol characteristics     | `0x4F98`          |
| 12     | 2    | Max packets before ACK       | `0x0000`          |
| 14     | 2    | Hardware byte order          | `0x0001` (big-endian) |
| 16     | 2    | Connect data length          | (computed)        |
| 18     | 2    | Connect data offset          | `0x004A` (74)     |
| 20     | 4    | Max receivable connect data  | `0x00000000`      |
| 24     | 2    | ANO flags                    | `0x0101` (ANO-capable; see §33) |
| 26     | 24   | Reserved                     | `0x00...`         |
| 50     | 4    | Session Data Unit (large)    | `0x00002000` (8192) |
| 54     | 4    | Transport Data Unit (large)  | `0x00002000` (8192) |
| 58     | 4    | Connect flags 1              | `0x00000000`      |
| 62     | 4    | Connect flags 2              | `0x00000001` (OOB check) |

seerdb advertises **protocol version 319** (`#155`) — the version a 23ai
server needs to negotiate the end-of-response framing pipelining (`#132`) rides
on. The 319 layout adds the 16-byte trailer (offsets 50–66: large SDU/TDU +
connect flags) and moves the connect data to offset 74. The `300` lowest-
compatible floor keeps older servers working: 9i (max version 312), 10g, and
11g negotiate down (`min(their_max, 319)`) and fall back to the legacy 16-bit
packet framing (§1.1); only ≥315 servers (21c/23ai) use the large framing. The
CONNECT packet itself is sent in the legacy 16-bit-length envelope regardless.

**Connect descriptor** (at offset 74): An Oracle Net connect descriptor string in the standard `(DESCRIPTION=(...))` format:

```
(DESCRIPTION=
  (CONNECT_DATA=
    (SERVICE_NAME=<service>)
    (CID=(PROGRAM=<app>)(HOST=<client_host>)(USER=<user>)))
  (ADDRESS=
    (PROTOCOL=TCP)
    (HOST=<server_host>)
    (PORT=<port>)))
```

When SSL/TLS is used, `PROTOCOL=TCPS`.

Two optional parts go where python-oracledb 26.1 writes them (#2456):
- `(EXPIRE_TIME=<minutes>)` opens the DESCRIPTION, when `expire_time` is above 0. The client also turns TCP keepalive on, with the first probe after that many minutes of quiet.
- `(INSTANCE_NAME=<instance>)` follows the service name, before `(SERVER=...)`.

The listener acts on the instance name. Measured on 9i, 10g, 11g and 23ai (2026-11-04): the instance it serves connects, and one it doesn't know is refused with ORA-12521, *connection refused by the listener*. The Mirror doesn't check it yet (#2471).

**A descriptor over 230 bytes** does not ride in the CONNECT (#1768). A server
reads at most 230 bytes of connect data from the CONNECT packet. Given more, it
waits for data that never comes and the connect hangs. The limit was measured on
10g, 11g, 21c and 23ai: a 230-byte descriptor connects, a 231-byte one times out.

A longer descriptor goes in a TNS_DATA packet sent straight after the CONNECT:
- The CONNECT still states the full length (offset 16) and offset 74, but ends
  at offset 74, carrying no connect data.
- The DATA packet follows the CONNECT, with data flags `0x0000`, in the legacy
  16-bit envelope (nothing has been negotiated yet).

Captured from python-oracledb 26.0.1 with a 238-byte descriptor:

```
C2S CONNECT 0x004a bytes   ... connect data length 0x00ee, offset 0x004a
C2S DATA    0x00f8 bytes   00f8 0000 06 00 0000 | 0000 | (DESCRIPTION=...
```

Every bed from 8i to 26ai accepts the split form. Older listeners still refuse
a very long descriptor outright: 9i and 10g refuse a 3000-byte one.

### 2.2 TNS_ACCEPT (Server -> Client)

The server responds with TNS_ACCEPT. The client extracts the negotiated SDU from offset bytes 4-5 (16-bit big-endian) of the accept body. The negotiated SDU is used for all subsequent packet fragmentation.

### 2.3 TNS_REFUSE (Server -> Client)

If the server refuses the connection, it sends TNS_REFUSE with a 4-byte header (2 reserved bytes + 2-byte error length) followed by an error message string.

### 2.4 TNS_REDIRECT (Server -> Client)

The server may redirect the client to a different address — common with
shared-server (the listener hands off to a dispatcher), RAC, and listeners
that register services dynamically. The redirect body (everything after the
8-byte header, often after a 2-byte data-length) is an ASCII connect
descriptor carrying the new address, e.g.
`(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=...)(PORT=...))...)`. It may also
echo the original `CONNECT_DATA` (whose `CID` holds the *client* host) after a
NUL, so the parser scopes to the `ADDRESS` block for the reconnect target.

seerdb follows the redirect: it pulls `HOST`/`PORT` out of the `ADDRESS`,
closes the socket, reconnects to that address, and re-sends `TNS_CONNECT` to
restart the handshake there. Redirects are capped (5) so a looping listener
fails fast rather than spinning. Sync and async (`§handle_login`).

### 2.5 TNS_RESEND (Server -> Client)

Requests the client to re-send the TNS_CONNECT packet. If using TLS, the client renegotiates the TLS session before resending.

### 2.6 Server-side handshake — a captured 11g exchange (the Mirror)

The server side of §2.1–2.5, as a real Oracle XE 11.2.0.2 listener answers it.
Captured through `tools/capture_proxy.py` with `sqlplus` 11.2 as the client; the
exact bytes live in `tests/handshake_11g.py`. This is what the Mirror server
(`seerdb/server/`) must reproduce for an 11g client.

| # | Dir | Packet   | Size | Notes                                             |
|---|-----|----------|------|---------------------------------------------------|
| 1 | C→S | CONNECT  | 212  | connect descriptor                                |
| 2 | S→C | RESEND   | 8    | header only — asks the client to re-send CONNECT  |
| 3 | C→S | CONNECT  | 212  | identical re-send                                 |
| 4 | S→C | ACCEPT   | 32   | negotiated **version 0x013a = 314**               |
| 5 | C→S | DATA/ANO | 161  | Native Services negotiation, a `deadbeef` container (§33.2) |
| 6 | S→C | DATA/ANO | 127  | its null-negotiation reply: no cipher, no checksum (§4.1.1) |
| 7 | C→S | DATA/PRO | 38   | `TTI_PRO` request: versions `06…00` + the platform (§4.1) |
| 8 | S→C | DATA/PRO | 238  | `TTI_PRO` reply: version, banner, capability block (§4.1) |

then the data-type round (§4.2.1), the O5LOGON auth rounds (§4) and the query.
This is the sqlplus (OCI) client: it opens with an ANO round, which a thin client
skips (its first DATA packet is the `TTI_PRO` request, and its PRO reply is the
same 238 bytes). The Mirror names its replies by these rounds:
`encode_ano_null_reply`, `encode_pro_reply` (`oci=True` for sqlplus's form of the
capability block) and `encode_oci_dty_reply` (#1979).

**Auth lives with the backend.** O5LOGON is *mutual* — the server must itself
know the client's secret to prove itself (it never sees the client's password,
only a key derived from it), so the Mirror needs each user's plaintext password
to build the challenge. It holds none of its own: `handle_login` obtains the
secret from `backend.authenticate(username)` (returns the secret, or `None` to
reject), keeping identity a property of the data source — the same place Oracle
stores it. The example backends authenticate against a `credentials` map passed
in; a real backend could consult a table instead.

Auth is verified in **both** directions, like Oracle. The server proves itself
via `AUTH_SVR_RESPONSE` (the client's `validate()` checks it), *and* the server
verifies the client's `AUTH_PASSWORD` proof (`verify_password` — decrypt it
under the derived ConnKey and match the account password). Without the second
half a client that simply ignores the server proof would be served with any
password. An unknown user **or** a wrong password gets an **ORA-01017**
("invalid username/password; logon denied") OER in place of the next auth reply,
which the client raises out of `connect()` — the same denial Oracle gives,
rather than a soft connection that fails later.

**ACCEPT specifics for 11g.** Version **314** is `< 315` (`TNS_VERSION_MIN_LARGE_SDU`),
so the connection uses **legacy 2-byte packet framing** — no large-SDU uint32
trailer. It is also `< 318` (`TNS_VERSION_MIN_OOB_CHECK`), so there is **no
extended flags2 / end-of-response** negotiation. The negotiated SDU is the
16-bit field at accept-body offset 4–5 (`8192` here). seerdb's own client
parsers (`_parse_accept_sdu` / `_parse_accept_eor`) decode the captured ACCEPT
without error — the capture is conformant, not a guess.

Unlike modern versions, **PRO and DTY are ordinary TTC `DATA` messages**, not
distinct TNS packet types — the server's replies are DATA-framed payloads.

**ACCEPT specifics at ≥ 315 (large SDU).** From `TNS_VERSION_MIN_LARGE_SDU` the
body grows past the legacy 24 bytes and the SDU/TDU move: the **16-bit pair at
offsets 4–7 is zeroed** and the real values become **`ub4` SDU at offset 24** and
**`ub4` TDU at offset 28**. Captured live:

| Server | Version | Body len | SDU16/TDU16 | SDU32 @24 | TDU32 @28 | flags2 @33 |
|--------|---------|----------|-------------|-----------|-----------|------------|
| XE 11.2    | 314 | 24 | 8192 / 65535 | –    | –       | –          |
| XE 21c     | 318 | 37 | 0 / 0        | 8192 | 8192    | `0x00000000` |
| 23ai/26ai  | 320 | 53 | 0 / 0        | 8192 | 2097152 | `0x1a000000` |

A client reads `flags2` only at ≥ 318 (`TNS_VERSION_MIN_OOB_CHECK`), so a server
below that never advertises end-of-response whatever it puts there. **The version
number alone drives the framing switch**, and it applies to everything *after*
the ACCEPT: the CONNECT and ACCEPT packets themselves stay in the legacy 16-bit
form (§1.1), and both ends move to the 4-byte packet length from the next `DATA`
onward.

The version scale is anchored by those three captures (11.2 → 314, 21c → 318,
23ai → 320). **12.1 and 12.2 fall in the gap and are not captured here**; the
Mirror takes 12.2 as **316**, which is what matters behaviourally — large-SDU
framing, no end-of-response.

## 3. Presentation Layer: TTC (Two-Task Common)

Once the TNS connection is accepted, all further communication occurs inside TNS_DATA packets using the TTC/TTI protocol. Each TTC message begins with a 1-byte token identifier.

### 3.1 TTC Token Types

| Value | Name    | Description                                |
|-------|---------|--------------------------------------------|
| 1     | TTI_PRO | Protocol negotiation                       |
| 2     | TTI_DTY | Data type negotiation                      |
| 3     | TTI_FUN | Function call (wraps a function ID)        |
| 4     | TTI_OER | Oracle error response                      |
| 6     | TTI_RXH | Row transfer header                        |
| 7     | TTI_RXD | Row data                                   |
| 8     | TTI_RPA | Return parameter (key-value pairs)         |
| 9     | TTI_STA | Status (transaction complete)              |
| 10    | TTI_ROW | Row descriptor                             |
| 11    | TTI_IOV | I/O vector (bind direction indicator)      |
| 12    | TTI_UDS | User describe information                  |
| 13    | TTI_OAC | Oracle Access Column descriptor            |
| 14    | TTI_LOB | LOB data                                   |
| 15    | TTI_WRN | Warning message                            |
| 16    | TTI_DCB | Describe information (column metadata)     |
| 17    | TTI_PFN | Piggyback function                         |
| 19    | TTI_FOB | Flush out binds                            |
| 21    | TTI_BVC | Bit vector for changed columns             |

### 3.2 TTC Function IDs (TTI_FUN)

Function calls are sent as `TTI_FUN` messages with a function ID byte:

| Value | Name         | Description                        |
|-------|--------------|------------------------------------|
| 2     | TTI_OPEN     | Open cursor                        |
| 4     | TTI_EXEC     | Execute statement                  |
| 5     | TTI_FETCH    | Fetch rows                         |
| 9     | TTI_LOGOFF   | Log off                            |
| 14    | TTI_COMMIT   | Commit transaction                 |
| 15    | TTI_ROLLBACK | Rollback transaction               |
| 20    | TTI_CANCEL   | Cancel operation                   |
| 48    | TTI_STRT     | Startup database                   |
| 49    | TTI_STOP     | Shutdown database                  |
| 59    | TTI_VERSION  | Get server version                 |
| 71    | TTI_ALL7     | Generic execute (Oracle 7)         |
| 81    | TTI_3LOGON   | O3LOGON authentication (legacy)    |
| 82    | TTI_3LOGA    | O3LOGON response                   |
| 94    | TTI_ALL8     | Generic execute (Oracle 8+)        |
| 96    | TTI_LOBOPS   | LOB operations                     |
| 103   | TTI_TXSE     | Transaction start                  |
| 104   | TTI_TXEN     | Transaction end                    |
| 105   | TTI_OCCA     | Close all cursors                  |
| 107   | TTI_80SES    | Session operations (Oracle 8)      |
| 115   | TTI_AUTH     | O5LOGON authentication             |
| 118   | TTI_SESS     | Session setup                      |
| 120   | TTI_CANA     | Cancel / close cursor(s)           |
| 125   | TTI_KPN      | Key-pair notification              |
| 135   | TTI_SCID     | Session/connection ID              |
| 138   | TTI_SPFP     | Set protocol feature parameters    |
| 147   | TTI_PING     | Ping                               |

## 4. Authentication Phase

After TNS connection acceptance, the client and server negotiate the TTC protocol, exchange data type capabilities, and perform authentication. The sequence is:

```
Client                              Server
  |                                    |
  |--- TNS_CONNECT ------------------->|
  |<-- TNS_ACCEPT ---------------------|
  |                                    |
  |--- TTI_PRO (protocol negotiation)->|
  |<-- TTI_PRO (server protocol) ------|
  |--- TTI_DTY (data types) ---------> |
  |<-- TTI_DTY (data types) ---------- |
  |--- TTI_FUN/TTI_SESS (session) ---> |
  |<-- TTI_RPA (auth challenge) -------|
  |--- TTI_FUN/TTI_AUTH (auth resp) -->|
  |<-- TTI_RPA (auth result + ver) ----|
  |                                    |
  |        [connected]                 |
```

### 4.1 Protocol Negotiation (TTI_PRO)

Client sends:
```
TTI_PRO | 6 | 5 | 4 | 3 | 2 | 1 | 0 | "<client banner>" | 0
```
- `6, 5, 4, 3, 2, 1, 0`: Protocol version vector (descending preference).
- `"<client banner>"`: NUL-terminated client self-identifier. A real Oracle
  client sends its platform (e.g. `x86_64/Linux`); seerdb sends
  `seerdb <machine>/<system>` (e.g. `seerdb x86_64/Linux`) so the value both
  identifies the driver and carries the platform (#381). The server accepts an
  arbitrary length here (verified 9i–23ai). Earlier releases sent the bare
  `python`.

The server replies with a TTI_PRO message carrying its own capabilities — this
is where the client learns the server's TTC field version and negotiates the
effective one (`min(client, server)`). Layout (`decode_token_pro`):
```
TTI_PRO | server_version (UB1) | 0 |
  banner (NUL-terminated) | charset_id (UB2 LE) | server_flags (UB1) |
  num_elem (UB2 LE) | num_elem × 5 bytes (charset element array) |
  fdo_length (UB2 BE) | fdo[fdo_length] |
  compile_caps (UB1 len + bytes) | runtime_caps (UB1 len + bytes)
```
Each charset element is a fixed 5-byte record `<a> 03 <b> 03 <flag>`: two operand
bytes, each followed by a constant `03` tag, then a flag. The 11.2 server sends ten
— a hub operand (`0x66`) paired both ways with `{0x40, 0x48, 0x52, 0x61, 0x1f}`,
flag `0x01` except the forward `0x66`→`0x1f` pair (`0x08`); the operands are the
server's NLS charset-conversion codes (`0x1f` is charset 31, WE8ISO8859P1).

The `fdo` (Fixed Data Object) is a length-framed charset descriptor:
`u32 BE content-length | 01 | secA_len | secB_len | 50-byte type-representation
vector | 83 | db_charset (UB2 BE) | national_charset (UB2 BE) | 03 | zero pad`.
A client locates the pair at offset `6 + fdo[5] + fdo[6]` (the two section lengths)
and reads the national charset from it; the DB charset sits just before. Against
11g these are AL32UTF8 (873) and AL16UTF16 (2000). The type-representation vector
and the `0x83`/`0x03` frame tags are not interpreted by clients.

The server's field version is `compile_caps[7]` (`CCAP_FIELD_VERSION`, §4.2).
seerdb stores the negotiated minimum as `connection.field_version` and sends
it back in its own DTY; against 11g both sides are `6` (11.2). `server_version`
is the TTC protocol byte (`6` = 8.1+), distinct from the product release that
arrives later in the auth result (`AUTH_VERSION_NO`).

#### 4.1.1 PRO dialects — the server mirrors the client (server-side / the Mirror)

The two clients do not speak different PRO dialects: **sqlplus (thick OCI)
runs one more round first**. Its first DATA packet is a `DE AD BE EF` Native
Services (ANO) negotiation, and only then the same `TTI_PRO` request a thin
client opens with (§2.6 has the 11g capture). Captured against the same 11g XE
listener, round by round:

| round | thin (oracledb, seerdb) | sqlplus 11.2 |
|-------|-------------------------|--------------|
| ANO negotiation | — | request 161 B, null reply **127 B** |
| `TTI_PRO` | reply **238 B** | the same reply, **238 B** |
| data type | flag `01` + type table; reply **924 B** | flag `02`, no table; the 16-byte reply of §4.2.1 |

So the first message a server reads tells it which client it has: a
`deadbeef` container means sqlplus / thick OCI, a `TTI_PRO` token a thin client.
A server must answer the ANO round when it comes, then the same PRO round for
both, and the data-type round in the form the client's flag asks for.
`decode_token_pro` reads only a `TTI_PRO` reply, so sending the ANO reply where a
thin client expects PRO fails to parse.

seerdb's server (the Mirror) serves **both** clients (#265). `serve_login`
inspects the first message — `opens_with_oci_ano` checks whether its TTC payload
leads with the `deadbeef` magic — and answers each round with the reply named
for it (#1979). sqlplus gets `encode_ano_null_reply` (127 B), then
`encode_pro_reply(oci=True)` (238 B, the same capability block a thin client
gets) and `encode_oci_dty_reply` for its data-type round (§4.2.1). A thin client
gets `encode_pro_reply` (238 B) and then `encode_dty_reply` (924 B). All of them
are built so the client negotiates field version 6.

**The 127 B `deadbeef` reply is an ANO null-negotiation response** (#564). The
name is not incidental: `0xDEADBEEF` is the ANO / Native Services container magic
(§33.2). sqlplus / thick OCI opens its login with an ANO negotiation, and the
server answers by selecting the *null* algorithm for every service, so no cipher
or MAC is activated and the session stays plaintext. This is the byte-identical
twin of the reply the thin ANO path (§33) replays as its null response — it *is*
that response. The Mirror builds it field-by-field from the ANO codec
(`build_ano_null_reply`), no longer a verbatim blob. Its 117 B TTC payload
decodes (via the project's own `decode_ano`) as a container plus four services:

| Field | Value | Note |
|-------|-------|------|
| container magic / length / **version** / count | `DEADBEEF` / 117 / **`0x00000000`** / 4 | the sqlplus/OCI stamp — a modern thin client's container stamps `0x0B200200` here instead |
| supervisor (svc 4) | version `0x0B200200`, status `31` (OK), service-array `[4, 1]` | announces the supervisor + auth services |
| auth (svc 1) | version `0x0B200200`, status `0xFBFF` | (a thin client's auth status is `0xFCFF`) |
| encryption (svc 2) | version `0x0B200200`, selected-algo **`0`** | null cipher — plaintext |
| data-integrity (svc 3) | version `0x0B200200`, selected-algo **`0`** | null checksum — no MAC |

The container version is `0x00000000` while every *service* still echoes the
modern `VERSION_11_2_0_2` (`0x0B200200`) — the one wrinkle that separates this reply
from `encode_ano_response` (§33), together with the `0xFBFF` auth status and the
null algorithm selections. `tests/test_handshake_generation.py` pins the built
bytes to the live 11g capture.

**What selects the OCI marshalling is the client's data-type request, not the
server** (#1764). sqlplus and a thin client send the same `TTI_PRO` request
shape, and get the same PRO reply. Its 100-byte FDO, including the 50-byte
type-representation vector, is byte-identical from 10g, 11g and 23ai, to
sqlplus 10.2, 11.2, 23.26 and a thin client alike. What differs is the data-type
message that follows:

| client | encoding flag | type table |
|--------|---------------|------------|
| thin (oracledb, seerdb) | `01` | each type with its representation (1137 B from seerdb) |
| sqlplus 10.2 / 11.2 | `02` | **none** |

With no table, the server uses its native representations: the fixed 4-byte
little-endian lengths and 8-byte pointer fields of §4.1.2. In place of the table,
sqlplus sends the time-zone block, from 11.2 a ub4 timezone-file version, and the
national charset. This is sqlplus's data-type round, §4.2.1.

#### 4.1.2 The deadbeef / OCI auth phase (server-side / the Mirror)

Past the handshake, sqlplus / thick OCI marshals the whole O5LOGON exchange
differently from the thin form, but over the **same mutual-auth crypto** (§4.3).
The Mirror (`seerdb/server/`) drives it from captured 11g templates so a real
sqlplus 11.2 logs in — verified live. The rounds:

1. **Extra data-type round.** Unlike a thin client (which jumps from DTY to
   OSESSKEY), sqlplus runs a third negotiation: a `ttc=02` request the server
   answers with a fixed **26-byte** reply, *then* OSESSKEY. The reply is
   `TTI_DTY`, the 11-byte time-zone block, then the ub4 timezone-file version,
   but only for a client whose request carried one. sqlplus 10.2's request has
   none (13 bytes behind its capabilities, against 11.2's 17), and 10g and 11g
   both answer it without the ub4 (a 22-byte packet). The four bytes it doesn't
   expect draw a break (#1764).
2. **OCI field marshalling.** The `TTI_FUN` auth messages (OSESSKEY, AUTH)
   replace thin's `0x01` pointer bytes with an **8-byte `FE FF FF FF FF FF FF FF`
   indicator** (`0xFFFFFFFFFFFFFFFE` LE) and use **fixed 4-byte little-endian
   ub4** lengths (not Oracle variable-length ub4). The header up to the username
   is constant, so the ub1-length-prefixed username sits at a **fixed offset 51**
   (`parse_osesskey_oci` / `parse_auth_response_oci`).
   The indicator is 11.2's way of filling an 8-byte **pointer field**: sqlplus
   10.2 writes the client's own 64-bit address in the same fields (`80 a8 ba e2
   fd 7f 00 00`), at the same offsets 3, 19, 35 and 43. What a server can rely on
   is that a present field is non-zero (`oci.pointer_present`). With that, and
   the type round of item 1, sqlplus 10.2 logs in to an 11.2 Mirror. It takes
   the 11.2-sized challenge and result as they are, although 11g sends it shorter
   ones (310 and 1653 bytes against 382 and 1757) (#1764).
3. **Challenge** (S→C, **390 B**). A fixed template; only `AUTH_SESSKEY` (96 hex)
   and the `AUTH_VFR_DATA` salt (20 hex — a **10-byte** salt, vs thin's 16) vary.
   `encode_challenge_oci` substitutes those two fixed-size values in place.
4. **AUTH** (C→S, ~906 B). Each key-value pair is `<key> <ub4 declared-len>
   <DALC value>`: a fixed 4-byte length precedes a **DALC-chunked** (`0xFE`-marked)
   uppercase-hex value — the same chunk encoding seerdb's client `decode_dalc`
   reads. Un-hex gives the client's **48-byte `AUTH_SESSKEY`** (→ ConnKey via
   `derive_conn_key`) and its **32-byte `AUTH_PASSWORD`** proof (→ `verify_password`).
5. **Result** (S→C, **1762 B**). A fixed template carrying version/DB/NLS
   descriptors plus `AUTH_SVR_RESPONSE`; only the proof (96 hex) and the
   session-identity fields (session id, serial, server PID — which the client
   does not cryptographically check) vary. `encode_result_oci` substitutes the
   proof in place and keeps the template's identity values.

**A refused login** (#1290). A live server refuses sqlplus (wrong password, or
unknown user after the OSESSKEY) in two steps:
1. it opens a **break / reset marker exchange** (`01 00 01`, then `01 00 02`),
   and waits for the client's own reset;
2. it sends, in place of the reply to the refused call, an OCI OER carrying the
   ORA error and its text.

That OER is the error envelope (§36) without the statement fields: a success
status byte `01`, zero category, error position and command type, a zero
sequence, the refused call's own sequence at offset 49 (3 for the AUTH), and
zero at offset 52. At the 12c band it widens like every OER. A thin-dialect
OER, which the Mirror used to send, is lost on sqlplus: it sees only the
connection close and reports ORA-03113. `encode_login_refusal_oci` reproduces
11g's refusal byte for byte.

**`AUTH_SVR_RESPONSE` is 48 bytes here, not thin's 16.** The real 11g listener
sends `AES-CBC(nonce16 ‖ "SERVER_TO_CLIENT" ‖ PKCS7-pad, ConnKey)` — a 16-byte
nonce, the marker, and a full 0x10 pad block. The client finds the marker
substring after decrypting, so the nonce is an unchecked filler
(`server_proof_oci`). Reconstructing it byte-for-byte from a decrypted live
capture confirmed the structure.

**From 12.1 the login takes the 12c-band shape (#1282).** Once the ACCEPT says
315 or later, a modern sqlplus (23.26 measured) hangs up on the 11g challenge
above. What an 18c server sends instead, and what the Mirror now sends at field
version 12.1+:

- **Challenge: six pairs, not three.** `AUTH_SESSKEY` (a **32-byte** server
  session, 64 hex), `AUTH_VFR_DATA` (a 16-byte salt, flag **`0x4815`** — the 12c
  SHA-2 verifier), `AUTH_PBKDF2_CSK_SALT`, `AUTH_PBKDF2_VGEN_COUNT` (`4096`),
  `AUTH_PBKDF2_SDER_COUNT` (`3`), `AUTH_GLOBALLY_UNIQUE_DBID`. The crypto is the
  thin 256-bit scheme (§4.5): `KeySess = SHA-512(PBKDF2-SHA512(pw, salt ‖
  "AUTH_PBKDF2_SPEEDY_KEY", 4096) ‖ salt)[:32]`. The client still answers with
  the §4.1.2 AUTH form, only with a 32-byte session key.
- **`CCAP_LOGON_TYPES` needs `0x20` (O7LOGON).** The 11.2 identity advertises
  `0x0F`; 18c sends `0x6F`. With the SHA-2 challenge but without that bit,
  sqlplus derives a different key and the login fails. Setting `0x20` alone
  (`0x2F`) is enough, and `0x40` alone (`0x4F`) is not. The Mirror sets it only
  in the deadbeef DTY reply's capability block; the thin PRO reply keeps `0x0F`.
- **Both auth trailers are 144 bytes, not 136.** They are the same OER frame
  followed by eight zero bytes. Apart from those eight bytes, 18c's differ from
  the Mirror's only at the per-message counter (offsets 5–6) and at a leaked
  native pointer (offsets 72–77).

With these, sqlplus 23.26 logs in to a 12.1 Mirror.

**The layout past login follows the advertised field version.** sqlplus sends
the same statement as 321 bytes to 11g (field version 6), 351 to a Mirror
advertising 12.1 (7) and 385 to 18c (11). There is no 12.1 server to capture, so
from 12.1 the deadbeef DTY reply advertises **18c's field version** and the
Mirror serves sqlplus in 18c's layout, while thin clients keep 12.1. sqlplus
accepts that over a 12.1 ACCEPT.

**That band is per client (#1291).** An older sqlplus cannot use it: sqlplus
11.2 answers the 12c-band challenge with ORA-28041. So, as a real server does,
the Mirror serves each sqlplus at the version the client speaks. That version
is in the client's capability block, and in this dialect the block arrives one
round later than the Mirror's round names suggest: the "DTY" round carries
sqlplus's `TTI_PRO`, and the "TYPE" round the DTY proper. sqlplus does not
come down to what the Mirror advertised, as a thin client does. sqlplus 23.26
sends 27 and sqlplus 11.2 sends 6, so the Mirror takes the lower of the
client's version and its own. Everything after that point follows it: the
challenge, the result trailer, and the session's OCI layout. The lowest it
serves is 10.2 (field version 4), as for a thin client. sqlplus 10.2's own
widths are the type round, pointer fields, OALL8 preamble, describe and
DESCRIBE reply described in this section (#1764). An older sqlplus is
refused by name.

In that layout the narrow `OALL8` preamble grows by **64
zero bytes** ahead of the SQL, eight more 8-byte slots. The SQL text moves from
offset 176 to 240, while the bind count (71) and the bind section behind the SQL
stay put. The inserted bytes are all zero, so the session's field version, not
the wire, says which layout a statement is in.

**The statement replies.** 11g and 18c answer sqlplus 23 with the same messages
(`TTI_DCB` describe, row header, rows, RPA, OER). 18c's are 11g's with two
widenings, and the Mirror applies both at the 12c band:

- **Every OER is 144 bytes, not 136.** The error number appears again at offset
  132 (1403 at the end of a fetch, 942 on a failed parse), and a ub8 row count
  follows it. This covers the auth trailers, the status frames, the error
  reply and the end of fetch. sqlplus takes a DML statement's "N rows created"
  from that row count, not from the frame's own field, so it reported 0 rows
  until the Mirror filled it in. On query replies the Mirror leaves it zero,
  and sqlplus counts the rows itself.
- **Each describe column's pre-name block is 56 bytes, not 48.** It gains 4 zero
  bytes ahead of the char-semantics flag (offset 15 → 19) and 4 more ahead of the
  charset (30 → 38). The first column's leading byte is `0x5c` (11g: `0x51`). A
  character column carries a ub4 `0x3ffe` behind `max_size`, meaning unpinned,
  where 11g has zero. Measured on NUMBER, DATE, VARCHAR2, NCHAR and NVARCHAR2
  columns.

The row header and the describe tail keep their 11g length: 18c's differ only
in instance values (an SCN).

**Below 11.2 the describe narrows (#1764).** 11g answers sqlplus 10.2 with the
same messages it sends 11.2. Rows, row headers and status frames are the same
length, but every describe is `3 + 4 × columns + 4` bytes shorter, in three
places:

- the cursor preamble's length is a **ub1**: `10 17` and then the 23 bytes,
  where 11.2 gets `10 17 00 00 00`;
- each column's post-name block is **9 bytes, not 13**: column blocks 61 bytes
  apart for a 3-character name, against 65;
- the describe trailer lacks the zero ub4 just ahead of its marker:
  `02000000 02000000 06…` with nothing between, so the marker and the column
  count sit 4 bytes earlier. A CLOB select's describe trailer (no inline row)
  loses the same ub4, its last four bytes, and is 29 bytes.

A 10.2 client given the 11.2 widths crashes (sqlplus exits 139) on the first
describe.

**The `DESCRIBE <object>` reply** (§6.0) is a different message, with its own
widening at the 12c band. Against a live 18c's describe of a NUMBER / VARCHAR2 /
DATE table, it is the 11g reply with zero runs inserted and three carried values
changed:
- the header gains 8 zero bytes after its third describe-time entry;
- each column block gains 20 zero bytes after its post-name byte 34, which reads
  `0x04` (11g: `0x24`), and the block's leading byte reads `0x7a` (11g: `0x5c`);
- the trailer frame is 137 bytes, not 121: 8 zero bytes in front and 8 at the
  end, byte 4 reading `0x05` (11g: `0x04`), and the type-dependent bytes zero;
- its OER widens like every other.
None of the changed values is decoded; they are carried.

To sqlplus 10.2 the same reply is **narrower** (#1764): 1217 bytes against 11.2's
1222 for a 4-column table. Each column block lacks one zero byte, the one right
behind the `0x24` mark at post-name offset 34, where the 12c form inserts its 20.
So a non-last column's describe-time entry sits a byte earlier. The trailer frame
is 120 bytes ahead of the OER, not 121. Given the 11.2 form, sqlplus 10.2 hangs.

**The end-to-end tracing piggyback** (`11 87`) sqlplus sends ahead of a call
has a head 16 bytes longer at the 12c band, so its values start at offset 155,
not 139. The Mirror walks it there, and lands on the call behind it.

With these, sqlplus 23.26's output against a 12.1 Mirror is byte-identical to
the same session at 11.2. That covers queries, fetches in batches, errors, DDL,
DML, commit and rollback, `DESCRIBE`, `VARIABLE` / `EXEC` out binds and bind
variables. What still fails at 11.2 fails the same way at 12.1: a CLOB select
hangs (over PostgreSQL and SQLite alike), and over the SQLite example `SET
SERVEROUTPUT ON` loses the session.

These captured templates are **stepping stones** — the crypto and offsets are
understood; a proper `deadbeef` codec (encoding these packets field-by-field
rather than replaying templates) can replace them later. Auth is only the login
phase; the OCI **query** marshalling (post-login `ttc` calls) is the next
frontier — a thin client's query response is not what sqlplus expects.

#### 4.1.3 sqlplus `PASSWORD` — the OCI changepassword (#21)

sqlplus's `PASSWORD` command (`OCIPasswordChange`) changes the password on the
live, already-authenticated session. Its wire form is the OCI analogue of the
thin changepassword (§ password change): a `TTI_FUN`/`TTI_AUTH` carrying
**`AUTH_PASSWORD` (current)** and **`AUTH_NEWPASSWORD` (new)**, each the
`AES-CBC(ConnKey)` ciphertext hex-encoded (the *same* login `ConnKey` — no fresh
`AUTH_SESSKEY`), marshalled in the OCI dialect (§4.1.2: 8-byte indicators, fixed
ub4 lengths, username at offset 51). There is no old-password proof to verify —
the live session is the authorisation.

Two framing details make it easy to misroute:

- It arrives wrapped in a **TTI_80SES (`0x11 0x6b`) piggyback**, not the OCCA
  (`0x11 0x69`) close-cursors piggyback that wraps ordinary executes. Both have a
  fixed 15-byte prefix; the real `TTI_FUN` call begins at offset 15
  (`strip_oci_piggyback`).
- The post-login **version call** uses the *same* `0x11 0x6b` TTI_80SES wrapper
  (`OCI_PIGGYBACK_80SES`) and 15-byte prefix — they differ only in the wrapped inner
  function (`0x03 0x3b` version vs. `0x03 0x73` `TTI_AUTH`). So the recogniser
  keys on the **inner** function (`is_version_call_oci`), else a changepassword is
  answered with the version banner and sqlplus hangs.

The Mirror decrypts both fields with the login `ConnKey`, drives
`backend.change_password(user, old, new)`, and replies with the auth-complete
status (`encode_changepassword_status_oci`) that sqlplus renders as **"Password
changed"**. Verified live: sqlplus `PASSWORD` against the Mirror (passthrough
backend) changes the password on the real 11g and reconnects with the new one.

The 139-byte reply is an **empty RPA return-parameter envelope** (`08 00 00` —
`TTI_RPA` + a zero `ub2` count) followed by an **OER return-status token** whose
body is the shared §36 OER envelope (`_OCI_OER_ENVELOPE`, including the fixed
`20 f6 31 0a` instance marker). Six bytes differ from that envelope and are all
fixed here — the status byte, offsets 5 / 8 / 18 / 22, and the offset-49 echo —
so the reply is built on the shared envelope rather than stored as a second copy
of it. Captured byte-for-byte across **four** independent live 11g password
changes in separate sessions, the whole reply is invariant: unlike the
query-path OERs, offset 5 and its offset-49 echo are not a live sequence here but
constants, so the Mirror emits it verbatim.

#### 4.1.4 DRCP on 11g needs the native form (client side, #2466)

A dedicated 11g session takes the same native form, and with `oall8=True` the
client speaks it there too (#2463). Only the close differs: sqlplus 11.2 ends a
dedicated session with the plain logoff (`TTI_LOGOFF`, `03 09 <seq>`, answered
with a bare `TTI_STA`), where a pooled one ends with the session release below.
Sent to a dedicated server, the session release aborts the call
(`ORA-03137 [DRCP:kpplsSessRls_1]`). A killed dedicated session is answered with
ORA-00028, not the pool's EOF packet; the native call status carries the code,
which `is_healthy()` reads. A dedicated session changes its password as OCI
11.2's `OCIPasswordChange` on an open session does (`encode_chgpwd_oci11`): an
AUTH of mode `0x102` (WITH_PASSWORD | CHANGE_PASSWORD), an empty `AUTH_SESSKEY`
with flag 1, `AUTH_PASSWORD` and `AUTH_NEWPASSWORD` encrypted with the login's
key as the converted form's are, and the session's own pairs. The reply is an
RPA with no pairs and the status. OCI sends a `TTI_80SES` piggyback (107) naming
the session ahead of it, which the server does not need. A pooled session's
server refuses the change (ORA-56609).

11g's connection pool serves a pooled session (`SERVER=POOLED`) only to a client
speaking the native form above. Measured on 11g XE 11.2.0.2, its pool started,
against sqlplus 11.2:

- **The login asks for DRCP with one bit**, `0x10` in compile capability 31
  (`OCI2`; python-oracledb's `TNS_CCAP_DRCP`). Without it the second AUTH phase
  is refused with ORA-56606 (*DRCP: Client version does not support the
  feature*), whatever the session pairs say. seerdb's converted 11.2 vector has
  `0x0c` there, and its 12c+ vector has `0x10`.
- **The converted form logs in with that bit and then crashes the pool.** The
  first call's reply opens with a server-side piggyback, `SESS_RET` (opcode 4),
  which below 12.1 is one `ub2` only. The next call, whatever it is, aborts the
  pooled server process with `ORA-00600 [kpplsPreProcessState:1] [21]
  [<function>]`. A native client gets no `SESS_RET`, and its calls run.
- **What sets the native form apart is the whole of it**, not one field.
  Replaying sqlplus's own session with seerdb's values put back one at a time
  (the CONNECT, each capability byte, each `OCI2` bit, the AUTH's pairs) never
  brings the `SESS_RET` back.

So a pooled login to an 11g server (an ACCEPT at version 314) speaks the native
form throughout: the OCI banner in the PRO (§19.18), the data-type request with no
table and sqlplus 11.2's capability vectors (§4.2.1), and the OSESSKEY and AUTH at
OCI's widths (§4.1.2), every length declared at three bytes a character, as
sqlplus 11.2 declares them. The O5LOGON values and the DRCP pairs
(`AUTH_KPPL_CONN_CLASS`, `AUTH_KPPL_PURITY`) are the converted AUTH's. A proxy
login (`user[schema]`, #126) names the schema first, `PROXY_CLIENT_NAME` ahead
of the proof, as sqlplus 11.2's does through the pool; without it the pool
logged in as the proxy user itself. It ends
as sqlplus ends it: `TNS_FUNC_SESSION_RELEASE` (163) with an absent tag pointer, a
zero tag length and mode 3, which the server answers with a bare `TTI_STA`, then
the EOF packet. The native form is the client machine's own, and seerdb assumes
both ends are little-endian; a big-endian client is refused.

**The calls**, measured against sqlplus 11.2 through the pool: a query, its
fetches, DDL, DML, `COMMIT`, `ROLLBACK` and a failing statement.

- **The execute** is OALL8's head (`_ALL8_HEAD`) in OCI's wide form, the SQL's
  length declared at three bytes a character; then two indicators and 32 zero
  bytes, the SQL, and the al8i4 array of 13 ub4s carrying 8i's meanings: `[0]` 1,
  `[1]` the execute flag (0 for a query, whose rows come with the execute), `[7]`
  the statement type (1 query, 2 update, 3 delete, 4 insert, 5 create, 6 drop,
  17 rollback, 21 commit). The options are thin's bits, with `NOT_PLSQL`
  (`0x8000`) on every statement but `COMMIT` and `ROLLBACK`: `0x8061` for a
  query, `0x8021` for DML and DDL, `0x21` for those two. sqlplus sends `COMMIT`
  and `ROLLBACK` as statements, and so does seerdb on these sessions. sqlplus
  leaves its own address in one pointer field (offset 131) where seerdb sends the
  indicator. The fetch (`_FETCH`) and the close of finished cursors, piggybacked
  in front of the next call (`_CLOSE_CURSORS`), are the shared schemas at OCI's
  widths.
- **Binds** follow the al8i4 array: one descriptor each (`_OAC` at OCI's widths:
  sqlplus 11.2 sends flags `0x03` whatever the direction, a character bind with
  the session's charset and form 1 and its buffer at three bytes a character, a
  NUMBER at 22 bytes), then `TTI_RXD` and the values in the native 9.2 form (an
  unset OUT bind is the placeholder `fd 01`; a value wider than 4000 bytes goes
  last, outside a block). A bind adds `BIND` (`0x08`) to the options; a PL/SQL
  block carries `PLSQL_BIND` (`0x400`, with binds) and the block bit
  (`0x40000`) and no `NOT_PLSQL`, statement type 8 (`0x40021` without binds,
  `0x40429` with them).
- **A value past the SQL inline limits** (4000 bytes of text, 2000 of RAW)
  goes as itself, as an OCI 11.2 program sends one through the pool: a VARCHAR
  (type 1) or a RAW (type 23) declared at its byte size, the value inline in
  ub1-length chunks. The server takes it into a CLOB, BLOB, LONG or LONG RAW
  column alike: 50,000 bytes into a CLOB and 300,000 into a BLOB, measured. A
  LONG or LONG RAW bind is sent the same way, as OCI sends `SQLT_LNG` and
  `SQLT_LBI`. In PL/SQL, past 32,767 bytes, the server refuses one with
  ORA-01460, as it does OCI's, so seerdb sends such a value through a
  temporary LOB (below).
- **A temporary LOB** is made as OCI 11.2's `OCILobCreateTemporary` makes one
  through the pool: `TTI_LOBOPS` CREATE_TEMP (`0x110`) in `_LOBOPS_READ`'s
  fields, the session's duration (10) in the destination length, the charset
  form in the source offset (1 a CLOB, 2 an NCLOB, 0 a BLOB), the type in the
  destination offset (112 or 113), an empty 86-byte locator (`00 54` and
  zeros), then the charset as a ub2 (873 for a CLOB or an NCLOB, 0 for a BLOB),
  one zero ub4 SCN slot and the duration as a ub8 (`_OCI11_LOBOPS_CREATE_TEMP`).
  The reply is `TTI_RPA`, the new 40-byte locator (`00 26` and 38 bytes) in the
  86 bytes the request's took, the charset and a ub8 of 1, then the status
  (`_OCI11_CREATE_TEMP_REPLY`). A pooled session's temporary LOBs are gone once
  it's released back to the pool (`v$temporary_lobs`, the same session), so
  seerdb, like the thin path, frees none of its own.
- **A LOB bound IN** goes by its locator, as OCI binds a temporary or a fetched
  one: the descriptor a CLOB (112) or a BLOB (113) of 72 bytes, a CLOB's or an
  NCLOB's with charset 873 and form 1; the value a ub4 length and the locator
  as a value, its ub2 length in front, as a row's LOB cell carries it. A LOB
  Var's value and a value past 32,767 bytes into PL/SQL go through a temporary
  LOB, as on 12c+, in every row of an array DML too. A NULL one bound IN (an
  unset LOB Var in a DML, `NullLobBind`) keeps that descriptor, and its value is
  a ub4 of 0 with no locator behind it, as OCI 11.2's `SQLT_CLOB` / `SQLT_BLOB`
  bind with indicator -1 sends it. In a PL/SQL block an unset LOB Var is an OUT
  bind, the empty 86-byte locator. A fetched BFILE bound IN goes as OCI 11.2's
  `SQLT_BFILE` bind of one: the descriptor a BFILE (114) of the same 72 bytes,
  no charset and no form, and the value a ub4 length and the locator as it was
  fetched, its ub2 length in front.
- **An object or collection column** (XMLType among them) is described as
  type 109 with its type's schema and name, and its row cell is the native 9.2
  form's image (`_O9I_OBJECT_CELL`): the 9i native dialect's reader takes it as
  it is, and the cursor decodes the image against the type the dictionary
  describes, as on every tier. sqlplus 11.2 fetches each type's descriptor
  first, with a run of `TTI_KOD` (`0x5c`) calls; seerdb needs none of them.
  Nothing new is sent, so nothing new was measured to send: the change is
  that the column is no longer refused.
- **A BFILE column** comes in the row as the 9.2 form's LOB cell, its locator
  (59 bytes for `BFILENAME('SEERDB_BFILE_DIR', 'pyoracle_bfile_test.txt')`).
  Its calls are `_LOBOPS_READ`'s fields too, as OCI 11.2's `OCILobFile*` make
  them: FILE_EXISTS (`0x800`) and FILE_ISOPEN (`0x400`) set the null-LOB
  pointer and are answered with a flag byte; FILE_OPEN (`0x100`) sends its mode
  (11, read-only) in the amount and is answered with the opened locator, which
  is not the one sent, and which GET_LENGTH, READ and FILE_CLOSE (`0x200`, no
  pointer) take. A directory or file that is not there fails the call with a
  break, then ORA-22285.
- **`ping()`** is OCI 11.2's OCIPing: `TTI_PING` (147) and the sequence, no
  token (`encode_oci11_ping`), answered with a bare `TTI_STA`, call status 1
  and the session's sequence; a first call's reply has the session return
  ahead of it. The piggybacks waiting ride on it, as on OCIPing's.
- **An application context's change** is OCI 11.2's OCIAppCtxSet or
  OCIAppCtxClearAll through the pool (`encode_oci11_app_context`): the func-154
  piggyback thin sends (#1775), at OCI's widths, ahead of the next call's
  cursor closes, a ping's included. Its fields:
  - the namespace's pointer, and its length as a ub8;
  - the entries' pointer (none for a clear) and their count;
  - the flags, thin's with `0x08` set: 9 to set, 10 to clear;
  - eight bytes no field is known for, zero;
  - the namespace, then each entry's key and value, each a ub4 length and the
    bytes (an empty one just the zero count), and a ub4 of 0.

  OCI 11.2 refuses a namespace the session may not set in OCIAppCtxSet itself
  (ORA-28267), before anything is sent. seerdb, as on 10g+, lets the server
  refuse it: the call that carries it fails with ORA-28267, and the session
  goes on.
- **A scrollable cursor** is OCI 11.2's `OCI_STMT_SCROLLABLE_READONLY` cursor
  through the pool. Its open is the query's execute with `al8i4[9]`
  SCROLLABLE | NO_CANCEL_ON_EOF (`0x82`), `[10]` CURRENT and `[11]` row 1, so
  the cursor stays open past its last row; the reply brings the first rows,
  and the OER's row count (`row_kind` in `_OCI_OER`) is the cursor's
  position. Each `OCIStmtFetch2` is the LONG fetch's OALL8 with the same
  `al8i4[9]`, positioned: OCI asks for every row by its 1-based position,
  CURRENT and the row (a NEXT, a PRIOR, a RELATIVE worked out on its side),
  and for the last as LAST and -1 (`encode_oci11_scroll_fetch`). Past the
  last row the reply is ORA-01403 and no rows, and the cursor stays open.
  seerdb's cursor already works out the row, so it sends OCI's form; the
  cursor is closed with the next call once the Python cursor is closed or
  run again.
- **`cursor.parse()`** is OCI 11.2's parse-only execute: PARSE alone in the
  options, `al8i4[1]` 0, nothing run. For a query, as OCI_DESCRIBE_ONLY, also
  DESCRIBE and NOT_PLSQL (`0x28001`), and the reply is the describe and the
  status, so the cursor has its description. A DML that was only parsed has
  its command type in the OER and no rowid behind it, where an executed one
  has the touched row's. A statement that fails to parse is answered as a
  failed execute is, with its error's offset.
- **A password change is refused by the server on a DRCP session.** OCI
  11.2's `OCIPasswordChange` (TTI_AUTH) through the pool is answered with
  ORA-56609 (*Usage not supported with DRCP*), with a right old password or a
  wrong one, and the password is not changed. seerdb refuses
  `changepassword()` there before sending it, naming that error.
- **A killed session** (`ALTER SYSTEM KILL SESSION`) is answered on its next
  call with a DATA packet of data flags `0x0040` (EOF) alone and no payload:
  no ORA-00028, which a dedicated server sends. python-oracledb reads that as
  the session shut down (TNS-12572). seerdb marks the connection unhealthy
  (`ends_session`), closes it, and fails the call with an `OperationalError`
  worded as python-oracledb's DPY-4011; it no longer hands the empty reply
  to the dialect to misread.
- **An open cursor bound IN** to a block (a scrollable one, open on the
  server) goes as OCI 11.2's `SQLT_RSET` bind of an open statement handle: the
  OUT bind's descriptor, a REF CURSOR (102) of one byte, and the cursor's id as
  a 4-byte value where the OUT form sends 0. Bound to an IN OUT parameter the
  cursor comes back in the cursor cell below (an unopened one once the block
  has closed it). Outside a block it is refused, as the OUT bind is.
- **A REF CURSOR OUT bind** is bound as sqlplus 11.2 binds a `variable
  refcursor`: a REF CURSOR (102) of one byte, the value a cursor id of 0 in
  four bytes. The block's reply carries the cursor it opened, in the cell a
  `CURSOR(...)` column's row carries too (`_OCI11_CURSOR_CELL`):
  - a lead byte, `0x4c`, as the Mirror's `_REFCURSOR_OUT` has it;
  - the describe's body as a query's `TTI_DCB` carries it: the row size, the
    column count, the columns and the trailer;
  - the cursor's id; an OUT bind's then its indicator.

  A cursor the block left unopened, or closed, has no columns, and then the
  byte OCI's trailer opens with (`date_lead`) is not sent either: it belongs
  to the column array, as 9.2's describe has it (`columns_lead`). seerdb reads
  it as None (`_OCI11_UNOPENED_CURSOR_CELL`). The cursor's rows come with an
  OALL8 with no SQL: the cursor, FETCH in the options, `max_long` the widest
  column's buffer and one, `al8i4[1]` the rows (sqlplus's 15) and `[7]`
  SELECT (`encode_oci11_cursor_fetch`). sqlplus fetches a query's own rows
  after the first with the plain fetch, and a nested cursor's with this.
- **A LONG or LONG RAW column** is read as sqlplus 11.2 reads one through the
  pool. The query's execute asks for none of the value (`max_long` 0), and its
  reply is the describe and the status, no rows. Each row then comes with an
  OALL8 that carries no SQL: the cursor, the options FETCH | `0x40000`,
  `max_long` the most of the value to read (sqlplus's `set long`; seerdb's
  `0x7FFFFFFF`, the whole value), `al8i4[1]` the one row and `[7]` SELECT. The
  row's LONG cell is the 9.2 form's: chunked, `fe`, 255-byte chunks and `00`,
  then a ub2 indicator and a ub2 return code, both 0; a NULL is an empty value,
  the indicator -1 and the return code 1405 (ORA-01405, `ff ff 7d 05`). sqlplus
  fetches the rows after
  the first with the plain fetch, `max_long` holding; seerdb sends the LONG
  fetch for each, which the server answers the same way.
- **A LOB bound OUT** sends the empty locator, a ub4 86 and 86 bytes (`00 54`
  and zeros), as CREATE_TEMP does; IN OUT, its temporary LOB's. The block's
  reply carries the new locator the same way, a ub4 length and the locator as
  a value (a NULL: a length of 0 and nothing), then the indicator other OUT
  values have. The descriptor's flag bit `0x01` asks for that indicator: OCI
  sets it only when the program binds an indicator variable, and without it
  the locator has none after it. seerdb sends sqlplus's flags (`0x03`), so it
  always comes. A DML's RETURNING into a CLOB or BLOB goes the same way,
  through the PL/SQL wrap.
- **11g's own conversion corrupts some large text binds.** A CLOB bound from
  the 320,000-byte UTF-8 value `'中😀x' * 40000` is stored with the `中` at
  UTF-16 offset 8132, the LOB's chunk size, broken into two replacement
  characters, and one unit too long. OCI 11.2's own bind of it, over a pooled
  or a dedicated connection, and seerdb's dedicated thin bind are stored the
  same way. A value of `中` or `😀` alone, at that size, is stored whole.
- **An array DML** (`executemany`) sends its rows in the one execute, each its
  own `TTI_RXD` and values behind the one set of descriptors, `al8i4[1]` the
  row count, as the native 9.2 form does; batch errors are asked for with
  `BATCH_ERRORS` (`0x80000`). The OER's row count is the rows applied, a
  failing batch's too, which is the row it stopped at. In batch-errors mode the
  status is ORA-24381 and the OER's batch-error slots (at offsets 88, 104 and
  120: a pointer and a count each, where the Mirror's schema had a pad) count
  the error codes (ub2s), the rows (ub4s) and the messages (a ub4 length, the
  text, 6 bytes), which follow the OER before ORA-24381's own message; byte 7 of
  that OER is 0, where every other carries 1.
- **A DML's RETURNING ... INTO**, an array DML's too, goes as OCI 11.2 sends one
  through the pool, not as the PL/SQL block 8i and 9i take: the statement as it
  is, with a block's options (`0x40429`: BIND, PLSQL_BIND and the block bit, no
  NOT_PLSQL), `al8i4[1]` the iterations, each target's descriptor with flags 5
  and its value the unset placeholder `fd 01` in every row. The reply is the
  bind prompt, then per iteration `TTI_RXD` and, for each target in bind order,
  a ub4 row count and that many rows: the value (an empty one for a NULL), a
  ub2 indicator and a ub2 return code, 1405 for a NULL (indicator -1) and 1406
  for a value cut to its declared size (the indicator its whole length).
  An iteration that matched nothing has a count of 0. A statement that fails
  breaks, then asks the client to flush out its binds: a bare `TTI_FOB`, or its
  bind prompt alone, which OCI answers with a `TTI_FOB` of its own. Only then
  does it break again and send the error. Unanswered, the server read the
  next call as a protocol violation (`ORA-03137 [opiexe: protocol
  violation]`) and the pooled server process died. A RETURNING into a CLOB or
  BLOB still goes through the PL/SQL block, which serves it, as its native
  form is not measured.
- **A block's reply** opens with the bind prompt (`TTI_IOV`, the 9.2 form's: a
  50-byte head and one direction mask a bind, `0x10` OUT, `0x20` IN, `0x30` IN
  OUT), then, when the block writes binds, `TTI_RXD` and each OUT or IN OUT
  value followed by a ub2 indicator (0, `0xFFFF` for a NULL; 9.2 sends four
  bytes), then the status. A session's first call has its session return
  between the prompt and the values. A block that fails answers with the status
  alone.
- **A query's reply** is the describe (`_DCB_COLUMN` at OCI's widths, the uds
  flags included), its trailer, the row header and the rows, then the status. A
  fetch's reply is the rows and the status. ORA-01403 in the OER ends the rows.
- **Rows come in two forms.** Plain rows are the native 9.2 form's (repeated
  columns behind `TTI_BVC`). When the row header's byte 2 has `0x08` (`0x1a`,
  against `0x22` for an execute's plain rows and `0x02` for a fetch's), each row
  is `TTI_RXD` and one value, chunked past 252 bytes, holding the row as a data
  block stores it: a flag byte (`0x2c`, a whole row), a lock byte, the cell
  count, and the cells (a ub1 length, `0xFF` for NULL, `0xFE` and a
  little-endian ub2 past 250 bytes). Trailing NULL columns are left out. 11g
  sends them for some queries over tables, sqlplus's and seerdb's alike.
- **The status** is the return parameters, thin's RPA at OCI's widths (a count
  of ub4 values, 6, the third the statement's cursor; the transaction id; the
  session's changed settings as keyword pairs, which an `ALTER SESSION` returns
  with its NLS values; the registration), then the OER (§36). With no pairs the
  RPA is the 35 bytes the Mirror sends (and reads as `_OCI_STATUS_FRAME`). The
  OER's first byte is the call status, its `TXN_IN_PROGRESS` bit `0x02` set
  after a DML; its row count is the rows so far on a fetch and the rows changed
  on a DML; an error's message follows it. Behind the OER of an INSERT, UPDATE,
  DELETE or MERGE that succeeded comes the touched row's rowid as the 9.2 form's
  UROWID cell (a ub2 size and the bytes): 13 bytes for a heap table's, a logical
  rowid for an index-organized table's.
- **CLOB and BLOB columns:** the execute's reply is the describe and the status
  alone; the fetch brings the rows, each LOB cell `_LOB_CELL` (a ub4 locator
  size, the locator as a value, the content's start inline in it; a NULL the
  zero size). The content is read with `TTI_LOBOPS` READ in OCI's wide form
  (`_LOBOPS_READ`: the locator, source offset 1, sqlplus's dest offset 4, the
  amount); the reply is `TTI_LOB` and the content as a value (none for an empty
  LOB), then `TTI_RPA`, the locator again and a ub8 amount, then the status. A
  CLOB's text comes as UTF-16, an NCLOB's too. sqlplus frees a temporary LOB
  after reading it (`FREE_TEMP`, `0x111`); seerdb leaves that to the session's
  end for now.
- **A LOB object's other calls**, measured from an OCI 11.2 program
  (`OCILobGetLength`, `OCILobWrite` and the rest) through the pool, are
  `_LOBOPS_READ`'s fields too, each with the locator as fetched:
  - GET_LENGTH (`0x1`) and GET_CHUNK_SIZE (`0x4000`) set the amount's pointer
    and send 0;
  - OPEN (`0x8000`) sends its mode in the amount, TRIM (`0x20`) the new length;
  - WRITE (`0x40`) sends the source offset and the amount, then `TTI_LOB` and
    the data as a value (`_OCI11_LOBOPS_WRITE`): ub1-length chunks of up to
    255 bytes past 252;
  - IS_OPEN (`0x11000`) sets the null-LOB pointer and no amount; CLOSE
    (`0x10000`) sets neither.

  The reply (`_OCI11_LOBOPS_REPLY`) is `TTI_RPA`, the locator as the server now
  sees it (a ub2 length and the body; a WRITE or a TRIM changes it), the value
  as a ub8 when the request carried an amount, or IS_OPEN's one byte, then the
  status. A call that fails, such as a write on a row not locked (ORA-22920),
  is answered with the status alone. A CLOB's text goes as UTF-16 big-endian,
  as it comes, and its amount counts UTF-16 code units: a character past the
  BMP is two. Counted as one, the server read the rest of the data as a
  protocol error, `ORA-03137 [12333]`, and the pooled server process died.
- **The statement's cursor** is in the OER at offset 18 (a ub2), where the
  Mirror writes a category that sqlplus does not read, and in the RPA. The next
  close names it.
- **Server piggybacks** come ahead of the first reply and of the OER: the session
  return (`SESS_RET`, opcode 4), python-oracledb's 12c+ layout at OCI's widths,
  carrying the pooled session's own SID and serial (not the login's), and the
  pooled server's OS process id (`OS_PID_MTS`, opcode 2: a ub2, then the id as a
  value). The session return in the converted form (§4.1.4's first point) is the
  one-`ub2` layout; in the native form it is this one.

### 4.2 Data Type Negotiation (TTI_DTY)

TTI_DTY (message type `2`, `TNS_MSG_TYPE_DATA_TYPES`) advertises the client's
capabilities and the wire representation it wants for each Oracle data type:

```
msgtype=2 | charset_in (UB2 LE) | charset_out (UB2 LE) | flag (UB1) |
  ccap_len (UB1) | compile_caps[ccap_len] |
  rcap_len  (UB1) | runtime_caps[rcap_len] |
  datatype table | 0
```

- **charset_in / charset_out**: the client's database and national charset ids.
  seerdb advertises **AL32UTF8 (873)** for both — establishing an AL32UTF8
  *session* charset, independent of the server's actual database charset. This
  must be 873 (real UTF-8), **not** Oracle's legacy "UTF8" (871) — 871 is
  CESU-8, which encodes supplementary-plane characters (emoji, rare CJK, U+10000
  and above) as a six-byte surrogate pair instead of a four-byte sequence, and
  Python's `utf-8` codec then decodes them to replacement characters. (#29)

  Because the session charset is AL32UTF8, the server converts to/from it
  regardless of the database charset — so on a non-UTF-8 database (e.g. a 9i
  `WE8ISO8859P1` instance) the wire is still AL32UTF8, and bind/decode never need
  to know the database charset. The decoder picks the codec by the column's
  **character-set form** (csfrm), not its reported database charset id (#174):
  ordinary CHAR/VARCHAR2/CLOB (csfrm 1) arrive in the AL32UTF8 session charset
  (decode as UTF-8); national NCHAR/NVARCHAR2/NCLOB (csfrm 2) arrive as
  **AL16UTF16** (decode as UTF-16BE — the server does *not* fold national data
  into the session charset). String binds mirror this: ordinary binds declare
  AL32UTF8 and send UTF-8; a national bind (`DB_TYPE_NVARCHAR` / `DB_TYPE_NCHAR`)
  declares AL16UTF16 and sends UTF-16BE. The pre-10g (fv2) bind path follows the
  same rule — it formerly declared the database charset on the OAC while sending
  UTF-8, which a non-UTF-8 9i server then mis-converted (#174). **Server side —
  the Mirror (#484)** reads the csfrm byte from each bind's OAC (`decode_oac_fields`)
  and decodes the value with it, so an NCHAR / NVARCHAR bind (csfrm 2, UTF-16BE)
  is recovered as text rather than mojibake; the common 5-tuple OAC decode drops
  csfrm, which had defaulted every bind to the ordinary form.

  **The form belongs to the BIND, not to the value (#991/#990).** Two places got
  this wrong by looking the form up from whatever they happened to hold:

  * An associative array's **elements** are encoded as bare Python values, which
    carry no type, so a national array sent them as UTF-8. The server read those
    bytes as UTF-16BE and produced a string of **half the length** — silently,
    because they are a valid if wrong string. The form has to be applied per
    element, from the array's own declaration.
  * The OUT-bind and RETURNING decode paths built their column dict without a
    csfrm at all, so **every** national OUT value — scalar as well as array —
    came back as raw UTF-16BE read one byte per character.

  Server side, the same rule has to reach the **backend**: a national bind is
  not a distinct TNS type (NVARCHAR2 is VARCHAR plus csfrm 2), so a backend
  handed `tns_type` alone binds the ordinary type upstream and a PL/SQL table of
  the national one refuses it with `PLS-00418: array bind type must match PL/SQL
  table`. The Mirror carries the form on its `BindVar` for that reason.
- **compile_caps / runtime_caps**: two length-prefixed byte arrays. Each index
  is a named feature slot (`TNS_CCAP_*` / `TNS_RCAP_*`). The most important is
  the **field version** at compile-cap index 7 (`TNS_CCAP_FIELD_VERSION`): it
  selects the auth-verifier scheme and the version-gated wire formats the rest
  of the session uses. seerdb advertises `16` (21.1) by default and the
  server negotiates it down to its own max (`min(client, server)`), so an 11g
  server settles on `6` (11.2) and seerdb then emits the 11g vectors/formats;
  pass `field_version=FIELD_VERSION_11_2` to force the legacy vector. The
  capability *contents* are stable across 12c+ releases, so for any negotiated
  12c+ version seerdb renders the 21.1 base vector with that version byte
  patched in (`capability_arrays`).
- **datatype table**: per-type `(type, conv, repr, flags)` entries. seerdb
  uses the 11g 1-byte-per-field form (4 bytes/entry, terminated by `0 0`); 12c+
  uses a 2-byte-per-field form (`UB2`×4, terminated by `UB2 0`).

Selected capability indices (reverse-engineered from python-oracledb's
`constants.pxi`/`data_types.pyx` and verified against live 11g and 21c
captures), with the values seerdb's 11.2 vector vs python-oracledb's 21.1
vector send:

| idx | name | 11.2 | 21.1 | notes |
|----:|------|-----:|-----:|-------|
| 0 | SQL_VERSION | 6 | 6 | `SQL_VERSION_MAX` |
| 4 | LOGON_TYPES | 0x6a | 0xea | 21.1 adds `O8LOGON_LONG_IDENTIFIER` |
| 5 | FEATURE_BACKPORT | 1 | 0x18 | |
| 7 | **FIELD_VERSION** | **6** | **16** | the version gate |
| 23 | LOB | 0x4f | 0xcf | 21.1 adds `LOB_12C` |
| 27 | UB2_DTY | 0 | 1 | 2-byte data-type ids |
| 34 | CLIENT_FN | 6 | 12 | `CLIENT_FN_MAX` |
| 37 | TTC3 | 1 | 0xb8 | |
| 39 | SESS_SIGNATURE_VERSION | — | 8 | new 12c+ slot |
| 52 | VECTOR_FEATURES | — | 3 | new (23ai vectors) |

The compile array grew from 38 bytes (`TNS_CCAP_MAX` 11g) to 53 (12c+); the
runtime array from 7 to 11, with runtime index 6 (`TNS_RCAP_TTC`) gaining
`ZERO_COPY | 32K` (`0x05`). seerdb models both arrays as `{index: value}`
maps keyed on the field version in `seerdb/tns.py` (`capability_arrays`).

The negotiated version can also go *below* 11.2: an Oracle **10g** server
settles on field version **4**. seerdb advertises its highest version and
gates the *older* wire formats on `field_version < FIELD_VERSION_11_2` — the
pre-11g describe layout (§6.4) and the unsalted DES auth (§4.4) — so a single
build speaks 10g through 23ai. (Reference field versions: 10.2 = 4, 11.2 = 6,
12.1 = 7, 12.2 = 8, 19c = 12, 21c = 16, 23ai = 17, fast-auth-max = 24.)

**Which "12c" layouts start at 12.1 and which at 12.2 (#1144).** A client that
negotiates 12.1 (7) — a real 12.1 client against any newer server — gets the
12c forms of the execute tail's array-DML block (§5.1), the one-byte describe
scale (§6), the bind OAC (§5.1) and `ub4` chunk lengths (§6.4). Only the
execute's SQL-signature pointers and the `oaccolid` of describe and bind
metadata wait for 12.2 (8). seerdb had gated all of them on 12.2, and no testbed
ever negotiates 7, so it went unseen until the Mirror advertised 12.1: forced
to 7 against 23ai, 409 of 454 integration tests failed, 406 with `ORA-03120`.
Forcing a lower version against a newer server (`SEERDB_TEST_FIELD_VERSION=7`)
is the way to test it, since that is exactly what a real 12.1 client does.

> **Oracle 26ai advertises field version 27 (#458).** The
> `container-registry.oracle.com/database/free:latest` image — branded **26ai**
> (`ORACLE_HOME=.../26ai/dbhomeFree`), release 23.26.2.0.0 — sends `compile_caps[7] = 27` in its PRO,
> above the 23ai fast-auth maximum of 24. seerdb caps its own advertised field
> version at 24 (`FIELD_VERSION_23_4`) and so negotiates `min(24, 27) = 24`,
> connecting and running the full 23ai surface (auth, ANO native encryption,
> queries — all validated live). The capability arrays also grew: `compile_caps`
> from 45 bytes (21c) to **54**, `runtime_caps` from 7 to **13**, with new bits
> in `LOGON_TYPES` (#4 `0xEF`), `OCI3` (#35), `TTC4` (#40 `0xFF`), `LOB2` (#42),
> `TTC5` (#44 `0xFF`), and 9 new trailing slots (45–53, incl. `FEATURE_BACKPORT2`
> at 45 and `VECTOR_FEATURES` at 52). The reference thin client also caps at 24
> and has no code path for 25–27. Measured live on 26ai: advertising field
> version 25 or 26 changes nothing (login, describe and fetch are identical to
> 24); advertising 27 keeps login and fast-auth working, but the fv24-shaped
> OALL8 execute then gets no reply at all, so 27 changes the request
> marshalling. Of the new capability bits, three have a known meaning:
> `FEATURE_BACKPORT2` bit `0x02` (end-user security context, §34), bit `0x01`
> (transaction priority, §42) and `TTC4` bit `0x40` (explicit request
> boundaries). Slot 51 (`0x07`) and slot 53 (`0x02`) are set but named by no thin
> client, and `TTC6` (index 54, HA readiness) lies beyond the 54-byte array (#458).

> **12c+ support (issue #27) — RESOLVED.** Advertising a 12c+ field version is
> necessary for 21c login but not sufficient: it changes how the server frames
> every subsequent message (DTY table form, OER layout, datatype encodings), so
> it had to land together with the matching version-gated decoders. All of that
> is now done — the 256-bit O5LOGON crypto (§4.5), the capability layout (this
> section) and the version-gated formats. seerdb logs in and runs its full
> test suite against 11g, **12c+ (21c, 23ai)** and 10g from one build.

#### 4.2.1 The deadbeef third-round type reply (server-side / the Mirror)

sqlplus / thick OCI's **data-type round** is its third, after ANO and PRO, and
comes before it sends OSESSKEY. Its request carries encoding flag `02` and no
type table (§4.1.1); the Mirror answers it with `encode_oci_dty_reply`. The server answers
that third `ttc=02` request with a fixed **16-byte TTC payload** (a 26-byte DATA
packet). Despite living outside the ordinary DTY exchange, it is an ordinary
**data-type reply carrying the DB session time zone and the server's
timezone-file version** (#565) — not an opaque blob. The Mirror builds it
field-by-field (`build_oci_dty_reply`):

```
02                       TTI_DTY message code
80 00 00 00              time-zone block bytes [0..3]  (fixed framing)
3c 3c 3c                 the h/m/s offset triplet, each biased by +60
                           → (60,60,60) − 60 = +00:00:00  → DB time zone = UTC
80 00 00 00              time-zone block bytes [7..10]  (fixed framing)
00 00 00 0e              timezone-file version (ub4 BE) = 14
```

The `+60` bias on each of the hours / minutes / seconds fields is Oracle's
time-zone encoding (a real client reads each byte back as `value − 60`), so the
stored `3c 3c 3c` decodes to a zero offset. `0x0E` (14) is the 11.2 default
timezone-file (DST-rules) version. The 8 fixed framing bytes around the triplet
are the block's captured 11.2 identity. `tests/test_handshake_generation.py`
pins the built bytes to the live 11g capture.

### 4.3 Session Setup (TTI_FUN/TTI_SESS)

```
TTI_FUN | TTI_SESS | SeqNum | 1 | UserLen | AuthMode | 1 | NumPairs | 1 | 1 |
  User | KV("AUTH_PROGRAM_NM", app) | KV("AUTH_MACHINE", host) |
  KV("AUTH_PID", pid) | KV("AUTH_SID", user)
```

- **AuthMode**: Bitmask — `1` (basic) | `32` (SYSDBA role) | `128` (PRELIM auth).
- **NumPairs**: Number of key-value pairs (typically 4).

### 4.4 Authentication Challenge (TTI_RPA from Server)

The server responds with TTI_RPA containing key-value pairs:

| Key                      | Description                                          |
|--------------------------|------------------------------------------------------|
| `AUTH_SESSKEY`           | Server session key (hex-encoded)                     |
| `AUTH_VFR_DATA`          | Verifier salt (hex-encoded); **empty on 10g**        |
| `AUTH_PBKDF2_CSK_SALT`   | PBKDF2 ConnKey salt — present ⇔ a 12c+ server         |
| `AUTH_PBKDF2_VGEN_COUNT` | PBKDF2 iterations for the session key (256-bit)      |
| `AUTH_PBKDF2_SDER_COUNT` | PBKDF2 iterations for the ConnKey                    |

The **verifier-type flag** on the `AUTH_VFR_DATA` pair — the ub4 that trails every
key-value pair, *not* a length — names the account's password-verifier generation.
These are opaque Oracle identifiers (the hex forms carry no structure); each is
live-confirmed on the wire:

| Flag  | Hex      | Account verifier | Confirmed                  |
|-------|----------|------------------|----------------------------|
| 2361  | `0x0939` | 10g / legacy DES | live 10.2.0.5              |
| 6949  | `0x1B25` | 11g SHA-1        | 11g capture + live XE 11.2 |
| 18453 | `0x4815` | 12c SHA-2        | live 21c / 23ai / 26ai     |

The key schedule is chosen from the verifier type **and**, *independently*, from
whether the server advertised PBKDF2 (`AUTH_PBKDF2_CSK_SALT` present ⇔ 12c+
server). The two signals are orthogonal, so salt-presence alone is **not** a
reliable selector:

| Verifier (flag)  | Server   | `AUTH_VFR_DATA` | `CSK_SALT` | Key schedule                              |
|------------------|----------|-----------------|------------|-------------------------------------------|
| legacy (2361)    | 10g      | empty (+ flag)  | absent     | 128-bit, salt-less DES verifier           |
| 11g SHA-1 (6949) | 11g      | salt            | absent     | 192-bit SHA-1 key, legacy MD5 ConnKey     |
| 11g SHA-1 (6949) | **12c+** | salt            | **present**| 192-bit SHA-1 key, **PBKDF2 ConnKey** (#311)|
| 12c SHA-2 (18453)| 12c+     | salt            | present    | 256-bit PBKDF2                            |

The third row is the subtle case — a modern server serving a pre-SHA-2 account.
Because it sends *both* a salt and a CSK salt, a naive "salt present ⇒ 256-bit"
rule mis-selects the SHA-2 schedule and the login fails `ORA-01017`; the `6949`
flag is what disambiguates it (#311 / #312, validated live in `test_integration`).

**Oracle 10g (field version 4)** has no 11g/12c password verifier, so it sends
`AUTH_SESSKEY` with an **empty** `AUTH_VFR_DATA` (no salt) and no PBKDF2 fields —
though the `2361` verifier-type flag still rides on that empty pair, which is why
salt-presence and verifier type are independent signals (see the table above).
seerdb detects the absence of *both* the salt and the derived salt and takes
the legacy **DES-verifier** path (the 128-bit case below). Note this is still an
AES session key: **O5LOGON debuted in 10g** — 11g only *added* the salted SHA-1
verifier (the 192-bit variant), and 12c the PBKDF2 verifier (256-bit). The
genuinely older **O3LOGON** (an 8-byte *DES* session key; Oracle 8i/9i; tokens
`TTI_3LOGON` / `TTI_3LOGA`, §3.2) is a different, pre-10g handshake that seerdb
carries (`crypto.o3logon`), verified live against 9.2.0.4 and, in the OSESSKEY
envelope 8i wraps it in, 8.1.7 (§19.8).

9i takes O3LOGON in the key-value **OSESSKEY / OAUTH** envelope, thin-coded
(`encode_o7_osesskey`, `encode_o7_oauth`, #2342): the 10g login's head and pairs
(`_AUTH_HEAD`, `_AUTH_PAIR`) with the user raw, as a 10g client below 12.1 sends
them; mode 1 and then 0x101; the session pairs such a client sends, program,
machine, pid and osuser (`AUTH_SID`), and at phase two `AUTH_PASSWORD` (the hex of
the DES blocks and the pad count, as 8i's) and `AUTH_ACL`. Each reply is the RPA,
a `ub2` pair count and the pairs (`_PRE10_AUTH_REPLY`): `AUTH_SESSKEY` alone, then
23 pairs from `AUTH_VERSION_STRING` on; a refusal at either phase is a status alone
(§19.2, #2340). 9.2.0.4 takes the machine sent as its `USERENV HOST`.

The Oracle JDBC thin driver sends 9i the positional `TTI_3LOGA` (0x52) /
`TTI_3LOGON` (0x51) instead, which seerdb sent until #2342: the user's pointer and
length, an attribute block, the user, the password and four session strings.
Part of that block, `02 10 00 00 00 01 01 10` and a phase tail carrying `10` again,
is not understood: 9.2.0.4 took the login only when its two lengths were equal and
at least 16, so it carried JDBC's own 16-character program name, and every 9i
session called itself `JDBC Thin Client` on a host called `o9i`.

### 4.5 Authentication Response (TTI_FUN/TTI_AUTH)

The client computes the authentication response:

**Key derivation** depends on the variant:

- **128-bit, no salt (10g / legacy DES verifier)**: `KeySess` is the classic
  Oracle DES verifier zero-padded to a 16-byte AES-128 key. The verifier is the
  normalized (uppercased, UTF-16BE) `USER+PASSWORD` run through DES-CBC under the
  fixed key `0x0123456789ABCDEF`, then DES-CBC again under the **last 8 bytes** of
  that result — the verifier is the last 8 bytes of the second pass (this equals
  the value stored in `sys.user$.password`). Then `ConnKey = MD5(XOR(SrvSess[16:32],
  CliSess[16:32]))`. Verified against a live 10.2.0.5 server (the derived verifier
  matches `sys.user$.password`; login succeeds sync + async).
- **192-bit, SHA-1** (11g verifier): `KeySess` = SHA-1(`PASSWORD + unhex(SALT)`)
  zero-padded to 24 bytes (AES-192). The **ConnKey** then depends on the server:
  an 11g server (no CSK salt) uses the legacy MD5-based 24-byte derivation; a
  **modern (12c+) server** serving this account (flag `6949`, both salts present)
  reuses the *same* SHA-1 `KeySess` but derives the ConnKey with the 256-bit path's
  `PBKDF2-HMAC-SHA512(hexlify(CliSess || SrvSess), salt = unhex(AUTH_PBKDF2_CSK_SALT),
  iterations = AUTH_PBKDF2_SDER_COUNT)` at **24-byte** length (#311).
- **256-bit** (12c+, e.g. 21c XE): `Data = PBKDF2-HMAC-SHA512(PASSWORD, salt =
  unhex(AUTH_VFR_DATA) || "AUTH_PBKDF2_SPEEDY_KEY", iterations = AUTH_PBKDF2_VGEN_COUNT
  (server-advertised, default 4096; hardcoding these broke #309), dklen = 64)`, then
  `KeySess = SHA-512(Data || unhex(AUTH_VFR_DATA))[:32]` (the
  AES-256 key). `Data` is also carried to the server in `AUTH_PBKDF2_SPEEDY_KEY` (below).

**Session key exchange**:
1. Decrypt `AUTH_SESSKEY` (server's) with `KeySess` using AES-CBC (IV = 0) → `SrvSess`.
2. Generate a random client session key `CliSess` of the same size.
3. Encrypt `CliSess` with `KeySess` and send it as `AUTH_SESSKEY`.
4. Derive the connection key `ConnKey` from the server and client session keys:
   - 128-bit: MD5 over XOR/concatenation; 192-bit: MD5-based, 24 bytes.
   - **256-bit**: `ConnKey = PBKDF2-HMAC-SHA512(hexlify(CliSess || SrvSess), salt =
     unhex(AUTH_PBKDF2_CSK_SALT), iterations = AUTH_PBKDF2_SDER_COUNT (server-advertised,
     default 3; #309), dklen = 32)`.
     Note the order — **client session key first**, and the *unpadded* keys are concatenated.

**Password encryption**: `AUTH_PASSWORD = AES-CBC(ConnKey, IV=0)` of `pad1(PASSWORD)`, where
`pad1` is a 16-byte prefix block + `PASSWORD` + PKCS#7 padding. Sent hex-encoded (uppercase).

**256-bit field encoding (verified against python-oracledb / 21c on the wire):**
- `AUTH_SESSKEY` (client, 32 bytes), `AUTH_PASSWORD` (32 bytes) and `AUTH_PBKDF2_SPEEDY_KEY`
  (80 bytes) are encrypted block-aligned and sent **as-is, NOT given an extra PKCS#7 block**
  (the client session key is the raw 32-byte `CliSess`; the speedy key is `random(16) ||
  Data(64)`). All three values are **hex-encoded** (uppercase) on the wire — sending the
  speedy key as raw bytes gives `ORA-03146` ("invalid buffer length for TTC field").
- `AUTH_PBKDF2_SPEEDY_KEY` carries `Data` so the server can recover it (and verify the
  password) without the plaintext.

> **12c+ login — RESOLVED.** The 256-bit crypto above is byte-identical to
> python-oracledb and 21c / 23ai now log in and run the full test suite. The
> earlier `ORA-01017` was indeed not in the auth message: it was the capability
> negotiation — seerdb's compile/runtime cap arrays had to match the 21.1
> vectors (§4.2) for the server to accept the 12c verifier.

The auth response message:
```
TTI_FUN | TTI_AUTH | SeqNum | 1 | UserLen | AuthMode | 1 | NumPairs | 1 | 1 |
  User |
  [KV("PROXY_CLIENT_NAME", proxy)]
  KV("AUTH_PASSWORD", encrypted_password) |
  [KV("AUTH_NEWPASSWORD", encrypted_new_password)] |
  [KV("AUTH_PBKDF2_SPEEDY_KEY", encrypted_speedy_key)] |
  KV("AUTH_SESSKEY", encrypted_client_session_key) |
  [KV("AUTH_ALTER_SESSION", "ALTER SESSION SET TIME_ZONE='±hh:mm'\0")] |
  KV("SESSION_CLIENT_DRIVER_NAME", "python") |
  KV("SESSION_CLIENT_VERSION", "186647296")
```

- **AuthMode**: `256` (O5LOGON) | `1` (password) | `18` (new password) | `32` (SYSDBA) | `128` (PRELIM).
- **`AUTH_ALTER_SESSION`** pins the session time zone to the client's UTC offset,
  the way oracledb / OCI / sqlplus do — else `SESSIONTIMEZONE`,
  `CURRENT_TIMESTAMP` / `LOCALTIMESTAMP`, and `TIMESTAMP WITH LOCAL TIME ZONE`
  reflect the server default, not the client. Sent on **12c+** (`field_version
  >= FIELD_VERSION_12_1`): that is where oracledb (thin) operates and the
  phase-two AUTH accepts the extra pair; 10g / 11g have a stricter parse that
  desyncs on it (and no oracledb reference to match). The fv24 fast-auth path
  carries the same pair among its session-context KVs (§20). oracledb prefixes
  the value with `%`; the server accepts it with or without.

### 4.6 Authentication Result (TTI_RPA from Server)

The OSESSKEY also carries the client's **session identity** — what a server
records in `v$session` (#826):

| Pair | `v$session` column |
|---|---|
| `AUTH_PROGRAM_NM` | `program` |
| `AUTH_MACHINE` | `machine` |
| `AUTH_TERMINAL` | `terminal` |
| `AUTH_SID` | **`osuser`** — not a session id, despite the name |

None of it is authenticated; the server simply records what it is told. It is
readable *only* through this message, so a client that wants its own values there
has to send them here, and a relaying server has to read them here.

**The driver name is not among them.** `client_driver`, in
`v$session_connect_info`, arrives one message later — in the AUTH, after the
OSESSKEY. That ordering matters to anything that opens a downstream connection
during authentication: the first four are available in time, the driver name is
not.

If successful, the server returns TTI_RPA with:

| Key                     | Description                        |
|-------------------------|------------------------------------|
| `AUTH_SVR_RESPONSE`     | Server proof (hex-encoded)         |
| `AUTH_VERSION_NO`       | Server version number              |
| `AUTH_SESSION_ID`       | Session identifier                 |
| `AUTH_SERIAL_NUM`       | Session serial number              |
| `AUTH_MAX_OPEN_CURSORS` | Session's max open cursors (12.1+) |
| `AUTH_MAX_IDEN_LENGTH`  | Longest identifier, `128` (12.2+)  |
| `AUTH_INSTANCENAME`     | Instance name                      |
| `AUTH_SC_DBUNIQUE_NAME` | Database unique name               |
| `AUTH_SC_REAL_DBUNIQUE_NAME` | Database unique name (21c+)   |
| `AUTH_SC_DB_DOMAIN`     | Database domain                    |
| `AUTH_SC_SERVICE_NAME`  | Service name                       |

**The session's identity is reported here and NOWHERE else (#826).** A client
exposes `session_id`, `serial_num`, `instance_name`, `db_name`, `db_domain` and
`service_name` straight from this reply and never queries for them, so a server
that omits them leaves those attributes empty for the life of the connection
however correct the session otherwise is — `sys_context('userenv', 'sid')` will
happily return the right value in the same breath. Measured on a live 23ai:
`AUTH_INSTANCENAME` `FREE`, `AUTH_SC_DBUNIQUE_NAME` `FREE`,
`AUTH_SC_SERVICE_NAME` `freepdb1` (lower case, unlike the others).

`AUTH_MAX_IDEN_LENGTH` is the longest identifier the server takes, a client's
`max_identifier_length` (#2456). It depends on the **negotiated field version**,
not the server's release. Measured on 2026-11-04:
- 23ai sends `128` to a session at field version 8 (12.2) or later, and nothing to
  one at 7 (12.1);
- 18c and 21c send `128`;
- 10g and 11g never send it.

Where it isn't sent, the attribute is `None` rather than a value the client
assumes. The Mirror sends it to a session at field version 12.2 or later.

The unique name is `sys_context('userenv', 'db_unique_name')`, and it comes in
two keys (#1774). 21c and 23ai send both `AUTH_SC_DBUNIQUE_NAME` and
`AUTH_SC_REAL_DBUNIQUE_NAME`; 10g, 11g and 18c send only the first; 8i and 9i
send neither, and their USERENV has no `DB_UNIQUE_NAME` (ORA-02003). On every
bed that sends them, the values equal what `sys_context` reports (11g `XE`, 18c and
21c `XE` from an `XEPDB1` login, 23ai `FREE`). python-oracledb 26 reads only
the REAL key, so its `db_unique_name` is None on 18c and earlier. seerdb reads
the REAL key and falls back to the other.

A server with no database domain still sends `AUTH_SC_DB_DOMAIN`, with an
**empty** value: a zero length, which a client reads as `None`. Measured on 10g,
11g, 18c, 21c, 23ai and 26ai, each with `sys_context('userenv', 'db_domain')`
NULL. (8i and 9i answer the login differently and send no such pair.) This
section once said the opposite, and the Mirror left the key out to match;
it now sends it empty (#1820).

The client validates by decrypting `AUTH_SVR_RESPONSE` with the connection key and checking for the presence of `"SERVER_TO_CLIENT"` in the plaintext.

`AUTH_MAX_OPEN_CURSORS` (a live 23ai reports its `open_cursors`, 300) sizes the
array a thin client tracks cursors-to-close in. A missing or zero value clamps
that array to length **1**, so the second cursor the client closes overruns it
with `IndexError: array assignment index out of range` — the statement-cache
path every `executemany` and cursor reuse drives. seerdb's Mirror sends it only
in the 12.1+ result, as a pre-12.1 server does not.

`AUTH_SERIAL_NUM` is in the reply at **every** version, not only 12.1+. A
captured 11.2 reply carries it (1725, beside `AUTH_SESSION_ID` 160), and 10g,
11g, 18c, 21c and 23ai all send it. With `AUTH_SESSION_ID` it names the session
as `ALTER SYSTEM KILL SESSION 'sid,serial'` does, and the pair equals
`dbms_debug_jdwp.current_session_id` / `current_session_serial`. The Mirror
used to send it from 12.1 only, which left a pre-12.1 client with no serial
(#1234). A 9i reply carries neither.

`AUTH_VERSION_NO` is a decimal string of a single packed integer holding
the server's release. Before 18c, decode it as `major` (bits 24-31), `minor`
(20-23), `update` (12-19), `patch` (8-11), `port-specific update`
(0-7) — e.g. `186647040` = `0x0B200200` = `11.2.0.2.0`, matching
`product_component_version` on XE. From 18c the fields are the release
update's: `major` (24-31), `update` (16-23), `revision` (12-15), `increment`
(4-11), `extension` (0-3), the reading python-oracledb gives (#2097). The
older layout read 23ai's word as 23.1.162.0.0. seerdb exposes the dotted form
as `Connection.version` and masks the major release out for its protocol
version gate.

Decoding what three live servers send confirms the layout across releases:

| Server | `AUTH_VERSION_NO` | Packed | Decodes to | `AUTH_VERSION_SQL` |
|--------|-------------------|--------|------------|--------------------|
| XE 11.2   | `186647040` | `0x0B200200` | 11.2.0.2.0   | `22` |
| XE 18c    | `301989888` | `0x12000000` | 18.0.0.0.0   | |
| XE 21c    | `352518144` | `0x15030000` | 21.3.0.0.0   | `25` |
| 23ai/26ai | `387588096` | `0x171A2000` | 23.26.2.0.0  | `26` |

18c's word names the base release; its `product_component_version` says
18.4.0.0.0.

`AUTH_VERSION_SQL` is a small counter that moves with the release. Nothing reads
it back — a client decodes only `AUTH_VERSION_NO` into its version property — so
it is descriptive rather than load-bearing.

### 4.7 Password Change (TTI_FUN/TTI_AUTH on a live session)

`Connection.changepassword(old, new)` (#21) reuses the **already-authenticated
session** rather than re-running the handshake. After a normal login it sends a
single `TTI_AUTH` (0x73) call whose layout is identical to the login OAUTH
(§4.5) except:

- **Logon mode `0x102`** = `WITH_PASSWORD` (0x100) | `CHANGE_PASSWORD` (0x02),
  and notably *without* the `LOGON` (0x01) bit the login carries.
- Exactly **two** key/value pairs and **no** `AUTH_SESSKEY` /
  `AUTH_PBKDF2_SPEEDY_KEY` — the session key from login is reused:

  | Key                | Value                                              |
  |--------------------|----------------------------------------------------|
  | `AUTH_PASSWORD`    | current password, AES-CBC(IV=0) under the ConnKey  |
  | `AUTH_NEWPASSWORD` | new password, encrypted the same way               |

Both values use the same encryption as the login `AUTH_PASSWORD`
(`encrypt_password`): a fixed 16-byte block is prepended (the server discards
it) so the first ciphertext block is shared — a fresh random prefix, as
oracledb sends, is not required. Wire layout (mirrors `encode_dictionary_auth`):

```
TTI_FUN | TTI_AUTH | SeqNum | 1 | UserLen(SB4) | LogonMode=0x102(SB4) |
  1 | KVCount=2(SB4) | 1 | 1 | UserField |
  KV(AUTH_PASSWORD) | KV(AUTH_NEWPASSWORD)
```

The server replies with a `TTI_RPA` + `TTI_OER`: error code 0 on success (the
session stays usable), `ORA-28008` for a wrong current password, or e.g.
`ORA-28003` when a password-verify function rejects the new one. Verified on
both 11g (128/192-bit O5LOGON) and 21c (256-bit). Reverse-engineered from an
oracledb-thin capture through the logging proxy (`tools/capture_proxy.py`).

**Server side (the Mirror, #21/#486).** A `TTI_AUTH` arriving *after* login is a
changepassword (the only post-login auth op). The session loop reuses the login
`conn_key` to `decrypt_password` both `AUTH_PASSWORD` (current) and
`AUTH_NEWPASSWORD` (new) — the inverse of `encrypt_password`: AES-CBC decrypt,
drop the leading 16-byte block, strip the PKCS7 tail — then calls the backend's
optional `change_password(user, old, new)`, and replies with an `encode_status(0)`
OER (or an ORA error). The backend both changes the real credential (the
passthrough runs `ALTER USER … IDENTIFIED BY … REPLACE …`, which validates the
old password) and updates a **shared** credential map so a fresh session's
O5LOGON authenticates with the new password and rejects the old one. `handle_login`
now returns the `conn_key` alongside `(user, is_sqlplus)` for exactly this reuse.

## 5. SQL Execution

### 5.1 Execute (TTI_FUN/TTI_ALL8)

All SQL operations (queries, DML, PL/SQL blocks) use the `TTI_ALL8` function:

```
TTI_FUN | TTI_ALL8 | SeqNum |
  Options(SB4) | Cursor(SB4) |
  QueryPresent(UB1) | QueryLength(SB4) |
  All8Present(UB1) | All8Length(SB4) |
  0 | 0 |
  LongMaxValue(SB4) | FetchRows(SB4) | MaxValue(SB4) |
  BindIndicator(UB1) | [BindCount(SB4)] |
  0 | 0 | 0 | 0 | 0 |
  DefColsPresent(UB1) | DefColsCount(SB4) |
  0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
  [QueryData] | [All8Array] | [OAC descriptors] | [RXD bind data]
```

**Options bitmask**:

| Bit(s)  | Meaning                     |
|---------|-----------------------------|
| 0x0001  | Parse statement             |
| 0x0008  | Bind values present         |
| 0x0010  | Define columns present      |
| 0x0020  | Execute                     |
| 0x0100  | Autocommit                  |
| 0x0400  | PL/SQL block                |
| 0x8000  | Fetch                       |

Common option combinations:
- **SELECT** (new cursor): `0x8021` (parse + execute + fetch), with bind: `0x8029`.
- **SELECT** (reuse cursor): `0x80A0` (execute + fetch + define).
- **DML** (INSERT/UPDATE/DELETE): `0x8021` (+ `0x0100` for autocommit), with bind: `0x8029`.
- **PL/SQL block**: `0x0421` (parse + execute + PL/SQL), with bind: `0x0429`.
- **RETURNING clause**: `0x0421` (same as PL/SQL).
- **Fetch more rows**: `0x8020` or `0x8030` (execute + fetch, with optional define).

**All8 array** encodes execution parameters as SB4 values:
`[Options, FetchCount, 0, 0, 0, 0, 0, Type, 0, 0, 0, 0, 0]`
- Type: `1` for SELECT, `0` for DML/PL/SQL.

**Cursor reuse**: The protocol allows reusing a previously-parsed cursor ID
instead of resending the SQL text, skipping the server-side re-parse. seerdb
caches the cursor id the server returns (per connection, LRU, DML only) and on
a repeat execute of the same SQL sends that id with an empty query string; the
OAC descriptors are then omitted (the server already knows the column types
from the first parse) and only the `TTI_RXD` bind values are sent.

**Anonymous PL/SQL blocks** (`BEGIN`/`DECLARE` …) must use the PL/SQL option
set (`0x0421` / `0x0429`), not the DML `change` set — sending a block with
binds through the DML path is rejected with `ORA-00600 [12259]`. The returned
OUT/IN OUT values come back in a `TTI_IOV` token (§6.5).

**Array DML batch errors and row counts** (`executemany`, 12c+). Two optional
modes layer onto an array-DML execute, each oracledb-compatible:

- **`batcherrors`** — OR `0x80000` (`TNS_EXEC_OPTION_BATCH_ERRORS`) into the
  leading Options word. A per-row error then no longer aborts the batch; the
  good rows apply and the failures come back in the OER's batch-error
  code/offset/message arrays (§6.7), summarised by a non-fatal `ORA-24381`.

- **`arraydmlrowcounts`** — ask the server for the per-iteration affected-row
  count. Two coordinated request-side changes (no Options bit):
  1. `al8i4[9]` — the exec-flags word — gains **`DML_ROWCOUNTS` = `0x4000`**.
     That bit alone is the request. seerdb's client writes `0xC000`, which is
     `DML_ROWCOUNTS | IMPLICIT_RESULTSET (0x8000)`; a real server accepts the
     pair (verified on every 12c+ tier), but the two are unrelated flags that
     share a word, and the reference thin client sets `IMPLICIT_RESULTSET` on
     **every** ordinary execute — DDL, DML and array DML alike — so a server
     that tests for the composite takes every such execute for a row-count
     request. That is exactly what the Mirror did (#859, below).
  2. The 12c+ `al8pidmlrc` block — the three zero bytes that follow the
     register-id field in the post-11g OALL8 header — becomes
     `01 | iteration_count(SB4) | 01` (e.g. four iterations → `01 01 04 01`).

  Omitting either makes the server reject the execute as malformed
  (`ORA-03137 [kpoal8Check-4]`). The counts come back in the response's
  **return-parameters block** (`TTI_RPA`, token 8) that precedes the trailing
  OER. That block is not opaque; by field it is

  ```
  08 | ub2 al8o4l count | count × ub4 | ub2 al8txl length (+ bytes) |
       ub2 key/value pairs (+ pairs) | ub2 registration length (+ bytes) |
       [ ub4 rows | rows × ub8 ]        ← only when DML_ROWCOUNTS was set
  ```

  (the reference client's `_process_return_parameters`, matched against a
  live 23ai reply, `08 01 06 04 01 69 21 60 00 01 06 01 01 00 00 00 00 00 04 …`:
  six `al8o4l` words, three empty words, then the OER). seerdb's
  `decode_token_rpa_piggyback` reads it by those fields from 10.2 up, and pulls
  the row-count tail out (armed for the execute via a context flag) into
  `cursor.getarraydmlrowcounts()`. The two modes combine: a failed iteration
  reports a row count of `0`. On 9i the `al8o4l` count over-counts, so there
  the walk stays loose: a count, that many fields (stopping at a known token),
  then any zero bytes.

  **The key/value pairs are not always empty (#1141).** 11g answers
  `ALTER SESSION SET CURRENT_SCHEMA = SYSTEM` with two of them — the
  session-state change a later release reports in a server piggyback instead
  (§20.6). A pair is `ub2 text length (+ DALC) | ub2 binary length (+ DALC) |
  ub2 keyword`. Captured live from 11.2 XE:

  ```
  08 | 01 06 | 03 c1 40 83 | 00 | 01 02 | 01 02 | 00 | 00   six al8o4l words
     | 00                                                   al8txl length 0
     | 01 02                                                2 key/value pairs
     | 01 06  06 "SYSTEM" | 00 | 01 a8                      name, keyword 168
     | 00 | 01 04  04 00 00 00 05 | 01 a9                   id 5, keyword 169
     | 00                                                   registration length 0
     | 04 …                                                 the OER
  ```

  Skipping zero bytes past the `al8o4l` words — the walk every release used
  until then — stopped on the first pair's `01` and read it as a token
  (`no decoder for response token 1`). 23ai leaves the pair count at zero and
  never showed it.

  **Not every `TTI_RPA` has the trailing fields.** A `changepassword` reply is
  `08 00` and then its OER (`04 …`) — no `al8o4l` words and nothing after
  them. Read by the execute layout, the OER's own `04 01 01 02 98` is taken for
  the `al8txl` length and the parse runs off the end, after the server has
  already changed the password. seerdb therefore reads the three fields only
  when they parse cleanly and land on a token, the end of the data or an armed
  row-count tail, and otherwise falls back to skipping zero bytes.

  **The Mirror's side of it (#859).** Two faults, and the reference client's
  `executemany` needed both fixed. The Mirror detected the request with the
  composite, so every array execute from that client was answered with a
  row-count block it never asked for; and the block it sent framed the counts
  as a private `ub4 zero | ub4 count | count × ub4` rather than the layout
  above. seerdb's own decoder accepted both shapes, which is why the Mirror
  passed its own suite; the reference client read the four words by name, took
  the count for `al8txl`, skipped that many bytes, and parsed the values as
  key/value pairs until a length byte of 4 sat where it expected a `ub2`
  (`DPY-5002`). The Mirror now tests `DML_ROWCOUNTS` alone and, when it is set,
  emits the block above with four empty words.

### 5.2 Fetch (TTI_FUN/TTI_FETCH)

For fetching additional rows from an open cursor:

```
TTI_FUN | TTI_FETCH | SeqNum | Cursor(SB4) | RowsToFetch(SB4)
```

The default fetch size is 100 rows (configurable via the `fetch` parameter),
matching oracledb's effective batch so a large `fetchall` drains in ~n/100
round-trips rather than ~n/15.

**sqlplus / thick OCI** sends the same call with fixed-width fields: `03 05
<seq>`, then the cursor and the row count as ub4 LE (`03 05 0f 02 00 00 00 0f
00 00 00` asks cursor 2 for 15 rows, which is what sqlplus 23.26 asks for). The
count is a hard limit here: sqlplus sizes its fetch buffer to it, and a reply
with more rows overruns that buffer and **crashes the client**. A live 11g
answers a 30-row query with 1 row in the execute reply, then 15, then the last
14. A batch with rows still to come ends with a plain success OER and the last
one with the `ORA-01403` OER. The Mirror does the same (#1284).

**When a follow-up FETCH is required.** The execute response ends with an
OER (`§6.7`). What says "more rows are available on the cursor" is the
*absence* of the end-of-fetch code: an OER whose error is `ORA-01403` means
the cursor is drained, anything else with a cursor handle means the client
must issue `TTI_FETCH` against that handle to receive the remaining rows.
This happens unconditionally when at least one column is a LOB (`§11.9`):
Oracle returns DCB + RPA piggyback + OER and no inline rows for LOB queries,
regardless of the result-set size, and in an open transaction it defers even
a single LOB row this way.

The OER's `call_status` is **not** a "more rows" flag. It is a flag word
(python-oracledb's `TNS_EOCS_FLAGS_*`): it reads `1` with autocommit on, `2`
while a transaction is in progress (`TXN_IN_PROGRESS`), `5` right after a
PL/SQL execute. seerdb once fetched only on `call_status == 1`, which worked
solely because autocommit on was the default; with autocommit off a LOB
SELECT of an uncommitted row returned no rows at all (#712).

**Client side: `transaction_in_progress` (#2456).** The connection keeps the
`call_status` of the last reply it decoded and reports its `TXN_IN_PROGRESS` bit.
That reply is either an OER or, for a bare commit or rollback, the `TTI_STA`
that is the whole reply (`17 <ub4 call_status> <ub2 sequence>`). Measured on 10g,
11g and 23ai: an INSERT or UPDATE sets the bit, and the commit's or rollback's
status clears it. The last reply's error code is kept too: after ORA-00028,
ORA-01012, ORA-01089, ORA-01092, ORA-02396, ORA-03113, ORA-03114 or ORA-03135 the
session is gone, and `is_healthy()` says False without a round trip. seerdb
doesn't read the bit from the 8i and 9i replies, so there the attribute is
refused rather than guessed.

**Server side: the transaction bit is not optional (#889).** A client reads
`TXN_IN_PROGRESS` (`0x02`) to decide whether releasing a connection to a pool,
or closing it, owes a **rollback**. python-oracledb sends no rollback at all
when the bit is clear — it believes there is nothing to roll back. A server that
always reports `0` therefore leaves every uncommitted statement's TM lock held
until the session finally dies, and the next statement needing an exclusive lock
on that table fails with `ORA-00054`. Measured against the Mirror before the
fix: an `INSERT` with no commit, then a pool release, then `truncate table` from
a second connection — the truncate was refused, where the same sequence against
a live 23ai succeeded. seerdb's own client hides the bug completely, because it
rolls back unconditionally on close.

The Mirror therefore tracks the session's transaction state and OR's the bit
into every OER it builds (`_ENCODE_TXN_IN_PROGRESS`). It is OR'd, not assigned:
the caller's `call_status` says what the *reply* is ("more rows" is `1`), the
bit says what the *session* is, and both must survive. DML and PL/SQL open a
transaction, an explicit commit / rollback closes it, autocommit closes it
immediately, DDL commits implicitly, and a query leaves it alone. Note the 11g
end-of-fetch terminator is a constant built at import time, so it has to be
re-encoded rather than handed out while a transaction is open.

seerdb implements the FETCH flow in `OracleConnect._drain_cursor`:
after the initial EXEC response, if the OER is not `ORA-01403` and a cursor
handle was returned, it loops issuing `TTI_FETCH` (with the prior
DCB's RowFormat threaded into the decoder via `_handle_response`'s
`Acc` parameter, since FETCH responses don't repeat the DCB) until
the server returns `ORA-01403` end-of-fetch. Rows are concatenated
across responses and surfaced as one result set; the 1403 sentinel
is masked to 0 so it doesn't reach the caller as an error. Works for
any large non-LOB SELECT; LOB column data still needs a per-column
row decoder (`§11.9`).

### 5.2.1 Server-side scrollable cursors

A scrollable cursor (`cursor(scrollable=True)`, #181) keeps the server cursor
open and fetches rows from arbitrary positions instead of draining forward once.
The whole feature rides the **OALL8 execute** message — there is no dedicated
scroll function. The scroll request lives in the `al8i4` array (the 13-element
All8 list):

- `al8i4[9]` — exec flags; OR in `SCROLLABLE (0x02)` and `NO_CANCEL_ON_EOF
  (0x80)` (so the cursor survives past EOF and can scroll back). On 23ai this
  joins the `0x8000` query flag → `0x8082`.
- `al8i4[10]` — fetch orientation: `CURRENT 0x01`, `NEXT 0x02`, `FIRST 0x04`,
  `LAST 0x08`, `PRIOR 0x10`, `ABSOLUTE 0x20`, `RELATIVE 0x40`.
- `al8i4[11]` — 1-based fetch position (for ABSOLUTE / RELATIVE).

Two other `al8i4` slots matter to anything parsing an execute, and they are easy
to confuse:

- `al8i4[7]` — the **is-query** flag, 1 for a SELECT.
- `al8i4[1]` — **two different things, told apart by `al8i4[7]`.** For a DML it
  is the execute iteration count (`1 + array-DML batch length`, and the only
  record of it when a `RETURNING` clause fills every bind, §22.1). For a **query**
  it is the number of rows to **prefetch**: 0 on the opening parse+execute, and
  the client's fetch array size (oracledb's `arraysize`, 100 by default) on any
  re-execute of a cursor it already holds. Reading the query form as an iteration
  count turns a plain re-executed SELECT into an N-iteration array DML — the
  query never runs and the client is answered with a row count (#826).

**`cursor.parse()` — parse without executing (#826).** The options word carries
`PARSE (0x01)` and **not** `EXECUTE (0x20)`; a query adds `DESCRIBE (0x20000)`.
Captured from a live 23ai:

| statement | options | reply |
|---|---|---|
| `select ... where IntCol = :val` | `0x20001` | `TTI_DCB` describe, then a plain status |
| `begin :value := 5; end;` | `0x01` | a plain status |
| `insert into t (IntCol) values (:1)` | `0x01` | a plain status |

Two things a server has to get right here. The message **carries no bind values**
however many placeholders the statement has, so running it anyway fails with
`ORA-01008: value for bind variable placeholder was not provided`. And the query
reply is the describe followed by a **success** status — not the end-of-fetch
`ORA-01403` a real fetch ends on, because nothing was fetched.

The test is **not** the `PARSE` bit (#984). `PARSE` rides along with `EXECUTE` on
the first execute of any statement, and — the part that is easy to miss — the
**second** `parse()` of one statement does not set it at all. By then the client
has the statement cached, so it sends an OALL8 by cursor id with an empty
statement and options `0x0`: nothing to parse, nothing to run. Reading the PARSE
bit takes that for an ordinary execute and runs it, and since a parse carries no
bind values the server answers the same `ORA-01008` this whole paragraph is about.

So what marks a parse is the **absence of any bit asking for work**. Measured on
a live 23ai:

| call | options | |
|---|---|---|
| `parse()`, statement unseen | `0x1` | PARSE |
| `parse()`, statement cached | `0x0` | — |
| `parse()` of a query | `0x20001` | PARSE \| DESCRIBE |
| `execute()`, cached | `0x8029` | NOT_PLSQL \| COMMIT \| EXECUTE \| PARSE |
| `execute()`, first / DDL | `0x8021` | NOT_PLSQL \| EXECUTE \| PARSE |
| a SELECT | `0x8061` | NOT_PLSQL \| FETCH \| EXECUTE \| PARSE |
| define round-trip | `0x8010` | NOT_PLSQL \| DEFINE |
| scroll re-execute | `0x8040` | NOT_PLSQL \| FETCH |

The last two have no `EXECUTE` and are still not parses — one takes the rows
already parked (§14.5d), the other repositions an open cursor (§11.8) — so the
test is "no `EXECUTE`, no `DEFINE`, no `FETCH`".

**Sending one** (#1018). Everything else in the OALL8 is byte-identical to an
ordinary execute of the same statement — the al8i4 array, the SQL, the header
fields — with two exceptions, both of them query-execute fields that have to
come off *with* the `EXECUTE` bit:

- the **prefetch row count** (the header's `Fetch` field) is `1`, not the
  connection's fetch array size;
- **al8i4[9]** carries no query flag: on 23ai an ordinary SELECT sets `0x8000`
  there (§20.4), and a parse must not.

Leaving either in place asks the server to fetch, and it answers `ORA-01002:
fetch out of sequence`. So does draining the cursor afterwards: the reply to a
query parse is a describe with **no result set**, so the usual follow-up
`TTI_FETCH` (§5.2) fetches from a cursor the parse never positioned. A client
must skip the drain for a parse — the cursor is still queued for close.

**Open** — a normal parse+execute (cursor 0, SQL present) with the al8i4 scroll
fields and orientation `CURRENT`/1. It keeps the fv24 query options `0x8061`
(`NOT_PLSQL | FETCH | EXECUTE | PARSE`) and prefetches only a small batch
(oracledb's `prefetchrows`, default 2) so the cursor stays mid-stream rather than
draining to EOF.

**Scroll re-execute** — a no-parse OALL8 against the open cursor (cursor id set,
empty query) with the new orientation/position in al8i4. Two things differ from
the open and from every other execute, both required or the server rejects the
call as malformed (`ORA-03137 [12316]`):

1. **Exec options `0x8040`** (`NOT_PLSQL | FETCH`, **no** `EXECUTE 0x20`). With
   EXECUTE set the server re-runs the query and resets to the top, so the
   orientation positions from row 1 and every scroll comes back empty. `set_opts`
   structurally forces the `0x20` bit on for a `Flag=0` select, so
   `encode_dictionary_exec` clears it for a scroll re-execute.
2. **No length-prefixed SQL.** The empty query must emit *no* bytes — the 12c+
   path otherwise writes a zero-length prefix (`0x00`), which shifts the server's
   read of the al8i4 array by one byte. This path is unique to scroll: every
   other 12c+ execute carries real SQL (the statement cache is disabled on 12c+,
   so there are no empty-query re-executes elsewhere).

The response echoes the cursor's **cumulative row position** in the OER
`rowcount` field — the absolute row number of the last row in the batch. The
client places its buffer window from it: `buffer_min = rowcount − batch_len + 1`
(oracledb's `_post_process_scroll`).

**Fetch-on-demand.** When the client buffer drains, the next batch is fetched as
another **positioned scroll re-execute** with orientation `CURRENT` at the next
absolute row — **not** a plain `TTI_FETCH`. Mixing a `TTI_FETCH` in advances the
physical cursor but desyncs the server's scroll reference, so a later `RELATIVE`
scroll returns the wrong rows. Every batch, forward or repositioned, is a
re-execute.

**Column compression on reposition (row-header bit vector).** When a scroll
lands on a row whose column value equals the last row already returned, the
server omits the value and flags the column "reuse previous" in the row-header
bit vector (`§6.1`) rather than a standalone `TTI_BVC`. A common trigger is
`LAST` after the buffer already reached EOF (the last row repeats). The bit
vector must be passed to the row decoder; duplicate detection is per-response, so
across a re-execute the client seeds the previous fetch's last row to resolve the
reused column.

**Tiers.** Server-side scroll works on 10g+ (the OALL8 path: fv4/fv6/fv16/fv24
all verified). 9i (field version 2) speaks the older TTI_ALL7 dialect and has no
OALL8 scroll, so `scrollable=True` there falls back to a client-side buffered
scroll over the fully-fetched result set (#161): `scroll()` is a local index
move, available in every mode.

**Server side (the Mirror, #485).** The Mirror answers scroll entirely from a
materialised result — it reads `al8i4[9]` for the SCROLLABLE flag and
`al8i4[10]`/`al8i4[11]` for the orientation and position (`parse_exec`), then:

- **Open** (cursor 0, SQL present, SCROLLABLE set) — runs the query on the
  backend, parks the *whole* row set keyed by a fresh cursor id (a scrollable
  cursor stays open and revisits arbitrary rows, unlike the forward-only
  `_Cursors` that hands out and forgets batches), and replies with describe +
  the first `prefetch` rows + a terminator carrying the cursor id and the
  cumulative row number.
- **Re-execute** (an open scroll cursor id, empty SQL) — resolves the start row
  (`FIRST`→1, `LAST`→the last row; `ABSOLUTE`/`RELATIVE`/`CURRENT` take the
  client's already-absolute position verbatim), slices `rows[start-1 :
  start-1+fetch]`, and replies with just that batch + terminator. A position
  off either end yields an empty batch ending in `ORA-01403`.

The terminator sets the OER `rowcount` to the absolute position of the last row
delivered and reports `ORA-01403` once a batch reaches the end. The Mirror never
emits the row-header **bit-vector compression** — it always sends full column
values — so a `LAST`-after-EOF reposition that repeats the last value still
decodes correctly (the client's previous-row seed simply goes unused). Because
scroll is a wire-level feature, the same Mirror path serves the sync and async
clients identically.

### 5.3 OAC (Oracle Access Column) Descriptor

Each bind variable or column is described by an OAC structure:

```
DataType(UB1) | Flags(3) | Precision(0) | Scale(0) |
MaxDataLength(SB4) | MaxArrayElem(0) | ContFlags(SB4) |
OID(0) | Version(0) | CharsetID(SB4) | CharsetForm(UB1) | MXLC(SB4)
```

**CharsetForm**: `1` for database charset, `2` for national charset (AL16UTF16).

**OID (object / REF binds)**: the `OID` slot holds the referenced type's 16-byte
OID for an object (type 109) or REF (type 111) bind, and is written with **two
lengths** (`write_bytes_with_two_lengths`: a `ub4` count then, only when
non-empty, the length-prefixed bytes) — **not** a plain DALC. For a scalar bind
the OID is empty and both forms are the single byte `0x00`, so a decoder that
reads it as a bare DALC works for every scalar but **desyncs the whole OAC** on a
real 16-byte OID (it reads the leading `ub4` count as the value), dropping the
next bind — which the server reports as `ORA-01008` (missing placeholder). The
Mirror's `decode_oac_fields` reads the two-length form and pairs the OID with the
REF locator (the bind value, a plain DALC) to rebuild the `DbRef` the backend
re-binds (#139).

The layout above is the 11g form. 12c+ (field version >= 12.1,
`encode_token_raw`) uses oracledb's `_write_column_metadata` layout instead:
a fixed flag byte (`TNS_BIND_USE_INDICATORS = 1`), `ContFlags` as a `ub8`, an
`OID`/`Version`, the bind charset as a `ub2` (AL32UTF8 = 873 for char binds,
0 otherwise), the `CharsetForm` byte, a LOB-prefetch length, and — from 12.2
only — a trailing `oaccolid` `ub4`. A 12.1 session sent the `oaccolid` answers
`ORA-03106`; one sent the 11g layout, `ORA-03120` (#1144). The hand-built OACs
(LOB, object, REF) follow the same rule, except that below 12.1 the LOB one
keeps the trailing field it has always carried. Sending the 11g OAC to a 12c server is rejected with
`ORA-03115` (unsupported network datatype). The bind *value* (TTI_RXD) is the
same in both, except long values use the version-gated `bytes_with_length`
chunking described in §6.4 (`encode_chr`): 11g chunks anything over 64 bytes
with single-byte lengths, 12c+ sends a single length byte for values up to
252 bytes and `ub4` chunks from 253 bytes up (sending the 11g chunking to 12c
gives `ORA-03120`). The boundary is 252, not 253: `0xFD` (253) is the TTC
escape byte, `0xFE` opens a chunked value and `0xFF` is NULL, so a 253-byte
value or statement text sent behind a plain length byte is an escape where
the server expects a length, and 12c+ rejects the whole call with `ORA-03125`
(#707). python-oracledb's `TNS_MAX_SHORT_LENGTH` is the same 252.

**MaxDataLength and the LONG-reorder trap**: `MaxDataLength` must reflect the
value's real size, **not** a flat maximum. A VARCHAR/RAW bind whose
`MaxDataLength` exceeds the 4000-byte VARCHAR2 limit is treated by the server
as a streamed LONG and processed *after* the following bind — which silently
reorders binds relative to their placeholders (so e.g. `SET name=:1 WHERE
id=:2` binds the string to `id`). seerdb therefore sizes a VARCHAR/RAW OAC to
the actual value's byte length (NULL → 1); values genuinely over 4000 bytes
keep their true size and the intended LONG handling (the multi-KiB CLOB/BLOB
regular-path bind). For array DML the single OAC is sized to the widest value
in each column across all rows, and its **type** is taken from a non-NULL value
in the column, not the first row: a column NULL in row 0 but holding a value
later would otherwise type as a minimal VARCHAR2, and the later value overflowed
it on a real server (ORA-01461 — the value exceeded the maximum VARCHAR2 length,
which a DataFrame column with a leading NULL hits, #894). A column NULL in every
row keeps the VARCHAR2 NULL bind.

### 5.4 Bind Data (TTI_RXD)

Bind values are encoded inline following OAC descriptors:

| Python Type             | Wire Encoding                                          |
|-------------------------|--------------------------------------------------------|
| `int`, `bool`           | Oracle NUMBER format (length-prefixed mantissa bytes)  |
| `float`, `complex`      | Oracle NUMBER format (non-finite `inf`/`nan` auto-route to BINARY_DOUBLE) |
| `decimal.Decimal`       | Oracle NUMBER, exact base-100 encoding (all significant digits preserved, up to Oracle's ~38-digit limit — no float detour) |
| `seerdb.BinaryFloat`    | 4-byte order-preserving IEEE-754 (§11.7)               |
| `seerdb.BinaryDouble`   | 8-byte order-preserving IEEE-754 (§11.7)               |
| `str`                   | Length-prefixed UTF-8 character data (chunked if > 64 bytes) |
| `bytes` / `bytearray`   | Length-prefixed RAW (verbatim bytes)                   |
| `datetime.date`         | 7-byte Oracle DATE (century, year, month, day, h, m, s) |
| `datetime.datetime`     | 7-byte DATE if microsecond == 0; otherwise 11-byte TIMESTAMP (+ 4-byte BE nanoseconds) |
| `datetime.datetime` w/ `tzinfo` | 13-byte TIMESTAMP WITH TIME ZONE (UTC wall clock + offset bias bytes) |
| `datetime.timedelta`    | 11-byte INTERVAL DAY TO SECOND (§11.6)                 |
| `seerdb.IntervalYM`     | 5-byte INTERVAL YEAR TO MONTH (§11.5)                  |
| `None`                  | Single `0x00` byte                                     |
| `seerdb.Var` (OUT/IN OUT) | the seeded value, or `0x00` (NULL) for a pure OUT; OAC driven by the Var's declared type |
| `Var(seerdb.ROWID)` / `Var(DB_TYPE_UROWID)` | the rowid's text; OAC a VARCHAR of 5267 characters, the longest universal rowid, on every tier from 8i (#1397, #1399) |
| `seerdb.cursor.cursor` / `Var(seerdb.CURSOR)` | a `ub4` count, then that many `ub4` cursor ids; OAC type 102, buffer 4, charset 0, the same for IN and OUT (below) |

**A REF CURSOR bind carries cursor ids, not a DALC** (#1047). The OAC is the
same for IN and OUT (`66 01 00 00 01 04 00 00 00 00 00 00 00`); only the value
differs: `07 00` for OUT (count 0, "open one for me") and `07 01 01 01 03` for an
IN bind of cursor 3 (count 1, id 3). A narrower OAC (buffer 1, the database
charset) is harmless for OUT, where the server fills the slot, but for IN the
server sizes its buffer from the OAC and then waits for bytes that do not fit: a
hang, not an error. A server that reads the value as a DALC gets the count where
it wanted the id, and the two are often both 1. The bound cursor must still be
open on the server with rows unread; one already fetched to its end is answered
`ORA-01007`.

**A NULL bind still has to declare a type** (#696). The row data for one is the
same single `0x00` whatever it stands for, so the OAC in front of it is the only
thing that says what the server should treat it as. A client that types the bind
from the value has nothing to go on and sends the default character descriptor;
the server then takes the bind as CHAR and refuses to compare it to anything
else:

```
select id from t where case when :foo is not null then :foo else d end = d
ORA-00932: expression ("T"."D") is of data type DATE,
           which is incompatible with expected data type CHAR
```

This is not a driver quirk — it is what any client does until told the type, and
python-oracledb fails on the same statement identically. The type is supplied out
of band, through `Cursor.setinputsizes`, which changes only the OAC: seerdb binds
such a position as a `Var` of the declared type, so the descriptor announces it
while the row data stays the same `0x00`.

**And once declared, the declaration governs the payload too** (#701). The server
measures the row data against the descriptor, so a bind that announces one type
and sends another is rejected — `ORA-01483: invalid length for DATE or NUMBER
bind variable`. This bites wherever one Python type has more than one width on
the wire:

| Value | Declared | Sent |
|-------|----------|------|
| `datetime` with microseconds | DATE | 7 bytes, microseconds dropped |
| the same value | TIMESTAMP | 11 bytes, microseconds kept |
| `float` | NUMBER (default) | base-100 NUMBER |
| the same value | BINARY_DOUBLE / BINARY_FLOAT | 8 / 4 IEEE-754 bytes |

The declared type wins and the value is coerced to it, which is both what the
descriptor already promised and what python-oracledb does.

**Chunked encoding** (for data > 64 bytes): `0xFE` header, then repeated `<length><data>` chunks of up to 64 bytes each, terminated by `0x00`.

**Array DML** (`executemany`): the OAC descriptors are sent once (sized to the
widest value in each column across all rows), the All8 iteration count is the
number of rows, and each row's values follow as its own `TTI_RXD` token after
the OAC block.

Because there is one descriptor per column, **every row must fit the type that
descriptor declares**. That is not automatic for a temporal column. A
`datetime` with no sub-second part is bound as DATE, and one with microseconds
as TIMESTAMP. A batch mixing the two was declared by one row's type, and an
11-byte row under a DATE descriptor made the server answer `ORA-01483: invalid
length for DATE or NUMBER bind variable`.

seerdb therefore declares such a column TIMESTAMP (#1098). Only the declaration
widens. Each whole-second row still goes out in the 7-byte form, which a
TIMESTAMP descriptor takes as §11.4b describes, so the bytes match
python-oracledb's and a declared bind's (#1805). The values are unchanged, and a
DATE column still truncates the sub-second part server-side. Aware values are
left alone: widening one would mean inventing a zone for the others. This
concerns binds whose type comes from their values; a bind *declared* TIMESTAMP
or LTZ follows §11.4b.

**LONG-class binds come last** (#705). The server takes a character or RAW bind
in place only up to its *maximum string size*: 32767 bytes when its runtime
capability vector carries the 32K TTC bit (`RCAP_TTC` bit `0x04`, which 12c and
later advertise), 4000 bytes otherwise (10g, 11g). A bind whose OAC declares
more than that is a LONG-class bind, and the server reads a row's LONG-class
values only after it has read all the row's other values. So each `TTI_RXD` row
is written as the non-LONG values in bind order, then the LONG-class values in
bind order:

```
insert into t (id, a, b) values (:1, :2, :3)     :2 = Var(str) -> OAC 32767
OAC   NUMBER(22)  VARCHAR(32767)  VARCHAR(6)
RXD   1  'second'  'first'                       <- :3 before :2 on 11g
```

Written in place nothing fails: the server takes `:3`'s value for `:2` and
`:2`'s for `:3`, and the two columns silently swap. A `seerdb.Var(str)` declares
32767 by default, so any Var followed by a plain bind hit this on 10g and 11g,
while 21c and 23ai, which take 32767 in place, never showed it. The same rule is
what lets a plain string over 4000 bytes reach a CLOB on 11g through the regular
bind path (its OAC is sized to the value, so it is LONG-class there). PL/SQL
blocks are exempt: their values always ride in place. So are associative-array
binds. python-oracledb applies exactly this rule; the Mirror reads rows by it.
8i and 9i apply the same 4000-byte rule through their own request forms
(§19.11, §19.3), so their builders write rows the same way (#714, #723). A 9i
PL/SQL block keeps every value in place.

## 6. Response Processing

### 6.0 A SELECT response, server-side (the Mirror)

For completeness, the whole shape a server sends in reply to an `OALL8`
execute of a query (`seerdb/server/query.py` builds it — the inverse of the
decoders below):

```
TTI_DCB  describe (§6-describe): cursor-uuid preamble + column metadata
TTI_RXH  row header (§6.1)
TTI_RXD  one per row (§6.2): each column value a DALC
TTI_OER  status (§6.5): ORA-01403 "no data found" ends the fetch
```

The describe rides **inline** in the first execute's response (no separate
describe round-trip). The client reads rows until the terminal OER; a `1403`
status means "cursor drained" (all rows delivered), *not* an error — so a
finite result set with every row already sent terminates on `ORA-01403`, and
the client hides that sentinel from the caller. Only the describe's column
type/length/charset/name and the row DALC values carry meaning; the many
skipped scalar fields are emitted as well-formed zeros.

**Batched fetch (the Mirror).** A result set larger than the execute's requested
fetch count is not inlined whole — it is returned in batches (§5.2). The execute
response carries the describe + the first `fetch` rows and, if rows remain, ends
with a **"more rows"** OER instead of `1403`: `call_status = 1`, error `0`, and a
non-zero **cursor id** (`encode_more_rows`). The client then issues
`TTI_FETCH(cursor_id, fetch)` calls, each answered with the next batch (rows +
terminator, *no* describe — the metadata is already established), until the
server sends `ORA-01403`. The Mirror keeps the undelivered rows per cursor id in
`_Cursors` (its only cross-call state), dropping a cursor once drained. Batching
matters even for a moderately large result set: the client's row decoder recurses
once per row within a single response, so inlining thousands of rows would exhaust
the recursion limit — fetch-sized batches keep each response shallow.

**A zero prefetch means no rows on the execute** (#856). The execute's `fetch`
field is the client's prefetch, and a zero is a real value with its own meaning:
*send none of the result inline, I will ask for it*. It is not "no limit". A
client that turns prefetching off (`prefetchrows = 0`) allocates no fetch buffer
on the execute, so rows sent anyway are written past the end of its define
array — the reference thin client dies inside its own row decoder with an
`IndexError` in `_process_row_data`, before the reply can become an error anyone
can read. Captured off a live 23ai, a prefetch-0 `SELECT` execute answers with
**describe + status and not one `TTI_RXD` token** (149 bytes), the whole result
waiting on the cursor for the following `TTI_FETCH`. The Mirror applies the rule
in `_prefetch_batch` at the three places a prefetch governs an execute reply:
the ordinary query, the scrollable open, and `REEXECUTE_AND_FETCH`. A
`TTI_FETCH` and a scroll *reposition* are the other kind of request — they ask
for rows now rather than declaring a prefetch — so a zero there still means "as
many as there are".

The rule reaches one more reply that is easy to overlook: the **define
re-execute** of a LOB-class result (§14.5d). That round-trip serves rows the
opening execute parked rather than running the statement again, but it is still
an EXECUTE, so its `fetch` field is still a prefetch — a zero there sends no
rows and leaves the result on the cursor, `more` set, for the `TTI_FETCH` that
follows. Reading that particular zero as "all of them" does not overrun anything
(the client has applied its define by now), so it fails in a quieter way: the
values arrive one round-trip early, inside `execute()` instead of on the fetch,
and any error decoding them surfaces from the wrong call (#1113). A REF CURSOR
re-execute, which shares the same code path, is a fresh open rather than a
continuation, and no capture yet says what a real server prefetches for one.

**Temporal values are width-fixed by the column type, not the value.** The
client-side encoder (§10.3) is value-driven — it picks 7/11/13 bytes from
whether a `datetime` carries sub-second or zone parts — but a *column* must emit
one consistent width for every row it describes. So the server encodes each
temporal value by its column's `data_type`: `DATE` (12) → 7 bytes (second
precision), `TIMESTAMP` (180) → 11 bytes always (a value with no microseconds
still writes 4 zero nanosecond bytes), `TIMESTAMP WITH TIME ZONE` (181) → 13
bytes (a naive value is taken as UTC). `seerdb/server/query.py::_encode_temporal`
does this; the example backends map each source column to the matching Oracle
type (Postgres `date`/`timestamp`/`timestamptz` OIDs 1082/1114/1184; SQLite a
column declared `DATE`/`TIMESTAMP` via `PARSE_DECLTYPES`).

**Numeric values follow the column type too.** A `NUMBER` (12) column encodes as
base-100 (`encode_token_num` / `encode_token_decimal`), carrying its
precision/scale in the describe; a `BINARY_FLOAT` (100) / `BINARY_DOUBLE` (101)
column encodes the IEEE-754 value in Oracle's order-preserving form (§11.7)
rather than converting to decimal. The example PostgreSQL backend maps `numeric`
→ NUMBER (with `numeric(p, s)` precision/scale) and `float4` / `float8` →
BINARY_FLOAT / BINARY_DOUBLE, so a float column stays an exact IEEE float instead
of a base-100 approximation.

**Transaction control (the Mirror).** The client drives commit / rollback two
ways, both of which the Mirror honours. In autocommit mode it sets the
commit-on-success bit (`0x100`) in the OALL8 options word, and the Mirror
commits the backend right after a successful execute. In explicit-transaction
mode it sends a bare `TTI_COMMIT` (14) / `TTI_ROLLBACK` (15) function message and
blocks for a reply; the Mirror runs `backend.commit()` / `rollback()` and answers
with a success status (`encode_status(0)`) — a message the loop must handle, or
the client's `commit()` hangs waiting. Backends therefore run transactionally
(not autocommit) so a rollback truly discards. The example PostgreSQL backend
wraps each statement in a `SAVEPOINT` so a failed statement rolls back only
itself and the surrounding transaction survives — Oracle's statement-level error
model, not PostgreSQL's abort-the-whole-transaction default.

**Array DML / `executemany` (the Mirror).** An array-DML execute carries the OAC
type descriptors once (one per bind column) followed by **one `TTI_RXD` row per
iteration**. `parse_exec` reads the column types, then loops consuming an RXD row
(a `TTI_RXD` token plus one DALC per column) until the rows run out — a plain
execute is just the one-row case. The session applies every row through the
backend and replies with the **summed** affected-row count, so `cursor.rowcount`
matches the total inserted/updated.

With **`batcherrors`** (the `0x80000` options bit, which `parse_exec` now reads),
the session applies the good rows and catches each per-row `BackendError` instead
of aborting, collecting `(offset, code, message)`. It then replies with
`encode_batch_errors_status`: an OER carrying a non-fatal `ORA-24381` and the
three position-aligned batch-error arrays — codes and offsets as `ub4 count`
+ a DALC blob of packed `ub4`s, messages as `ub4 count` + indicator + per-message
`ub4`-length text (§6.7). The client surfaces them through `getbatcherrors()`
rather than raising, and the applied rows still commit.

**The errors are not in row order** (#1031). Measured on a live 23ai, with each
batch arranged so the orders disagree:

| the batch | reported |
|---|---|
| dup@1, check@2, too-large@3 | `(2, ORA-02290) (3, ORA-01438) (1, ORA-00001)` |
| dup@2, too-large@4 | `(4, ORA-01438) (2, ORA-00001)` |
| dup@1, dup@3 | `(1, ORA-00001) (3, ORA-00001)` |

It is not an ordering on the codes either — `ORA-01400` precedes `ORA-01438` in
one arrangement and follows it in another. Everything comes in **row order
except the unique-constraint violations, which come after all of it**, each
group still ascending. That is what index maintenance being a separate pass
looks like from outside: a column conversion (`ORA-01438`), a `NOT NULL`
(`ORA-01400`) and even a `CHECK` (`ORA-02290`) are evaluated with the row, while
the unique index is updated afterwards. A server that applies the rows one at a
time — the Mirror does — collects everything in row order and has to re-group.
Only `ORA-00001` was measured; a foreign key is presumably the same pass.

**`batcherrors` and `arraydmlrowcounts` are not alternatives.** One execute may
set both, and then the `ORA-24381` reply owes the per-iteration counts as well —
the `TTI_RPA` block (§6.7) rides in front of it exactly as it rides in front of a
success status. A row that failed affected nothing and **still holds its slot**
in the counts, or every count after it shifts.

The same is true of a batch that **aborts**: a client that asked for
`arraydmlrowcounts` is owed the counts for the rows that did apply in the ERROR
reply too. Without them it reports the mode as never enabled, which tells the
caller less than the failure does — and the rows really were written.

**Cursor cache (the Mirror, #80/#486).** On the pre-12c connection the client
caches a DML's server cursor id keyed on `(SQL, bind-OAC signature)` and, on the
next identical execute, sends a **re-execute**: the cursor id set, an **empty
query**, and the bind values as a `TTI_RXD` row with **no OACs** (the server is
expected to remember the bind format from the first parse). So the Mirror returns
a fresh cursor id in the DML status OER (`encode_status(rowcount, cursor_id)`) and
remembers the SQL + bind types keyed by that id. On a re-execute it reads the
cursor id and empty-query flag from the header (`peek_exec_cursor`), hands the
remembered bind types to `parse_exec` so the OAC-less RXD decodes, runs the stored
SQL with the new binds, and replies with the same cursor id. A PL/SQL block is
never assigned an id (the client doesn't cache blocks).

**An empty query does not imply absent OACs** (#859). That is seerdb's own
client's convention, not the protocol's: the reference thin client also sends
empty-SQL executes — its `executemany` after the first, on the same cursor — and
those still carry a full set of bind descriptors. A server that infers "no SQL,
therefore use the remembered types" then leaves its read position on an OAC where
it expects a `TTI_RXD`, finds no bind rows at all, and hands the backend an
execute with no values (`ORA-01008`). Decide from the wire instead: the
descriptors are absent exactly when the bind area already sits on a `TTI_RXD`
token, and the remembered types are the fallback for that case alone.

**Only real DML may be cached** (#703). Reusing a cursor is a saved *parse*: the
statement is parsed once and executed again per set of binds, which is exactly
how INSERT / UPDATE / DELETE / MERGE work. DDL is different — it does its work
when the server **parses** it, so a re-execute has nothing left to do. The server
answers such a re-execute with an ordinary success status and changes nothing,
raising no error, so the statement is lost in silence:

```
create table t (id number)   -- first time: parsed, table created
drop table t
create table t (id number)   -- cached re-execute: "success", no table
```

Measured on 10g and 11g, which use the cache; 21c and 23ai are unaffected because
the cache is disabled from 12.1. Anything that is not one of the four DML verbs
must therefore be re-parsed, including statements the client cannot classify —
being wrong that way costs a parse, while being wrong the other way loses the
statement.

**DDL flushes the cache, and a LONG-class statement is never cached** (#720).
A cursor the server has invalidated, because its table was dropped and
re-created, is not merely re-parsed on the next re-execute: on 10g and 11g the
server reused the **previous execution's value** for a LONG-class bind (§5.4)
when the new execution bound NULL for it. The stale bytes then hit the new
column, `ORA-12899` when it is too narrow for them, stored in silence when it is
not. The client therefore forgets every cached cursor when the session runs
DDL or a PL/SQL block (closing them with the next call's OCCA piggyback), and
never caches a statement that carries a LONG-class bind at all, since the DDL
may come from another session. A plain string bind is sized to its value and
is safe to cache.

**The re-execute functions (the Mirror, #833/#854).** The 12.1+ thin client
does not re-send an OALL8 for a statement it has already executed on a cursor.
Once the cursor id is set, the statement executed, and nothing about it changed
(bind *types* unchanged, not DDL, not scrollable / batch-errors / parse-only),
the next execute goes out as a **re-execute** — one of two functions with the
same body, `_write_reexecute_message` in the reference client:

```
03 <func> seq [ub8 token @fv24] | ub4 cursor | ub4 iterations | ub4 options_1 | ub4 options_2 | (07 <row>)*
```

- **`REEXECUTE_AND_FETCH` (78)** — a query with `prefetchrows > 0`:
  `iterations` is the prefetch size and `options_1` carries `EXECUTE` (0x20).
  The reply is a fetch: the first batch of rows and a terminator, no describe.
- **`REEXECUTE` (4)** — everything else: every repeated DML / PL/SQL call, and a
  query with prefetching off. `iterations` is the execution count (`num_execs`,
  > 1 for an `executemany` whose batch size matched the first one), `options_2`
  bit 0 is `COMMIT_REEXECUTE` (the client's autocommit). One `TTI_RXD` row per
  iteration follows, **with no OACs**: the values are typed by the OACs of the
  execute that opened the cursor, which the server remembers. Captured off 23ai:

  ```
  03 04 08 00 | 01 03 | 01 01 | 00 | 00 | 07 02 c1 03 04 72 6f 77 32      INSERT ... (:1, :2) with (2, 'row2')
  03 04 0b 00 | 01 05 | 01 01 | 00 | 00 | 07 01 79 02 c1 06               UPDATE ... s = :1 WHERE id > :2 with ('y', 5)
  03 04 0d 00 | 01 04 | 01 01 | 00 | 00 | 07 02 c1 04                     SELECT ... WHERE id > :1, prefetchrows = 0
  ```

  The reply is a bare **status OER** — `call_status 2 | seq | rowcount | 0 |
  0 0 | cursor | 0 | sql_type…` — the same shape as the OALL8 cached
  re-execute's, with the affected-row count for DML (`01 01` = 1, `00` = 0 for
  the UPDATE that matched nothing) and **rowcount 0 for a query**, whose rows
  the client then drains with `TTI_FETCH` against the same cursor id.

The Mirror serves 4 by reshaping it into the OALL8 cached re-execute it already
answers: the cursor supplies the SQL and bind types (kept for query cursors too),
`parse_reexecute` decodes the rows with them, and a DML cursor runs through the
ordinary execute path — array rows, autocommit, temp-LOB binds and all — while a
query cursor runs with its fresh binds, parks every row, and answers
`encode_status(0, cursor_id)`. A cursor id the session does not hold is refused
as `ORA-01001` rather than acknowledged with a zero rowcount. Before #854 the
function was refused outright as `ORA-03115 (TTC function 4)`, so through the
Mirror only the *first* execute of any statement worked with the reference
client — a loop of inserts died on its second iteration.

**OALL8 execute request — two preamble widths (the Mirror, OCI dialect, #866).**
The OCI execute's header up to the SQL is a fixed preamble: 8-byte
`FE FF FF FF FF FF FF FF` pointer indicators (§4.1.2) with scalar slots between
them, and the ub1-length-prefixed SQL text at the end. It comes in **two widths**,
and which one a client sends is fixed for the life of its connection:

| field | wide (sqlplus 11.2-era) | narrow (sqlplus 23.26) |
| --- | --- | --- |
| scalar slots | `ub8` | `ub4` |
| options (`ub4`) | 3 | 3 |
| cursor id (`ub4`) | 7 | 7 |
| SQL length (`ub4`), see below | 19 | 19 |
| second indicator | 27 | 23 |
| bind count (`ub4`) | 83 | 71 |
| SQL text | 196 | 176 |

Five slots shrink from 8 bytes to 4, so the narrow preamble is **20 bytes
shorter** overall — but they are spread through the header, so each field behind
them moves by a **different** amount, the running total of the slots ahead of it:
the second indicator by 4, the bind count by 12, the SQL text by the full 20.
The cursor id and the SQL length sit ahead of all five and do not move.

**The options word** is the thin form's, little-endian, in every width
(sqlplus 10.2 and 23.26 alike). Its commit bit `0x100` is how `SET AUTOCOMMIT ON`
asks for a commit: sqlplus sets it on each statement, sends no COMMIT call of its
own, and prints "Commit complete." on the success reply, so the server commits
after a statement that succeeds (#2011). Measured against live 11g and 23ai: the
`INSERT` captured with the setting off and on differs in that bit alone, and the
row survives a later `ROLLBACK` only with it on. At field version 24, as sqlplus
23.26 speaks to a 23ai directly, 14 bytes more sit between the sequence number
and the options word; the Mirror never negotiates that layout with sqlplus.

sqlplus 10.2 sends a third form: the narrow preamble with the bind count still
at 71 but the SQL text at **148**, 28 bytes earlier, in every statement it sent
to 10g and 11g (#1764). That is 48 bytes shorter than the wide form, and its
close-cursors piggyback is 48 bytes shorter too. Its pointer fields hold real
addresses rather than the indicator, and an address at 23 can leave bytes at 27
that look like one, so the session's field version, not the wire, says which
form it is.

**The SQL length depends on the client's character set** (#1427). A client in
AL32UTF8, the database's own, declares the SQL's byte length. One in any other
set (UTF8, US7ASCII, the unset default) declares **three times** it, a conversion
buffer's worth. Measured with sqlplus 23.26 on `select 1 from dual`: `0x12` with
`NLS_LANG=…AL32UTF8`, `0x36` with `…UTF8`. The ub1 prefix before the text is the
byte length either way. A server that always divides by three rejected every
AL32UTF8 statement, and sqlplus failed each one with SP2-0642. The
indicators stay 8 bytes wide in both, and that is what makes the two forms
tellable apart on the wire: the second indicator is at 27 in the wide form and 23
in the narrow one, and the two cannot both hold (the pattern starts `FE` and
continues `FF`, so an indicator at 23 puts `FF` at 27). The bind section behind
the SQL is read by scanning from the end of the SQL text, so it is the same in
both widths and needs no offset of its own.

**A statement longer than 252 bytes is chunked**, as on the thin path: the length
prefix is `0xFE`, then `<ub1 len><bytes>` runs end at a zero length. The bind
section starts after the chunks, the same as after a short statement. sqlplus's
`SHOW ERRORS` query is one (#2028): `SELECT … FROM ALL_ERRORS A WHERE A.NAME =
UPPER(:NMBIND_SHOW_OBJ) …`, longer than 252 bytes with one bind. Its descriptor
reads `01 01 20 00 00 18 00 00 00`, a VARCHAR2 of 24 bytes with the flag byte
`0x20` where an ordinary bind has `0x03`; its value is a plain DALC all the same.
sqlplus 23.26 sends the same bytes direct to 18c. The Mirror read binds only after
a short statement, refused this one with ORA-03115, and `SHOW ERRORS` failed.

**A placeholder name used twice in a SQL statement** (`select :n a, :n b from
dual`) counts in the bind count once per occurrence, and each occurrence has a
descriptor. A repeat's descriptor is `01 01 80 00 00` with a zero size: type byte
1, flag byte `0x80`, and nothing that says which earlier name it repeats. The RXD
row then holds one value per distinct name, in first-appearance order. For
`select :s a, :n b, :s c from dual`, the descriptors are VARCHAR2 30, NUMBER 22
and the repeat, and the row is `07 01 78 02 c1 08`: two values for three
placeholders. sqlplus 23.26 sends this to 18c (#2034); sqlplus 11.2, through a
Mirror that reads it so, prints what it prints direct. The reader matches each repeat to its name by the statement's
placeholders, in order. It hands the backend one value per occurrence, as a thin
client sends for a SQL statement. The Mirror refused these statements until then.
A PL/SQL block (`exec :n := :n + :n`) counts each name once and has no repeats.

`_oci_all8_layout` picks the width from the wire on every execute rather than
assuming one, and raises when neither shape holds. Read with the wide offsets, a
narrow execute lands 20 bytes past the SQL length prefix, and the Mirror then
answered every modern-sqlplus statement with a no-rows success status, which
sqlplus reports as `SP2-0642: SQL*Plus internal error state 2090` on the first
query whose row it needs (its `SELECT DECODE(USER, …) FROM SYS.DUAL` login
probe). Read with one **global** 20-byte shift instead of per-field ones, the
bind count comes off an indicator as `0xFFFFFFFE` and sqlplus `PRINT` of a bound
variable reports `ORA-01008`. The widths are the only difference; the field
order is identical.

**OUT-bind reply (the Mirror, OCI dialect).** The classic sqlplus `VARIABLE v
NUMBER` / `EXEC :v := 42` flow sends a PL/SQL block that assigns literals to OUT
binds; the client parks bind buffers and expects the values back. The Mirror
answers with a **`ttc=0b01`** message (`encode_out_bind_response_oci`), reduced
to structure from live 11g replies (single NUMBER, two NUMBERs, VARCHAR):

```
0b 01 05 cc | <bindcount ub1 @4> | … fixed header (50 B) …
<0x10 × bindcount>          # one define marker per OUT bind
07                          # TTI_RXD
per OUT bind: <DALC value> 00 00   # value + a 2-byte per-bind return code
08 06 00 … fixed status/OER tail (171 B) …
```

Each OUT value is marshalled as a DALC — the same wire form as a fetched column
(NUMBER `7` → `02 c1 08`, VARCHAR `"hi"` → `02 68 69`) — so the client reads it
straight into its bound buffer. Note the trailing return code is **two** bytes
here, versus the thin client-decode path's single indicator byte (§6.5). The
server pointer (offset 18), the SCN, and an internal sequence counter are
instance-specific and zeroed; everything else — bind count, define markers, the
RXD values — is computed, not a captured blob. The single-bind case (the common
`EXEC :key := N`) reproduces the live reply byte-for-byte. Over PostgreSQL the
backend runs the block as PL/pgSQL and returns the assigned values, so a
following `SELECT … WHERE k = :v` receives the value as an ordinary IN bind
(§5.4).

**OUT-bind request marker (`fd 01`).** The `EXEC :v := 42` request is an ordinary
`OALL8` execute carrying the `BEGIN … END;` block and one OAC per bind — but the
wire **does not carry a bind's direction** (Oracle infers IN vs OUT from the
block). An OUT bind therefore has no input value: in the `TTI_RXD` bind row its
value slot holds the 2-byte placeholder **`fd 01`** instead of a DALC — `fd` is
the wire's escape / absent-value sentinel (`TNS_ESCAPE_CHAR`, `0xFD`), shared with
the thin dialect, and `01` the following field. Verified
against live 11g across NUMBER and VARCHAR OUT binds, single and multiple —
`BEGIN :a := 1; :b := 'x'; END;` sends `07 fd 01 fd 01`. The Mirror decodes each
`fd 01` to `None` (`parse_exec_oci` / `_parse_oci_binds`) so the OUT bind is not
fed a garbage input, and hands every bind to the backend OUT-capable (the same
directionless-bind handling the thin exec uses, §5.4); an ordinary IN bind in the
same slot is a normal DALC (`:x = 7` → `07 02 c1 08`). The OAC is identical for IN
and OUT — the `fd 01` value marker is the only direction signal on the wire.

**`REFCURSOR` (the Mirror, OCI dialect, #2014).** `variable rc refcursor`, a
block that opens it, and `print rc` take three calls. Captured from sqlplus
23.26 against 11g and 18c, and from 10.2 and 11.2 against 11g:

1. The block binds `:rc` as type **102**: the descriptor `01 66 01 00 00` and a
   ub4 size of 1, the value `04 00 00 00 00`, a cursor id of 0.
2. The reply is the OUT-bind reply above, its marker `30` (the bind came in with
   a value), and the cursor's OUT value is
   ```
   4c                          # lead byte
   <max row size ub4> <column count ub4> <column blocks>   # the describe body
   00 07 00 00 00 07 <date, 7 B>   # the describe-time date
   <4 x ub4> [<ub4 0>]         # flags, then from 11.2 an empty query-cache key
   <cursor id ub4> 00 00       # and the return code every OUT value ends on
   ```
   That is the thin REF CURSOR value (§6.5) in fixed widths. The describe body is
   byte-identical to the one the same query's own execute reply carries. The lead
   byte is `4c` from 11g and 18c to every sqlplus; a live 10g sends `3c`. A live
   server fills in the date, and for a DATE column one of the flags (8168); the
   Mirror zeroes both, as in its queries' describe tail, and sqlplus accepts it.
3. `print rc` re-executes the cursor by id: an OALL8 with no SQL (no pointer at
   offset 11), the options word `0x40` and the id at offset 7. The thin `al8i4`
   array starts where the SQL length would be, so the second element, the rows
   sqlplus has room for, sits at the SQL offset plus 3: `0f 00 00 00` in every
   capture, at 243 in the 12c narrow preamble, 199 in the wide one and 151 in
   sqlplus 10.2's. The reply is the rows, with a fetch reply's framing; while
   rows remain sqlplus fetches by the same id (`03 05`).

   A cursor whose columns hold a CLOB, a BLOB or a LONG streams its rows the way
   that query's own execute does (#2033). The re-execute is answered with the
   first row, a LOB as its locator. sqlplus reads each LOB's content over
   TTI_LOBOPS (§14), and fetches the next row by the cursor's id; the fetch after
   the last row ends with ORA-01403. sqlplus 23.26 and 11.2 print it through the
   Mirror as they do direct to 18c. The Mirror refused such a cursor until then.
   Sent in one plain reply, its rows hung sqlplus.

The Mirror numbers these cursors from `0x100` up, clear of the fixed ids its
other OCI replies carry (0, `0x5be8`, `0x5beb`), so a re-execute of a
statement's own cursor is never served from one. A block that does not open the
cursor answers id 0 and no columns, and `print` reports ORA-24338, as live.

**`CLOB` / `BLOB` variables (the Mirror, OCI dialect, #2015).** `variable vc
clob`, `exec :vc := 'clob var'` and `print vc`, captured from sqlplus 23.26 against
11g and 18c:

- **The bind** is type 112 (113 for a BLOB), its descriptor `01 70 01 00 00 50 00
  00 00`. Its value is a ub4 length and then the locator as a value. While the
  variable holds nothing, that locator is sqlplus's own 4000-byte buffer, chunked
  with fixed-width chunk lengths like every OCI length. The width does not follow
  the field version: `fe a0 0f 00 00 …` (a ub4 LE) to a live 18c, but `fe ff …`
  (a ub1) to 11g and to a Mirror at that same field version. The ub4 in front
  gives the locator's length, so the Mirror takes whichever reading adds up to it.
  Once the variable holds NULL, the value is just the zero length.
- **The OUT value** is the locator of a temporary LOB, in the same form as a LOB
  column's cell. A NULL is the zero length with the return code `ff ff`. The marker
  before it is `10` while the variable held nothing and `30` once it did. Before
  the first `print` or assignment, sqlplus runs `BEGIN :vc := empty_clob(); END;`
  itself.
- **`print vc`** runs `SELECT :vc vc FROM SYS.DUAL`, binding that locator, and
  reads the column like any LOB (§36). With the unset buffer bound instead, a live
  server returns the buffer as the row's locator, and sqlplus refuses it with
  ORA-22275.

The Mirror writes the OUT value as its own CLOB cell. The locator names the
variable's value by an id in four bytes of its zero run (offset 44, beside the row
slot at 40). When sqlplus binds the locator back, the Mirror finds that id. sqlplus
does not echo the locator byte for byte: it clears bit `0x08` of the second header
flag byte (`0c 88` comes back `0c 80`). So the match ignores the two flag bytes, as
well as the id and the content size the cell patches. The value goes to the
backend as a `ClobValue`. The unset buffer outside a block is answered
ORA-22275 at once, the error a live server's client ends on.

**INTERVAL and ROWID columns (the Mirror, OCI dialect, #2017).** sqlplus sizes
its row buffer from the describe's max row size, so a column counted as 0 there
crashes it (SIGSEGV) as soon as the row arrives. A backend can't always size a
column: the PEP 249 tuple a passthrough reads reports no size for an interval or
a ROWID. A live 18c describes each of the three with a data length of 1 (the
thin figure, §6.2). It counts them in the max row size as 11 (DAY TO SECOND),
5 (YEAR TO MONTH) and 16 (ROWID), one single-column SELECT apiece. The Mirror
falls back to those figures where the backend gives none.

BINARY_FLOAT and BINARY_DOUBLE are fixed-width, and a live 18c describes them so
whatever their source (#2018). Each has a data length of 1 and no max size, and
counts its 4 or 8 bytes toward the max row size. A passthrough's PEP 249 tuple
gives both a display size of 127. Described with that length, sqlplus refused
the column with ORA-03115 and printed "no rows selected". The row cells were
already right: `04 bf c0 00 00` and `08 c0 04 00 00 00 00 00 00` for 1.5 and 2.5.

TIMESTAMP WITH TIME ZONE is described the same way, length 1 and 13 toward the
max row size. Its cell differs from the thin form: OCI is sent the **wall clock**
at the value's own offset, and bit `0x40` of the offset-hour byte says so. The
thin form sends the time in UTC and no flag. Live 18c:

```
2024-01-02 03:04:05.5 -05:30   78 7c 01 02 04 05 06 1d cd 65 00 4f 1e
2024-01-01 00:30:00   +02:00   78 7c 01 01 01 1f 01 00 00 00 00 56 3c   (its own date)
2024-07-01 12:00 Europe/Prague 78 7c 07 01 0d 01 01 00 00 00 00 85 eb   (a region id, no 0x40)
```

**Which client gets that form.** A live 11g sends it to sqlplus 23.26 and the thin
form to sqlplus 11.2 and 10.2:

```
11g -> sqlplus 11.2   78 7c 01 02 09 23 06 1d cd 65 00 0f 1e   (08:34 UTC, no flag)
11g -> sqlplus 23.26  78 7c 01 02 04 05 06 1d cd 65 00 4f 1e
```

Sent the flagged cell, sqlplus 11.2 reads it as UTC and prints 03:04 +02:00 as
21:04 +66:00. A live 18c sends sqlplus 11.2 the flagged form too, but it
describes every column with a first byte of `0x59` (bit `0x08` set), where 11g
and the Mirror's pre-12c describe send `0x51`. The Mirror follows 11g. It sends
the flagged form to a client whose own capability block names field version 12.1
or later, and the thin form to an older one. That cut is inferred from the
captures: the capability bit the server keys on is not pinned down.

A passthrough gets a region-named value from the client as its offset, as the
thin path does, so it prints as `+02:00` where a live server prints the name.

The ROWID cell is not the thin form either. OCI reads 16 bytes, the data object
number, relative file number, block number and row number, each a ub4 LE. Four
rows of one table, against a live 18c:

```
AABAomAAMAAAACLAAA  10  26 0a 04 00  0c 00 00 00  8b 00 00 00  00 00 00 00
AABAomAAMAAAACLAEr  10  26 0a 04 00  0c 00 00 00  8b 00 00 00  2b 01 00 00
                        object 264742  file 12   block 139    row 299
```

**NLS parameters (the Mirror, OCI dialect, #2020).** sqlplus formats DATE,
TIMESTAMP and NUMBER columns itself: it is sent a DATE's seven bytes and renders
them by the session's NLS parameters. It learns those from the server. After an
`ALTER SESSION SET NLS_…` a live 18c's reply carries a **SYNC server piggyback**
(`17 05`), between the status frame and its OER. It is the thin form's fields
(§31) in fixed widths: a ub2 count of DTYs (1) and their length byte (`0x10`), a
ub4 count of pairs (18) and their length byte (`0x16`), then per pair a ub4
binary length, a ub4 text length, the text as a value and a ub2 keyword, and a
ub4 of flags last. The keywords, one `ALTER SESSION` per parameter, in the order
a live server sends them:

| kw | parameter | kw | parameter |
|---|---|---|---|
| 16 | NLS_LANGUAGE | 11 | NLS_SORT |
| 9 | NLS_TERRITORY | 57 | NLS_TIME_FORMAT |
| 0 | NLS_CURRENCY | 58 | NLS_TIMESTAMP_FORMAT |
| 1 | NLS_ISO_CURRENCY | 59 | NLS_TIME_TZ_FORMAT |
| 2 | NLS_NUMERIC_CHARACTERS | 60 | NLS_TIMESTAMP_TZ_FORMAT |
| 10 | NLS_CHARACTERSET | 52 | NLS_DUAL_CURRENCY |
| 12 | NLS_CALENDAR | 50 | NLS_COMP |
| 7 | NLS_DATE_FORMAT | 61 | NLS_LENGTH_SEMANTICS |
| 8 | NLS_DATE_LANGUAGE | 62 | NLS_NCHAR_CONV_EXCP |

The order matters. sqlplus applies the pairs in turn, and a territory resets
the formats it implies, so a date format sent before the territory is lost.
Every reply carries all of them, since one parameter implies others: setting the
territory to GERMANY changes nine.

sqlplus 10.2 gets the same pairs another way: inside the status frame, not as a
piggyback. A live 11g's 10.2 frame has, from byte 29, a **ub2** count of pairs,
the pairs as above and the ub4 of flags. The Mirror's 35-byte frame ends in
exactly that region, empty (a zero count and zero flags), which is why an
ordinary status already reads right to 10.2. The `17 05` piggyback instead made
10.2 drop the connection.

The Mirror reads them back from the backend's `NLS_SESSION_PARAMETERS` after the
statement, adds the character set (AL32UTF8) that view leaves out, and sends the
piggyback in that order. sqlplus 23.26, 11.2 and 10.2 then print what a live
server prints. `ALTER SESSION SET TIME_ZONE` gets a piggyback of its own, keyword
163 with a binary value, which isn't sent yet.

**`DESCRIBE <object>` (the Mirror, OCI dialect).** sqlplus `DESC table` sends a
dedicated describe call — `TTI_FUN 0x77` carrying the object name as the trailing
length-prefixed token (`… 02 00 00 00 <ub1 namelen> <name>`) — and expects a
dedicated describe reply, **not** the query DCB. The reply
(`encode_describe_reply_oci`) is a fixed preamble + the schema and table names
(DALCs: a ub4 char length, a ub1 byte length, then the bytes) + a header carrying a
**column count** (`N + 1`) + one ~163-byte **block per column** + a fixed trailer
(carrying the column count `N`). Reverse-engineered by differential capture against
live 11g: single-column NUMBER / VARCHAR / DATE describes are 732-byte replies that
differ in only 14 places, so the meaningful per-column fields are computed and the
rest carried:

- **size** (data length — 22 for NUMBER, 7 for DATE, the declared length for a
  char type), **TNS type**, **precision**, **scale** (NUMBER) / length (char),
  **nullability** (`1` nullable / `0` NOT NULL), and **charset + csfrm** (char types
  only) — computed from the column. A **TIMESTAMP**'s fractional-seconds precision
  (the `N` in `TIMESTAMP(N)`) is reported in the **precision** field, not just the
  scale — a live 11g `DESCRIBE` of `TIMESTAMP(6)` carries `06 06` (precision 6,
  scale 6) and sqlplus renders `TIMESTAMP(N)` from the precision. The client keeps
  that value in the column's scale (its precision is 0), so the describe block
  mirrors scale into precision for the TIMESTAMP family (`TNS_TYPE_TIMESTAMP` /
  `TIMESTAMPTZ` / `TIMESTAMPLTZ`). **INTERVAL** precisions lay out differently
  again: `INTERVAL YEAR TO MONTH` reports the leading (`YEAR`) precision in both
  fields (`YEAR(3)` -> `03 03`, sqlplus reading `YEAR(N)` from the scale byte),
  while `INTERVAL DAY TO SECOND` **swaps** them — the precision byte carries the
  `SECOND` fractional precision (the column's scale) and the scale byte the `DAY`
  leading precision (the column's precision), so `DAY(2) TO SECOND(6)` -> `06 02`.
  `_oci_desc_precision_scale` picks the per-family layout. A **national** char
  type (`NCHAR` / `NVARCHAR2`, csfrm 2) carries its data as **UTF-16BE** in the
  `AL16UTF16` charset: the value goes on the wire pre-encoded to UTF-16BE (both
  the thin row encoder and the OCI one route national values through
  `_national_wire_value`), the SELECT DCB sets a **character-length-semantics
  flag** (`0x10` at column pre-offset 15) so sqlplus sizes the column by the
  character `max_size` rather than the wider byte buffer, and the `DESCRIBE`
  reply reports the **byte** length in its size field with a `0x80` national flag
  and the character length in the scale byte, so sqlplus halves the byte size to
  render `NCHAR(N)`. **The rule is not confined to columns**: a national PL/SQL
  **OUT bind** carries its text the same way, and so does each element of a
  national `arrayvar`. Sent as UTF-8 instead, the client reads two bytes per
  character and `'Called'` comes back as `'\u434d\u6c6c\u6564'` — readable
  mojibake rather than an error, which is how it survives review (#826);
- each non-last column carries a `1` **continuation flag** three bytes before its
  end and a **describe-timestamp entry** in its post-name region (the last column
  leaves both zero);
- the describe **timestamp** and **object ids** are instance-specific — and sqlplus
  *rejects a describe reply whose timestamp / object id are zero* (it silently waits
  for more, unlike the query describe which tolerates a zeroed timestamp), so both
  must be valid. The **object ids** are the described object's dictionary identity —
  its `DBA_OBJECTS` **object id** (`_OCI_DESC_OBJECT_ID`, 446 in the capture) and
  **data-object id** (`_OCI_DESC_DATA_OBJECT_ID`, 116036), each a ub4 LE the header
  carries. They are real identities the Mirror has no source for, so they stay
  carried from the capture (a synthetic id would need live validation, like the DML
  rowid); naming them is what turns the header's recurring `be010000` / `44c50100`
  runs into fields rather than opaque bytes. The **timestamp**
  is **generated** — it is one 7-byte Oracle DATE (the moment the dictionary row was
  analyzed), and the Mirror reports the current time, the truthful analyze time,
  via `_oci_desc_timestamp()`. One generated value is threaded through every site it
  appears — the header (three times) and each non-last column block — each behind a
  `27 <field-id>` tag as a describe-time DALC (`ub4 len 7 | ub1 len 7 | date`). The
  byte-for-byte capture test pins it to the capture's date so the rest is still
  checked exactly.

The **trailer** is not opaque either: its 257 bytes are a 121-byte describe-specific
frame (zero but for the column count, the type-dependent opaque byte, and four
carried framing constants) followed by a **standard 136-byte OER return status** —
the same envelope every other reply ends with (§36), built by `encode_oci_oer`,
whose offset-56 `36 01` and offset-72 `20 f6 31 0a` are the fixed 11g constants.
Its carried fields are the statement category `0`, the offset-8 row slot `1`, a
sequence of `19` (the diagnostic counter the client discards, left as captured)
with its `sequence + 2` echo, and a status byte of `0x05` — the value the execute
path names `OCI_OER_STATUS_ERROR`, on a *successful* describe with error code 0;
carried as the describe's terminal status, its meaning on this path unpinned.

Two framing points matter: the reply body follows the 8-byte TNS header and the
**2-byte data flags** (`00 00`) — a describe reply that folds the data flags into
its body desyncs sqlplus's parse by two bytes (it hangs). And the whole exchange is
**two round-trips**: the `0x77` describe, then a small follow-up status call.
Verified live: `DESC` of single- and multi-column tables renders the right
`Name / Null? / Type` for NUMBER(p,s), VARCHAR2(n), and DATE (incl. NOT NULL).

**DML completion reply (the Mirror, OCI dialect).** A DML that returns no columns
(`INSERT` / `UPDATE` / `DELETE`) still needs sqlplus to print `N rows created.` /
`N rows updated.` / `N rows deleted.` rather than the generic PL/SQL message.
sqlplus derives the **verb** from statement-type fields in the reply (the SQL
command code — `INSERT` 2, `UPDATE` 6, `DELETE` 7 — plus neighbours at body
offsets 53/55/57), and the **count** from a `ub4` little-endian at **body offset
43**. The Mirror (`encode_dml_status_oci`) keeps one captured 187-byte body per
verb and injects only the count:

```
08 06 00 | … | <affected count ub4-LE @43> | … | <cmd-code + neighbours @53/55/57> | …
```

The surrounding structure (the `08 06 00` return marker, an SCN region, the
cursor/rowid trailer, and a session row-counter at offsets 75/186 that is *not*
the count) is carried as-is from the live 11g reply; only the count field is
computed. The backend supplies the count (`Result.rowcount`); a `MERGE` or any
unrecognised verb falls back to the `INSERT` template. Fully computing the OER
(rather than patching a captured body) is a follow-up.

**DDL completion reply (the Mirror, OCI dialect).** `CREATE TABLE` and
`DROP TABLE` share the same reply shape as the DML status above, so sqlplus prints
`Table created.` / `Table dropped.` instead of the generic PL/SQL message. The
verb comes from the SQL command code at **body offset 57** — `CREATE TABLE` 1,
`DROP TABLE` 12 (the `V$SQL.COMMAND_TYPE` values, the same field the DML verbs use:
INSERT 2 / UPDATE 6 / DELETE 7) — plus neighbouring type fields at offsets
40/53/55/84 that co-vary with it. A DDL affects no rows, so unlike the DML case
**nothing is computed**: `encode_ddl_status_oci` keeps one captured 171-byte body
per verb and returns it verbatim (the two differ only at offsets 40/53/55/57/84
and instance-specific SCN/counter bytes). Only `CREATE` and `DROP` are captured;
other DDL verbs and the non-`TABLE` object variants (`Index created.`,
`Table altered.`, …) keep the generic no-row status until captured. Statements the
classifier recognises as neither DML nor DDL still get the generic `08 06 00`
171-byte `encode_status_oci` tail.

**LOB read round-trip (the Mirror, OCI dialect, #405).** A `SELECT` of a CLOB /
BLOB column doesn't return the value inline: the row carries an opaque **locator**
and sqlplus fetches the content with follow-up `TTI_LOBOPS` reads (§11.9, §14).
The full server side, reduced from live 11g out-of-line CLOB captures:

1. **Execute → LOB describe.** The reply is *not* an ordinary describe. The LOB
   column reports **`data_length` 4000** and the describe carries a distinct
   **33-byte tail** (`_oci_lob_describe_tail`): the same describe-time DALC head
   as the ordinary DCB tail (a ub4 char-length of 7 + the byte-length 7, the
   timestamp zeroed), *without* the `06 01 22` DCB marker, and all zero except one
   `ub4` at **offset 17** (`0x1fe8` = 8168 from the capture — not instance-specific,
   so carried as a stable structural value of unpinned meaning). It is followed by
   a LOB execute status — `encode_lob_describe_oci`, not the
   inline-row `encode_query_response_oci`. This is load-bearing: with the ordinary
   describe sqlplus sets up its LOB define wrong and **breaks on the locator row**
   even when that row is byte-identical to Oracle's. **An empty result gets the
   LOB describe too** (#1428): a live 11g answers `SELECT c FROM t` (no rows)
   with the same LOB describe, and the re-execute sqlplus sends once its LOB
   define is set up with the end of fetch, `ORA-01403`. Given the ordinary no-row
   reply and then a plain success, sqlplus prints one row holding an
   uninitialized LOB (`SP2-1504`) and "1 row selected".
2. **Fetch → locator row.** Delivered with the LOB row header (`_oci_lob_rxh`,
   `06 01 22 fd 01 …`) and ending with a **non-terminator "more" OER**
   (`encode_lob_fetch_rows_oci`) — the content still has to come over `TTI_LOBOPS`,
   so the cursor is not drained; a *following* fetch draws the 1403 terminator.
   The minted locator's **size field is the content BYTE count** (2× characters
   for a CLOB — UTF-16 on the wire — raw bytes for a BLOB), big-endian. A **CLOB**
   and a **BLOB** use *different* locator templates: they differ in the LOB type
   bytes (row offsets 9/11/14) and the **charset** (offset 37 — `03 69` = 873
   AL32UTF8 for a CLOB, `00 00` binary for a BLOB). The charset is load-bearing —
   with a CLOB locator sqlplus decodes a BLOB's raw bytes *as characters* and
   mangles them (`CA FE BA BE` → `??`), so the Mirror keys the template on the
   column type (#406).
3. **`TTI_LOBOPS` READ → LOB_DATA.** sqlplus loops over the LOB in
   `SET LONGCHUNKSIZE`-sized slices, each read carrying a 1-based **source offset**
   (`ub8`-LE at request offset 91) and **amount** (`ub8`-LE at offset 269), both
   counts (characters for a CLOB, bytes for a BLOB). The Mirror
   (`parse_lobops_read`) serves exactly that slice as `LOB_DATA` (`0e fe` +
   `0xFF`-byte chunks, chunked at every length, §14.3) + the echoed-locator RPA +
   OER; a read returning fewer units than
   requested ends the loop. The row locator and the READ reply come from one
   capture, so they echo the same opaque locator and stay consistent.

**What a modern sqlplus changes (#1287).** sqlplus 23.26 against that path
hung on any CLOB select. A live 11g answers it differently from sqlplus 11.2 in
two places, and each client can only read its own form:

- **The LOB column value.** It leads with the locator length (a fixed ub4). For
  a client whose compile capabilities set **`CCAP_LOB_12C` (0x80 of
  `CCAP_LOB`)** the server then sends the **LOB's length** (ub8, characters for a
  CLOB) and its **chunk size** (ub4, 8132 from 11g), and only then the locator.
  sqlplus 23.26 sets the bit; sqlplus 11.2 does not, and gets the locator
  straight after its length. The 11g server does not set the bit itself: it
  follows the client's. The Mirror reads the bit from sqlplus's capability
  block and answers in the same form. That block arrives in the round *after*
  sqlplus's `TTI_PRO`: in this dialect the Mirror's "DTY" round carries the
  `TTI_PRO`, and its "TYPE" round the DTY proper.
- **A NULL LOB is four zero bytes** (the ub4 length at 0), not one. A single
  `00` left both sqlplus versions waiting for the rest of the row.
- **The READ request is narrower.** sqlplus 23.26 writes its scalar slots
  narrower, as it does in its `OALL8` (#866). In that form the header is 135
  bytes, with the locator length (ub4) at 11, the offset (ub8) at 75 and a second
  pointer indicator at 91, followed by the locator and then the amount (ub8). An
  indicator at 91 identifies the narrow form, because in the wide one the offset
  sits there. Read with the wide offsets, the request was too short, so the
  Mirror served the whole LOB to every read.

With these, sqlplus 11.2 and 23.26 print the same CLOB / BLOB results the live
11g gives them, NULLs included, against a Mirror at 11.2.

Verified live on 11g over the SQLite-backed Mirror: CLOB and BLOB values display
under default sqlplus settings (the 80-char read loop) and with a large
`LONGCHUNKSIZE` (single read, multi-packet), single- and multi-row, session clean
afterward. The demo backend types a column as a CLOB / BLOB from its **declared**
type (via `PRAGMA table_info`), not its value size, so a plain VARCHAR2 / RAW
value stays inline (the thin dialect has its own LOB emit, below).

**LOB write (the Mirror, OCI dialect, #406).** For sqlplus, `INSERT` / `UPDATE`
of a CLOB / BLOB value that fits an inline literal or bind is an **ordinary DML**
— the value rides in the execute (no `TTI_LOBOPS` WRITE), the backend stores it,
and a following `SELECT` returns it via the read path above. So the write round-
trips for free once the read is correct; #406 is really the BLOB half of the read
(a BLOB needs the binary locator, above, or its bytes come back mangled). Verified
live: `INSERT` / `UPDATE` of CLOB and BLOB values round-trip byte-for-byte
(`x'deadbeefcafe'` comes back `DEADBEEFCAFE`). A `TTI_LOBOPS` WRITE / temp-LOB
path (for values too large for an inline bind, used by programmatic OCI clients)
is a follow-up.

**LOB read (the Mirror, thin dialect, #413).** A thin client (oracledb / seerdb)
reads a LOB the same shape as sqlplus — locator in the row, content over
`TTI_LOBOPS` — but the wire is the *thin* codec, not the OCI describe/RXH dance:

1. **Locator in the RXD.** The thin describe already types the column as a CLOB /
   BLOB (`_encode_dcb_column`); the row value is then not the content but a minted
   opaque locator, `encode_lob_locator_thin` → `sb4 length | bytes_with_length`
   over the ordinary RXD. A NULL LOB is the bare `0x00` (`§12`), drawing no read.
   The client keeps the locator opaque and echoes it back.

2. **`TTI_LOBOPS` READ → the requested slice.** seerdb's own client requests the
   whole LOB in one read (amount `0x40000000`), but the reference client reads at
   an explicit 1-based offset and amount (`lob.read(offset, amount)`, `str(lob)`),
   so the Mirror honours both (`§14`). The READ carries its **column-LOB locator
   raw**, not ub2-length-prefixed the way a temp-LOB op does, so the parser skips
   it by the declared source-locator-length (which spans the field in either
   form) to reach the trailing amount — reading the first two locator bytes as a
   length overshot, threw, and dropped every read to a "whole LOB from offset 1"
   fallback that served the wrong row's queue entry (#903). The Mirror answers
   with `encode_lob_read_response_thin` — the slice as `LOB_DATA` (`0e fe` +
   `0xFF`-byte chunks, §14.3) followed by a **success OER** `04 01 <status>`
   (`_encode_oer(1,0,0,b'')`). The client reads the content, scans to the OER, and
   stops; CLOB content is UTF-16BE (decoded to `str`), BLOB is raw `bytes`.

   **A READ is answered by its locator.** Each column LOB is emitted under a
   locator of its own (`mint_column_lob_locator`, #888) and the content served
   under it is remembered, so a READ says exactly which row's LOB it wants and
   the answer never depends on the order the reads arrive. Re-reading one, or
   skipping one, or reading them back-to-front all work.

   This replaces the original read-order rule, which was the follow-up this
   section used to describe: the locator was a shared placeholder, so the Mirror
   tracked position by arrival — a read at offset 1 started the *next* queued
   LOB and later offsets continued the current one. That is right only for a
   client that reads every LOB exactly once, in the order the locators went out.
   The reference client does not: reading one LOB from offset 1 twice (`read()`
   then `str(lob)`) advanced the queue early, and from there every later row got
   its neighbour's content and the last got nothing at all (seerdb#826). The
   order-based path remains for a locator the log does not know — an OCI
   (sqlplus) client, whose locators are not minted this way, and the
   session-persistent object-attribute queue below.

Unlike the OCI locator, the thin locator carries no load-bearing size / charset
fields (the CLOB / BLOB split is already in the describe, and the read is
single-shot), so one template serves both. Verified against the seerdb thin client
over the SQLite-backed Mirror: small and multi-chunk (6000-char CLOB / 5120-byte
BLOB) values, NULL, and multi-row / multi-LOB-column results all round-trip, CLOB
as `str` and BLOB as exact `bytes` (`tests/test_sqlite_backend.py`). LOB column
typing is still by **declared** type, so VARCHAR2 / RAW stay inline. A thin
`TTI_LOBOPS` WRITE path (large LOB writes) remains the #412 follow-up.

### 6.1 Row Header (TTI_RXH)

Precedes row data in SELECT results. All numeric fields use Oracle's
variable-length integer encoding (`§12.1`), not fixed BE widths:

```
TTI_RXH | Flags(UB1) | NumRequests(UB2) | IterationNumber(UB4) |
NumIters(UB4) | BufferLength(UB2) |
BitVectorLength(UB4) | [SkippedLengthByte(UB1) | BitVector(N bytes)] |
Rxhrid(bytes_with_length)
```

When `BitVectorLength` is non-zero, a single repeated length byte
follows and then `BitVectorLength` raw bytes of bit vector. The
trailing `rxhrid` is a `bytes_with_length` (ub4 count + chunked DALC).

That embedded bit vector carries the same column-reuse semantics as a standalone
`TTI_BVC` (`§6.3`) and **must be passed to the following RXD**, not skipped —
otherwise the RXD reads the next token as a column value and desyncs (it surfaces
as an "unknown token" on the bogus `TTI_ROW 0x0a`). The server uses it when a row
repeats the previous row's value, most notably on a scrollable cursor's `LAST`
re-execute after EOF (`§5.2.1`).

### 6.2 Row Data (TTI_RXD)

Contains the actual column values for one row, encoded according to each column's data type from the describe information.

A character / RAW value longer than **252 bytes**, the largest single-byte DALC
length (§12.2), is **chunked**, and the chunk framing is field-version-specific:
before 12.1 each chunk has a single length byte, from 12.1 a `ub4`. A server must
encode row values with the *negotiated* form — `seerdb/server/query.py` uses
`encode_chr` (field-version-aware), not the always-12c+ `_bytes_with_length`, or
an 11g client decodes a value past 252 bytes as a "truncated DALC field".

What a real server sends for a VARCHAR2 or RAW column, measured on 11g (fv 6) and
23ai (fv 24):

| value length | 11g | 23ai |
|---|---|---|
| 252 | `fc` + 252 bytes | `fc` + 252 bytes |
| 253 | `fe fd` + 253 bytes, `00` | `fe 01 fd` + 253 bytes, `00` |
| 255 | `fe ff` + 255 bytes, `00` | `fe 01 ff` + 255 bytes, `00` |
| 256 | `fe ff` + 255 bytes, `01` + 1 byte, `00` | `fe 02 01 00` + 256 bytes, `00` |

So 253 is the first length that is chunked, and **inside the run a chunk length
is a plain count**: `fd`, `fe` and `ff` are markers only as the value's first
length byte. Before 12.1 a chunk is at most 255 bytes; from 12.1 its length is a
`ub4` and one chunk can hold the whole value. LOB content (`TTI_LOB`, §14.3)
is chunked the same way but sooner: a 252-byte BLOB read already arrives as
`0e fe fc` + 252 bytes + `00` on 11g and `0e fe 01 fc` … on 23ai.

**A column described with a zero data length carries no bytes at all** — not
even the empty DALC an ordinary NULL sends — and its value is always NULL. The
describe is the only thing that says so; nothing in the row marks the omission.
`SELECT NULL AS x` and `SELECT '' AS x` describe this way, as VARCHAR with data
length 0. Reading a DALC for such a column consumes whatever follows, which is
normally the response's terminating token, and the rest of the response then
decodes as garbage (#682).

Two neighbouring cases make this easy to get wrong:

| Described as | data length | max size | Carries bytes? |
|--------------|-------------|----------|----------------|
| `NULL` / `''` literal | 0  | 0 | **no** |
| `NUMBER`              | 22 | 0 | yes |
| `LONG`                | 0  | 0 | yes, its own chunked framing |

So the test is the **data length**, not the max size — a NUMBER is described
with a max size of zero while carrying a value — and it has to be applied after
the types that have their own row encoding, since a LONG is also described with
a zero data length. Confirmed identically on 11g, 21c and 23ai.

**The obligation this puts on a server** (#690). A zero data length is a claim,
not a way of saying "unknown": describe a column that does carry bytes as
zero-length and a conforming client reads no bytes for it and then misreads the
rest of the row. A real server never does this, and every type below has a
non-zero length whatever the column holds. Measured identically on live 10g,
11g, 21c and 23ai — the odd-looking values are what Oracle sends, not a
convention:

| Type | Code | data length |
|------|------|-------------|
| NUMBER               | 2   | 22 |
| DATE                 | 12  | 1 |
| TIMESTAMP            | 180 | 11 |
| TIMESTAMP WITH TZ    | 181 | 1 |
| TIMESTAMP WITH LTZ   | 231 | 11 |
| INTERVAL YEAR TO MONTH | 182 | 1 |
| INTERVAL DAY TO SECOND | 183 | 1 |
| BINARY_FLOAT         | 100 | 1 |
| BINARY_DOUBLE        | 101 | 1 |
| REF                  | 111 | 2000 |
| CLOB / BLOB          | 112 / 113 | 4000 |
| BOOLEAN              | 252 | 1 |
| ROWID                | 11  | 1 |
| UROWID               | 208 | 292 |
| object (ADT, XMLType) | 109 | 2000 |
| JSON / VECTOR        | 119 / 127 | 8200 (§14.5e) |
| nested cursor (REF CURSOR column) | 102 | 5 |
| BFILE                | 114 | 530 |

A character or RAW column is absent from that list on purpose: zero is a
truthful answer there, and it is exactly what `SELECT NULL AS x` describes.

This bites a server built over another database, which is where the Mirror hit
it: a PEP 249 `description` tuple reports no size for a temporal, interval or
REF column, so a backend deriving the length from one arrives at zero and
describes something untrue.

### 6.3 Bit Vector for Changed Columns (TTI_BVC)

When the server uses differential row encoding it emits a BVC token
between consecutive RXDs. The token body is a `NumColumnsSent` ub2
followed by a packed bit vector. The vector has `ceil(num_columns / 8)`
bytes; bit semantics are LSB-first within each byte (column 0 = bit 0
of byte 0, column 8 = bit 0 of byte 1, etc.).

- **Bit set** → the column is present in the next RXD's data section.
- **Bit unset** → the column value is duplicated from the previous row
  and is *not* carried in the next RXD.

Without honouring the bit vector, the RXD decoder reads too many DALCs
and walks off the end of the packet.

**"Previous row" spans fetch boundaries.** Differential encoding is relative to
the immediately preceding row, which may sit in an *earlier* `TTI_FETCH`
response — a large result set is drained across several fetches, and the first
row of a continuation batch can reuse a column from the last row of the prior
batch. The decoder resets its per-response row list each fetch, so the client
must seed that last-fetched row before decoding the next batch (the same seeding
a scrollable re-execute needs, §6.1). Missing it decodes the reused column as
`None` for the first row of every continuation batch (#326).

### 6.4 Describe Information (TTI_DCB)

Column metadata for result sets. The 11g layout begins with a header
block that older documents tend to omit:

```
TTI_DCB |
  describe-info preamble (chunked DALC: cursor UUID + Oracle DATE) |
  max_row_size (ub4, skipped) |
  num_columns (ub4) |
  [reserved byte, present only when num_columns > 0] |
  per-column metadata x num_columns (see below) |
  current_date (bytes_with_length, skipped) |
  dcbflag (ub4, skipped) |
  dcbmdbz (ub4, skipped) |
  dcbmnpr (ub4, skipped) |
  dcbmxpr (ub4, skipped) |
  dcbqcky (bytes_with_length, skipped)
```

Per-column metadata on 11g:

```
ora_type_num (ub1) | flags (ub1, skipped) |
precision (sb1) | scale (sb4, variable) |
buffer_size (ub4) | max_array_elems (ub4, skipped) |
cont_flags (ub4, skipped) |
oid (bytes_with_length) |
version (ub2, skipped) | charset_id (ub2) |
csfrm (ub1) | max_size (ub4) |
nulls_allowed (ub1) | v7_name_length (ub1, skipped) |
column_name (str_with_length) |
schema_name (str_with_length, skipped) |
type_name (str_with_length, skipped) |
column_position (ub2, skipped) | uds_flags (ub4, skipped)
```

**Pre-11g (field version < 11.2, e.g. 10g = 4)** *omits two fields* the layout
above shows, both of which are 11g additions:
- the per-column trailing **`uds_flags`** ub4 is absent — 10g ends the per-column
  block at `column_position`. Reading a phantom `uds_flags` consumes the next
  column's first bytes, so on a multi-column describe every column after the
  first is mis-typed (and the row decode desyncs).
- the **`dcbqcky`** trailer is absent — the query result cache is an 11g feature,
  so there is no query-cache key. Skipping a phantom `bytes_with_length` here
  consumes the first row token.

seerdb gates both on `field_version >= FIELD_VERSION_11_2` (#84/#85),
reverse-engineered by diffing 1/2/6-column, mixed-type and 0-row describes from a
live 10.2.0.5 server against the identical 11g responses.

12c+ differs from 11g in the per-column block: from 12.1 (field version 7)
scale is `sb1` (a raw signed byte) rather than 11g's variable-length
sb4, and from 12.2 an extra `oaccolid` ub4 follows `max_size` (#1144). seerdb decodes
all three (10g / 11g / 12c+), gated on the negotiated TTC field version
(§4.2): the response handler passes `connection.field_version` into
`decode_packet`, which publishes it (via a `ContextVar`) to the token
decoders for the duration of that response.

**23ai (field version 17)** appends two more per-column fields after
`uds_flags`: the column's **SQL-domain schema** and **domain name**, each a
`str_with_length` (a `ub4` count, then a DALC string — the same codec as
`column_name`), empty (a single `00`) for a column with no domain. Earlier
seerdb read them as plain `ub4`s, which only survives the empty case; a real
domain (`01 03 03 'PYO' 01 07 07 'PYO_DOM'`) then desynced the row decode
(#53). Reverse-engineered by diffing a domain column vs a plain one on 23ai and
cross-checked against python-oracledb's `domain_schema` / `domain_name`. Column
**annotations** are carried elsewhere in the describe (a plain column and an
annotated one have identical trailing fields here), so they neither surface nor
desync at this point — surfacing them is future work.

**Chunked (LONG) values.** A value whose length byte is `254` is sent in
chunks. On 11g each chunk is a single length byte followed by that many
data bytes, terminated by a zero byte. 12c+ prefixes each chunk with a
`ub4` length and ends with a zero-length chunk (the same framing as every
other `bytes_with_length` field). `decode_chr` picks the form by field
version; without this a multi-chunk value (e.g. a 300-char string) walks
off the end of the buffer. The same single-byte-vs-`ub4` chunk-length
split applies to LONG / LONG RAW columns (`_read_long_column`, which on
12c+ also sends the chunk after a `0xFE` marker with `ub4` lengths).

### 6.5 I/O Vector (TTI_IOV)

When an executed anonymous PL/SQL block carries bind variables, the server
replies with a `TTI_IOV` token that lists each bind's direction and is
immediately followed (when any bind is OUT / IN OUT) by the returned values.
Layout reverse-engineered from XE 11g and cross-referenced with
python-oracledb's `_process_io_vector`:

```
ub1   token (TTI_IOV = 11)
ub1   flag                                   (skip)
ub2   num_requests   \  num_binds =
ub4   num_iters      /    num_iters * 256 + num_requests
ub4   num iters this time                    (skip)
ub2   uac buffer length                      (skip)
ub2   fast-fetch bit-vector length + bytes   (skip)
ub2   rowid length + bytes                   (skip)
per bind:
  ub1 direction                              # 16 OUT, 32 IN, 48 IN OUT
```

**Direction codes** (`TNS_BIND_DIR_*`): `16` = OUT, `32` = IN, `48` = IN OUT.

A server reports these **on the way back only** — a bind carries no direction on
the way in — so this reply is the only place a caller learns what the block did
with each bind. `cursor.bind_directions` surfaces them, and the Mirror's
passthrough forwards them so its own reply says what its upstream said; a backend
that cannot know leaves them out and every bind is reported OUT, as the Mirror
did for every block before (#1064). It matters because an IN bind carries **no**
value back: marking one OUT and returning its value shifts the client's reading
of everything after it, and for a LONG-declared bind the echoed chunked value
cannot be read in that position at all (`DPY-5000`, #1105).

If any bind is OUT / IN OUT, a `TTI_RXD` (`0x07`) token follows, then one
value per OUT / IN OUT bind **in bind order** (IN binds contribute nothing):

- **Scalar** OUT value: a DALC blob (decoded by the bind's declared type) plus
  a trailing 1-byte indicator (`0x00` = present).
  e.g. NUMBER `10` → `02 c1 0b 00`, VARCHAR `"hi!"` → `03 68 69 21 00`.
- **LOB-class** OUT value (CLOB / NCLOB / BLOB / JSON / VECTOR, #978): **not a
  DALC.** It is the LOB column framing of §22.1b, byte for byte — the block
  length, the locator's `ub8` size and `ub4` chunk size, then the locator as a
  DALC — followed by the same `ub4` return code every OUT value carries.
  Measured on a live 23ai returning an IN OUT `CLOB` a block had appended to:

  ```
  07                     TTI_RXD
  01 28                  ub4 block length = 40
  02 c3 55               ub8 size         = 50005
  02 1f c4               ub4 chunk size   = 8132
  28 <40 bytes>          DALC locator
  00                     ub4 return code
  ```

  A NULL LOB is the single byte `0x00` instead of the whole block, again plus
  the return code. Reading any of this as a DALC takes the block length for the
  entire value and leaves the size, chunk size and locator in the stream, whose
  next byte then decodes as a response token — the `02` above surfaced as
  "no decoder for response token 2". Note this is the framing a **bind** gets
  even though the value never rode in a row: the size and chunk size are always
  present here, unlike a fetched column, where a live server sends the bare
  locator to some clients (§22.1b).

  The bind is recognised by its **declared type**, so a bind promoted to a
  temp-LOB locator on the way out (§14.2) has to keep pointing back at the
  `Var` it replaced — otherwise the reply has neither a type to decode against
  nor a destination.

- **REF CURSOR** OUT value: a 1-byte length, then an inline describe of the
  cursor's result set (the same per-column metadata *and trailer* as a `TTI_DCB`,
  §6.4), then the nested cursor id (`ub2`) and the per-value **`ub4` return code**
  (`actual_num_bytes`, `0`) that follows every OUT-bind value. The client then
  drains that cursor id with a FETCH-only `OALL8` on it (below). See python-oracledb's
  `_create_cursor_from_describe`, which reads that return code with `read_sb4`
  after the cursor id. A `0x01` "present" byte there (an earlier seerdb guess)
  is read as a length-1 integer and swallows the next bind's first byte, so a
  REF CURSOR that is not the *last* OUT bind — the object-type metadata cursor's
  `attrs_rc`, §21.9 — desyncs every bind after it; the zero return code is one
  `0x00` byte, which the reader takes as its present indicator all the same
  (#84/#87/#888). Because this nested describe reuses the §6.4 format, it also
  carries the **same pre-11g difference**: at field version < 11.2 (10g) there is
  no `dcbqcky` trailer, so skipping a phantom one consumes the cursor id and
  desyncs the IOV decode. seerdb gates both identically.

  **A nested cursor COLUMN is the same value MINUS that trailer (#826).**
  `select IntCol, CURSOR(select ...) from ...` returns one cursor per row, and
  its cell is the 1-byte length + inline describe + `ub2` cursor id and **nothing
  more** — python-oracledb reads exactly that (`skip_ub1`,
  `_create_cursor_from_describe`, `read_ub2`) with no return code after it,
  because in a row the next byte is the following row's `TTI_RXD` token.
  Consuming an indicator there swallows that token, and the decoder then reports
  the first byte of the next row's data as an unknown response token — the number
  varies with the data, which is what makes it look like a decoder gap rather
  than an off-by-one. seerdb reads both forms through the same helper, with the
  trailer switched off for a column.

  **Serving one** (#826) needs two more things beyond writing that value. The
  column's **describe length is 5** — measured on a live 23ai; a zero there is
  the same trap BOOLEAN, ROWID/UROWID/ADT, VECTOR and JSON each fell into before
  it (§6.4's length table), and it is the *fifth* occurrence. And **every level
  needs a parked cursor of its own**: a nested cursor may itself select a
  `CURSOR(...)` column, so the walk that parks rows and the one that drains them
  both have to recurse, or the inner result set reaches the row encoder as a raw
  value. seerdb parks them on every path that runs a statement fresh — the
  query, the re-execute and the scroll open — because the remainder a query parks
  is served later from the same converted rows. A **REF CURSOR OUT bind** is one
  more such path: its rows can hold a `CURSOR(...)` column too (`OPEN rc FOR
  SELECT ..., CURSOR(...)`), and parking only the REF CURSOR itself let the inner
  result set reach the row encoder when the client drained it (#1465).

  **Fetching one: an `OALL8` on the cursor id, not `TTI_FETCH` (#1462).** A
  cursor the client holds no SQL for (a nested cursor, a REF CURSOR) is fetched
  the way python-oracledb (`_fetch_rows`: an ExecuteMessage whenever the
  statement has no SQL) and OCI fetch it. The call is an `OALL8` on its id with
  an empty statement and the options **`0x8040`** (NOT_PLSQL | FETCH, with no
  EXECUTE and no PARSE), and it carries no piggybacks. The difference shows when
  that cursor's rows hold cursors in turn:

  | fetched with | 10g, 11g, 18c, 21c | 23ai |
  |---|---|---|
  | `TTI_FETCH` | each inner cursor cell is cut to `02` + the `ub4` cursor id, with **no inline describe** (`02 01 03` for cursor 3) | full cell |
  | `OALL8` fetch-only | full cell (`4c`, describe, cursor id) | full cell |

  Read as a full cell, the short form takes the cursor id for the max row size
  and desyncs the row. An execute reply always carries the full form, which is
  why one level of nesting worked everywhere: the first level comes in the
  execute reply. The call must carry **no close-cursors piggyback**. The close
  queue can hold the nested cursor's own parent, and closing the parent first
  closes the nested cursor too, so every fetch then comes back empty. A plain
  `TTI_FETCH` never flushed that queue. Measured on 10g, 11g, 18c, 21c and 23ai.

- **OBJECT / collection** OUT value: the object frame a row cell carries
  (§21.2) — a constructed 36-byte toid, the object OID, snapshot, version, image
  gate, flags and the image — then the per-value `ub4` return code. Not a DALC.

  **Which binds get it is the part that bites.** A client naturally recognises
  an object bind by the `Var` wrapped around it, and that is not the only shape
  one arrives in: `cursor.callproc(name, (3, obj))` passes the object **itself**,
  with no `Var` anywhere, and that is the ordinary way to call a procedure.
  Recognising only the wrapped form sends the bare object down the scalar branch,
  where the toid's leading `24` is read as a length; the reply then desyncs two
  bytes in, onto that toid's own `00 22 02 08` prefix, and the decoder reports
  "response token 34". Put a second bind behind the object and the number changes
  to whatever that bind's first byte is — the number is **data**, which is what
  makes this read like a missing decoder and not an off-by-one (#1029).

  This is the fourth carrier of the same frame — a fetched row (§21.2), a DML
  RETURNING bind (§22.1c), an inbound bind, and here — and each has had to learn
  it separately, exactly as the LOB block did across its three.

  A client also has to put the value **back where the caller can see it**. With
  a `Var` there is somewhere to put it; with a bare object there is not, and the
  caller's own object is the handle on the result — so the decoded image is
  written into it in place. A NULL object OUT clears its contents but keeps its
  shape (a record's attribute names survive, all NULL): the type did not change,
  only the value.

After the values come the usual `TTI_RPA` and `TTI_OER` tokens.

**Server side — the Mirror answering a thin client (#483).** The wire carries
**no** bind direction in the request — Oracle infers IN / OUT / IN OUT from the
block source — so the Mirror can't label binds from the OALL8 alone. Instead it
hands the backend *every* bind of a PL/SQL block as a `BindVar` (value + declared
type + OAC buffer size); the backend registers each as an OUT-capable variable,
runs the block (a pure-IN param simply keeps its input value, an OUT/IN OUT one
is written back), and returns every variable's value. `encode_out_bind_response_thin`
then emits the IOV with **all** binds marked IN OUT (`48`) and a DALC value +
`ub4` return code per bind. The client keeps only the positions it bound as a
`Var` (`_assign_out_binds` filters by its own bind list), so the extra echoed IN
values are read and discarded — correct, if slightly more than a real server
sends. IN OUT, not OUT (`16`), because the direction also governs the *next*
execute: a client re-executing the block by cursor id sends **no value** for a bind
it was told is pure OUT, so `:v := :v + 5` run twice got NULL for `:v` the second
time (#1363). Marked IN OUT, every bind sends its value, and a pure-OUT one merely
sends a NULL the block overwrites. A backend that does know the directions reports
them, and the Mirror passes those on instead. This
is what carries the thin `callproc` / `callfunc` / OUT-`Var` flow; passing the
value with its type + size is also the fix for the `ORA-06502: buffer too small`
a value-only OUT bind hit.

A **LOB-class OUT bind** is the exception to "a DALC value" above (#979): it
carries the LOB block, because that is what the client's reader expects. The
Mirror has no upstream locator to pass along — a passthrough backend reads its
upstream with `fetch_lobs=False`, so the value arrives already materialised — so
it **mints** a locator, records the content against it in the session's
`LobEmitLog`, and writes the block with `encode_lob_locator_thin`, exactly as the
LOB *column* path does. The read the client then issues is answered from that log
by locator (§14.5b), so nothing about the read path changes. A NULL LOB is the
single byte `0x00`.

Getting one **into** the backend needs the matching step: a large LOB IN value
reaches the Mirror as a temp LOB the client streamed in (§14.2), which the
passthrough had been binding upstream as plain `str` / `bytes`. That is IN-only —
a block that writes to the bind fails upstream with `ORA-06502` — so the value is
registered as a LOB `Var` instead, on an upstream at 12.1 or above. Below that a
LOB `Var` has no bind encoding at all, so the plain value stays, and an IN OUT LOB
is simply out of reach on such an upstream.

A **REF CURSOR OUT bind** (`OUT SYS_REFCURSOR`, #483) is returned in that same
RXD slot but in the inline-describe form above: the backend opens the cursor, the
Mirror drains its columns + rows into a `CursorResult`, parks the rows on a fresh
cursor id (the ordinary `_Cursors` registry), and `encode_out_bind_response_thin`
emits `<len><describe body><cursor id><ub4 return code>` for that position (the
describe body is the shared §6.4 encoder). The client reads the marker, then
drains that cursor id — with `TTI_FETCH` like any other result set, or by
**re-executing the id with an empty statement** (python-oracledb does the latter
for the object-type metadata cursor, §21.9). A REF CURSOR has no statement of its
own, so on that re-execute the Mirror serves the parked rows with a full
describe + rows reply rather than forwarding the empty statement to the backend
(which would answer `ORA-01009`). Because the inline describe reuses the §6.4
body, it inherits the same field-version gating (no `dcbqcky` before 11.2).

### 6.5c A PL/SQL block has a cursor id, and re-executes by it (#1064)

A block is a cacheable statement like any other: its first execute returns a
**server cursor id** in the reply's OER, and the client re-executes by that id
afterwards. The id is not cosmetic — the reference client keeps a block in
*single-execute* mode for exactly as long as its cursor id is zero:

```python
cdef bint requires_single_execute(self):
    return self._is_plsql and (self._cursor_id == 0 or self._binds_changed)
```

(the reason, from its own docstring: the IN/OUT split of a block's binds is only
settled once the block has run). Answer 0 forever and an `executemany` of a block
is re-sent one iteration at a time — merely slow, until the client pipelines
(§6.9), at which point it walks off the end of its own bind array.

Three things separate a block's re-execute from a DML one, and each was captured
off a live 23ai.

**1. A pure-OUT bind sends no value.** The re-execute writer drops every
`TNS_BIND_DIR_OUTPUT` bind before writing the row, so the row is narrower than
the bind list. `callproc("proc_Test2", ("hi", 5), {"a_OutValue": out_var})`,
re-run on cursor 3:

```
03 04 07 00 | 01 03 | 01 01 | 00 | 00 | 07 | 02 68 69 | 02 c1 06
             cursor  1 iter  opts opts  RXD   'hi'       5
```

Three binds, two values. Reading a value for the third consumes the next bind's
bytes and the row comes apart a position at a time — which is why the directions
the first execute reported have to be *remembered against the cursor*: the
re-execute message itself carries no OACs and cannot restate them.

**2. A block's LONG-class binds ride IN PLACE.** Only DML sorts binds wider than
`max_string_size` to the end of the row (§5.4). A block's binds are routinely
wide — a `VARCHAR` OUT bind declares 16000, an object bind 16000 — so reading one
the DML way puts the first value second. The message carries no statement, so
whether the cursor stands for a block is something only the *server* knows, from
what it parked under that id.

**3. The reply's shape follows the message, not the statement.** A plain
re-execute (func 4 / 78) is answered with one `TTI_RXD` per iteration carrying
that iteration's OUT values, and **no IOV** — it could not restate the directions
anyway. An `executemany` whose remaining four rows went in one re-execute:

```
07 02 c1 07 00 | 07 02 c1 16 00 | 07 02 c1 12 00 | 07 02 c1 2c 00 | 04 ...
RXD  6     rc    RXD  21    rc    RXD  17    rc    RXD  43    rc    OER
```

An OALL8 carrying a cursor id and no SQL is a full execute message, and its reply
**does** carry the IOV, exactly as the opening execute's does.

Which iteration failed is carried by the OER's **rowcount** field, and it is the
only way the client can report an offset: it adds that count to however many
iterations it ran before sending this message. Leaving it zero blames the first
row for every failure.

### 6.6 Return Parameter (TTI_RPA)

Contains cursor information and bookkeeping after statement execution. For authentication, it carries key-value pairs. For SQL execution, it carries the cursor ID for subsequent fetch operations.

### 6.7 Error Response (TTI_OER)

The OER block is emitted at the end of every server response, success
or failure. The layout is unified — there is no separate "error" vs
"success" structure on the wire; instead every field is always present
and the error code distinguishes the outcome. On 11g:

```
TTI_OER |
  call_status (ub4) |
  end_to_end_seq# (ub2, skipped)  -- diagnostic only; the Mirror advances it
                                  -- per message, see 36.2 |
  current_row_number (ub4)    -- the DML rowcount on 11g (see note) |
  ora_error_code (ub2)        -- 0 on success |
  array_elem_error (ub2, skipped) | array_elem_error (ub2, skipped) |
  cursor_id (ub2) |
  error_position (sb2)         -- the parse offset; surfaced as DatabaseError.offset (oracledb parity) |
  sql_type, fatal, flags, user_cursor_options, upi_param,
    warn_flags (6 x ub1; flags is a ub2 below 12.1, see 6.3a)
                              -- warn_flags carries a real signal |
  rowid (ub4 data_object + ub2 rel_file + ub1 + ub4 block + ub2 slot) |
  os_error (ub4, skipped) |
  statement_number (ub1, skipped) | call_number (ub1, skipped) |
  padding (ub2, skipped) |
  successful_iterations (ub4)  -- always 1 for non-array execute on 11g |
  oerrdd (bytes_with_length, skipped) |
  num_batch_error_codes (ub2)   [+ batch error codes block]
  num_batch_error_offsets (ub4) [+ batch offsets block]
  num_batch_error_messages (ub2)[+ batch messages block]
  [trailing message DALC iff ora_error_code != 0]
```

**"iff" means a server must not write the message on success either** — not
even an empty one. From 12.1 a client reads it only `if error_num != 0`, so a
zero-length DALC (`0x00`) on a successful OER is a byte nothing consumes. That
was invisible for as long as the OER ended the response, because the client
stopped there. Under end-of-response framing (§32.1) it does not stop: it reads
on for the marker and takes that `0x00` as the next message type — *"unknown
protocol message type 0"* — which is how the Mirror's every login failed once it
advertised the capability (#1059). The general lesson: end-of-response turns any
trailing byte that used to be harmless into a desync.

#### 6.1a ORA-01017 means the credential failed, and nothing else (#1006)

A login can fail for reasons that have nothing to do with the credential: the
proof verifies, and then the server cannot produce a session for it. A Mirror
feels this most sharply — its backend is a second database, which can be full,
down, or refusing — but a real server has the same distinction.

`ORA-01017` is deliberately vague about **user versus password**, and that is
the only ambiguity it is allowed to carry. Sending it for anything else tells
the caller they got their password wrong when they did not, and the one thing
they cannot then do is tell a bad password from a server with no session to
give.

Relay what actually happened:

| cause | what the client is told |
|---|---|
| the password proof did not verify | `ORA-01017`, as Oracle sends it |
| the backend refused with its own code | **that code** — e.g. `ORA-12516` when the database is out of processes |
| the backend failed with no ORA code | `ORA-01034`, the instance is not available |

Relaying the backend's own code is what lets a client behind a passthrough see
exactly what a direct connection would have seen.

Worth recording why this is not cosmetic. A full-suite run produced a burst of
`ORA-01017` setup errors, twice, in two different sessions. Both times the
credential was correct and the affected file passed in isolation, so both times
it was written off as flaky account state. It was actually the database hitting
its process limit (`v$resource_limit`: 173 of 200), and only the Mirror's own
log said so. A misreported error does not just lose information — it sends the
reader somewhere else entirely.

#### 6.2a A message is a byte stream; a parse fault must not end the session (#1000)

A TTC message spans as many DATA packets as it needs, and python-oracledb sends
the continuations with **no MORE flag** — so the first parse of a large request
runs off the end *by design*, and the server grows the body until it does not.
That works only because every decode primitive says "I ran off the end" the same
way. Two reads in the OAC walk did not: a `struct.unpack` of the 3-byte header
and a bare index for the csfrm byte, which raise `struct.error` and `IndexError`.
Neither reads as "read more", and neither was caught, so a PL/SQL block with
~1400 binds took the whole connection down (`DPY-4011`).

Both now raise the truncation signal. And, separately, **a parse fault answers
rather than kills**: reaching the request parser with something it cannot walk is
always a bug in that parser, but the server's contract is that it never desyncs,
so it logs loudly and refuses the one call. A client that gets an error can
carry on; a client whose connection was dropped mid-suite cannot.

#### 6.3a `warn_flags`: a warning on a call that SUCCEEDED (#993)

**Below 12.1, `flags`, the third of the six, is a variable-length ub2, not a
byte** (#1995). It is `00` when zero, so an ordinary reply looks like six single
bytes, but a warning sets it, and then it takes two. An aggregate that skipped
NULLs (`SELECT g, AVG(n) ... GROUP BY g` over an all-NULL group) is one such
warning, captured from live servers:

| server | sql_type … warn_flags |
|---|---|
| 10g, 11g | `03 00 01 20 00 00 05` |
| 18c, 21c, 23ai, and 23ai negotiated at 12.1 or 12.2 | `03 00 20 00 00 05` |
| no warning, any server | `03 00 00 00 00 00` |

Read as one byte, the 10g/11g form leaves the reader one byte early: the rowid
starts on `05`, and every field after it is misread. 11g then failed on the
batch-error arrays, while 10g happened to come through.

Five of those six fields are diagnostic and skipped. The **last** one
is not. Bit `0x20` says the statement created a PL/SQL object that **compiled
with errors** — a `CREATE PROCEDURE` with a syntax error *succeeds*, the object
exists in an invalid state, `ora_error_code` is 0 and the reply is otherwise
indistinguishable from a clean one.

Measured by diffing a live 23ai's reply to the same `CREATE` compiled clean and
broken. The two packets are 69 bytes each and differ in **four** bytes — three
of them the end-to-end sequence and SCN, and this:

```
offset 47:   broken = 0x21      clean = 0x00
```

`0x01` rides alongside in other captures either way, so the test is the bit, not
the value: `flags & 0x20`.

The reference client surfaces it as `cursor.warning`, an object carrying
`DPY-7000: creation succeeded with compilation errors`, set by the execute that
raised the bit and cleared by the next one that does not — so a `DROP` of the
same object clears it. seerdb matches that, including `full_code`.

Skipping the byte loses the only signal there is: the caller is told the create
succeeded, which is true, and never that the object it just made does not
compile.

**Server side — the Mirror (#995).** `encode_status(..., compilation_warning=True)`
raises the bit; everything else about the reply is unchanged, because the call
*did* succeed. The backend has to be able to tell — a passthrough reads it
straight off its own upstream cursor, and a backend that cannot leaves it unset,
which is what the client saw before any of this existed.

The OCI reply carries the same signal in its own OER, at offset `27` (§36.1),
and sqlplus prints "Warning: Procedure created with compilation errors." from it.
The Mirror's OCI DDL status set it from #2013 on; before, sqlplus printed a plain
"Procedure created." for an object that did not compile.

**11g rowcount quirk.** The field labelled "current row number" in
newer Oracle (and in python-oracledb's source) doubles as the affected
row count on 11g: an UPDATE / DELETE / INSERT writes the number of
rows touched there. The later `successful_iterations` field is the
call iteration count — always 1 for a single non-array execute — so
it cannot serve as the rowcount the caller wants. 12c+ moved the
affected count to a separate ub8 field at the end of the OER (after
two additional `info.num` / `info.rowcount` extensions); seerdb
doesn't parse that variant yet.

**Rowid → `lastrowid`.** The `rowid` field carries the rowid of the row
the statement touched, in the same physical-rowid layout as a ROWID
column (`§14`): data object number, relative file number, an unused
byte, block number, slot number. seerdb renders it via the same
base-64 encoder and surfaces it as `Cursor.lastrowid` for
INSERT / UPDATE / DELETE. For a SELECT the server fills it with the last
fetched row's rowid, which is not a "last modified row", so the driver
clears `lastrowid` on result-set statements; a zero block number (DDL /
no row) means no rowid.

In a **bigfile** tablespace (23ai's default `USERS`) this field and a fetched
ROWID column disagree on the relative file number: the status token carries the
bigfile marker **1024**, the column **0**. So the same row prints `…AQAAAD…` as
`lastrowid` and `…AAAAAD…` as a fetched ROWID or through `ROWIDTOCHAR`, and the
server accepts either back (`WHERE ROWID = :1` finds the row with both).
python-oracledb reports exactly the same pair, so compare rowids by the row they
name, never as strings. Status tokens do not even agree among themselves: a
DELETE's carries the relative file as **0** where the INSERT of the same row
carried **1024** (#1079), so compare by data object, block and slot. Measured on
23ai.

The Mirror writes these fields from the backend's `Result.last_rowid` (its
printable form, parsed back by `string_to_rowid`); a backend with no Oracle
rowids leaves them zero (#1077). 8i and 9i carry the rowid in their short status
too, in the same fields (§19.3, §19.12); unlike 10g+, a statement that touched
nothing leaves the previous rowid there rather than zeroing the block (#1079).

**Common error codes**:
- `0`: Success.
- `1`: ORA-00001 — unique constraint violated.
- `942`: ORA-00942 — table or view does not exist.
- `1403`: ORA-01403 — no more data (end of result set; normal SELECT
  completion).
- `1722`: ORA-01722 — invalid number.

**Trailing message.** When `ora_error_code != 0`, a single DALC
follows the batch-error-messages count carrying the human-readable
`"ORA-NNNNN: ..."` string. Forward this verbatim to callers — do not
embed a copy of Oracle's error-message catalogue in the driver
(`CONTRIBUTING.md` calls this out explicitly).

On 11g that DALC comes right after the batch-error arrays. 12c+ inserts
the extended-precision error number (`ub4`) and rowcount (`ub8`) before
it, and 20.1+ adds a `ub4` SQL type and `ub4` server checksum. `decode_
token_oer` skips these by field version (§4.2); without it the message
DALC is mis-aligned and decodes to garbage even though the early
`ora_error_code` (and thus the exception class) is still correct.

**The 20.1 pair follows the server's release, not the negotiated version
(#1145).** 21c and 23ai send the SQL type and checksum to every session,
including one that negotiated 12.1, 12.2 or 19c (7, 8, 12). The OER bytes are
identical at every negotiated version apart from the sequence number:

```
… 02 06 ba | 00 | 01 03 | 00 | 7e "ORA-01722: …"
  ext err    ub8   sql     checksum  message
  (1722)     rows  type
```

Read by the negotiated version, a session below 20.1 took the SQL type for the
message length and lost every error's text. The client therefore gates the pair
on the field version the server **advertised** in its compile-time
capabilities, and the Mirror on the one it presents. The extended error number
and rowcount stay on the negotiated 12.1.

#### 6.3b The rowcount field is read on an ERROR too (#998/#1003)

`current_row_number` is not only a success field. An `executemany` whose batch
aborts part-way really did apply the rows before the failing one, and the server
reports how many **there**, alongside the error — a caller reading
`cursor.rowcount` in an `except` block is asking what actually happened, which is
exactly when it matters.

Both sides of that have to agree. A client that sets its rowcount only on the
success path keeps whatever it had — the `-1` a fresh cursor starts with, or a
count left over from an earlier statement, which is the worse of the two because
it looks plausible. And a server that hard-codes 0 into every error OER tells a
caller nothing happened when three rows did.

Note the count is what the call **managed**, so a statement that failed outright
reports 0 rather than inheriting the previous statement's number.

### 6.8 Status (TTI_STA)

Indicates successful completion of a transaction operation (COMMIT, ROLLBACK, PING).

### 6.9 Flush Out Binds (TTI_FOB)

Sent by the server when processing RETURNING clauses. The client acknowledges by
echoing TTI_FOB back.

**When it arrives** (#697): on a DML statement carrying a `RETURNING` clause that
**fails**. The same statement succeeding never produces one, and a failing
statement *without* a RETURNING clause answers with its error directly. Verified
identically on 10g, 11g, 21c and 23ai — this is not a version quirk, and it is
not specific to the array form.

**What arrives**: a DATA packet whose entire body is the single byte `0x13`. No
error, no status, nothing after it. The server then **waits**. The real error
response is only sent once the client has echoed the token back, in a DATA packet
that is likewise just `0x13`.

So it is a request, not a result, and a client that reads it as one is left in
the worst position available: it has an unusable value in hand, and the server is
still waiting for an answer that is never coming. The next statement on that
connection is rejected — **ORA-03137** (`opiexe: protocol violation`) on 11g and
later, **ORA-00600** with the same text on 10g — because the server is still in
the middle of the previous call. The failure therefore does not look like what it
is: it lands on whatever statement runs next.

seerdb answers it in the connection's response loop, which reads on afterwards
for the response the request was standing in front of, so the caller sees the
ordinary exception the statement earned (`ORA-01400` for a NOT NULL violation,
say) and the connection stays usable. One request is what a real server sends;
the loop caps how many it will answer so that a server which never stops asking
ends the call rather than spinning on it.

## 7. Piggyback Functions (TTI_PFN)

Piggyback functions allow batching cursor management operations with the next request:

```
TTI_PFN | FunctionID | SeqNum | 1 | CursorCount(SB4) | Cursors(SB4[])
```

- **TTI_CANA (120)**: Close specified cursors.
- **TTI_OCCA (105)**: Close all cursors.

These are prepended to the next TTI_FUN/TTI_ALL8 message to avoid extra round trips.

## 8. Transaction Control

Transaction operations are simple TTI_FUN messages:

```
TTI_FUN | FunctionID | SeqNum
```

| Function     | ID  | Description                          |
|-------------|-----|--------------------------------------|
| TTI_COMMIT  | 14  | Commit current transaction           |
| TTI_ROLLBACK| 15  | Rollback current transaction         |
| TTI_COMON   | 12  | Enable autocommit mode               |
| TTI_COMOFF  | 13  | Disable autocommit mode              |
| TTI_PING    | 147 | Connection health check              |

When autocommit is disabled, the library automatically issues a ROLLBACK before closing the connection.

## 9. Database Startup/Shutdown

### Startup (TTI_STRT)

```
TTI_FUN | TTI_SPFP | SeqNum | 1 | 1 | 100 | 1 | 1 | 0 | 0 | 0 | 0 | 0
TTI_FUN | TTI_STRT | SeqNum | Mode(SB4) | 1
```

Modes: `0` = no restrict, `1` = restrict, `16` = force.

### Shutdown (TTI_STOP)

```
TTI_FUN | TTI_STOP | SeqNum | Mode(SB4) | 1
```

Modes: `2` = immediate, `4` = normal, `8` = final, `64` = abort, `128` = transactional.

## 10. Connection Teardown

```
TTI_FUN | TTI_LOGOFF | SeqNum
```

Before closing the socket, the library:
1. Rolls back uncommitted transactions (if autocommit is off).
2. Closes any cached cursors via piggyback TTI_CANA / TTI_OCCA.
3. Sends TTI_LOGOFF and reads its response.
4. **Sends a final empty TNS_DATA packet with `data_flags = 0x0040`**
   (the TNS EOF marker). Without this byte the server can hold the
   session in a half-released state long enough that rapid reconnect
   cycles exhaust the listener and start surfacing ORA-01013 on new
   connections.
5. `shutdown(SHUT_WR)` the socket so the FIN flushes the queued EOF
   packet to the server, then `close()`.

The 10-byte EOF packet wire format is the standard TNS_DATA header
with no body:

```
00 0a | 00 00 | 06 | 00 | 00 40
length | flags | typ| f | data_flags = EOF
```

**A clean logoff commits** (#1429). Step 1 is the *client's* choice. A session
that sends `TTI_LOGOFF` with a transaction still open has it **committed** by the
server, on every version measured (8i, 9i, 10g, 11g, 23ai). Only a dropped
connection rolls back. sqlplus depends on it: with the default `EXITCOMMIT ON`,
`INSERT …; exit` sends the INSERT and then `TTI_LOGOFF`, no COMMIT (captured,
sqlplus 23.26 against 11g). python-oracledb and seerdb roll back first when
autocommit is off, so a closed connection loses its uncommitted work for them;
the Mirror commits what is left open at a logoff, thin or OCI, as Oracle does.

### 10.1 The server's logoff reply (thin)

Step 3 above — "reads its response" — is load-bearing from python-oracledb
26.0.0 on. Its `LogoffMessage` sends `TTI_LOGOFF` and then **reads a reply**
before closing; earlier thin clients sent `TTI_LOGOFF` and closed the socket
without reading, so a server (or the Mirror) could end the session silently.
Against 26.0.0 a silent close is an unexpected EOF — `DPY-4011: the database or
network closed the connection` — raised even on a clean `connection.close()`.

The reply is a `TTI_STA` status token, then the per-response `END_OF_RESPONSE`
marker (`0x1d`, 29):

```
09 | 01 01 | 00 | 1d
STA| call status (ub4 = 1) | end-to-end seq (ub2 = 0) | END_OF_RESPONSE
```

The integers are the thin protocol's variable-length form, **not** the
fixed-width little-endian the OCI/sqlplus logoff ack (§36.2) uses. A bare
`STATUS` token does not by itself end a response for a client that negotiated
end-of-response, so the `0x1d` marker is required. Byte-identical to a live 23ai
reply. (The Mirror sends this from its thin loop; the OCI loop keeps its own
`_OCI_LOGOFF_STATUS`.)

## 11. Data Type Encoding

### 11.1 Oracle NUMBER

Oracle's proprietary variable-length number format:

- Byte 0: Exponent byte. High bit indicates sign (1 = positive, 0 = negative).
  The magnitude is biased by 193 (positive) or its one's complement (negative);
  exponent *N* means the first mantissa group carries `100**N`.
- Bytes 1..N: Mantissa digits, each representing a base-100 digit.
  - Positive: digit + 1 (range 1-100).
  - Negative: 101 - digit (range 1-100), with a trailing `102` sentinel.
- Special value `0x80` represents zero.

`encode_token_decimal` encodes a `Decimal` straight to this base-100 form (no
float round-trip). Two *independent* limits apply:

- **Significant digits:** the mantissa holds at most **20 base-100 groups**
  (≈ 38 significant decimal digits); a longer value is rounded half-up.
- **Magnitude:** the biased exponent spans roughly `1e-130` … `9.999e125`.

A value can therefore sit at a huge magnitude with only a few significant
digits — its trailing all-zero groups are **not** stored as mantissa bytes, they
are absorbed by the exponent (e.g. `10**125` is a *single* mantissa group with a
large exponent, not 63 zero groups).

`encode_token_num` keeps the int / float fast paths, but its integer encoder
(`lnxmin`) materialises groups least-significant-first and caps at 20, so it only
covers `|value| < 10**40`. A larger **integral** NUMBER is routed to the exact
base-100 encoder above, so those trailing-zero groups fold into the exponent
instead of overflowing the 20-group buffer (previously this raised; #316). All
paths are the exact inverse of `decode_number`.

> **Sentinels.** Besides `0x80` (zero), Oracle has single-byte forms `0x00` and
> `0xFF 0x65` — internal −∞ / +∞ markers. These are not emitted for an actual
> `NUMBER` column (the type has no infinity), so seerdb does not special-case
> them; `decode_number` currently reads them as large finite values (tracked as
> an observation under #304).

### 11.2 Oracle DATE

7-byte fixed format:
```
Century+100 | Year+100 | Month | Day | Hour+1 | Minute+1 | Second+1
```

A year **before 1** (Oracle's DATE reaches back to -4712, i.e. 4712 BC, with no
year 0) counts **down** from the same bias: both the century and the
year-of-century of `|year|` are subtracted from 100. Measured with `DUMP(col, 16)`
of stored columns on 23ai:

| year  | century, year bytes |
|-------|---------------------|
| -4712 | `35 58` (100-47, 100-12) |
| -101  | `63 63` |
| -100  | `63 64` |
| -44   | `64 38` |
| -1    | `64 63` (century 0) |

The other five bytes are as for any date, and a TIMESTAMP's fraction follows as
usual. No Python `datetime` can hold such a value. The client reports it as
`DateOutOfRangeError`, a `DataError` and `ValueError` (#1060). A Mirror backend
hands one over as `seerdb.server.BcDate`, which the row encoder writes in this
form (#1071); a BC `TIMESTAMP WITH TIME ZONE` is not covered.

The client binds a `BcDate` too. Declared, it takes the declared type's form.
Undeclared, it follows a `datetime`'s rule: DATE (`12`, 7 bytes) without a
fraction, TIMESTAMP (`180`, 11 bytes) with one. An `executemany` column that
mixes the two is declared TIMESTAMP as in §5.4 (#1098). Before #1804 an
undeclared one had no OAC and the bind failed before anything was sent.

### 11.3 TIMESTAMP

11 bytes: 7-byte DATE + 4-byte nanosecond fractional seconds (big-endian unsigned integer).

### 11.4 TIMESTAMP WITH TIME ZONE

13 bytes: the 11-byte TIMESTAMP wall clock (which the server expresses
in UTC) plus a 2-byte timezone encoding.

Timezone encoding has two forms:
- **Offset-based**: `Hour + 20`, `Minute + 60` (when bit 0x80 of the
  first byte is clear). seerdb handles this form.
- **Named zone (region ID)**: when bit 0x80 of the first byte is set,
  the two TZ bytes carry an Oracle timezone region id instead of an
  offset: `region_id = ((byte0 & 0x7f) << 6) + (byte1 >> 2)`. Note the low
  tz byte (`byte1`) is **0** for any region id that is a multiple of 64
  (Africa/Windhoek=64, America/Manaus=192, Asia/Macao=256, Europe/Gibraltar=384,
  …). A 13-byte frame is *always* a real zone — DATE is 7 bytes, TIMESTAMP 7/11,
  and TIMESTAMP WITH LOCAL TIME ZONE carries no tz bytes — so the decoder must
  **not** treat a zero low byte as "no zone" (doing so returned a naive UTC wall
  clock for those zones; #304). seerdb
  maps the id to an IANA zone name (`seerdb/_tzregions.py`, a stable
  id→name table generated from the server's `V$TIMEZONE_NAMES`) and then
  asks the standard-library `zoneinfo` module for the offset **at that
  instant** — so DST is applied correctly and offsets track the live IANA
  tz database rather than any table frozen into an Oracle release. An id
  not present in the table (a few obsolete Oracle aliases) falls back to a
  naive `datetime.datetime`.

When decoding, seerdb treats the wall-clock bytes as UTC and then
shifts to the tagged offset, so the resulting Python `datetime` both
compares equal to the original instant and prints with the original
local time. The encoder is symmetric: a `datetime` with `tzinfo` is
first converted to UTC for the wall-clock bytes, then tagged with the
original offset.

### 11.4a TIMESTAMP WITH LOCAL TIME ZONE

11 bytes — the **same** shape as a plain TIMESTAMP (§11.3), not the 13-byte TZ
form: no zone travels on the wire and no offset bytes are carried. Its describe
length is 11 accordingly (§6.2), which is the giveaway: a 13-byte frame is always
a real TIMESTAMP WITH TIME ZONE.

**The wire value is the instant in the database time zone** (`DBTIMEZONE`), not
the session's. A fetched LTZ value arrives in the database zone, and a bind
declared LTZ (type 231) is read as an instant in that zone and round-trips
unchanged. Only a plain TIMESTAMP going into an LTZ column (a TIMESTAMP bind, a
`TIMESTAMP '…'` literal, or `CAST(ts AS TIMESTAMP WITH LOCAL TIME ZONE)`) is read
as a wall-clock time in the **session** zone, and it comes back converted to
the database zone. Measured with seerdb and the reference thin client side by
side, identical (#1208, #1967), binding 13:45 into an LTZ column:

| bed | database / session zone | LTZ bind fetches | TIMESTAMP bind fetches |
|---|---|---|---|
| 23ai | `+00:00` / `+05:00` | 13:45 | 08:45 |
| 9i | `-08:00` / `+00:00` | 13:45 | 05:45 |

The two bind kinds decode to the same naive `datetime`, so a server has to keep
the bind's declared type to tell them apart; the Mirror hands its backend an
`LtzValue` for an LTZ bind (#1222). `SYSTIMESTAMP` and `CURRENT_TIMESTAMP` are
TIMESTAMP WITH TIME ZONE, `LOCALTIMESTAMP` is TIMESTAMP.

The consequence for an encoder is that dispatch must be on the column's
`data_type`, and TIMESTAMPLTZ (231) must land on the 11-byte branch. Falling
through to the 7-byte DATE form produces a frame the client reads without
complaint and **silently drops the fractional seconds** — `22:30:02.5` arrives
as `22:30:02` with no error anywhere (seerdb#826). A `datetime`'s `tzinfo`, if
any, is discarded rather than applied: the value on the wire is already the
instant in the database zone.

### 11.4b A declared TIMESTAMP / LTZ bind with no fractional seconds

In the **bind** direction the width of a TIMESTAMP or TIMESTAMP WITH LOCAL TIME
ZONE value is not fixed by its descriptor. A value whose fractional seconds are
zero goes out in the **7-byte DATE form** under the 11-byte descriptor, and only
a value with a fraction takes the 11-byte form. The reference thin client does
exactly this, and its encoder says the protocol requires it.

The two forms of the same instant are **not** read alike by the server. Measured
live on 10g, 11g, 21c and 23ai (#1337): with a bind declared
`TIMESTAMP WITH LOCAL TIME ZONE` and the session in the database's zone,
`WHERE trunc(ltz_column) = :midnight` matches the row when `:midnight` arrives
as 7 bytes and matches **nothing** when it arrives as 11 bytes with a zero
fraction. Yet `DUMP` and `TO_CHAR` of the bind show the same value either way.
seerdb therefore strips a zero fraction from a declared TIMESTAMP / LTZ bind.
DATE stays 7 bytes and WITH TIME ZONE 13. The **row** direction (a server or
the Mirror encoding a column value) keeps the fixed 11-byte form of §11.4a.

### 11.5 INTERVAL YEAR TO MONTH

5 bytes: `Year(4 bytes, big-endian) | Month(1 byte)`, biased by `2**31` and `60`
respectively. Both fields share the interval's sign. Maps to
`seerdb.IntervalYM(years, months)`.
Example: `3-7` → `80 00 00 03 43` (years `0x80000003 − 2**31 = 3`, months
`0x43 − 60 = 7`); `-1-2` → `7f ff ff ff 3a`. The Mirror emits the same 5 bytes
from an `IntervalYM` column value (`encode_interval_ym`, #484).

### 11.6 INTERVAL DAY TO SECOND

11 bytes: `Day(4) | Hour(1) | Minute(1) | Second(1) | FracSec(4, BE
nanoseconds)`. Day biased by `2**31`; H/M/S biased by `60`; FracSec biased by
`2**31`. All fields share the interval's sign. Maps to `datetime.timedelta`.
Example: `5 04:03:02.123456` → `80 00 00 05 40 3f 3e 87 5b ca 00`. The Mirror
emits the same 11 bytes from a `timedelta` column value (`encode_interval_ds`,
#484); a negative interval's sub-day fields are reconstructed from the
sign-normalised total, not the floor-divided `timedelta.days` / `.seconds`.

`timedelta` sub-microsecond precision is lost (Oracle stores nanoseconds; Python
has microseconds), and its range is slightly narrower than Oracle's on the
negative side: `timedelta.min` is exactly `-999_999_999 00:00:00`, whereas
`INTERVAL DAY(9) TO SECOND` reaches `-999_999_999 23:59:59.999999`. seerdb raises
`DataError` for such an out-of-range value rather than leaking Python's raw
`OverflowError`. The positive extreme fits `timedelta.max`.

### 11.7 BINARY_FLOAT / BINARY_DOUBLE

4-byte (float) / 8-byte (double) IEEE-754 in Oracle's **order-preserving** form
so the raw bytes sort the same as the numbers:

- **Encode**: if the value is positive, set the high (sign) bit; if negative,
  invert every bit.
- **Decode**: if the high bit is set, the value was positive — clear it; else
  the value was negative — invert every bit. Then read as IEEE-754.

Example: `1.5` (IEEE `3fc00000`) → `bfc00000`; `-2.25` (IEEE `c0100000`) →
`3fefffff`. `inf` / `nan` / `-0.0` round-trip; binding them requires the native
binary types (NUMBER cannot represent them).

### 11.8 ROWID

A REF/physical rowid (TNS type 11) is read from RXD as: a 1-byte present
indicator (0 / 0xff = NULL), then Object ID (UB4), File# (UB2), an unused UB1,
Block Number (UB4), Slot Number (UB2). Rendered as the 18-character extended
rowid: base-64 (`A-Z a-z 0-9 + /`) with fixed field widths 6+3+6+3 over
object / file / block / slot. Example: object 44681, file 4, block 8591,
slot 0 → `AAAK6JAAEAAACGPAAA` (matches `ROWIDTOCHAR`).

A **UROWID** (universal / logical rowid, TNS type 208 — e.g. the rowid of an
index-organized table) uses the same RXD framing as a LOB column: `ub4
num_bytes`, a 1-byte length echo, then `num_bytes` raw rowid bytes. The first
byte is a **type tag, and the printable form depends on it** (captured from 23ai,
#1086):

- **`02` — logical** (an index-organized table's rowid): `"*"` + standard
  base-64 of the remaining bytes (no `=` padding). Example: value
  `02 04 01 00 19 83 02 c1 02 fe` → `*BAEAGYMCwQL+` (the trailing `c1 02` is the
  table's NUMBER primary key, since an IOT rowid is logical).
- **`01` — physical** (an ordinary rowid stored in a UROWID column): 13 bytes,
  the tag then data object (ub4), partition / relative file (ub2), block (ub4)
  and slot (ub2), big-endian, rendered as the ordinary 18-character extended
  rowid. Example: `01 0001f5c1 0000 00015aed 0000` → `AAAfXBAAAAAAVrtAAA`,
  which is what the same row's ROWID column prints. python-oracledb branches on
  the tag the same way; rendering this one in the `*` form gave a string that
  matched neither.

NULL when `num_bytes` is 0.

**Server side — the Mirror (#484).** The Mirror holds a rowid as its rendered
string (what the backend hands back), so it inverts the render before emitting.
`encode_rowid_value` parses the 18-char string back to object / file / block /
slot (`string_to_rowid`, the inverse of the render) and writes the structured
RID; `encode_urowid_value` picks the tag from the string: a `*` rowid is tag
`02` + its base64-decoded body, an 18-character one is tag `01` + its four
big-endian fields (#1086). The tag is not cosmetic: a client renders by it, so
the old fixed `01` made python-oracledb read every logical rowid as a physical
one, which then matched no row. Both
are routed before the scalar NULL path, since a NULL rowid still carries its own
framing (the RID present indicator / a zero `num_bytes`), not the empty DALC.
Verified live over 11g: `ROWID == ROWIDTOCHAR(ROWID)`, a rowid used as a bind,
and an IOT UROWID.

### 11.9 LOB Locators (CLOB, NCLOB, BLOB, BFILE)

LOBs are *not* sent inline with row data. What appears in RXD for a
LOB column is a fixed-size **locator** — an opaque server-side handle
(~40 bytes) plus a couple of metadata fields. Reading the actual LOB
content requires a separate `TTI_LOBOPS` round-trip per locator
(`§14`).

The per-column wire layout in RXD for a LOB:

```
ub4    num_bytes           # 0 = NULL LOB; otherwise size of locator block
[
  ub8    size                # in bytes (CLOB/NCLOB: characters)
  ub4    chunk_size          # server-preferred read chunk size
  DALC   locator             # opaque locator bytes
]                            # CLOB / NCLOB / BLOB

[ DALC   locator ]           # BFILE (no size / chunk_size prefix)
```

Per python-oracledb the locator buffer is canonically 40 bytes;
internal flags inside the locator (`TNS_LOB_LOC_OFFSET_FLAG_*`)
distinguish temporary LOBs that need cleanup on close from regular
ones. Embedding the locator format isn't necessary on the client
side — the bytes are opaque to anything other than `TTI_LOBOPS`.

The TNS data type numbers (`§3.1`) for LOBs are:

| Type    | TNS code |
|---------|----------|
| CLOB    | 112      |
| BLOB    | 113      |
| BFILE   | 114      |
| NCLOB   | 112 + national charset form |

seerdb's row decoder reads the LOB column as `ub4 num_bytes |
DALC locator_block`. The locator block (the locator metadata plus any
inline content section) is a **DALC** (`§12.2`): a single length-prefixed
chunk while the block stays under 254 bytes, or the `0xFE` chunked form
(length-prefixed sub-chunks terminated by a zero length) once it reaches
254. The block crosses 254 bytes when the LOB's content is woven inline
into the locator — for medium CLOBs, and for NCLOBs at half the character
count because their inline content is UTF-16BE (two bytes per character).
Decoding the block as a DALC (not as a 1-byte size echo + `num_bytes` raw
bytes, which only matched the single-chunk case) is what makes those
mid-size inline LOBs decode instead of spilling content bytes into the
token stream (#37). The reassembled locator is exactly what the server
expects back as the source pointer in a `TTI_LOBOPS` READ. NULL LOBs
(single `0x00` byte) come back as Python `None`; non-NULL LOBs come back
as `seerdb.lob.LOB` objects that `Cursor.execute` automatically resolves
to `str` (CLOB) or `bytes` (BLOB) via `LOB.read()`.

Confirmed against XE 11g captures: `num_bytes` scales with content
as `102 + 2 × utf16_chars` for CLOBs and `102 + content_bytes` for
BLOBs. `LOB.read()` issues `TTI_LOBOPS` READ (`§14`) and decodes the
returned chunk as UTF-16BE for CLOB or surfaces raw bytes for BLOB.
EMPTY_CLOB() / EMPTY_BLOB() short-circuit without a round-trip.
The same path handles both inline-content LOBs and out-of-line LOBs
uniformly (the server packs content inline or fetches it from storage
as needed — that detail is opaque to the client).

### 11.10 LONG / LONG RAW

A LONG (TNS type 8) or LONG RAW (type 24) column in RXD is a chunked value
followed by **two trailing `ub4` indicators** (the actual / return lengths,
`0` / `0` for an ordinary value):

```
0x00            NULL, no body
0xfe            chunked: repeated [ub1 length][bytes] until a zero-length chunk
else            ub1 length + that many bytes
ub4 ub4         two trailing indicators (skip)
```

Large values are split into many chunks of at most 255 bytes, each with its
own length byte (XE uses 64-byte chunks for LONG; §6.2 has the general rule),
not one big chunk. LONG decodes to `str` (charset-aware), LONG RAW to `bytes`,
NULL to `None`. Confirmed against XE 11g (NULL, single-chunk, a 700-byte
multi-chunk value, and a LONG that is not the last column).

**Server side — the Mirror answering sqlplus (OCI, #407).** A LONG / LONG RAW
column is streamed inline (no LOB locator), but sqlplus drives it through a
distinct **describe → re-execute → fetch** flow, not the inline execute reply the
scalar types use:

- **Describe.** The column reports type 8 / 24 with `data_length`, `max_size`, and
  the describe **max-row-size** all `0` (the value is unbounded and streamed).
  LONG is a character type (charset + the `0x80` char flag, like VARCHAR2); LONG
  RAW is binary.
- **Row value.** Always the `0xFE`-chunked form — `0xFE`, then `<ub1 len><bytes>`
  chunks (the Mirror emits ≤ `0xFC`-byte chunks) terminated by a zero-length
  chunk — followed by a single trailing `ub4` indicator (`0`). A NULL value is
  `0x00` followed by that same trailing `ub4`. (The Mirror emits one trailing
  `ub4`; the thin-decode form above tolerates the pair.)
- **Flow.** The first execute returns the describe with a "more rows" status and
  **no row inline** (an inline LONG row crashes sqlplus, which sets up its
  streaming define first). sqlplus then **re-executes** the cursor — an `OALL8`
  with the cursor id set and **no SQL** (the SQL-pointer indicator at OALL8 byte
  11 is absent) — and the Mirror replies with the first row: row header (`TTI_RXH`)
  + `TTI_RXD` + the **execute row-status** (`08 06 00 …`). Each subsequent row
  comes on a `TTI_FETCH`, replied as `TTI_RXH` + `TTI_RXD` + a **"more rows" OER
  status** (`04 01 …`, no ORA-01403 message). A final empty fetch draws the
  ORA-01403 terminator. Verified live on 11g: single-row, multi-row, multi-chunk
  (300+ bytes), NULL, and multi-column results, with the session continuing
  cleanly afterward. sqlplus renders LONG RAW poorly (a display quirk of its own,
  reproduced against real Oracle); the bytes round-trip intact.

**Server side — the Mirror answering a thin client (#484).** A thin client
(seerdb / oracledb-thin) needs no streaming dance: the LONG / LONG RAW value
rides **inline in the ordinary execute reply**, in the same `TTI_RXD` as the
other columns (`encode_long_value_thin`). The value is the `0xFE`-chunked form
(chunks ≤ 252 bytes as the Mirror writes them, terminated by a zero-length
chunk; a chunk could be up to 255, §6.2), and — unlike the OCI
path — it carries **both** trailing `ub4` indicators (`0` / `0`) that
`_read_long_column` consumes. A NULL is a bare `0x00` marker still followed by
those two indicators, so it can **not** take the empty-DALC NULL path the scalar
types use — the Mirror routes LONG columns to the streaming encoder before the
generic NULL check. Verified live on 11g through the passthrough: single value,
700-byte multi-chunk, a value over the SDU, LONG-not-last-column, and NULL LONG /
LONG RAW.

## 12. Wire Encoding Primitives

### 12.1 Variable-Length Integer (SB4/SB2)

A compact encoding for 32-bit integers: a length byte followed by that
many big-endian magnitude bytes.

| Value         | Encoding                         |
|---------------|----------------------------------|
| 0             | `0x00`                           |
| 0..255        | `0x01, <byte>`                   |
| 0..65535      | `0x02, <hi>, <lo>`               |
| 0..16777215   | `0x03, <b2>, <b1>, <b0>`        |
| 0..4294967295 | `0x04, <b3>, <b2>, <b1>, <b0>`  |
| Negative      | `(0x80 | len), <len big-endian magnitude bytes>` |

For a negative value the high bit of the length byte is set and the low
7 bits give the magnitude byte count, so the magnitude can span several
bytes — e.g. NUMBER scale `-127` arrives as `0x81 0x7f` and `-256` as
`0x82 0x01 0x00`.

### 12.2 DALC (Data with Attached Length Code)

Variable-length data with a length prefix:

| Length byte    | Encoding                                                 |
|----------------|----------------------------------------------------------|
| `0x00` (empty) | nothing follows                                          |
| `0x01`..`0xFC` | `<length>, <data>` — **252 is the largest real length**   |
| `0xFD` (253)   | **escape / absent value**: the 2-byte placeholder `FD 01`, no data. Not a length. |
| `0xFE` (254)   | chunked: repeated `<chunk_len>, <chunk_data>`, terminated by a zero chunk length. A chunk length is a plain count, a single byte up to 255 before 12.1 and a `ub4` from 12.1 (§6.2); seerdb writes 64-byte chunks |
| `0xFF` (255)   | null marker, no data follows                             |

**The top three bytes are markers, not lengths**, and getting that wrong is not
theoretical. This table used to read `1..253` for the plain form, contradicting
§11's own statement that "the boundary is 252, not 253" — and `decode_dalc` was
written from the table. A NULL `BOOLEAN` bind, whose value slot carries the
`FD 01` placeholder, was therefore read as a length of 253, so the decoder asked
for bytes that had never been sent, the message looked truncated, and the Mirror
blocked waiting for a continuation that could never arrive (#869, and the hang
it caused, #868).

`FD 01` means **the slot carries no value**: a pure-OUT bind, or a NULL of a
type with no inline form. §19.7 documents the same placeholder on the OCI
dialect's bind rows — it is shared, not OCI-specific, which is precisely what
the thin decoder had missed.

### 12.3 Key-Value Pair Encoding

Used in authentication messages:

```
KeyLength(SB4) | KeyLen(UB1) | KeyData | ValueLength(SB4) | ValueLen(UB1) | ValueData | NbPair(SB4)
```

Zero-length keys or values are encoded as a single `0x00` byte.

### 12.4 Byte order of fixed-width integers (pre-10g is server-native-endian)

The variable-length integers of §12.1 are byte-order independent. A handful of
**fixed-width** integer fields in the **pre-10g (8i / 9i-era)** codec are not:
they are written in the **server's native byte order**, not a fixed
little-endian. 10g and later normalise these on the wire, so the question only
arises for the 8i/9i dialects. Known native-endian sites:

- the bind OAC `max_size` (2-byte; §5.3);
- the DCB describe header `rowwidth` / `numcols` (ub4; §6.4);
- the LOB `num_bytes` in an 8i LOB read (ub4; §14);
- the DML row count in the 8i OER status (ub4; §6.7);
- and, latently, the `charset_id` and charset-element count read from the
  TTI_PRO response (ub2; §4.1).

There is **no dedicated endianness byte or capability flag** in the handshake.
The only signal is the **platform banner** in the TTI_PRO response (§4.1), e.g.
`IBMPC/WIN_NT-8.1.0` — `IBMPC` denotes x86, i.e. little-endian. A big-endian
server (8i/9i on SPARC/Solaris, HP-UX/PA-RISC, AIX/POWER, IRIX/MIPS) would carry
a different platform string and send these fields big-endian.

> **Little-endian is assumed, and big-endian is unsupported by design.** Every
> platform that still runs a pre-10g Oracle *and* is big-endian is effectively a
> museum piece: live big-endian Oracle (AIX on POWER) runs 10g+, whose wire is
> normalised, so it never exercises this path. seerdb has no big-endian testbed,
> and the exact big-endian banner strings are unknown without one to capture
> from — so a byte-order-detecting branch cannot even be written and verified.
> seerdb therefore decodes these fields as little-endian and does **not** claim
> big-endian support; a real big-endian pre-10g capture would be needed before
> any such branch is added. (Tracked and closed as a known limitation, #380.)

## 13. Character Set Support

The library supports a wide range of Oracle character sets, identified by Oracle character set IDs:

| Charset          | ID    | Charset          | ID    |
|------------------|-------|------------------|-------|
| US7ASCII         | 1     | AL32UTF8         | 873   |
| WE8ISO8859P1     | 31    | AL16UTF16        | 2000  |
| EE8ISO8859P2     | 32    | JA16EUC          | 830   |
| WE8MSWIN1252     | 178   | JA16SJIS         | 832   |
| CL8MSWIN1251     | 171   | ZHS16GBK         | 852   |
| UTF8             | 871   | ZHT16BIG5        | 865   |

seerdb advertises and decodes **AL32UTF8 (873)** — real UTF-8 — for both the
database and national charset (see §4.1). Note the trap: Oracle's `UTF8` (871)
is **not** the same as AL32UTF8; it is CESU-8, which mis-encodes
supplementary-plane characters. seerdb never advertises 871. National-charset
columns (`NCHAR` / `NVARCHAR2` / `NCLOB`, charset id 2000 / AL16UTF16, CharsetForm
2) are converted by the server to AL32UTF8 on the wire and decode through the
same UTF-8 path.

## 14. LOB Operations (TTI_LOBOPS)

LOB content is transferred via the `TTI_LOBOPS` function call
(`TTI_FUN | TTI_LOBOPS | …`). The same function multiplexes a family
of opcodes — read, write, get length, trim, get chunk size, create
temporary LOB, free temporary LOB, open, close, plus BFILE-specific
operations. The wire layout is the same for all of them; the opcode
field selects behaviour.

### 14.1 Common request layout

```
TTI_FUN | TTI_LOBOPS | SeqNum |
  ub1 source_pointer_flag    # 1 if source locator is sent, else 0
  ub4 source_locator_length  # bytes following at the locator slot
  ub1 dest_pointer_flag      # 0 for plain reads
  ub4 dest_length            # read amount target (bytes/chars)
  ub4 short_source_offset    # 0; long offset goes below
  ub4 short_dest_offset      # 0
  ub1 charset_pointer_flag   # 0 except for CREATE_TEMP
  ub1 short_amount_flag      # 0; long amount goes below
  ub1 null_lob_pointer_flag  # 1 for CREATE_TEMP / IS_OPEN / FILE_*
  ub4 operation              # opcode, see below
  ub1 scn_array_pointer_flag # 0
  ub1 scn_array_length       # 0
  ub8 source_offset          # 1-based offset into the LOB
  ub8 dest_offset            # 0 for plain reads
  ub1 amount_pointer_flag    # 1 if amount is sent at end (READ), 0 for WRITE
  ub16be 0, 0, 0             # three reserved array-LOB slots
  [ locator ]                # see locator framing below
  [ ub8  amount ]            # READ: amount to read (no trailing data)
  [ 0x0E + chunked-bytes ]   # WRITE: marker + payload (see §14.2)
```

**Locator framing (two variants).** A *persistent*-LOB READ sends the locator
raw, with `source_locator_length` = the locator byte count. A *temporary*-LOB
op (CREATE_TEMP / WRITE, and a READ of a temp locator) instead sends the
locator as a `ub2`-length-prefixed field and declares `source_locator_length`
= locator length **+ 2** (counting the prefix) — the form python-oracledb uses.
A temp-LOB READ returns empty content without the prefix; switching persistent
reads to the prefixed form regresses them on 11g + 21c. seerdb keeps the raw
form by default and opts into the prefix per call (`locator_prefixed`).

### 14.2 Opcodes

| Value     | Name              | Description                          |
|-----------|-------------------|--------------------------------------|
| `0x0001`  | GET_LENGTH        | Total length of the LOB              |
| `0x0002`  | READ              | Read content from the LOB            |
| `0x0020`  | TRIM              | Shorten the LOB to `amount`          |
| `0x0040`  | WRITE             | Write at `source_offset`             |
| `0x4000`  | GET_CHUNK_SIZE    | The server's chunk size              |
| `0x8000`  | OPEN              | Open; `amount` carries the MODE      |
| `0x10000` | CLOSE             | Close                                |
| `0x11000` | IS_OPEN           | Is the LOB open? (§14.4c)            |

**CREATE_TEMP body** (no source locator): a field block captured from
python-oracledb (21c, then all three kinds on 23ai, #1066). It is a fixed
16-byte head, then the kind, then 47 zero bytes, then the charset as an `sb4`:

```
01 01 28 00 01 0a 00 00 01 00 01 02 01 10 00 00   # fixed head
<form>                                            # CLOB 01 01, NCLOB 01 02, BLOB 00
01 <type>                                         # 70 CLOB / NCLOB, 71 BLOB
00 x 47
<sb4 charset>                                     # 02 03 69 (873) CLOB and BLOB,
                                                  # 02 07 d0 (2000) NCLOB
```

An NCLOB is a CLOB (type `0x70`) told apart only by the form byte and the
**national** charset: sending the CLOB body for it makes a CLOB. The server
returns the new locator in the response RPA.

**WRITE payload.** After the locator the request appends a `0x0E` marker then a
chunked-bytes field: when the data is `<= 0xFC` bytes, a `ub1` length + the
bytes; otherwise a `0xFE` marker followed by repeated `<sb4 chunk_len><chunk>`
(chunks `<= 0x7FFF` bytes) terminated by a zero-length chunk. CLOB data is
UTF-16BE on the wire; BLOB data is raw. `source_offset` is the 1-based write
position (1 = overwrite from start).
| `0x0020`  | TRIM              | Truncate the LOB                     |
| `0x0040`  | WRITE             | Write content into the LOB           |
| `0x0100`  | FILE_OPEN         | Open a BFILE                         |
| `0x0200`  | FILE_CLOSE        | Close a BFILE                        |
| `0x0400`  | FILE_ISOPEN       | Test whether a BFILE is open         |
| `0x0800`  | FILE_EXISTS       | Test whether a BFILE exists          |
| `0x4000`  | GET_CHUNK_SIZE    | Server-preferred chunk size          |
| `0x0110`  | CREATE_TEMP       | Allocate a temporary LOB             |
| `0x0111`  | FREE_TEMP         | Release a temporary LOB              |
| `0x8000`  | OPEN              | Open the LOB                         |
| `0x10000` | CLOSE             | Close the LOB                        |
| `0x11000` | IS_OPEN           | Test whether the LOB is open         |
| `0x80000` | ARRAY             | Array-style operation                |

**Serving a BFILE (the Mirror, #1102).** Measured against 23ai, a BFILE column
differs from a CLOB / BLOB in three ways, and each one costs a desync:

- **The locator** is `ub2 inner length | 000108080000000100000000000000 | ub1
  dir length | DIRECTORY | 00 | ub1 file length | file`, and carries nothing
  else -- so a server needs no state to answer a FILE_* call, the names come
  back in the locator the client sends. A client's LOBOPS request sends it from
  the fixed block onward, without the leading inner length.
- **The describe** says `data_length` **530**, charset 0, csfrm 0. Zero there is
  the sixth time that trap has bitten (after BOOLEAN, ROWID, VECTOR, JSON and
  REF CURSOR): the client reads no bytes for the column and takes the locator's
  first byte for the next message type.
- **The value** rides in the BARE form, `ub4 length | DALC locator`, NOT the
  size / chunk-size metadata form a CLOB or BLOB carries. Captured: a BFILE is
  `00000007 01 1a | 1a <locator>` where a BLOB has `02 0b b8 | 02 1f 7c`
  between the two.

A BFILE column is also **LOB-class for the deferred-row rule** above: 23ai
answers the execute with a describe and no row, and the client re-executes by
cursor id to collect them.

**BFILE native read (#46).** A BFILE must be opened before it can be read.
python-oracledb's `lob.read()` issues, on 21c: `FILE_ISOPEN` (pre-check, boolean
result) → `FILE_OPEN` → `READ` → `FILE_CLOSE`. seerdb does the minimal
`FILE_OPEN → READ → FILE_CLOSE` (the ISOPEN pre-check is skippable). Details,
reverse-engineered byte-for-byte and verified on 10g / 11g / 21c / 23ai:

- The BFILE locator is the same one a `SELECT BFILENAME` returns; it is sent
  **ub2-length-prefixed** (declared length + 2), like temp LOBs. As fetched
  (`LOB.raw`) it already carries that leading ub2 inner-length, so the driver
  strips it before re-encoding.
- **`FILE_OPEN`** (op `0x0100`) sets the amount pointer and carries the open
  mode as the trailing "amount" `sb4 0x0B` (read-only); source offset 0. Its
  response RPA returns an **updated locator with an "open" flag byte set** —
  `READ` and `FILE_CLOSE` must use *that* locator. A `READ` against the
  original (unopened) locator returns empty bytes — the symptom that long
  blocked native BFILE support. After the locator the reply **echoes the
  mode** as the amount, as a LOB's `OPEN` does (23ai):

  ```
  08 | 00 36 <54-byte locator, open flag set> | 01 0b | 04 ... (OER)
  ```

  A client that sent an amount reads one back, so a reply without it has the
  OER's first byte taken for the amount and desyncs (#1672).
- **`READ`** (op `0x0002`) is the ordinary read with the ub2-prefixed (opened)
  locator; content streams back as the normal `LOB_DATA` chunk (§14.3).
- **`FILE_CLOSE`** (op `0x0200`) sends neither amount nor data.
- **`FILE_EXISTS`** (op `0x0800`, #1109) shares that field block but differs in
  **one byte**: it sets the *null-lob pointer*, because the field it sets is
  where the answer comes back — the server writes "is this LOB null" into it.
  Source offset 0, no amount, no data. Sending the READ shape instead (pointer
  clear, an amount, source offset 1) is answered

  ```
  ORA-03137: malformed TTC packet from client rejected: [kpolob:lobnull 0]
  ```

  which names the field outright. A *directory* that does not exist is not a
  `False`: the server raises `ORA-22285` for it, because "there is no such
  alias" and "the file is missing" are different answers.

- **`FILE_EXISTS`** (op `0x0800`) and **`FILE_ISOPEN`** (`0x0400`) answer with
  the echoed locator **field** and then a ub1 flag. The field is what matters:
  the client reads `len(locator)` raw bytes and only then the flag, and a BFILE
  locator's length *includes its own leading ub2* (§14.4d) — so a reply that
  echoes the body inside the field is two bytes short and the flag is read from
  inside the locator. python-oracledb does not merely get the wrong answer, it
  desyncs: `DPY-5000: unknown protocol message type 1 at position 68` (#1120).

  Note the asymmetry on the server side: a BFILE request's locator arrives with
  that ub2 **stripped** (the op's field is ub2-prefixed, so the parser consumes
  it), and the acknowledging replies re-add it — so whichever encoder builds the
  reply has to know which of the two it has been handed.

**Retargeting a BFILE locator (#1109).** `setfilename` replaces only the two
names; the **16 bytes in front of them are kept verbatim**. That span covers the
locator's own ub2 inner length and the 14 fixed bytes behind it, and it is the
server's — a locator built from scratch is answered `ORA-22285` or `ORA-22275:
invalid LOB locator specified`, because what makes a locator valid is that the
server minted it. Each name rides behind a **ub2** length:

```
00 36 | 00 01 08 08 00 00 00 01 00 00 00 00 00 00 | 00 0d 'PYO_BFILE_DIR' | 00 17 'pyoracle_bfile_test.txt'
^ub2    ^14 fixed bytes -- kept                     ^ub2  dir              ^ub2  file
```

(Read the other way round, a ub2 under 256 is a zero byte then a ub1, which is
how the locator *reader* walks it — the same bytes either way for any name
shorter than 256.) The names start at offset **16** counted from the start of
the locator as fetched.

This replaced an earlier server-side PL/SQL helper
(`DBMS_LOB.FILEOPEN`/`LOADBLOBFROMFILE`), removing its `CREATE PROCEDURE`
privilege requirement and the stored function it left in the user's schema.

### 14.3 Response

The server returns a `TNS_MSG_TYPE_LOB_DATA` (= 14) message carrying
the LOB chunk as length-prefixed bytes:

```
0x0E  msg_type = LOB_DATA
DALC  data            # raw bytes for BLOB/BFILE;
                      # decode as per-LOB charset for CLOB/NCLOB
```

For `GET_LENGTH` / `READ` / similar value-returning opcodes, the
server then emits the standard `TTI_RPA` return-parameters block
followed by the OER status. The `RPA` return block echoes the
updated locator (the server may rewrite internal flags) and, for
operations declared with `send_amount`, an `sb8` carrying the actual
amount read/written. `IS_OPEN`, `FILE_EXISTS`, `FILE_ISOPEN` add a
trailing `ub1` boolean flag.

The `LOB_DATA` content is **always chunked**, whatever its length: a `0xFE`
marker, the chunks, and a zero terminator. Before 12.1 each chunk has a single
length byte (up to 255), from 12.1 a `ub4`. Measured on 11g and 23ai, a 1-byte
BLOB read is `0e fe 01 71 00` (11g) and `0e fe 01 01 71 00` (23ai). A plain
`<len><data>` is not a form the server uses; for 253–255 bytes it cannot work,
since those length bytes are the escape, chunked and NULL markers. The Mirror
once sent short content that way, and a 254-byte read below 12.1 hung the client
(#1970). An empty LOB carries no `TTI_LOB` at all on a real server; the Mirror
sends `0e 00`, which clients read as empty.
`_read_lob_response` walks tokens until the trailing OER; that OER opens
with `04 01 XX` (TTI_OER + `call_status` ub4) and then a per-call
end-to-end seq#. Without the `ub4` chunk-length handling on 12c the
content desyncs and the reader blocks waiting for a packet that never
comes (the LOB fetch hangs).

**The OER `call_status` is not always 1.** It is `1` after a standalone
LOBOPS with autocommit on, `2` while a transaction is open (#712), and `5`
immediately after a PL/SQL execute (the temp-LOB bind path, §14.4). A content-free LOBOPS response (WRITE / temp ops) is therefore decoded
by `decode_lobops_oer`, which skips the RPA's binary locator (it can contain a
stray `0x04`) using the `ub2` length prefix, then matches the OER token + a
valid `ub4` length **regardless of the status value** — a fixed `04 01 01`
scan misses the post-PL/SQL `04 01 05` and hangs.

### 14.4 Implementation status

seerdb implements `TTI_LOBOPS` READ (`encode_dictionary_lobops`
in `seerdb/tns.py`, response handling in
`OracleConnect._read_lob_response`) and uses it transparently from
`LOB.read()` for every non-empty LOB cell. Worth noting:

- **Don't send `amount = 0xFFFFFFFF`.** XE 11g quietly stops
  responding when the request asks for `uint32` max. Use a large but
  finite value instead — seerdb defaults to `0x40000000` (1 GiB),
  comfortably past any realistic LOB while staying inside signed
  int32.
- **Locator bytes go on the wire as-is.** The bytes seerdb extracts
  from the RXD column (after skipping the `ub4 num_bytes` prefix +
  the 1-byte size echo) are exactly what the server expects as the
  source pointer; no DALC wrapping, no length prefix beyond what the
  request body already carries.
- **The response carries `TTI_LOB` (content) + `TTI_RPA`
  (updated locator) + `TTI_OER` (call status)** in a single packet.
  seerdb decodes the LOB chunk(s) and skips past the RPA block by
  scanning forward for the OER `04 01 XX 01` signature — the RPA
  layout is complex enough that we don't try to parse it, and we
  don't need anything out of it.

LOB *column* writes (LOB binds on INSERT / UPDATE) do **not** need a
`TTI_LOBOPS` WRITE round-trip. They go through the regular VARCHAR2 / RAW
bind path: a value larger than 4000 bytes is sent as a streamed LONG
(the OAC max-size is set to the value's length, §5.3), and the server
writes that streamed value straight into the CLOB / BLOB column. Once a
bind exceeds the SDU the request simply fragments across TNS packets
(§1.4, data flags `0x0020` on non-final fragments — the fragmentation fix
in #8). This round-trips CLOB and BLOB binds byte-for-byte at arbitrary
size; the integration suite covers 50 KiB and 500 KiB of both on 11g and
12c+.

**Large LOB into a PL/SQL locator param needs a temp LOB (#91).** The streamed
path above only works for LOB *columns*. Binding a str / bytes value over the
32767-byte PL/SQL VARCHAR2 / RAW limit into a `CLOB` / `BLOB` **parameter** of a
PL/SQL block fails with **ORA-01460** ("unimplemented or unreasonable
conversion"). seerdb handles it the way python-oracledb does, on 12c+:

1. `CREATE_TEMP` (§14.2) allocates a session-duration temp LOB; the locator
   comes back in the response RPA.
2. `WRITE` streams the value into it (chunked-bytes payload, §14.2).
3. The temp locator is bound as a CLOB / BLOB value: the OAC is type `0x70` /
   `0x71` with the LOB cont-flag `0x02000000`, and the bind value is the
   LOB-descriptor `01 28 28` + `ub2` locator length + locator (the same
   descriptor framing the native VECTOR / JSON binds use, §18.1 / §17). The
   OAC's **max-data-length** field is the LOB's fixed buffer-size factor (112
   for both CLOB and BLOB, what python-oracledb sends for *every* temp-LOB bind),
   **not** the value's byte budget: the server reads a length of `0` there as
   "no LOB" and binds NULL, so an **empty** temp LOB announced with length 0 was
   stored NULL — `ORA-01400` on a NOT NULL column (#903). A non-zero value size
   happened to work, which hid it. seerdb now always announces 112.
   An **NCLOB** temp LOB binds with the CLOB OAC and charset form `02` in place
   of `01`; the charset field stays 873, as python-oracledb sends it:
   `70 01 00 00 01 70 00 04 02 00 00 00 00 00 02 03 69 02 00 00`.
4. `execute`. No `FREE_TEMP` — the temp LOB is released at session end.

`Cursor.execute` / `AsyncCursor.execute` do this transparently: a PL/SQL block
(detected by `_is_plsql`) with an over-limit str/bytes bind has that bind
promoted to a `TempLob` marker before encoding. Plain DML keeps the
streamed-LONG path. **11g is excluded** — it rejects this `CREATE_TEMP` outright
(immediate FIN, no error packet), there is no thin reference to crack it
against, and a large PL/SQL LOB bind there keeps its prior ORA-01460 behaviour;
the feature is gated on `field_version >= 12.1`. On 11g the native form serves
temporary LOBs (`oall8=True`, §4.1.4).

Measured on 11g's converted form for #2463, and left there: the fields OCI 11.2's
native `CREATE_TEMP` carries (`_OCI11_LOBOPS_CREATE_TEMP`), written at thin's
widths, **are** answered with a real 38-byte temporary locator. Where the 12c
body above has a 40-byte zero locator space, it has OCI's 86-byte empty locator,
an SCN slot of 0, and the session duration (10) again as a ub8 amount. But the
converted form's `WRITE` into that locator ends the server process with
`ORA-03137 [12333] [120]`, where a `WRITE` into a fetched LOB works. Every guess
past that point costs a server process, so the converted form gets no
temporary LOB below 12.1.

`Connection.createlob(lob_type, data=None)` / `AsyncConnection.createlob`
(#1066) hand this temp LOB to the caller as a `LOB` object for
`DB_TYPE_CLOB` / `DB_TYPE_NCLOB` / `DB_TYPE_BLOB`. The object holds the locator
**with** the `ub2` it came framed in from the CREATE_TEMP reply, which is the
form every later LOBOPS call on it expects (without it the server answers
ORA-22275). Bound as a parameter it becomes the `TempLob` marker above, which
takes the bare locator and writes its own `ub2`. A `LOB` that a query returned
is not rebound this way; its bind has not been measured. Also 12.1+ only.

A bind **declared** a CLOB / BLOB — `cursor.var(DB_TYPE_CLOB)` or
`setinputsizes(DB_TYPE_BLOB)` — promotes the same way, on any statement and any
value size, because a LOB has no inline wire form: its OAC is the fixed LOB bind
OAC (`_encode_lob_bind_oac`, type `0x70` / `0x71`, cont-flag `0x02000000`, the
112-byte fixed buffer factor, **not** a size derived from the Var, which a live
server rejects with ORA-03120), and its value rides as the temp-LOB locator
(`Cursor._promote_lob_var_binds`). A NULL such Var (a pure OUT bind, or a NULL
IN) is not promoted and keeps the OAC with a NULL value. This is what closed the
last of the six declared-type bind encoders (#902); 11g, with no `CREATE_TEMP`,
raises `NotSupportedError` for a declared LOB Var as before.

### 14.5 Temp-LOB WRITE (the Mirror, server side, #412)

The Mirror answers the *server* half of the temp-LOB write flow above, so a
programmatic client (python-oracledb thick, OCI apps, or seerdb's own
`create_temp_lob` / `write_temp_lob` primitives) can write a LOB too large for an
inline bind. It is the inverse of §14.1/§14.2:

1. **`CREATE_TEMP`** (op `0x0110`). Recognised by the client's fixed field block,
   which opens `01 01 28` — unmistakable against the WRITE / READ layout, whose
   second field is a locator length (~40-86 bytes), never `0x01`. CLOB vs BLOB is
   the LOB type byte (`0x70` / `0x71`) in the block. The Mirror mints a unique
   opaque locator (it only has to be stable and distinct — the client keeps it
   opaque and echoes it back) and returns it in a bare `TTI_RPA`: `08`, `ub2`
   length, then the locator bytes. **Distinct means for the life of the session,
   so the number in a locator comes from a counter, never from the count of live
   temp LOBs** (#857): a count reissues an index as soon as anything is freed,
   and the reissued locator collides with one still in use. That is not
   theoretical — it broke the third large-LOB statement of every connection. The
   third `CREATE_TEMP` was handed the locator the second was holding, resetting
   its buffer, and the close-temp-LOBs piggyback (§14.5) riding on the third call
   then freed the locator that same call was about to bind, so the bind resolved
   to nothing and the column was written NULL (`ORA-01400`).
   **Two bytes of the locator are not opaque to the client.** The thin
   reference client picks the encoding of every WRITE to, and READ from, a CLOB
   off two flag bytes: flag byte 3 (offset 6 of the 40 bytes the client holds,
   offset 4 of the 38 the server sends after the `ub2` length) carries the
   **variable-length-charset** bit `0x80`, and flag byte 4 (offset 7 / 5) the
   **little-endian** bit `0x40`. The client writes UTF-16BE when the charset bit
   is set and the little-endian bit clear, UTF-16LE when both are set, and UTF-8
   when the charset bit is clear (an NCLOB is UTF-16BE regardless, by its charset
   form). Captured off a live 23ai (`createlob` of each type, then a WRITE of
   `abc`): the temp **CLOB** locator comes back with flags `82 08 80 03` —
   charset set, little-endian clear — and the client's WRITE payload is `00 61
   00 62 00 63` (UTF-16BE); the temp BLOB's flags are `81 08 00 03` and the
   NCLOB's `84 48 00 03`. So the Mirror mints its temp CLOB locators with the
   charset bit set and the little-endian bit clear (`mint_temp_lob_locator`),
   which is the UTF-16BE it decodes on the bind. Before that the bytes held
   ASCII: the charset bit was clear (client wrote UTF-8) and, once set, byte 4
   still held `'d'` (`0x64`), whose `0x40` made the client write UTF-16LE —
   either way the bind's UTF-16BE decode produced mojibake and the session died
   (#903). seerdb's own client never noticed: it writes UTF-16BE
   unconditionally.
2. **`WRITE`** (op `0x0040`). The Mirror walks the §14.1 field block to the
   operation, then to the `ub2`-length-prefixed locator and the `0x0E` chunked
   payload (`ub1` len ≤ `0xFC`, else `0xFE` + `sb4`-length chunks + a zero
   terminator), and appends the bytes to that locator's buffer. It replies with a
   `TTI_RPA` echoing the (`ub2`-prefixed) locator then a **success OER** — the
   client skips the locator by its length prefix and walks to the OER
   (`decode_lobops_oer`), so no real content is needed.
3. **Bind on execute.** The bound value arrives as OAC type `0x70` / `0x71`
   (cont-flag `0x02000000`) with the RXD value `01 28 28 | ub2 loclen | locator`
   — the LOB descriptor, **not** a plain DALC: the descriptor's leading `0x01`
   would otherwise be mistaken for a DALC length. The Mirror reads it by type,
   resolves the locator to the accumulated bytes (CLOB → UTF-16BE decoded to
   `str`, BLOB → raw), and hands the real value to the backend. The temp-LOB
   OAC also carries a trailing `oaccolid` field the shared OAC decoder stops
   short of, so the server swallows one byte after a CLOB / BLOB bind OAC to keep
   the next descriptor aligned. An **empty** temp LOB is resolved to a typed LOB
   bind rather than a bare `''` / `b''`: a backend that binds the bare value
   stores NULL on an Oracle target (an empty scalar is NULL there), losing the
   empty, non-NULL LOB the client meant (#903). Any other content arrives as a
   `ClobValue` / `BlobValue`: a `str` / `bytes` that still says it was a LOB.
   Bound on to Oracle as a bare `str` it is a VARCHAR2, which refuses anything
   past 32 KB with ORA-01461, so a genuine LOB argument such as `sys.xmltype(:1)`
   failed through the Mirror while working against the server behind it (#1067).
   A backend with no LOB binding needs nothing new, since the value is still a
   string. The Oracle passthrough example binds both kinds back through an
   upstream temp LOB on a 12.1+ upstream, since seerdb has no CLOB / BLOB
   Var-bind of its own.

Verified over the SQLite-backed Mirror driven by the seerdb thin client's temp-LOB
primitives (the auto-promotion is `12.1`+/PL/SQL-gated and the Mirror pins 11g, so
the test calls `create_temp_lob` / `write_temp_lob` directly, as a thick client
would): a multi-chunk CLOB (~72 KB) + BLOB (~77 KB) and a single-chunk CLOB
round-trip byte-for-byte, with a NULL LOB alongside
(`tests/test_sqlite_backend.py`). A `FREE_TEMP` is not required for correctness —
a real client releases the temp LOB at session end and the Mirror's buffers die
with the session — but the Mirror honours it anyway (below).

**The remaining `TTI_LOBOPS` state ops (the Mirror, #417).** A programmatic client
brackets its temp-LOB work with more opcodes than `CREATE_TEMP` / `WRITE` /
`READ`. The Mirror recognises them off the operation field (walking the same
§14.1 block to the `ub2`-prefixed locator) and answers with the content-free
`TTI_RPA` + success OER ack — the same reply `WRITE` uses, which the client reads
via `decode_lobops_oer`. This is what keeps such a client from **desyncing**: an
unrecognised op used to fall through to the READ path and get a LOB-content reply
of the wrong shape.

- **`FREE_TEMP`** (`0x0111`) — the Mirror drops the temp LOB's buffer (freeing it
  early rather than at session end) and acks.
- **Close-temp-LOBs piggyback** (#852) — the *piggyback* form of `FREE_TEMP`.
  A thin client does not send a `FREE_TEMP` call for temp LOBs whose objects
  went out of scope; it collects their locators and rides them in front of its
  next call as message type `0x11`, function `TTI_LOBOPS` (96): the piggyback
  header (`11 60 seq`, plus the `ub8` token at fv24), then a `FREE_TEMP`
  request block with the **`ARRAY` bit** (`0x80000`) on the operation —
  `01` pointer, `ub4` total locator bytes, `00`, `ub4 0`, `ub4 0`, `ub4 0`,
  three pointer bytes, `ub4 0x80111`, `00`, `ub4 0`, `ub8 0`, `ub8 0`, `00`,
  three (pointer byte + `ub4 0`) array slots — and finally the locators
  themselves, each in its `ub2`-length-prefixed 40-byte form, `total` bytes
  with no count (captured off a live 23ai in front of the second large-LOB
  insert of a session, where it rides on the `REEXECUTE` (func 4) of the first
  insert's statement). The Mirror walks it in `_skip_piggybacks`, drops the
  named buffers and serves the call behind it (`parse_free_temp_lobs_piggyback`
  / `encode_free_temp_lobs_piggyback`). Before #852 it was refused as
  `ORA-03115 (piggyback 96)`, so only the *first* temp-LOB write of a session
  ever worked.
- **`OPEN`** (`0x8000`) / **`CLOSE`** (`0x10000`) — acked, and the state is
  **remembered**, because `IS_OPEN` reports it back and because the bracket is
  not idempotent (§14.4c). **`TRIM`** (`0x0020`) / **`GET_CHUNK_SIZE`**
  (`0x4000`) are acked without one; their value-returning forms (a real
  server-preferred chunk size, applying `TRIM`'s new length) stay deferred to
  #421. `READ` (and any unrecognised op) still routes to the #413 read path,
  unchanged.

  Note this bullet used to defer `IS_OPEN` alongside them, on the reasoning that
  "pinning those reply bytes needs a capture from a client that actually sends
  them (the thin client doesn't)". That was **wrong**: python-oracledb thin
  sends `IS_OPEN` on every `lob.isopen()`, and because the op had no case it
  fell through to the read path and the client walked off the end of the reply
  (#903/#887). An op assumed unreachable is worth re-testing before it is
  deferred again.

### 14.4c IS_OPEN, and the open/close bracket (#903/#887)

**`IS_OPEN` (`0x11000`) owes an answer**, unlike `OPEN` / `CLOSE`. The reply is
the acknowledged locator, a **`ub1`** flag (nonzero = open), then the success
OER — and the locator is echoed **RAW**, without the `ub2` length an ordinary
ack carries:

```
08 <locator bytes …> <ub1 flag> <OER>
```

The client reads it as `read_raw_bytes(len(its own locator))` followed by
`read_ub1`, so a length prefix shifts every following byte and it takes two
locator bytes as the flag. A plain ack is not a safe fallback either: the flag
byte is read regardless, so the client would consume whatever follows and then
desync.

Establishing that took **two** sources, because one was not enough. Captured
from 23ai, the two replies — asked once while closed and once while open —
differ in **three of 169 bytes**, so the capture alone does not say which is the
answer. The reference client's decoder settles it: it reads the locator, then a
single `ub1`, and treats `> 0` as open. The other two moving bytes are
server-side state *inside* the locator, which the client copies over its own
but does not consult here.

**The bracket is not idempotent.** A second `OPEN` and a `CLOSE` of something
never opened are errors, and the reply is a **bare OER with no locator echo**:

| condition | code | message (verbatim from 23ai) |
|---|---|---|
| open an already-open LOB | 22293 | `ORA-22293: LOB already opened in the same transaction` |
| close an unopened LOB | 22289 | `ORA-22289: cannot perform  operation on an unopened file or LOB` |

The double space after "perform" in ORA-22289 is the server's own.

### 14.4d The locator field rule (#903/#887)

One rule governs **every** TTI_LOBOPS op, and getting it wrong is what produced
the whole `DPY-5000` / `DPY-5002` family:

1. **Parse by the declared source length.** The request's `source_loc_len`
   spans the locator field whichever form it takes. Do *not* read a `ub2`
   prefix: a **column** LOB sends its locator raw, and its first two bytes are
   locator content, not a length.
2. **Echo the field back VERBATIM.** The client reads it with
   `read_raw_bytes(len(its own locator))` and consumes no length prefix, so
   adding one shifts every following byte. It then **adopts** the echoed bytes
   as its locator, so a mis-echoed locator corrupts every later call on that
   LOB — which is how a bad `WRITE` reply made the next `size()` return 0.
3. **Resolve the key by recognition, never by inspecting bytes.** A **temp**
   locator is what the Mirror handed back, so the client holds it *including*
   the `ub2` the reply carried (declaring `len + 2`); a **column** locator
   arrives raw in row data (declaring `len`). Try the field, then the field
   without its first two bytes, against what the session actually minted or
   emitted.

Why this hid for so long: **a real Oracle locator begins with its own 2-byte
length** — `00 70` for a 114-byte one. That reads exactly like a framing prefix.
Stripping it and re-adding `ub2(112)` reproduces the identical bytes, so the
wrong model round-trips perfectly against a real server and corrupts only
locators whose first two bytes are something else, such as the Mirror's own
`00 73`. #826 recorded the mistaken reading as fact ("GET_LENGTH carries the
locator ub2-prefixed where READ sends it bare"), and the hand-built fixture
written to match could never falsify it.

**`WRITE` is the one exception to (1) in spirit**: both readings advance to the
same place, because its payload follows the locator immediately, so its extent
must be exact. It still takes the declared length — but its reply must echo
verbatim, and passing the field to the ordinary ack (which prepends a length)
desynced 44 tests.

**A write or trim of a COLUMN LOB updates what the Mirror served**, not the
temp-LOB store: the emit log is what answers a later `size()` or `read()`.
`WRITE` splices at its 1-based offset — `lob.write(v, 1)` overwrites from the
start rather than appending — in the LOB's own units, characters for a CLOB.

**`OPEN`, `CLOSE` and `IS_OPEN` must extract the locator the same way**, since
one records a state the next reads back. `isopen()` denied an open it had just
accepted when they disagreed.

### 14.4b Operations on a temp LOB the CLIENT created (#826)

`connection.createlob()` mints a temp LOB on the server and then drives it over
TTI_LOBOPS like any other. Three of those ops owe a real answer, and none of them
is the column-read path:

**GET_LENGTH (`0x0001`)** — the acknowledged locator, the current length, a
status. Captured from a live 23ai for a 260-byte BLOB:

```
08 | 00 26 <38 locator bytes> | 02 01 04 | 04 ... (OER)
     ub2 len + locator          ub4 260
```

An empty LOB sends a ub4 zero (a bare `00`), not an absent field. The length is
in the LOB's own units — characters for a CLOB, bytes for a BLOB.

**TRIM (`0x0020`)** — carries its new length as a **trailing ub4** after the
locator, and is answered with exactly the GET_LENGTH reply above carrying that
new length. It is *not* a content-free acknowledgement.

**READ** — the ordinary read reply, but it must echo **the client's own
locator**, not a placeholder:

```
0e fe 01 05 | 41 42 43 44 45 | 00 | 08 00 26 <38 locator> | 01 05 | 04 ... (OER)
  LOB_DATA    "ABCDE"          end   the locator back       ub4 5
```

A column LOB can get away with a placeholder there because the client ignores
what comes back; a temp LOB cannot, because the client reads back exactly as many
bytes as the locator it sent.

**The failure mode is identical for all three and misleading.** Anything that
falls through to the column-read path is answered with a read reply (token
`0x0e`) echoing the column placeholder — the wrong token *and* the wrong locator
— so the client desyncs on the very first `lob.size()` of something it created
itself, long before any of its content is in question.

### 14.4c The operations a LOB object needs (#964)

Captured from a live 23ai against a **persistent column** locator, which is a
different animal from the temp locator §14.5 covers.

**A value-returning reply.** GET_LENGTH, GET_CHUNK_SIZE, TRIM, OPEN and CLOSE
all answer in one shape — the updated locator, then a `ub4`, then the OER:

```
08 | 00 70 | <112-byte updated locator> | 01 0b | 04 <OER>
     ub2 112                              ub4 = 11
```

GET_LENGTH's `ub4` is the length (characters for a CLOB, bytes for a BLOB),
GET_CHUNK_SIZE's is the chunk size (**8060** on 23ai), and TRIM's is the **new**
length. OPEN / CLOSE carry the field without a meaningful value.

**The reply's locator is not the one you sent, and that matters.** Every call
answers with the locator as the server now sees it, and a mutating one really
does change it. Reusing the original meant the next read was served the
*pre-write* value, so a write looked like it had silently done nothing. The two
forms also differ by a header: a locator taken from a ROW carries a 2-byte
length prefix that the reply's does not (measured: `reply == row[2:]`), so the
prefix has to be put back before the next call or it is refused with ORA-22275.

**OPEN takes a mode in the amount field.** `1` (read-only) and `2` (read-write)
are accepted; `0` and `11` are refused with `ORA-64219: invalid LOB locator
encountered`, which names the locator rather than the mode and is therefore
thoroughly misleading. A second OPEN answers `ORA-22293`, and a CLOSE of an
unopened LOB `ORA-22289` — the codes a client surfaces directly.

**Mutation needs the ROW locked.** TRIM and WRITE against a committed row answer
`ORA-22920: row containing the LOB value is not locked prior to update`. The
lock comes from an open transaction over that row — `SELECT ... FOR UPDATE`, or
simply an uncommitted INSERT in the same transaction.

**WRITE frames its locator differently per kind.** A TEMP locator rides
ub2-length-prefixed with the declared length counting the prefix (`len + 2`); a
PERSISTENT one rides bare with its own length, the same split READ already
makes. Sending a column locator in the temp form is answered ORA-22275 on
**every** tier (10g / 11g / 21c / 23ai, measured). (READ wants the bare form and
GET_LENGTH the prefixed one, so the two are not simply "temp vs persistent" — it
is per operation.)

**Writing a persistent LOB is 11g and up.** The bare form 11g, 21c and 23ai all
accept makes **10g drop the connection outright** — no error, no reply, the
socket closes. That is worse than a refusal in a specific way: the session dies
holding the row's lock, so the *next* statement fails `ORA-00054: resource busy`
and the cause looks like a locking problem several steps removed from the write.
What 10g does want is not known; seerdb refuses `LOB.write()` / `LOB.trim()`
below 11g with `NotSupportedError` rather than take a session down looking for
it. Reads, `size()` and `getchunksize()` are unaffected and work on 10g.

### 14.5b LOB **column** value framing, and its two forms (#853)

A CLOB / BLOB column value in an RXD row is

```
ub4 locator length | ub8 size | ub4 chunk size | <ub1 len> locator
```

captured from a live 23ai for a 3000-byte BLOB as
`01 72 | 02 0b b8 | 02 1f 7c | 72 <114 locator bytes>` — length 114, size 3000,
chunk size 8060. The reference thin client reads exactly this, and reads the two
middle fields **unconditionally** for every CLOB / BLOB / BFILE column
(`read_lob_with_length`); given only `ub4 length | locator` it takes the
locator's own length prefix for the `ub8` size and fails with `DPY-5002`. JSON
and VECTOR columns are *not* read by that path (`read_oson` / `read_vector`) —
they carry the same three metadata fields but then the **value itself**, ahead of
the locator; see §14.5e.

**A real server sends two different forms, and the switch is not known.** A live
23ai sends the framing above to the reference client and the bare
`ub4 length | locator` to seerdb — same row, same connection settings, both
reproducible back to back. Everything the two clients declare was compared and
is identical: the 53-byte compile capability array (`CCAP_LOB = 0xcf`,
`CCAP_LOB2 = 0x05`), the 11-byte runtime capabilities, the DTY type table (321
entries, including CLOB/BLOB/BFILE), and the executes themselves (same options
`0x8061`, no defines); prefetch size was tested and makes no difference. The
handshakes differ only in `AUTH_PROGRAM_NM` / `AUTH_PID` / `AUTH_SID`. Whatever
selects the form has not been found, and it is recorded here rather than
guessed at.

Consequences for seerdb:

- **The Mirror always sends the metadata form** for CLOB / BLOB — the stricter
  reader requires it, and the more tolerant one is ours to fix.
- **`_read_lob_column` accepts either form**, so seerdb's client reads the Mirror
  and a real server alike. The forms are told apart by the byte after the
  length: in the bare form it is the locator's own length prefix and equals that
  length (or `0xFE` for a chunked block); in the metadata form it is the size's
  length marker, at most 4. They cannot collide for a real locator, which is 38
  bytes at the smallest, so the test is only applied above a length of 8. This
  is a heuristic and is written down as one; it becomes unnecessary the day the
  switch above is identified.

### 14.5c A type change to CLOB / BLOB under a cached cursor stays **inline** (#826)

A client caches a statement against the cursor id the server reported and
re-executes it by that id (§19.x, func 78 / a bare OALL8). If the statement's
shape changed underneath — the classic case is a view redefined between the two
executes — the server answers the re-execute with a **fresh TTI_DCB** instead of
a bare row batch. That much is the ordinary re-describe.

What is not obvious is how the value is then framed. When the column's new type
is **CLOB or BLOB** and the describe being replaced said **CHAR / VARCHAR2 /
LONG** (respectively **RAW / LONG RAW**), the server reports the new LOB type in
the describe but **sends the value inline, as LONG (RAW), in the row itself** —
no locator, no follow-up TTI_LOBOPS. It is the same framing a define of a LOB as
string / bytes produces. The reference client depends on it: on reading such a
describe it rewrites the column's fetch type to LONG (RAW) itself
(`_adjust_metadata`) and therefore neither sets "requires define" nor issues a
LOB read. A locator in that row is read as a LONG length and desyncs the stream
— `DPY-5000: unknown protocol message type 38`.

Two details captured from a live 23ai (`create or replace view` swapping the
column type, `select * from` it twice on one cursor):

- **The describe still names the LOB type.** The re-describe carries
  `data_type = 112` (CLOB), `data_length = 4000`, `max_size = 0`. The LONG is
  the client's own reinterpretation, never something the wire says.
- **The charset form is the OLD one.** A column that was `NVARCHAR2` and became
  a `CLOB` arrives as **UTF-16BE**, although the new describe reports
  `csfrm = 1`; the client took csfrm from the variable it already held. Captured
  as `07 12 | 00 63 00 6c 00 6f 00 62 00 5f 00 34 00 36 00 30 00 33 00 00` for
  `'clob_4603'`, against `07 09 | 63 6c 6f 62 5f 34 36 30 30` for the plain
  VARCHAR2 → CLOB case.

Once a column is being served this way it stays that way: the client's variable
is LONG from then on, so every later re-execute of that cursor pairs LONG with
CLOB and inlines again. The reverse pairing (a CLOB replaced by a VARCHAR2) is
an ordinary re-describe and uses the new type's own framing.

In seerdb this is `inline_long_after_type_change()`, whose mark on a column
routes it past the locator branch in `_thin_column_value` and out of the
`oci_lob_contents` queue.

### 14.5d The define round-trip, and what the client actually asks for (#826)

§14.5c's "inline as LONG" framing has a second, more common trigger: the client
simply **asks** for it. A client fetching a LOB as string / bytes — an
`outputtypehandler` returning a `DB_TYPE_VARCHAR` / `DB_TYPE_RAW` variable for a
CLOB / BLOB column — reads the describe, sets "requires define", and re-executes
the cursor with the **DEFINE** execute option (`0x10`) and one OAC per column.

That define execute is the one place a client tells the server what it wants each
column *as*:

```
options   0x8010        NOT_PLSQL | DEFINE       (no EXECUTE, no FETCH, no PARSE)
cursor    <id>          the cursor the describe reported
sql       absent
binds     0             a define execute never carries binds
defines   <n>           one per column, where the bind count would be
```

and after the `al8i4` array, one OAC per column in the **same layout a bind OAC
uses** — so the same decoder reads them. Captured from a live 23ai for a CLOB
column an `outputtypehandler` fetched as a string:

```
08 01 00 00 | 04 7f ff ff ff | 00 | 00 00 00 00 | 00 | 02 03 69 | 01 | 00 | 00
^^ LONG       ^^ buffer size                            ^^ 873     ^^ csfrm
```

and for a BLOB fetched as bytes, `18 ...` — LONG RAW, with `csfrm 0` and so no
charset field. Note the client has already converted its `VARCHAR` / `RAW`
variable into a **LONG (RAW)** define; the wire never carries the user's type.

**A VECTOR column defined this way gets its TEXT form** inline, not the binary
image (#1107). Measured on 23ai, reading each back through a LONG define:

| vector | text |
|---|---|
| sparse float32 `[1, 0, 5]` | `[16,[1,3,5],[1.0E+000,0,5.0E+000]]` |
| sparse float64 `[1.5, 0.25, 0.5]` | `[16,[1,3,5],[1.5E+000,2.5E-001,5.0E-001]]` |
| dense float64 | `[1.5E+000,-2.0E+000,3.25E+000]` |
| dense int8 | `[1,2,3]` |

A float element prints in scientific form with a three-digit exponent and at
least one decimal; an exact zero prints bare; an INT8 element prints as an
integer; sparse is `[dims, [indices], [values]]`. Serving the image instead left
the client reading it under a character variable (`DPY-5000`).

**A native JSON column defined this way** gets the document as **compact JSON
text** — no space after `:` or `,` — in place of the OSON image (#1106).
Captured from 23ai: `{"name":"John","city":"Delhi"}`. Same failure mode when the
image goes out instead.

The reply is rows alone (`TTI_RXH` + `TTI_RXD`, no describe — the client has it),
with the value framed inline exactly as §14.5c describes:

```
06 22 01 01 00 01 02 00 00 00 | 07 09 62 6c 6f 62 5f 34 36 32 30 | 00 00
                                ^^ RXD, 9 bytes, "blob_4620"       ^^ LONG trailer
```

**No TTI_LOBOPS follows.** The client asked for the bytes and got them, so it
never issues a read — which is why a Mirror that answers this with a locator both
desyncs the row and leaves an orphan in its LOB queue, shifting every later LOB's
position.

In seerdb the define OACs are `ExecRequest.define_types`, and
`inline_long_for_defines()` applies them to the parked columns before the reply
is built.

### 14.5d-bis A define **stands for the life of the cursor** (#826)

§14.5d covers the round-trip that *carries* a define. What it does not say is how
long one lasts: a client sends a define **once**, on the round-trip after the
first describe, and every later execute of that cursor carries none at all.

So a server has to remember it. Forgetting reverts the column to LOB-class
handling on the re-execute — another describe the client is not expecting, then a
locator for a column it is still reading as a string or bytes — and the row
stream desyncs (`DPY-5000 ... unknown protocol message type`). Measured against a
live 23ai: the re-execute reply is rows alone, no describe, value inline, exactly
as the define asked.

There is a second half to this, and it is easy to miss. A re-run of a cached
query **mints a fresh cursor id** and reports that one, so the defines standing
on the id the client re-executed have to travel to it. Without that the failure
appears on the *third* execute of a statement rather than the second, which makes
it look like whatever else changed on that call — in oracledb's own suite, a bind
whose type went from `str` to `int`, so the test is named "changing bind type
with define needed" and the bind type has nothing to do with it.

The **bind format** a cursor records has the same shape of problem, and it bites
in the other direction (#999). An OAC-less re-execute decodes its rows with the
format recorded against the cursor, which is written once, at open. A client
re-describes its binds mid-stream whenever their types change — and a column
that is all-NULL in the first `executemany` batch and carries numbers in a later
one does exactly that. The batch carrying the re-describe decodes fine, because
it brought its own OACs; the batch **after** it does not, and the numbers arrive
as their raw NUMBER bytes read as text (`ORA-01722 ... UNISTR('\FFFD')`). So the
record has to be refreshed whenever an execute carries OACs, and left alone when
it does not — an execute with none is asking to reuse the format, not to clear
it.

**And a third half, on the fetch side (#982).** "For the life of the cursor"
includes every *batch* of one result set, not just every execute of it. The rows
of a LOB-class result are parked by the execute, **before** the define exists —
such a result defers its rows (§11.9), so the client gets a describe-only reply
and sends its define on the round-trip after it. That define round-trip serves
the first batch inline and leaves the rest parked, so a plain `TTI_FETCH` for the
remainder has to apply the define too.

A server that applies it only where it arrives sends **two framings for the same
column in one result set** — the first rows inline, every later row a locator.
The client reports it as `DPY-5000 ... unknown protocol message type 38`, and the
38 is nothing but `0x26`, the length byte of the locator it was not expecting; the
number moves with the locator, which is what makes this read like a decoder gap
rather than a lost define. It needs a result larger than one prefetch batch to
show up at all, so a one-row test passes.

### 14.5e JSON and VECTOR are **prefetched into the row** (#887, #826)

A native JSON or VECTOR column is LOB-class in the describe but is never fetched
over TTI_LOBOPS. The server sends the whole value in the row, in the LOB metadata
framing of §14.5b with the image spliced in before the locator:

```
ub4 locator length | ub8 image size | ub4 chunk size | DALC image | DALC locator
```

Captured from a live 23ai for `select JsonCol from TestJson` holding
`{'a': 1, 'b': 'x'}`:

```
01 28 | 01 2a | 02 7f 58 | 2a <42-byte OSON image> | 28 <40-byte locator>
  40     42      32600
```

Note the first field is the **locator's** length, not the image's — it is the
same `ub4` a plain LOB column puts there, and the client uses it only as a
non-zero "present" marker. The locator is read and **discarded**
(`read_oson` / `read_vector` both end with a throwaway `read_bytes()`), so a
reply that stops after the image leaves the client consuming the next token as
locator bytes.

**A live server chooses per client which form to send; the Mirror cannot.** For
the same row a 23ai sends this prefetched form to the reference thin client and
the **bare locator** to seerdb, which then reads the content over TTI_LOBOPS like
any other LOB. The Mirror has one reply for everybody and must send the
prefetched form, because that is the one the reference client can read at all
(§14.5b's bare form kills it, #887). So a client has to handle **both**, and the
rule is: *if the image is there, it is the value* — the locator behind it is a
placeholder that resolves to nothing, and a fetch for it comes back empty. seerdb
keeps that image on the LOB and answers `read()` from it, rather than issuing a
TTI_LOBOPS call whose reply is an empty image the decoder then rejects
(seerdb#959).

The chunk size is **32600** (`02 7f 58`), measured identical for VECTOR columns
of 3, 5 and 16 float32 elements and for a JSON column — it is not derived from
the value.

**The describe must report length 8200 for both.** Measured on 23ai as
`02 20 08`, whatever the document or the vector's dimension and element format. A
zero there is not a harmless "unknown": the reference client builds a fetch
variable that reads no bytes, consumes nothing from the row, and takes the
image's first byte for a message type — `DPY-5000 ... unknown protocol message
type`. This is the same trap §6.4's length table exists for, and JSON was the
fourth column type to fall into it after BOOLEAN, ROWID/UROWID/ADT and VECTOR.

Consequence for a server: such a column belongs in the row encoder and **not** in
the TTI_LOBOPS content queue. An entry there is never drained, and it shifts the
position of every later CLOB / BLOB in the same result.

### 14.6 Persistent-LOB locator field map (Mirror, deadbeef dialect)

The Mirror hands sqlplus a **persistent-LOB locator** in the row value
(`encode_lob_locator_oci`) and echoes it in the READ reply. It is a 105-byte
structure; both the row value and the read-tail embed the *same* locator, so
`_oci_lob_locator(is_clob)` builds it once. Offsets are within the locator:

| off | field | CLOB / BLOB | kind |
|---|---|---|---|
| `0..2` | length `0x68 0x00` + version `0x01` | same | structural |
| `3` | **LOB kind** | `02` (CLOB) / `01` (BLOB); `04` (NCLOB) | generated |
| `4..5` | **flags** — `[4]` bit `0x40` = national form, `[5]` bit `0x80` = variable-width charset | `0c 88` / `0c 08`; NCLOB `4c 08` | generated |
| `8` | **LOB type** | `02` / `01` | generated |
| `16` | LID marker `0x56` | same | structural |
| `17..26`, `36..38`, `52..54`, `80..82`, `102..104` | **physical LID** — object id + three segment DBAs + SCN | **synthetic (zeros)** | generated |
| `31..32` | **charset id** (ub2 BE) | `0369` (873 = AL32UTF8) / `0000`; NCLOB `07d0` (2000 = AL16UTF16) | generated |
| `40..43` | **slot** (ub4 BE): the LOB's column index + 1, so a read names which of its row's LOBs it wants; `0` = none (#1430) | per LOB | generated |
| `91..94` | content byte size (ub4 BE) | patched per value | runtime |

The whole locator is generated field by field. The 9-byte header (`0..8`) carries
the LOB kind; the body is one shared structural template with the charset id set
for a CLOB. The read-tail is `08 00` + this locator + the ub4-LE amount read
(2000 chars for a CLOB, 4000 bytes for a BLOB) + the LOB-row OER, generated by
`encode_oci_oer(SUCCESS, sequence=17, row_kind=LOB, command_type=0)` (offset 18
zeroed).

**The physical LID is opaque to the client** — go-ora and other drivers echo the
locator without interpreting it (only reading flag bits `[6]&0x80` / `[7]&0x40`).
So the Mirror, which has no real LOB segment, emits a **synthetic LID of zeros**.
**Verified live** against sqlplus 11.2 over the Mirror: it reads both CLOB and
BLOB content back correctly with the object id / DBAs / SCN zeroed. With the
physical LID gone the CLOB and BLOB bodies are identical bar the charset id, so
one template serves both.

**Interleaved reads** (#1430). sqlplus reads the LOBs of a row interleaved: with
two LOB columns and `SET LONGCHUNKSIZE 7` it asks for `a@1, b@1, a@8, b@8, …`
(measured, sqlplus 23.26). The only thing that tells `a`'s reads from `b`'s is the
locator each READ echoes. With one shared locator, a server that serves "the LOB
read last" hands `a`'s second chunk from `b`: the wrong content and no error.
11g's locators are each a real LOB's. The Mirror's carry the LOB's column index
in four of the template's zero bytes (offsets `40..43`, inside the synthetic LID),
in the row value and in every READ reply's echo. A narrow-form request
(`_OCI_LOBOPS_NARROW_*`) carries the locator at offset 135, and the slot is read
back from there. A read at offset 1 takes that column's next LOB (row order), and
a later offset continues it. A request with no slot, the wide form of an older
sqlplus, keeps the old "next LOB" order.

**NCLOB** (#1369). An NCLOB is a CLOB in the national character-set form, and its
locator says so in three places. Measured against a live 11g, sqlplus 23.26
selecting an NCLOB and then a CLOB column of the same table: the locators differ
only in the header's LOB kind (`04` vs `02`), its flags (`4c 08` vs `0c 88`: the
national bit set, and the variable-width bit clear because AL16UTF16 is fixed
width), and the charset id (`07d0` vs `0369`). The two ub2 fields just before the
charset id read `0002 0002` for the NCLOB and `0003 0003` for the CLOB on 11g. The
Mirror's template carries `0002 0002` for both, and sqlplus accepts it for both.
The content is UTF-16 for both. The describe carries the column's form too
(charset 2000, form 2, vs 873, form 1). A CLOB-form locator under an NCLOB describe
makes sqlplus refuse the value with **ORA-24806** ("character set form of buffer
and LOB do not match"), and so does a READ reply echoing one: sqlplus sends the
echoed locator on its next read, so the row value and every read reply must carry
the same form.

## 15. TNS Marker Protocol

TNS_MARKER packets serve as break/attention signals. The marker body is 3 bytes:

- `0x01, 0x00, 0x01`: **break** — the server is cancelling the in-flight call.
- `0x01, 0x00, 0x02`: **reset** — line-clear acknowledgement.

The server cancels an errored/interrupted call by sending `break` then `reset`
followed by the inline error/result. The client answers with **exactly one**
reset and drains the rest silently (2 server markers : 1 client reset). See
§1.4 for the full handshake and the #45 desync it fixes.

## 16. Sequence Numbers

Each TTC function call includes an incrementing sequence number (1 byte, wrapping from 127 back to 1). The sequence number is managed per-connection and ensures ordered request processing.

## 17. Native JSON (OSON)

Oracle 21c+ stores a native `JSON` column as a BLOB-backed **OSON** image (a
compact binary JSON). The column's TNS data type is **119** (`TNS_TYPE_JSON`).
On the wire it behaves exactly like a BLOB: the RXD row carries a LOB *locator*,
and the OSON image is fetched over `TTI_LOBOPS` (§14). seerdb reads it through
the normal LOB locator path and then decodes the OSON in `seerdb/oson.py`.

The format below was reverse-engineered from images captured off a live 21c
server, each with known content. An OSON image is:

```
magic "FF 4A 5A" | version (1) | flags (ub2) | body
```

`flags & 0x2000` marks a **tree** image (object/array). Otherwise the body is a
single **bare scalar**: `reserved(ub1) | value_size(ub1) | <scalar node>`.

A tree body is:

```
num_fnames (ub1) | fnames_seg_size (ub2) | tree_seg_size (ub2|ub4) | reserved (ub2)
hash_array     (num_fnames × ub1)   one hash byte per field name (unused on read)
offset_array   (num_fnames × ub2)   field-id → offset into fnames_seg
fnames_seg                          field names, each <len(ub1)><utf8 bytes>
tree_seg                            the node tree, root node at offset 0
```

`tree_seg_size` is **`ub4`** (not `ub2`) when the header flag `0x1000` is set —
i.e. the tree segment exceeds 64 KiB (#88). `fnames_seg_size` stays `ub2`.

A field id is 1-based: `offset_array[id - 1]` locates the field's name in
`fnames_seg`.

### 17.0b Image version 3 — field names over 255 bytes (#826)

The byte after the magic is a **version**, and it is load-bearing. Two values
occur: **1**, the layout above, whose field-name length prefix is a `ub1` and so
caps a name at 255 bytes; and **3**, which adds a *second* field-name segment for
the names that do not fit.

Version 3's three extra sizing fields sit between `fnames_seg_size` and
`tree_seg_size`:

```
secondary_flags (ub2) | num_long_fnames (ub4) | long_fnames_seg_size (ub4)
```

and its segment follows the short one, before `tree_seg`:

```
long_hash_array   (num_long × ub2)   TWO bytes per name here, not one
long_offset_array (num_long × ub2|ub4)   ub2 when secondary_flags & 0x0100
long_fnames_seg                      the names, each <len(ub2)><utf8 bytes>
```

The two segments **share one field-id space**: ids `1..num_fnames` index the
short segment, ids above it index the long one (offset by `num_fnames`).

Captured from a live 23ai for `{"A"×256: 6700}` — `num_fnames` 0, so the whole
document lives in the long segment:

```
ff 4a 5a | 03 | 20 06 | 00 | 00 00 | 01 00 | 00 00 00 01 | 00 00 01 02 | 00 08 | 00 00
           ^ver  ^flags  ^0 short   ^0 size ^sec=0x0100   ^1 long name  ^258    ^tree 8
c5 62 | 00 00 | 01 00 <256 × 'A'> | <8-byte tree>
^hash   ^offset ^ub2 len 256
```

**When it appears:** only for an image the **server** encoded — a JSON-text
insert, `JSON_OBJECT`, and so on — and only when a long name is actually present.
A document the client encoded stays version 1, and a server image whose names are
all short does too. That is why this went unnoticed for so long: every JSON test
that binds a native value round-trips version 1.

**Reading the version as part of the flags is silent corruption**, not an error:
a version-3 image parsed as version 1 is 8 bytes out by the time it reaches the
tree and reports a nonsense node tag (`unsupported OSON node tag 0x73 at offset
0`), which looks like an unimplemented node type rather than a header fault.
seerdb therefore refuses an unknown version outright.

**Writing one has a trap of its own.** The header's field-name count is the
**short** names' count, but the flag that sizes it (`0x0400`) also sizes *every
field id in the tree*. A document of 676 long names and no short ones therefore
still needs that flag set, even though the count it sizes is zero — drive it off
the **total**. Reading the ids one byte wide instead produces
`DPY-5006: unexpected end of data: want 1 bytes but only -16771386 bytes are
available`, a negative figure that gives the real cause away.

### 17.0c Compressed columns: relative offsets and shared field ids (#826)

A JSON column declared `store as (compress high)` writes two things an ordinary
column does not. Both show up in every image from such a column — header flags
`0x2107`, the `0x01` being the new one.

**Relative offsets** (image flag `0x01`). A container's child value-offsets count
from **that container's own offset** within the tree segment, not from the start
of it. An image whose only container is the root decodes identically either way,
which is why a one-object document hides the difference.

**Shared field ids** (container tag count-bits `0x18`). The two bits that
normally select the count width — `00` ub1, `01` ub2, `10` ub4 — mean something
else entirely when both are set: *this object stores no field-id array; its keys
come from another object, whose offset follows in their place.* Read the donor's
tag byte and count to recover both the entry count and where its field ids live,
then read this node's own value offsets from straight after the donor pointer.

**The donor pointer is absolute even in relative mode.** Only the value offsets
are rebased. Rebasing the donor too lands mid-value and reports a nonsense count.

Captured from a live 23ai for `[{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]` in a
compressed column — the tree segment, with absolute offsets in the margin:

```
 0  c0 02 00 06 00 13     array, 2 children at 6 and 19 (root: relative == absolute)
 6  86 02 01 02 00 08 00 0b   object, ids a,b; children at +8, +11 → 14, 17
14  21 c1 02              the number 1
17  01 78                 the string "x"
19  9c 00 06 00 07 00 0a  object, SHARES the ids at 6; children at +7, +10 → 26, 29
26  21 c1 03              the number 2
29  01 79                 the string "y"
```

**A decoder trap.** The `0x18` test must be applied to **container tags only**.
DATE (`0x3C`), TIMESTAMP (`0x39`), TIMESTAMP WITH TZ (`0x7C`) and both intervals
all happen to carry both bits, so an unguarded test turns every bare-scalar
temporal image into a malformed object.

### 17.0d The field-name hash array is **load-bearing** (#826)

The `hash_array` in a tree image is not decoration, and it is not optional. The
server indexes a document's field names through it, so an image whose hashes are
wrong **stores, fetches and `json_serialize`s perfectly and matches no JSON path
at all**: `json_exists` returns false, `json_query` and `json_value` return NULL,
and a `where json_...` predicate finds no rows. Nothing errors. This is the
quietest failure in the whole format.

Two rules, and both are needed:

**The hash is FNV-1a, 32-bit**, over the name's UTF-8 bytes:

```
h = 0x811C9DC5
for byte in name:  h = ((h ^ byte) * 16777619) & 0xFFFFFFFF
```

A short name stores `h & 0xff` (one byte). A **long** name (version 3's segment)
stores `h & 0xffff` **little-endian** — so its first byte is the short form's
byte and the second extends it. Measured on 23ai: `a` → `2c`, `b` → `e5`,
`short_name` → `9d`, `arr` → `18`, `outer` → `74`; `"A"×256` → `c5 62` and
`"B"×256` → `c5 dd`.

**The names are stored in hash order**, sorted by

```
(h & 0xff, len(name_bytes), name_bytes)
```

— the length and the bytes only breaking a tie in the low byte, which for a
document of any width is common. Captured for
`{"outer": {"inner": {"deep": "v"}}, "arr": [{"k": 1}]}`, 23ai stores the names
as `arr, inner, deep, outer, k` — hashes `18 27 6f 74 ea`, ascending — not in the
order they appear in the document.

A decoder does not care about either: it resolves a field id through the offset
array. That is exactly why this can be wrong for a long time without anything
looking broken.

### 17.1 Node encoding

| Tag byte            | Node                                                        |
|---------------------|-------------------------------------------------------------|
| `0x00`–`0x1F`       | short string, length = tag, then that many UTF-8 bytes      |
| `0x20`–`0x2F`       | number, Oracle NUMBER of `(tag − 0x1F)` bytes               |
| `0x30` / `0x31` / `0x32` | `null` / `true` / `false`                              |
| `0x33`              | string, `ub1` length prefix, then UTF-8 bytes               |
| `0x34`              | number, `ub1` length prefix, then Oracle NUMBER bytes       |
| `0x37`              | string, `ub2` length prefix (value > 255 bytes, #88)        |
| `0x38`              | string, `ub4` length prefix (value > 64 KiB, #88)           |
| `(tag & 0xC0) == 0x80` | object: `count`, `field_id × count`, `value_offset × count` |
| `(tag & 0xC0) == 0xC0` | array: `count`, `value_offset × count`                   |

Container value-offsets are relative to the tree segment start. Objects list
their `(field_id, value_offset)` pairs in document order.

**Extended scalar nodes (#69).** JSON can carry Oracle-native scalars (e.g. via
`JSON_SCALAR(<native>)`). Each is a tag byte followed by a fixed-width Oracle
binary value (no length prefix — the width is intrinsic), decoded by the same
routines as the column wire forms; binary float/double are in the
order-preserving ("sortable") form:

| Tag    | Type                    | Width |
|--------|-------------------------|-------|
| `0x36` | BINARY_DOUBLE           | 8     |
| `0x7F` | BINARY_FLOAT            | 4     |
| `0x3C` | DATE                    | 7     |
| `0x39` | TIMESTAMP               | 11    |
| `0x7C` | TIMESTAMP WITH TIME ZONE| 13    |
| `0x3D` | INTERVAL YEAR TO MONTH  | 5     |
| `0x3E` | INTERVAL DAY TO SECOND  | 11    |
| `0x7D` | DATE (ub4-offset images)| 7     |

**The extended wrapper `0x7B` (#1114).** One extended node is not fixed-width:
tag `0x7B`, a sub-tag byte, a `ub4` length, then that many bytes. Sub-tag `0x01`
is a **VECTOR**, and the payload is the bare vector image of §18 — magic, flags,
element format, dimension count, the 8-byte norm, then the body:

```
7b 01 | 00 00 00 1d | db 00 00 16 02 00 00 00 03 c0 12 38 8a c0 05 9c 28 bf c0 00 00 ...
^tag    ^ub4 len 29   ^the §18 image (JSON_SCALAR(TO_VECTOR('[1.5, 2.5, 3.5]')))
```

Dense and **sparse** vectors share this wrapper: what distinguishes them is the
sparse flag inside the image, not the node. A decoder therefore returns two
different Python types from the same tag, and an encoder that re-serialises a
decoded document has to accept both — handling only the dense one makes the
codec unable to re-encode its own output, which is how a JSON document holding a
sparse vector became unservable through the Mirror.

**Width selectors (#69, #88).** Widths are chosen by header flags and per-node
tag bits:
- *Container count + field-ids* — from the container node tag: `ub4` if the
  `0x10` bit is set (> 65535 entries/keys), else `ub2` if the `0x08` bit is set
  (> 255), else `ub1`.
- *Container value-offsets* — `ub4` if the container tag's `0x20` bit is set
  (the container's values span a > 64 KiB tree, #88), otherwise the image-level
  width: `ub2` when header flag `0x04` is set (server `JSON_OBJECT` / `JSON()`
  literals), else `ub4` (oracledb-produced, flags `0x2102`). Reading the wrong
  width mis-walks the value-offsets (e.g. back to offset 0), so the width is
  taken per node; a genuinely cyclic offset is bounded at decode time (see the
  robustness note below).
- *`tree_seg_size`* — `ub4` when header flag `0x1000` is set (tree > 64 KiB).
- *`num_fnames`* — `ub2` when header flag `0x0400` is set (> 255 field names),
  else `ub1`.
- *String value length* — `ub1` (`0x33`), `ub2` (`0x37`), or `ub4` (`0x38`).

> **Not yet covered** (raises `OsonError` / mis-decodes rather than guess): a
> `ub4` *fnames* segment (> 64 KiB of distinct field names) and a `ub8` hash-id
> array — both extreme and unobserved in captures. The common large-document
> cases (long strings, > 64 KiB trees, > 65535-element containers, oracledb
> images) are all handled.
>
> Multi-row JSON `SELECT`s ride the same LOB-locator path as multi-row LOB
> reads and share the #45 desync limitation under load — single-row reads are
> reliable.

**Malformed images (#165).** The image arrives from the server, so its counts
and offsets are untrusted. The decoder bounds the walk rather than trusting
them: a container `count` whose entries would overrun the image, or a value
offset that forms a cycle or revisits a shared node (an exponential blow-up),
raises `OsonError` (#226); a header, node, or segment cut short likewise raises
`OsonError`, not a raw `IndexError` (#225). python-oracledb trusts the server
here and guards neither.

### 17.2 Binds (#50, #70)

A bare Python `dict` is auto-detected as JSON (it has no other bind meaning);
wrap a `list` / scalar in `seerdb.JSON(value)` to bind it as JSON too, since a
bare `list` means a VECTOR and bare scalars bind as their native SQL types.
`Decimal` binds as a JSON number via the exact base-100 NUMBER encoder (all
significant digits preserved), matching the decoder, which returns JSON numbers
as `Decimal`.

seerdb prefers a **native binary OSON** bind (#70, the inverse of the §17.1
decoder in `seerdb/oson.py:encode_oson`). It is sent exactly like the native
VECTOR bind (§18.1): the bind OAC is the JSON one (`_JSON_BIND_OAC`, type 119
with a 32 MiB max length, built by `_encode_native_lob_oac`) and the value
carries the same 19-byte LOB-backed descriptor, the image length (ub2), 22 zero
bytes, then the OSON image over the 12c length framing. The encoder writes the
compact small-document form — the object/array node uses a ub1 count, ub1
field-ids and ub2 value-offsets; field-name hashes are sent as zero (the server
accepts that, verified by round-trip). Both fv16 (21c) and fv17 (23ai) accept
it.

`encode_oson` raises `OsonError` for anything it does not encode compactly —
strings over 255 bytes, objects/arrays over 255 entries, segments over 64 KiB —
and the bind path then falls back to the **text cast** (#50): serialise to JSON
text (`json.dumps`, `ensure_ascii=False`) and bind it as a `VARCHAR` the server
casts to `JSON`. So a wide (>255-key) document still binds, via the text path,
and reads back through the §17.1 wide-object decode. (Reading back a document
with a string longer than the decoder's ub1-string support is the separate,
pre-existing long-string decode gap, not a bind limitation.)

### 17.2b Binding a JSON value: NOT a LONG-class bind (#826)

A native JSON (or VECTOR) bind's OAC declares a 32 MiB maximum size. That is
larger than the server takes in place, which is the usual test for a LONG-class
bind whose value rides **after** all the row's other values (§5.4). It is not one:
it carries its own descriptor framing and rides **in place**.

Sorting it to the end swaps it with every bind after it. The symptom depends on
which side gets it wrong:

* a **server** that reorders reads the following bind's slot as the image and the
  image's bytes as that bind — `update t set j = :1 where id = :2` produced a
  NUMBER of `-1E+126` from OSON bytes;
* a **client** that reorders writes the value out of place and a real 23ai
  answers `ORA-24813: cannot send or receive an unsupported LOB`.

Both go unnoticed for a long time, because a JSON bind is usually the **last**
bind in a statement — `insert into t values (:1, :2)` — where the move is a no-op.
It is `UPDATE ... SET json = :1 WHERE ...` that exposes it.

### 18.1 Binds (#55 / #62)

seerdb binds a vector with the **native binary image** (matching
python-oracledb). The full exec bind for a vector is `OAC | TTI_RXD | value`:

- **OAC** (`encode_token_oac` → `_encode_native_lob_oac`): a fixed 25-byte block,
  built field-by-field — type 127, the max data length (1 MiB), the *cont-flag*
  `0x02000000`, and the *LOB-prefetch length* set to the same 1 MiB max, with the
  trailing *oaccolid* zero:
  `7f 01 00 00 | 04 00100000 | 00 | 04 02000000 | 00 00 00 00 | 04 00100000 | 00`.
  python-oracledb emits the two size fields as a **non-minimal** 4-byte ub4 (the
  leading zero of `00 10 00 00` is kept), so they are encoded fixed-width to match
  the capture. Without the `0x02000000` flag the server rejects the inline value
  (ORA-03120); a too-short OAC desyncs (ORA-03106).
- **Value** (`encode_token_rxd`, after the `TTI_RXD`=0x07 token): an 18-byte
  **descriptor** (`01 28 28 00 26 00 04 61 08 00 00 00 01 00 00 00 00 00` — the
  same one python-oracledb uses for any LOB-backed inline bind, so #70 JSON
  reuses it), then the **image length as THREE bytes**, **22 zero bytes**, then
  the image framed like RAW (`encode_chr`: a single length byte < 254, else the
  `0xFE` marker + `ub4` chunks). Works at field version 16 and 17.

  **The length is three bytes, and that is easy to get wrong (#1008).** The
  descriptor is often written as 19 bytes ending in `00` followed by a `ub2`
  length — which produces identical bytes for every image under 64 KiB, because
  that trailing `00` *is* the field's high byte. It only shows up above the
  ceiling, where a `ub2` cannot hold the value at all. Measured on a live 23ai,
  binding one column with a 4-dimension vector and a 30,000-dimension one and
  aligning the two on the descriptor:

  ```
  SMALL  ... 01 00 00 00 00 | 00 00 31 | 00 00 ...    image = 49 bytes
  LARGE  ... 01 00 00 00 00 | 03 a9 91 | 00 00 ...    image = 240,017 bytes
                              ^^^^^^^^
  ```

  Three bytes allows 16 MiB, past the 65,533-dimension maximum — a float64
  vector that size has a ~512 KB image.
- **Image** (`encode_vector`): the read image (§18) with the 8-byte norm sent as
  **zeros** (the server recomputes it). FLOAT32/64 use the sortable encoding,
  INT8 raw bytes, BINARY packed bytes; a SparseVector emits the §18.2 sparse
  image. Dense `list`/`tuple` → FLOAT32; an `array.array` maps by typecode.

### 18.2 SPARSE vectors (#68)

A `VECTOR(n, T, SPARSE)` column stores only the non-zero elements. Its image is
**version `2`** with the **`0x20`** flag set, and after the header + norm carries:

```
count (ub2) | indices (ub4 × count) | values (element × count)
```

`num_elements` (header) is the total dimension count; `count` is the number of
stored elements; the values use the same per-element encoding as a dense image
(sortable FLOAT32/64, raw INT8). seerdb decodes it to an `seerdb.SparseVector`
(`num_dimensions`, `indices`, `values`) and binds one back natively via §18.1
(the sparse image carries the same OAC + descriptor). Captured on 23ai across
FLOAT32/INT8 and a 300-dim vector (index 299 confirms the ub4 indices).

> As with JSON, multi-row VECTOR `SELECT`s share the #45 LOB desync limitation
> under load; single-row reads are reliable.

## 18. Native VECTOR (23ai+)

Oracle 23ai+ stores a native `VECTOR` column as a binary image delivered, like
JSON (§17), through a LOB locator: the RXD row carries a locator and the image
is fetched over `TTI_LOBOPS` (§14). The column's TNS data type is **127**
(`TNS_TYPE_VECTOR`). seerdb reads it through the normal LOB locator path and
decodes the image in `seerdb/vector.py`.

The format below was reverse-engineered from images captured off a live 23ai
server, each with known content. A VECTOR image is:

```
magic 0xDB | version (ub1) | flags (ub2) | element_type (ub1) | num_elements (ub4)
[ norm (8 bytes, present when flags & 0x10) ]
elements ...
```

`version` is `0x00` for FLOAT32/FLOAT64/INT8 and `0x01` for BINARY; the decoder
ignores it. The 8-byte `norm` is a cached magnitude (sortable-encoded, see
below) that is not part of the value and is skipped.

| `element_type` | Type     | Element encoding                                        |
|----------------|----------|---------------------------------------------------------|
| `2`            | FLOAT32  | 4 bytes, order-preserving ("sortable") float            |
| `3`            | FLOAT64  | 8 bytes, order-preserving ("sortable") float            |
| `4`            | INT8     | 1 byte, plain two's-complement                          |
| `5`            | BINARY   | bits packed 8/byte; see below                           |

**Sortable float** (FLOAT32/64): the encoding makes a byte-wise compare order
values numerically — for a positive value the sign bit is set, for a negative
value every bit is inverted. Reverse it by: if the top bit is set, clear it;
otherwise invert all bits. Then read the result as a big-endian IEEE-754 float.

**BINARY** (bit vectors): `num_elements` is the **dimension (bit) count**, not a
byte count, and the payload is those bits packed 8 to a byte —
`ceil(num_elements / 8)` bytes. seerdb surfaces the packed bytes verbatim as a
list of ints, matching the form a `VECTOR(n, BINARY)` literal takes (e.g.
`'[170, 1]'` for a 16-dim vector stores bytes `AA 01` and reads back `[170, 1]`).

Captured reference images:

```
[1.5, 2.5, 3.5]  FLOAT32  db 00 0012 02 00000003 c012388ac0059c28 ...
[1, -2, 3, -4]   INT8     db 00 0012 04 00000004 c015e8add236a58f 01 fe 03 fc
[170]            BINARY   db 01 0010 05 00000008 8000000000000000 aa
[170, 1]         BINARY   db 01 0010 05 00000010 8000000000000000 aa 01
```

**Malformed images (#165).** `num_elements`, the sparse stored-element count,
and the packed-bit count arrive from the server and are validated against the
image length before iterating, so a crafted count (e.g. a ~4-billion `ub4`)
raises `VectorError` rather than spinning to build an unbounded list (#228).

## 19. Oracle 9i (pre-10g) query/fetch — the fv2 dialect (#97)

Oracle 9i negotiates **TTC field version 2** (`FIELD_VERSION_9_2`). Its login is
O3LOGON (§4, gated `field_version < FIELD_VERSION_10_2`); its **query/fetch path
is a different RPC** from the `TTI_ALL8` (§5.1) seerdb sends to 10g+. A 9i
server answers an `ALL8` execute with an empty return, so SELECTs come back with
no describe and no rows. 9i instead uses the older **`TTI_ALL7` (func `0x47`)**
execute, and a query is a **four-call sequence** (reverse-engineered from the
Oracle JDBC thin driver — ojdbc14 — captured against a live 9.2.0.4 server; the
same reference that cracked the 9i login). All calls are `TTI_FUN (0x03) <func>
<seq> …`. Gate every fv2 path on `field_version < FIELD_VERSION_10_2`.

| # | Call           | Func               | Response                                   |
|---|----------------|--------------------|--------------------------------------------|
| 0 | Open cursor    | `0x02` (OOPEN)     | `TTI_RPA` (08) — allocates the server cursor|
| 1 | Parse/describe | `0x47` (`TTI_ALL7`)| `TTI_RPA` (08) — cursor id                  |
| 2 | Describe cols  | `0x62`             | `TTI_RPA` (08) — **column metadata** (below)|
| 3 | Execute+fetch  | `0x47` (`TTI_ALL7`)| `TTI_RXH` (06) + N×`TTI_RXD` (07) + `TTI_OER`(04) ORA-01403 |
| 4 | Close cursor   | `0x14`             | `TTI_STA` (09)                              |

An **OOPEN** (`03 02 <seq> 01 00`) must precede the parse — it allocates the
server cursor that the parse/describe/execute/close then operate on (they all
carry cursor field 0 = "current"). Without it the parse fails **ORA-01001**
("invalid cursor"). All five calls carry cursor/sequence byte `0`.

Call 1 carries the SQL inline, length-prefixed, after a fixed option header
(`02 80 21 01 01 01 01 <sqllen> 00 00 01 01 07 01 01 02 00 00 00 00 00 <SQL>
01 01 01 01 00 00 00 00 00`); call 3 repeats `0x47` with option word `02 80 50`
and a per-column **define block**. The `ORA-01403` ("no data found") trailing the
row stream is the **end-of-fetch marker**, not an error (seerdb already treats
01403 as end-of-cursor, §6.7).

### 19.1 fv2 describe (the `0x62` response — describe lives in the RPA)

Unlike 10g+, which returns a dedicated `TTI_DCB` (§6.4), 9i packs the column
metadata **inside the `TTI_RPA` (08)** answering the `0x62` call:

```
08 <ub4 numcols> <column>*  <status>
column = <OAC-fv2> <null_ok:1B> <namelen_bytes:1B> <ub4 namelen_chars> <DALC name>
         <ub4 type_schema_len> [<DALC type_schema>] <ub4 type_name_len> [<DALC type_name>]
```

The per-column **`OAC-fv2`** is exactly the §5.3 OAC field order **minus the
trailing `Mxlc` ub4** (a later-version addition):

```
DataType(1B) Flag(1B) Precision(1B) Scale(ub4) MaxLen(ub4)
MaxArrLen(ub4) Flags2(ub4) ToId(DALC) Version(ub4) Charset(ub4) FormOfUse(1B)
```

The leading **`DataType` byte is the standard Oracle internal type code** — the
same numbering as seerdb's `TNS_TYPE_*` constants (1=VARCHAR2, 2=NUMBER,
12=DATE, 23=RAW, 96=CHAR, 181=TIMESTAMP) — so the fv2 path **reuses the existing
type→value decoders**, no new numbering. The OAC is followed by a **`null_ok`
byte** (`0x00` = NOT NULL, `0x01` = nullable), a **1-byte `namelen_bytes`**, a
**`ub4 namelen_chars`**, then the **DALC-encoded UPPERCASE name**, and last the
schema and name of the column's type, each a `ub4` length and the name when there
is one. Only an object column names its type (`01 03 03 PYO`, `01 06 06 TY2248`,
#2258); every other column sends the two zero lengths, `00 00`, which read like a
separator between columns but end the last column too. The column count is a
`ub4` (`01 <n>` up to 255, `02 01 2c` for 300, #2306), and `namelen_bytes` is one
byte because the server cuts a name to 255 bytes: an expression's column, named
by its text, comes back `ff 01 ff` and the name in 64-byte chunks. seerdb reads
it all from one schema, `_O7_DESCRIBE` (#2284), and every column ends on the
next one or on the call's status.

> **Do not read the post-OAC fields as two `ub4` name-lengths.** The first byte
> is `null_ok`, not a length. It only *looks* like a ub4 width byte for nullable
> columns, where `null_ok = 0x01` reads as "width 1" and its value coincidentally
> equals the name length. A **NOT NULL** column sends `null_ok = 0x00`, which a
> ub4 decoder misreads as width-0/value-0 (one byte), slipping the whole column
> stream: the name garbles (`USERNAME` → `\x08USERNAM`) and a multi-column
> NOT-NULL fetch then dies with **ORA-03115**. Read `null_ok` + the 1-byte
> byte-length explicitly, then the genuine `ub4` char-length. `null_ok` feeds
> `Cursor.description[6]`. The earlier "two ub4 name-lengths" model survived only
> because the initial captures were all `SELECT <literal> AS name FROM dual` —
> literals are always nullable, so `null_ok` was always `0x01` and the slip never
> triggered.
>
> Two more RE traps: a single-character column name (e.g. `N`) mis-anchors if you
> scan for the name by ASCII — parse the OAC deterministically instead; and the
> **last** column's OAC runs straight into the describe trailer, so only interior
> columns segment cleanly by eye.

**The declared size (#2326).** Neither 9i's describe nor 8i's (§19.10) has the
OAC's `max_chars`, the declared size 10g's sends, which `cursor.description`
reports. The decoders give it as 10g's describe has it: a VARCHAR2's or CHAR's
buffer, halved in AL16UTF16 (an NCHAR(4) describes 8 bytes), and 0 for every
other column. The buffer stood in before, and a DATE and a ROWID, which
describe a buffer of 1, reported a size of 1, a LOB 4000 and a 9i NUMBER 22.

### 19.2 fv2 row data

The execute+fetch (`0x47`, call 3) carries a per-column **define block** telling
the server the type the client wants each column returned as, then returns
`TTI_RXH` (§6.1) + one `TTI_RXD` (§6.2) per row, terminated by `TTI_OER` carrying
ORA-01403. The **row value encoding is version-independent** — Oracle NUMBER
(§11.1), DATE (§11.2), and length-prefixed character/raw values decode with the
existing §11 decoders (verified: `c1 2b`→42, `68 69`→"hi", a 7-byte date → the
wire date). Multiple rows arrive in a single RXH+RXD stream when they fit the
fetch array.

The define block follows a fixed prefix (`01 01 <numcols> 00 00 01 01 01 0a
00 00 00 00 00`) with one 13-byte entry per column:

```
<deftype:1B> <flag:1B> 00 00 <MaxSize:ub4> 00 00 00 00 <Charset:ub4> <FormOfUse:1B>
```

`deftype` is the client's *requested* return type built from the call-2 describe:
NUMBER→`0x06` (VARNUM, MaxSize 22), VARCHAR2→`0x01` (MaxSize = described max),
CHAR→`0x60` (flag `0x21`), DATE→`0x0c` (MaxSize 7).

The `TTI_RXH` is the 10g+ one: flags, then as `ub2`s the number of columns
requested, the iteration, the iterations the fetch asked for (`0a`) and the
buffer length, then the column bit vector's and the rowid's lengths (`ub4`s)
and their bytes. 9.2.0.4 sends seerdb both lengths, zero in every reply, rows
repeating each other or not, so no value is ever left out of a row (§6.1's bit
vector, #181). It sends **ojdbc14** neither: that client's header ends at the
buffer length, `06 02 01 01 00 01 0a 00`, and the row's `07` follows. Its short
status (§19.3) likewise stops at the iterations, the message straight after.
The server shapes both by what the client negotiated (#2284).

In the returned `TTI_RXD`, each column is a DALC value followed by an indicator,
a signed `ub4`: `0x00` (0) for a value; for a **NULL** column an empty value
(`0x00`) and **`0x81 0x01`**, -1, the indicator OCI gives a NULL. Reading the
indicator as one byte silently truncates the row stream (consumes one byte too
few and desyncs the following rows). A LOB's value is a `ub4` length and, unless
it is zero, the locator; a LONG's comes chunked (`0xFE`) however short. seerdb
reads the header and each cell from a schema (`_O7_RXH`, `_O7_CELL`,
`_O7_LOB_CELL`, `_O7_LONG_CELL`, `_O7_EMPTY_CELL`).

A column the describe gives a **zero data length** (§19.1's MaxLen) -- an untyped
`SELECT NULL`, or anything Oracle folds to one at parse, such as
`DECODE(3, 1, 'one')` -- sends **no value at all**, only the `0x81 0x01` marker
(#1185; captured on 9.2.0.4: `SELECT NULL AS a, 5 AS b` → `07 81 01 02 c1 06 00`).
It is the 9i form of §6.2's zero-length rule (#682). LONG and LONG RAW are also
described with a zero length and are the exception: they carry data.

A result set larger than the fetch-array size is drained by **re-sending the
same exec+fetch `TTI_ALL7`** — the server continues the cursor and ends with
ORA-01403 (#99; verified: 28 rows arrive as 10 + 10 + 8 across three identical
exec calls).

### 19.3 Binds and DML

**Binds** (#100) ride in the **parse** call, not the execute: the option word
flips `02 80 21` → `02 80 29`, a bind-count field precedes the SQL, and after the
SQL trailer each bind's OAC (the same 13/14-byte descriptor as a define entry) is
appended, followed by a single `TTI_RXD` (`0x07`) carrying all the bind values in
order. The describe/execute calls are unchanged.

**DML** (INSERT/UPDATE/DELETE, #101) is simpler than a query: `OOPEN` then a
single `TTI_ALL7` parse (`02 80 21`, with binds if any) that *also executes* the
statement — no describe, no fetch. The response is an RPA piggyback followed by
the short OER whose **first field is the affected-row count** (ORA code 0 =
success). 9i's parse carries no autocommit bit, so the client issues an explicit
`TTI_COMMIT` when autocommit is on (verified to persist on 9.2.0.4).

The short OER is the 10g+ one (§ "Rowid → `lastrowid`") **without its first two
fields** (call status, end-to-end sequence number). After the token: row count,
ORA code, two array-error fields, cursor id and error position (a `ub4` each),
six single bytes (the first is the SQL command type: `02` INSERT, `06` UPDATE,
`07` DELETE, `09` CREATE INDEX, …), then the **touched row's rowid** in the
same fields as 10g+: `ub4` data object, `ub4` relative file, one reserved byte,
`ub4` block, `ub4` slot (#1079). Captured on 9.2.0.4, a one-row INSERT (object
91683, file 1, block 47378, slot 2):

```
08 01 02 04 01 95 59 43 00          RPA (count 2: the counter, 0)
04 01 01 00 00 00 01 01 01 0c       OER: rows 1, ORA 0, 0, 0, cursor 1, errpos 12
02 00 00 00 00 00                   command type INSERT + five flag bytes
03 01 66 23 01 01 00 02 b9 12 01 02 rowid: object, file, reserved, block, slot
…                                   (the rest of the status, below)
```

The third of the six single bytes is a `ub2` flags field (`00` when zero), as at
10g and 11g (#1995); the sixth is the warning flags, `0x20` for an object that
compiled with errors (#2262). After the rowid come the OS error (`ub4`), the
statement and call numbers (a byte each), padding (`ub2`), the successful
iterations (`ub4`), the oerrdd -- a `ub4` length and the value, the 13-byte
fixed-width rowid after a DML -- then the arrays a `batcherrors` call collects
(§ batch errors, #2247): the codes and the offsets, each a `ub4` count and one
value packing that many `ub4`s, and the messages, a `ub4` count, an indicator
byte when there are any, and per message a `ub4` length, the text and two bytes.
Last, when the ORA code is set, the server's message, in 64-byte chunks past 64
(the `0xFE` form), ORA-01403's included. seerdb reads it all from two schemas,
`_O7_STATUS_HEAD` (to the rowid) and `_O7_STATUS_TAIL` (#2284); 57 live 9.2.0.4
statuses read to their last byte.

The server does **not** clear the field: a DDL, or a DML that touched no row,
carries the previous statement's rowid. Its row count is 0, which is how the
client drops it, exactly as it does for 10g+ (#1078).

`RETURNING ... INTO` cannot be carried in this form: the 9.2 server answers
`ORA-00439: feature not enabled: RETURNING clause from this client type`, and
the 8i OALL8 form (§19.12) returns no value and drops the connection when the
statement fails. The client therefore runs the statement as an anonymous block,
`BEGIN <dml> RETURNING ... INTO :n; END;`, whose INTO targets are ordinary OUT
binds (§19.7), on 8i and 9i alike (#801, #802; §22). Multi-column RETURNING,
UPDATE, DELETE and `SQL%ROWCOUNT` all work; a multi-row RETURNING into a scalar
raises `ORA-01422` as on any Oracle, and a failing statement is an ordinary
PL/SQL error with the session intact.

The capability route does not work. Setting `compile_caps[CCAP_FIELD_VERSION]`
to 2, as the native 9.2 OCI client does, clears ORA-00439, but every bind then
fails with `ORA-03120`: the server parses binds in the native OCI marshalling
(64-bit pointer and length fields). Adding the runtime word-size capability
(`02 01`) commits the session to the full native OCI login, and 9.2.0.4 closes
the connection after the thin data-type table (#716, #790). The pre-10 error reply (§19.2)
carries the code and text but no error position.

The RPA piggyback is `08`, a `ub4` parameter count, then exactly that many
`ub4` parameters; the first is a counter that grows with the instance. Its
length byte reads `0x04` once the counter passes 2**24, which is also the OER
token, so the parameters must be consumed by count and never by sniffing for a
token: a decoder that stopped at the `0x04` took the counter for the status and
turned every successful DDL and DML on an aged 9i into a garbled negative ORA
code (#711). Captured with the counter at `0x0129c868`.

### 19.4 Errors, ROWID, and unsupported types (#102)

A parse/execute that fails returns the **short OER** as the response (in place
of the RPA), e.g. `04 00 02 03 ae … 28 'ORA-00942: …'`: field 1 is 0, field 2 the
ORA code, and the trailing length-prefixed string is the message. The fv2 path
checks the parse response for this and raises the real code + text rather than
marching on into a desync.

**ROWID** is requested in the define block as **VARCHAR(128)** (deftype `0x01`,
not the native ROWID type 11) — exactly as JDBC does — so it returns as the
familiar 18-char rowid string; the native ROWID return form desyncs the row
stream (ORA-01002). A **UROWID**, an index-organized table's logical rowid,
holds the table's key, and its text runs to 5267 characters: it is defined as
VARCHAR(5267), the size the bind path uses. Defined at 128, a longer one came
back cut to 128 characters with no error (#2335).

**LONG / LONG RAW** are supported: requested in the define block with the 2 GiB
max buffer, they stream back inline as a chunked DALC (the `0xfe` form — single
or multi-chunk) and decode through the normal column path. In batch fetch they
carry no per-row trailing descriptor (that only appears in single-row fetch).

**CLOB / BLOB** are read by the two-call TTI_LOBOPS sequence in §19.5. **BFILE**
(type 114) still needs its own fv2 FILE_OPEN/READ/CLOSE framing, so the driver
detects it in the describe and raises `NotSupportedError` before the execute (a
`SELECT` of it would desync the server, ORA-01002). Transactions (`COMMIT` /
`ROLLBACK`) work unchanged on 9i.

### 19.5 CLOB / BLOB read — the two-call TTI_LOBOPS GETLEN + READ (#102)

A CLOB / BLOB cell in the RXD is **not** an inline value: it is a LOB **locator**
(`ub4 num_bytes` + a DALC block, the 86-byte `00 54 <84-byte locator>` form),
followed by a 1-byte `00` present indicator. A NULL LOB instead uses the scalar
empty-value form `00 81 01` (empty DALC + the `81 01` null indicator); a present
locator's `num_bytes` is always ≥ 86 (first byte `0x01`), so a leading `0x00`
unambiguously marks NULL. `_read_lob_column` extracts the locator; the cell
becomes a `LOB` object that the fv2 SELECT path resolves **before closing the
cursor** (`_resolve_fv2_lobs`), matching what the JDBC reference client does.

9i's TTI_LOBOPS request is far shorter than the modern (10g+) form, and the
reference client issues it as a **pair** per LOB cell (the modern single-shot
READ returns empty on 9i):

1. **GETLEN** — learn the content length:
   `03 60 <seq> 01 01 56 00 00 00 00 00 01 00 01 01 00 00 00` `<ub1 len><locator>`
   `00`. The locator field is `_read_lob_column`'s output with its leading byte
   dropped (`54 <84 bytes>`). The reply is a TTI_RPA: `08 00 <ub1 len><locator
   echo> <ub4 amount> …`; `amount` is in **chars** for CLOB and **bytes** for
   BLOB.
2. **READ** — pull exactly that amount, from offset 1:
   `03 60 <seq> 01 01 56 00 00 01 01 00 00 01 00 01 02 00 00 00` `<ub1 len><locator>`
   `<sb4 amount>`. The reply is the content: `0e fe` then `<ub1 len><bytes>`
   chunks (9i uses ~64-byte chunks) ending at a **zero-length chunk**. The
   trailing RPA is ignored. Unlike modern replies the fv2 READ reply carries
   **no `04 01 01` OER call-status** (a single-row fetch happened to include one;
   a multi-row fetch does not), so the zero-length chunk terminator — not an OER —
   is the only reliable stop signal (`decode_fv2_lob_chunks`). Content may span
   packets.

The request is the 10g+ TTI_LOBOPS head (§14's `_LOBOPS_HEAD`, at field
version 2): the source locator's pointer and length, the destination's, the
short source and destination offsets, the charset, short-amount and null-LOB
pointers, the **operation** (`TNS_LOB_OP_*` — GET_LENGTH `0x01`, READ `0x02`,
FILE_OPEN `0x0100`, FILE_CLOSE `0x0200`, …). Then the SCN array's pointer and
length, the locator whole — its `ub2` length and body, the bytes the source
length counts — and the **short amount** when its pointer says so: what the "op
middle" and "trailer" of the first reading are. There is no amount pointer: read
as one and a value of the body, the locator's `ub2` length looks the same while
the body is 252 bytes or less, and past that the value goes out in chunks, which
9.2.0.4 refuses with ORA-03120 — a BFILE's locator with a long file name
(#2331).
9i has neither the long offsets nor the array slots 10g added. The short amount
is the READ's count, TRIM's new length, OPEN's mode, FILE_OPEN's `0x0b`, `0` for
GETLEN, whose reply fills it in; CLOSE and FILE_CLOSE ask none, and IS_OPEN sets
the null-LOB pointer instead. The reply is the RPA, the locator as the server now
has it (a `ub2` length and the body: the `00` after `08` is its high byte), the
short amount if asked for, and IS_OPEN's answer, then the status. seerdb writes
and reads them from `_O7_LOBOPS` and `_O7_LOBOPS_REPLY` (#2284), and 8i's from
the same schemas at its fixed little-endian widths (§19.17).

An **empty** LOB (`EMPTY_CLOB()` / `EMPTY_BLOB()`) has a valid locator but GETLEN
returns amount 0, so no READ is issued and the value is `""` / `b""`. CLOB content
arrives in the column's **DB charset** (a single-byte run on a typical 9i, **not**
the UTF-16BE the modern path uses) and is decoded with that charset; BLOB content
is returned as raw bytes.

A `Var` in a plain statement is an IN bind whose type was declared
(`setinputsizes`); its descriptor carries the Var's type and size like a block's
OUT bind, with one exception. 9i treats a CHAR bind as `CHAR(max_size)` and
blank-pads the value to it, so a declared CHAR sized by the Var's default (2000)
read back padded to 2000 where 8i and 10g+ return it as sent (#737). A declared
CHAR that carries a string value is therefore sized to that value's encoded
length (UTF-8, or UTF-16BE for a national CHAR). A block's binds keep the Var's
size: there it is the return buffer.

What 9i does with the bind is then right, `LENGTH(:x)` is the value's own
length, but it still types a `SELECT :x` expression at a width of its own (32
for a short value, 128 for a longer one, measured) and pads the *fetched*
expression to it, where 8i and 10g+ return the value as sent whatever width
they describe. That is the server's CHAR expression typing, not the bind, and
declaring VARCHAR instead would lose the blank-padded comparison a CHAR bind is
declared for.

### 19.6 Anonymous PL/SQL blocks (#102, IN binds)

A `BEGIN … END;` / `DECLARE … ;` block runs as **OOPEN + a single ALL7
parse-execute** (no describe / fetch — structurally like §19.3 DML), but with two
differences from a SELECT/DML parse, both essential — the server rejects a block
sent with DML opts with **ORA-00600**:

1. **Option word.** A block uses `01 21` (no binds) or `02 04 29` (with binds)
   where a SELECT/DML uses `02 80 21` / `02 80 29`. The `0x8000` bit (set in the
   DML form) means "bind values are inline"; a block does **not** set it.
2. **Bind values are a separate round-trip.** The parse-execute carries the bind
   **OAC** descriptors but **no values**. The server then replies with a bind
   prompt (`0b 05 …`); the client sends the values as a standalone `TTI_RXD`
   (`07` + the DALC-encoded values, exactly `encode_tokens_rxd`); the server
   returns the final RPA + short OER. A block with **no** binds skips the prompt
   and the parse-execute returns the RPA + OER directly.

The response decodes through the same `decode_fv2_dml_response` (RPA piggyback +
short OER); a compile error (e.g. ORA-06550) or runtime error (ORA-20001 +
ORA-06512) surfaces from the OER via `_fv2_raise_for_error`, and the connection
stays usable afterward. `encode_o7_block` builds the request and
`OracleConnect._execute_fv2_block` (+ the async port) drives the sequence.

OUT / IN OUT binds extend this same flow — see §19.7.

### 19.7 PL/SQL block OUT / IN OUT binds (#102)

The bind **direction is not encoded in the OAC or the option word** — a block
with OUT binds is the same `02 04 29` parse-execute, with one OAC per bind in
position order (every bind, regardless of direction). For a `Var` the OAC carries
its registered type and return-buffer size (NUMBER → VARNUM(6)/22; VARCHAR →
the Var size, default `0x7fff`; ROWID / UROWID → VARCHAR(5267) carrying the
rowid's text, since declared as type 11 / 208 the server answers with a garbled
error, #1399). The server infers each bind's direction from the
block and signals it in the prompt; the round-trip then differs by direction:

- **Bind prompt**: the `TTI_IOV` I/O vector of §6.5, the message 10g+ sends
  too. Flags (`05`), the requests and the iterations, whose
  `iterations * 256 + requests` is the number of binds -- `01 02 00` for 2 binds,
  `01 2c 01 01` for 300, `01 08 01 02` for 520 (#2311) -- the iterations this
  time (`01 01`), the buffer length, the bit vector's and rowid's lengths, then
  one mask per bind, `0x20` = IN, `0x10` = OUT, `0x30` = IN OUT. 9.2.0.4 sends
  seerdb both lengths (`00 00 00` before the masks) and ojdbc14 neither (`00`),
  as in the row header (§19.2). seerdb reads it from `_O7_IOV` (#2284); a mask
  is never how a `ub4` opens, which tells the two forms apart.
- **Input values** (client → server): a `TTI_RXD` with the values of the **IN and
  IN OUT** binds, in position order, skipping pure-OUT binds. Sent only when at
  least one such bind exists.
- **Return values** (server → client): a `TTI_RXD` carrying one `DALC value +
  1-byte indicator` per **OUT and IN OUT** bind, in position order, skipping
  pure-IN binds, immediately before the RPA + OER (`decode_fv2_block_out`).

**The prompt's masks are authoritative (#1242).** The client used to guess the
directions from its own binds, counting every `Var` as an output. A `Var` the
block only reads (set with `setvalue`, never assigned) is an IN bind, so no value
comes back for it, and counting it shifted every value after it: `:1 := :2 * 10`
with two `Var`s decoded the RPA as the second value. The driver now reads the
masks (`decode_fv2_bind_directions`, one per bind after the I/O vector's
fields), sends inputs for the binds marked IN and
expects values for those marked OUT. It falls back to the guess only when a reply
carries no prompt. Captured: `0b0501020001010000001020` is OUT, IN, and
`0b050103000101000000102030` is OUT, IN, IN OUT.

A **pure-OUT** block (no IN/IN OUT bind) needs no input frame: the server packs
the prompt, the return RXD and the RPA + OER into a single reply. When inputs
exist, the prompt is its own packet, the client sends the input RXD, and the
return values arrive in the next reply.

The returned values are handed to the cursor as the same
`{'out_positions', 'out_values'}` record the modern IOV path produces, so
`Cursor._assign_out_binds` decodes each by its `Var`'s type unchanged — a pure-OUT
`Var` (`has_value` false) and an IN OUT `Var` (seeded with `setvalue`) are
distinguished there. `_execute_fv2_block` drives the whole sequence (sync +
async).

### 19.8 BFILE read (#102)

A `BFILE` column (type 114) arrives in the RXD as a locator like CLOB/BLOB, but
shorter and **variable length** — a `<ub2 inner-length>` + flags + the
`DIRECTORY` object name and file name in plain ASCII (e.g. 34 bytes for
`BFDIR` / `hello.bin`). `_read_lob_column` extracts it and `LOB.directory_name`
/ `LOB.filename` parse it. Reading the file is a four-call TTI_LOBOPS sequence —
the fv2 form of the modern `bfile_read_native`:

1. **FILE_OPEN** (op middle `00 00 00 00 01 00 02 01 00 00 00 00`, trailer
   `01 0b` = read-only mode) → the reply's RPA carries an **updated** locator
   with the open flag set; GETLEN / READ / FILE_CLOSE must use *that* one
   (`decode_fv2_opened_locator`). A bad file surfaces here as ORA-22288.
2. **GETLEN** (§19.5 form) → the byte length.
3. **READ** (§19.5 form) → the content as `0e fe <chunks>`.
4. **FILE_CLOSE** (op middle `00 00 00 00 00 02 02 00 00 00 00`, no trailer).

All four share the common fv2 LOBOPS shape `03 60 <seq> 01 <sb4 locator-length>
<op middle> <locator[1:]> <trailer>` (`_encode_o7_lobop`); the locator length is
computed because BFILE locators vary (CLOB/BLOB are a fixed 86 bytes).
`Fv2Dialect.bfile_read` drives the sequence (closing in a `finally`). The fetch
leaves the BFILE column a `LOB`, and its `read()` / `aread()` runs the sequence
through `bfile_read_native`, like the modern path; reading it during the fetch
made a BFILE naming a missing directory fail the SELECT (#1103). This completes the 9i LOB surface (CLOB, BLOB,
BFILE) and, with §19.6 / §19.7, the PL/SQL surface (IN, OUT, IN OUT).

### 19.8 Oracle 8i login — the OSESSKEY-envelope O3LOGON (#244)

Oracle **8i (8.1.7)** also negotiates field version 2 and uses the same DES
**O3LOGON crypto** as 9i, but it does **not** speak 9i's positional
`TTI_3LOGA`/`TTI_3LOGON` messages — sending those draws a `TTI_OER`. Instead 8i
wraps the O3LOGON exchange in the **OSESSKEY (`0x76`) / OAUTH (`0x73`, `TTI_AUTH`)**
function envelope with key-value `AUTH_` pairs, the same envelope 10g+ uses for
O5LOGON but carrying the 8i-era DES crypto. Reverse-engineered from a live
9.2-client → 8.1.7 capture (a stock 11.2 client is too new to connect to 8i).
seerdb detects 8i from the PRO banner (major version 8) and pins field version 2
(8i's PRO carries no caps to negotiate it down, else the client stays at its
default and wrongly takes the fv24 fast-auth path).

**The envelope is 10g's at fixed widths.** Both calls are the 10g login's head
and pairs (`_AUTH_HEAD`, `_AUTH_PAIR`, #2284) at the 8i codec's little-endian
widths: a pointer, the user's `ub4` length, the `ub4` mode (1 for OSESSKEY, 0x101
for OAUTH), a pointer, the `ub4` pair count, two pointers and the user as a value
(a `ub1` length and the bytes); then each pair, a `ub4` key length, the key as a
value, a `ub4` value length, the value as a value, and a `ub4` flags word (0).
Read first as `ub1(len) ub4be(len) <data>` and a big-endian padding word, the
bytes are the same for a non-empty value; but an empty one is a zero length and
no value, as 8.1.7 writes one (its `AUTH_CAPABILITY_TABLE`), and written as one
zero byte it failed the login (#2344). The "phase-two logon mode `0x105`" of the
first reading was the mode 0x101 and the pair count, five. The replies are the
RPA, a `ub2` pair count and the pairs (`_O8I_AUTH_REPLY`): `AUTH_SESSKEY` alone at
phase one, 22 at phase two, whose `AUTH_NLS_` keys count their NUL terminators in
their lengths.

The `ub1` caps a value at **252 bytes**, because 253, 254 and 255 are the TTC
escape, long-form and NULL markers. Measured on 8.1.7 with `AUTH_PROGRAM_NM`:

| value length | 8.1.7 |
|---|---|
| up to 252 | logs in; `v$session.program` keeps the first 64 characters |
| 253, 255 | the login fails |
| 254 | the reply comes back broken |

seerdb cuts a longer informational value (program, machine, pid) to 252 bytes on
a character boundary. The server keeps the same 64 characters either way (#1773).

The two-phase exchange:

| Phase | Client `TTI_FUN` | Carries | Server `TTI_RPA` (08) |
|-------|------------------|---------|-----------------------|
| 1 | `0x76` OSESSKEY | username + `AUTH_PROGRAM_NM`/`AUTH_MACHINE`/`AUTH_PID` | `AUTH_SESSKEY` (8-byte DES key, ASCII-hex) |
| 2 | `0x73` OAUTH    | username + `AUTH_PASSWORD` (+ `AUTH_ACL`, info pairs) | `AUTH_VERSION_STRING` … = **authenticated** |

`AUTH_PASSWORD` is `hex(DES blocks) + decimal pad count` — identical to the 9i
computation (`des_verifier` + `o3logon`), so the crypto is reused unchanged;
only the message envelope differs. Phase two succeeding with a value RPA (not the
clean `TTI_OER` 9i answers with) means authenticated — there is no server proof
to validate on the pre-10g path. Encoders: `encode_o3logon_osesskey_phase1` /
`encode_o3logon_oauth_phase2` / `parse_8i_auth_sesskey`, gated on the `_is_8i`
flag.

**8i needs its own DTY.** 8i predates ~37 later data types (so its identity map
is shorter — 1019 B vs the modern 1167 B) and has **no Unicode charset** — it
negotiates single-byte **WE8ISO8859P1 (31)**, not AL32UTF8 (873). Sending the
modern DTY draws **ORA-03120** ("two-task conversion: integer overflow") on the
following OSESSKEY. seerdb sends the captured `_DTY_8I` constant when `_is_8i`
(the datatype negotiation does not vary with the workload, so it is a constant
the same way §4.2's modern table is). Its 42-byte header is built from named
fields — `TTI_DTY` token, charset + national charset (both ISO Latin-1 = 31), the
26-byte fv2 capability vector (captured 8i identity), and the DB time-zone block set
to UTC (the `80000000` pad + the `+60`-biased `(60,60,60)` triplet) — followed by the
conversion-entry list. The 8i **query** path is §19.9–19.10.

### 19.9 Oracle 8i SELECT — the 9.2-era OALL8 request (#244)

8i's query dialect is **neither** 9i's `TTI_ALL7` four-call sequence (§19.1–19.3)
**nor** the modern `TTI_ALL8` (`0x5e`) request this driver builds for 10g+. 8i
answers the same `0x5e` function code but expects the **9.2-era OALL8 layout** —
sending the modern one draws an **empty DATA packet followed by a hangup**.
Reverse-engineered from the 9.2-client → 8.1.7 trace; the request is fixed apart
from the `TTI_FUN` sequence byte and the SQL length:

```
03 5e <seq>  61 80 00 00 00 00 00 00  01 <ub4le sqllen>
01 0c 00 00 00 00 01 00 00 00 00 01 00 00 00 00  <12×00>
01 <SQL as pre-10g chunked string>
01 <27×00> 01 <19×00>          # bind-count / define-count markers (none)
```

The SQL length rides twice. In the **header** it is a `0x01` marker + a **fixed
4-byte little-endian** count (8i is x86) — **not** `encode_sb4`. The variable-width
`encode_sb4` is byte-identical for a length ≤ 255 (`01 <len> 00 00 00`) but one
byte longer at ≥ 256 (`02 01 1c …` vs `01 1c 01 00 00`), which shifts the whole
request and the server rejects it with **ORA-01009** (#391). The SQL **text**
follows as a pre-10g chunked string (`encode_chr`: a plain length byte up to 64
bytes, else the `0xFE` + 64-byte-chunk form). No define block is sent — the column
layout comes back in the describe (§19.10).
The execute returns only the **first row batch** and never signals EOF on the
execute itself; the remaining rows are pulled by the **fetch** OALL8 (option
`0x40`, the server-assigned cursor id, no SQL, a `ub4` row count), repeated until
a batch comes back empty (the 8i equivalent of ORA-01403):

```
03 5e <seq>  40  <ub4 cursor>  00×8  01 0c 00×4 01 00×5 <ub4 count>  00×12
01 00×4 0f  00×23 01 00×19
```

Encoders: `encode_8i_oall8_query` / `encode_8i_oall8_fetch`. IN binds are §19.11;
The whole 8i surface (login + query/DML/PL/SQL/LOB) is ported to both the sync
(`OracleConnect`) and async (`AsyncOracleConnect`) clients.

**Charset.** Unlike 9i+, 8i does **not** negotiate an AL32UTF8 session (its DTY
declares WE8ISO8859P1), and its national charset is **also WE8ISO8859P1**, not
Unicode — 8i predates Unicode `NCHAR`. So **all** 8i char data — `VARCHAR2` /
`CHAR` / `NVARCHAR2` / `NCHAR` / `LONG` — arrives in **Latin-1**, regardless of
csform. The 8i row decoder flags this (`set_decode_8i`) so `_string_charset`
picks Latin-1 rather than the UTF-8 (csform 1) / UTF-16BE (csform 2) a modern
session would use; without it non-ASCII `VARCHAR2` mojibakes and `NVARCHAR2` /
`NCHAR` read as garbage (#366).

### 19.10 Oracle 8i response — the fixed-field DCB describe and 4-byte RXD (#244)

The reply is fv2-style but its own shape. The **describe** is a `TTI_DCB` (`0x10`)
block whose fields are **fixed-width and little-endian**, as OCI's are — not the
variable-width integers the 10g+ DCB (§4.2's `decode_token_dcb`) reads, so the
modern decoder sees `num_columns = 0` and desyncs. It is 10g's describe head,
then 9i's columns (§19.1, `_O7_DESCRIBE_COLUMN`) at those widths, then the
describe time (`_O8I_DESCRIBE`, #2284; `decode_8i_dcb_describe`):

```
10                    TTI_DCB
ub1 25, 25 bytes      the describe-info preamble (a cursor uuid and a time)
ub4 max_row_size      the select list's widest row
ub4 count             the columns
ub1 0x33              when there are columns
per column, the OAC at OCI's widths and the name:
  ub1 data_type       1 VARCHAR2, 2 NUMBER, 96 CHAR, 112 CLOB, …
  ub1 flags           0x80 for VARCHAR2 and CHAR
  ub1 precision, ub1 scale (signed: FLOAT is 126, -127)
  ub4 max_length      the buffer: 22 for a NUMBER, 4000 for a VARCHAR2(4000)
  ub4 max_array, ub4 cont_flags, ub4 toid_length (and the toid when set)
  ub2 version, ub2 charset (31 = WE8ISO8859P1; 0 for NUMBER), ub1 csfrm
  ub1 null_ok         0 NOT NULL, 1 nullable
  ub1 name_bytes, ub4 name_chars, then the name: a ub1 length and the text
  ub4 type_schema_length, ub4 type_name_length (and the names when set)
ub4 7, ub1 7, 7 bytes the describe time, a DATE
```

Read from 14 describes of a live 8.1.7. Read before as big-endian words, the
flags, precision and scale bytes and the first byte of `max_length` made one
"size field", so a column of 256 bytes or more was described by its low byte:
a VARCHAR2(4000) as 160 (#2324).

The **rows** follow as row headers (`TTI_RXH`, `06`) and rows (`TTI_RXD`, `07`).
The row header is 9i's (§19.2, `_O7_RXH` and `_O7_VECTORS`) at 8i's fixed
widths, 18 bytes when it has no vector: flags, `ub2` columns sent, `ub2`
iteration, `ub2` iterations (100 in a fetch), `ub2` buffer length, then the
bit vector and the rowid, each a `ub4` length and a value. Each cell is a value
and a **fixed 4-byte trailer**, an `sb2` indicator and a `ub2` return code
(`_O8I_CELL`):

```
value cell        <value> 00 00 00 00      a ub1 length, or past 252 bytes fe,
                                           chunks with ub1 lengths, 00
NULL              ff ff 00 00              the trailer alone; a length is never ff
LONG, LONG RAW    fe 0a <10 bytes> 00 ...  chunked however short;
                  00 ff ff 7d 05           NULL: a bare zero, return code 1405
CLOB, BLOB, BFILE ub4 length, the locator as a value, the trailer;
                  00 00 00 00 ff ff 00 00  NULL
ROWID             0e, the rowid, the trailer; NULL 00 and the trailer
UROWID            ub2 length, the logical rowid as a value, the trailer;
                  00 00 ff ff 00 00        NULL
```

Read from 47 row streams of a live 8.1.7. Values are **WE8ISO8859P1**
(latin-1). The rows end in the call's status (§19.12), with or without the RPA
in front of it; its **cursor id** drives the fetch loop. Decoders:
`decode_8i_exec_response` / `decode_8i_cursor_id`.

**Rejected SELECT (#384).** When the server rejects the statement (bad table, bad
column, …) the execute reply is a **`TTI_OER` (`0x04`)** error status, *not* the
`TTI_DCB` (`0x10`) describe: the status (§19.12) alone, its message the server's
`ORA-NNNNN: …` text (`decode_8i_terminal_error`). `execute_query` checks the first
byte and raises the mapped ORA error; feeding an OER to `decode_8i_dcb_describe` (which assumes a
describe header) overruns and raises a meaningless `IndexError`.

**A describe wider than a packet (#1226).** 8i caps each DATA packet at the SDU
(2 KB here) with no end-of-message flag, so a wide select list continues in the
next packet with nothing saying so. The 45 columns of `V$SESSION` describe to
2776 bytes: a first packet of 2009, then 767 more. Whether the client sees
them apart depends on timing. The transport returns every packet that has
already arrived in one read, so a 60-column table's describe usually comes
back whole. `V$SESSION` is computed live, and the server pauses between its
packets. The decoder raises `Truncated` when a column or the trailer runs past
the data, and the reader (`O8iDialect._recv_describe`) reads the next packet and
decodes again, as the row reader does (#849).

**A describe cut short by an error (#1226).** A statement that fails as it
*executes* can stop the describe partway. 8i sends what fitted in the first
packet, then the error as a `TTI_OER` of its own (`04 <ub4 rows> <ub4 LE code>
… ORA-NNNNN: …`), and nothing more: the rest of the describe never comes.
Captured with `SELECT * FROM v$session WHERE sid = sys_context('userenv',
'sid')`, which 8i refuses with ORA-02003 (USERENV has no SID before 10g). Just
as often it refuses up front with a bare OER instead. So when the continuation
of an incomplete describe opens with `TTI_OER` and carries an `ORA-` text, that
error is the answer. A reader that waits for more of the describe hangs for its
read timeout.

**Duplicate-column compression.** Like the modern `TTI_BVC`, 8i omits a column
from the RXD when it repeats the previous row's value — but 8i carries the
**column bit vector inside the RXH**, its `ub4` length and the vector, rather
than as a separate token. LSB = column 0; an **unset** bit means "repeat the
previous row", so the RXD only carries the set-bit columns (e.g. a 12-column
row with 8 columns sent has the vector `02 87 0f`, and the header's column
count is 8). The vector applies to the one row after its header. Because 8i
fetches one batch per round trip, a row can repeat a column from the
**previous batch's** last row, so `decode_8i_exec_response` threads the last
decoded row across calls. Missing this desyncs the RXD as soon as two
consecutive rows share a column value.

**ROWID / UROWID (#385).** These are **not** length-prefixed DALCs. A physical
**ROWID** (type 11) is a byte (`0e`; 0 = NULL), the rowid at fixed widths as in
the status (§19.12) — data object (ub4 LE), relative file (ub2 LE), an unused
byte, block (ub4 LE), slot (ub2 LE) — then the trailer (`_O8I_ROWID_CELL`); it
renders to the extended base64 string (matches `ROWIDTOCHAR`), e.g.
`33 68 00 00 05 00 00 bb 00 00 00 00 00` → `AAAGgzAAFAAAAC7AAA`. A **UROWID**
(type 208, e.g. an index-organized table's logical rowid) is a `ub2` length,
the logical rowid as a value (a `ub1` length and the bytes), then the trailer
(`_O8I_UROWID_CELL`); it renders as the `*`-prefixed base64 form
(`urowid_to_string`). Read as an indicator byte, a reserved byte and a `ub1`
length, a set UROWID decoded right and a NULL one, `00 00`, left a byte unread,
and the fetch then failed with ORA-01002 (#2328). Both are usable as binds (a
ROWID/UROWID string binds straight back into `WHERE ROWID = :r`). Note:
`ROWIDTOCHAR(ROWID)` on an IOT raises ORA-01410 on 8i, so the UROWID reference
comes from the raw value, not that function.

### 19.11 Oracle 8i IN binds — the 9.2-era bind section (#359)

Parameterized statements ride the same OALL8 (§19.9) with three header changes
and a bind section appended after the trailer. The execute **option byte** gains
bit `0x08` (`0x61` → `0x69`), and the al8i4 count block carries the **iteration
count** (1) and the **bind count**:

```
… 01 0c 00 00 00 00 01 00 00 00 00 01 00 00 00 00   00 00 00 01 <nbinds> 00×7 …
```

After the trailer come **all bind OACs**, then a single `0x07` value-section
marker, then **all bind values** in order (so N binds = N descriptors, one `0x07`,
N values — not interleaved). Each bind OAC is the 25-byte descriptor mirroring the
describe column OAC (§19.10):

```
ub1  data type (1 VARCHAR2, 2 NUMBER, 12 DATE, 23 RAW)
ub1  flag 0x03    ub2 reserved(0)
ub2-LE  max_size  (22 for NUMBER, 7 for DATE, value length otherwise)   [+4]
13 bytes reserved
ub4be  character set (31 for char types, 0 otherwise)                   [+19]
ub1 reserved(0)  ub1 csform (1 for char types, 0 otherwise)
```

A ROWID / UROWID `Var` declares type 1 with `max_size` 5267 and carries the
rowid's text, as on 9i and 10g+; declared as its own type, the bind drops the
session (#1399).

`max_size` is a **little-endian ub2 at offset +4** (8i is x86). For values ≤ 255
this is byte-identical to a big-endian 3-byte field (so short binds worked
either way), but a bind of **≥ 256 bytes** needs the little-endian form — a value
sent with `max_size` in the wrong bytes is mis-read as a LONG and rejected with
**ORA-01461** (#375). Values > 64 bytes ride the chunked string form (`0xFE` +
64-byte chunks), same as any long char value.

Each value is a plain DALC (`encode_token_rxd`): NUMBER 5 → `02 c1 06`, `'SYS'` →
`03 53 59 53` (WE8ISO8859P1), a **NULL** bind → the empty DALC `00`. The encode
field version is pinned to fv2 so the chunked-string / pre-23ai value forms are
used regardless of any concurrent connection. Encoder: `encode_8i_oall8_query`
(the `Binds` argument), with `_encode_8i_bind_oac` / `_encode_8i_bind_value`.

### 19.12 Oracle 8i DML / DDL and transaction control (#360)

INSERT / UPDATE / DELETE and DDL ride the **same OALL8** as a SELECT (§19.9,
binds §19.11) — the whole option word derives from the **statement type** carried
at trailer offset +28 (`1` SELECT, `2` UPDATE, `3` DELETE, `4` INSERT, `5` CREATE,
`6` DROP, `7` ALTER, `0` transaction control):

- **option byte** = `0x21` base, `+0x40` for a query (only SELECT fetches),
  `+0x08` with binds; the following byte is `0x80` for a cursor statement and
  `0x00` for `COMMIT` / `ROLLBACK`.
- **trailer exec flag** (offset +4) is `0` for a query (execute deferred to the
  fetch) and `1` otherwise.

There is no describe or fetch. The response is an RPA, then the status. The RPA
(`_O8I_RPA`, 23 bytes) is `08`, a `ub2` count (4), that many `ub4`s, the third the
statement's cursor, and four zero bytes, where 10g sends two `ub2` lengths. An
error, and a fetch that ends with ORA-01403, sends the status alone.

The status (`_O8I_STATUS`, #2284) holds **the same fields as 9i's short status
(§19.2), at fixed widths and little-endian** — 8i is x86/Windows, so they ride
native-endian:

```
04                    TTI_OER
ub4 rows              the affected-row count (300 = 2c 01 00 00)
ub2 code              the ORA code (ORA-01403 = 7b 05)
ub2 array_error, ub2 array_error_2
ub2 cursor            the statement's cursor (256 = 00 01, #2285)
ub2 position          the error's offset in the SQL text
ub1 sql_type          the command code: 2 INSERT, 3 SELECT, 6 UPDATE, 7 DELETE,
                      12 DROP TABLE, 44 COMMIT, 45 ROLLBACK, 47 a PL/SQL block
ub1 fatal, ub1 flags, ub1 cursor_options, ub1 upi_param
ub1 warnings          0x10 an UPDATE / DELETE without WHERE, 0x20 a compile
                      error; 0x01 with any
rowid                 ub4 data object, ub2 file, a reserved byte, ub4 block,
                      ub2 slot: the row a DML touched (#1079)
ub4 os_error, ub1 statement, ub1 call (it counts up), ub2 padding
ub4 iterations
ub2 oerrdd length     13 after a DML, then a ub1 13 and the rowid in its
                      extended form: 01, the object, file, block and slot
                      big-endian
ub4 x 3               the counts of the batch-error arrays; 8i has no array DML
message               when the code is set: a ub1 length and the text, or past
                      252 bytes `fe`, chunks with ub1 lengths, `00` (#2322)
```

Read from 311 statuses of a live 8.1.7 with nothing left over. Captured on
8.1.7 for an INSERT (object 73009, file 5, block 207, slot 2):
`… 04 01 00 00 00 … 02 00 00 00 00 00 31 1d 01 00 05 00 00 cf 00 00 00 02 00 …`.
As on 9i, a statement that touched no row leaves the previous rowid in place,
and the zero row count drops it. A failed statement is an error with no row
count. 8i marks no packet as a reply's last, so the reader of a fetch counts a
status as whole only once every field has its bytes, the message too
(`o8i_terminal_complete`, #2280).

**COMMIT / ROLLBACK** have no modern `TTI_COMMIT` / `TTI_ROLLBACK` on 8i; they
ride the OALL8 as ordinary statements (type `0`). Encoder: `encode_8i_oall8_dml`
(over the shared `_encode_8i_oall8`); decoder: `decode_8i_dml_response`;
statement classification: `o8i_stmt_type`.

### 19.13 Oracle 8i anonymous PL/SQL blocks — IN binds (#361)

`BEGIN` / `DECLARE` blocks ride the same OALL8 (statement type `8` / `9`) with a
distinct option word: the byte after the option is `0x00` (or `0x04` when the
block has binds), and the **next byte is `0x04`** — the PL/SQL-block marker
(`21 00 04` for a no-bind block, `29 04 04` for a bound one). Unlike 9i, 8i sends
the **IN bind values inline** (§19.11), so a block executes in a **single round
trip** — no separate bind-value exchange.

The reply is the bind **prompt** (`0x0b`, informational — it echoes each bind's
direction: `0x20` IN, `0x10` OUT, `0x30` IN OUT) followed by the RPA + OER, all
in one packet; a no-bind block skips straight to the RPA + OER. A block that fails
(compile or runtime, e.g. ORA-06550 / PLS-00201) gets its status alone, no prompt,
and its error is the status's (§19.12). OUT / IN OUT binds — whose returned values ride an RXD inside that reply —
are §19.14. Driver: `_execute_8i_block`.

### 19.14 Oracle 8i PL/SQL OUT binds — callproc / callfunc (#362)

An OUT (or IN OUT) parameter is a `Var` bind. In the **request** it declares its
type + return-buffer size in the OAC (§19.11), and its slot in the value section
carries the fixed OUT placeholder **`fd 01`** (an IN OUT bind sends its input
value inline instead). So `callproc('p', [5, y, z])` → `BEGIN p(:1,:2,:3); END;`
with the value section `07 <5> fd 01 fd 01`.

In the **reply**, after the `0x0b` prompt (whose direction bytes are `0x10` for
each OUT), a single `07` RXD carries the returned values in OUT-bind order, each a
value and an `sb2` indicator, with no return code (`_O8I_OUT_CELL`: `02 c1 33 00
00` = 50, `08 proc-out 00 00`, `03 c2 02 08 00 00` = 107; a NULL is an empty
value and `ff ff`), then the RPA + OER. An OUT bind the block never assigned is
`ff` where the value would be and the indicator 3105, `ff 21 0c`
(`_O8I_OUT_UNASSIGNED`), as 9i marks one (§19.7, #801). A reply carrying long
OUT values spans packets — a 4000-character value's is 2009, 2009 and 105
bytes — none marked last, so the reader reads on until the vector, every value
the vector marks OUT and a whole status are there (`o8i_block_complete`, #2334);
read from its first packet alone, it failed about one call in two. `decode_8i_block_out` returns the raw value bytes per OUT bind; the
cursor's `_assign_out_binds` decodes each against its `Var`'s type. `callfunc`
is the same shape with the return value as the first (`:1`) OUT bind.

An **IN OUT** bind (#363) is a `Var` whose value is set: it sends its input value
**inline** in the request (not the `fd 01` placeholder) and its updated value
comes back in the reply's RXD, both in the same single round trip. Its prompt
direction is `0x30`. No extra machinery — the inline value path and the OUT-value
decode above already cover it.

8i's prompt is 9i's I/O vector (§19.7) at fixed little-endian widths
(`_O8I_IOV`, #2284): `0b`, the flags (5), a `ub2` of requests and a `ub2` of
iterations — the binds are `iterations * 256 + requests`, 300 coming as `2c 00
01 00` (#2311) — a `ub4` of iterations this time (1), and eight bytes zero in
every reply measured, where the buffer length and the two vector lengths go;
then the masks. Captured `0b0502000000010000…0010200702c147…` is OUT, IN, then
the one OUT value. Read from 20 live 8.1.7 block replies with nothing left
over. A `Var`
the block only reads gets no value back here either, so the driver takes the OUT
positions from the masks (#1242).

### 19.15 Oracle 8i LOB read — the single TTI_LOBOPS READ (#364)

A LOB column in the row is a **`ub4`-LE `num_bytes`** then a DALC **locator** (86
bytes for a CLOB/BLOB) then the 4-byte trailer — `decode_8i_exec_response` turns
it into a `LOB` the connection resolves after the fetch. **Two latent bugs the
LOB describe exposed:** the DCB header's row width and `num_columns` are `ub4`-LE
(not a 1-byte width + big-endian count) — a CLOB's 4000-byte row width is
`a0 0f 00 00`, so any row ≥ 256 bytes wide (LOB or a wide VARCHAR2) mis-read
`num_columns` before the fix (§19.10).

**NULL vs EMPTY LOB (#387).** `num_bytes` is the locator length (86), *not* the
content size — both a present and an `EMPTY_CLOB()`/`EMPTY_BLOB()` cell carry
`num_bytes = 0x56` and a full locator. A **NULL** LOB is the exception: `num_bytes
== 0` followed **directly** by the 4-byte trailer (`ff ff 00 00`, indicator −1)
with **no locator DALC**. Calling `decode_dalc` on a NULL cell (there is no
locator) eats the indicator's first byte and desyncs every following row, so the
decoder keys on `num_bytes == 0` → `None`, else reads the locator. Reading an
**empty** LOB's content then returns a bare **`0x08`** piggyback with no `TTI_LOB`
(`0x0e`) block — `_lob_read_8i` treats a non-`TTI_LOB` reply as empty (`''`/`b''`)
rather than waiting for a zero-length chunk that never comes.

Unlike 9i's GETLEN + READ pair, 8i reads the whole value in **one** `TTI_LOBOPS`
(`0x60`) READ from offset 1 (§19.17's request, `_O7_LOBOPS` at 8i's widths), its
short amount the chars for a CLOB, bytes for a BLOB — pass a large value to read
it all. The reply is the **shared `0e fe <chunks> 00`** content
form (`decode_fv2_lob_chunks`), possibly spanning packets; CLOB text decodes with
the column charset (WE8ISO8859P1), BLOB stays bytes (`decode_fv2_lob`). Encoder:
`encode_8i_lob_read`; driver: `_lob_read_8i` / `_resolve_8i_lobs`. BFILE is a
follow-up.

### 19.16 Oracle 8i LONG / LONG RAW read — the fetch long-size field (#377)

A LONG (TNS type 8) or LONG RAW (type 24) value rides in the RXD as an ordinary
**chunked DALC** — the `0xFE` marker then one length byte per chunk (up to 255),
ended by a zero-length chunk — so `decode_8i_exec_response` already reassembles
it. The catch is **how much of the value the server sends**, which is governed by
two `ub4` **little-endian** fields in the `encode_8i_oall8_fetch` request:

```
offset 31  ub4-LE  LONG fetch size — max bytes of a LONG/LONG RAW returned per row
offset 49  ub4-LE  rows to fetch this call
```

8i **truncates** the value to the long-fetch-size and does **not** continue one
LONG across fetch round trips (a size of 1000 returns exactly 1000 bytes), so the
driver passes a large cap (`0x7FFFFFFF`) whenever a describe column is type 8/24.
It also drops the row count to **1** for such a cursor — 8i forces single-row
fetches when a LONG is present (`sqlplus` does the same). An earlier encoder
wrote the row count **big-endian** across offsets 28–31; its low byte landed on
the long-fetch-size and capped every LONG at `fetch` bytes (the #377 symptom: a
17-byte LONG read back as 15).

**Multi-packet reassembly.** A LONG larger than the negotiated SDU (2048 by
default) makes the fetch response span several `TNS_DATA` packets, and 8i sets
**no end-of-message flag** — every packet header carries `flags = 0x00`. There is
no framing signal, so the driver accumulates packets and uses the decoder itself
as the completeness test: `decode_8i_exec_response` raises while a value is still
truncated, and a complete response ends on a terminal token (`0x08` piggyback /
`0x04` OER, ≥ 12 bytes for the cursor id). The reader reads until that holds.
Driver: `O8iDialect.execute_query` / `recv_rows`; encoder: `encode_8i_oall8_fetch`.

**Which raise means "read on" matters (#1061).** Only a field that ran **off the
end** means more packets are coming — the codec's explicit `Truncated` (#849),
or an `IndexError` from an older primitive. Any other `DataError` comes from a
message that is already **complete** and holds a value that genuinely does not
decode, and must reach the caller. Treating the whole `DataError` family as
"incomplete" made the reader ask for a packet that was never going to arrive, so
a BC date — valid Oracle data a Python `datetime` cannot hold — hung for the full
read timeout instead of raising. The multi-packet LONG tests above are what
confirm the narrower rule is enough: every short-buffer path raises `Truncated`.
It is the same distinction the Mirror draws when growing a request (§6.2a).

### 19.17 Oracle 8i BFILE read — the native TTI_LOBOPS wire (#401)

A **BFILE** (TNS type 114) is a pointer to an external OS file, not inline LOB
content. `decode_8i_exec_response` turns the column into a `LOB` whose locator
parses into `directory_name` / `filename` (a length-prefixed directory-object
name then file name — e.g. `… 05 "BDUMP" 0c "ORCLALRT.LOG"`), the same as the
10g+ locator.

Reading the bytes is a `TTI_LOBOPS` **FILE_OPEN → GETLEN → READ → FILE_CLOSE**
sequence, natively — no `DBMS_LOB` helper. Every op is 9i's request
(`_O7_LOBOPS`, §19.5) at 8i's fixed little-endian widths (#2284): `03 60 <seq>`,
the source locator's pointer `01` and `ub4` length, the destination's pointer and
length, the short source and destination offsets (`ub4`), the charset,
short-amount and null-LOB pointers, the `ub4` operation, the SCN pointer and
`ub4` length — the "25-byte op middle" of the first reading — then the locator
whole, its `ub2` length and body, and the `ub4` short amount when its pointer is
set — the "trailer". Every request a live 8.1.7 session sends is built that way
byte for byte, and a locator past 252 bytes goes whole, as 8.1.7 reads it
(#2331). Reverse-engineered first from a 9.2 OCI client → 8.1.7 capture
(`OCILobFileOpen/GetLength/Read/FileClose`; `sqlplus` alone shows only the
locator, so the capture came from a linked OCI program):

| op | 25-byte middle (hex) | trailer | reply |
|----|----------------------|---------|-------|
| FILE_OPEN | `00000000000000000000000000000100000100000000000000` | `0b000000` (ub4-LE open mode `0x0b`, read-only) | `08` + **opened locator** + OER |
| GETLEN | `00000000000000000000000000000100010000000000000000` | `00000000` | `08` + locator + **ub4-LE length** + OER |
| READ | `00000000000100000000000000000100020000000000000000` (= the CLOB/BLOB read middle) | ub4-LE amount | `0e fe <chunks> 00` (§19.15) + RPA + OER |
| FILE_CLOSE | `00000000000000000000000000000000000200000000000000` | *(none)* | `08` + locator + OER |

**FILE_OPEN returns an updated locator** with the open flag set (the byte at
locator offset 11 flips `00 → 01`); GETLEN / READ / FILE_CLOSE must use *that*
locator, exactly like the 9i path — so the same `decode_fv2_opened_locator`
extracts it. The replies are 9i's (`_O7_LOBOPS_REPLY`) at 8i's widths: GETLEN's
carries the file length in the `ub4` short amount after the echoed locator
(`decode_o8i_bfile_getlen`). READ's content is the shared
`0e fe <chunks> 00` form (`decode_fv2_lob_chunks`), so a large file streams across
packets and terminates on the zero-length chunk. A missing file surfaces the
server's `ORA-22285` at FILE_OPEN, as 8i's status alone (§19.12); a 9i OER
reader finds nothing there (#1103).

The fetch does not read the file: the row hands back the `LOB`, and its
`read()` / `aread()` runs this sequence, as on 9i (§19.8) and 10g+. Reading at
fetch time made a BFILE naming a missing directory fail the SELECT (#1103).

Encoders: `encode_o8i_bfile_open` / `encode_o8i_bfile_getlen` /
`encode_o8i_bfile_close` (+ `encode_8i_lob_read` for the READ), all built by 9i's
`_encode_o7_lobop` with the 8i codec. Driver: `O8iDialect.bfile_read`, reached
from `bfile_read_native` (sync + async). This replaced an earlier `DBMS_LOB`
temp-BLOB helper, removing its `CREATE PROCEDURE` requirement and the stored
function it left in the user's schema — the same win #46 brought to 10g+/21c.

### 19.18 Oracle 9i native OALL8 — the 64-bit thick request form (#716, #790)

9i can speak the same OALL8 (`0x5e`) as 8i, but a native 9.2 OCI client marshals
it in a **64-bit** form. seerdb's ordinary 9i path uses the compact minimal-caps
request (the JDBC-thin form, §19.1–19.8); this native form is an opt-in
(`oall8=True`).

Reaching it needs the **whole native OCI login handshake**, not a pair of
capability bytes. An earlier hypothesis — that `compile_caps[CCAP_FIELD_VERSION]`
= 2 plus a two-byte `runtime_caps` `02 01` (a word-size cap) unlock the 64-bit
form on an otherwise thin login — was **disproven in #790**: on a thin login the
server rejects OALL8 with `ORA-03120` ("two-task conversion routine: integer
overflow") in all four combinations of {cap[7] = 0 or 2} × {32-bit, 64-bit}
encoders, and advertising the word-size cap makes 9.2.0.4 close the connection
after the thin data-type table (see §19.3). The native form is reached only by
the full OCI login: the OCI-form TTI_PRO banner (`<machine>/<os> 2.4.xx`, which
the 9.2 server parses to identify the platform), the compact native data-type
negotiation, and the OCI `OSESSKEY`/`OAUTH` login envelope — with
`CCAP_LOGON_TYPES` forced to 0 so the server issues the 8-byte DES O3LOGON key
seerdb authenticates (the native sqlplus 16-byte key's proof is a separate,
deferred variant). Once that session is up, the 64-bit data form below is what it
speaks.

The request is the **same token stream** as the other tiers — same opcode, same
SQL text, same bind values — differing only in two field widths. Measured across
captures (`~/o8i/captures/phaseA_thick_vs_thin_11g.md`), the width ladder is:

| form | pointer field | length field | source |
| --- | --- | --- | --- |
| thin (10g+ seerdb) | `01` (1 byte) | ub1 / ub2 compact | live |
| 8i native (§19.9) | `01` (1 byte) | ub4 (4-byte LE) | `ret_8i.pcap` |
| 11g thick (64-bit OCI) | 8-byte `0xFE` sentinel | ub4 (4-byte LE) | `capA_thick_11g.log` |
| **9i native (64-bit)** | **8-byte `0xFE` sentinel** | **ub8 (8-byte LE)** | `ret_9i.pcap` |

The two widths are independently negotiated (11g thick pairs 8-byte pointers with
ub4 lengths); 9i native is the widest rung — both pointer and length are 64-bit.
The pointer slots carry the client's heap addresses, which the **server ignores**,
so the encoder writes the `0xFFFFFFFFFFFFFFFE` (`oci.OCI_INDICATOR`) sentinel
instead. The SQL-length anchor makes this concrete: 56 rides as `38 00 00 00`
(ub4) on 8i / 11g-thick and `38 00 00 00 00 00 00 00` (ub8) on 9i.

So the 9i encoder is the 8i encoder (§19.9, §19.11–19.12) with every pointer and
length field widened to 8 bytes and the `0xFE` present-pointer sentinel where the
8i form writes a `01` flag; the SQL text and the bind values (`_encode_8i_bind_value`,
e.g. `07 02 c1 2b` for NUMBER 42) are shared verbatim. Encoders:
`_encode_9i_oall8` / `encode_9i_oall8_dml` / `_encode_9i_bind_oac`. The encoders are byte-verified against a native 9.2 client
(`test_tns_encode.TestO9iOall8Messages`).

**The client's `oall8` dialect (#798).**
- It runs on 8i's OALL8 call sequence, with per-version hooks where 9.2 differs.
- Each 9.2 frame is 8i's wire schema at the 64-bit widths, or the shared OCI
  schema.
- It covers what the default 9i path covers, sync and async: SELECT, DML / DDL,
  PL/SQL with IN / OUT binds, array DML, LOBs, BFILE and LONG, and REF CURSOR OUT
  binds.
- It also covers object, collection, XMLTYPE and `CURSOR()` columns. For these,
  the 9.2 describe has a ub4 type-name length, one `0x4b` byte before the first
  column, and a trailer with no lead byte. It carries the dictionary type codes
  58 / 121 / 122 / 123, which map to `TNS_TYPE_ADT`.
- Over the 9.2 bed it passes the integration suite except the cursor-cache
  tests: the dialect keeps no cursor cache.
- One server difference: a bare `CONNECT BY LEVEL` on `dual` returns one row over
  the native form, as it does to sqlplus 9.2, but every row through a subquery.

**It stays an opt-in (#799).** The client must choose the dialect before the
server identifies itself: the OCI-form banner is in its first TTI_PRO, and
nothing earlier tells an 8i server from a 9i one. The default 9i path is
byte-identical with or without this code.

## 20. Oracle 23ai field version 24 — fast-auth + the fv24 framing (#89)

Column **annotations** are only delivered when the client advertises a TTC
field version ≥ 18. But advertising fv ≥ 18 changes both the login and the data
path; the legacy forms are rejected (ORA-03146 / ORA-03120) or hang. seerdb
reaches field version 24 — the 23ai maximum — and decodes annotations.

### 20.1 Gating and the protocol version

seerdb keeps its **CONNECT packet at protocol version 313**, deliberately
below the end-of-response era (≥ 319). At 319 a 23ai server requires
end-of-response response framing and closes the connection if the client clears
that capability bit; staying at 313 sidesteps that whole layer while still
reaching fv24. At 313 the ACCEPT carries no fast-auth flag, so seerdb gates on
the **server's own field version** taken from its TTI_PRO reply (23ai advertises
27): after a normal PRO exchange, if `min(client, server) > 17`, switch to
fast-auth. The default `field_version` is the fv24 constant; older servers
negotiate it down (21c→16, 11g→6, 10g→4, 9i→2) and keep the legacy handshake.

### 20.2 FAST_AUTH (`0x22`)

The legacy three-message handshake (PRO, DTY, OSESSKEY as separate packets) is
rejected at fv ≥ 18. Instead the three are bundled into one TNS DATA packet:

```
0x22  ver=1  SERVER_CONVERTS_CHARS(0x01)  flag2=0
<PRO message>
charset(ub2)=0  flag(ub1)=0  ncharset(ub2)=0
ttc_field_version byte = 19_1_EXT_1 (13)      # note: not 24 here
<DTY message>                                 # its caps array still carries fv24
<OSESSKEY (auth phase-one) message>
```

The server replies with the three responses concatenated (PRO + DTY + the
auth-challenge RPA). The challenge RPA is located by scanning for the TTI_RPA
whose decode yields a session key (the DTY datatype table contains `0x08` bytes,
so a naive token scan mis-hits), then handed to the normal phase-two path. The
23ai server tolerates the duplicate PRO that the bundle re-sends.

**The Mirror serves this too** (server side): it advertises fv24 (from the
backend, § `Backend.field_version`), and when the packet after its PRO reply is a
FAST_AUTH (`0x22`) rather than a bare DTY it unbundles the OSESSKEY — the tail
`03 76` message, located and validated by `find_fast_auth_osesskey` the same way
the client finds the RPA — authenticates, and replies with the PRO + DTY replies
+ the auth challenge as one packet (`encode_fast_auth_reply`), then runs the
existing phase-two AUTH. The fv24 OAUTH header (§20.3) is parsed in
`_parse_fun_auth`. (The fv24 *query* path — §20.4 — is a separate increment.)

Normally the client sends a bare PRO first (ACCEPT → PRO → PRO-reply → bundle)
purely to learn whether the negotiated field version reaches the fast-auth
threshold. With the opt-in **negotiation cache** (#438), a reconnect to a target
whose prior login recorded a fast-auth field version skips that bare PRO and
sends the bundle straight after the ACCEPT — one round trip fewer. If the cached
value is stale (the server changed), the bundle is rejected; the client then
invalidates the entry and retries a full negotiation. This changes only the
client's packet *sequence*, not any wire format.

### 20.3 Phase two (OAUTH) and changepassword

At fv > 17 the OAUTH header replicates oracledb byte-for-byte: the has-user
pointer byte is `0` followed by an extra `0x01`, the logon mode gains `0x20000`,
the username is still sent length-prefixed, and the call carries the session
pairs the server now requires (`SESSION_CLIENT_CHARSET`,
`SESSION_CLIENT_DRIVER_NAME`, `SESSION_CLIENT_VERSION`, `AUTH_ALTER_SESSION`,
`AUTH_CONNECT_STRING`). changepassword is the same TTI_AUTH shape (extra leading
byte + `0x20000` logon mode); without it the server returns ORA-03120.

### 20.4 The fv24 data path

Every TTI **function** message (execute, fetch, commit/rollback, LOB ops,
logoff) gains **one extra pointer byte after the sequence number** — oracledb's
`_write_function_code` at fv24. Omitting it desyncs the call (ORA-03146 /
ORA-03120, or a hung read on the continuation fetch). This is centralised in
`_fun_header`.

The **execute** carries three more fv24-only changes:
- the prefetch-buffer-size field (the first SELECT's `0xffffffff` long-fetch
  sentinel) must be `0`, or the server overflows (ORA-03120);
- a SELECT/fetch execute sets the `0x40` options bit and `al8i4[9] |= 0x8000`
  (query flags; on a DDL/DML execute these give ORA-03137 `kpoal8Check-5`).

### 20.5 Per-column annotations and vector descriptor

At fv > 17 each column's describe (DCB) appends, after the SQL-domain fields,
its **annotation map** and a **vector descriptor**:

```
ub4 num_annotations
if num_annotations > 0:
    ub1 pointer
    ub4 num_annotations            # repeated
    ub1 pointer
    for each pair:
        str key  (ub4-counted DALC)
        str value
        ub4 flags
    ub4 flags                      # trailing
ub4 vector_dimensions
ub1 vector_format
ub1 vector_flags
```

Both must be consumed or the row stream desyncs (it surfaces as an unknown token
`0x7e`). The annotation map is decoded into the column metadata and exposed as
`cursor.annotations` — a list aligned with `cursor.description`, one `{name:
value}` dict per annotated column (`''` value for a name-only annotation) or
`None` for an unannotated column.

For a native `VECTOR` column the descriptor's `vector_dimensions` (declared
dimension count, `0` for a flexible `VECTOR`) and `vector_format` (element
format: `2` FLOAT32, `3` FLOAT64, `4` INT8, `5` BINARY; `0` flexible — the same
codes as the value image's element type, §18) are kept and exposed on the
`cursor.description` entry, which is a `FetchInfo` (a 7-tuple subclass with
`.vector_dimensions` / `.vector_format` attributes, oracledb parity). Both are
`None` for a non-VECTOR column or a pre-23.4 server (which sends no descriptor).
`vector_flags` bit `0x01` marks a flexible format and `0x02` a sparse column.

**The Mirror serves the fv24 data path too** (§20.4–20.5): its function-message
parsers (`parse_exec`, `parse_fetch`, `parse_lobops_request`, `peek_exec_cursor`)
skip the extra token byte after the sequence at fv > 17 via `_skip_fun_header` —
without it every field mis-aligns and binds are dropped (the backend then sees
`:1` unbound → ORA-01009). Its describe (`_encode_dcb_column`) carries the
column's SQL domain (schema + name, two counted strings, from fv 17) and appends
its annotation map and the vector descriptor (dimensions / format / flags, from
the column's own vector metadata) at fv > 17, which the client consumes or the
row stream desyncs. The map is the count, a pointer byte, the count again, a
pointer byte, then key / value / ub4 flags per pair and a trailing ub4 flags; an
empty map is a bare count of 0. Both readers skip the pointer bytes and flags, so
the Mirror writes `01` and `0`. A backend supplies the domain and annotations on
`ColumnMeta`, and the passthrough relays its upstream's (#1082); python-oracledb's
`test_4361` / `test_6347` read them through it. Validated end to end: the
full integration suite passes through the Mirror in front of a live 23ai server
at fv24.

### 20.6 Token auth — OAuth2 / OCI IAM (#125)

Token auth (for Autonomous Database / OCI) **replaces** the O5LOGON
challenge/response entirely: after PRO/DTY the client sends *no* OSESSKEY and no
password. There is no session-key exchange, no `ConnKey`, and no server proof —
just a single `TTI_AUTH` (func `0x73`) message, sent where OSESSKEY would be,
with no username, logon mode `NoNewPass` (`0x1`), and the key/value pairs:

- `AUTH_TOKEN` — the JWT (always).
- `AUTH_HEADER` — OCI IAM only: `date:<RFC 1123 GMT>\n(request-target):<service>\nhost:<host>:<port>`.
- `AUTH_SIGNATURE` — OCI IAM only: base64 of an RSA-SHA256 / PKCS#1 v1.5
  signature over `AUTH_HEADER`, proving possession of the key paired with the
  token. (OAuth2 / DB tokens are bare — `AUTH_TOKEN` only, no signature.)

The server replies with the auth **result** RPA carrying `AUTH_VERSION_NO` +
`AUTH_SESSION_ID` and **no `AUTH_SVR_RESPONSE`** — the client recognises a
proof-less result (a `TTI_SESS` challenge always carries `AUTH_SESSKEY`; a result
carries `AUTH_VERSION_NO`) and authenticates without validating a proof.

Because the RSA signature is ~344 base64 bytes, this is the first auth pair whose
value exceeds 252 bytes, so `encode_kv` uses the chunked
`write_bytes_with_length` form (the `254` marker + ub4-length chunks) that the
short single-byte-length form could not carry.

Validated by a client↔Mirror round-trip (the Mirror verifies the IAM signature
against a configured public key); the real ADB path needs cloud infra and is
untested. Client + Mirror, both variants, sync + async.

## 21. SQL OBJECT / ADT decode (#115)

A SQL object (ADT) column has TNS data type **109** (`TNS_TYPE_ADT`). Decoding a
value is **two-phase** (mirrors python-oracledb `base.pyx _process_column_data`
→ `read_dbobject`): the row carries the object's serialised *image*, but the
*attribute layout* needed to walk it lives in the type, not the row. The framing
and image below are identical across 10g/11g/21c/23ai (fv 4/6/16/24) — verified
live; there is no field-version-specific variation.

### 21.1 Describe — the type identity

In the per-column `TTI_DCB` (§6.4) an object column carries the type's **16-byte
OID** (the `OidLen > 0` branch, previously skipped) and, in the trailing
schema / type-name fields, the type's **owner** and **name** (e.g. `PYO` /
`ADDR_T`). seerdb stashes these on the column metadata (`type_oid`,
`type_schema`, `type_name`) so the row decoder can find the attribute layout.

### 21.2 Row value framing (`read_dbobject`)

The object value in the `TTI_RXD` is **not** a plain DALC; it is:

```
bytes_with_length   type OID
bytes_with_length   object OID
bytes_with_length   snapshot                 (skipped)
ub2                 version                  (skipped)
ub4                 image-present gate        (0 ⇒ NULL object, no image)
ub2                 flags                    (skipped)
bytes               packed image             (its own length prefix)
```

The image is a **self-delimiting blob** — a 1-byte length (or the `0xFE` chunked
form), *not* `gate` raw bytes; the `ub4` gate only signals whether an image
follows (a NULL object stops after the flags). Reading the gate count as the
image length is off by the blob's own length prefix and desyncs the next row.
This framing needs no attribute layout, so seerdb reads it into an
`ObjectImage` placeholder during row decode (keeping the stream in sync) and
resolves it after the fetch.

**The chunked form follows the field version (#1261).** An image longer than
252 bytes is `0xFE` followed by chunks and a zero-length terminator, and each
chunk's length has the width every other chunked value uses (§6.4, LONG): **one
byte before 12.1, a `ub4` from 12.1**. A live 11g sends a 312-byte image as
`fe ff <255 bytes> 39 <57 bytes> 00`. Reading those lengths as `ub4`s on 10g /
11g lost the chunk boundaries: a 300-character attribute decoded as one
character, silently, and an object with three LOB locators (322 bytes) desynced
the row (`no decoder for response token …`). The same width rule applies to
every `bytes_with_length` a Mirror writes (a long error message, say). Token
auth is the exception: it exists only on 12.2+ servers, so its long values
always go out in the `ub4` form, whatever the login has negotiated so far. The
login-phase AUTH and change-password messages carry long values too (an
encrypted 1500-character password), and are encoded at the session's negotiated
version. They had taken whatever an earlier execute left, and a 10g / 11g
server answered `ORA-03120` (#1090).

The phase-one session message (OSESSKEY) is encoded at the negotiated version
too. Its program, machine and osuser values can exceed 252 bytes. It used to
take whatever an earlier connection had left in the thread, or a default below
12.1. So the first login in a process, or any login after an async one, sent
one-byte chunk lengths to a 12.1+ server, which answered `ORA-03120: two-task
conversion routine: integer overflow` (#1816).

### 21.3 The packed image

The image is the attributes serialised length-prefixed in declaration order
behind a short header (python-oracledb `DbObjectPickleBuffer.read_header`):

```
ub1   flags          (0x80 IS_VERSION_81 | 0x04 NO_PREFIX_SEG | 0x10 IS_DEGENERATE)
ub1   version
len   image length    (1 byte, or 0xFE + 4-byte BE; skipped)
[ if not NO_PREFIX_SEG: len prefix_seg_length + that many bytes  (skipped) ]
per attribute, in declaration order:
    len  value length  (0x00/0xFF ⇒ NULL, 0xFE ⇒ 4-byte BE length, else the byte)
    <value bytes>      (the scalar's normal on-wire encoding — §11 decoders)
```

For `ADDR_T(street VARCHAR2, zip NUMBER, code CHAR)` = `('Main St', 12345, 'US')`
the image is `84 01 13 | 07 "Main St" | 04 c3 02 18 2e | 02 "US"` (flags `0x84`,
version 1, length `0x13`; then a length-prefixed VARCHAR2, NUMBER and CHAR). Each
attribute value is the same encoding the column form uses, so the existing
scalar decoders (§11) apply unchanged. `IS_DEGENERATE` (object stored in a LOB)
raises `NotSupportedError`.

That includes the character set (#1433). An `NVARCHAR2` / `NCHAR` attribute, or
a collection of them, carries **AL16UTF16** (UTF-16BE) in the image, as a
national column does. Everything else carries the session's AL32UTF8. Measured
on 23ai: `N'žába 猫'` stored correctly dumps as 12 bytes
(`01 7e 00 e1 00 62 …`). An image that writes the attribute as UTF-8 stores its
10 UTF-8 bytes in their place, a different 5-character string. The server takes
the bytes as they come, and seerdb read its own UTF-8 back as the right text, so
only `LENGTH` / `DUMP` on the server or another client sees the corruption.

Three members are **not** in their column form (#1607). A `BOOLEAN` attribute
(23ai's SQL BOOLEAN, or a PL/SQL record's), and a PL/SQL record's `PLS_INTEGER`
/ `BINARY_INTEGER` field, is **length 4 and a big-endian 32-bit integer**:
`04 00 00 00 01` for TRUE, `04 ff ff ff d3` for -45. That is neither a NUMBER
nor the `01 01` a BOOLEAN bind is. A NULL one is `0xFF` like any scalar.
python-oracledb packs them this way (`_pack_value`, and `read_*` with
`from_dbobject`). Their dictionary names say which they are:
`ALL_PLSQL_TYPE_ATTRS` names the integers `PL/SQL PLS INTEGER` and
`PL/SQL BINARY INTEGER`. Measured on 23ai with a record `(NUMBER, VARCHAR2,
DATE, TIMESTAMP, BOOLEAN, PLS_INTEGER, BINARY_INTEGER)`: a record bound with
`FALSE, 21, -5` in these three fields reads back in PL/SQL as `false, 21, -5`,
and an OUT record filled with `TRUE, 45, 10` decodes as that. A PL/SQL index
table of `BOOLEAN` keyed 1..4 with three TRUE elements counts 3 in a loop over
it.

### 21.4 Attribute layout (data-dictionary)

The ordered layout is fetched from `ALL_TYPE_ATTRS` (`attr_name`,
`attr_type_name`, `length`, `precision`, `scale`, `character_set_name`
`ORDER BY attr_no`) keyed by
`(owner, type_name)` and **cached per connection** — seerdb buffers the whole
result set on execute (the server cursor is drained), so this extra query runs
safely during row resolution. The SQL type name maps to a TNS type code for the
scalar decoder; a name we don't map (e.g. a nested object type — #117/#118)
leaves the attribute as raw bytes rather than desyncing. `character_set_name`
`NCHAR_CS` marks a national attribute (AL16UTF16, above). The type name can't:
10g lists an `NVARCHAR2` attribute as `VARCHAR2` (and an `NCLOB` one as `CLOB`),
while 11g and later name them, and `CHARACTER_SET_NAME` says `NCHAR_CS` on all of
them. `ALL_COLL_TYPES` does the same for a collection's element (#1433).

Decoded values surface as an `seerdb.DbObject` exposing attributes by name
(`obj.STREET`) / item (`obj['STREET']`), plus `aslist()` / `asdict()`. A NULL
object is `None`. VARRAY / nested table / REF are #117 / #118 / #119; XMLType
(type 109 with no object type) is #124.

### 21.5 Binding an object (#116)

`connection.gettype(name)` returns a `DbObjectType` (the type's 16-byte OID +
version + layout, fetched via `_describe_object_type` and cached);
`typ.newobject(values=None)` builds a settable `DbObject` to bind. The bind is
the exact inverse of the read path (python-oracledb `write_dbobject` /
`_get_packed_data` / `create_new_object`):

- **Bind value** (`_encode_object_bind_value`): `two_lengths(toid)` +
  `two_lengths(b"")` (empty object OID) + `ub4 0` snapshot + `ub4 0` version +
  `ub4 len(image)` + `ub4 TNS_OBJ_TOP_LEVEL` flags + `bytes_with_length(image)`.
  The bind **toid** is constructed: `00 22` + `02 08`
  (`NON_NULL_OID|HAS_EXTENT_OID`) + the 16-byte type OID +
  `TNS_EXTENT_OID` (`00…00010001`) — the same structure seen on read.
- **Image** (`encode_object_image`): `flags 0x84` + `version 1` + the length
  written long-form (`0xFE` + ub4, covering the 7-byte header) + each attribute
  length-prefixed in declaration order (`write_length`: ≤245 a single byte, else
  `0xFE` + ub4). A NULL scalar attribute is a single `0xFF`. Each scalar uses the
  same encoder as its column-form bind. A **temporal** attribute takes its
  width from the attribute's **type**, not from the value, as a declared bind
  does (§11.4b). DATE is 7 bytes. TIMESTAMP and LTZ are 11 bytes, or 7 when the
  fraction is zero. WITH TIME ZONE is always 13. A live 23ai writes its own
  images the same way: `SELECT T(timestamp '2020-02-29 00:00:00')` of a
  one-TIMESTAMP-attribute type comes back `84 01 0b 07 78 78 02 1d 01 01 01`.
  Sizing by the value instead sent a fraction into a DATE attribute, and a zone
  into a TIMESTAMP one, as forms the server read as other values (#1803). The
  encoder **recurses** exactly as the
  decoder frames it (§21.2 / §21.6, python-oracledb `_pack_value`): an object
  attribute of an object rides **inline, no header**; a NULL nested object is the
  atomic-null `0xFD`; a collection attribute — and any object *or* collection
  **inside** a collection — is a length-prefixed **full image** (own header),
  with a NULL collection written as `0xFF`.
- **OAC** (`_encode_object_oac`): the 12c+ bind-metadata layout — `type 109`,
  flag `TNS_BIND_USE_INDICATORS`, precision/scale `0`, buffer size, the type OID
  via `two_lengths`, and the type version (no charset). For an object **value**,
  the buffer size is `0`, as python-oracledb sends it for every object bind. The
  image carries its own length. seerdb used to send the image length here, and
  every server accepted that too. With `0`, 18c, 21c, 23ai and 26ai bind objects
  and collections alike, up to a 400 KB nested table (#1806). A
  `cursor.var(objtype)` keeps a fixed nonzero size for the server to return
  into. This is the **12c+** OAC;
  there is no python-oracledb reference for a pre-12c object-bind OAC (thin needs
  12.1+) and a 12c+ OAC sent to 10g/11g is rejected with a fatal ORA-03106, so
  seerdb **gates object binds on field version ≥ 12.1** (`NotSupportedError`)
  before anything goes on the wire. Object *decode* still works on every tier.

Verified by round-trip (bind via seerdb, read back via §21.1–21.4) on 21c and
23ai, scalar attribute types + NULL attributes, sync + async. Binding a bare
Python `None` to an object column is unsupported (an untyped `None` carries no
type identity); use a typed value. REF binds are #119.

**Server side (the Mirror, #116).** To serve a fetched object *back to* an
external client as a row value, `encode_object_column_value` emits the §21.2
framing — identical to the bind (`_encode_object_bind_value`): the toid, empty
object OID, zero snapshot/version, the image length, `TNS_OBJ_TOP_LEVEL` flags,
then the packed image. A **NULL** object column still carries the whole frame
with a **zero image-length gate** (and the column's type toid from
`ColumnMeta.type_oid` when known) — never a bare `0x00` DALC, which would desync
the reader. `_thin_column_value` / `_encode_oci_value` route a type-109 column
here. The image itself is byte-compatible with python-oracledb: its
`write_header` also writes the length long-form (`0xFE` + ub4), so a client that
would receive Oracle's short-form length accepts the long form unchanged.

### 21.6 Collections — VARRAY / nested table (#117 / #118)

A collection is the same TNS type 109 with the same value framing (§21.2) and
the same bind OAC (§21.5) — only the *type metadata* and the *image body* differ.

- **Type metadata**: a collection (`ALL_TYPES.TYPECODE = 'COLLECTION'`) has a
  single **element type** instead of named attributes, read from
  `ALL_COLL_TYPES` (`elem_type_name`, length/precision/scale, `coll_type`
  `'VARYING ARRAY'` = VARRAY vs `'TABLE'` = nested table, `upper_bound`). The
  `DbObjectType` gains `is_collection` / `collection_type` (VARRAY 3 /
  NESTED_TABLE 2) / `element` / `max_elements`.
- **Image**: the header carries a **prefix segment** (`image_flags` =
  `IS_VERSION_81|IS_COLLECTION` = `0x88`; the shared `read_header` already reads
  and skips it). Then a `ub1` collection-flags marker (`0` for VARRAY / nested
  table), a length-prefixed **element count**, and that many length-prefixed
  element values (decoded / encoded with the single element type, NULL element =
  `0xFF`). A PL/SQL associative array sets **`HAS_INDEXES` (0x10)** in that
  marker and prefixes each element with its key — see §21.6b.
- **Value framing + OAC**: unchanged from §21.2 / §21.5; only the image body is
  collection-shaped. The 12c+ bind gate applies identically.

A fetched collection surfaces as an `seerdb.DbObject` with **list semantics**
(`iter` / index / `len` / `append` / `extend` / `aslist()`), carrying its type so
it can be re-bound; build one with `typ.newobject([...])`. Decode works on every
tier (verified 10g/11g read), bind is 12c+ (round-trip 21c/23ai, sync + async).

**Both VARRAY (#117) and nested table (#118) go through this one path** — they
share the image and bind framing exactly, differing only in `collection_type`
(VARRAY 3 vs nested table 2), so nested-table support needed no new wire code
(verified read 10g/11g/21c/23ai, bind round-trip 21c/23ai).

### 21.6b Associative-array element keys (#1053)

A PL/SQL associative array (`INDEX BY BINARY_INTEGER`, `coll_type`
`'PL/SQL INDEX TABLE'`, §21.6a) sets **`HAS_INDEXES` = `0x10`** in the
collection-flags byte and prefixes every element with its key. The image is
self-describing: the flag says the keys are there, so a decoder need not consult
the type metadata to read the body.

The key is a **4-byte big-endian two's-complement signed** integer, and the
elements ride in **sorted-key order**. Captured from 23ai —
`pkg_TestStringArrays.TestIndexBy`, which keys four strings at -1048576, -576,
284 and 8388608:

```
88 01 51 01 03 | 10 | 04 | ff f0 00 00 | 0d 'First element' | ff ff fd c0 | 0e 'Second element' | …
   header        flags count   key         value               key
```

| raw | signed | unsigned |
|---|---|---|
| `ff f0 00 00` | **-1048576** | 4293918720 |
| `ff ff fd c0` | **-576** | 4294966720 |
| `00 00 01 1c` | 284 | 284 |
| `00 80 00 00` | 8388608 | 8388608 |

**Signed is not a detail.** `BINARY_INTEGER` spans the negative half, and a
server uses it: the two readings agree on every key a dense 1..N array has and
diverge only on a real one, so a round-trip over dense arrays cannot tell them
apart. seerdb read the key unsigned (and *dropped* it, renumbering 1..N on
re-encode) until #1053; an external client then saw a correctly framed image
carrying the wrong numbers.

A collection decoded off the wire must therefore be re-encoded under **its own**
keys. One built locally is keyed **0..N-1**, and an appended element takes the
highest key plus one — starting at **0**, matching the reference client
(`new_index = keys[-1] + 1 if keys else 0`).

**Zero, not one.** PL/SQL written for these arrays indexes from zero — the
ordinary idiom is `for i in 0..a_Value.count - 1` — so a 1-based array makes
`a_Value(0)` a missing key, and a missing key raises NO_DATA_FOUND, i.e.
`ORA-01403`. seerdb keyed locally built arrays 1..N until #1055, and binding one
to any such procedure failed.

Two header details differ between the server's image and seerdb's encoder, with
no known consequence: the server writes the **short** image length (`88 01 51`)
where the encoder always writes the long form (`88 01 FE` + ub4), and its prefix
segment is `01 03` against the encoder's `01 01`.

Note this is a different mechanism from `cursor.arrayvar()` (§26, #122), which
binds an `INDEX BY PLS_INTEGER` parameter as a **bulk array** — `ub4 count` +
values, with no keys at all. The two share the phrase "associative array" and
nothing else.

### 21.6a PL/SQL package-level types live in their own dictionaries (#1030)

A type declared **inside a package** — `PKG_TESTRECORDS.UDT_RECORD`,
`PKG_TESTNUMBERARRAYS.UDT_NUMBERLIST` — is a first-class object type on the
wire: same TNS type 109, same value framing (§21.2), same bind OAC (§21.5),
identified by the same 16-byte OID. Only the **metadata** is somewhere else,
and it is invisible to the `ALL_TYPES` / `ALL_TYPE_ATTRS` pair a schema-level
type is read from:

| what | schema-level | package-level |
|---|---|---|
| OID + typecode | `ALL_TYPES` | `ALL_PLSQL_TYPES` |
| record attributes | `ALL_TYPE_ATTRS` | `ALL_PLSQL_TYPE_ATTRS` |
| collection element | `ALL_COLL_TYPES` | `ALL_PLSQL_COLL_TYPES` |

Keyed by `(owner, package_name, type_name)` rather than `(owner, type_name)` —
two packages may each declare a `UDT_RECORD`, so the package is part of the
identity and belongs in the type's full name.

Three consequences worth stating:

- **`coll_type` has a third value here**, `'PL/SQL INDEX TABLE'`, alongside
  `'VARYING ARRAY'` and `'TABLE'`. It is not cosmetic: an index table prefixes
  each image element with its signed int32 key (§21.6b), so reading the kind
  wrong mis-encodes every element. (A *decoder* is safe either way — the image's
  own `HAS_INDEXES` flag says whether the keys are present.)
- **A name is one to three parts.** `OWNER.PACKAGE.TYPE` is unambiguous;
  `A.B` is not — it may be `SCHEMA.TYPE` or `PACKAGE.TYPE` in the current
  schema. Resolving the schema reading first keeps every name that worked
  before pointing at the same type.
- **The OID resolves back to a name through the same split.** A bind OAC
  carries only the OID, so a server (or a Mirror) turning one back into a type
  looks in `ALL_TYPES` first and `ALL_PLSQL_TYPES` second.

### 21.7 REF — object references (#119)

A REF column has TNS data type **111**. Its value is **not** the object — it is
an opaque locator (a structured pointer: `00 28 02 09` + the object-table OID +
the target row's OID/rowid, e.g.
`00280209 <16B> <16B> 0300223e0000`). It arrives in the RXD as a plain
length-prefixed value (no special framing), so it reads on every tier without
desync. To read the referenced object, dereference in SQL —
`SELECT DEREF(ref_col) ...` returns a normal object that decodes via §21.1–21.4.

seerdb surfaces a REF as `seerdb.DbRef` exposing `.bytes` / `.hex` and the
referenced type identity (`.type_name` / `.type_schema` / `.type_oid`, captured
from the per-column describe, which carries the referenced type's OID +
owner/name in the same fields an ADT column uses, §21.1). Note python-oracledb
has **no** REF type at all, so there is no thin-mode reference for this; the
locator structure above was read from live captures (10g/11g/21c/23ai).

**Server side (the Mirror, #494).** `ColumnMeta` gained `type_oid` /
`type_schema` / `type_name`, which `_encode_dcb_column` now emits in the §21.1
fields (the OID as a length-prefixed value, the owner/name as `str_with_length`)
— previously always empty. A REF column's row value is the DbRef's `.bytes`
wrapped as a plain DALC (`_encode_value`, type 111). The one wrinkle is that a
REF column's type identity is **not** in the PEP-249 description the passthrough
backend gets — only in the `DbRef` values — so the backend copies it from the
first non-null value into the `ColumnMeta` before the describe goes out. With
that, `SELECT REF(p)` round-trips a typed `DbRef` (so `ref.type_name` is set);
the REF *bind* back into an INSERT / DEREF stays a 12c+ concern (the OAC form,
§21.8), which the integration test skips below fv 12.1.

### 21.8 REF bind (#139)

A fetched `DbRef` can be bound back — e.g. `INSERT INTO t (r) VALUES (:ref)` or
`SELECT DEREF(:ref) ...`. Since python-oracledb has no REF type, the bind format
was captured from the **Oracle JDBC thin** driver (the only client that emits a
type-111 bind). Two parts:

- **OAC** — the same 12c+ ADT-style metadata as an OBJECT bind (§21.5) but with
  type code **111** and the *referenced* type's 16-byte OID:
  `6f 03 00 00 | sb4(buffer) | sb4(0) | sb4(0) | <ub4-count + len + OID> |
  sb4(version) | sb4(charset) | csfrm | sb4(0) | sb4(0)`. The OID comes from the
  `DbRef` (kept from its describe); a `DbRef` without it cannot be bound.
- **Value** — just the opaque locator, length-prefixed (`_bytes_with_length`) —
  the exact inverse of the read path; no image, no envelope.

**12c+ only** (like all object/collection binds — no pre-12c reference): a REF
bind on field version < 12.1 raises `NotSupportedError` up front. Verified on
21c/23ai, sync + async (round-trip through `DEREF` returns the original object).
This completes the object-type family (#115–#119).

### 21.9 Object-type metadata cursor — the Mirror serving a thin client (#888)

Before python-oracledb reads an object column it resolves the type: on the first
describe that names an ADT column (§21.1) it builds a *partial* type from the
column's OID + schema + name, then runs a metadata PL/SQL block —
`dbms_pickler.get_type_shape` — whose OUT binds return the type descriptor
segment (TDS) and an `attrs_rc` REF CURSOR of the attribute rows. Serving that
call through the passthrough Mirror needs three things beyond the ordinary
object read, each of which desyncs the client if wrong:

- **The ADT column describe must carry the type identity.** Oracle sends the
  object type's schema + name (and 16-byte OID) in the same per-column fields a
  REF uses (§21.1). Without them the client builds a type with `name = None` and
  raises before any row is read. seerdb surfaces the identity on the client's
  `FetchInfo` (`type_schema` / `type_name` / `type_oid`), and the passthrough
  copies it into the `ColumnMeta` the describe re-emits.
- **A `BINARY_INTEGER` OUT bind rides as a NUMBER.** `get_type_shape`'s `ret_val`
  and `version` come back as `DB_TYPE_BINARY_INTEGER`, which the client reads as
  a NUMBER. Encoding them with the native integer form renders `0` as an empty
  DALC that reads back as NULL, and the client then rejects the call with
  `DPY-2035` because `ret_val` was NULL rather than `0`; so the Mirror encodes an
  INT-typed OUT value as a NUMBER (`_encode_out_bind_value`). **Decoding is the
  same fact in reverse** and applies to any client, Mirror or not: a column or
  bind described as type 3 carries base-100 NUMBER bytes, so `decode_value` must
  run them through `decode_number`. Left with no branch of its own the raw bytes
  came back as a `DB_TYPE_RAW` value — `select :1 from dual` on a
  `DB_TYPE_BINARY_INTEGER` bind yielded `b'\xc1 '` instead of `31` (seerdb#826).
- **The `attrs_rc` REF CURSOR is drained by re-execute.** The client re-executes
  the nested cursor id with an empty statement rather than a `TTI_FETCH`; the
  Mirror serves its parked rows with a full describe + rows reply (§6.5). The
  REF CURSOR value's trailer is the `ub4` return code every OUT bind carries, not
  a `0x01` marker — a middle REF CURSOR with the wrong trailer desyncs the binds
  after it (§6.5). Any literal-NULL column in the attrs query (e.g. a `NULL`
  select-list entry) describes with a zero buffer size and so sends **no** row
  bytes, exactly as `SELECT NULL` does (§21.2 / the decoder's data-length-0 rule);
  the row encoder emits nothing for it.

With these, python-oracledb resolves the object type and fetches scalar objects,
nested objects, NULL objects and collections through the Mirror.

### 21.10 Binding an object *into* a call — the Mirror (#888)

An inbound object (ADT) bind arrives in the RXD as the `write_dbobject` framing
(§21.5) — the same bytes a fetched object column carries — behind a type-109 OAC
whose only type identity is the 16-byte OID. The Mirror reads it with the shared
`_read_object_column` (`_read_bind_value`'s ADT branch), producing an
`ObjectImage` placeholder (or `None` for a NULL object). The passthrough backend
then resolves the OID to a name (`all_types.type_oid`), describes the type to get
the attribute (or element) layout, decodes the image into a `DbObject` — an
object via `decode_object_image`, a VARRAY / nested table via
`decode_collection_image` — and re-binds it upstream. In a PL/SQL block the
object rides as a plain value (not an OUT `Var`); an echoed object bind position
in the IOV reply carries the full object frame (`encode_object_column_value`),
never a bare `0x00`, so the client stays in sync (§6.5).

### 21.11 `cursor.var()` of an object type (#888)

An object / collection **OUT** bind (a function returning one) and a **typed-NULL**
object bind both need the bind to carry its type when the value cannot — a NULL
says nothing about its type, and a pure-OUT slot has no value at all. The client
supports this by letting a `DbObjectType` (from `connection.gettype`) stand in as
a `cursor.var()` type: the type exposes the minimal DbType surface a `Var` reads
(`tns_type` = 109, no fixed size, no charset form), and the Var routes the object
path throughout:

- **OAC** (`_object_oac`): type 109 + the type's 16-byte OID + version, sized for
  the server to return into — the same OAC an object value binds with, minus the
  image length.
- **Value**: a `DbObject` seeded on the Var binds as its `write_dbobject` image; an
  unseeded Var (pure OUT) or a NULL sends the typed-NULL object frame
  (`encode_object_column_value(None, oid)`), never the bare `0x00` a scalar NULL
  sends — the server reads this slot with `read_dbobject`.
- **OUT read-back** (`_read_iov` → `_assign_out_binds`): the returned value is the
  object framing (an `ObjectImage`, then the per-value return code), which the
  cursor rebuilds into a `DbObject` of the Var's type — attributes for an object,
  the element list for a collection.

**Server side (the Mirror).** The passthrough threads the OAC's type OID onto the
`BindVar` (an object bind's value alone is `None` for OUT / typed-NULL), and for
such a bind registers `cursor.var(objtype)` upstream so the function's object
result comes back typed and a NULL binds with its type for overload resolution.
This closes object binding in both directions — python-oracledb's
`data_types/test_1900_dbobject` reaches 39 / 48 through the Mirror (IN, OUT and
typed-NULL object and collection binds); the rest are attribute-fidelity for
specific attribute types, XMLType (§21 / #124), and a large-collection case.

### 21.12 LOB attributes of an object — the Mirror fetch path (#888)

A `CLOB` / `NCLOB` / `BLOB` **attribute** of an object rides **inside the packed
image** (§21.3) as a plain LOB **locator** — the same length-prefixed `read_bytes`
field a scalar attribute uses, carrying no `size`/`chunk` metadata (unlike a
top-level LOB *column*, §6.x). The external client reads that locator out of the
image, builds a LOB from it, and then reads the content over `TTI_LOBOPS` exactly
as for a column LOB. `ALL_TYPE_ATTRS` reports these attribute types by name
(`CLOB` / `NCLOB` / `BLOB`), which the attribute layout (§21.4) maps to the wire
type so the image walkers can tell a LOB attribute from an inline scalar; `NCLOB`
shares `CLOB`'s wire type with a national character-set form, as `NVARCHAR2`
shares `VARCHAR2`'s.

**The Mirror serves the content it has already read, not an upstream locator.**
Two pieces make this work:

1. **Resolve upstream, re-emit a minted locator.** A locator decoded from the
   upstream image points at the *upstream* database — useless to the external
   client, which would read it against the Mirror. So the backend reads each LOB
   attribute's content over its own connection while it has one, and the image the
   Mirror re-encodes carries a **minted** locator in each LOB attribute field. The
   content is queued for the read path; only the locator is written inline.

2. **A distinct locator + a persistent queue.** Object-attribute LOBs use a
   locator **distinct** from a column LOB's, and their content rides a
   **session-persistent** queue rather than the transient row-major column queue.
   This is required, not cosmetic: resolving an object column's *type* happens
   **after** its describe (the `get_type_shape` metadata cursor, §21.9), and those
   metadata queries would reset a single shared LOB queue before the client ever
   issued its `TTI_LOBOPS` reads. Routing a read to the right queue by its locator
   keeps the object LOBs intact across that interleaving. Within the queue the
   order is row-major then attribute-order — the exact order the image emits the
   locators, and the order the client reads them.

**One locator per attribute LOB, answered by locator (#1262).** The design
above served every attribute LOB under the same locator, from a queue in fetch
order. That only works if the client reads each LOB once, in that order, before
its next query. Reading object A's LOBs after fetching object B returned B's
content, and binding a fetched attribute LOB back had no content to find, so it
bound NULL. So inside a session each attribute LOB now gets its own minted
locator, recorded with its content in the session's emit log as a column LOB's
is. A read is answered from the log by locator, in any order and any number of
times, and a bind resolves it like a fetched column LOB (§21.13). The shared
locator and its queue remain only for encoding with no session behind it.

Verified through the Mirror against a live 23ai: python-oracledb's
`test_1900_dbobject` test 1904 (fetch an object holding `CLOB` / `NCLOB` / `BLOB`
attributes, plus a nested object and a collection) reads every attribute back.

### 21.13 Binding an object that carries LOB attributes — the inbound path (#888)

The reverse of §21.12: the client sets an object's LOB attribute to a LOB it
holds — one it fetched (`obj.CLOBVALUE = clob`) or a temp LOB it created
(`obj.CLOBVALUE = conn.createlob(...)`) — and binds the object. It writes that
LOB's **locator** into the image: the attribute's length byte, then the locator
**exactly as the server handed it out**, which starts with its own ub2 length
(`_obj_write_length(2 + n) | ub2 n | <n bytes>`). That ub2 is part of the
locator, not framing: a LOB object's raw locator already holds it, so writing the
raw verbatim is right and adding another ub2 in front is refused (§21.14). But the locator
is one the *Mirror* invented, with no live upstream LOB behind it; binding it
straight through fails `ORA-22275 invalid LOB locator`.

The Mirror turns each such locator back into a real upstream LOB before binding:

1. **Remember what a fetch served.** Every column LOB the Mirror emits gets a
   **unique** locator (byte-identical to the fixed one but for a per-LOB counter,
   so the row reader — which is order-based — is unaffected) and its content is
   kept in a session **emit log** keyed by that locator. A temp LOB's content is
   already kept, keyed by the locator `CREATE_TEMP` minted. So both kinds of LOB
   a client can bind are recoverable from a locator.

2. **Resolve, materialise, rebind.** The session hands every object-image bind the
   content map (emit log + temp LOBs). The backend decodes the image, and for each
   LOB attribute looks its locator up in the map (as-is for a bare fetched locator,
   or with a leading ub2 length stripped for a temp locator, which rides
   ub2-prefixed), streams the content into a fresh **upstream** temp LOB, and binds
   the attribute to that. A locator with no known content binds NULL rather than
   desyncing. The upstream LOB carries the ub2-prefixed form, which the object
   encoder writes verbatim.

Verified end to end against a live 23ai: `test_1900_dbobject` test 1907 (insert an
object holding both a fetched and a `createlob` `CLOB` / `NCLOB` / `BLOB`, then read
it back) passes through the Mirror. Object dbobject count 40 → 41.

### 21.14 LOB attributes in the client (#1260)

Captured with the reference thin client against a live 23ai, for a type
`(id NUMBER, c CLOB, b BLOB)`:

- **Fetch.** A LOB attribute's image field is its length byte followed by the
  locator, `00 70` + 112 bytes for a stored CLOB (`72 00 70 00 02 02 0c …`). The
  client makes it a LOB object on the connection, read over `TTI_LOBOPS` like a
  column LOB. A NULL attribute is the `0xFF` null and stays `None`.
- **Bind, attribute set to a LOB.** A fetched LOB goes back as the same field it
  came in (`72 00 70 …`), and a temp LOB as `28 00 26 …`: the length byte, then the
  locator verbatim with its own ub2. Writing an extra ub2 in front, as the encoder
  once did for every LOB (`2a 00 28 00 26 …`), draws `ORA-22275 invalid LOB
  locator specified`.
- **Bind, attribute set to `str` / `bytes`.** The image has no room for a value,
  only a locator. The reference client therefore first makes a temporary LOB for
  each such attribute: `TTI_LOBOPS` CREATE_TEMP, then a WRITE with the content,
  one pair per attribute in image order. It then sends the execute with those
  locators in the image. seerdb does the same on a copy of the bound object, so
  the caller's object keeps the `str` it was given. CREATE_TEMP needs 12.1+, as an
  object bind does anyway.
- **NCLOB.** It shares CLOB's wire type. The national form comes from the
  attribute's type name, and a temp NCLOB is created with charset form 2.

On 10g and 11g, an object with three LOB attributes once broke the fetch. Its
image passed 252 bytes and went chunked, with one-byte chunk lengths (§21.2,
#1261).

## 22. DML RETURNING ... INTO (#120)

`INSERT/UPDATE/DELETE ... RETURNING col[, ...] INTO :b[, ...]` returns the
affected row(s)' column values into OUT binds. It is an ordinary `TTI_ALL8` DML
execute — **no special al8i4 flag or exec option**; the server infers RETURNING
from the SQL. Two framing differences from a plain DML:

1. **Request**: an OAC (bind descriptor) is written for **every** bind, but the
   `TTI_RXD` row carries values for the **input** binds only — the return (OUT)
   binds are skipped (if every bind is a return bind, the row is omitted). The
   return-bind OAC is just the Var's declared type/size. When the row is
   omitted, the execute's **iteration count still rides in `al8i4[1]`** (the same
   field array DML uses, `1 + batch length`), so a parser reading the request
   knows how many times the statement runs even though no `TTI_RXD` arrives —
   an empty INSERT ... RETURNING or a WHERE-bind-less DELETE ... RETURNING.
2. **Response**: the server sends a `TTI_RXD` (token 7) carrying the out-bind
   return data — **not** query rows. For each return bind, in bind order:
   ```
   ub4  num_rows                         # rows the DML affected
   per row:
       <value>        (length-prefixed, the normal per-type encoding)
       sb4 actual_len (truncation check; 0 = ok, discarded)
   ```
   So each return bind yields a **list** of values (one per affected row);
   multi-row UPDATE/DELETE RETURNING returns several, a zero-row DML returns an
   empty list.

seerdb detects the return-bind positions by parsing the `RETURNING ... INTO`
clause (the trailing K binds), arms the RXD decoder for that one response (a
ContextVar, like the array-DML row counts), keeps the raw return-value bytes,
and the cursor decodes each by its `Var`'s type. `var.getvalue()` returns the
list of returned values (python-oracledb-compatible). Sync + async; verified on
10g/11g/21c/23ai (INSERT / multi-row UPDATE / multi-row DELETE / zero-row /
all-return-no-input).

**This form is for a DML statement only — a PL/SQL block is never it.** A block
may well contain `... RETURNING col INTO :b`, but that is the block's own PL/SQL:
the INTO target is an ordinary OUT bind and the block executes like any other
anonymous block. Text-matching `RETURNING ... INTO` without first excluding a
block gets this catastrophically wrong in a way that is hard to read from a
capture, because **nothing is sent**: rule 1 says the client writes no value for
a return bind, so the server keeps waiting for bind bytes that never arrive, the
client keeps waiting for a reply, and the connection sits dead until one side's
read timeout fires (seerdb#826 — then 15 s, reported as a network read timeout
rather than anything naming the real cause; since seerdb#1568 the client's
connect timeout bounds only connecting, so a call is bounded by `call_timeout`
alone, as in python-oracledb). Both ends of seerdb share one classifier
(`returning_bind_positions`), so the same misreading appeared symmetrically: the
client hung on its own request, and the Mirror routed an inbound block into its
DML-RETURNING path.

Note that the pre-10g fallback wraps a real DML RETURNING *into* a block
deliberately (§19.3 — those servers refuse the native form with `ORA-00439`).
That is consistent with the rule rather than an exception to it —
once wrapped, the statement genuinely is a block with ordinary OUT binds, which
is exactly why those servers accept it. Its return-bind positions are computed
from the original statement, before the wrap.

### 22.1 Array RETURNING (`executemany`, #687)

An array execute of a RETURNING statement follows the same two rules, applied
per iteration. Both halves are easy to get wrong, and getting either wrong is
not a soft failure:

1. **Request**: the OAC still describes every bind exactly once, sized across
   all iterations as for any array DML, but **no** iteration's `TTI_RXD` carries
   a value for a return bind. Emitting one shifts the server's read of the
   following iteration and the whole call is rejected with **ORA-03137**
   (`opiexe: protocol violation`), followed by **ORA-03106** — the connection
   does not survive it.
2. **Response**: the server sends **one `TTI_RXD` per iteration**, each laid out
   exactly as the single-execute form above. The `num_rows` in a record counts
   the rows *that iteration* affected, so an array UPDATE returns a different
   count in each. Reading only the first record silently reports one iteration's
   values for the whole batch.

seerdb keeps every record and stores them on the `Var` as its per-iteration
values: `var.getvalue(pos)` selects the iteration and yields that iteration's
list, while `var.getvalue()` still reads the first — so a single execute is
unchanged. python-oracledb-compatible. Sync + async; verified on
10g/11g/21c/23ai (array INSERT, array UPDATE with a different row count per
iteration, single-row batch, and multiple return binds).

### 20.6 A session-state change is REPORTED BACK (#973)

`ALTER SESSION SET CURRENT_SCHEMA = X` does not merely succeed. The server
answers with the execute's return-parameters block (`TTI_RPA`, §5.1) carrying
the new value, and that reply is the **only** place a client learns it —
`connection.current_schema` is never queried for. A bare status leaves the
client's attribute stale for the life of the session.

Reconstructed from live 23ai captures taken with schema names of three different
lengths, which separated the value from its frame:

```
08                      TTI_RPA
01 06                   ub4 al8o4l count = 6
04 01 b6 ff 73 | 00 | 01 02 | 01 02 | 00 | 00      the six al8o4l fields
00 00 00                three zero words
17 05 01 01 10          frame (constant across every capture)
01 02 16                flag | KEY | type
01 03 | 03 50 59 4f     ub4 length, then a DALC repeating it: "PYO"
00 01 a8 ... 01 a9 00   two trailing entries
<status>                the ordinary OER
```

Both length fields scale — a long name sends the ub4 and the DALC alike — which
is the same double-length shape the SET_SCHEMA piggyback uses in the other
direction (§20.5).

**The KEY says which attribute changed.** Measured by altering one thing at a
time:

| key | attribute | value | trailing entries |
|---|---|---|---|
| `0x02` | `CURRENT_SCHEMA` | the name | `0xa8`, `0xa9` |
| `0x01` | `EDITION` | the name | `0xac` |
| `0x12` / `0x10` | `NLS_LANGUAGE` / `NLS_TERRITORY` | `AMERICAN` / `AMERICA` | — |

The trailing entries differ per attribute, so they are part of what the key
selects rather than a fixed tail.

A statement that changes nothing (`select 1 from dual`) carries no such block at
all.

**What is frame and what is payload.** The words before the entry are identical
across captures that changed *different* attributes, which is what marks them as
frame rather than data; their meaning is not established. The two trailing
entries (`0xa8` / `0xa9`, and `0xac` for an edition change) carry values that
move with the session and look like counters — nothing reads them back, but a
reply that **drops** them is rejected by the client, so they are sent as
captured. The status after them must be **generated**: reusing the captured one
freezes its sequence number, and the client then waits for a reply that never
matches — a hang, not an error.

### 22.1e The trailing `sb4` is the value's **actual length** (#1021)

Every returned value is followed by an `sb4`, and it is not padding. It is the
value's **actual length**, and it has three shapes — only one of which is a
report. Measured on a live 23ai:

| what came back | value on the wire | trailing `sb4` |
|---|---|---|
| 23 bytes into `var(str, 2)` | `41 20` (`'A '`) | **`01 17`** = 23 |
| 23 bytes into `var(str, 100)` | the whole 23 bytes | `00` |
| a NUMBER that fitted | `c1 07` | `00` |
| **NULL** — NUMBER, VARCHAR2, RAW or CLOB alike | nothing / `00` | `81 01` = **-1** |

A positive length longer than what arrived is the server's one and only report
that what it just sent is not the whole answer. `0` means it fitted, and `-1`
means the value is NULL — **not** a length at all, and reading it as one turns
every NULL RETURNING into a truncation.

Discard it and a too-small variable returns a **silently cut-down value** — the
right shape with the wrong content, and no error anywhere. That is worse than a
desync, which at least announces itself.

Two rules for a client reading it. Compare the length with what actually
arrived rather than trusting a non-zero value — that is what makes `-1` and a
server echoing the true length for a value that *did* fit both harmless. And
report it **after the whole message is read**, not at the value: the response
still has the remaining binds, the RPA and the status in it, and raising part
way through leaves the session out of step — the same trap §6.9 (`TTI_FOB`)
sets.

Only a value that arrived as plain bytes can be compared, which is the whole
set that truncates this way. A LOB, OBJECT or JSON / VECTOR return bind carries
its own framing (§22.1b–d) and its length field says nothing about a buffer.

**Serving it.** A server cuts each value to the size the client declared for
that bind and writes the value's real length here — which means it must hold
the *whole* value at that point. The Mirror's passthrough learned this the hard
way: it sized its upstream receiver with the client's own buffer, so the
upstream truncated first and left the Mirror with the short value and no idea
what the real length was (#1023). Size the receiver for the column, cut on the
way out.

Only the types whose declared size is a real buffer are cut — VARCHAR2, CHAR,
RAW. A NUMBER or DATE is fixed width and always fits, and a character value is
cut on a **character boundary**, since a buffer that splits a multi-byte
character hands the client an undecodable tail.

### 22.1d A LOB return bind carries the **LOB block** (#985)

`RETURNING ClobCol INTO :b` frames the returned value exactly as a fetched LOB
column is framed in a row (§14.5b) — a `ub4` block length, the locator's `ub8`
size and `ub4` chunk size, then the locator as a DALC. Not a DALC on its own.
A **NULL** LOB is the single byte `0x00` in place of the whole block, and either
way the per-value `sb4` truncation length follows.

This is the third carrier of that same block, and each one had to learn it
separately:

| carrier | |
|---|---|
| a fetched row | §14.5b |
| an OUT / IN OUT bind | §6.5 |
| a DML RETURNING bind | here |

All three fail identically when read as a DALC: the block length is taken for
the entire value, the size, chunk size and locator stay in the stream, and the
next byte decodes as a response token. **The number in the error comes from the
data**, so the same bug reports itself as a different unknown token each time —
`2` from the ub4 length marker of the size field, `38` from a locator's own
length byte. That is what makes each instance look like a fresh decoder gap.

An `UPDATE` touching several rows returns one block per row, so a reader that
mis-measures the first never reaches the second intact — a single-row test
passes.

**Server side — the Mirror serving one (#987).** Same shape as the OUT bind in
§6.5: no upstream locator exists (a passthrough reads its upstream with
`fetch_lobs=False`, so the value arrives materialised), so the Mirror mints a
locator, records the content against it in the session's `LobEmitLog`, and writes
the block. The read the client then issues is answered from that log by locator.
Sending a DALC instead does **not** error — the client reads the block length as
the whole value and hands back an **empty string**, which is the right shape with
the wrong content.

**A LONG return bind, by contrast, IS a plain DALC (#987)** — and this is the
part that catches you out, because a LONG *column* is not. `cursor.var(DB_TYPE_LONG)`
receiving a CLOB column gets, measured on a live 23ai:

```
07 | 01 01 | 13 <19 bytes> | 00 | 08 ...
^^   ^^      ^^              ^^   ^^ RPA
RXD  rows=1  DALC, length 19  sb4 truncation length
```

No `0xFE` chunk marker and no trailing indicators — a LONG column in a row has
both (§14.5c). Give a return bind the column framing and the client reads the
chunk marker as the value, then desyncs on a zero byte
(`DPY-5000 ... unknown protocol message type 0`).

### 22.1c An OBJECT return bind carries the **object frame** (#826)

`RETURNING ObjectCol INTO :b` frames the returned value exactly as an ADT column
is framed in a row (§21.2) — the constructed 36-byte toid, the object OID, a
snapshot, a `ub2` version, the image-length gate, `ub2` flags, then the packed
image. Not a DALC.

Read as a DALC, the toid's leading length is taken for the value's length and
the reply desyncs **two bytes in**, landing on that toid's own `00 22 02 08`
prefix — which is then reported as an unknown *token 34*. The error names a
token number and says nothing about objects, so the useful tell is the 16-byte
type OID visible in the bytes, matching the OID the bind itself sent:

```
22 02 08 5b 5c 96 bc cc 22 5a fc e0 63 96 00 a8 c0 2c a9 …  ff 20 <the string>
         └─────────────── the type OID ───────────────┘      └── image ──┘
```

The **client** needs the type's attribute layout to walk the image; a returning
Var is built from the type itself, so it already has it (a fetched column has to
look it up from the describe instead). The **server side** is the same rule
backwards: a Mirror encodes the value with the object frame, and the bind's type
OID has to survive parsing to get there — dropping it leaves the backend building
an untyped receiver and the real server then refuses the statement with
`ORA-00932: expression is of data type <SCHEMA>.<TYPE>, which is incompatible
with expected data type CHAR`.

### 22.1b A JSON / VECTOR return bind carries its **image**, not a DALC (#826)

`DALC + sb4 0` describes every return bind but two. `RETURNING JsonCol INTO :b`
(and the same for a VECTOR column) frames the returned value the way such a
column is framed in a row — §14.5e's prefetched form:

```
ub4 locator length | ub8 image size | ub4 chunk size | DALC image | DALC locator
```

Captured from a live 23ai for `insert into TestJson values (:1, :2) returning
JsonCol into :json_out`, the whole RXD record:

```
07        TTI_RXD
01 01     ub4 num_rows = 1
01 28 | 01 25 | 02 1f 7c | 25 <37-byte OSON image> | 28 <40-byte locator>
00        sb4 truncation length
```

Note the chunk size here is **8060** (`02 1f 7c`), not the 32600 a fetched column
reports — it is skipped by every reader, so nothing depends on it, but it is not
a constant of the type.

Read as a plain DALC, the image is taken for the value and the **locator is left
in the stream**, where it becomes the next field and desyncs the rest of the
response. Against a live 23ai that surfaces as `no decoder for response token 2`
— a byte from inside the locator read as a token. A server that writes the bare
locator instead of this framing fails the reference client the other way, with
`DPY-5002: read integer of length 38 when expecting integer of no more than
length 8`.

Because the framing depends on the bind's type and the request carries no
describe for out-binds, a **decoder has to be told the return binds' types** —
it cannot infer them from the reply. In seerdb that is
`set_decode_return_binds(positions, types)`.

### 22.2 Serving it — the same rule read backwards (#689)

A **server** parsing such a request faces the exact mirror of §22.1's first
rule, and getting it wrong fails the same way. The RXD row carries one value per
bind **except** the return binds, so a parser that reads a value for every bind
consumes the next value as this one's tail and misreads everything after it. The
row order in an array request is per iteration, so the mistake compounds: with
one receiver and three iterations, the second iteration's value is read as the
first's, and the third packet ends short.

The reply owes **one `TTI_RXD` record per iteration**, in submitted order, each
laid out exactly as §22 describes and grouped **by bind, not by row**: for each
return bind in bind order, `ub4 num_rows` then that many `DALC + sb4 0` values.
An iteration that affected nothing still sends its record, with a zero count —
omitting it slides every later iteration's values one position earlier. The
records precede the ordinary success status OER.

A **LONG / LONG RAW OUT bind** of a PL/SQL block follows the same rule as a LONG
return bind: a plain DALC and its return code, measured on 23ai as
`07 | 03 61 62 63 | 00` for `begin :v := 'abc'; end;`. The chunked form a LONG
*column* takes in a row adds a chunk marker and trailing indicators, which the
client reads as the next message: "unknown protocol message type 0" (#1458).

Each value goes out in the **return bind's** type, which need not be its column's
(#1501). `RETURNING IntCol INTO :v` with a VARCHAR `:v` returns the number as
text, the way Oracle converts it, which is TO_CHAR's default: measured on 23ai,
`1` → `'1'`, `0.5` → `'.5'`, `-0.5` → `'-.5'`, `1e-10` → `'.0000000001'`. Encoded
in the column's type instead, the value is NUMBER bytes inside a VARCHAR DALC
(`01 02 c1 02`), which the client fails to decode as text.

Row order **within** a record is not defined. A RETURNING clause takes no
`ORDER BY`, and neither Oracle nor any other server promises one, so a client
must treat a record as the set of rows that iteration touched.

seerdb's Mirror implements both halves: `parse_exec` derives the return-bind
positions from the statement text (the same scan the client uses, shared in
`seerdb/common/sqltext.py`, so the two cannot drift) and keeps a `None` in each
so the row stays aligned with the bind descriptors;
`encode_returning_response` builds the reply. A backend that cannot do
RETURNING is refused with an ORA error rather than a broken connection.

## 23. Implicit result sets — DBMS_SQL.RETURN_RESULT (#121)

A 12c+ PL/SQL block can hand result sets back to the client with
`DBMS_SQL.RETURN_RESULT(refcursor)`. The client opts in by setting
**`TNS_EXEC_FLAGS_IMPLICIT_RESULTSET` (0x8000)** in the execute's al8i4[9]
exec-flags word; without it the server rejects the block with **ORA-29481**
("implicit results cannot be returned to client"). seerdb sets the flag on
PL/SQL **block** executes on 12c+ (scoping it to blocks leaves the DML/DDL exec
paths untouched).

The results come back in the block's response as a **`TTI_IRD` (token 27,
`TNS_MSG_TYPE_IMPLICIT_RESULTSET`)** message, before the block's RPA/OER:

```
ub4  num_results
per result:
    ub1 len + that many bytes        (preamble, skipped)
    describe body                    (column metadata — the same body as the
                                      TTI_DCB token, §6.4, minus the preamble)
    ub2 cursor_id
```

Each result is therefore a server cursor (a cursor id + a row format), exactly
like a REF CURSOR (§ REF CURSOR) — seerdb keeps the `(row_format, cursor_id)`
pairs and **`cursor.nextset()`** fetches each on demand (via the same
`fetch_all_rows` path), making that set's rows fetchable and updating
`cursor.description`; it returns `True` per set and `None` when exhausted. The
describe body is shared with the `TTI_DCB` decoder (`_decode_describe_body`).
Sync + async; verified on 21c / 23ai (multiple result sets, varying shapes);
12c+ only (11g lacks `DBMS_SQL.RETURN_RESULT`).

### 23.1 Serving it (#826)

A server owes the same block, and the ordering is what matters: **each result's
rows have to be parked on the cursor id it names before the block's reply goes
out**, because the client fetches them afterwards exactly as it fetches a REF
CURSOR. The reply is the `TTI_IRD` block then a plain success status — the block
itself returned neither rows nor a row count.

A block that returned no results is not a special case: the token still decodes,
with a zero count.

A relaying server gets these from its backend however that backend surfaces them
— seerdb's own client surfaces them PEP 249 style, so the passthrough drains
`nextset()` until it returns `None`. That call is **optional** on a DB-API
cursor, so it is probed for rather than assumed: a statement that returned
nothing must not fail because the cursor has no `nextset`.

### 23.2 The OCI form (#2431)

sqlplus 23.26 gets the same block from a 21c, which logs it in the classic way
(captured with one result, two, and a block with an OUT bind as well). The
fields are at OCI's fixed widths. Each result carries one more zero byte, at the
place where a REF CURSOR OUT value has its lead byte (0x4c). The describe body
and its trailer follow, as that value carries them:

```
ub1  0x1b                            (TTI_IRD)
ub4  num_results                     (little-endian)
per result:
    ub1 0                            (preamble length, as thin)
    ub1 0
    describe body + trailer          (as in a REF CURSOR OUT value)
    ub4 cursor_id                    (little-endian; no return code)
```

The block goes between the block's OUT values, if any, and its status, as in
thin. sqlplus then prints `ResultSet #n` and re-executes each cursor id with no
SQL (`035e … 40`, the cursor id, room for 15 rows). That is the same call it
sends to print a REF CURSOR, and it is answered the same way: the rows, then
ORA-01403 at the end.

## 24. XMLType (#124)

An XMLType column is **TNS type 109 with no user object type** — the same row
framing as a SQL object (§21.2), but the packed image is decoded by a
specialised walk (python-oracledb `read_xmltype`) instead of the attribute walk.
seerdb recognises it by the column's described type identity (`SYS.XMLTYPE`,
§21.1) and short-circuits the object describe.

Image (after the shared header, §21.3):

```
ub1   XML version                       (skip)
ub4   xml_flag
[ if xml_flag & 0x100000 (SKIP_NEXT_4): 4 bytes skipped ]
<content>
```

- `xml_flag & 0x0004` (**STRING**) → the content is the document text (decoded
  with the DB charset). This covers inline documents and SQL-built XML
  (`XMLELEMENT`/`XMLAGG`, which set the SKIP_NEXT_4 bit) on every tier.
- `xml_flag & 0x0001` (**LOB**) → the content is a CLOB locator; seerdb reads
  it through the LOB path (§14) and returns the string. This is the large-document
  form on 12c+, and how 10g stores XMLType columns.

**Bind** needs no special framing: a plain string bind works, either through the
`XMLTYPE(:1)` constructor or directly into an XMLType column (the server
converts). Verified on 10g/11g/21c/23ai. (A document over the ~32 KB regular-bind
limit hits the usual streamed-LONG ORA-01461 — the general large-bind limit, not
XMLType-specific.)

**Serving one** (the Mirror) is the same rule read backwards, and the trap is
that the column is an ADT by describe while its VALUE is not an object. Every
client surfaces an XMLType as a string, so a backend hands one over as a `str`;
it rides the ordinary object frame (§21.2 — toid, object OID, snapshot, version,
image length, flags) with an **XML image** inside rather than a packed object
image. Encoding it as an object instead asks a `str` for its type, which is not
an ORA error but an `AttributeError`: the Mirror answers with an internal fault
and the client's connection **dies** (`DPY-4011`) rather than receiving an error
it can act on (seerdb#826).

A **large** document is served inline too, not through a LOB. Captured from 23ai
serving a 32 KB XMLType to python-oracledb, the image is the same STRING form
with its length field in the long form, `fe` + a 4-byte big-endian length that
spans the whole image (its own five bytes included):

| document | image head |
|---|---|
| `<s>tiny</s>\n` (12 bytes) | `85 01 14 01 00000014` (length 20) |
| 32782 bytes | `85 01 fe 0000801a 01 00000014` (length 32794) |

Around the image nothing changes: the frame's image-length `sb4` simply grows,
and the image rides as ordinary chunked column bytes (the server chunked it at
2000 bytes). The Mirror used to refuse anything over the 1-byte length with
ORA-03115, which is what python-oracledb's `test_2531` / `test_2534` hit (#1073).

**Limitation:** Oracle **11g** XMLType *columns* are CLOB-stored with a complex
binary image whose locator seerdb can't read (a reference-less case —
python-oracledb requires 12.1+). That image sets a distinguishing flag bit
(`0x01000000`, never set on the working 10g / 12c+ forms), so seerdb raises a
clear `NotSupportedError` for it rather than returning corrupt data; cast such a
column in SQL (`XMLTYPE.getclobval(col)` / `XMLSERIALIZE`) to read it. Inline XML
(`XMLELEMENT`, etc.) on 11g uses the STRING flag and works. Sync + async.

### 24.1 XMLType as an object attribute

An XMLType **attribute** of an object rides *inside the packed image* (§21.3),
not as a nested object's inline attributes. It is a **length-prefixed XMLType
image** — the `_read_length` prefix (§21.3), then the §24 image above — and a
NULL attribute is the single `0xFF` length-null marker (not the `0xFD`
atomic-null a normal nested object uses). Treating it as a normal nested object
(recursing into `SYS.XMLTYPE`'s empty attribute list) consumes no bytes and
bleeds the XMLType image into the next attribute; seerdb tells the two apart by
the attribute's type identity (`SYS.XMLTYPE`) and routes to the XMLType walk.

The image encoder emits the inline STRING form (`xml_flag & 0x0004`); a live
server also sets a `0x10` bit there, which python-oracledb ignores (it checks
only STRING / LOB / SKIP_NEXT_4), so the STRING flag alone round-trips. Through
the Mirror this closes python-oracledb's `test_1900_dbobject` XMLType-in-object
cases (a populated and a NULL XMLType attribute); the object suite is then 47/50,
the remaining three being thick-mode-only skips and an environmental credential.

## 25. Query cancellation / call_timeout (#123, #144)

`connection.cancel()` interrupts the call currently executing on the connection,
and `connection.call_timeout` (milliseconds, 0 = none) does the same
automatically when a call runs too long. The break has **two paths**, matching
python-oracledb (#144, fixing the OOB-only break originally shipped in #123):

- **OOB** — when the server advertised attention support, an out-of-band urgent
  byte `send(b"!", MSG_OOB)`. The accept packet's global service options carry
  `TNS_GSO_CAN_RECV_ATTENTION` (`0x0400`); seerdb records it as
  `connection._supports_oob`. The urgent byte reaches the server's attention
  handler immediately, even while it's compute-bound — the fastest interrupt.
- **In-band** — otherwise, a `TNS_MARKER` packet with body `01 00 03`
  (INTERRUPT) written straight to the socket. It's an ordinary packet, so it
  works on every tier and over any network path (including rootless-container
  port-forwards that drop OOB); the server's two-task layer polls for it
  mid-call. #123 sent OOB *unconditionally*, which silently did nothing against
  a server that doesn't advertise OOB — the call only ended on the client read
  timeout. The in-band fallback is the fix.

Either way the server interrupts the call and replies with break/reset markers
followed by `ORA-01013` (user requested cancel); the reader drains the markers
via the existing reset handshake (the #45 break/reset machinery), the connection
resyncs, and it's immediately reusable.

**An interrupt that finds nothing running** (sent while the connection is idle,
or after the call already finished) still opens an episode, and the cancel
becomes the **next** call's answer. Measured with an in-band interrupt on 26ai:
the server answers with a reset and waits for the client's reset. The request
the client sent meanwhile is not executed; its answer is `ORA-01013`, and the
call after it runs normally. With encryption on, both sides re-derive their
integrity keystreams in that exchange (§33.6).

The Mirror (§33.5) answers an interrupt the same way (#1346): it sends one
reset, reads until the client's reset (dropping the queued request), re-derives
when encryption is on, and replies `ORA-01013`. Before that it executed the queued
request in between: the cancel then arrived one call late, and under encryption
the request's reply went out under keys the client had already re-derived, so it
failed the client's integrity check. The Mirror does not honour the OOB urgent
byte yet (#1349).

- **call_timeout**: a timer (`threading.Timer` sync, `loop.call_later` async)
  fires the break after the timeout; the resulting `ORA-01013` is remapped to a
  call-timeout `OperationalError`. The timer is disarmed as soon as the call
  completes, so a normal call with `call_timeout` armed is unaffected.
- Marker packet form `01 00 <type>`: BREAK=1, RESET=2, INTERRUPT=3 (seerdb
  sends INTERRUPT to cancel and replies RESET=2 to a server break).

**Verified** end-to-end on 10g/11g/21c/23ai, sync + async: `cancel()` (from
another thread) and `call_timeout` interrupt a long-running query with
`ORA-01013`, and the connection is reusable afterwards. None of these Free/XE
servers advertise `CAN_RECV_ATTENTION`, so the **in-band** path is what's
exercised live; the OOB path is taken automatically against a server that does
advertise it. The async break reaches the real socket under the asyncio
`TransportSocket` wrapper.

## 26. PL/SQL associative-array binds (#122)

`cursor.arrayvar(type, value_or_numelements)` binds a PL/SQL `TABLE OF <scalar>
INDEX BY PLS_INTEGER` (associative array) parameter as a bulk array — IN, OUT,
or IN OUT. It returns a `Var` flagged `is_array` with a declared capacity
(`num_elements`); `getvalue()` yields a Python list. The array Var flows through
the normal PL/SQL-block OUT-bind path (the IOV reply, § OUT binds).

Versus a scalar bind:

- **OAC** (bind descriptor): the flag byte gains **`TNS_BIND_ARRAY` (0x40)** —
  `0x41` on the 12c+ form — and the **max-num-elements** field (0 for a scalar)
  carries `num_elements`.
- **Value** (input row): `ub4 count` then `count` element values (the normal
  per-type encoding); `count` = 0 for a pure-OUT array.
- **OUT/IN OUT return** (IOV RXD): `ub4 count` then `count` × (value +
  indicator) — decoded into the Var's list by element type.

```python
arr = cur.arrayvar(int, [1, 2, 3])
cur.callproc('pkg.double_all', [arr])      # IN OUT
arr.getvalue()                              # [2, 4, 6]
names = cur.arrayvar(str, 10)
cur.callproc('pkg.make_names', [3, names])  # OUT -> ['name1', 'name2', 'name3']
```

Sync + async. **12c+ only:** there is no python-oracledb reference for a pre-12c
array bind OAC (thin requires 12.1+), and the pre-12c short OAC doesn't signal
array-ness — the server then mis-types the argument (PLS-00306). So seerdb
gates array binds on field version ≥ 12.1 with a clear `NotSupportedError`
(alongside the object-bind gate, §21.5), raised before anything goes on the
wire. Verified on 21c/23ai (IN / OUT / IN OUT, NUMBER + VARCHAR2 elements);
clean gate on 10g/11g. Scalar element types only (nested object/collection
elements are out of scope).


The Mirror reads the same forms (#743): the capacity off the OAC (the ARRAY flag
and max-array-size field of the 12.1+ layout, the second flag word and trailing
field of the 11g one), the value as its count and elements, and it answers an
OUT array with the count and one value plus return code per element.

## 27. Proxy authentication (#126)

Connecting as `proxy_user[schema]` authenticates as `proxy_user` (with its own
password) but runs the session in `schema`'s context — the `SESSION_USER` /
current schema becomes `schema` while `SYS_CONTEXT('USERENV','PROXY_USER')`
reports `proxy_user`. The target must have granted it
(`ALTER USER schema GRANT CONNECT THROUGH proxy_user`).

It's almost free on the wire: seerdb splits the user name (`_split_proxy_user`:
`proxy_user[schema]` → real user `proxy_user` + bracketed `schema`), performs the
**normal** O5LOGON/O3LOGON as `proxy_user`, and adds **one auth key/value pair**
to the final auth message — `PROXY_CLIENT_NAME = schema` — bumping the pair
count by one. No auth-mode bit changes. The pair is appended after the existing
`AUTH_PASSWORD` / `AUTH_SESSKEY` (and 23ai session) pairs in both the fv ≤ 17 and
the fv24 fast-auth phase-two layouts.

Verified on 10g/11g/21c/23ai (sync + async): `proxy_user[schema]` runs as the
target schema; a plain user name is unchanged. Works on every tier (it predates
the 12c+ features and needs no version-specific framing).

## 28. Two-phase commit / XA (#131)

Distributed transactions via `connection.xid(format_id, gtrid, bqual)` +
`tpc_begin` / `tpc_end` / `tpc_prepare` / `tpc_commit` / `tpc_rollback`. Two TTI
function messages carry it:

- **TransactionSwitch** (`TNS_FUNC_TPC_TXN_SWITCH` = 103) — `tpc_begin` (op
  `START`) and `tpc_end` (op `DETACH`). Body: operation, a context pointer +
  length, the xid descriptor (`format_id`, `len(gtrid)`, `len(bqual)`, xid
  pointer + length), flags, timeout, three return pointers, internal/external
  name pointers, then the data: the context bytes (on detach), the **xid
  zero-padded to 128 bytes** (`gtrid + bqual + pad`), the application value, and
  the names. The response (an RPA return-parameter token, `0x08`) carries an
  application value (ub4), a context length (ub2), and the opaque **transaction
  context** — held and replayed on the later calls.
- **TransactionChangeState** (`TNS_FUNC_TPC_TXN_CHANGE_STATE` = 104) —
  `tpc_prepare` (op `PREPARE`), `tpc_commit` (op `COMMIT`), `tpc_rollback` (op
  `ABORT`). Body: operation, context pointer+len, xid descriptor, timeout, the
  requested state, an out-state pointer, flags, then context + padded xid. The
  response (RPA) carries a `ub4` final **state**: `tpc_prepare` returns True for
  `REQUIRES_COMMIT` / False for `READ_ONLY`; `tpc_commit` expects
  `COMMITTED`/`READ_ONLY` (one-phase) or `FORGOTTEN` (after prepare);
  `tpc_rollback` expects `ABORTED`.

Use `autocommit=False` so the DML between `tpc_begin` and `tpc_end` is part of
the branch. Sync + async. **12c+ only:** python-oracledb requires 12.1+ and
there's no pre-12c reference; pre-12c the global-transaction DML response is
framed differently and desyncs, so `tpc_begin` raises `NotSupportedError` on
field version < 12.1 (before any wire activity — the connection stays usable).
Verified on 21c/23ai (two-phase commit, one-phase commit, rollback, read-only
prepare), sync + async.

**Recovering in-doubt branches (#2457).**
- **`tpc_recover`** isn't a wire message. It is a query on
  `DBA_PENDING_TRANSACTIONS` (`formatid, globalid, branchid`), as python-oracledb
  documents it, and it needs SELECT on that view. A second session then settles
  each branch with `tpc_commit` / `tpc_rollback` by XID, no context needed.
- **Settling by XID works only while the branch is unclaimed.** Measured on 23ai,
  2026-11-04:
  - while the session that prepared the branch stays open, a rollback by XID from
    another session succeeds at any delay tried (0 to 10 s);
  - once that session closes, it succeeds for about a second. After 2 s it is
    refused with ORA-24756, "transaction ... does not exist", from python-oracledb
    too: the database's recovery process has taken the branch, now listed in
    `DBA_2PC_PENDING`, and only `COMMIT FORCE` / `ROLLBACK FORCE` settle it.
- **`tpc_forget`** is refused. python-oracledb 26.1 refuses it in thin mode
  (DPY-3001, thick mode only). The change-state message with op `FORGET` (4) and
  state 0 is refused by 23ai as malformed (ORA-03137, `[kpotxen: bad args] [0] [4]
  [0]`). With no thin reference, seerdb raises NotSupportedError. A heuristically
  completed branch is cleared with `DBMS_TRANSACTION.PURGE_LOST_DB_ENTRY`.

## 29. Advanced Queuing (#128)

Enqueue/dequeue via `connection.queue(name[, payload_type])` →
`enqone`/`deqone` (single) and `enqmany`/`deqmany` (array), with
`connection.msgproperties(payload=...)` and the queue's `enqoptions`/
`deqoptions`. Three TTI functions, laid out as python-oracledb sends them:

- **Enqueue** (`TNS_FUNC_AQ_ENQ` = 121) — queue name, the message properties
  block, recipients, visibility, the 16-byte payload **TOID** (RAW = `…00 17`,
  object = the type OID), a payload-pointer triple selecting RAW vs object vs
  JSON, the return-msgid request, then the data: queue name, TOID, payload. The
  RPA response returns the 16-byte message id.
- **Dequeue** (`TNS_FUNC_AQ_DEQ` = 122) — queue name, dequeue mode/navigation/
  visibility/wait, consumer/correlation/condition, TOID. The RPA response (when
  a message is present) carries the message properties, recipients, payload and
  msgid; an empty queue comes back as ORA-25228 → `None`.
- **Array** (`TNS_FUNC_ARRAY_AQ` = 145) — `enqmany`/`deqmany`, the messages
  framed with ROW_HEADER/ROW_DATA/STATUS markers; the response returns one block
  of concatenated msgids (enqueue) or N messages (dequeue).

Message properties use a mix of length encodings: most fields are
`read/write_bytes_with_length` (a ub4 count + a single-byte/0xFE-chunked value),
while the enqueue-time **date** and the payload **image** use the single-byte
`read_raw_bytes_and_length` / `read_bytes()` form — getting this split wrong
drifts the whole parse. The shard id (props and array) and the JSON pointer are
gated at field versions 21.1 / 20.1.

**Payloads:** RAW (`bytes`), SQL object (a `DbObjectType` from `gettype()`,
reusing the §21 object machinery), and **JSON** (`queue(name, seerdb.JSON)`,
#150). RAW + object support both single and array; sync + async.

**JSON payload framing** (#150): the OSON image is wrapped in a fixed
descriptor — `01 28 00 26 00 04 61 08 00 00 00 01 00 00 00 00 00 00` then the
image length (ub2), 22 zero bytes, and the image length-prefixed
(`write_bytes_with_length`). RE'd from an oracledb-thin capture; it's the
native-LOB value form used for JSON columns (#70) but with a one-byte-different
descriptor. The image must use the 12c+ single-byte/0xFE-chunked length form —
the 11g `encode_chr` path chunks at 64 bytes and desyncs the server (ORA-03120).
JSON numbers dequeue as `Decimal` (Oracle semantics). JSON is **single-message
only**: `enqmany`/`deqmany` for a JSON queue raise `NotSupportedError` (the
server errors — ORA-00600 even from python-oracledb — on these editions), and a
payload whose OSON exceeds ~254 bytes is bounded by the native-encoder limit
tracked in #88.

**12c+** (no pre-12c reference); verified on 21c and 23ai.

## 30. DRCP / implicit connection pooling (#130)

`connect(..., server_type='pooled')` (or `:pooled` / `(SERVER=POOLED)` in the
DSN) requests a Database Resident Connection Pool server; `cclass` and `purity`
say which session it should be. Two small additions to the existing connect flow:

- **Connect descriptor** — `server_type` puts `(SERVER=<type>)` in the
  `CONNECT_DATA`, and `pooled` tells the listener to route to the connection
  broker instead of a dedicated server. A connection class or a purity alone adds
  nothing here: it labels the session and requests no pooled server, as in
  python-oracledb (#1990).
- **Auth pairs** — the final auth message carries `AUTH_KPPL_CONN_CLASS` (the
  connection class) and `AUTH_KPPL_PURITY` (the purity as a decimal string), each
  only when given, the same way proxy auth (§27) adds its pair. Purity is
  `seerdb.PURITY_NEW` (1) or `PURITY_SELF` (2); a pooled standalone connection
  left at `PURITY_DEFAULT` sends `NEW`. Measured from python-oracledb 26.0.1:

| arguments | `(SERVER=…)` | auth pairs |
|---|---|---|
| `cclass='C1'` | none | `CONN_CLASS`=C1 |
| `purity=SELF` | none | `PURITY`=2 |
| `server_type='pooled'` | `pooled` | `PURITY`=1 |
| `server_type='pooled'`, `cclass='C1'` | `pooled` | `CONN_CLASS`=C1, `PURITY`=1 |

A **pool** asking for a pooled server differs again (#2006): python-oracledb
gives it a class of its own, `DPY:` plus the base64 of 16 random bytes, new for
each pool, and defaults purity to SELF, so the pool's sessions are reused by it
alone. seerdb's pools do the same under the prefix `SEERDB:`; a class or a
purity given is kept.

The DRCP capability itself is already advertised (`compile_caps[CCAP_OCI2]` has
the `0x10` DRCP bit at field version ≥ 21.1), so no handshake change is needed.

The one decode addition: a DRCP-pooled session's responses are preceded by a
**server-side piggyback** (token 23) — `SESS_RET` (the assigned session id /
serial and any session-state key/value pairs) and `OS_PID_MTS`. The response
decoder consumes the piggyback (`decode_token_server_piggyback`) and continues
to the real status/data; without it the stream desyncs on the first call. The
trailing `ORA-01403` on a fetch is the normal end-of-data marker, not an error.

Verified on 21c and 23ai (sync + async): connections route through the broker
(`v$cpool_stats` / `v$cpool_conn_info` show the connection class). Needs the
server pool started (`DBMS_CONNECTION_POOL.START_POOL`).

## 31. Sessionless transactions (#133, 23ai)

`begin_sessionless_transaction(transaction_id=None, timeout=60)` /
`suspend_sessionless_transaction()` / `resume_sessionless_transaction(id,
timeout=60)`. A transaction is started on one session, suspended, then resumed
and committed on **any** session — the transaction lives in the database, not
the session. Built entirely on the existing two-phase-commit machinery (§28):
there is **no new function code**.

- **The switch message reuses `TNS_FUNC_TPC_TXN_SWITCH` (103)** with the same
  `encode_tpc_switch` body. The sessionless identity is carried in the xid slot
  with a fixed magic **format-id `0x4e5c3e`** and the user transaction id (≤ 64
  bytes, defaulting to a fresh uuid4) in the gtrid; bqual is empty. `begin` is
  op `START` with flags `NEW(0x01) | SESSIONLESS(0x10)`; `resume` is op `START`
  with `RESUME(0x04) | SESSIONLESS`; `suspend` is op `DETACH` with `SESSIONLESS`
  only and **no xid attached**. `timeout` (seconds the server keeps the
  suspended transaction resumable) goes in the message's timeout field.
- **Commit / rollback are ordinary** `TTI_COMMIT` / `TTI_ROLLBACK` messages —
  they end the sessionless transaction with no sessionless flag.
- **Server sync state** — while a sessionless transaction is active the server
  piggybacks a **`SYNC` server-side piggyback (opcode 5)** onto the next call's
  response, carrying keyword-value pairs (keyword `201` = the transaction id and
  a 2-byte sync state, e.g. `0x83 0x01` = unset|version-1 after a commit).
  seerdb tracks the active flag client-side and consumes the piggyback
  byte-for-byte in `decode_token_server_piggyback`; without that the stream
  desyncs on the first call after `begin`. The pair loop mirrors `SESS_RET`
  (§30): per pair a ub2-gated text value, a ub2-gated binary value, then the
  keyword number, followed by an overall ub4 flags field.

Use `autocommit=False` so the DML between `begin`/`resume` and `suspend`/commit
joins the transaction; a suspended transaction's rows are invisible to other
sessions until committed. Sync + async. **23ai+ only:** `begin`/`resume`/
`suspend` raise `NotSupportedError` on field version < 23.1 (before any wire
activity). The wire format was confirmed against the oracledb-thin reference
through the logging proxy; the server accepts seerdb's minimal sb4 encoding of
the format-id (`03 4e5c3e`) where oracledb pads to four bytes. Verified on 23ai
(suspend/resume across sessions, cross-session isolation, rollback), sync +
async.

## 32. Request pipelining (#132, #158)

`pipeline = seerdb.create_pipeline()` collects operations
(`add_execute` / `add_executemany` / `add_fetchone` / `add_fetchmany` /
`add_fetchall` / `add_commit` / `add_callproc` / `add_callfunc`); running
`connection.run_pipeline(pipeline, continue_on_error=False)` returns a
`PipelineOpResult` per op (`.rows` / `.return_value` / `.columns` / `.error`).
With `continue_on_error` a failing op records its error and the rest still run;
otherwise the first error is raised after its result is recorded. Sync + async.

On a 23ai server that negotiated end-of-response framing (#155) a pipeline of
exec-family ops (execute / executemany / fetchone / fetchmany / fetchall) is
sent as **one token-tagged burst and its responses read back in a single round
trip** (#158). Other servers — or a pipeline carrying a commit / callproc /
callfunc op — run each op **serially**; the API, ordering and results are
identical either way. The wire flow, byte-validated against both an
oracledb-thin async-pipeline capture and seerdb's own capture on 23ai:

- **Token framing** — at field version 24 each function-call header carries a
  ub8 token number after the sequence byte (`_fun_header`). An ordinary call
  uses token 0 (`encode_sb4(0)` = the historical single `0x00`); a pipelined
  call numbers itself 1..N (threaded through `encode_dictionary_exec` via the
  dict's `token_num`). Each op is built fresh (no cursor cache); a pipelined
  `fetchall` asks for a large prefetch so its rows come back inline, and any
  overflow is drained with ordinary `TTI_FETCH` calls once the burst is read.
- **Begin-pipeline piggyback** (`TNS_FUNC_PIPELINE_BEGIN` = 199, message type
  `0x11`) rides on the first pipelined message, carrying the error mode. The
  wire always sends **continue mode** (`1`) so the server returns a response for
  every op (a partial burst would desync the stream); the caller's abort
  semantics are applied client-side. The first packet sets the `BEGIN_PIPELINE`
  (0x1000) data flag, and every op packet sets `END_OF_REQUEST` (0x800). Op
  packets are framed with `encode_data_packet` (explicit data flags), not the
  ordinary `encode_packet` path.
- **End-of-pipeline** (`TNS_FUNC_PIPELINE_END` = 200, ordinary data flags 0)
  closes the burst and **draws its own terminating response after the N op
  responses** — read and discard it, or the next call reads a stale packet.
- **Response correlation** — the server prefixes each op's response with a
  `TOKEN` (33) marker carrying the matching ub8 token and ends it with the
  end-of-response (29) marker (§1.1). The pipelined reader assembles packets
  directly (the ordinary `recv` coalesces consecutive complete packets, which
  would merge op responses) and stops each response at its first
  response-final packet.
- **Per-op errors** — in continue mode the server interjects a bare break
  marker (`01 00 01`) before an erroring op's response but does **not** wait for
  a reset and keeps streaming; the pipelined reader skips the marker silently
  (unlike the break/reset handshake of §27 / #45).

### 32.1 The server half (#1059)

What a server has to do for a client to pipeline at all — established against a
live 23ai, because the Mirror did none of it and python-oracledb then **never
pipelined**: it silently fell back to running the operations one at a time. On
that fallback path it reads `oracledb.defaults` at *run* time rather than the
per-operation values captured at *add* time, so a pipeline built inside a
`defaults_context_manager("fetch_decimals", True)` came back as plain `int`s.
Nothing was wrong with the fetch handling; the options never reached it. Note
that "44 of 49 pipelining tests pass" therefore meant **none of them were
pipelined** — they passed because the fallback is equivalent for them.

1. **Advertise** `0x02000000` in the ACCEPT `flags2` word (offset 33) at a
   negotiated version ≥ 318. A client reads that word only from 318 up, so
   setting it lower is noise. `FAST_AUTH` (`0x10000000`, which a real 23ai also
   sets — its full value is `0x1A000000`) is a separate, unimplemented
   capability and stays clear; without it the client uses the three-message
   PRO / DTY / OSESSKEY handshake rather than one bundled packet.
2. **Frame every DATA reply from the first one after the ACCEPT**: data flags
   `0x2000` (`END_OF_RESPONSE`) and a trailing `TTI_END_OF_RESPONSE` (`0x1d`).
   The ACCEPT is the commitment — a live server puts the marker on its PRO
   answer, *before* the client has sent the DTY that carries its CCAP opt-in.
   Turning it on after login left the client waiting for a marker the handshake
   replies never carried, and it hung before authenticating.

   More precisely, measured against a live 23ai since (#1822): the reply that
   carries the marker first is the one to the fast-auth bundle, which opens with
   the PRO answer. python-oracledb sends nothing before the bundle. A client that
   negotiates native services first (seerdb's thin client, sqlplus) gets that
   reply **unmarked**: header flag `0x20`, data flags `0000`, no `0x1d`. A plain
   PRO answer to seerdb is unmarked too, and the marker starts with the bundle
   reply. The Mirror advertises end-of-response without fast auth, a combination
   a real 23ai never produces, so its thin clients take the three-round login
   and keep the marker from the PRO answer on.

   **sqlplus is served unmarked.** sqlplus 23.26 opts in (`CCAP_TTC4` `0xff`),
   and a live 23ai marks its replies once fast auth has bundled the login. But
   on the Mirror's three-round OCI login it refuses a marked reply at every
   step. The native-services reply draws `ORA-12699`, and each later login reply
   draws a break. Served without end-of-response, whatever the ACCEPT said, it
   runs a whole session: queries, DML, a CLOB, `DESCRIBE`, out binds, server
   output (#1822).
3. **Nothing may trail the last token.** Without end-of-response the client
   treats the OER as the end of the response and stops; with it, it reads on
   for the marker — python-oracledb:

   ```python
   # an error message marks the end of a response if no explicit end of
   # response is available
   if not buf._caps.supports_end_of_response:
       self.end_of_response = True
   ```

   So a byte after the OER that was always silently ignored is now read as the
   next message type. The Mirror wrote exactly such a byte on **every success
   OER**: the empty message's length (`0x00`), which a 12.1+ client reads only
   `if error_num != 0`. Every login failed with *"unknown protocol message type
   0"*. It is no longer written from 12.1 (§6.5); below 12.1 the captured bytes
   stand, and end-of-response cannot be negotiated there anyway.
4. **Correlate each pipelined reply.** A call is marked by the data flags alone
   — `BEGIN_PIPELINE | END_OF_REQUEST` (`0x1800`) on the first, `END_OF_REQUEST`
   (`0x0800`) on the rest — and carries its token right after the 3-byte header
   (from 23.1). Its reply opens with `TTI_TOKEN` and that token:

   ```
   21 01 01 <reply> 1d        first call
   21 01 02 <reply> 1d        second call
   ```

   On the first call the header carrying the token is the `PIPELINE_BEGIN`
   piggyback's (function 199), which shares the call's token. Its body is an sb4
   `0`, a zero byte, then the error mode; a server may answer every call
   regardless of mode, since the reference client runs its bursts in
   `CONTINUE_ON_ERROR` and enforces abort itself.
5. **Answer `PIPELINE_END`** (function 200) with a bare status and nothing else:
   `09 01 01 00`, then the marker. The client reads that reply and discards it.

A server that meets 1–5 but still answers a PL/SQL block with cursor id `0` will
break a pipelined `executemany` of that block: the client keeps the block in
single-execute mode and re-sends each row, piling several replies onto one
operation. That is #1064.

## 33. Native network encryption / data integrity (ANO, #437)

Oracle Advanced Networking (ANO) negotiates *native network encryption* and
*data integrity* right after the ACCEPT and before PRO. Every field below is
validated byte-for-byte against a live client's session on a 26ai server
configured `SQLNET.ENCRYPTION_SERVER=REQUIRED` (AES256) +
`CRYPTO_CHECKSUM_SERVER=REQUIRED` (SHA256), and end-to-end connect+query on that
server.

### 33.1 Advertising and the gate

The CONNECT descriptor's ANO flags (§2.1, body offset 24) must be `0x0101`
(ANO-capable); the legacy `0x8484` (disabled) makes an ANO server RESET after
round 1. Once ANO-capable is advertised, whether to negotiate is gated on the
**ACCEPT** body flags `ACFL0` (offset 14) and `ACFL1` (offset 15):

    negotiate ⇔ (ACFL0 & 0x01) and not (ACFL0 & 0x04) and not (ACFL1 & 0x08)

`ACFL0 & 0x01` = ANO supported (set on 10g→26ai); `ACFL0 & 0x10` additionally
means encryption is *required*. The gate fires on every modern server, so the
negotiation runs even when the server ultimately selects no encryption — a
plaintext server just answers with the null algorithm and the session stays
plaintext.

### 33.2 The negotiation packets (`DEADBEEF` container)

A negotiation packet is a container (`magic 0xDEADBEEF | length(2) |
version(4) | service_count(2) | err(1)`) followed by N services (`type(2) |
subpacket_count(2) | err(4) | subpackets`); each sub-packet is `length(2) |
type(2) | payload`. All big-endian. The **version must be `0x0B200200`** — the
server keys its data-packet wire format off it and closes on the first encrypted
packet if it differs.

- **Round 1 (C→S)** offers four services in order: supervisor (4), auth (1),
  encryption (2, offering the RC4/DES/AES ids prefixed with the null id 0),
  data-integrity (3, offering MD5/SHA1/SHA-2 prefixed with 0).
- **Response (S→C)** selects one encryption id and one integrity id. When the
  server selects encryption, its data-integrity service carries **8 sub-packets**
  tailing a Diffie-Hellman exchange: `gen-bitlen, prime-bitlen (UB2), generator,
  prime, server_public, server_iv (bytes)`. A plaintext server selects
  encryption id 0 and carries no DH — the client stops here, plaintext.
- **Round 2 (C→S)** is a one-service container (data-integrity, a single `bytes`
  sub-packet) carrying the client's DH public key.

DH is the classic modular exchange over the server's group (gen=2, 2048-bit
prime): `client_public = gen^priv mod p`, `shared = server_public^priv mod p`,
both left-padded to the prime's byte length. `server_iv` is the constant
`b"foo bar baz bat quux"` (20 bytes).

### 33.3 The encrypted data-packet wire format

After round 2 the client activates a per-packet transform; the negotiation
itself is plaintext. Each `TNS_DATA` payload (the bytes after the 8-byte header +
2-byte data flags) becomes:

    AES-CBC( plaintext ‖ MAC(plaintext) ) ‖ 0x00

- **MAC** (present whenever a checksum algorithm is negotiated — SHA256 here):
  computed over the plaintext and appended *before* encryption. It is *not* an
  HMAC. Keying: `aes_key = shared[:5] ‖ 0xFF` (zero-filled to 16) drives one
  AES-CBC pass over 32 zero bytes with IV `server_iv[:16]`, seeding a base key
  (first 16 B) + base IV (next 16 B); the per-direction keystream key is that
  base key with **byte 5** set to `90` (sender) / `180` (receiver), swapped
  between client and server. Each packet advances the keystream one block; the
  packet MAC is `SHA256(payload ‖ keystream_block)`. Stateful — identical
  payloads get different MACs.
- **Cipher**: AES-CBC, key = `shared[:keysize]` (16/24/32), **IV = 16 zero
  bytes** (the DH IV is *not* used by the cipher). Oracle padding: zero-pad the
  plaintext up to the 16-byte block (no block added when already aligned), and
  append one trailing marker byte `padding_count + 1` (1..16) *after* the
  ciphertext. A fresh CBC state per packet (no IV chaining across packets).
- **Key-fold flag**: one trailing `0x00` byte. No auth-key folding happens on
  the wire for this server when the client sends 0: the server mirrors the
  client's value. The classic sqlplus client sets it to `01` in both directions
  after login (observed in the sibling ODBC driver's investigation,
  seerdb/SeerODBC#55); what it folds is not documented here.

Receive reverses it: strip the flag byte, AES-CBC decrypt (removing the padding
marker + padding), then verify and strip the trailing MAC. Each `TNS_DATA`
packet on the wire is an independent encrypt+MAC unit, so multi-packet responses
decrypt per packet before reassembly, and the MAC keystreams stay in lock-step.
That includes a **pipeline's** packets (§32): each op's request fragments are
encrypted with the pipeline's data flags (BEGIN_PIPELINE, END_OF_REQUEST) kept
in the clear header, and each response packet is decrypted before its op's reply
is decoded. Sent in the clear, a burst is refused op by op with ORA-12599
(cryptographic checksum mismatch); the break marker the server interjects for a
failing op needs no re-derivation, as no reset follows it (#1849).

### 33.4 Login sequence with ANO active

The negotiation completes before PRO. From there the ordinary handshake runs
unchanged, but each `TNS_DATA` is wrapped as above: PRO → PRO reply →
(fast-auth bundle at fv≥18, §20) → auth → result. There is no key re-keying
after authentication for this server, except the integrity re-derivation that
every break/reset exchange triggers (§33.6).

### 33.5 Server side (the Mirror)

Real 11g and 26ai advertise ANO in the ACCEPT (`ACFL0 & 0x01`), so a modern thin
client negotiates against them, and the Mirror runs the inverse of the client
half (#448). Its behaviour follows a per-Mirror **stance**:

- **`accepted`** (default) — answer a modern client's round-1 (version
  `0x0B200200`) with the null-algorithm response (every service selects id 0),
  so no cipher/MAC is activated and the session stays plaintext. This is the
  both-sides-ACCEPTED outcome (Oracle only encrypts when a side asks for it), and
  it keeps every existing plaintext / sqlplus test unchanged.
- **`requested` / `required`** — select the strongest AES the client offered
  (AES256 ▷ AES192 ▷ AES128) plus a SHA-2 checksum, and reply with the DH
  exchange: the server emits generator 2, the RFC 3526 2048-bit MODP prime, its
  own public key, and the IV constant. It then reads the client's round-2 public
  key, derives the same shared secret, and switches the stream to encrypted
  framing before reading the (now encrypted) PRO. `required` fails the login if
  the client offered no algorithm the Mirror implements; `requested` falls back
  to plaintext.

The server channel is the same `AnoChannel` as the client's but built
`ClientSide=False` — the cipher is symmetric and the MAC's send/receive
keystreams swap, so the two ends decrypt each other. Every DATA packet from PRO
onward (including the captured-template PRO/DTY replies, re-framed through the
encrypted path) is encrypted + MAC'd. Validated end-to-end: a seerdb client
(sync and async) connects, authenticates, and queries a `required` Mirror over
AES256 + SHA256.

An encrypted reply is framed like a plaintext one at its end: when end-of-response
framing is on, its last fragment carries the `0x2000` END_OF_RESPONSE data flag
(§1), as 26ai's encrypted replies do, for a client that reads a reply to that flag
(#1847, #1845).

The classic sqlplus / thick-OCI client also negotiates ANO but stamps version
`0x00000000`; that path is handled inline by the `deadbeef` dialect (§4.1.1) and
is unaffected by the stance.

Like the client, the server re-derives its integrity keystreams once per
break/reset exchange (§33.6). For the Mirror, that exchange is the cancel
episode (§25): it re-derives when the client's reset closes it, just before the
`ORA-01013` it sends (#1346). The Mirror reports ordinary SQL errors to a thin
client as plain DATA, with no break, so those need nothing.

### 33.6 A break/reset re-derives the integrity keystreams (#1345)

A server with out-of-band breaks disabled reports a SQL error **in-band**: a
break marker (`01 00 01`), a reset marker (`01 00 02`), the client's reset marker,
then the error `TNS_DATA`. After that exchange **both sides re-derive their
data-integrity keystreams**. The cipher is unaffected. The MAC state is:

- a **seed generator**, AES-128-CBC. At channel creation it is keyed
  `shared[:5] ‖ 0xFF` (zero-filled to 16) with IV `server_iv[:16]`, the key §33.3
  describes;
- a 32-byte **seed**, initially zero.

**Derive:** `seed = seed_generator.encrypt(seed)`; the seed generator becomes
AES-128-CBC(key `seed[:16]`, IV `seed[16:32]`); each direction's keystream cipher
becomes AES-128-CBC(key `seed[:16]` with byte 5 set to its `90` / `180` tag,
IV `seed[16:32]`). The first derivation, at channel creation, is exactly §33.3's
(one pass over 32 zero bytes). The server derives again at **every** break/reset
exchange, so the client must too: once per episode, when it answers the server's
break with its own reset, before it unwraps the error packet. The evolving
per-packet keystream blocks are **not** reset; they carry on under the re-keyed
ciphers.

A client that doesn't re-derive still decrypts the error packet, but its MAC
fails. The session is lost at its first error: the next request times out.

Measured on 26ai with encryption and integrity REQUIRED (AES-256, SHA-256) and
`DISABLE_OOB=ON`:
- seerdb's client raised `data integrity check failed` on the first ORA-00942,
  then timed out on the next query;
- with the re-derivation both errors of a session come back as ORA-00942 and the
  session carries on, sync and async;
- a recorded session (`tests/fixtures/ano_reset_session.txt`: shared secret,
  server IV, every server `payload ‖ MAC`, the reset points) verifies packet for
  packet only with it. Without it, the first packet after a reset fails.

The same behaviour was found independently in the sibling ODBC driver
(seerdb/SeerODBC#55). The Mirror's side, re-deriving when it breaks for an error
with encryption required, is #1346.


### 33.7 The KERBEROS5 authentication exchange (#2378)

A Kerberos login offers the `KERBEROS5` method in the authentication service of
the negotiation, and the server authenticates the user from the ticket inside
ANO. The TTC login that follows has no O5LOGON at all. Measured with sqlplus
23.26 against Oracle 26ai Free (23.26), whose `sqlnet.ora` lists
`KERBEROS5PRE, KERBEROS5`, and reproduced by seerdb's client.

**The offer.** The client's authentication service carries two more
sub-packets after the version, the marker `0xe0e1` and the status `0xfcff`:
`ub1 1` and `string "KERBEROS5"`.

**The selection.** The server's authentication service answers:

```
version, status 0xfaff (a method selected), ub1 1, string "KERBEROS5",
version, ub4 9, ub4 2
```

**The method's rounds.** Then come containers carrying the authentication
service alone, one service, error 0:

| # | from | sub-packets |
|---|---|---|
| 1 | client | version, `ub4 9`, `ub4 2` (the selection's two words, echoed), `ub1 0` |
| 2 | server | `string` service name (`oracle`), `string` host (`sulaco.local`) |
| 3 | client | `ub2` address type (Kerberos's: 2 IPv4, 24 IPv6), `ub4` address length, `bytes` the client's address, `bytes` the AP-REQ |
| 4 | server | `ub1 0`, `bytes` the AP-REP |
| 5 | client | `bytes` the credentials to forward: a KRB-CRED with the user's TGT, or **empty** |

- **The principal comes from the server.** The client builds the service
  principal from round 2, `<service>/<host>`, not from the host it connected
  to. Through a proxy on `localhost`, sqlplus still asked for
  `oracle/sulaco.local`.
- **Raw Kerberos messages.** The AP-REQ and AP-REP are the messages
  themselves (ASN.1 APPLICATION 14 and 15), not GSS-API tokens. A GSS-API
  initiator's token unwraps to an AP-REQ the server accepts (its authenticator
  carries GSS-API's checksum, type 0x8003). The server's AP-REP wraps back
  into the GSS token the initiator completes the context with: `0x60`, a DER
  length, the Kerberos mechanism's OID `1.2.840.113554.1.2.2`, then TOK_ID
  `01 00` for an AP-REQ or `02 00` for an AP-REP.
- **Forwarding is optional.** sqlplus forwards the user's TGT in round 5 when
  the ticket is forwardable, and sends an empty `bytes` sub-packet otherwise.
  Both log in. seerdb always sends the empty one, so the user's ticket is never
  delegated to the database.
- **The server answers round 5 with nothing,** and the login goes on.

**The TTC login after it.** There is no OSESSKEY and no challenge: one
TTI_AUTH with no user (user pointer 0, length 0), logon mode `NoNewPass` (0x1),
and only the session-context pairs, as token authentication's (§20.6) has. The
server's reply is the session (`AUTH_VERSION_STRING` and the rest), with no
server proof.
- **Before field version 18,** that AUTH follows the usual PRO and DTY
  rounds.
- **From 18 on,** it rides in the fast-auth bundle where the OSESSKEY goes
  (§20), and the bundled reply's RPA is the session rather than a challenge.
  Sent as a separate round at field version 18 or above, the classic sequence
  fails with ORA-03120.

The session is then the externally identified user the ticket's principal maps
to (`CREATE USER ... IDENTIFIED EXTERNALLY AS 'pyo@REALM'`): `USERENV`
`AUTHENTICATION_METHOD` is `KERBEROS`, and `AUTHENTICATED_IDENTITY` the
principal.

## 34. End-user security context (#460, post-23ai / milestone #29)

An **end-user security context** attaches a distinct end-user identity plus
authorization details (a database access token, optional data roles and
attributes) to an already-authenticated session — the Deep Data Security
piggyback used in proxy / real-application-user scenarios. It is a discrete
`field_version ≤ 24` feature (no field-version bump), first surfaced by the 26ai
capability-array exploration (§4.2, #458).

### 34.1 Negotiation and the tcps gate

The server advertises support via a bit in the compile-cap array: **`compile_caps[45]`**
(`FEATURE_BACKPORT2`) **bit `0x02`**. Oracle 26ai advertises `caps[45] = 0x03`;
older servers do not carry the slot at all. seerdb records the server compile
caps at PRO time and gates `set_end_user_security_context` on this bit.

The reference thin client additionally restricts the feature to **TLS (tcps)
transports** — attaching a context on a cleartext connection raises an error and
the piggyback is *never* emitted in the clear. seerdb mirrors this: the setter
requires an `ssl` transport (else `ProgrammingError`) and a server that
advertises the bit (else `NotSupportedError`). A consequence is that this wire
form cannot be captured on a plaintext proxy; the layout below was reconstructed
from the reference client and pinned with an offline fixture.

### 34.2 The func-205 piggyback

Once set, the context rides as a piggyback in front of **every** subsequent
call's message (it is not one-shot like the tracing/close-cursors piggybacks —
it re-rides until cleared). Layout, all multi-byte integers in Oracle's
variable-length form:

```
uint8   TTI_MSG_TYPE_PIGGYBACK (0x11)
uint8   TNS_FUNC_END_USER_SECURITY_CTX (205 / 0xCD)
uint8   seq
[ub8    token_num]                       # only when field_version > 23.1 (fv24 qualifies); 0
ub4     TNS_SECURITY_CONTEXT_ATTACH_FLAG (0x01)
uint8   0x01                             # pointer(kpdkve) non-null
ub4     0x01                             # number of key-value pairs
  -- one keyword-value pair --
  ub4   0x00                             # pair flags
  kv    "ORCL_XS_AUTHZ_CONTEXT"          # keyword, write_bytes_with_two_lengths
  kv    <null>                           # text (unused)
  kv    <OSON image>                     # value, write_bytes_with_two_lengths
```

`write_bytes_with_two_lengths` is a `ub4` count followed, for a non-empty value,
by the `write_bytes_with_length` (chunked) bytes — the same encoding seerdb uses
for object attributes.

### 34.3 The context payload (OSON)

The value is the **OSON image** (Oracle binary JSON, magic `ff 4a 5a`) of a dict
whose keys are inserted in this order so the OSON field table matches the
reference client:

```
ver                     "1.0"
end_user_token          <str>   # IAM / Entra ID token identity   (token path)
end_user_name           <str>   # database-managed user name      (name/key path)
end_user_contextid      <str>   # the key of the (name, key) pair (name/key path)
database_access_token   <str>   # required
data_roles              [<str>] # optional
attributes              [{"name": k, "values": v}, ...]  # optional
```

Either `end_user_token` (a token string identity) or the
`end_user_name` + `end_user_contextid` pair is present, never both. The image
must not exceed 65535 bytes (it is `ub2`-length-prefixed on the wire). seerdb's
existing OSON encoder (`seerdb.common.oson.encode_oson`) produces the image;
`seerdb.create_end_user_security_context` builds the dict and returns an
`EndUserSecurityContext`, attached with
`OracleConnect.set_end_user_security_context` (sync and async).

Live end-to-end validation (a server *accepting* the attached context) requires
a TLS path to a 26ai instance and is pending; the encoder, guards, cap
negotiation, and OSON payload are pinned offline and the guards verified live
against 26ai on `:1523`.

## 35. Request boundaries (#464, post-23ai / milestone #29)

**Request boundaries** let a pooled connection tell the server when a logical
request begins and ends, so the server can reset or reclaim session state
between requests (a DRCP / connection-pool resource optimisation). There is no
correctness or user-visible effect, and it applies only to **pooled**
connections — standalone connections never send it.

### 35.1 Negotiation

`supports_request_boundaries` requires the server to advertise **both**:
- compile `compile_caps[40]` (TTC4) bit `0x40` (`EXPLICIT_BOUNDARY`), and
- runtime `runtime_caps[6]` (TTC) bit `0x10` (`SESSION_STATE_OPS`).

Oracle 21c, 23ai and 26ai advertise both; 10g/11g do not (so the feature is
silently inactive there). seerdb records the server's compile *and* runtime cap
arrays at PRO time to evaluate the gate.

### 35.2 The func-176 piggyback

The marker is a piggyback, func `SESSION_STATE = 176`, one-shot:

```
uint8  TTI_MSG_TYPE_PIGGYBACK (0x11)
uint8  TNS_FUNC_SESSION_STATE (176 / 0xB0)
uint8  seq
[ub8   token_num]                 # only when field_version > 23.1; 0
ub8    (state | 0x40)             # EXPLICIT_BOUNDARY OR'd in
                                  #   REQUEST_BEGIN (0x04) -> 0x44
                                  #   REQUEST_END   (0x08) -> 0x48
```

Unlike the end-user-security piggyback (§34) it does not re-ride; the desired
state is cleared once emitted.

### 35.3 Pool lifecycle

- **Acquire:** arm `REQUEST_BEGIN`. It rides the piggyback slot in front of the
  connection's next call (typically the caller's first execute) — no extra
  round-trip.
- **Release:** if `BEGIN` was armed but never flushed (the caller ran no
  operation) it is cancelled and nothing is sent. Otherwise `REQUEST_END` is
  emitted, piggybacked on a **rollback** round-trip (mirroring the reference
  client, which rolls back at end-of-request); this is the one added round-trip
  per release when the feature is active.

Both `Pool` and `AsyncPool` drive this, on `connection.py` / `aconnection.py`.
Validated live on 26ai (`:1523`): a pooled `select 1 from dual` sends
`11 b0 07 00 01 44` (BEGIN) in front of the execute and `11 b0 09 00 01 48`
(END) in front of the release rollback.

## 36. OCI OER return-status token (Mirror, #265/#350)

Every OCI (deadbeef-dialect) server response ends with an **OER** — the "Oracle
Error" return-status token (`0x04`) — carrying success/error status, the
affected-row count, any ORA error, and the statement's command type. It is the
same token the thin client decodes (§ error path); the Mirror's several status
trailers are all this one **fixed-width little-endian** structure, so they are
generated by `encode_oci_oer` rather than stored as near-identical blobs.

### 36.1 Field map (reverse-engineered against live 11g)

RE'd by controlled capture — sqlplus through the logging proxy (`tools/capture_proxy.py`)
to real 11g, varying one thing at a time. Offsets are from the `0x04` token:

| offset | width | field | evidence |
|---|---|---|---|
| `0` | 1 | token tag `0x04` (TTI_OER) | constant |
| `1` | 1 | **status** — `0x01` success, `0x05` error | error vs success replies |
| `5..7` | ub2 LE | **end-to-end sequence number** — a per-session diagnostic counter | high byte `0` in every capture; a live monotonic counter, read-and-discarded by every client (see below) |
| `7` | 1 | constant `0x01` | constant across captures |
| `8` | 1 | **row kind** — `0` none, `1` LOB row, `2` LONG row | LOB vs LONG fetch status |
| `8..12` | ub4 LE | **rowcount** (affected rows) | ins1→1, ins3→3, upd/del→4 |
| `12..16` | ub4 LE | **error code** | ORA-00942 → `ae 03`, ORA-01403 → `7b 05` |
| `18` | 1 | statement category — `2` query / PL-SQL, `1` DDL | DDL vs describe/outbind frames |
| `20` | 1 | error position (parse offset; the column sqlplus draws its caret under) | ORA-00942 → `0x0e`; the Mirror emits the backend-supplied offset (`encode_error_oci(error_pos=...)`), clamped to one byte, or `0x0e` when unknown |
| `22` | 1 | **V$SQL command type** | INSERT=2, UPDATE=6, DELETE=7, SELECT=3, CREATE TABLE=1, DROP TABLE=12, PL/SQL=47 |
| `27..40` | | rowid of the touched row (DML only) | capture-specific; the Mirror reuses a fixed frame |
| `27` | 1 | **warning flags** on a DDL status — `0x21` when a `CREATE` made a PL/SQL object that compiled with errors, `0` otherwise | the same `CREATE PROCEDURE` compiled clean and broken, sqlplus 23.26 against 11g and 18c: the only difference but the counters (#2013). The thin OER carries the same value (§6.3a) |
| `49..51` | ub2 LE | **sequence of the call being answered** — the client's own `03 <func> <seq>` byte | decoded across every reply kind in one live 11g session and confirmed on 10g; *not* an echo of offset `5` (§36.1a) |
| `52` | 1 | constant `0x01` | constant across captures |
| `56..58` | ub2 LE | fixed 11g constant — `0x0136` (310) | **not** the TTC version (disproven by differential capture: absent from 21c/23ai, which replace the whole trailer); an 11g OER-format constant, carried |
| `72..76` | | fixed `20 f6 31 0a` marker | an 11g OER-trailer constant; byte-identical across every 11g reply, absent from 21c/23ai |

The rest of the 136-byte frame (SCN region, cursor/rowid slots) is a fixed
zero-filled envelope. For an error, the `ORA-NNNNN: <message>` DALC follows the
136-byte OER. Offset `18` carries a value whose exact semantics are not
yet pinned down (a non-zero position under a *success* describe status); it is
carried from the captures byte-for-byte. Offset `49` **is** pinned — see §36.1a. Offset `56` looks like the session's negotiated TTC
protocol version (`310` sits in the same `0x013x` family as the versions the
handshake negotiates); the Mirror emits the captured value rather than its own,
which sqlplus accepts — whether the field must track the live negotiation is
not confirmed.

#### 36.1a The two sequence fields are independent

The OER carries two counters, and they are **not** the same number:

- **offset `5`** is the *server's* free-running per-session counter (below).
- **offset `49`** is the sequence number of the **call being answered** — the
  `seq` byte from the client's own `03 <func> <seq>` header, after any
  piggybacks in front of it have been stripped. Where a request carries
  piggybacks the field takes the **call's** sequence, never a piggyback's.

One live 11g sqlplus session, every reply kind, through `tools/capture_proxy.py`:

| request | offset `5` | offset `49` |
| --- | --- | --- |
| `FUN 118` seq 2 (OSESSKEY) | 2 | 2 |
| `FUN 115` seq 3 (AUTH) | 3 | 3 |
| `FUN 94` seq 6 (execute) | 4 | 6 |
| `FUN 5` seq 7 (fetch) | 5 | 7 |
| `FUN 94` seq 11 (PL/SQL, outbind reply) | 8 | 11 |
| `PGY 105/12 + FUN 94/13` | 10 | 13 |
| `PGY 105/15 + FUN 94/16` (DDL) | 13 | 16 |
| `PGY 105/19 + FUN 94/20` (DML) | 17 | 20 |
| `PGY 105/24 + FUN 119/25` (describe) | 22 | 25 |
| `FUN 94` seq 26 | 23 | 26 |

Thirteen replies, thirteen matches, across success and error statuses and on 10g
as well. The two counters diverge as a session runs: the client burns sequence
numbers on piggybacks the server's counter does not tick for, so the gap grows
from 0 to 2 to 3 over the captures above.

That divergence is what makes the field decidable. It was previously written as
`sequence + 2`, fitted to a handful of early-session captures where the gap
happened to be exactly 2 — every one of those still reproduces byte-for-byte
under the decoded rule, but `+2` fails for the later replies (offset `5` of 8
against an echo of 11, 10 against 13, 22 against 25). The outbind reply was
likewise thought to zero the field; it carries 11, like everything else.

The Mirror publishes the call sequence per message on a ContextVar
(`_ENCODE_OCI_CALL_SEQ`), the same shape the thin path uses for its own counter,
rather than threading a second parameter through every encoder. Note the
**compact 24-byte OER** (§36.2) is too short to have this field at all, so the
replies that use it — the SELECT execute status, the fetch terminator, the no-row
status — carry no call sequence.

The `sequence` at offset `5` is the OER's **end-to-end sequence number** — a
diagnostic/tracing counter (same family as the end-to-end application-tracing
attributes, §17), **not** a protocol-correctness field. It is
read-and-discarded by every client: the thin client skips it on decode, and both
reference implementations (thin and thick) do the same — one reads it into a
struct field that is never read again, the other skips it outright in the error
token. No client validates, echoes, or transmits it, and there is no
"wrong sequence" Oracle error (`ORA-03137`/`ORA-03106` are framing/parse
failures, not sequence-value mismatches).

Because the field is consumer-ignored, the Mirror is free to emit **any**
monotonic value — but a real server *advances* it per reply, so the Mirror does
too, on **both** reply paths:

- **thick / OCI** — `seerdb/server/session.py:_OciSequence`, a per-session
  counter (`+1` per OER-bearing reply, starting at `1`) threaded into every OCI
  status builder.
- **thin** — the `_ENCODE_OER_SEQ` context variable, advanced once per message
  by the session loop beside the field version and read by `_encode_oer`, so
  every thin status, error and fetch terminator in a session carries a moving
  value (#842). A caller that pins `seq` explicitly is reproducing a captured
  frame byte-for-byte and is deliberately unaffected — that is what keeps
  `_END_OF_FETCH` verbatim.

Both replace the frozen per-capture constant each status was reverse-engineered
with. On the thin side the live evidence is the 23ai auth exchange captured for
§4.1.2, where consecutive replies differ in exactly this field —
`04 01 01 02 18 16` for the challenge and `04 01 01 02 18 17` for the result. The captured adjacency of the SELECT execute status (`19`) and the
following fetch terminator (`20`) is the evidence that the real field advances
`+1` per reply. The start value and step are therefore Mirror
response-generation policy, not a decoded Oracle rule. (Offline tests reproduce
each live capture byte-for-byte by passing that capture's original sequence
value; §36.2.)

### 36.2 Generation

`encode_oci_oer(status, *, sequence, row_kind, error_pos, error_code,
command_type)` builds the token from the named fields over the shared
`_OCI_OER_ENVELOPE`. Everything that ends in this OER is generated from it, not
stored: the error / LONG-row / LOB-row **return-status trailers** (three direct
calls, pinned by `tests/test_oci_oer_generation.py`) and the **describe / DDL /
outbind / DML execute-status frames**, each a 35-byte preamble followed by an OER
from this builder. That preamble is itself built — `_oci_status_frame_prefix` —
not stored: it is the `08 06` header, a ub2-LE **cursor id** at offset 4 (present
on the DDL/DML statuses, `0` on describe/outbind), and two statement-kind marker
bytes carried from the capture (offset 11 = `0x02` on a value/row-producing
status, offset 15 = `0x01` on the DML status). The describe and outbind frames
set the murky OER `18`/`49` fields themselves.

**Compact 24-byte form.** The simple replies — a SELECT execute status, the
fetch terminator (`ORA-01403`), and the no-row (PL/SQL / DDL) status — carry a
*compact* 24-byte OER instead of the 136-byte envelope. It holds the same
logical fields (`04 01` tag+success, `sequence` ub2 at `5`, `error_code` ub4 at
`12`, statement `category` at `18`, `command_type` at `22`; offsets `7`/`8` are
the constant `0x01`) and is generated by `_oci_oer_short(sequence, command_type,
category, error_code)`. Here `category` is `2` for a row/value-producing
statement and `1` for a no-row one — the same offset-`18` field as the envelope,
so it is carried, not fully pinned.

**The 7-byte `TTI_STA` acks.** A bare commit / rollback and a logoff are answered
without any OER frame at all, by a 7-byte token: `09 | ub4 LE call status |
ub2 LE sequence`. That trailing `ub2` is the **same end-to-end sequence** the
full OER carries at offset `5`, not a row count or a length — a live 11g answers
`7` there while the OERs on either side of it carry `5` and `8`, and a live 10g
answers `6` in the same position with its whole call chain one sequence lower.
So the commit ack takes the session counter like every other reply
(`encode_commit_status_oci(sequence)`); before #883 it emitted a frozen `0x12`
carried from one capture, which made a session's replies jump to 18 between a 4
and a 6.

The **logoff** ack is the one exception: a live server sends a literal `0` there,
on both 10g and 11g and in every captured session, so `_OCI_LOGOFF_STATUS` stays
a constant. The `ub4` call status is the OER's flag word (§36.1) — `5` on the
commit, `1` on the logoff — and **not** the offset-`1` OER status byte, which
happens to use the same two values for success and error.

**The error text after an error OER** (#1520). The ORA message follows the OER
length-prefixed: one byte for up to 252 bytes, else the chunked form. Captured
with sqlplus 23.26 and a 333-byte `RAISE_APPLICATION_ERROR` message:

```
11g   fe ff <255 bytes> 4e <78 bytes> 00          255-byte chunks, ub1 lengths
18c   fe 4d 01 00 00 <333 bytes> 00 00 00 00      one chunk, ub4 LE lengths
```

The width is **not** the field version: the Mirror speaks 18c's to sqlplus
(§36 / #1282), and sqlplus hangs on the ub4 form from the Mirror while it reads
the ub1 one. It follows some capability the real 18c and the Mirror negotiate
differently, not yet identified. The Mirror sends the 11g form in both bands
(`_oci_error_text`); it used to write a one-byte length whatever the message,
and a longer message raised while the reply was built, ending the session.

### 36.3 DML execute-status

The DML execute-status reply wraps the OER in a larger status frame: a 35-byte
preamble (with a cursor id) + the OER + a 16-byte trailer. Its OER **is** built
on the envelope by `encode_oci_oer` (call status `2`, the live per-session
sequence of §36.1), with the touched row's physical **rowid** patched into
offsets `27..40`. The 16-byte
trailer is **derived** from that same rowid (`_oci_dml_frame_trailer`): a fixed
frame with two of the rowid's 2-byte words spliced back in byte-swapped
(rowid `1..3` → trailer offset `6`, rowid `9..11` → trailer offset `12`). The
rowid is capture-specific and opaque to sqlplus, which
renders the completion message from just **two** fields: the V$SQL **command
type** at frame offset `57` (= the OER's offset `22`) and the affected-row
**count** (ub4 LE) at offset `43`, both patched per call by
`encode_dml_status_oci`. The DDL completion message (`Table created.` and the
rest) comes from the same command-type field on an envelope-built OER via
`encode_ddl_status_oci`. So every OER-bearing status now builds on
`_OCI_OER_ENVELOPE`; only the physical rowid is carried (a `FIXME`, like the LOB
LID in §14.6). **Verified live** against sqlplus over the
Mirror: `insert/update/delete` print the right verb and count, `create/drop`
print `Table created.` / `Table dropped.` (and, via the resolved command type, `Index created.`, `Table altered.`, `View dropped.`, `Table truncated.`, and the rest).

**The command type is V$SQLCOMMAND's** (#2012). The code a server puts at OER
offset 22 is the statement kind's `COMMAND_TYPE` in `V$SQLCOMMAND`, whose 238 rows
on a 23ai name each kind by its statement's own leading words: `CREATE PACKAGE
BODY` 97, `ALTER SESSION` 42, `COMMENT` 29, `DROP FUNCTION` 93. A statement
resolves by its longest leading phrase that is a name, with the modifiers that
can stand between the verb and the object kind skipped (`OR REPLACE`,
`EDITIONABLE`, `FORCE`, `PUBLIC`, `UNIQUE`, `GLOBAL TEMPORARY`, ...). `GRANT`,
`REVOKE`, `AUDIT` and `NOAUDIT` are listed as `<verb> OBJECT`, and `CALL` as `CALL
METHOD`.

`SHOW ERRORS` is a separate matter. Direct to a 23ai, after a `CREATE` that
compiled with errors, sqlplus queries `ALL_ERRORS` with the object's kind and
its name bound (`:NMBIND_SHOW_OBJ`). Through a Mirror that does not report the
compile warning, it sends no query at all and prints "No errors." itself, so it
depends on that warning (#2013), not on the command type.

A bare `COMMIT` / `ROLLBACK` typed in sqlplus is executed as a SQL statement (`OCIStmtExecute`), not `OCITransCommit` / `OCITransRollback`, so it reaches the OCI **execute** path rather than the `TTI_COMMIT` / `TTI_ROLLBACK` piggyback. Its reply is the same no-row command-complete OER, tagged with the transaction-control command type — **`COMMIT` = 44**, **`ROLLBACK` = 45** (captured live from 11g) — from which sqlplus renders `Commit complete.` / `Rollback complete.` The live-server frame also carries a session cursor id and SCN region, but sqlplus renders the message from the command type alone, so the Mirror reuses `encode_ddl_status_oci` and does not fabricate those.

Every OCI reply that carries an OER draws the live counter, including the
`TTI_LOBOPS` READ reply's tail (`_oci_lob_read_tail`, §14.6): its OER sits at the
end of a TTI_RPA + OER tail and is built from `encode_oci_oer` with the session
sequence, so a multi-read LOB fetch advances the field on every slice returned.

## 37. Sharding keys are not on the thin wire (#164)

A **sharding key** (`shardingkey` / `supershardingkey`) routes a connection to a
specific shard of a sharded database. This is an **OCI-client-only** capability:
the shard resolution happens below the thin TTC/TNS protocol, and a pure-protocol
thin client has no message to carry it. Confirmed by capture — driving the thin
reference client with a sharding key against a (non-sharded) 23ai listener through
the logging proxy sends **zero** bytes: the client rejects the request locally,
before the connect, with a "not supported in thin mode" error. A second
independent thin-protocol reference implementation has no sharding code at all.

There is therefore **nothing to reverse-engineer or emit** here, and no capture
source for the OCI encoding in a thin context. seerdb accepts the two
oracledb-compatible parameters for API parity but raises `NotSupportedError` up
front (`_reject_sharding`), so code ported from a thin driver gets the recognizable
exception instead of an unexpected-keyword `TypeError`. A downstream thin
implementation should do the same rather than search for a wire encoding that the
thin protocol does not have.

## 38. Continuous Query Notification is not on the thin wire (#129)

> **Superseded.** python-oracledb 4.0.0 (May 2026) added CQN and AQ
> notifications to its thin mode, so the finding below no longer holds for
> current servers and clients. It is kept as the 2026-08 record until the
> thin form is measured and documented here (#2460). Until then seerdb still
> raises `NotSupportedError` from `subscribe()`.

Continuous Query Notification (CQN) registers a **server-initiated
subscription**: the client asks the database to watch a query / set of objects
and, when they change, the *server opens a callback connection back to the
client* to push a notification. That callback channel — a listener the client
runs, plus the registration that points the server at it — is an OCI-client
capability that sits outside the thin TTC/TNS request-response protocol. A
pure-protocol thin client has no way to host the callback, so it cannot offer
CQN; the reference thin driver rejects `subscribe()` for the same reason.

As with sharding keys (§37), there is nothing to reverse-engineer or emit on the
thin wire. seerdb exposes `subscribe` / `unsubscribe` for API parity but raises
`NotSupportedError` (`_reject_cqn`), so code ported from a thin driver gets the
recognizable exception rather than an `AttributeError`. A downstream thin
implementation should do the same.

## 39. The Mirror's fixed 11.2-identity constants (#566)

The Mirror (`seerdb/server/`) presents itself to a client as a real XE **11.2**
listener, so its handshake and post-login replies pin that server's identity as
a set of fixed byte constants. Some are **computed** — assembled field-by-field
by a real codec, with the meaningful fields parameterized and only the parts a
client skips left zero. Others are **captured verbatim** — a byte string lifted
from a live 11.2 capture and replayed as-is. This section says which is which and,
for the verbatim ones, why they cannot currently be regenerated. It is the
transparency baseline any later decision about un-pinning the Mirror from field
version 11.2 has to build on.

**Everything here is the 11.2 identity by design.** "Captured verbatim" is not a
gap to be closed for its own sake — while the Mirror deliberately answers *as* an
11.2 server, these bytes simply *are* that server's identity. The distinction that
matters is whether a value has been *decoded* (its structure understood) or is
still an undifferentiated blob.

### 39.1 Handshake identity — `server/handshake.py` (§4.1, §4.2)

The PRO / DTY capability block is **computed** (`build_caps_block_reply` frames
the banner, charset id, and the pieces below into the TTC payload); the pieces it
frames are the fixed 11.2 identity, each now modelled by its own builder or named
feature-map rather than a verbatim blob:

| Constant | Size | What it is | Status |
|----------|-----:|------------|--------|
| version banner, charset id | — | `x86_64/Linux …` banner + AL32UTF8 (873) | computed (literal) |
| `_PRO_CHARSET_ELEMENTS` | 50 B | 10 × 5-byte charset elements `<a> 03 <b> 03 <flag>` | **generated** — `encode_charset_elements` from a `(a, b, flag)` entry list; operands carried as captured NLS ground truth |
| `_PRO_FDO` | 100 B | the fixed descriptor block (FDO) | **generated** — length-framed charset descriptor; the DB + national charset ids (AL32UTF8, AL16UTF16) are named, the type-representation vector carried opaque (§4.1) |
| `_SERVER_COMPILE_CAPS` | 39 B | the 11g **compile** capability vector | **generated** — a named `{CCAP_*: value}` feature map (`_render_caps`); this *is* the field-version-6 identity (§4.2), the client negotiates off `[CCAP_FIELD_VERSION]` |
| `_SERVER_RUNTIME_CAPS` | 7 B | the 11g **runtime** capability vector | **generated** — a named `{RCAP_*: value}` feature map (`_render_caps`) |
| `_SERVER_DTY_TABLE` | 913 B | the type-conversion matrix (thin DTY reply) | **generated** — `encode_dty_table(_SERVER_DTY_ENTRIES)` from a readable per-type `(type, conv, rep)` entry list (#611); structure known (§4.2) |
| `_PRO_SQLPLUS_PAYLOAD` | 117 B | the `deadbeef` PRO reply | **computed (#564)** — an ANO null-negotiation response, built field-by-field from the ANO codec (§4.1.1) |
| `_TYPE_REPLY_SQLPLUS_PAYLOAD` | 16 B | the `deadbeef` third-round type reply | **computed (#565)** — a DTY reply carrying the DB time zone + timezone-file version (§4.2.1) |

The two `deadbeef` blocks were the last opaque negotiation blobs; #564 and #565
decoded both, so nothing in the handshake path is now an undifferentiated blob —
the verbatim rows are all the fixed capability / charset identity, replayed
because the Mirror pins 11.2, not because their meaning is unknown.

### 39.2 Query path — `query.py` (§36)

| Constant | Size | What it is | Status |
|----------|-----:|------------|--------|
| `_oci_version_trailer` | 10 B | packed release + capability word on the post-login version-call reply (`encode_version_banner_oci`) | **computed** — the release is the session's identity's, by client (§39.3); the capability word is the pinned 11.2 value |
| OCI describe column trailer | 13 B + 23 B | the zeroed post-name block (`_DCB_COLUMN`) and cursor-uuid preamble on `encode_describe_oci` | **computed** — every meaningful field (type/precision/scale/length/charset/csfrm/max_size/null_ok/name) is built; only the describe-timestamp / instance-id region the client skips is emitted as zeros |
| OER return-status trailers | var | the execute / DML / DDL / fetch / commit / logoff status envelopes | **computed** — reduced to load-bearing structure (§36); meaningful fields parameterized. Opaque regions are mostly **zeroed** (a real reply's describe timestamp, SCN and counts, which the client skips), but a few are **carried verbatim** because zeroing them breaks the client — see below |

Not every opaque byte can be zeroed. Three small markers are **carried** —
load-bearing by position, their byte values' meaning still opaque, but their
*nature* pinned by a differential capture (sqlplus through `tools/capture_proxy.py`
against 11g, 21c and 23ai, 2026-09-07):

| Marker | Where | Finding |
|--------|-------|---------|
| `06 01 22` (the head of `_OCI_RXH`) | describe-column trailer, offset 33: the row header's token, flags and offset-2 byte | client draws ORA-03113 if zeroed; **version-independent** — byte-identical in the describe reply of all three servers |
| `f6 31 0a` (`_OCI_FETCH_CONST`) | end-of-fetch OER; recurs as `20 f6 31 0a` at `_OCI_OER_ENVELOPE` offset 72 | a **fixed 11g OER-trailer constant** — identical across every 11g reply, absent from 21c/23ai (which replace the whole trailer) |
| touched-row **rowid** (`_OCI_DML_ROWID`) | DML status OER, offsets 27..40, echoed byte-swapped in the trailer | real physical row identity; a synthetic value is unvalidated |

The capture also disproved a standing guess: the OER offset-56 `0x0136` (310) is
**not** the negotiated TTC protocol version — it does not track the server (21c
and 23ai lack it entirely), it is another fixed 11g OER-format constant. What
stays undecoded is only the *meaning* of these fixed bytes, not their nature or
their version-dependence; both are now settled.

### 39.3 The version-call trailer, decoded

`_OCI_VERSION_TRAILER` is the packed version + a capability word. RE'd by
capturing sqlplus (through `tools/capture_proxy.py`) against **three** live
servers and diffing the trailer that follows the banner:

| server | client | banner | trailer |
|---|---|---|---|
| 10.2.0.5.0 | sqlplus 10.2 | `banner` | `05 20 0a` · `09 01 00 00 00 03 00` |
| 11.2.0.2.0 | sqlplus 11.2, 23.26 | `banner` | `02 20 0b` · `09 01 00 00 00 03 00` |
| 18.4.0.0.0 | sqlplus 11.2 | `banner` | `00 00 12` · `09 01 00 00 00` · 2 bytes |
| 18.4.0.0.0 | sqlplus 23.26 | `banner_full` | `00 04 12` · `09 01 00 00 00` · 2 bytes |
| 21.3.0.0.0 | sqlplus 11.2 | `banner` | `00 00 15` · `09 01 00 00 00` · 2 bytes |
| 21.3.0.0.0 | sqlplus 23.26 | `banner_full` | `00 03 15` · `09 01 00 00 00` · 3 bytes |
| 23.26.2.0.0 | sqlplus 11.2 | `banner` | `00 00 17` · `09 01 00 00 00` · 2 bytes |
| 23.26.2.0.0 | sqlplus 23.26 | `banner_full` | `20 1a 17` · `09 01 00 00 00` · 3 bytes |

- **Bytes `0..2` — the release** sqlplus prints for `SHOW RELEASE`: the high
  three bytes of Oracle's packed release word in **little-endian** order. Before
  18c the word is `(major<<24)|(minor<<20)|(component<<12)|(patchset<<8)`, so
  11.2.0.2 → `02 20 0b`. From 18c it is `(major<<24)|(update<<16)|(revision<<12)`,
  so 23.26.2 → `20 1a 17` (#2024). Generated by `_oci_version_trailer(release)`.
- **Which release, and which banner, go by the client** (#2024). An 18c or later
  server tells sqlplus 23.26 its full release (`product_component_version
  .version_full`) and the two-line `v$version.banner_full` ("...\nVersion
  23.26.2.0.0"), and sqlplus 11.2 its base release (`version`, 23.0.0.0.0) and
  the one-line `banner`. The Mirror draws the line at a client whose own
  capability block names field version 18.1 or later (`banner_full` is 18c's);
  no sqlplus between 11.2 and 23.26 has been tried.
- **Bytes `3..7` (`09 01 00 00 00`)** are stable across all of them.
- **The bytes after them** change from one session to the next on 18c and later
  (23ai: `f1 0e 1d`, `fa 0e 1d`, `03 0f 1d`), and are `03 00` on 10.2 / 11.2.
  The Mirror pins the 11.2 value (`_OCI_VERSION_CAPS`).

A passthrough presents its upstream's release in both, and in the login's
`AUTH_VERSION_NO`, through the backend's `session_release()`. The Mirror over
PostgreSQL presents the identity of its field version.

## 40. OCI object-type describe — `TTI_KOD`, function 92 (#1411)

An OCI client (sqlplus, thick python-oracledb) learns an object or collection
type through function **92 (`0x5c`, `TTI_KOD`)**, not through SQL as the thin
client does (§21.9). sqlplus needs it for `set serveroutput on`: before it reads
`DBMS_OUTPUT.GET_LINES` it describes `DBMSOUTPUT_LINESARRAY`, and with the type
in hand binds the lines as that collection (§40.4). Captured with sqlplus 23.26
and with thick python-oracledb's `gettype()` against a live 11g (2026-10-03).
The integers are OCI's fixed-width little-endian (§36), not the thin
variable-length form.

### 40.1 Request

`03 5c <seq>`, a `ub4` opcode, then a mostly-zero call frame. Two forms were seen:

- **By name** (opcode `3`; what sqlplus sends):

  ```
  03 5c <seq> 03 00 00 00 | 92 x 00 | ub4 2 | ub4 schema buffer length
  (3 x its characters; 0: none) | [ub1 length + schema] | ub4 0
  | ub4 name buffer length (3 x the name's characters, 63 for 21)
  | ub1 length + name | 00 00 00 00 00 01
  ```

  The schema is there when the client names one: `09 00 00 00 03 'SYS'` for
  SYS.XMLTYPE (§40.5). With none, its bytes are absent, not a zero length.

- **By REF** (opcode `4`; thick `gettype()` after resolving the name with a
  describe of its own, and sqlplus for the system types of §40.3): the same frame
  carrying a 36-byte REF (§40.2) of the type wanted.

### 40.2 Reply

A by-REF reply is one or more **records** then an ordinary OER (§36). A by-name
reply opens with a header first:

```
0d 02 | ub4 2 | TEXT schema | ub4 0 | TEXT name | ub1 0
      | ITEM(REF of the type) | 01 00                 then the records
```

`TEXT` is a `ub4` count, then the `ub1` length and the bytes (`03 00 00 00 03
'PYO'`).

The schema in that header is the **connected user's** (`PYO`), even for a SYS
type reached through a public synonym; the record's own image names the real
owner.

Each record, verified on every record of every capture:

```
0d 01
ITEM(REF of the record's TYPE)   ub1 1
ITEM(REF of the object itself)   ub1 <the last byte of the type's id>
ITEM(18 00 <3 bytes> 00 x 19)    -- the 3 bytes differ per session, fixed within one
00 01 00 | ub4 image length | 09 00 | the image, as a DALC (ub1 length, or fe + ub1 chunks + 00)
```

`ITEM` is a `ub4` length then that many bytes. The descriptor's three
per-session bytes were `fb b9 81`, then `fc 09 86`, `fc 09 87` … in later
sessions, climbing like a counter; the Mirror sends the first.
The closing OER is the 136-byte envelope (§36) with a success status,
`row_kind` 1, and command type and category 0. A **REF** item is 36 bytes:
`24 00`, a flags triple (`22 12 08` for the metatypes' own records, `22 02 08`
otherwise), the 16-byte object id, then 15 bytes that were `00 x 13 01 00` in
every capture.

The **image** is a pickled object (§21.3): `85 01 fe <ub4 BE length>`, then one
value per attribute (a `ub1` length, `fe` + `ub4 BE` length, or `ff` for NULL).
The object is a **type descriptor**: an instance of a system type whose own
descriptor says how to read it.

### 40.3 The system types

| id (16 bytes) | type | what an instance describes |
|---|---|---|
| `00 x 15 01` | `SYS.KOTTD` | a type: its name, typecode, TDS |
| `00 x 15 02` | `SYS.KOTTB` | a collection's element part |
| `00 x 15 03` | `SYS.KOTAD` | an attribute |
| `00 x 15 42` | (not yet named) | another part of a type |
| `00 x 15 0f` | `SYS.NUMBER` | the built-in NUMBER |

A user type described by REF comes back as one `KOTTD` record and one each of the
`KOTTB` / `KOTAD` / `0x42` parts, their ids the type's own with byte 5 counting
up. The client then asks for each system type it has not seen by its id; those
answers are the same in every session.

A **`KOTTD` instance** has ten attributes. `KOTTD` describes itself, and its own
TDS lists exactly these ten leaves (`0e`, three `07 00 1e 01 00 00`, `0d`, `11`,
`11`, `0d`, `0d`, `09`):

| # | value | DBMSOUTPUT_LINESARRAY | KOTTD itself |
|---|---|---|---|
| 0 | 4 bytes | `ae 9a 00 01` | `ae 9a 00 01` |
| 1 | schema | `SYS` | `SYS` |
| 2 | name | `DBMSOUTPUT_LINESARRAY` | `KOTTD` |
| 3 | version | `$8.0` | `$8.0` |
| 4 | ub2 BE typecode | `00 7a` (122, named collection) | `00 6c` (108, object) |
| 5 | the TDS (§21.9) | VARRAY, bound `7fffffff`, of VARCHAR(32767) | ten leaves |
| 6 | the null-image TDS | | |
| 7 | ub2 BE | `80 00` | `00 16` |
| 8 | ub2 BE | `00 01` | `00 01` |
| 9 | a REF | the type's next part | |

The TDS in attribute 5 is **byte for byte** what the PG backend's
`dbms_pickler.get_type_shape` answer builds (`_tds` in
`seerdb/server/backends/postgres.py`): for `DBMSOUTPUT_LINESARRAY`,
`_TdsCollection(varray=True, bound=0x7fffffff, element=_tds_chars(7, 32767, False))`.

**The 12c band** (sqlplus 23.26 against a live 18c). The same exchange, but:

- the record descriptor is a bare 35 bytes, `22 00 de ad be ef 00 01 00 22`, five
  zeros, three per-session bytes (`69 47 19`), zeros -- no `ITEM` length;
- the by-name header ends `01 00 00 00 00 00`;
- KOTTD's three name leaves are VARCHAR(**128**), the identifier length 12.2
  raised, and its attribute part has another id;
- the closing OER is the 144-byte wide form (§36) with row kind and offset 52
  both 0, where 11g sends 1 at both.

Sending a 12c client the 11g forms made it break the call off with a marker.

**The Mirror's side.** `encode_kod_reply` / `encode_kod_image` build the reply in
either band. `kod_system_record` holds SYS.KOTTD's description of itself, and
`kod_type_record` / `encode_kod_named_reply` describe a user type from what a
backend's `describe_type(name)` returns -- schema, name, id, kind and the TDS pair.
The Mirror-over-PG backend answers it from the catalog, with
`DBMSOUTPUT_LINESARRAY` a VARRAY domain in `sys`. A passthrough answers it for a
collection type from its upstream (#2016). It gets the id and TDS from
`DBMS_PICKLER.GET_TYPE_SHAPE(schema, name, …)`, the form 11g has as well as 23ai,
and the owner and kind from `ALL_COLL_TYPES`, resolving a bare name to the
current schema and then a public synonym. Its null-image TDS is the one every
collection has, a single null leaf. A live 23ai's TDS for
`DBMSOUTPUT_LINESARRAY` is byte for byte the one the PG backend builds. An object
type isn't served by a passthrough yet: its null-image TDS needs the attribute
tree, and `GET_TYPE_SHAPE`'s other output, the `LDS`, is a layout descriptor, not
that tree. Against the captures both
bands' replies are byte for byte the live ones, but for the instance marker every
Mirror OER carries.

**Inferred, not yet confirmed:** the TDS leaf codes `0d`, `0e`, `11` and `09`
are read here as a 2-byte integer, a 4-byte integer, raw bytes and a REF, from
the sizes of the values they describe. Attribute 0, attributes 7 and 8, and the
`0x42` part are unnamed.

### 40.4 Binding the collection (`GET_LINES`)

With the type described, sqlplus binds `:LINES` as type **109** (`0x6d`). Its
OCI bind descriptor carries, in place of a scalar's `01 <type> 03 00 00 <size>`,
`00 6d 00 00 00`, the `ub4` buffer size (2000), twelve zeros, `ub4 16`, `ub1 16`
and the type's 16-byte id, then `ub4 1`. Its IN value is the type's REF `ITEM`
followed by `01`, twelve zeros and `01 00` — a collection carrying nothing.

A pre-12c sqlplus (10.2, 11.2) writes the same call with three differences
(#1826):
- the descriptor has **ten** zeros before `ub4 16` and `ub1 16`, so the id sits at
  offset 24 from the marker, not 26;
- the IN value's empty tail has **fourteen** zeros;
- `:NUMLINES`'s descriptor reads `01 02 01 00 00` (flag `01`, not `03`), and its IN
  value is the whole 22-byte buffer, `16 c1 06` and then zeros, where 23.26 sends
  `02 c1 06`. No NUMBER ends in a zero byte (its digits are 1 to 100, a negative's
  terminator is `0x66`), so the padding is cut.

The Mirror reads the id from the descriptor (§43) and accepts either tail. Unread, the
call was refused and `SET SERVEROUTPUT ON` printed nothing.

The reply is the ordinary OCI OUT-bind reply (§36): the 50-byte header with the
bind count, a **direction marker per bind** — `0x10` OUT, `0x30` IN OUT, the masks
of the 9i bind prompt (§19.7): `10 30` here, the count being IN OUT, and `10` for
a lone OUT collection — then `07` and the values. The collection's value is its
REF `ITEM`, `01` and zeros (ten from 11g, eight from 18c), the image's `ub4`
length, `01 00`, the image as a DALC, and no return code after it; the image is
the pickle of §21.6: `88 01 13 01 03 00 02 0a 'from plsql' ff` for one line,
`88 01 09 01 03 00 02 ff ff` for none. The count follows as an ordinary NUMBER
with its return code.

**The batches after the first (#2041).** GET_LINES hands back at most as many
lines as `:NUMLINES` asks, 15 for sqlplus 23.26. For the next batch sqlplus
doesn't send the block again. It runs the same cursor with **`TTI_EXEC`**
(function 4): `03 04 <seq>`, the cursor id and an iteration count (ub4 LE
each), eight zero bytes, then an RXD row holding the values of the binds that
came in with one, `:NUMLINES` alone (`07 02 c1 10`). The pure-OUT lines
collection carries nothing. The cursor id is the one the first reply's status
frame names at offset 11: a live 18c sent 4, and the Mirror's frames have always
carried 2 there.

The reply is the first execute's RXD row of OUT values and its OER, with neither
the 50-byte OUT-bind header nor the status frame. sqlplus repeats it until a
batch comes back short. The Mirror keeps the last block that handed OUT values
back and runs it again with the new IN values. Before that, it refused the call,
and sqlplus printed the first 30 lines and dropped the rest, over every backend.

**A batch past 252 bytes (#2042).** The lines collection's image is a value
like any other, and past 252 bytes it is chunked: `0xFE`, then chunks, then a
zero length. The chunk lengths' width is set by one compile capability:
**BIG_CHUNK_CLR**, bit `0x20` of `CCAP_TTC3` (python-oracledb's
`TNS_CCAP_BIG_CHUNK_CLR`).
- A server that advertises it, as a live 18c does, sends ub4 LE lengths in
  chunks of up to 2000 bytes: a 3026-byte image as `fe d0 07 00 00` + 2000,
  `02 04 00 00` + 1026, `00 00 00 00`.
- One that doesn't, as 11g and the Mirror don't, sends ub1 lengths in 255-byte
  chunks, whatever the field version: a 615-byte image as `fe ff` + 255, `ff`
  + 255, `69` + 105, `00`. Live 11g sends this even to sqlplus 23.26.

The bit sets the width in both directions. Against a server that advertises it,
sqlplus also sends its long SQL text and bind values in ub4 chunks, which is why
#2015 saw a 4000-byte LOB buffer arrive with ub4 lengths at a live 18c and ub1
lengths at the Mirror. The Mirror keeps the bit clear and sends ub1 chunks
(`_oci_value_bytes`). Before, it sent the thin form, whose chunk lengths are ub4
in the 12c band, and sqlplus misread the image and hung. Setting the bit instead
was tried. Every GET_LINES batch then printed, but sqlplus also switched its LOB
reads and its long SQL text to big chunks, which the Mirror doesn't read, and
`SHOW ERRORS` and a 5000-byte CLOB select broke.

**Every value, both ways (#2053).** The framing is not GET_LINES's own. It
covers every OCI value past 252 bytes: a scalar OUT value, a character or RAW
row cell, and an IN value. sqlplus sends a 300-character VARCHAR2 variable's
value back to the Mirror as `fe ff` + 255, `2d` + 45, `00`, and a live 18c sends
the OUT value as one big `fe 2c 01 00 00` chunk, since it advertises the bit.
In the thin form a long OUT value or row cell hung sqlplus, a `select rpad('x',
1000, 'y')` among them. Read with the thin decoder, a long IN value lost its
start. The Mirror reads IN values in ub1 chunks (`_oci_read_value`) and frames
OUT values and character, CHAR and RAW cells in them.

The Mirror reads the bind (`_oci_bind_descriptors`, the type id riding on
`bind_types` to the backend as `BindVar.toid`) and writes the value
(`encode_out_bind_response_oci` with `types` / `inputs`); against the captures the
values part is the live one byte for byte in both bands. Its scalar OUT binds
used to carry `0x10` whatever their direction; they now report it too.

A backend hands a collection OUT value back as an object of the bind's type --
Mirror-over-PG turns orafce's `text[]` into one (`_collection_outs`) -- and the
Mirror pickles it as sqlplus was seen to get it (`_oci_object_image`): the image
length in **one byte** when it fits (`88 01 13 …`), and the collection's **kind**
in the prefix segment (`01 03` for a VARRAY), where the thin path's pickle writes
`fe` and four bytes, and `01 01`. python-oracledb reads either form.

Decoders: `parse_kod_request`, `decode_kod_reply`, `decode_kod_image`, pinned
to the captured exchange by `tests/test_kod_decode.py`.

Against a server that cannot describe the type (ORA-03115), sqlplus falls back to
binding `:LINES` as a plain PL/SQL VARCHAR array (`01 01 43 …`, element size
32765) and re-executes the block by cursor id while its line count stays above
zero (#1411, #1515).

### 40.5 An XMLTYPE column (#2050)

A live 11g and 18c tell an OCI client that an XMLTYPE column is type **58**, an
opaque type, where a thin client is told 109. sqlplus 11.2 against 11g and 23.26
against 18c were captured.

- **The describe column** carries the type. Its second byte is `00` (`01` for a
  plain column), the length is 2000, and there is no max size. Where a plain
  column has the type id's ub4 length 0 (offset 18, 22 in the 12c band), this
  one has `10 00 00 00`, then `10` and the 16-byte id
  `00 x 13 02 01 00`, then the ub2 version 1. From there to the null flag it
  has 7 zero bytes (11 in the 12c band), where a plain column has 20 (24). After
  the name, the schema and the type name each go as a ub4 length then a ub1
  length and the bytes (`03 00 00 00 03 'SYS' 07 00 00 00 07 'XMLTYPE'`), where
  a plain column has two zero ub4s. The column adds nothing to the max row size.
- **The execute reply is the describe alone**, as for a LOB (§6.0), with the LOB
  describe tail and status. sqlplus then describes SYS.XMLTYPE by name and
  SYS.KOTTD by REF (§40.3), and only then fetches.
- **The type's record** is a KOTTD instance unlike a user type's. Its image is
  flagged `84` (a user type's `85`), and its values are:
  - the flags `ae 9a 01 01`;
  - SYS, XMLTYPE, and the version, `$8.0` from 11g and `$VSN_1` from 18c;
  - typecode `00 3a`;
  - a TDS and a null TDS, the same from both servers;
  - the kind word `50 00` and the ub2 1;
  - a REF to the type's version, under an id of the database's own.

  The header names the type under SYS, as asked, not under the user.
- **A row cell** is the object frame of §40.4, under XMLTYPE's id. The image
  inside is the thin form's (§24) with the flag word `00 00 00 14` (STRING
  and a 0x10 bit). A NULL has image length 0 and ends at the `01 00`. Past 252
  bytes the image is chunked: in 255-byte ub1 chunks from 11g, and in ub4
  chunks of 2000 from 18c, which advertises BIG_CHUNK_CLR (§40.4).

Through the Mirror, sqlplus broke off after a 109 describe, and the session
ended in the reset-marker loop. The Mirror now answers each step as above. It
serves SYS.XMLTYPE's record itself, whatever the backend, carrying each
capture's version id.

## 41. Application context — function 154 (#1775)

`set_app_context(namespace, **values)` / `clear_app_context(namespace)` do what
`DBMS_SESSION.SET_CONTEXT` / `CLEAR_CONTEXT` do without a round trip of their
own: the change rides the next call as a piggyback (`0x11`, function `0x9A`),
once, one piggyback per namespace. A client advertises it with bit `0x80` of its
`OCI1` compile capability; the server advertises nothing.

```
11 9a <seq> [ub8 token 0, field version 23.1 ext 1 and up]
01 <ub4 namespace length>              pointer, length
01|00 <ub4 entry count>                pointer: 1 set, 0 clear
<ub2 flags>                            0x01 set, 0x02 clear
00                                     field version 12.1 and up only
<namespace with its length>
per entry: <key, two lengths> <value, two lengths> <ub4 0>
```

Captured from python-oracledb 26 on 23ai, `set_app_context('CLIENTCONTEXT',
ATTR1='VALUE1', ATTR2='V2')`:

```
11 9a 03 00 01 01 0d 01 01 02 01 01 00 0d 43 4c 49 45 4e 54 43 4f 4e 54 45 58 54
01 05 05 41 54 54 52 31 01 06 06 56 41 4c 55 45 31 00
01 05 05 41 54 54 52 32 01 02 02 56 32 00
```

**The zero byte follows the negotiated field version, not the server.** At 12.1
and up it is there; at 11.2 and below it is not, and a piggyback that has it
fails the call with ORA-03120 (a set) or ORA-28267 (a clear, whose namespace is
then read one byte early). Measured: 10g (field version 4) and 11g (6) take the
old form; 23ai takes the old form when held at 11.2, and the new one at 12.1,
12.2, 18.1 and its own. 18c and 21c take the new form.

**8i and 9i take the piggyback and ignore it**: no error, and the context is not
set. seerdb refuses `set_app_context()` / `clear_app_context()` there
(`NotSupportedError`) rather than let a change silently not happen. A pooled
11g session sends OCI's form of it (§4.1.4).

A namespace the session may not set fails the call the piggyback rode in front
of with ORA-28267, through a break/reset; the session carries on. `CLIENTCONTEXT`
is the namespace any session may set.

## 42. Transaction priority — ALTER SESSION, function 204 (#1776)

23ai's priority transactions give a session a `TXN_PRIORITY` of `LOW`, `MEDIUM`
or `HIGH`. A thin client sets it three ways and learns it one way.

**At login** the priority joins the time-zone statement the AUTH carries as
`AUTH_ALTER_SESSION`: `ALTER SESSION SET TIME_ZONE='+02:00' TXN_PRIORITY='medium'`.
Only to a server with the feature, which rejects the whole statement otherwise.

**Later** a change rides the next call as an ALTER SESSION piggyback (`0x11`,
function `0xCC`), once:

```
11 cc <seq> [ub8 token 0, field version 23.1 ext 1 and up]
<ub4 flags 0> 01 <ub4 1>               pointer, one key-value pair
<"TXN_PRIORITY", two lengths> <value, two lengths> <ub4 flag>
```

The pair's flag is 1 for an empty value, which restores the database default,
and 0 otherwise. Captured from python-oracledb 26 on 23ai, `'low'`:

```
11 cc 03 00 00 01 01 01 01 0c 0c 54 58 4e 5f 50 52 49 4f 52 49 54 59 01 03 03 6c 6f 77 00
```

**The piggyback needs data type 668 (`ALTSESS`) in the client's data-type
table.** Without it 23ai fails the call with ORA-03115, whatever the client's
capabilities say: seerdb's capability bytes were byte-for-byte python-oracledb's
and its table differed by that one entry. python-oracledb added 668 in 26.

**The server reports the priority** as keyword 204 of a SYNC server piggyback
(`17 05`, the keyword-value pairs also used for sessionless transactions' keyword
201): at login, after the AUTH reply's own pairs, and on the reply to any call
that changed it, the piggyback or an `ALTER SESSION SET TXN_PRIORITY` in SQL
alike. 23ai reports `HIGH` by default, and a value set by the client in the
case it was sent:

```
17 05 01 01 10 01 01 16 01 03 03 6c 6f 77 00 01 cc 00
```

It does so only for a client advertising bit `0x01` of `FEATURE_BACKPORT2`
(compile capability 45), and advertises the same bit itself when it has the
feature: 23ai and 26ai send `0x03` there, 18c and 21c have no byte 45. A
client refuses the feature against a server without the bit, as python-oracledb
does (DPY-3043). Measured working at seerdb's own field versions down to 12.1
against 23ai.

**23ai reports after every client change, even to the same value.** A client
holds an empty priority after a reset until the report replaces it, so a server
that reports only what differs leaves it empty. A SQL `ALTER SESSION SET
TXN_PRIORITY` takes a bare value in upper case (`medium` is reported as
`MEDIUM`) and a quoted one as written (`'Low'`); anything but LOW, MEDIUM or
HIGH, the empty string included, is `ORA-00096: invalid value URGENT for
parameter txn_priority, must be from among LOW, MEDIUM, HIGH` (measured for
#1779).

## 43. OCI bind descriptors and the value row (sqlplus, #2064)

An OCI `OALL8` (sqlplus) carries, behind the SQL and the `al8i4` array, one
descriptor per bind and then the `07` (RXD) row of values, as the thin execute
does (§5.1). The descriptor is the thin OAC's (§5.3) fields at fixed width — `ub1` type,
flags and precision, a `ub1` scale, `ub4` max length, max array, continuation
flags and TOID length, the TOID, a `ub2` version and charset, a `ub1` form, a `ub4`
max characters — with OCI's own parts:

- a lead byte, `01` for a scalar, `00` for an object (type `0x6d`);
- from 12c, four zeros before the continuation flags and four before the
  charset;
- for a scalar, six zeros after the version, one after the form, and a `ub4`
  column id after the max characters.

So a scalar's descriptor is 41 bytes before 12c and 49 from it. The lengths are
the client's buffer: three bytes a character for the database charset, two for
NCHAR (a `VARCHAR2(4000)` is 12000, an `NCHAR(5)` 10, with 5 max characters).
The form is `2` for `NCHAR`, `NVARCHAR2` and `NCLOB`, whose values ride as
UTF-16; NUMBER carries `0`. Flag `0x80` marks a name that occurs again (#2034):
its value is not in the row.

**Values ride in descriptor order, except that a char or RAW bind whose buffer
is wider than 4000 bytes rides last**, as a thin LONG-class bind does. sqlplus
23.26 and 11.2 binding `VARCHAR2(7)`, `VARCHAR2(4000)`, `CHAR(13)`,
`NCHAR(5)`, `NVARCHAR2(9)` and `NUMBER` to a Mirror sent `abc`, `ij`, the two
NCHAR values, `42`, then `defgh`. To a live 18c, which advertises
`BIG_CHUNK_CLR`, sqlplus 23.26 sent the same six in descriptor order and its
NCHAR values chunked with `ub4` lengths; the Mirror does not advertise it
(#2042) and is sent the order above, with `ub1`-length chunks.

Read by a pattern search for each descriptor's lead, the Mirror took descriptor
bytes for the first value, and PostgreSQL refused the NUL in them.
