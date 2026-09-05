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
| 5 | C→S | DATA/PRO | 161  | protocol negotiation (§4.1), body marker `dead…`  |
| 6 | S→C | DATA/PRO | 127  | server PRO reply (version banner)                 |
| 7 | C→S | DATA/DTY | 38   | data-type negotiation (§4.2)                      |
| 8 | S→C | DATA/DTY | 238  | server DTY reply (type capabilities)              |

then the O5LOGON auth rounds (§4) and the query.

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

The layout above is the **oracledb / seerdb dialect**: the request leads with
the `TTI_PRO` (`0x01`) token. **Old clients (sqlplus 11.2) speak a different
PRO dialect** whose request leads with a `DE AD BE EF` magic. Verified by
capturing both against the same 11g XE listener:

| Client PRO request | Server PRO reply | Server DTY reply |
|--------------------|------------------|------------------|
| `TTI_PRO 0x01 …` (oracledb, seerdb) | `TTI_PRO`-form, **238 B** | **924 B** |
| `DE AD BE EF …` (sqlplus 11.2)      | `DEADBEEF`-form, **127 B** | 238 B |

**The server replies in the client's dialect** — a `0x01` request gets a
`TTI_PRO` reply, a `deadbeef` request gets a `deadbeef` reply. Both negotiate
the same field version (`6` for 11g), but the two reply shapes are not
interchangeable: `decode_token_pro` only understands the `TTI_PRO` form, so
replaying a `deadbeef` reply to seerdb (or vice-versa) fails to parse. A server
(the Mirror, `seerdb/server/`) must therefore answer in whichever dialect the
client's PRO request used.

seerdb's server (the Mirror) serves **both** dialects (#265). `serve_login`
inspects the PRO request — `pro_is_sqlplus` checks whether its TTC payload leads
with the `deadbeef` magic — and holds that verdict so both `encode_pro_reply`
and `encode_dty_reply` answer in one dialect: the `TTI_PRO` reply (238 B / 924 B)
for a thin client, or the `deadbeef` reply (127 B / 238 B) for sqlplus / thick
OCI. Both replay the captured 11g bytes so the client negotiates field version 6.
The `deadbeef` DTY reply (238 B) carries the same capability block the `TTI_PRO`
dialect puts in its PRO reply, just packaged into the other message.

**The 127 B `deadbeef` PRO reply is an ANO null-negotiation response** (#564). The
name is not incidental: `0xDEADBEEF` is the ANO / Native Services container magic
(§33.2). sqlplus / thick OCI opens its login with an ANO negotiation, and the
server answers by selecting the *null* algorithm for every service, so no cipher
or MAC is activated and the session stays plaintext. This is the byte-identical
twin of the reply the thin ANO path (§33) replays as its null response — it *is*
that response. The Mirror builds it field-by-field from the ANO codec
(`build_pro_sqlplus_reply`), no longer a verbatim blob. Its 117 B TTC payload
decodes (via the project's own `decode_ano`) as a container plus four services:

| Field | Value | Note |
|-------|-------|------|
| container magic / length / **version** / count | `DEADBEEF` / 117 / **`0x00000000`** / 4 | the sqlplus/OCI stamp — a modern thin client's container stamps `0x0B200200` here instead |
| supervisor (svc 4) | version `0x0B200200`, status `31` (OK), service-array `[4, 1]` | announces the supervisor + auth services |
| auth (svc 1) | version `0x0B200200`, status `0xFBFF` | (a thin client's auth status is `0xFCFF`) |
| encryption (svc 2) | version `0x0B200200`, selected-algo **`0`** | null cipher — plaintext |
| data-integrity (svc 3) | version `0x0B200200`, selected-algo **`0`** | null checksum — no MAC |

The container version is `0x00000000` while every *service* still echoes the
modern `ANO_VERSION` (`0x0B200200`) — the one wrinkle that separates this reply
from `encode_ano_response` (§33), together with the `0xFBFF` auth status and the
null algorithm selections. `tests/test_handshake_generation.py` pins the built
bytes to the live 11g capture.

#### 4.1.2 The deadbeef / OCI auth phase (server-side / the Mirror)

Past the handshake, sqlplus / thick OCI marshals the whole O5LOGON exchange
differently from the thin form, but over the **same mutual-auth crypto** (§4.3).
The Mirror (`seerdb/server/`) drives it from captured 11g templates so a real
sqlplus 11.2 logs in — verified live. The rounds:

1. **Extra data-type round.** Unlike a thin client (which jumps from DTY to
   OSESSKEY), sqlplus runs a third negotiation: a `ttc=02` request the server
   answers with a fixed **26-byte** reply, *then* OSESSKEY.
2. **OCI field marshalling.** The `TTI_FUN` auth messages (OSESSKEY, AUTH)
   replace thin's `0x01` pointer bytes with an **8-byte `FE FF FF FF FF FF FF FF`
   indicator** (`0xFFFFFFFFFFFFFFFE` LE) and use **fixed 4-byte little-endian
   ub4** lengths (not Oracle variable-length ub4). The header up to the username
   is constant, so the ub1-length-prefixed username sits at a **fixed offset 51**
   (`parse_osesskey_oci` / `parse_auth_response_oci`).
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

**`AUTH_SVR_RESPONSE` is 48 bytes here, not thin's 16.** The real 11g listener
sends `AES-CBC(nonce16 ‖ "SERVER_TO_CLIENT" ‖ PKCS7-pad, ConnKey)` — a 16-byte
nonce, the marker, and a full 0x10 pad block. The client finds the marker
substring after decrypting, so the nonce is an unchecked filler
(`server_proof_oci`). Reconstructing it byte-for-byte from a decrypted live
capture confirmed the structure.

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
- The post-login **version call** (`OCI_VERSION_CALL`) uses the *same* `0x11 0x6b`
  TTI_80SES wrapper and 15-byte prefix — they differ only in the wrapped inner
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

> **Oracle 26ai advertises field version 27 (#458).** The
> `container-registry.oracle.com/database/free:latest` image — branded **26ai**
> (`ORACLE_HOME=.../26ai/dbhomeFree`), though the engine still reports
> `23.1.162.0.0` via `v$version` — sends `compile_caps[7] = 27` in its PRO,
> above the 23ai fast-auth maximum of 24. seerdb caps its own advertised field
> version at 24 (`FIELD_VERSION_23_4`) and so negotiates `min(24, 27) = 24`,
> connecting and running the full 23ai surface (auth, ANO native encryption,
> queries — all validated live). The capability arrays also grew: `compile_caps`
> from 45 bytes (21c) to **54**, `runtime_caps` from 7 to **13**, with new bits
> in `LOGON_TYPES` (#4 `0xEF`), `OCI3` (#35), `TTC4` (#40 `0xFF`), `LOB2` (#42),
> `TTC5` (#44 `0xFF`), and 9 new trailing slots (45–53, incl. `FEATURE_BACKPORT2`
> at 45 and `VECTOR_FEATURES` at 52). What those fv-25–27 additions actually
> unlock is unknown from the capability bits alone and needs a fv-27-capable
> reference-client capture — tracked as exploratory, non-blocking work in #458.

> **12c+ support (issue #27) — RESOLVED.** Advertising a 12c+ field version is
> necessary for 21c login but not sufficient: it changes how the server frames
> every subsequent message (DTY table form, OER layout, datatype encodings), so
> it had to land together with the matching version-gated decoders. All of that
> is now done — the 256-bit O5LOGON crypto (§4.5), the capability layout (this
> section) and the version-gated formats. seerdb logs in and runs its full
> test suite against 11g, **12c+ (21c, 23ai)** and 10g from one build.

#### 4.2.1 The deadbeef third-round type reply (server-side / the Mirror)

sqlplus / thick OCI runs an **extra data-type round** after DTY, before it sends
OSESSKEY (a thin client jumps straight to OSESSKEY — §4.1.2). The server answers
that third `ttc=02` request with a fixed **16-byte TTC payload** (a 26-byte DATA
packet). Despite living outside the ordinary DTY exchange, it is an ordinary
**data-type reply carrying the DB session time zone and the server's
timezone-file version** (#565) — not an opaque blob. The Mirror builds it
field-by-field (`build_type_reply_sqlplus`):

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
carries (`crypto.o3logon`) but cannot test for lack of a 9i/8i server, so 10g is
the oldest auth seerdb is verified against.

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

If successful, the server returns TTI_RPA with:

| Key                   | Description                        |
|-----------------------|------------------------------------|
| `AUTH_SVR_RESPONSE`   | Server proof (hex-encoded)         |
| `AUTH_VERSION_NO`     | Server version number              |
| `AUTH_SESSION_ID`     | Session identifier                 |

The client validates by decrypting `AUTH_SVR_RESPONSE` with the connection key and checking for the presence of `"SERVER_TO_CLIENT"` in the plaintext.

`AUTH_VERSION_NO` is a decimal string of a single packed integer holding
the server's release. Decode it as `major` (bits 24-31), `minor`
(20-23), `update` (12-19), `patch` (8-11), `port-specific update`
(0-7) — e.g. `186647040` = `0x0B200200` = `11.2.0.2.0`, matching
`product_component_version` on XE. seerdb exposes the dotted form as
`Connection.version` and masks the major release out for its protocol
version gate.

Decoding what three live servers send confirms the layout across releases:

| Server | `AUTH_VERSION_NO` | Packed | Decodes to | `AUTH_VERSION_SQL` |
|--------|-------------------|--------|------------|--------------------|
| XE 11.2   | `186647040` | `0x0B200200` | 11.2.0.2.0   | `22` |
| XE 21c    | `352518144` | `0x15030000` | 21.0.48.0.0  | `25` |
| 23ai/26ai | `387588096` | `0x171A2000` | 23.1.162.0.0 | `26` |

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
  1. `al8i4[9]` (the 10th All8 element, normally `0`) is set to `0xC000`.
  2. The 12c+ `al8pidmlrc` block — the three zero bytes that follow the
     register-id field in the post-11g OALL8 header — becomes
     `01 | iteration_count(SB4) | 01` (e.g. four iterations → `01 01 04 01`).

  Omitting either makes the server reject the execute as malformed
  (`ORA-03137 [kpoal8Check-4]`). The counts come back in the response **RPA
  region** (`TTI_RPA`, token 8) that precedes the trailing OER, as a
  `count(UB4) | count × UB4` block sitting between the opaque RPA body and the
  OER token. seerdb extracts it in `decode_token_rpa_piggyback` (armed for
  the execute via a context flag) and surfaces it through
  `cursor.getarraydmlrowcounts()`. The two modes combine: a failed iteration
  reports a row count of `0`.

### 5.2 Fetch (TTI_FUN/TTI_FETCH)

For fetching additional rows from an open cursor:

```
TTI_FUN | TTI_FETCH | SeqNum | Cursor(SB4) | RowsToFetch(SB4)
```

The default fetch size is 100 rows (configurable via the `fetch` parameter),
matching oracledb's effective batch so a large `fetchall` drains in ~n/100
round-trips rather than ~n/15.

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

The layout above is the 11g form. 12c+ (field version >= 12.2,
`encode_token_raw`) uses oracledb's `_write_column_metadata` layout instead:
a fixed flag byte (`TNS_BIND_USE_INDICATORS = 1`), `ContFlags` as a `ub8`, an
`OID`/`Version`, the bind charset as a `ub2` (AL32UTF8 = 873 for char binds,
0 otherwise), the `CharsetForm` byte, a LOB-prefetch length, and a trailing
`oaccolid` `ub4`. Sending the 11g OAC to a 12c server is rejected with
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
in each column across all rows.

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
| `seerdb.cursor.cursor` / `Var(seerdb.CURSOR)` | `0x01, 0x00` (REF CURSOR placeholder); value returned in the IOV (§6.5) |

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
8i applies the same 4000-byte rule through its own request form (§19.11), so
the 8i builder writes rows the same way (#714); 9i is unverified until #711.

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
`EXEC :key := N`) reproduces the live reply byte-for-byte. The compatibility shim
(`examples/oracle_compat_backend.py`) evaluates the literal `:v := <literal>`
assignments; a non-Oracle backend cannot run general PL/SQL, but this one idiom
covers the bind-a-value-then-use-it flow, so a following `SELECT … WHERE k = :v`
receives the value as an ordinary IN bind (§5.4).

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
  render `NCHAR(N)`;
- each non-last column carries a `1` **continuation flag** three bytes before its
  end and a **describe-timestamp entry** in its post-name region (the last column
  leaves both zero);
- the describe **timestamp** and **object id** are instance-specific — but sqlplus
  *rejects a describe reply whose timestamp / object id are zero* (it silently
  waits for more, unlike the query describe which tolerates a zeroed timestamp), so
  the Mirror carries the non-zero captured values verbatim rather than zeroing them.

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
   even when that row is byte-identical to Oracle's.
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
   (`parse_lobops_read`) serves exactly that slice as `LOB_DATA` (`0e` + `0xFF`-byte
   chunks) + the echoed-locator RPA + OER; a read returning fewer units than
   requested ends the loop. The row locator and the READ reply come from one
   capture, so they echo the same opaque locator and stay consistent.

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

2. **`TTI_LOBOPS` READ → whole content, once.** The thin client does *not* loop:
   its `encode_dictionary_lobops` requests the whole LOB in one read (amount
   `0x40000000`, no per-chunk offset walk). The Mirror answers with
   `encode_lob_read_response_thin` — the full content as `LOB_DATA` (`0e` +
   `0xFF`-byte chunks, §14) followed by a **success OER** `04 01 <status>`
   (`_encode_oer(1,0,0,b'')`). The client reads the content, scans to the OER, and
   stops; CLOB content is UTF-16BE (decoded to `str`), BLOB is raw `bytes`.

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

A character / RAW value longer than the single-byte DALC length (253 bytes) is
**chunked**, and the chunk framing is field-version-specific (§6.4): 11g uses
single-byte chunk lengths, 12c+ uses ub4 chunk lengths. A server must encode row
values with the *negotiated* form — `seerdb/server/query.py` uses `encode_chr`
(field-version-aware), not the always-12c+ `_bytes_with_length`, or an 11g client
decodes a value past 253 bytes as a "truncated DALC field".

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

12c+ (field version >= 12.2) differs from 11g in the per-column block:
scale is `sb1` (a raw signed byte) rather than 11g's variable-length
sb4, and an extra `oaccolid` ub4 follows `max_size`. seerdb decodes
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

If any bind is OUT / IN OUT, a `TTI_RXD` (`0x07`) token follows, then one
value per OUT / IN OUT bind **in bind order** (IN binds contribute nothing):

- **Scalar** OUT value: a DALC blob (decoded by the bind's declared type) plus
  a trailing 1-byte indicator (`0x00` = present).
  e.g. NUMBER `10` → `02 c1 0b 00`, VARCHAR `"hi!"` → `03 68 69 21 00`.
- **REF CURSOR** OUT value: a 1-byte length, then an inline describe of the
  cursor's result set (the same per-column metadata *and trailer* as a `TTI_DCB`,
  §6.4), then the nested cursor id (`ub2`) and a 1-byte indicator. The client then
  drains that cursor id with `TTI_FETCH` (§5.2). See python-oracledb's
  `_create_cursor_from_describe`. Because this nested describe reuses the §6.4
  format, it carries the **same pre-11g difference**: at field version < 11.2 (10g)
  there is no `dcbqcky` trailer, so skipping a phantom one consumes the cursor id
  and desyncs the IOV decode. seerdb gates it identically (#84/#87); the
  per-column metadata already shares the field-version-gated decoder.

After the values come the usual `TTI_RPA` and `TTI_OER` tokens.

**Server side — the Mirror answering a thin client (#483).** The wire carries
**no** bind direction in the request — Oracle infers IN / OUT / IN OUT from the
block source — so the Mirror can't label binds from the OALL8 alone. Instead it
hands the backend *every* bind of a PL/SQL block as a `BindVar` (value + declared
type + OAC buffer size); the backend registers each as an OUT-capable variable,
runs the block (a pure-IN param simply keeps its input value, an OUT/IN OUT one
is written back), and returns every variable's value. `encode_out_bind_response_thin`
then emits the IOV with **all** binds marked OUT (`16`) and a DALC value + `ub4`
return code per bind. The client keeps only the positions it bound as a `Var`
(`_assign_out_binds` filters by its own bind list), so the extra echoed IN values
are read and discarded — correct, if slightly more than a real server sends. This
is what carries the thin `callproc` / `callfunc` / OUT-`Var` flow; passing the
value with its type + size is also the fix for the `ORA-06502: buffer too small`
a value-only OUT bind hit.

A **REF CURSOR OUT bind** (`OUT SYS_REFCURSOR`, #483) is returned in that same
RXD slot but in the inline-describe form above: the backend opens the cursor, the
Mirror drains its columns + rows into a `CursorResult`, parks the rows on a fresh
cursor id (the ordinary `_Cursors` registry), and `encode_out_bind_response_thin`
emits `<len><describe body><cursor id><indicator>` for that position (the describe
body is the shared §6.4 encoder). The client reads the marker, then drains that
cursor id with `TTI_FETCH` like any other result set. Because the inline describe
reuses the §6.4 body, it inherits the same field-version gating (no `dcbqcky`
before 11.2).

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
  end_to_end_seq# (ub2, skipped) |
  current_row_number (ub4)    -- the DML rowcount on 11g (see note) |
  ora_error_code (ub2)        -- 0 on success |
  array_elem_error (ub2, skipped) | array_elem_error (ub2, skipped) |
  cursor_id (ub2) |
  error_position (sb2)         -- the parse offset; surfaced as DatabaseError.offset (oracledb parity) |
  sql_type, fatal, flags, user_cursor_options, upi_param,
    warn_flags (6 x ub1) |
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
byte is a type tag; the printable form is `"*"` + standard base-64 of the
remaining bytes (no `=` padding). Example: value
`02 04 01 00 19 83 02 c1 02 fe` → `*BAEAGYMCwQL+` (the trailing `c1 02` is the
table's NUMBER primary key, since an IOT rowid is logical). NULL when
`num_bytes` is 0.

**Server side — the Mirror (#484).** The Mirror holds a rowid as its rendered
string (what the backend hands back), so it inverts the render before emitting.
`encode_rowid_value` parses the 18-char string back to object / file / block /
slot (`string_to_rowid`, the inverse of the render) and writes the structured
RID; `encode_urowid_value` base64-decodes the `*`-body and re-frames it with a
leading type tag (the tag is stripped on decode, so any value round-trips). Both
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

Large values are split into many ≤253-byte chunks (XE uses 64-byte chunks),
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
(chunks ≤ 253 bytes, terminated by a zero-length chunk), and — unlike the OCI
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

| Length     | Encoding                                                     |
|------------|--------------------------------------------------------------|
| 0 (empty)  | `0x00`                                                       |
| 1..253     | `<length>, <data>`                                           |
| 254 (long) | `0xFE`, then chunked: repeated `<chunk_len>, <chunk_data>` (max 64 bytes per chunk), terminated by `0x00` |
| 255 (null) | `0xFF` — null marker, no data follows                        |

### 12.3 Key-Value Pair Encoding

Used in authentication messages:

```
KeyLength(SB4) | KeyLen(UB1) | KeyData | ValueLength(SB4) | ValueLen(UB1) | ValueData | NbPair(SB4)
```

Zero-length keys or values are encoded as a single `0x00` byte.

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

**CREATE_TEMP body** (no source locator): a fixed field block captured verbatim
from python-oracledb on 21c, differing between CLOB (type `0x70`) and BLOB
(type `0x71`) in the type-spec bytes and both ending with the trailing
`sb4 0x0369`. The server returns the new locator in the response RPA.

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
  blocked native BFILE support.
- **`READ`** (op `0x0002`) is the ordinary read with the ub2-prefixed (opened)
  locator; content streams back as the normal `LOB_DATA` chunk (§14.3).
- **`FILE_CLOSE`** (op `0x0200`) sends neither amount nor data.

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

The `LOB_DATA` chunk is length-prefixed with the version-gated
`bytes_with_length` form (§6.4): 11g uses single-byte chunk lengths,
12c+ a `0xFE` marker with `ub4` chunk lengths and a zero terminator.
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
   descriptor framing the native VECTOR / JSON binds use, §18.1 / §17).
4. `execute`. No `FREE_TEMP` — the temp LOB is released at session end.

`Cursor.execute` / `AsyncCursor.execute` do this transparently: a PL/SQL block
(detected by `_is_plsql`) with an over-limit str/bytes bind has that bind
promoted to a `TempLob` marker before encoding. Plain DML keeps the
streamed-LONG path. **11g is excluded** — it rejects `CREATE_TEMP` outright
(immediate FIN, no error packet), there is no thin reference to crack it
against, and a large PL/SQL LOB bind there keeps its prior ORA-01460 behaviour;
the feature is gated on `field_version >= 12.1`.

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
   length, then the locator bytes.
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
   the next descriptor aligned.

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
- **`OPEN`** (`0x8000`) / **`CLOSE`** (`0x10000`) / **`TRIM`** (`0x0020`) /
  **`GET_CHUNK_SIZE`** (`0x4000`) — acked. Their *value-returning* forms (a real
  server-preferred chunk size, applying `TRIM`'s new length, `GET_LENGTH` /
  `IS_OPEN`) are deferred to #421: pinning those reply bytes needs a capture from
  a client that actually sends them (the thin client doesn't, and thick needs
  Instant Client), and the ack already keeps the wire in sync. `READ` (and any
  unrecognised op) still routes to the #413 read path, unchanged.

### 14.6 Persistent-LOB locator field map (Mirror, deadbeef dialect)

The Mirror hands sqlplus a **persistent-LOB locator** in the row value
(`encode_lob_locator_oci`) and echoes it in the READ reply. It is a 105-byte
structure; both the row value and the read-tail embed the *same* locator, so
`_oci_lob_locator(is_clob)` builds it once. Offsets are within the locator:

| off | field | CLOB / BLOB | kind |
|---|---|---|---|
| `0..2` | length `0x68 0x00` + version `0x01` | same | structural |
| `3` | **charset form** | `02` (char) / `01` (binary) | generated |
| `4..5` | **flags** `0x0c __` — bit `0x80` = variable-width charset | `0c 88` / `0c 08` | generated |
| `8` | **LOB type** | `02` / `01` | generated |
| `16` | LID marker `0x56` | same | structural |
| `17..26`, `36..38`, `52..54`, `80..82`, `102..104` | **physical LID** — object id + three segment DBAs + SCN | **synthetic (zeros)** | generated |
| `31..32` | **charset id** (ub2 BE) | `0369` (873 = AL32UTF8) / `0000` | generated |
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
- **Value** (`encode_token_rxd`, after the `TTI_RXD`=0x07 token): a fixed 19-byte
  **descriptor** (`01 28 28 00 26 00 04 61 08 00 00 00 01 00 00 00 00 00 00` —
  the same one python-oracledb uses for any LOB-backed inline bind, so #70 JSON
  reuses it), then the **image length (ub2)**, **22 zero bytes**, then the image
  framed like RAW (`encode_chr`: a single length byte < 254, else the `0xFE`
  marker + `ub4` chunks). Both constants are stable across element types and
  sizes; works at field version 16 and 17.
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
08 01 <numcols:1B> <column>*  <trailer>
column = <OAC-fv2> <null_ok:1B> <namelen_bytes:1B> <ub4 namelen_chars> <DALC name> 00 00
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
**`ub4 namelen_chars`**, then the **DALC-encoded UPPERCASE name** and a two-byte
`00 00` inter-column separator.

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

In the returned `TTI_RXD`, each column is a DALC value followed by an indicator:
a present value is followed by a single `0x00`; a **NULL** column is an empty
value (`0x00`) followed by the two-byte marker **`0x81 0x01`**. Missing the
wider NULL indicator silently truncates the row stream (consumes one byte too
few and desyncs the following rows).

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
stream (ORA-01002).

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

The **op middle** is a flag block (go-ora's LOB request layout, sb4-encoded on
fv2): has-dest, dest length, source offset, dest offset, charset-present, a reply
flag (`1` except for FILE_CLOSE), null-o2u, the **operation** (`TNS_LOB_OP_*` —
GET_LENGTH `0x01`, READ `0x02`, FILE_OPEN `0x0100`, FILE_CLOSE `0x0200`), has-scn,
scn length. Across the four ops only the operation, the READ's source offset (`1`)
and the reply flag change, so `_o7_lobop_mid(operation, …)` generates all four
(and `_o8i_lobop_mid` the 8i form — the same block with fixed ub4-LE fields,
§19.17).

An **empty** LOB (`EMPTY_CLOB()` / `EMPTY_BLOB()`) has a valid locator but GETLEN
returns amount 0, so no READ is issued and the value is `""` / `b""`. CLOB content
arrives in the column's **DB charset** (a single-byte run on a typical 9i, **not**
the UTF-16BE the modern path uses) and is decoded with that charset; BLOB content
is returned as raw bytes.

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
the Var size, default `0x7fff`). The server infers each bind's direction from the
block and signals it in the prompt; the round-trip then differs by direction:

- **Bind prompt** `0b 05 01 <numbinds> 00 01 01 00` + a direction section — one
  mask per bind, `0x20` = IN, `0x10` = OUT, `0x30` = IN OUT. Its length varies
  (the live server pads with a leading `00`), so the driver scans past the 8-byte
  fixed prefix to the first RXD/RPA token rather than computing it
  (`strip_fv2_bind_prompt`).
- **Input values** (client → server): a `TTI_RXD` with the values of the **IN and
  IN OUT** binds, in position order, skipping pure-OUT binds. Sent only when at
  least one such bind exists.
- **Return values** (server → client): a `TTI_RXD` carrying one `DALC value +
  1-byte indicator` per **OUT and IN OUT** bind, in position order, skipping
  pure-IN binds, immediately before the RPA + OER (`decode_fv2_block_out`).

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
`_bfile_read_fv2` drives the sequence (closing in a `finally`) and is dispatched
from `_resolve_fv2_lobs` by data type; the BFILE column resolves to the file
bytes, like the modern path. This completes the 9i LOB surface (CLOB, BLOB,
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

**Pre-10g key-value coding.** Each `AUTH_` pair is `ub1(len) ub4be(len) <data>`
for the key, the same for the value, then a `ub4be` padding word — distinct from
the modern variable-length `encode_sb4` form. The two-phase exchange:

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
block whose header and per-column descriptors use **fixed-width big-endian**
fields — not the `ub1`-length-prefixed `ub4`s the 10g+ DCB (§4.2's
`decode_token_dcb`) reads, so the modern decoder sees `num_columns = 0` and
desyncs. `decode_8i_dcb_describe`:

```
10  <ub1 preamble-len> <preamble: SCN + 7-byte date>
<ub1 row-width>  <ub4be num_columns>  <ub4be 0x33 (const)>
per column:
  ub1  data type (1=VARCHAR2, 2=NUMBER, 96=CHAR, …)
  ub4be  size field — NUMBER: `00 <precision> <scale sb1> <internal size 22>`;
         else bit31 = character flag | low 31 bits = max_size
  14 bytes  reserved (always 0 in captures)
  ub4be  character set (31 = WE8ISO8859P1; 0 for NUMBER)
  ub1 reserved(0)  ub1 csform  ub1 null_ok(0=NOT NULL,1=nullable)
  ub1 namelen  ub1 namelen  ub4be namelen  <name bytes>
  8-byte inter-column trailer (type-OID slot; 0 for scalar types)
describe trailer: current date as 8i bytes-with-length (ub1 len, ub4be len, data)
```

The **rows** follow as repeated `TTI_RXH` (`06`) + `TTI_RXD` (`07`) pairs. Unlike
the 9i 1-byte indicator (§19.2), each 8i column value is a DALC **followed by a
fixed 4-byte trailer** (`sb2` indicator + `ub2` return code, both zero when
present). A **NULL** column carries no value DALC at all — it is the bare 4-byte
`ff ff 00 00` (indicator −1). Values are **WE8ISO8859P1** (latin-1). The
**cursor id** for the fetch loop sits at offset 11 of the post-row terminal —
whether that opens with the `0x08` session-state piggyback or the `0x04` OER.
Decoders: `decode_8i_exec_response` / `decode_8i_cursor_id`.

**Rejected SELECT (#384).** When the server rejects the statement (bad table, bad
column, …) the execute reply is a **`TTI_OER` (`0x04`)** error status, *not* the
`TTI_DCB` (`0x10`) describe — the human-readable `ORA-NNNNN: …` text sits inline
(`_scan_ora_message`). `_execute_8i_select` checks the first byte and raises the
mapped ORA error; feeding an OER to `decode_8i_dcb_describe` (which assumes a
describe header) overruns and raises a meaningless `IndexError`.

**Duplicate-column compression.** Like the modern `TTI_BVC`, 8i omits a column
from the RXD when it repeats the previous row's value — but 8i carries the
**column bit vector inside the RXH** (a `ub1` length + the vector, at offset 14)
rather than as a separate token. LSB = column 0; an **unset** bit means "repeat
the previous row", so the RXD only carries the set-bit columns (e.g. a 3-column
row whose middle value repeats sends bit vector `05` = `0b101`). Because 8i
fetches one batch per round trip, a row can repeat a column from the **previous
batch's** last row, so `decode_8i_exec_response` threads the last decoded row
across calls. Missing this desyncs the RXD as soon as two consecutive rows share
a column value.

**ROWID / UROWID (#385).** These are **not** length-prefixed DALCs. A physical
**ROWID** (type 11) is a 1-byte reserved-size indicator (`0e`; 0 = NULL), a
**fixed 13-byte struct** — data object (ub4 LE), relative file (ub2 LE), an
unused byte, block (ub4 LE), slot (ub2 LE) — then the 4-byte trailer; it renders
to the extended base64 string (matches `ROWIDTOCHAR`), e.g. struct
`33 68 00 00 05 00 00 bb 00 00 00 00 00` → `AAAGgzAAFAAAAC7AAA`. A **UROWID**
(type 208, e.g. an index-organized table's logical rowid) is the indicator, a
reserved byte, a 1-byte body length, the body, then the trailer; it renders as
the `*`-prefixed base64 form (`urowid_to_string`). Both are usable as binds
(a ROWID/UROWID string binds straight back into `WHERE ROWID = :r`). Reading a
ROWID as a DALC over-consumes one byte and desyncs the next column. Decoder:
`_decode_8i_rowid`. Note: `ROWIDTOCHAR(ROWID)` on an IOT raises ORA-01410 on 8i,
so the UROWID reference comes from the raw value, not that function.

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

There is no describe or fetch. The response is a `0x08` RPA session-state
piggyback (a fixed 23 bytes) then the OER, whose first field after the token is
the **affected-row count as a little-endian `ub4`** — 8i is x86/Windows, so the
count rides native-endian (300 = `2c 01 00 00`). A server error is surfaced from
the trailing `ORA-NNNNN: ...` text (the binary OER layout differs from 9i's).

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
in one packet; a no-bind block skips straight to the RPA + OER. An error (compile
or runtime, e.g. ORA-06550 / PLS-00201) is surfaced from the trailing `ORA-`
text. OUT / IN OUT binds — whose returned values ride an RXD inside that reply —
are §19.14. Driver: `_execute_8i_block`.

### 19.14 Oracle 8i PL/SQL OUT binds — callproc / callfunc (#362)

An OUT (or IN OUT) parameter is a `Var` bind. In the **request** it declares its
type + return-buffer size in the OAC (§19.11), and its slot in the value section
carries the fixed OUT placeholder **`fd 01`** (an IN OUT bind sends its input
value inline instead). So `callproc('p', [5, y, z])` → `BEGIN p(:1,:2,:3); END;`
with the value section `07 <5> fd 01 fd 01`.

In the **reply**, after the `0x0b` prompt (whose direction bytes are `0x10` for
each OUT), a single `07` RXD carries the returned values in OUT-bind order, each a
**DALC + 2-byte trailer** (`c1 33` = 50, `08 proc-out`, `c2 02 08` = 107), then
the RPA + OER. `decode_8i_block_out` returns the raw value bytes per OUT bind; the
cursor's `_assign_out_binds` decodes each against its `Var`'s type. `callfunc`
is the same shape with the return value as the first (`:1`) OUT bind.

An **IN OUT** bind (#363) is a `Var` whose value is set: it sends its input value
**inline** in the request (not the `fd 01` placeholder) and its updated value
comes back in the reply's RXD, both in the same single round trip. Its prompt
direction is `0x30`. No extra machinery — the inline value path and the OUT-value
decode above already cover it.

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
(`0x60`) READ: `03 60 <seq> 01` + `ub4`-LE locator length + a 25-byte op middle +
the locator + `ub4`-LE amount (chars for a CLOB, bytes for a BLOB — pass a large
value to read it all). The reply is the **shared `0e fe <chunks> 00`** content
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
`0x04` OER, ≥ 12 bytes for the cursor id). `_recv_8i_rows` reads until that holds.
Driver: `_execute_8i_select` / `_recv_8i_rows`; encoder: `encode_8i_oall8_fetch`.

### 19.17 Oracle 8i BFILE read — the native TTI_LOBOPS wire (#401)

A **BFILE** (TNS type 114) is a pointer to an external OS file, not inline LOB
content. `decode_8i_exec_response` turns the column into a `LOB` whose locator
parses into `directory_name` / `filename` (a length-prefixed directory-object
name then file name — e.g. `… 05 "BDUMP" 0c "ORCLALRT.LOG"`), the same as the
10g+ locator.

Reading the bytes is a `TTI_LOBOPS` **FILE_OPEN → GETLEN → READ → FILE_CLOSE**
sequence, natively — no `DBMS_LOB` helper. Every op rides the **8i LOBOPS
envelope** (the same family as the CLOB/BLOB read §19.15): `03 60 <seq> 01` + a
**ub4-LE locator length** + a **25-byte op middle** + the locator + an
op-specific trailer. Reverse-engineered from a 9.2 OCI client → 8.1.7 capture
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
extracts it. GETLEN's reply carries the file length as a `ub4-LE` right after the
echoed locator (`decode_o8i_bfile_getlen`). READ's content is the shared
`0e fe <chunks> 00` form (`decode_fv2_lob_chunks`), so a large file streams across
packets and terminates on the zero-length chunk. A missing file surfaces the
server's `ORA-22285` at FILE_OPEN.

Encoders: `encode_o8i_bfile_open` / `encode_o8i_bfile_getlen` /
`encode_o8i_bfile_close` (+ `encode_8i_lob_read` for the READ), all built on the
shared `_encode_o8i_lobop` envelope. Driver: `_resolve_8i_lobs` →
`_bfile_read_8i` (sync + async). This replaced an earlier `DBMS_LOB`
temp-BLOB helper, removing its `CREATE PROCEDURE` requirement and the stored
function it left in the user's schema — the same win #46 brought to 10g+/21c.

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
value exceeds 253 bytes, so `encode_kv` uses the chunked
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

### 21.4 Attribute layout (data-dictionary)

The ordered layout is fetched from `ALL_TYPE_ATTRS` (`attr_name`,
`attr_type_name`, `length`, `precision`, `scale` `ORDER BY attr_no`) keyed by
`(owner, type_name)` and **cached per connection** — seerdb buffers the whole
result set on execute (the server cursor is drained), so this extra query runs
safely during row resolution. The SQL type name maps to a TNS type code for the
scalar decoder; a name we don't map (e.g. a nested object type — #117/#118)
leaves the attribute as raw bytes rather than desyncing.

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
  `0xFE` + ub4). A NULL attribute is a single `0xFF`. Each scalar uses the same
  encoder as its column-form bind.
- **OAC** (`_encode_object_oac`): the 12c+ bind-metadata layout — `type 109`,
  flag `TNS_BIND_USE_INDICATORS`, precision/scale `0`, buffer size, the type OID
  via `two_lengths`, and the type version (no charset). This is the **12c+** OAC;
  there is no python-oracledb reference for a pre-12c object-bind OAC (thin needs
  12.1+) and a 12c+ OAC sent to 10g/11g is rejected with a fatal ORA-03106, so
  seerdb **gates object binds on field version ≥ 12.1** (`NotSupportedError`)
  before anything goes on the wire. Object *decode* still works on every tier.

Verified by round-trip (bind via seerdb, read back via §21.1–21.4) on 21c and
23ai, scalar attribute types + NULL attributes, sync + async. Binding a bare
Python `None` to an object column is unsupported (an untyped `None` carries no
type identity); use a typed value. REF binds are #119.

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
  `0xFF`). PL/SQL associative arrays additionally prefix each element with an
  int32 key — that is #122.
- **Value framing + OAC**: unchanged from §21.2 / §21.5; only the image body is
  collection-shaped. The 12c+ bind gate applies identically.

A fetched collection surfaces as an `seerdb.DbObject` with **list semantics**
(`iter` / index / `len` / `append` / `extend` / `aslist()`), carrying its type so
it can be re-bound; build one with `typ.newobject([...])`. Decode works on every
tier (verified 10g/11g read), bind is 12c+ (round-trip 21c/23ai, sync + async).

**Both VARRAY (#117) and nested table (#118) go through this one path** — they
share the image and bind framing exactly, differing only in `collection_type`
(VARRAY 3 vs nested table 2), so nested-table support needed no new wire code
(verified read 10g/11g/21c/23ai, bind round-trip 21c/23ai). PL/SQL
associative-array element keys are #122.

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

## 22. DML RETURNING ... INTO (#120)

`INSERT/UPDATE/DELETE ... RETURNING col[, ...] INTO :b[, ...]` returns the
affected row(s)' column values into OUT binds. It is an ordinary `TTI_ALL8` DML
execute — **no special al8i4 flag or exec option**; the server infers RETURNING
from the SQL. Two framing differences from a plain DML:

1. **Request**: an OAC (bind descriptor) is written for **every** bind, but the
   `TTI_RXD` row carries values for the **input** binds only — the return (OUT)
   binds are skipped (if every bind is a return bind, the row is omitted). The
   return-bind OAC is just the Var's declared type/size.
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

**Limitation:** Oracle **11g** XMLType *columns* are CLOB-stored with a complex
binary image whose locator seerdb can't read (a reference-less case —
python-oracledb requires 12.1+). That image sets a distinguishing flag bit
(`0x01000000`, never set on the working 10g / 12c+ forms), so seerdb raises a
clear `NotSupportedError` for it rather than returning corrupt data; cast such a
column in SQL (`XMLTYPE.getclobval(col)` / `XMLSERIALIZE`) to read it. Inline XML
(`XMLELEMENT`, etc.) on 11g uses the STRING flag and works. Sync + async.

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

## 29. Advanced Queuing (#128)

Enqueue/dequeue via `connection.queue(name[, payload_type])` →
`enqone`/`deqone` (single) and `enqmany`/`deqmany` (array), with
`connection.msgproperties(payload=...)` and the queue's `enqoptions`/
`deqoptions`. Three TTI functions, RE'd from python-oracledb:

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

`connect(..., cclass=..., purity=...)` requests a Database Resident Connection
Pool server. Two small additions to the existing connect flow:

- **Connect descriptor** — when a connection class or non-default purity is
  given, the `CONNECT_DATA` gains `(SERVER=POOLED)`, which tells the listener to
  route to the connection broker instead of a dedicated server.
- **Auth pairs** — the final auth message carries `AUTH_KPPL_CONN_CLASS` (the
  connection class) and `AUTH_KPPL_PURITY` (the purity as a decimal string), the
  same way proxy auth (§27) adds its pair. Purity is `seerdb.PURITY_NEW` (1) or
  `PURITY_SELF` (2); when DRCP is requested with `PURITY_DEFAULT` a standalone
  connection defaults to `NEW` (matching python-oracledb).

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
  the wire for this server (the byte is always 0).

Receive reverses it: strip the flag byte, AES-CBC decrypt (removing the padding
marker + padding), then verify and strip the trailing MAC. Each `TNS_DATA`
packet on the wire is an independent encrypt+MAC unit, so multi-packet responses
decrypt per packet before reassembly, and the MAC keystreams stay in lock-step.

### 33.4 Login sequence with ANO active

The negotiation completes before PRO. From there the ordinary handshake runs
unchanged, but each `TNS_DATA` is wrapped as above: PRO → PRO reply →
(fast-auth bundle at fv≥18, §20) → auth → result. There is no key re-keying
after authentication for this server.

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

The classic sqlplus / thick-OCI client also negotiates ANO but stamps version
`0x00000000`; that path is handled inline by the `deadbeef` dialect (§4.1.1) and
is unaffected by the stance.

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
| `49..51` | ub2 LE | echo of the sequence field | `sequence + 2` for row/return statuses; `0` in the outbind reply |
| `52` | 1 | constant `0x01` | constant across captures |
| `56..58` | ub2 LE | TTC protocol version — `0x0136` (310) | in the TNS-version family (the Mirror pins 11g at 314 = `0x013a`); carried from the 11.2 capture |
| `72..76` | | fixed `20 f6 31 0a` instance marker | constant across captures |

The rest of the 136-byte frame (SCN region, cursor/rowid slots) is a fixed
zero-filled envelope. For an error, the `ORA-NNNNN: <message>` DALC follows the
136-byte OER. Offsets `18` and `49` carry values whose exact semantics are not
yet pinned down (a non-zero position under a *success* describe status, an echo
that is `+2` for some replies and `0` for others); they are carried from the
captures byte-for-byte. Offset `56` looks like the session's negotiated TTC
protocol version (`310` sits in the same `0x013x` family as the versions the
handshake negotiates); the Mirror emits the captured value rather than its own,
which sqlplus accepts — whether the field must track the live negotiation is
not confirmed.

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
too: `seerdb/server/session.py:_OciSequence` is a per-session counter (`+1` per
OER-bearing reply, starting at `1`) threaded into every OCI status builder,
replacing the frozen per-capture constant each status was reverse-engineered
with. The captured adjacency of the SELECT execute status (`19`) and the
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

### 39.1 Handshake identity — `_handshake_11g.py` (§4.1, §4.2)

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
| `_OCI_VERSION_TRAILER` | 10 B | packed version + capability word on the post-login version-call reply (`encode_version_banner_oci`) | **computed** — the version is generated by `_oci_version_trailer(major, minor, component, patchset)`; the capability word is the pinned 11.2 value (§39.3) |
| OCI describe column trailer | 13 B + 23 B | the zeroed post-name block (`_OCI_DCB_COL_POSTNAME`) and cursor-uuid preamble on `encode_describe_oci` | **computed** — every meaningful field (type/precision/scale/length/charset/csfrm/max_size/null_ok/name) is built; only the describe-timestamp / instance-id region the client skips is emitted as zeros |
| OER return-status trailers | var | the execute / DML / DDL / fetch / commit / logoff status envelopes | **computed** — reduced to load-bearing structure (§36); meaningful fields parameterized. Opaque regions are mostly **zeroed** (a real reply's describe timestamp, SCN and counts, which the client skips), but a few are **carried verbatim** because zeroing them breaks the client — see below |

Not every opaque byte can be zeroed. Three small markers are **carried verbatim
as capture ground truth** — load-bearing by position but with their byte values'
meaning unpinned (not decoded, not invented):

| Marker | Where | Why carried |
|--------|-------|-------------|
| `06 01 22` (`_OCI_DCB_MARKER`) | describe-column trailer, offset 33 | client draws ORA-03113 if zeroed |
| `f6 31 0a` (`_OCI_FETCH_CONST`) | end-of-fetch OER; recurs as `20 f6 31 0a` in `_OCI_OER_ENVELOPE` | fixed instance marker the client expects |
| touched-row **rowid** (`_OCI_DML_ROWID`) | DML status OER, offsets 27..40, echoed byte-swapped in the trailer | real physical row identity; a synthetic value is unvalidated |

These are the residual undecoded bytes on the query path. Decoding them further
needs real SCN/rowid/marker ground truth from a differential capture across
servers, **not** guessed meanings.

### 39.3 The version-call trailer, decoded

`_OCI_VERSION_TRAILER` is the packed version + a capability word. RE'd by
capturing sqlplus (through `tools/capture_proxy.py`) against **three** live
servers and diffing the trailer that follows the banner:

| release | trailer |
|---|---|
| 10.2.0.5.0 | `05 20 0a` · `09 01 00 00 00 03 00` |
| 11.2.0.2.0 | `02 20 0b` · `09 01 00 00 00 03 00` |
| 21.0.0.0.0 | `00 00 15` · `09 01 00 00 00 25 18` |

- **Bytes `0..2` — the version**, the low three bytes of Oracle's packed version
  word (`(major<<24)|(minor<<20)|(component<<12)|(patchset<<8)`) in **little-endian**
  order: `patchset`, `(minor<<4)|component`, `major`. So 11.2.0.2 → `02 20 0b`,
  10.2.0.5 → `05 20 0a`, 21.0.0.0 → `00 00 15`. Generated by
  `_oci_version_trailer(11, 2, 0, 2)`.
- **Bytes `3..7` (`09 01 00 00 00`)** are stable across all three releases.
- **Bytes `8..9`** are a version-era capability level (`03 00` on 10.2 / 11.2,
  larger on 21c). The Mirror pins the 11.2 capability word (`_OCI_VERSION_CAPS`).

A client only echoes the banner text, so the trailer never had to be decoded to
work; this pins it to a generated version rather than a blob. Every query-path
constant is now a real codec.
