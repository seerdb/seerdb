<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/seerdb-mark-paper.svg">
  <img src="assets/seerdb-mark-ink.svg" alt="" width="76" align="right">
</picture>

# seerdb

A pure-Python driver for a proprietary database, implementing the
[DB-API 2.0](https://peps.python.org/pep-0249/) interface by speaking the
database's native wire protocol (TNS/TTC) directly over TCP.

No proprietary client libraries or SDKs are required.

[简体中文简介](README.zh-CN.md)

> **Independent project — not affiliated with Oracle.** seerdb is a clean-room,
> independent effort and is not affiliated with, endorsed by, or sponsored by
> Oracle Corporation. Oracle®, Oracle Database, and related names are trademarks
> of Oracle and/or its affiliates. seerdb reimplements the wire protocol for
> interoperability only.

## Status

seerdb is a functional pure-Python driver: the core DB-API 2.0 and SQL
surface is stable, and it already covers async connection pooling, server-side
scrollable cursors, 23ai types (JSON / `BOOLEAN` / `VECTOR`), and the SODA
document store. It is usable for the features listed below; the feature matrix
spells out what is and isn't supported.

[`ROADMAP.md`](ROADMAP.md) covers what is being worked on now, what comes
next, and the principle behind it.
[`docs/USE-CASES.md`](docs/USE-CASES.md) collects situations seerdb could fit,
and where each stops being the right tool.

The wire protocol is reverse-engineered and implemented incrementally as a
clean-room effort — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the rules
contributors are expected to follow (no Oracle proprietary sources, no
decompiled binaries, no copied error-message catalogs; public references and
packet captures are fine).

The package also contains **the Mirror** (`seerdb.server`) — a *server* side of
the same wire protocol, which makes a non-Oracle backend (PostgreSQL, SQLite, or
a real Oracle) answer Oracle clients such as `sqlplus` or a thin driver. It is
an initial implementation, a **technology preview until general
availability**: not yet for production, outside the version promise the client
keeps, and free to change in any release until then. `pip install "seerdb[mirror]"` adds what its
PostgreSQL backend needs, and `seerdb-mirror` starts one: see
[`docs/MIRROR.md`](docs/MIRROR.md). Its wire details live in
[`docs/PROTOCOL.md`](docs/PROTOCOL.md).
Everything below describes the client.

What works:

- TNS transport layer (packet framing, fragmentation, SDU negotiation)
- TTC presentation layer (token encoding/decoding)
- Authentication handshake (O3LOGON, O5LOGON with 128/192/256-bit keys)
- Token-based authentication: pass `access_token=` instead of a password to
  authenticate with an OAuth2 bearer JWT or an OCI IAM token (for Autonomous
  Database). Accepts a token `str`, a `(token, private_key_pem)` tuple (IAM
  signs the request header with RSA-SHA256), or a zero-arg callable returning
  either — so a short-lived token can be refreshed per connection. Sync and
  async. Needs the `token` extra — `pip install seerdb[token]`
- Session setup and teardown
- SQL statement execution, full result-set decoding (DCB / RXH / RXD / BVC)
- DB-API 2.0 surface: `seerdb.connect()`, `Connection.cursor()`,
  `Cursor.execute / fetchone / fetchmany / fetchall / description /
  rowcount`, iteration protocol, context managers, PEP 249 exception
  hierarchy
- DB-API conveniences: `Connection.stmtcachesize` (read/write statement-
  cache size), `Connection.version` (server release string, e.g.
  `"11.2.0.2.0"`), `Cursor.rowfactory` (callable applied to each fetched
  row, invoked with the column values as positional arguments), and
  `Cursor.lastrowid` (ROWID of the last row an INSERT / UPDATE / DELETE
  touched). Sync and async
- Scrollable cursors: open with `conn.cursor(scrollable=True)`, then
  `Cursor.scroll(value, mode)` with `mode` in `relative` / `absolute` /
  `first` / `last` repositions the cursor and the next `fetchone()` returns
  the row at the new position (out-of-range raises `IndexError`). On 10g+
  the cursor is opened server-side and rows are fetched on demand as you
  scroll; pre-10g (9i, 8i) uses a client-buffered fallback. Sync and async
- Bind variables: `cur.execute(sql, [v1, v2])` (positional) or
  `cur.execute(sql, {"name": v})` (named, `:name` placeholders, case-
  insensitive). A name the plain form cannot express — a reserved word,
  or one starting with a digit — can be quoted as `:"name"`, which unlike
  the plain form is case-sensitive and is keyed with the quotes included:
  `{'"name"': v}`. A bind whose value cannot say what type it is — a
  `None` — takes its type from `cur.setinputsizes(name=seerdb.DB_TYPE_DATE)`
  (or positionally, or with a Python type); without that the server
  infers CHAR and rejects the comparison. The declaration applies to the
  next `execute` only. Accepted bind types are `int`, `float`, `Decimal`,
  `str`, `bytes`, `bool`, `datetime.date` / `datetime` (with optional
  timezone and microseconds), `datetime.timedelta` (→ INTERVAL DAY TO
  SECOND), `seerdb.IntervalYM(years, months)` (→ INTERVAL YEAR TO
  MONTH), and `None`. A plain `float` binds as NUMBER; wrap it in
  `seerdb.BinaryFloat(x)` / `seerdb.BinaryDouble(x)` to send a native
  32/64-bit IEEE-754 binary float (the only way to bind `inf` / `nan`,
  which a non-finite plain `float` also auto-routes to BINARY_DOUBLE).
  `str` and `bytes` binds round-trip into CLOB / BLOB columns at any
  size: a value larger than the regular ~32 KiB ceiling is streamed to
  the server across multiple TNS packets (tested byte-for-byte to
  hundreds of KiB on both 11g and 12c+)
- Anonymous PL/SQL blocks with bind variables: `cur.execute("BEGIN
  ... :x ...; END;", [val])` runs the block server-side
- Stored procedures and OUT / IN OUT binds: `cur.callproc(name,
  [in_val, out_var, ...])` where an OUT / IN OUT argument is a
  `cur.var(type)` (type is a Python type or an `seerdb` constant like
  `seerdb.NUMBER` / `seerdb.STRING` / `seerdb.DB_TYPE_TIMESTAMP` /
  `seerdb.DB_TYPE_TIMESTAMP_TZ` / `seerdb.DB_TYPE_BINARY_FLOAT` /
  `seerdb.DB_TYPE_BINARY_DOUBLE` / `seerdb.DB_TYPE_INTERVAL_DS` /
  `seerdb.DB_TYPE_INTERVAL_YM`). Seed an IN OUT value with
  `var.setvalue(0, v)`; read results with `var.getvalue()`, which gives
  back the Python type the `var` was created with — a `var(float)` reads
  as a `float` even though a NUMBER column can also be read as an `int`
  or a `Decimal`. `callproc`
  returns the argument list with OUT slots replaced by their values.
  OUT binds also work through `cur.execute` directly (pass a `Var`).
  Stored functions: `cur.callfunc(name, return_type, [args...])` returns
  the function's value (`return_type` is a Python type or `seerdb`
  constant). A REF CURSOR OUT parameter is a `cur.var(seerdb.CURSOR)`;
  after the call `var.getvalue()` is a ready-to-fetch nested cursor.
  Available on both the sync and async cursors
- Array DML: `cur.executemany(sql, [row1, row2, ...])` binds every row
  and executes the whole batch in a single server round trip (one parse,
  N iterations) instead of one `execute` per row; `cursor.rowcount`
  reflects the total rows affected. Column types are taken from the
  first row. Sync and async
- Python type coercion for fetched values: NUMBER → `int` / `Decimal`,
  VARCHAR2 / CHAR → `str` (charset-aware), DATE / TIMESTAMP / TIMESTAMP
  WITH TIME ZONE → `datetime.datetime` (a named-region zone, e.g.
  `US/Eastern`, resolves to the correct DST-aware offset via the stdlib
  `zoneinfo`, not a frozen Oracle offset table), BINARY_FLOAT / BINARY_DOUBLE →
  `float`, INTERVAL DAY TO SECOND → `datetime.timedelta`, INTERVAL YEAR
  TO MONTH → `seerdb.IntervalYM`, ROWID → `str` (the 18-char extended
  rowid, usable directly in a `WHERE ROWID = :r` bind), UROWID → `str`
  (the `*`-prefixed universal rowid, e.g. for index-organized tables),
  LONG → `str`, LONG RAW → `bytes`, NULL → `None`
- TLS connections (pass `ssl=True` to `seerdb.connect` for the system
  trust store; or `ssl={"ca_certs": ..., "certfile": ..., ...}` for a
  custom configuration; or hand in an `ssl.SSLContext` directly)
- Wallet-based mutual TLS (Oracle / ADB connection wallet): pass
  `wallet_location="/path/to/wallet"` (with `wallet_password=...` for a
  password-protected `ewallet.p12`, or none for an auto-login
  `ewallet.pem`) and, optionally, `dsn="mydb_high"` to resolve the
  host / port / service and the server-certificate DN from the wallet's
  `tnsnames.ora` / `sqlnet.ora` (`SSL_SERVER_DN_MATCH` is enforced after
  the handshake). What the alias names wins over `host` / `port` /
  `service_name` passed beside it, as in python-oracledb. Needs the `wallet` extra — `pip install seerdb[wallet]`
  — which pulls in `cryptography` for the X.509 / PKCS#12 decode
- Native network encryption (Advanced Networking / ANO): when the server sets
  `SQLNET.ENCRYPTION_SERVER` and/or `SQLNET.CRYPTO_CHECKSUM_SERVER`, the
  connection negotiates a cipher and data-integrity algorithm at connect time
  and transparently encrypts every packet — AES (128 / 192 / 256-bit CBC) plus
  an SHA-2 MAC — using pycryptodome, no extra dependency. Negotiated and
  validated live against a 26ai server that *requires* AES256 + SHA256. Sync
  and async
- Negotiation cache (opt-in): pass `negotiation_cache=True` to remember a
  server's field-version protocol negotiation (keyed by host / port / service)
  so reconnects to the same target skip the bare-protocol probe round trip;
  a stale entry is detected and transparently retried from scratch
- DML rowcount and full server error messages: `cursor.rowcount`
  reflects the rows affected by `INSERT` / `UPDATE` / `DELETE` (read
  from the OER block); `DatabaseError(code=NNN)` carries the full
  `"ORA-NNNNN: ..."` text the server sent, not just the numeric code
- Follow-up `TTI_FETCH` flow for result sets larger than a single
  server response — `OracleConnect.execute` automatically drains the
  cursor when the EXEC OER signals `call_status = 1`
- Arrow / DataFrame bulk fetch: `cur.fetch_df_all()` returns the result
  set as a `pyarrow.Table`, `cur.fetch_df_batches(size=N)` yields it as
  record batches (column types derived from the describe, so a NUMBER /
  Decimal column lands as the right Arrow type without inference). Sync
  and async
- LOB objects: a SELECT of a CLOB / BLOB returns a `LOB` you can
  `read(offset, amount)`, `size()`, `write(value, offset)`, `trim()`,
  `open()` / `close()` / `isopen()` and `getchunksize()` — sync, and the
  same set prefixed `a` on an async cursor. NULL LOBs come back as
  `None`. **Mutating one needs its row locked** (`SELECT ... FOR UPDATE`,
  or an uncommitted INSERT in the same transaction), as Oracle requires;
  otherwise the server answers `ORA-22920`
- `fetch_lobs=False` on `connect()` restores value semantics: CLOB /
  BLOB columns materialise to `str` / `bytes` of any size, with
  `EMPTY_CLOB()` / `EMPTY_BLOB()` as `""` / `b""`. The default is `True`,
  matching python-oracledb
- BFILE read: SELECT of a `BFILENAME(...)` / BFILE column round-trips
  the external file contents as `bytes`, read natively over
  `TTI_LOBOPS` (`FILE_OPEN` → `READ` → `FILE_CLOSE`). The only
  privilege the user needs is READ on the relevant DIRECTORY object —
  no server-side PL/SQL helper or CREATE PROCEDURE is installed
- Transaction control (commit, rollback, ping); sessionless transactions
  (start / suspend / resume by transaction id)
- End-to-end application tracing: `connection.module` / `action` /
  `client_identifier` / `clientinfo` / `dbop` flow to the server for
  monitoring (V$SESSION etc.)
- Multiple character set support, including the national charset: bind
  full Unicode through `DB_TYPE_NVARCHAR` / `DB_TYPE_NCHAR` regardless of
  the database charset, and read NVARCHAR2 / NCHAR / NCLOB back as `str`
- Cursor caching for DML: repeat `execute()` of the same INSERT /
  UPDATE / DELETE reuses the server-side cursor handle and skips
  the parse step. Cache size capped at 32 entries per connection
  (LRU eviction)
- Connection pool: `seerdb.create_pool(host=..., user=...,
  password=..., service_name=..., min=2, max=10)` returns a
  thread-safe pool of warm authenticated connections. `pool.acquire()`
  returns a context manager that releases on `__exit__`. Idle
  connections health-check on next acquire (configurable via
  `idle_timeout`)
- Async (asyncio) API: `await seerdb.connect_async(...)` returns
  an `AsyncOracleConnect`; `conn.cursor()` returns an
  `AsyncCursor` with `await cur.execute(...)`, `await cur.fetchone()`,
  `async for row in cur` iteration, and `async with` context
  managers. LOB cells (CLOB / BLOB / BFILE) auto-resolve through
  `await lob.aread()` exactly like the sync path. Async pool
  via `await seerdb.create_pool_async(...)` with the same
  `acquire/release/idle health-check` semantics as the sync `Pool`.
  Shares the protocol code with the sync APIs; the duplication is
  just the I/O layer
- SODA (Simple Oracle Document Access), 18c+: `conn.getSodaDatabase()`
  returns a `SodaDatabase` for JSON document collections —
  `createCollection` / `openCollection` / `getCollectionNames`, document
  `insertOne` / `insertOneAndGet` / `insertMany`, upsert `save` /
  `saveAndGet`, query-by-example
  `find().filter(...).getDocuments()` / `getOne()` / `count()` /
  `skip` / `limit` and streaming `getCursor()`,
  `replaceOne` / `replaceOneAndGet` / `remove`, and
  `createIndex` / `dropIndex` / `getDataGuide`. Built on `DBMS_SODA`.
  Sync and async

## Design goals & non-goals

seerdb is **pure Python by design** — no C extensions, no build step, no
compiler, and no Oracle Instant Client. It installs anywhere CPython runs
(`pip install`, no per-platform wheels), the whole package is type-annotated and
mypy-checked in CI, and the source stays easy to read, audit, and contribute to.

Staying pure Python is a deliberate **non-goal to add Cython or native
extensions**: they would trade that portability and readability for speed the
project does not need today. If a hot path ever warrants it, the plan is to
profile with the benchmark harness (#166) and optimize the Python — or ship an
*optional* accelerator with a pure-Python fallback — never a hard C dependency.

## Compatibility

**Oracle 9i.** `RETURNING ... INTO` works, though not the way it does on 10g+.
The 9i server rejects the clause in the modern request form (`ORA-00439`), so
the driver rewrites the statement into an anonymous PL/SQL block, where the
`INTO` targets are ordinary OUT binds — a form 9i has always supported. This is
transparent: pass a `var()` as you would anywhere else, `getvalue()` returns a
list just as it does on 10g+ (`[]` when nothing matched), and `cursor.rowcount`
reports the rows the statement touched.

Two limits follow from running as a block. Multi-row `RETURNING` into scalar
binds raises `ORA-01422`, exactly as on a current server, and there is no
`BULK COLLECT` or `executemany()` with `RETURNING`: 9i has array DML, but not
for a block, and 8i has none. A *quoted* bind name (`:"my bind"`) is refused
with `NotSupportedError`: the server rejects a quoted placeholder inside a
PL/SQL block even though plain pre-10g DML accepts one. Use an unquoted name.

**Oracle 8i.** The same rewrite serves `RETURNING ... INTO` here too. It also
settles an older failure mode: sent in the native form, a *failing* RETURNING
left 8i mid-protocol and the next statement died with `ORA-00600`. Inside a
block the same failure is an ordinary PL/SQL error — the statement raises
`ORA-00001` and the session stays usable.

`DatabaseError.offset` is `None` on 8i, whose error reply carries no position;
9i reports it.

The driver negotiates the wire dialect per connection, so a single build speaks
to every supported server — from Oracle **8i (8.1.7) through 26ai**:

| Oracle Database | Status | Notes |
| --- | --- | --- |
| 26ai | ✅ supported | validated live (auth, native encryption, queries). The `free:latest` "26ai" image advertises TTC field version 27; the driver negotiates it down to 24 and runs the full 23ai surface. Its engine reports release `23.26.2`, of the 23ai lineage, so it shares the 23ai row's feature set. Fv-25–27 additions are unexplored ([#458](https://github.com/seerdb/seerdb/issues/458)) |
| 23ai | ✅ supported | fast-auth login at field version 24; JSON / OSON, native `BOOLEAN`, `VECTOR` (dense + sparse), column annotations |
| 21c | ✅ supported | |
| 19c · 18c · 12c | ✅ supported | same 12c+ wire protocol as 21c |
| 11g (11.2) | ✅ supported | primary reference tier |
| 10g (10.2) | ✅ supported | |
| 9i (9.2) | ✅ common surface | the legacy field-version-2 (`TTI_ALL7`) dialect — see the matrix note; the native `OALL8` dialect is an experimental opt-in (`oall8=True`) |
| 8i (8.1.7) | ✅ common surface | the 9.2-era `OALL8` dialect; the oldest and most limited tier — see the matrix note. 8.1.7 is the floor (Oracle 8.0 is unsupported) |

CI runs the offline suite on Python 3.10–3.14 and the integration suite against
live 11g, 18c, 21c and 23ai, and 23ai at 12.1 compatibility; 10g, 9i and 8i are
validated locally, and 12c–19c share the 12c+ protocol the 18c and 21c tiers
exercise.

## Feature matrix

| Area | Support |
| --- | --- |
| **DB-API 2.0** — `connect`, cursors, `execute` / `executemany`, `fetchone` / `fetchmany` / `fetchall`, `description`, `rowcount`, iteration, context managers, PEP 249 exception hierarchy | ✅ |
| **Bind variables** — positional & named (`:name`, or `:"name"` for a name the plain form cannot express), all scalar types, `None` | ✅ |
| **Scalar types** — NUMBER, VARCHAR2 / CHAR / NVARCHAR2 / NCHAR, DATE, TIMESTAMP [WITH [LOCAL] TIME ZONE], INTERVAL DAY-SECOND / YEAR-MONTH, RAW, BINARY_FLOAT / BINARY_DOUBLE, ROWID / UROWID | ✅ |
| **LONG / LONG RAW** | ✅ |
| **LOBs** — CLOB, NCLOB, BLOB, BFILE read; large `str` / `bytes` → CLOB / BLOB binds (streamed past the ~32 KiB inline limit) | ✅ |
| **23ai types** — JSON / OSON, `BOOLEAN`, `VECTOR` (dense + sparse) | ✅ |
| **23ai column annotations** — `cursor.annotations` (per-column `{name: value}` maps), via fast-auth at field version 24 | ✅ |
| **PL/SQL** — anonymous blocks, `callproc`, `callfunc`, OUT / IN OUT binds, REF CURSOR OUT | ✅ |
| **Transactions** — commit, rollback, autocommit, ping | ✅ |
| **Array DML** — `executemany`, `getbatcherrors`, `getarraydmlrowcounts` (12.1+) | ✅ |
| **Result handling** — large-result `TTI_FETCH` drain, server-side scrollable cursors (`scroll()`, with a client-buffered fallback), `rowfactory`, `lastrowid` | ✅ |
| **Statement validation** — `cursor.parse()` parses a statement on the server without running it (10g+) | ✅ |
| **Arrow / DataFrame fetch** — `cursor.fetch_df_all` / `fetch_df_batches` (pyarrow `Table` / record batches) | ✅ |
| **SODA** — document store over `DBMS_SODA`: collections, documents, query-by-example (with streaming), insert / read / upsert / update / delete / bulk, indexing + data guide (18c+) | ✅ |
| **Connection** — pool (warm sessions + idle health-check), statement cache, `changepassword`, TLS, wallet mTLS, DRCP (`server_type='pooled'`, with `cclass` / `purity`; a DRCP pool generates its own class, as in python-oracledb), proxy auth, an opt-in negotiation cache that skips a round trip on fast-auth reconnects; `dsn` as an Easy Connect string, a connect descriptor (with address failover) or a `tnsnames.ora` alias, IPv6, TCPS through an HTTPS proxy; `ws://` / `wss://` to a Mirror's WebSocket listener (a seerdb extension, the `ws` extra) | ✅ |
| **Authentication** — O3LOGON (8i / 9i) and O5LOGON (10g+, 128 / 192 / 256-bit); token-based auth — OAuth2 (bare JWT) and OCI IAM (signed) for Autonomous Database | ✅ |
| **Native network encryption** — Advanced Networking (ANO): AES-CBC encryption + SHA-2 data-integrity negotiated at connect, for a server with `SQLNET.ENCRYPTION_SERVER` / `CRYPTO_CHECKSUM_SERVER` set | ✅ |
| **Advanced Queuing (AQ)** — enqueue / dequeue over `DBMS_AQ`, including JSON payloads | ✅ |
| **Implicit result sets** — `DBMS_SQL.RETURN_RESULT` (`getimplicitresults`) | ✅ |
| **Two-phase commit / XA** — `tpc_begin` / `tpc_prepare` / `tpc_commit` / `tpc_rollback` with an `Xid` | ✅ |
| **Request pipelining** — `create_pipeline()` batches operations into one round trip (23ai) | ✅ |
| **Async** — full `asyncio` API (connection, cursor, pool) at parity with the sync API | ✅ |
| **Character sets** — AL32UTF8 and others; national-charset (`DB_TYPE_NVARCHAR` / `NCHAR`) binds | ✅ |
| Continuous Query Notification (CQN), sharding keys | ❌ not supported — thick-only (OCI) capabilities absent from the thin protocol; `conn.subscribe(...)` and `shardingkey=` / `supershardingkey=` are accepted but raise `NotSupportedError`, matching the thin reference |

Most of the above works across every supported server version; a few features
are inherently version-scoped: the **23ai types** need 23ai (`VECTOR` /
`BOOLEAN`) or 21c+ (JSON), **SODA** needs 18c+, and **array DML** needs 12.1+.

**Oracle 9i** (the legacy field-version-2 / `TTI_ALL7` dialect) runs the common
surface — DB-API, scalar and national-charset binds, DATE / TIMESTAMP / INTERVAL,
RAW, LONG / LONG RAW, LOB reads, DML, PL/SQL blocks with IN / OUT / IN OUT binds,
transactions, and the full async API — and much of what later versions add:
array DML (`executemany`, with `batcherrors`), REF CURSOR OUT binds and nested
`CURSOR()` columns, LOB objects (read, write, trim, size, open / close), object
types fetched as `DbObject`s, the cursor cache, `DatabaseError.offset`,
`cursor.warning` and `cursor.bind_directions`. It lacks `BINARY_FLOAT` /
`BINARY_DOUBLE`, a plain bind past 4000 bytes (declare a LONG / LONG RAW
column's value `DB_TYPE_LONG` / `DB_TYPE_LONG_RAW`, and write a CLOB / BLOB
through its locator), object and REF binds, array DML with `RETURNING`, and
`changepassword`. Its DB charset also can't store text it doesn't cover, so use
`DB_TYPE_NVARCHAR` / `NCHAR` for full Unicode there rather than a plain `str`
bind.

**Experimental: the native 9i dialect** (`connect(..., oall8=True)`, also on
`connect_async`). Instead of the compact form, seerdb logs in and talks to 9i as
a native 9.2 OCI client does: the 64-bit `OALL8` form, on the same call sequence
as 8i. Over the 9.2 bed it passes the integration suite like the default path
does, with these differences:
- **No cursor cache**, as on 8i, so a repeated statement is parsed again.
- **Only the 8-byte O3LOGON key.** The 16-byte variant native sqlplus gets is not
  supported.
- **9.2's own answers can differ.** A bare `CONNECT BY LEVEL` on `dual` returns
  one row, as it does to sqlplus 9.2. Wrap it in `SELECT * FROM (...)` to get
  every row.
- **Validated on 9.2.0.4 only.**

It stays an opt-in: the client has to choose the dialect before the server
identifies its version (#799). The flag is ignored on other tiers.

**Oracle 8i** (8.1.7, the 9.2-era `OALL8` dialect) is the oldest and most limited
tier. It runs connect (`O3LOGON`), SELECT, single-row DML / DDL, PL/SQL blocks
with IN / OUT binds, CLOB / BLOB and native BFILE reads, LONG / LONG RAW, ROWID /
UROWID, and transactions — sync and async. On top of the 9i gaps above it predates
`TIMESTAMP` and `INTERVAL` (only `DATE`), the AL16UTF16 national charset
(`WE8ISO8859P1` only), and returns a single row for `CONNECT BY LEVEL`. Oracle
**8.0** (pre-8i) is out of scope — 8.1.7 is the floor.

### Intentional differences from python-oracledb

seerdb matches oracledb's **types** — `cursor.description` type codes are the
same `DB_TYPE_*` objects, with the same `precision` / `scale` / `display_size` /
`internal_size` semantics — but is deliberately more forgiving about bind
**parameters**, where its behaviour is the saner default:

- a **positional** list may supply a single value for a repeated placeholder —
  `cur.execute("… :x … :x …", [v])` reuses `v` for every `:x`; oracledb requires
  one value per textual occurrence and raises otherwise.
- **extra keys** in a named-bind dict are ignored rather than rejected.

In both cases the bind values that reach the server are identical to a strict
call; seerdb just doesn't second-guess the count. Pass exactly the binds the
statement uses if you want oracledb's stricter validation.

A **server-side scrollable cursor** (`conn.cursor(scrollable=True)`, 10g+) also
treats scrolling *past the last row* like `file.seek()` past EOF — the next
`fetchone()` returns `None` and a later in-range `scroll()` repositions back —
rather than raising `IndexError`. That lets a `relative` scroll into an unknown
position return `None` instead of forcing a try/except. (A target before the
first row still raises `IndexError`, and the buffered non-scrollable path raises
for out-of-range in either direction, matching PEP 249 / oracledb.)

**LOB** columns are fetched as their **content directly** — a `CLOB` / `NCLOB`
comes back as `str`, a `BLOB` as `bytes` — rather than as a `LOB` object you have
to `.read()` (oracledb's default). Simplest for typical values; note the whole
LOB is materialised in memory. (Oracle's `'' == NULL` rule still applies, so an
empty-string / empty-bytes bind stores — and reads back — as `None`.)

## Requirements

Core (installed automatically):

- Python >= 3.10
- [pycryptodome](https://pypi.org/project/pycryptodome/) — login/auth crypto
  (O3LOGON / O5LOGON) and the AES + SHA-2 of native network encryption (ANO)
- [tzdata](https://pypi.org/project/tzdata/) — IANA time-zone database for
  named-region `TIMESTAMP WITH TIME ZONE` values (a no-op where the OS ships
  system zoneinfo)
- [pyarrow](https://pypi.org/project/pyarrow/) — backs the Arrow / DataFrame
  bulk fetch (`cursor.fetch_df_all` / `fetch_df_batches`)

Optional — [cryptography](https://pypi.org/project/cryptography/) is the only
extra dependency, needed by two features that pycryptodome can't cover. It is
imported lazily, so the core install stays lean and `import seerdb` works without
it; install the matching extra only if you use the feature:

- `pip install "seerdb[token]"` — **token-based auth** (`access_token=`): OAuth2 /
  OCI IAM sign the auth header with RSA-SHA256.
- `pip install "seerdb[wallet]"` — **wallet mutual TLS**: decoding an Oracle / ADB
  wallet (X.509 / PKCS#12).

## Installation

```
pip install .
```

## Quick start

```python
import seerdb

with seerdb.connect(host="dbhost", port=1521, user="scott",
                    password="tiger", service_name="MYDB") as conn:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, name FROM employees WHERE dept = :dept ORDER BY id",
            {"dept": "ENG"},
        )
        for row in cur:
            print(row)
```

An Easy Connect string works too, as in python-oracledb:
`seerdb.connect(user="scott", password="tiger", dsn="dbhost:1521/MYDB")`.
The form is `[user[/password]@][//]host[:port][/service_name]`; the port
defaults to 1521, and the DSN wins over `host` / `port` / `service_name` passed
beside it. A connect descriptor works as well
(`dsn="(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=dbhost)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=MYDB)))"`).
With several addresses (`ADDRESS`es, `ADDRESS_LIST`s, a `DESCRIPTION_LIST`)
they are tried as python-oracledb tries them: in order, the next when the TCP
connect fails or the listener refuses; only the first with `FAILOVER=OFF`;
shuffled with `LOAD_BALANCE=ON`; the whole list again `RETRY_COUNT` times,
`RETRY_DELAY` seconds apart. A `FAILOVER` or `LOAD_BALANCE` on any level applies
to the whole list, coarser than Oracle Net's per-list nesting.
So does a `tnsnames.ora` alias (`dsn="mydb"`), read from `config_dir=`, else
`TNS_ADMIN`, else `$ORACLE_HOME/network/admin`, with `IFILE` includes followed;
`config_dir` is taken as a wallet location only when it holds `ewallet.pem` or
`ewallet.p12`. A `tcps://` prefix, or `PROTOCOL=TCPS` in a descriptor or
alias, turns TLS on as `ssl=True` does; an `ssl=` configuration passed beside it
is kept. A TCPS address can be reached through an HTTPS proxy, as with
python-oracledb: `https_proxy` / `https_proxy_port` as arguments, as `?`
parameters or as `HTTPS_PROXY` / `HTTPS_PROXY_PORT` in a descriptor `ADDRESS`
open an HTTP `CONNECT` tunnel, and TLS then verifies the database server through
it; a proxy beside a plain TCP address is not used. A `:server_type` suffix (`dbhost/MYDB:pooled`) or `(SERVER=...)` in a
descriptor sets `server_type`, which `connect()` also takes: `dedicated`,
`shared` or `pooled`, the last asking for DRCP (`cclass` and `purity` only label
the session, as in python-oracledb). A
descriptor parameter seerdb does not act on yet (`SDU`, `SECURITY`, …) is
refused with `NotSupportedError` for now. Of Easy Connect's `?` parameters, `sdu`, `pool_connection_class`
(`cclass`), `pool_purity` (`new` / `self`), `transport_connect_timeout`
(seconds, or `ms` / `sec` / `min`; it sets `timeout`, which also bounds the
login), `retry_count` / `retry_delay` and `https_proxy` / `https_proxy_port` are read and win over the arguments beside them; any other is refused by
name, where python-oracledb ignores the ones it does not know. python-oracledb
ignores descriptor parameters it does not know; seerdb refuses them by name.

## Quick start (async)

```python
import asyncio
import seerdb


async def main():
    async with await seerdb.connect_async(
        host="dbhost", port=1521, user="scott",
        password="tiger", service_name="MYDB",
    ) as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT id, name FROM employees WHERE dept = :dept ORDER BY id",
                {"dept": "ENG"},
            )
            async for row in cur:
                print(row)


asyncio.run(main())
```

A connection pool keeps authenticated sessions warm. Sync:

```python
pool = seerdb.create_pool(host="dbhost", user="scott",
                          password="tiger", service_name="MYDB",
                          min=2, max=10)
with pool.acquire() as conn:
    ...
pool.close()
```

Async:

```python
pool = await seerdb.create_pool_async(host="dbhost", user="scott",
                                       password="tiger", service_name="MYDB",
                                       min=2, max=10)
async with pool.acquire() as conn:
    ...
await pool.close()
```

## Running tests

The default test suite is offline (encoders, crypto, packet round-trips):

```
python3 -m unittest discover -v tests/
```

A second suite of **integration tests** exercises type coercion and the
Cursor API against a real database. They are skipped unless connection
parameters are exported in the environment:

```
export SEERDB_TEST_USER=pyo
export SEERDB_TEST_PASSWORD=pyo123
export SEERDB_TEST_HOST=127.0.0.1          # optional, default 127.0.0.1
export SEERDB_TEST_PORT=1521               # optional, default 1521
export SEERDB_TEST_SERVICE=XE              # optional, default XE
python3 -m unittest discover -v tests/
```

The user only needs `CREATE SESSION` and `CREATE TABLE` privileges plus
a writable tablespace. Each test creates and drops its own scratch
table.

> **Connect-rate note.** Oracle XE rate-limits very rapid new connections
> at the listener (issue #7). The suite opens a fresh connection per test,
> so it keeps a small pre-connect pause (default 50&nbsp;ms, override with
> `SEERDB_TEST_CONNECT_DELAY`) to stay under that limit; the `Pool`
> (issue #6) avoids it entirely by keeping connections warm. At the default
> pace the suite runs clean.
>
> Earlier this surfaced as a `ORA-01013` ("user requested cancel") flake
> roughly one run in five: a mid-session cancel (from the throttle or an
> errored call) tripped the driver's break/reset handling, desynced the
> connection and cascaded into many failures. That driver bug was fixed in
> issue #45, so the default-pace suite is now reliably green. Only running
> with *no* pre-connect pause at all still trips the raw listener throttle,
> which now shows up as dropped connections rather than `ORA-01013`.

A third, opt-in suite exercises **wallet-based mutual TLS** against a real
TCPS (TLS) Oracle listener. It is skipped unless `SEERDB_WALLET_LIVE` is
set; [`docs/wallet_mtls_live_testing.md`](docs/wallet_mtls_live_testing.md)
walks through standing up a self-hosted 23ai Free + TCPS test bed (reusing
the committed fixture wallet) and running `tests/test_wallet_live.py`.

## Debug logging

seerdb logs through the standard `logging` module and emits nothing by
default. Turning on `DEBUG` traces the login/handshake negotiation, and —
the part that is hard to reconstruct any other way — the per-value row
codec and the Mirror's statement dispatch:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Narrow it to what you are chasing, because the row lines are per column
per row:

| logger | what it traces |
| --- | --- |
| `seerdb.client.connection` | login, protocol negotiation, encryption |
| `seerdb.common.tns` | row value encode / decode, including the framing chosen for each LOB-class cell |
| `seerdb.server` | the Mirror: sessions, and which backend call each statement dispatches to |

```python
logging.getLogger('seerdb.common.tns').setLevel(logging.DEBUG)
```

The row-codec lines report exactly the fields the encoder and decoder
branch on, so a value that desyncs a row usually shows up as an encoder
and a decoder disagreeing on one of them. The calls are guarded, so a
disabled level costs nothing per row.

## Contributing

Pull requests are welcome. Please read
[`CONTRIBUTING.md`](CONTRIBUTING.md) first — seerdb's clean-room
posture means there are a few sources you must NOT consult when
preparing a contribution, and a few citation expectations to follow
when you open a PR.

## Trademarks

Oracle and Oracle Database are trademarks or registered trademarks of Oracle
Corporation and/or its affiliates. seerdb is an independent, unaffiliated,
clean-room project — not endorsed by, sponsored by, or affiliated with Oracle
Corporation. References to "Oracle" are nominative, describing the database this
driver interoperates with. See [`NOTICE`](NOTICE).

## License

Licensed under the [MIT License](LICENSES/MIT.txt).
This project is [REUSE](https://reuse.software/) compliant.
