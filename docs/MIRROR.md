<!-- SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com> -->
<!-- SPDX-License-Identifier: MIT -->

# The Mirror

> **An initial implementation, a technology preview until general
> availability.** It is not yet for production.
> - **No compatibility promise yet.** It is outside the semantic-versioning
>   promise the client (DB-API 2.0) keeps. Its Python API, its command line and
>   its behaviour may change in any release, a minor or patch one included. Pin
>   an exact seerdb version if you depend on it.
> - **What general availability will promise** is under *Stability* below.
> - **When:** general availability comes when the gating milestones close (the
>   [gate](https://github.com/seerdb/seerdb/milestone/51)).

> **For trusted networks.** Run it on localhost, or behind a firewall or VPN,
> for clients you trust, until the security review closes. *Security* below
> says what is in place and what is still owed.

The Mirror is a server that speaks Oracle's wire protocol. Oracle clients
(python-oracledb, seerdb itself, sqlplus, SeerODBC, anything built on Oracle's
thin or OCI protocol) connect to it as they would to an Oracle database, and it
answers them from a backend:

- **PostgreSQL.** Oracle SQL and PL/SQL are translated to PostgreSQL as they
  arrive, so an Oracle application can run against a PostgreSQL database
  unchanged, and move to native PostgreSQL a statement at a time.
- **A real Oracle database (passthrough).** The Mirror relays every call to an
  Oracle server and returns its answers. It exists for testing and capture:
  run a client's test suite through it, and any failure is a gap in the Mirror's
  protocol handling, not in SQL translation.

Its protocol details are in [PROTOCOL.md](PROTOCOL.md). This guide is about
running one.

## Stability

Until general availability, nothing is promised: anything may change in any
release. From general availability on, the Mirror follows the package's
semantic versioning for what this list promises. A breaking change to any of it
needs a major release, and a rename or removal goes through *Deprecations*
first. Decided in [#1861](https://github.com/seerdb/seerdb/issues/1861).

**Promised:**
- **The launcher, `seerdb-mirror`:** the server and `profile compare` commands,
  with their options (*Options*).
- **The config file:** its `[server]`, `[clients]` and `[backend]` sections and
  their keys, and the `MIRROR_USERS` variable.
- **The defaults:** listening on `127.0.0.1:1521`, encryption `requested`, and
  presenting 23ai. A default that loosens security is a breaking change. One
  that tightens it is not, but the ChangeLog lists it.
- **The Python entry points:** `seerdb.serve()` and `seerdb.Server`.
- **The backend protocol,** so that backends of your own are supported:
  - `Backend`, with its required methods and the optional ones it documents;
  - the types it takes and returns: `BackendFactory`, `Result`, `CursorResult`,
    `ColumnMeta`, `BindVar`, `BackendError`, `UnsupportedFeature`, `Capability`,
    `Credentials` and `credential_lookup`;
  - the value types `BlobValue`, `ClobValue`, `VarcharValue`, `BFile`, `LtzValue`
    and `BcDate`.
- **A deployment's data across upgrades:** a database that a released Mirror
  over PostgreSQL set up keeps working when a newer release of the same major
  version connects to it. That covers its accounts, roles, recorded grants,
  invisible columns, object tables and the like. A Mirror older than the
  database refuses its sessions, rather than misread it. Databases from the
  preview releases get no upgrade path: set them up afresh.
- **The migration profile:** a profile file one release records can be read by
  `profile compare` of any later release of the same major version.

**Not promised:**
- **The wire-level names `seerdb.server` also exports:** `PacketStream`,
  `Listener`, the `*Request` classes and the `encode_*` helpers. Neither is
  anything else under `seerdb.server` outside the list above.
- **What the Mirror keeps in PostgreSQL:** the `sys`, `system` and
  `seerdb_auth` schemas, the `sys.ora_*` records and the translation log's
  columns. Only the upgrade promise above covers them.
- **The SQL the Mirror sends PostgreSQL**, its log messages, and
  `seerdb-mirror observe`, a bring-up tool.
- **Oracle compatibility itself.** It grows release by release. A feature this
  guide lists as supported that stops working is a bug, not a broken promise.

## What is supported

### Clients

The Mirror serves any client that speaks Oracle's thin protocol at the field
version of Oracle 10.2 or later, and sqlplus (OCI) from 10.2. Oracle 8i and 9i
clients are not served. What is checked, and how (measured 2026-10-31):

| client | checked by | result |
|---|---|---|
| python-oracledb (thin) | its own test suite (v26.1.0), `tools/run_oracledb_suite.py` | over PostgreSQL: 2468 passed; through a passthrough: 2472 passed |
| seerdb | seerdb's integration suite, in CI on every change | over PostgreSQL: 615 passed when presenting 23ai, 570 when presenting 12.1 |
| sqlplus 10.2 and 23.26 | `tools/sqlplus_survey.py`, compared with sqlplus against Oracle directly | the subset sqlplus uses for real database work |

- **Excluded from python-oracledb's run:** some feature areas aren't served at
  all (*Not served* below), so their test files are left out. Over PostgreSQL,
  a few tests are also deselected because PostgreSQL itself can't do what they
  check (*Known limits*).
- **Skips in seerdb's suite:** tests for features the presented release lacks,
  and for features only a real Oracle has, are skipped. That's why the 12.1 run
  passes fewer.

### Releases it presents

- **Over PostgreSQL:** the Mirror presents Oracle 23ai, or 12.1 with
  `--presents 12.1`. Clients see that release's version banner, error codes and
  dictionary.
- **As a passthrough:** it presents what its upstream speaks.

### Protocol features

- **Login:** O5LOGON with the accounts the Mirror holds. It supports password
  changes at login and with `ALTER USER`, proxy logins (`CONNECT THROUGH`), and
  lockout after repeated failures (*Accounts*).
- **Encryption:** TLS 1.2 and later (TCPS), with client certificates if you
  require them, and native network encryption (ANO) with AES and SHA-2
  checksums (*Encryption*).
- **Calls:**
  - queries, DML, DDL and PL/SQL, with binds of every scalar type;
  - array DML with batch errors;
  - LOBs, read and written;
  - REF CURSORs and implicit results (`DBMS_SQL.RETURN_RESULT`);
  - scrollable cursors;
  - `DBMS_OUTPUT`;
  - object and collection binds and fetches.
- **Transactions:** commit and rollback, savepoints, sessionless transactions
  (within one Mirror process), and transaction priority as session state.
- **Two seerdb extensions:** a WebSocket listener for browser clients, and a
  JSON query endpoint (*The WebSocket listener*).

### SQL and PL/SQL over PostgreSQL

Oracle SQL and PL/SQL are translated as they arrive, with
[orafce](https://github.com/orafce/orafce) supplying Oracle's built-in
functions. This covers:

- **Tables, views, sequences, indexes and constraints,** with Oracle's DDL,
  and the dictionary views clients read (`USER_*`, `ALL_*`, `DBA_*`, `V$` views
  that clients query).
- **Data types:**
  - `NUMBER`, the character types, `DATE`, `TIMESTAMP` with and without time
    zone, `INTERVAL`, `RAW`;
  - `CLOB`, `BLOB`, `BFILE`;
  - 23ai's `BOOLEAN`, JSON, and `VECTOR` (with pgvector);
  - `XMLTYPE`;
  - SQL domains and column annotations.
- **PL/SQL:** anonymous blocks, procedures, functions, packages and triggers,
  with definer's and invoker's rights (`AUTHID`).
- **Object types:** objects, VARRAYs, nested tables, and object tables with
  `REF` and `DEREF`.
- **Other features:**
  - `ROWID`, and `UROWID` for index-organized tables;
  - invisible columns;
  - editions, by name;
  - DIRECTORY objects.
- **Users and privileges:** `CREATE` / `ALTER` / `DROP USER`, and object and
  column grants. PostgreSQL enforces them when each user runs as a role of its
  own (*Per-user roles*).
- **Native PostgreSQL:** as an operator opt-in, a statement can bypass
  translation and run as PostgreSQL (*Native PostgreSQL*).

Each area has limits, listed under *Known limits*.

### Not served

These are out of the Mirror's scope, by design:
- Advanced Queuing and SODA;
- Continuous Query Notification;
- two-phase commit (XA);
- external (OS) authentication;
- direct path load;
- Oracle 8i and 9i clients.

## Installing

```sh
pip install "seerdb[mirror]"
```

The `mirror` extra adds psycopg 3.2 or later, which the PostgreSQL backend uses.
The passthrough needs nothing beyond seerdb. A plain `pip install seerdb` stays
client-only in its dependencies, and `import seerdb` never loads the Mirror.

## Starting one

`seerdb-mirror` (or `python -m seerdb.server`, the same program) starts a
Mirror in the foreground:

```sh
# Over PostgreSQL
MIRROR_USERS='scott:tiger' seerdb-mirror postgres 'host=db dbname=app user=mirror password=...'

# As a passthrough to a real Oracle
MIRROR_USERS='scott:tiger' seerdb-mirror passthrough oracle.example.com:1521/FREEPDB1
```

Then point a client at it:

```python
import oracledb
conn = oracledb.connect(user='scott', password='tiger', dsn='127.0.0.1:1521/ANY')
```

Any service name is accepted.

### Options

| option | default | meaning |
|---|---|---|
| `--host` | `127.0.0.1` | listen address, IPv4 or IPv6 (`::1`); give `0.0.0.0` (IPv4) or `::` (IPv4 and IPv6 on one socket) to accept other hosts |
| `--port` | `1521` | listen port |
| `--encryption` | `requested` | native network encryption (ANO): `requested` encrypts whenever the client offers AES, `required` refuses a client that doesn't, `accepted` never encrypts |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |
| `--tls-cert` | | serve TCPS: the server's certificate chain, PEM (see *Encryption*) |
| `--tls-key` | | that certificate's private key, PEM |
| `--tls-ca` | | require client certificates issued by this CA, PEM |
| `--profile FILE` | | record per-statement statistics to FILE (see *Migration profile*) |
| `--max-sessions` | no limit | serve at most this many connections at once; one more is closed as it arrives (see *Resource limits*) |
| `--failed-login-attempts` | `10` | lock a user name after this many failed logins in a row; `0` never locks (see *Accounts*) |
| `--ws-port` | | also serve the seerdb WebSocket transport on this port (see *The WebSocket listener*) |
| `--ws-origin` | | a browser origin the WebSocket listeners admit; repeatable |
| `--query-ws-port` | | also serve the JSON query endpoint on this port (see *The JSON query endpoint*) |
| `--config FILE` | | an INI file with the same options (below) |

For `postgres`:

| option | default | meaning |
|---|---|---|
| `CONNINFO` | | a libpq connection string for the backing database |
| `--presents` | `23ai` | the Oracle release the Mirror presents: `23ai` or `12.1` |
| `--auth-conninfo` | | keep the accounts in the database, connecting as this role (see *Accounts*) |
| `--translation-report` | off | record each statement's translation in `sys.ora_translation_log` |
| `--native-sql` | off | let clients run native PostgreSQL SQL (see *Native PostgreSQL*) |
| `--per-user-roles` | off | run each user's sessions as a PostgreSQL role of its own (see *Per-user roles*) |

For `passthrough`:

| option | default | meaning |
|---|---|---|
| `UPSTREAM` | | `host:port/service` of the Oracle database |
| `--field-version` | probed | the protocol field version to present; by default the Mirror logs in to the upstream once at start-up, with the first configured account, and presents what it negotiates |
| `--auth-conninfo` | | keep the accounts in a PostgreSQL database, connecting as this role (see *Passthrough*) |

`seerdb-mirror observe` runs a bring-up tool instead: it accepts a client and
logs every packet the client sends, in hex. It answers nothing.

`seerdb-mirror profile compare` compares two migration profiles; it starts no
server (see *Comparing two profiles*).

The command line wins over the config file, and the file over the defaults.

### The config file

```ini
[server]
host = 127.0.0.1
port = 1521
encryption = requested
log_level = INFO
; tls_cert = /etc/mirror/server.pem
; tls_key = /etc/mirror/server.key
; tls_ca = /etc/mirror/clients-ca.pem
; profile = /var/lib/mirror/profile.json
; max_sessions = 200
; failed_login_attempts = 10
; ws_port = 1531
; ws_origins = https://app.example.com, https://admin.example.com
; query_ws_port = 1532

[clients]
SCOTT = tiger

[backend]
type = postgres
conninfo = host=db dbname=app user=mirror password=...
presents = 23ai
; auth_conninfo = host=db dbname=app user=mirror_auth password=...
; translation_report = no
; native_sql = no
; per_user_roles = no

; For a passthrough instead:
; type = passthrough
; upstream = oracle.example.com:1521/FREEPDB1
; field_version = 24
```

```sh
seerdb-mirror --config mirror.ini
```

The file holds passwords, so keep it readable only by the account that runs
the Mirror.

### Deprecations

From general availability on, the launcher's options and the config file's keys
change only this way:

- **A renamed or removed option keeps working** for at least one minor release.
  A renamed one acts as its replacement. Where both spellings are given, the new
  one wins.
- **Each use is logged at start-up** as a warning that names the replacement and
  the release that removes the old spelling, for example: `--old is deprecated:
  use --new instead; it will be removed in seerdb 4.2.0`.
- **The ChangeLog lists every deprecation.**

Nothing is deprecated yet. What general availability promises is under
*Stability*. Until then the Mirror is a technology preview, and anything may
change in any release.

### Accounts

Oracle's login (O5LOGON) is mutual: the server proves it knows the password as
the client does. So the Mirror has to hold each account's password, not just a
hash of it. It serves exactly the accounts it is given, from:

- the config file's `[clients]` section;
- `MIRROR_USERS`, a comma-separated list of `user:password` pairs;
- for the PostgreSQL backend with `--auth-conninfo`, a `seerdb_auth.accounts`
  table in the database (below).

Names fold to upper case, as Oracle's do. There is no default account, and a
Mirror with no accounts refuses to start. Passwords are never taken from the
command line, where other local users could read them.

Without `--auth-conninfo`, the accounts live in the Mirror process. A password
changed by a client, or a user created with `CREATE USER`, lasts until the
Mirror stops. With it, they live in the database and persist. That table
belongs to the auth role; the role the sessions run as must not be able to read
it, so it must be a different role, not a superuser, and not the table's owner.

**Failed logins.** As Oracle's default profile does, the Mirror counts failed
logins per user name:
- Each failure's reply is delayed, the longer the more failures in a row.
- After 10 in a row (`--failed-login-attempts`), the name is locked, and a login
  gets ORA-28000 until an administrator runs `ALTER USER name ACCOUNT UNLOCK`, or
  the Mirror restarts.
- A name that is no account's is counted, challenged and refused just as an
  account's is, so the answers don't tell which accounts exist.

**Proxy logins.** A login as `user[target]` opens a session as `target`, with
`user` as its proxy, only where `target` allowed it:
`ALTER USER target GRANT CONNECT THROUGH user`. `REVOKE CONNECT THROUGH` takes
that away, and `PROXY_USERS` lists the grants. Any other proxy login is refused
with ORA-01017, as Oracle refuses it. The PostgreSQL backend keeps the grants
in its dictionary; the passthrough leaves the decision to its upstream.

### Encryption

**TLS (TCPS).** Given a certificate, the Mirror serves TCPS: every connection is
TLS from its first byte, as an Oracle TCPS listener's is, and the Oracle
protocol runs inside it.

```sh
seerdb-mirror --port 2484 --tls-cert server.pem --tls-key server.key postgres '...'
```

- **Versions.** TLS 1.2 and later.
- **Client certificates.** With `--tls-ca`, a client must present a
  certificate that CA issued (mutual TLS, as an Oracle wallet provides).
- **The certificate itself.** Clients check its DN or host name against what
  they expect (`ssl_server_cert_dn`, `ssl_server_dn_match`). Recent Python
  clients, python-oracledb's thin mode among them, also refuse a certificate
  without the standard extensions (such as an Authority Key Identifier), so
  issue it from a proper CA.
- **Mixing transports.** A listener serves either TCP or TCPS. Run two Mirrors
  to offer both.

TLS is the way to protect a Mirror that listens beyond localhost: unlike ANO, it
authenticates the server.

**Native network encryption (ANO).** AES-128, -192 or -256 with a SHA-2
checksum. By default (`requested`) the Mirror encrypts whenever the client
offers ANO, and serves a client that doesn't in plaintext. Give `--encryption
required` to serve only clients that encrypt, or `accepted` to never encrypt
(a client that requires encryption is then refused). seerdb's client offers ANO
by default; sqlplus and other OCI clients offer it when their `sqlnet.ora`
asks for it. ANO's key exchange does not authenticate the server, so it does
not protect against a man in the middle; use TLS for that.

### The WebSocket listener (a seerdb extension)

`--ws-port PORT` serves the **seerdb WebSocket transport** (a seerdb extension,
not Oracle) beside the TCP/TCPS listener: seerdb clients connect with a
`ws://host:PORT/service` DSN (`wss://` when `--tls-cert` is given), carrying TNS
in WebSocket binary messages. With the passthrough backend this makes the Mirror
an **auditing gateway** for browser clients — their traffic reaches a real
Oracle through code that understands it, so logging and policy apply, unlike a
protocol-blind bridge. No Oracle client speaks it; it needs the `ws` extra
(`pip install "seerdb[ws]"`).

`--ws-origin ORIGIN` (repeatable; or `ws_origins` in the config) is the browser
`Origin` allow-list, enforced at the WebSocket handshake. With none given, any
origin may connect — not recommended.

> **A browser-facing endpoint is outside the Mirror's stated threat model**
> (behind a firewall or VPN). This listener enforces the origin allow-list,
> authenticates before any backend work, and honours `--max-sessions`, but the
> full security review (the
> [mirror-security-hardening](https://github.com/seerdb/seerdb/milestone/52)
> milestone) is still owed: treat it as a technology preview, and put it behind
> an allow-list and TLS.

#### The JSON query endpoint

`--query-ws-port PORT` serves a thin **JSON-over-WebSocket query endpoint**
beside the listeners above (a seerdb extension, MVP). Instead of raw TNS, a
browser or Node tool exchanges JSON **text** frames — no TNS codec needed — and
the Mirror drives the same backend one layer above TNS:

```jsonc
-> {"type":"login","user":"PYO","password":"pyo123"}   <- {"type":"login_ok"}
-> {"type":"query","id":1,"sql":"select id,name from t where id > :1","binds":[100]}
<- {"type":"result","id":1,
    "columns":[{"name":"ID","type":"NUMBER"},{"name":"NAME","type":"VARCHAR2"}],
    "rows":[[101,"ada"]],"rowcount":1}
-> {"type":"commit"} | {"type":"rollback"}             <- {"type":"ok"}
<- {"type":"error","id":1,"code":"UNSUPPORTED","message":"..."}
```

One statement in flight at a time; binds are a positional JSON list of scalars.
`NUMBER` is serialized as a string (to keep precision), dates as ISO-8601, and
`RAW`/`BLOB` as base64. It is `wss` when `--tls-cert` is set (else `ws`), and
shares `--ws-origin` and `--max-sessions` with the raw-TNS listener. Auth takes
the account password in the login frame, so it relies on the `wss` TLS — the
same operator-controlled threat model and milestone-52 caveat above apply.
Otherwise a login here is a TNS login's: failed logins count toward the same
lock (*Failed logins*), a client has 60 seconds to log in, and in per-user mode
the session is the user's own role. Until it has logged in, a client may send
only messages of up to 1 MiB, on this listener and the raw-TNS one alike.
Richer typing, LOBs, named binds and streaming are deliberately out of this MVP.

## Mirror over PostgreSQL

### Choosing a mode

| | single-role (the default) | per-user roles (`--per-user-roles`) |
|---|---|---|
| PostgreSQL role of a session | the connection string's, shared by every account | the user's own, one per Mirror user |
| who sees whose objects | everyone everything, by naming the schema | as `GRANT` allows, enforced by PostgreSQL |
| who may manage accounts, directories, editions | every account | the configured accounts only |
| needs | PostgreSQL with orafce | PostgreSQL 16+, a `CREATEROLE` connection role, `--auth-conninfo` |
| fits | one application, or users who trust each other | users who must not see each other's data |

Both modes translate the same SQL and PL/SQL; only who may do what differs.

### A deployment, step by step

1. **A database** with orafce, and pgvector if the application uses `VECTOR`
   (*What the database needs*).
2. **The connection role:** the Mirror's own, owning that database, not a
   superuser (*Which role to connect as*). Give it `CREATEROLE` for per-user
   roles.
3. **The auth role**, for `--auth-conninfo`: where the accounts are kept, in a
   schema the connection role cannot read (*Accounts*). It may be the
   connection role in per-user mode, where no session runs as it.
4. **The accounts:** the administrators in the config file's `[clients]`. The
   other users are made with `CREATE USER` through the Mirror.
5. **TLS:** a certificate from a proper CA (`--tls-cert`, `--tls-key`),
   because the Mirror listens beyond localhost. Add `--encryption required` if
   no plaintext client may connect at all.
6. **The listen address:** a trusted network only, until the security review
   closes (*Security*).
7. **The config file,** readable by the account that runs the Mirror only, and
   the Mirror run under a service manager that restarts it.
8. **Limits** on the PostgreSQL side (*Resource limits*).

### What the database needs

- **PostgreSQL**, tested on 16.
- **[orafce](https://github.com/orafce/orafce)** 4.17 or later, which supplies
  Oracle's built-in functions (`NVL`, `DECODE`, `TO_CHAR`, `ADD_MONTHS`, ...)
  and `UTL_RAW`. It is a requirement: without it, much ordinary Oracle SQL
  fails, and an older one is refused. The Mirror runs
  `CREATE EXTENSION IF NOT EXISTS orafce` when it connects; if its role may not
  create extensions, have an administrator create it in the database first.
  `UTL_RAW` then takes a character argument as hex, as Oracle does, only if
  the Mirror's role may create in orafce's schema:
  `GRANT CREATE ON SCHEMA utl_raw TO` the role.
- **[pgvector](https://github.com/pgvector/pgvector)**, optional, for Oracle's
  `VECTOR` type. Without it a `VECTOR` column is refused.
- **[plpgsql_check](https://github.com/okbob/plpgsql_check)**, optional, so that
  a PL/SQL procedure or function that names an undeclared variable, an unknown
  column or table, or a call no routine takes is created INVALID with Oracle's
  errors, as Oracle's compiler makes it. Without it such a routine is created
  VALID and fails when it runs. Its creation needs a superuser; the Mirror runs
  `CREATE EXTENSION IF NOT EXISTS plpgsql_check` as it installs its dictionary.
  CI pins v2.10.11: v2.10.12 crashes the server on a function that fetches from
  a cursor parameter, and a crash in it restarts every session.

The repository's [`examples/mirror-pg.Dockerfile`](../examples/mirror-pg.Dockerfile)
builds PostgreSQL 16 with all three, as CI uses it.

### Which role to connect as

**The role in the connection string is the Mirror's security boundary.** Unless
the Mirror runs with `--per-user-roles` (see *Per-user roles*), every account it
serves runs as that one PostgreSQL role, and with
`--native-sql` a client can send native PostgreSQL through the Mirror (below).
So whatever that role may do in PostgreSQL, every Mirror user may do. Give the
Mirror a role of its own:

- **not a superuser**;
- owning the database it serves, or at least its schemas, and nothing outside it;
- without `pg_read_server_files`, `pg_write_server_files` or
  `pg_execute_server_program`, unless you want the features that need them (BFILE
  needs `pg_read_server_files`, and with it every Mirror user can read any file
  that PostgreSQL's server process can).

Some features are better with a superuser and degrade without one:

- **Ordering a `TIMESTAMP WITH TIME ZONE` column.** Its operator classes need a
  superuser. Without them, comparison still works by instant.
- **Storing a `BOOLEAN` into a `NUMBER` column.** That needs a cast between
  built-in types, which needs a superuser. Without it, the assignment is refused.

Prefer the restricted role and accept these.

### One tenant per database

Without `--per-user-roles`, all Mirror accounts share the one PostgreSQL role,
so they share its privileges:

- **Schemas.** Each account gets a schema of its name, and its unqualified names
  resolve there, as an Oracle user's do. But a user can read and change another
  user's tables by naming the schema, whatever was granted. A `GRANT` on a type
  only decides whether another user can look the type up.
- **Accounts.** Any account can manage accounts with `CREATE USER`,
  `ALTER USER` and `DROP USER`, including other users' passwords.

Treat one Mirror over one database as **one tenant**: users who would trust each
other with each other's data. Serve separate tenants from separate Mirrors over
separate databases, each with its own role, or use per-user roles.

### Per-user roles

With `--per-user-roles` (`per_user_roles = yes`), each Mirror user's sessions
run as a PostgreSQL role of its own, so PostgreSQL's own privilege checks keep
users apart, as Oracle's do between schemas. It needs:

- **PostgreSQL 16 or later.** From 16, a role with `CREATEROLE` manages only
  the roles it made.
- **A connection role with `CREATEROLE`.** It installs the dictionary as before,
  and makes and drops the users' roles.
- **`--auth-conninfo`.** Each user's role has a password the Mirror makes up,
  kept with the account. The auth role may be the connection role here, since
  no session runs as it.

**What a user is.** Each user's role is named as its schema: user `SCOTT` logs
in as role `scott`, which owns schema `scott`. The role is made by `CREATE USER`,
or for an account from the config file or `MIRROR_USERS` at its first login. A
proxy login runs as the target's role. PostgreSQL roles belong to the whole
server, not to one database, so two Mirror databases on one PostgreSQL server
can't both have a user of the same name. A `CREATE USER` or a first login whose
role already exists, made by something other than the Mirror, is refused with
ORA-01920.

**Which schemas can be a user's.** A schema with a user's name and no account
counts as that user, as a user made before the Mirror kept accounts is.
- It must be owned by that user's role, or by the connection role.
- It must not be one of these:
  - the installation's: `sys`, `system` and the packages' (`dbms_lob`, ...);
  - `seerdb_auth`;
  - an extension's;
  - PostgreSQL's: `public`, `information_schema` and `pg_*`.

A user is never made or dropped for any other schema, and no role is given one.
- `CREATE USER` of such a name, or a first login under one, is ORA-01920.
- `ALTER USER`, `DROP USER` and a grant are ORA-01918 or ORA-01917.

So don't keep other schemas under the connection role: a user named like one
would take it over at its first login. A database of the Mirror's own is
simplest.

**What a user sees and may do:**
- its own objects, and others' only as PostgreSQL privileges allow; otherwise
  ORA-00942;
- in `ALL_*` views, only what it owns or holds a privilege on;
- routines and types of its own that are private to it: the Mirror takes back
  the EXECUTE and USAGE PostgreSQL grants to PUBLIC on what the role makes;
- its own password changed with `ALTER USER ... IDENTIFIED BY`.

**What it can't hide: source text.** Every user can read the text of every
user's PL/SQL units, triggers and views. PostgreSQL shows any role the source
of every function (`pg_proc.prosrc`) and the definition of every view
(`pg_views`), and the Mirror's own records of the Oracle source are readable
alike. On Oracle, a user sees only the source of what it may run. So don't put
secrets in source: keep them in a table, behind a grant.

**Administrators.** The accounts the operator configures (`[clients]`,
`MIRROR_USERS`) are the administrators. Only they may run a DBA's statements:
- `CREATE USER`, `DROP USER`, and `ALTER USER` on another user;
- `ALTER USER ... GRANT` or `REVOKE CONNECT THROUGH`;
- `CREATE` or `DROP DIRECTORY`, and `CREATE` or `DROP EDITION`;
- `ALTER SYSTEM KILL SESSION`.

A user created with SQL gets ORA-01031 for these, unless it holds the system
privilege the statement needs, or the `DBA` role:

| statement | privilege |
|---|---|
| `CREATE USER` / `DROP USER` | `CREATE USER` / `DROP USER` |
| `ALTER USER` on another user, `CONNECT THROUGH` | `ALTER USER` |
| `CREATE` / `DROP DIRECTORY` | `CREATE ANY DIRECTORY` / `DROP ANY DIRECTORY` |
| `CREATE` / `DROP EDITION` | `CREATE ANY EDITION` / `DROP ANY EDITION` |
| `ALTER SYSTEM KILL SESSION` | `ALTER SYSTEM` |

`GRANT p TO u [WITH ADMIN OPTION]` and `REVOKE p FROM u` give and take them, as
on Oracle:
- **Who may grant or revoke:** an administrator, a `DBA`, or a holder of the
  privilege `WITH ADMIN OPTION`.
- **Revoking doesn't cascade.**
- **Errors:** ORA-01917 for an unknown grantee; ORA-01951 or ORA-01952 for a
  revoke of what wasn't granted.
- **Listing them:** `USER_SYS_PRIVS`, `USER_ROLE_PRIVS`, `SESSION_PRIVS` and
  `SESSION_ROLES` list a user's own and `PUBLIC`'s. `DBA_SYS_PRIVS` and
  `DBA_ROLE_PRIVS` list all.
- **Other privileges and roles:** any other system privilege or role
  (`CREATE SESSION`, `CONNECT`, `RESOURCE`, …) is accepted and does nothing.
- **The administrators themselves:** their right comes from the
  configuration, not a grant, so `SESSION_PRIVS` doesn't list it.

In single-role mode, grants are recorded and listed but enforce nothing.

**The DBA's views.** In per-user mode, `DBA_SYS_PRIVS`, `DBA_ROLE_PRIVS`,
`DBA_DIRECTORIES` and `PROXY_USERS` are for the administrators and the users
granted `DBA`. Other users get an error, as on Oracle.
- **How:** these roles are members of a group, `<connection role>_mirror_dbas`,
  which may read the views.
- **Timing:** `GRANT DBA` and `REVOKE DBA` take effect at once, open sessions
  included.
- **A limit:** an account taken out of the configuration keeps reading the
  views until its role is next repaired or the user is dropped. Its DBA
  statements are refused at once all the same.

The Mirror runs these statements on a connection of the connection role.
`DROP USER` drops the user's role and what it owns, along with the user's
grants, and refuses a user with a session open (ORA-01940), as Oracle does.

**Object grants.** `GRANT` and `REVOKE` on a table, view, sequence, procedure,
function, package or type become PostgreSQL's own, so another user's object
needs a grant, as on Oracle:

| Oracle privilege | on | in PostgreSQL |
|---|---|---|
| `SELECT`, `READ` | table, view | `SELECT` |
| `INSERT`, `UPDATE`, `DELETE`, `REFERENCES` | table, view | the same |
| `SELECT` | sequence | `USAGE, SELECT` |
| `EXECUTE` | procedure, function | `EXECUTE` on every overload |
| `EXECUTE` | package | `USAGE` on its schema, `EXECUTE` on its routines, `USAGE` on its types |
| `EXECUTE` | type | `USAGE` |

- **What is only recorded:** the privileges PostgreSQL has no counterpart
  for (`ALTER`, `INDEX`, `DEBUG`, `FLASHBACK`, …).
- **Schema access:** a grant also gives `USAGE` on the owner's schema, taken
  back once the grantee holds nothing else there from that grantor.
- **`ALL`:** recorded as the privileges the presented release lists for the
  object.
- **`WITH GRANT OPTION`:** a user may pass on a privilege it holds this way.
  `REVOKE` takes away what the grantee passed on, as Oracle's cascade does,
  and takes only what one granted oneself (ORA-01927).
- **Replacing an object:** a grant survives `CREATE OR REPLACE`. A `DROP`
  takes it.
- **Listing grants:** `ALL_TAB_PRIVS`, `USER_TAB_PRIVS` and their `_MADE` and
  `_RECD` forms list them, as 23ai does, in either mode.
- **Errors:** a user with no privilege on another user's table gets ORA-00942.
  With some privilege but not the one used, it gets ORA-41900 when the Mirror
  presents 23ai (`missing INSERT privilege on "A"."T"`), and ORA-01031 when it
  presents 12.1. An `UPDATE` or `DELETE` that may write but not read the
  columns its `WHERE` names lacks `SELECT`, which 23ai names so.
- **ROWID:** an `INSERT`, `UPDATE` or `DELETE` on a table where the user lacks
  `SELECT` reports no ROWID, because PostgreSQL's `RETURNING` needs `SELECT`.
- **Column grants:** `INSERT`, `UPDATE` and `REFERENCES` may be granted on
  columns, `GRANT UPDATE (c1, c2) ON t TO u`, and become PostgreSQL's column
  privileges.
  - A list may mix them with table privileges:
    `GRANT SELECT, UPDATE (c1) ON t`.
  - Errors: another privilege with a column list is ORA-00969, an unknown
    column ORA-00904, and a column named twice ORA-00957.
  - A `REVOKE` naming columns is ORA-01750, as on Oracle. Revoking the
    privilege from the whole table takes its column grants too, and
    `DROP COLUMN` takes the column's.
  - `ALL_COL_PRIVS`, `USER_COL_PRIVS` and their `_MADE` and `_RECD` forms
    list them.

**Whose rights a routine runs with.** As on Oracle, a procedure, function or
package runs with its owner's rights unless it says `AUTHID CURRENT_USER`. A
user granted EXECUTE on it reaches what the owner may, even without a grant on
the owner's tables.
- **Unqualified names:** the routine is created with its owner's schema first
  on its search path, so an unqualified name means the owner's object, in
  either mode.
- **`USER` and `SESSION_USER`:** the caller, as on Oracle.
- **`CURRENT_USER` and `CURRENT_SCHEMA`:** the owner. In single-role mode,
  `CURRENT_USER` is the one role.
- **`AUTHID CURRENT_USER`:** the caller's rights and search path. One
  difference remains for packages: an invoker-rights package still resolves
  unqualified names on its owner's path, because its members find each other
  through it.
- **`ALL_PROCEDURES.AUTHID`** shows which.
- **Invoker-rights routines in views, defaults and CHECKs:** refused in
  per-user mode, with ORA-03001. On Oracle, an `AUTHID CURRENT_USER` routine
  that a view calls runs with the view owner's rights. PostgreSQL runs it with
  the rights of whoever reads the view, and does the same for a column default
  or a CHECK constraint with whoever writes the row. A user could then have
  someone else, an administrator say, run their code. So a view, default or
  CHECK may not call a user's `AUTHID CURRENT_USER` routine, a package
  member's included. Declare the routine `AUTHID DEFINER`, Oracle's default,
  instead. When the routine and the view have the same owner, that runs it
  exactly as Oracle would. Built-in functions are not affected.

In single-role mode, grants are checked and recorded the same way, but every
user is the one role, so they enforce nothing beyond who sees a type.

A login connects to PostgreSQL once, straight as the user's role, and costs no
more than in single-role mode. The exceptions connect as the connection role
first, which makes or repairs the user's role, and then as the user's:
- a process's first login;
- a user's first login;
- a proxy login, whose target is only known later;
- a login whose role fails its checks.

### Upgrades

The Mirror keeps two things in its database:
- the dictionary: views, helper functions and types;
- the data: accounts, users' roles, recorded grants and columns, object
  tables.

A newer release connecting to the database installs its own dictionary, and
brings the data up to date in steps, each recorded in the database. So upgrading
is installing the new seerdb and restarting the Mirror, with nothing to run by
hand.

- **One release per database at a time.** Two releases sharing a database
  each install their own dictionary in turn. Once a newer one has moved the
  data on, the older refuses its sessions rather than misread it. Upgrade every
  Mirror serving a database together.
- **Within a major release:** a database set up by a released Mirror keeps
  working after every upgrade (*Stability*).
- **From the preview releases:** there is no upgrade path. Once general
  availability arrives, a database a preview release set up is refused with
  *set it up afresh*.

Take a backup of the database before upgrading, as for any schema change.

### Resource limits

What the Mirror bounds itself:
- **Packets:** a packet longer than the negotiated SDU closes the connection.
  So does a message longer than 1 MiB before login, or 1 GiB after it.
- **Logins:** a client has 60 seconds to log in, or the connection is closed.
- **Sessions:** `--max-sessions` caps the connections served at once. It is
  off by default; set it to what the database can take.

The size of a single statement's result and of a LOB are not bounded. Bound
the rest on the PostgreSQL side:

- **Sessions:** each Mirror session holds one PostgreSQL connection, and a
  login also opens short-lived ones to the auth database. `max_connections`
  caps them all. In single-role mode, so does `CONNECTION LIMIT` on the
  connection role. With per-user roles, each session runs as its user's role
  instead.
- **Long statements and idle transactions:** set `statement_timeout` and
  `idle_in_transaction_session_timeout` on the database
  (`ALTER DATABASE app SET ...`), so they apply to every user's role.
- **Memory:** a statement's rows and a LOB's value pass through the Mirror's
  process; bound it with the service manager (for example `MemoryMax=` under
  systemd).

### Native PostgreSQL

With `--native-sql` (`native_sql = yes` in the config file), a statement can
bypass translation and run as PostgreSQL:

```sql
SELECT /*+ PG */ CAST(jsonb_build_object('a', n) AS text) FROM generate_series(1, 3) AS g(n)
ALTER SESSION SET seerdb_dialect = 'postgres'   -- every statement native, until
ALTER SESSION SET seerdb_dialect = 'oracle'
```

This is how an application moves to PostgreSQL over the same connection, one
statement at a time. Binds stay Oracle's (`:name`, `:1`). Since an Oracle client
reads `::type` as a bind, write casts as `CAST(x AS type)`. A result of a type
with no Oracle form (`jsonb`, `uuid`, arrays, ...) is refused by name.

It is off unless the operator turns it on. Off, the `/*+ PG */` hint is ignored,
as Oracle ignores a hint it doesn't know, so the statement is translated as
Oracle SQL. `ALTER SESSION SET seerdb_dialect` is refused with ORA-02248, as
Oracle refuses a parameter it doesn't have. On, it is available to every
account, which is why the role matters.

**Native SQL in per-user mode has PostgreSQL's rules, not Oracle's.** The
Mirror's checks apply to Oracle SQL only. With native SQL, a user can create
what PostgreSQL allows, including code that runs with the rights of another
user who touches their objects:
- a `SECURITY INVOKER` function called from a view, a default, a CHECK or an
  index expression;
- a trigger whose function is `SECURITY INVOKER`, which runs as whoever
  writes the table;
- a row-level security policy that calls such a function.

This is how PostgreSQL behaves for its own users, and its documentation warns
about it. A user, an administrator above all, should not read or write
another user's objects without trusting their owner. Turn native SQL on in
per-user mode only for users who may run code with each other's rights.

## Passthrough

The passthrough presents what its upstream speaks: it logs in once at start-up
with the first account and presents the protocol version it negotiates, unless
`--field-version` sets one.

Each client session opens its own upstream session, with the same user name and
password the client logged in with. So every account the Mirror serves must
exist upstream with the same password.

The Mirror keeps those accounts as the PostgreSQL backend does (*Accounts*):
from `[clients]` and `MIRROR_USERS`, or with `--auth-conninfo` in a PostgreSQL
database's `seerdb_auth.accounts`. That needs psycopg (`seerdb[mirror]`). It
follows what the upstream accepts: once `CREATE USER ... IDENTIFIED BY`,
`ALTER USER ... IDENTIFIED BY` or `DROP USER` succeeds upstream through the
Mirror, or a client changes its password, the Mirror's accounts change too. With
an auth database those changes outlive a restart. A user created upstream some
other way has to be added to the Mirror's accounts too.

Uses:

- **Testing a client.** Run its suite through the Mirror against a real database.
  A failure that the direct run doesn't show is a Mirror protocol gap.
- **Capture.** `--log-level DEBUG` logs each statement the Mirror dispatches,
  with how it decoded the call.
- **Migration.** Put the passthrough in front of the application today, and
  replace it with the PostgreSQL backend later, with no change to the
  application.

## Security

This section states the position as it stands. General availability waits on
a security review ([#1687](https://github.com/seerdb/seerdb/issues/1687)) and
the fixes it brings, each filed in the milestone
[mirror-security-hardening](https://github.com/seerdb/seerdb/milestone/52).
This section is revised when the review closes.

**The threat model.** The Mirror is built for a network its operator controls:
localhost, or behind a firewall or VPN that admits only your own hosts. Its
clients are applications you run. Exposing it to the internet is outside that
model until the review closes.

**What is in place:**
- **Before login,** a client is bounded (*Resource limits*):
  - packets no longer than the negotiated SDU;
  - messages of at most 1 MiB;
  - 60 seconds to log in;
  - 30 seconds for a TLS handshake;
  - `--max-sessions` connections at once.
- **Logins** are O5LOGON, mutual as Oracle's is. Failed logins are delayed and
  locked out per user name, and the answers don't tell which accounts exist
  (*Accounts*).
- **Passwords:**
  - The Mirror holds each one as it is, because O5LOGON needs it. Keep the
    config file readable by the Mirror's account only, and keep the auth table
    behind its own role (*Accounts*).
  - The log, the migration profile and the translation report never record a
    password a statement carries (`IDENTIFIED BY`, `REPLACE`).
- **The wire:**
  - TLS authenticates the server, and with `--tls-ca` the client.
  - ANO encrypts, but doesn't authenticate the server.
  - Beyond localhost, use TLS.
- **Users:** per-user roles let PostgreSQL itself keep users apart
  (*Per-user roles*).
- **Browser endpoints:** the WebSocket listeners check an origin allow-list,
  authenticate before any backend work and count against `--max-sessions`.

**How to run it until the review closes:**

- **Who can reach it.** Keep the default listen address (`127.0.0.1`), or put
  the Mirror behind a firewall that admits only your own hosts. The bounds above
  limit what an unauthenticated client can do, but they are not the review.
- **Who logs in.**
  - In single-role mode, every account can do more than an Oracle user of the
    same name could: manage the other accounts, including their passwords, and
    read any file the PostgreSQL role can, through DIRECTORY objects. Serve
    only accounts that may see each other's data (*One tenant per database*).
  - With per-user roles, those are the configured administrators' alone, and
    PostgreSQL keeps the users apart (*Per-user roles*). With native SQL on,
    a user can have another run their code (*Native PostgreSQL*).
- **What the role may do.** The connection role is the boundary of
  single-role mode, and with native SQL a client can use whatever it may
  (*Which role to connect as*). Never a superuser; no server-file or
  server-program privileges unless you need them.
- **The wire.** Use TLS (`--tls-cert`) beyond localhost. ANO alone doesn't
  authenticate the server.
- **The browser endpoints.** Give `--ws-origin`, and serve them as `wss://`
  only.

**Reporting a vulnerability:** privately, as [SECURITY.md](../SECURITY.md)
describes, never in a public issue.

## Running it

**Under a service manager.** The Mirror runs in the foreground and logs to
standard error, so a service manager can supervise it. A systemd unit, for
example:

```ini
[Unit]
Description=seerdb Mirror
After=network-online.target

[Service]
User=mirror
ExecStart=/opt/mirror/venv/bin/seerdb-mirror --config /etc/seerdb-mirror/mirror.ini
Restart=on-failure
MemoryMax=2G

[Install]
WantedBy=multi-user.target
```

- **Stopping:** SIGTERM stops it as an interrupt does, and writes the migration
  profile if one is being recorded.
- **The profile:** SIGUSR1 writes it without stopping.
- **Configuration changes:** there is no reload. Restart the Mirror to apply
  them.

**Containers.** There is no official Mirror image. Install `seerdb[mirror]` into
a Python image, run `seerdb-mirror` as its command, and give it `--host 0.0.0.0`
so the container's port is reachable. The database side has its own recipe:
[`examples/mirror-pg.Dockerfile`](../examples/mirror-pg.Dockerfile) builds
PostgreSQL 16 with the extensions the Mirror uses.

**The log** (`--log-level`):
- **WARNING:** what an operator must see, such as the start-up notice and a
  deprecated option.
- **INFO, the default,** adds each login and each session's end, with the
  client's address and user, and password changes.
- **DEBUG** adds every statement the Mirror dispatches, with how it decoded the
  call. That is the application's SQL. It is redacted of passwords, but treat a
  DEBUG log as holding application data.

**Health checks.** The Mirror has no health endpoint. A TCP connect checks that
it listens. A login with a monitoring account and `SELECT 1 FROM dual` checks
the whole path, the backend included. Give that account nothing else.

**Backups.** Over PostgreSQL, everything the Mirror keeps is in the database:
the dictionary, the accounts if you use `--auth-conninfo`, and the records
(*Upgrades*). Back up the database as you would any PostgreSQL database. The
config file holds the remaining state: the listener, the backend and the
configured accounts.

## Migration profile

`--profile FILE` records what every session runs, statement by statement, with
either backend. Run the application once through a passthrough Mirror in
front of Oracle and once through the Mirror over PostgreSQL, and the two
recordings say where PostgreSQL is slower.

Statements are grouped by a fingerprint: the text with its literals and binds
each a `?`, comments dropped, words in upper case and spacing ignored. So
`WHERE id = 1` and `WHERE id = :x` are one statement. For each one the profile
keeps:

- calls, rows in and out, total and mean time, and p50 / p95 / p99 from a
  sample of up to 1000 calls;
- errors by ORA code, and the kind of call: `execute`, `plsql`, `executemany`,
  or `lob` for a BFILE read;
- one example of the statement as the client sent it;
- over PostgreSQL, the statements the Mirror sent PostgreSQL per call, the
  time spent waiting on PostgreSQL apart from the Mirror's own, and the
  PostgreSQL text the statement ran as.

Fetches are served from what the statement already fetched, so their rows
count toward it. The Mirror serves LOB reads itself, except a BFILE's.

The file is JSON, written whole. It is written when the Mirror stops (an
interrupt or SIGTERM), on `SIGUSR1`, and as sessions end, at most every 10
seconds:

```sh
kill -USR1 $(pgrep -f seerdb-mirror)    # write the profile now
```

It also records the time the profiler itself took (`profiler_seconds`). Over
seerdb's integration suite through the Mirror over PostgreSQL that was under 1% of
the time recorded.

### Comparing two profiles

```sh
seerdb-mirror profile compare oracle.json postgres.json --html report.html
```

The first profile is the baseline (the run against Oracle), the second the
candidate (the run over PostgreSQL). The two are joined by fingerprint. A
statement that only one run saw, such as one that failed on one side, is
listed apart.

Statements are ranked by the time the candidate loses on them: the difference
in mean time per call, times the candidate's calls. They are not ranked by the
ratio: twice as slow on a statement called a million times outranks fifty
times as slow on one called twice. The ratio is shown alongside.

For each statement the report gives:
- calls, mean, total and p95 time on each side;
- errors by ORA code on each side;
- over PostgreSQL, the statements the Mirror sent PostgreSQL per call, and a
  call's time split between waiting on PostgreSQL and the Mirror's own.

That split says where to look. The **fix** column names the larger part of the
loss:
- **Mirror:** the Mirror's own time per call, so its emulation is the cost;
- **SQL:** PostgreSQL's time beyond Oracle's whole call, so the statement itself is the cost.

The command prints a plain-text summary of the top statements (`--top N`,
default 20). `--html FILE` also writes a self-contained HTML report of all of
them.

Two runs compare only on similar hardware, network and data volume. Both
reports say so, and show what the recordings can about each run: sessions,
calls, the time recorded, and the rows read and written.

### Suggestions

For each statement that loses time, both reports suggest how to win it back.
Each suggestion shows the statement as the client sent it, beside the
PostgreSQL text it ran as, as a starting point for a native rewrite. Each
suggestion also says whose fix it is:
- **application:** a rewrite the application can send over the same
  connection (see *Native PostgreSQL*);
- **Mirror:** a cost of the Mirror's emulation that every application pays.
  That's a Mirror performance issue to report, not a rewrite.

| rule | when | fix |
|---|---|---|
| index | a function around a column in a condition (`trunc(d) = :x`, `upper(name) = :x`): PostgreSQL cannot use an index on the column | application: compare the column itself (a range in place of `trunc`), or index the expression |
| anonymous block | a PL/SQL block that runs as a PostgreSQL `DO` block, planned afresh on every call | application: create it once as a PostgreSQL function and call that |
| helper per row | a query of 10 rows or more per call that runs one of the Mirror's `sys.*` helpers per row (`sys.deref`, `sys.ora_rowid`) | application: a rewrite without the Oracle feature, such as a join in place of a DEREF |
| statements per call | the Mirror sends PostgreSQL more than 1.5 statements per call above the usual (about 2 for a query, 4 for anything else), over at least 10 calls | Mirror |
| ROWID | an INSERT that asks PostgreSQL for the new row's ROWID, for the reply Oracle gives, whether or not the application reads it | Mirror |

The rules start from what the Mirror's own performance work measured, and
grow with the patterns that real recordings show.

## Performance

`tools/mirror_benchmark.py` runs `tools/benchmark.py` against Oracle directly
and through each kind of Mirror, plaintext and with ANO, and lays the results
side by side (#1866):

```sh
SEERDB_TEST_HOST=... SEERDB_TEST_PORT=... SEERDB_TEST_SERVICE=... \
SEERDB_TEST_USER=... SEERDB_TEST_PASSWORD=... MIRROR_PG='host=... dbname=...' \
    python3 tools/mirror_benchmark.py --scale 2000
```

**Measured 2026-10-17**, scale 2000, with:
- the client and the Mirror on one host;
- Oracle 23ai and PostgreSQL 16 on another, across a LAN;
- ratios to Oracle directly.

| scenario | direct | passthrough | passthrough + ANO | over PG | over PG + ANO |
|---|---|---|---|---|---|
| connect + close (20) | 1.9 s | 1.1x | 2.1x | 1.9x | 2.4x |
| a one-row query (200) | 1.3 s | 1.1x | 1.0x | 1.1x | 1.1x |
| a PL/SQL call (200) | 1.1 s | 1.3x | 1.1x | 1.1x | 1.5x |
| an insert, row by row (2000) | 11.7 s | 1.0x | 1.1x | 1.3x | 1.2x |
| `executemany` (2000 rows) | 0.05 s | 3.0x | 2.7x | 5.0x | 5.2x |
| `fetchall` (2000 rows) | 0.16 s | 1.1x | 1.1x | 0.3x | 0.3x |
| a 1 MiB CLOB written (5) | 3.3 s | 3.0x | 3.0x | 2.5x | 3.1x |
| a 1 MiB CLOB read (5) | 1.0 s | 1.4x | 1.5x | 0.7x | 0.8x |

Read them as follows:

- **The passthrough costs almost nothing per call.** Its exceptions are
  `executemany` and LOB writes.
- **Over PostgreSQL, a small call now costs about what Oracle's does.** On
  2026-10-14, on the same hosts, a one-row query took 4.4x and a connect 7.1x,
  because each Oracle call cost several PostgreSQL round trips. The round-trip
  work (milestone mirror-pg-performance, now closed; #1331, #1939) brought that
  to about one.
  `executemany` is still 5x, and bulk fetches and LOB reads are faster than
  Oracle's.
- **Known open cost:** some plain INSERTs send PostgreSQL about twice the usual
  number of statements per call
  ([#2392](https://github.com/seerdb/seerdb/issues/2392)). General
  availability needs every such issue fixed or accepted.
- **Encryption** costs most at connect (the key exchange), and little per call.

## Known limits

The PostgreSQL backend does not reproduce all of Oracle. The main limits:

- **Invalid UTF-8** cannot be stored in a string column (#1659).
- **Fractional seconds** stop at six digits; a `TIMESTAMP(9)` is a
  `TIMESTAMP(6)`.
- **`MEDIAN`** works as an aggregate, exact over a `NUMBER` and a `DATE`. As an
  analytic function (`MEDIAN(x) OVER (PARTITION BY ...)`) it is refused, since
  PostgreSQL has no exact median it can window.
- **`ROWNUM`** works as a top-N filter only. With `ORDER BY`, `GROUP BY`,
  `DISTINCT`, an aggregate, a set operator or `OR` at the same level, it is
  refused by name.
- **`ROWID`** is PostgreSQL's `ctid`, which changes when a row is updated or the
  table is vacuumed. `DBMS_ROWID` is not there.
- **PL/SQL packages, partly.** They have no package variables or initialization
  section. A `COMMIT` inside a routine waits until the call ends. A `ROLLBACK`
  inside one fails.
- **Object types** have no methods. A collection computed in a query fetches as
  a plain array.
- **Privileges.** Object grants are enforced with per-user roles only. In
  single-role mode they are recorded, and decide only who sees a type (*One
  tenant per database*). System privileges and roles are accepted and do
  nothing.
- **DIRECTORY and BFILE.** Files are read on the PostgreSQL host. `DBMS_LOB`'s
  file routines are not there.
- **Editions** are kept by name only; objects are not versioned per edition.
- **`VECTOR`** columns of `FLOAT32` hold at most 16000 dimensions, pgvector's
  limit (#1734).
- **SQL domains and annotations** are supported on columns only.
- **Sessionless transactions** resume only within the same Mirror process.
- **Transaction priority** is recorded and reported, but has no effect.
- **A quoted lower-case identifier**, such as `"t1"`, comes back upper-case.

The full list, with the reasons, is in the backend module's docstring
(`seerdb/server/backends/postgres.py`).

Two limits apply to the Mirror itself, whatever the backend:
- **The clients it serves:** thin clients from 10.2 on, and sqlplus / OCI from
  10.2 on. Oracle 8i and 9i clients are not served.
- **Newer types reach older clients unadapted.** A column of a type newer than
  the client's protocol, such as 23ai's `BOOLEAN` or `VECTOR` sent to a client
  that negotiated an 11g-era version, goes out with its own type code. Real
  Oracle sends those clients a form they know. Carrying such features to older
  clients in a form they can read is planned:
  [#2394](https://github.com/seerdb/seerdb/issues/2394) measures it, and
  [#2395](https://github.com/seerdb/seerdb/issues/2395) is the design.

## Troubleshooting

**The Mirror won't start.** It says why and exits. The common ones:
- `no accounts to serve`: list accounts under `[clients]` or in
  `MIRROR_USERS`, or keep them in a database with `--auth-conninfo`.
- `--per-user-roles needs --auth-conninfo`: per-user mode keeps each user's
  role password with the account.
- `cannot load the TLS certificate or key`: check the PEM files and that the
  Mirror's account can read them.
- For a passthrough, `give --field-version, or an account ... to probe the
  upstream with`: the Mirror logs in upstream once at start-up to learn the
  version to present.

**A client can't log in.**
- **ORA-01017:** the user name or password is wrong, or the account isn't one
  the Mirror serves. Names fold to upper case.
- **ORA-28000:** the name is locked after repeated failures. An administrator
  runs `ALTER USER name ACCOUNT UNLOCK`, or the Mirror restarts.
- **The client is refused before the password:** check what it negotiated.
  The log names a client below the version the Mirror serves (`client
  negotiated TTC field version ..., below the ... this Mirror serves`).
- **TLS fails:** recent clients, python-oracledb's thin mode among them, refuse
  a certificate without the standard extensions, such as an Authority Key
  Identifier. Issue it from a proper CA (*Encryption*). A client that requires
  ANO is refused by a Mirror run with `--encryption accepted`.

**Ordinary Oracle SQL fails.**
- **Built-in functions are missing** (`NVL`, `DECODE`, `TO_CHAR`,
  `ADD_MONTHS`, ...): orafce isn't installed in the database. The Mirror tries
  `CREATE EXTENSION orafce` when it connects. If its role may not, have an
  administrator create it (*What the database needs*).
- **A `VECTOR` column is refused:** pgvector isn't installed.
- **A statement is refused by name**, such as `ROWNUM` with `ORDER BY` at the
  same level: it is one of the *Known limits*, and the message says which.

**After an upgrade, sessions are refused.** Another Mirror serving the same
database is still on an older release. Upgrade every Mirror serving a database
together (*Upgrades*). A database a preview release set up is refused with *set
it up afresh*.

**It is slower than expected.** Record a migration profile and compare it with
one recorded through a passthrough in front of Oracle (*Migration profile*).
The report says whether the time is the Mirror's own or the statement's in
PostgreSQL.

## Writing a backend

The `Backend` protocol is promised from general availability (*Stability*), so
a backend of your own is supported.

- **Where it is defined:** in `seerdb/server/backend.py`, with the types it
  takes and returns.
- **What a backend implements:**
  - `capabilities`, the features it supports;
  - `authenticate(username)`, returning that user's password, which O5LOGON
    needs, or `None` to refuse. `credential_lookup` covers a plain map of
    accounts;
  - `execute(sql, binds)`;
  - `commit()`, `rollback()` and `close()`.
  
  Optional methods add features. A feature a backend doesn't have is refused
  with a clean ORA error, never mis-encoded.
- **Serving it:** `seerdb.serve(host, port, backend_factory=...)` serves it,
  with one backend per session.

[`examples/sqlite_backend.py`](../examples/sqlite_backend.py) is a small
complete one, over SQLite. [`examples/mirror_over_sqlite.py`](../examples/mirror_over_sqlite.py)
runs it. SQLite runs no PL/SQL, so it serves thin clients only: sqlplus's login
needs a backend that runs PL/SQL.
