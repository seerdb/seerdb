# Notes for coding agents

This file collects repeatable procedures for automated / AI agents working
on seerdb. For the project's clean-room posture and contribution rules, read
[`CONTRIBUTING.md`](CONTRIBUTING.md) first — those requirements always apply.

## Layout

`seerdb/` has three subpackages: `common/` is the wire codec and the types both
sides share (`tns.py`, `tns_consts.py`, `crypto.py`, ...), `client/` the DB-API
driver, and `server/` the Mirror, with its backends under `server/backends/`.
The root `__init__.py` re-exports the public API.

## Before you open a PR

Linting and type checking are expensive to run on GitHub, so they are **not**
what CI is for. Run them locally — they gate opening a PR:

```sh
ruff check seerdb tests
ruff format --check seerdb tests
python -m mypy
reuse lint
```

All four, every time, including before amending onto a PR that is already open.

These bite repeatedly:

- **`python -m mypy` takes no path.** Bare, it checks every file including the
  tests; `mypy seerdb` checks a third of them and has passed while the real gate
  failed. Prefer narrowing a type to silencing it — a wrong `# type: ignore[...]`
  error code is itself an error.
- **`reuse lint` sees untracked files.** A suite run leaves
  `mirror-passthrough.log` and `mirror-postgres.log` beside the checkout, and
  `reuse` flags them even though git ignores them. Delete them before linting,
  and never stage them.
- **CI's mypy runs without the `mirror` extra.** There `psycopg` is `Any`, so
  code that passes locally with psycopg installed can fail with `[has-type]`.
  To reproduce, use a venv with only `pip install . mypy`.
- **CI runs Python 3.10 to 3.14.** An annotation that 3.10 evaluates eagerly (a
  name shadowed by a class attribute breaks `X | None` at import) and an
  `await` inside a nested comprehension (a `SyntaxError` before 3.12) both pass
  a newer local interpreter. Use `from __future__ import annotations`, write
  await-loops as plain `for` loops, and check `gh pr checks` after opening.
- **Grep before adding a module-level name to a large module.** In
  `seerdb/server/backends/postgres.py` and the big test modules, a new constant
  or helper with an existing name silently rebinds it, and neither ruff nor
  mypy flags a reassigned constant.

### Tests

CI runs the offline suite on every change. Each integration leg runs only for the
paths it can reach (#1470):

- **Oracle legs** (11g, 18c, 21c, 23ai, 23ai at 12.1, and SQLAlchemy on 11g and
  23ai) run when `seerdb/client`, `seerdb/common`, the root package, the test
  harness or `pyproject.toml` changed. A Mirror-only change, or a new test in
  `tests/test_integration.py` alone, does not run them.
- **Mirror-over-PG legs** (the integration suite and SQLAlchemy through the
  Mirror) run for any change under `seerdb/` (the seerdb client drives the
  Mirror, so a client change can break it), `examples/`, or the integration and
  backend test modules. The passthrough backend
  (`seerdb/server/backends/passthrough.py`) is the exception: those legs never
  load it, and python-oracledb's suite through it runs weekly in CI and locally
  per PR.
- A **nightly** run takes every leg whatever changed.

8i, 9i, 10g, the passthrough Mirror and python-oracledb's own suite are **local
only** per PR. Locally, run what CI never runs for the paths your PR touches,
not the whole matrix (a PR touching several rows runs the union):

| PR touches | run locally |
|---|---|
| anything | the static checks above, before pushing |
| `seerdb/server/backends/postgres.py` (the Mirror-over-PG backend) or `examples/` | `tests/test_postgres_backend.py` before pushing, then python-oracledb's suite (`tools/run_oracledb_suite.py`) against a Mirror-over-PG |
| the rest of `seerdb/server` | python-oracledb's suite against a passthrough Mirror over 23ai, on the branch and on its `master` base, and against a Mirror-over-PG |
| the Mirror's OCI (sqlplus) dialect: the OCI code in `seerdb/server/session.py`, `seerdb/common/oci.py` or the OCI codec in `seerdb/common/tns.py` | `tools/sqlplus_survey.py` with sqlplus 23.26, direct to 23ai and through a passthrough Mirror over it, compared on the branch and on its `master` base |
| `seerdb/client` | the integration suite on 8i, 9i and 10g, and with `SEERDB_TEST_OALL8=1` on 9i, 10g and 11g |
| `seerdb/common` | the integration suite on 8i, 9i and 10g, with `SEERDB_TEST_OALL8=1` on 9i, 10g and 11g, on the 26ai bed under required native encryption, and through a passthrough Mirror over 23ai; and both python-oracledb suite runs |

Run these while the PR is a draft, and put the legs you ran and their numbers
in the PR. CI covers the rest for those paths, and the nightly run covers every CI
leg whatever changed; 8i, 9i and 10g run nowhere but locally, which is why a
client change still needs them. Don't repeat a CI leg locally (#2046): the 11g,
18c, 21c and 23ai beds, 23ai at 12.1 and both Mirror-over-PG legs all run once
the PR is ready, though never with `SEERDB_TEST_OALL8=1`, so 11g's run with it
stays local. A leg on its own bed or database can run alongside the others;
two on one bed cannot.

CI minutes are a limited quota and local runs are free, and every push to a PR
re-runs every leg its paths reach (#1942). So:

- A **draft** PR runs only the offline suite, typecheck, packaging, lint and
  REUSE. The Oracle and Mirror integration legs, both SQLAlchemy runs and
  CodeQL wait until it is marked ready for review, then run on every push.
- So open the PR as a draft once the change is committed, and run the local
  legs meanwhile. Mark it ready for review once they pass, which starts the
  heavy legs once.
- Collect review fixes into one amend and one push.
- When two PRs touch the same code, open the second after the first merges,
  rebased once. Don't rebase a PR that still merges cleanly.

CI runs the offline suite on every push, drafts included, and its codec modules
under `unittest` in a different order (the `unittest` step in
`.github/workflows/tests.yml`). So the whole offline suite isn't a local leg.
While working, run the modules you touched, and run the `unittest` step too when
a test changes shared state, so state it leaves behind shows up before the push.
If a leg is red for a reason unrelated to the change, show it with the same run
on the `master` base and say so in the PR.

A docs-only change needs none of the test tiers; the repository's own workflows
skip them on those paths too.

### Proving a test

- **A new test must fail without the fix.** pytest puts the test file's own
  tree on `sys.path` ahead of `PYTHONPATH`, so
  `PYTHONPATH=<base> pytest <branch>/tests/test_x.py` still imports the branch.
  Copy the test into the base's checkout and run it there.
- **seerdb's own decoder proves nothing about its encoder**, and neither does a
  hand-written wire fixture: each holds the same assumption. Where the server
  interprets what was written (a JSON image's hash array, an index, a sort
  order), check that the server acts on it, and diff against a server-built
  image of the same value. When a live run disagrees with a fixture, fix the
  fixture from a capture.
- **A direct call into the codec runs at the field-version defaults**
  (`_DECODE_FIELD_VERSION` / `_ENCODE_FIELD_VERSION` in `seerdb/common/tns.py`).
  Before reporting a codec or Mirror bug from such a call, set them as the
  session that makes the call does, or reproduce it live.
- **A Mirror performance or caching change** is timed by running
  python-oracledb's suite alone, on the branch and on its merge base. A
  per-call benchmark of a short statement cannot see a cost that grows with the
  statement's length.

### PostgreSQL versions

The Mirror-over-PG supports PostgreSQL 16 and later, and uses what the newest
PostgreSQL, orafce, pgvector and plpgsql_check offer. It doesn't keep to what
every supported version has.

- **CI's image tracks the newest releases**, each pinned exactly
  (`examples/mirror-pg.Dockerfile`). Test a bump before moving the pin:
  plpgsql_check v2.10.12 crashed the server.
- **A feature only a newer version has is installed only where the server has
  it.** Check the server's version at install, so the dictionary still installs
  on 16. A construct the oldest version can't parse must never reach the install
  unguarded, or the Mirror stops working there altogether.
- **Its tests skip below that version** rather than fail.
- **Document it**: add a row to docs/MIRROR.md's *By PostgreSQL version*,
  saying what an older server does instead. Don't work around it for the older
  versions.
- **The oldest supported setup** has a non-blocking CI leg (#2668) and a local
  bed. Its failures are what that table should say; a gap missing from the
  table is a docs bug.
- **When a newer version would lift a documented restriction**, propose raising
  the minimum in a ticket of its own.

### Sharing a database or a bed

- **One suite per database or bed at a time.** The Mirror-over-PG legs,
  `tests/test_postgres_backend.py` and a hand-started Mirror each install their
  own checkout's dictionary into the database they connect to and create and
  drop objects there, so two runs against one database break each other. An
  Oracle bed is the same: the SQLAlchemy dialect's schema reset drops tables
  from under a running integration suite. A leg that failed while something
  else ran is rerun alone before it counts as a regression.
- **The offline leg must not inherit `MIRROR_PG`** while a Mirror-over-PG leg
  runs: with it set, `pytest tests` also runs the live backend module against
  the same database. Run it with `env -u MIRROR_PG`.
- **Test against CI's PostgreSQL.** CI builds its database from
  `examples/mirror-pg.Dockerfile`, with orafce and pgvector pinned, and orafce
  changes behaviour between versions. A change to which orafce function runs is
  checked against an image built from that file.
- **A change to how the backend wraps statements in transactions** runs on a
  fresh database and through `tools/run_mirror_suite.py postgres` at both
  `MIRROR_PRESENTS=23ai` and `12.1`, not only the backend module: psycopg's
  prepared-statement cache and the connection's prelude break in ways only the
  integration suite reaches.
- **A fail-without check on a used database proves little.** A branch that adds
  a view, function or column leaves it behind, and the base never drops it, so
  the new test passes on the base too. Drop the object first, and clear the
  installation stamp so the next connect reinstalls:
  `COMMENT ON SCHEMA system IS NULL`.

## Merging

Merging is the maintainer's, with one exception: an agent may merge a
**docs-only** PR itself, once its checks (lint, REUSE) have passed. Docs-only
means it touches nothing under `.github/`, `seerdb/`, `tests/`, `tools/` or
`examples/`, and not `pyproject.toml`: README, `docs/`, the ChangeLog, this file
and the like. Anything else waits for the maintainer, a release PR included.

## Cutting a release

seerdb releases publish to PyPI automatically via GitHub Actions Trusted
Publishing, triggered when the maintainer **pushes a version tag**. An agent's
job is to *prepare* the release on a branch and open the PR — never to merge or
tag it. The steps:

1. **Branch off `master`**, named `release-x.y.z` (e.g. `release-2.3.0`).

2. **Bump the version in both places — they must stay in sync:**
   - `pyproject.toml` → `version = "x.y.z"`
   - `seerdb/common/tns.py` → `_CLIENT_VERSION = 'x.y.z'`

   `_CLIENT_VERSION` is also packed into the `SESSION_CLIENT_VERSION` the driver
   sends on the wire, so a mismatch is a real bug, not just cosmetic.
   `seerdb.__version__` is that same string re-exported, so it needs no bump of
   its own; `tests/test_version.py` fails when the two places drift.

3. **Update the [`ChangeLog`](ChangeLog):** prepend a new `version x.y.z:` block
   at the top (releases are newest-first; bullets within a release run
   oldest-to-youngest). Each bullet is a short prose line — bold the headline
   phrase and cite the issue/PR as `(#NNN)`. Cover what changed since the last
   tag (`git log <last-tag>..master`), skipping dependabot / pure-CI noise.
   Mirror (`seerdb.server`) changes are listed too, from the release that
   first ships it (3.1.0), each bullet starting **Mirror (tech preview):** so
   nobody reads it as a promise the client keeps. Bring `README.md` up to date
   in the same PR: the Compatibility table, the Feature matrix and the Status
   list.

4. **Open a PR** against upstream `master` following the normal fork→upstream
   flow (push the branch to your fork, open the PR against `seerdb/seerdb`).
   Title it `Release x.y.z`. In the body, summarise the shipped features and
   state the validation status honestly (which tiers were tested live; call out
   anything validated only against the Mirror / a local bed rather than a real
   server).

5. **Stop there. Do NOT merge the PR, and do NOT create or push the tag.** The
   maintainer reviews, merges, runs a final live-matrix pass, and pushes the
   `x.y.z` tag. Tagging is what publishes to PyPI and creates the GitHub
   release — it is deliberately a human step.

### Compatibility with the SQLAlchemy dialect

The driver and `sqlalchemy-seerdb` release independently, so each one's suite
says what the other may rely on:

- **This driver must pass the released dialect's compliance suite**: the
  `SQLAlchemy` workflow checks out the dialect at its newest git tag, installs
  the driver from the checkout on top of it, and runs SQLAlchemy's dialect
  compliance suite against 11g and 23ai. It gates: a driver change that breaks
  what users have installed fails here.
- **The dialect, for its part, must pass against this driver's releases**,
  and only watches this driver's `master` as an early warning that does not
  gate. A failure on that leg is raised here, as a driver regression, unless
  it is a dialect change waiting for the next driver release.
- Release order follows: this driver releases first, then the dialect raises
  its `seerdb>=` floor and releases against it.

### Versioning

Follow semantic versioning against the **client (DB-API 2.0) surface**, which is
the stable public API. Additive, backward-compatible features are a **minor**
bump; bug fixes are a **patch**. A breaking change to the client API (e.g.
the `oracle` → `seerdb` package rename in 2.0.0) is a **major** bump.

The server-side "Mirror" (`seerdb.server`, the `mirror` extra) is an **initial
implementation**, a technology preview until its general availability: it ships with
the package but is *not* covered by semver, and its API, command line and
behaviour may change in any release. From GA on, semver covers the list in
docs/MIRROR.md *Stability* (#1861):
- the launcher's options and config keys, its defaults, and `seerdb.serve` /
  `seerdb.Server`;
- the `Backend` protocol and the types it exchanges;
- a deployment's database across upgrades within a major release;
- the migration profile's format.

The wire-level helpers `seerdb.server` exports, and what the backend keeps in
PostgreSQL, stay outside it.

**The Mirror-over-PG data version** (#1862) lives in
`seerdb/server/backends/postgres.py`:
- `_DATA_VERSION`: the version this release writes;
- `_DATA_BASELINE`: the oldest version it upgrades from;
- `_DATA_UPGRADES`: the steps, each `(version, SQL)` and idempotent;
- `_ADOPT_UNVERSIONED`: whether a database with no version is adopted.

How to use them:
- **The GA release** sets `_DATA_BASELINE = _DATA_VERSION`, bumped to a number
  of its own, and `_ADOPT_UNVERSIONED = False`. A preview database is then
  refused with "set it up afresh".
- **From GA on**, a change to what the records hold (a `sys.ora_*` table's
  columns or rows, the accounts) bumps `_DATA_VERSION` and adds the step that
  brings an existing database there, with a test that upgrades one.
- **Before GA**, the no-compatibility rule stands: no steps are written.

**Renaming or removing a Mirror launcher option or config key** follows the
deprecation policy in docs/MIRROR.md (*Deprecations*, #1863). It binds from the
Mirror's general availability on:

1. Add the old spelling to `_DEPRECATED_OPTIONS` (`--old`) or `_DEPRECATED_KEYS`
   (`(section, key)`) in `seerdb/server/launcher.py`. Name its replacement, or
   `None` for an option removed with nothing in its place, which then stays
   defined. Name the release that removes it, at least one minor release away.
2. Add a ChangeLog bullet naming it in backquotes with the word *deprecated*.
   `tests/test_server_launcher.py` checks that it is there.
3. Remove the entry and the old spelling in the release it names.
