#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Run the integration suite THROUGH the Mirror, in one command.

Starts a Mirror (``python -m seerdb.server``, the checkout's) as a separate
process, points the suite's SEERDB_TEST_* environment at it, runs pytest, and
tears the Mirror down::

    python3 tools/run_mirror_suite.py postgres     [pytest args...]
    python3 tools/run_mirror_suite.py passthrough  [pytest args...]

``postgres``    — the Mirror serving every statement from PostgreSQL (needs
                  orafce; see examples/mirror-pg.Dockerfile). Connection string
                  from the MIRROR_PG environment variable (the same one
                  tests/test_postgres_backend.py reads); MIRROR_PRESENTS,
                  MIRROR_AUTH_PG and SEERDB_TRANSLATION_REPORT=1 become its
                  --presents, --auth-conninfo and --translation-report.
``passthrough`` — the Mirror relaying to a real Oracle, from SEERDB_TEST_HOST /
                  _PORT / _SERVICE (the same variables the direct suite uses),
                  so a failure isolates a Mirror gap rather than a
                  backend-dialect limit. MIRROR_FIELD_VERSION becomes its
                  --field-version.

The Mirror serves the suite's account (SEERDB_TEST_USER / _PASSWORD, PYO /
pyo123 by default) and any more in MIRROR_USERS.

The Mirror runs as a SEPARATE process on purpose: run in-process, the suite's
client-side monkeypatches (send counting) would also see the passthrough's
upstream traffic, and per-backend credential copies break changepassword.
The Mirror's port comes from MIRROR_PORT (default 15521); its log is written
next to the checkout as mirror-<backend>.log and printed when the suite fails.
Committed defaults stay generic (127.0.0.1); point the variables at your beds.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_BACKENDS = ('postgres', 'passthrough')
_DEFAULT_PG = 'host=127.0.0.1 port=5433 user=pyo password=pyo123 dbname=mirror'


def _launcher_args(backend: str, port: int) -> list[str]:
    # The seerdb-mirror command line for this leg (#1835). The suite connects
    # as service XE, which neither backend serves by its own name (#2471).
    args = ['--port', str(port), '--service', 'XE', backend]
    if backend == 'postgres':
        args.append(os.environ.get('MIRROR_PG', _DEFAULT_PG))
        if os.environ.get('MIRROR_PRESENTS'):
            args += ['--presents', os.environ['MIRROR_PRESENTS']]
        if os.environ.get('MIRROR_AUTH_PG'):
            args += ['--auth-conninfo', os.environ['MIRROR_AUTH_PG']]
        if os.environ.get('SEERDB_TRANSLATION_REPORT') == '1':
            args.append('--translation-report')
        return args
    args.append(
        f'{os.environ.get("SEERDB_TEST_HOST", "127.0.0.1")}:'
        f'{os.environ.get("SEERDB_TEST_PORT", "1521")}/'
        f'{os.environ.get("SEERDB_TEST_SERVICE", "XE")}'
    )
    if os.environ.get('MIRROR_FIELD_VERSION'):
        args += ['--field-version', os.environ['MIRROR_FIELD_VERSION']]
    return args


def _wait_for(port: int, process: subprocess.Popen, seconds: float = 15.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in _BACKENDS:
        print(__doc__, file=sys.stderr)
        return 2
    backend, pytest_args = argv[0], argv[1:] or ['tests/test_integration.py']
    port = int(os.environ.get('MIRROR_PORT', '15521'))
    log_path = os.path.join(_ROOT, f'mirror-{backend}.log')
    # Run the checkout's Mirror, whatever seerdb is pip-installed.
    env = dict(os.environ, PYTHONPATH=_ROOT)
    env.setdefault('SEERDB_TEST_USER', 'PYO')
    env.setdefault('SEERDB_TEST_PASSWORD', 'pyo123')
    # The suite's account first: the passthrough probes its upstream as the
    # first one.
    suite_account = f'{env["SEERDB_TEST_USER"]}:{env["SEERDB_TEST_PASSWORD"]}'
    env['MIRROR_USERS'] = ','.join(filter(None, (suite_account, env.get('MIRROR_USERS'))))
    with open(log_path, 'w') as log:
        mirror = subprocess.Popen(
            [sys.executable, '-m', 'seerdb.server', *_launcher_args(backend, port)],
            cwd=_ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            if not _wait_for(port, mirror):
                print(f'the Mirror did not come up on {port}; see {log_path}')
                return 2
            # The suite now talks to the Mirror, which advertises service XE.
            env.update(
                SEERDB_TEST_HOST='127.0.0.1',
                SEERDB_TEST_PORT=str(port),
                SEERDB_TEST_SERVICE='XE',
                # Tell the suite it is talking to a Mirror, so a test can skip
                # for a feature the Mirror does not serve yet rather than fail
                # as though the CLIENT were at fault (#964). The value names the
                # backend, because some of what a leg cannot do belongs to the
                # backend rather than to the Mirror: PostgreSQL cannot parse
                # Oracle SQL, so it serves no `cursor.parse()` of a non-query,
                # while the passthrough does (#1019).
                SEERDB_TEST_MIRROR=backend,
            )
            env.pop('SEERDB_TEST_FIELD_VERSION', None)
            status = subprocess.call(
                [
                    sys.executable,
                    '-m',
                    'pytest',
                    '-p',
                    'no:cacheprovider',
                    *pytest_args,
                ],
                cwd=_ROOT,
                env=env,
            )
        finally:
            mirror.terminate()
            try:
                mirror.wait(timeout=10)
            except subprocess.TimeoutExpired:
                mirror.kill()
    if status:
        print(f'--- {log_path} (tail) ---')
        with open(log_path) as log:
            print(''.join(log.readlines()[-60:]))
    return status


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
