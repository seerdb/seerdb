#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""What a Mirror in the path costs: tools/benchmark.py against Oracle directly
and through each kind of Mirror, side by side (#1866).

    SEERDB_TEST_HOST=... SEERDB_TEST_PORT=... SEERDB_TEST_SERVICE=... \\
    SEERDB_TEST_USER=... SEERDB_TEST_PASSWORD=... MIRROR_PG='host=... dbname=...' \\
        python3 tools/mirror_benchmark.py [--scale N] [--targets a,b,...]

Targets (default: all):

``direct``               the Oracle in SEERDB_TEST_*, no Mirror;
``passthrough``          a Mirror relaying to that Oracle, plaintext;
``passthrough-ano``      the same with native encryption (``--encryption requested``);
``pg``                   a Mirror over the PostgreSQL in MIRROR_PG, plaintext;
``pg-ano``               the same with native encryption.

Each Mirror is this checkout's ``python -m seerdb.server``, started for its run
and stopped after, serving the SEERDB_TEST_* account. The table gives seconds per
scenario per target and, in brackets, the ratio to ``direct``. Compare runs on
the same hosts only: the numbers are wall-clock, and where PostgreSQL runs
matters most (#1331).
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_TARGETS = ('direct', 'passthrough', 'passthrough-ano', 'pg', 'pg-ano')
_LINE = re.compile(r'^(?P<name>\S.*?)\s+(?P<count>\d+) \S+\s+(?P<seconds>[\d.]+)s\s')


def _wait_for(port: int, process: subprocess.Popen, seconds: float = 30.0) -> bool:
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


def _mirror_args(target: str, port: int) -> list[str]:
    encryption = 'requested' if target.endswith('-ano') else 'accepted'
    args = ['--port', str(port), '--service', 'XE', '--encryption', encryption]
    if target.startswith('pg'):
        return [*args, 'postgres', os.environ['MIRROR_PG']]
    upstream = (
        f'{os.environ.get("SEERDB_TEST_HOST", "127.0.0.1")}:'
        f'{os.environ.get("SEERDB_TEST_PORT", "1521")}/'
        f'{os.environ.get("SEERDB_TEST_SERVICE", "XE")}'
    )
    return [*args, 'passthrough', upstream]


def run_target(target: str, scale: int, port: int) -> dict[str, float]:
    """Run tools/benchmark.py against one target; scenario name -> seconds."""
    env = dict(os.environ, PYTHONPATH=_ROOT)
    mirror = None
    if target != 'direct':
        user = env.get('SEERDB_TEST_USER', 'pyo')
        password = env.get('SEERDB_TEST_PASSWORD', '')
        log = open(os.path.join(_ROOT, f'mirror-bench-{target}.log'), 'w')
        mirror = subprocess.Popen(
            [sys.executable, '-m', 'seerdb.server', *_mirror_args(target, port)],
            cwd=_ROOT,
            env=dict(env, MIRROR_USERS=f'{user}:{password}'),
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        if not _wait_for(port, mirror):
            mirror.kill()
            raise SystemExit(f'{target}: the Mirror did not come up on {port}')
        env.update(
            SEERDB_TEST_HOST='127.0.0.1',
            SEERDB_TEST_PORT=str(port),
            SEERDB_TEST_SERVICE='XE',
        )
    try:
        out = subprocess.run(
            [sys.executable, os.path.join(_ROOT, 'tools', 'benchmark.py'), str(scale)],
            cwd=_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        if mirror is not None:
            mirror.terminate()
            try:
                mirror.wait(timeout=10)
            except subprocess.TimeoutExpired:
                mirror.kill()
    if out.returncode:
        print(out.stdout, out.stderr, sep='\n', file=sys.stderr)
        raise SystemExit(f'{target}: the benchmark failed')
    results: dict[str, float] = {}
    for line in out.stdout.splitlines():
        match = _LINE.match(line)
        if match:
            results[match['name'].strip()] = float(match['seconds'])
    return results


def table(results: dict[str, dict[str, float]]) -> str:
    """Seconds per scenario (rows) per target (columns), with the ratio to
    ``direct`` where it ran."""
    targets = list(results)
    scenarios: list[str] = []
    for per_target in results.values():
        scenarios += [name for name in per_target if name not in scenarios]
    lines = [f'{"scenario":<26}' + ''.join(f'{t:>20}' for t in targets)]
    for name in scenarios:
        row = f'{name:<26}'
        base = results.get('direct', {}).get(name)
        for target in targets:
            seconds = results[target].get(name)
            if seconds is None:
                row += f'{"-":>20}'
            elif base and target != 'direct':
                row += f'{seconds:>11.3f}s ({seconds / base:4.1f}x)'
            else:
                row += f'{seconds:>19.3f}s'
        lines.append(row)
    return '\n'.join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--scale', type=int, default=5000)
    parser.add_argument('--targets', default=','.join(_TARGETS))
    parser.add_argument('--port', type=int, default=15591)
    args = parser.parse_args(argv)
    targets = [t for t in args.targets.split(',') if t]
    unknown = [t for t in targets if t not in _TARGETS]
    if unknown:
        parser.error(f'unknown targets: {", ".join(unknown)}')
    results = {}
    for target in targets:
        print(f'... {target}', file=sys.stderr)
        results[target] = run_target(target, args.scale, args.port)
    print(f'scale {args.scale}')
    print(table(results))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
