# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline guard for tools/mirror_benchmark.py (#1866): it reads
tools/benchmark.py's lines and lays the targets side by side. Running it needs
a live Oracle and PostgreSQL."""

from __future__ import annotations

import importlib.util
import os

_PATH = os.path.join(os.path.dirname(__file__), '..', 'tools', 'mirror_benchmark.py')


def _load():
    spec = importlib.util.spec_from_file_location('seerdb_mirror_benchmark', _PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_a_benchmark_line_is_read() -> None:
    mod = _load()
    line = 'round trip (1-row query)         200 calls     1.325s           151 calls/s'
    match = mod._LINE.match(line)
    assert match is not None
    assert (match['name'], match['seconds']) == ('round trip (1-row query)', '1.325')
    # The per-call latency line under it is not a scenario.
    assert mod._LINE.match(' ' * 47 + '6.62ms / call') is None


def test_targets_side_by_side_with_the_ratio_to_direct() -> None:
    mod = _load()
    out = mod.table(
        {
            'direct': {'fetchall (tuples)': 0.5, 'PL/SQL call': 1.0},
            'pg': {'fetchall (tuples)': 1.0},
        }
    )
    lines = out.splitlines()
    assert lines[0].split() == ['scenario', 'direct', 'pg']
    assert '0.500s' in lines[1] and '2.0x)' in lines[1]
    assert lines[2].rstrip().endswith('-')  # pg has no PL/SQL row


def test_each_mirror_target_runs_the_launcher_it_names() -> None:
    mod = _load()
    os.environ.setdefault('MIRROR_PG', 'dbname=mirror')
    # The benchmark connects as XE, served besides the backend's own (#2471).
    assert mod._mirror_args('pg-ano', 1)[2:7] == [
        '--service',
        'XE',
        '--encryption',
        'requested',
        'postgres',
    ]
    assert mod._mirror_args('passthrough', 1)[2:7] == [
        '--service',
        'XE',
        '--encryption',
        'accepted',
        'passthrough',
    ]
