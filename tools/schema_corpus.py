#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Regenerate tests/schema_corpus.txt: the messages the schema decoders read (#2290).

    python3 tools/schema_corpus.py            # from a checkout's root

Runs the offline suite with every compiled schema decoder in
seerdb/common/tns.py wrapped, records each distinct message one decodes (the
bytes it consumed, what it was given, the field version), and writes them out
for tests/test_schema_round_trip.py to re-encode. Most are the captures the
tests hold; some are what seerdb's own client sends the Mirror in a test.

Left out, and counted in the file's header: what a fuzz test feeds a
decoder, what a test feeds one to show it does not raise on rubbish, and the
cut-short prefixes and arbitrary bytes the resumable AUTH walk is checked on --
bytes, not messages.
"""

import json
import os
import subprocess
import sys
import tempfile
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, 'tests', 'schema_corpus.txt')
# A test whose input is random bytes, by name, or cut-short and arbitrary
# bytes: the resumable AUTH walk is fed every prefix of a message and pairs of
# arbitrary bytes, to agree with a whole walk on each (GHSA-vxvf-jx7x-rcx8).
_NOT_MESSAGES = ('test_fuzz', 'rubbish', 'test_the_auth_walk_')

_PLUGIN = """
import json, os, re
import pytest
from seerdb.common import tns

_out = open(os.environ['SCHEMA_CORPUS_LOG'], 'w')
_seen = set()
_current = ['?']
_src = open(tns.__file__).read()
_DECODERS = {
    name: (schema, codec)
    for name, schema, codec in re.findall(
        r'^(_[A-Z0-9_]+) = wire_schema\\.compile_decoder\\(\\s*(_[A-Z0-9_]+),\\s*(_[A-Z0-9_]+)',
        _src, re.M)
}


def _plain(value):
    if isinstance(value, (int, str, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray)):
        return {'hex': bytes(value).hex()}
    return None


def _wrap(name, decode):
    def recorded(data, given=None):
        result = decode(data, given)
        consumed = bytes(data[: len(data) - len(result[1])])
        plain = {k: _plain(v) for k, v in (given or {}).items()}
        key = (name, consumed, json.dumps(plain, sort_keys=True))
        if key not in _seen:
            _seen.add(key)
            schema, codec = _DECODERS[name]
            _out.write(json.dumps({'schema': schema, 'codec': codec,
                                   'fv': tns._DECODE_FIELD_VERSION.get(),
                                   'given': plain, 'consumed': consumed.hex(),
                                   'test': _current[0]}) + '\\n')
        return result
    return recorded


for _name in _DECODERS:
    setattr(tns, _name, _wrap(_name, getattr(tns, _name)))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    _current[0] = item.nodeid
    yield
    _out.flush()
"""


def _record() -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, 'schema_corpus_plugin.py'), 'w') as f:
            f.write(_PLUGIN)
        log = os.path.join(tmp, 'decoded.jsonl')
        env = dict(
            os.environ, PYTHONPATH=f'{ROOT}{os.pathsep}{tmp}', SCHEMA_CORPUS_LOG=log
        )
        for name in ('SEERDB_TEST_USER', 'MIRROR_PG'):
            env.pop(name, None)  # the offline suite only
        subprocess.run(
            [
                sys.executable,
                '-m',
                'pytest',
                '-q',
                '-p',
                'no:cacheprovider',
                '-p',
                'schema_corpus_plugin',
                # The test that reads the corpus, which is being written.
                '-k',
                'not TestTheMessagesTheDecodersReadRoundTrip',
                'tests',
            ],
            cwd=ROOT,
            env=env,
            check=True,
        )
        with open(log) as f:
            return [json.loads(line) for line in f]


def main() -> None:
    sys.path.insert(0, ROOT)
    dropped: Counter = Counter()
    kept = []
    for r in _record():
        if any(word in r['test'] for word in _NOT_MESSAGES):
            dropped['random or cut-short bytes, not messages'] += 1
        else:
            kept.append(r)
    kept.sort(key=lambda r: (r['schema'], r['codec'], r['fv'], r['consumed']))
    with open(CORPUS, 'w') as f:
        f.write(
            # Split so REUSE reads these as the corpus's tags, not this file's.
            '# SPDX'
            '-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>\n'
            '# SPDX'
            '-License-Identifier: CC0-1.0\n'
            '#\n'
            '# The messages the wire schemas decode in the offline suite (#2290),\n'
            '# written by tools/schema_corpus.py; tests/test_schema_round_trip.py\n'
            '# re-encodes each. One per line: schema, codec, field version, what the\n'
            '# decoder was given (JSON), the bytes it read (hex), and the test it\n'
            '# came from. Regenerate after a schema or a capture changes. A message\n'
            '# the Mirror builds as the test runs carries its time (an OCI describe\n'
            "# head's), so that line changes on each regeneration.\n"
            f'# {len(kept)} messages; left out:\n'
        )
        for reason, n in sorted(dropped.items()):
            f.write(f'#   {n} {reason}\n')
        for r in kept:
            given = json.dumps(r['given'], sort_keys=True, separators=(',', ':'))
            f.write(
                f'{r["schema"]}\t{r["codec"]}\t{r["fv"]}\t{given}\t{r["consumed"]}\t{r["test"]}\n'
            )
    print(f'{CORPUS}: {len(kept)} messages, left out {dict(dropped)}')


if __name__ == '__main__':
    main()
