# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Every wire schema decodes what it encodes (#2290).

A schema (seerdb/common/wire_schema.py) says what a message carries once, and
compile_encoder / compile_decoder build both directions from it with a codec.
So for every schema in seerdb/common/tns.py, in every codec, encoding a set of
field values and decoding the bytes must give the same values back, at each
field version where a codec's framing changes. tns.py compiles many schemas in
one direction only; this compiles both, here.

The values are built from the schema itself: each field kind takes the edges it
can hold (0, a byte's and a ub2's limits, empty and over-252-byte values, an
absent `when` branch, an empty `each`), a different mix per sample. A schema
with a `raw` field holds bytes already encoded and has no decoder; those are
listed, so that a new one shows up in review.
"""

import itertools
import json
import os
import re
import unittest
from typing import Any

from seerdb.common import tns, wire_schema
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_23_1_EXT_1,
    FIELD_VERSION_23_4,
)

CODECS = {
    'thin': tns._THIN,
    'oci': tns._OCI,
    'oci-wide': tns._OCI_WIDE,
    'o8i': tns._O8I,
    'o9i': tns._O9I,
}
# The field versions at which a codec's framing changes: thin chunks long
# values with one-byte lengths before 12.1 and ub4 ones from it.
FIELD_VERSIONS = (FIELD_VERSION_11_2, FIELD_VERSION_12_1, FIELD_VERSION_23_4)
# Schemas holding a `raw` field: bytes already encoded, written as they are,
# with no length to read them back by. Encode-only by design.
ONE_WAY = {
    '_REFCURSOR_OUT',
    '_OBJECT_FRAME',
    '_LOB_READ_REPLY',
    '_DCB_COLUMN',
    # 9i OALL8's describe and the schemas around it carry _DCB_COLUMN (#798).
    '_DCB_COLUMN_9I',
    '_O9I_DESCRIBE_BODY',
    '_O9I_DESCRIBE',
    '_O9I_CURSOR_CELL',
    '_O9I_REFCURSOR_OUT',
    # 11g's cursor cell carries the same columns (#2466).
    '_OCI11_CURSOR_CELL',
    # The describe body it carries per result is pre-encoded, a raw field.
    '_IMPLICIT_RESULTS',
    # 9i's SQL length counts characters, not the bytes its text takes (#2275).
    '_O7_ALL7',
    # A direct path LOAD STREAM's rows, packed into pieces before (#2462).
    '_DIRECT_PATH_LOAD_STREAM',
}
SAMPLES = 12


def _auth_head(values: dict) -> None:
    # The user goes one way or the other, prefixed with its length or as the
    # bytes the header's own length counts, and that length is the user's.
    values['user_raw'] = 0 if values.get('user_prefixed') else 1
    values['user_length'] = len(values.get('user', b''))


def _o9i_iov(values: dict) -> None:
    # A 9.2 bind prompt counts its binds as `iterations * 256 + requests`, and the
    # directions are that many bytes (#798, #2311).
    binds = len(values.get('directions', b''))
    values['requests'] = binds % 256
    values['iterations'] = binds // 256
    values['binds'] = binds


# What a caller keeps to that the schema does not say, per schema.
CONTRACTS = {'_AUTH_HEAD': _auth_head, '_O9I_IOV': _o9i_iov}


def _schemas() -> dict[str, wire_schema.Schema]:
    # Every module-level `name: wire_schema.Schema = (...)` in tns.py.
    return {
        name: getattr(tns, name)
        for name, annotation in tns.__annotations__.items()
        if annotation in (wire_schema.Schema, 'wire_schema.Schema')
    }


def _has(schema: wire_schema.Schema, kind: str) -> bool:
    for field in schema:
        if field[0] == kind:
            return True
        if field[0] in ('when', 'only') and _has(field[2], kind):
            return True
        if field[0] == 'each' and _has(field[3], kind):
            return True
    return False


def _width(codec_name: str, kind: str) -> int:
    # The largest integer a kind holds in a codec, in bytes.
    if kind in ('u8', 'n1'):
        return 1
    if kind in ('n2', 'be2', 'le2'):
        return 2
    if kind == 'n8' and codec_name in ('oci', 'oci-wide', 'o9i'):
        return 8
    if kind == 'wn4' and codec_name in ('oci-wide', 'o9i'):
        return 8
    return 4


class _Values:
    # Field values for one sample: each kind cycles through its edges, from an
    # offset that differs per sample, so the samples mix them.

    def __init__(self, codec_name: str, sample: int, fv: int) -> None:
        self.codec_name = codec_name
        self.sample = sample
        self.fv = fv
        self.counter = itertools.count(sample)

    def _pick(self, choices: list) -> Any:
        return choices[next(self.counter) % len(choices)]

    def integer(self, kind: str) -> int:
        top = (1 << (8 * _width(self.codec_name, kind))) - 1
        return self._pick([v for v in (0, 1, 255, 256, 65535, 65536, top) if v <= top])

    def blob(self) -> bytes:
        return self._pick([b'', b'x', bytes(range(252)), bytes(range(256)) * 2])

    def fill(self, schema: wire_schema.Schema, values: dict[str, Any]) -> None:
        for field in schema:
            kind = field[0]
            if kind in ('const', 'pad'):
                continue
            if kind == 'only':
                if field[1] == self.codec_name.split('-')[0] or (
                    field[1] == 'oci' and self.codec_name in ('o8i', 'o9i')
                ):
                    self.fill(field[2], values)
                continue
            if kind == 'when':
                # The test is a field read before, or what the caller gives.
                if field[1] not in values:
                    values[field[1]] = self._pick([0, 1])
                if values[field[1]]:
                    self.fill(field[2], values)
                continue
            if kind == 'each':
                # The count chosen ahead, which a field read before the items
                # may test: 9i's batch messages have an indicator byte before
                # them only when there are any (#2284).
                count = values.get(field[2], self._pick([0, 1, 2]))
                values[field[2]] = count
                items = []
                for _ in range(count):
                    # A count inside an item (a RETURNING target's row count,
                    # #2466) is chosen ahead too; filled as a plain integer
                    # it asked for billions of items.
                    item: dict[str, Any] = {
                        ahead: self._pick([0, 1, 2])
                        for ahead in _needed_ahead(field[3])
                    }
                    self.fill(field[3], item)
                    items.append(item)
                values[field[1]] = items
                continue
            if kind == 'derive':
                values[field[1]] = field[2](values)
                continue
            name = field[1]
            if name in values:
                # A length or count chosen for a later field already set it.
                continue
            if kind == 'bytes':
                size = field[2]
                if not isinstance(size, int):
                    if size not in values:
                        values[size] = self._pick([0, 1, 5])
                    size = values[size]
                values[name] = bytes(range(size % 256)) * (size // 256) + bytes(
                    range(size % 256)
                )
                values[name] = values[name][:size]
            elif kind in ('u8', 'n1', 'n2', 'n4', 'n8', 'wn4', 'be2', 'be4', 'le2'):
                values[name] = self.integer(kind)
            elif kind == 'cstr':
                # A NUL-terminated string: its bytes cannot themselves hold a NUL.
                values[name] = self._pick([b'', b'x', b'banner text'])
            elif kind == 'scale':
                values[name] = self._pick([0, 1, 127, -1, -127])
            elif kind == 'ptr':
                values[name] = self._pick([False, True])
            elif kind == 'token':
                # Thin sends a function's token from 23ai and OCI never, both
                # directions by the field version: below 23ai a token given is
                # not written, so it does not come back.
                thin_token = (
                    self.codec_name == 'thin' and self.fv >= FIELD_VERSION_23_1_EXT_1
                )
                values[name] = self._pick([0, 7]) if thin_token else None
            elif kind in ('value', 'chr', 'lob'):
                values[name] = self.blob()
            elif kind == 'long':
                values[name] = self._pick([None, *[self.blob()]])
            else:
                raise AssertionError(f'no sample for field kind {kind!r}')


def _needed_ahead(schema: wire_schema.Schema) -> set[str]:
    # The names a `bytes` length or an `each` count refers to, which a sample
    # chooses with the field that uses them.
    names: set[str] = set()
    for field in schema:
        if field[0] == 'bytes' and not isinstance(field[2], int):
            names.add(field[2])
        elif field[0] == 'each':
            names.add(field[2])
            names |= _needed_ahead(field[3])
        elif field[0] in ('when', 'only'):
            names |= _needed_ahead(field[2])
    return names


def _sample(
    name: str, schema: wire_schema.Schema, codec_name: str, sample: int, fv: int
) -> dict:
    values: dict[str, Any] = {}
    gen = _Values(codec_name, sample, fv)
    # A length or count read before the field it sizes is set from what that
    # field holds: choose those first, so the earlier field writes them.
    for ahead in _needed_ahead(schema):
        values[ahead] = gen._pick([0, 1, 2])
    gen.fill(schema, values)
    if name in CONTRACTS:
        CONTRACTS[name](values)
    return values


def _same(sent: Any, got: Any) -> bool:
    if isinstance(sent, list):
        return (
            isinstance(got, list)
            and len(sent) == len(got)
            and all(_same(a, b) for a, b in zip(sent, got))
        )
    if isinstance(sent, dict):
        return isinstance(got, dict) and all(
            k in got and _same(v, got[k]) for k, v in sent.items()
        )
    return sent == got


class TestEverySchemaRoundTrips(unittest.TestCase):
    def test_the_one_way_schemas_are_those_with_a_raw_field(self):
        raw = {name for name, schema in _schemas().items() if _has(schema, 'raw')}
        self.assertEqual(raw, ONE_WAY)

    def test_every_schema_decodes_what_it_encodes(self):
        schemas = _schemas()
        self.assertGreater(len(schemas), 25)
        for name, schema in schemas.items():
            if name in ONE_WAY:
                continue
            for codec_name, codec in CODECS.items():
                encode = wire_schema.compile_encoder(schema, codec)
                decode = wire_schema.compile_decoder(schema, codec)
                for fv in FIELD_VERSIONS:
                    enc = tns._ENCODE_FIELD_VERSION.set(fv)
                    dec = tns._DECODE_FIELD_VERSION.set(fv)
                    try:
                        for sample in range(SAMPLES):
                            values = _sample(name, schema, codec_name, sample, fv)
                            with self.subTest(
                                schema=name, codec=codec_name, fv=fv, sample=sample
                            ):
                                wire = encode(values)
                                (got, rest) = decode(wire + b'\xee', values)
                                self.assertEqual(rest, b'\xee')
                                self.assertTrue(
                                    _same(values, got),
                                    f'{values!r} came back as {got!r}',
                                )
                    finally:
                        tns._ENCODE_FIELD_VERSION.reset(enc)
                        tns._DECODE_FIELD_VERSION.reset(dec)


class TestThinIntegersAreSigned(unittest.TestCase):
    """Thin's integer fields read TTC's sign-magnitude negatives, so they must
    write them too (#2299): a NUMBER bind with FLOAT's scale of -127 decoded,
    and re-encoding it raised."""

    def test_a_negative_round_trips(self):
        for kind in ('n1', 'n2', 'n4'):
            encode = getattr(tns._THIN, kind)
            decode = getattr(tns._THIN, 'read_' + kind)
            for value in (-1, -127, -128, -256, -65536, -(1 << 31)):
                with self.subTest(kind=kind, value=value):
                    self.assertEqual(decode(encode(value) + b'\xee'), (value, b'\xee'))
        self.assertEqual(tns._THIN.n4(-1), b'\x81\x01')
        self.assertEqual(tns._THIN.n4(-127), b'\x81\x7f')
        # The non-negative form is unchanged.
        self.assertEqual(tns._THIN.n4(127), b'\x01\x7f')

    def test_a_float_binds_descriptor_round_trips(self):
        # A NUMBER bind's OAC with scale -127, as test_tns_decode's
        # test_tns_decode_token_oac_01 holds it.
        oac = bytes.fromhex('020000817f010200000000000000')
        (values, rest) = wire_schema.compile_decoder(tns._OAC, tns._THIN)(oac)
        self.assertEqual((values['scale'], rest), (-127, b''))
        self.assertEqual(wire_schema.compile_encoder(tns._OAC, tns._THIN)(values), oac)


# --- The messages the decoders read, re-encoded (tests/schema_corpus.txt) ----

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema_corpus.txt')
# Where a real message may differ from its re-encoding, by design: the field
# reads it without keeping the bytes. Anything else must come back exactly.
_KEEPS_NO_BYTES = {
    # sqlplus sends the pointer's address; the schema keeps only whether one
    # is there, and writes the indicator.
    ('ptr', '_OCI'),
    ('ptr', '_OCI_WIDE'),
    # A native 9.2 server's status does the same (#798).
    ('ptr', '_O9I'),
}
_THIN_INTEGERS = ('n1', 'n2', 'n4', 'n8', 'wn4', 'token', 'scale')
# A pad a peer fills, which the schema skips and writes as zeros, named.
_FILLED_PADS = {
    # sqlplus writes the auth pairs' count as a ub4 and leaves the next four
    # bytes as they were (#2249).
    ('_AUTH_HEAD', '_OCI'): ('only', 'oci'),
}
# Text a peer chunks otherwise than the codec writes it, named: 8.1.7 sends a
# long message, a LONG and a long OUT value in chunks of 255 bytes, and the 8i
# codec writes text in thin's chunks of 64, the form 8i reads in a request
# (#2322), and a LONG in OCI's of 252.
_RECHUNKED_TEXT = {
    ('_O8I_STATUS', '_O8I'): ('when', 'code'),
    ('_O9I_STATUS', '_O9I'): ('when', 'code'),
    ('_O8I_LONG_CELL', '_O8I'): ('long', 'value'),
    ('_O8I_OUT_CELL', '_O8I'): ('chr', 'value'),
    # A server sends a multi-chunk LONG column in its own chunk sizes; the thin
    # codec rewrites the value in 252-byte chunks, so the bytes differ while the
    # value is the same (#2293).
    ('_LONG_CELL', '_THIN'): ('long', 'content'),
    # 11g sends a pooled session's LONG in OCI's chunks of 255 bytes, where the
    # 9.2 codec writes 252 (#2466).
    ('_O8I_LONG_CELL', '_O9I'): ('long', 'value'),
}


def _given(record: dict) -> dict:
    return {
        k: bytes.fromhex(v['hex']) if isinstance(v, dict) else v
        for k, v in record['given'].items()
    }


def round_trip(record: dict) -> tuple[bytes, dict, dict]:
    """A corpus record decoded, encoded again, and the new bytes decoded:
    (bytes again, values, values again)."""
    schema = getattr(tns, record['schema'])
    codec = getattr(tns, record['codec'])
    data = bytes.fromhex(record['consumed'])
    given = _given(record)
    enc = tns._ENCODE_FIELD_VERSION.set(record['fv'])
    dec = tns._DECODE_FIELD_VERSION.set(record['fv'])
    try:
        decode = wire_schema.compile_decoder(schema, codec)
        (values, _) = decode(data, given)
        again = wire_schema.compile_encoder(schema, codec)(values)
        (values_again, _) = decode(again, given)
    finally:
        tns._ENCODE_FIELD_VERSION.reset(enc)
        tns._DECODE_FIELD_VERSION.reset(dec)
    return again, values, values_again


def _field_at(record: dict, offset: int) -> tuple:
    # The top-level field whose bytes hold `offset` in the recorded message.
    schema = getattr(tns, record['schema'])
    codec = getattr(tns, record['codec'])
    data = bytes.fromhex(record['consumed'])
    dec = tns._DECODE_FIELD_VERSION.set(record['fv'])
    try:
        for i in range(1, len(schema) + 1):
            (_, rest) = wire_schema.compile_decoder(schema[:i], codec)(
                data, _given(record)
            )
            if len(data) - len(rest) > offset:
                return schema[i - 1]
    finally:
        tns._DECODE_FIELD_VERSION.reset(dec)
    return ('end',)


def _unexplained(record: dict, again: bytes) -> list[str]:
    # The differences between a message and its re-encoding that no field
    # kind explains, by offset and field.
    data = bytes.fromhex(record['consumed'])
    if again == data:
        return []
    offsets = [i for i, (a, b) in enumerate(zip(again, data)) if a != b]
    if len(again) != len(data):
        # A variable-width integer written longer than it needs: what follows
        # is shifted, so only the first difference says where it is.
        offsets = offsets[:1] or [min(len(again), len(data))]
    out = []
    for offset in offsets:
        field = _field_at(record, offset)
        kind = field[0]
        if (kind, record['codec']) in _KEEPS_NO_BYTES:
            continue
        if record['codec'] == '_THIN' and kind in _THIN_INTEGERS:
            continue
        if _FILLED_PADS.get((record['schema'], record['codec'])) == field[:2]:
            continue
        if _RECHUNKED_TEXT.get((record['schema'], record['codec'])) == field[:2]:
            continue
        out.append(f'{offset}: {field[:2]}')
    return sorted(set(out))


def _corpus() -> list[dict]:
    records = []
    with open(CORPUS) as f:
        for line in f:
            if not line.strip() or line.startswith('#'):
                continue
            (schema, codec, fv, given, consumed, test) = line.rstrip('\n').split('\t')
            records.append(
                {
                    'schema': schema,
                    'codec': codec,
                    'fv': int(fv),
                    'given': json.loads(given),
                    'consumed': consumed,
                    'test': test,
                }
            )
    return records


class TestTheMessagesTheDecodersReadRoundTrip(unittest.TestCase):
    """encode(decode(message)) == message, for the messages the decoders read
    in the offline suite, the tests' captures among them (#2290). A message
    may differ from its re-encoding only where a field keeps no bytes by
    design; its fields must always come back the same."""

    def test_the_corpus_covers_every_two_way_decoder(self):
        records = _corpus()
        self.assertGreater(len(records), 500)
        covered = {r['schema'] for r in records}
        with open(tns.__file__) as f:
            source = f.read()
        # A whole name: `_LOB_CELL_FROM_` is inside `_O7_LOB_CELL_FROM_THIN`.
        decoded = {
            name
            for name in _schemas()
            if name not in ONE_WAY and re.search(rf'(?<!\w){name}_FROM_', source)
        }
        self.assertEqual(decoded - covered, set())

    def test_each_message_comes_back(self):
        for record in _corpus():
            with self.subTest(
                schema=record['schema'], codec=record['codec'], test=record['test']
            ):
                (again, values, values_again) = round_trip(record)
                self.assertTrue(_same(values, values_again), 'its fields changed')
                self.assertEqual(_unexplained(record, again), [])


class TestThinTokenFollowsTheFieldVersion(unittest.TestCase):
    """Thin's token is written as it is read: from 23ai, whatever the caller
    gives, and not before. Its encoder wrote what it was given and its
    decoder read by the field version, so a token given below 23ai made a
    message its own decoder misread (#2290)."""

    def _encode(self, fv: int, value: int | None) -> bytes:
        token = tns._ENCODE_FIELD_VERSION.set(fv)
        try:
            return tns._THIN.token(value)
        finally:
            tns._ENCODE_FIELD_VERSION.reset(token)

    def test_below_23ai_no_token_is_written(self):
        for value in (None, 0, 7):
            self.assertEqual(self._encode(FIELD_VERSION_12_1, value), b'')

    def test_from_23ai_a_token_is_always_written(self):
        self.assertEqual(self._encode(FIELD_VERSION_23_4, None), b'\x00')
        self.assertEqual(self._encode(FIELD_VERSION_23_4, 0), b'\x00')
        self.assertEqual(self._encode(FIELD_VERSION_23_4, 7), b'\x01\x07')

    def test_a_piggyback_goes_by_the_connection_s_version(self):
        # Whatever the context says, the close-cursors piggyback and the fetch
        # take the field version they are given.
        token = tns._ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_4)
        try:
            old = tns.encode_close_cursors_piggyback(3, FIELD_VERSION_12_1, [1])
            fetch = tns.encode_dictionary_fetch(
                {
                    'seq': 3,
                    'cursor': 1,
                    'fetch': 10,
                    'field_version': FIELD_VERSION_12_1,
                }
            )
        finally:
            tns._ENCODE_FIELD_VERSION.reset(token)
        new = tns.encode_close_cursors_piggyback(3, FIELD_VERSION_23_4, [1])
        self.assertEqual(len(new) - len(old), 1)  # the token `00`
        self.assertEqual(fetch[3:4], b'\x01')  # the cursor, no token before it


if __name__ == '__main__':
    unittest.main()
