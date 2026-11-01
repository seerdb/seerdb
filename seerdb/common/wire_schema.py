# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""One message schema, two serialisations (#2064).

Thin and OCI clients write the same TTC messages, but pack their primitives
differently: thin writes TTC's variable-width integers, OCI writes fixed-width
little-endian ones, and their long values are chunked to different rules. A
schema says *what* a message carries, once; a codec says *how* a dialect packs
each primitive. :func:`compile_encoder` and :func:`compile_decoder` turn the
pair into an encoder and a decoder, once, at import.

A schema is a tuple of fields:

- ``('const', b'...')``: literal bytes, the same in every dialect;
- ``('u8', name)``: one byte, the same in every dialect;
- ``('n4', name)`` / ``('n2', name)``: an integer the codec packs, TTC
  variable-width in thin, a ub4 / ub2 little-endian in OCI;
- ``('value', name)``: bytes with their length, chunked past 252 bytes;
- ``('chr', name)``: a character or RAW cell's bytes, framed as each dialect
  frames text;
- ``('lob', name)``: LOB_DATA content, always chunked unless empty;
- ``('scale', name)``: a describe column's scale, one signed byte, which thin
  before 12.1 writes in its variable-width signed form;
- ``('long', name)``: a LONG / LONG RAW cell's content, always chunked, and
  ``None`` for NULL;
- ``('token', name)``: a function call's token number, which thin sends from
  23ai (``None`` for none) and OCI never;
- ``('ptr', name)``: whether a pointer is present, a flag byte in thin, an
  8-byte pointer in OCI;
- ``('n1', name)``: a small count, TTC variable-width in thin, one byte in
  OCI;
- ``('n8', name)``: a 64-bit count, TTC variable-width in thin, a ub8
  little-endian in OCI;
- ``('wn4', name)``: a count that a wide OCI preamble writes as a ub8, and is
  an ``n4`` otherwise;
- ``('bytes', name, length)``: as many bytes as the integer field
  ``length`` says, or ``length`` itself when it is a number, as they are;
- ``('be2', name)`` / ``('be4', name)``: a big-endian ub2 / ub4 whatever
  the dialect, as in a LOB locator;
- ``('le2', name)``: a little-endian ub2 whatever the dialect, as in a
  TTI_PRO charset id;
- ``('cstr', name)``: a NUL-terminated byte string -- its bytes then a
  ``00`` -- as in a TTI_PRO banner; the bytes must not contain a ``00``;
- ``('pad', size)``: ``size`` bytes no field is known for, zero when written
  and passed over when read;
- ``('derive', name, function)``: no bytes; reading sets ``name`` to
  ``function(values)`` of the fields read so far, for a ``when`` to test;
- ``('raw', name)``: bytes already encoded, written as they are; a schema
  that has one encodes only;
- ``('when', name, fields)``: ``fields`` only when the integer ``name`` is not
  zero;
- ``('each', name, count, fields)``: ``fields`` once per item of the list
  ``name``, whose length the integer ``count`` gives; each item is read with
  the caller's ``given``;
- ``('only', dialect, fields)``: ``fields`` in that dialect alone.

A codec has a ``name`` (``'thin'`` or ``'oci'``) and the primitives ``n4``,
``n2``, ``value``, ``lob``, ``token``, ``ptr`` and ``wn4``, and to decode the
same names after ``read_``, each taking the bytes and returning the value
and the rest. This module knows no codec: :mod:`seerdb.common.tns` defines
them, beside the encoders they replaced.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, Protocol

Schema = tuple[tuple[Any, ...], ...]
# The field kinds a codec packs itself.
_PRIMITIVES = (
    'n4',
    'n2',
    'value',
    'chr',
    'lob',
    'long',
    'scale',
    'token',
    'ptr',
    'wn4',
    'n8',
    'n1',
)
_BIG_ENDIAN = {'be2': 2, 'be4': 4}
_LITTLE_ENDIAN = {'le2': 2}
Encoder = Callable[[dict[str, Any]], bytes]
Decoder = Callable[..., tuple[dict[str, Any], bytes]]


class Codec(Protocol):
    name: str

    def n4(self, value: int) -> bytes: ...
    def n2(self, value: int) -> bytes: ...
    def value(self, data: bytes) -> bytes: ...
    def lob(self, data: bytes) -> bytes: ...
    def chr(self, data: str | bytes) -> bytes: ...
    def long(self, data: bytes | None) -> bytes: ...
    def scale(self, value: int) -> bytes: ...
    def token(self, value: int | None) -> bytes: ...
    def ptr(self, value: bool) -> bytes: ...
    def wn4(self, value: int) -> bytes: ...
    def n8(self, value: int) -> bytes: ...
    def n1(self, value: int) -> bytes: ...
    def read_n4(self, data: bytes) -> tuple[int, bytes]: ...
    def read_n2(self, data: bytes) -> tuple[int, bytes]: ...
    def read_value(self, data: bytes) -> tuple[bytes, bytes]: ...
    def read_lob(self, data: bytes) -> tuple[bytes, bytes]: ...
    def read_chr(self, data: bytes) -> tuple[bytes, bytes]: ...
    def read_long(self, data: bytes) -> tuple[bytes | None, bytes]: ...
    def read_scale(self, data: bytes) -> tuple[int, bytes]: ...
    def read_token(self, data: bytes) -> tuple[int | None, bytes]: ...
    def read_ptr(self, data: bytes) -> tuple[bool, bytes]: ...
    def read_wn4(self, data: bytes) -> tuple[int, bytes]: ...
    def read_n8(self, data: bytes) -> tuple[int, bytes]: ...
    def read_n1(self, data: bytes) -> tuple[int, bytes]: ...


def _encode_part(field: tuple[Any, ...], codec: Codec) -> Callable[[dict], bytes]:
    kind = field[0]
    if kind == 'const':
        literal = field[1]
        return lambda values: literal
    if kind == 'u8':
        name = field[1]
        return lambda values: bytes((values[name],))
    if kind in ('raw', 'bytes'):
        name = field[1]
        return lambda values: values[name]
    if kind in _BIG_ENDIAN:
        (width, name) = (_BIG_ENDIAN[kind], field[1])
        return lambda values: values[name].to_bytes(width, 'big')
    if kind in _LITTLE_ENDIAN:
        (width, name) = (_LITTLE_ENDIAN[kind], field[1])
        return lambda values: values[name].to_bytes(width, 'little')
    if kind == 'cstr':
        name = field[1]
        return lambda values: values[name] + b'\x00'
    if kind == 'pad':
        zeros = bytes(field[1])
        return lambda values: zeros
    if kind == 'derive':
        return lambda values: b''
    if kind in _PRIMITIVES:
        (pack, name) = (getattr(codec, kind), field[1])
        return lambda values: pack(values[name])
    if kind == 'when':
        (name, inner) = (field[1], compile_encoder(field[2], codec))
        return lambda values: inner(values) if values[name] else b''
    if kind == 'each':
        (name, inner) = (field[1], compile_encoder(field[3], codec))
        return lambda values: b''.join([inner(item) for item in values[name]])
    if kind == 'only':
        if field[1] != codec.name:
            return lambda values: b''
        return compile_encoder(field[2], codec)
    raise ValueError(f'unknown field kind {kind!r}')


def compile_encoder(schema: Schema, codec: Codec) -> Encoder:
    """The encoder of ``schema`` in ``codec``'s dialect: the message's bytes
    from a dict of its fields' values."""
    parts = [_encode_part(field, codec) for field in schema]
    if len(parts) == 1:
        return parts[0]
    return lambda values: b''.join([part(values) for part in parts])


# Where a decoder is: the rest of the message, as a view.
_Step = Callable[[memoryview, dict[str, Any], Any], memoryview]


def _leaf(value: Any) -> Any:
    # A primitive read over a view returns a view of its bytes; the decoded
    # value is bytes of its own, so it outlives the message.
    return bytes(value) if isinstance(value, memoryview) else value


def _decode_part(field: tuple[Any, ...], codec: Codec) -> _Step:
    # One field's reader: the view after it, from the view before it, with
    # the field's value set in ``values``. ``given`` is what the caller of the
    # decoder gave, which an ``each`` hands each of its items.
    kind = field[0]
    if kind == 'const':
        literal = field[1]
        size = len(literal)

        def const(data: memoryview, values: dict, given: Any) -> memoryview:
            if data[:size] != literal:
                raise ValueError(f'expected {literal.hex()} at {data[:8].hex()}')
            return data[size:]

        return const
    if kind == 'u8':
        name = field[1]

        def u8(data: memoryview, values: dict, given: Any) -> memoryview:
            values[name] = data[0]
            return data[1:]

        return u8
    if kind == 'raw':

        def raw(data: memoryview, values: dict, given: Any) -> memoryview:
            raise ValueError('a raw field has no length to decode by')

        return raw
    if kind in _BIG_ENDIAN or kind in _LITTLE_ENDIAN:
        (name, width) = (field[1], _BIG_ENDIAN.get(kind) or _LITTLE_ENDIAN[kind])
        order: Literal['big', 'little'] = 'big' if kind in _BIG_ENDIAN else 'little'

        def integer(data: memoryview, values: dict, given: Any) -> memoryview:
            if len(data) < width:
                raise IndexError(f'{kind} past the end of the message')
            values[name] = int.from_bytes(data[:width], order)
            return data[width:]

        return integer
    if kind == 'cstr':
        name = field[1]

        def cstr(data: memoryview, values: dict, given: Any) -> memoryview:
            for end, byte in enumerate(data):
                if byte == 0:
                    values[name] = bytes(data[:end])
                    return data[end + 1 :]
            raise IndexError('cstr: no terminating NUL')

        return cstr
    if kind == 'pad':
        size = field[1]

        def pad(data: memoryview, values: dict, given: Any) -> memoryview:
            if len(data) < size:
                raise IndexError('pad past the end of the message')
            return data[size:]

        return pad
    if kind == 'derive':
        (name, function) = (field[1], field[2])

        def derive(data: memoryview, values: dict, given: Any) -> memoryview:
            values[name] = function(values)
            return data

        return derive
    if kind == 'bytes':
        (name, length) = (field[1], field[2])

        def counted(data: memoryview, values: dict, given: Any) -> memoryview:
            size = length if isinstance(length, int) else values[length]
            values[name] = bytes(data[:size])
            return data[size:]

        return counted
    if kind in _PRIMITIVES:
        (name, read) = (field[1], getattr(codec, 'read_' + kind))

        def primitive(data: memoryview, values: dict, given: Any) -> memoryview:
            (value, data) = read(data)
            values[name] = _leaf(value)
            return data

        return primitive
    if kind in ('when', 'only'):
        if kind == 'only' and field[1] != codec.name:
            return lambda data, values, given: data
        inner = _decode_fields(field[2], codec)
        test = field[1] if kind == 'when' else None

        def nested(data: memoryview, values: dict, given: Any) -> memoryview:
            if test is not None and not values[test]:
                return data
            # The fields read into a copy of what was read so far, which they
            # see as what their own ``each`` items are given.
            more = dict(values)
            data = inner(data, more, values)
            values.update(more)
            return data

        return nested
    if kind == 'each':
        (name, count, inner) = (field[1], field[2], _decode_fields(field[3], codec))

        def each(data: memoryview, values: dict, given: Any) -> memoryview:
            items = []
            for _ in range(values[count]):
                # Every item takes at least a byte, so a count past the
                # message's end fails here, not after billions of empty
                # items (#2272).
                if not data:
                    raise IndexError(f'{name}: count past the end of the message')
                # Each item sees what the caller gave (a session flag a
                # `when` in it tests), not the other fields read so far.
                item = dict(given or {})
                data = inner(data, item, given)
                items.append(item)
            values[name] = items
            return data

        return each
    raise ValueError(f'unknown field kind {kind!r}')


def _decode_fields(schema: Schema, codec: Codec) -> _Step:
    steps = [_decode_part(field, codec) for field in schema]

    def fields(data: memoryview, values: dict, given: Any) -> memoryview:
        for step in steps:
            data = step(data, values, given)
        return data

    return fields


def compile_decoder(schema: Schema, codec: Codec) -> Decoder:
    """The decoder of ``schema`` in ``codec``'s dialect: the fields' values
    and the bytes that follow the message. A ``when`` that tests what isn't on
    the wire -- the session's field version, say -- reads it from ``given``,
    which the result includes.

    Each field is compiled to its reader once, here. The readers walk a view of
    the message, so a field's rest is not a copy of everything after it, and a
    decode takes time in proportion to the message rather than to its square
    (GHSA-jhv3-6267-8qhw); each value is bytes of its own."""
    walk = _decode_fields(schema, codec)

    def decode(
        data: bytes, given: dict[str, Any] | None = None
    ) -> tuple[dict[str, Any], bytes]:
        values: dict[str, Any] = dict(given or {})
        rest = walk(memoryview(data), values, given)
        return values, bytes(rest)

    return decode
