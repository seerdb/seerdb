# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The codec primitives report a truncated field instead of mis-reading it (#849).

Python slicing past the end of a buffer returns fewer bytes rather than failing,
so before this a short read produced a WRONG VALUE with no error at all: a ub4
that claimed four bytes and had two decoded as 258. A message that spans TNS
packets arrives in pieces, and a reader can only ask for the next piece if the
decoders say the current one ran out -- the foundation for #848.

Both directions matter equally here: truncated input must raise, and complete
input must decode exactly as it always did. The second half is what protects the
client, which shares these primitives.
"""

import pytest

from seerdb.common.exceptions import DataError, Truncated
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    _decode_lobops_chunked,
    decode_chr,
    decode_dalc,
    decode_ub4,
    encode_sb4,
)
from seerdb.common.tns_consts import FIELD_VERSION_12_1


@pytest.mark.parametrize(
    'label, fn',
    [
        ('ub4, empty', lambda: decode_ub4(b'')),
        ('ub4, claims 4 bytes, has 2', lambda: decode_ub4(bytes([4, 1, 2]))),
        ('ub4, two-byte lenient form cut short', lambda: decode_ub4(bytes([0x19]))),
        ('DALC, claims 10 bytes, has 3', lambda: decode_dalc(bytes([10]) + b'abc')),
        ('CHR, claims 5 bytes, has 2', lambda: decode_chr(bytes([5]) + b'ab')),
        (
            'LOB write, single form short',
            lambda: _decode_lobops_chunked(bytes([9]) + b'abc'),
        ),
        (
            'LOB write, chunk of 100 with 20 present',
            lambda: _decode_lobops_chunked(bytes([0xFE, 1, 100]) + b'A' * 20),
        ),
        (
            # The exact #848 shape: whole chunks, but the terminator never came
            # because it was in a later TNS packet.
            'LOB write, complete chunks but no terminator yet',
            lambda: _decode_lobops_chunked(bytes([0xFE]) + encode_sb4(3) + b'AAA'),
        ),
    ],
)
def test_truncated_fields_raise(label, fn) -> None:
    with pytest.raises(Truncated):
        fn()


def test_chunked_chr_short_at_12_2() -> None:
    # The 12.2+ framing (ub4 length per chunk) takes a separate path from 11g's.
    token = _DECODE_FIELD_VERSION.set(24)
    try:
        with pytest.raises(Truncated):
            decode_chr(bytes([0xFE]) + encode_sb4(50) + b'x' * 10)
    finally:
        _DECODE_FIELD_VERSION.reset(token)


def test_complete_fields_decode_exactly_as_before() -> None:
    assert decode_ub4(bytes([2, 1, 2])) == (258, b'')
    assert decode_ub4(bytes([0])) == (0, b'')
    assert decode_ub4(bytes([0x81, 0x01])) == (-1, b'')
    assert decode_dalc(bytes([3]) + b'abc' + b'rest') == (b'abc', b'rest')
    assert decode_dalc(bytes([0xFF])) == ([], b'')
    assert decode_dalc(bytes([0])) == ([], b'')
    assert decode_chr(bytes([2]) + b'hi') == (b'hi', b'')
    # A chunk's length is a ub4 from 12.1 and a byte below (#2844).
    token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_12_1)
    try:
        payload = bytes([0xFE]) + encode_sb4(3) + b'AAA' + encode_sb4(2) + b'BB'
        assert _decode_lobops_chunked(payload + encode_sb4(0)) == b'AAABB'
    finally:
        _DECODE_FIELD_VERSION.reset(token)
    narrow = bytes([0xFE, 3]) + b'AAA' + bytes([2]) + b'BB' + bytes([0])
    assert _decode_lobops_chunked(narrow) == b'AAABB'
    assert _decode_lobops_chunked(bytes([3]) + b'xyz') == b'xyz'


def test_the_lenient_ub4_branch_is_untouched() -> None:
    # decode_ub4 reads widths 5..0x7f leniently on purpose: a strict version once
    # broke `SELECT level FROM dual CONNECT BY level <= 50` (#24). Only a length
    # check was added, never a new opinion about the content.
    assert decode_ub4(bytes([0x19, 7, 9])) == (-7, b'\t')
    assert decode_ub4(bytes([0x19, 7])) == (-7, b'')


def test_truncated_is_a_data_error_but_not_an_index_error() -> None:
    # A DataError, so callers that already treat a truncated field as bad data
    # keep doing so. NOT an IndexError: decode_dalc catches that one, and would
    # otherwise swallow the signal and report something else.
    assert issubclass(Truncated, DataError)
    assert not issubclass(Truncated, IndexError)
