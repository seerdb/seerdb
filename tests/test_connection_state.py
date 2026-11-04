# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Connection state read from the replies, and the SQL name helpers (#2456)."""

from __future__ import annotations

import pytest

import seerdb
from seerdb.common import tns
from seerdb.common.exceptions import ProgrammingError
from seerdb.common.tns import (
    decode_packet,
    encode_sb4,
    recording_session_keywords,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_23_1,
    TNS_EOCS_FLAGS_TXN_IN_PROGRESS,
    TTI_STA,
)


def _oer(call_status: int, code: int, message: bytes) -> bytes:
    # An OER as a 23.1 session gets it: the codec writes at its default field
    # version unless told otherwise.
    token = tns._ENCODE_FIELD_VERSION.set(FIELD_VERSION_23_1)
    try:
        return tns._encode_oer(call_status, code, 0, message)
    finally:
        tns._ENCODE_FIELD_VERSION.reset(token)


def _recorded(reply: bytes) -> list[int]:
    status: list[int] = []
    with recording_session_keywords({}, status):
        decode_packet(reply, (None, None, []), FIELD_VERSION_23_1, FIELD_VERSION_23_1)
    return status


def test_an_oer_records_its_call_status_and_error() -> None:
    # The TXN_IN_PROGRESS bit a DML's reply carries, and its error code.
    reply = _oer(TNS_EOCS_FLAGS_TXN_IN_PROGRESS, 0, b'')
    assert _recorded(reply) == [TNS_EOCS_FLAGS_TXN_IN_PROGRESS, 0]
    killed = _oer(0, 28, b'ORA-00028: your session has been killed')
    assert _recorded(killed) == [0, 28]


def test_a_bare_status_records_its_call_status() -> None:
    # A commit's whole reply is a TTI_STA: the call status, then the sequence.
    reply = bytes([TTI_STA]) + encode_sb4(0) + bytes([1, 1])
    assert _recorded(reply) == [0, 0]


def test_nothing_is_recorded_without_a_connection_recording() -> None:
    reply = _oer(TNS_EOCS_FLAGS_TXN_IN_PROGRESS, 0, b'')
    decode_packet(reply, (None, None, []), FIELD_VERSION_23_1, FIELD_VERSION_23_1)


# What python-oracledb 26.1 returns for the same input, measured.
@pytest.mark.parametrize(
    ('value', 'literal'),
    [
        ('abc', "'abc'"),
        ("O'Brien", "'O''Brien'"),
        ("''", "''''''"),
        ('', "''"),
        ('a"b', "'a\"b'"),
        ('  x  ', "'  x  '"),
    ],
)
def test_enquote_literal(value: str, literal: str) -> None:
    assert seerdb.enquote_literal(value) == literal


@pytest.mark.parametrize(
    ('value', 'capitalized', 'kept'),
    [
        ('abc', '"ABC"', '"abc"'),
        ("O'Brien", '"O\'BRIEN"', '"O\'Brien"'),
        ('', '""', '""'),
        ('mixed Case', '"MIXED CASE"', '"mixed Case"'),
        ('é', '"É"', '"é"'),
    ],
)
def test_enquote_name(value: str, capitalized: str, kept: str) -> None:
    assert seerdb.enquote_name(value) == capitalized
    assert seerdb.enquote_name(value, capitalize=False) == kept


def test_enquote_name_refuses_an_embedded_quote() -> None:
    with pytest.raises(ProgrammingError, match='embedded quotes'):
        seerdb.enquote_name('a"b')


@pytest.mark.parametrize(
    ('value', 'simple'),
    [
        ('abc', True),
        ('A1_$#', True),
        ('1abc', False),
        ('_abc', False),
        ('$a', False),
        ('a-b', False),
        ('a.b', False),
        ('abc def', False),
        (' abc ', True),
        ('\tabc\n', True),
        ('é', True),
        ('a' * 200, True),
        ('"Mixed Case"', True),
        ('"a.b"', True),
        (' "x" ', True),
        ('"a""b"', False),
        ('"x" y', False),
        ('""', False),
        ('', False),
    ],
)
def test_is_simple_sql_name(value: str, simple: bool) -> None:
    assert seerdb.is_simple_sql_name(value) is simple
