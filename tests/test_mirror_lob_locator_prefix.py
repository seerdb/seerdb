# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Mirror's LOB locators open with their own length, as a server's do (#2791).

A server's locator opens with a big-endian ub2 of its length less those two
bytes, and each LOB call's reply echoes the locator whole after TTI_RPA. seerdb's
client reads the echo back by that ub2. The Mirror's locators opened with
``00 73`` (``\\x00s``), so the client read 115 bytes for a 38-byte locator, ran
past the value behind it, and size() and getchunksize() of a fetched LOB were 0.
"""

from __future__ import annotations

from seerdb.common.tns import (
    _COLUMN_LOB_LOC_FLAGS,
    _THIN_LOB_LOCATOR,
    _THIN_OBJ_LOB_LOCATOR,
    LobEmitLog,
    decode_lobops_locator,
    decode_lobops_value,
    encode_lobops_length,
    is_prefixed_locator,
    mint_column_lob_locator,
    prefixed_locator,
)


def test_every_minted_locator_opens_with_its_length() -> None:
    for kind, flags in _COLUMN_LOB_LOC_FLAGS.items():
        locator = mint_column_lob_locator(7, kind)
        assert len(locator) == 38
        assert locator[:2] == bytes.fromhex('0024')
        assert is_prefixed_locator(locator)
        assert locator[4:8] == flags
    for fixed in (_THIN_LOB_LOCATOR, _THIN_OBJ_LOB_LOCATOR):
        assert is_prefixed_locator(fixed)


def test_the_client_reads_a_length_reply_past_the_echo() -> None:
    # GET_LENGTH and GET_CHUNK_SIZE answer `08 | locator | ub4 value | OER`; the
    # value reads back, and the echoed locator is the minted one less its ub2,
    # as a real server's reply carries it (prefixed_locator puts it back).
    locator = mint_column_lob_locator(3, 'blob')
    reply = encode_lobops_length(locator, 5) + bytes.fromhex('04')
    assert decode_lobops_value(reply) == 5
    echoed = decode_lobops_locator(reply)
    assert echoed == locator[2:]
    assert prefixed_locator(echoed) == locator


def test_the_log_takes_each_spelling_of_a_locator() -> None:
    log = LobEmitLog()
    locator = log.record(b'\x01\x02', False)
    for spelling in (locator, locator[2:], prefixed_locator(locator)):
        assert log.content(spelling) == (b'\x01\x02', False)
        assert log.key(spelling) == locator
    assert log.content(b'\x00\x05other') is None
