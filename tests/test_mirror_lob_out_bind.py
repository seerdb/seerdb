# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A LOB OUT bind from the Mirror to a client below 12.1 (#2859).

Below 12.1, 11.2.0.2 answers a PL/SQL block's CLOB or BLOB OUT bind with the
bare LOB block, the locator's length and the locator. The Mirror sent the
block with the size and chunk size too, and JDBC thin 11.2 (ojdbc6) read them
as the locator: "Protocol violation: [11, 7, 1]". Checked against 11.2.0.2's
reply to ojdbc6 11.2.0.3, captured.
"""

from __future__ import annotations

import unittest

from seerdb.common import tns, wire_schema
from seerdb.common.tns import _ENCODE_FIELD_VERSION, encode_lob_bind_block
from seerdb.common.tns_consts import FIELD_VERSION_11_2, FIELD_VERSION_12_1
from tests.replay import load_capture

_CELL = wire_schema.compile_decoder(tns._LOB_CELL, tns._THIN)
# 11.2.0.2's I/O vector for the block's two OUT binds, ahead of the row.
_IOV = bytes.fromhex('0b0501020001010000001010')


def _out_bind(value: object, is_clob: bool, field_version: int) -> bytes:
    token = _ENCODE_FIELD_VERSION.set(field_version)
    try:
        return encode_lob_bind_block(value, is_clob=is_clob, out_bind=True)
    finally:
        _ENCODE_FIELD_VERSION.reset(token)


class TestTheOutBindBelow121(unittest.TestCase):
    def test_11_2_0_2_sends_the_bare_block(self):
        reply = load_capture('oracle11g_lob_out_bind_reply.hexdump')
        self.assertEqual(reply[: len(_IOV)], _IOV)
        rest = reply[len(_IOV) + 1 :]  # behind the row's 07
        for length in (130, 106):  # the CLOB's locator, then the BLOB's
            (cell, rest) = _CELL(rest, {'has_metadata': False})
            self.assertEqual(cell['locator_length'], length)
            self.assertEqual(len(cell['locator']), length)
            # Each OUT value is followed by its actual length, 0 here.
            self.assertEqual(rest[:1], b'\x00')
            rest = rest[1:]

    def test_the_mirror_sends_it_too(self):
        for value, is_clob in (('temporary text', True), (b'\x01\x02', False)):
            with self.subTest(is_clob=is_clob):
                block = _out_bind(value, is_clob, FIELD_VERSION_11_2)
                (cell, rest) = _CELL(block, {'has_metadata': False})
                self.assertEqual(rest, b'')
                self.assertEqual(len(cell['locator']), cell['locator_length'])

    def test_from_12_1_the_block_keeps_its_metadata(self):
        block = _out_bind('text', True, FIELD_VERSION_12_1)
        (cell, rest) = _CELL(block, {'has_metadata': True})
        self.assertEqual(rest, b'')
        self.assertEqual(cell['size'], 4)

    def test_a_returning_bind_keeps_its_block(self):
        # No capture says what 11.2.0.2 sends a RETURNING LOB; it is left alone.
        token = _ENCODE_FIELD_VERSION.set(FIELD_VERSION_11_2)
        try:
            block = encode_lob_bind_block('text', is_clob=True)
        finally:
            _ENCODE_FIELD_VERSION.reset(token)
        (cell, rest) = _CELL(block, {'has_metadata': True})
        self.assertEqual(rest, b'')
        self.assertEqual(cell['size'], 4)


if __name__ == '__main__':
    unittest.main()
