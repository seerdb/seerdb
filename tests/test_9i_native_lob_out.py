# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A LOB OUT bind on 9i's native form (#2839): the cell is the locator's
length, the locator and a ub2 indicator, with no return code, and the block's
status is the one after its RPA. Read from 9.2.0.4's replies."""

import os
import sys
import unittest

from seerdb.common.tns import _o9i_oall8_oer, decode_9i_oall8_block_out

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402


def _capture(name: str) -> bytes:
    return bytes(load_capture(name))


class TestTheLobOutCell(unittest.TestCase):
    def test_the_value_after_it_reads_whole(self):
        # BEGIN SELECT c INTO :c FROM t; :n := 7; END; -- read with a return
        # code, the CLOB's cell took the NUMBER's first two bytes.
        reply = _capture('native_9i_clob_then_number_out_reply.hexdump')
        (values, rows, code, _) = decode_9i_oall8_block_out(
            reply, 2, 2, Lobs=frozenset({0})
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(values[0]), 86)  # the locator
        self.assertEqual(values[1], b'\xc1\x08')  # 7

    def test_a_returning_reads_its_own_status(self):
        # The wrap's three binds, two OUT: the CLOB and the row count. Its RPA's
        # SCN holds `04 03 00 00 00 00`, which read as ORA-00001.
        reply = _capture('native_9i_returning_clob_reply.hexdump')
        (values, rows, code, _) = decode_9i_oall8_block_out(
            reply, 3, 2, Lobs=frozenset({0})
        )
        self.assertEqual((rows, code), (1, 0))
        self.assertEqual(values[1], b'\xc1\x02')


class TestTheStatusFinder(unittest.TestCase):
    def test_it_takes_the_oer_after_the_rpa_not_a_04_inside_it(self):
        # The whole reply, its bind prompt and OUT values first: a bare scan
        # stopped at the SCN's 04.
        reply = _capture('native_9i_returning_clob_reply.hexdump')
        oer = _o9i_oall8_oer(reply)
        self.assertEqual(oer[:5], b'\x04\x02\x00\x00\x00')


if __name__ == '__main__':
    unittest.main()
