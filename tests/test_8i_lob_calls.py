# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A LOB object's calls on 8i (#2804): 8.1.7 serves them as OCI 9.2 makes
them, the 9i compact form's TTI_LOBOPS at the 8i codec's widths. Checked
against OCI 9.2's own calls and 8.1.7's replies, captured on the 9i VM."""

import os
import sys
import unittest

from seerdb.common.tns import (
    decode_fv2_lob_value,
    encode_8i_lob_read,
    encode_o7_lobop,
)
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    ISO_LATIN_1_CHARSET,
    TNS_LOB_OP_IS_OPEN,
    TNS_LOB_OP_WRITE,
)

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402


def _capture(name: str) -> bytes:
    return bytes(load_capture(name))


def _locator(request: bytes) -> bytes:
    # The CLOB's locator as a call carries it: its ub2 length (84) and body.
    at = request.index(b'\x00\x54\x00\x01')
    return request[at : at + 86]


class TestTheCallsAreOci92s(unittest.TestCase):
    def test_a_write(self):
        theirs = _capture('oci92_lob_write_8i.hexdump')
        ours = encode_o7_lobop(
            theirs[2],
            _locator(theirs),
            TNS_LOB_OP_WRITE,
            Offset=1,
            Amount=9,
            Data=b'hello lob',
            O8i=True,
        )
        self.assertEqual(ours, theirs)

    def test_a_read_from_an_offset(self):
        theirs = _capture('oci92_lob_read_8i.hexdump')
        self.assertEqual(encode_8i_lob_read(theirs[2], _locator(theirs), 64, 1), theirs)

    def test_is_open(self):
        theirs = _capture('oci92_lob_is_open_8i.hexdump')
        ours = encode_o7_lobop(
            theirs[2], _locator(theirs), TNS_LOB_OP_IS_OPEN, O8i=True
        )
        self.assertEqual(ours, theirs)


class TestTheRepliesReadBack(unittest.TestCase):
    def test_a_write_says_its_amount_and_the_updated_locator(self):
        reply = _capture('oci92_lob_write_reply_8i.hexdump')
        (amount, locator) = decode_fv2_lob_value(reply, TNS_LOB_OP_WRITE, True)
        self.assertEqual((amount, len(locator)), (9, 84))

    def test_is_open_is_one_byte(self):
        # 8.1.7 answers IS_OPEN in a byte, as 9.2 answers a 9.2 client: read as
        # a ub4, it took the status's first bytes along (66560).
        reply = _capture('oci92_lob_is_open_reply_8i.hexdump')
        (flag, locator) = decode_fv2_lob_value(reply, TNS_LOB_OP_IS_OPEN, True)
        self.assertEqual((flag, len(locator)), (0, 84))


class TestTheText(unittest.TestCase):
    def test_an_8i_write_is_the_single_byte_charset(self):
        # An 8i session speaks the database's single-byte charset: sent as
        # UTF-8, 'é' was two bytes against an amount of one, and 8.1.7 ended the
        # session at the next call.
        from seerdb.common.types import fv2_lob_payload

        self.assertEqual(
            fv2_lob_payload('éa', False, ISO_LATIN_1_CHARSET), (b'\xe9a', 2)
        )
        self.assertEqual(
            fv2_lob_payload('éa', False, AL32UTF8_CHARSET), ('éa'.encode(), 2)
        )

    def test_the_8i_dialect_serves_lob_objects_in_its_charset(self):
        from seerdb.client.dialect import CAP_LOB_OBJECT, O8iDialect, lob_object_charset

        dialect = O8iDialect(lambda: 1)
        self.assertIn(CAP_LOB_OBJECT, dialect.capabilities())
        self.assertEqual(lob_object_charset(dialect, None), ISO_LATIN_1_CHARSET)


if __name__ == '__main__':
    unittest.main()
