# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A LOB write past one LOB_DATA chunk below 12.1 (#2844): the data goes in
252-byte chunks behind one-byte lengths, not the 12.1 form's 32 KiB ones
behind ub4 lengths, which 10.2 and 11.2 misread. Checked against JDBC thin
11.2 (ojdbc6) writing 300 characters into a CLOB on 10.2.0.5 and 600 bytes
into a BLOB on 11.2.0.2, captured through tools/capture_proxy.py."""

import os
import sys
import unittest

from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    encode_dictionary_lobops,
    parse_lobops_request,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    TNS_LOB_OP_WRITE,
)

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402

# The head ends with the six array slots, then the locator (its length at
# byte 5), then the amount and the LOB_DATA.
_LOCATOR_AT = 27
_TEXT = ''.join(chr(65 + k % 26) for k in range(300)).encode('utf-16-be')
_DATA = bytes(k % 251 for k in range(600))
_CAPTURES = (
    ('jdbc6_lob_write_clob300_10g.hexdump', _TEXT, 300, FIELD_VERSION_10_2),
    ('jdbc6_lob_write_blob600_11g.hexdump', _DATA, 600, FIELD_VERSION_11_2),
)


def _write(theirs: bytes, data: bytes, amount: int, field_version: int) -> bytes:
    # seerdb's WRITE of the same value on the capture's locator.
    return encode_dictionary_lobops(
        {
            'seq': theirs[2],
            'field_version': field_version,
            'locator': theirs[_LOCATOR_AT : _LOCATOR_AT + theirs[5]],
            'operation': TNS_LOB_OP_WRITE,
            'source_offset': 1,
            'locator_prefixed': False,
            'data': data,
            'amount': amount,
        }
    )


class TestTheChunksBelow121(unittest.TestCase):
    def test_a_write_past_one_chunk_is_jdbc_thins(self):
        for capture, data, amount, fv in _CAPTURES:
            with self.subTest(capture=capture):
                theirs = load_capture(capture)
                self.assertEqual(_write(theirs, data, amount, fv), theirs)

    def test_the_mirror_reads_jdbc_thins_chunks(self):
        for capture, data, _amount, fv in _CAPTURES:
            with self.subTest(capture=capture):
                token = _DECODE_FIELD_VERSION.set(fv)
                try:
                    got = parse_lobops_request(load_capture(capture))
                finally:
                    _DECODE_FIELD_VERSION.reset(token)
                self.assertEqual((got.kind, got.payload), ('write', data))

    def test_12c_keeps_its_32k_chunks(self):
        # python-oracledb's form from 12.1: chunks behind ub4 lengths, here
        # one of 600 bytes (`02 02 58`), then the empty one (`00`).
        theirs = load_capture('jdbc6_lob_write_blob600_11g.hexdump')
        ours = _write(theirs, _DATA, 600, FIELD_VERSION_12_1)
        self.assertTrue(ours.endswith(b'\x0e\xfe\x02\x02\x58' + _DATA + b'\x00'))


if __name__ == '__main__':
    unittest.main()
