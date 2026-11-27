# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Writing a persistent LOB below 12.1 (#2803): the LOBOPS WRITE carries its
amount, which 10.2 closes the connection without, and the reply echoes it.
Checked against JDBC thin 11.2 (ojdbc6) writing a CLOB and a BLOB on
10.2.0.5, and 10.2.0.5's replies to seerdb's own, captured through
tools/capture_proxy.py."""

import os
import sys
import unittest

from seerdb.common.tns import decode_lobops_oer, encode_dictionary_lobops
from seerdb.common.tns_consts import (
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    TNS_LOB_OP_WRITE,
)

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_capture  # noqa: E402

# Where the captured WRITE puts its fields: the head ends with the six array
# slots, then the locator (its length at byte 5), then the amount and the data.
_LOCATOR_AT = 27
_AMOUNT_FLAG_AT = 20


def _write(capture: str, data: bytes, field_version: int) -> tuple[bytes, bytes]:
    # The capture, and seerdb's WRITE of the same value on the same locator.
    theirs = load_capture(capture)
    locator = theirs[_LOCATOR_AT : _LOCATOR_AT + theirs[5]]
    ours = encode_dictionary_lobops(
        {
            'seq': theirs[2],
            'field_version': field_version,
            'locator': locator,
            'operation': TNS_LOB_OP_WRITE,
            'source_offset': 3,
            'locator_prefixed': False,
            'data': data,
            'amount': 3,
        }
    )
    return (theirs, ours)


class TestTheWriteBelow121(unittest.TestCase):
    def test_a_clob_write_is_jdbc_thins(self):
        (theirs, ours) = _write(
            'jdbc6_lob_write_clob_10g.hexdump',
            'XYZ'.encode('utf-16-be'),
            FIELD_VERSION_10_2,
        )
        self.assertEqual(ours, theirs)

    def test_a_blob_write_is_jdbc_thins(self):
        (theirs, ours) = _write(
            'jdbc6_lob_write_blob_10g.hexdump', b'\xaa\xbb\xcc', FIELD_VERSION_10_2
        )
        self.assertEqual(ours, theirs)

    def test_11g_gets_the_same_write(self):
        # JDBC thin 11.2 sends 11.2 the same bytes as 10.2.
        (theirs, ours) = _write(
            'jdbc6_lob_write_clob_10g.hexdump',
            'XYZ'.encode('utf-16-be'),
            FIELD_VERSION_11_2,
        )
        self.assertEqual(ours, theirs)

    def test_12c_keeps_its_write_without_the_amount(self):
        # python-oracledb's form from 12.1 (#91): the amount's pointer clear and
        # no amount behind the locator; the rest as below 12.1.
        (theirs, ours) = _write(
            'jdbc6_lob_write_clob_10g.hexdump',
            'XYZ'.encode('utf-16-be'),
            FIELD_VERSION_12_1,
        )
        end = _LOCATOR_AT + theirs[5]
        without = (
            theirs[:_AMOUNT_FLAG_AT]
            + b'\x00'
            + theirs[_AMOUNT_FLAG_AT + 1 : end]
            + theirs[end + 2 :]
        )
        self.assertEqual(theirs[_AMOUNT_FLAG_AT], 1)
        self.assertEqual(ours, without)


class TestTheWritesReplyBelow121(unittest.TestCase):
    # The reply echoes the amount after the locator. A WRITE of 4 units answers
    # `01 04` there, then the status's own `04`; the status is found past the
    # amount, not at its 04.
    def test_a_four_byte_writes_status_is_read_past_its_amount(self):
        reply = load_capture('oracle10g_temp_blob_write4_reply.hexdump')
        self.assertEqual(
            decode_lobops_oer(reply, FIELD_VERSION_10_2, Amount=True), (0, None)
        )

    def test_a_four_character_writes_status_is_read_past_its_amount(self):
        reply = load_capture('oracle10g_lob_write4_reply.hexdump')
        self.assertEqual(
            decode_lobops_oer(reply, FIELD_VERSION_10_2, Amount=True), (0, None)
        )


if __name__ == '__main__':
    unittest.main()
