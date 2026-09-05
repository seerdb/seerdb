# SPDX-FileCopyrightText: 2025 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""The 9i DML status reply, captured live (#711).

The reply is an RPA piggyback of two parameters, then the short OER. The first
parameter is a counter that grows with the instance; once it passes 2**24 its
length byte is 0x04, the OER token, and a decoder that stopped the parameter
loop at a token-looking byte read the counter as the status: every successful
CREATE, INSERT and DROP on 9i raised a garbled negative ORA code.
"""

import unittest

from seerdb.common.tns import decode_fv2_dml_response

# Captured from 9.2.0.4: the counter 0x0129c868 is the first RPA parameter.
_CREATE = bytes.fromhex(
    '080102040129c868000400000000010100010000000000000000000000000000010100000000'
)
_INSERT = bytes.fromhex(
    '080102040129c79d000401010000000101010c020000000000028dca01010002baba00000000000101010d0d0100008dca00010000baba00000000'
)
_DROP = bytes.fromhex(
    '080102040129c8750004000000000101010b0c0000000000000000000000000000010100000000'
)
# The same shape while the counter still fitted three bytes.
_CREATE_YOUNG = bytes.fromhex(
    '08010203029c6800040000000001010001000000000000000000000000000001010000'
)


class TestNineiStatusWithAWideCounter(unittest.TestCase):
    def test_a_successful_create(self):
        self.assertEqual(decode_fv2_dml_response(_CREATE), (0, 0))

    def test_a_successful_insert_reports_its_row(self):
        self.assertEqual(decode_fv2_dml_response(_INSERT), (1, 0))

    def test_a_successful_drop(self):
        self.assertEqual(decode_fv2_dml_response(_DROP), (0, 0))

    def test_a_young_instance_still_decodes(self):
        self.assertEqual(decode_fv2_dml_response(_CREATE_YOUNG), (0, 0))
