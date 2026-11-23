# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# What a TTI_LOBOPS reply leads with: RPA, then the updated locator after a
# big-endian ub2 of its length (PROTOCOL.md §14.4, §14.6). One schema in
# common reads it for every caller: the LOB calls, CREATE_TEMP and FILE_OPEN
# in both dialects.

import unittest

from seerdb.common.exceptions import DataError
from seerdb.common.tns import (
    decode_lobops_locator,
    decode_lobops_oer,
    decode_lobops_value,
    decode_o7_create_temp,
)
from seerdb.common.tns_consts import FIELD_VERSION_21_1

_LOCATOR = bytes(range(1, 39))
# The locator holds an 0x04 (TTI_OER) byte, which a scan must not stop at.
_TRICKY = bytes([0x04, 0x01, 0x00, 0x04])


def _reply(Locator: bytes, After: bytes = b'') -> bytes:
    return bytes([0x08]) + len(Locator).to_bytes(2, 'big') + Locator + After


class LobReplyHeadTest(unittest.TestCase):
    def test_the_locator_comes_back_as_sent(self):
        self.assertEqual(decode_lobops_locator(_reply(_LOCATOR, b'\x04')), _LOCATOR)

    def test_a_reply_without_the_rpa_has_no_locator(self):
        self.assertIsNone(decode_lobops_locator(b'\x04\x01\x00'))
        self.assertIsNone(decode_lobops_locator(b''))
        self.assertIsNone(decode_lobops_locator(b'\x08\x00'))

    def test_a_reply_that_ends_inside_its_locator_has_none(self):
        self.assertIsNone(decode_lobops_locator(_reply(_LOCATOR)[:-1]))

    def test_an_empty_locator_is_none(self):
        self.assertIsNone(decode_lobops_locator(_reply(b'')))

    def test_the_value_follows_the_locator(self):
        # GET_LENGTH: ub4 11 between the locator and the OER (§14.6).
        self.assertEqual(decode_lobops_value(_reply(_TRICKY, b'\x01\x0b\x04')), 11)

    def test_no_value_when_the_oer_follows_the_locator(self):
        self.assertIsNone(decode_lobops_value(_reply(_TRICKY, b'\x04\x01')))
        self.assertIsNone(decode_lobops_value(_reply(_TRICKY)))

    def test_the_oer_scan_starts_past_the_locator(self):
        # A locator whose bytes look like an OER is skipped by its length; a
        # reply with nothing after it reports no error.
        self.assertEqual(
            decode_lobops_oer(_reply(_TRICKY), FIELD_VERSION_21_1), (0, None)
        )

    def test_a_9i_create_temp_reply_is_its_bare_locator(self):
        self.assertEqual(decode_o7_create_temp(_reply(_LOCATOR, b'\x04')), _LOCATOR)

    def test_a_9i_create_temp_reply_cut_short_is_refused(self):
        with self.assertRaises(DataError):
            decode_o7_create_temp(_reply(_LOCATOR)[:-1])
        with self.assertRaises(DataError):
            decode_o7_create_temp(b'\x04')


if __name__ == '__main__':
    unittest.main()
