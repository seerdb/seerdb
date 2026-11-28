# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Mirror's temporary LOBs for a client below 12.1 (#2847).

Below 12.1, JDBC thin 11.2 (ojdbc6) sends a CREATE_TEMP of its own shape, and
10.2 and 11.2.0.2 answer it in theirs. They also echo a WRITE's amount. The
Mirror wrote the 12.1 forms, and ojdbc6 hung at its first CREATE_TEMP.
Checked against ojdbc6's requests and 10.2's and 11.2.0.2's replies, captured
(#2846).
"""

from __future__ import annotations

import unittest

from seerdb.common import tns
from seerdb.common.tns import (
    _CREATE_TEMP_REPLY_PRE12_FROM_THIN,
    _DECODE_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    _LOBOPS_CREATE_TEMP_FROM_THIN,
    decode_create_temp_reply,
    decode_lobops_oer,
    encode_create_temp_response,
    encode_lobops_write_ack,
    mint_temp_lob_locator,
    parse_lobops_request,
)
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    FIELD_VERSION_10_2,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    TTI_OER,
)
from tests.replay import load_capture


class _AtFieldVersion:
    def __init__(self, field_version: int) -> None:
        self.field_version = field_version

    def __enter__(self) -> None:
        self.tokens = (
            _DECODE_FIELD_VERSION.set(self.field_version),
            _ENCODE_FIELD_VERSION.set(self.field_version),
        )

    def __exit__(self, *exc: object) -> None:
        _DECODE_FIELD_VERSION.reset(self.tokens[0])
        _ENCODE_FIELD_VERSION.reset(self.tokens[1])


class TestTheRequestIsReadWhole(unittest.TestCase):
    def test_ojdbc6s_create_temp_below_12_1(self):
        # Its SCN slot and amount follow the charset. Read as the 12.1 shape,
        # the SCN slot was taken for the amount and the last field left over.
        for capture, is_blob in (
            ('jdbc6_create_temp_clob_10g.hexdump', False),
            ('jdbc6_create_temp_blob_10g.hexdump', True),
        ):
            with self.subTest(capture=capture):
                body = load_capture(capture)
                (fields, rest) = _LOBOPS_CREATE_TEMP_FROM_THIN(body)
                self.assertEqual(rest, b'')
                self.assertEqual(fields['amount'], 10)  # the duration again
                for field_version in (FIELD_VERSION_10_2, FIELD_VERSION_11_2):
                    with _AtFieldVersion(field_version):
                        request = parse_lobops_request(body)
                    self.assertEqual(request.kind, 'create_temp')
                    self.assertEqual(request.is_blob, is_blob)


class TestTheReplyBelow121(unittest.TestCase):
    def test_create_temp_is_answered_in_10gs_form(self):
        # The locator, the charset as an n2 -- the session's for a CLOB, 1 for
        # a BLOB, as 10.2 sends them --, an SCN slot and an amount of 1, then
        # the status.
        for is_blob, real in (
            (False, 'oracle10g_create_temp_clob_reply.hexdump'),
            (True, 'oracle10g_create_temp_blob_reply.hexdump'),
        ):
            with self.subTest(is_blob=is_blob):
                (theirs, _) = _CREATE_TEMP_REPLY_PRE12_FROM_THIN(load_capture(real))
                locator = mint_temp_lob_locator(0, is_blob=is_blob)
                with _AtFieldVersion(FIELD_VERSION_11_2):
                    reply = encode_create_temp_response(locator, is_blob=is_blob)
                (ours, status) = _CREATE_TEMP_REPLY_PRE12_FROM_THIN(reply)
                self.assertEqual(ours['locator'], locator)
                self.assertEqual(ours['charset'], theirs['charset'])
                self.assertEqual(ours['charset'], 1 if is_blob else AL32UTF8_CHARSET)
                self.assertEqual(ours['amount'], theirs['amount'])
                self.assertEqual(status[:1], bytes([TTI_OER]))
                # And seerdb's own client reads it so.
                self.assertEqual(decode_create_temp_reply(reply)[0], locator)
                self.assertEqual(
                    decode_lobops_oer(status, FIELD_VERSION_11_2), (0, None)
                )

    def test_a_write_echoes_its_amount(self):
        # 10.2's reply to a temporary BLOB's 4-byte write: the locator field as
        # sent, the amount (01 04), then the status.
        real = load_capture('oracle10g_temp_blob_write4_reply.hexdump')
        locator_field = real[1:41]
        self.assertEqual(real[41:43], b'\x01\x04')
        with _AtFieldVersion(FIELD_VERSION_10_2):
            reply = encode_lobops_write_ack(locator_field, 4)
        self.assertEqual(reply[:43], real[:43])
        self.assertEqual(reply[43:44], bytes([TTI_OER]))


class TestFrom121Unchanged(unittest.TestCase):
    def test_the_12_1_forms_stand(self):
        locator = mint_temp_lob_locator(0, is_blob=False)
        with _AtFieldVersion(FIELD_VERSION_12_1):
            self.assertEqual(
                encode_create_temp_response(locator, is_blob=True),
                encode_create_temp_response(locator),
            )
            self.assertEqual(
                encode_lobops_write_ack(locator, 3),
                tns.encode_lobops_echo(locator),
            )


if __name__ == '__main__':
    unittest.main()
