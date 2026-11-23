# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Every TTI_LOBOPS request the client writes, read back by the Mirror's
parser (#2773): one request shape, _LOBOPS_REQUEST, both ways."""

import itertools
import unittest

from seerdb.common.exceptions import Truncated
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    encode_dictionary_lobops,
    parse_lobops_request,
    prefixed_locator,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_23_4,
    TNS_LOB_OP_CLOSE,
    TNS_LOB_OP_FILE_CLOSE,
    TNS_LOB_OP_FILE_EXISTS,
    TNS_LOB_OP_FILE_OPEN,
    TNS_LOB_OP_FREE_TEMP,
    TNS_LOB_OP_GET_CHUNK_SIZE,
    TNS_LOB_OP_GET_LENGTH,
    TNS_LOB_OP_IS_OPEN,
    TNS_LOB_OP_OPEN,
    TNS_LOB_OP_READ,
    TNS_LOB_OP_TRIM,
    TNS_LOB_OP_WRITE,
)

VERSIONS = (FIELD_VERSION_11_2, FIELD_VERSION_12_1, FIELD_VERSION_23_4)
# A real server's temp locator is 38 bytes, a column one longer.
TEMP = bytes(range(38))
COLUMN = bytes(range(100, 186))


class TestTheRequestsReadBack(unittest.TestCase):
    def tearDown(self):
        _ENCODE_FIELD_VERSION.set(6)

    def _parse(self, fv, request):
        data = encode_dictionary_lobops({'seq': 4, 'field_version': fv, **request})
        token = _DECODE_FIELD_VERSION.set(fv)
        try:
            return parse_lobops_request(data)
        finally:
            _DECODE_FIELD_VERSION.reset(token)

    def test_a_temporary_lob_of_each_type(self):
        for fv, (is_blob, csfrm) in itertools.product(
            VERSIONS, ((False, 1), (False, 2), (True, 1))
        ):
            with self.subTest(fv=fv, is_blob=is_blob, csfrm=csfrm):
                got = self._parse(
                    fv, {'create_temp': True, 'is_blob': is_blob, 'csfrm': csfrm}
                )
                self.assertEqual((got.kind, got.is_blob), ('create_temp', is_blob))

    def test_a_write_short_and_chunked(self):
        # A temp LOB's locator goes with its ub2 length, a column LOB's raw, and
        # the reply echoes the field as sent.
        for fv, data, prefixed in itertools.product(
            VERSIONS, (b'', b'abc', bytes(range(256)) * 300), (True, False)
        ):
            locator = TEMP if prefixed else COLUMN
            with self.subTest(fv=fv, size=len(data), prefixed=prefixed):
                got = self._parse(
                    fv,
                    {
                        'operation': TNS_LOB_OP_WRITE,
                        'locator': locator,
                        'data': data,
                        'source_offset': 7,
                        'locator_prefixed': prefixed,
                    },
                )
                field = prefixed_locator(locator) if prefixed else locator
                self.assertEqual(
                    (got.kind, got.locator, got.payload, got.offset),
                    ('write', field, data, 7),
                )

    def test_a_read(self):
        for fv, prefixed in itertools.product(VERSIONS, (True, False)):
            locator = TEMP if prefixed else COLUMN
            with self.subTest(fv=fv, prefixed=prefixed):
                got = self._parse(
                    fv,
                    {
                        'operation': TNS_LOB_OP_READ,
                        'locator': locator,
                        'locator_prefixed': prefixed,
                        'source_offset': 9000,
                        'amount': 300,
                    },
                )
                field = prefixed_locator(locator) if prefixed else locator
                self.assertEqual(
                    (got.kind, got.locator, got.offset, got.amount),
                    ('read', field, 9000, 300),
                )

    def test_an_offset_and_amount_past_4_gib(self):
        # Both are ub8s; written as ub4s they raised struct.error (#2788).
        got = self._parse(
            FIELD_VERSION_23_4,
            {
                'operation': TNS_LOB_OP_READ,
                'locator': COLUMN,
                'source_offset': 2**32 + 5,
                'amount': 2**40,
            },
        )
        self.assertEqual((got.offset, got.amount), (2**32 + 5, 2**40))

    def test_the_state_calls(self):
        # They key on the field as sent, and OPEN and TRIM carry the amount.
        kinds = {
            TNS_LOB_OP_GET_LENGTH: ('get_length', 0),
            TNS_LOB_OP_IS_OPEN: ('is_open', 0),
            TNS_LOB_OP_OPEN: ('open', 2),
            TNS_LOB_OP_CLOSE: ('close', 0),
            TNS_LOB_OP_TRIM: ('trim', 2),
            TNS_LOB_OP_GET_CHUNK_SIZE: ('get_chunk_size', 0),  # #2790
        }
        for fv, (op, (kind, amount)) in itertools.product(VERSIONS, kinds.items()):
            with self.subTest(fv=fv, kind=kind):
                got = self._parse(fv, {'operation': op, 'locator': COLUMN, 'amount': 2})
                self.assertEqual((got.kind, got.locator), (kind, COLUMN))
                if kind in ('open', 'trim'):
                    self.assertEqual(got.amount, amount)

    def test_the_calls_on_a_prefixed_locator(self):
        # FREE_TEMP and the BFILE calls name the locator inside its ub2 length.
        kinds = {
            TNS_LOB_OP_FREE_TEMP: 'free_temp',
            TNS_LOB_OP_FILE_OPEN: 'file_open',
            TNS_LOB_OP_FILE_CLOSE: 'file_close',
            TNS_LOB_OP_FILE_EXISTS: 'file_exists',
        }
        for fv, (op, kind) in itertools.product(VERSIONS, kinds.items()):
            with self.subTest(fv=fv, kind=kind):
                got = self._parse(
                    fv, {'operation': op, 'locator': TEMP, 'locator_prefixed': True}
                )
                self.assertEqual((got.kind, got.locator), (kind, TEMP))
                if op == TNS_LOB_OP_FILE_OPEN:
                    self.assertEqual(got.amount, 0x0B)  # read-only

    def test_a_write_cut_inside_its_locator_says_truncated(self):
        # So the Mirror reads the rest of the message on (#849).
        data = encode_dictionary_lobops(
            {
                'seq': 4,
                'field_version': FIELD_VERSION_23_4,
                'operation': TNS_LOB_OP_WRITE,
                'locator': TEMP,
                'data': b'abc',
            }
        )
        token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_23_4)
        try:
            with self.assertRaises(Truncated):
                parse_lobops_request(data[:30])
        finally:
            _DECODE_FIELD_VERSION.reset(token)

    def test_a_read_that_does_not_fit_reads_the_lob_whole(self):
        data = encode_dictionary_lobops(
            {
                'seq': 4,
                'field_version': FIELD_VERSION_12_1,
                'operation': TNS_LOB_OP_READ,
                'locator': COLUMN,
            }
        )
        token = _DECODE_FIELD_VERSION.set(FIELD_VERSION_12_1)
        try:
            got = parse_lobops_request(data[:-20])
        finally:
            _DECODE_FIELD_VERSION.reset(token)
        # No locator and no amount: the read path's "the whole LOB" (#903).
        self.assertEqual((got.kind, got.locator, got.amount), ('read', b'', 0))


if __name__ == '__main__':
    unittest.main()
