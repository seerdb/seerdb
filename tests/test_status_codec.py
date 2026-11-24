# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The status token's batch-error arrays and a describe column's annotation
map, written as a server writes them (#2773, #2793): each checked against
bytes captured from 11g and 23ai, and read back."""

import unittest

from seerdb.common.tns import (
    _DCB_ANNOTATIONS,
    _DECODE_FIELD_VERSION,
    _DECODE_SERVER_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    _ENCODE_SERVER_FIELD_VERSION,
    _THIN,
    _annotation_values,
    _encode_oer,
    decode_token_oer,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    FIELD_VERSION_23_4,
)
from seerdb.common.wire_schema import compile_encoder

# 23ai's status for an executemany(batcherrors=True) of two rows that both
# failed with ORA-01438, as python-oracledb 26.1 received it.
OER_23AI_TWO_ERRORS = bytes.fromhex(
    '04010302dca400025f3d00000104012002000000000004ffffffff0000000000'
    '0005000101000102fe010302059e010302059e000102fe010100010201010001'
    '02160148484f52412d30313433383a2076616c75652031302067726561746572'
    '207468616e2073706563696669656420707265636973696f6e2028312c203029'
    '20666f7220636f6c756d6e200a00000148484f52412d30313433383a2076616c'
    '75652031312067726561746572207468616e2073706563696669656420707265'
    '636973696f6e2028312c20302920666f7220636f6c756d6e200a0000025f3d00'
    '010200214f52412d32343338313a206572726f7228732920696e206172726179'
    '20444d4c0a'
)
# The arrays of two errors at rows 0 and 1, from the codes' count to the
# messages' indicator, as 23ai and 11g sent them: past one element, 0xFE, each
# element in a chunk of its own, and 00 -- a chunk's length a ub4 from 12.1, a
# ub1 before.
ARRAYS_23AI = bytes.fromhex('0102fe010302059e010302059e000102fe0101000102010100010216')
ARRAYS_11G = bytes.fromhex('0102fe0302059e0302059e000102fe010002010100010216')
# One error: the element as a value of its own, as every server sent it.
ARRAYS_ONE = bytes.fromhex('0101 03 02059e 0101 01 00 0101 16')


def _errors(n):
    return [(row, 1438, f'ORA-01438: value {row}') for row in range(n)]


class _AtFieldVersion:
    def __init__(self, fv, server=None):
        (self.fv, self.server) = (fv, server or fv)

    def __enter__(self):
        self.tokens = (
            _ENCODE_FIELD_VERSION.set(self.fv),
            _DECODE_FIELD_VERSION.set(self.fv),
            _ENCODE_SERVER_FIELD_VERSION.set(self.server),
            _DECODE_SERVER_FIELD_VERSION.set(self.server),
        )

    def __exit__(self, *exc):
        (enc, dec, enc_server, dec_server) = self.tokens
        _DECODE_SERVER_FIELD_VERSION.reset(dec_server)
        _ENCODE_SERVER_FIELD_VERSION.reset(enc_server)
        _DECODE_FIELD_VERSION.reset(dec)
        _ENCODE_FIELD_VERSION.reset(enc)


def _decode(data):
    # decode_token_oer's batch errors, error code and message.
    got = decode_token_oer(data, (None, None, []))
    return (got[7], got[1], got[5])


class TestTheBatchArraysAsServersWriteThem(unittest.TestCase):
    def test_two_errors_at_23ai(self):
        with _AtFieldVersion(FIELD_VERSION_23_4):
            data = _encode_oer(1, 24381, 2, b'ORA-24381', batch_errors=_errors(2))
        self.assertIn(ARRAYS_23AI, data)

    def test_two_errors_at_11g(self):
        with _AtFieldVersion(FIELD_VERSION_11_2):
            data = _encode_oer(1, 24381, 2, b'ORA-24381', batch_errors=_errors(2))
        self.assertIn(ARRAYS_11G, data)

    def test_one_error(self):
        for fv in (FIELD_VERSION_11_2, FIELD_VERSION_23_4):
            with self.subTest(fv=fv), _AtFieldVersion(fv):
                data = _encode_oer(1, 24381, 1, b'ORA-24381', batch_errors=_errors(1))
                self.assertIn(ARRAYS_ONE, data)

    def test_100_errors_read_back(self):
        # 300 bytes of codes: packed into one value, its chunks split them and
        # python-oracledb failed with DPY-5002 (#2793).
        for fv in (FIELD_VERSION_11_2, FIELD_VERSION_12_1, FIELD_VERSION_23_4):
            with self.subTest(fv=fv), _AtFieldVersion(fv):
                data = _encode_oer(
                    1, 24381, 100, b'ORA-24381', batch_errors=_errors(100)
                )
                (errors, code, _) = _decode(data)
                self.assertEqual(code, 24381)
                self.assertEqual(
                    [(e['offset'], e['code'], e['message']) for e in errors],
                    [(row, 1438, f'ORA-01438: value {row}') for row in range(100)],
                )


class TestA23aiStatusReads(unittest.TestCase):
    def test_its_batch_errors(self):
        with _AtFieldVersion(FIELD_VERSION_23_4):
            (errors, code, message) = _decode(OER_23AI_TWO_ERRORS)
        self.assertEqual(code, 24381)
        self.assertEqual(message, 'ORA-24381: error(s) in array DML')
        self.assertEqual(
            [(e['offset'], e['code']) for e in errors], [(0, 1438), (1, 1438)]
        )
        self.assertTrue(errors[1]['message'].startswith('ORA-01438: value 11 greater'))


class TestTheAnnotationMapAs23aiWritesIt(unittest.TestCase):
    # Three columns' maps from a 23ai describe: `a number annotations (Akey
    # 'Aval')`, `b ... (Bk1 'v1', Bk2 'v2')` and `c ... (Ck1 'x', Ck2, Ck3
    # 'zzz')`.
    CAPTURED = {
        ((b'AKEY', b'Aval'),): (
            '01 01 10 01 01 16 01 04 04 41 4b 45 59 01 04 04 41 76 61 6c 00 00'
        ),
        ((b'BK1', b'v1'), (b'BK2', b'v2')): (
            '01 01 10 01 02 16 01 03 03 42 4b 31 01 02 02 76 31 00'
            ' 01 03 03 42 4b 32 01 02 02 76 32 00 00'
        ),
        ((b'CK1', b'x'), (b'CK2', b''), (b'CK3', b'zzz')): (
            '01 01 10 01 03 16 01 03 03 43 4b 31 01 01 01 78 00'
            ' 01 03 03 43 4b 32 00 00 01 03 03 43 4b 33 01 03 03 7a 7a 7a 00 00'
        ),
    }

    def test_each(self):
        encode = compile_encoder(_DCB_ANNOTATIONS, _THIN)
        with _AtFieldVersion(FIELD_VERSION_23_4):
            for annotations, captured in self.CAPTURED.items():
                with self.subTest(annotations=annotations):
                    self.assertEqual(
                        encode(_annotation_values(annotations)),
                        bytes.fromhex(captured),
                    )

    def test_none(self):
        encode = compile_encoder(_DCB_ANNOTATIONS, _THIN)
        self.assertEqual(encode(_annotation_values(())), b'\x00')


if __name__ == '__main__':
    unittest.main()
