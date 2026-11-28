# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The Mirror's LOB columns for a client that prefetches them (#2859).

JDBC thin 11.2 (ojdbc6) fetches a LOB column in two calls: the execute, which
gets the describe only, then a define-and-fetch call. That second call asks
for its rows in al8i4[1], not the header, and its define asks for the data
with the locator (TNS_LOB_PREFETCH_FLAG). The Mirror sent no rows, then
values without their data, in locators whose flag bytes named an NCLOB.
Checked against ojdbc6 11.2.0.3 and 11.2.0.2, captured.
"""

from __future__ import annotations

import unittest

from seerdb.common import tns, wire_schema
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    ColumnMeta,
    LobEmitLog,
    encode_lob_locator_thin,
    inline_long_for_defines,
    mint_column_lob_locator,
    parse_exec,
)
from seerdb.common.tns_consts import (
    AL16UTF16_CHARSET,
    FIELD_VERSION_11_2,
    TNS_TYPE_BLOB,
    TNS_TYPE_CLOB,
)
from tests.replay import load_capture

_CELL = wire_schema.compile_decoder(tns._LOB_CELL_PREFETCH, tns._THIN)

# Each column of the capture, the value it held, and its locator's flag bytes.
_VALUES = {
    'c': (TNS_TYPE_CLOB, 1, 'abc'),
    'n': (TNS_TYPE_CLOB, 2, 'xyz'),
    'l': (TNS_TYPE_CLOB, 1, 'w' * 300),
    'e': (TNS_TYPE_CLOB, 1, ''),
    'b': (TNS_TYPE_BLOB, 0, b'\x0a\x0b\x0c'),
}


def _real_cell(column: str) -> dict:
    # The value cell of 11.2.0.2's reply: the row behind the row header (`06`).
    reply = load_capture(f'oracle11g_lob_prefetch_{column}_reply.hexdump')
    (data_type, csfrm, _) = _VALUES[column]
    given = {'prefetch_text': data_type == TNS_TYPE_CLOB}
    (fields, _) = _CELL(reply[reply.index(b'\x07', 1) + 1 :], given)
    return fields


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


class TestTheDefineCall(unittest.TestCase):
    def test_its_row_count_and_its_prefetch(self):
        # The header's row count is 0; al8i4[1] asks for 10. The CLOB define
        # carries the prefetch flag and ojdbc6's default size, 4000.
        with _AtFieldVersion(FIELD_VERSION_11_2):
            request = parse_exec(load_capture('jdbc6_lob_define_fetch_11g.hexdump'))
        self.assertEqual(request.fetch, 10)
        self.assertEqual(request.define_types, [(TNS_TYPE_CLOB, 1, 4000)])

    def test_the_define_marks_its_column(self):
        clob = ColumnMeta(b'C', TNS_TYPE_CLOB, 0, 0)
        (marked,) = inline_long_for_defines([clob], [(TNS_TYPE_CLOB, 1, 4000)])
        self.assertEqual(marked.lob_prefetch, 4000)
        # python-oracledb sets the flag with a length of 0: no data.
        (plain,) = inline_long_for_defines([clob], [(TNS_TYPE_CLOB, 1, 0)])
        self.assertEqual(plain.lob_prefetch, 0)


class TestTheValueIsTheServers(unittest.TestCase):
    def test_each_kind_of_value(self):
        # The size, the charset fields and the data are 11.2.0.2's; the
        # locator and its chunk size are the Mirror's own.
        for column, (data_type, csfrm, value) in _VALUES.items():
            with self.subTest(column=column):
                real = _real_cell(column)
                col = ColumnMeta(
                    b'X', data_type, 0, 0, csfrm=csfrm or 1, lob_prefetch=4000
                )
                kind = {0: 'blob', 1: 'clob', 2: 'nclob'}[csfrm]
                cell = encode_lob_locator_thin(
                    len(value),
                    with_metadata=True,
                    locator=mint_column_lob_locator(0, kind),
                    prefetch=tns._lob_prefetch_data(col, value),
                )
                (ours, rest) = _CELL(
                    cell, {'prefetch_text': data_type == TNS_TYPE_CLOB}
                )
                self.assertEqual(rest, b'')
                for field in (
                    'size',
                    'has_charset',
                    'charset',
                    'prefetch_csfrm',
                    'data',
                ):
                    self.assertEqual(ours.get(field), real.get(field), field)
                if column == 'c':
                    self.assertEqual(ours['charset'], AL16UTF16_CHARSET)

    def test_a_null_is_the_plain_cell(self):
        reply = load_capture('oracle11g_lob_prefetch_z_reply.hexdump')
        self.assertEqual(reply[reply.index(b'\x07', 1) + 1], 0)


class TestTheLocatorsFlags(unittest.TestCase):
    def test_flag_bytes_as_11_2_0_2s(self):
        # Offsets 4 to 7, which JDBC thin builds its CLOB, NCLOB or BLOB from;
        # the ASCII there before named every LOB an NCLOB.
        for column, kind in (('c', 'clob'), ('n', 'nclob'), ('b', 'blob')):
            with self.subTest(kind=kind):
                real = _real_cell(column)['locator']
                self.assertEqual(mint_column_lob_locator(5, kind)[4:8], real[4:8])

    def test_the_log_mints_each_kind(self):
        log = LobEmitLog()
        self.assertEqual(log.record('x', True)[4:8], bytes.fromhex('020c8000'))
        self.assertEqual(log.record('x', True, True)[4:8], bytes.fromhex('044c0000'))
        self.assertEqual(log.record(b'x', False)[4:8], bytes.fromhex('010c0000'))


if __name__ == '__main__':
    unittest.main()
