# SPDX-FileCopyrightText: 2025 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""A LONG-class bind's value travels after the row's other values.

The server takes a character / RAW bind in place only up to its maximum string
size (4000 bytes before 12c, 32767 after). A bind declared wider is a LONG-class
bind, and the server reads a row's LONG-class values after all its others. A
`Var(str)` declares 32767 by default, so on 11g an INSERT with such a Var at :2
and a plain string at :3 stored the two crossed -- nothing failed, the columns
just swapped (docs/PROTOCOL.md 5.4).
"""

import unittest

import seerdb
from seerdb.common.datatypes import Var
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    decode_ub4,
    encode_dictionary_exec,
    max_string_size,
    parse_exec,
)
from seerdb.common.tns_consts import FIELD_VERSION_11_2, FIELD_VERSION_23_1

PRE_12C = 4000
FROM_12C = 32767

# Runtime capability vectors as the servers advertised them, live.
_CAPS_10G = bytes.fromhex('0201000118')
_CAPS_11G = bytes.fromhex('02010001180003')
_CAPS_21C = bytes.fromhex('0201000118007f')
_CAPS_23AI = bytes.fromhex('0201000118007f010200000000')


def _exec_bytes(
    sql,
    bind,
    batch=(),
    *,
    size,
    kind='change',
    return_binds=None,
    version=FIELD_VERSION_11_2,
):
    return encode_dictionary_exec(
        {
            'field_version': version,
            'max_string_size': size,
            'seq': 3,
            'query': {
                'type': kind,
                'auto': 0,
                'fetch': 0,
                'server_version': 0,
                'cursor': 0,
                'query': sql,
                'bind': bind,
                'batch': list(batch),
                'def': [],
                'batcherrors': False,
                'arraydmlrowcounts': False,
                'return_binds': return_binds,
                'scrollable': False,
                'scroll': None,
            },
        }
    )


def _wide(value):
    """A string bind declared wider than any server takes in place."""
    variable = Var(str)  # 32767 by default
    variable.setvalue(0, value)
    return variable


INSERT = 'insert into t (id, a, b) values (:1, :2, :3)'


class TestTheClientWritesLongClassValuesLast(unittest.TestCase):
    def test_a_wide_bind_is_written_after_the_row(self):
        encoded = _exec_bytes(INSERT, [1, _wide('WIDE'), 'PLAIN'], size=PRE_12C)
        self.assertLess(encoded.index(b'PLAIN'), encoded.index(b'WIDE'))

    def test_a_bind_the_server_takes_in_place_stays_in_place(self):
        encoded = _exec_bytes(INSERT, [1, _wide('WIDE'), 'PLAIN'], size=FROM_12C)
        self.assertLess(encoded.index(b'WIDE'), encoded.index(b'PLAIN'))

    def test_the_declared_size_decides_not_the_value(self):
        # A plain string is declared at its own length, so it is never
        # LONG-class below the threshold however wide the Var next to it.
        small = Var(str, 10)
        small.setvalue(0, 'SMALL')
        encoded = _exec_bytes(INSERT, [1, small, 'PLAIN'], size=PRE_12C)
        self.assertLess(encoded.index(b'SMALL'), encoded.index(b'PLAIN'))

    def test_a_plsql_block_keeps_every_value_in_place(self):
        block = 'begin p(:1, :2, :3); end;'
        encoded = _exec_bytes(
            block, [1, _wide('WIDE'), 'PLAIN'], size=PRE_12C, kind='block'
        )
        self.assertLess(encoded.index(b'WIDE'), encoded.index(b'PLAIN'))

    def test_the_threshold_comes_from_the_connection(self):
        # Nothing is wide, so both thresholds give the same bytes: the size only
        # matters through the OAC, never on its own.
        bind = [1, 'X', 'Y']
        self.assertEqual(
            _exec_bytes(INSERT, bind, size=PRE_12C),
            _exec_bytes(INSERT, bind, size=FROM_12C),
        )


class TestThe9iBuilderWritesLongClassValuesLast(unittest.TestCase):
    """9i has its own request builder and the same rule (#723)."""

    SQL = 'insert into t values (:1, :2, :3)'

    def test_a_wide_bind_is_written_after_the_row(self):
        from seerdb.common.tns import encode_o7_parse

        encoded = encode_o7_parse(3, self.SQL, [1, _wide('WIDE'), 'PLAIN'])
        self.assertLess(encoded.index(b'PLAIN'), encoded.index(b'WIDE'))

    def test_a_bind_within_4000_bytes_stays_in_place(self):
        from seerdb.common.tns import encode_o7_parse

        small = Var(str, 4000)
        small.setvalue(0, 'SMALL')
        encoded = encode_o7_parse(3, self.SQL, [1, small, 'PLAIN'])
        self.assertLess(encoded.index(b'SMALL'), encoded.index(b'PLAIN'))

    def test_a_plsql_block_keeps_every_value_in_place(self):
        # A 9i block's parse carries only the descriptors; the dialect sends the
        # values afterwards as one RXD built straight from the bind list, which
        # is the in-place order the server wants for a block.
        from seerdb.common.tns import encode_o7_block, encode_tokens_rxd

        bind = [1, _wide('WIDE'), 'PLAIN']
        parse = encode_o7_block(3, 'begin p(:1, :2, :3); end;', bind)
        self.assertNotIn(b'PLAIN', parse)
        values = encode_tokens_rxd(bind, b'')
        self.assertLess(values.index(b'WIDE'), values.index(b'PLAIN'))


class TestThe8iBuilderWritesLongClassValuesLast(unittest.TestCase):
    """8i has its own request builder and the same rule (#714)."""

    def _bytes(self, bind):
        from seerdb.common.tns import encode_8i_oall8_query

        return encode_8i_oall8_query(
            3, b'select 1 from t where a = :1 and b = :2 and c = :3', bind
        )

    def test_a_wide_bind_is_written_after_the_row(self):
        encoded = self._bytes([1, _wide('WIDE'), 'PLAIN'])
        self.assertLess(encoded.index(b'PLAIN'), encoded.index(b'WIDE'))

    def test_a_plsql_block_keeps_every_value_in_place(self):
        from seerdb.common.tns import O8I_STMT_BEGIN, encode_8i_oall8_dml

        encoded = encode_8i_oall8_dml(
            3, b'begin p(:1, :2, :3); end;', O8I_STMT_BEGIN, [1, _wide('WIDE'), 'PLAIN']
        )
        self.assertLess(encoded.index(b'WIDE'), encoded.index(b'PLAIN'))

    def test_a_bind_within_4000_bytes_stays_in_place(self):
        small = Var(str, 4000)
        small.setvalue(0, 'SMALL')
        encoded = self._bytes([1, small, 'PLAIN'])
        self.assertLess(encoded.index(b'SMALL'), encoded.index(b'PLAIN'))


class TestTheMirrorReadsByTheSameRule(unittest.TestCase):
    """The Mirror's parser is the inverse: fed the client's bytes and the same
    threshold it recovers the rows exactly, on every field version."""

    def tearDown(self):
        _DECODE_FIELD_VERSION.set(FIELD_VERSION_11_2)

    def _round_trip(
        self,
        sql,
        bind,
        batch=(),
        *,
        size,
        read_size=None,
        version=FIELD_VERSION_11_2,
        **kw,
    ):
        # Encoded and decoded in the same layout, as one session would.
        encoded = _exec_bytes(sql, bind, batch, size=size, version=version, **kw)
        _DECODE_FIELD_VERSION.set(version)
        return parse_exec(
            encoded, max_string_size=size if read_size is None else read_size
        )

    def _values(self, row):
        return [v.getvalue() if isinstance(v, Var) else v for v in row]

    def test_one_row(self):
        for version in (FIELD_VERSION_11_2, FIELD_VERSION_23_1):
            with self.subTest(version=version):
                request = self._round_trip(
                    INSERT, [1, _wide('WIDE'), 'PLAIN'], size=PRE_12C, version=version
                )
                self.assertEqual(request.binds, [1, 'WIDE', 'PLAIN'])

    def test_every_iteration_of_an_array_execute(self):
        rows = [[1, _wide('W1'), 'P1'], [2, _wide('W2'), 'P2'], [3, _wide('W3'), 'P3']]
        request = self._round_trip(INSERT, rows[0], rows[1:], size=PRE_12C)
        self.assertEqual(
            request.bind_rows, [[1, 'W1', 'P1'], [2, 'W2', 'P2'], [3, 'W3', 'P3']]
        )

    def test_a_returning_bind_and_a_wide_bind_together(self):
        sql = 'insert into t (a, b) values (:1, :2) returning id into :3'
        receiver = Var(int)
        request = self._round_trip(
            sql,
            [_wide('WIDE'), 'PLAIN', receiver],
            size=PRE_12C,
            return_binds=frozenset({2}),
        )
        self.assertEqual(request.binds, ['WIDE', 'PLAIN', None])

    def test_reading_with_the_wrong_threshold_is_the_bug(self):
        # What 11g did to a client that wrote in place: the values cross.
        request = self._round_trip(
            INSERT, [1, _wide('WIDE'), 'PLAIN'], size=FROM_12C, read_size=PRE_12C
        )
        self.assertEqual(request.binds, [1, 'PLAIN', 'WIDE'])


class TestTheThresholdIsReadOffTheServerCaps(unittest.TestCase):
    def test_pre_12c_servers(self):
        self.assertEqual(max_string_size(_CAPS_10G), PRE_12C)
        self.assertEqual(max_string_size(_CAPS_11G), PRE_12C)

    def test_12c_and_later(self):
        self.assertEqual(max_string_size(_CAPS_21C), FROM_12C)
        self.assertEqual(max_string_size(_CAPS_23AI), FROM_12C)

    def test_no_caps_at_all_means_the_classic_limit(self):
        self.assertEqual(max_string_size(b''), PRE_12C)


class Declared9iCharBind(unittest.TestCase):
    # 9i pads a CHAR bind to the descriptor's max size, so a declared CHAR IN
    # bind in a plain statement is sized to its value; a block's Var keeps its
    # buffer size, which is the return buffer there (#737).

    def _max_size(self, oac: bytes) -> int:
        return decode_ub4(oac[4:])[0]

    def test_declared_char_in_a_statement_is_sized_to_its_value(self):
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import _o7_bind_oac
        from seerdb.common.tns_consts import TNS_TYPE_CHAR

        var = Var(seerdb.DB_TYPE_CHAR)
        var.setvalue(0, 'ab')
        oac = _o7_bind_oac(var, Statement=True)
        self.assertEqual(oac[0], TNS_TYPE_CHAR)
        self.assertEqual(self._max_size(oac), 2)
        # In a block the same Var is a return buffer and keeps its size.
        self.assertEqual(self._max_size(_o7_bind_oac(var)), 2000)
        # Without a value there is nothing to size by; the default stands.
        self.assertEqual(
            self._max_size(_o7_bind_oac(Var(seerdb.DB_TYPE_CHAR), Statement=True)),
            2000,
        )

    def test_declared_national_char_is_sized_in_utf16(self):
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import _o7_bind_oac

        var = Var(seerdb.DB_TYPE_NCHAR)
        var.setvalue(0, 'ab')
        self.assertEqual(self._max_size(_o7_bind_oac(var, Statement=True)), 4)


class TestArrayDmlOacRepresentative(unittest.TestCase):
    """The single OAC an array-DML batch sends must take each column's TYPE from
    a non-NULL value, not the first row: a column NULL in the first row but
    holding a value later would otherwise type as a minimal VARCHAR2, and the
    later value overflowed it on a real server (ORA-01461, #894)."""

    def test_a_leading_null_column_types_from_a_later_value(self):
        from seerdb.common.tns import _oac_rep_row

        self.assertEqual(
            _oac_rep_row([[1, None], [2, -12312.1], [3, None]]), [1, -12312.1]
        )

    def test_the_widest_string_still_wins_for_sizing(self):
        from seerdb.common.tns import _oac_rep_row

        self.assertEqual(_oac_rep_row([['a'], [None], ['bbb']]), ['bbb'])

    def test_an_all_null_column_stays_null(self):
        from seerdb.common.tns import _oac_rep_row

        self.assertEqual(_oac_rep_row([[None], [None]]), [None])


class TestAPre10BlockTakesAWideValue(unittest.TestCase):
    """8i and 9i take a plain value past the SQL limits in a PL/SQL block, up to
    32512 bytes, where it was refused up front; 9i's descriptor declares it at
    32767, as ojdbc14 does (#2637, PROTOCOL.md 19.3.1)."""

    def test_the_check_lets_a_block_value_through_to_32512_bytes(self):
        from seerdb.client.connection import _check_fv2_bind_sizes
        from seerdb.common.exceptions import NotSupportedError

        _check_fv2_bind_sizes(['q' * 32512, bytes(32512)], Tier='9i', Block=True)
        with self.assertRaisesRegex(
            NotSupportedError, r'32512 bytes in a PL/SQL block.*CLOB'
        ):
            _check_fv2_bind_sizes(['q' * 32513], Tier='9i', Block=True)
        with self.assertRaisesRegex(
            NotSupportedError, r'32512 bytes in a PL/SQL block.*BLOB'
        ):
            _check_fv2_bind_sizes([bytes(32513)], Tier='8i', Block=True)

    def test_sql_still_refuses_one_and_names_the_block_route(self):
        from seerdb.client.connection import _check_fv2_bind_sizes
        from seerdb.common.exceptions import NotSupportedError

        _check_fv2_bind_sizes(['q' * 4000, bytes(2000)], Tier='9i')
        with self.assertRaisesRegex(
            NotSupportedError, r'4000 bytes in SQL.*PL/SQL block'
        ):
            _check_fv2_bind_sizes(['q' * 4001], Tier='9i')
        with self.assertRaisesRegex(NotSupportedError, r'2000 bytes in SQL.*LONG RAW'):
            _check_fv2_bind_sizes([bytes(2001)], Tier='9i')

    def test_a_9i_block_declares_a_wide_value_at_32767(self):
        from seerdb.common.tns import encode_o7_block, encode_o7_parse

        block = 'BEGIN INSERT INTO t VALUES (:1, :2); END;'
        wide = encode_o7_block(3, block, ['q' * 5000, bytes(3000)])
        # VARCHAR (01) and RAW (17), each declared 02 7f ff.
        self.assertIn(bytes([0x01, 0x01, 0, 0, 0x02, 0x7F, 0xFF]), wide)
        self.assertIn(bytes([0x17, 0x01, 0, 0, 0x02, 0x7F, 0xFF]), wide)
        narrow = encode_o7_block(3, block, ['q' * 100, bytes(100)])
        self.assertIn(bytes([0x01, 0x01, 0, 0, 0x02, 0x0F, 0xA0]), narrow)
        self.assertNotIn(bytes([0x02, 0x7F, 0xFF]), narrow)
        # A plain statement keeps 4000: its values are inline in the parse.
        statement = encode_o7_parse(3, 'INSERT INTO t VALUES (:1)', ['q' * 5000])
        self.assertNotIn(bytes([0x01, 0x01, 0, 0, 0x02, 0x7F, 0xFF]), statement)
