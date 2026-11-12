# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the Arrow / DataFrame bulk fetch (#162): build_table
reshapes buffered rows + a PEP 249 description into a pyarrow.Table."""

import datetime
import re
import unittest
from decimal import Decimal

import pyarrow as pa

from seerdb.client.dataframe import _explicit_type, build_table
from seerdb.common.tns_consts import (
    TNS_TYPE_BFLOAT,
    TNS_TYPE_DATE,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
)


def _desc(name, type_code, scale=None, precision=None):
    # (name, type_code, display_size, internal_size, precision, scale, null_ok)
    return (name, type_code, None, None, precision, scale, True)


class TestBuildTable(unittest.TestCase):
    def test_column_major_and_types(self):
        desc = [
            _desc('ID', TNS_TYPE_NUMBER, 0),
            _desc('PRICE', TNS_TYPE_NUMBER, 2),
            _desc('NAME', TNS_TYPE_VARCHAR),
            _desc('DT', TNS_TYPE_DATE),
        ]
        rows = [
            [1, Decimal('1.50'), 'a', datetime.datetime(2026, 1, 1)],
            [2, Decimal('2.25'), 'b', datetime.datetime(2026, 1, 2)],
        ]
        t = build_table(rows, desc)
        self.assertEqual(t.num_rows, 2)
        self.assertEqual(t.column_names, ['ID', 'PRICE', 'NAME', 'DT'])
        self.assertEqual(t.column('ID').to_pylist(), [1, 2])
        self.assertEqual(t.column('NAME').to_pylist(), ['a', 'b'])
        self.assertTrue(pa.types.is_integer(t.schema.field('ID').type))
        self.assertTrue(pa.types.is_timestamp(t.schema.field('DT').type))

    def test_empty_result_keeps_schema(self):
        desc = [
            _desc('ID', TNS_TYPE_NUMBER, 0),
            _desc('NAME', TNS_TYPE_VARCHAR),
            _desc('DATA', TNS_TYPE_RAW),
        ]
        t = build_table([], desc)
        self.assertEqual(t.num_rows, 0)
        self.assertEqual(t.column_names, ['ID', 'NAME', 'DATA'])
        self.assertTrue(pa.types.is_integer(t.schema.field('ID').type))
        self.assertTrue(pa.types.is_string(t.schema.field('NAME').type))
        self.assertTrue(pa.types.is_binary(t.schema.field('DATA').type))

    def test_all_null_column_uses_fallback_type(self):
        desc = [_desc('N', TNS_TYPE_VARCHAR)]
        t = build_table([[None], [None]], desc)
        self.assertEqual(t.num_rows, 2)
        self.assertEqual(t.column('N').to_pylist(), [None, None])
        self.assertTrue(pa.types.is_string(t.schema.field('N').type))

    def test_mixed_int_and_decimal_number_column(self):
        # Oracle NUMBER decodes integer values to int and fractional to Decimal;
        # pyarrow unifies the column to decimal128.
        desc = [_desc('V', TNS_TYPE_NUMBER, 2)]
        t = build_table([[1], [Decimal('2.5')], [3]], desc)
        self.assertEqual(
            [v for v in t.column('V').to_pylist()],
            [Decimal('1.0'), Decimal('2.5'), Decimal('3.0')],
        )

    def test_explicit_type_mapping(self):
        # The exact Arrow type derived from the describe metadata (#190).
        self.assertEqual(
            _explicit_type(TNS_TYPE_NUMBER, 10, 2), pa.decimal128(10, 2)
        )  # NUMBER(10,2) -> Decimal
        self.assertEqual(_explicit_type(TNS_TYPE_NUMBER, 8, 0), pa.int64())
        self.assertEqual(_explicit_type(TNS_TYPE_BFLOAT, None, None), pa.float32())
        self.assertEqual(_explicit_type(TNS_TYPE_VARCHAR, None, None), pa.string())
        self.assertEqual(_explicit_type(TNS_TYPE_RAW, None, None), pa.binary())
        self.assertEqual(_explicit_type(TNS_TYPE_DATE, None, None), pa.timestamp('us'))
        # Unconstrained NUMBER (no precision / -127 scale marker), a >18-digit
        # integer, and TZ-aware timestamps stay on inference (None).
        self.assertIsNone(_explicit_type(TNS_TYPE_NUMBER, None, None))
        self.assertIsNone(_explicit_type(TNS_TYPE_NUMBER, 0, -127))
        self.assertIsNone(_explicit_type(TNS_TYPE_NUMBER, 20, 0))
        self.assertIsNone(_explicit_type(TNS_TYPE_TIMESTAMPTZ, None, None))

    def test_constrained_number_uses_explicit_decimal128(self):
        # NUMBER(10,2) -> decimal128(10,2) directly (skips inference), with
        # NULLs and Decimals of varying stored scale rescaled to fit.
        desc = [_desc('P', TNS_TYPE_NUMBER, 2, 10)]
        t = build_table(
            [[Decimal('5')], [Decimal('1380.5')], [None], [Decimal('-7.25')]], desc
        )
        self.assertEqual(t.schema.field('P').type, pa.decimal128(10, 2))
        self.assertEqual(
            t.column('P').to_pylist(),
            [Decimal('5.00'), Decimal('1380.50'), None, Decimal('-7.25')],
        )

    def test_constrained_integer_uses_int64(self):
        desc = [_desc('I', TNS_TYPE_NUMBER, 0, 8)]
        t = build_table([[5], [-7], [None]], desc)
        self.assertEqual(t.schema.field('I').type, pa.int64())
        self.assertEqual(t.column('I').to_pylist(), [5, -7, None])


if __name__ == '__main__':
    unittest.main()


class TestArrowBatches(unittest.TestCase):
    """executemany's DataFrame input (#2461): each record batch as the bind
    types of its columns, by position, and its rows, as python-oracledb binds a
    frame."""

    def _one(self, table):
        from seerdb.client.dataframe import arrow_batches

        ((types, rows),) = arrow_batches(table)
        return types, rows

    def test_each_arrow_type_binds_as_python_oracledb_binds_it(self):
        import seerdb

        cases = [
            (pa.int8(), 1, seerdb.DB_TYPE_NUMBER),
            (pa.uint64(), 2**64 - 1, seerdb.DB_TYPE_NUMBER),
            (pa.decimal256(40, 2), Decimal('1.25'), seerdb.DB_TYPE_NUMBER),
            (pa.string(), 'a', seerdb.DB_TYPE_VARCHAR),
            (pa.null(), None, seerdb.DB_TYPE_VARCHAR),
            (pa.binary(), b'\x01', seerdb.DB_TYPE_RAW),
            (pa.binary(2), b'\x01\x02', seerdb.DB_TYPE_RAW),
            (pa.float32(), 1.5, seerdb.DB_TYPE_BINARY_FLOAT),
            (pa.float64(), 1.5, seerdb.DB_TYPE_BINARY_DOUBLE),
            (pa.bool_(), True, seerdb.DB_TYPE_BOOLEAN),
            (
                pa.timestamp('s'),
                datetime.datetime(2026, 1, 2),
                seerdb.DB_TYPE_TIMESTAMP,
            ),
            (pa.date32(), datetime.date(2026, 1, 2), seerdb.DB_TYPE_DATE),
            (pa.large_string(), 'a', seerdb.DB_TYPE_LONG),
            (pa.large_binary(), b'\x01', seerdb.DB_TYPE_LONG_RAW),
        ]
        for arrow_type, value, bound in cases:
            with self.subTest(arrow_type=str(arrow_type)):
                (types, _) = self._one(pa.table({'c': pa.array([value], arrow_type)}))
                self.assertIs(types[0], bound)

    def test_values_come_as_python_oracledb_converts_them(self):
        # An empty string or binary is NULL; a timestamp its UTC wall time to
        # the microsecond, whatever its zone; a date a midnight datetime; an
        # interval's months are ignored.
        ts = datetime.datetime(2026, 11, 12, 1, 2, 3, 456789)
        table = pa.table(
            {
                's': pa.array(['', 'a'], pa.string()),
                'b': pa.array([b'', b'\x01'], pa.binary()),
                'tz': pa.array([ts, None], pa.timestamp('us', tz='UTC')).cast(
                    pa.timestamp('us', tz='Europe/Prague')
                ),
                'ns': pa.array([1_000_000_001_999, None], pa.timestamp('ns')),
                'd32': pa.array([datetime.date(2026, 11, 12), None], pa.date32()),
                'd64': pa.array([86_400_000, None], pa.date64()),
                'iv': pa.array(
                    [pa.MonthDayNano([5, 2, 1_500]), None], pa.month_day_nano_interval()
                ),
            }
        )
        (_, rows) = self._one(table)
        self.assertEqual(
            rows,
            [
                (
                    None,
                    None,
                    ts,
                    datetime.datetime(1970, 1, 1, 0, 16, 40, 1),
                    datetime.datetime(2026, 11, 12),
                    datetime.datetime(1970, 1, 2),
                    datetime.timedelta(days=2, microseconds=1),
                ),
                ('a', b'\x01', None, None, None, None, None),
            ],
        )

    def test_vectors_are_arrays_and_sparse_vectors(self):

        import seerdb

        sparse = pa.struct(
            [
                ('num_dimensions', pa.int64()),
                ('indices', pa.list_(pa.uint32())),
                ('values', pa.list_(pa.float32())),
            ]
        )
        table = pa.table(
            {
                'f': pa.array([[1.5, 2.5]], pa.list_(pa.float32())),
                'b': pa.array([[1, 255]], pa.list_(pa.uint8(), 2)),
                's': pa.array(
                    [{'num_dimensions': 9, 'indices': [3], 'values': [0.5]}], sparse
                ),
            }
        )
        (types, ((f, b, s),)) = self._one(table)
        self.assertEqual(types, [seerdb.DB_TYPE_VECTOR] * 3)
        self.assertEqual((f.typecode, list(f)), ('f', [1.5, 2.5]))
        self.assertEqual((b.typecode, list(b)), ('B', [1, 255]))
        self.assertEqual(
            (s.num_dimensions, list(s.indices), list(s.values), s.values.typecode),
            (9, [3], [0.5], 'f'),
        )

    def test_an_unsupported_type_is_refused_whatever_batch_it_is_in(self):
        from seerdb.client.dataframe import arrow_batches
        from seerdb.common.exceptions import NotSupportedError

        for arrow_type, value in (
            (pa.time64('us'), datetime.time(1, 2)),
            (pa.list_(pa.string()), ['a']),
            (pa.dictionary(pa.int8(), pa.string()), 'a'),
        ):
            with self.subTest(arrow_type=str(arrow_type)):
                table = pa.table({'c': pa.array([value], arrow_type)})
                with self.assertRaisesRegex(
                    NotSupportedError, re.escape(str(arrow_type))
                ):
                    arrow_batches(table)

    def test_each_record_batch_is_one_execute_and_empty_ones_are_skipped(self):
        from seerdb.client.dataframe import arrow_batches

        schema = pa.schema([('i', pa.int64())])
        batches = [
            pa.record_batch([pa.array([1, 2])], schema=schema),
            pa.record_batch([pa.array([], pa.int64())], schema=schema),
            pa.record_batch([pa.array([3])], schema=schema),
        ]
        reader = pa.RecordBatchReader.from_batches(schema, batches)
        self.assertEqual(
            [rows for (_, rows) in arrow_batches(reader)], [[(1,), (2,)], [(3,)]]
        )
        self.assertEqual(arrow_batches(pa.table({'i': pa.array([], pa.int64())})), [])

    def test_a_pre_12_session_leaves_strings_and_binaries_to_their_values(self):
        # Below 12.1 a declared string or binary goes with the type's 32 KB
        # buffer, which 9i takes for a LONG, and a LONG must be declared to bind
        # past 4000 bytes. From 12.1 every column is declared.
        import seerdb
        from seerdb.client.dataframe import arrow_batches
        from seerdb.common.tns_consts import FIELD_VERSION_11_2, FIELD_VERSION_12_1

        table = pa.table(
            {
                's': pa.array(['a'], pa.string()),
                'b': pa.array([b'\x01'], pa.binary()),
                'l': pa.array(['a'], pa.large_string()),
                'r': pa.array([b'\x01'], pa.large_binary()),
            }
        )
        ((old, _),) = arrow_batches(table, FIELD_VERSION_11_2)
        self.assertEqual(
            old, [None, None, seerdb.DB_TYPE_LONG, seerdb.DB_TYPE_LONG_RAW]
        )
        ((new, _),) = arrow_batches(table, FIELD_VERSION_12_1)
        self.assertEqual(
            new,
            [
                seerdb.DB_TYPE_VARCHAR,
                seerdb.DB_TYPE_RAW,
                seerdb.DB_TYPE_LONG,
                seerdb.DB_TYPE_LONG_RAW,
            ],
        )
