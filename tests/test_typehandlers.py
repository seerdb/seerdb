# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for output type handlers, fetch_decimals, the cursor.var()
converters and seerdb.defaults (#2458).

The expected values are python-oracledb 26.1 thin's, measured against 23ai,
except where seerdb's own fetch types differ (a NUMBER is an int or a Decimal,
never a float); those are named where they are tested."""

import datetime
import types
import unittest
from decimal import Decimal

import seerdb
from seerdb.client.connection import OracleConnect
from seerdb.client.cursor import Cursor, FetchInfo
from seerdb.client.typehandlers import (
    apply_fetch_plan,
    build_fetch_plan,
    lob_columns,
    plan_for_var,
)
from seerdb.common.datatypes import Var


def _info(name, type_code, precision=None, scale=None, max_size=0):
    return FetchInfo(
        (name, type_code, None, None, precision, scale, True), max_size=max_size
    )


def _convert(source, var, value):
    return apply_fetch_plan([plan_for_var(source, var)], [value])[0]


def _stub_cursor(connection=None):
    return Cursor(connection or types.SimpleNamespace(sock=object()))


class FetchInfoFieldsTest(unittest.TestCase):
    def test_the_seven_fields_by_name(self):
        info = FetchInfo(('N', seerdb.DB_TYPE_NUMBER, 127, None, 0, -127, True))
        self.assertEqual(info.name, 'N')
        self.assertIs(info.type_code, seerdb.DB_TYPE_NUMBER)
        self.assertIs(info.type, seerdb.DB_TYPE_NUMBER)
        self.assertEqual(info.display_size, 127)
        self.assertIsNone(info.internal_size)
        self.assertEqual((info.precision, info.scale), (0, -127))
        self.assertTrue(info.null_ok)
        # Still the plain 7-tuple to a PEP 249 consumer.
        self.assertEqual(info, ('N', seerdb.DB_TYPE_NUMBER, 127, None, 0, -127, True))


class ConversionTest(unittest.TestCase):
    def test_number_to_text_is_positional(self):
        text = seerdb.Var(str)
        self.assertEqual(_convert(seerdb.DB_TYPE_NUMBER, text, Decimal('1.5')), '1.5')
        self.assertEqual(_convert(seerdb.DB_TYPE_NUMBER, text, 4371), '4371')
        # python-oracledb's text, not Decimal's '-1E-7'.
        self.assertEqual(
            _convert(seerdb.DB_TYPE_NUMBER, text, Decimal('-1E-7')), '-0.0000001'
        )

    def test_number_to_the_python_type_asked_for(self):
        self.assertEqual(_convert(seerdb.DB_TYPE_NUMBER, Var(float), 4371), 4371.0)
        self.assertIsInstance(
            _convert(seerdb.DB_TYPE_NUMBER, Var(float), Decimal('1.5')), float
        )
        self.assertEqual(
            _convert(seerdb.DB_TYPE_NUMBER, Var(Decimal), 4371), Decimal('4371')
        )
        # var(int) keeps a NUMBER as seerdb fetches it: rounding would lose the
        # fraction the statement returned.
        self.assertEqual(
            _convert(seerdb.DB_TYPE_NUMBER, Var(int), Decimal('1.5')), Decimal('1.5')
        )
        self.assertEqual(
            _convert(seerdb.DB_TYPE_NUMBER, Var(seerdb.DB_TYPE_BINARY_INTEGER), 7), 7
        )

    def test_a_binary_double_to_decimal_goes_through_its_text(self):
        # Decimal(1.1) would be the binary value; python-oracledb hands back a
        # float here, seerdb the Decimal that was asked for.
        self.assertEqual(
            _convert(seerdb.DB_TYPE_BINARY_DOUBLE, Var(Decimal), 1.1), Decimal('1.1')
        )

    def test_a_string_column_to_a_number(self):
        self.assertEqual(_convert(seerdb.DB_TYPE_VARCHAR, Var(float), '42.5'), 42.5)
        self.assertEqual(
            _convert(seerdb.DB_TYPE_VARCHAR, Var(seerdb.NUMBER), '42.5'),
            Decimal('42.5'),
        )
        self.assertEqual(_convert(seerdb.DB_TYPE_VARCHAR, Var(seerdb.NUMBER), '42'), 42)
        with self.assertRaises(seerdb.DataError):
            _convert(seerdb.DB_TYPE_VARCHAR, Var(float), 'abc')

    def test_datetimes_and_intervals_to_text(self):
        when = datetime.datetime(2026, 11, 4, 10, 11, 12, 123456)
        self.assertEqual(
            _convert(seerdb.DB_TYPE_TIMESTAMP, Var(str), when),
            '2026-11-04 10:11:12.123456',
        )
        self.assertEqual(
            _convert(
                seerdb.DB_TYPE_INTERVAL_DS,
                Var(seerdb.DB_TYPE_LONG),
                datetime.timedelta(days=1, hours=2, minutes=3, seconds=4.5),
            ),
            '1 day, 2:03:04.500000',
        )

    def test_a_lob_to_its_content_reads_the_lob(self):
        for source, target in (
            (seerdb.DB_TYPE_CLOB, str),
            (seerdb.DB_TYPE_CLOB, seerdb.DB_TYPE_LONG),
            (seerdb.DB_TYPE_NCLOB, str),
            (seerdb.DB_TYPE_BLOB, bytes),
            (seerdb.DB_TYPE_BLOB, seerdb.DB_TYPE_LONG_RAW),
        ):
            plan = plan_for_var(source, Var(target))
            self.assertTrue(plan.read_lob, (source, target))
            self.assertIsNone(plan.convert)

    def test_a_datetime_kept_as_one(self):
        when = datetime.datetime(2026, 11, 4, 10, 11, 12, 123456)
        # DATE from a TIMESTAMP keeps the fraction, as python-oracledb keeps it.
        self.assertEqual(
            _convert(seerdb.DB_TYPE_TIMESTAMP, Var(seerdb.DATETIME), when), when
        )

    def test_refused_conversions(self):
        refused = (
            (seerdb.DB_TYPE_NUMBER, bytes),
            (seerdb.DB_TYPE_NUMBER, seerdb.DB_TYPE_DATE),
            (seerdb.DB_TYPE_DATE, float),
            (seerdb.DB_TYPE_INTERVAL_DS, float),
            (seerdb.DB_TYPE_INTERVAL_YM, str),
            (seerdb.DB_TYPE_ROWID, bytes),
            (seerdb.DB_TYPE_CLOB, float),
            (seerdb.DB_TYPE_CLOB, bytes),
            (seerdb.DB_TYPE_BLOB, str),
            (seerdb.DB_TYPE_NCLOB, bytes),
            (seerdb.DB_TYPE_VARCHAR, bytes),
        )
        for source, target in refused:
            with self.subTest(source=source, target=target):
                with self.assertRaises(seerdb.DatabaseError):
                    plan_for_var(source, Var(target))

    def test_the_same_type_needs_no_conversion(self):
        plan = plan_for_var(seerdb.DB_TYPE_CLOB, Var(seerdb.DB_TYPE_CLOB))
        self.assertIsNone(plan.convert)
        self.assertFalse(plan.read_lob)


class OutconverterTest(unittest.TestCase):
    def test_applied_after_the_conversion_and_not_to_null(self):
        plan = [plan_for_var(seerdb.DB_TYPE_NUMBER, Var(str, outconverter=len))]
        self.assertEqual(apply_fetch_plan(plan, [Decimal('12.5')]), [4])
        self.assertEqual(apply_fetch_plan(plan, [None]), [None])

    def test_convert_nulls_passes_null_too(self):
        V = Var(seerdb.NUMBER, outconverter=lambda v: ('c', v), convert_nulls=True)
        plan = [plan_for_var(seerdb.DB_TYPE_NUMBER, V)]
        self.assertEqual(apply_fetch_plan(plan, [1]), [('c', 1)])
        self.assertEqual(apply_fetch_plan(plan, [None]), [('c', None)])


class BuildFetchPlanTest(unittest.TestCase):
    def setUp(self):
        self.description = [
            _info('N', seerdb.DB_TYPE_NUMBER, 0, -127),
            _info('C', seerdb.DB_TYPE_CLOB),
            _info('S', seerdb.DB_TYPE_CHAR, max_size=2),
        ]

    def test_no_handler_and_no_fetch_decimals_is_no_plan(self):
        self.assertIsNone(build_fetch_plan(_stub_cursor(), self.description, False))

    def test_the_handler_is_called_once_per_column_with_the_fetch_info(self):
        seen = []

        def handler(cursor, metadata):
            seen.append((cursor, metadata))
            return None

        cur = _stub_cursor()
        cur.outputtypehandler = handler
        self.assertIsNone(build_fetch_plan(cur, self.description, False))
        self.assertEqual([m for _, m in seen], self.description)
        self.assertTrue(all(c is cur for c, _ in seen))

    def test_the_cursor_handler_wins_over_the_connection_handler(self):
        conn = types.SimpleNamespace(
            sock=object(), outputtypehandler=lambda c, m: c.var(str)
        )
        cur = _stub_cursor(conn)
        self.assertIsNotNone(build_fetch_plan(cur, self.description, False))
        cur.outputtypehandler = lambda c, m: None
        self.assertIsNone(build_fetch_plan(cur, self.description, False))

    def test_the_older_six_argument_form(self):
        seen = []

        def handler(cursor, name, default_type, size, precision, scale):
            seen.append((name, default_type, size, precision, scale))

        cur = _stub_cursor()
        cur.outputtypehandler = handler
        build_fetch_plan(cur, self.description, False)
        # As python-oracledb passes them: N NUMBER 0 0 -127, S CHAR 2 0 0.
        self.assertEqual(seen[0], ('N', seerdb.DB_TYPE_NUMBER, 0, 0, -127))
        self.assertEqual(seen[2], ('S', seerdb.DB_TYPE_CHAR, 2, 0, 0))

    def test_a_handler_returning_something_else_is_refused(self):
        cur = _stub_cursor()
        cur.outputtypehandler = lambda c, m: 5
        with self.assertRaises(seerdb.ProgrammingError):
            build_fetch_plan(cur, self.description, False)

    def test_fetch_decimals_takes_number_columns_only(self):
        plan = build_fetch_plan(_stub_cursor(), self.description, True)
        self.assertEqual(
            apply_fetch_plan(plan, [4371, 'x', 'ab']), [Decimal('4371'), 'x', 'ab']
        )
        self.assertEqual(apply_fetch_plan(plan, [None, None, None]), [None] * 3)

    def test_a_handler_var_wins_over_fetch_decimals(self):
        cur = _stub_cursor()
        cur.outputtypehandler = lambda c, m: (
            c.var(str) if m.type_code is seerdb.DB_TYPE_NUMBER else None
        )
        plan = build_fetch_plan(cur, self.description, True)
        self.assertEqual(apply_fetch_plan(plan, [4371, 'x', 'ab'])[0], '4371')

    def test_lob_columns_are_the_ones_read(self):
        cur = _stub_cursor()
        cur.outputtypehandler = lambda c, m: (
            c.var(str) if m.type_code is seerdb.DB_TYPE_CLOB else None
        )
        self.assertEqual(
            lob_columns(build_fetch_plan(cur, self.description, False)), [1]
        )


class CursorFetchTest(unittest.TestCase):
    def _cursor_with(self, rows, handler=None, fetch_decimals=False):
        cur = _stub_cursor()
        cur.outputtypehandler = handler
        cur._fetch_decimals = fetch_decimals
        cur._description = [
            _info('N', seerdb.DB_TYPE_NUMBER),
            _info('S', seerdb.DB_TYPE_VARCHAR),
        ]
        cur._rows = rows
        cur._row_index = 0
        cur._plan_fetch()
        return cur

    def test_the_rowfactory_sees_converted_values(self):
        cur = self._cursor_with(
            [[Decimal('1.5'), 'a']],
            handler=lambda c, m: c.var(str) if m.name == 'N' else None,
        )
        cur.rowfactory = lambda *a: a
        self.assertEqual(cur.fetchone(), ('1.5', 'a'))

    def test_fetchall_and_fetchmany_convert_too(self):
        cur = self._cursor_with([[1, 'a'], [2, 'b'], [3, 'c']], fetch_decimals=True)
        self.assertEqual(cur.fetchmany(1), [(Decimal(1), 'a')])
        self.assertEqual(cur.fetchall(), [(Decimal(2), 'b'), (Decimal(3), 'c')])

    def test_a_refused_conversion_leaves_no_result_set(self):
        with self.assertRaises(seerdb.DatabaseError):
            self._cursor_with([[1, 'a']], handler=lambda c, m: c.var(bytes))
        cur = _stub_cursor()
        cur._description = [_info('N', seerdb.DB_TYPE_NUMBER)]
        cur._rows = [[1]]
        cur.outputtypehandler = lambda c, m: c.var(bytes)
        with self.assertRaises(seerdb.DatabaseError):
            cur._plan_fetch()
        self.assertIsNone(cur.description)
        with self.assertRaises(seerdb.InterfaceError):
            cur.fetchone()


class VarOptionsTest(unittest.TestCase):
    def test_python_oracledb_s_parameters(self):
        cur = _stub_cursor()
        v = cur.var(str, 10, arraysize=3, outconverter=len, convert_nulls=True)
        self.assertIs(v.type, seerdb.DB_TYPE_VARCHAR)
        self.assertEqual((v.size, v.num_elements), (10, 3))
        self.assertIs(v.outconverter, len)
        self.assertIsNone(v.inconverter)
        self.assertTrue(v.convert_nulls)

    def test_the_inconverter_is_applied_to_a_value_set(self):
        v = _stub_cursor().var(int, inconverter=lambda x: x * 2)
        v.setvalue(0, 21)
        self.assertEqual(v.getvalue(), 42)

    def test_what_seerdb_does_not_act_on_is_refused(self):
        cur = _stub_cursor()
        for kwargs in (
            {'typename': 'SOME_TYPE'},
            {'encoding_errors': 'replace'},
            {'bypass_decode': True},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(seerdb.NotSupportedError):
                    cur.var(str, **kwargs)


class DefaultsTest(unittest.TestCase):
    def setUp(self):
        self.saved = {N: getattr(seerdb.defaults, N) for N in seerdb.Defaults.__slots__}

    def tearDown(self):
        for N, V in self.saved.items():
            setattr(seerdb.defaults, N, V)

    def test_python_oracledb_s_initial_values(self):
        d = seerdb.Defaults()
        self.assertEqual((d.arraysize, d.prefetchrows), (100, 2))
        self.assertIs(d.fetch_lobs, True)
        self.assertIs(d.fetch_decimals, False)
        self.assertIsNone(d.config_dir)

    def test_an_unknown_name_is_refused(self):
        with self.assertRaises(AttributeError):
            seerdb.defaults.arraysizee = 5  # type: ignore[attr-defined]

    def test_a_cursor_starts_from_them(self):
        seerdb.defaults.arraysize = 7
        seerdb.defaults.prefetchrows = 5
        cur = _stub_cursor()
        self.assertEqual((cur.arraysize, cur.prefetchrows), (7, 5))
        cur.arraysize = 9
        self.assertEqual(seerdb.defaults.arraysize, 7)

    def test_fetch_decimals_is_read_at_each_execute(self):
        cur = _stub_cursor()
        seerdb.defaults.fetch_decimals = True
        cur._fetch_decimals_for(None)
        self.assertTrue(cur._fetch_decimals)
        cur._fetch_decimals_for(False)
        self.assertFalse(cur._fetch_decimals)

    def test_a_connection_starts_from_them(self):
        seerdb.defaults.fetch_lobs = False
        seerdb.defaults.stmtcachesize = 5
        seerdb.defaults.program = 'from-defaults'
        conn = OracleConnect()
        self.assertIs(conn.fetch_lobs, False)
        self.assertEqual(conn.stmtcachesize, 5)
        self.assertEqual(conn.program, 'from-defaults')
        self.assertIsNone(conn.outputtypehandler)
        # An argument still wins.
        self.assertIs(OracleConnect(fetch_lobs=True).fetch_lobs, True)
        self.assertEqual(OracleConnect(program='mine').program, 'mine')


if __name__ == '__main__':
    unittest.main()
