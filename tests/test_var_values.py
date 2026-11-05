# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests: what a Var accepts as its value (#2477).

A value that doesn't fit the variable's type used to be bound anyway, and the
server read its bytes as the variable's type. The accepted sets are
python-oracledb 26.1's, measured against 23ai."""

import datetime
import unittest
from decimal import Decimal

import seerdb
from seerdb.common.datatypes import BcDate, Var

_VALUES = {
    'int': 12,
    'float': 1.5,
    'Decimal': Decimal('1.25'),
    'bool': True,
    'str': '12',
    'bytes': b'ab',
    'date': datetime.date(2026, 11, 5),
    'datetime': datetime.datetime(2026, 11, 5, 1, 2, 3),
    'timedelta': datetime.timedelta(days=1),
}
_NUMBERS = {'int', 'float', 'Decimal', 'bool'}
_DATES = {'date', 'datetime'}

# The variable type, and which of _VALUES python-oracledb accepts for it.
_ACCEPTS = {
    str: {'str', 'bytes'},
    seerdb.DB_TYPE_VARCHAR: {'str', 'bytes'},
    seerdb.DB_TYPE_CHAR: {'str', 'bytes'},
    seerdb.DB_TYPE_NVARCHAR: {'str', 'bytes'},
    seerdb.DB_TYPE_LONG: {'str', 'bytes'},
    int: _NUMBERS,
    float: _NUMBERS,
    Decimal: _NUMBERS,
    seerdb.DB_TYPE_NUMBER: _NUMBERS,
    seerdb.DB_TYPE_BINARY_INTEGER: _NUMBERS,
    seerdb.DB_TYPE_BINARY_FLOAT: _NUMBERS,
    seerdb.DB_TYPE_BINARY_DOUBLE: _NUMBERS,
    bytes: {'str', 'bytes'},
    seerdb.DB_TYPE_RAW: {'str', 'bytes'},
    seerdb.DB_TYPE_LONG_RAW: {'str', 'bytes'},
    datetime.datetime: _DATES,
    seerdb.DB_TYPE_DATE: _DATES,
    seerdb.DB_TYPE_TIMESTAMP: _DATES,
    seerdb.DB_TYPE_TIMESTAMP_TZ: _DATES,
    seerdb.DB_TYPE_TIMESTAMP_LTZ: _DATES,
    datetime.timedelta: {'timedelta'},
    seerdb.DB_TYPE_INTERVAL_DS: {'timedelta'},
}


class AcceptedValuesTest(unittest.TestCase):
    def test_each_type_takes_what_python_oracledb_takes_and_refuses_the_rest(self):
        for typ, accepted in _ACCEPTS.items():
            for name, value in _VALUES.items():
                with self.subTest(var=typ, value=name):
                    v = Var(typ)
                    if name in accepted:
                        v.setvalue(0, value)
                        self.assertTrue(v.has_value)
                    else:
                        with self.assertRaises(seerdb.NotSupportedError):
                            v.setvalue(0, value)
                        self.assertFalse(v.has_value)

    def test_none_is_always_accepted(self):
        for typ in _ACCEPTS:
            v = Var(typ)
            v.setvalue(0, None)
            self.assertIsNone(v.getvalue())

    def test_a_binary_float_takes_a_decimal_or_bool_as_its_float(self):
        for typ in (seerdb.DB_TYPE_BINARY_DOUBLE, seerdb.DB_TYPE_BINARY_FLOAT):
            v = Var(typ)
            v.setvalue(0, Decimal('1.25'))
            self.assertEqual(v._value, 1.25)
            self.assertIsInstance(v._value, float)
            v.setvalue(0, True)
            self.assertEqual(v._value, 1.0)

    def test_a_date_before_year_one(self):
        v = Var(seerdb.DB_TYPE_DATE)
        v.setvalue(0, BcDate(-4712, 1, 1))
        self.assertIsInstance(v._value, BcDate)

    def test_an_array_checks_each_element(self):
        v = Var(int, is_array=True, num_elements=3)
        v.setvalue(0, [1, 2, 3])
        self.assertEqual(v._value, [1, 2, 3])
        with self.assertRaises(seerdb.NotSupportedError):
            v.setvalue(0, [1, 'two', 3])

    def test_the_inconverter_runs_first(self):
        v = Var(str, inconverter=str)
        v.setvalue(0, 12)
        self.assertEqual(v.getvalue(), '12')

    def test_the_other_types_keep_what_they_took(self):
        # LOBs take str / bytes and are bound as a temporary LOB.
        v = Var(seerdb.DB_TYPE_CLOB)
        v.setvalue(0, 'text')
        self.assertEqual(v._value, 'text')
        v = Var(seerdb.DB_TYPE_BLOB)
        v.setvalue(0, b'raw')
        self.assertEqual(v._value, b'raw')


if __name__ == '__main__':
    unittest.main()
