# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""A `var` hands back the Python type it was created with (#688).

Three Python types share one database type: a NUMBER column can be read as an
`int`, a `float` or a `Decimal`, and nothing on the wire says which the caller
wanted. Asking for one and receiving another makes the type argument worthless,
so the value is brought back to it on the way out.

Nothing here needs a database — the coercion is on the way out of the `Var`, so
it can be exercised by putting a decoded value in and reading it back.
"""

import datetime
import unittest
from decimal import Decimal

import seerdb
from seerdb.common.datatypes import Var


def _received(var: Var, value: object) -> object:
    """What `var` reads back after the decoder left `value` on it."""
    var._value = value
    var.has_value = True
    return var.getvalue()


class TestNumericVarReadsBackAsRequested(unittest.TestCase):
    def test_float_is_a_float(self):
        # The report: a Decimal came back from a var asked for a float.
        got = _received(Var(float), [Decimal('8.5514716')])
        self.assertEqual(got, [8.5514716])
        self.assertIsInstance(got[0], float)

    def test_float_from_a_whole_number(self):
        # A NUMBER with no fractional part decodes to an int; it is still a float
        # that was asked for.
        got = _received(Var(float), [42])
        self.assertIsInstance(got[0], float)
        self.assertEqual(got, [42.0])

    def test_decimal_is_a_decimal(self):
        got = _received(Var(Decimal), [42])
        self.assertIsInstance(got[0], Decimal)
        self.assertEqual(got, [Decimal(42)])

    def test_int_is_left_alone(self):
        # Deliberate: rounding to an int would discard the fractional part the
        # statement actually returned, which is worse than a neighbouring numeric
        # type. A whole NUMBER already arrives as an int.
        self.assertEqual(_received(Var(int), [Decimal('8.55')]), [Decimal('8.55')])
        self.assertEqual(_received(Var(int), [42]), [42])

    def test_a_database_type_decides_for_itself(self):
        # Asking with a database type rather than a Python one records no
        # preference, so the value arrives however that type decodes.
        got = _received(Var(seerdb.DB_TYPE_NUMBER), [Decimal('8.55')])
        self.assertIsInstance(got[0], Decimal)


class TestCoercionReachesEveryShape(unittest.TestCase):
    def test_a_scalar_out_bind(self):
        # A PL/SQL OUT bind leaves a bare value, not a list.
        got = _received(Var(float), Decimal('1.25'))
        self.assertIsInstance(got, float)

    def test_each_iteration_of_an_array_returning(self):
        var = Var(float)
        var._value = [Decimal('1.5')]
        var._iteration_values = [[Decimal('1.5')], [Decimal('2.5')]]
        var.has_value = True
        self.assertEqual([var.getvalue(i) for i in range(2)], [[1.5], [2.5]])
        self.assertIsInstance(var.getvalue(1)[0], float)

    def test_a_float_seeded_by_hand_converts_through_its_decimal_string(self):
        # An IN OUT bind can be seeded and read back before the server writes
        # one. Decimal(8.55) is the exact binary value, which reads as
        # 8.5500000000000007105427357601001858711242675781250; going through the
        # string gives what was seeded.
        var = Var(Decimal)
        var.setvalue(0, 8.55)
        self.assertEqual(var.getvalue(), Decimal('8.55'))

    def test_null_stays_none(self):
        self.assertEqual(_received(Var(float), [None]), [None])
        self.assertIsNone(_received(Var(float), None))


class TestAPythonTypeNamesItsDatabaseType(unittest.TestCase):
    def test_bool_is_a_boolean(self):
        # It was refused, "unsupported var() type"; python-oracledb's
        # var(bool) is a DB_TYPE_BOOLEAN (#2658).
        from seerdb import DB_TYPE_BOOLEAN

        self.assertIs(Var(bool).dbtype, DB_TYPE_BOOLEAN)
        self.assertIsNot(Var(int).dbtype, DB_TYPE_BOOLEAN)

    def test_datetime_is_a_timestamp(self):
        # It was a DATE, which dropped an OUT value's microseconds; python-
        # oracledb's var(datetime) is a TIMESTAMP (#2658). A date stays a DATE.
        from seerdb import DB_TYPE_DATE, DB_TYPE_TIMESTAMP

        self.assertIs(Var(datetime.datetime).dbtype, DB_TYPE_TIMESTAMP)
        self.assertIs(Var(datetime.date).dbtype, DB_TYPE_DATE)


class TestNonNumericVarsAreUntouched(unittest.TestCase):
    """Every other type has a database type of its own, which already decides."""

    def test_text_and_bytes(self):
        self.assertEqual(_received(Var(str), ['text']), ['text'])
        self.assertEqual(_received(Var(bytes), [b'raw']), [b'raw'])

    def test_temporal(self):
        when = datetime.datetime(2026, 9, 4, 12, 30)
        self.assertEqual(_received(Var(datetime.datetime), [when]), [when])

    def test_a_value_of_an_unexpected_type_passes_through(self):
        # The coercion only claims numbers. Anything else is handed back as it
        # arrived rather than being forced through float().
        marker = object()
        self.assertIs(_received(Var(float), marker), marker)


if __name__ == '__main__':
    unittest.main()
