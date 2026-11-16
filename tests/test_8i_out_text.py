# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""An 8i OUT bind's text is WE8ISO8859P1, as a fetched row's is.

seerdb's 8i descriptor declares a character bind's charset as WE8ISO8859P1
(31), and 8.1.7 converts an OUT value to it: `BEGIN :1 := 'caf' || CHR(233);
END;` returns `63 61 66 e9`. The cursor read it as UTF-8, the session charset of
9i and later, and `'café'` came back `'caf\\ufffd'`, where a SELECT of the same
expression read `'café'`. A RETURNING's text on 8i, which comes back as the OUT
binds of the PL/SQL block it runs as, read the same way.
"""

import unittest

import seerdb
from seerdb.client.cursor import _assign_out_binds, _assign_return_binds
from seerdb.client.dialect import Fv2Dialect, O8iDialect
from seerdb.common.datatypes import Var


def _result(*values):
    record = {'out_positions': list(range(len(values))), 'out_values': list(values)}
    return (0, 0, 0, (None, None), [record], None, None, [], None)


class _Conn:
    def __init__(self, dialect):
        self._dialect = object.__new__(dialect)


class EightIOutTextTest(unittest.TestCase):
    def test_8i_out_text_is_latin_1(self):
        out = Var(seerdb.DB_TYPE_VARCHAR, 20)
        _assign_out_binds([out], _result(b'caf\xe9'), _Conn(O8iDialect))
        self.assertEqual(out.getvalue(), 'café')

    def test_an_8i_array_s_elements_are_latin_1(self):
        out = Var(seerdb.DB_TYPE_VARCHAR, 20, is_array=True, num_elements=2)
        out._value = []
        array = {'_array': True, 'values': [b'na\xefve', b'']}
        _assign_out_binds([out], _result(array), _Conn(O8iDialect))
        self.assertEqual(out.getvalue(), ['naïve', None])

    def test_an_8i_returning_s_text_is_latin_1(self):
        out = Var(seerdb.DB_TYPE_VARCHAR, 20)
        record = {'return_positions': [0], 'return_values': [[b'na\xefve']]}
        result = (0, 0, 0, (None, None), [record], None, None, [], None)
        _assign_return_binds([out], result, _Conn(O8iDialect))
        self.assertEqual(out.getvalue(), ['naïve'])

    def test_9i_out_text_stays_utf_8(self):
        out = Var(seerdb.DB_TYPE_VARCHAR, 20)
        _assign_out_binds([out], _result('café'.encode()), _Conn(Fv2Dialect))
        self.assertEqual(out.getvalue(), 'café')


if __name__ == '__main__':
    unittest.main()
