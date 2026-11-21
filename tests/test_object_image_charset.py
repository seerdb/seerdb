# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""An object's or a collection's image holds its text in the database's charset.

The session's charset -- AL32UTF8 from 9i on, WE8ISO8859P1 on 8i -- is what a
VARCHAR2 column comes back in, but an image carries its text as the database
stores it. On the 8i and 9i beds, both WE8ISO8859P1 databases, `SELECT
seerdb_t8i('café'), seerdb_t8j('café') FROM dual` -- an object of `(s
VARCHAR2(20))` and a VARRAY of VARCHAR2(20) -- sends `84 01 08 04 63 61 66 e9`
and `88 01 0c 01 01 00 01 04 63 61 66 e9`, where 10g, 11g and 23ai (AL32UTF8)
send `63 61 66 c3 a9`. Read as UTF-8, the attribute and the element came back
`'caf\\ufffd'`. And an object bound with `'café'` went in as UTF-8: 9.2 and
8.1.7 stored it as five characters, `'cafÃ©'`.

The connection knows the database's charset from its login (TTI_PRO): it reads
an image in it and stamps the types it describes with it
(`DbObjectType.db_charset`), which the image encoder writes their text in.
"""

import asyncio
import unittest

from seerdb.client._conn_logic import _ConnectionLogic
from seerdb.client.acursor import AsyncCursor
from seerdb.client.cursor import _resolve_objects
from seerdb.common.dbobject import DbObjectType, ObjectImage
from seerdb.common.tns import encode_object_image
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
    ISO_LATIN_1_CHARSET,
    TNS_TYPE_VARCHAR,
)


def _types(db_charset=None):
    obj = DbObjectType(
        'SYSTEM',
        'SEERDB_T8I',
        bytes.fromhex('65a16aaa6a9649bf8104434c957f3e09'),
        1,
        [{'name': 'S', 'data_type': TNS_TYPE_VARCHAR}],
    )
    varray = DbObjectType(
        'SYSTEM',
        'SEERDB_T8J',
        bytes.fromhex('b03164cc19da43b2baa794df855fda80'),
        1,
        [],
        is_collection=True,
        element={'name': 'element', 'data_type': TNS_TYPE_VARCHAR},
        max_elements=3,
    )
    obj.db_charset = varray.db_charset = db_charset
    return (obj, varray)


# The images 8.1.7 and 9.2 send (WE8ISO8859P1), and 23ai's (AL32UTF8).
_LATIN_1 = (
    bytes.fromhex('84010804636166e9'),
    bytes.fromhex('88010c0101000104636166e9'),
)
_UTF_8 = (
    bytes.fromhex('84010905636166c3a9'),
    bytes.fromhex('88010d0101000105636166c3a9'),
)


class _Conn(_ConnectionLogic):
    def __init__(self, server_charset):
        self._server_charset = server_charset
        self._types = dict((t.name, t) for t in _types(server_charset))

    def _describe_object_type(self, schema, name):
        return self._types[name]


class _AsyncConn(_Conn):
    async def _describe_object_type(self, schema, name):
        return self._types[name]


def _row(images, types):
    return [
        ObjectImage(t.oid, 'SYSTEM', t.name, 0, image)
        for (image, t) in zip(images, types)
    ]


class ObjectImageCharsetTest(unittest.TestCase):
    def test_a_latin_1_database_s_image_reads_as_latin_1(self):
        conn = _Conn(ISO_LATIN_1_CHARSET)
        (obj, varray) = _resolve_objects(conn, _row(_LATIN_1, _types()))
        self.assertEqual(obj.S, 'café')
        self.assertEqual(varray.aslist(), ['café'])

    def test_a_utf_8_database_s_image_reads_as_utf_8(self):
        for charset in (AL32UTF8_CHARSET, None):
            (obj, varray) = _resolve_objects(_Conn(charset), _row(_UTF_8, _types()))
            self.assertEqual(obj.S, 'café')
            self.assertEqual(varray.aslist(), ['café'])

    def test_the_async_cursor_reads_it_so_too(self):
        cursor = object.__new__(AsyncCursor)
        cursor._connection = _AsyncConn(ISO_LATIN_1_CHARSET)
        ((obj, varray),) = asyncio.run(cursor._resolve_rows([_row(_LATIN_1, _types())]))
        self.assertEqual(obj.S, 'café')
        self.assertEqual(varray.aslist(), ['café'])

    def test_a_bound_image_writes_the_type_s_database_charset(self):
        # The text and its length as the server's image has them; seerdb's
        # header is the long form, so only the tail is compared.
        for charset, text in (
            (ISO_LATIN_1_CHARSET, b'\x04caf\xe9'),
            (None, b'\x05caf\xc3\xa9'),
        ):
            (obj_type, varray_type) = _types(charset)
            self.assertTrue(
                encode_object_image(obj_type.newobject({'S': 'café'})).endswith(text)
            )
            self.assertTrue(
                encode_object_image(varray_type.newobject(['café'])).endswith(text)
            )

    def test_a_nested_member_writes_its_parent_s_charset(self):
        # A nested type the connection never stamped takes its parent's.
        (inner, varray) = _types()
        outer = DbObjectType(
            'SYSTEM',
            'SEERDB_T8O',
            bytes(16),
            1,
            [
                {'name': 'O', 'data_type': 109, 'object_type': inner},
                {'name': 'L', 'data_type': 122, 'object_type': varray},
            ],
        )
        outer.db_charset = ISO_LATIN_1_CHARSET
        value = outer.newobject(
            {'O': inner.newobject({'S': 'café'}), 'L': varray.newobject(['café'])}
        )
        image = encode_object_image(value)
        self.assertEqual(image.count(b'\x04caf\xe9'), 2)
        self.assertNotIn(b'\xc3\xa9', image)


if __name__ == '__main__':
    unittest.main()
