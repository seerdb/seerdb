# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for decoding SQL OBJECT (ADT) values (#115).
#
# The wire bytes are not invented: they were captured from a live Oracle 21c
# (XEPDB1) selecting `addr` from a table whose column is
# ADDR_T(street VARCHAR2(40), zip NUMBER, code CHAR(2)) holding the row
# ('Main St', 12345, 'US'). The object value framing (read_dbobject) and the
# packed image are identical across 10g/11g/21c/23ai (fv 4/6/16/24), verified
# live, so a single fixture exercises every tier.

import struct
import unittest

from seerdb.common.dbobject import (
    COLLECTION_NESTED_TABLE,
    COLLECTION_PLSQL_INDEX_TABLE,
    COLLECTION_VARRAY,
    DbObject,
    DbObjectType,
    DbRef,
    ObjectImage,
    decode_collection_image,
    decode_collection_keyed,
    decode_object_image,
    decode_xmltype,
    lob_attribute_csfrm,
    map_object_lobs,
    served_lob_content,
    type_name_to_tns,
)
from seerdb.common.exceptions import NotSupportedError, ProgrammingError
from seerdb.common.lob import LOB
from seerdb.common.tns import (
    _DECODE_FIELD_VERSION,
    _ENCODE_FIELD_VERSION,
    _THIN_LOB_LOCATOR,
    _THIN_OBJ_LOB_LOCATOR,
    ColumnMeta,
    LobEmitLog,
    _bytes_with_length,
    _encode_object_bind_value,
    _encode_ref_bind_value,
    _encode_ref_oac,
    _read_bind_value,
    _read_chunked_bytes,
    _read_object_column,
    _skip_chunked_bytes,
    encode_object_column_value,
    encode_object_image,
    encode_sb4,
    mint_column_lob_locator,
    object_lob_contents,
)
from seerdb.common.tns_consts import (
    AL16UTF16_CHARSET,
    AL32UTF8_CHARSET,
    FIELD_VERSION_11_2,
    FIELD_VERSION_12_1,
    TNS_TYPE_ADT,
    TNS_TYPE_BLOB,
    TNS_TYPE_CHAR,
    TNS_TYPE_CLOB,
    TNS_TYPE_NUMBER,
    TNS_TYPE_REF,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_VARCHAR,
)
from seerdb.common.types import decode_value

# The full on-wire object column value for ('Main St', 12345, 'US') plus four
# trailing bytes (the start of the next row) used as a desync sentinel.
_OBJ_COLUMN = bytes.fromhex(
    '01 24 24 00 22 02 08 54 88 dc 42 c0 05 09 31 e0 63 c0 00 a8 c0 9d 0b'
    '00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 01 00 00 00 01 13'
    '01 01 13'
    '84 01 13 07 4d 61 69 6e 20 53 74 04 c3 02 18 2e 02 55 53'
    '08 01 06 03'.replace(' ', '')
)
_SENTINEL = bytes.fromhex('08010603')

# Just the packed image (header + attributes), as read_dbobject would hand it
# to the image walk.
_IMAGE = bytes.fromhex('840113074d61696e20537404c302182e025553')

_ADDR_LAYOUT = [
    {'name': 'STREET', 'data_type': TNS_TYPE_VARCHAR, 'charset': None},
    {'name': 'ZIP', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
    {'name': 'CODE', 'data_type': TNS_TYPE_CHAR, 'charset': None},
]


class TestObjectColumnFraming(unittest.TestCase):
    def test_read_object_column_keeps_stream_in_sync(self):
        Col = {'type_schema': 'PYO', 'type_name': 'ADDR_T', 'charset': 0}
        (Val, Rest) = _read_object_column(_OBJ_COLUMN, Col)
        self.assertIsInstance(Val, ObjectImage)
        self.assertEqual(Val.image, _IMAGE)
        self.assertEqual(Val.type_schema, 'PYO')
        self.assertEqual(Val.type_name, 'ADDR_T')
        # Exactly the object value is consumed; the next row's bytes remain.
        self.assertEqual(Rest, _SENTINEL)

    def test_null_object_consumes_no_image(self):
        # A NULL object: framing present but a zero image-gate, no image blob.
        # toid(empty) oid(empty) snapshot(empty) version(0) gate(0) flags(0).
        Null = bytes.fromhex('00 00 00 00 00 00'.replace(' ', '')) + _SENTINEL
        (Val, Rest) = _read_object_column(Null, {})
        self.assertIsNone(Val)
        self.assertEqual(Rest, _SENTINEL)


class TestImageWalk(unittest.TestCase):
    def test_decode_addr_image(self):
        Attrs = decode_object_image(_IMAGE, _ADDR_LAYOUT)
        self.assertEqual(Attrs, [('STREET', 'Main St'), ('ZIP', 12345), ('CODE', 'US')])

    def test_null_attribute(self):
        # STREET NULL (length 0), ZIP 12345, CODE 'US'.
        Image = bytes.fromhex('8401130004c302182e025553')
        Attrs = decode_object_image(Image, _ADDR_LAYOUT)
        self.assertEqual(Attrs, [('STREET', None), ('ZIP', 12345), ('CODE', 'US')])


class TestDbObjectApi(unittest.TestCase):
    def setUp(self):
        Attrs = decode_object_image(_IMAGE, _ADDR_LAYOUT, AL32UTF8_CHARSET)
        self.obj = DbObject('PYO.ADDR_T', Attrs)

    def test_attribute_access(self):
        self.assertEqual(self.obj.STREET, 'Main St')
        self.assertEqual(self.obj.ZIP, 12345)
        self.assertEqual(self.obj.CODE, 'US')

    def test_item_access_and_views(self):
        self.assertEqual(self.obj['ZIP'], 12345)
        self.assertEqual(self.obj.aslist(), ['Main St', 12345, 'US'])
        self.assertEqual(
            self.obj.asdict(), {'STREET': 'Main St', 'ZIP': 12345, 'CODE': 'US'}
        )
        self.assertEqual(self.obj.type_name, 'PYO.ADDR_T')

    def test_unknown_attribute_raises(self):
        with self.assertRaises(AttributeError):
            _ = self.obj.NOPE

    def test_equality_and_repr(self):
        Twin = DbObject('PYO.ADDR_T', decode_object_image(_IMAGE, _ADDR_LAYOUT))
        self.assertEqual(self.obj, Twin)
        self.assertIn("STREET='Main St'", repr(self.obj))


_ADDR_TYPE = DbObjectType(
    'PYO', 'ADDR_T', bytes.fromhex('00112233445566778899aabbccddeeff'), 1, _ADDR_LAYOUT
)


class TestNationalAttribute(unittest.TestCase):
    # An NVARCHAR2 / NCHAR attribute is AL16UTF16 in the object image, as in a
    # column; the client learns which attributes are national from their
    # CHARACTER_SET_NAME (#1433). The live check that the server stores what
    # this writes is NationalAttributeIntegration's LENGTH(x.o.v).

    LAYOUT = [
        {'name': 'V', 'data_type': TNS_TYPE_VARCHAR, 'charset': AL16UTF16_CHARSET},
        {'name': 'W', 'data_type': TNS_TYPE_VARCHAR, 'charset': None},
    ]
    TYPE = DbObjectType('PYO', 'NAT_T', bytes(16), 1, LAYOUT)

    def test_the_national_form_comes_from_the_character_set_name(self):
        from seerdb.common.dbobject import national_charset

        self.assertEqual(national_charset('NCHAR_CS'), AL16UTF16_CHARSET)
        self.assertIsNone(national_charset('CHAR_CS'))
        self.assertIsNone(national_charset(None))

    def test_a_national_attribute_is_written_and_read_as_al16utf16(self):
        text = 'ko\u010dka \u4e2d'
        image = encode_object_image(self.TYPE.newobject({'V': text, 'W': text}))
        self.assertIn(text.encode('utf-16-be'), image)  # V
        self.assertIn(text.encode('utf-8'), image)  # W, the session's
        self.assertEqual(
            decode_object_image(image, self.LAYOUT), [('V', text), ('W', text)]
        )


class TestObjectBindEncode(unittest.TestCase):
    # The bind encode writes the image length long-form (0xFE + ub4), while the
    # server sends it short-form, so the encoder isn't byte-equal to a captured
    # image; the contract is that it round-trips back through the #115 decoders.

    def test_image_encode_decode_roundtrip(self):
        Obj = _ADDR_TYPE.newobject({'STREET': 'Main St', 'ZIP': 12345, 'CODE': 'US'})
        Image = encode_object_image(Obj)
        self.assertEqual(
            decode_object_image(Image, _ADDR_LAYOUT),
            [('STREET', 'Main St'), ('ZIP', 12345), ('CODE', 'US')],
        )

    def test_image_encode_null_attribute(self):
        Obj = _ADDR_TYPE.newobject({'STREET': None, 'ZIP': 7, 'CODE': None})
        Attrs = decode_object_image(encode_object_image(Obj), _ADDR_LAYOUT)
        self.assertEqual(Attrs, [('STREET', None), ('ZIP', 7), ('CODE', None)])

    def test_bind_value_framing_roundtrips(self):
        # The full write_dbobject framing must parse back through the row
        # decoder (with the next-row sentinel preserved).
        Obj = _ADDR_TYPE.newobject({'STREET': 'Main St', 'ZIP': 12345, 'CODE': 'US'})
        Wire = _encode_object_bind_value(Obj) + _SENTINEL
        Col = {'type_schema': 'PYO', 'type_name': 'ADDR_T', 'charset': 0}
        (Val, Rest) = _read_object_column(Wire, Col)
        self.assertIsInstance(Val, ObjectImage)
        self.assertEqual(Rest, _SENTINEL)
        self.assertEqual(
            decode_object_image(Val.image, _ADDR_LAYOUT),
            [('STREET', 'Main St'), ('ZIP', 12345), ('CODE', 'US')],
        )

    def test_bind_value_carries_type_oid(self):
        # The bind toid wraps the type's 16-byte OID (00 22 02 08 + oid + extent).
        Obj = _ADDR_TYPE.newobject()
        Wire = _encode_object_bind_value(Obj)
        # toid = 00 22 02 08 + the 16-byte type OID + the fixed extent OID.
        self.assertIn(b'\x00\x22\x02\x08' + _ADDR_TYPE.oid, Wire)

    def test_read_bind_value_decodes_inbound_object(self):
        # The server reads an inbound object (ADT) bind the same framing the
        # client writes (#888): _read_bind_value hands back an ObjectImage the
        # backend resolves + decodes. The next bind's bytes stay untouched.
        from seerdb.common.tns_consts import TNS_TYPE_ADT

        Obj = _ADDR_TYPE.newobject({'STREET': 'Main St', 'ZIP': 12345, 'CODE': 'US'})
        Wire = _encode_object_bind_value(Obj) + _SENTINEL
        Val, Rest = _read_bind_value(TNS_TYPE_ADT, 0, Wire, _ADDR_TYPE.oid)
        self.assertIsInstance(Val, ObjectImage)
        self.assertEqual(Rest, _SENTINEL)
        self.assertEqual(
            decode_object_image(Val.image, _ADDR_LAYOUT),
            [('STREET', 'Main St'), ('ZIP', 12345), ('CODE', 'US')],
        )

    def test_read_bind_value_null_object_is_none(self):
        # A NULL object bind carries the full frame with a zero image gate, and
        # reads back as None (the backend then binds a typed NULL).
        from seerdb.common.tns_consts import TNS_TYPE_ADT

        Wire = encode_object_column_value(None, _ADDR_TYPE.oid) + _SENTINEL
        Val, Rest = _read_bind_value(TNS_TYPE_ADT, 0, Wire, _ADDR_TYPE.oid)
        self.assertIsNone(Val)
        self.assertEqual(Rest, _SENTINEL)


class TestObjectColumnValueEncode(unittest.TestCase):
    # The Mirror re-encoding a fetched object as an RXD column value (#116). The
    # populated frame is the write_dbobject framing (verified to round-trip); the
    # NULL frame is byte-checked against a live 23ai capture: an object column
    # still carries the full toid + zero image-length gate, never a bare 0x00.

    # `select cast(null as ADDR_T)` on 23ai: the toid (00 22 02 08 + type OID +
    # extent OID), empty object OID, zero snapshot/version, a zero image-length
    # gate (=> NULL, no image), and the TOP_LEVEL flags. No packed image follows.
    _NULL_COLUMN = bytes.fromhex(
        '01 24 24 00 22 02 08 00112233445566778899aabbccddeeff'
        '00000000000000000000000000010001 00 00 00 00 01 01'.replace(' ', '')
    )

    def test_populated_column_value_roundtrips(self):
        Obj = _ADDR_TYPE.newobject({'STREET': 'Main St', 'ZIP': 12345, 'CODE': 'US'})
        Wire = encode_object_column_value(Obj, _ADDR_TYPE.oid) + _SENTINEL
        Col = {'type_schema': 'PYO', 'type_name': 'ADDR_T', 'charset': 0}
        (Val, Rest) = _read_object_column(Wire, Col)
        self.assertIsInstance(Val, ObjectImage)
        self.assertEqual(Rest, _SENTINEL)
        self.assertEqual(
            decode_object_image(Val.image, _ADDR_LAYOUT),
            [('STREET', 'Main St'), ('ZIP', 12345), ('CODE', 'US')],
        )

    def test_null_column_value_matches_capture(self):
        self.assertEqual(
            encode_object_column_value(None, _ADDR_TYPE.oid), self._NULL_COLUMN
        )

    def test_null_column_value_keeps_stream_in_sync(self):
        Wire = encode_object_column_value(None, _ADDR_TYPE.oid) + _SENTINEL
        (Val, Rest) = _read_object_column(Wire, {'charset': 0})
        self.assertIsNone(Val)
        self.assertEqual(Rest, _SENTINEL)

    def test_null_without_type_oid_still_decodes(self):
        # With no column type OID the frame carries an empty toid; it must still
        # decode to NULL and leave the following row untouched.
        Wire = encode_object_column_value(None) + _SENTINEL
        (Val, Rest) = _read_object_column(Wire, {'charset': 0})
        self.assertIsNone(Val)
        self.assertEqual(Rest, _SENTINEL)


class TestObjectVar(unittest.TestCase):
    # cursor.var() of an object type (#888): the Var carries the DbObjectType, so
    # an object OUT bind and a typed-NULL object bind announce their type in the
    # OAC and read back as a DbObject.

    def test_var_accepts_object_type(self):
        from seerdb.common.datatypes import Var

        var = Var(_ADDR_TYPE)
        self.assertEqual(var.dbtype.tns_type, TNS_TYPE_ADT)
        self.assertIs(var.dbtype, _ADDR_TYPE)

    def test_var_object_oac_carries_type_oid(self):
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import encode_token_oac

        _ENCODE_FIELD_VERSION.set(24)
        try:
            oac = encode_token_oac(Var(_ADDR_TYPE))
        finally:
            _ENCODE_FIELD_VERSION.set(6)
        self.assertEqual(oac[0], TNS_TYPE_ADT)
        self.assertIn(_ADDR_TYPE.oid, oac)

    def test_unseeded_object_var_binds_typed_null_frame(self):
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import encode_token_rxd

        wire = encode_token_rxd(Var(_ADDR_TYPE))  # no setvalue -> NULL object
        self.assertNotEqual(wire, bytes([0]))  # not the bare scalar NULL DALC
        (val, rest) = _read_object_column(
            wire + _SENTINEL, {'type_oid': _ADDR_TYPE.oid}
        )
        self.assertIsNone(val)
        self.assertEqual(rest, _SENTINEL)

    def test_object_out_bind_round_trips(self):
        from seerdb.client.cursor import _object_from_out_image
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import (
            ScalarOutBind,
            _read_iov,
            encode_out_bind_response_thin,
        )

        Obj = _ADDR_TYPE.newobject({'STREET': 'Main St', 'ZIP': 12345, 'CODE': 'US'})
        reply = encode_out_bind_response_thin(
            [ScalarOutBind(value=Obj, tns_type=TNS_TYPE_ADT)]
        )
        _, out_values, _ = _read_iov(reply, [Var(_ADDR_TYPE)])
        self.assertIsInstance(out_values[0], ObjectImage)
        back = _object_from_out_image(out_values[0], _ADDR_TYPE)
        self.assertEqual(back.aslist(), ['Main St', 12345, 'US'])


class TestTypeNameSplitting(unittest.TestCase):
    # How `gettype` reads a type name (#1030). One to three parts: TYPE,
    # SCHEMA.TYPE or PACKAGE.TYPE, and OWNER.PACKAGE.TYPE for a PL/SQL package
    # type -- which is why the old two-part split could not express one at all.

    def test_one_two_and_three_part_names(self):
        from seerdb.client.connection import _split_type_name

        self.assertEqual(_split_type_name('ADDR_T'), ['ADDR_T'])
        self.assertEqual(_split_type_name('PYO.ADDR_T'), ['PYO', 'ADDR_T'])
        self.assertEqual(_split_type_name('PYO.PKG.UDT'), ['PYO', 'PKG', 'UDT'])

    def test_a_rowtype_name_is_its_table_and_schema(self):
        # `T%ROWTYPE` and `SCHEMA.T%ROWTYPE`, any case, name a table's record
        # type (#1476); anything else is no record-type name.
        from seerdb.client.connection import _rowtype_name

        self.assertEqual(_rowtype_name('t%rowtype'), (None, 'T'))
        self.assertEqual(_rowtype_name('pyo.T%ROWTYPE'), ('PYO', 'T'))
        self.assertEqual(_rowtype_name('"Mixed"%ROWTYPE'), (None, 'Mixed'))
        self.assertIsNone(_rowtype_name('PYO.ADDR_T'))
        self.assertIsNone(_rowtype_name('A.B.C%ROWTYPE'))

    def test_a_dot_inside_a_quoted_identifier_is_not_a_separator(self):
        # Oracle allows a quoted identifier to contain a dot; splitting on it
        # would look up a package that does not exist.
        from seerdb.client.connection import _split_type_name

        self.assertEqual(_split_type_name('"my.type"'), ['"my.type"'])
        self.assertEqual(_split_type_name('PYO."my.type"'), ['PYO', '"my.type"'])

    def test_an_unquoted_part_is_upper_cased_and_a_quoted_one_is_not(self):
        from seerdb.client.connection import _normalise_type_part

        self.assertEqual(_normalise_type_part('addr_t'), 'ADDR_T')
        self.assertEqual(_normalise_type_part('"addr_t"'), 'addr_t')

    def test_a_package_type_reports_its_package_in_full_name(self):
        # The package is part of the identity -- two packages may each declare a
        # UDT_RECORD -- and python-oracledb reports it the same way.
        typ = DbObjectType('PYO', 'UDT_REC', bytes(16), 1, [], package_name='PKG_A')
        self.assertEqual(typ.full_name, 'PYO.PKG_A.UDT_REC')
        self.assertEqual(typ.name, 'UDT_REC')
        self.assertIsNone(_ADDR_TYPE.package_name)
        self.assertEqual(_ADDR_TYPE.full_name, 'PYO.ADDR_T')


class TestBareObjectOutBind(unittest.TestCase):
    # An object passed to callproc / execute WITHOUT a Var around it (#1029).
    # `cursor.callproc(name, (3, obj))` is how python-oracledb is normally
    # called, and recognising only the Var form sent the bare object down the
    # plain-DALC branch: the object frame's 36-byte toid was read as a length
    # and the reply desynced onto that toid's own `00 22 02 08` prefix, reported
    # as "no decoder for response token 34".

    def _reply(self, value):
        from seerdb.common.tns import ScalarOutBind, encode_out_bind_response_thin

        return encode_out_bind_response_thin(
            [ScalarOutBind(value=value, tns_type=TNS_TYPE_ADT)]
        )

    def test_a_bare_object_is_recognised_as_an_object_bind(self):
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import _is_object_bind, _object_bind_type

        obj = _ADDR_TYPE.newobject({'STREET': 'Main St', 'ZIP': 1, 'CODE': 'US'})
        self.assertTrue(_is_object_bind(obj))
        self.assertIs(_object_bind_type(obj), _ADDR_TYPE)
        # The Var form keeps working, and a plain value is still not one.
        self.assertTrue(_is_object_bind(Var(_ADDR_TYPE)))
        self.assertFalse(_is_object_bind('a string'))
        self.assertFalse(_is_object_bind(Var(int)))

    def test_a_bare_object_out_value_reads_as_the_object_frame(self):
        from seerdb.client.cursor import _object_from_out_image
        from seerdb.common.datatypes import Var
        from seerdb.common.tns import (
            ScalarOutBind,
            _read_iov,
            encode_out_bind_response_thin,
        )
        from seerdb.common.tns_consts import TNS_TYPE_NUMBER

        sent = _ADDR_TYPE.newobject({'STREET': 'Main St', 'ZIP': 12345, 'CODE': 'US'})
        # A SECOND bind behind the object is the real check: the frame has to
        # consume exactly its own bytes, and a mis-measurement shows up as the
        # next value being garbage (or a bogus token) rather than a wrong one.
        reply = encode_out_bind_response_thin(
            [
                ScalarOutBind(value=sent, tns_type=TNS_TYPE_ADT),
                ScalarOutBind(value=4242, tns_type=TNS_TYPE_NUMBER),
            ]
        )
        # The bind list holds the object ITSELF, as callproc leaves it.
        _, out_values, _ = _read_iov(reply, [sent, Var(int)])
        self.assertIsInstance(out_values[0], ObjectImage)
        back = _object_from_out_image(out_values[0], _ADDR_TYPE)
        self.assertEqual(back.aslist(), ['Main St', 12345, 'US'])
        self.assertTrue(out_values[1])  # the bind behind it survived

    def test_the_out_value_lands_in_the_caller_s_own_object(self):
        # python-oracledb mutates the object the caller passed; a new DbObject
        # built beside it would leave the caller looking at an empty one.
        from seerdb.client.cursor import _assign_out_binds

        target = _ADDR_TYPE.newobject()
        record = {'out_positions': [0], 'out_values': [None]}
        sent = _ADDR_TYPE.newobject({'STREET': 'Main St', 'ZIP': 12345, 'CODE': 'US'})
        from seerdb.common.tns import _read_iov

        _, out_values, _ = _read_iov(self._reply(sent), [target])
        record['out_values'] = out_values
        _assign_out_binds([target], (None, None, None, None, [record]))
        self.assertEqual(target.aslist(), ['Main St', 12345, 'US'])

    def test_a_null_out_value_empties_the_caller_s_object(self):
        # A NULL object OUT must not leave the INPUT half of an IN OUT bind
        # behind, which reads as a successful no-op.
        from seerdb.client.cursor import _assign_out_binds
        from seerdb.common.tns import _read_iov

        target = _ADDR_TYPE.newobject({'STREET': 'Old St', 'ZIP': 1, 'CODE': 'GB'})
        _, out_values, _ = _read_iov(self._reply(None), [target])
        record = {'out_positions': [0], 'out_values': out_values}
        _assign_out_binds([target], (None, None, None, None, [record]))
        self.assertEqual(target.aslist(), [None, None, None])


class TestNestedObjectImageEncode(unittest.TestCase):
    # The recursive image encoder (#116/#117/#118), the inverse of the nested
    # decode (#920): an object attribute of an object rides inline (no header), a
    # NULL nested object is the atomic-null 0xFD, and an object inside a
    # collection is a length-prefixed full image. Synthetic types (the framing is
    # layout-independent), each encode round-tripped back through the decoder.
    _SUB_LAYOUT = [
        {'name': 'N', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
        {'name': 'S', 'data_type': TNS_TYPE_VARCHAR, 'charset': None},
    ]
    _SUB_TYPE = DbObjectType('PYO', 'SUB_T', bytes.fromhex('aa' * 16), 1, _SUB_LAYOUT)
    _NEST_LAYOUT = [
        {'name': 'ID', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
        {
            'name': 'SUB',
            'data_type': TNS_TYPE_ADT,
            'charset': None,
            'object_type': _SUB_TYPE,
        },
    ]
    _NEST_TYPE = DbObjectType(
        'PYO', 'NEST_T', bytes.fromhex('bb' * 16), 1, _NEST_LAYOUT
    )
    _ARR_TYPE = DbObjectType(
        'PYO',
        'ARR_T',
        bytes.fromhex('cc' * 16),
        1,
        [],
        is_collection=True,
        collection_type=COLLECTION_VARRAY,
        element={
            'data_type': TNS_TYPE_ADT,
            'charset': None,
            'object_type': _SUB_TYPE,
        },
    )

    def test_nested_object_roundtrips(self):
        Sub = self._SUB_TYPE.newobject({'N': 9, 'S': 'sub'})
        Obj = self._NEST_TYPE.newobject({'ID': 1, 'SUB': Sub})
        Attrs = dict(decode_object_image(encode_object_image(Obj), self._NEST_LAYOUT))
        self.assertEqual(Attrs['ID'], 1)
        self.assertEqual((Attrs['SUB'].N, Attrs['SUB'].S), (9, 'sub'))

    def test_nested_null_object_is_atomic_null(self):
        Obj = self._NEST_TYPE.newobject({'ID': 2, 'SUB': None})
        # The NULL nested object rides as the single atomic-null byte 0xFD.
        Image = encode_object_image(Obj)
        self.assertIn(bytes([0xFD]), Image)
        Attrs = dict(decode_object_image(Image, self._NEST_LAYOUT))
        self.assertEqual(Attrs['ID'], 2)
        self.assertIsNone(Attrs['SUB'])

    def test_collection_of_objects_roundtrips(self):
        Els = [
            self._SUB_TYPE.newobject({'N': 1, 'S': 'a'}),
            self._SUB_TYPE.newobject({'N': 2, 'S': 'b'}),
        ]
        Coll = self._ARR_TYPE.newobject(Els)
        Out = decode_collection_image(encode_object_image(Coll), self._ARR_TYPE.element)
        self.assertEqual([(e.N, e.S) for e in Out], [(1, 'a'), (2, 'b')])


class TestRefBindEncode(unittest.TestCase):
    # REF bind (#139). Byte fixtures captured from the Oracle JDBC thin driver
    # binding a fetched REF back (oracledb has no REF type, so JDBC is the only
    # reference) on 23ai: person_t REF for ('Alice'), bound into DEREF(?).
    _OID = bytes.fromhex('54b3dec71d796414e063c000a8c01de8')
    _LOCATOR = bytes.fromhex(
        '0028020954b3dec71d7f6414e063c000a8c01de8'
        '54b3dec71d7e6414e063c000a8c01de800017afb0000'
    )
    _CAP_OAC = bytes.fromhex(
        '6f030000020fa0000001101054b3dec71d796414e063c000a8c01de801010102000000'
    )
    _CAP_VAL = bytes.fromhex(
        '2a0028020954b3dec71d7f6414e063c000a8c01de8'
        '54b3dec71d7e6414e063c000a8c01de800017afb0000'
    )

    def setUp(self):
        _ENCODE_FIELD_VERSION.set(24)

    def tearDown(self):
        _ENCODE_FIELD_VERSION.set(6)

    def _ref(self, oid=None):
        return DbRef(
            self._LOCATOR, 'PERSON_T', 'PYO', self._OID if oid is None else oid
        )

    def test_oac_matches_jdbc_capture(self):
        self.assertEqual(_encode_ref_oac(self._ref()), self._CAP_OAC)

    def test_value_is_length_prefixed_locator(self):
        self.assertEqual(_encode_ref_bind_value(self._ref()), self._CAP_VAL)

    def test_oac_carries_referenced_type_oid(self):
        self.assertIn(self._OID, _encode_ref_oac(self._ref()))
        self.assertEqual(_encode_ref_oac(self._ref())[0], TNS_TYPE_REF)

    def test_bind_without_oid_rejected(self):
        # A DbRef lacking the type OID (e.g. a describe that didn't carry it)
        # cannot build the bind OAC.
        with self.assertRaises(NotSupportedError):
            _encode_ref_oac(DbRef(self._LOCATOR, 'PERSON_T'))


class TestPreTwelveObjectBindRefusal(unittest.TestCase):
    # Below 10g's thin session an object bind is refused up front, the server
    # answering it with a fatal ORA-03106 (#116) -- an object value, and an
    # object or collection Var, the OUT bind, which got through and lost the
    # connection (#2039). A 10g or 11g thin session sends both, without the
    # descriptor's oaccolid (#2704), and so does 12.1.
    def _check(self, field_version, bind):
        from types import SimpleNamespace

        from seerdb.client.cursor import _check_object_bind_support

        _check_object_bind_support(SimpleNamespace(field_version=field_version), bind)

    def test_object_binds_are_refused_below_10g(self):
        from seerdb.common.datatypes import Var
        from seerdb.common.tns_consts import FIELD_VERSION_9_2

        for bind in (
            [_ADDR_TYPE.newobject()],
            [Var(_ADDR_TYPE)],
            {'o': Var(_ADDR_TYPE)},
        ):
            with self.subTest(bind=bind), self.assertRaises(NotSupportedError):
                self._check(FIELD_VERSION_9_2, bind)

    def test_object_binds_go_out_on_10g_and_11g_thin_sessions(self):
        from seerdb.common.datatypes import Var
        from seerdb.common.tns_consts import FIELD_VERSION_10_2, FIELD_VERSION_11_2

        for version in (FIELD_VERSION_10_2, FIELD_VERSION_11_2):
            with self.subTest(version=version):
                self._check(version, [_ADDR_TYPE.newobject(), Var(_ADDR_TYPE)])

    def test_object_binds_go_out_from_12_1(self):
        from seerdb.common.datatypes import Var

        self._check(FIELD_VERSION_12_1, [_ADDR_TYPE.newobject(), Var(_ADDR_TYPE)])


class TestDbObjectTypeApi(unittest.TestCase):
    def test_newobject_defaults_null(self):
        Obj = _ADDR_TYPE.newobject()
        self.assertEqual(Obj.aslist(), [None, None, None])
        self.assertIs(Obj._dbtype, _ADDR_TYPE)

    def test_newobject_seed_case_insensitive(self):
        Obj = _ADDR_TYPE.newobject({'street': 'X', 'Zip': 1, 'CODE': 'US'})
        self.assertEqual(Obj.STREET, 'X')
        self.assertEqual(Obj.ZIP, 1)

    def test_set_and_reject_unknown(self):
        Obj = _ADDR_TYPE.newobject()
        Obj.STREET = 'Main'
        self.assertEqual(Obj.STREET, 'Main')
        with self.assertRaises(AttributeError):
            Obj.NOPE = 1
        with self.assertRaises(KeyError):
            Obj['NOPE'] = 1

    def test_seed_from_sequence(self):
        Obj = _ADDR_TYPE.newobject(['Main St', 12345, 'US'])
        self.assertEqual(Obj.aslist(), ['Main St', 12345, 'US'])

    def test_type_repr_and_names(self):
        self.assertEqual(_ADDR_TYPE.full_name, 'PYO.ADDR_T')
        self.assertEqual(_ADDR_TYPE.attr_names, ['STREET', 'ZIP', 'CODE'])


_NUM_VA = DbObjectType(
    'PYO',
    'NUM_VA',
    bytes.fromhex('ffeeddccbbaa99887766554433221100'),
    1,
    [],
    is_collection=True,
    collection_type=COLLECTION_VARRAY,
    element={'name': 'element', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
    max_elements=5,
)


class TestVarrayCollection(unittest.TestCase):
    def test_newobject_list_semantics(self):
        v = _NUM_VA.newobject([10, 20, 30])
        self.assertTrue(v.is_collection)
        self.assertEqual(list(v), [10, 20, 30])
        self.assertEqual(v[1], 20)
        self.assertEqual(len(v), 3)
        v.append(40)
        v.extend([50, 60])
        self.assertEqual(v.aslist(), [10, 20, 30, 40, 50, 60])
        v[0] = 99
        self.assertEqual(v[0], 99)

    def test_empty_and_default(self):
        self.assertEqual(_NUM_VA.newobject().aslist(), [])
        self.assertEqual(_NUM_VA.newobject([]).aslist(), [])

    def test_image_encode_decode_roundtrip(self):
        v = _NUM_VA.newobject([10, 20, 30])
        Image = encode_object_image(v)
        self.assertEqual(decode_collection_image(Image, _NUM_VA.element), [10, 20, 30])

    def test_image_roundtrip_empty_and_null_element(self):
        self.assertEqual(
            decode_collection_image(
                encode_object_image(_NUM_VA.newobject([])), _NUM_VA.element
            ),
            [],
        )
        v = _NUM_VA.newobject([1, None, 3])
        self.assertEqual(
            decode_collection_image(encode_object_image(v), _NUM_VA.element),
            [1, None, 3],
        )

    def test_bind_value_framing_roundtrips(self):
        v = _NUM_VA.newobject([7, 8, 9])
        Wire = _encode_object_bind_value(v) + _SENTINEL
        (Val, Rest) = _read_object_column(Wire, {'charset': 0})
        self.assertIsInstance(Val, ObjectImage)
        self.assertEqual(Rest, _SENTINEL)
        self.assertEqual(decode_collection_image(Val.image, _NUM_VA.element), [7, 8, 9])

    def test_asdict_is_the_index_view_on_a_collection(self):
        # asdict() used to refuse a collection outright. It is now the keyed
        # view python-oracledb gives -- index -> value, positions for a VARRAY
        # (#1035).
        self.assertEqual(_NUM_VA.newobject([7, 8, 9]).asdict(), {0: 7, 1: 8, 2: 9})


class TestNestedTableCollection(unittest.TestCase):
    # A nested table (#118) shares the VARRAY image and bind framing exactly;
    # only collection_type differs (2 vs 3). These lock that in offline.
    _NT = DbObjectType(
        'PYO',
        'NUM_NT',
        bytes.fromhex('0102030405060708090a0b0c0d0e0f10'),
        1,
        [],
        is_collection=True,
        collection_type=COLLECTION_NESTED_TABLE,
        element={'name': 'element', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
    )

    def test_collection_type_is_nested_table(self):
        self.assertEqual(self._NT.collection_type, COLLECTION_NESTED_TABLE)
        self.assertNotEqual(COLLECTION_NESTED_TABLE, COLLECTION_VARRAY)

    def test_image_encode_decode_roundtrip(self):
        v = self._NT.newobject([10, 20, 30])
        self.assertEqual(
            decode_collection_image(encode_object_image(v), self._NT.element),
            [10, 20, 30],
        )

    def test_bind_value_framing_roundtrips(self):
        v = self._NT.newobject([1, None, 3])
        Wire = _encode_object_bind_value(v) + _SENTINEL
        (Val, Rest) = _read_object_column(Wire, {'charset': 0})
        self.assertEqual(Rest, _SENTINEL)
        self.assertEqual(
            decode_collection_image(Val.image, self._NT.element), [1, None, 3]
        )


class TestDbRef(unittest.TestCase):
    # A REF locator captured from a live 21c `SELECT REF(o)` (#119).
    _LOC = bytes.fromhex(
        '00280209548b330e9c292c65e063c000a8c03c4e'
        '548b330e9c282c65e063c000a8c03c4e0300223e0000'
    )

    def test_decode_value_wraps_ref(self):
        v = decode_value({'data_type': TNS_TYPE_REF, 'type_name': 'REF_OBJ'}, self._LOC)
        self.assertIsInstance(v, DbRef)
        self.assertEqual(v.bytes, self._LOC)
        self.assertEqual(v.hex, self._LOC.hex())
        self.assertEqual(v.type_name, 'REF_OBJ')

    def test_null_ref_is_none(self):
        self.assertIsNone(decode_value({'data_type': TNS_TYPE_REF}, b''))

    def test_equality_and_hash(self):
        a = DbRef(self._LOC, 'REF_OBJ')
        b = DbRef(self._LOC, 'OTHER')  # equality is by locator bytes
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertNotEqual(a, DbRef(self._LOC[:-1] + b'\x99'))
        self.assertEqual(len({a, b}), 1)

    def test_repr_includes_type(self):
        self.assertIn('REF_OBJ', repr(DbRef(self._LOC, 'REF_OBJ')))


class TestXmlType(unittest.TestCase):
    # XMLType images captured from live servers (#124).
    # 21c column '<a><b>hi</b></a>' (pretty-printed): header + STRING flag 0x14.
    _INLINE = bytes.fromhex('85011d0100000014') + b'<a>\n  <b>hi</b>\n</a>\n'
    # XMLELEMENT("r", 42): STRING + SKIP_NEXT_4 (flag 0x100414), then a 4-byte
    # skip, then the content.
    _XMLELEMENT = bytes.fromhex('8501150100100414') + bytes(4) + b'<r>42</r>'
    # 11g CLOB-stored column: LOB + legacy-storage bit (flag 0x1020011) -> error.
    _LEGACY_11G = bytes.fromhex('8501080101020011')

    def test_inline_string(self):
        (is_lob, value) = decode_xmltype(self._INLINE)
        self.assertFalse(is_lob)
        self.assertEqual(value, '<a>\n  <b>hi</b>\n</a>\n')

    def test_xmlelement_skip_next_4(self):
        (is_lob, value) = decode_xmltype(self._XMLELEMENT)
        self.assertFalse(is_lob)
        self.assertEqual(value, '<r>42</r>')

    def test_11g_legacy_storage_unsupported(self):
        with self.assertRaises(NotSupportedError):
            decode_xmltype(self._LEGACY_11G)


class TestTypeNameMap(unittest.TestCase):
    def test_known_names(self):
        self.assertEqual(type_name_to_tns('VARCHAR2'), TNS_TYPE_VARCHAR)
        # A precision inside the name, as a table column spells it (#1476).
        from seerdb.common.tns_consts import TNS_TYPE_INTERVALDS, TNS_TYPE_TIMESTAMPTZ

        self.assertEqual(
            type_name_to_tns('TIMESTAMP(6) WITH TIME ZONE'), TNS_TYPE_TIMESTAMPTZ
        )
        self.assertEqual(
            type_name_to_tns('INTERVAL DAY(2) TO SECOND(6)'), TNS_TYPE_INTERVALDS
        )
        self.assertEqual(type_name_to_tns('NUMBER'), TNS_TYPE_NUMBER)
        self.assertEqual(type_name_to_tns('CHAR'), TNS_TYPE_CHAR)

    def test_precision_suffix_stripped(self):
        self.assertEqual(type_name_to_tns('TIMESTAMP(6)'), TNS_TYPE_TIMESTAMP)

    def test_unknown_name_is_none(self):
        # A nested object type (out of scope for #115) yields None, so the
        # attribute decodes to its raw bytes rather than desyncing.
        self.assertIsNone(type_name_to_tns('SOME_NESTED_TYPE'))
        self.assertIsNone(type_name_to_tns(None))


if __name__ == '__main__':
    unittest.main()


class TestNestedObjectDecode(unittest.TestCase):
    """Recursive object-image decode (#117/#118): nested object and collection
    attributes, and the atomic-null (0xFD) marker that precedes a NULL nested
    object -- which the flat decoder mistook for a length of 253 and desynced."""

    @staticmethod
    def _dalc(raw: bytes) -> bytes:
        return bytes([len(raw)]) + raw

    def _num(self, n: int) -> bytes:
        from seerdb.common.tns import encode_token_num

        return self._dalc(encode_token_num(n))

    def _sub_type(self) -> DbObjectType:
        return DbObjectType(
            'T',
            'SUB',
            b'',
            1,
            [
                {'name': 'X', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
                {'name': 'Y', 'data_type': TNS_TYPE_VARCHAR, 'charset': None},
            ],
        )

    def _parent_layout(self, sub: DbObjectType) -> list:
        return [
            {'name': 'A', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
            {'name': 'SUB', 'data_type': None, 'charset': None, 'object_type': sub},
        ]

    def _image(self, body: bytes) -> bytes:
        # 0x84 = IS_VERSION_81 | NO_PREFIX_SEG; short length = whole image.
        return bytes([0x84, 0x01, 3 + len(body)]) + body

    def test_nested_object_populated_inline(self):
        sub = self._sub_type()
        # SUB rides inline (no header): X=5, Y='hi'.
        sub_inline = self._num(5) + self._dalc(b'hi')
        image = self._image(self._num(1) + sub_inline)
        attrs = decode_object_image(image, self._parent_layout(sub))
        self.assertEqual(attrs[0], ('A', 1))
        obj = attrs[1][1]
        self.assertEqual((obj.X, obj.Y), (5, 'hi'))

    def test_nested_object_atomic_null(self):
        sub = self._sub_type()
        image = self._image(self._num(1) + bytes([0xFD]))
        attrs = decode_object_image(image, self._parent_layout(sub))
        self.assertEqual(attrs, [('A', 1), ('SUB', None)])

    def test_collection_of_objects(self):
        sub = self._sub_type()
        coll = DbObjectType(
            'T',
            'ARR',
            b'',
            1,
            [],
            is_collection=True,
            element={
                'name': 'element',
                'data_type': None,
                'charset': None,
                'object_type': sub,
            },
        )
        # Each element is a length-prefixed full object image (own header).
        elem1 = self._image(self._num(1) + self._dalc(b'a'))
        elem2 = self._image(self._num(2) + self._dalc(b'b'))
        body = bytes([0x00]) + bytes([2]) + self._dalc(elem1) + self._dalc(elem2)
        # collection header 0x88 with a prefix segment (01 01).
        image = bytes([0x88, 0x01, 4 + len(body), 0x01, 0x01]) + body
        elements = decode_collection_image(image, coll.element)
        self.assertEqual([(e.X, e.Y) for e in elements], [(1, 'a'), (2, 'b')])


class TestTypeNameMapAdditions(unittest.TestCase):
    def test_number_subtypes_and_tz_names(self):
        for name in ('INTEGER', 'SMALLINT', 'REAL', 'DOUBLE PRECISION'):
            self.assertEqual(type_name_to_tns(name), TNS_TYPE_NUMBER, name)
        from seerdb.common.tns_consts import TNS_TYPE_TIMESTAMPLTZ, TNS_TYPE_TIMESTAMPTZ

        self.assertEqual(type_name_to_tns('TIMESTAMP WITH TZ'), TNS_TYPE_TIMESTAMPTZ)
        self.assertEqual(
            type_name_to_tns('TIMESTAMP WITH LOCAL TZ'), TNS_TYPE_TIMESTAMPLTZ
        )

    def test_lob_attribute_type_names(self):
        # A LOB attribute is typed so the object walkers tell it from an inline
        # scalar; NCLOB shares CLOB's wire type (#888).
        self.assertEqual(type_name_to_tns('CLOB'), TNS_TYPE_CLOB)
        self.assertEqual(type_name_to_tns('NCLOB'), TNS_TYPE_CLOB)
        self.assertEqual(type_name_to_tns('BLOB'), TNS_TYPE_BLOB)


# An object type with LOB attributes: NAME (VARCHAR2), DOC (CLOB), PIC (BLOB).
_DOC_LAYOUT = [
    {'name': 'NAME', 'data_type': TNS_TYPE_VARCHAR, 'charset': None},
    {'name': 'DOC', 'data_type': TNS_TYPE_CLOB, 'charset': None},
    {'name': 'PIC', 'data_type': TNS_TYPE_BLOB, 'charset': None},
]
_DOC_TYPE = DbObjectType(
    'PYO', 'DOC_T', bytes.fromhex('00112233445566778899aabbccddeeff'), 1, _DOC_LAYOUT
)
_ADT_COLUMN = ColumnMeta(
    name=b'DOCCOL', data_type=TNS_TYPE_ADT, data_length=0, max_size=0
)


class TestObjectLobAttributes(unittest.TestCase):
    # A fetched object's LOB attributes ride as locators inside the image; their
    # content is read back over TTI_LOBOPS from a separate queue (#888).

    def _doc(self, name, doc, pic):
        return DbObject(
            'PYO.DOC_T', [('NAME', name), ('DOC', doc), ('PIC', pic)], dbtype=_DOC_TYPE
        )

    def test_image_carries_locator_not_content(self):
        # The CLOB / BLOB attributes are the distinct object-LOB locator, and the
        # content ("hello" / b"\\x01\\x02") is not written inline.
        image = encode_object_image(self._doc('file', 'hello', b'\x01\x02'))
        self.assertEqual(image.count(_THIN_OBJ_LOB_LOCATOR), 2)
        self.assertNotIn(b'hello', image)
        self.assertNotIn('hello'.encode('utf-16-be'), image)
        self.assertIn(b'file', image)  # a plain scalar attribute stays inline

    def test_object_lob_contents_order_and_encoding(self):
        # Row-major, attribute order: CLOB content is UTF-16BE (is_clob True),
        # BLOB content raw bytes (is_clob False).
        rows = [(self._doc('a', 'hello', b'\x01\x02'),)]
        self.assertEqual(
            object_lob_contents([_ADT_COLUMN], rows),
            [('hello'.encode('utf-16-be'), True), (b'\x01\x02', False)],
        )

    def test_null_lob_attribute_contributes_nothing(self):
        # A NULL LOB attribute is the 0xFF null in the image and queues no content.
        obj = self._doc('a', None, b'\x02')
        image = encode_object_image(obj)
        self.assertEqual(image.count(_THIN_OBJ_LOB_LOCATOR), 1)  # only PIC
        self.assertEqual(
            object_lob_contents([_ADT_COLUMN], [(obj,)]), [(b'\x02', False)]
        )

    def test_null_object_and_non_object_columns_ignored(self):
        # A NULL object cell and a non-ADT column carry no object LOBs.
        self.assertEqual(object_lob_contents([_ADT_COLUMN], [(None,)]), [])
        scalar_col = ColumnMeta(
            name=b'N', data_type=TNS_TYPE_NUMBER, data_length=0, max_size=0
        )
        self.assertEqual(object_lob_contents([scalar_col], [(5,)]), [])


class TestLobEmitLog(unittest.TestCase):
    # Each column LOB the Mirror emits gets a unique locator whose content the
    # session remembers, so a later object bind carrying it can be resolved (#888).

    def test_unique_locators_and_content_recall(self):
        log = LobEmitLog()
        loc_a = log.record('first', True)
        loc_b = log.record(b'second', False)
        self.assertNotEqual(loc_a, loc_b)
        self.assertEqual(log.content(loc_a), ('first', True))
        self.assertEqual(log.content(loc_b), (b'second', False))
        self.assertIsNone(log.content(b'unknown'))

    def test_index_zero_reproduces_the_fixed_locator(self):
        # Index 0 is byte-identical to the fixed session locator, so a Mirror that
        # emits exactly one LOB is unchanged on the wire.
        self.assertEqual(mint_column_lob_locator(0), _THIN_LOB_LOCATOR)
        self.assertEqual(len(mint_column_lob_locator(7)), len(_THIN_LOB_LOCATOR))
        self.assertNotEqual(mint_column_lob_locator(7), _THIN_LOB_LOCATOR)


class TestPre12ChunkedObjectImage(unittest.TestCase):
    # An object image past 252 bytes rides chunked. Before 12.1 each chunk has a
    # single length byte; from 12.1 a ub4 one. Read the 12.1 way on 11g, a
    # 300-character attribute decoded as one character (#1261).

    # A live 11g's image for `c61_ov(RPAD('x', 300, 'x'))`, `v VARCHAR2(400)`:
    # the 0xFE marker, chunks of 255 and 57 bytes, the zero terminator.
    _CAPTURED = bytes.fromhex(
        'feff8401fe00000138fe0000012c' + '78' * 243 + '39' + '78' * 57 + '00'
    )
    _LAYOUT = [{'name': 'V', 'data_type': TNS_TYPE_VARCHAR, 'charset': None}]

    def _at(self, version):
        token = _DECODE_FIELD_VERSION.set(version)
        self.addCleanup(_DECODE_FIELD_VERSION.reset, token)

    def test_an_11g_image_reads_whole(self):
        self._at(FIELD_VERSION_11_2)
        (image, rest) = _read_chunked_bytes(self._CAPTURED + b'\x99')
        self.assertEqual((len(image), rest), (312, b'\x99'))
        self.assertEqual(
            dict(decode_object_image(image, self._LAYOUT)), {'V': 'x' * 300}
        )

    def test_the_encoder_writes_the_width_the_decoder_reads(self):
        for version, first_chunk in (
            (FIELD_VERSION_11_2, b'\x40'),
            (FIELD_VERSION_12_1, encode_sb4(0x40)),
        ):
            with self.subTest(version=version):
                enc = _ENCODE_FIELD_VERSION.set(version)
                dec = _DECODE_FIELD_VERSION.set(version)
                try:
                    out = _bytes_with_length(b'y' * 1000)
                    self.assertEqual(out[: 1 + len(first_chunk)], b'\xfe' + first_chunk)
                    self.assertEqual(_read_chunked_bytes(out), (b'y' * 1000, b''))
                    self.assertEqual(_skip_chunked_bytes(out + b'!'), b'!')
                finally:
                    _DECODE_FIELD_VERSION.reset(dec)
                    _ENCODE_FIELD_VERSION.reset(enc)


class TestObjectLobAttributeBind(unittest.TestCase):
    # The inbound direction: an object whose LOB attribute is a LOB -- fetched,
    # temporary, or an upstream one the passthrough made -- carries its locator
    # verbatim, which starts with its own ub2 length (#888, #1260).

    # The image python-oracledb sent for `cla_o(2, <temp CLOB>, <temp BLOB>)`
    # (id NUMBER, c CLOB, b BLOB), captured against a live 23ai: each LOB
    # attribute is its length byte (0x28) and the 40-byte locator the
    # CREATE_TEMP reply returned, `00 26` and all.
    _CAPTURED = bytes.fromhex(
        '8401fe0000005c02c10328002600018208800300029c83000000d10000000103690'
        '00a0000000100001aab82f100000001000028002600018108000300019c83000000'
        'd1000000020000000a0000000100001aab82f1000000010000'
    )
    _CLOB_LOCATOR = _CAPTURED[11:51]
    _BLOB_LOCATOR = _CAPTURED[52:92]
    _TYPE = DbObjectType(
        'PYO',
        'CLA_O',
        bytes(16),
        1,
        [
            {'name': 'ID', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
            {
                'name': 'C',
                'type_name': 'CLOB',
                'data_type': TNS_TYPE_CLOB,
                'charset': None,
            },
            {
                'name': 'B',
                'type_name': 'BLOB',
                'data_type': TNS_TYPE_BLOB,
                'charset': None,
            },
        ],
    )

    def _lob_obj(self):
        return self._TYPE.newobject(
            {
                'ID': 2,
                'C': LOB(TNS_TYPE_CLOB, self._CLOB_LOCATOR, connection=None),
                'B': LOB(TNS_TYPE_BLOB, self._BLOB_LOCATOR, connection=None),
            }
        )

    def test_the_locators_ride_verbatim(self):
        self.assertEqual(self._CLOB_LOCATOR[:2], b'\x00\x26')
        self.assertEqual(encode_object_image(self._lob_obj()), self._CAPTURED)

    def test_the_captured_image_decodes_to_those_locators(self):
        attrs = dict(decode_object_image(self._CAPTURED, self._TYPE.attrs))
        self.assertEqual(
            (attrs['C'], attrs['B']), (self._CLOB_LOCATOR, self._BLOB_LOCATOR)
        )

    def test_lob_object_attribute_queues_no_content(self):
        # A bound LOB is not the Mirror's to serve, so it queues nothing.
        self.assertEqual(object_lob_contents([_ADT_COLUMN], [(self._lob_obj(),)]), [])


class TestServedLobContent(unittest.TestCase):
    # The content the Mirror served under a LOB attribute's locator, for a bound
    # image to be resolved against (#888); shared by every backend.

    _CONTENTS = {b'fetched-loc': ('fetched', True), b'temp-loc': (b'\x01', False)}

    def test_a_locator_is_found_as_it_came(self):
        self.assertEqual(
            served_lob_content(self._CONTENTS, b'fetched-loc'), ('fetched', True)
        )

    def test_a_ub2_stating_the_rest_is_stripped(self):
        locator = struct.pack('>H', len(b'temp-loc')) + b'temp-loc'
        self.assertEqual(served_lob_content(self._CONTENTS, locator), (b'\x01', False))

    def test_a_leading_pair_that_is_no_length_is_kept(self):
        self.assertIsNone(served_lob_content(self._CONTENTS, b'\x00\x01temp-loc'))

    def test_an_unknown_locator_is_none(self):
        self.assertIsNone(served_lob_content(self._CONTENTS, b'other'))

    def test_the_image_answers_from_its_own_map(self):
        image = ObjectImage(bytes(16), 'PYO', 'T', None, b'')
        self.assertIsNone(image.served_lob(b'fetched-loc'))
        image.lob_contents = dict(self._CONTENTS)
        self.assertEqual(image.served_lob(b'fetched-loc'), ('fetched', True))


class TestMapObjectLobs(unittest.TestCase):
    # The walk that turns a decoded object's LOB leaves into LOBs, and finds the
    # str / bytes ones a bind turns into temporary LOBs (#1260).

    _NCLOB_TYPE = DbObjectType(
        'PYO',
        'N_T',
        bytes(16),
        1,
        [
            {'name': 'ID', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
            {
                'name': 'N',
                'type_name': 'NCLOB',
                'data_type': TNS_TYPE_CLOB,
                'charset': None,
            },
        ],
    )
    _LIST_TYPE = DbObjectType(
        'PYO',
        'N_LIST',
        bytes(16),
        1,
        [],
        is_collection=True,
        collection_type=COLLECTION_NESTED_TABLE,
        element={
            'name': 'element',
            'data_type': TNS_TYPE_ADT,
            'object_type': _NCLOB_TYPE,
        },
    )

    def test_each_lob_leaf_is_mapped_in_image_order(self):
        value = self._LIST_TYPE.newobject(
            [
                self._NCLOB_TYPE.newobject({'ID': 1, 'N': b'loc-1'}),
                None,
                self._NCLOB_TYPE.newobject({'ID': 2, 'N': None}),
                self._NCLOB_TYPE.newobject({'ID': 3, 'N': b'loc-3'}),
            ]
        )
        seen = []

        def fn(attr, leaf):
            seen.append((lob_attribute_csfrm(attr), leaf))
            return leaf.upper()

        mapped = map_object_lobs(value, fn)
        # NULLs are skipped; the NCLOB's national form comes from its type name.
        self.assertEqual(seen, [(2, b'loc-1'), (2, b'loc-3')])
        self.assertEqual(
            [e.N if e else None for e in mapped.aslist()],
            [b'LOC-1', None, None, b'LOC-3'],
        )
        # The original is left as it was.
        self.assertEqual(value.aslist()[0].N, b'loc-1')

    def test_a_non_object_passes_through(self):
        self.assertEqual(map_object_lobs('text', lambda a, v: 1 / 0), 'text')


_INDEX_TABLE_TYPE = DbObjectType(
    'PYO',
    'NUMLIST_T',
    bytes.fromhex('dd' * 16),
    1,
    [],
    is_collection=True,
    collection_type=COLLECTION_PLSQL_INDEX_TABLE,
    element={'name': 'element', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
)


class TestImageInt32Members(unittest.TestCase):
    # In an object image a BOOLEAN, and a PL/SQL record's PLS_INTEGER /
    # BINARY_INTEGER field, is a length 4 and a big-endian 32-bit integer -- not
    # a NUMBER, and not the 0x0101 a BOOLEAN bind is -- as python-oracledb packs
    # it; 23ai read these images back as bound (#1607).

    def setUp(self):
        from seerdb.common.tns_consts import TNS_TYPE_BOOLEAN, TNS_TYPE_INT

        self.attrs = [
            {'name': 'N', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
            {'name': 'B', 'data_type': TNS_TYPE_BOOLEAN, 'charset': None},
            {'name': 'I', 'data_type': TNS_TYPE_INT, 'charset': None},
        ]
        self.typ = DbObjectType('PYO', 'R', bytes(16), 1, self.attrs, package_name='PK')

    def test_the_dictionary_names_map_to_the_wire_types(self):
        from seerdb.common.tns_consts import TNS_TYPE_BOOLEAN, TNS_TYPE_INT

        self.assertEqual(type_name_to_tns('BOOLEAN'), TNS_TYPE_BOOLEAN)
        self.assertEqual(type_name_to_tns('PL/SQL PLS INTEGER'), TNS_TYPE_INT)
        self.assertEqual(type_name_to_tns('PL/SQL BINARY INTEGER'), TNS_TYPE_INT)

    def test_a_record_packs_them_as_ub4(self):
        image = encode_object_image(self.typ.newobject({'N': 25, 'B': True, 'I': -45}))
        self.assertEqual(image.hex(), '8401fe0000001402c11a040000000104ffffffd3')
        self.assertEqual(
            decode_object_image(image, self.attrs), [('N', 25), ('B', True), ('I', -45)]
        )

    def test_a_null_member_is_the_null_indicator(self):
        image = encode_object_image(self.typ.newobject({'N': None, 'B': None, 'I': 7}))
        self.assertEqual(
            decode_object_image(image, self.attrs), [('N', None), ('B', None), ('I', 7)]
        )

    def test_an_index_table_of_booleans(self):
        from seerdb.common.tns_consts import TNS_TYPE_BOOLEAN

        typ = DbObjectType(
            'PYO', 'L', bytes(16), 1, [], is_collection=True,
            collection_type=COLLECTION_PLSQL_INDEX_TABLE,
            element={'name': 'element', 'data_type': TNS_TYPE_BOOLEAN, 'charset': None},
        )  # fmt: skip
        image = encode_object_image(typ.newobject([True, False, None], keys=[1, 5, 9]))
        self.assertEqual(
            decode_collection_keyed(image, typ.element),
            ([True, False, None], [1, 5, 9]),
        )


class TestPlsqlIndexTableImage(unittest.TestCase):
    # A PL/SQL associative array (index table) sets the HAS_INDEXES flag (0x10)
    # in the collection body and prefixes each element with its int32 key; a SQL
    # collection does neither (#888).

    def test_index_table_image_flag_and_keys(self):
        obj = _INDEX_TABLE_TYPE.newobject([10, 20, 30])
        image = encode_object_image(obj)
        # Collection header is flags(0x88) version(01) 0xFE + ub4 length + prefix
        # (01 01); the body then opens with the HAS_INDEXES flag byte.
        self.assertEqual(image[7:9], bytes([1, 1]))  # prefix segment
        self.assertEqual(image[9], 0x10)  # HAS_INDEXES collection flag
        # A locally built array is keyed 0..N-1: PL/SQL written for these arrays
        # indexes from zero (`for i in 0..count-1`), and a 1-based array makes
        # `a(0)` raise NO_DATA_FOUND (#1055).
        self.assertEqual(
            decode_collection_keyed(image, _INDEX_TABLE_TYPE.element)[1], [0, 1, 2]
        )
        self.assertIn(struct.pack('>i', 0), image)

    def test_index_table_roundtrips(self):
        obj = _INDEX_TABLE_TYPE.newobject([10, 20, 30])
        image = encode_object_image(obj)
        self.assertEqual(
            decode_collection_image(image, _INDEX_TABLE_TYPE.element), [10, 20, 30]
        )

    def test_index_table_keeps_its_own_keys(self):
        # A decoded array re-encodes under the keys it arrived with, not 1..N.
        obj = _INDEX_TABLE_TYPE.newobject([10, 20, 30], keys=[-576, 284, 8388608])
        image = encode_object_image(obj)
        for key in (-576, 284, 8388608):
            self.assertIn(struct.pack('>i', key), image)
        self.assertNotIn(struct.pack('>i', 1), image)
        (values, keys) = decode_collection_keyed(image, _INDEX_TABLE_TYPE.element)
        self.assertEqual(values, [10, 20, 30])
        self.assertEqual(keys, [-576, 284, 8388608])

    def test_negative_key_encodes_signed(self):
        # struct.pack('>I', -576) RAISES rather than mis-encoding, so the old
        # unsigned pack could not represent a real index-by key at all. Signed
        # and unsigned agree on every key a dense 1..N array has, which is why
        # this went unnoticed for so long (#1053).
        obj = _INDEX_TABLE_TYPE.newobject([10], keys=[-1048576])
        image = encode_object_image(obj)
        self.assertIn(bytes.fromhex('fff00000'), image)
        self.assertEqual(
            decode_collection_keyed(image, _INDEX_TABLE_TYPE.element)[1], [-1048576]
        )

    def test_varray_has_no_keys(self):
        # keys is None for a SQL collection -- it has none, which is not the
        # same as having an empty list of them.
        varray_image = encode_object_image(
            DbObjectType(
                'PYO',
                'INTS_T',
                bytes.fromhex('ee' * 16),
                1,
                [],
                is_collection=True,
                collection_type=COLLECTION_VARRAY,
                element=_INDEX_TABLE_TYPE.element,
            ).newobject([10, 20, 30])
        )
        self.assertIsNone(
            decode_collection_keyed(varray_image, _INDEX_TABLE_TYPE.element)[1]
        )

    def test_locally_built_array_is_zero_based(self):
        # The case that failed live: a seerdb-built array bound to PL/SQL that
        # loops `for i in 0..count - 1` raised ORA-01403, because we keyed the
        # elements 1..N and `a(0)` did not exist (#1055).
        obj = _INDEX_TABLE_TYPE.newobject([10, 20, 30])
        self.assertEqual(object.__getattribute__(obj, '_keys'), [0, 1, 2])

    def test_append_to_empty_starts_at_zero(self):
        obj = _INDEX_TABLE_TYPE.newobject()
        obj.append(10)
        obj.append(20)
        self.assertEqual(
            decode_collection_keyed(
                encode_object_image(obj), _INDEX_TABLE_TYPE.element
            )[1],
            [0, 1],
        )

    def test_varray_gets_no_keys_from_its_type(self):
        # Only an INDEX TABLE is keyed; a SQL collection stays keyless, so the
        # zero-based seeding must not leak into VARRAY / nested table.
        varray = DbObjectType(
            'PYO',
            'INTS_T',
            bytes.fromhex('ee' * 16),
            1,
            [],
            is_collection=True,
            collection_type=COLLECTION_VARRAY,
            element=_INDEX_TABLE_TYPE.element,
        )
        obj = varray.newobject([10, 20, 30])
        self.assertIsNone(object.__getattribute__(obj, '_keys'))
        obj.append(40)
        self.assertIsNone(object.__getattribute__(obj, '_keys'))

    def test_append_keeps_keys_parallel(self):
        # Growing a keyed array must extend _keys too, or the encoder pairs each
        # value with some other element's key.
        obj = _INDEX_TABLE_TYPE.newobject([10, 20], keys=[-576, 284])
        obj.append(30)
        obj.extend([40, 50])
        (values, keys) = decode_collection_keyed(
            encode_object_image(obj), _INDEX_TABLE_TYPE.element
        )
        self.assertEqual(values, [10, 20, 30, 40, 50])
        self.assertEqual(keys, [-576, 284, 285, 286, 287])


class TestCollectionIndexAccess(unittest.TestCase):
    # first/last/next/prev/exists/getelement/setelement/delete/size/asdict
    # (#1035). Every expectation here was compared against python-oracledb
    # driving the same live 23ai array, value for value and message for
    # message -- not read off its source.

    _VARRAY = DbObjectType(
        'PYO',
        'INTS_T',
        bytes.fromhex('ee' * 16),
        1,
        [],
        is_collection=True,
        collection_type=COLLECTION_VARRAY,
        element={'name': 'element', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
    )

    def _assoc(self):
        # The keys pkg_TestStringArrays.TestIndexBy really returns.
        return _INDEX_TABLE_TYPE.newobject(
            [10, 20, 30, 40],
            keys=[-1048576, -576, 284, 8388608],
        )

    def test_walk_an_associative_array(self):
        obj = self._assoc()
        self.assertEqual(obj.first(), -1048576)
        self.assertEqual(obj.last(), 8388608)
        self.assertEqual(obj.next(-576), 284)
        self.assertEqual(obj.prev(284), -576)
        self.assertEqual(obj.size(), 4)
        self.assertTrue(obj.exists(-576))
        self.assertFalse(obj.exists(-577))
        self.assertEqual(obj.getelement(284), 30)

    def test_walk_off_either_end_is_none(self):
        obj = self._assoc()
        self.assertIsNone(obj.next(8388608))
        self.assertIsNone(obj.prev(-1048576))

    def test_empty_collection_has_no_first_or_last(self):
        obj = _INDEX_TABLE_TYPE.newobject()
        self.assertIsNone(obj.first())
        self.assertIsNone(obj.last())
        self.assertEqual(obj.size(), 0)
        self.assertEqual(obj.asdict(), {})

    def test_asdict_is_the_keyed_view(self):
        self.assertEqual(
            self._assoc().asdict(),
            {-1048576: 10, -576: 20, 284: 30, 8388608: 40},
        )

    def test_delete_leaves_a_hole(self):
        # The survivors keep their OWN keys; only a positional collection shifts.
        obj = self._assoc()
        obj.delete(-576)
        obj.delete(284)
        self.assertEqual(obj.aslist(), [10, 40])
        self.assertEqual(obj.asdict(), {-1048576: 10, 8388608: 40})
        self.assertEqual(obj.next(-1048576), 8388608)
        self.assertFalse(obj.exists(-576))

    def test_delete_survives_the_encoder(self):
        # A hole must reach the wire as a hole, not be renumbered away.
        obj = self._assoc()
        obj.delete(-576)
        self.assertEqual(
            decode_collection_keyed(
                encode_object_image(obj), _INDEX_TABLE_TYPE.element
            )[1],
            [-1048576, 284, 8388608],
        )

    def test_setelement_replaces_and_creates(self):
        obj = self._assoc()
        obj.setelement(284, 99)
        self.assertEqual(obj.getelement(284), 99)
        self.assertEqual(obj.size(), 4)
        # An unused key CREATES an element, as `a(k) := v` does in PL/SQL, and
        # the keys stay sorted so the image goes out in key order.
        obj.setelement(-1000, 77)
        self.assertEqual(obj.first(), -1048576)
        self.assertEqual(obj.next(-1048576), -1000)
        self.assertEqual(obj.getelement(-1000), 77)
        self.assertEqual(
            decode_collection_keyed(
                encode_object_image(obj), _INDEX_TABLE_TYPE.element
            )[1],
            [-1048576, -1000, -576, 284, 8388608],
        )

    def test_missing_index_raises(self):
        obj = self._assoc()
        with self.assertRaises(ProgrammingError) as ctx:
            obj.getelement(999)
        self.assertIn('DPY-2038', str(ctx.exception))
        with self.assertRaises(ProgrammingError):
            obj.delete(999)

    def test_varray_indexes_by_position_from_zero(self):
        obj = self._VARRAY.newobject([10, 20, 30])
        self.assertEqual(obj.first(), 0)
        self.assertEqual(obj.last(), 2)
        self.assertEqual(obj.next(0), 1)
        self.assertIsNone(obj.prev(0))
        self.assertTrue(obj.exists(0))
        self.assertFalse(obj.exists(3))
        self.assertEqual(obj.getelement(0), 10)
        self.assertEqual(obj.asdict(), {0: 10, 1: 20, 2: 30})

    def test_varray_delete_shifts(self):
        # Unlike an associative array: the index IS the position here, so the
        # later elements move down.
        obj = self._VARRAY.newobject([10, 20, 30])
        obj.delete(0)
        self.assertEqual(obj.aslist(), [20, 30])
        self.assertEqual(obj.asdict(), {0: 20, 1: 30})

    def test_varray_setelement_out_of_range_raises(self):
        obj = self._VARRAY.newobject([10, 20, 30])
        with self.assertRaises(ProgrammingError) as ctx:
            obj.setelement(7, 40)
        self.assertIn('DPY-2039', str(ctx.exception))

    def test_index_access_rejects_a_non_collection(self):
        obj = _ADDR_TYPE.newobject({'STREET': 'Main St', 'ZIP': 1, 'CODE': 'US'})
        for Call in (
            obj.first,
            obj.last,
            obj.size,
            lambda: obj.next(0),
            lambda: obj.prev(0),
            lambda: obj.exists(0),
            lambda: obj.getelement(0),
            lambda: obj.setelement(0, 1),
            lambda: obj.delete(0),
        ):
            with self.assertRaises(TypeError):
                Call()
        # asdict stays the attribute view on an object type.
        self.assertEqual(obj.asdict()['STREET'], 'Main St')


class TestPlsqlIndexTableCapture(unittest.TestCase):
    # The real thing: the image a live 23ai sends for
    # `pkg_TestStringArrays.TestIndexBy`, which keys four strings at -1048576,
    # -576, 284 and 8388608 (#1053). Captured rather than hand-built -- the
    # signedness of the key is exactly the field a hand-written fixture would
    # have encoded my assumption about.
    _IMAGE = bytes.fromhex(
        '88 01 51 01 03 10 04'
        + 'fff00000'
        + '0d'
        + b'First element'.hex()
        + 'fffffdc0'
        + '0e'
        + b'Second element'.hex()
        + '0000011c'
        + '0d'
        + b'Third element'.hex()
        + '00800000'
        + '0e'
        + b'Fourth element'.hex()
    )

    _ELEMENT = {
        'name': 'element',
        'data_type': TNS_TYPE_VARCHAR,
        'charset': None,
    }

    def test_capture_decodes_to_its_real_keys(self):
        (values, keys) = decode_collection_keyed(self._IMAGE, self._ELEMENT)
        self.assertEqual(
            values,
            ['First element', 'Second element', 'Third element', 'Fourth element'],
        )
        self.assertEqual(keys, [-1048576, -576, 284, 8388608])

    def test_capture_re_encodes_byte_identical(self):
        # Decode then re-encode must reproduce the server's own bytes: this is
        # the Mirror's passthrough path, where losing a key hands an external
        # client a well-formed image full of wrong numbers.
        typ = DbObjectType(
            'PYO',
            'UDT_STRINGLIST',
            bytes.fromhex('cc' * 16),
            1,
            [],
            is_collection=True,
            collection_type=COLLECTION_PLSQL_INDEX_TABLE,
            element=self._ELEMENT,
        )
        (values, keys) = decode_collection_keyed(self._IMAGE, self._ELEMENT)
        again = encode_object_image(typ.newobject(values, keys=keys))
        # Bodies only. The two headers legitimately differ in form: the server
        # wrote the SHORT length (`88 01 51`, 5 bytes to the body) where the
        # encoder always writes the long one (`88 01 FE` + ub4 + prefix, 9), and
        # its prefix segment is `01 03` against our `01 01`. Neither has ever
        # been shown to matter; what must match to the byte is the keyed body.
        self.assertEqual(again[9:], self._IMAGE[5:])

    def test_varray_has_no_index_flag(self):
        # The SQL collection path is unchanged: flag byte 0, no per-element keys.
        varray = DbObjectType(
            'PYO',
            'INTS_T',
            bytes.fromhex('ee' * 16),
            1,
            [],
            is_collection=True,
            collection_type=COLLECTION_VARRAY,
            element={'name': 'element', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
        )
        image = encode_object_image(varray.newobject([10, 20, 30]))
        self.assertEqual(image[9], 0x00)  # no HAS_INDEXES flag
        self.assertEqual(decode_collection_image(image, varray.element), [10, 20, 30])


# SYS.XMLTYPE stands in as an object attribute type; it is framed as an XMLType
# image, not a normal nested object (#124).
_XML_TYPE = DbObjectType('SYS', 'XMLTYPE', bytes.fromhex('11' * 16), 1, [])
_XML_OBJ_LAYOUT = [
    {'name': 'NUMBERVALUE', 'data_type': TNS_TYPE_NUMBER, 'charset': None},
    {'name': 'XMLVALUE', 'type_name': 'XMLTYPE', 'object_type': _XML_TYPE},
    {'name': 'STRINGVALUE', 'data_type': TNS_TYPE_VARCHAR, 'charset': None},
]
_XML_OBJ_TYPE = DbObjectType(
    'PYO', 'OBJ_WITH_XML', bytes.fromhex('22' * 16), 1, _XML_OBJ_LAYOUT
)


class TestXmlTypeInObject(unittest.TestCase):
    def test_encode_xmltype_roundtrips(self):
        from seerdb.common.dbobject import decode_xmltype, encode_xmltype

        blob = encode_xmltype('<item>ab</item>')
        self.assertEqual(decode_xmltype(blob), (False, '<item>ab</item>'))

    def test_a_large_document_uses_the_long_length_the_server_sends(self):
        # Captured from 23ai serving a 32 KB XMLType to python-oracledb: the same
        # inline STRING image, its length in the long form -- fe + 4 bytes,
        # spanning the whole image -- and no LOB anywhere (#1073). It used to be
        # refused with ORA-03115. Only the flag word differs: 23ai also sets a
        # 0x10 bit no reader checks (#124).
        from seerdb.common.dbobject import decode_xmltype, encode_xmltype

        captured_head = bytes.fromhex('8501fe0000801a' + '01' + '00000014')
        doc = '<data>' + 'x' * 32768 + '</data>\n'  # 32782 bytes, as served
        image = encode_xmltype(doc)
        self.assertEqual(image[:7], captured_head[:7])
        self.assertEqual(image[7:12], bytes.fromhex('0100000004'))
        self.assertEqual(len(image), 0x801A)
        self.assertEqual(decode_xmltype(image), (False, doc))

    def test_a_small_document_keeps_the_one_byte_length(self):
        # '<s>tiny</s>\n' as 23ai sends it: 85 01 14, a 20-byte image.
        from seerdb.common.dbobject import encode_xmltype

        image = encode_xmltype('<s>tiny</s>\n')
        self.assertEqual(image[:3], bytes.fromhex('850114'))
        self.assertEqual(len(image), 0x14)

    def test_object_with_xmltype_attribute_roundtrips(self):
        obj = _XML_OBJ_TYPE.newobject(
            {
                'NUMBERVALUE': 2339,
                'XMLVALUE': '<item>test</item>',
                'STRINGVALUE': 'a string',
            }
        )
        attrs = dict(decode_object_image(encode_object_image(obj), _XML_OBJ_LAYOUT))
        # The XMLType attribute decodes back to the string, and the trailing
        # scalar is not corrupted (the old bug bled XML bytes into it).
        self.assertEqual(attrs['NUMBERVALUE'], 2339)
        self.assertEqual(attrs['XMLVALUE'], '<item>test</item>')
        self.assertEqual(attrs['STRINGVALUE'], 'a string')

    def test_null_xmltype_attribute_is_ff_marker(self):
        obj = _XML_OBJ_TYPE.newobject(
            {'NUMBERVALUE': 1, 'XMLVALUE': None, 'STRINGVALUE': 'x'}
        )
        image = encode_object_image(obj)
        attrs = dict(decode_object_image(image, _XML_OBJ_LAYOUT))
        self.assertIsNone(attrs['XMLVALUE'])
        self.assertEqual(attrs['STRINGVALUE'], 'x')  # not corrupted by the NULL


class TestTypeMetadata(unittest.TestCase):
    # DbObjectType.attributes / element_type, as python-oracledb lists them
    # (#1490); the expectations are python-oracledb's on 23ai.

    def _typ(self, attrs, **kw):
        return DbObjectType('PYO', 'T', b'\x00' * 16, 1, attrs, **kw)

    def test_numbers_and_timestamps_take_python_oracledbs_precision(self):
        from seerdb.common import datatypes as T

        attrs = [
            {'name': 'N', 'type_name': 'NUMBER'},
            {'name': 'N9', 'type_name': 'NUMBER', 'precision': 9, 'scale': 0},
            {'name': 'N92', 'type_name': 'NUMBER', 'precision': 9, 'scale': 2},
            {'name': 'NS', 'type_name': 'NUMBER', 'scale': 0},  # a table's INTEGER
            {'name': 'F10', 'type_name': 'FLOAT', 'precision': 10},
            {'name': 'R', 'type_name': 'REAL'},
            {'name': 'I', 'type_name': 'INTEGER'},
            {'name': 'TS', 'type_name': 'TIMESTAMP(3)', 'scale': 3},
            {'name': 'TZ', 'type_name': 'TIMESTAMP WITH TZ'},
            {'name': 'BD', 'type_name': 'BINARY_DOUBLE'},
        ]
        self.assertEqual(
            [
                (a.name, a.type, a.precision, a.scale)
                for a in self._typ(attrs).attributes
            ],
            [
                ('N', T.DB_TYPE_NUMBER, 0, -127),
                ('N9', T.DB_TYPE_NUMBER, 9, 0),
                ('N92', T.DB_TYPE_NUMBER, 9, 2),
                ('NS', T.DB_TYPE_NUMBER, 38, 0),
                ('F10', T.DB_TYPE_NUMBER, 126, -127),
                ('R', T.DB_TYPE_NUMBER, 63, -127),
                ('I', T.DB_TYPE_NUMBER, 38, 0),
                ('TS', T.DB_TYPE_TIMESTAMP, 0, 3),
                ('TZ', T.DB_TYPE_TIMESTAMP_TZ, 0, 6),
                ('BD', T.DB_TYPE_BINARY_DOUBLE, None, None),
            ],
        )

    def test_a_character_attributes_size_is_in_bytes(self):
        from seerdb.common.dbobject import attr_max_size

        self.assertEqual(attr_max_size('VARCHAR2', 20), 20)
        self.assertEqual(attr_max_size('VARCHAR2', 10, 'C'), 40)
        self.assertEqual(attr_max_size('CHAR', 3, 'B'), 3)
        self.assertEqual(attr_max_size('NVARCHAR2', 5, 'C'), 10)
        self.assertEqual(attr_max_size('RAW', 16), 16)
        self.assertIsNone(attr_max_size('NUMBER', 22))
        self.assertIsNone(attr_max_size('CLOB', 4000))

    def test_ten_gs_national_attribute_reads_as_national(self):
        # 10g lists an NVARCHAR2 attribute as VARCHAR2 in NCHAR_CS.
        from seerdb.client.connection import _type_attr
        from seerdb.common import datatypes as T

        attr = _type_attr(('NV', 'VARCHAR2', None, 5, None, None, 'NCHAR_CS'))
        (described,) = self._typ([attr]).attributes
        self.assertEqual((described.type, described.max_size), (T.DB_TYPE_NVARCHAR, 10))

    def test_a_rowtype_columns_size_is_its_data_length(self):
        from seerdb.client.connection import _rowtype_attr

        attrs = [
            _rowtype_attr('VC', 'VARCHAR2', 40),
            _rowtype_attr('N', 'NUMBER', 22, 9, 2),
            _rowtype_attr('D', 'DATE', 7),
        ]
        self.assertEqual(
            [(a.precision, a.scale, a.max_size) for a in self._typ(attrs).attributes],
            [(None, None, 40), (9, 2, None), (None, None, None)],
        )

    def test_element_type_iscollection_and_call(self):
        from seerdb.common import datatypes as T

        nested = self._typ([{'name': 'X', 'type_name': 'NUMBER'}])
        coll = self._typ(
            [], is_collection=True, element={'name': 'element', 'type_name': 'NUMBER'}
        )
        objs = self._typ(
            [],
            is_collection=True,
            element={'name': 'element', 'type_name': 'T', 'object_type': nested},
        )
        self.assertEqual(
            (coll.iscollection, coll.element_type), (True, T.DB_TYPE_NUMBER)
        )
        self.assertIs(objs.element_type, nested)
        self.assertEqual((nested.iscollection, nested.element_type), (False, None))
        self.assertEqual(coll([1, 2]).aslist(), [1, 2])
        self.assertEqual(repr(nested.attributes[0]), '<seerdb.DbObjectAttr X>')
