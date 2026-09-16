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
    COLLECTION_VARRAY,
    DbObject,
    DbObjectType,
    DbRef,
    ObjectImage,
    decode_collection_image,
    decode_object_image,
    decode_xmltype,
    type_name_to_tns,
)
from seerdb.common.exceptions import NotSupportedError
from seerdb.common.lob import LOB
from seerdb.common.tns import (
    _ENCODE_FIELD_VERSION,
    _THIN_LOB_LOCATOR,
    _THIN_OBJ_LOB_LOCATOR,
    ColumnMeta,
    LobEmitLog,
    _encode_object_bind_value,
    _encode_ref_bind_value,
    _encode_ref_oac,
    _read_bind_value,
    _read_object_column,
    encode_object_column_value,
    encode_object_image,
    mint_column_lob_locator,
    object_lob_contents,
)
from seerdb.common.tns_consts import (
    AL32UTF8_CHARSET,
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

    def test_asdict_rejected_on_collection(self):
        with self.assertRaises(TypeError):
            _NUM_VA.newobject([1]).asdict()


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


class TestObjectLobAttributeBind(unittest.TestCase):
    # The inbound direction: an object whose LOB attribute is set to a resolved
    # upstream LOB rides its real locator behind a ub2 length prefix (#888).

    def _lob_obj(self):
        lob = LOB(TNS_TYPE_CLOB, b'UPSTREAM-LOCATOR-BYTES', connection=None)
        return _DOC_TYPE.newobject({'NAME': 'file', 'DOC': lob, 'PIC': None})

    def test_lob_object_attribute_is_ub2_prefixed_locator(self):
        image = encode_object_image(self._lob_obj())
        # The image carries the raw locator behind its ub2 length, not the fetch
        # placeholder locator.
        self.assertIn(struct.pack('>H', len(b'UPSTREAM-LOCATOR-BYTES')), image)
        self.assertIn(b'UPSTREAM-LOCATOR-BYTES', image)
        self.assertNotIn(_THIN_OBJ_LOB_LOCATOR, image)

    def test_lob_object_attribute_queues_no_content(self):
        # A bound upstream LOB is not the Mirror's to serve, so it queues nothing.
        self.assertEqual(object_lob_contents([_ADT_COLUMN], [(self._lob_obj(),)]), [])
