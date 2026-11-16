# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""Object binds on 8i (SeerODBC #172).

OCI 9.2 on the 9i VM binds `seerdb_obt8c(7, 'seven')` -- an object of `(n
NUMBER, s VARCHAR2(10))` -- to 8.1.7 with OCIBindObject: into an INSERT, as a
NULL, and IN and OUT through a block, in the OALL8 form seerdb's 8i dialect
speaks. Its descriptor is 9i's at 8i's widths with the type's OID and version:
an ADT of 2000 bytes, flags 0, no charset. Its value is the cell an 8i row
carries the object in, without the row's indicator and return code, and an OUT
object comes back in that form. OCI writes the image's header length in the
short form; seerdb's long one, as 9i's ojdbc14 writes it, 8.1.7 takes as well.
"""

import unittest

from seerdb.common.datatypes import Var
from seerdb.common.dbobject import DbObjectType
from seerdb.common.tns import (
    _encode_8i_bind_oac,
    _encode_8i_bind_value,
    decode_8i_block_cursor,
    decode_8i_block_out,
    encode_object_image,
    o8i_block_complete,
)
from seerdb.common.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR

_TOID = bytes.fromhex('f5f360f6cff8486387a9ca4c976a30e0')
_TYPE = DbObjectType(
    'SYSTEM',
    'SEERDB_OBT8C',
    _TOID,
    1,
    [
        {'name': 'N', 'data_type': TNS_TYPE_NUMBER},
        {'name': 'S', 'data_type': TNS_TYPE_VARCHAR},
    ],
)
# OCI 9.2's descriptor, the same for the INSERT, its NULL and an OUT bind.
_OAC = (
    bytes.fromhex('6d000000d0070000' + '00' * 8 + '10000000' + '10')
    + _TOID
    + bytes.fromhex('0100000000')
)
# The frame OCI 9.2 sends around an image: the type block, no object OID or
# snapshot, version 0, the image's length, flags 1.
_TYPE_BLOCK = (
    bytes.fromhex('240000002400220208') + _TOID + bytes.fromhex('00' * 12 + '00010001')
)
_NULL_VALUE = _TYPE_BLOCK + bytes.fromhex('00000000000000000000000000000100')
# The reply to the block: the I/O vector (IN, OUT), then the OUT object,
# seerdb_obt8c(8, 'seven!'), and the status.
_BLOCK_REPLY = bytes.fromhex(
    '0b050200000001000000000000000000000020100724000000240022020844d3e413d1fe4bd4'
    '824413b6024de4b100000000000000000000000000010001000000000000000000000d000000'
    '01000d84010d02c10906736576656e2108040067532b0000000000010000000100000000000000'
    '0401000000000000000000010000002f00000000002b450300050000ff000000010000000000'
    '00150000010000000000000000000000000000000000'
)
_OUT_IMAGE = bytes.fromhex('84010d02c10906') + b'seven!'


def _seven():
    obj = _TYPE.newobject()
    obj.N = 7
    obj.S = 'seven'
    return obj


class O8iObjectBindTest(unittest.TestCase):
    def test_an_object_s_descriptor_is_oci_s(self):
        self.assertEqual(_encode_8i_bind_oac(_seven()), _OAC)

    def test_an_out_one_is_declared_alike(self):
        self.assertEqual(_encode_8i_bind_oac(Var(_TYPE)), _OAC)

    def test_the_value_is_the_frame_around_the_image(self):
        image = encode_object_image(_seven())
        frame = bytes.fromhex('00000000000000000000')
        frame += len(image).to_bytes(4, 'little') + bytes.fromhex('0100')
        self.assertEqual(
            _encode_8i_bind_value(_seven()),
            _TYPE_BLOCK + frame + bytes([len(image)]) + image,
        )

    def test_a_null_or_out_one_goes_as_the_frame_alone(self):
        self.assertEqual(_encode_8i_bind_value(Var(_TYPE)), _NULL_VALUE)

    def test_the_out_object_comes_back_as_its_image(self):
        self.assertEqual(
            decode_8i_block_out(_BLOCK_REPLY, 1, Objects=frozenset({0})), [_OUT_IMAGE]
        )

    def test_the_reply_is_whole_only_once_the_object_is_there(self):
        self.assertTrue(o8i_block_complete(_BLOCK_REPLY, Objects=frozenset({0})))
        self.assertFalse(o8i_block_complete(_BLOCK_REPLY[:60], Objects=frozenset({0})))

    def test_the_status_after_the_object_names_the_block_s_cursor(self):
        # OCI's session runs each statement on cursor 1. Read as a plain value,
        # the object's cell left the status misaligned, naming cursor 0, and the
        # block's cursor was never closed.
        self.assertEqual(
            decode_8i_block_cursor(_BLOCK_REPLY, 1, Objects=frozenset({0})), 1
        )


if __name__ == '__main__':
    unittest.main()
