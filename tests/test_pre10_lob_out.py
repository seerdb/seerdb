# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""CLOB / BLOB OUT binds on 8i and 9i (SeerODBC #167).

The replies are 9.2.0.4's and 8.1.7's to a block that makes a temporary CLOB
('small') or BLOB (DE AD BE EF) and assigns it to its one OUT bind, and to one
that assigns NULL. The value is a LOB column's cell: on 9i a ub4 length, the
locator and an indicator, `00 81 01` for NULL, as ojdbc14 reads it; on 8i a
ub4 length, the locator and a ub2 indicator, `00000000 ffff` for NULL. The 8i
bind is sqlplus 9.2's to 8.1.7: the OAC flag 0x01 at a size of 32, and an
empty 86-byte locator as its value, where the bind the other Vars take left
the server waiting.
"""

import unittest

import seerdb
from seerdb.common.datatypes import Var
from seerdb.common.lob import LOB
from seerdb.common.tns import (
    _encode_8i_bind_oac,
    _encode_8i_bind_value,
    decode_8i_block_out,
    decode_fv2_block_out,
    o8i_block_complete,
)
from seerdb.common.tns_consts import TNS_TYPE_BLOB, TNS_TYPE_CLOB

_9I_CLOB = bytes.fromhex(
    '0b0501010001010000001007015656005400010208000300010000000000000000000100'
    '1f000a00000001000000000da869b8daf566480000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000008010204029e'
    'e25d000401010000000101002f0000000000000000000000000000010100000000'
)
_9I_BLOB = bytes.fromhex(
    '0b0501010001010000001007015656005400010108000300010000000000000000000200'
    '00000a000000010000000064d258d1d1a9cf920000000000000000000000000000000000'
    '00000000000000000000000000000000000000000000000000000000000008010204029e'
    'e25d000401010000000101002f0000000000000000000000000000010100000000'
)
_9I_NULL = bytes.fromhex(
    '0b050101000101000000100700810108010204029ee25d000401010000000101002f0000'
    '000000000000000000000000010100000000'
)
_8I_CLOB = bytes.fromhex(
    '0b0501000000010000000000000000000000100756000000560054000102080003000100'
    '000000000000000003001f000a000000030000000043f43e839db344fb00000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000804004b872a00000000000100000000000000000000000401000000000000'
    '000000010000002f00400000000000000000000000000000000000000000000600000100'
    '00000000000000000000000000000000'
)
_8I_BLOB = bytes.fromhex(
    '0b0501000000010000000000000000000000100756000000560054000101080003000100'
    '0000000000000000060000000a000000030000000086d8abecf21802bc00000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000804004b872a00000000000200000000000000000000000401000000000000'
    '000000020000002f00400000000000000000000000000000000000000000000800000100'
    '00000000000000000000000000000000'
)
_8I_NULL = bytes.fromhex(
    '0b0501000000010000000000000000000000100700000000ffff0804004b872a00000000'
    '000300000000000000000000000401000000000000000000030000002f00400000000000'
    '000000000000000000000000000000000a00000100000000000000000000000000000000'
    '00'
)
# sqlplus 9.2's CLOB OUT bind to 8.1.7: the OAC, the value section's marker,
# and the empty locator it sends as the value.
_8I_SQLPLUS_CLOB_BIND = (
    bytes.fromhex('700100002000')
    + bytes(13)
    + bytes.fromhex('0000001f0001')
    + b'\x07'
    + bytes.fromhex('5600000056')
    + b'\x00\x54'
    + bytes(84)
)

_CLOB = {0: (TNS_TYPE_CLOB, 1)}
_BLOB = {0: (TNS_TYPE_BLOB, 1)}


class Fv2LobOutTest(unittest.TestCase):
    def test_a_clob_out_is_a_lob_of_its_locator(self):
        (values, _rows, code) = decode_fv2_block_out(_9I_CLOB, 1, _CLOB)
        self.assertEqual(code, 0)
        self.assertIsInstance(values[0], LOB)
        self.assertEqual(values[0].data_type, TNS_TYPE_CLOB)
        self.assertEqual(len(values[0].raw), 86)
        self.assertEqual(values[0].raw[:4], bytes.fromhex('00540001'))

    def test_a_blob_out_is_a_lob_of_its_locator(self):
        (values, _rows, code) = decode_fv2_block_out(_9I_BLOB, 1, _BLOB)
        self.assertEqual(code, 0)
        self.assertEqual(values[0].data_type, TNS_TYPE_BLOB)
        self.assertEqual(len(values[0].raw), 86)

    def test_a_null_lob_out_is_none(self):
        (values, _rows, code) = decode_fv2_block_out(_9I_NULL, 1, _CLOB)
        self.assertEqual((values, code), ([None], 0))

    def test_an_uninitialised_locator_is_none(self):
        # A RETURNING of a NULL LOB answers with the locator's length and zeros.
        at = _9I_CLOB.index(bytes.fromhex('0156560054')) + 3
        reply = _9I_CLOB[:at] + b'\x00\x54' + bytes(84) + _9I_CLOB[at + 86 :]
        self.assertEqual(decode_fv2_block_out(reply, 1, _CLOB)[0], [None])


class O8iLobOutTest(unittest.TestCase):
    def test_the_bind_is_sqlplus_s(self):
        var = Var(seerdb.DB_TYPE_CLOB)
        self.assertEqual(
            _encode_8i_bind_oac(var) + b'\x07' + _encode_8i_bind_value(var),
            _8I_SQLPLUS_CLOB_BIND,
        )

    def test_a_blob_bind_has_no_charset(self):
        oac = _encode_8i_bind_oac(Var(seerdb.DB_TYPE_BLOB))
        self.assertEqual(oac[:6], bytes.fromhex('710100002000'))
        self.assertEqual(oac[-6:], bytes(6))

    def test_a_lob_var_holding_a_lob_binds_its_locator(self):
        var = Var(seerdb.DB_TYPE_CLOB)
        locator = b'\x00\x54' + bytes(range(84))
        var.setvalue(0, LOB(TNS_TYPE_CLOB, locator))
        self.assertEqual(
            _encode_8i_bind_value(var), bytes.fromhex('5600000056') + locator
        )

    def test_a_clob_out_is_a_lob_of_its_locator(self):
        (value,) = decode_8i_block_out(_8I_CLOB, 1, Lobs=_CLOB)
        self.assertEqual(value.data_type, TNS_TYPE_CLOB)
        self.assertEqual(len(value.raw), 86)
        self.assertEqual(value.raw[:4], bytes.fromhex('00540001'))

    def test_a_blob_out_is_a_lob_of_its_locator(self):
        (value,) = decode_8i_block_out(_8I_BLOB, 1, Lobs=_BLOB)
        self.assertEqual(value.data_type, TNS_TYPE_BLOB)

    def test_a_null_lob_out_is_none(self):
        self.assertEqual(decode_8i_block_out(_8I_NULL, 1, Lobs=_CLOB), [None])

    def test_the_reply_is_whole(self):
        # Read as a value, the cell's length ran past the reply, which then
        # looked unfinished and the client waited on.
        for reply in (_8I_CLOB, _8I_BLOB, _8I_NULL):
            self.assertTrue(o8i_block_complete(reply, _CLOB))
        self.assertFalse(o8i_block_complete(_8I_CLOB[:60], _CLOB))


if __name__ == '__main__':
    unittest.main()
