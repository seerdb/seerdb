# SPDX-FileCopyrightText: 2025 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""The 9i DML status reply, captured live (#711).

The reply is an RPA piggyback of two parameters, then the short OER. The first
parameter is a counter that grows with the instance; once it passes 2**24 its
length byte is 0x04, the OER token, and a decoder that stopped the parameter
loop at a token-looking byte read the counter as the status: every successful
CREATE, INSERT and DROP on 9i raised a garbled negative ORA code.
"""

import unittest

from seerdb.common.tns import decode_fv2_dml_response

# Captured from 9.2.0.4: the counter 0x0129c868 is the first RPA parameter.
_CREATE = bytes.fromhex(
    '080102040129c868000400000000010100010000000000000000000000000000010100000000'
)
_INSERT = bytes.fromhex(
    '080102040129c79d000401010000000101010c020000000000028dca01010002baba00000000000101010d0d0100008dca00010000baba00000000'
)
_DROP = bytes.fromhex(
    '080102040129c8750004000000000101010b0c0000000000000000000000000000010100000000'
)
# The same shape while the counter still fitted three bytes.
_CREATE_YOUNG = bytes.fromhex(
    '08010203029c6800040000000001010001000000000000000000000000000001010000'
)


class TestNineiStatusWithAWideCounter(unittest.TestCase):
    def test_a_successful_create(self):
        self.assertEqual(decode_fv2_dml_response(_CREATE), (0, 0))

    def test_a_successful_insert_reports_its_row(self):
        self.assertEqual(decode_fv2_dml_response(_INSERT), (1, 0))

    def test_a_successful_drop(self):
        self.assertEqual(decode_fv2_dml_response(_DROP), (0, 0))

    def test_a_young_instance_still_decodes(self):
        self.assertEqual(decode_fv2_dml_response(_CREATE_YOUNG), (0, 0))


# #1079: the short status carries the rowid of the row the statement touched,
# in the 10g+ layout. Captured on 9.2 (the third of three one-row INSERTs, then
# a CREATE INDEX) and on 8.1.7 (the third INSERT, then a failed statement). The
# rowids are Oracle's own ROWIDTOCHAR of those rows.
_INSERT_SLOT_2 = bytes.fromhex(
    '0801020401955943000401010000000101010c02000000000003016624010100'
    '02b9120102000000000101010d0d010001662400010000b9120002000000'
)
_DDL_AFTER_IT = bytes.fromhex(
    '080102040195594e000400000000010101180900000000000301662401010002'
    'b912010200000000010100000000'
)
_8I_INSERT_SLOT_2 = bytes.fromhex(
    '0804004a12100000000000070000000100000000000000040100000000000000'
    '000007000c00020000000000311d0100050000cf000000020000000000000d00'
    '00010000000d000d0100011d310005000000cf00020000000000000000000000'
    '00'
)


class TestTheRowidInTheShortStatus(unittest.TestCase):
    def test_9i_reports_the_inserted_row(self):
        from seerdb.common.tns import decode_fv2_dml_rowid

        self.assertEqual(decode_fv2_dml_rowid(_INSERT_SLOT_2), 'AAAWYkAABAAALkSAAC')
        # The #711 capture's INSERT: data object 36298, file 1, block 47802, slot 0.
        self.assertEqual(decode_fv2_dml_rowid(_INSERT), 'AAAI3KAABAAALq6AAA')

    def test_9i_leaves_the_last_rowid_in_a_ddl_reply(self):
        # The server does not clear the field: a DDL (row count 0) still carries
        # the INSERT's rowid, which the cursor drops for touching no row.
        from seerdb.common.tns import decode_fv2_dml_response, decode_fv2_dml_rowid

        self.assertEqual(decode_fv2_dml_response(_DDL_AFTER_IT), (0, 0))
        self.assertEqual(decode_fv2_dml_rowid(_DDL_AFTER_IT), 'AAAWYkAABAAALkSAAC')

    def test_9i_statements_that_touched_nothing_carry_no_rowid(self):
        from seerdb.common.tns import decode_fv2_dml_rowid

        for reply in (_CREATE, _DROP, _CREATE_YOUNG, b''):
            self.assertIsNone(decode_fv2_dml_rowid(reply))

    def test_8i_reports_the_inserted_row(self):
        from seerdb.common.tns import decode_8i_dml_response, decode_8i_dml_rowid

        self.assertEqual(decode_8i_dml_response(_8I_INSERT_SLOT_2)[:2], (1, 0))
        self.assertEqual(decode_8i_dml_rowid(_8I_INSERT_SLOT_2), 'AAAR0xAAFAAAADPAAC')

    def test_8i_error_carries_no_rowid(self):
        from seerdb.common.tns import decode_8i_dml_rowid

        failed = (
            bytes.fromhex('0400000000ae03')
            + bytes(40)
            + b'(ORA-00942: table or view does not exist\n'
        )
        self.assertIsNone(decode_8i_dml_rowid(failed))


# A successful ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY', captured live from 8.1.7 and
# from 9.2.0.4 over the native OALL8 form (#2687): the RPA carries the session's
# NLS settings as keyword-value pairs, and the status follows them.
_8I_ALTER_SESSION = bytes.fromhex(
    '0804004bec280000000000010000000000000000001000000000000800000008414d4552'
    '4943414e1000000000000700000007414d45524943410900000000000100000001240000'
    '000000000700000007414d455249434101000000000002000000022e2c0200000000000c'
    '0000000c57453849534f3838353950310a00000000000900000009475245474f5249414e'
    '0c00000000000400000004595959590700000000000800000008414d45524943414e0800'
    '00000000060000000642494e4152590b00000000000e0000000e48482e4d492e53535846'
    '4620414d390000000000180000001844442d4d4f4e2d52522048482e4d492e5353584646'
    '20414d3a0000000000160000001648482e4d492e535358464620414d20545a483a545a4d'
    '3b0000000000200000002044442d4d4f4e2d52522048482e4d492e535358464620414d20'
    '545a483a545a4d3c0000000000010000000124340000000000060000000642494e415259'
    '32000400000000000000000000010000002a004000000000000000000000000000000000'
    '0000000000060000010000000000000000000000000000000000'
)
_9I_ALTER_SESSION = bytes.fromhex(
    '080500032e95020000000001000000000000000000000000001200000000000800000008'
    '414d45524943414e1000000000000700000007414d455249434109000000000001000000'
    '01240000000000000700000007414d455249434101000000000002000000022e2c020000'
    '0000000c0000000c57453849534f3838353950310a00000000000900000009475245474f'
    '5249414e0c00000000000400000004595959590700000000000800000008414d45524943'
    '414e080000000000060000000642494e4152590b00000000000e0000000e48482e4d492e'
    '535358464620414d390000000000180000001844442d4d4f4e2d52522048482e4d492e53'
    '5358464620414d3a0000000000120000001248482e4d492e535358464620414d20545a52'
    '3b00000000001c0000001c44442d4d4f4e2d52522048482e4d492e535358464620414d20'
    '545a523c0000000000010000000124340000000000060000000642494e41525932000000'
    '00000400000004425954453d0000000000050000000546414c53453e0004010000000100'
    '000000000000000000010000002a00000000000000000000000000000000000000000000'
    '00000000070000010000003601000000000000000000000000000080d0d4030000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000'
    '00000000000000000000000000000000000000'
)


class TestTheRpaCarriesTheSessionsSettings(unittest.TestCase):
    # The RPA's last two words are a transaction id's length and a pair count
    # (#2687). Read as four bytes of padding, the pairs hid the status, and the
    # reply decoded as one with no status at all.

    def test_8i_reads_the_pairs_and_the_status_after_them(self):
        from seerdb.common.tns import _O8I_RPA_FROM_O8I, TTI_OER, _o8i_status

        (rpa, rest) = _O8I_RPA_FROM_O8I(_8I_ALTER_SESSION)
        self.assertEqual(rpa['pair_count'], 16)
        settings = {pair['keyword']: pair.get('binary') for pair in rpa['pairs']}
        self.assertEqual(settings[7], b'YYYY')
        self.assertEqual(settings[10], b'WE8ISO8859P1')
        self.assertEqual(rest[:1], bytes([TTI_OER]))
        status = _o8i_status(_8I_ALTER_SESSION)
        self.assertIsNotNone(status)
        self.assertEqual(status['code'], 0)

    def test_9i_reads_the_pairs_and_the_status_after_them(self):
        from seerdb.common.tns import _O8I_RPA_FROM_O9I, TTI_OER

        (rpa, rest) = _O8I_RPA_FROM_O9I(_9I_ALTER_SESSION)
        self.assertEqual(rpa['pair_count'], 18)
        settings = {pair['keyword']: pair.get('binary') for pair in rpa['pairs']}
        self.assertEqual(settings[7], b'YYYY')
        self.assertEqual(settings[62], b'FALSE')
        self.assertEqual(rest[:1], bytes([TTI_OER]))

    def test_a_reply_cut_inside_the_pairs_is_refused(self):
        from seerdb.common.exceptions import DataError
        from seerdb.common.tns import _o8i_status_strict

        with self.assertRaises(DataError):
            _o8i_status_strict(_8I_ALTER_SESSION[:200])
