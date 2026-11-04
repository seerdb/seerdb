# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for sessionless transactions (#133, 23ai). They reuse the
# func-103 TPC switch encoder with the SESSIONLESS flag and a magic format-id;
# the server reports txn-id sync state back via a SYNC server-side piggyback.
# Byte fixtures below are real captures from a 23ai (23.26) server taken with
# the oracledb-thin reference through the logging proxy. The full
# begin/suspend/resume/commit flow is covered live on 23ai.

import unittest

from seerdb.client.connection import Xid, _normalize_sessionless_txn_id
from seerdb.common.tns import (
    _ENCODE_FIELD_VERSION,
    decode_token_server_piggyback,
    encode_tpc_switch,
)
from seerdb.common.tns_consts import (
    TNS_FUNC_TPC_TXN_SWITCH,
    TNS_TPC_SESSIONLESS_FORMAT_ID,
    TNS_TPC_TXN_DETACH,
    TNS_TPC_TXN_START,
    TPC_BEGIN_NEW,
    TPC_BEGIN_RESUME,
    TPC_TXN_FLAGS_SESSIONLESS,
    TTI_FUN,
)


def _switch(operation, txnid, flags, timeout):
    xid = None if txnid is None else Xid(TNS_TPC_SESSIONLESS_FORMAT_ID, txnid, b'')
    return encode_tpc_switch(7, 24, operation, xid, flags, timeout, None)


class TestNormalizeTxnId(unittest.TestCase):
    def test_str_to_utf8(self):
        self.assertEqual(_normalize_sessionless_txn_id('abc'), b'abc')

    def test_bytes_passthrough(self):
        self.assertEqual(_normalize_sessionless_txn_id(b'\x01\x02'), b'\x01\x02')

    def test_none_yields_uuid(self):
        out = _normalize_sessionless_txn_id(None)
        self.assertEqual(len(out), 16)
        self.assertNotEqual(out, _normalize_sessionless_txn_id(None))

    def test_too_long_rejected(self):
        with self.assertRaises(ValueError):
            _normalize_sessionless_txn_id(b'x' * 65)

    def test_bad_type_rejected(self):
        with self.assertRaises(TypeError):
            _normalize_sessionless_txn_id(123)


class TestEncode(unittest.TestCase):
    def setUp(self):
        _ENCODE_FIELD_VERSION.set(24)

    def tearDown(self):
        _ENCODE_FIELD_VERSION.set(6)

    # Begin body for begin_sessionless_transaction("pyo-sl-001", timeout=120):
    # func 103, op START, magic format-id 0x4e5c3e, gtrid in the xid slot
    # padded to 128 bytes, flags NEW|SESSIONLESS = 0x11 ("01 11"), timeout 0x78.
    # Verified live on 23ai: the server accepts seerdb's minimal sb4 form of
    # the format-id ("03 4e5c3e"); the oracledb reference pads it to four bytes.
    _BEGIN = (
        bytes.fromhex(
            '0367070001010000034e5c3e010a000101800111017801010100000000'
            '70796f2d736c2d303031'
        )
        + bytes(118)
        + bytes([0])
    )

    def test_begin_matches_capture(self):
        out = _switch(
            TNS_TPC_TXN_START,
            b'pyo-sl-001',
            TPC_BEGIN_NEW | TPC_TXN_FLAGS_SESSIONLESS,
            120,
        )
        self.assertEqual(out, self._BEGIN)
        self.assertEqual(out[1], TNS_FUNC_TPC_TXN_SWITCH)  # func 103
        # the magic format-id 0x4e5c3e is present in the xid descriptor
        self.assertIn(bytes.fromhex('4e5c3e'), out)

    def test_resume_flag(self):
        out = _switch(
            TNS_TPC_TXN_START,
            b'pyo-sl-001',
            TPC_BEGIN_RESUME | TPC_TXN_FLAGS_SESSIONLESS,
            120,
        )
        self.assertEqual(out[0], TTI_FUN)
        # RESUME|SESSIONLESS = 0x14, encoded sb4 "01 14"
        self.assertIn(bytes.fromhex('0114') + bytes.fromhex('0178'), out)

    def test_suspend_has_no_xid(self):
        out = _switch(TNS_TPC_TXN_DETACH, None, TPC_TXN_FLAGS_SESSIONLESS, 0)
        self.assertEqual(out[1], TNS_FUNC_TPC_TXN_SWITCH)
        # no magic format-id when detaching (xid is None)
        self.assertNotIn(bytes.fromhex('4e5c3e'), out)
        # SESSIONLESS-only flag 0x10
        self.assertIn(bytes.fromhex('0110'), out)


class TestSyncPiggybackDecode(unittest.TestCase):
    # Real SYNC server-side piggyback (opcode 5) from a 23ai commit that ended a
    # sessionless transaction: keyword 201 (transaction id) carrying the 2-byte
    # sync state 0x83 0x01 (UNSET | version 1). seerdb consumes it byte for
    # byte and continues with the rest of the response.
    _SYNC = bytes.fromhex('170501011001011600010202830101c900090105022f65')

    def test_consumes_and_continues(self):
        # must not raise "Unhandled server-side piggyback opcode 5"
        result = decode_token_server_piggyback(self._SYNC, (None, None, [], None))
        self.assertEqual(result, (True, (None, None, [], None)))


# A 23ai (23.26) reply to resuming an unknown sessionless transaction, captured
# 2026-10-10: a server piggyback (0x17) then the TTI_OER carrying ORA-26218.
_RESUME_UNKNOWN_REPLY = bytes.fromhex(
    '170501011001011600010202820101c90004010102572f0002666a000000000000000000000000'
    '00000000000700000000000002666a0000004f4f52412d32363231383a2073657373696f6e6c65'
    '7373207472616e73616374696f6e2077697468204754524944203733364333363244364536463730'
    '363520646f6573206e6f742065786973742e0a1d'
)


# 23ai's reply to a rollback of an XID that never existed, captured at field
# version 24 (#2474): ORA-24756, whose message runs over two lines.
_ROLLBACK_UNKNOWN_REPLY = bytes.fromhex(
    '04010102fd4d000260b40000000000000000000000000000000000070000000000000260b400'
    '0000724f52412d32343735363a207472616e73616374696f6e2077697468206964656e746966'
    '696572206774693a20307830303030303030312e373336353635373236343632324436453635'
    '3736363537323244373736313733206269643a20307833310a20646f6573206e6f7420657869'
    '73740a1d'
)


class TestReplyErrors(unittest.TestCase):
    # A TPC reply that failed is raised, not discarded (#1755): the server's
    # ORA code and its whole message (#2474), read by the codec at the field
    # version of the session the reply was captured in, as a connection sets it.
    def setUp(self):
        from seerdb.common.tns import (
            _DECODE_FIELD_VERSION,
            _DECODE_SERVER_FIELD_VERSION,
        )

        self._tokens = (
            (_DECODE_FIELD_VERSION, _DECODE_FIELD_VERSION.set(24)),
            (_DECODE_SERVER_FIELD_VERSION, _DECODE_SERVER_FIELD_VERSION.set(24)),
        )

    def tearDown(self):
        for var, token in self._tokens:
            var.reset(token)

    def test_failed_resume_raises_its_ora_error(self):
        # A reply that opens with a SYNC piggyback.
        from seerdb.client.connection import _check_tpc_reply
        from seerdb.common.exceptions import DatabaseError

        with self.assertRaises(DatabaseError) as ctx:
            _check_tpc_reply(_RESUME_UNKNOWN_REPLY)
        self.assertEqual(ctx.exception.code, 26218)
        self.assertEqual(
            str(ctx.exception),
            'ORA-26218: sessionless transaction with GTRID 736C362D6E6F7065 '
            'does not exist.',
        )

    def test_a_message_over_two_lines_is_kept_whole(self):
        from seerdb.client.connection import _check_tpc_reply
        from seerdb.common.exceptions import DatabaseError

        with self.assertRaises(DatabaseError) as ctx:
            _check_tpc_reply(_ROLLBACK_UNKNOWN_REPLY)
        self.assertEqual(ctx.exception.code, 24756)
        self.assertTrue(str(ctx.exception).startswith('ORA-24756: transaction'))
        self.assertTrue(str(ctx.exception).endswith('bid: 0x31\n does not exist'))

    def test_return_params_pass(self):
        from seerdb.client.connection import _check_tpc_reply

        reply = bytes([0x08]) + b'\x00' * 8
        self.assertIs(_check_tpc_reply(reply), reply)


if __name__ == '__main__':
    unittest.main()
