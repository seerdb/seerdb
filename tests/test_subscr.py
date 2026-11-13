# SPDX-FileCopyrightText: 2026 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Client-initiated subscriptions (#2460), against python-oracledb 26.1 thin's calls
to 23ai FREEPDB1, captured: a database-change subscription with a registered query
(QOS query and ROWIDs), and an AQ one on a sharded RAW queue. Field version 24."""

import unittest
from types import SimpleNamespace

from seerdb.client import subscr
from seerdb.client.subscr import Subscription
from seerdb.common import tns
from seerdb.common.exceptions import NotSupportedError
from seerdb.common.tns_consts import FIELD_VERSION_MAX

_FV = FIELD_VERSION_MAX
_CQN = {
    'register': '037d0300010104010103000001010101010106000100010101010101011d010370796f'
    '0102000000010800000001300000000000000000',
    'reply': '0801010002012e010102012e0000010101363628414444524553533d2850524f544f434f'
    '4c3d5443502928484f53543d3237303432646664383835612928504f52543d313532312929010a0a4f'
    '43493a45503a33303109010102ed201d',
    'notify': '03bb0300010a0a4f43493a45503a3330310100',
    'stream': '0000000b0620000000000d0000001206200000000001030002012e00000000000d06200000'
    '0000000000000000760620000000000101000001646400010000000000000007000846524545504442'
    '310a000300ce3b00000000000000000001000000010000000000000007000100000002000e50594f2e'
    '534545525f43514e5f5400048e39000100000002001241414249343541414141414155697341414100',
}
_AQ = {
    'register': '037d0300010104010103000001010101010106000100010101010101011d010370796f'
    '0101010a0a534545525f4e54465f510000010800000001200000000000000000',
    'reply': '080101000001010201310000010101363628414444524553533d2850524f544f434f4c3d54'
    '43502928484f53543d3237303432646664383835612928504f52543d313532312929010a0a4f43493a'
    '45503a33303409010102a6361d',
    'notify': '03bb0300010a0a4f43493a45503a3330340100',
    'stream': '0000000b0620000000000d000000260620000000000101000201310112122250594f222e22'
    '534545525f4e54465f5122000000003b0620000000000110100000000000000000000000000466000001'
    '016c010400000000000103010107787e0b0d17073c0000000000000000',
}


def _bytes(case: dict, key: str) -> bytes:
    return bytes.fromhex(case[key])


class TestTheCalls(unittest.TestCase):
    def test_register_is_the_captured_call(self):
        for case, namespace, name, flags in (
            (_CQN, 2, None, 0x30),
            (_AQ, 1, b'SEER_NTF_Q', 0x20),
        ):
            with self.subTest(namespace=namespace):
                self.assertEqual(
                    tns.encode_subscribe(
                        3, _FV, 1, b'pyo', None, namespace, name, 8, 0, flags
                    ),
                    _bytes(case, 'register'),
                )

    def test_the_reply_gives_the_registration_and_the_client_id(self):
        for case, registration, client_id in (
            (_CQN, 302, b'OCI:EP:301'),
            (_AQ, 305, b'OCI:EP:304'),
        ):
            with self.subTest(registration=registration):
                (found, cid, rest) = tns.decode_subscribe_reply(
                    _bytes(case, 'reply')[1:]
                )
                self.assertEqual((found, cid), (registration, client_id))
                self.assertEqual(tns.decode_error_reply(rest), (0, None))

    def test_notify_is_the_captured_call(self):
        self.assertEqual(
            tns.encode_notify(3, _FV, b'OCI:EP:301'), _bytes(_CQN, 'notify')
        )

    def test_the_wire_qos_and_flags(self):
        # As python-oracledb computes them: secure always; the query and ROWID
        # bits among the flags. An AQ subscription's QOS defaults to 8.
        sub = SimpleNamespace(
            qos=subscr.SUBSCR_QOS_QUERY | subscr.SUBSCR_QOS_ROWIDS, operations=0
        )
        self.assertEqual(Subscription._wire_qos_and_flags(sub), (0x08, 0x30))  # type: ignore[arg-type]
        sub = SimpleNamespace(
            qos=subscr.SUBSCR_QOS_RELIABLE | subscr.SUBSCR_QOS_DEREG_NFY, operations=2
        )
        self.assertEqual(Subscription._wire_qos_and_flags(sub), (0x19, 0x02))  # type: ignore[arg-type]


class _Socket:
    """Hands back the captured bytes a few at a time, then EOF."""

    def __init__(self, data: bytes, size: int = 7):
        self._data = data
        self._size = size

    def recv(self, _limit: int) -> bytes:
        (chunk, self._data) = (self._data[: self._size], self._data[self._size :])
        return chunk


def _emon(stream: bytes) -> SimpleNamespace:
    return SimpleNamespace(
        _sock=_Socket(stream),
        sdu=8192,
        _large_packets=True,
        _ano=None,
        field_version=_FV,
        db_unique_name='FREE',
    )


class TestTheStream(unittest.TestCase):
    def _read(self, case: dict, namespace: int, qos: int = 0) -> list:
        got: list = []
        sub = Subscription(
            None,  # type: ignore[arg-type]
            namespace,
            0,
            got.append,
            0,
            0,
            0,
            qos,
            None,
            0,
            0,
            1,
            None,  # type: ignore[arg-type]
        )
        sub._read(_emon(_bytes(case, 'stream')))  # type: ignore[arg-type]
        return got

    def test_a_query_change(self):
        (message,) = self._read(
            _CQN, 2, subscr.SUBSCR_QOS_QUERY | subscr.SUBSCR_QOS_ROWIDS
        )
        self.assertEqual(message.type, subscr.EVENT_QUERYCHANGE)
        self.assertEqual(message.dbname, 'FREEPDB1')
        self.assertTrue(message.registered)
        (query,) = message.queries
        self.assertEqual((query.id, query.operation), (1, 7))
        (table,) = query.tables
        self.assertEqual((table.name, table.operation), ('PYO.SEER_CQN_T', 2))
        self.assertEqual(
            [(r.operation, r.rowid) for r in table.rows],
            [(subscr.OPCODE_INSERT, 'AABI45AAAAAAUisAAA')],
        )

    def test_an_aq_message(self):
        (message,) = self._read(_AQ, 1)
        self.assertEqual(message.type, subscr.EVENT_AQ)
        self.assertEqual(message.queue_name, '"PYO"."SEER_NTF_Q"')
        self.assertIsNone(message.consumer_name)
        self.assertEqual(message.msgid, bytes(12) + b'\x04\x66\x00\x00')
        self.assertEqual(message.dbname, 'FREE')

    def test_a_stop_record_ends_it(self):
        # The OAC token, then a STOP record (type 4).
        got: list = []
        sub = Subscription(None, 2, 0, got.append, 0, 0, 0, 0, None, 0, 0, 1, None)  # type: ignore[arg-type]
        body = bytes([0, 0, 13, 1, 4])  # data flags, OAC, ub4 4
        packet = (10 + 3).to_bytes(4, 'big') + bytes([6, 0, 0, 0]) + body
        sub._read(_emon(packet + b'never read'))  # type: ignore[arg-type]
        self.assertEqual(got, [])


class TestTheArguments(unittest.TestCase):
    def test_only_client_initiated(self):
        with self.assertRaises(NotSupportedError):
            subscr.subscription_arguments(False, 0)
        with self.assertRaises(NotSupportedError):
            subscr.subscription_arguments(True, subscr.SUBSCR_PROTO_MAIL)

    def test_an_async_connection_has_none(self):
        from seerdb.client.aconnection import AsyncOracleConnect

        conn = AsyncOracleConnect(host='x', port=1, user='pyo', password='p')
        with self.assertRaises(NotSupportedError):
            conn.subscribe(callback=print)


if __name__ == '__main__':
    unittest.main()
